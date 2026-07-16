import { generateKeyPairSync, type KeyObject } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { utils, type ParsedKey } from 'ssh2'
import { EncryptedVaultStore } from './encrypted-vault-store'
import { formatSshKeyMaterial } from './ssh-key-format'
import { VaultService } from './vault-service'

const MASTER_PASSWORD = 'correct horse battery staple'
const temporaryDirectories: string[] = []

interface TestKey {
  privateKey: string
  publicKey: string
  fingerprint: string
  parsed: ParsedKey
}

function makeKey(type: 'ed25519' | 'rsa' | 'p256' | 'p384' | 'p521'): TestKey {
  const keyObject: KeyObject =
    type === 'ed25519'
      ? generateKeyPairSync('ed25519').privateKey
      : type === 'rsa'
        ? generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
        : generateKeyPairSync('ec', {
            namedCurve: type === 'p256' ? 'prime256v1' : type === 'p384' ? 'secp384r1' : 'secp521r1'
          }).privateKey
  const material = formatSshKeyMaterial(keyObject)
  const parsed = utils.parseKey(material.privateKey)
  if (parsed instanceof Error || Array.isArray(parsed)) throw parsed
  return { ...material, parsed }
}

async function createHarness(): Promise<VaultService> {
  const directory = await mkdtemp(join(tmpdir(), 'bearwarden-agent-vault-test-'))
  temporaryDirectories.push(directory)
  const service = new VaultService(new EncryptedVaultStore(join(directory, 'vault.json')), {
    copyText: vi.fn(),
    openExternal: vi.fn()
  })
  await service.setup(MASTER_PASSWORD)
  return service
}

function readSshString(buffer: Buffer, offset: number): { value: Buffer; offset: number } {
  const length = buffer.readUInt32BE(offset)
  const start = offset + 4
  return { value: buffer.subarray(start, start + length), offset: start + length }
}

function derLength(length: number): Buffer {
  if (length < 128) return Buffer.from([length])
  const bytes: number[] = []
  for (let remaining = length; remaining > 0; remaining = Math.floor(remaining / 256)) {
    bytes.unshift(remaining & 0xff)
  }
  return Buffer.from([0x80 | bytes.length, ...bytes])
}

function sshEcdsaToDer(signature: Buffer): Buffer {
  const r = readSshString(signature, 0)
  const s = readSshString(signature, r.offset)
  const integer = (value: Buffer): Buffer =>
    Buffer.concat([Buffer.from([0x02]), derLength(value.length), value])
  const body = Buffer.concat([integer(r.value), integer(s.value)])
  return Buffer.concat([Buffer.from([0x30]), derLength(body.length), body])
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true }))
  )
})

describe('VaultService SSH Agent boundary', () => {
  it('lists only active supported SSH identities and never exposes private material', async () => {
    const service = await createHarness()
    const activeKey = makeKey('ed25519')
    const archivedKey = makeKey('rsa')
    const deletedKey = makeKey('p256')
    const active = await service.createLogin({
      type: 'sshKey',
      name: 'Active key',
      reprompt: 1,
      ...activeKey
    })
    const archived = await service.createLogin({
      type: 'sshKey',
      name: 'Archived key',
      ...archivedKey
    })
    const deleted = await service.createLogin({
      type: 'sshKey',
      name: 'Deleted key',
      ...deletedKey
    })
    await service.createLogin({ type: 'login', name: 'Not an SSH key' })
    await service.createLogin({
      type: 'sshKey',
      name: 'Malformed key',
      privateKey: 'not a private key',
      publicKey: 'not a public key',
      fingerprint: 'not a fingerprint'
    })
    await service.archiveLogin({ id: archived.id })
    await service.deleteLogin({ id: deleted.id })

    const identities = await service.listSshAgentIdentities()
    expect(identities).toHaveLength(1)
    expect(identities[0]).toMatchObject({
      itemId: active.id,
      name: 'Active key',
      fingerprint: activeKey.fingerprint,
      reprompt: 1,
      generation: expect.any(Number)
    })
    expect(identities[0]!.publicKeyBlob.equals(activeKey.parsed.getPublicSSH())).toBe(true)
    expect(identities[0]).not.toHaveProperty('privateKey')

    await service.lock()
    await expect(service.listSshAgentIdentities()).rejects.toMatchObject({ code: 'LOCKED' })
  })

  it.each([
    ['ed25519', undefined, 'ssh-ed25519'],
    ['rsa', 'sha256', 'rsa-sha2-256'],
    ['rsa', 'sha512', 'rsa-sha2-512'],
    ['p256', undefined, 'ecdsa-sha2-nistp256'],
    ['p384', undefined, 'ecdsa-sha2-nistp384'],
    ['p521', undefined, 'ecdsa-sha2-nistp521']
  ] as const)('signs and verifies %s SSH Agent requests', async (type, rsaHash, algorithm) => {
    const service = await createHarness()
    const key = makeKey(type)
    const item = await service.createLogin({ type: 'sshKey', name: `${type} key`, ...key })
    const [identity] = await service.listSshAgentIdentities()
    const data = Buffer.from(`SSH Agent ${type} signing test`)

    const result = await service.signSshAgentRequest(
      {
        publicKeyBlob: identity!.publicKeyBlob,
        data,
        rsaHash,
        expectedGeneration: identity!.generation
      },
      () => false
    )

    expect(result).toMatchObject({ itemId: item.id, generation: identity!.generation, algorithm })
    const signature = type.startsWith('p') ? sshEcdsaToDer(result.signature) : result.signature
    expect(
      type === 'rsa'
        ? key.parsed.verify(data, signature, algorithm)
        : key.parsed.verify(data, signature)
    ).toBe(true)
    expect(result).not.toHaveProperty('privateKey')
  })

  it('rejects unknown, inactive, duplicate, and mismatched identities', async () => {
    const service = await createHarness()
    const expected = makeKey('ed25519')
    const wrongPrivate = makeKey('ed25519')
    const unknown = makeKey('ed25519')
    const item = await service.createLogin({
      type: 'sshKey',
      name: 'Mismatched key',
      privateKey: wrongPrivate.privateKey,
      publicKey: expected.publicKey,
      fingerprint: expected.fingerprint
    })
    const [identity] = await service.listSshAgentIdentities()
    const request = {
      publicKeyBlob: identity!.publicKeyBlob,
      data: Buffer.from('payload'),
      rsaHash: undefined,
      expectedGeneration: identity!.generation
    }

    await expect(service.signSshAgentRequest(request, () => true)).rejects.toThrow(
      'does not match private key'
    )
    await expect(
      service.signSshAgentRequest(
        { ...request, publicKeyBlob: unknown.parsed.getPublicSSH() },
        () => true
      )
    ).rejects.toMatchObject({ code: 'NOT_FOUND' })

    await service.updateLogin({
      id: item.id,
      privateKey: expected.privateKey,
      publicKey: expected.publicKey,
      fingerprint: expected.fingerprint
    })
    await service.createLogin({
      type: 'sshKey',
      name: 'Duplicate identity',
      privateKey: expected.privateKey,
      publicKey: expected.publicKey,
      fingerprint: expected.fingerprint
    })
    await expect(service.signSshAgentRequest(request, () => true)).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
  })

  it('re-checks reprompt atomically and rejects approval capabilities from an older epoch', async () => {
    const service = await createHarness()
    const key = makeKey('ed25519')
    const item = await service.createLogin({ type: 'sshKey', name: 'Protected key', ...key })
    const [approvalContext] = await service.listSshAgentIdentities()
    const request = {
      publicKeyBlob: approvalContext!.publicKeyBlob,
      data: Buffer.from('protected request'),
      rsaHash: undefined,
      expectedGeneration: approvalContext!.generation
    }

    // This models a sync/update enabling reprompt after the approval context was created.
    await service.updateLogin({ id: item.id, reprompt: 1 })
    const expiredApproval = vi.fn(() => false)
    await expect(service.signSshAgentRequest(request, expiredApproval)).rejects.toMatchObject({
      code: 'REPROMPT_REQUIRED'
    })
    expect(expiredApproval).toHaveBeenCalledWith([item.id], {
      generation: approvalContext!.generation
    })

    const validApproval = vi.fn(
      (ids: readonly string[], state: { generation: number }) =>
        ids.length === 1 && ids[0] === item.id && state.generation === approvalContext!.generation
    )
    await expect(service.signSshAgentRequest(request, validApproval)).resolves.toMatchObject({
      itemId: item.id
    })

    await service.lock()
    await service.unlock(MASTER_PASSWORD)
    await expect(service.signSshAgentRequest(request, () => true)).rejects.toMatchObject({
      code: 'LOCKED'
    })
  })

  it('does not sign an identity archived after its approval context was created', async () => {
    const service = await createHarness()
    const key = makeKey('ed25519')
    const item = await service.createLogin({ type: 'sshKey', name: 'Soon archived', ...key })
    const [identity] = await service.listSshAgentIdentities()
    await service.archiveLogin({ id: item.id })

    await expect(
      service.signSshAgentRequest(
        {
          publicKeyBlob: identity!.publicKeyBlob,
          data: Buffer.from('must not sign'),
          rsaHash: undefined,
          expectedGeneration: identity!.generation
        },
        () => true
      )
    ).rejects.toMatchObject({ code: 'NOT_FOUND' })
  })
})
