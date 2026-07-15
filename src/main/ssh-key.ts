import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto'
import type { SshKeyMaterial } from '../shared/vault-contract'

export type { SshKeyMaterial } from '../shared/vault-contract'

const KEY_TYPE = 'ssh-ed25519'
const OPENSSH_MAGIC = Buffer.from('openssh-key-v1\0', 'ascii')
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')
const ED25519_KEY_BYTES = 32
const OPENSSH_BLOCK_SIZE = 8
const PEM_LINE_LENGTH = 70

function uint32(value: number): Buffer {
  const encoded = Buffer.allocUnsafe(4)
  encoded.writeUInt32BE(value)
  return encoded
}

function sshString(value: string | Buffer): Buffer {
  const bytes = typeof value === 'string' ? Buffer.from(value, 'utf8') : value
  const encoded = Buffer.allocUnsafe(4 + bytes.length)
  encoded.writeUInt32BE(bytes.length, 0)
  bytes.copy(encoded, 4)
  return encoded
}

function wrapOpenSshPrivateKey(binary: Buffer): string {
  const base64 = binary.toString('base64')
  const lines: string[] = []
  for (let offset = 0; offset < base64.length; offset += PEM_LINE_LENGTH) {
    lines.push(base64.slice(offset, offset + PEM_LINE_LENGTH))
  }
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${lines.join('\n')}\n-----END OPENSSH PRIVATE KEY-----\n`
}

function rawKeyFromDer(der: Buffer, prefix: Buffer): Buffer {
  if (
    der.length !== prefix.length + ED25519_KEY_BYTES ||
    !der.subarray(0, prefix.length).equals(prefix)
  ) {
    throw new Error('SSH_KEY_GENERATION_FAILED')
  }
  return Buffer.from(der.subarray(prefix.length))
}

export function generateSshKeyMaterial(): SshKeyMaterial {
  let privateDer: Buffer | undefined
  let publicDer: Buffer | undefined
  let seed: Buffer | undefined
  let publicKeyBytes: Buffer | undefined
  let privateKeyPair: Buffer | undefined
  let checkBytes: Buffer | undefined
  let privateSection: Buffer | undefined
  let encodedPrivateSection: Buffer | undefined
  let opensshPrivateKey: Buffer | undefined

  const disposable: Buffer[] = []

  try {
    const generated = generateKeyPairSync('ed25519', {
      privateKeyEncoding: { format: 'der', type: 'pkcs8' },
      publicKeyEncoding: { format: 'der', type: 'spki' }
    })
    privateDer = generated.privateKey
    publicDer = generated.publicKey
    seed = rawKeyFromDer(privateDer, PKCS8_ED25519_PREFIX)
    publicKeyBytes = rawKeyFromDer(publicDer, SPKI_ED25519_PREFIX)

    const publicBlob = Buffer.concat([sshString(KEY_TYPE), sshString(publicKeyBytes)])
    disposable.push(publicBlob)

    checkBytes = randomBytes(4)
    const check = checkBytes.readUInt32BE(0)
    privateKeyPair = Buffer.allocUnsafe(ED25519_KEY_BYTES * 2)
    seed.copy(privateKeyPair, 0)
    publicKeyBytes.copy(privateKeyPair, ED25519_KEY_BYTES)

    const privateParts = [
      uint32(check),
      uint32(check),
      sshString(KEY_TYPE),
      sshString(publicKeyBytes),
      sshString(privateKeyPair),
      sshString('')
    ]
    disposable.push(...privateParts)
    const privateLength = privateParts.reduce((total, part) => total + part.length, 0)
    const paddingLength =
      (OPENSSH_BLOCK_SIZE - (privateLength % OPENSSH_BLOCK_SIZE)) % OPENSSH_BLOCK_SIZE
    const padding = Buffer.allocUnsafe(paddingLength)
    for (let index = 0; index < padding.length; index += 1) padding[index] = index + 1
    disposable.push(padding)
    privateSection = Buffer.concat([...privateParts, padding])

    encodedPrivateSection = sshString(privateSection)
    const outerParts = [
      OPENSSH_MAGIC,
      sshString('none'),
      sshString('none'),
      sshString(''),
      uint32(1),
      sshString(publicBlob),
      encodedPrivateSection
    ]
    disposable.push(...outerParts.slice(1, -1))
    opensshPrivateKey = Buffer.concat(outerParts)

    const publicKey = `${KEY_TYPE} ${publicBlob.toString('base64')}`
    const fingerprintDigest = createHash('sha256')
      .update(publicBlob)
      .digest('base64')
      .replace(/=+$/u, '')
    const fingerprint = `SHA256:${fingerprintDigest}`
    return {
      privateKey: wrapOpenSshPrivateKey(opensshPrivateKey),
      publicKey,
      fingerprint
    }
  } catch {
    throw new Error('SSH_KEY_GENERATION_FAILED')
  } finally {
    privateDer?.fill(0)
    publicDer?.fill(0)
    seed?.fill(0)
    publicKeyBytes?.fill(0)
    privateKeyPair?.fill(0)
    checkBytes?.fill(0)
    privateSection?.fill(0)
    encodedPrivateSection?.fill(0)
    opensshPrivateKey?.fill(0)
    for (const buffer of disposable) buffer.fill(0)
  }
}
