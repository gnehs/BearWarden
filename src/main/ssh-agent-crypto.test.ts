import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { utils, type ParsedKey } from 'ssh2'
import { formatSshKeyMaterial } from './ssh-key-format'
import { SshAgentSigningError, signSshAgentData } from './ssh-agent-crypto'

function parsedKey(type: 'ed25519' | 'rsa' | 'p256' | 'p384' | 'p521'): {
  privateKey: string
  parsed: ParsedKey
} {
  const keyObject =
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
  return { privateKey: material.privateKey, parsed }
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

describe('signSshAgentData', () => {
  it('signs Ed25519 data with the SSH algorithm identifier', () => {
    const key = parsedKey('ed25519')
    const data = Buffer.from('authenticate me')
    const result = signSshAgentData(key.privateKey, key.parsed.getPublicSSH(), data, undefined)
    expect(result.algorithm).toBe('ssh-ed25519')
    expect(key.parsed.verify(data, result.signature)).toBe(true)
  })

  it.each([
    ['sha256', 'rsa-sha2-256'],
    ['sha512', 'rsa-sha2-512']
  ] as const)('signs RSA data with %s', (hash, algorithm) => {
    const key = parsedKey('rsa')
    const data = Buffer.from(`rsa ${hash}`)
    const result = signSshAgentData(key.privateKey, key.parsed.getPublicSSH(), data, hash)
    expect(result.algorithm).toBe(algorithm)
    expect(key.parsed.verify(data, result.signature, algorithm)).toBe(true)
  })

  it.each(['p256', 'p384', 'p521'] as const)(
    'encodes %s ECDSA signatures as SSH mpints',
    (type) => {
      const key = parsedKey(type)
      const data = Buffer.from(`ecdsa ${type}`)
      const result = signSshAgentData(key.privateKey, key.parsed.getPublicSSH(), data, undefined)
      expect(result.algorithm).toBe(key.parsed.type)
      expect(key.parsed.verify(data, sshEcdsaToDer(result.signature))).toBe(true)
    }
  )

  it('rejects RSA SHA-1 fallback and mismatched public keys', () => {
    const rsa = parsedKey('rsa')
    expect(() =>
      signSshAgentData(rsa.privateKey, rsa.parsed.getPublicSSH(), Buffer.from('data'), undefined)
    ).toThrow(SshAgentSigningError)

    const other = parsedKey('ed25519')
    expect(() =>
      signSshAgentData(other.privateKey, rsa.parsed.getPublicSSH(), Buffer.from('data'), undefined)
    ).toThrow('does not match')
  })

  it('rejects public-only and malformed material', () => {
    const key = parsedKey('ed25519')
    const publicLine = `${key.parsed.type} ${key.parsed.getPublicSSH().toString('base64')}`
    expect(() =>
      signSshAgentData(publicLine, key.parsed.getPublicSSH(), Buffer.from('data'), undefined)
    ).toThrow('Invalid SSH private key')
    expect(() =>
      signSshAgentData('not a key', key.parsed.getPublicSSH(), Buffer.from('data'), undefined)
    ).toThrow('Invalid SSH private key')
  })
})
