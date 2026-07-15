import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { generateSshKeyMaterial } from './ssh-key'

const KEY_TYPE = 'ssh-ed25519'
const MAGIC = Buffer.from('openssh-key-v1\0', 'ascii')
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')

interface ParsedOpenSshPrivateKey {
  publicBlob: Buffer
  publicKeyBytes: Buffer
  seed: Buffer
  comment: string
  padding: Buffer
}

class StrictReader {
  private offset = 0

  constructor(private readonly bytes: Buffer) {}

  read(length: number): Buffer {
    if (!Number.isSafeInteger(length) || length < 0 || this.offset + length > this.bytes.length) {
      throw new Error('INVALID_OPENSSH_KEY')
    }
    const value = this.bytes.subarray(this.offset, this.offset + length)
    this.offset += length
    return value
  }

  readUint32(): number {
    return this.read(4).readUInt32BE(0)
  }

  readString(): Buffer {
    return this.read(this.readUint32())
  }

  expectEnd(): void {
    if (this.offset !== this.bytes.length) throw new Error('INVALID_OPENSSH_KEY')
  }

  remaining(): Buffer {
    return this.read(this.bytes.length - this.offset)
  }
}

function expectAscii(actual: Buffer, expected: string): void {
  expect(actual.toString('utf8')).toBe(expected)
}

function parsePublicBlob(blob: Buffer): Buffer {
  const reader = new StrictReader(blob)
  expectAscii(reader.readString(), KEY_TYPE)
  const publicKeyBytes = reader.readString()
  expect(publicKeyBytes).toHaveLength(32)
  reader.expectEnd()
  return publicKeyBytes
}

function parsePrivateKey(privateKey: string): ParsedOpenSshPrivateKey {
  const lines = privateKey.split('\n')
  expect(lines[0]).toBe('-----BEGIN OPENSSH PRIVATE KEY-----')
  expect(lines.at(-2)).toBe('-----END OPENSSH PRIVATE KEY-----')
  expect(lines.at(-1)).toBe('')
  const bodyLines = lines.slice(1, -2)
  expect(bodyLines.length).toBeGreaterThan(0)
  expect(bodyLines.every((line) => line.length > 0 && line.length <= 70)).toBe(true)

  const encoded = bodyLines.join('')
  expect(encoded).toMatch(/^[A-Za-z0-9+/]+={0,2}$/)
  const binary = Buffer.from(encoded, 'base64')
  const reader = new StrictReader(binary)
  expect(reader.read(MAGIC.length).equals(MAGIC)).toBe(true)
  expectAscii(reader.readString(), 'none')
  expectAscii(reader.readString(), 'none')
  expect(reader.readString()).toHaveLength(0)
  expect(reader.readUint32()).toBe(1)
  const publicBlob = reader.readString()
  const outerPublicKeyBytes = parsePublicBlob(publicBlob)
  const privateSection = reader.readString()
  reader.expectEnd()

  const privateReader = new StrictReader(privateSection)
  const firstCheck = privateReader.readUint32()
  expect(privateReader.readUint32()).toBe(firstCheck)
  expectAscii(privateReader.readString(), KEY_TYPE)
  const innerPublicKeyBytes = privateReader.readString()
  expect(innerPublicKeyBytes.equals(outerPublicKeyBytes)).toBe(true)
  const keyPair = privateReader.readString()
  expect(keyPair).toHaveLength(64)
  expect(keyPair.subarray(32).equals(outerPublicKeyBytes)).toBe(true)
  const comment = privateReader.readString().toString('utf8')
  const padding = privateReader.remaining()
  expect(padding.length).toBeGreaterThan(0)
  for (let index = 0; index < padding.length; index += 1) {
    expect(padding[index]).toBe(index + 1)
  }
  expect(privateSection.length % 8).toBe(0)

  return {
    publicBlob: Buffer.from(publicBlob),
    publicKeyBytes: Buffer.from(outerPublicKeyBytes),
    seed: Buffer.from(keyPair.subarray(0, 32)),
    comment,
    padding: Buffer.from(padding)
  }
}

describe('generateSshKeyMaterial', () => {
  it('generates an unencrypted Ed25519 OpenSSH private key with matching public material', () => {
    const material = generateSshKeyMaterial()
    const parsed = parsePrivateKey(material.privateKey)
    let pkcs8: Buffer | undefined
    let derivedSpki: Buffer | undefined

    try {
      expect(parsed.comment).toBe('')
      expect(material.publicKey).toBe(`${KEY_TYPE} ${parsed.publicBlob.toString('base64')}`)

      pkcs8 = Buffer.concat([PKCS8_ED25519_PREFIX, parsed.seed])
      const privateKeyObject = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' })
      derivedSpki = createPublicKey(privateKeyObject).export({ format: 'der', type: 'spki' })
      expect(derivedSpki.subarray(-32).equals(parsed.publicKeyBytes)).toBe(true)

      const message = Buffer.from('BearWarden SSH key consistency test', 'utf8')
      const signature = sign(null, message, privateKeyObject)
      expect(verify(null, message, createPublicKey(privateKeyObject), signature)).toBe(true)
      signature.fill(0)
    } finally {
      parsed.publicBlob.fill(0)
      parsed.publicKeyBytes.fill(0)
      parsed.seed.fill(0)
      parsed.padding.fill(0)
      pkcs8?.fill(0)
      derivedSpki?.fill(0)
    }
  })

  it('computes the standard SHA256 fingerprint over the SSH public-key blob', () => {
    let material = generateSshKeyMaterial()
    for (let attempt = 0; attempt < 64 && !/[+/]/u.test(material.fingerprint); attempt += 1) {
      material = generateSshKeyMaterial()
    }
    const [, encodedPublicBlob, comment] = material.publicKey.split(' ')
    expect(comment).toBeUndefined()
    const publicBlob = Buffer.from(encodedPublicBlob!, 'base64')

    try {
      const expected = createHash('sha256').update(publicBlob).digest('base64').replace(/=+$/u, '')
      expect(material.fingerprint).toBe(`SHA256:${expected}`)
      expect(material.fingerprint).not.toContain('=')
      expect(material.fingerprint).toMatch(/[+/]/u)
      expect(material.fingerprint).not.toMatch(/[-_]/u)
    } finally {
      publicBlob.fill(0)
    }
  })

  it('uses fresh CSPRNG material for every generated key', () => {
    const first = generateSshKeyMaterial()
    const second = generateSshKeyMaterial()

    expect(second.privateKey).not.toBe(first.privateKey)
    expect(second.publicKey).not.toBe(first.publicKey)
    expect(second.fingerprint).not.toBe(first.fingerprint)
  })
})
