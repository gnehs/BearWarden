import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject
} from 'node:crypto'
import { pbkdf } from 'bcrypt-pbkdf'
import { utils, type ParsedKey } from 'ssh2'
import { describe, expect, it, vi } from 'vitest'
import { importSshKey, type SshKeyImportErrorCode } from './ssh-key-import'

vi.mock('bcrypt-pbkdf', async (importOriginal) => {
  const original = await importOriginal<typeof import('bcrypt-pbkdf')>()
  return { ...original, pbkdf: vi.fn(original.pbkdf) }
})

const mockedPbkdf = vi.mocked(pbkdf)

const PASSWORD = 'test-only-passphrase'

// Official ssh-key 0.7.0-rc.10 ChaCha20-Poly1305 interop fixture; password: hunter42.
const RUST_SSH_KEY_CHACHA_FIXTURE = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAAHWNoYWNoYTIwLXBvbHkxMzA1QG9wZW5zc2guY29tAAAABm
JjcnlwdAAAABgAAAAQ9lHKPvsVkE0FwhalBB6omgAAABAAAAABAAAAMwAAAAtzc2gtZWQy
NTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJiRvYDd00XU/W
BkZ93ZW52HNwvM2m3z/MHuqD8q/tk16rKKtBNOc95wo4gyRzkdGYhKnF1RFCJYcdvlw6zo
kctfmmhQ6W54G6u9Eh9bIJtHt3l4FQgzriuIsBTUKZIlvvk6Fo5ItNPHM00r2ehuX81lcZ
QHMaims6Blw8Esl6G3NYCAa2NKyqlmM5LIfkga/Ymydvrbc7EQmN2hbii0c0aMUdYQclyk
F4o=
-----END OPENSSH PRIVATE KEY-----
`

function expectImportError(run: () => unknown, code: SshKeyImportErrorCode): void {
  try {
    run()
    expect.fail(`Expected ${code}`)
  } catch (error) {
    expect(error).toMatchObject({
      name: 'SshKeyImportError',
      code,
      message: code
    })
  }
}

function exportPkcs8(privateKey: KeyObject, encrypted = false): string {
  return privateKey.export(
    encrypted
      ? { format: 'pem', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase: PASSWORD }
      : { format: 'pem', type: 'pkcs8' }
  ) as string
}

function expectCanonicalMaterial(privateKey: string, expectedType: string): void {
  const parsed = utils.parseKey(privateKey)
  expect(parsed).not.toBeInstanceOf(Error)
  const key = parsed as ParsedKey
  expect(key.isPrivateKey()).toBe(true)
  expect(key.type).toBe(expectedType)
  expect(key.comment).toBe('')

  const message = Buffer.from('BearWarden imported SSH key verification', 'utf8')
  const signature = key.sign(message)
  try {
    expect(key.verify(message, signature)).toBe(true)
  } finally {
    message.fill(0)
    signature.fill(0)
  }
}

function mutateOpenSsh(
  pem: string,
  mutate: (binary: Buffer, readString: () => Buffer, readUint32: () => number) => void
): string {
  const encoded = pem
    .replace('-----BEGIN OPENSSH PRIVATE KEY-----', '')
    .replace('-----END OPENSSH PRIVATE KEY-----', '')
    .replace(/\s/gu, '')
  const binary = Buffer.from(encoded, 'base64')
  let offset = Buffer.byteLength('openssh-key-v1\0', 'ascii')
  const readString = (): Buffer => {
    const length = binary.readUInt32BE(offset)
    offset += 4
    const value = binary.subarray(offset, offset + length)
    offset += length
    return value
  }
  const readUint32 = (): number => {
    const value = binary.readUInt32BE(offset)
    offset += 4
    return value
  }

  try {
    mutate(binary, readString, readUint32)
    return `-----BEGIN OPENSSH PRIVATE KEY-----\n${binary.toString('base64')}\n-----END OPENSSH PRIVATE KEY-----\n`
  } finally {
    binary.fill(0)
  }
}

describe('importSshKey OpenSSH', () => {
  it.each([
    ['Ed25519', () => utils.generateKeyPairSync('ed25519').private, 'ssh-ed25519'],
    ['RSA', () => utils.generateKeyPairSync('rsa', { bits: 2048 }).private, 'ssh-rsa'],
    [
      'ECDSA P-256',
      () => utils.generateKeyPairSync('ecdsa', { bits: 256 }).private,
      'ecdsa-sha2-nistp256'
    ],
    [
      'ECDSA P-384',
      () => utils.generateKeyPairSync('ecdsa', { bits: 384 }).private,
      'ecdsa-sha2-nistp384'
    ],
    [
      'ECDSA P-521',
      () => utils.generateKeyPairSync('ecdsa', { bits: 521 }).private,
      'ecdsa-sha2-nistp521'
    ]
  ])('imports unencrypted %s and emits a usable canonical key', (_name, generate, keyType) => {
    const material = importSshKey(generate())

    expect(material.publicKey.split(' ')).toHaveLength(2)
    expect(material.publicKey.startsWith(`${keyType} `)).toBe(true)
    expectCanonicalMaterial(material.privateKey, keyType)
  })

  it('imports an AES-encrypted OpenSSH key and classifies password failures', () => {
    const encrypted = utils.generateKeyPairSync('ed25519', {
      cipher: 'aes256-ctr',
      passphrase: PASSWORD,
      rounds: 16
    }).private

    expectImportError(() => importSshKey(encrypted), 'PasswordRequired')
    expectImportError(() => importSshKey(encrypted, 'wrong-test-password'), 'WrongPassword')
    expectCanonicalMaterial(importSshKey(encrypted, PASSWORD).privateKey, 'ssh-ed25519')
  })

  it.each([
    'aes128-cbc',
    'aes192-cbc',
    'aes256-cbc',
    'aes128-ctr',
    'aes192-ctr',
    'aes256-ctr',
    'aes128-gcm@openssh.com',
    'aes256-gcm@openssh.com',
    '3des-cbc'
  ])('imports ssh-key-compatible %s encryption', (cipher) => {
    const encrypted = utils.generateKeyPairSync('ed25519', {
      cipher,
      passphrase: PASSWORD,
      rounds: 1
    }).private

    expectCanonicalMaterial(importSshKey(encrypted, PASSWORD).privateKey, 'ssh-ed25519')
  })

  it('imports the official Rust ssh-key ChaCha20-Poly1305 fixture', () => {
    const material = importSshKey(RUST_SSH_KEY_CHACHA_FIXTURE, 'hunter42')

    expect(material.publicKey).toBe(
      'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti'
    )
    expectCanonicalMaterial(material.privateKey, 'ssh-ed25519')
    expectImportError(
      () => importSshKey(RUST_SSH_KEY_CHACHA_FIXTURE, 'wrong-test-password'),
      'WrongPassword'
    )
  })

  it('does not mutate caller-owned key or password buffers', () => {
    const key = Buffer.from(utils.generateKeyPairSync('ed25519').private)
    const password = Buffer.from('unused-test-password')
    const originalKey = Buffer.from(key)
    const originalPassword = Buffer.from(password)

    try {
      importSshKey(key, password)
      expect(key.equals(originalKey)).toBe(true)
      expect(password.equals(originalPassword)).toBe(true)
    } finally {
      key.fill(0)
      password.fill(0)
      originalKey.fill(0)
      originalPassword.fill(0)
    }
  })

  it('rejects excessive bcrypt rounds before invoking the KDF', () => {
    const excessiveRounds = mutateOpenSsh(RUST_SSH_KEY_CHACHA_FIXTURE, (_binary, readString) => {
      readString() // cipher
      readString() // KDF
      const options = readString()
      const saltLength = options.readUInt32BE(0)
      options.writeUInt32BE(257, 4 + saltLength)
    })
    mockedPbkdf.mockClear()

    expectImportError(() => importSshKey(excessiveRounds, 'hunter42'), 'ParsingError')
    expect(mockedPbkdf).not.toHaveBeenCalled()
  })
})

describe('importSshKey PKCS#8', () => {
  it.each([
    ['Ed25519', () => generateKeyPairSync('ed25519').privateKey, 'ssh-ed25519'],
    ['RSA', () => generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey, 'ssh-rsa'],
    [
      'ECDSA P-256',
      () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey,
      'ecdsa-sha2-nistp256'
    ],
    [
      'ECDSA P-384',
      () => generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).privateKey,
      'ecdsa-sha2-nistp384'
    ],
    [
      'ECDSA P-521',
      () => generateKeyPairSync('ec', { namedCurve: 'secp521r1' }).privateKey,
      'ecdsa-sha2-nistp521'
    ]
  ])('imports unencrypted and encrypted %s keys', (_name, generate, keyType) => {
    const privateKey = generate()
    const unencrypted = importSshKey(exportPkcs8(privateKey))
    const encrypted = importSshKey(exportPkcs8(privateKey, true), PASSWORD)

    expect(unencrypted.publicKey).toBe(encrypted.publicKey)
    expect(unencrypted.fingerprint).toBe(encrypted.fingerprint)
    expectCanonicalMaterial(unencrypted.privateKey, keyType)
    expectCanonicalMaterial(encrypted.privateKey, keyType)
  })

  it('accepts 1Password-style single-line PKCS#8', () => {
    const privateKey = generateKeyPairSync('ed25519').privateKey
    const singleLine = exportPkcs8(privateKey).replaceAll('\n', '')

    expectCanonicalMaterial(importSshKey(singleLine).privateKey, 'ssh-ed25519')
  })

  it('classifies encrypted PKCS#8 password failures', () => {
    const privateKey = generateKeyPairSync('ed25519').privateKey
    const encrypted = exportPkcs8(privateKey, true)

    expectImportError(() => importSshKey(encrypted), 'PasswordRequired')
    expectImportError(() => importSshKey(encrypted, 'wrong-test-password'), 'WrongPassword')
  })
})

describe('importSshKey validation', () => {
  it('rejects missing PEM and malformed supported content as parsing errors', () => {
    expectImportError(() => importSshKey('not a private key'), 'ParsingError')
    expectImportError(
      () => importSshKey('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n'),
      'ParsingError'
    )
  })

  it('bounds clipboard input and decoded DER before cryptographic parsing', () => {
    const oversizedInput = Buffer.alloc(2 * 1024 * 1024 + 1, 0x41)
    try {
      expectImportError(() => importSshKey(oversizedInput), 'ParsingError')
    } finally {
      oversizedInput.fill(0)
    }

    const oversizedDer = Buffer.alloc(1024 * 1024 + 1)
    try {
      const pem = `-----BEGIN PRIVATE KEY-----\n${oversizedDer.toString('base64')}\n-----END PRIVATE KEY-----\n`
      expectImportError(() => importSshKey(pem), 'ParsingError')
    } finally {
      oversizedDer.fill(0)
    }
  })

  it('rejects unknown OpenSSH ciphers and mismatched outer public keys as parsing errors', () => {
    const unknownCipher = mutateOpenSsh(RUST_SSH_KEY_CHACHA_FIXTURE, (_binary, readString) => {
      readString().fill(0x78)
    })
    expectImportError(() => importSshKey(unknownCipher, 'hunter42'), 'ParsingError')

    const generated = utils.generateKeyPairSync('ed25519').private
    const mismatchedPublic = mutateOpenSsh(generated, (_binary, readString, readUint32) => {
      readString() // cipher
      readString() // KDF
      readString() // KDF options
      expect(readUint32()).toBe(1)
      const publicBlob = readString()
      publicBlob[publicBlob.length - 1] ^= 1
    })
    expectImportError(() => importSshKey(mismatchedPublic), 'ParsingError')
  })

  it('rejects unsupported PEM labels, PKCS#1, and SEC1', () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
    const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey

    expectImportError(
      () => importSshKey('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n'),
      'UnsupportedKeyType'
    )
    expectImportError(
      () => importSshKey(rsa.export({ format: 'pem', type: 'pkcs1' }) as string),
      'UnsupportedKeyType'
    )
    expectImportError(
      () => importSshKey(ec.export({ format: 'pem', type: 'sec1' }) as string),
      'UnsupportedKeyType'
    )
  })

  it('rejects DSA and PuTTY keys without exposing input or passwords', () => {
    const dsa = generateKeyPairSync('dsa', {
      modulusLength: 1024,
      divisorLength: 160
    }).privateKey
    expectImportError(() => importSshKey(exportPkcs8(dsa)), 'UnsupportedKeyType')

    const ppk = 'PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: test-fixture'
    try {
      importSshKey(ppk, 'do-not-leak-this-test-password')
      expect.fail('Expected ParsingError')
    } catch (error) {
      expect(error).toMatchObject({ code: 'ParsingError', message: 'ParsingError' })
      expect((error as Error).message).not.toContain('do-not-leak')
      expect((error as Error).message).not.toContain('PuTTY')
    }
  })

  it('emits a canonical public blob and standard unpadded Base64 fingerprint', () => {
    const material = importSshKey(utils.generateKeyPairSync('ed25519').private)
    const [type, encoded, comment] = material.publicKey.split(' ')
    const publicBlob = Buffer.from(encoded!, 'base64')

    try {
      expect(type).toBe('ssh-ed25519')
      expect(comment).toBeUndefined()
      const expected = createHash('sha256').update(publicBlob).digest('base64').replace(/=+$/u, '')
      expect(material.fingerprint).toBe(`SHA256:${expected}`)
      expect(material.fingerprint).not.toContain('=')
      expect(material.fingerprint).not.toMatch(/[-_]/u)

      const parsed = utils.parseKey(material.privateKey) as ParsedKey
      const privateKey = createPrivateKey(parsed.getPrivatePEM())
      const message = Buffer.from('canonical output test')
      const signature = sign(null, message, privateKey)
      expect(verify(null, message, privateKey, signature)).toBe(true)
      message.fill(0)
      signature.fill(0)
    } finally {
      publicBlob.fill(0)
    }
  })
})
