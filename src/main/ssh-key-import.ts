import { chacha20orig } from '@noble/ciphers/chacha.js'
import { poly1305 } from '@noble/ciphers/_poly1305.js'
import { createPrivateKey, timingSafeEqual, type KeyObject } from 'node:crypto'
import { utils, type ParsedKey } from 'ssh2'
import { pbkdf } from 'bcrypt-pbkdf'
import type { SshKeyMaterial } from '../shared/vault-contract'
import { formatSshKeyMaterial } from './ssh-key-format'

export type SshKeyImportErrorCode =
  'ParsingError' | 'UnsupportedKeyType' | 'PasswordRequired' | 'WrongPassword'

export class SshKeyImportError extends Error {
  readonly code: SshKeyImportErrorCode

  constructor(code: SshKeyImportErrorCode) {
    super(code)
    this.name = 'SshKeyImportError'
    this.code = code
  }
}

const OPENSSH_MAGIC = Buffer.from('openssh-key-v1\0', 'ascii')
const CHACHA_CIPHER = 'chacha20-poly1305@openssh.com'
const AUTH_TAG_LENGTH = 16
// OpenSSH defaults to 16 bcrypt rounds; 256 still accepts deliberately hardened keys while
// bounding synchronous work performed for untrusted clipboard input in Electron's main process.
const MAX_BCRYPT_ROUNDS = 256
const MAX_BCRYPT_SALT_BYTES = 1024
const MAX_DER_BYTES = 1024 * 1024
const MAX_INPUT_BYTES = 2 * 1024 * 1024
const ALLOWED_OPENSSH_CIPHERS = new Set([
  'none',
  'aes128-cbc',
  'aes192-cbc',
  'aes256-cbc',
  'aes128-ctr',
  'aes192-ctr',
  'aes256-ctr',
  'aes128-gcm@openssh.com',
  'aes256-gcm@openssh.com',
  CHACHA_CIPHER,
  '3des-cbc'
])
const SUPPORTED_KEY_TYPES = new Set([
  'ssh-ed25519',
  'ssh-rsa',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521'
])

interface PemEnvelope {
  label: string
  der: Buffer
}

interface OpenSshEnvelope {
  cipher: string
  encrypted: boolean
  publicBlob: Buffer
  privateBlob: Buffer
  authTag?: Buffer
  salt?: Buffer
  rounds?: number
}

class Reader {
  private offset = 0

  constructor(private readonly bytes: Buffer) {}

  read(length: number): Buffer {
    if (!Number.isSafeInteger(length) || length < 0 || this.offset + length > this.bytes.length) {
      throw importError('ParsingError')
    }
    const result = this.bytes.subarray(this.offset, this.offset + length)
    this.offset += length
    return result
  }

  readUint32(): number {
    return this.read(4).readUInt32BE(0)
  }

  readString(): Buffer {
    return this.read(this.readUint32())
  }

  remaining(): Buffer {
    return this.read(this.bytes.length - this.offset)
  }

  expectEnd(): void {
    if (this.offset !== this.bytes.length) throw importError('ParsingError')
  }
}

function importError(code: SshKeyImportErrorCode): SshKeyImportError {
  return new SshKeyImportError(code)
}

function isWhitespace(byte: number): boolean {
  return byte === 0x09 || byte === 0x0a || byte === 0x0d || byte === 0x20
}

function decodePem(input: Buffer, owned: Buffer[]): PemEnvelope {
  let start = 0
  let end = input.length
  while (start < end && isWhitespace(input[start]!)) start += 1
  while (end > start && isWhitespace(input[end - 1]!)) end -= 1

  const beginPrefix = Buffer.from('-----BEGIN ', 'ascii')
  const boundaryEnd = Buffer.from('-----', 'ascii')
  owned.push(beginPrefix, boundaryEnd)
  if (
    end - start <= beginPrefix.length ||
    !input.subarray(start, start + beginPrefix.length).equals(beginPrefix)
  ) {
    throw importError('ParsingError')
  }

  const labelStart = start + beginPrefix.length
  const labelEnd = input.indexOf(boundaryEnd, labelStart)
  if (labelEnd < 0 || labelEnd === labelStart) throw importError('ParsingError')
  const label = input.toString('ascii', labelStart, labelEnd)
  if (!/^[A-Z0-9](?:[A-Z0-9 ]*[A-Z0-9])?$/u.test(label)) throw importError('ParsingError')
  if (
    label !== 'OPENSSH PRIVATE KEY' &&
    label !== 'PRIVATE KEY' &&
    label !== 'ENCRYPTED PRIVATE KEY'
  ) {
    throw importError('UnsupportedKeyType')
  }

  const bodyStart = labelEnd + boundaryEnd.length
  const footer = Buffer.from(`-----END ${label}-----`, 'ascii')
  owned.push(footer)
  const footerStart = input.indexOf(footer, bodyStart)
  if (footerStart < 0) throw importError('ParsingError')
  for (let index = footerStart + footer.length; index < end; index += 1) {
    if (!isWhitespace(input[index]!)) throw importError('ParsingError')
  }

  const compact = Buffer.allocUnsafe(footerStart - bodyStart)
  owned.push(compact)
  let compactLength = 0
  for (let index = bodyStart; index < footerStart; index += 1) {
    const byte = input[index]!
    if (isWhitespace(byte)) continue
    const isBase64 =
      (byte >= 0x41 && byte <= 0x5a) ||
      (byte >= 0x61 && byte <= 0x7a) ||
      (byte >= 0x30 && byte <= 0x39) ||
      byte === 0x2b ||
      byte === 0x2f ||
      byte === 0x3d
    if (!isBase64) throw importError('ParsingError')
    compact[compactLength] = byte
    compactLength += 1
  }
  const encoded = compact.subarray(0, compactLength)
  if (encoded.length === 0 || encoded.length % 4 !== 0) throw importError('ParsingError')

  const firstPadding = encoded.indexOf(0x3d)
  if (
    firstPadding >= 0 &&
    (firstPadding < encoded.length - 2 ||
      encoded.subarray(firstPadding).some((byte) => byte !== 0x3d))
  ) {
    throw importError('ParsingError')
  }

  const encodedText = encoded.toString('ascii')
  const der = Buffer.from(encodedText, 'base64')
  owned.push(der)
  if (der.length === 0 || der.length > MAX_DER_BYTES || der.toString('base64') !== encodedText) {
    throw importError('ParsingError')
  }
  return { label, der }
}

function readAscii(value: Buffer): string {
  if (value.length === 0 || value.some((byte) => byte < 0x20 || byte > 0x7e)) {
    throw importError('ParsingError')
  }
  return value.toString('ascii')
}

function validatePublicBlob(publicBlob: Buffer): string {
  const reader = new Reader(publicBlob)
  const keyType = readAscii(reader.readString())
  if (!SUPPORTED_KEY_TYPES.has(keyType)) throw importError('UnsupportedKeyType')

  switch (keyType) {
    case 'ssh-ed25519':
      if (reader.readString().length !== 32) throw importError('ParsingError')
      break
    case 'ssh-rsa':
      if (reader.readString().length === 0 || reader.readString().length === 0) {
        throw importError('ParsingError')
      }
      break
    default: {
      const expectedCurve = keyType.slice('ecdsa-sha2-'.length)
      if (readAscii(reader.readString()) !== expectedCurve) throw importError('ParsingError')
      const point = reader.readString()
      const coordinateLength =
        keyType === 'ecdsa-sha2-nistp256' ? 32 : keyType === 'ecdsa-sha2-nistp384' ? 48 : 66
      if (point.length !== 1 + coordinateLength * 2 || point[0] !== 4) {
        throw importError('ParsingError')
      }
    }
  }
  reader.expectEnd()
  return keyType
}

function parseOpenSshEnvelope(der: Buffer): OpenSshEnvelope {
  const reader = new Reader(der)
  if (!reader.read(OPENSSH_MAGIC.length).equals(OPENSSH_MAGIC)) throw importError('ParsingError')
  const cipher = readAscii(reader.readString())
  if (!ALLOWED_OPENSSH_CIPHERS.has(cipher)) throw importError('ParsingError')
  const kdf = readAscii(reader.readString())
  const kdfOptions = reader.readString()
  const encrypted = cipher !== 'none'
  if (
    (!encrypted && (kdf !== 'none' || kdfOptions.length !== 0)) ||
    (encrypted && kdf !== 'bcrypt')
  ) {
    throw importError('ParsingError')
  }
  if (reader.readUint32() !== 1) throw importError('ParsingError')
  const publicBlob = reader.readString()
  validatePublicBlob(publicBlob)
  const privateBlob = reader.readString()
  if (privateBlob.length === 0) throw importError('ParsingError')
  const remainder = reader.remaining()

  const hasAuthTag =
    cipher === CHACHA_CIPHER ||
    cipher === 'aes128-gcm@openssh.com' ||
    cipher === 'aes256-gcm@openssh.com'
  if (
    (!hasAuthTag && remainder.length !== 0) ||
    (hasAuthTag && remainder.length !== AUTH_TAG_LENGTH)
  ) {
    throw importError('ParsingError')
  }

  const result: OpenSshEnvelope = {
    cipher,
    encrypted,
    publicBlob,
    privateBlob,
    authTag: hasAuthTag ? remainder : undefined
  }
  if (encrypted) {
    const optionsReader = new Reader(kdfOptions)
    result.salt = optionsReader.readString()
    result.rounds = optionsReader.readUint32()
    optionsReader.expectEnd()
    if (
      result.salt.length === 0 ||
      result.salt.length > MAX_BCRYPT_SALT_BYTES ||
      result.rounds === 0 ||
      result.rounds > MAX_BCRYPT_ROUNDS
    ) {
      throw importError('ParsingError')
    }
  }
  return result
}

function sshString(value: string | Buffer, owned: Buffer[]): Buffer {
  const bytes = typeof value === 'string' ? Buffer.from(value, 'ascii') : value
  if (typeof value === 'string') owned.push(bytes)
  const encoded = Buffer.allocUnsafe(4 + bytes.length)
  encoded.writeUInt32BE(bytes.length, 0)
  bytes.copy(encoded, 4)
  owned.push(encoded)
  return encoded
}

function wrapOpenSshBinary(binary: Buffer, owned: Buffer[]): Buffer {
  const encoded = Buffer.from(binary.toString('base64'), 'ascii')
  const header = Buffer.from('-----BEGIN OPENSSH PRIVATE KEY-----\n', 'ascii')
  const footer = Buffer.from('\n-----END OPENSSH PRIVATE KEY-----\n', 'ascii')
  const pem = Buffer.concat([header, encoded, footer])
  owned.push(encoded, header, footer, pem)
  return pem
}

function makeUnencryptedOpenSsh(publicBlob: Buffer, privateBlob: Buffer, owned: Buffer[]): Buffer {
  const parts = [
    Buffer.from(OPENSSH_MAGIC),
    sshString('none', owned),
    sshString('none', owned),
    sshString('', owned),
    Buffer.from([0, 0, 0, 1]),
    sshString(publicBlob, owned),
    sshString(privateBlob, owned)
  ]
  owned.push(...parts)
  const binary = Buffer.concat(parts)
  owned.push(binary)
  return wrapOpenSshBinary(binary, owned)
}

function deriveBcrypt(
  password: Buffer,
  salt: Buffer,
  rounds: number,
  length: number,
  owned: Buffer[]
): Buffer {
  const output = Buffer.alloc(length)
  owned.push(output)
  if (pbkdf(password, password.length, salt, salt.length, output, output.length, rounds) !== 0) {
    throw importError('WrongPassword')
  }
  return output
}

function decryptChacha(
  envelope: OpenSshEnvelope,
  password: Buffer,
  outputLength: 40 | 64,
  owned: Buffer[]
): Buffer | undefined {
  const derived = deriveBcrypt(password, envelope.salt!, envelope.rounds!, outputLength, owned)
  const key = derived.subarray(0, 32)
  const nonce = Buffer.alloc(8)
  const zeroBlock = Buffer.alloc(64)
  const keyStream = Buffer.alloc(64)
  owned.push(nonce, zeroBlock, keyStream)
  chacha20orig(key, nonce, zeroBlock, keyStream)
  const poly1305Key = keyStream.subarray(0, 32)
  const actualTagBytes = poly1305(envelope.privateBlob, poly1305Key)
  const actualTag = Buffer.from(
    actualTagBytes.buffer,
    actualTagBytes.byteOffset,
    actualTagBytes.byteLength
  )
  owned.push(actualTag)
  if (!timingSafeEqual(actualTag, envelope.authTag!)) return undefined

  const plaintext = Buffer.alloc(envelope.privateBlob.length)
  owned.push(plaintext)
  chacha20orig(key, nonce, envelope.privateBlob, plaintext, 1)
  return plaintext
}

function parseOpenSshKey(
  pem: Buffer,
  envelope: OpenSshEnvelope,
  password: Buffer | undefined,
  owned: Buffer[]
): ParsedKey {
  let parsed: ParsedKey | Error
  if (envelope.cipher === CHACHA_CIPHER) {
    let plaintext = decryptChacha(envelope, password!, 40, owned)
    if (plaintext === undefined) plaintext = decryptChacha(envelope, password!, 64, owned)
    if (plaintext === undefined) throw importError('WrongPassword')
    parsed = utils.parseKey(makeUnencryptedOpenSsh(envelope.publicBlob, plaintext, owned))
  } else {
    parsed = utils.parseKey(pem, envelope.encrypted ? password : undefined)
  }

  if (parsed instanceof Error || !parsed.isPrivateKey()) {
    throw importError(envelope.encrypted ? 'WrongPassword' : 'ParsingError')
  }
  if (!SUPPORTED_KEY_TYPES.has(parsed.type)) throw importError('UnsupportedKeyType')
  return parsed
}

function assertSupportedPrivateKey(privateKey: KeyObject): void {
  switch (privateKey.asymmetricKeyType) {
    case 'ed25519':
    case 'rsa':
      return
    case 'ec': {
      const curve = privateKey.asymmetricKeyDetails?.namedCurve
      if (curve === 'prime256v1' || curve === 'secp384r1' || curve === 'secp521r1') return
      break
    }
  }
  throw importError('UnsupportedKeyType')
}

function importOpenSsh(
  pem: Buffer,
  der: Buffer,
  password: Buffer | undefined,
  owned: Buffer[]
): SshKeyMaterial {
  const envelope = parseOpenSshEnvelope(der)
  if (envelope.encrypted && password === undefined) throw importError('PasswordRequired')
  const parsed = parseOpenSshKey(pem, envelope, password, owned)
  const privatePem = Buffer.from(parsed.getPrivatePEM(), 'ascii')
  const parsedPublic = Buffer.from(parsed.getPublicSSH())
  owned.push(privatePem, parsedPublic)

  let privateKey: KeyObject
  try {
    privateKey = createPrivateKey(privatePem)
  } catch {
    throw importError('ParsingError')
  }
  assertSupportedPrivateKey(privateKey)
  const material = formatSshKeyMaterial(privateKey)
  const [, encodedPublic] = material.publicKey.split(' ')
  const canonicalPublic = Buffer.from(encodedPublic!, 'base64')
  owned.push(canonicalPublic)
  if (!canonicalPublic.equals(envelope.publicBlob) || !canonicalPublic.equals(parsedPublic)) {
    throw importError('ParsingError')
  }
  return material
}

function readDerLength(bytes: Buffer, offset: number): { length: number; offset: number } {
  if (offset >= bytes.length) throw importError('ParsingError')
  const first = bytes[offset]!
  if (first < 0x80) return { length: first, offset: offset + 1 }
  const lengthBytes = first & 0x7f
  if (lengthBytes === 0 || lengthBytes > 4 || offset + 1 + lengthBytes > bytes.length) {
    throw importError('ParsingError')
  }
  let length = 0
  for (let index = 0; index < lengthBytes; index += 1) {
    length = length * 256 + bytes[offset + 1 + index]!
  }
  if (length < 0x80) throw importError('ParsingError')
  return { length, offset: offset + 1 + lengthBytes }
}

function readDerElement(
  bytes: Buffer,
  offset: number,
  expectedTag: number
): { start: number; end: number } {
  if (bytes[offset] !== expectedTag) throw importError('ParsingError')
  const decoded = readDerLength(bytes, offset + 1)
  const end = decoded.offset + decoded.length
  if (end > bytes.length) throw importError('ParsingError')
  return { start: decoded.offset, end }
}

function validateEncryptedPkcs8(der: Buffer): void {
  const outer = readDerElement(der, 0, 0x30)
  if (outer.end !== der.length) throw importError('ParsingError')
  const algorithm = readDerElement(der, outer.start, 0x30)
  if (algorithm.start === algorithm.end) throw importError('ParsingError')
  const encrypted = readDerElement(der, algorithm.end, 0x04)
  if (encrypted.start === encrypted.end || encrypted.end !== outer.end)
    throw importError('ParsingError')
}

function isWrongPkcs8Password(error: unknown): boolean {
  if (!(error instanceof Error)) return false
  const opensslError = error as Error & { code?: string; reason?: string }
  return (
    opensslError.code === 'ERR_OSSL_BAD_DECRYPT' ||
    opensslError.reason === 'bad decrypt' ||
    opensslError.message.toLowerCase().includes('bad decrypt')
  )
}

function importPkcs8(
  der: Buffer,
  encrypted: boolean,
  password: Buffer | undefined
): SshKeyMaterial {
  if (encrypted && password === undefined) throw importError('PasswordRequired')
  if (encrypted) validateEncryptedPkcs8(der)

  let privateKey: KeyObject
  try {
    privateKey = createPrivateKey({
      key: der,
      format: 'der',
      type: 'pkcs8',
      passphrase: encrypted ? password : undefined
    })
  } catch (error) {
    throw importError(encrypted && isWrongPkcs8Password(error) ? 'WrongPassword' : 'ParsingError')
  }
  assertSupportedPrivateKey(privateKey)
  return formatSshKeyMaterial(privateKey)
}

/** Import a supported OpenSSH or PKCS#8 private key into canonical SSH material. */
export function importSshKey(
  encodedKey: string | Buffer,
  password?: string | Buffer
): SshKeyMaterial {
  const owned: Buffer[] = []

  try {
    const inputLength = Buffer.isBuffer(encodedKey)
      ? encodedKey.length
      : Buffer.byteLength(encodedKey, 'utf8')
    if (inputLength > MAX_INPUT_BYTES) throw importError('ParsingError')
    const input = Buffer.isBuffer(encodedKey)
      ? Buffer.from(encodedKey)
      : Buffer.from(encodedKey, 'utf8')
    const passwordBytes =
      password === undefined
        ? undefined
        : Buffer.isBuffer(password)
          ? Buffer.from(password)
          : Buffer.from(password, 'utf8')
    owned.push(input)
    if (passwordBytes !== undefined) owned.push(passwordBytes)

    const pem = decodePem(input, owned)
    switch (pem.label) {
      case 'OPENSSH PRIVATE KEY':
        return importOpenSsh(input, pem.der, passwordBytes, owned)
      case 'PRIVATE KEY':
        return importPkcs8(pem.der, false, passwordBytes)
      case 'ENCRYPTED PRIVATE KEY':
        return importPkcs8(pem.der, true, passwordBytes)
      default:
        throw importError('UnsupportedKeyType')
    }
  } catch (error) {
    if (error instanceof SshKeyImportError) throw error
    throw importError('ParsingError')
  } finally {
    for (const buffer of owned) buffer.fill(0)
  }
}
