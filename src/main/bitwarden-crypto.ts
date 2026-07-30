import {
  constants,
  argon2,
  createHash,
  createDecipheriv,
  createHmac,
  createPrivateKey,
  createPublicKey,
  createCipheriv,
  pbkdf2,
  privateDecrypt,
  randomBytes,
  timingSafeEqual,
  verify,
  webcrypto,
  type KeyObject
} from 'node:crypto'
import { promisify } from 'node:util'
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { Decoder, Encoder } from 'cbor-x'

const pbkdf2Async = promisify(pbkdf2)
const argon2Async = promisify(argon2)

const KEY_BYTES = 32
const COMBINED_KEY_BYTES = 64
const IV_BYTES = 16
const MAC_BYTES = 32
const MAX_INPUT_BYTES = 1024 * 1024
const MAX_CIPHERTEXT_BYTES = 64 * 1024 * 1024
const MAX_ATTACHMENT_CIPHERTEXT_BYTES = 128 * 1024 * 1024
const MIN_PBKDF2_ITERATIONS = 5_000
const MIN_ARGON2_MEMORY_MIB = 16
const MIN_ARGON2_ITERATIONS = 2
const MAX_PBKDF2_ITERATIONS = 10_000_000
// Treat server-provided KDF settings as untrusted input. This follows the
// compatibility ceiling used by current desktop clients without allowing a
// self-hosted endpoint to request multi-gigabyte allocations beyond 1 GiB.
const MAX_ARGON2_MEMORY_MIB = 1_024
const MAX_ARGON2_ITERATIONS = 100
const MAX_ARGON2_PARALLELISM = 64
const XCHACHA_KEY_BYTES = 32
const XCHACHA_KEY_ID_BYTES = 16
const XCHACHA_NONCE_BYTES = 24
const XCHACHA_TAG_BYTES = 16
const XCHACHA20_POLY1305_ALGORITHM = -70_000
const COSE_KEY_TYPE_SYMMETRIC = 4
const COSE_CONTENT_TYPE_OCTET_STREAM = 42
const COSE_CONTENT_TYPE_COSE_KEY = 101
const COSE_CONTENT_TYPE_PKCS8 = 284
const COSE_CONTENT_TYPE_UTF8 = 'application/x.bitwarden.utf8-padded'
const COSE_CONTENT_TYPE_LEGACY_KEY = 'application/x.bitwarden.legacy-key'
const COSE_KEY_OPERATIONS = [3, 4, 5, 6] as const
const TEXT_PADDING_BLOCK_BYTES = 32
const COSE_KEY_TYPE_OKP = 1
const COSE_KEY_TYPE_AKP = 7
const COSE_ALGORITHM_EDDSA = -8
const COSE_ALGORITHM_ML_DSA_44 = -48
const COSE_CONTENT_TYPE_CBOR = 60
const COSE_SIGNING_NAMESPACE = -80_000
const ED25519_CURVE = 6
const ED25519_SEED_BYTES = 32
const ED25519_SIGNATURE_BYTES = 64
const ML_DSA_44_PUBLIC_KEY_BYTES = 1_312
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const AES_256_GCM_ALGORITHM = 3
const AES_GCM_NONCE_BYTES = 12
const DATA_ENVELOPE_PADDING_BYTES = 64
const COSE_CONTENT_TYPE_PADDED_CBOR = 'application/x.bitwarden.cbor-padded'
const COSE_SAFE_OBJECT_NAMESPACE = -80_002
const COSE_SAFE_CONTENT_NAMESPACE = -80_001
const DATA_ENVELOPE_OBJECT_NAMESPACE = 2
const VAULT_ITEM_CONTENT_NAMESPACE = 1
const SEND_SEED_BYTES = 16
const SEND_KDF_ITERATIONS = 100_000

const cborEncoder = new Encoder({
  mapsAsObjects: false,
  tagUint8Array: false,
  useRecords: false
})
const cborDecoder = new Decoder({ mapsAsObjects: false, useRecords: false })

export interface BitwardenXChaCha20Poly1305Key {
  algorithm: 'xchacha20-poly1305'
  keyId: Buffer
  encryptionKey: Buffer
}

export type BitwardenSymmetricKey = Buffer | BitwardenXChaCha20Poly1305Key

export type BitwardenCoseContentType = 'octet-stream' | 'utf8' | 'legacy-key' | 'cose-key' | 'pkcs8'

export interface BitwardenV2AccountState {
  wrappedPrivateKey?: string | null
  wrappedSigningKey: string
  securityState: string
  signedPublicKey?: string | null
  publicKey?: string | null
}

export type BitwardenCipherBlobValue =
  | null
  | boolean
  | number
  | string
  | BitwardenCipherBlobValue[]
  | { [key: string]: BitwardenCipherBlobValue }

export type BitwardenKdf =
  | { type: 'pbkdf2'; iterations: number }
  | { type: 'argon2id'; iterations: number; memoryMiB: number; parallelism: number }

export class BitwardenCryptoError extends Error {
  constructor(
    readonly code:
      | 'INVALID_INPUT'
      | 'INVALID_KEY'
      | 'INVALID_CIPHERSTRING'
      | 'AUTHENTICATION_FAILED'
      | 'UNSUPPORTED_CIPHER_TYPE'
      | 'ARGON2_UNAVAILABLE'
      | 'DECRYPTION_FAILED',
    message: string = code
  ) {
    super(message)
    this.name = 'BitwardenCryptoError'
  }
}

interface ParsedCipherString {
  type: 1 | 2 | 3 | 4 | 7
  iv?: Buffer
  ciphertext: Buffer
  mac?: Buffer
}

function invalidInput(message: string): never {
  throw new BitwardenCryptoError('INVALID_INPUT', message)
}

function requireString(value: unknown, name: string, allowEmpty = false): string {
  if (typeof value !== 'string' || (!allowEmpty && value.length === 0)) {
    invalidInput(`${name} must be a ${allowEmpty ? '' : 'non-empty '}string`)
  }
  if (Buffer.byteLength(value, 'utf8') > MAX_INPUT_BYTES) {
    invalidInput(`${name} exceeds the maximum supported size`)
  }
  return value
}

function requirePositiveInteger(value: unknown, name: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum) {
    invalidInput(`${name} must be a positive integer no greater than ${maximum}`)
  }
  return value as number
}

function requireBuffer(value: unknown, name: string, length?: number): Buffer {
  if (!Buffer.isBuffer(value) || (length !== undefined && value.length !== length)) {
    throw new BitwardenCryptoError('INVALID_KEY', `${name} has an invalid length`)
  }
  return value
}

function decodeBase64(value: string, name: string, expectedLength?: number): Buffer {
  if (
    value.length === 0 ||
    value.length > Math.ceil((MAX_CIPHERTEXT_BYTES * 4) / 3) + 4 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', `${name} is not canonical base64`)
  }

  const decoded = Buffer.from(value, 'base64')
  if (decoded.toString('base64') !== value || decoded.length > MAX_CIPHERTEXT_BYTES) {
    decoded.fill(0)
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', `${name} is not canonical base64`)
  }
  if (expectedLength !== undefined && decoded.length !== expectedLength) {
    decoded.fill(0)
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', `${name} has an invalid length`)
  }
  return decoded
}

function parseCipherString(value: string): ParsedCipherString {
  if (typeof value !== 'string' || value.length === 0) {
    throw new BitwardenCryptoError(
      'INVALID_CIPHERSTRING',
      'cipher string must be a non-empty string'
    )
  }
  if (value.length > Math.ceil((MAX_CIPHERTEXT_BYTES * 4) / 3) + 256) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'cipher string exceeds the maximum size')
  }

  const separator = value.indexOf('.')
  if (separator !== 1 || !/^[12347]$/.test(value[0] ?? '')) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'cipher string type is invalid')
  }
  const type = Number(value[0]) as ParsedCipherString['type']
  const parts = value.slice(2).split('|')

  if (type === 7) {
    if (parts.length !== 1) {
      throw new BitwardenCryptoError(
        'INVALID_CIPHERSTRING',
        'COSE cipher string has invalid fields'
      )
    }
    return { type, ciphertext: decodeBase64(parts[0]!, 'COSE_Encrypt0') }
  }

  if (type === 3 || type === 4) {
    if (parts.length !== 1) {
      throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'RSA cipher string has invalid fields')
    }
    return { type, ciphertext: decodeBase64(parts[0]!, 'RSA ciphertext') }
  }

  if (parts.length !== 3) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'AES cipher string has invalid fields')
  }
  const iv = decodeBase64(parts[0]!, 'IV', IV_BYTES)
  const ciphertext = decodeBase64(parts[1]!, 'ciphertext')
  const mac = decodeBase64(parts[2]!, 'MAC', MAC_BYTES)
  if (ciphertext.length === 0 || ciphertext.length % IV_BYTES !== 0) {
    iv.fill(0)
    ciphertext.fill(0)
    mac.fill(0)
    throw new BitwardenCryptoError(
      'INVALID_CIPHERSTRING',
      'ciphertext has an invalid AES-CBC length'
    )
  }
  return { type, iv, ciphertext, mac }
}

function isLegacyMasterKeyWrappedUserKey(value: string): boolean {
  if (typeof value !== 'string' || value.length === 0) return false
  if (value.startsWith('0.')) return true
  return !value.includes('.') && value.split('|').length === 2
}

function parseLegacyMasterKeyWrappedUserKey(value: string): {
  iv: Buffer
  ciphertext: Buffer
} {
  if (!isLegacyMasterKeyWrappedUserKey(value)) {
    throw new BitwardenCryptoError(
      'INVALID_CIPHERSTRING',
      'legacy master-key user-key envelope must use type 0'
    )
  }
  if (value.length > Math.ceil((MAX_CIPHERTEXT_BYTES * 4) / 3) + 256) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'cipher string exceeds the maximum size')
  }
  const serialized = value.startsWith('0.') ? value.slice(2) : value
  const parts = serialized.split('|')
  if (parts.length !== 2) {
    throw new BitwardenCryptoError(
      'INVALID_CIPHERSTRING',
      'legacy master-key user-key envelope has invalid fields'
    )
  }
  let iv: Buffer | undefined
  let ciphertext: Buffer | undefined
  try {
    iv = decodeBase64(parts[0]!, 'IV', IV_BYTES)
    ciphertext = decodeBase64(parts[1]!, 'ciphertext')
    if (ciphertext.length === 0 || ciphertext.length % IV_BYTES !== 0) {
      throw new BitwardenCryptoError(
        'INVALID_CIPHERSTRING',
        'ciphertext has an invalid AES-CBC length'
      )
    }
    return { iv, ciphertext }
  } catch (error) {
    iv?.fill(0)
    ciphertext?.fill(0)
    throw error
  }
}

function hmacSha256(key: Buffer, ...parts: Buffer[]): Buffer {
  const hmac = createHmac('sha256', key)
  for (const part of parts) hmac.update(part)
  return hmac.digest()
}

function hkdfExpandSha256(prk: Buffer, info: string, outputLength: number): Buffer {
  if (outputLength < 1 || outputLength > 255 * MAC_BYTES) {
    invalidInput('HKDF output length is invalid')
  }
  const infoBytes = Buffer.from(info, 'utf8')
  const blocks: Buffer[] = []
  let previous: Buffer<ArrayBufferLike> = Buffer.alloc(0)
  try {
    for (let counter = 1; Buffer.concat(blocks).length < outputLength; counter += 1) {
      previous = hmacSha256(prk, previous, infoBytes, Buffer.from([counter]))
      blocks.push(previous)
    }
    const result = Buffer.concat(blocks, outputLength)
    return result
  } finally {
    previous.fill(0)
    infoBytes.fill(0)
    for (const block of blocks) block.fill(0)
  }
}

/** Bitwarden's purpose-bound HKDF: HKDF-Extract(salt, material), then Expand(purpose). */
export function deriveBitwardenPurposeKey(
  material: Buffer,
  salt: string,
  purpose: string,
  outputBytes = COMBINED_KEY_BYTES
): Buffer {
  requireBuffer(material, 'HKDF material')
  requireString(salt, 'HKDF salt', true)
  requireString(purpose, 'HKDF purpose', true)
  const saltBytes = Buffer.from(salt, 'utf8')
  const prk = createHmac('sha256', saltBytes).update(material).digest()
  try {
    return hkdfExpandSha256(prk, purpose, outputBytes)
  } finally {
    saltBytes.fill(0)
    prk.fill(0)
  }
}

/** Derives the 64-byte Send content key from the 128-bit URL-fragment seed. */
export function deriveBitwardenSendKey(seed: Buffer): Buffer {
  requireBuffer(seed, 'Send seed', SEND_SEED_BYTES)
  return deriveBitwardenPurposeKey(seed, 'bitwarden-send', 'send')
}

/** Derives the public password proof used by Bitwarden Send owner requests. */
export function deriveBitwardenSendPasswordHash(password: string, seed: Buffer): Promise<Buffer> {
  requireString(password, 'Send password')
  requireBuffer(seed, 'Send seed', SEND_SEED_BYTES)
  return derivePbkdf2Sha256(password, seed, SEND_KDF_ITERATIONS)
}

/**
 * Derives the 32-byte Bitwarden master key. Returned Buffers are caller-owned:
 * clear them with `buffer.fill(0)` as soon as they are no longer needed.
 */
export async function deriveMasterKey(
  password: string,
  emailOrSalt: string,
  kdf: BitwardenKdf
): Promise<Buffer> {
  requireString(password, 'password', true)
  const salt = requireString(emailOrSalt, 'email or salt')
  if (!kdf || typeof kdf !== 'object') invalidInput('KDF must be an object')

  if (kdf.type === 'pbkdf2') {
    const iterations = requirePositiveInteger(
      kdf.iterations,
      'PBKDF2 iterations',
      MAX_PBKDF2_ITERATIONS
    )
    if (iterations < MIN_PBKDF2_ITERATIONS) {
      invalidInput(`PBKDF2 iterations must be at least ${MIN_PBKDF2_ITERATIONS}`)
    }
    return derivePbkdf2Sha256(password, salt, iterations)
  }
  if (kdf.type !== 'argon2id') invalidInput('unsupported KDF type')

  const iterations = requirePositiveInteger(
    kdf.iterations,
    'Argon2id iterations',
    MAX_ARGON2_ITERATIONS
  )
  const memoryMiB = requirePositiveInteger(
    kdf.memoryMiB,
    'Argon2id memoryMiB',
    MAX_ARGON2_MEMORY_MIB
  )
  const parallelism = requirePositiveInteger(
    kdf.parallelism,
    'Argon2id parallelism',
    MAX_ARGON2_PARALLELISM
  )
  if (
    iterations < MIN_ARGON2_ITERATIONS ||
    memoryMiB < MIN_ARGON2_MEMORY_MIB ||
    memoryMiB * 1024 < parallelism * 8
  ) {
    invalidInput('Argon2id parameters are below Bitwarden minimums')
  }

  const saltHash = createHash('sha256').update(salt, 'utf8').digest()
  const passwordBytes = Buffer.from(password, 'utf8')
  try {
    return Buffer.from(
      await argon2Async('argon2id', {
        message: passwordBytes,
        nonce: saltHash,
        parallelism,
        memory: memoryMiB * 1024,
        passes: iterations,
        tagLength: KEY_BYTES
      })
    )
  } finally {
    saltHash.fill(0)
    passwordBytes.fill(0)
  }
}

/** PBKDF2-HMAC-SHA256 primitive with a caller-specified output length. */
export async function derivePbkdf2Sha256(
  password: string | Buffer,
  salt: string | Buffer,
  iterations: number,
  outputBytes = KEY_BYTES
): Promise<Buffer> {
  if (!(typeof password === 'string' || Buffer.isBuffer(password)))
    invalidInput('password must be a string or Buffer')
  if (!(typeof salt === 'string' || Buffer.isBuffer(salt)))
    invalidInput('salt must be a string or Buffer')
  const rounds = requirePositiveInteger(iterations, 'PBKDF2 iterations', MAX_PBKDF2_ITERATIONS)
  const length = requirePositiveInteger(outputBytes, 'PBKDF2 outputBytes', MAX_INPUT_BYTES)
  return Buffer.from(await pbkdf2Async(password, salt, rounds, length, 'sha256'))
}

/** Derives Bitwarden's 32-byte password key: PBKDF2(masterKey, password, 1). */
export function derivePasswordKey(masterKey: Buffer, password: string): Promise<Buffer> {
  requireBuffer(masterKey, 'master key', KEY_BYTES)
  requireString(password, 'password', true)
  return derivePbkdf2Sha256(masterKey, password, 1)
}

/**
 * Expands (without HKDF-Extract) a 32-byte master key into Bitwarden's AES and MAC keys.
 * All returned Buffers are independently allocated and caller-owned.
 */
export function stretchMasterKey(masterKey: Buffer): {
  encKey: Buffer
  macKey: Buffer
  combinedKey: Buffer
} {
  requireBuffer(masterKey, 'master key', KEY_BYTES)
  const encKey = hkdfExpandSha256(masterKey, 'enc', KEY_BYTES)
  const macKey = hkdfExpandSha256(masterKey, 'mac', KEY_BYTES)
  return { encKey, macKey, combinedKey: Buffer.concat([encKey, macKey]) }
}

function isXChaChaKey(key: BitwardenSymmetricKey): key is BitwardenXChaCha20Poly1305Key {
  return !Buffer.isBuffer(key) && key.algorithm === 'xchacha20-poly1305'
}

function asBuffer(value: unknown, length: number, name: string): Buffer {
  if (!(value instanceof Uint8Array) || value.byteLength !== length) {
    throw new BitwardenCryptoError('INVALID_KEY', `${name} has an invalid length`)
  }
  return Buffer.from(value)
}

function cborArgument(
  source: Buffer,
  offset: number,
  additional: number,
  name: string
): { value: number; offset: number } {
  if (additional < 24) return { value: additional, offset }
  const sizes = new Map([
    [24, 1],
    [25, 2],
    [26, 4],
    [27, 8]
  ])
  const size = sizes.get(additional)
  if (!size || offset + size > source.length) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', `${name} has invalid CBOR lengths`)
  }
  let value: number
  if (size === 8) {
    const wide = source.readBigUInt64BE(offset)
    if (wide > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new BitwardenCryptoError('INVALID_CIPHERSTRING', `${name} has an oversized CBOR value`)
    }
    value = Number(wide)
  } else {
    value = source.readUIntBE(offset, size)
  }
  const minimum = size === 1 ? 24 : size === 2 ? 256 : size === 4 ? 65_536 : 4_294_967_296
  if (value < minimum) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', `${name} uses non-minimal CBOR`)
  }
  return { value, offset: offset + size }
}

function scanCborItem(
  source: Buffer,
  start: number,
  depth: number,
  state: { nodes: number },
  name: string
): number {
  if (depth > 32 || start >= source.length || ++state.nodes > 200_000) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', `${name} exceeds CBOR limits`)
  }
  const initial = source[start]!
  const major = initial >>> 5
  const additional = initial & 31
  if (additional >= 28) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', `${name} uses unsupported CBOR`)
  }
  const argument = cborArgument(source, start + 1, additional, name)
  let offset = argument.offset

  if (major === 0 || major === 1) return offset
  if (major === 2 || major === 3) {
    offset += argument.value
    if (offset > source.length) {
      throw new BitwardenCryptoError('INVALID_CIPHERSTRING', `${name} has truncated CBOR`)
    }
    return offset
  }
  if (major === 4) {
    for (let index = 0; index < argument.value; index += 1) {
      offset = scanCborItem(source, offset, depth + 1, state, name)
    }
    return offset
  }
  if (major === 5) {
    const keys = new Set<string>()
    for (let index = 0; index < argument.value; index += 1) {
      const keyStart = offset
      offset = scanCborItem(source, offset, depth + 1, state, name)
      const key = source.subarray(keyStart, offset).toString('hex')
      if (keys.has(key)) {
        throw new BitwardenCryptoError('INVALID_CIPHERSTRING', `${name} has duplicate CBOR keys`)
      }
      keys.add(key)
      offset = scanCborItem(source, offset, depth + 1, state, name)
    }
    return offset
  }
  if (major === 7 && additional >= 20 && additional <= 22) return offset
  throw new BitwardenCryptoError('INVALID_CIPHERSTRING', `${name} uses unsupported CBOR types`)
}

function assertStrictCbor(value: Uint8Array, name: string): void {
  const source = Buffer.from(value.buffer, value.byteOffset, value.byteLength)
  const offset = scanCborItem(source, 0, 0, { nodes: 0 }, name)
  if (offset !== source.length) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', `${name} has trailing CBOR data`)
  }
}

function decodeCbor(value: Uint8Array, name: string): unknown {
  try {
    assertStrictCbor(value, name)
    return cborDecoder.decode(value)
  } catch (error) {
    if (error instanceof BitwardenCryptoError) throw error
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', `${name} is not valid CBOR`)
  }
}

function requireMap(value: unknown, name: string): Map<unknown, unknown> {
  if (!(value instanceof Map)) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', `${name} must be a CBOR map`)
  }
  return value
}

function unpadKey(value: Buffer): Buffer {
  const padding = value.at(-1) ?? 0
  if (padding < 1 || padding > value.length || value.length - padding < 65) {
    throw new BitwardenCryptoError('INVALID_KEY', 'V2 user key padding is invalid')
  }
  for (let index = value.length - padding; index < value.length; index += 1) {
    if (value[index] !== padding) {
      throw new BitwardenCryptoError('INVALID_KEY', 'V2 user key padding is invalid')
    }
  }
  return value.subarray(0, value.length - padding)
}

function padToMinimum(value: Buffer, minimum: number): Buffer {
  const padding = Math.max(1, minimum - value.length)
  if (padding > 255) {
    throw new BitwardenCryptoError('INVALID_INPUT', 'padding exceeds the supported size')
  }
  return Buffer.concat([value, Buffer.alloc(padding, padding)])
}

function unpadStrict(value: Buffer, name: string): Buffer {
  const padding = value.at(-1) ?? 0
  if (padding < 1 || padding > value.length) {
    throw new BitwardenCryptoError('DECRYPTION_FAILED', `${name} padding is invalid`)
  }
  for (let index = value.length - padding; index < value.length; index += 1) {
    if (value[index] !== padding) {
      throw new BitwardenCryptoError('DECRYPTION_FAILED', `${name} padding is invalid`)
    }
  }
  return value.subarray(0, value.length - padding)
}

/** Parses the decrypted user-key bytes returned by the Bitwarden master-key envelope. */
export function decodeBitwardenUserKey(value: Buffer): BitwardenSymmetricKey {
  requireBuffer(value, 'decrypted user key')
  if (value.length === COMBINED_KEY_BYTES) return Buffer.from(value)
  if (value.length < 66 || value.length > 4_096) {
    throw new BitwardenCryptoError('INVALID_KEY', 'decrypted user key has an unsupported length')
  }

  const encoded = unpadKey(value)
  const coseKey = requireMap(decodeCbor(encoded, 'V2 user key'), 'V2 user key')
  if (coseKey.size !== 5 || coseKey.get(1) !== COSE_KEY_TYPE_SYMMETRIC) {
    throw new BitwardenCryptoError('INVALID_KEY', 'V2 user key has an unsupported key type')
  }
  if (coseKey.get(3) !== XCHACHA20_POLY1305_ALGORITHM) {
    throw new BitwardenCryptoError('INVALID_KEY', 'V2 user key has an unsupported algorithm')
  }
  const operations = coseKey.get(4)
  if (
    !Array.isArray(operations) ||
    operations.length !== COSE_KEY_OPERATIONS.length ||
    !COSE_KEY_OPERATIONS.every((operation) => operations.includes(operation))
  ) {
    throw new BitwardenCryptoError('INVALID_KEY', 'V2 user key has invalid operations')
  }
  return {
    algorithm: 'xchacha20-poly1305',
    keyId: asBuffer(coseKey.get(2), XCHACHA_KEY_ID_BYTES, 'V2 user key id'),
    encryptionKey: asBuffer(coseKey.get(-1), XCHACHA_KEY_BYTES, 'V2 user encryption key')
  }
}

export function clearBitwardenSymmetricKey(key: BitwardenSymmetricKey | null): void {
  if (!key) return
  if (Buffer.isBuffer(key)) {
    key.fill(0)
    return
  }
  key.keyId.fill(0)
  key.encryptionKey.fill(0)
}

function coseContentType(value: BitwardenCoseContentType): string | number {
  switch (value) {
    case 'octet-stream':
      return COSE_CONTENT_TYPE_OCTET_STREAM
    case 'cose-key':
      return COSE_CONTENT_TYPE_COSE_KEY
    case 'pkcs8':
      return COSE_CONTENT_TYPE_PKCS8
    case 'utf8':
      return COSE_CONTENT_TYPE_UTF8
    case 'legacy-key':
      return COSE_CONTENT_TYPE_LEGACY_KEY
  }
}

function parseCoseContentType(value: unknown): BitwardenCoseContentType {
  if (value === COSE_CONTENT_TYPE_OCTET_STREAM) return 'octet-stream'
  if (value === COSE_CONTENT_TYPE_COSE_KEY) return 'cose-key'
  if (value === COSE_CONTENT_TYPE_PKCS8) return 'pkcs8'
  if (value === COSE_CONTENT_TYPE_UTF8) return 'utf8'
  if (value === COSE_CONTENT_TYPE_LEGACY_KEY) return 'legacy-key'
  throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'COSE content type is unsupported')
}

function padUtf8(value: Buffer): Buffer {
  const minimum =
    TEXT_PADDING_BLOCK_BYTES * (1 + Math.floor(value.length / TEXT_PADDING_BLOCK_BYTES))
  const padding = Math.max(1, minimum - value.length)
  if (padding > 255) throw new BitwardenCryptoError('INVALID_INPUT', 'UTF-8 padding is invalid')
  return Buffer.concat([value, Buffer.alloc(padding, padding)])
}

function unpadUtf8(value: Buffer): Buffer {
  const padding = value.at(-1) ?? 0
  if (padding < 1 || padding > value.length) {
    throw new BitwardenCryptoError('DECRYPTION_FAILED', 'UTF-8 padding is invalid')
  }
  for (let index = value.length - padding; index < value.length; index += 1) {
    if (value[index] !== padding) {
      throw new BitwardenCryptoError('DECRYPTION_FAILED', 'UTF-8 padding is invalid')
    }
  }
  return value.subarray(0, value.length - padding)
}

function decryptXChaCha(
  serialized: Buffer,
  key: BitwardenXChaCha20Poly1305Key
): { plaintext: Buffer; contentType: BitwardenCoseContentType } {
  const outer = decodeCbor(serialized, 'COSE_Encrypt0')
  if (!Array.isArray(outer) || outer.length !== 3) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'COSE_Encrypt0 has invalid fields')
  }
  const protectedBytes = asBuffer(
    outer[0],
    (outer[0] as Uint8Array | undefined)?.byteLength ?? -1,
    'COSE protected header'
  )
  if (protectedBytes.length === 0 || protectedBytes.length > 1_024) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'COSE protected header is invalid')
  }
  const protectedHeader = requireMap(
    decodeCbor(protectedBytes, 'COSE protected header'),
    'COSE protected header'
  )
  const unprotectedHeader = requireMap(outer[1], 'COSE unprotected header')
  if (
    protectedHeader.size !== 3 ||
    protectedHeader.get(1) !== XCHACHA20_POLY1305_ALGORITHM ||
    unprotectedHeader.size !== 1
  ) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'COSE headers are invalid')
  }
  const keyId = asBuffer(protectedHeader.get(4), XCHACHA_KEY_ID_BYTES, 'COSE key id')
  const nonce = asBuffer(unprotectedHeader.get(5), XCHACHA_NONCE_BYTES, 'COSE nonce')
  const ciphertext = asBuffer(
    outer[2],
    (outer[2] as Uint8Array | undefined)?.byteLength ?? -1,
    'COSE ciphertext'
  )
  if (ciphertext.length < XCHACHA_TAG_BYTES || ciphertext.length > MAX_CIPHERTEXT_BYTES) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'COSE ciphertext has an invalid length')
  }
  if (!timingSafeEqual(keyId, key.keyId)) {
    throw new BitwardenCryptoError('INVALID_KEY', 'COSE key id does not match')
  }
  const contentType = parseCoseContentType(protectedHeader.get(3))
  const aad = cborEncoder.encode(['Encrypt0', protectedBytes, Buffer.alloc(0)])
  try {
    const plaintext = Buffer.from(
      xchacha20poly1305(key.encryptionKey, nonce, aad).decrypt(ciphertext)
    )
    if (contentType !== 'utf8') return { plaintext, contentType }
    const unpadded = Buffer.from(unpadUtf8(plaintext))
    plaintext.fill(0)
    return { plaintext: unpadded, contentType }
  } catch (error) {
    if (error instanceof BitwardenCryptoError) throw error
    throw new BitwardenCryptoError('AUTHENTICATION_FAILED', 'COSE authentication failed')
  } finally {
    keyId.fill(0)
    nonce.fill(0)
    ciphertext.fill(0)
    aad.fill(0)
  }
}

function encryptXChaCha(
  plaintext: Buffer,
  key: BitwardenXChaCha20Poly1305Key,
  contentType: BitwardenCoseContentType
): string {
  const protectedHeader = cborEncoder.encode(
    new Map<unknown, unknown>([
      [1, XCHACHA20_POLY1305_ALGORITHM],
      [3, coseContentType(contentType)],
      [4, key.keyId]
    ])
  )
  const nonce = randomBytes(XCHACHA_NONCE_BYTES)
  const aad = cborEncoder.encode(['Encrypt0', protectedHeader, Buffer.alloc(0)])
  const padded = contentType === 'utf8' ? padUtf8(plaintext) : Buffer.from(plaintext)
  let ciphertext: Buffer | null = null
  try {
    ciphertext = Buffer.from(xchacha20poly1305(key.encryptionKey, nonce, aad).encrypt(padded))
    const serialized = cborEncoder.encode([
      protectedHeader,
      new Map<unknown, unknown>([[5, nonce]]),
      ciphertext
    ])
    return `7.${Buffer.from(serialized).toString('base64')}`
  } catch {
    throw new BitwardenCryptoError('DECRYPTION_FAILED', 'COSE encryption failed')
  } finally {
    protectedHeader.fill(0)
    nonce.fill(0)
    aad.fill(0)
    padded.fill(0)
    ciphertext?.fill(0)
  }
}

type BitwardenVerifyingKey =
  | { algorithm: -8; keyId: Buffer; publicKey: KeyObject }
  | { algorithm: -48; keyId: Buffer; publicKey: Buffer }

function signingKeyOperation(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.length >= 1 &&
    value.length <= 2 &&
    value.includes(1) &&
    value.every((operation) => operation === 1 || operation === 2)
  )
}

function verifyingKeyFromSigningKey(encoded: Buffer): BitwardenVerifyingKey {
  const coseKey = requireMap(decodeCbor(encoded, 'V2 signing key'), 'V2 signing key')
  const keyId = asBuffer(coseKey.get(2), XCHACHA_KEY_ID_BYTES, 'V2 signing key id')
  const algorithm = coseKey.get(3)
  if (!signingKeyOperation(coseKey.get(4))) {
    keyId.fill(0)
    throw new BitwardenCryptoError('INVALID_KEY', 'V2 signing key has invalid operations')
  }

  if (
    coseKey.size === 6 &&
    coseKey.get(1) === COSE_KEY_TYPE_OKP &&
    algorithm === COSE_ALGORITHM_EDDSA &&
    coseKey.get(-1) === ED25519_CURVE
  ) {
    const seed = asBuffer(coseKey.get(-4), ED25519_SEED_BYTES, 'Ed25519 signing seed')
    const der = Buffer.concat([ED25519_PKCS8_PREFIX, seed])
    try {
      const privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
      return { algorithm: COSE_ALGORITHM_EDDSA, keyId, publicKey: createPublicKey(privateKey) }
    } catch {
      keyId.fill(0)
      throw new BitwardenCryptoError('INVALID_KEY', 'Ed25519 signing key is invalid')
    } finally {
      seed.fill(0)
      der.fill(0)
    }
  }

  if (
    coseKey.size === 6 &&
    coseKey.get(1) === COSE_KEY_TYPE_AKP &&
    algorithm === COSE_ALGORITHM_ML_DSA_44
  ) {
    const publicKey = asBuffer(
      coseKey.get(-1),
      ML_DSA_44_PUBLIC_KEY_BYTES,
      'ML-DSA-44 verifying key'
    )
    const seed = asBuffer(coseKey.get(-2), ED25519_SEED_BYTES, 'ML-DSA-44 signing seed')
    seed.fill(0)
    return { algorithm: COSE_ALGORITHM_ML_DSA_44, keyId, publicKey }
  }

  keyId.fill(0)
  throw new BitwardenCryptoError('INVALID_KEY', 'V2 signing key algorithm is unsupported')
}

async function verifySignedObject(
  encoded: string,
  verifyingKey: BitwardenVerifyingKey,
  namespace: 1 | 2
): Promise<Buffer> {
  const serialized = decodeBase64(encoded, 'COSE_Sign1')
  let protectedBytes: Buffer | null = null
  let payload: Buffer | null = null
  let signature: Buffer | null = null
  let structure: Buffer | null = null
  try {
    const outer = decodeCbor(serialized, 'COSE_Sign1')
    if (!Array.isArray(outer) || outer.length !== 4) {
      throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'COSE_Sign1 has invalid fields')
    }
    protectedBytes = asBuffer(
      outer[0],
      (outer[0] as Uint8Array | undefined)?.byteLength ?? -1,
      'COSE signature protected header'
    )
    const protectedHeader = requireMap(
      decodeCbor(protectedBytes, 'COSE signature protected header'),
      'COSE signature protected header'
    )
    const unprotectedHeader = requireMap(outer[1], 'COSE signature unprotected header')
    if (
      protectedHeader.size !== 4 ||
      unprotectedHeader.size !== 0 ||
      protectedHeader.get(1) !== verifyingKey.algorithm ||
      protectedHeader.get(3) !== COSE_CONTENT_TYPE_CBOR ||
      protectedHeader.get(COSE_SIGNING_NAMESPACE) !== namespace
    ) {
      throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'COSE signature headers are invalid')
    }
    const keyId = asBuffer(protectedHeader.get(4), XCHACHA_KEY_ID_BYTES, 'COSE signature key id')
    try {
      if (!timingSafeEqual(keyId, verifyingKey.keyId)) {
        throw new BitwardenCryptoError('INVALID_KEY', 'COSE signature key id does not match')
      }
    } finally {
      keyId.fill(0)
    }
    payload = asBuffer(
      outer[2],
      (outer[2] as Uint8Array | undefined)?.byteLength ?? -1,
      'COSE signature payload'
    )
    signature = asBuffer(
      outer[3],
      (outer[3] as Uint8Array | undefined)?.byteLength ?? -1,
      'COSE signature'
    )
    structure = cborEncoder.encode(['Signature1', protectedBytes, Buffer.alloc(0), payload])
    let valid: boolean
    if (verifyingKey.algorithm === COSE_ALGORITHM_EDDSA) {
      valid =
        signature.length === ED25519_SIGNATURE_BYTES &&
        verify(null, structure, verifyingKey.publicKey, signature)
    } else {
      const publicKey = await webcrypto.subtle.importKey(
        'raw-public',
        verifyingKey.publicKey,
        'ML-DSA-44',
        false,
        ['verify']
      )
      valid = await webcrypto.subtle.verify('ML-DSA-44', publicKey, signature, structure)
    }
    if (!valid) {
      throw new BitwardenCryptoError('AUTHENTICATION_FAILED', 'account signature is invalid')
    }
    return Buffer.from(payload)
  } catch (error) {
    if (error instanceof BitwardenCryptoError) throw error
    throw new BitwardenCryptoError('AUTHENTICATION_FAILED', 'account signature is invalid')
  } finally {
    serialized.fill(0)
    protectedBytes?.fill(0)
    payload?.fill(0)
    signature?.fill(0)
    structure?.fill(0)
  }
}

/** Verifies the V2 signed security state before any vault data is trusted. */
export async function verifyBitwardenV2AccountState(
  state: BitwardenV2AccountState,
  userKey: BitwardenSymmetricKey
): Promise<number> {
  if (!isXChaChaKey(userKey)) {
    throw new BitwardenCryptoError('INVALID_KEY', 'V2 account state requires a V2 user key')
  }
  if (state.wrappedPrivateKey) {
    const privateKeyResult = decryptBitwardenPayload(state.wrappedPrivateKey, userKey)
    try {
      if (privateKeyResult.contentType !== 'pkcs8') {
        throw new BitwardenCryptoError(
          'INVALID_CIPHERSTRING',
          'private key has the wrong content type'
        )
      }
      const privateKey = createPrivateKey({
        key: privateKeyResult.plaintext,
        format: 'der',
        type: 'pkcs8'
      })
      if (state.publicKey) {
        const derivedPublicKey = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
        const advertisedPublicKey = decodeBase64(state.publicKey, 'account public key')
        try {
          if (
            derivedPublicKey.length !== advertisedPublicKey.length ||
            !timingSafeEqual(derivedPublicKey, advertisedPublicKey)
          ) {
            throw new BitwardenCryptoError(
              'AUTHENTICATION_FAILED',
              'account public and private keys do not match'
            )
          }
        } finally {
          derivedPublicKey.fill(0)
          advertisedPublicKey.fill(0)
        }
      }
    } catch (error) {
      if (error instanceof BitwardenCryptoError) throw error
      throw new BitwardenCryptoError('INVALID_KEY', 'account private key is invalid')
    } finally {
      privateKeyResult.plaintext.fill(0)
    }
  }
  const signingKeyResult = decryptBitwardenPayload(state.wrappedSigningKey, userKey)
  if (signingKeyResult.contentType !== 'cose-key') {
    signingKeyResult.plaintext.fill(0)
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'signing key has the wrong content type')
  }
  let verifyingKey: BitwardenVerifyingKey
  try {
    verifyingKey = verifyingKeyFromSigningKey(signingKeyResult.plaintext)
  } finally {
    signingKeyResult.plaintext.fill(0)
  }

  try {
    const securityPayload = await verifySignedObject(state.securityState, verifyingKey, 2)
    let version: number
    try {
      const securityState = requireMap(
        decodeCbor(securityPayload, 'signed security state'),
        'signed security state'
      )
      version = securityState.get('version') as number
      const legacyEntityId = securityState.get('entityId')
      const fieldsAreSupported = [...securityState.keys()].every(
        (field) => field === 'version' || field === 'entityId'
      )
      if (
        !fieldsAreSupported ||
        securityState.size < 1 ||
        securityState.size > 2 ||
        !Number.isSafeInteger(version) ||
        version < 2 ||
        (legacyEntityId !== undefined &&
          (!(legacyEntityId instanceof Uint8Array) || legacyEntityId.byteLength !== 16))
      ) {
        throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'security state is invalid')
      }
    } finally {
      securityPayload.fill(0)
    }

    if (state.signedPublicKey) {
      const publicKeyPayload = await verifySignedObject(state.signedPublicKey, verifyingKey, 1)
      try {
        const message = requireMap(
          decodeCbor(publicKeyPayload, 'signed public key'),
          'signed public key'
        )
        const publicKey = message.get('publicKey')
        if (
          message.size !== 3 ||
          message.get('algorithm') !== 0 ||
          message.get('contentFormat') !== 0 ||
          !(publicKey instanceof Uint8Array)
        ) {
          throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'signed public key is invalid')
        }
        if (state.publicKey) {
          const advertised = decodeBase64(state.publicKey, 'account public key')
          try {
            const signed = Buffer.from(publicKey)
            if (advertised.length !== signed.length || !timingSafeEqual(advertised, signed)) {
              throw new BitwardenCryptoError(
                'AUTHENTICATION_FAILED',
                'signed public key does not match account public key'
              )
            }
          } finally {
            advertised.fill(0)
          }
        }
      } finally {
        publicKeyPayload.fill(0)
      }
    }
    return version
  } finally {
    verifyingKey.keyId.fill(0)
    if (Buffer.isBuffer(verifyingKey.publicKey)) verifyingKey.publicKey.fill(0)
  }
}

function decryptAes(parsed: ParsedCipherString, key: Buffer): Buffer {
  if (!parsed.iv || !parsed.mac || (parsed.type !== 1 && parsed.type !== 2)) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING')
  }
  const expectedKeyLength = parsed.type === 1 ? KEY_BYTES : COMBINED_KEY_BYTES
  requireBuffer(key, 'symmetric key', expectedKeyLength)
  const encryptionKey = parsed.type === 1 ? key.subarray(0, 16) : key.subarray(0, KEY_BYTES)
  const macKey = parsed.type === 1 ? key.subarray(16) : key.subarray(KEY_BYTES)
  const expectedMac = hmacSha256(macKey, parsed.iv, parsed.ciphertext)
  try {
    if (!timingSafeEqual(expectedMac, parsed.mac)) {
      throw new BitwardenCryptoError(
        'AUTHENTICATION_FAILED',
        'cipher string MAC verification failed'
      )
    }
  } finally {
    expectedMac.fill(0)
  }

  try {
    const decipher = createDecipheriv(
      parsed.type === 1 ? 'aes-128-cbc' : 'aes-256-cbc',
      encryptionKey,
      parsed.iv
    )
    return Buffer.concat([decipher.update(parsed.ciphertext), decipher.final()])
  } catch {
    throw new BitwardenCryptoError('DECRYPTION_FAILED', 'AES-CBC decryption failed')
  }
}

function decryptRsa(
  parsed: ParsedCipherString,
  privateKey: string | KeyObject | undefined
): Buffer {
  if (!privateKey || (parsed.type !== 3 && parsed.type !== 4)) {
    throw new BitwardenCryptoError('UNSUPPORTED_CIPHER_TYPE', 'an RSA private key is required')
  }
  try {
    return privateDecrypt(
      {
        key: privateKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: parsed.type === 3 ? 'sha256' : 'sha1'
      },
      parsed.ciphertext
    )
  } catch {
    throw new BitwardenCryptoError('DECRYPTION_FAILED', 'RSA-OAEP decryption failed')
  }
}

function decryptBitwardenPayload(
  cipherString: string,
  key: BitwardenSymmetricKey,
  privateKey?: string | KeyObject
): { plaintext: Buffer; contentType: BitwardenCoseContentType | null } {
  const parsed = parseCipherString(cipherString)
  try {
    if (parsed.type === 7) {
      if (!isXChaChaKey(key)) {
        throw new BitwardenCryptoError('INVALID_KEY', 'COSE encryption requires a V2 user key')
      }
      return decryptXChaCha(parsed.ciphertext, key)
    }
    if (parsed.type === 3 || parsed.type === 4) {
      return { plaintext: decryptRsa(parsed, privateKey), contentType: null }
    }
    if (isXChaChaKey(key)) {
      throw new BitwardenCryptoError('INVALID_KEY', 'legacy encryption requires an AES key')
    }
    if (parsed.type === 1 || parsed.type === 2) {
      return { plaintext: decryptAes(parsed, key), contentType: null }
    }
    throw new BitwardenCryptoError('UNSUPPORTED_CIPHER_TYPE')
  } finally {
    parsed.iv?.fill(0)
    parsed.ciphertext.fill(0)
    parsed.mac?.fill(0)
  }
}

/** Decrypts a type 1/2/3/4/7 Bitwarden EncString to caller-owned raw bytes. */
export function decryptBitwardenBytes(
  cipherString: string,
  key: BitwardenSymmetricKey,
  privateKey?: string | KeyObject
): Buffer {
  return decryptBitwardenPayload(cipherString, key, privateKey).plaintext
}

/** Identifies the historical unauthenticated user-key envelope accepted only during master unlock. */
export function isBitwardenLegacyMasterKeyWrappedUserKey(cipherString: string): boolean {
  return isLegacyMasterKeyWrappedUserKey(cipherString)
}

/**
 * Decrypts the account user key with the raw 32-byte master key.
 *
 * This compatibility boundary intentionally accepts unauthenticated AES-256-CBC type 0 only here.
 * Current type 2 envelopes are authenticated with the stretched master key. General vault
 * ciphertext must continue through decryptBitwardenBytes, which rejects type 0.
 */
export function decryptBitwardenMasterKeyWrappedUserKey(
  cipherString: string,
  masterKey: Buffer
): BitwardenSymmetricKey {
  requireBuffer(masterKey, 'master key', KEY_BYTES)
  let encodedUserKey: Buffer | undefined
  let stretched: ReturnType<typeof stretchMasterKey> | undefined
  try {
    if (isLegacyMasterKeyWrappedUserKey(cipherString)) {
      const parsed = parseLegacyMasterKeyWrappedUserKey(cipherString)
      try {
        const decipher = createDecipheriv('aes-256-cbc', masterKey, parsed.iv)
        encodedUserKey = Buffer.concat([decipher.update(parsed.ciphertext), decipher.final()])
      } catch {
        throw new BitwardenCryptoError(
          'DECRYPTION_FAILED',
          'legacy master-key user-key decryption failed'
        )
      } finally {
        parsed.iv.fill(0)
        parsed.ciphertext.fill(0)
      }
    } else {
      if (!cipherString.startsWith('2.')) {
        throw new BitwardenCryptoError(
          'UNSUPPORTED_CIPHER_TYPE',
          'master-key user-key envelope type is unsupported'
        )
      }
      stretched = stretchMasterKey(masterKey)
      encodedUserKey = decryptBitwardenBytes(cipherString, stretched.combinedKey)
    }
    return decodeBitwardenUserKey(encodedUserKey)
  } finally {
    encodedUserKey?.fill(0)
    stretched?.encKey.fill(0)
    stretched?.macKey.fill(0)
    stretched?.combinedKey.fill(0)
  }
}

/** Decrypts an item key and verifies the V2 COSE legacy-key content type. */
export function decryptBitwardenWrappedKey(
  cipherString: string,
  key: BitwardenSymmetricKey
): Buffer {
  const result = decryptBitwardenPayload(cipherString, key)
  if (result.contentType !== null && result.contentType !== 'legacy-key') {
    result.plaintext.fill(0)
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'wrapped key has the wrong content type')
  }
  return result.plaintext
}

/**
 * Decrypts Bitwarden's binary EncArrayBuffer attachment envelope.
 *
 * Type 0 is the historical unauthenticated AES-256-CBC format and accepts a
 * 32-byte AES key or a 64-byte combined key. Type 2 is AES-256-CBC-HMAC-SHA256 and requires Bitwarden's
 * combined 64-byte encryption/MAC key. The returned Buffer is caller-owned.
 */
export function decryptBitwardenAttachmentBuffer(envelope: Buffer, key: Buffer): Buffer {
  if (!Buffer.isBuffer(envelope)) {
    throw new BitwardenCryptoError('INVALID_INPUT', 'attachment envelope must be a Buffer')
  }
  if (envelope.length > MAX_ATTACHMENT_CIPHERTEXT_BYTES) {
    throw new BitwardenCryptoError(
      'INVALID_INPUT',
      'attachment envelope exceeds the maximum supported size'
    )
  }
  if (envelope.length < 1 + IV_BYTES + IV_BYTES) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'attachment envelope is truncated')
  }

  const type = envelope[0]
  if (type !== 0 && type !== 2) {
    throw new BitwardenCryptoError(
      'UNSUPPORTED_CIPHER_TYPE',
      'attachment envelope type is unsupported'
    )
  }

  const macOffset = 1 + IV_BYTES
  const ciphertextOffset = type === 2 ? macOffset + MAC_BYTES : macOffset
  if (envelope.length < ciphertextOffset + IV_BYTES) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'attachment envelope is truncated')
  }
  const ciphertextLength = envelope.length - ciphertextOffset
  if (ciphertextLength % IV_BYTES !== 0) {
    throw new BitwardenCryptoError(
      'INVALID_CIPHERSTRING',
      'attachment ciphertext has an invalid AES-CBC length'
    )
  }

  requireBuffer(key, 'attachment key')
  if (
    (type === 2 && key.length !== COMBINED_KEY_BYTES) ||
    (type === 0 && key.length !== KEY_BYTES && key.length !== COMBINED_KEY_BYTES)
  ) {
    throw new BitwardenCryptoError('INVALID_KEY', 'attachment key has an invalid length')
  }
  const iv = envelope.subarray(1, macOffset)
  const ciphertext = envelope.subarray(ciphertextOffset)

  if (type === 2) {
    const mac = envelope.subarray(macOffset, ciphertextOffset)
    const expectedMac = hmacSha256(key.subarray(KEY_BYTES), iv, ciphertext)
    try {
      if (!timingSafeEqual(expectedMac, mac)) {
        throw new BitwardenCryptoError(
          'AUTHENTICATION_FAILED',
          'attachment MAC verification failed'
        )
      }
    } finally {
      expectedMac.fill(0)
    }
  }

  try {
    const decipher = createDecipheriv('aes-256-cbc', key.subarray(0, KEY_BYTES), iv)
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
  } catch {
    throw new BitwardenCryptoError('DECRYPTION_FAILED', 'attachment AES-CBC decryption failed')
  }
}

/**
 * Encrypts caller-owned bytes as Bitwarden's authenticated type-2 binary
 * EncArrayBuffer attachment envelope:
 * `[2][16-byte IV][32-byte HMAC-SHA256][AES-256-CBC ciphertext]`.
 *
 * The returned Buffer is caller-owned. Neither the plaintext nor key is
 * modified; all temporary key-dependent material is cleared before return.
 */
export function encryptBitwardenAttachmentBuffer(plaintext: Buffer, key: Buffer): Buffer {
  requireBuffer(plaintext, 'attachment plaintext')
  requireBuffer(key, 'attachment key', COMBINED_KEY_BYTES)

  // PKCS#7 always appends at least one byte. Reject before encryption when the
  // resulting envelope could exceed the in-memory attachment safety ceiling.
  const ciphertextLength = Math.ceil((plaintext.length + 1) / IV_BYTES) * IV_BYTES
  const envelopeLength = 1 + IV_BYTES + MAC_BYTES + ciphertextLength
  if (envelopeLength > MAX_ATTACHMENT_CIPHERTEXT_BYTES) {
    throw new BitwardenCryptoError(
      'INVALID_INPUT',
      'attachment envelope exceeds the maximum supported size'
    )
  }

  const iv = randomBytes(IV_BYTES)
  let ciphertext: Buffer | undefined
  let mac: Buffer | undefined
  try {
    const cipher = createCipheriv('aes-256-cbc', key.subarray(0, KEY_BYTES), iv)
    ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
    mac = hmacSha256(key.subarray(KEY_BYTES), iv, ciphertext)
    return Buffer.concat([Buffer.of(2), iv, mac, ciphertext])
  } finally {
    iv.fill(0)
    ciphertext?.fill(0)
    mac?.fill(0)
  }
}

/** Decrypts a type 1/2/3/4/7 Bitwarden EncString to strict UTF-8 text. */
export function decryptBitwardenString(
  cipherString: string,
  key: BitwardenSymmetricKey,
  privateKey?: string | KeyObject
): string {
  const result = decryptBitwardenPayload(cipherString, key, privateKey)
  const plaintext = result.plaintext
  try {
    if (result.contentType !== null && result.contentType !== 'utf8') {
      throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'string has the wrong content type')
    }
    return new TextDecoder('utf-8', { fatal: true }).decode(plaintext)
  } catch {
    throw new BitwardenCryptoError('DECRYPTION_FAILED', 'plaintext is not valid UTF-8')
  } finally {
    plaintext.fill(0)
  }
}

/** Encrypts caller-owned raw bytes as a type 2 or type 7 Bitwarden EncString. */
export function encryptBitwardenBytes(
  plaintext: Buffer,
  key: BitwardenSymmetricKey,
  contentType: BitwardenCoseContentType = 'octet-stream'
): string {
  requireBuffer(plaintext, 'plaintext')
  if (plaintext.length > MAX_CIPHERTEXT_BYTES) invalidInput('plaintext exceeds the maximum size')
  if (isXChaChaKey(key)) return encryptXChaCha(plaintext, key, contentType)
  requireBuffer(key, 'symmetric key', COMBINED_KEY_BYTES)
  const iv = randomBytes(IV_BYTES)
  let ciphertext: Buffer | undefined
  let mac: Buffer | undefined
  try {
    const cipher = createCipheriv('aes-256-cbc', key.subarray(0, KEY_BYTES), iv)
    ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
    mac = hmacSha256(key.subarray(KEY_BYTES), iv, ciphertext)
    return `2.${iv.toString('base64')}|${ciphertext.toString('base64')}|${mac.toString('base64')}`
  } finally {
    iv.fill(0)
    ciphertext?.fill(0)
    mac?.fill(0)
  }
}

/** Encrypts UTF-8 text as a type 2 Bitwarden EncString. */
export function encryptBitwardenString(plaintext: string, key: BitwardenSymmetricKey): string {
  requireString(plaintext, 'plaintext', true)
  const bytes = Buffer.from(plaintext, 'utf8')
  try {
    return encryptBitwardenBytes(bytes, key, 'utf8')
  } finally {
    bytes.fill(0)
  }
}

interface BitwardenDataEnvelopeKey {
  algorithm: 'aes-256-gcm' | 'xchacha20-poly1305'
  keyId: Buffer
  encryptionKey: Buffer
}

function decodeDataEnvelopeKey(encodedAndPadded: Buffer): BitwardenDataEnvelopeKey {
  if (encodedAndPadded.length < 33 || encodedAndPadded.length > 4_096) {
    throw new BitwardenCryptoError('INVALID_KEY', 'data-envelope key has an invalid length')
  }
  const encoded = unpadStrict(encodedAndPadded, 'data-envelope key')
  const coseKey = requireMap(decodeCbor(encoded, 'data-envelope key'), 'data-envelope key')
  const algorithm = coseKey.get(3)
  const operations = coseKey.get(4)
  if (
    coseKey.size !== 5 ||
    coseKey.get(1) !== COSE_KEY_TYPE_SYMMETRIC ||
    !Array.isArray(operations) ||
    operations.length !== 1 ||
    operations[0] !== 4 ||
    (algorithm !== AES_256_GCM_ALGORITHM && algorithm !== XCHACHA20_POLY1305_ALGORITHM)
  ) {
    throw new BitwardenCryptoError('INVALID_KEY', 'data-envelope key is invalid')
  }
  return {
    algorithm: algorithm === AES_256_GCM_ALGORITHM ? 'aes-256-gcm' : 'xchacha20-poly1305',
    keyId: asBuffer(coseKey.get(2), XCHACHA_KEY_ID_BYTES, 'data-envelope key id'),
    encryptionKey: asBuffer(coseKey.get(-1), KEY_BYTES, 'data-envelope encryption key')
  }
}

function clearDataEnvelopeKey(key: BitwardenDataEnvelopeKey | null): void {
  key?.keyId.fill(0)
  key?.encryptionKey.fill(0)
}

function cborToCipherBlobValue(
  value: unknown,
  depth = 0,
  state: { nodes: number } = { nodes: 0 }
): BitwardenCipherBlobValue {
  if (depth > 32 || ++state.nodes > 200_000) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'cipher blob exceeds data limits')
  }
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value
  if (Array.isArray(value)) {
    return value.map((entry) => cborToCipherBlobValue(entry, depth + 1, state))
  }
  if (value instanceof Map) {
    const result: Record<string, BitwardenCipherBlobValue> = {}
    for (const [key, entry] of value) {
      if (typeof key !== 'string' || Object.hasOwn(result, key)) {
        throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'cipher blob has invalid keys')
      }
      Object.defineProperty(result, key, {
        value: cborToCipherBlobValue(entry, depth + 1, state),
        enumerable: true,
        configurable: true,
        writable: true
      })
    }
    return result
  }
  throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'cipher blob contains unsupported data')
}

function cipherBlobValueToCbor(
  value: BitwardenCipherBlobValue,
  depth = 0,
  state: { nodes: number } = { nodes: 0 }
): unknown {
  if (depth > 32 || ++state.nodes > 200_000) {
    throw new BitwardenCryptoError('INVALID_INPUT', 'cipher blob exceeds data limits')
  }
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value
  if (Array.isArray(value)) {
    return value.map((entry) => cipherBlobValueToCbor(entry, depth + 1, state))
  }
  if (typeof value === 'object') {
    const result = new Map<string, unknown>()
    for (const [key, entry] of Object.entries(value)) {
      result.set(key, cipherBlobValueToCbor(entry, depth + 1, state))
    }
    return result
  }
  throw new BitwardenCryptoError('INVALID_INPUT', 'cipher blob contains unsupported data')
}

function decryptDataEnvelope(envelope: string, key: BitwardenDataEnvelopeKey): Buffer {
  const serialized = decodeBase64(envelope, 'data envelope')
  let protectedBytes: Buffer | null = null
  let nonce: Buffer | null = null
  let ciphertext: Buffer | null = null
  let aad: Buffer | null = null
  try {
    const outer = decodeCbor(serialized, 'data envelope')
    if (!Array.isArray(outer) || outer.length !== 3) {
      throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'data envelope has invalid fields')
    }
    protectedBytes = asBuffer(
      outer[0],
      (outer[0] as Uint8Array | undefined)?.byteLength ?? -1,
      'data-envelope protected header'
    )
    const protectedHeader = requireMap(
      decodeCbor(protectedBytes, 'data-envelope protected header'),
      'data-envelope protected header'
    )
    const unprotectedHeader = requireMap(outer[1], 'data-envelope unprotected header')
    const expectedAlgorithm =
      key.algorithm === 'aes-256-gcm' ? AES_256_GCM_ALGORITHM : XCHACHA20_POLY1305_ALGORITHM
    if (
      protectedHeader.size !== 5 ||
      protectedHeader.get(1) !== expectedAlgorithm ||
      protectedHeader.get(3) !== COSE_CONTENT_TYPE_PADDED_CBOR ||
      protectedHeader.get(COSE_SAFE_OBJECT_NAMESPACE) !== DATA_ENVELOPE_OBJECT_NAMESPACE ||
      protectedHeader.get(COSE_SAFE_CONTENT_NAMESPACE) !== VAULT_ITEM_CONTENT_NAMESPACE ||
      unprotectedHeader.size !== 1
    ) {
      throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'data-envelope headers are invalid')
    }
    const keyId = asBuffer(protectedHeader.get(4), XCHACHA_KEY_ID_BYTES, 'data-envelope key id')
    try {
      if (!timingSafeEqual(keyId, key.keyId)) {
        throw new BitwardenCryptoError('INVALID_KEY', 'data-envelope key id does not match')
      }
    } finally {
      keyId.fill(0)
    }
    nonce = asBuffer(
      unprotectedHeader.get(5),
      key.algorithm === 'aes-256-gcm' ? AES_GCM_NONCE_BYTES : XCHACHA_NONCE_BYTES,
      'data-envelope nonce'
    )
    ciphertext = asBuffer(
      outer[2],
      (outer[2] as Uint8Array | undefined)?.byteLength ?? -1,
      'data-envelope ciphertext'
    )
    if (ciphertext.length < XCHACHA_TAG_BYTES || ciphertext.length > MAX_CIPHERTEXT_BYTES) {
      throw new BitwardenCryptoError(
        'INVALID_CIPHERSTRING',
        'data-envelope ciphertext has an invalid length'
      )
    }
    aad = Buffer.from(cborEncoder.encode(['Encrypt0', protectedBytes, Buffer.alloc(0)]))
    if (key.algorithm === 'xchacha20-poly1305') {
      return Buffer.from(xchacha20poly1305(key.encryptionKey, nonce, aad).decrypt(ciphertext))
    }
    const encrypted = ciphertext.subarray(0, -XCHACHA_TAG_BYTES)
    const tag = ciphertext.subarray(-XCHACHA_TAG_BYTES)
    const decipher = createDecipheriv('aes-256-gcm', key.encryptionKey, nonce)
    decipher.setAAD(aad)
    decipher.setAuthTag(tag)
    return Buffer.concat([decipher.update(encrypted), decipher.final()])
  } catch (error) {
    if (error instanceof BitwardenCryptoError) throw error
    throw new BitwardenCryptoError('AUTHENTICATION_FAILED', 'data-envelope authentication failed')
  } finally {
    serialized.fill(0)
    protectedBytes?.fill(0)
    nonce?.fill(0)
    ciphertext?.fill(0)
    aad?.fill(0)
  }
}

/** Decrypts Bitwarden's version-1 SealedCipherBlob stored in `Cipher.data`. */
export function decryptBitwardenCipherBlob(
  sealedBlob: string,
  itemKey: Buffer
): BitwardenCipherBlobValue {
  requireBuffer(itemKey, 'cipher item key', COMBINED_KEY_BYTES)
  const encodedContainer = requireString(sealedBlob, 'sealed cipher blob')
  if (encodedContainer.length > Math.ceil((MAX_CIPHERTEXT_BYTES * 4) / 3) + 8_192) {
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'sealed blob exceeds the maximum size')
  }
  let serialized: Buffer | null = null
  let wrappedCek: string
  let envelope: string
  let encodedCek: Buffer | null = null
  let cek: BitwardenDataEnvelopeKey | null = null
  let paddedPayload: Buffer | null = null
  try {
    if (encodedContainer.trimStart().startsWith('{')) {
      let container: unknown
      try {
        container = JSON.parse(encodedContainer)
      } catch {
        throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'sealed blob container is invalid')
      }
      if (
        typeof container !== 'object' ||
        container === null ||
        Array.isArray(container) ||
        Reflect.get(container, 'format_version') !== 1 ||
        typeof Reflect.get(container, 'wrapped_cek') !== 'string' ||
        typeof Reflect.get(container, 'envelope') !== 'string'
      ) {
        throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'sealed blob container is invalid')
      }
      wrappedCek = Reflect.get(container, 'wrapped_cek') as string
      envelope = Reflect.get(container, 'envelope') as string
    } else {
      // BearWarden builds before the official schema correction encoded the outer
      // object as base64(CBOR). Keep this read path so existing local vault data migrates.
      serialized = decodeBase64(encodedContainer, 'sealed blob')
      const container = requireMap(decodeCbor(serialized, 'sealed blob'), 'sealed blob')
      if (
        container.size !== 3 ||
        container.get('format_version') !== 1 ||
        typeof container.get('wrapped_cek') !== 'string' ||
        typeof container.get('envelope') !== 'string'
      ) {
        throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'sealed blob container is invalid')
      }
      wrappedCek = container.get('wrapped_cek') as string
      envelope = container.get('envelope') as string
    }
    encodedCek = decryptBitwardenWrappedKey(wrappedCek, itemKey)
    cek = decodeDataEnvelopeKey(encodedCek)
    paddedPayload = decryptDataEnvelope(envelope, cek)
    const payloadBytes = unpadStrict(paddedPayload, 'data envelope')
    const versioned = requireMap(decodeCbor(payloadBytes, 'cipher blob'), 'cipher blob')
    if (versioned.size !== 2 || versioned.get('version') !== '1' || !versioned.has('content')) {
      throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'cipher blob version is unsupported')
    }
    return cborToCipherBlobValue(versioned.get('content'))
  } finally {
    serialized?.fill(0)
    encodedCek?.fill(0)
    clearDataEnvelopeKey(cek)
    paddedPayload?.fill(0)
  }
}

function encryptDataEnvelope(
  payload: Buffer,
  key: BitwardenDataEnvelopeKey
): { envelope: string; wrappedKeyBytes: Buffer } {
  const protectedBytes = Buffer.from(
    cborEncoder.encode(
      new Map<unknown, unknown>([
        [1, AES_256_GCM_ALGORITHM],
        [3, COSE_CONTENT_TYPE_PADDED_CBOR],
        [4, key.keyId],
        [COSE_SAFE_OBJECT_NAMESPACE, DATA_ENVELOPE_OBJECT_NAMESPACE],
        [COSE_SAFE_CONTENT_NAMESPACE, VAULT_ITEM_CONTENT_NAMESPACE]
      ])
    )
  )
  const nonce = randomBytes(AES_GCM_NONCE_BYTES)
  const aad = Buffer.from(cborEncoder.encode(['Encrypt0', protectedBytes, Buffer.alloc(0)]))
  let encrypted: Buffer | null = null
  let tag: Buffer | null = null
  try {
    const cipher = createCipheriv('aes-256-gcm', key.encryptionKey, nonce)
    cipher.setAAD(aad)
    encrypted = Buffer.concat([cipher.update(payload), cipher.final()])
    tag = cipher.getAuthTag()
    const envelope = Buffer.from(
      cborEncoder.encode([
        protectedBytes,
        new Map<unknown, unknown>([[5, nonce]]),
        Buffer.concat([encrypted, tag])
      ])
    )
    const rawKey = Buffer.from(
      cborEncoder.encode(
        new Map<unknown, unknown>([
          [1, COSE_KEY_TYPE_SYMMETRIC],
          [2, key.keyId],
          [3, AES_256_GCM_ALGORITHM],
          [4, [4]],
          [-1, key.encryptionKey]
        ])
      )
    )
    try {
      return { envelope: envelope.toString('base64'), wrappedKeyBytes: padToMinimum(rawKey, 65) }
    } finally {
      envelope.fill(0)
      rawKey.fill(0)
    }
  } finally {
    protectedBytes.fill(0)
    nonce.fill(0)
    aad.fill(0)
    encrypted?.fill(0)
    tag?.fill(0)
  }
}

/** Encrypts a V1 vault-item payload into Bitwarden's current SealedCipherBlob format. */
export function encryptBitwardenCipherBlob(
  content: BitwardenCipherBlobValue,
  itemKey: Buffer
): string {
  requireBuffer(itemKey, 'cipher item key', COMBINED_KEY_BYTES)
  if (content === null || Array.isArray(content) || typeof content !== 'object') {
    invalidInput('cipher blob content must be an object')
  }
  const serializedPayload = Buffer.from(
    cborEncoder.encode(
      new Map<unknown, unknown>([
        ['version', '1'],
        ['content', cipherBlobValueToCbor(content)]
      ])
    )
  )
  const paddedPayload = padToMinimum(serializedPayload, DATA_ENVELOPE_PADDING_BYTES)
  const cek: BitwardenDataEnvelopeKey = {
    algorithm: 'aes-256-gcm',
    keyId: randomBytes(XCHACHA_KEY_ID_BYTES),
    encryptionKey: randomBytes(KEY_BYTES)
  }
  let wrappedKeyBytes: Buffer | null = null
  try {
    const encrypted = encryptDataEnvelope(paddedPayload, cek)
    wrappedKeyBytes = encrypted.wrappedKeyBytes
    const wrappedCek = encryptBitwardenBytes(wrappedKeyBytes, itemKey, 'legacy-key')
    return JSON.stringify({
      format_version: 1,
      wrapped_cek: wrappedCek,
      envelope: encrypted.envelope
    })
  } finally {
    serializedPayload.fill(0)
    paddedPayload.fill(0)
    wrappedKeyBytes?.fill(0)
    clearDataEnvelopeKey(cek)
  }
}

/** Decrypts and validates an encrypted PKCS#8 RSA private key (PEM, DER, or base64 DER). */
export function decryptRsaPrivateKey(cipherString: string, userKey: Buffer): KeyObject {
  const privateKeyBytes = decryptBitwardenBytes(cipherString, userKey)
  try {
    if (privateKeyBytes.subarray(0, 11).toString('ascii') === '-----BEGIN ') {
      return createPrivateKey(privateKeyBytes)
    }
    try {
      return createPrivateKey({ key: privateKeyBytes, format: 'der', type: 'pkcs8' })
    } catch {
      const base64Der = new TextDecoder('utf-8', { fatal: true }).decode(privateKeyBytes)
      const der = decodeBase64(base64Der, 'private key')
      try {
        try {
          return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
        } catch {
          return createPrivateKey(der)
        }
      } finally {
        der.fill(0)
      }
    }
  } catch {
    throw new BitwardenCryptoError('DECRYPTION_FAILED', 'decrypted private key is invalid')
  } finally {
    privateKeyBytes.fill(0)
  }
}
