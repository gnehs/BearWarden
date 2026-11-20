import {
  constants,
  createHash,
  createHmac,
  generateKeyPairSync,
  privateDecrypt,
  randomInt,
  type KeyObject
} from 'node:crypto'
import {
  clearBitwardenSymmetricKey,
  decodeBitwardenUserKey,
  type BitwardenSymmetricKey
} from './bitwarden-crypto'
import { BitwardenDirectError } from './bitwarden-direct-error'
import { loadEffLongWordlist } from './eff-wordlist'

/** Matches the server: Bitwarden's `UserRequestExpiration` and Vaultwarden's purge window. */
export const DEVICE_LOGIN_VALIDITY_MS = 15 * 60 * 1_000

const ACCESS_CODE_LENGTH = 25
const ACCESS_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'

/**
 * The phrase both devices show for one auth request: HKDF-SHA256-Expand(SHA-256(public key),
 * lowercase email) rendered as six EFF long-list words, as in the official `getFingerprint`.
 */
export function authRequestFingerprint(email: string, publicKeyDer: Buffer): string {
  const prk = createHash('sha256').update(publicKeyDer).digest()
  const info = Buffer.from(email.toLocaleLowerCase('en-US'), 'utf8')
  const expanded = createHmac('sha256', prk)
    .update(info)
    .update(Buffer.from([1]))
    .digest()
  try {
    const words = loadEffLongWordlist()
    let value = BigInt(`0x${expanded.toString('hex')}`)
    const radix = BigInt(words.length)
    const phrase: string[] = []
    // Six EFF-long words exceed the required 64-bit minimum and match this feature's UX contract.
    for (let index = 0; index < 6; index += 1) {
      phrase.push(words[Number(value % radix)]!)
      value /= radix
    }
    return phrase.join('-')
  } finally {
    prk.fill(0)
    info.fill(0)
    expanded.fill(0)
  }
}

/**
 * One single-use Login with device request from this installation. It holds the RSA-2048 private
 * key and the access code in the main process only; `dispose` drops both and zeroes the approved
 * user key, after which every accessor throws.
 */
export class DeviceLoginRequest {
  readonly publicKey: string
  readonly fingerprint: string
  readonly createdAt: number
  #privateKey: KeyObject | null
  #accessCode: string | null
  #id: string | null = null
  #userKey: BitwardenSymmetricKey | null = null

  private constructor(email: string, createdAt: number) {
    const pair = generateKeyPairSync('rsa', { modulusLength: 2_048 })
    const publicKeyDer = pair.publicKey.export({ format: 'der', type: 'spki' })
    this.publicKey = publicKeyDer.toString('base64')
    this.fingerprint = authRequestFingerprint(email, publicKeyDer)
    this.createdAt = createdAt
    this.#privateKey = pair.privateKey
    this.#accessCode = Array.from(
      { length: ACCESS_CODE_LENGTH },
      () => ACCESS_CODE_ALPHABET[randomInt(ACCESS_CODE_ALPHABET.length)]
    ).join('')
  }

  static create(email: string, createdAt: number): DeviceLoginRequest {
    return new DeviceLoginRequest(email, createdAt)
  }

  get accessCode(): string {
    if (this.#accessCode === null) throw new BitwardenDirectError('ABORTED')
    return this.#accessCode
  }

  get id(): string {
    if (this.#id === null || this.#accessCode === null) throw new BitwardenDirectError('ABORTED')
    return this.#id
  }

  get approved(): boolean {
    return this.#userKey !== null
  }

  /** Binds the server-assigned request id once the request was accepted. */
  accept(id: string): void {
    if (this.#id !== null || this.#accessCode === null) throw new BitwardenDirectError('ABORTED')
    this.#id = id
  }

  /** Decrypts the approving device's `4.` RSA-OAEP-SHA1 envelope; the private key is then dropped. */
  approve(encryptedKey: string): void {
    const privateKey = this.#privateKey
    if (privateKey === null || this.#userKey !== null) throw new BitwardenDirectError('ABORTED')
    const ciphertext = Buffer.from(encryptedKey.slice(2), 'base64')
    let decrypted: Buffer | null = null
    try {
      decrypted = privateDecrypt(
        { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' },
        ciphertext
      )
      this.#userKey = decodeBitwardenUserKey(decrypted)
    } catch {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    } finally {
      ciphertext.fill(0)
      decrypted?.fill(0)
    }
    this.#privateKey = null
  }

  /** Returns a caller-owned copy of the approved user key. */
  userKey(): BitwardenSymmetricKey {
    const key = this.#userKey
    if (key === null) throw new BitwardenDirectError('ABORTED')
    return Buffer.isBuffer(key)
      ? Buffer.from(key)
      : {
          algorithm: key.algorithm,
          keyId: Buffer.from(key.keyId),
          encryptionKey: Buffer.from(key.encryptionKey)
        }
  }

  dispose(): void {
    clearBitwardenSymmetricKey(this.#userKey)
    this.#userKey = null
    this.#privateKey = null
    this.#accessCode = null
  }
}
