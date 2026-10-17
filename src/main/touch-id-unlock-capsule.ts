import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import {
  BASE_PAYLOAD_LENGTH,
  isValidUnlockKeyMaterial,
  MAX_PAYLOAD_LENGTH,
  packUnlockKeyMaterial,
  unpackUnlockKeyMaterial,
  type UnlockKeyMaterial
} from './unlock-key-payload'

/**
 * Touch ID capsule v1 file layout. The outer header is plaintext so legacy master-password files
 * (raw `safeStorage` ciphertext, which never begins with this magic) are distinguishable without
 * decrypting them first.
 *
 *   magic(8) | version(1) | wrappedDataKeyLength(u16be) | wrappedDataKey | iv(12) | tag(16) | ciphertext
 *
 * `wrappedDataKey` is the platform `safeStorage` ciphertext of a random AES-256 data key. The
 * payload is authenticated with AES-256-GCM so a tampered file is rejected even though the
 * platform layer is not authenticated encryption on every OS.
 */
const CAPSULE_MAGIC = Buffer.from('BWTIDCAP', 'ascii')
const CAPSULE_VERSION = 1
const HEADER_LENGTH = CAPSULE_MAGIC.length + 1 + 2
const DATA_KEY_LENGTH = 32
const IV_LENGTH = 12
const AUTH_TAG_LENGTH = 16
const MAX_WRAPPED_DATA_KEY_LENGTH = 4_096

export class TouchIdCapsuleError extends Error {
  constructor() {
    super('TOUCH_ID_CAPSULE_INVALID')
    this.name = 'TouchIdCapsuleError'
  }
}

/**
 * Key material that reopens the local vault and restores the Bitwarden account key bound to one
 * server-wrapped-key generation. It never contains the master password.
 */
export type TouchIdUnlockMaterial = UnlockKeyMaterial

/** Platform key-wrapping boundary; production uses Electron `safeStorage`. */
export interface TouchIdDataKeyProtector {
  wrap: (dataKey: string) => Promise<Buffer>
  /** Must reject when the platform reports the wrapped key cannot be used as-is. */
  unwrap: (wrapped: Buffer) => Promise<string>
}

export function clearTouchIdUnlockMaterial(material: TouchIdUnlockMaterial | null): void {
  material?.key.fill(0)
  material?.salt.fill(0)
  material?.sync?.accountKey.fill(0)
  material?.sync?.wrappedKeyFingerprint.fill(0)
}

export function isTouchIdCapsule(file: Buffer): boolean {
  return (
    file.length >= CAPSULE_MAGIC.length &&
    file.subarray(0, CAPSULE_MAGIC.length).equals(CAPSULE_MAGIC)
  )
}

function header(wrappedDataKeyLength: number): Buffer {
  const value = Buffer.alloc(HEADER_LENGTH)
  CAPSULE_MAGIC.copy(value, 0)
  value.writeUInt8(CAPSULE_VERSION, CAPSULE_MAGIC.length)
  value.writeUInt16BE(wrappedDataKeyLength, CAPSULE_MAGIC.length + 1)
  return value
}

export async function sealTouchIdCapsule(
  material: TouchIdUnlockMaterial,
  protector: TouchIdDataKeyProtector
): Promise<Buffer> {
  if (!isValidUnlockKeyMaterial(material)) throw new TouchIdCapsuleError()
  let dataKey: Buffer | undefined
  let payload: Buffer | undefined
  let wrappedDataKey: Buffer | undefined
  let ciphertext: Buffer | undefined
  try {
    dataKey = randomBytes(DATA_KEY_LENGTH)
    const iv = randomBytes(IV_LENGTH)
    payload = packUnlockKeyMaterial(material)
    wrappedDataKey = await protector.wrap(dataKey.toString('base64'))
    if (wrappedDataKey.length === 0 || wrappedDataKey.length > MAX_WRAPPED_DATA_KEY_LENGTH) {
      throw new TouchIdCapsuleError()
    }
    const aad = header(wrappedDataKey.length)
    const cipher = createCipheriv('aes-256-gcm', dataKey, iv, { authTagLength: AUTH_TAG_LENGTH })
    cipher.setAAD(Buffer.concat([aad, wrappedDataKey]))
    ciphertext = Buffer.concat([cipher.update(payload), cipher.final()])
    return Buffer.concat([aad, wrappedDataKey, iv, cipher.getAuthTag(), ciphertext])
  } finally {
    dataKey?.fill(0)
    payload?.fill(0)
    wrappedDataKey?.fill(0)
    ciphertext?.fill(0)
  }
}

export async function openTouchIdCapsule(
  file: Buffer,
  protector: TouchIdDataKeyProtector
): Promise<TouchIdUnlockMaterial> {
  if (
    !isTouchIdCapsule(file) ||
    file.length < HEADER_LENGTH ||
    file.readUInt8(CAPSULE_MAGIC.length) !== CAPSULE_VERSION
  ) {
    throw new TouchIdCapsuleError()
  }
  const wrappedDataKeyLength = file.readUInt16BE(CAPSULE_MAGIC.length + 1)
  const ivOffset = HEADER_LENGTH + wrappedDataKeyLength
  const tagOffset = ivOffset + IV_LENGTH
  const ciphertextOffset = tagOffset + AUTH_TAG_LENGTH
  const ciphertextLength = file.length - ciphertextOffset
  if (
    wrappedDataKeyLength === 0 ||
    wrappedDataKeyLength > MAX_WRAPPED_DATA_KEY_LENGTH ||
    ciphertextLength < BASE_PAYLOAD_LENGTH ||
    ciphertextLength > MAX_PAYLOAD_LENGTH
  ) {
    throw new TouchIdCapsuleError()
  }

  let dataKey: Buffer | undefined
  let plaintext: Buffer | undefined
  try {
    const encodedDataKey = await protector.unwrap(
      Buffer.from(file.subarray(HEADER_LENGTH, ivOffset))
    )
    dataKey = Buffer.from(encodedDataKey, 'base64')
    if (dataKey.length !== DATA_KEY_LENGTH) throw new TouchIdCapsuleError()
    try {
      const decipher = createDecipheriv(
        'aes-256-gcm',
        dataKey,
        file.subarray(ivOffset, tagOffset),
        { authTagLength: AUTH_TAG_LENGTH }
      )
      decipher.setAAD(file.subarray(0, ivOffset))
      decipher.setAuthTag(file.subarray(tagOffset, ciphertextOffset))
      plaintext = Buffer.concat([
        decipher.update(file.subarray(ciphertextOffset)),
        decipher.final()
      ])
    } catch {
      throw new TouchIdCapsuleError()
    }

    const material = unpackUnlockKeyMaterial(plaintext)
    if (!material) throw new TouchIdCapsuleError()
    return material
  } finally {
    dataKey?.fill(0)
    plaintext?.fill(0)
  }
}
