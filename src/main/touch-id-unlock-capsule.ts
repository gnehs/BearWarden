import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'

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
const VAULT_KEY_LENGTH = 32
const VAULT_SALT_LENGTH = 16
const ACCOUNT_KEY_LENGTH_BYTES = 2
const MIN_ACCOUNT_KEY_LENGTH = 64
const MAX_ACCOUNT_KEY_LENGTH = 4_096
const WRAPPED_KEY_FINGERPRINT_LENGTH = 32
const BASE_PAYLOAD_LENGTH = VAULT_KEY_LENGTH + VAULT_SALT_LENGTH + ACCOUNT_KEY_LENGTH_BYTES
const MAX_PAYLOAD_LENGTH =
  BASE_PAYLOAD_LENGTH + MAX_ACCOUNT_KEY_LENGTH + WRAPPED_KEY_FINGERPRINT_LENGTH

export class TouchIdCapsuleError extends Error {
  constructor() {
    super('TOUCH_ID_CAPSULE_INVALID')
    this.name = 'TouchIdCapsuleError'
  }
}

export interface TouchIdSyncKeyMaterial {
  accountKey: Buffer
  wrappedKeyFingerprint: Buffer
}

/**
 * Key material that reopens the local vault and restores the Bitwarden account key bound to one
 * server-wrapped-key generation. It never contains the master password.
 */
export interface TouchIdUnlockMaterial {
  key: Buffer
  salt: Buffer
  sync: TouchIdSyncKeyMaterial | null
}

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

function assertMaterialShape(material: TouchIdUnlockMaterial): void {
  if (
    material.key.length !== VAULT_KEY_LENGTH ||
    material.salt.length !== VAULT_SALT_LENGTH ||
    (material.sync !== null &&
      (material.sync.accountKey.length < MIN_ACCOUNT_KEY_LENGTH ||
        material.sync.accountKey.length > MAX_ACCOUNT_KEY_LENGTH ||
        material.sync.wrappedKeyFingerprint.length !== WRAPPED_KEY_FINGERPRINT_LENGTH))
  ) {
    throw new TouchIdCapsuleError()
  }
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
  assertMaterialShape(material)
  const sync = material.sync
  let dataKey: Buffer | undefined
  let payload: Buffer | undefined
  let wrappedDataKey: Buffer | undefined
  let ciphertext: Buffer | undefined
  try {
    dataKey = randomBytes(DATA_KEY_LENGTH)
    const iv = randomBytes(IV_LENGTH)
    payload = Buffer.alloc(
      BASE_PAYLOAD_LENGTH + (sync ? sync.accountKey.length + WRAPPED_KEY_FINGERPRINT_LENGTH : 0)
    )
    material.key.copy(payload, 0)
    material.salt.copy(payload, VAULT_KEY_LENGTH)
    payload.writeUInt16BE(sync?.accountKey.length ?? 0, VAULT_KEY_LENGTH + VAULT_SALT_LENGTH)
    if (sync) {
      sync.accountKey.copy(payload, BASE_PAYLOAD_LENGTH)
      sync.wrappedKeyFingerprint.copy(payload, BASE_PAYLOAD_LENGTH + sync.accountKey.length)
    }
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

    const accountKeyLength = plaintext.readUInt16BE(VAULT_KEY_LENGTH + VAULT_SALT_LENGTH)
    const expectedLength =
      BASE_PAYLOAD_LENGTH +
      (accountKeyLength === 0 ? 0 : accountKeyLength + WRAPPED_KEY_FINGERPRINT_LENGTH)
    if (
      plaintext.length !== expectedLength ||
      (accountKeyLength !== 0 &&
        (accountKeyLength < MIN_ACCOUNT_KEY_LENGTH || accountKeyLength > MAX_ACCOUNT_KEY_LENGTH))
    ) {
      throw new TouchIdCapsuleError()
    }
    return {
      key: Buffer.from(plaintext.subarray(0, VAULT_KEY_LENGTH)),
      salt: Buffer.from(plaintext.subarray(VAULT_KEY_LENGTH, VAULT_KEY_LENGTH + VAULT_SALT_LENGTH)),
      sync:
        accountKeyLength === 0
          ? null
          : {
              accountKey: Buffer.from(
                plaintext.subarray(BASE_PAYLOAD_LENGTH, BASE_PAYLOAD_LENGTH + accountKeyLength)
              ),
              wrappedKeyFingerprint: Buffer.from(
                plaintext.subarray(BASE_PAYLOAD_LENGTH + accountKeyLength)
              )
            }
    }
  } finally {
    dataKey?.fill(0)
    plaintext?.fill(0)
  }
}
