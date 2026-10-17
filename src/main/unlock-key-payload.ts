/**
 * Plaintext layout shared by the PIN and Touch ID capsules, sealed by each with its own cipher:
 *
 *   vaultKey(32) | vaultSalt(16) | accountKeyLength(u16be) | [accountKey | wrappedKeyFingerprint(32)]
 *
 * The bracketed part is present only when the Bitwarden account key is bound to the capsule.
 */
const VAULT_KEY_LENGTH = 32
const VAULT_SALT_LENGTH = 16
const ACCOUNT_KEY_LENGTH_BYTES = 2
const MIN_ACCOUNT_KEY_LENGTH = 64
const MAX_ACCOUNT_KEY_LENGTH = 4_096
const WRAPPED_KEY_FINGERPRINT_LENGTH = 32

export const BASE_PAYLOAD_LENGTH = VAULT_KEY_LENGTH + VAULT_SALT_LENGTH + ACCOUNT_KEY_LENGTH_BYTES
export const MAX_PAYLOAD_LENGTH =
  BASE_PAYLOAD_LENGTH + MAX_ACCOUNT_KEY_LENGTH + WRAPPED_KEY_FINGERPRINT_LENGTH

export interface UnlockSyncKeyMaterial {
  accountKey: Buffer
  wrappedKeyFingerprint: Buffer
}

export interface UnlockKeyMaterial {
  key: Buffer
  salt: Buffer
  sync: UnlockSyncKeyMaterial | null
}

export function isValidUnlockKeyMaterial(material: UnlockKeyMaterial): boolean {
  return (
    material.key.length === VAULT_KEY_LENGTH &&
    material.salt.length === VAULT_SALT_LENGTH &&
    (material.sync === null ||
      (material.sync.accountKey.length >= MIN_ACCOUNT_KEY_LENGTH &&
        material.sync.accountKey.length <= MAX_ACCOUNT_KEY_LENGTH &&
        material.sync.wrappedKeyFingerprint.length === WRAPPED_KEY_FINGERPRINT_LENGTH))
  )
}

/** The caller owns and must zero the returned buffer. */
export function packUnlockKeyMaterial(material: UnlockKeyMaterial): Buffer {
  const sync = material.sync
  const payload = Buffer.alloc(
    BASE_PAYLOAD_LENGTH + (sync ? sync.accountKey.length + WRAPPED_KEY_FINGERPRINT_LENGTH : 0)
  )
  material.key.copy(payload, 0)
  material.salt.copy(payload, VAULT_KEY_LENGTH)
  payload.writeUInt16BE(sync?.accountKey.length ?? 0, VAULT_KEY_LENGTH + VAULT_SALT_LENGTH)
  if (sync) {
    sync.accountKey.copy(payload, BASE_PAYLOAD_LENGTH)
    sync.wrappedKeyFingerprint.copy(payload, BASE_PAYLOAD_LENGTH + sync.accountKey.length)
  }
  return payload
}

/** Returns independent copies, or null when the authenticated plaintext is structurally invalid. */
export function unpackUnlockKeyMaterial(plaintext: Buffer): UnlockKeyMaterial | null {
  if (plaintext.length < BASE_PAYLOAD_LENGTH || plaintext.length > MAX_PAYLOAD_LENGTH) return null
  const accountKeyLength = plaintext.readUInt16BE(VAULT_KEY_LENGTH + VAULT_SALT_LENGTH)
  const expectedLength =
    BASE_PAYLOAD_LENGTH +
    (accountKeyLength === 0 ? 0 : accountKeyLength + WRAPPED_KEY_FINGERPRINT_LENGTH)
  if (
    plaintext.length !== expectedLength ||
    (accountKeyLength !== 0 &&
      (accountKeyLength < MIN_ACCOUNT_KEY_LENGTH || accountKeyLength > MAX_ACCOUNT_KEY_LENGTH))
  ) {
    return null
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
}
