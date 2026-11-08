/** Account and organization key unwrapping and user-decryption metadata from `/sync`. */
import { createPrivateKey, type KeyObject } from 'node:crypto'
import {
  BitwardenCryptoError,
  decryptBitwardenBytes,
  decryptRsaPrivateKey,
  verifyBitwardenV2AccountState,
  type BitwardenSymmetricKey
} from './bitwarden-crypto'
import { isJsonObject, type JsonObject } from './bitwarden-http'
import { MAX_REMOTE_ENTITIES } from './vault/limits'
import { readField } from './bitwarden-fields'
import { BitwardenDirectError, invalidResponse } from './bitwarden-direct-error'
import { USER_KEY_BYTES, recordProperty, stringProperty } from './bitwarden-cipher-codec'

/** Secret-free account capabilities observed in the latest committed sync snapshot. */
export interface BitwardenUserDecryptionCapabilities {
  hasWebAuthnPrfOptions: boolean
  hasV2UpgradeToken: boolean
  /** BearWarden does not yet perform PRF-based account unlock. */
  webAuthnPrfUnlockSupported: false
  /** BearWarden accepts V2 accounts but does not initiate an account-key upgrade. */
  v2AccountUpgradeSupported: false
}

export function noUserDecryptionCapabilities(): BitwardenUserDecryptionCapabilities {
  return {
    hasWebAuthnPrfOptions: false,
    hasV2UpgradeToken: false,
    webAuthnPrfUnlockSupported: false,
    v2AccountUpgradeSupported: false
  }
}

/** Accepts a raw 64-byte organization key or the legacy Base64 text encoding of one. */
function unwrapOrganizationKey(
  decrypt: () => Buffer,
  reason: 'organization-key' | 'provider-organization-key'
): Buffer {
  try {
    const plaintext = decrypt()
    try {
      if (plaintext.length === USER_KEY_BYTES) return Buffer.from(plaintext)
      if (
        plaintext.length !== Math.ceil(USER_KEY_BYTES / 3) * 4 ||
        plaintext.some((byte) => byte > 0x7f)
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const encoded = plaintext.toString('ascii')
      if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(encoded)) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const key = Buffer.from(encoded, 'base64')
      if (key.length !== USER_KEY_BYTES || key.toString('base64') !== encoded) {
        key.fill(0)
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      return key
    } finally {
      plaintext.fill(0)
    }
  } catch (error) {
    if (
      (error instanceof BitwardenDirectError && error.code === 'INVALID_RESPONSE') ||
      error instanceof BitwardenCryptoError
    ) {
      throw invalidResponse(reason)
    }
    throw error
  }
}

export function findWrappedUserKey(payload: JsonObject, profile: JsonObject): string {
  const userDecryption = recordProperty(payload, 'userDecryption')
  const masterPasswordUnlockValue = userDecryption
    ? readField(userDecryption, 'masterPasswordUnlock')
    : undefined
  if (
    masterPasswordUnlockValue !== undefined &&
    masterPasswordUnlockValue !== null &&
    !isJsonObject(masterPasswordUnlockValue)
  ) {
    throw invalidResponse('user-decryption-data')
  }
  const masterPasswordUnlock = userDecryption
    ? recordProperty(userDecryption, 'masterPasswordUnlock')
    : null
  const encryptedName = masterPasswordUnlock
    ? stringProperty(masterPasswordUnlock, 'masterKeyEncryptedUserKey')
    : null
  const wrappedName = masterPasswordUnlock
    ? stringProperty(masterPasswordUnlock, 'masterKeyWrappedUserKey')
    : null
  if (encryptedName && wrappedName && encryptedName !== wrappedName) {
    throw invalidResponse('user-decryption-data')
  }
  const modern = encryptedName ?? wrappedName
  const legacy = stringProperty(profile, 'key')
  const wrapped = modern ?? legacy
  if (!wrapped) {
    // `UsesKeyConnector` is an authoritative sync-profile flag. Only map the account to the
    // specific unsupported flow when the server explicitly reports it.
    if (readField(profile, 'usesKeyConnector') === true && masterPasswordUnlock === null) {
      throw new BitwardenDirectError('KEY_CONNECTOR_UNSUPPORTED')
    }
    // Newer identity/sync shapes may include the login decryption options. Trusted-device and
    // Key Connector errors are intentionally restricted to an explicit passwordless option;
    // an absent legacy key by itself remains the generic encryption compatibility error.
    const decryptionOptions =
      recordProperty(payload, 'userDecryptionOptions') ??
      recordProperty(profile, 'userDecryptionOptions')
    if (
      decryptionOptions &&
      readField(decryptionOptions, 'hasMasterPassword') === false &&
      recordProperty(decryptionOptions, 'masterPasswordUnlock') === null
    ) {
      const keyConnectorOption = recordProperty(decryptionOptions, 'keyConnectorOption')
      const trustedDeviceOption = recordProperty(decryptionOptions, 'trustedDeviceOption')
      const webAuthnPrfOption =
        readField(decryptionOptions, 'webAuthnPrfOption') ??
        readField(decryptionOptions, 'webAuthnPrfOptions')
      if (keyConnectorOption && !trustedDeviceOption && webAuthnPrfOption == null) {
        throw new BitwardenDirectError('KEY_CONNECTOR_UNSUPPORTED')
      }
      if (trustedDeviceOption && !keyConnectorOption && webAuthnPrfOption == null) {
        throw new BitwardenDirectError('TRUSTED_DEVICE_UNSUPPORTED')
      }
    }
    throw new BitwardenDirectError('UNSUPPORTED_ACCOUNT_ENCRYPTION')
  }
  return wrapped
}

export function parseUserDecryptionCapabilities(
  payload: JsonObject
): BitwardenUserDecryptionCapabilities {
  const raw = readField(payload, 'userDecryption')
  if (raw === undefined || raw === null) return noUserDecryptionCapabilities()
  if (!isJsonObject(raw)) {
    throw invalidResponse('user-decryption-data')
  }
  const prfOptions = readField(raw, 'webAuthnPrfOptions')
  if (
    prfOptions !== undefined &&
    prfOptions !== null &&
    (!Array.isArray(prfOptions) ||
      prfOptions.length > MAX_REMOTE_ENTITIES ||
      prfOptions.some((option) => !isJsonObject(option)))
  ) {
    throw invalidResponse('user-decryption-data')
  }
  const v2UpgradeToken = readField(raw, 'v2UpgradeToken')
  if (v2UpgradeToken !== undefined && v2UpgradeToken !== null && !isJsonObject(v2UpgradeToken)) {
    throw invalidResponse('user-decryption-data')
  }
  return {
    hasWebAuthnPrfOptions: Array.isArray(prfOptions) && prfOptions.length > 0,
    hasV2UpgradeToken: isJsonObject(v2UpgradeToken),
    webAuthnPrfUnlockSupported: false,
    v2AccountUpgradeSupported: false
  }
}

export async function validateAccountKeys(
  profile: JsonObject,
  userKey: BitwardenSymmetricKey
): Promise<void> {
  const accountKeys = recordProperty(profile, 'accountKeys')
  const encryptionPair = accountKeys
    ? recordProperty(accountKeys, 'publicKeyEncryptionKeyPair')
    : null
  const wrappedPrivateKey = encryptionPair
    ? stringProperty(encryptionPair, 'wrappedPrivateKey')
    : null
  const signaturePair = accountKeys ? recordProperty(accountKeys, 'signatureKeyPair') : null
  const security = accountKeys ? recordProperty(accountKeys, 'securityState') : null

  if (Buffer.isBuffer(userKey)) {
    if (wrappedPrivateKey?.startsWith('7.') || signaturePair !== null || security !== null) {
      throw new BitwardenDirectError('UNSUPPORTED_ACCOUNT_ENCRYPTION')
    }
    return
  }

  const wrappedSigningKey = signaturePair
    ? stringProperty(signaturePair, 'wrappedSigningKey')
    : null
  const securityState = security ? stringProperty(security, 'securityState') : null
  if (!wrappedPrivateKey?.startsWith('7.') || !wrappedSigningKey || !securityState) {
    throw new BitwardenDirectError('UNSUPPORTED_ACCOUNT_ENCRYPTION')
  }
  try {
    await verifyBitwardenV2AccountState(
      {
        wrappedPrivateKey,
        wrappedSigningKey,
        securityState,
        signedPublicKey: encryptionPair ? stringProperty(encryptionPair, 'signedPublicKey') : null,
        publicKey: encryptionPair ? stringProperty(encryptionPair, 'publicKey') : null
      },
      userKey
    )
    decryptV2AccountPrivateKey(wrappedPrivateKey, userKey)
  } catch {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
}

export function resolveAccountPrivateKey(
  profile: JsonObject,
  userKey: BitwardenSymmetricKey
): KeyObject | null {
  const accountKeys = recordProperty(profile, 'accountKeys')
  const encryptionPair = accountKeys
    ? recordProperty(accountKeys, 'publicKeyEncryptionKeyPair')
    : null
  const wrappedPrivateKey = encryptionPair
    ? stringProperty(encryptionPair, 'wrappedPrivateKey')
    : null
  if (wrappedPrivateKey?.startsWith('7.')) {
    return decryptV2AccountPrivateKey(wrappedPrivateKey, userKey)
  }

  const legacyPrivateKey = stringProperty(profile, 'privateKey') ?? wrappedPrivateKey
  if (!legacyPrivateKey || !Buffer.isBuffer(userKey)) return null
  try {
    return validateAccountPrivateKey(decryptRsaPrivateKey(legacyPrivateKey, userKey))
  } catch {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
}

function decryptV2AccountPrivateKey(
  wrappedPrivateKey: string,
  userKey: BitwardenSymmetricKey
): KeyObject {
  const privateKeyBytes = decryptBitwardenBytes(wrappedPrivateKey, userKey)
  try {
    return validateAccountPrivateKey(
      createPrivateKey({ key: privateKeyBytes, format: 'der', type: 'pkcs8' })
    )
  } catch {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  } finally {
    privateKeyBytes.fill(0)
  }
}

function validateAccountPrivateKey(privateKey: KeyObject): KeyObject {
  if (
    privateKey.type !== 'private' ||
    privateKey.asymmetricKeyType !== 'rsa' ||
    privateKey.asymmetricKeyDetails?.modulusLength !== 2_048
  ) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return privateKey
}

export function decryptOrganizationKey(
  encryptedKey: string,
  userKey: BitwardenSymmetricKey,
  privateKey: KeyObject,
  reason: 'organization-key' | 'provider-organization-key'
): Buffer {
  return unwrapOrganizationKey(() => {
    if (!encryptedKey.startsWith('3.') && !encryptedKey.startsWith('4.')) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    return decryptBitwardenBytes(encryptedKey, userKey, privateKey)
  }, reason)
}

export function decryptSymmetricWrappedKey(encryptedKey: string, wrappingKey: Buffer): Buffer {
  return unwrapOrganizationKey(
    () => decryptBitwardenBytes(encryptedKey, wrappingKey),
    'provider-organization-key'
  )
}
