import {
  constants,
  createHash,
  createHmac,
  createPublicKey,
  publicEncrypt,
  randomBytes,
  randomUUID
} from 'node:crypto'
import { Encoder } from 'cbor-x'
import {
  BitwardenCryptoError,
  clearBitwardenSymmetricKey,
  decryptBitwardenAttachmentBuffer,
  decryptBitwardenMasterKeyWrappedUserKey,
  decodeBitwardenUserKey,
  decryptBitwardenBytes,
  decryptBitwardenString,
  decryptBitwardenWrappedKey,
  deriveMasterKey,
  derivePasswordKey,
  encryptBitwardenBytes,
  encryptBitwardenAttachmentBuffer,
  encryptBitwardenString,
  isBitwardenLegacyMasterKeyWrappedUserKey,
  deriveBitwardenSendKey,
  deriveBitwardenSendPasswordHash,
  stretchMasterKey,
  type BitwardenKdf,
  type BitwardenSymmetricKey
} from './bitwarden-crypto'
import {
  BitwardenHttpClient,
  BitwardenHttpError,
  isJsonObject,
  type BitwardenAccountBreachReport,
  type BitwardenAuthRequest,
  type BitwardenAccountDevice,
  type BitwardenAccountSecurityProfile,
  type BitwardenAuthenticatorSetup,
  type BitwardenEmailTwoFactorSetup,
  type BitwardenAttachmentDownload,
  type BitwardenAttachmentUpload,
  type BitwardenEquivalentDomainSettings,
  type BitwardenEquivalentDomainUpdate,
  type BitwardenEmergencyAccess,
  type BitwardenSendFileRequest,
  type BitwardenSendRequest,
  type BitwardenPrelogin,
  type BitwardenPersonalApiKey,
  type BitwardenPersonalCipherImportRequest,
  type BitwardenTwoFactorProvider,
  type BitwardenWebAuthnKey,
  type BitwardenWebAuthnSetup,
  type BitwardenSession,
  type JsonObject,
  type JsonValue
} from './bitwarden-http'
import { loadEffLongWordlist } from './eff-wordlist'
import type {
  SyncInvalidResponseReason,
  SyncInvalidResponseStage,
  VaultCustomField,
  VaultCustomFieldType,
  VaultItemFields,
  VaultItemType,
  VaultLoginUri,
  VaultPasswordHistoryEntry,
  VaultReprompt
} from '../shared/vault-contract'
import type { StoredPasskeyCredential } from './passkey'
import {
  authenticatedAttachmentPlaintext,
  encryptAttachmentSource,
  spoolEncryptedAttachment,
  type BitwardenAttachmentByteSource,
  type BitwardenEncryptedAttachmentFile
} from './bitwarden-attachment-stream'
import {
  serializeAccountWebAuthnAssertion,
  type AccountWebAuthnAssertion
} from './account-webauthn-codec'
import type { BitwardenPolicySet } from './bitwarden-policy'
import type {
  AccountWebAuthnAttestation,
  AccountWebAuthnRegistrationChallenge
} from './account-webauthn-registration-codec'
import { cloneCustomFields } from './vault/custom-fields'
import { emptyItemFields, ITEM_FIELD_NAMES } from './vault/item-fields'
import {
  MAX_ATTACHMENTS,
  MAX_ATTACHMENT_FILE_NAME_LENGTH,
  MAX_CUSTOM_FIELDS,
  MAX_LOGIN_URIS,
  MAX_SEND_FILE_NAME_LENGTH,
  MAX_SYNC_SECRET_LENGTH,
  MAX_URI_LENGTH
} from './vault/limits'
import { clonePasswordHistory } from './vault/password-history'
import { readField } from './bitwarden-fields'
import { UUID_PATTERN } from './validation-primitives'
import { BitwardenDirectError } from './bitwarden-direct-error'
import type { LoginRequestAccount } from './bitwarden-cipher-codec'
import {
  USER_KEY_BYTES,
  MAX_CUSTOM_FIELD_STRING_LENGTH,
  recordProperty,
  nullableStringProperty,
  requiredStringProperty,
  assertUuidValue,
  customFieldLinkedId,
  normalizedBitwardenTimestamp,
  parsePasswordHistory,
  plainHistoryPassword,
  sendFileSize,
  organizationCipher,
  decryptSend,
  decryptLogin,
  cipherKey,
  encryptLoginRequest,
  type BitwardenFolder,
  type BitwardenAttachment,
  type BitwardenLoginItem,
  type BitwardenOrganization,
  type BitwardenCollection,
  type BitwardenOrganizationCipher,
  type BitwardenSendItem,
  type CachedFolder,
  type CachedLogin,
  type CachedSend,
  type ResolvedBitwardenDraft
} from './bitwarden-cipher-codec'
import {
  noUserDecryptionCapabilities,
  findWrappedUserKey,
  parseUserDecryptionCapabilities,
  validateAccountKeys,
  resolveAccountPrivateKey,
  type BitwardenUserDecryptionCapabilities
} from './bitwarden-account-keys'
import {
  decodeSyncPayload,
  SyncPayloadError,
  type DecodedSyncSnapshot
} from './bitwarden-sync-decoder'
export type { BitwardenUserDecryptionCapabilities } from './bitwarden-account-keys'
export { addAggregateRemoteRows } from './bitwarden-cipher-codec'
export type {
  BitwardenFolder,
  BitwardenLoginUri,
  BitwardenAttachment,
  BitwardenLoginItem,
  BitwardenOrganization,
  BitwardenCollection,
  BitwardenOrganizationCipher,
  BitwardenSendFile,
  BitwardenSendItem
} from './bitwarden-cipher-codec'
export { BitwardenDirectError } from './bitwarden-direct-error'
export type { BitwardenDirectErrorCode } from './bitwarden-direct-error'
const MAX_SEND_FILE_PLAINTEXT_BYTES = 128 * 1024 * 1024 - 65
const MAX_WEBAUTHN_REGISTRATION_SLOTS = 10
const MIN_PERSONAL_IMPORT_CIPHERS = 2
const MAX_PERSONAL_IMPORT_CIPHERS = 500
const MIN_IMPORT_RECONCILIATION_MARKERS = 1
const PREPARED_IMPORT_TOKEN_BYTES = 32
const MAX_IMPORT_MARKER_LENGTH = 1_024
const MINIMUM_CLIENT_VERSION = '2025.5.0'
const userKeyEncoder = new Encoder({
  mapsAsObjects: false,
  tagUint8Array: false,
  useRecords: false
})

function protocolClientVersion(value: string | undefined): string {
  if (!value) return MINIMUM_CLIENT_VERSION
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([^+]+))?(?:\+.+)?$/.exec(value)
  if (!match) return MINIMUM_CLIENT_VERSION
  const requested = match.slice(1, 4).map(Number)
  const minimum = MINIMUM_CLIENT_VERSION.split('.').map(Number)
  for (let index = 0; index < minimum.length; index += 1) {
    if (requested[index]! > minimum[index]!) return value
    if (requested[index]! < minimum[index]!) return MINIMUM_CLIENT_VERSION
  }
  return match[4] ? MINIMUM_CLIENT_VERSION : value
}

function nextWebAuthnRegistrationId(keys: readonly BitwardenWebAuthnKey[]): number {
  const occupied = new Set(keys.map(({ id }) => id))
  for (let id = 1; id <= MAX_WEBAUTHN_REGISTRATION_SLOTS; id += 1) {
    if (!occupied.has(id)) return id
  }
  throw new BitwardenDirectError('CONFLICT')
}

function clearAccountWebAuthnAttestation(attestation: AccountWebAuthnAttestation): void {
  attestation.id = ''
  attestation.rawId = ''
  attestation.response.clientDataJSON = ''
  attestation.response.attestationObject = ''
  attestation.clientExtensionResults = {}
  attestation.authenticatorAttachment = null
}

const DEFAULT_SYNC_INVALID_REASON: Record<SyncInvalidResponseStage, SyncInvalidResponseReason> = {
  prelogin: 'response-shape',
  authentication: 'response-shape',
  'access-token': 'response-shape',
  response: 'response-shape',
  account: 'account-profile',
  organization: 'organization-profile',
  folder: 'folder-data',
  cipher: 'cipher-data',
  collection: 'collection-data',
  send: 'send-data',
  snapshot: 'snapshot-limit'
}

/** A dispatched mutation that fails with one of these codes may still have committed. */
function isUnknownMutationOutcome(error: BitwardenDirectError): boolean {
  return error.code === 'NETWORK' || error.code === 'ABORTED' || error.code === 'INVALID_RESPONSE'
}

export interface BitwardenTwoFactor {
  method: 0 | 1 | 3
  code: string
  /** Existing providers continue to remember by default. */
  remember?: boolean
}

export interface BitwardenWebAuthnTwoFactor {
  method: 7
  assertion: AccountWebAuthnAssertion
  /** WebAuthn requires an explicit user choice. */
  remember: boolean
}

export type BitwardenLoginTwoFactor = BitwardenTwoFactor | BitwardenWebAuthnTwoFactor

/**
 * A decrypted attachment returned only to main-process callers.  The caller owns
 * `data` and must clear it after writing it to the user-selected destination.
 */
export interface BitwardenDownloadedAttachment {
  fileName: string
  data: Buffer
}

/** Safe metadata for an actionable Login with device request. */
export interface BitwardenLoginApprovalRequest {
  id: string
  fingerprint: string
  requestDeviceType: string
  createdAt: string
}

export interface BitwardenStreamedAttachment {
  fileName: string
  data: BitwardenAttachmentByteSource
  dispose(): Promise<void>
}

export interface BitwardenSendDraft {
  name: string
  notes: string | null
  text: string
  hidden: boolean
  maxAccessCount: number | null
  expirationDate: string | null
  deletionDate: string
  /** Undefined on update means preserve the existing server-side password proof. */
  password?: string | null
  disabled: boolean
  hideEmail: boolean
}

/** Main-process-only file Send draft. Plaintext bytes never cross the renderer boundary. */
export interface BitwardenFileSendDraft {
  name: string
  notes: string | null
  fileName: string
  data: Buffer
  maxAccessCount: number | null
  expirationDate: string | null
  deletionDate: string
  password?: string | null
  disabled: boolean
  hideEmail: boolean
}

export interface BitwardenLoginDraft extends Partial<VaultItemFields> {
  type?: VaultItemType
  name: string
  notes?: string | null
  folderId?: string | null
  favorite?: boolean
  archivedAt?: string | null
  reprompt?: VaultReprompt
  uris?: VaultLoginUri[]
  customFields?: VaultCustomField[]
  passkeys?: StoredPasskeyCredential[]
  passwordHistory?: VaultPasswordHistoryEntry[]
  passwordRevisionDate?: string | null
  autofillOnPageLoad?: boolean | null
}

export interface BitwardenLoginImportEntry {
  localId: string
  draft: BitwardenLoginDraft
}

export interface BitwardenPreparedLoginImportEntry {
  localId: string
  /** The wrapped, per-item key used only to reconcile an unknown import result. */
  marker: string
  remoteFolderId: string | null
}

export interface BitwardenPreparedLoginImport {
  /** Opaque, main-process-only capability. Prepared imports are never persisted. */
  token: string
  entries: BitwardenPreparedLoginImportEntry[]
}

export interface BitwardenReconciledLoginImportEntry {
  marker: string
  remoteId: string
}

export interface BitwardenLoginRequest {
  email: string
  password: string
  twoFactor?: BitwardenLoginTwoFactor
  newDeviceOtp?: string
  signal?: AbortSignal
}

export interface BitwardenUnlockRequest {
  password: string
  twoFactor?: BitwardenLoginTwoFactor
  newDeviceOtp?: string
  signal?: AbortSignal
}

export interface BitwardenMasterPasswordChangeRequest {
  currentPassword: string
  newPassword: string
  hint?: string | null
  signal?: AbortSignal
}

/** Main-process-only setup state. It must not be persisted in exportState(). */
export interface BitwardenWebAuthnRegistrationSetup {
  enabled: boolean
  keys: BitwardenWebAuthnKey[]
  registrationId: number
  registrationChallenge: AccountWebAuthnRegistrationChallenge
  verificationMode: BitwardenWebAuthnSetup['verificationMode']
  userVerificationToken: string | null
}

export interface BitwardenWebAuthnRegistrationRequest {
  id: number
  name: string
  attestation: AccountWebAuthnAttestation
  verificationMode: BitwardenWebAuthnSetup['verificationMode']
  userVerificationToken?: string
  /** Required only for Vaultwarden. Cleared after the request finishes. */
  masterPassword?: string
}

export interface BitwardenDirectState {
  session: BitwardenSession | null
  /** Server-issued opaque token for the remembered two-step-login provider (5). */
  rememberedTwoFactorToken?: string
  deviceIdentifier: string
  profileId: string | null
  securityStamp: string | null
  /** Secret-free organization policy metadata from the latest committed sync snapshot. */
  policySet?: BitwardenPolicySet
}

export interface BitwardenPinUnlockMaterial {
  accountKey: Buffer
  wrappedKeyFingerprint: Buffer
}

export interface BitwardenSyncClient {
  status(signal?: AbortSignal): Promise<{ status: 'unauthenticated' | 'locked' | 'unlocked' }>
  pinUnlockMaterial?(): BitwardenPinUnlockMaterial | null
  restorePinUnlockMaterial?(material: BitwardenPinUnlockMaterial): void
  getAccountSecurityProfile?(signal?: AbortSignal): Promise<BitwardenAccountSecurityProfile>
  updateAccountProfileName?(
    name: string,
    expectedName: string,
    signal?: AbortSignal
  ): Promise<BitwardenAccountSecurityProfile>
  updateAccountAvatarColor?(
    avatarColor: string | null,
    expectedAvatarColor: string | null,
    signal?: AbortSignal
  ): Promise<BitwardenAccountSecurityProfile>
  getAccountDevices?(signal?: AbortSignal): Promise<BitwardenAccountDevice[]>
  resendVerificationEmail?(signal?: AbortSignal): Promise<void>
  sendEmailTwoFactorLoginCode?(masterPassword: string, signal?: AbortSignal): Promise<void>
  resendNewDeviceOtp?(masterPassword: string, signal?: AbortSignal): Promise<void>
  revisionDate?(signal?: AbortSignal): Promise<string>
  userDecryptionCapabilities?(): BitwardenUserDecryptionCapabilities
  policySet?(): BitwardenPolicySet
  purgePersonalVault?(masterPassword: string, signal?: AbortSignal): Promise<void>
  deauthorizeAllSessions?(masterPassword: string, signal?: AbortSignal): Promise<void>
  getPersonalApiKey?(
    masterPassword: string,
    rotate: boolean,
    signal?: AbortSignal
  ): Promise<{ clientId: string; clientSecret: string; revisionDate: string }>
  getTwoFactorProviders?(signal?: AbortSignal): Promise<BitwardenTwoFactorProvider[]>
  getTwoFactorRecoveryCode?(masterPassword: string, signal?: AbortSignal): Promise<string>
  disableTwoFactorProvider?(
    type: 0 | 1 | 2 | 3 | 7,
    masterPassword: string,
    signal?: AbortSignal
  ): Promise<void>
  beginAuthenticatorSetup?(
    masterPassword: string,
    signal?: AbortSignal
  ): Promise<BitwardenAuthenticatorSetup>
  completeAuthenticatorSetup?(
    request: {
      key: string
      token: string
      verificationMode: BitwardenAuthenticatorSetup['verificationMode']
      userVerificationToken?: string
      masterPassword?: string
    },
    signal?: AbortSignal
  ): Promise<void>
  beginEmailTwoFactorSetup?(
    masterPassword: string,
    signal?: AbortSignal
  ): Promise<BitwardenEmailTwoFactorSetup>
  sendEmailTwoFactorSetup?(
    request: {
      email: string
      verificationMode: BitwardenEmailTwoFactorSetup['verificationMode']
      userVerificationToken?: string
      masterPassword?: string
    },
    signal?: AbortSignal
  ): Promise<void>
  completeEmailTwoFactorSetup?(
    request: {
      email: string
      token: string
      verificationMode: BitwardenEmailTwoFactorSetup['verificationMode']
      userVerificationToken?: string
      masterPassword?: string
    },
    signal?: AbortSignal
  ): Promise<void>
  beginWebAuthnSetup?(
    masterPassword: string,
    signal?: AbortSignal
  ): Promise<BitwardenWebAuthnRegistrationSetup>
  completeWebAuthnSetup?(
    request: BitwardenWebAuthnRegistrationRequest,
    signal?: AbortSignal
  ): Promise<void>
  deleteWebAuthnKey?(id: number, masterPassword: string, signal?: AbortSignal): Promise<void>
  /** Authenticated Vaultwarden HIBP account-breach report; it does not require vault decryption. */
  getAccountBreachReport(email: string, signal?: AbortSignal): Promise<BitwardenAccountBreachReport>
  getEquivalentDomainSettings(signal?: AbortSignal): Promise<BitwardenEquivalentDomainSettings>
  /**
   * Fetches the complete settings document instead of the filtered matching hints embedded in
   * `/sync`. Callers must use this for revision checks and replacement writes.
   */
  getAuthoritativeEquivalentDomainSettings?(
    signal?: AbortSignal
  ): Promise<BitwardenEquivalentDomainSettings>
  /** Secret-free IDs of personal cipher rows isolated from the latest committed snapshot. */
  isolatedPersonalCipherIds?(): readonly string[]
  updateEquivalentDomainSettings(
    update: BitwardenEquivalentDomainUpdate,
    signal?: AbortSignal
  ): Promise<void>
  listOrganizations?(): Promise<BitwardenOrganization[]>
  listCollections?(): Promise<BitwardenCollection[]>
  listOrganizationCiphers?(): Promise<BitwardenOrganizationCipher[]>
  createOrganizationCipher?(
    organizationId: string,
    collectionIds: string[],
    draft: BitwardenLoginDraft,
    signal?: AbortSignal
  ): Promise<BitwardenOrganizationCipher>
  editOrganizationCipher?(
    id: string,
    draft: BitwardenLoginDraft,
    signal?: AbortSignal
  ): Promise<BitwardenOrganizationCipher>
  listEmergencyAccess?(signal?: AbortSignal): Promise<BitwardenEmergencyAccess[]>
  listSends?(signal?: AbortSignal): Promise<BitwardenSendItem[]>
  createFileSend?(draft: BitwardenFileSendDraft, signal?: AbortSignal): Promise<BitwardenSendItem>
  downloadFileSend?(
    id: string,
    password: string | null,
    signal?: AbortSignal
  ): Promise<BitwardenDownloadedAttachment>
  createSend?(draft: BitwardenSendDraft, signal?: AbortSignal): Promise<BitwardenSendItem>
  updateSend?(
    id: string,
    draft: BitwardenSendDraft,
    signal?: AbortSignal
  ): Promise<BitwardenSendItem>
  removeSendPassword?(id: string, signal?: AbortSignal): Promise<BitwardenSendItem>
  deleteSend?(id: string, signal?: AbortSignal): Promise<void>
  copySendLink?(id: string, copy: (value: string) => void | Promise<void>): Promise<void>
  notificationAccessToken?(signal?: AbortSignal): Promise<string>
  getLoginRequest?(id: string, signal?: AbortSignal): Promise<BitwardenLoginApprovalRequest>
  listPendingLoginRequests?(signal?: AbortSignal): Promise<BitwardenLoginApprovalRequest[]>
  respondLoginRequest?(
    id: string,
    expectedFingerprint: string,
    approved: boolean,
    signal?: AbortSignal
  ): Promise<void>
  login(request: BitwardenLoginRequest): Promise<void>
  unlock(request: BitwardenUnlockRequest): Promise<void>
  changeMasterPassword?(request: BitwardenMasterPasswordChangeRequest): Promise<void>
  sync(signal?: AbortSignal): Promise<void>
  listFolders(signal?: AbortSignal): Promise<BitwardenFolder[]>
  listPersonalLogins(signal?: AbortSignal): Promise<BitwardenLoginItem[]>
  downloadAttachment(
    id: string,
    attachmentId: string,
    signal?: AbortSignal
  ): Promise<BitwardenDownloadedAttachment>
  downloadAttachmentStream?(
    id: string,
    attachmentId: string,
    signal?: AbortSignal
  ): Promise<BitwardenStreamedAttachment>
  uploadAttachment(
    id: string,
    fileName: string,
    data: Buffer,
    signal?: AbortSignal,
    onCommitted?: () => void
  ): Promise<BitwardenAttachment>
  uploadAttachmentStream?(
    id: string,
    fileName: string,
    data: BitwardenAttachmentByteSource,
    signal?: AbortSignal,
    onCommitted?: () => void
  ): Promise<BitwardenAttachment>
  deleteAttachment(
    id: string,
    attachmentId: string,
    signal?: AbortSignal,
    onCommitted?: () => void
  ): Promise<void>
  upgradeLegacyAttachment(
    id: string,
    attachmentId: string,
    signal?: AbortSignal,
    onCommitted?: () => void
  ): Promise<BitwardenAttachment>
  createFolder(name: string, signal?: AbortSignal): Promise<BitwardenFolder>
  editFolder(id: string, name: string, signal?: AbortSignal): Promise<BitwardenFolder>
  deleteFolder(id: string, signal?: AbortSignal): Promise<void>
  createLogin(draft: BitwardenLoginDraft, signal?: AbortSignal): Promise<BitwardenLoginItem>
  prepareLoginImport?(
    entries: readonly BitwardenLoginImportEntry[]
  ): Promise<BitwardenPreparedLoginImport>
  executePreparedLoginImport?(token: string, signal?: AbortSignal): Promise<void>
  reconcileLoginImportMarkers?(
    markers: readonly string[]
  ): Promise<BitwardenReconciledLoginImportEntry[]>
  discardPreparedLoginImport?(token: string): Promise<void>
  editLogin(
    id: string,
    draft: BitwardenLoginDraft,
    signal?: AbortSignal
  ): Promise<BitwardenLoginItem>
  softDeleteLogin(id: string, signal?: AbortSignal): Promise<void>
  softDeleteLogins?(ids: readonly string[], signal?: AbortSignal): Promise<void>
  restoreLogin(id: string, signal?: AbortSignal): Promise<void>
  restoreLogins?(ids: readonly string[], signal?: AbortSignal): Promise<void>
  moveLogins?(ids: readonly string[], folderId: string | null, signal?: AbortSignal): Promise<void>
  archiveLogin(id: string, signal?: AbortSignal): Promise<void>
  archiveLogins?(ids: readonly string[], signal?: AbortSignal): Promise<void>
  unarchiveLogin(id: string, signal?: AbortSignal): Promise<void>
  unarchiveLogins?(ids: readonly string[], signal?: AbortSignal): Promise<void>
  hardDeleteLogin(id: string, signal?: AbortSignal): Promise<void>
  hardDeleteLogins?(ids: readonly string[], signal?: AbortSignal): Promise<void>
  /** Backward-compatible alias for permanent deletion. */
  deleteLogin(id: string, signal?: AbortSignal): Promise<void>
  lock(): Promise<void>
  logout(): Promise<void>
  exportState(): BitwardenDirectState
}

export interface BitwardenDirectOptions {
  serverUrl: string
  email: string
  state?: BitwardenDirectState | null
  httpClient?: BitwardenHttpClient
  onStateChanged?: (state: BitwardenDirectState) => void | Promise<void>
  deviceName?: string
  deviceType?: number
  clientVersion?: string
}

interface PreparedLoginImportPayload {
  request: BitwardenPersonalCipherImportRequest
}

const EMPTY_POLICY_SET: BitwardenPolicySet = { source: 'none', policies: [] }

function invalidPersistedPolicySet(): BitwardenPolicySet {
  return { source: 'none', policies: [], parseFailure: 'invalid-response' }
}

function hasOnlyPolicyKeys(
  record: JsonObject,
  required: readonly string[],
  optional: readonly string[] = []
): boolean {
  const prototype = Object.getPrototypeOf(record)
  if (prototype !== Object.prototype && prototype !== null) return false
  const ownKeys = Reflect.ownKeys(record)
  const allowed = new Set([...required, ...optional])
  return (
    ownKeys.every((key) => typeof key === 'string' && allowed.has(key)) &&
    required.every((key) => Object.hasOwn(record, key))
  )
}

function isPlainPolicyArray(value: unknown[], maximum: number): boolean {
  if (value.length > maximum) return false
  const ownKeys = Reflect.ownKeys(value)
  return (
    ownKeys.length === value.length + 1 &&
    ownKeys.includes('length') &&
    value.every((_, index) => Object.hasOwn(value, String(index)))
  )
}

function isSafePersistedPolicyData(value: JsonObject): boolean {
  const kind = value.kind
  if (
    kind === 'organizationDataOwnership' ||
    kind === 'disableSend' ||
    kind === 'disablePersonalVaultExport' ||
    kind === 'removeUnlockWithPin'
  ) {
    return hasOnlyPolicyKeys(value, ['kind'])
  }
  if (kind === 'sendControls') {
    return (
      hasOnlyPolicyKeys(value, ['kind', 'disableSend']) && typeof value.disableSend === 'boolean'
    )
  }
  if (kind === 'maximumVaultTimeout') {
    return (
      hasOnlyPolicyKeys(value, ['kind', 'minutes', 'timeoutType', 'action']) &&
      typeof value.minutes === 'number' &&
      Number.isSafeInteger(value.minutes) &&
      value.minutes > 0 &&
      value.minutes <= 366 * 24 * 60 &&
      (value.timeoutType === null ||
        value.timeoutType === 'never' ||
        value.timeoutType === 'onAppRestart' ||
        value.timeoutType === 'onSystemLock' ||
        value.timeoutType === 'immediately' ||
        value.timeoutType === 'custom') &&
      (value.action === null || value.action === 'lock' || value.action === 'logOut')
    )
  }
  if (kind === 'restrictedItemTypes') {
    const cipherTypes = value.cipherTypes
    return (
      hasOnlyPolicyKeys(value, ['kind', 'cipherTypes']) &&
      Array.isArray(cipherTypes) &&
      isPlainPolicyArray(cipherTypes, 16) &&
      cipherTypes.every(
        (type) => typeof type === 'number' && Number.isSafeInteger(type) && type >= 1 && type <= 8
      ) &&
      new Set(cipherTypes).size === cipherTypes.length
    )
  }
  if (kind === 'passwordGenerator') {
    if (
      !hasOnlyPolicyKeys(value, [
        'kind',
        'overridePasswordType',
        'minLength',
        'useUppercase',
        'useLowercase',
        'useNumbers',
        'numberCount',
        'useSpecial',
        'specialCount',
        'minNumberWords',
        'capitalize',
        'includeNumber'
      ]) ||
      (value.overridePasswordType !== '' &&
        value.overridePasswordType !== 'password' &&
        value.overridePasswordType !== 'passphrase')
    ) {
      return false
    }
    for (const name of ['minLength', 'numberCount', 'specialCount', 'minNumberWords']) {
      const number = value[name]
      const maximum = name === 'minLength' ? 4_096 : 1_024
      if (
        typeof number !== 'number' ||
        !Number.isSafeInteger(number) ||
        number < 0 ||
        number > maximum
      ) {
        return false
      }
    }
    return [
      'useUppercase',
      'useLowercase',
      'useNumbers',
      'useSpecial',
      'capitalize',
      'includeNumber'
    ].every((name) => typeof value[name] === 'boolean')
  }
  return false
}

/** Persisted state is an input boundary. Restore only bounded, secret-free policy metadata. */
function restorePolicySet(value: unknown): BitwardenPolicySet {
  if (value === undefined) return { ...EMPTY_POLICY_SET, policies: [] }
  if (
    !isJsonObject(value) ||
    !hasOnlyPolicyKeys(value, ['source', 'policies'], ['parseFailure', 'applicableOrganizationIds'])
  ) {
    return invalidPersistedPolicySet()
  }
  const source = value.source
  const policies = value.policies
  const parseFailure = value.parseFailure
  const applicableOrganizationIds = value.applicableOrganizationIds
  if (
    (source !== 'policiesNew' && source !== 'policies' && source !== 'none') ||
    !Array.isArray(policies) ||
    !isPlainPolicyArray(policies, 256) ||
    (parseFailure !== undefined &&
      parseFailure !== 'invalid-response' &&
      parseFailure !== 'limit-exceeded') ||
    (applicableOrganizationIds !== undefined &&
      (!Array.isArray(applicableOrganizationIds) ||
        !isPlainPolicyArray(applicableOrganizationIds, 256)))
  ) {
    return invalidPersistedPolicySet()
  }
  if (parseFailure !== undefined && (source !== 'none' || policies.length !== 0)) {
    return invalidPersistedPolicySet()
  }
  const organizationIds = new Set<string>()
  if (Array.isArray(applicableOrganizationIds)) {
    for (const id of applicableOrganizationIds) {
      if (
        typeof id !== 'string' ||
        id !== id.toLowerCase() ||
        !UUID_PATTERN.test(id) ||
        organizationIds.has(id)
      ) {
        return invalidPersistedPolicySet()
      }
      organizationIds.add(id)
    }
  }
  for (const policy of policies) {
    if (
      !isJsonObject(policy) ||
      !hasOnlyPolicyKeys(policy, [
        'id',
        'organizationId',
        'type',
        'typeName',
        'enabled',
        'canToggleState',
        'revisionDate',
        'execution',
        'data'
      ])
    ) {
      return invalidPersistedPolicySet()
    }
    const typeName = policy.typeName
    const revisionDate = policy.revisionDate
    const execution = policy.execution
    if (
      typeof policy.id !== 'string' ||
      policy.id !== policy.id.toLowerCase() ||
      !UUID_PATTERN.test(policy.id) ||
      typeof policy.organizationId !== 'string' ||
      policy.organizationId !== policy.organizationId.toLowerCase() ||
      !UUID_PATTERN.test(policy.organizationId) ||
      typeof policy.type !== 'number' ||
      !Number.isSafeInteger(policy.type) ||
      policy.type < 0 ||
      policy.type > 65_535 ||
      (typeName !== null && (typeof typeName !== 'string' || typeName.length > 64)) ||
      typeof policy.enabled !== 'boolean' ||
      typeof policy.canToggleState !== 'boolean' ||
      (revisionDate !== null &&
        (typeof revisionDate !== 'string' ||
          revisionDate.length > 40 ||
          !Number.isFinite(Date.parse(revisionDate)))) ||
      (execution !== 'actionable' &&
        execution !== 'unsupported' &&
        execution !== 'unknown' &&
        execution !== 'malformed') ||
      (policy.data !== null && !isJsonObject(policy.data))
    ) {
      return invalidPersistedPolicySet()
    }
    if (
      (execution === 'actionable' &&
        (!isJsonObject(policy.data) || !isSafePersistedPolicyData(policy.data))) ||
      (execution !== 'actionable' && policy.data !== null)
    ) {
      return invalidPersistedPolicySet()
    }
  }
  try {
    return structuredClone(value) as unknown as BitwardenPolicySet
  } catch {
    return invalidPersistedPolicySet()
  }
}

function assertSyncSecret(value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_SYNC_SECRET_LENGTH) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
}

function draftReprompt(value: unknown): VaultReprompt {
  if (value !== 0 && value !== 1) throw new BitwardenDirectError('INVALID_RESPONSE')
  return value
}

function draftCustomFieldType(value: JsonValue | undefined): VaultCustomFieldType {
  if (value === 'text' || value === 'hidden' || value === 'boolean' || value === 'linked') {
    return value
  }
  throw new BitwardenDirectError('INVALID_RESPONSE')
}

function validateDraftCustomFields(value: unknown): VaultCustomField[] {
  if (!Array.isArray(value) || value.length > MAX_CUSTOM_FIELDS) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value.map((field) => {
    if (!isJsonObject(field)) throw new BitwardenDirectError('INVALID_RESPONSE')
    const name = readField(field, 'name')
    const fieldValue = readField(field, 'value')
    if (
      typeof name !== 'string' ||
      name.length > MAX_CUSTOM_FIELD_STRING_LENGTH ||
      typeof fieldValue !== 'string' ||
      fieldValue.length > MAX_CUSTOM_FIELD_STRING_LENGTH
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    return {
      name,
      value: fieldValue,
      type: draftCustomFieldType(readField(field, 'type')),
      linkedId: customFieldLinkedId(field)
    }
  })
}

function customFieldsEqual(
  left: readonly VaultCustomField[],
  right: readonly VaultCustomField[]
): boolean {
  return (
    left.length === right.length &&
    left.every((field, index) => {
      const other = right[index]
      return (
        other !== undefined &&
        field.name === other.name &&
        field.value === other.value &&
        field.type === other.type &&
        field.linkedId === other.linkedId
      )
    })
  )
}

function draftNullableBoolean(value: unknown): boolean | null {
  if (value === null || typeof value === 'boolean') return value
  throw new BitwardenDirectError('INVALID_RESPONSE')
}

function validateDraftPasswordHistory(value: unknown): VaultPasswordHistoryEntry[] {
  if (!Array.isArray(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
  return parsePasswordHistory(value as JsonValue[], plainHistoryPassword)
}

function passwordHistoryEqual(
  left: readonly VaultPasswordHistoryEntry[],
  right: readonly VaultPasswordHistoryEntry[]
): boolean {
  return (
    left.length === right.length &&
    left.every(
      (entry, index) =>
        entry.password === right[index]?.password &&
        entry.lastUsedDate === right[index]?.lastUsedDate
    )
  )
}

function resolveDraft(
  draft: BitwardenLoginDraft,
  previous: BitwardenLoginItem | null
): ResolvedBitwardenDraft {
  const fields = { ...emptyItemFields(), ...(previous ?? {}) }
  for (const name of ITEM_FIELD_NAMES) {
    const value = draft[name]
    if (value !== undefined) {
      Object.assign(fields, { [name]: value })
    }
  }
  const customFields =
    draft.customFields === undefined
      ? cloneCustomFields(previous?.customFields ?? [])
      : validateDraftCustomFields(draft.customFields)
  const passwordHistory =
    draft.passwordHistory === undefined
      ? clonePasswordHistory(previous?.passwordHistory ?? [])
      : validateDraftPasswordHistory(draft.passwordHistory)
  const passwordRevisionDate =
    draft.passwordRevisionDate === undefined
      ? (previous?.passwordRevisionDate ?? null)
      : draft.passwordRevisionDate === null
        ? null
        : normalizedBitwardenTimestamp(draft.passwordRevisionDate)
  const autofillOnPageLoad =
    draft.autofillOnPageLoad === undefined
      ? (previous?.autofillOnPageLoad ?? null)
      : draftNullableBoolean(draft.autofillOnPageLoad)
  const type = draft.type ?? previous?.type ?? 'login'
  let uris: VaultLoginUri[]
  if (type !== 'login') {
    if (draft.uris !== undefined && draft.uris.length > 0) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    uris = []
  } else if (draft.uris !== undefined) {
    uris = validateDraftUris(draft.uris)
    if (draft.uri !== undefined && draft.uri !== (uris[0]?.uri ?? null)) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
  } else if (draft.uri !== undefined) {
    const remaining = previous?.uris.slice(1).map((entry) => ({ ...entry })) ?? []
    uris =
      draft.uri === null
        ? remaining
        : [{ uri: draft.uri, match: previous?.uris[0]?.match ?? null }, ...remaining]
  } else {
    uris = previous?.uris.map((entry) => ({ ...entry })) ?? []
  }
  fields.uri = uris[0]?.uri ?? null
  return {
    ...fields,
    type,
    name: draft.name,
    notes: draft.notes === undefined ? (previous?.notes ?? null) : draft.notes,
    folderId: draft.folderId === undefined ? (previous?.folderId ?? null) : draft.folderId,
    favorite: draft.favorite ?? previous?.favorite ?? false,
    archivedAt: draft.archivedAt === undefined ? (previous?.archivedAt ?? null) : draft.archivedAt,
    reprompt: draftReprompt(
      draft.reprompt === undefined ? (previous?.reprompt ?? 0) : draft.reprompt
    ),
    uris,
    customFields,
    passwordHistory,
    passwordRevisionDate: type === 'login' ? passwordRevisionDate : null,
    autofillOnPageLoad: type === 'login' ? autofillOnPageLoad : null,
    passkeys: draft.passkeys ?? previous?.passkeys.map((passkey) => ({ ...passkey })) ?? [],
    totpChanged: previous === null || draft.totp !== undefined,
    customFieldsChanged:
      previous === null ||
      (draft.customFields !== undefined && !customFieldsEqual(customFields, previous.customFields)),
    passkeysChanged: previous === null || draft.passkeys !== undefined,
    passwordHistoryChanged:
      previous === null ||
      (draft.passwordHistory !== undefined &&
        !passwordHistoryEqual(passwordHistory, previous.passwordHistory))
  }
}

function validateDraftUris(value: unknown): VaultLoginUri[] {
  if (!Array.isArray(value) || value.length > MAX_LOGIN_URIS) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value.map((entry) => {
    if (
      !entry ||
      typeof entry !== 'object' ||
      typeof entry.uri !== 'string' ||
      entry.uri.length > MAX_URI_LENGTH ||
      (entry.match !== null &&
        entry.match !== 0 &&
        entry.match !== 1 &&
        entry.match !== 2 &&
        entry.match !== 3 &&
        entry.match !== 4 &&
        entry.match !== 5)
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    return { uri: entry.uri, match: entry.match }
  })
}

function cloneLoginItem(item: BitwardenLoginItem): BitwardenLoginItem {
  return {
    ...item,
    uris: item.uris.map((uri) => ({ ...uri })),
    customFields: cloneCustomFields(item.customFields),
    passkeys: item.passkeys.map((passkey) => ({ ...passkey })),
    passwordHistory: clonePasswordHistory(item.passwordHistory),
    attachments: item.attachments.map((attachment) => ({ ...attachment }))
  }
}

function cloneOrganizationCipher(item: BitwardenOrganizationCipher): BitwardenOrganizationCipher {
  const loginItem = cloneLoginItem({ ...item, organizationId: null })
  return {
    ...loginItem,
    organizationId: item.organizationId,
    collectionIds: [...item.collectionIds],
    edit: item.edit,
    viewPassword: item.viewPassword,
    delete: item.delete,
    restore: item.restore
  }
}

interface FreshAttachmentMetadata {
  encryptedKey: string | null
  size: number
}

/**
 * The HTTP layer validates the fresh metadata shape and id, resolves the short-lived URL, and
 * keeps that URL private. This layer binds each field to the cached personal item before it
 * accepts the downloaded bytes.
 */
function freshAttachmentMetadata(
  response: BitwardenAttachmentDownload,
  expected: BitwardenAttachment,
  cipherKey: BitwardenSymmetricKey
): FreshAttachmentMetadata {
  const fileName = decryptBitwardenString(response.fileName, cipherKey)
  if (
    fileName !== expected.fileName ||
    (response.key === null) !== expected.legacy ||
    response.size !== expected.size
  ) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return { encryptedKey: response.key, size: response.size }
}

function normalizeEmail(value: string): string {
  const normalized = value.trim().toLocaleLowerCase('en-US')
  if (!normalized) throw new BitwardenDirectError('AUTH_REQUIRED')
  return normalized
}

function kdfFromPrelogin(prelogin: BitwardenPrelogin): BitwardenKdf {
  if (prelogin.kdfType === 0) return { type: 'pbkdf2', iterations: prelogin.iterations }
  if (prelogin.kdfType === 1 && prelogin.memory !== null && prelogin.parallelism !== null) {
    return {
      type: 'argon2id',
      iterations: prelogin.iterations,
      memoryMiB: prelogin.memory,
      parallelism: prelogin.parallelism
    }
  }
  throw new BitwardenDirectError('UNSUPPORTED_ACCOUNT_ENCRYPTION')
}

function kdfRequest(kdf: BitwardenKdf): JsonObject {
  return kdf.type === 'pbkdf2'
    ? { kdfType: 0, iterations: kdf.iterations }
    : {
        kdfType: 1,
        iterations: kdf.iterations,
        memory: kdf.memoryMiB,
        parallelism: kdf.parallelism
      }
}

function encodeUserKeyForMasterKeyWrap(key: BitwardenSymmetricKey): Buffer {
  if (Buffer.isBuffer(key)) return Buffer.from(key)
  const encoded = Buffer.from(
    userKeyEncoder.encode(
      new Map<unknown, unknown>([
        [1, 4],
        [2, key.keyId],
        [3, -70_000],
        [4, [3, 4, 5, 6]],
        [-1, key.encryptionKey]
      ])
    )
  )
  const padding = Math.max(1, 65 - encoded.length)
  try {
    return Buffer.concat([encoded, Buffer.alloc(padding, padding)])
  } finally {
    encoded.fill(0)
  }
}

function cloneBitwardenAccountKey(key: BitwardenSymmetricKey): BitwardenSymmetricKey {
  return Buffer.isBuffer(key)
    ? Buffer.from(key)
    : {
        algorithm: key.algorithm,
        keyId: Buffer.from(key.keyId),
        encryptionKey: Buffer.from(key.encryptionKey)
      }
}

function loginRequestFingerprint(email: string, request: BitwardenAuthRequest): string {
  const publicKey = Buffer.from(request.publicKey, 'base64')
  const prk = createHash('sha256').update(publicKey).digest()
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
    publicKey.fill(0)
    prk.fill(0)
    info.fill(0)
    expanded.fill(0)
  }
}

function loginRequestMetadata(
  email: string,
  request: BitwardenAuthRequest
): BitwardenLoginApprovalRequest {
  return {
    id: request.id,
    fingerprint: loginRequestFingerprint(email, request),
    requestDeviceType: request.requestDeviceType,
    createdAt: request.creationDate
  }
}

function desktopDeviceType(): number {
  if (process.platform === 'win32') return 6
  if (process.platform === 'darwin') return 7
  return 8
}

function responseEntity(value: JsonObject, wrapper: string): JsonObject {
  return recordProperty(value, wrapper) ?? value
}

export class BitwardenDirectClient implements BitwardenSyncClient {
  private readonly email: string
  private readonly http: BitwardenHttpClient
  private readonly deviceName: string
  private readonly deviceType: number
  private state: BitwardenDirectState
  private stretchedKey: Buffer | null = null
  private pendingMasterKey: Buffer | null = null
  private userKey: BitwardenSymmetricKey | null = null
  private wrappedUserKeyFingerprint: Buffer | null = null
  private folders = new Map<string, CachedFolder>()
  private logins = new Map<string, CachedLogin>()
  private organizations = new Map<string, BitwardenOrganization>()
  private collections = new Map<string, BitwardenCollection>()
  private organizationCiphers = new Map<string, BitwardenOrganizationCipher>()
  private organizationCipherRaws = new Map<string, JsonObject>()
  private organizationKeys = new Map<string, Buffer>()
  private sends = new Map<string, CachedSend>()
  private isolatedPersonalCiphers = new Set<string>()
  private runtimeGeneration = 0
  private stateChangeQueue: Promise<void> = Promise.resolve()
  private syncQueue: Promise<void> = Promise.resolve()
  private syncedEquivalentDomainSettings: BitwardenEquivalentDomainSettings | null = null
  private syncedUserDecryptionCapabilities = noUserDecryptionCapabilities()
  private preparedLoginImports = new Map<string, PreparedLoginImportPayload>()

  constructor(private readonly options: BitwardenDirectOptions) {
    this.email = normalizeEmail(options.email)
    this.deviceName = options.deviceName ?? 'BearWarden desktop'
    this.deviceType = options.deviceType ?? desktopDeviceType()
    this.state = options.state
      ? {
          session: options.state.session
            ? {
                accessToken: options.state.session.accessToken,
                refreshToken: options.state.session.refreshToken,
                expiresAt: options.state.session.expiresAt,
                ...(options.state.session.clientId
                  ? { clientId: options.state.session.clientId }
                  : {})
              }
            : null,
          ...((options.state.rememberedTwoFactorToken ?? options.state.session?.twoFactorToken)
            ? {
                rememberedTwoFactorToken:
                  options.state.rememberedTwoFactorToken ?? options.state.session?.twoFactorToken
              }
            : {}),
          deviceIdentifier: options.state.deviceIdentifier,
          profileId: options.state.profileId,
          securityStamp: options.state.securityStamp,
          policySet: restorePolicySet(options.state.policySet)
        }
      : {
          session: null,
          rememberedTwoFactorToken: undefined,
          deviceIdentifier: randomUUID(),
          profileId: null,
          securityStamp: null,
          policySet: { ...EMPTY_POLICY_SET, policies: [] }
        }
    this.http =
      options.httpClient ??
      new BitwardenHttpClient({
        server: options.serverUrl,
        clientName: 'desktop',
        clientVersion: protocolClientVersion(options.clientVersion),
        onSessionChanged: async (session) => {
          if (session === null) {
            this.state.session = null
            await this.notifyStateChanged(null)
            return
          }
          const normalizedSession = this.normalizedSession(session)
          await this.notifyStateChanged(normalizedSession)
          this.captureRememberedTwoFactorToken(session)
          this.state.session = normalizedSession
        }
      })
    if (this.state.session) this.http.setSession(this.state.session)
  }

  exportState(): BitwardenDirectState {
    const session = this.http.exportSession()
    return {
      session: session ? this.normalizedSession(session) : null,
      ...(this.state.rememberedTwoFactorToken
        ? { rememberedTwoFactorToken: this.state.rememberedTwoFactorToken }
        : {}),
      deviceIdentifier: this.state.deviceIdentifier,
      profileId: this.state.profileId,
      securityStamp: this.state.securityStamp,
      policySet: restorePolicySet(this.state.policySet)
    }
  }

  pinUnlockMaterial(): BitwardenPinUnlockMaterial | null {
    if (!this.userKey || !this.wrappedUserKeyFingerprint) return null
    return {
      accountKey: encodeUserKeyForMasterKeyWrap(this.userKey),
      wrappedKeyFingerprint: Buffer.from(this.wrappedUserKeyFingerprint)
    }
  }

  restorePinUnlockMaterial(material: BitwardenPinUnlockMaterial): void {
    if (material.wrappedKeyFingerprint.length !== 32) {
      throw new BitwardenDirectError('AUTH_REQUIRED')
    }
    const userKey = decodeBitwardenUserKey(material.accountKey)
    clearBitwardenSymmetricKey(this.userKey)
    this.wrappedUserKeyFingerprint?.fill(0)
    this.userKey = userKey
    this.wrappedUserKeyFingerprint = Buffer.from(material.wrappedKeyFingerprint)
  }

  async status(): Promise<{ status: 'unauthenticated' | 'locked' | 'unlocked' }> {
    if (!this.http.exportSession()) return { status: 'unauthenticated' }
    return { status: this.stretchedKey || this.userKey ? 'unlocked' : 'locked' }
  }

  async getAccountBreachReport(
    email: string,
    signal?: AbortSignal
  ): Promise<BitwardenAccountBreachReport> {
    try {
      return await this.http.getAccountBreachReport(email, signal)
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async getAccountSecurityProfile(signal?: AbortSignal): Promise<BitwardenAccountSecurityProfile> {
    try {
      return await this.http.getAccountSecurityProfile(signal)
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async updateAccountProfileName(
    name: string,
    expectedName: string,
    signal?: AbortSignal
  ): Promise<BitwardenAccountSecurityProfile> {
    const current = await this.authoritativeAccountProfile(signal)
    if (current.name !== expectedName) throw new BitwardenDirectError('ACCOUNT_PROFILE_STALE')
    return this.applyAccountProfileMutation(
      () => this.http.updateAccountProfileName(name, signal),
      (profile) => profile.name === name,
      signal
    )
  }

  async updateAccountAvatarColor(
    avatarColor: string | null,
    expectedAvatarColor: string | null,
    signal?: AbortSignal
  ): Promise<BitwardenAccountSecurityProfile> {
    const target = avatarColor?.toLocaleUpperCase('en-US') ?? null
    const expected = expectedAvatarColor?.toLocaleUpperCase('en-US') ?? null
    const current = await this.authoritativeAccountProfile(signal)
    if (current.avatarColor !== expected) {
      throw new BitwardenDirectError('ACCOUNT_PROFILE_STALE')
    }
    return this.applyAccountProfileMutation(
      () => this.http.updateAccountAvatarColor(target, signal),
      (profile) => profile.avatarColor === target,
      signal
    )
  }

  async getAccountDevices(signal?: AbortSignal): Promise<BitwardenAccountDevice[]> {
    try {
      const devices = await this.http.getDevices(this.state.deviceIdentifier, signal)
      await this.captureSession()
      return devices
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async resendVerificationEmail(signal?: AbortSignal): Promise<void> {
    try {
      await this.http.resendVerificationEmail(signal)
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async purgePersonalVault(masterPassword: string, signal?: AbortSignal): Promise<void> {
    let masterPasswordHash = ''
    let mutationStarted = false
    try {
      assertSyncSecret(masterPassword)
      this.requireProfileId()
      masterPasswordHash = await this.deriveMasterPasswordHash(masterPassword, signal)
      if (signal?.aborted) throw new BitwardenDirectError('ABORTED')
      mutationStarted = true
      await this.http.purgePersonalVault(masterPasswordHash, signal)
      await this.captureSession()
    } catch (error) {
      const mapped = this.mapError(error)
      if (mutationStarted && (mapped.code === 'NETWORK' || mapped.code === 'ABORTED')) {
        throw new BitwardenDirectError('VAULT_PURGE_UNKNOWN')
      }
      throw mapped
    } finally {
      masterPasswordHash = ''
    }
  }

  async deauthorizeAllSessions(masterPassword: string, signal?: AbortSignal): Promise<void> {
    let masterPasswordHash = ''
    let mutationStarted = false
    try {
      assertSyncSecret(masterPassword)
      this.requireProfileId()
      masterPasswordHash = await this.deriveMasterPasswordHash(masterPassword, signal)
      if (signal?.aborted) throw new BitwardenDirectError('ABORTED')
      await this.http.deauthorizeAllSessions(masterPasswordHash, signal, () => {
        mutationStarted = true
      })
      await this.clearDeauthorizedSession()
    } catch (error) {
      const mapped = this.mapError(error)
      if (mutationStarted && isUnknownMutationOutcome(mapped)) {
        await this.clearDeauthorizedSession().catch(() => undefined)
        throw new BitwardenDirectError('SESSION_DEAUTHORIZATION_UNKNOWN')
      }
      throw mapped
    } finally {
      masterPasswordHash = ''
    }
  }

  async getPersonalApiKey(
    masterPassword: string,
    rotate: boolean,
    signal?: AbortSignal
  ): Promise<{ clientId: string; clientSecret: string; revisionDate: string }> {
    let result: BitwardenPersonalApiKey | null = null
    let rotationRequestStarted = false
    try {
      assertSyncSecret(masterPassword)
      const profileId = this.requireProfileId()
      const masterPasswordHash = await this.deriveMasterPasswordHash(masterPassword, signal)
      rotationRequestStarted = rotate
      result = await this.http.getPersonalApiKey(masterPasswordHash, rotate, signal)
      await this.captureSession()
      return {
        clientId: `user.${profileId}`,
        clientSecret: result.apiKey,
        revisionDate: result.revisionDate
      }
    } catch (error) {
      const mapped = this.mapError(error)
      if (rotationRequestStarted && mapped.code === 'NETWORK') {
        throw new BitwardenDirectError('API_KEY_ROTATION_UNKNOWN')
      }
      throw mapped
    } finally {
      if (result) result.apiKey = ''
    }
  }

  async changeMasterPassword(request: BitwardenMasterPasswordChangeRequest): Promise<void> {
    let currentMasterKey: Buffer | null = null
    let currentHash: Buffer | null = null
    let newMasterKey: Buffer | null = null
    let newHash: Buffer | null = null
    let stretched: ReturnType<typeof stretchMasterKey> | null = null
    let wrappedUserKey = ''
    let encodedUserKey: Buffer | null = null
    let mutationStarted = false
    try {
      const { currentPassword, newPassword, signal } = request
      const hint = request.hint ?? ''
      if (
        typeof currentPassword !== 'string' ||
        typeof newPassword !== 'string' ||
        typeof hint !== 'string' ||
        currentPassword.length === 0 ||
        newPassword.length < 12 ||
        currentPassword.length > MAX_SYNC_SECRET_LENGTH ||
        newPassword.length > MAX_SYNC_SECRET_LENGTH ||
        hint.length > 50
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const userKey = this.requireUserKey()
      encodedUserKey = encodeUserKeyForMasterKeyWrap(userKey)
      const prelogin = await this.http.prelogin(this.email, signal)
      const passwordChangeContract = await this.http.passwordChangeContract(signal)
      const salt = prelogin.salt ?? this.email
      const kdf = kdfFromPrelogin(prelogin)
      currentMasterKey = await deriveMasterKey(currentPassword, salt, kdf)
      currentHash = await derivePasswordKey(currentMasterKey, currentPassword)
      newMasterKey = await deriveMasterKey(newPassword, salt, kdf)
      newHash = await derivePasswordKey(newMasterKey, newPassword)
      stretched = stretchMasterKey(newMasterKey)
      wrappedUserKey = encryptBitwardenBytes(encodedUserKey, stretched.combinedKey)
      const masterPasswordHash = currentHash.toString('base64')
      const newMasterPasswordHash = newHash.toString('base64')
      const kdfPayload = kdfRequest(kdf)
      if (signal?.aborted) throw new BitwardenDirectError('ABORTED')
      mutationStarted = true
      await this.http.changeMasterPassword(
        passwordChangeContract === 'official'
          ? {
              contract: 'official',
              masterPasswordHash,
              authenticationData: {
                salt,
                kdf: structuredClone(kdfPayload),
                masterPasswordAuthenticationHash: newMasterPasswordHash
              },
              unlockData: {
                salt,
                kdf: structuredClone(kdfPayload),
                masterKeyWrappedUserKey: wrappedUserKey
              },
              masterPasswordHint: hint
            }
          : {
              contract: 'vaultwarden',
              masterPasswordHash,
              newMasterPasswordHash,
              masterPasswordHint: request.hint ?? null,
              key: wrappedUserKey
            },
        signal
      )
      this.clearDecryptedState()
      this.state.session = null
      this.http.clearSession()
      await this.notifyStateChanged()
    } catch (error) {
      const mapped = this.mapError(error)
      if (mutationStarted && isUnknownMutationOutcome(mapped)) {
        this.clearDecryptedState()
        this.state.session = null
        this.http.clearSession()
        await this.notifyStateChanged().catch(() => undefined)
        throw new BitwardenDirectError('MASTER_PASSWORD_CHANGE_UNKNOWN')
      }
      throw mapped
    } finally {
      currentMasterKey?.fill(0)
      currentHash?.fill(0)
      newMasterKey?.fill(0)
      newHash?.fill(0)
      encodedUserKey?.fill(0)
      stretched?.encKey.fill(0)
      stretched?.macKey.fill(0)
      stretched?.combinedKey.fill(0)
      wrappedUserKey = ''
    }
  }

  async getTwoFactorProviders(signal?: AbortSignal): Promise<BitwardenTwoFactorProvider[]> {
    try {
      return await this.http.getTwoFactorProviders(signal)
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async getTwoFactorRecoveryCode(masterPassword: string, signal?: AbortSignal): Promise<string> {
    try {
      assertSyncSecret(masterPassword)
      this.requireProfileId()
      const masterPasswordHash = await this.deriveMasterPasswordHash(masterPassword, signal)
      const code = await this.http.getTwoFactorRecoveryCode(masterPasswordHash, signal)
      await this.captureSession()
      return code
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async disableTwoFactorProvider(
    type: 0 | 1 | 2 | 3 | 7,
    masterPassword: string,
    signal?: AbortSignal
  ): Promise<void> {
    let masterPasswordHash = ''
    let authenticatorSetup: BitwardenAuthenticatorSetup | null = null
    let emailSetup: BitwardenEmailTwoFactorSetup | null = null
    let providerSetup: Awaited<ReturnType<BitwardenHttpClient['getTwoFactorDisableSetup']>> | null =
      null
    let webAuthnSetup: BitwardenWebAuthnSetup | null = null
    let usedUnverifiableProviderEscape = false
    let mutationStarted = false
    try {
      if (
        !([0, 1, 2, 3, 7] as const).includes(type) ||
        typeof masterPassword !== 'string' ||
        masterPassword.length === 0 ||
        masterPassword.length > MAX_SYNC_SECRET_LENGTH
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      this.requireProfileId()
      masterPasswordHash = await this.deriveMasterPasswordHash(masterPassword, signal)
      if (type === 0) {
        authenticatorSetup = await this.http.getAuthenticatorSetup(masterPasswordHash, signal)
        if (!authenticatorSetup.enabled) throw new BitwardenDirectError('INVALID_RESPONSE')
        mutationStarted = true
        await this.http.disableTwoFactorProvider(
          authenticatorSetup.verificationMode === 'server-token'
            ? {
                type,
                verificationMode: 'server-token',
                key: authenticatorSetup.key,
                userVerificationToken: authenticatorSetup.userVerificationToken!
              }
            : { type, verificationMode: 'master-password', masterPasswordHash },
          signal
        )
      } else if (type === 1) {
        emailSetup = await this.http.getEmailTwoFactorSetup(masterPasswordHash, signal)
        if (!emailSetup.enabled) throw new BitwardenDirectError('INVALID_RESPONSE')
        mutationStarted = true
        await this.http.disableTwoFactorProvider(
          emailSetup.verificationMode === 'server-token'
            ? {
                type,
                verificationMode: 'server-token',
                userVerificationToken: emailSetup.userVerificationToken!
              }
            : { type, verificationMode: 'master-password', masterPasswordHash },
          signal
        )
      } else if (type === 2 || type === 3) {
        try {
          providerSetup = await this.http.getTwoFactorDisableSetup(type, masterPasswordHash, signal)
        } catch (error) {
          if (
            type !== 3 ||
            !(error instanceof BitwardenHttpError) ||
            !(
              error.code === 'INVALID_RESPONSE' ||
              (error.code === 'NETWORK' && error.status === 400)
            )
          ) {
            throw error
          }
          // Vaultwarden can hide an already-enabled provider when its server-side
          // Duo/Yubico integration is no longer usable. Its generic endpoint is the
          // documented escape hatch and still validates this fresh password proof.
          usedUnverifiableProviderEscape = true
        }
        // Vaultwarden reports `enabled: false` when the database row exists but
        // the server-side Duo/Yubico integration is unusable. The generic endpoint
        // is the only escape hatch for that state and is also a safe no-op when the
        // provider is genuinely absent.
        if (providerSetup && !providerSetup.enabled) usedUnverifiableProviderEscape = true
        mutationStarted = true
        await this.http.disableTwoFactorProvider(
          providerSetup?.verificationMode === 'server-token' && !usedUnverifiableProviderEscape
            ? {
                type,
                verificationMode: 'server-token',
                userVerificationToken: providerSetup.userVerificationToken!
              }
            : { type, verificationMode: 'master-password', masterPasswordHash },
          signal
        )
      } else {
        webAuthnSetup = await this.http.getWebAuthnSetup(masterPasswordHash, signal)
        if (!webAuthnSetup.enabled) throw new BitwardenDirectError('INVALID_RESPONSE')
        mutationStarted = true
        await this.http.disableTwoFactorProvider(
          webAuthnSetup.verificationMode === 'server-token'
            ? {
                type,
                verificationMode: 'server-token',
                userVerificationToken: webAuthnSetup.userVerificationToken!
              }
            : { type, verificationMode: 'master-password', masterPasswordHash },
          signal
        )
      }
      await this.captureSession()
    } catch (error) {
      const mapped = this.mapError(error)
      if (mutationStarted && isUnknownMutationOutcome(mapped)) {
        if (
          !usedUnverifiableProviderEscape &&
          (await this.isTwoFactorProviderAuthoritativelyDisabled(type, masterPasswordHash, signal))
        ) {
          await this.captureSession()
          return
        }
        throw new BitwardenDirectError('TWO_FACTOR_MUTATION_UNKNOWN')
      }
      throw mapped
    } finally {
      masterPasswordHash = ''
      if (authenticatorSetup) {
        authenticatorSetup.key = ''
        authenticatorSetup.userVerificationToken = null
      }
      if (emailSetup) {
        emailSetup.email = null
        emailSetup.userVerificationToken = null
      }
      if (providerSetup) providerSetup.userVerificationToken = null
      if (webAuthnSetup) {
        webAuthnSetup.userVerificationToken = null
        webAuthnSetup.keys.splice(0)
      }
    }
  }

  private async isTwoFactorProviderAuthoritativelyDisabled(
    type: 0 | 1 | 2 | 3 | 7,
    masterPasswordHash: string,
    signal?: AbortSignal
  ): Promise<boolean> {
    try {
      if (type === 0)
        return !(await this.http.getAuthenticatorSetup(masterPasswordHash, signal)).enabled
      if (type === 1)
        return !(await this.http.getEmailTwoFactorSetup(masterPasswordHash, signal)).enabled
      if (type === 2 || type === 3) {
        return !(await this.http.getTwoFactorDisableSetup(type, masterPasswordHash, signal)).enabled
      }
      return !(await this.http.getWebAuthnSetup(masterPasswordHash, signal)).enabled
    } catch {
      // In particular, a Vaultwarden Yubico configuration failure makes absence
      // impossible to prove. Keep the outcome unknown instead of guessing.
      return false
    }
  }

  async beginAuthenticatorSetup(
    masterPassword: string,
    signal?: AbortSignal
  ): Promise<BitwardenAuthenticatorSetup> {
    try {
      assertSyncSecret(masterPassword)
      this.requireProfileId()
      const masterPasswordHash = await this.deriveMasterPasswordHash(masterPassword, signal)
      const setup = await this.http.getAuthenticatorSetup(masterPasswordHash, signal)
      await this.captureSession()
      return setup
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async completeAuthenticatorSetup(
    request: {
      key: string
      token: string
      verificationMode: BitwardenAuthenticatorSetup['verificationMode']
      userVerificationToken?: string
      masterPassword?: string
    },
    signal?: AbortSignal
  ): Promise<void> {
    let mutationStarted = false
    try {
      let masterPasswordHash: string | undefined
      if (request.verificationMode === 'master-password') {
        const password = request.masterPassword
        assertSyncSecret(password)
        masterPasswordHash = await this.deriveMasterPasswordHash(password, signal)
      }
      mutationStarted = true
      await this.http.enableAuthenticator(
        {
          key: request.key,
          token: request.token,
          verificationMode: request.verificationMode,
          ...(request.userVerificationToken
            ? { userVerificationToken: request.userVerificationToken }
            : {}),
          ...(masterPasswordHash ? { masterPasswordHash } : {})
        },
        signal
      )
      await this.captureSession()
    } catch (error) {
      const mapped = this.mapError(error)
      if (mutationStarted && mapped.code === 'NETWORK') {
        throw new BitwardenDirectError('TWO_FACTOR_MUTATION_UNKNOWN')
      }
      throw mapped
    } finally {
      if (request.masterPassword !== undefined) request.masterPassword = ''
      if (request.userVerificationToken !== undefined) request.userVerificationToken = ''
    }
  }

  async beginEmailTwoFactorSetup(
    masterPassword: string,
    signal?: AbortSignal
  ): Promise<BitwardenEmailTwoFactorSetup> {
    try {
      assertSyncSecret(masterPassword)
      this.requireProfileId()
      const masterPasswordHash = await this.deriveMasterPasswordHash(masterPassword, signal)
      const setup = await this.http.getEmailTwoFactorSetup(masterPasswordHash, signal)
      await this.captureSession()
      return setup
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async sendEmailTwoFactorSetup(
    request: {
      email: string
      verificationMode: BitwardenEmailTwoFactorSetup['verificationMode']
      userVerificationToken?: string
      masterPassword?: string
    },
    signal?: AbortSignal
  ): Promise<void> {
    let mutationStarted = false
    try {
      let masterPasswordHash: string | undefined
      if (request.verificationMode === 'master-password') {
        const password = request.masterPassword
        assertSyncSecret(password)
        masterPasswordHash = await this.deriveMasterPasswordHash(password, signal)
      }
      mutationStarted = true
      await this.http.sendEmailTwoFactorSetup(
        {
          email: request.email,
          verificationMode: request.verificationMode,
          ...(request.userVerificationToken
            ? { userVerificationToken: request.userVerificationToken }
            : {}),
          ...(masterPasswordHash ? { masterPasswordHash } : {})
        },
        signal
      )
      await this.captureSession()
    } catch (error) {
      const mapped = this.mapError(error)
      if (mutationStarted && mapped.code === 'NETWORK') {
        throw new BitwardenDirectError('TWO_FACTOR_MUTATION_UNKNOWN')
      }
      throw mapped
    } finally {
      if (request.masterPassword !== undefined) request.masterPassword = ''
      if (request.userVerificationToken !== undefined) request.userVerificationToken = ''
    }
  }

  async completeEmailTwoFactorSetup(
    request: {
      email: string
      token: string
      verificationMode: BitwardenEmailTwoFactorSetup['verificationMode']
      userVerificationToken?: string
      masterPassword?: string
    },
    signal?: AbortSignal
  ): Promise<void> {
    let mutationStarted = false
    try {
      let masterPasswordHash: string | undefined
      if (request.verificationMode === 'master-password') {
        const password = request.masterPassword
        assertSyncSecret(password)
        masterPasswordHash = await this.deriveMasterPasswordHash(password, signal)
      }
      mutationStarted = true
      await this.http.enableEmailTwoFactor(
        {
          email: request.email,
          token: request.token,
          verificationMode: request.verificationMode,
          ...(request.userVerificationToken
            ? { userVerificationToken: request.userVerificationToken }
            : {}),
          ...(masterPasswordHash ? { masterPasswordHash } : {})
        },
        signal
      )
      await this.captureSession()
    } catch (error) {
      const mapped = this.mapError(error)
      if (mutationStarted && mapped.code === 'NETWORK') {
        throw new BitwardenDirectError('TWO_FACTOR_MUTATION_UNKNOWN')
      }
      throw mapped
    } finally {
      request.token = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      if (request.userVerificationToken !== undefined) request.userVerificationToken = ''
    }
  }

  async beginWebAuthnSetup(
    masterPassword: string,
    signal?: AbortSignal
  ): Promise<BitwardenWebAuthnRegistrationSetup> {
    let masterPasswordHash = ''
    let setup: BitwardenWebAuthnSetup | null = null
    try {
      assertSyncSecret(masterPassword)
      this.requireProfileId()
      masterPasswordHash = await this.deriveMasterPasswordHash(masterPassword, signal)
      setup = await this.http.getWebAuthnSetup(masterPasswordHash, signal)
      const registrationChallenge = await this.http.getWebAuthnRegistrationChallenge(
        setup.verificationMode === 'server-token'
          ? {
              verificationMode: 'server-token',
              userVerificationToken: setup.userVerificationToken!
            }
          : { verificationMode: 'master-password', masterPasswordHash },
        signal
      )
      await this.captureSession()
      return {
        enabled: setup.enabled,
        keys: setup.keys.map((key) => ({ ...key })),
        registrationId: nextWebAuthnRegistrationId(setup.keys),
        registrationChallenge,
        verificationMode: setup.verificationMode,
        userVerificationToken: setup.userVerificationToken
      }
    } catch (error) {
      throw this.mapError(error)
    } finally {
      masterPasswordHash = ''
      if (setup) {
        setup.userVerificationToken = null
        setup.keys.splice(0)
      }
    }
  }

  async completeWebAuthnSetup(
    request: BitwardenWebAuthnRegistrationRequest,
    signal?: AbortSignal
  ): Promise<void> {
    let masterPasswordHash = ''
    let mutationStarted = false
    try {
      if (
        !Number.isSafeInteger(request.id) ||
        request.id < 1 ||
        request.id > MAX_WEBAUTHN_REGISTRATION_SLOTS
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      this.requireProfileId()
      if (request.verificationMode === 'master-password') {
        const password = request.masterPassword
        assertSyncSecret(password)
        masterPasswordHash = await this.deriveMasterPasswordHash(password, signal)
      }
      mutationStarted = true
      await this.http.enableWebAuthn(
        {
          id: request.id,
          name: request.name,
          attestation: request.attestation,
          verificationMode: request.verificationMode,
          ...(request.userVerificationToken
            ? { userVerificationToken: request.userVerificationToken }
            : {}),
          ...(masterPasswordHash ? { masterPasswordHash } : {})
        },
        signal
      )
      await this.captureSession()
    } catch (error) {
      const mapped = this.mapError(error)
      if (mutationStarted && mapped.code === 'NETWORK') {
        throw new BitwardenDirectError('TWO_FACTOR_MUTATION_UNKNOWN')
      }
      throw mapped
    } finally {
      masterPasswordHash = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      if (request.userVerificationToken !== undefined) request.userVerificationToken = ''
      clearAccountWebAuthnAttestation(request.attestation)
    }
  }

  async deleteWebAuthnKey(id: number, masterPassword: string, signal?: AbortSignal): Promise<void> {
    let masterPasswordHash = ''
    let setup: BitwardenWebAuthnSetup | null = null
    let mutationStarted = false
    try {
      if (
        !Number.isSafeInteger(id) ||
        id < 1 ||
        typeof masterPassword !== 'string' ||
        masterPassword.length === 0 ||
        masterPassword.length > MAX_SYNC_SECRET_LENGTH
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      this.requireProfileId()
      masterPasswordHash = await this.deriveMasterPasswordHash(masterPassword, signal)
      setup = await this.http.getWebAuthnSetup(masterPasswordHash, signal)
      if (!setup.keys.some((key) => key.id === id)) throw new BitwardenDirectError('NOT_FOUND')
      mutationStarted = true
      await this.http.deleteWebAuthnKey(
        setup.verificationMode === 'server-token'
          ? {
              id,
              verificationMode: 'server-token',
              userVerificationToken: setup.userVerificationToken!
            }
          : { id, verificationMode: 'master-password', masterPasswordHash },
        signal
      )
      await this.captureSession()
    } catch (error) {
      const mapped = this.mapError(error)
      if (mutationStarted && mapped.code === 'NETWORK') {
        throw new BitwardenDirectError('TWO_FACTOR_MUTATION_UNKNOWN')
      }
      throw mapped
    } finally {
      masterPasswordHash = ''
      if (setup) {
        setup.userVerificationToken = null
        setup.keys.splice(0)
      }
    }
  }

  async getEquivalentDomainSettings(
    signal?: AbortSignal
  ): Promise<BitwardenEquivalentDomainSettings> {
    if (this.syncedEquivalentDomainSettings) {
      return structuredClone(this.syncedEquivalentDomainSettings)
    }
    try {
      return await this.http.getEquivalentDomainSettings(signal)
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async getAuthoritativeEquivalentDomainSettings(
    signal?: AbortSignal
  ): Promise<BitwardenEquivalentDomainSettings> {
    try {
      return await this.http.getEquivalentDomainSettings(signal)
    } catch (error) {
      throw this.mapError(error)
    }
  }

  isolatedPersonalCipherIds(): readonly string[] {
    return [...this.isolatedPersonalCiphers]
  }

  async updateEquivalentDomainSettings(
    update: BitwardenEquivalentDomainUpdate,
    signal?: AbortSignal
  ): Promise<void> {
    // The following read must be authoritative even if the mutation fails after dispatch.
    this.syncedEquivalentDomainSettings = null
    try {
      await this.http.updateEquivalentDomainSettings(update, signal)
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async listSends(signal?: AbortSignal): Promise<BitwardenSendItem[]> {
    void signal
    this.requireUserKey()
    return [...this.sends.values()].map(({ item }) => ({ ...item }))
  }

  async createSend(draft: BitwardenSendDraft, signal?: AbortSignal): Promise<BitwardenSendItem> {
    const userKey = this.requireUserKey()
    const request = await this.encryptSendRequest(draft, userKey)
    try {
      const raw = await this.http.createSend(request, signal)
      const cached = decryptSend(raw, userKey)
      this.sends.set(cached.item.id, cached)
      return { ...cached.item }
    } catch (error) {
      throw this.mapError(error)
    } finally {
      request.key = ''
      request.name = ''
      request.notes = null
      request.text.text = ''
      request.password = null
    }
  }

  async createFileSend(
    draft: BitwardenFileSendDraft,
    signal?: AbortSignal
  ): Promise<BitwardenSendItem> {
    const userKey = this.requireUserKey()
    if (
      typeof draft.fileName !== 'string' ||
      draft.fileName.length === 0 ||
      draft.fileName.length > MAX_SEND_FILE_NAME_LENGTH ||
      /[\0\r\n/\\]/u.test(draft.fileName) ||
      !Buffer.isBuffer(draft.data) ||
      draft.data.length > MAX_SEND_FILE_PLAINTEXT_BYTES
    ) {
      throw new BitwardenDirectError(
        Buffer.isBuffer(draft.data) && draft.data.length > MAX_SEND_FILE_PLAINTEXT_BYTES
          ? 'TOO_LARGE'
          : 'INVALID_RESPONSE'
      )
    }
    const seed = randomBytes(16)
    let sendKey: Buffer | null = null
    let encryptedData: Buffer | null = null
    let createdId: string | null = null
    let uploaded = false
    let request: BitwardenSendFileRequest | null = null
    try {
      sendKey = deriveBitwardenSendKey(seed)
      const encryptedFileName = encryptBitwardenString(draft.fileName, sendKey)
      encryptedData = encryptBitwardenAttachmentBuffer(draft.data, sendKey)
      const password = draft.password?.length ? draft.password : null
      const authType = password ? 1 : 2
      request = {
        type: 1,
        fileLength: encryptedData.length,
        authType,
        name: encryptBitwardenString(draft.name, sendKey),
        notes: draft.notes === null ? null : encryptBitwardenString(draft.notes, sendKey),
        key: encryptBitwardenBytes(seed, userKey),
        maxAccessCount: draft.maxAccessCount,
        expirationDate: draft.expirationDate,
        deletionDate: draft.deletionDate,
        file: { fileName: encryptedFileName },
        password: null,
        emails: null,
        disabled: draft.disabled,
        hideEmail: draft.hideEmail
      }
      if (password) {
        const passwordHash = await deriveBitwardenSendPasswordHash(password, seed)
        try {
          request.password = passwordHash.toString('base64')
        } finally {
          passwordHash.fill(0)
        }
      }
      const upload = await this.http.createFileSend(request, signal)
      createdId = assertUuidValue(requiredStringProperty(upload.sendResponse, 'id'))
      if (upload.fileUploadType !== 'direct') throw new BitwardenDirectError('INVALID_RESPONSE')
      const created = decryptSend(upload.sendResponse, userKey)
      if (
        created.item.type !== 'file' ||
        !created.item.file ||
        created.item.file.fileName !== draft.fileName
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      this.sends.set(created.item.id, created)
      await this.http.uploadSendFileDirect(
        created.item.id,
        created.item.file.id,
        encryptedFileName,
        encryptedData,
        signal
      )
      uploaded = true
      await this.sync(signal)
      const confirmed = this.sends.get(created.item.id)
      if (
        !confirmed ||
        confirmed.item.type !== 'file' ||
        !confirmed.item.file ||
        confirmed.item.file.fileName !== draft.fileName
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      return {
        ...confirmed.item,
        file: { ...confirmed.item.file }
      }
    } catch (error) {
      if (createdId && !uploaded) {
        await this.http.deleteSend(createdId).catch(() => undefined)
        this.sends.delete(createdId)
      }
      throw this.mapError(error)
    } finally {
      if (request) {
        request.key = ''
        request.name = ''
        request.notes = null
        request.file.fileName = ''
        request.password = null
      }
      seed.fill(0)
      sendKey?.fill(0)
      encryptedData?.fill(0)
    }
  }

  async downloadFileSend(
    id: string,
    password: string | null,
    signal?: AbortSignal
  ): Promise<BitwardenDownloadedAttachment> {
    this.requireUserKey()
    const cached = this.sends.get(assertUuidValue(id))
    if (!cached || cached.item.type !== 'file' || !cached.item.file) {
      throw new BitwardenDirectError('NOT_FOUND')
    }
    if (
      password !== null &&
      (typeof password !== 'string' || password.length > MAX_SYNC_SECRET_LENGTH)
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    const userKey = this.requireUserKey()
    let seed: Buffer | null = null
    let sendKey: Buffer | null = null
    let encrypted: Buffer | null = null
    let plaintext: Buffer | null = null
    try {
      seed = decryptBitwardenBytes(requiredStringProperty(cached.raw, 'key'), userKey)
      if (seed.length !== 16) throw new BitwardenDirectError('INVALID_RESPONSE')
      sendKey = deriveBitwardenSendKey(seed)
      const access = await this.http.getSendAccess(cached.item.accessId, password, signal)
      const accessId = assertUuidValue(requiredStringProperty(access, 'id'))
      const accessType = readField(access, 'type')
      const accessFile = recordProperty(access, 'file')
      if (accessId !== cached.item.id || accessType !== 1 || !accessFile) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const fileId = requiredStringProperty(accessFile, 'id')
      const encryptedFileName = requiredStringProperty(accessFile, 'fileName')
      const fileName = decryptBitwardenString(encryptedFileName, sendKey)
      const size = sendFileSize(readField(accessFile, 'size'))
      if (
        fileId !== cached.item.file.id ||
        fileName !== cached.item.file.fileName ||
        !Number.isSafeInteger(size) ||
        size !== cached.item.file.size
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const download = await this.http.getSendFileDownload(
        cached.item.id,
        fileId,
        password,
        size,
        signal
      )
      encrypted = await download.download(signal)
      if (encrypted.length !== size) throw new BitwardenDirectError('INVALID_RESPONSE')
      plaintext = decryptBitwardenAttachmentBuffer(encrypted, sendKey)
      const result: BitwardenDownloadedAttachment = { fileName, data: plaintext }
      plaintext = null
      return result
    } catch (error) {
      if (error instanceof BitwardenCryptoError && error.code === 'AUTHENTICATION_FAILED') {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      throw this.mapError(error)
    } finally {
      seed?.fill(0)
      sendKey?.fill(0)
      encrypted?.fill(0)
      plaintext?.fill(0)
    }
  }

  async updateSend(
    id: string,
    draft: BitwardenSendDraft,
    signal?: AbortSignal
  ): Promise<BitwardenSendItem> {
    const userKey = this.requireUserKey()
    const cached = this.sends.get(assertUuidValue(id))
    if (!cached) throw new BitwardenDirectError('NOT_FOUND')
    if (cached.item.type !== 'text') throw new BitwardenDirectError('INVALID_RESPONSE')
    const request = await this.encryptSendRequest(draft, userKey, cached.raw)
    try {
      const raw = await this.http.updateSend(cached.item.id, request, signal)
      const next = decryptSend(raw, userKey)
      this.sends.set(next.item.id, next)
      return { ...next.item }
    } catch (error) {
      throw this.mapError(error)
    } finally {
      request.key = ''
      request.name = ''
      request.notes = null
      request.text.text = ''
      request.password = null
    }
  }

  async removeSendPassword(id: string, signal?: AbortSignal): Promise<BitwardenSendItem> {
    this.requireUserKey()
    const cached = this.sends.get(assertUuidValue(id))
    if (!cached) throw new BitwardenDirectError('NOT_FOUND')
    try {
      const raw = await this.http.removeSendPassword(cached.item.id, signal)
      const next = decryptSend(raw, this.requireUserKey())
      this.sends.set(next.item.id, next)
      return { ...next.item }
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async deleteSend(id: string, signal?: AbortSignal): Promise<void> {
    this.requireUserKey()
    const cached = this.sends.get(assertUuidValue(id))
    if (!cached) throw new BitwardenDirectError('NOT_FOUND')
    try {
      await this.http.deleteSend(cached.item.id, signal)
      this.sends.delete(cached.item.id)
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async copySendLink(id: string, copy: (value: string) => void | Promise<void>): Promise<void> {
    const userKey = this.requireUserKey()
    const cached = this.sends.get(assertUuidValue(id))
    if (!cached) throw new BitwardenDirectError('NOT_FOUND')
    const encryptedKey = requiredStringProperty(cached.raw, 'key')
    const seed = decryptBitwardenBytes(encryptedKey, userKey)
    try {
      if (seed.length !== 16) throw new BitwardenDirectError('INVALID_RESPONSE')
      const accessId = requiredStringProperty(cached.raw, 'accessId')
      await copy(`${this.http.sendUrl()}${accessId}/${seed.toString('base64url')}`)
    } finally {
      seed.fill(0)
    }
  }

  async notificationAccessToken(signal?: AbortSignal): Promise<string> {
    try {
      const token = await this.http.activeAccessToken(signal)
      await this.captureSession()
      return token
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async getLoginRequest(id: string, signal?: AbortSignal): Promise<BitwardenLoginApprovalRequest> {
    this.requireUserKey()
    try {
      return loginRequestMetadata(this.email, await this.http.getAuthRequest(id, signal))
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async listPendingLoginRequests(signal?: AbortSignal): Promise<BitwardenLoginApprovalRequest[]> {
    this.requireUserKey()
    try {
      const requests = await this.http.getPendingAuthRequests(signal)
      return requests.map((request) => loginRequestMetadata(this.email, request))
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async respondLoginRequest(
    id: string,
    expectedFingerprint: string,
    approved: boolean,
    signal?: AbortSignal
  ): Promise<void> {
    const userKey = this.requireUserKey()
    if (
      typeof expectedFingerprint !== 'string' ||
      expectedFingerprint.length === 0 ||
      expectedFingerprint.length > 1_024 ||
      /[\0\r\n]/u.test(expectedFingerprint) ||
      typeof approved !== 'boolean'
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    let encodedUserKey: Buffer | null = null
    let publicKey: Buffer | null = null
    let encryptedUserKey: Buffer | null = null
    try {
      // Re-fetch immediately before encrypting and responding so stale UI metadata cannot approve
      // a replacement request with the same id but different key material.
      const request = await this.http.getAuthRequest(id, signal)
      const currentFingerprint = loginRequestFingerprint(this.email, request)
      if (currentFingerprint !== expectedFingerprint) throw new BitwardenDirectError('CONFLICT')
      encodedUserKey = encodeUserKeyForMasterKeyWrap(userKey)
      publicKey = Buffer.from(request.publicKey, 'base64')
      encryptedUserKey = publicEncrypt(
        {
          key: createPublicKey({ key: publicKey, format: 'der', type: 'spki' }),
          padding: constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha1'
        },
        encodedUserKey
      )
      await this.http.respondAuthRequest(
        request.id,
        {
          key: `4.${encryptedUserKey.toString('base64')}`,
          masterPasswordHash: null,
          deviceIdentifier: this.state.deviceIdentifier,
          requestApproved: approved
        },
        signal
      )
    } catch (error) {
      throw this.mapError(error)
    } finally {
      encodedUserKey?.fill(0)
      publicKey?.fill(0)
      encryptedUserKey?.fill(0)
    }
  }

  async login(request: BitwardenLoginRequest): Promise<void> {
    if (normalizeEmail(request.email) !== this.email) {
      throw new BitwardenDirectError('AUTH_REQUIRED')
    }
    await this.deriveAndAuthenticate(
      request.password,
      request.twoFactor,
      request.newDeviceOtp,
      true,
      request.signal
    )
  }

  async sendEmailTwoFactorLoginCode(masterPassword: string, signal?: AbortSignal): Promise<void> {
    let masterPasswordHash = ''
    try {
      assertSyncSecret(masterPassword)
      masterPasswordHash = await this.deriveMasterPasswordHash(masterPassword, signal)
      if (signal?.aborted) throw new BitwardenDirectError('ABORTED')
      await this.http.sendEmailTwoFactorLoginCode(
        {
          email: this.email,
          masterPasswordHash,
          deviceIdentifier: this.state.deviceIdentifier,
          deviceType: this.deviceType
        },
        signal
      )
    } catch (error) {
      throw this.mapError(error)
    } finally {
      masterPassword = ''
      masterPasswordHash = ''
    }
  }

  async resendNewDeviceOtp(masterPassword: string, signal?: AbortSignal): Promise<void> {
    let masterPasswordHash = ''
    try {
      assertSyncSecret(masterPassword)
      masterPasswordHash = await this.deriveMasterPasswordHash(masterPassword, signal)
      if (signal?.aborted) throw new BitwardenDirectError('ABORTED')
      await this.http.resendNewDeviceOtp({ email: this.email, masterPasswordHash }, signal)
    } catch (error) {
      throw this.mapError(error)
    } finally {
      masterPassword = ''
      masterPasswordHash = ''
    }
  }

  async revisionDate(signal?: AbortSignal): Promise<string> {
    try {
      return await this.http.revisionDate(signal)
    } catch (error) {
      throw this.mapError(error)
    }
  }

  userDecryptionCapabilities(): BitwardenUserDecryptionCapabilities {
    return { ...this.syncedUserDecryptionCapabilities }
  }

  policySet(): BitwardenPolicySet {
    return restorePolicySet(this.state.policySet)
  }

  async unlock(request: BitwardenUnlockRequest): Promise<void> {
    await this.deriveAndAuthenticate(
      request.password,
      request.twoFactor,
      request.newDeviceOtp,
      !this.http.exportSession() ||
        request.twoFactor !== undefined ||
        request.newDeviceOtp !== undefined,
      request.signal
    )
  }

  async sync(signal?: AbortSignal): Promise<void> {
    const previous = this.syncQueue
    let acquired = false
    let release!: () => void
    this.syncQueue = new Promise<void>((resolve) => {
      release = resolve
    })
    try {
      await this.waitForSyncTurn(previous, signal)
      acquired = true
      await this.performSync(signal)
    } finally {
      if (acquired) release()
      else void previous.then(release)
    }
  }

  private async performSync(signal?: AbortSignal): Promise<void> {
    let invalidResponseStage: SyncInvalidResponseStage | null = 'access-token'
    let wrappedKeyFingerprint: Buffer | null = null
    const pendingMasterKey = this.pendingMasterKey
    const operationGeneration = this.runtimeGeneration
    let accountIdentityChange: 'profile' | 'security-stamp' | null = null
    let accountKeysValidated = false
    try {
      // Match the official client flow by refreshing a known-expiring token before `/sync`.
      // Waiting for a raw 401 is not sufficient when an authentication proxy rewrites it.
      await this.http.activeAccessToken(signal)
      invalidResponseStage = 'response'
      const payload = await this.http.sync(signal)
      invalidResponseStage = 'account'
      const profile = recordProperty(payload, 'profile')
      if (!profile) throw new BitwardenDirectError('INVALID_RESPONSE')
      const profileId = requiredStringProperty(profile, 'id')
      const securityStamp = nullableStringProperty(profile, 'securityStamp')
      accountIdentityChange = this.accountIdentityChange(profileId, securityStamp)
      if (accountIdentityChange) throw new BitwardenDirectError('ACCOUNT_CHANGED')
      const nextUserDecryptionCapabilities = parseUserDecryptionCapabilities(payload)

      const wrappedUserKey = findWrappedUserKey(payload, profile)
      wrappedKeyFingerprint = createHash('sha256').update(wrappedUserKey, 'utf8').digest()
      const requiresLegacyUserKeyProof =
        pendingMasterKey !== null && isBitwardenLegacyMasterKeyWrappedUserKey(wrappedUserKey)
      const userKey = this.unwrapSyncUserKey(
        wrappedUserKey,
        wrappedKeyFingerprint,
        pendingMasterKey
      )
      try {
        await validateAccountKeys(profile, userKey)
        if (requiresLegacyUserKeyProof && resolveAccountPrivateKey(profile, userKey) === null) {
          throw new BitwardenDirectError('INVALID_RESPONSE')
        }
      } catch (error) {
        clearBitwardenSymmetricKey(userKey)
        throw error
      }
      accountKeysValidated = true

      let snapshot: DecodedSyncSnapshot
      try {
        snapshot = decodeSyncPayload(payload, profile, userKey)
      } catch (error) {
        clearBitwardenSymmetricKey(userKey)
        if (!(error instanceof SyncPayloadError)) throw error
        invalidResponseStage = error.stage
        throw error.cause
      }
      invalidResponseStage = null

      if (operationGeneration !== this.runtimeGeneration) {
        clearBitwardenSymmetricKey(userKey)
        for (const organizationKey of snapshot.organizationKeys.values()) organizationKey.fill(0)
        throw new BitwardenDirectError(this.http.exportSession() ? 'ABORTED' : 'AUTH_REQUIRED')
      }
      this.runtimeGeneration += 1
      clearBitwardenSymmetricKey(this.userKey)
      this.wrappedUserKeyFingerprint?.fill(0)
      this.userKey = userKey
      this.wrappedUserKeyFingerprint = wrappedKeyFingerprint
      wrappedKeyFingerprint = null
      this.folders = snapshot.folders
      this.logins = snapshot.logins
      this.organizations = snapshot.organizations
      this.collections = snapshot.collections
      this.organizationCiphers = snapshot.organizationCiphers
      this.organizationCipherRaws = snapshot.organizationCipherRaws
      for (const organizationKey of this.organizationKeys.values()) organizationKey.fill(0)
      this.organizationKeys = snapshot.organizationKeys
      this.sends = snapshot.sends
      this.isolatedPersonalCiphers = snapshot.isolatedPersonalCiphers
      this.syncedEquivalentDomainSettings = structuredClone(snapshot.equivalentDomainSettings)
      this.syncedUserDecryptionCapabilities = nextUserDecryptionCapabilities
      this.state.profileId = profileId
      this.state.securityStamp = securityStamp
      this.state.policySet = snapshot.policySet
      const session = this.http.exportSession()
      this.state.session = session ? this.normalizedSession(session) : null
      await this.notifyStateChanged()
    } catch (error) {
      const mapped =
        accountKeysValidated &&
        error instanceof BitwardenCryptoError &&
        error.code === 'AUTHENTICATION_FAILED'
          ? new BitwardenDirectError('INVALID_RESPONSE')
          : this.mapError(error)
      if (mapped.code === 'ACCOUNT_CHANGED' && accountIdentityChange === 'security-stamp') {
        if (operationGeneration !== this.runtimeGeneration) {
          throw new BitwardenDirectError('ABORTED')
        }
        // A changed security stamp is recoverable through a fresh password login. Keep the
        // profile binding so a different account cannot be merged into the existing vault.
        await this.clearDeauthorizedSession().catch(() => undefined)
        throw new BitwardenDirectError('AUTH_REQUIRED')
      }
      if (
        error instanceof BitwardenHttpError &&
        (error.code === 'AUTH' || error.code === 'SESSION_EXPIRED')
      ) {
        if (operationGeneration !== this.runtimeGeneration) {
          throw new BitwardenDirectError('ABORTED')
        }
        await this.clearDeauthorizedSession().catch(() => undefined)
      }
      if (
        mapped.code === 'INVALID_RESPONSE' &&
        !mapped.syncInvalidResponseStage &&
        invalidResponseStage
      ) {
        const diagnosticStage =
          mapped.syncInvalidResponseReason === 'session-response'
            ? 'access-token'
            : invalidResponseStage
        throw new BitwardenDirectError(
          'INVALID_RESPONSE',
          undefined,
          diagnosticStage,
          undefined,
          mapped.syncInvalidResponseReason ?? DEFAULT_SYNC_INVALID_REASON[invalidResponseStage]
        )
      }
      throw mapped
    } finally {
      wrappedKeyFingerprint?.fill(0)
      pendingMasterKey?.fill(0)
      if (this.pendingMasterKey === pendingMasterKey) this.pendingMasterKey = null
    }
  }

  /** Returns a caller-owned user key for `wrappedUserKey`, or clears state when none applies. */
  private unwrapSyncUserKey(
    wrappedUserKey: string,
    wrappedKeyFingerprint: Buffer,
    pendingMasterKey: Buffer | null
  ): BitwardenSymmetricKey {
    if (pendingMasterKey) {
      return decryptBitwardenMasterKeyWrappedUserKey(wrappedUserKey, pendingMasterKey)
    }
    if (this.userKey && this.wrappedUserKeyFingerprint?.equals(wrappedKeyFingerprint)) {
      return cloneBitwardenAccountKey(this.userKey)
    }
    if (isBitwardenLegacyMasterKeyWrappedUserKey(wrappedUserKey)) {
      this.clearDecryptedState()
      throw new BitwardenDirectError('AUTH_REQUIRED')
    }
    if (this.stretchedKey) {
      const encodedUserKey = decryptBitwardenBytes(wrappedUserKey, this.stretchedKey)
      try {
        return decodeBitwardenUserKey(encodedUserKey)
      } finally {
        encodedUserKey.fill(0)
      }
    }
    if (
      !this.wrappedUserKeyFingerprint ||
      !this.wrappedUserKeyFingerprint.equals(wrappedKeyFingerprint)
    ) {
      this.clearDecryptedState()
      throw new BitwardenDirectError('AUTH_REQUIRED')
    }
    return cloneBitwardenAccountKey(this.requireUserKey())
  }

  private async waitForSyncTurn(previous: Promise<void>, signal?: AbortSignal): Promise<void> {
    if (!signal) {
      await previous
      return
    }
    if (signal.aborted) throw new BitwardenDirectError('ABORTED')
    await new Promise<void>((resolve, reject) => {
      let settled = false
      const cleanup = (): void => signal.removeEventListener('abort', onAbort)
      const finish = (callback: () => void): void => {
        if (settled) return
        settled = true
        cleanup()
        callback()
      }
      const onAbort = (): void => finish(() => reject(new BitwardenDirectError('ABORTED')))
      signal.addEventListener('abort', onAbort, { once: true })
      void previous.then(() => finish(resolve))
      if (signal.aborted) onAbort()
    })
  }

  async listFolders(): Promise<BitwardenFolder[]> {
    this.requireUserKey()
    return [...this.folders.values()].map(({ item }) => ({ ...item }))
  }

  async listPersonalLogins(): Promise<BitwardenLoginItem[]> {
    this.requireUserKey()
    return [...this.logins.values()].map(({ item }) => cloneLoginItem(item))
  }

  async listOrganizations(): Promise<BitwardenOrganization[]> {
    this.requireUserKey()
    return [...this.organizations.values()].map((organization) => ({ ...organization }))
  }

  async listCollections(): Promise<BitwardenCollection[]> {
    this.requireUserKey()
    return [...this.collections.values()].map((collection) => ({ ...collection }))
  }

  async listOrganizationCiphers(): Promise<BitwardenOrganizationCipher[]> {
    this.requireUserKey()
    return [...this.organizationCiphers.values()].map(cloneOrganizationCipher)
  }

  async createOrganizationCipher(
    organizationId: string,
    collectionIds: string[],
    draft: BitwardenLoginDraft,
    signal?: AbortSignal
  ): Promise<BitwardenOrganizationCipher> {
    this.requireUserKey()
    const organizationKey = this.organizationKeys.get(organizationId)
    if (!organizationKey) throw new BitwardenDirectError('INVALID_RESPONSE')
    const itemKey = randomBytes(USER_KEY_BYTES)
    try {
      const request = encryptLoginRequest(
        resolveDraft(draft, null),
        itemKey,
        null,
        this.loginRequestAccount()
      )
      request.organizationId = organizationId
      request.folderId = null
      request.collectionIds = [...collectionIds]
      request.key = encryptBitwardenBytes(itemKey, organizationKey, 'legacy-key')
      const response = await this.http.createCipher(request, signal)
      const raw = responseEntity(response, 'cipher')
      if (readField(raw, 'organizationId') !== organizationId) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const item = decryptLogin(raw, organizationKey)
      const parsed = organizationCipher(raw, item, organizationId)
      const selectedCollectionIds = new Set(collectionIds)
      if (
        parsed.collectionIds.length !== collectionIds.length ||
        parsed.collectionIds.some((collectionId) => !selectedCollectionIds.has(collectionId))
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const created: BitwardenOrganizationCipher = {
        ...parsed,
        collectionIds: [...collectionIds],
        edit: true,
        viewPassword: true,
        delete: false,
        restore: false
      }
      this.organizationCiphers.set(created.id, created)
      this.organizationCipherRaws.set(created.id, structuredClone(raw))
      await this.captureSession()
      return cloneOrganizationCipher(created)
    } catch (error) {
      throw this.mapError(error)
    } finally {
      itemKey.fill(0)
    }
  }

  async editOrganizationCipher(
    id: string,
    draft: BitwardenLoginDraft,
    signal?: AbortSignal
  ): Promise<BitwardenOrganizationCipher> {
    this.requireUserKey()
    const cached = this.organizationCiphers.get(id)
    const raw = this.organizationCipherRaws.get(id)
    if (!cached || !raw || !cached.edit) throw new BitwardenDirectError('INVALID_RESPONSE')
    const organizationKey = this.organizationKeys.get(cached.organizationId)
    if (!organizationKey) throw new BitwardenDirectError('INVALID_RESPONSE')
    const itemKey = cipherKey(raw, organizationKey)
    try {
      const resolved = resolveDraft(
        {
          ...draft,
          folderId: cached.folderId,
          favorite: cached.favorite,
          reprompt: cached.reprompt
        },
        { ...cached, organizationId: null }
      )
      const request = encryptLoginRequest(resolved, itemKey, raw, this.loginRequestAccount())
      request.organizationId = cached.organizationId
      request.collectionIds = [...cached.collectionIds]
      const response = await this.http.updateCipher(id, request, signal)
      const nextRaw = responseEntity(response, 'cipher')
      if (
        readField(nextRaw, 'organizationId') !== cached.organizationId ||
        requiredStringProperty(nextRaw, 'id') !== id
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const item = decryptLogin(nextRaw, organizationKey)
      const parsed = organizationCipher(nextRaw, item, cached.organizationId)
      const responseCollectionIds = readField(nextRaw, 'collectionIds')
      const cachedCollectionIds = new Set(cached.collectionIds)
      if (
        responseCollectionIds !== undefined &&
        responseCollectionIds !== null &&
        (parsed.collectionIds.length !== cached.collectionIds.length ||
          parsed.collectionIds.some((collectionId) => !cachedCollectionIds.has(collectionId)))
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const updated: BitwardenOrganizationCipher = {
        ...parsed,
        collectionIds: [...cached.collectionIds],
        edit: cached.edit,
        viewPassword: cached.viewPassword,
        delete: cached.delete,
        restore: cached.restore
      }
      this.organizationCiphers.set(id, updated)
      this.organizationCipherRaws.set(id, structuredClone(nextRaw))
      await this.captureSession()
      return cloneOrganizationCipher(updated)
    } catch (error) {
      throw this.mapError(error)
    } finally {
      if (itemKey !== organizationKey) clearBitwardenSymmetricKey(itemKey)
    }
  }

  async listEmergencyAccess(signal?: AbortSignal): Promise<BitwardenEmergencyAccess[]> {
    this.requireUserKey()
    try {
      return await this.http.listEmergencyAccess(signal)
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async downloadAttachment(
    id: string,
    attachmentId: string,
    signal?: AbortSignal
  ): Promise<BitwardenDownloadedAttachment> {
    const userKey = this.requireUserKey()
    if (signal?.aborted) throw new BitwardenDirectError('ABORTED')

    const cached = this.logins.get(id)
    const expected = cached?.item.attachments.find((attachment) => attachment.id === attachmentId)
    if (!cached || !expected) throw new BitwardenDirectError('INVALID_RESPONSE')

    let itemKey: BitwardenSymmetricKey | null = null
    let attachmentKey: Buffer | null = null
    let encrypted: Buffer | null = null
    let plaintext: Buffer | null = null
    try {
      itemKey = cipherKey(cached.raw, userKey)
      // Attachment file encryption remains an AES file format, including for a
      // V2 account whose user key is COSE/XChaCha.  The per-item key must be a
      // legacy 64-byte key before it can unwrap the attachment CEK.
      if (!Buffer.isBuffer(itemKey) || itemKey.length !== USER_KEY_BYTES) {
        throw new BitwardenDirectError('UNSUPPORTED_ACCOUNT_ENCRYPTION')
      }

      // Do not fall back to a URL retained in the sync response: the HTTP
      // layer resolves a fresh short-lived capability immediately before the
      // binary request and keeps that URL private to itself.
      const response = await this.http.prepareAttachmentDownload(id, attachmentId, signal)
      const metadata = freshAttachmentMetadata(response, expected, itemKey)

      if (metadata.encryptedKey === null) {
        attachmentKey = itemKey
      } else {
        attachmentKey = decryptBitwardenWrappedKey(metadata.encryptedKey, itemKey)
        if (attachmentKey.length !== USER_KEY_BYTES) {
          attachmentKey.fill(0)
          attachmentKey = null
          throw new BitwardenDirectError('INVALID_RESPONSE')
        }
      }

      // Fetch only after the fresh encrypted filename, key mode, and size match
      // the authenticated cached item. This prevents stale metadata from forcing
      // a large allocation or consuming the one-time signed URL.
      encrypted = await response.download(signal)
      if (encrypted.length !== metadata.size) throw new BitwardenDirectError('INVALID_RESPONSE')
      plaintext = decryptBitwardenAttachmentBuffer(encrypted, attachmentKey)
      const result: BitwardenDownloadedAttachment = { fileName: expected.fileName, data: plaintext }
      plaintext = null // Transfer ownership to the main-process file writer.
      return result
    } catch (error) {
      // A file MAC is authenticated by an already-unlocked local key; it is
      // corrupt remote data, not evidence that the user's master password is
      // wrong. Do not turn it into an unlock prompt.
      if (error instanceof BitwardenCryptoError && error.code === 'AUTHENTICATION_FAILED') {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      throw this.mapError(error)
    } finally {
      encrypted?.fill(0)
      plaintext?.fill(0)
      if (attachmentKey && attachmentKey !== itemKey) attachmentKey.fill(0)
      if (itemKey && itemKey !== userKey) clearBitwardenSymmetricKey(itemKey)
    }
  }

  async uploadAttachment(
    id: string,
    fileName: string,
    data: Buffer,
    signal?: AbortSignal,
    onCommitted?: () => void
  ): Promise<BitwardenAttachment> {
    try {
      return await this.uploadAttachmentInternal(id, fileName, data, null, signal, onCommitted)
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async downloadAttachmentStream(
    id: string,
    attachmentId: string,
    signal?: AbortSignal
  ): Promise<BitwardenStreamedAttachment> {
    const userKey = this.requireUserKey()
    if (signal?.aborted) throw new BitwardenDirectError('ABORTED')
    const cached = this.logins.get(id)
    const expected = cached?.item.attachments.find((attachment) => attachment.id === attachmentId)
    if (!cached || !expected) throw new BitwardenDirectError('INVALID_RESPONSE')

    let itemKey: BitwardenSymmetricKey | null = null
    let attachmentKey: Buffer | null = null
    let streamKey: Buffer | null = null
    let encryptedFile: BitwardenEncryptedAttachmentFile | null = null
    try {
      itemKey = cipherKey(cached.raw, userKey)
      if (!Buffer.isBuffer(itemKey) || itemKey.length !== USER_KEY_BYTES) {
        throw new BitwardenDirectError('UNSUPPORTED_ACCOUNT_ENCRYPTION')
      }
      const response = await this.http.prepareAttachmentDownload(id, attachmentId, signal)
      const metadata = freshAttachmentMetadata(response, expected, itemKey)
      attachmentKey =
        metadata.encryptedKey === null
          ? itemKey
          : decryptBitwardenWrappedKey(metadata.encryptedKey, itemKey)
      if (attachmentKey.length !== USER_KEY_BYTES) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const networkSource = await response.downloadStream(signal)
      encryptedFile = await spoolEncryptedAttachment(networkSource, metadata.size, signal)
      streamKey = Buffer.from(attachmentKey)
      const plaintext = await authenticatedAttachmentPlaintext(encryptedFile, streamKey, signal)
      const ownedFile = encryptedFile
      const ownedKey = streamKey
      encryptedFile = null
      streamKey = null
      return {
        fileName: expected.fileName,
        data: plaintext,
        dispose: async () => {
          ownedKey.fill(0)
          await ownedFile.dispose()
        }
      }
    } catch (error) {
      await encryptedFile?.dispose().catch(() => undefined)
      streamKey?.fill(0)
      if (error instanceof BitwardenCryptoError && error.code === 'AUTHENTICATION_FAILED') {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      throw this.mapError(error)
    } finally {
      if (attachmentKey && attachmentKey !== itemKey) attachmentKey.fill(0)
      if (itemKey && itemKey !== userKey) clearBitwardenSymmetricKey(itemKey)
    }
  }

  async uploadAttachmentStream(
    id: string,
    fileName: string,
    data: BitwardenAttachmentByteSource,
    signal?: AbortSignal,
    onCommitted?: () => void
  ): Promise<BitwardenAttachment> {
    try {
      return await this.uploadAttachmentInternal(id, fileName, data, null, signal, onCommitted)
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async deleteAttachment(
    id: string,
    attachmentId: string,
    signal?: AbortSignal,
    onCommitted?: () => void
  ): Promise<void> {
    try {
      this.requireUserKey()
      if (signal?.aborted) throw new BitwardenDirectError('ABORTED')
      const cached = this.logins.get(id)
      if (!cached?.item.attachments.some((attachment) => attachment.id === attachmentId)) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }

      await this.http.deleteAttachment(id, attachmentId, signal)
      onCommitted?.()
      // A successful DELETE is the irreversible remote commit point. Caller
      // cancellation must not prevent reconciling the local cache afterwards.
      await this.sync()
      const authoritative = this.logins.get(id)
      if (
        !authoritative ||
        authoritative.item.attachments.some((attachment) => attachment.id === attachmentId)
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async upgradeLegacyAttachment(
    id: string,
    attachmentId: string,
    signal?: AbortSignal,
    onCommitted?: () => void
  ): Promise<BitwardenAttachment> {
    this.requireUserKey()
    if (signal?.aborted) throw new BitwardenDirectError('ABORTED')
    const cached = this.logins.get(id)
    const legacy = cached?.item.attachments.find((attachment) => attachment.id === attachmentId)
    if (!cached || !legacy?.legacy) throw new BitwardenDirectError('INVALID_RESPONSE')

    let downloaded: BitwardenDownloadedAttachment | null = null
    let replacement: BitwardenAttachment | null = null
    let legacyDeleteStarted = false
    try {
      // Safety ordering is deliberate: a failed download or replacement upload
      // must never destroy the only copy. If deleting the old attachment fails,
      // both valid copies remain on the server and the failure is reported.
      downloaded = await this.downloadAttachment(id, attachmentId, signal)
      replacement = await this.uploadAttachmentInternal(
        id,
        downloaded.fileName,
        downloaded.data,
        attachmentId,
        signal,
        undefined,
        true
      )
      const replacementId = replacement.id
      if (signal?.aborted) throw new BitwardenDirectError('ABORTED')

      // Once the legacy DELETE has been attempted, a lost response makes the
      // remote outcome ambiguous. Preserve the replacement on any failure from
      // that point so a later authoritative sync/recovery can resolve it without
      // risking deletion of the only surviving copy.
      legacyDeleteStarted = true
      await this.http.deleteAttachment(id, attachmentId, signal)
      onCommitted?.()
      await this.sync()
      const authoritativeItem = this.logins.get(id)?.item
      const authoritative = authoritativeItem?.attachments.find(
        (attachment) => attachment.id === replacementId
      )
      if (
        !authoritativeItem ||
        authoritativeItem.attachments.some((attachment) => attachment.id === attachmentId) ||
        !authoritative ||
        authoritative.legacy
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      return { ...authoritative }
    } catch (error) {
      if (replacement && !legacyDeleteStarted) {
        await this.http.deleteAttachment(id, replacement.id).catch(() => undefined)
      }
      throw this.mapError(error)
    } finally {
      downloaded?.data.fill(0)
    }
  }

  private async uploadAttachmentInternal(
    id: string,
    fileName: string,
    data: Buffer | BitwardenAttachmentByteSource,
    allowedDuplicateId: string | null,
    signal?: AbortSignal,
    onCommitted?: () => void,
    transferRollback = false
  ): Promise<BitwardenAttachment> {
    const userKey = this.requireUserKey()
    if (signal?.aborted) throw new BitwardenDirectError('ABORTED')
    if (
      typeof fileName !== 'string' ||
      fileName.length === 0 ||
      fileName.length > MAX_ATTACHMENT_FILE_NAME_LENGTH ||
      (!Buffer.isBuffer(data) &&
        (!data || typeof data.size !== 'number' || typeof data.chunks !== 'function'))
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }

    const cached = this.logins.get(id)
    if (!cached || cached.item.attachments.length >= MAX_ATTACHMENTS) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    const duplicates = cached.item.attachments.filter(
      (attachment) => attachment.fileName === fileName
    )
    if (
      duplicates.some((attachment) => attachment.id !== allowedDuplicateId) ||
      (allowedDuplicateId === null && duplicates.length > 0)
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    const revisionDate = cached.item.revisionDate
    if (revisionDate === null || !Number.isFinite(Date.parse(revisionDate))) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }

    let itemKey: BitwardenSymmetricKey | null = null
    let attachmentKey: Buffer | null = null
    let encryptedData: Buffer | null = null
    let encryptedFile: BitwardenEncryptedAttachmentFile | null = null
    let created: BitwardenAttachmentUpload | null = null
    let committed = false
    try {
      itemKey = cipherKey(cached.raw, userKey)
      // Account Encryption V2 still stores attachment files in the AES file
      // format. A legacy 64-byte per-item key is therefore mandatory.
      if (!Buffer.isBuffer(itemKey) || itemKey.length !== USER_KEY_BYTES) {
        throw new BitwardenDirectError('UNSUPPORTED_ACCOUNT_ENCRYPTION')
      }

      attachmentKey = randomBytes(USER_KEY_BYTES)
      const encryptedFileName = encryptBitwardenString(fileName, itemKey)
      const wrappedKey = encryptBitwardenBytes(attachmentKey, itemKey, 'legacy-key')
      if (Buffer.isBuffer(data)) {
        encryptedData = encryptBitwardenAttachmentBuffer(data, attachmentKey)
      } else {
        encryptedFile = await encryptAttachmentSource(data, attachmentKey, signal)
      }
      const encryptedSize = encryptedData?.length ?? encryptedFile!.size
      created = await this.http.createAttachment(
        id,
        {
          key: wrappedKey,
          fileName: encryptedFileName,
          fileSize: encryptedSize,
          lastKnownRevisionDate: revisionDate
        },
        signal
      )
      if (created.attachmentId === allowedDuplicateId) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }

      const uploadBody = encryptedData ?? (await encryptedFile!.blob())
      if (created.fileUploadType === 'direct') {
        await this.http.uploadAttachmentDirect(
          id,
          created.attachmentId,
          encryptedFileName,
          uploadBody,
          signal
        )
      } else {
        await this.http.uploadAttachmentAzure(created.url, uploadBody, signal)
      }

      await this.sync(signal)
      const attachment = this.logins
        .get(id)
        ?.item.attachments.find((candidate) => candidate.id === created?.attachmentId)
      if (
        !attachment ||
        attachment.fileName !== fileName ||
        attachment.legacy ||
        attachment.size !== encryptedSize
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      if (!transferRollback) onCommitted?.()
      // A legacy upgrade transfers rollback ownership to its outer state
      // machine after this validated replacement is returned.
      committed = true
      return { ...attachment }
    } catch (error) {
      if (created && !committed) {
        // The metadata POST is non-idempotent. If its response itself is lost,
        // the attachment id is unknowable here and a later recovery sync is the
        // only safe reconciliation path. Once the id is known, roll back every
        // unconfirmed failure without letting cleanup mask the original error.
        await this.http.deleteAttachment(id, created.attachmentId).catch(() => undefined)
      }
      throw error
    } finally {
      attachmentKey?.fill(0)
      encryptedData?.fill(0)
      await encryptedFile?.dispose().catch(() => undefined)
      if (itemKey && itemKey !== userKey) clearBitwardenSymmetricKey(itemKey)
    }
  }

  async createFolder(name: string, signal?: AbortSignal): Promise<BitwardenFolder> {
    const userKey = this.requireUserKey()
    try {
      const response = await this.http.createFolder(
        { name: encryptBitwardenString(name, userKey) },
        signal
      )
      const raw = responseEntity(response, 'folder')
      const id = requiredStringProperty(raw, 'id')
      const item = { id, name }
      this.folders.set(id, { raw: structuredClone(raw), item })
      await this.captureSession()
      return { ...item }
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async editFolder(id: string, name: string, signal?: AbortSignal): Promise<BitwardenFolder> {
    const userKey = this.requireUserKey()
    try {
      const response = await this.http.updateFolder(
        id,
        { name: encryptBitwardenString(name, userKey) },
        signal
      )
      const raw = responseEntity(response, 'folder')
      const item = { id: requiredStringProperty(raw, 'id'), name }
      this.folders.set(id, { raw: structuredClone(raw), item })
      await this.captureSession()
      return { ...item }
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async deleteFolder(id: string, signal?: AbortSignal): Promise<void> {
    try {
      this.requireUserKey()
      await this.http.deleteFolder(id, signal)
      this.folders.delete(id)
      await this.captureSession()
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async createLogin(draft: BitwardenLoginDraft, signal?: AbortSignal): Promise<BitwardenLoginItem> {
    const userKey = this.requireUserKey()
    const itemKey = randomBytes(USER_KEY_BYTES)
    try {
      const request = encryptLoginRequest(
        resolveDraft(draft, null),
        itemKey,
        null,
        this.loginRequestAccount()
      )
      request.key = encryptBitwardenBytes(itemKey, userKey, 'legacy-key')
      const response = await this.http.createCipher(request, signal)
      const raw = responseEntity(response, 'cipher')
      const item = decryptLogin(raw, userKey)
      this.logins.set(item.id, { raw: structuredClone(raw), item })
      await this.captureSession()
      return cloneLoginItem(item)
    } catch (error) {
      throw this.mapError(error)
    } finally {
      itemKey.fill(0)
    }
  }

  async prepareLoginImport(
    entries: readonly BitwardenLoginImportEntry[]
  ): Promise<BitwardenPreparedLoginImport> {
    const userKey = this.requireUserKey()
    if (
      !Array.isArray(entries) ||
      entries.length < MIN_PERSONAL_IMPORT_CIPHERS ||
      entries.length > MAX_PERSONAL_IMPORT_CIPHERS ||
      this.preparedLoginImports.size !== 0
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }

    const localIds = new Set<string>()
    const markers = new Set<string>()
    const folders: Array<{ id: string; name: string }> = []
    const folderIndexes = new Map<string, number>()
    const ciphers: JsonObject[] = []
    const folderRelationships: Array<{ key: number; value: number }> = []
    const preparedEntries: BitwardenPreparedLoginImportEntry[] = []

    try {
      for (const [index, entry] of entries.entries()) {
        if (
          !isJsonObject(entry) ||
          typeof entry.localId !== 'string' ||
          !isJsonObject(entry.draft) ||
          typeof entry.draft.name !== 'string'
        ) {
          throw new BitwardenDirectError('INVALID_RESPONSE')
        }
        const localId = assertUuidValue(entry.localId)
        const normalizedLocalId = localId.toLocaleLowerCase('en-US')
        if (localIds.has(normalizedLocalId)) throw new BitwardenDirectError('INVALID_RESPONSE')
        localIds.add(normalizedLocalId)

        const resolved = resolveDraft(entry.draft as unknown as BitwardenLoginDraft, null)
        const itemKey = randomBytes(USER_KEY_BYTES)
        try {
          const request = encryptLoginRequest(resolved, itemKey, null, this.loginRequestAccount())
          const marker = encryptBitwardenBytes(itemKey, userKey, 'legacy-key')
          if (markers.has(marker)) throw new BitwardenDirectError('INVALID_RESPONSE')
          markers.add(marker)
          request.key = marker
          request.organizationId = null
          request.folderId = null
          delete request.attachments
          delete request.attachments2
          delete request.collectionIds
          ciphers.push(request)

          if (resolved.folderId !== null) {
            const cachedFolder = this.folders.get(resolved.folderId)
            if (!cachedFolder || cachedFolder.item.id !== resolved.folderId) {
              throw new BitwardenDirectError('INVALID_RESPONSE')
            }
            let folderIndex = folderIndexes.get(resolved.folderId)
            if (folderIndex === undefined) {
              folderIndex = folders.length
              folderIndexes.set(resolved.folderId, folderIndex)
              folders.push({
                id: resolved.folderId,
                name: requiredStringProperty(cachedFolder.raw, 'name')
              })
            }
            folderRelationships.push({ key: index, value: folderIndex })
          }
          preparedEntries.push({
            localId,
            marker,
            remoteFolderId: resolved.folderId
          })
        } finally {
          itemKey.fill(0)
        }
      }

      const token = randomBytes(PREPARED_IMPORT_TOKEN_BYTES).toString('base64url')
      this.preparedLoginImports.set(token, {
        request: { folders, ciphers, folderRelationships }
      })
      return {
        token,
        entries: preparedEntries.map((entry) => ({ ...entry }))
      }
    } catch (error) {
      this.clearPreparedLoginImportPayload({
        request: { folders, ciphers, folderRelationships }
      })
      throw this.mapError(error)
    }
  }

  async executePreparedLoginImport(token: string, signal?: AbortSignal): Promise<void> {
    const payload = this.takePreparedLoginImport(token)
    try {
      this.requireUserKey()
      await this.http.importPersonalCiphers(payload.request, signal)
      await this.captureSession()
    } catch (error) {
      throw this.mapError(error)
    } finally {
      this.clearPreparedLoginImportPayload(payload)
    }
  }

  async reconcileLoginImportMarkers(
    markers: readonly string[]
  ): Promise<BitwardenReconciledLoginImportEntry[]> {
    this.requireUserKey()
    if (
      !Array.isArray(markers) ||
      markers.length < MIN_IMPORT_RECONCILIATION_MARKERS ||
      markers.length > MAX_PERSONAL_IMPORT_CIPHERS
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    const expected = new Set<string>()
    for (const marker of markers) {
      if (
        typeof marker !== 'string' ||
        marker.length === 0 ||
        marker.length > MAX_IMPORT_MARKER_LENGTH ||
        expected.has(marker)
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      expected.add(marker)
    }

    const matches = new Map<string, string>()
    for (const [remoteId, cached] of this.logins) {
      const marker = readField(cached.raw, 'key')
      if (typeof marker !== 'string' || !expected.has(marker)) continue
      if (matches.has(marker)) throw new BitwardenDirectError('INVALID_RESPONSE')
      matches.set(marker, remoteId)
    }
    return markers.flatMap((marker) => {
      const remoteId = matches.get(marker)
      return remoteId ? [{ marker, remoteId }] : []
    })
  }

  async discardPreparedLoginImport(token: string): Promise<void> {
    const payload = this.takePreparedLoginImport(token)
    this.clearPreparedLoginImportPayload(payload)
  }

  async editLogin(
    id: string,
    draft: BitwardenLoginDraft,
    signal?: AbortSignal
  ): Promise<BitwardenLoginItem> {
    const userKey = this.requireUserKey()
    const cached = this.logins.get(id)
    if (!cached) throw new BitwardenDirectError('INVALID_RESPONSE')
    const itemKey = cipherKey(cached.raw, userKey)
    try {
      const request = encryptLoginRequest(
        resolveDraft(draft, cached.item),
        itemKey,
        cached.raw,
        this.loginRequestAccount()
      )
      const response = await this.http.updateCipher(id, request, signal)
      const raw = responseEntity(response, 'cipher')
      const item = decryptLogin(raw, userKey)
      this.logins.set(item.id, { raw: structuredClone(raw), item })
      await this.captureSession()
      return cloneLoginItem(item)
    } catch (error) {
      throw this.mapError(error)
    } finally {
      if (itemKey !== userKey) clearBitwardenSymmetricKey(itemKey)
    }
  }

  async softDeleteLogin(id: string, signal?: AbortSignal): Promise<void> {
    try {
      this.requireUserKey()
      await this.http.softDeleteCipher(id, signal)
      const cached = this.logins.get(id)
      if (cached) {
        const deletedAt = new Date().toISOString()
        cached.raw.deletedDate = deletedAt
        cached.item.deletedAt = deletedAt
      }
      await this.captureSession()
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async softDeleteLogins(ids: readonly string[], signal?: AbortSignal): Promise<void> {
    try {
      this.requireUserKey()
      const cachedLogins = this.requireCachedLogins(ids)
      await this.http.bulkSoftDeleteCiphers(ids, signal)
      const deletedAt = new Date().toISOString()
      for (const cached of cachedLogins) {
        cached.raw.deletedDate = deletedAt
        cached.item.deletedAt = deletedAt
      }
      await this.captureSession()
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async restoreLogin(id: string, signal?: AbortSignal): Promise<void> {
    const userKey = this.requireUserKey()
    try {
      const response = await this.http.restoreCipher(id, signal)
      const raw = responseEntity(response, 'cipher')
      const item = decryptLogin(raw, userKey)
      if (item.id !== id) throw new BitwardenDirectError('INVALID_RESPONSE')
      this.logins.set(item.id, { raw: structuredClone(raw), item })
      await this.captureSession()
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async restoreLogins(ids: readonly string[], signal?: AbortSignal): Promise<void> {
    const userKey = this.requireUserKey()
    try {
      this.requireCachedLogins(ids)
      const rows = await this.http.bulkRestoreCiphers(ids, signal)
      this.replaceBulkLoginRows(ids, rows, userKey, (item) => item.deletedAt === null)
      await this.captureSession()
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async moveLogins(
    ids: readonly string[],
    folderId: string | null,
    signal?: AbortSignal
  ): Promise<void> {
    try {
      this.requireUserKey()
      const cachedLogins = this.requireCachedLogins(ids)
      if (folderId !== null && !this.folders.has(folderId)) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      await this.http.bulkMoveCiphers(ids, folderId, signal)
      for (const cached of cachedLogins) {
        cached.raw.folderId = folderId
        cached.item.folderId = folderId
      }
      await this.captureSession()
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async archiveLogin(id: string, signal?: AbortSignal): Promise<void> {
    const userKey = this.requireUserKey()
    try {
      const response = await this.http.archiveCipher(id, signal)
      const raw = responseEntity(response, 'cipher')
      const item = decryptLogin(raw, userKey)
      if (item.id !== id || item.archivedAt === null) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      this.logins.set(item.id, { raw: structuredClone(raw), item })
      await this.captureSession()
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async archiveLogins(ids: readonly string[], signal?: AbortSignal): Promise<void> {
    const userKey = this.requireUserKey()
    try {
      this.requireCachedLogins(ids)
      const rows = await this.http.bulkArchiveCiphers(ids, signal)
      this.replaceBulkLoginRows(ids, rows, userKey, (item) => item.archivedAt !== null)
      await this.captureSession()
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async unarchiveLogin(id: string, signal?: AbortSignal): Promise<void> {
    const userKey = this.requireUserKey()
    try {
      const response = await this.http.unarchiveCipher(id, signal)
      const raw = responseEntity(response, 'cipher')
      const item = decryptLogin(raw, userKey)
      if (item.id !== id || item.archivedAt !== null) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      this.logins.set(item.id, { raw: structuredClone(raw), item })
      await this.captureSession()
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async unarchiveLogins(ids: readonly string[], signal?: AbortSignal): Promise<void> {
    const userKey = this.requireUserKey()
    try {
      this.requireCachedLogins(ids)
      const rows = await this.http.bulkUnarchiveCiphers(ids, signal)
      this.replaceBulkLoginRows(ids, rows, userKey, (item) => item.archivedAt === null)
      await this.captureSession()
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async hardDeleteLogin(id: string, signal?: AbortSignal): Promise<void> {
    try {
      this.requireUserKey()
      await this.http.hardDeleteCipher(id, signal)
      this.logins.delete(id)
      await this.captureSession()
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async hardDeleteLogins(ids: readonly string[], signal?: AbortSignal): Promise<void> {
    try {
      this.requireUserKey()
      this.requireCachedLogins(ids)
      await this.http.bulkHardDeleteCiphers(ids, signal)
      for (const id of ids) this.logins.delete(id)
      await this.captureSession()
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async deleteLogin(id: string, signal?: AbortSignal): Promise<void> {
    await this.hardDeleteLogin(id, signal)
  }

  async lock(): Promise<void> {
    this.clearDecryptedState()
  }

  async logout(): Promise<void> {
    this.clearDecryptedState()
    this.state.session = null
    this.http.clearSession()
    await this.notifyStateChanged()
  }

  /** Derives the base64 server proof and zeroes the intermediate key buffers before returning. */
  private async deriveMasterPasswordHash(
    masterPassword: string,
    signal?: AbortSignal
  ): Promise<string> {
    const prelogin = await this.http.prelogin(this.email, signal)
    const masterKey = await deriveMasterKey(
      masterPassword,
      prelogin.salt ?? this.email,
      kdfFromPrelogin(prelogin)
    )
    let passwordKey: Buffer | null = null
    try {
      passwordKey = await derivePasswordKey(masterKey, masterPassword)
      return passwordKey.toString('base64')
    } finally {
      masterKey.fill(0)
      passwordKey?.fill(0)
    }
  }

  private async deriveAndAuthenticate(
    password: string,
    twoFactor: BitwardenLoginTwoFactor | undefined,
    newDeviceOtp: string | undefined,
    requestToken: boolean,
    signal?: AbortSignal
  ): Promise<void> {
    const operationGeneration = this.runtimeGeneration
    let invalidResponseStage: SyncInvalidResponseStage = 'prelogin'
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
    let stretched: ReturnType<typeof stretchMasterKey> | null = null
    let twoFactorToken: string | undefined
    let installedPendingMasterKey: Buffer | null = null
    let installedRuntimeGeneration: number | null = null
    try {
      const prelogin = await this.http.prelogin(this.email, signal)
      try {
        masterKey = await deriveMasterKey(
          password,
          prelogin.salt ?? this.email,
          kdfFromPrelogin(prelogin)
        )
      } catch (error) {
        if (error instanceof BitwardenCryptoError && error.code === 'INVALID_INPUT') {
          throw new BitwardenDirectError(
            'INVALID_RESPONSE',
            undefined,
            'prelogin',
            undefined,
            'kdf-parameters'
          )
        }
        throw error
      }
      passwordKey = await derivePasswordKey(masterKey, password)
      stretched = stretchMasterKey(masterKey)
      if (requestToken) {
        invalidResponseStage = 'authentication'
        let twoFactorRemember: boolean | undefined
        const rememberedTwoFactorToken = twoFactor ? undefined : this.state.rememberedTwoFactorToken
        if (twoFactor) {
          if (twoFactor.method === 7) {
            if (typeof twoFactor.remember !== 'boolean') {
              throw new BitwardenDirectError('INVALID_RESPONSE')
            }
            twoFactorToken = serializeAccountWebAuthnAssertion(twoFactor.assertion)
            twoFactorRemember = twoFactor.remember
          } else {
            if (
              (twoFactor.method !== 0 && twoFactor.method !== 1 && twoFactor.method !== 3) ||
              typeof twoFactor.code !== 'string' ||
              (twoFactor.remember !== undefined && typeof twoFactor.remember !== 'boolean')
            ) {
              throw new BitwardenDirectError('INVALID_RESPONSE')
            }
            twoFactorToken = twoFactor.code
            twoFactorRemember = twoFactor.remember ?? true
          }
        }
        let session: BitwardenSession
        try {
          session = await this.http.passwordToken(
            {
              email: this.email,
              password: passwordKey.toString('base64'),
              deviceIdentifier: this.state.deviceIdentifier,
              deviceType: this.deviceType,
              deviceName: this.deviceName,
              ...(newDeviceOtp ? { newDeviceOtp } : {}),
              ...(twoFactor
                ? {
                    twoFactorProvider: twoFactor.method,
                    twoFactorToken,
                    twoFactorRemember
                  }
                : rememberedTwoFactorToken
                  ? {
                      twoFactorProvider: 5,
                      twoFactorToken: rememberedTwoFactorToken,
                      twoFactorRemember: false
                    }
                  : {})
            },
            signal
          )
        } catch (error) {
          if (
            rememberedTwoFactorToken &&
            error instanceof BitwardenHttpError &&
            error.code === 'TWO_FACTOR'
          ) {
            this.state.rememberedTwoFactorToken = undefined
            await this.notifyStateChanged().catch(() => undefined)
          }
          throw error
        }
        if (signal?.aborted || operationGeneration !== this.runtimeGeneration) {
          throw new BitwardenDirectError('ABORTED')
        }
        this.captureRememberedTwoFactorToken(session)
        const normalizedSession = this.normalizedSession(session)
        this.runtimeGeneration += 1
        installedRuntimeGeneration = this.runtimeGeneration
        this.http.setSession(normalizedSession)
        this.state.session = normalizedSession
      } else {
        if (signal?.aborted || operationGeneration !== this.runtimeGeneration) {
          throw new BitwardenDirectError('ABORTED')
        }
        this.runtimeGeneration += 1
        installedRuntimeGeneration = this.runtimeGeneration
      }
      this.stretchedKey?.fill(0)
      this.stretchedKey = stretched.combinedKey
      stretched.combinedKey = Buffer.alloc(0)
      this.clearPendingMasterKey()
      this.pendingMasterKey = masterKey
      installedPendingMasterKey = masterKey
      masterKey = null
      try {
        await this.notifyStateChanged()
      } catch {
        // Authentication is not committed until the encrypted vault state accepts the new
        // session. Fail closed so memory and durable state cannot disagree after a write failure.
        // A newer authentication or lock operation owns a later generation and must not be
        // rolled back by this stale persistence failure.
        if (this.runtimeGeneration === installedRuntimeGeneration) {
          this.clearDecryptedState()
          this.state.session = null
          this.state.rememberedTwoFactorToken = undefined
          this.http.clearSession()
        }
        throw new BitwardenDirectError('STATE_PERSISTENCE_FAILED')
      }
    } catch (error) {
      if (this.pendingMasterKey === installedPendingMasterKey) this.clearPendingMasterKey()
      const mapped = this.mapError(error)
      if (mapped.code === 'INVALID_RESPONSE' && !mapped.syncInvalidResponseStage) {
        throw new BitwardenDirectError(
          'INVALID_RESPONSE',
          undefined,
          invalidResponseStage,
          undefined,
          mapped.syncInvalidResponseReason ?? 'response-shape'
        )
      }
      throw mapped
    } finally {
      // JavaScript strings are immutable; release the local assertion/token reference promptly.
      twoFactorToken = undefined
      masterKey?.fill(0)
      passwordKey?.fill(0)
      stretched?.encKey.fill(0)
      stretched?.macKey.fill(0)
      stretched?.combinedKey.fill(0)
    }
  }

  private async encryptSendRequest(
    draft: BitwardenSendDraft,
    userKey: BitwardenSymmetricKey,
    existing?: JsonObject
  ): Promise<BitwardenSendRequest> {
    const seed = existing
      ? decryptBitwardenBytes(requiredStringProperty(existing, 'key'), userKey)
      : randomBytes(16)
    let sendKey: Buffer | null = null
    try {
      if (seed.length !== 16) throw new BitwardenDirectError('INVALID_RESPONSE')
      sendKey = deriveBitwardenSendKey(seed)
      const preservePassword = existing !== undefined && draft.password === undefined
      const existingAuthType = existing ? readField(existing, 'authType') : undefined
      const existingPassword = existing ? nullableStringProperty(existing, 'password') : null
      const existingEmails = existing ? nullableStringProperty(existing, 'emails') : null
      const password = preservePassword
        ? existingPassword
        : draft.password?.length
          ? draft.password
          : null
      const authType =
        preservePassword &&
        (existingAuthType === 0 || existingAuthType === 1 || existingAuthType === 2)
          ? existingAuthType
          : password
            ? 1
            : 2
      const request: BitwardenSendRequest = {
        type: 0,
        authType,
        name: encryptBitwardenString(draft.name, sendKey),
        notes: draft.notes === null ? null : encryptBitwardenString(draft.notes, sendKey),
        key: existing
          ? requiredStringProperty(existing, 'key')
          : encryptBitwardenBytes(seed, userKey),
        maxAccessCount: draft.maxAccessCount,
        expirationDate: draft.expirationDate,
        deletionDate: draft.deletionDate,
        text: {
          text: encryptBitwardenString(draft.text, sendKey),
          hidden: draft.hidden
        },
        password: preservePassword ? existingPassword : null,
        // Email OTP configuration is server-owned for now. Keeping the exact existing value on
        // metadata-only edits prevents silently weakening an Email-authenticated Send.
        emails: preservePassword && existingAuthType === 0 ? existingEmails : null,
        disabled: draft.disabled,
        hideEmail: draft.hideEmail
      }
      if (password && !preservePassword) {
        const passwordHash = await deriveBitwardenSendPasswordHash(password, seed)
        try {
          request.password = passwordHash.toString('base64')
        } finally {
          passwordHash.fill(0)
        }
      }
      return request
    } finally {
      seed.fill(0)
      sendKey?.fill(0)
    }
  }

  private accountIdentityChange(
    profileId: string,
    securityStamp: string | null
  ): 'profile' | 'security-stamp' | null {
    if (this.state.profileId && this.state.profileId !== profileId) {
      return 'profile'
    }
    if (this.state.securityStamp && securityStamp && this.state.securityStamp !== securityStamp) {
      return 'security-stamp'
    }
    return null
  }

  private assertAccountProfileOwnership(profile: BitwardenAccountSecurityProfile): void {
    if (profile.id !== this.requireProfileId()) throw new BitwardenDirectError('ACCOUNT_CHANGED')
    if (profile.email.toLocaleLowerCase('en-US') !== this.email.toLocaleLowerCase('en-US')) {
      throw new BitwardenDirectError('ACCOUNT_CHANGED')
    }
  }

  private async authoritativeAccountProfile(
    signal?: AbortSignal
  ): Promise<BitwardenAccountSecurityProfile> {
    try {
      this.requireProfileId()
      const profile = await this.http.getAccountSecurityProfile(signal)
      this.assertAccountProfileOwnership(profile)
      await this.captureSession()
      return profile
    } catch (error) {
      if (error instanceof BitwardenDirectError) throw error
      throw this.mapError(error)
    }
  }

  private async applyAccountProfileMutation(
    mutate: () => Promise<BitwardenAccountSecurityProfile>,
    matchesTarget: (profile: BitwardenAccountSecurityProfile) => boolean,
    signal?: AbortSignal
  ): Promise<BitwardenAccountSecurityProfile> {
    try {
      const profile = await mutate()
      this.assertAccountProfileOwnership(profile)
      if (!matchesTarget(profile)) throw new BitwardenDirectError('INVALID_RESPONSE')
      await this.captureSession()
      return profile
    } catch (error) {
      const mapped = error instanceof BitwardenDirectError ? error : this.mapError(error)
      if (
        mapped.code !== 'NETWORK' &&
        mapped.code !== 'ABORTED' &&
        mapped.code !== 'INVALID_RESPONSE' &&
        mapped.code !== 'ACCOUNT_CHANGED'
      ) {
        throw mapped
      }

      // A request may have committed even when its response was lost or malformed.
      // Reconcile once with an authoritative GET, but never automatically replay the mutation.
      if (!signal?.aborted) {
        try {
          const current = await this.authoritativeAccountProfile(signal)
          if (matchesTarget(current)) return current
        } catch {
          // The stable unknown-result error below intentionally hides transport details.
        }
      }
      throw new BitwardenDirectError('ACCOUNT_PROFILE_MUTATION_UNKNOWN')
    }
  }

  private requireUserKey(): BitwardenSymmetricKey {
    if (!this.userKey) throw new BitwardenDirectError('AUTH_REQUIRED')
    return this.userKey
  }

  private requireProfileId(): string {
    if (!this.state.profileId) throw new BitwardenDirectError('AUTH_REQUIRED')
    return this.state.profileId
  }

  private loginRequestAccount(): LoginRequestAccount {
    return { userKey: this.userKey, requireProfileId: () => this.requireProfileId() }
  }

  private requireCachedLogins(ids: readonly string[]): CachedLogin[] {
    const cachedLogins: CachedLogin[] = []
    for (const id of ids) {
      const cached = this.logins.get(id)
      if (!cached) throw new BitwardenDirectError('INVALID_RESPONSE')
      cachedLogins.push(cached)
    }
    return cachedLogins
  }

  private replaceBulkLoginRows(
    ids: readonly string[],
    rows: readonly JsonObject[],
    userKey: BitwardenSymmetricKey,
    validState: (item: BitwardenLoginItem) => boolean
  ): void {
    const expectedIds = new Map(ids.map((id) => [id.toLocaleLowerCase('en-US'), id] as const))
    const replacements: CachedLogin[] = []
    for (const raw of rows) {
      if (readField(raw, 'organizationId') !== null) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const item = decryptLogin(raw, userKey)
      if (expectedIds.get(item.id.toLocaleLowerCase('en-US')) !== item.id || !validState(item)) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      replacements.push({ raw: structuredClone(raw), item })
    }
    if (replacements.length !== expectedIds.size) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    for (const replacement of replacements) {
      this.logins.set(replacement.item.id, replacement)
    }
  }

  private async captureSession(): Promise<void> {
    const session = this.http.exportSession()
    if (session) this.captureRememberedTwoFactorToken(session)
    this.state.session = session ? this.normalizedSession(session) : null
    await this.notifyStateChanged()
  }

  private captureRememberedTwoFactorToken(session: BitwardenSession): void {
    if (session.twoFactorToken) this.state.rememberedTwoFactorToken = session.twoFactorToken
  }

  private normalizedSession(session: BitwardenSession): BitwardenSession {
    return {
      accessToken: session.accessToken,
      refreshToken: session.refreshToken,
      expiresAt: session.expiresAt,
      ...(session.clientId ? { clientId: session.clientId } : {})
    }
  }

  private async clearDeauthorizedSession(): Promise<void> {
    this.clearDecryptedState()
    this.state.session = null
    this.state.securityStamp = null
    this.http.clearSession()
    await this.notifyStateChanged()
  }

  private async notifyStateChanged(sessionOverride?: BitwardenSession | null): Promise<void> {
    const onStateChanged = this.options.onStateChanged
    if (!onStateChanged) return
    const snapshot = this.exportState()
    if (sessionOverride !== undefined) {
      snapshot.session = sessionOverride ? this.normalizedSession(sessionOverride) : null
    }
    const pending = this.stateChangeQueue
      .catch(() => undefined)
      .then(async () => onStateChanged(snapshot))
    this.stateChangeQueue = pending
    await pending
  }

  private takePreparedLoginImport(token: string): PreparedLoginImportPayload {
    if (
      typeof token !== 'string' ||
      token.length !== Math.ceil((PREPARED_IMPORT_TOKEN_BYTES * 8) / 6) ||
      !/^[A-Za-z0-9_-]+$/u.test(token)
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    const payload = this.preparedLoginImports.get(token)
    if (!payload) throw new BitwardenDirectError('INVALID_RESPONSE')
    // Consume the capability before starting I/O. An unknown result can therefore never be retried.
    this.preparedLoginImports.delete(token)
    return payload
  }

  private clearPreparedLoginImportPayload(payload: PreparedLoginImportPayload): void {
    for (const cipher of payload.request.ciphers) {
      for (const key of Object.keys(cipher)) cipher[key] = null
    }
    for (const folder of payload.request.folders) {
      folder.name = ''
      folder.id = null
    }
    ;(payload.request.ciphers as JsonObject[]).splice(0)
    ;(payload.request.folders as Array<{ id?: string | null; name: string }>).splice(0)
    ;(payload.request.folderRelationships as Array<{ key: number; value: number }>).splice(0)
  }

  private clearDecryptedState(): void {
    this.runtimeGeneration += 1
    for (const payload of this.preparedLoginImports.values()) {
      this.clearPreparedLoginImportPayload(payload)
    }
    this.preparedLoginImports.clear()
    this.stretchedKey?.fill(0)
    this.clearPendingMasterKey()
    clearBitwardenSymmetricKey(this.userKey)
    this.wrappedUserKeyFingerprint?.fill(0)
    this.stretchedKey = null
    this.userKey = null
    this.wrappedUserKeyFingerprint = null
    this.folders.clear()
    this.logins.clear()
    this.organizations.clear()
    this.collections.clear()
    this.organizationCiphers.clear()
    this.organizationCipherRaws.clear()
    for (const organizationKey of this.organizationKeys.values()) organizationKey.fill(0)
    this.organizationKeys.clear()
    this.sends.clear()
    this.isolatedPersonalCiphers.clear()
    this.syncedEquivalentDomainSettings = null
    this.syncedUserDecryptionCapabilities = noUserDecryptionCapabilities()
  }

  private clearPendingMasterKey(): void {
    this.pendingMasterKey?.fill(0)
    this.pendingMasterKey = null
  }

  private mapError(error: unknown): BitwardenDirectError {
    if (error instanceof BitwardenDirectError) return error
    if (error instanceof BitwardenCryptoError) {
      if (error.code === 'AUTHENTICATION_FAILED') {
        return new BitwardenDirectError('AUTH_REQUIRED')
      }
      if (error.code === 'ARGON2_UNAVAILABLE') {
        return new BitwardenDirectError('UNSUPPORTED_ACCOUNT_ENCRYPTION')
      }
      return new BitwardenDirectError('INVALID_RESPONSE')
    }
    if (error instanceof BitwardenHttpError) {
      if (error.code === 'AUTH' || error.code === 'SESSION_EXPIRED') {
        return new BitwardenDirectError('AUTH_REQUIRED')
      }
      if (error.code === 'SSO_REQUIRED') return new BitwardenDirectError('SSO_REQUIRED')
      if (error.code === 'TWO_FACTOR') {
        return new BitwardenDirectError(
          'TWO_FACTOR_REQUIRED',
          error.webAuthnChallenge,
          undefined,
          error.twoFactorProviders
        )
      }
      if (error.code === 'NEW_DEVICE') return new BitwardenDirectError('NEW_DEVICE_REQUIRED')
      if (error.code === 'CONFLICT') return new BitwardenDirectError('CONFLICT')
      if (error.code === 'ABORTED') return new BitwardenDirectError('ABORTED')
      if (error.code === 'NOT_FOUND') return new BitwardenDirectError('NOT_FOUND')
      if (error.code === 'FORBIDDEN') return new BitwardenDirectError('FORBIDDEN')
      if (error.code === 'TOO_LARGE') return new BitwardenDirectError('TOO_LARGE')
      if (error.code === 'STORAGE_LIMIT') return new BitwardenDirectError('STORAGE_LIMIT')
      if (error.code === 'ATTACHMENT_REJECTED') {
        return new BitwardenDirectError('ATTACHMENT_REJECTED')
      }
      if (error.code === 'USER_VERIFICATION_FAILED') {
        return new BitwardenDirectError('USER_VERIFICATION_FAILED')
      }
      if (error.code === 'INVALID_RESPONSE') {
        return new BitwardenDirectError(
          'INVALID_RESPONSE',
          undefined,
          undefined,
          undefined,
          error.invalidResponseReason
        )
      }
      return new BitwardenDirectError('NETWORK')
    }
    return new BitwardenDirectError('INVALID_RESPONSE')
  }
}
