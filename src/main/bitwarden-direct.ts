import {
  constants,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  publicEncrypt,
  randomBytes,
  randomUUID,
  type KeyObject
} from 'node:crypto'
import { Encoder } from 'cbor-x'
import {
  BitwardenCryptoError,
  clearBitwardenSymmetricKey,
  decryptBitwardenAttachmentBuffer,
  decryptBitwardenMasterKeyWrappedUserKey,
  decodeBitwardenUserKey,
  decryptBitwardenBytes,
  decryptBitwardenCipherBlob,
  decryptBitwardenString,
  decryptBitwardenWrappedKey,
  decryptRsaPrivateKey,
  deriveMasterKey,
  derivePasswordKey,
  encryptBitwardenBytes,
  encryptBitwardenAttachmentBuffer,
  encryptBitwardenCipherBlob,
  encryptBitwardenString,
  isBitwardenLegacyMasterKeyWrappedUserKey,
  deriveBitwardenSendKey,
  deriveBitwardenSendPasswordHash,
  stretchMasterKey,
  verifyBitwardenV2AccountState,
  type BitwardenKdf,
  type BitwardenCipherBlobValue,
  type BitwardenSymmetricKey
} from './bitwarden-crypto'
import {
  BitwardenHttpClient,
  BitwardenHttpError,
  parseEquivalentDomainSettings,
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
  type BitwardenTwoFactorProviderId,
  type BitwardenWebAuthnKey,
  type BitwardenWebAuthnSetup,
  type BitwardenSession,
  type JsonObject,
  type JsonValue
} from './bitwarden-http'
import { loadEffLongWordlist } from './eff-wordlist'
import type {
  VaultCustomField,
  VaultCustomFieldType,
  VaultItemFields,
  VaultItemType,
  VaultLoginUri,
  VaultPasswordHistoryEntry,
  VaultReprompt,
  VaultUriMatch
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
  type AccountWebAuthnAssertion,
  type AccountWebAuthnChallenge
} from './account-webauthn-codec'
import {
  BitwardenPolicyParseError,
  parseBitwardenPolicySync,
  type BitwardenPolicySet
} from './bitwarden-policy'
import type {
  AccountWebAuthnAttestation,
  AccountWebAuthnRegistrationChallenge
} from './account-webauthn-registration-codec'

const USER_KEY_BYTES = 64
const MAX_REMOTE_ENTITIES = 100_000
const MAX_CUSTOM_FIELDS = 1_000
const MAX_CUSTOM_FIELD_STRING_LENGTH = 5_000
const MAX_NAME_LENGTH = 256
const MAX_LOGIN_URIS = 1_000
const MAX_PASSKEYS_PER_ITEM = 1_000
const MAX_ATTACHMENTS_PER_ITEM = 1_000
const MAX_ATTACHMENT_ID_LENGTH = 256
const MAX_ATTACHMENT_FILE_NAME_LENGTH = 255
const MAX_ATTACHMENT_SIZE_NAME_LENGTH = 64
const MAX_PASSKEY_FIELD_LENGTH = 4_096
const MAX_URI_LENGTH = 4_096
const MAX_PASSWORD_LENGTH = 16_384
const MAX_PASSWORD_HISTORY = 5
const MAX_AGGREGATE_REMOTE_ROWS = 1_000_000
const MAX_SEND_FILE_ID_LENGTH = 256
const MAX_SEND_FILE_NAME_LENGTH = 255
const MAX_SEND_FILE_SIZE = 550_502_400
const MAX_SEND_FILE_SIZE_NAME_LENGTH = 64
const MAX_SEND_FILE_PLAINTEXT_BYTES = 128 * 1024 * 1024 - 65
const MAX_SYNC_SECRET_LENGTH = 16_384
const MAX_WEBAUTHN_REGISTRATION_SLOTS = 10
const MIN_PERSONAL_IMPORT_CIPHERS = 2
const MAX_PERSONAL_IMPORT_CIPHERS = 500
const MIN_IMPORT_RECONCILIATION_MARKERS = 1
const PREPARED_IMPORT_TOKEN_BYTES = 32
const MAX_IMPORT_MARKER_LENGTH = 1_024
const MINIMUM_CLIENT_VERSION = '2025.5.0'
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu
const userKeyEncoder = new Encoder({
  mapsAsObjects: false,
  tagUint8Array: false,
  useRecords: false
})

type BitwardenCipherType = 1 | 2 | 3 | 4 | 5

const WIRE_TYPE_BY_ITEM_TYPE = {
  login: 1,
  secureNote: 2,
  card: 3,
  identity: 4,
  sshKey: 5
} as const satisfies Record<VaultItemType, BitwardenCipherType>

const ITEM_TYPE_BY_WIRE_TYPE: Record<BitwardenCipherType, VaultItemType> = {
  1: 'login',
  2: 'secureNote',
  3: 'card',
  4: 'identity',
  5: 'sshKey'
}

const BLOB_TAG_BY_ITEM_TYPE = {
  login: 'login',
  secureNote: 'secureNote',
  card: 'card',
  identity: 'identity',
  sshKey: 'sshKey'
} as const satisfies Record<VaultItemType, string>

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

export type BitwardenDirectErrorCode =
  | 'AUTH_REQUIRED'
  | 'TWO_FACTOR_REQUIRED'
  | 'NEW_DEVICE_REQUIRED'
  | 'SSO_REQUIRED'
  | 'NETWORK'
  | 'INVALID_RESPONSE'
  | 'INVALID_SSH_KEY'
  | 'CONFLICT'
  | 'ABORTED'
  | 'NOT_FOUND'
  | 'FORBIDDEN'
  | 'TOO_LARGE'
  | 'STORAGE_LIMIT'
  | 'ATTACHMENT_REJECTED'
  | 'UNSUPPORTED_ACCOUNT_ENCRYPTION'
  | 'KEY_CONNECTOR_UNSUPPORTED'
  | 'TRUSTED_DEVICE_UNSUPPORTED'
  | 'ACCOUNT_CHANGED'
  | 'USER_VERIFICATION_FAILED'
  | 'API_KEY_ROTATION_UNKNOWN'
  | 'TWO_FACTOR_MUTATION_UNKNOWN'
  | 'MASTER_PASSWORD_CHANGE_UNKNOWN'
  | 'SESSION_DEAUTHORIZATION_UNKNOWN'
  | 'VAULT_PURGE_UNKNOWN'
  | 'ACCOUNT_PROFILE_STALE'
  | 'ACCOUNT_PROFILE_MUTATION_UNKNOWN'
  | 'STATE_PERSISTENCE_FAILED'

export type BitwardenSyncInvalidResponseStage =
  | 'prelogin'
  | 'authentication'
  | 'access-token'
  | 'response'
  | 'account'
  | 'organization'
  | 'folder'
  | 'cipher'
  | 'collection'
  | 'send'
  | 'snapshot'

/** Value-free, closed reasons safe to surface in sync diagnostics. */
export type BitwardenSyncInvalidResponseReason =
  | 'response-shape'
  | 'empty-response'
  | 'invalid-json'
  | 'non-object-response'
  | 'session-response'
  | 'prelogin-route-response'
  | 'kdf-settings'
  | 'kdf-parameters'
  | 'account-profile'
  | 'user-decryption-data'
  | 'organization-profile'
  | 'organization-key'
  | 'provider-organization-key'
  | 'folder-data'
  | 'unsupported-cipher-type'
  | 'cipher-data'
  | 'collection-data'
  | 'send-data'
  | 'snapshot-limit'

export class BitwardenDirectError extends Error {
  constructor(
    readonly code: BitwardenDirectErrorCode,
    /** Main-process-only, strictly normalized provider-7 request options. */
    readonly webAuthnChallenge?: AccountWebAuthnChallenge,
    /** Fixed, value-free location for sync response diagnostics. */
    readonly syncInvalidResponseStage?: BitwardenSyncInvalidResponseStage,
    /** Main-process-only, bounded provider ids from the token challenge. */
    readonly twoFactorProviders?: readonly BitwardenTwoFactorProviderId[],
    /** Fixed, value-free reason suitable for renderer diagnostics. */
    readonly syncInvalidResponseReason?: BitwardenSyncInvalidResponseReason
  ) {
    super(`Bitwarden direct sync failed (${code})`)
    this.name = 'BitwardenDirectError'
  }
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

export interface BitwardenFolder {
  id: string
  name: string
}

export interface BitwardenLoginUri extends VaultLoginUri {}

/**
 * Attachment metadata that is safe to show outside the direct-sync client.
 * File keys, download URLs, and file contents deliberately stay private to the main process.
 */
export interface BitwardenAttachment {
  id: string
  fileName: string
  size: number
  sizeName: string
  /** True when the server did not provide a per-attachment encrypted key. */
  legacy: boolean
}

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

/** @deprecated Use BitwardenLoginApprovalRequest. */
export type BitwardenLoginRequestMetadata = BitwardenLoginApprovalRequest

export interface BitwardenStreamedAttachment {
  fileName: string
  data: BitwardenAttachmentByteSource
  dispose(): Promise<void>
}

export interface BitwardenLoginItem extends VaultItemFields {
  id: string
  type: VaultItemType
  organizationId: null
  folderId: string | null
  name: string
  notes: string | null
  favorite: boolean
  uris: BitwardenLoginUri[]
  creationDate: string | null
  revisionDate: string | null
  deletedAt: string | null
  archivedAt: string | null
  reprompt: VaultReprompt
  customFields: VaultCustomField[]
  passkeys: StoredPasskeyCredential[]
  passwordHistory: VaultPasswordHistoryEntry[]
  passwordRevisionDate: string | null
  autofillOnPageLoad: boolean | null
  attachments: BitwardenAttachment[]
}

/** Renderer-safe metadata for an organization membership. Organization keys stay in main. */
export interface BitwardenOrganization {
  id: string
  name: string
  status: number | null
  type: number | null
  enabled: boolean
  identifier: string | null
  hasPublicAndPrivateKeys: boolean
}

/** Renderer-safe metadata for a synced organization Collection. */
export interface BitwardenCollection {
  id: string
  organizationId: string
  name: string
  externalId: string | null
  readOnly: boolean
  hidePasswords: boolean
  manage: boolean
  type: number
  assigned: boolean
}

/** Decrypted organization cipher with server-authoritative collection permissions. */
export type BitwardenOrganizationCipher = Omit<BitwardenLoginItem, 'organizationId'> & {
  organizationId: string
  collectionIds: string[]
  edit: boolean
  viewPassword: boolean
  delete: boolean
  restore: boolean
}

/** Renderer-safe metadata for a decrypted file Send. File bytes remain main-process-only. */
export interface BitwardenSendFile {
  id: string
  fileName: string
  size: number
  sizeName: string | null
}

/** Decrypted personal Send metadata; encrypted fields remain main-process-only cache data. */
export interface BitwardenSendItem {
  id: string
  accessId: string
  type: 'text' | 'file'
  name: string
  notes: string | null
  text: string
  /** Present only for file Sends. The encrypted file bytes never leave main. */
  file?: BitwardenSendFile
  hidden: boolean
  maxAccessCount: number | null
  accessCount: number
  revisionDate: string
  expirationDate: string | null
  deletionDate: string
  disabled: boolean
  hideEmail: boolean
  authType: 0 | 1 | 2
  passwordProtected: boolean
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

/** Secret-free account capabilities observed in the latest committed sync snapshot. */
export interface BitwardenUserDecryptionCapabilities {
  hasWebAuthnPrfOptions: boolean
  hasV2UpgradeToken: boolean
  /** BearWarden does not yet perform PRF-based account unlock. */
  webAuthnPrfUnlockSupported: false
  /** BearWarden accepts V2 accounts but does not initiate an account-key upgrade. */
  v2AccountUpgradeSupported: false
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

interface CachedFolder {
  raw: JsonObject
  item: BitwardenFolder
}

interface CachedLogin {
  raw: JsonObject
  item: BitwardenLoginItem
}

interface CachedSend {
  raw: JsonObject
  item: BitwardenSendItem
}

interface PreparedLoginImportPayload {
  request: BitwardenPersonalCipherImportRequest
}

interface ResolvedBitwardenDraft extends VaultItemFields {
  type: VaultItemType
  name: string
  notes: string | null
  folderId: string | null
  favorite: boolean
  archivedAt: string | null
  reprompt: VaultReprompt
  uris: VaultLoginUri[]
  customFields: VaultCustomField[]
  passkeys: StoredPasskeyCredential[]
  passwordHistory: VaultPasswordHistoryEntry[]
  passwordRevisionDate: string | null
  autofillOnPageLoad: boolean | null
  totpChanged: boolean
  customFieldsChanged: boolean
  passkeysChanged: boolean
  passwordHistoryChanged: boolean
}

function isRecord(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
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
    !isRecord(value) ||
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
      !isRecord(policy) ||
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
      (policy.data !== null && !isRecord(policy.data))
    ) {
      return invalidPersistedPolicySet()
    }
    if (
      (execution === 'actionable' &&
        (!isRecord(policy.data) || !isSafePersistedPolicyData(policy.data))) ||
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

function property(record: JsonObject, name: string): JsonValue | undefined {
  if (name in record) return record[name]
  const normalized = name.toLocaleLowerCase('en-US')
  const key = Object.keys(record).find(
    (candidate) => candidate.toLocaleLowerCase('en-US') === normalized
  )
  return key === undefined ? undefined : record[key]
}

function recordProperty(record: JsonObject, name: string): JsonObject | null {
  const value = property(record, name)
  return isRecord(value) ? value : null
}

function optionalRemoteArrayProperty(record: JsonObject, name: string): JsonValue[] {
  const value = property(record, name)
  if (value === undefined || value === null) return []
  if (!Array.isArray(value) || value.length > MAX_REMOTE_ENTITIES) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value
}

function requiredRemoteArrayProperty(record: JsonObject, name: string): JsonValue[] {
  const value = property(record, name)
  if (!Array.isArray(value) || value.length > MAX_REMOTE_ENTITIES) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value
}

function emptyEquivalentDomainSettings(): BitwardenEquivalentDomainSettings {
  return { equivalentDomains: [], globalEquivalentDomains: [] }
}

function parseSyncEquivalentDomainSettings(
  value: JsonValue | undefined
): BitwardenEquivalentDomainSettings {
  if (value === undefined || value === null) return emptyEquivalentDomainSettings()
  try {
    return parseEquivalentDomainSettings(value)
  } catch (error) {
    if (
      error instanceof BitwardenHttpError &&
      (error.code === 'INVALID_RESPONSE' || error.code === 'TOO_LARGE')
    ) {
      // Equivalent domains are ancillary matching hints. Invalid server-stored values must not
      // block vault data, and disabling every equivalence is the fail-closed matching fallback.
      return emptyEquivalentDomainSettings()
    }
    throw error
  }
}

function stringProperty(record: JsonObject, name: string): string | null {
  const value = property(record, name)
  return typeof value === 'string' ? value : null
}

function nullableStringProperty(record: JsonObject, name: string): string | null {
  const value = property(record, name)
  if (value === null || value === undefined) return null
  if (typeof value !== 'string') throw new BitwardenDirectError('INVALID_RESPONSE')
  return value
}

function requiredStringProperty(record: JsonObject, name: string): string {
  const value = stringProperty(record, name)
  if (!value) throw new BitwardenDirectError('INVALID_RESPONSE')
  return value
}

function assertUuidValue(value: string): string {
  if (!UUID_PATTERN.test(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
  return value
}

function booleanProperty(record: JsonObject, name: string, fallback = false): boolean {
  const value = property(record, name)
  if (value === undefined || value === null) return fallback
  if (typeof value !== 'boolean') throw new BitwardenDirectError('INVALID_RESPONSE')
  return value
}

function nullableBooleanProperty(record: JsonObject, name: string): boolean | null {
  const value = property(record, name)
  if (value === undefined || value === null) return null
  if (typeof value !== 'boolean') throw new BitwardenDirectError('INVALID_RESPONSE')
  return value
}

function nullableIsoDateProperty(record: JsonObject, name: string): string | null {
  const value = nullableStringProperty(record, name)
  if (value === null) return null
  if (!Number.isFinite(Date.parse(value))) throw new BitwardenDirectError('INVALID_RESPONSE')
  return new Date(value).toISOString()
}

function repromptProperty(record: JsonObject): VaultReprompt {
  const value = property(record, 'reprompt')
  if (value === undefined || value === null) return 0
  if (value !== 0 && value !== 1) throw new BitwardenDirectError('INVALID_RESPONSE')
  return value
}

function validatePersonalCipherSecurityMetadata(record: JsonObject): void {
  nullableStringProperty(record, 'folderId')
  booleanProperty(record, 'favorite')
  nullableStringProperty(record, 'creationDate')
  nullableStringProperty(record, 'revisionDate')
  repromptProperty(record)
  for (const name of ['deletedDate', 'archivedDate'] as const) {
    const value = nullableStringProperty(record, name)
    if (value !== null) normalizedBitwardenTimestamp(value)
  }
}

function draftReprompt(value: unknown): VaultReprompt {
  if (value !== 0 && value !== 1) throw new BitwardenDirectError('INVALID_RESPONSE')
  return value
}

function remoteCipherType(record: JsonObject): number {
  const value = property(record, 'type')
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > 2_147_483_647
  ) {
    throw new BitwardenDirectError(
      'INVALID_RESPONSE',
      undefined,
      undefined,
      undefined,
      'unsupported-cipher-type'
    )
  }
  return value
}

function isSupportedCipherType(value: number): value is BitwardenCipherType {
  return value === 1 || value === 2 || value === 3 || value === 4 || value === 5
}

function isQuarantinablePersonalCipherError(error: unknown): boolean {
  if (error instanceof BitwardenDirectError) {
    return (
      error.code === 'INVALID_RESPONSE' ||
      error.code === 'INVALID_SSH_KEY' ||
      error.code === 'UNSUPPORTED_ACCOUNT_ENCRYPTION'
    )
  }
  if (!(error instanceof BitwardenCryptoError)) return false
  return (
    error.code === 'INVALID_INPUT' ||
    error.code === 'INVALID_KEY' ||
    error.code === 'INVALID_CIPHERSTRING' ||
    error.code === 'AUTHENTICATION_FAILED' ||
    error.code === 'UNSUPPORTED_CIPHER_TYPE' ||
    error.code === 'DECRYPTION_FAILED'
  )
}

function bitwardenCipherType(record: JsonObject): BitwardenCipherType {
  const value = remoteCipherType(record)
  if (!isSupportedCipherType(value)) {
    throw new BitwardenDirectError(
      'INVALID_RESPONSE',
      undefined,
      undefined,
      undefined,
      'unsupported-cipher-type'
    )
  }
  return value
}

function emptyVaultItemFields(): VaultItemFields {
  return {
    username: '',
    password: '',
    totp: '',
    uri: null,
    cardholderName: '',
    brand: '',
    number: '',
    expMonth: '',
    expYear: '',
    code: '',
    title: '',
    firstName: '',
    middleName: '',
    lastName: '',
    address1: '',
    address2: '',
    address3: '',
    city: '',
    state: '',
    postalCode: '',
    country: '',
    company: '',
    email: '',
    phone: '',
    ssn: '',
    identityUsername: '',
    passportNumber: '',
    licenseNumber: '',
    privateKey: '',
    publicKey: '',
    fingerprint: ''
  }
}

const CUSTOM_FIELD_TYPE_BY_WIRE_TYPE: Record<number, VaultCustomFieldType> = {
  0: 'text',
  1: 'hidden',
  2: 'boolean',
  3: 'linked'
}

const WIRE_TYPE_BY_CUSTOM_FIELD_TYPE = {
  text: 0,
  hidden: 1,
  boolean: 2,
  linked: 3
} as const satisfies Record<VaultCustomFieldType, number>

function customFieldType(value: JsonValue | undefined): VaultCustomFieldType {
  if (value === undefined || value === null) return 'text'
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return CUSTOM_FIELD_TYPE_BY_WIRE_TYPE[value] ?? 'text'
}

function draftCustomFieldType(value: JsonValue | undefined): VaultCustomFieldType {
  if (value === 'text' || value === 'hidden' || value === 'boolean' || value === 'linked') {
    return value
  }
  throw new BitwardenDirectError('INVALID_RESPONSE')
}

function customFieldLinkedId(record: JsonObject): number | null {
  const value = property(record, 'linkedId')
  if (value === undefined || value === null) return null
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value
}

function nullableCustomFieldString(record: JsonObject, name: string): string | null {
  const value = property(record, name)
  if (value === undefined || value === null) return null
  if (typeof value !== 'string' || value.length > MAX_CUSTOM_FIELD_STRING_LENGTH) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value
}

function customFieldArray(value: JsonValue | undefined): JsonValue[] {
  if (value === undefined || value === null) return []
  if (!Array.isArray(value) || value.length > MAX_CUSTOM_FIELDS) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value
}

function decryptLegacyCustomFields(
  rawFields: JsonValue | undefined,
  key: BitwardenSymmetricKey
): VaultCustomField[] {
  return customFieldArray(rawFields).map((rawField) => {
    if (!isRecord(rawField)) throw new BitwardenDirectError('INVALID_RESPONSE')
    const name = nullableCustomFieldString(rawField, 'name')
    const value = nullableCustomFieldString(rawField, 'value')
    return {
      name: name === null ? '' : decryptBitwardenString(name, key),
      value: value === null ? '' : decryptBitwardenString(value, key),
      type: customFieldType(property(rawField, 'type')),
      linkedId: customFieldLinkedId(rawField)
    }
  })
}

function decryptBlobCustomFields(rawFields: JsonValue | undefined): VaultCustomField[] {
  return customFieldArray(rawFields).map((rawField) => {
    if (!isRecord(rawField)) throw new BitwardenDirectError('INVALID_RESPONSE')
    const name = nullableCustomFieldString(rawField, 'name')
    const value = nullableCustomFieldString(rawField, 'value')
    return {
      name: name ?? '',
      value: value ?? '',
      type: customFieldType(property(rawField, 'type')),
      linkedId: customFieldLinkedId(rawField)
    }
  })
}

function validateDraftCustomFields(value: unknown): VaultCustomField[] {
  if (!Array.isArray(value) || value.length > MAX_CUSTOM_FIELDS) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value.map((field) => {
    if (!isRecord(field)) throw new BitwardenDirectError('INVALID_RESPONSE')
    const name = property(field, 'name')
    const fieldValue = property(field, 'value')
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
      type: draftCustomFieldType(property(field, 'type')),
      linkedId: customFieldLinkedId(field)
    }
  })
}

function cloneCustomFields(fields: VaultCustomField[]): VaultCustomField[] {
  return fields.map((field) => ({ ...field }))
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

function encryptLegacyCustomFields(
  fields: VaultCustomField[],
  key: BitwardenSymmetricKey
): JsonValue[] {
  return fields.map((field) => ({
    name: encryptBitwardenString(field.name, key),
    value: field.type === 'linked' ? null : encryptBitwardenString(field.value, key),
    type: WIRE_TYPE_BY_CUSTOM_FIELD_TYPE[field.type],
    linkedId: field.linkedId
  }))
}

function customFieldsToBlob(fields: VaultCustomField[]): JsonValue[] {
  return fields.map((field) => ({
    name: field.name,
    value: field.type === 'linked' ? null : field.value,
    type: WIRE_TYPE_BY_CUSTOM_FIELD_TYPE[field.type],
    linkedId: field.linkedId
  }))
}

function passwordHistoryArray(value: JsonValue | undefined): JsonValue[] {
  if (value === undefined || value === null) return []
  if (!Array.isArray(value) || value.length > MAX_PASSWORD_HISTORY) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value
}

function normalizedBitwardenTimestamp(value: unknown): string {
  if (typeof value !== 'string') throw new BitwardenDirectError('INVALID_RESPONSE')

  // Bitwarden-compatible servers serialize UTC timestamps with differing fractional-second
  // precision. Normalize that precision without accepting Date.parse's broader date grammar or
  // calendar rollovers such as February 30.
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(value)
  if (!match) throw new BitwardenDirectError('INVALID_RESPONSE')

  const milliseconds = (match[2] ?? '').padEnd(3, '0').slice(0, 3)
  const canonical = `${match[1]}.${milliseconds}Z`
  const parsed = Date.parse(canonical)
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== canonical) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return canonical
}

function passwordHistoryDate(value: unknown): string {
  return normalizedBitwardenTimestamp(value)
}

function draftNullableBoolean(value: unknown): boolean | null {
  if (value === null || typeof value === 'boolean') return value
  throw new BitwardenDirectError('INVALID_RESPONSE')
}

function checkedHistoryPassword(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_PASSWORD_LENGTH) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value
}

function decryptLegacyPasswordHistory(
  value: JsonValue | undefined,
  key: BitwardenSymmetricKey
): VaultPasswordHistoryEntry[] {
  return passwordHistoryArray(value).map((raw) => {
    if (!isRecord(raw)) throw new BitwardenDirectError('INVALID_RESPONSE')
    const encrypted = requiredStringProperty(raw, 'password')
    return {
      password: checkedHistoryPassword(decryptBitwardenString(encrypted, key)),
      lastUsedDate: passwordHistoryDate(property(raw, 'lastUsedDate'))
    }
  })
}

function decryptBlobPasswordHistory(value: JsonValue | undefined): VaultPasswordHistoryEntry[] {
  return passwordHistoryArray(value).map((raw) => {
    if (!isRecord(raw)) throw new BitwardenDirectError('INVALID_RESPONSE')
    return {
      password: checkedHistoryPassword(property(raw, 'password')),
      lastUsedDate: passwordHistoryDate(property(raw, 'lastUsedDate'))
    }
  })
}

function validateDraftPasswordHistory(value: unknown): VaultPasswordHistoryEntry[] {
  if (!Array.isArray(value) || value.length > MAX_PASSWORD_HISTORY) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value.map((entry) => {
    if (!isRecord(entry)) throw new BitwardenDirectError('INVALID_RESPONSE')
    return {
      password: checkedHistoryPassword(property(entry, 'password')),
      lastUsedDate: passwordHistoryDate(property(entry, 'lastUsedDate'))
    }
  })
}

function clonePasswordHistory(
  entries: readonly VaultPasswordHistoryEntry[]
): VaultPasswordHistoryEntry[] {
  return entries.map((entry) => ({ ...entry }))
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

function encryptLegacyPasswordHistory(
  entries: readonly VaultPasswordHistoryEntry[],
  key: BitwardenSymmetricKey
): JsonValue {
  if (entries.length === 0) return null
  return entries.map((entry) => ({
    password: encryptBitwardenString(entry.password, key),
    lastUsedDate: entry.lastUsedDate
  }))
}

function passwordHistoryToBlob(entries: readonly VaultPasswordHistoryEntry[]): JsonValue[] {
  return entries.map((entry) => ({ ...entry }))
}

function resolveDraft(
  draft: BitwardenLoginDraft,
  previous: BitwardenLoginItem | null
): ResolvedBitwardenDraft {
  const fields = { ...emptyVaultItemFields(), ...(previous ?? {}) }
  const fieldNames = Object.keys(emptyVaultItemFields()) as (keyof VaultItemFields)[]
  for (const name of fieldNames) {
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
        : passwordHistoryDate(draft.passwordRevisionDate)
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

function attachmentSize(record: JsonObject): number {
  const value = property(record, 'size')
  if (value === undefined || value === null) return 0
  if (typeof value !== 'string' || !/^(0|[1-9]\d*)$/u.test(value)) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  const size = Number(value)
  if (!Number.isSafeInteger(size) || size < 0) throw new BitwardenDirectError('INVALID_RESPONSE')
  return size
}

function attachmentSizeName(record: JsonObject, size: number): string {
  const value = property(record, 'sizeName')
  if (value === undefined || value === null) return `${size} B`
  if (typeof value !== 'string' || value.length > MAX_ATTACHMENT_SIZE_NAME_LENGTH) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value
}

function decryptAttachments(raw: JsonObject, key: BitwardenSymmetricKey): BitwardenAttachment[] {
  const value = property(raw, 'attachments')
  if (value === undefined || value === null) return []
  const decryptAttachment = (
    id: string,
    encryptedFileName: string,
    details: JsonObject
  ): BitwardenAttachment => {
    if (!id || id.length > MAX_ATTACHMENT_ID_LENGTH) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    const fileName = decryptBitwardenString(encryptedFileName, key)
    if (!fileName || fileName.length > MAX_ATTACHMENT_FILE_NAME_LENGTH) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    const attachmentKey = property(details, 'key')
    if (
      attachmentKey !== undefined &&
      attachmentKey !== null &&
      typeof attachmentKey !== 'string'
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    if (typeof attachmentKey === 'string' && attachmentKey.length === 0) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    let unwrappedKey: Buffer | undefined
    try {
      if (typeof attachmentKey === 'string') {
        unwrappedKey = decryptBitwardenWrappedKey(attachmentKey, key)
        if (unwrappedKey.length !== USER_KEY_BYTES) {
          throw new BitwardenDirectError('INVALID_RESPONSE')
        }
      }
    } finally {
      unwrappedKey?.fill(0)
    }
    const size = attachmentSize(details)
    return {
      id,
      fileName,
      size,
      sizeName: attachmentSizeName(details, size),
      legacy: attachmentKey === undefined || attachmentKey === null
    }
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_ATTACHMENTS_PER_ITEM) throw new BitwardenDirectError('INVALID_RESPONSE')
    const attachments = value.map((entry) => {
      if (!isRecord(entry)) throw new BitwardenDirectError('INVALID_RESPONSE')
      return decryptAttachment(
        requiredStringProperty(entry, 'id'),
        requiredStringProperty(entry, 'fileName'),
        entry
      )
    })
    if (new Set(attachments.map((attachment) => attachment.id)).size !== attachments.length) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    return attachments
  }
  if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')

  const detailsValue = property(raw, 'attachments2')
  if (detailsValue !== undefined && detailsValue !== null && !isRecord(detailsValue)) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  const entries = Object.entries(value)
  if (entries.length > MAX_ATTACHMENTS_PER_ITEM) throw new BitwardenDirectError('INVALID_RESPONSE')
  const attachments = entries.map(([id, encryptedFileName]) => {
    if (!id || typeof encryptedFileName !== 'string' || !encryptedFileName) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    const details = detailsValue ? detailsValue[id] : undefined
    if (details !== undefined && !isRecord(details))
      throw new BitwardenDirectError('INVALID_RESPONSE')
    if (details) {
      const detailFileName = requiredStringProperty(details, 'fileName')
      if (detailFileName !== encryptedFileName) throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    return decryptAttachment(id, encryptedFileName, details ?? {})
  })
  if (new Set(attachments.map((attachment) => attachment.id)).size !== attachments.length) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return attachments
}

interface FreshAttachmentMetadata {
  encryptedKey: string | null
  size: number
}

/**
 * The HTTP layer resolves the short-lived attachment URL and deliberately does
 * not return it.  This layer still authenticates every fresh metadata field
 * against the cached personal item before it accepts the downloaded bytes.
 */
function freshAttachmentMetadata(
  response: BitwardenAttachmentDownload,
  attachmentId: string,
  expected: BitwardenAttachment,
  cipherKey: BitwardenSymmetricKey
): FreshAttachmentMetadata {
  if (response.id !== attachmentId) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  if (!Number.isSafeInteger(response.size) || response.size < 0) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }

  const fileName = decryptBitwardenString(response.fileName, cipherKey)
  if (fileName !== expected.fileName) throw new BitwardenDirectError('INVALID_RESPONSE')

  if (response.key !== null && typeof response.key !== 'string') {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  if (response.key === '') throw new BitwardenDirectError('INVALID_RESPONSE')
  const encryptedKey = response.key
  if ((encryptedKey === null) !== expected.legacy) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }

  const size = response.size
  if (size !== expected.size) throw new BitwardenDirectError('INVALID_RESPONSE')

  return { encryptedKey, size }
}

export function addAggregateRemoteRows(
  current: number,
  additional: number,
  maximum = MAX_AGGREGATE_REMOTE_ROWS
): number {
  if (
    !Number.isSafeInteger(current) ||
    current < 0 ||
    !Number.isSafeInteger(additional) ||
    additional < 0 ||
    additional > maximum - current
  ) {
    throw new BitwardenDirectError(
      'INVALID_RESPONSE',
      undefined,
      undefined,
      undefined,
      'snapshot-limit'
    )
  }
  return current + additional
}

function rawCipherNestedRows(raw: JsonObject): number {
  let rows = 0
  const addArray = (value: JsonValue | undefined): void => {
    if (Array.isArray(value)) rows = addAggregateRemoteRows(rows, value.length)
  }
  addArray(property(raw, 'fields'))
  addArray(property(raw, 'passwordHistory'))
  addArray(property(raw, 'collectionIds'))
  const attachments = property(raw, 'attachments')
  if (Array.isArray(attachments)) {
    rows = addAggregateRemoteRows(rows, attachments.length)
  } else if (isRecord(attachments)) {
    rows = addAggregateRemoteRows(rows, Object.keys(attachments).length)
  }
  const attachmentDetails = property(raw, 'attachments2')
  if (isRecord(attachmentDetails)) {
    rows = addAggregateRemoteRows(rows, Object.keys(attachmentDetails).length)
  }
  const login = recordProperty(raw, 'login')
  if (login) {
    addArray(property(login, 'uris'))
    addArray(property(login, 'fido2Credentials'))
  }
  return rows
}

function parsedCipherNestedRows(item: BitwardenLoginItem): number {
  return (
    item.uris.length +
    item.passkeys.length +
    item.customFields.length +
    item.passwordHistory.length +
    item.attachments.length
  )
}

function decodedBlobNestedRows(content: JsonObject): number {
  let rows = 0
  const addArray = (value: JsonValue | undefined): void => {
    if (Array.isArray(value)) rows = addAggregateRemoteRows(rows, value.length)
  }
  addArray(property(content, 'fields'))
  addArray(property(content, 'passwordHistory'))
  const typeData = recordProperty(content, 'typeData')
  if (typeData) {
    addArray(property(typeData, 'uris'))
    addArray(property(typeData, 'fido2Credentials'))
  }
  return rows
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

function optionalJson(record: JsonObject, name: string): JsonValue | undefined {
  const value = property(record, name)
  return value === undefined ? undefined : structuredClone(value)
}

function setOptional(target: JsonObject, name: string, value: JsonValue | undefined): void {
  if (value !== undefined) target[name] = value
}

function encryptLegacyUris(
  uris: readonly VaultLoginUri[],
  previousLogin: JsonObject | null,
  key: BitwardenSymmetricKey
): JsonValue[] {
  const previous = previousLogin ? property(previousLogin, 'uris') : null
  if (
    previous !== null &&
    previous !== undefined &&
    (!Array.isArray(previous) || previous.length > MAX_LOGIN_URIS)
  ) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  const previousUris = Array.isArray(previous) ? previous : []
  const preserved = new Map<string, { rows: JsonObject[]; next: number }>()
  for (const value of previousUris) {
    if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
    const encrypted = nullableStringProperty(value, 'uri')
    const plaintext = encrypted === null ? '' : decryptBitwardenString(encrypted, key)
    const match = validateUriMatch(property(value, 'match'))
    const matchKey = uriRowKey(plaintext, match)
    const group = preserved.get(matchKey) ?? { rows: [], next: 0 }
    group.rows.push(value)
    preserved.set(matchKey, group)
  }
  return uris.map((entry) => {
    const group = preserved.get(uriRowKey(entry.uri, entry.match))
    const previousEntry = group?.rows[group.next]
    if (group && previousEntry) {
      group.next += 1
      return structuredClone(previousEntry)
    }
    // A checksum is valid only for its exact plaintext. New or changed rows deliberately omit it.
    return { uri: encryptBitwardenString(entry.uri, key), match: entry.match }
  })
}

function blobUris(uris: readonly VaultLoginUri[], previous: JsonValue | undefined): JsonValue[] {
  if (
    previous !== null &&
    previous !== undefined &&
    (!Array.isArray(previous) || previous.length > MAX_LOGIN_URIS)
  ) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  const previousUris = Array.isArray(previous) ? previous : []
  const preserved = new Map<string, { rows: JsonObject[]; next: number }>()
  for (const value of previousUris) {
    if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
    const uri = nullableStringProperty(value, 'uri') ?? ''
    const match = validateUriMatch(property(value, 'match'))
    const matchKey = uriRowKey(uri, match)
    const group = preserved.get(matchKey) ?? { rows: [], next: 0 }
    group.rows.push(value)
    preserved.set(matchKey, group)
  }
  return uris.map((entry) => {
    const group = preserved.get(uriRowKey(entry.uri, entry.match))
    const previousEntry = group?.rows[group.next]
    if (group && previousEntry) {
      group.next += 1
      return structuredClone(previousEntry)
    }
    return { uri: entry.uri, match: entry.match }
  })
}

function uriRowKey(uri: string, match: VaultLoginUri['match']): string {
  return `${match === null ? 'null' : match}:${uri}`
}

function preservedAttachments(existing: JsonObject, request: JsonObject): void {
  const value = property(existing, 'attachments')
  if (value === undefined) return
  if (!Array.isArray(value)) {
    request.attachments = structuredClone(value)
    return
  }
  const revisionDate = optionalJson(existing, 'revisionDate') ?? null
  const attachments: JsonObject = {}
  const attachments2: JsonObject = {}
  for (const entry of value) {
    if (!isRecord(entry)) throw new BitwardenDirectError('INVALID_RESPONSE')
    const id = requiredStringProperty(entry, 'id')
    const fileName = requiredStringProperty(entry, 'fileName')
    attachments[id] = fileName
    const detail: JsonObject = { fileName, lastKnownRevisionDate: revisionDate }
    const key = optionalJson(entry, 'key')
    if (key !== undefined && key !== null) detail.key = key
    attachments2[id] = detail
  }
  request.attachments = attachments
  request.attachments2 = attachments2
}

function opaqueCipherBlob(record: JsonObject): string | null {
  const value = property(record, 'data')
  if (value === null || value === undefined || typeof value !== 'string') return null
  const data = value
  if (!data) return null
  if (data.trimStart().startsWith('{')) {
    let container: unknown
    try {
      container = JSON.parse(data)
    } catch {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    if (!isRecord(container) || property(container, 'format_version') !== 1) return null
    if (
      typeof property(container, 'wrapped_cek') !== 'string' ||
      typeof property(container, 'envelope') !== 'string'
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
  }
  return data
}

function decryptOptionalString(
  record: JsonObject,
  name: string,
  key: BitwardenSymmetricKey
): string {
  const encrypted = nullableStringProperty(record, name)
  return encrypted === null ? '' : decryptBitwardenString(encrypted, key)
}

function decryptOptionalNullableString(
  record: JsonObject,
  name: string,
  key: BitwardenSymmetricKey
): string | null {
  const encrypted = nullableStringProperty(record, name)
  return encrypted === null ? null : decryptBitwardenString(encrypted, key)
}

function assertCreationDate(value: string | null): string {
  return normalizedBitwardenTimestamp(value)
}

function assertPasskeyField(value: string): string {
  if (value.length > MAX_PASSKEY_FIELD_LENGTH) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value
}

function assertNullablePasskeyField(value: string | null): string | null {
  return value === null ? null : assertPasskeyField(value)
}

function validatePasskey(passkey: StoredPasskeyCredential): StoredPasskeyCredential {
  return {
    credentialId: assertPasskeyField(passkey.credentialId),
    keyType: assertPasskeyField(passkey.keyType),
    keyAlgorithm: assertPasskeyField(passkey.keyAlgorithm),
    keyCurve: assertPasskeyField(passkey.keyCurve),
    keyValue: assertPasskeyField(passkey.keyValue),
    rpId: assertPasskeyField(passkey.rpId),
    userHandle: assertNullablePasskeyField(passkey.userHandle),
    userName: assertNullablePasskeyField(passkey.userName),
    counter: assertPasskeyField(passkey.counter),
    rpName: assertNullablePasskeyField(passkey.rpName),
    userDisplayName: assertNullablePasskeyField(passkey.userDisplayName),
    discoverable: passkey.discoverable,
    creationDate: assertCreationDate(passkey.creationDate)
  }
}

function decryptFido2Credentials(
  login: JsonObject,
  key: BitwardenSymmetricKey
): StoredPasskeyCredential[] {
  const raw = property(login, 'fido2Credentials')
  if (raw === null || raw === undefined) return []
  if (!Array.isArray(raw) || raw.length > MAX_PASSKEYS_PER_ITEM) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return raw.map((value) => {
    if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
    return validatePasskey({
      credentialId: decryptBitwardenString(requiredStringProperty(value, 'credentialId'), key),
      keyType: decryptBitwardenString(requiredStringProperty(value, 'keyType'), key),
      keyAlgorithm: decryptBitwardenString(requiredStringProperty(value, 'keyAlgorithm'), key),
      keyCurve: decryptBitwardenString(requiredStringProperty(value, 'keyCurve'), key),
      keyValue: decryptBitwardenString(requiredStringProperty(value, 'keyValue'), key),
      rpId: decryptBitwardenString(requiredStringProperty(value, 'rpId'), key),
      userHandle: decryptOptionalNullableString(value, 'userHandle', key),
      userName: decryptOptionalNullableString(value, 'userName', key),
      counter: decryptBitwardenString(requiredStringProperty(value, 'counter'), key),
      rpName: decryptOptionalNullableString(value, 'rpName', key),
      userDisplayName: decryptOptionalNullableString(value, 'userDisplayName', key),
      discoverable:
        decryptBitwardenString(requiredStringProperty(value, 'discoverable'), key) === 'true',
      creationDate: requiredStringProperty(value, 'creationDate')
    })
  })
}

function parseBlobFido2Credentials(typeData: JsonObject): StoredPasskeyCredential[] {
  const raw = property(typeData, 'fido2Credentials')
  if (raw === null || raw === undefined) return []
  if (!Array.isArray(raw) || raw.length > MAX_PASSKEYS_PER_ITEM) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return raw.map((value) => {
    if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
    const counter = property(value, 'counter')
    const discoverable = property(value, 'discoverable')
    if (
      (typeof counter !== 'number' || !Number.isSafeInteger(counter) || counter < 0) &&
      (typeof counter !== 'string' || !/^\d+$/.test(counter))
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    if (typeof discoverable !== 'boolean') throw new BitwardenDirectError('INVALID_RESPONSE')
    return validatePasskey({
      credentialId: requiredStringProperty(value, 'credentialId'),
      keyType: requiredStringProperty(value, 'keyType'),
      keyAlgorithm: requiredStringProperty(value, 'keyAlgorithm'),
      keyCurve: requiredStringProperty(value, 'keyCurve'),
      keyValue: requiredStringProperty(value, 'keyValue'),
      rpId: requiredStringProperty(value, 'rpId'),
      userHandle: nullableStringProperty(value, 'userHandle'),
      userName: nullableStringProperty(value, 'userName'),
      counter: String(counter),
      rpName: nullableStringProperty(value, 'rpName'),
      userDisplayName: nullableStringProperty(value, 'userDisplayName'),
      discoverable,
      creationDate: requiredStringProperty(value, 'creationDate')
    })
  })
}

function encryptFido2Credential(
  passkey: StoredPasskeyCredential,
  key: BitwardenSymmetricKey
): JsonObject {
  const encryptNullable = (value: string | null): string | null =>
    value === null ? null : encryptBitwardenString(value, key)
  return {
    credentialId: encryptBitwardenString(passkey.credentialId, key),
    keyType: encryptBitwardenString(passkey.keyType, key),
    keyAlgorithm: encryptBitwardenString(passkey.keyAlgorithm, key),
    keyCurve: encryptBitwardenString(passkey.keyCurve, key),
    keyValue: encryptBitwardenString(passkey.keyValue, key),
    rpId: encryptBitwardenString(passkey.rpId, key),
    userHandle: encryptNullable(passkey.userHandle),
    userName: encryptNullable(passkey.userName),
    counter: encryptBitwardenString(passkey.counter, key),
    rpName: encryptNullable(passkey.rpName),
    userDisplayName: encryptNullable(passkey.userDisplayName),
    discoverable: encryptBitwardenString(String(passkey.discoverable), key),
    creationDate: passkey.creationDate
  }
}

function passkeyToBlob(passkey: StoredPasskeyCredential): JsonObject {
  const counter = Number(passkey.counter)
  if (!Number.isSafeInteger(counter) || counter < 0) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return {
    credentialId: passkey.credentialId,
    keyType: passkey.keyType,
    keyAlgorithm: passkey.keyAlgorithm,
    keyCurve: passkey.keyCurve,
    keyValue: passkey.keyValue,
    rpId: passkey.rpId,
    userHandle: passkey.userHandle,
    userName: passkey.userName,
    counter,
    rpName: passkey.rpName,
    userDisplayName: passkey.userDisplayName,
    discoverable: passkey.discoverable,
    creationDate: passkey.creationDate
  }
}

function validateUriMatch(value: JsonValue | undefined): VaultUriMatch | null {
  if (value === null || value === undefined) return null
  if (!Number.isSafeInteger(value) || typeof value !== 'number' || value < 0 || value > 5) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value as VaultUriMatch
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
  private syncedUserDecryptionCapabilities: BitwardenUserDecryptionCapabilities = {
    hasWebAuthnPrfOptions: false,
    hasV2UpgradeToken: false,
    webAuthnPrfUnlockSupported: false,
    v2AccountUpgradeSupported: false
  }
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
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
    let masterPasswordHash = ''
    let mutationStarted = false
    try {
      if (
        typeof masterPassword !== 'string' ||
        masterPassword.length === 0 ||
        masterPassword.length > MAX_SYNC_SECRET_LENGTH
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      this.requireProfileId()
      const prelogin = await this.http.prelogin(this.email, signal)
      masterKey = await deriveMasterKey(
        masterPassword,
        prelogin.salt ?? this.email,
        kdfFromPrelogin(prelogin)
      )
      passwordKey = await derivePasswordKey(masterKey, masterPassword)
      masterPasswordHash = passwordKey.toString('base64')
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
      masterKey?.fill(0)
      passwordKey?.fill(0)
      masterPasswordHash = ''
    }
  }

  async deauthorizeAllSessions(masterPassword: string, signal?: AbortSignal): Promise<void> {
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
    let masterPasswordHash = ''
    let mutationStarted = false
    try {
      if (
        typeof masterPassword !== 'string' ||
        masterPassword.length === 0 ||
        masterPassword.length > MAX_SYNC_SECRET_LENGTH
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      this.requireProfileId()
      const prelogin = await this.http.prelogin(this.email, signal)
      masterKey = await deriveMasterKey(
        masterPassword,
        prelogin.salt ?? this.email,
        kdfFromPrelogin(prelogin)
      )
      passwordKey = await derivePasswordKey(masterKey, masterPassword)
      masterPasswordHash = passwordKey.toString('base64')
      if (signal?.aborted) throw new BitwardenDirectError('ABORTED')
      await this.http.deauthorizeAllSessions(masterPasswordHash, signal, () => {
        mutationStarted = true
      })
      await this.clearDeauthorizedSession()
    } catch (error) {
      const mapped = this.mapError(error)
      if (
        mutationStarted &&
        (mapped.code === 'NETWORK' ||
          mapped.code === 'ABORTED' ||
          mapped.code === 'INVALID_RESPONSE')
      ) {
        await this.clearDeauthorizedSession().catch(() => undefined)
        throw new BitwardenDirectError('SESSION_DEAUTHORIZATION_UNKNOWN')
      }
      throw mapped
    } finally {
      masterKey?.fill(0)
      passwordKey?.fill(0)
      masterPasswordHash = ''
    }
  }

  async getPersonalApiKey(
    masterPassword: string,
    rotate: boolean,
    signal?: AbortSignal
  ): Promise<{ clientId: string; clientSecret: string; revisionDate: string }> {
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
    let result: BitwardenPersonalApiKey | null = null
    let rotationRequestStarted = false
    try {
      if (
        typeof masterPassword !== 'string' ||
        masterPassword.length === 0 ||
        masterPassword.length > MAX_SYNC_SECRET_LENGTH
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const profileId = this.requireProfileId()
      const prelogin = await this.http.prelogin(this.email, signal)
      masterKey = await deriveMasterKey(
        masterPassword,
        prelogin.salt ?? this.email,
        kdfFromPrelogin(prelogin)
      )
      passwordKey = await derivePasswordKey(masterKey, masterPassword)
      rotationRequestStarted = rotate
      result = await this.http.getPersonalApiKey(passwordKey.toString('base64'), rotate, signal)
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
      masterKey?.fill(0)
      passwordKey?.fill(0)
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
      if (
        mutationStarted &&
        (mapped.code === 'NETWORK' ||
          mapped.code === 'ABORTED' ||
          mapped.code === 'INVALID_RESPONSE')
      ) {
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
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
    try {
      if (
        typeof masterPassword !== 'string' ||
        masterPassword.length === 0 ||
        masterPassword.length > MAX_SYNC_SECRET_LENGTH
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      this.requireProfileId()
      const prelogin = await this.http.prelogin(this.email, signal)
      masterKey = await deriveMasterKey(
        masterPassword,
        prelogin.salt ?? this.email,
        kdfFromPrelogin(prelogin)
      )
      passwordKey = await derivePasswordKey(masterKey, masterPassword)
      const code = await this.http.getTwoFactorRecoveryCode(passwordKey.toString('base64'), signal)
      await this.captureSession()
      return code
    } catch (error) {
      throw this.mapError(error)
    } finally {
      masterKey?.fill(0)
      passwordKey?.fill(0)
    }
  }

  async disableTwoFactorProvider(
    type: 0 | 1 | 2 | 3 | 7,
    masterPassword: string,
    signal?: AbortSignal
  ): Promise<void> {
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
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
      const prelogin = await this.http.prelogin(this.email, signal)
      masterKey = await deriveMasterKey(
        masterPassword,
        prelogin.salt ?? this.email,
        kdfFromPrelogin(prelogin)
      )
      passwordKey = await derivePasswordKey(masterKey, masterPassword)
      masterPasswordHash = passwordKey.toString('base64')
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
      if (
        mutationStarted &&
        (mapped.code === 'NETWORK' ||
          mapped.code === 'ABORTED' ||
          mapped.code === 'INVALID_RESPONSE') &&
        !usedUnverifiableProviderEscape &&
        (await this.isTwoFactorProviderAuthoritativelyDisabled(type, masterPasswordHash, signal))
      ) {
        await this.captureSession()
        return
      }
      if (
        mutationStarted &&
        (mapped.code === 'NETWORK' ||
          mapped.code === 'ABORTED' ||
          mapped.code === 'INVALID_RESPONSE')
      ) {
        throw new BitwardenDirectError('TWO_FACTOR_MUTATION_UNKNOWN')
      }
      throw mapped
    } finally {
      masterKey?.fill(0)
      passwordKey?.fill(0)
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
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
    try {
      if (
        typeof masterPassword !== 'string' ||
        masterPassword.length === 0 ||
        masterPassword.length > MAX_SYNC_SECRET_LENGTH
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      this.requireProfileId()
      const prelogin = await this.http.prelogin(this.email, signal)
      masterKey = await deriveMasterKey(
        masterPassword,
        prelogin.salt ?? this.email,
        kdfFromPrelogin(prelogin)
      )
      passwordKey = await derivePasswordKey(masterKey, masterPassword)
      const setup = await this.http.getAuthenticatorSetup(passwordKey.toString('base64'), signal)
      await this.captureSession()
      return setup
    } catch (error) {
      throw this.mapError(error)
    } finally {
      masterKey?.fill(0)
      passwordKey?.fill(0)
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
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
    let mutationStarted = false
    try {
      let masterPasswordHash: string | undefined
      if (request.verificationMode === 'master-password') {
        const password = request.masterPassword
        if (
          typeof password !== 'string' ||
          password.length === 0 ||
          password.length > MAX_SYNC_SECRET_LENGTH
        ) {
          throw new BitwardenDirectError('INVALID_RESPONSE')
        }
        const prelogin = await this.http.prelogin(this.email, signal)
        masterKey = await deriveMasterKey(
          password,
          prelogin.salt ?? this.email,
          kdfFromPrelogin(prelogin)
        )
        passwordKey = await derivePasswordKey(masterKey, password)
        masterPasswordHash = passwordKey.toString('base64')
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
      masterKey?.fill(0)
      passwordKey?.fill(0)
      if (request.masterPassword !== undefined) request.masterPassword = ''
      if (request.userVerificationToken !== undefined) request.userVerificationToken = ''
    }
  }

  async beginEmailTwoFactorSetup(
    masterPassword: string,
    signal?: AbortSignal
  ): Promise<BitwardenEmailTwoFactorSetup> {
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
    try {
      if (
        typeof masterPassword !== 'string' ||
        masterPassword.length === 0 ||
        masterPassword.length > MAX_SYNC_SECRET_LENGTH
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      this.requireProfileId()
      const prelogin = await this.http.prelogin(this.email, signal)
      masterKey = await deriveMasterKey(
        masterPassword,
        prelogin.salt ?? this.email,
        kdfFromPrelogin(prelogin)
      )
      passwordKey = await derivePasswordKey(masterKey, masterPassword)
      const setup = await this.http.getEmailTwoFactorSetup(passwordKey.toString('base64'), signal)
      await this.captureSession()
      return setup
    } catch (error) {
      throw this.mapError(error)
    } finally {
      masterKey?.fill(0)
      passwordKey?.fill(0)
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
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
    let mutationStarted = false
    try {
      let masterPasswordHash: string | undefined
      if (request.verificationMode === 'master-password') {
        const password = request.masterPassword
        if (
          typeof password !== 'string' ||
          password.length === 0 ||
          password.length > MAX_SYNC_SECRET_LENGTH
        ) {
          throw new BitwardenDirectError('INVALID_RESPONSE')
        }
        const prelogin = await this.http.prelogin(this.email, signal)
        masterKey = await deriveMasterKey(
          password,
          prelogin.salt ?? this.email,
          kdfFromPrelogin(prelogin)
        )
        passwordKey = await derivePasswordKey(masterKey, password)
        masterPasswordHash = passwordKey.toString('base64')
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
      masterKey?.fill(0)
      passwordKey?.fill(0)
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
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
    let mutationStarted = false
    try {
      let masterPasswordHash: string | undefined
      if (request.verificationMode === 'master-password') {
        const password = request.masterPassword
        if (
          typeof password !== 'string' ||
          password.length === 0 ||
          password.length > MAX_SYNC_SECRET_LENGTH
        ) {
          throw new BitwardenDirectError('INVALID_RESPONSE')
        }
        const prelogin = await this.http.prelogin(this.email, signal)
        masterKey = await deriveMasterKey(
          password,
          prelogin.salt ?? this.email,
          kdfFromPrelogin(prelogin)
        )
        passwordKey = await derivePasswordKey(masterKey, password)
        masterPasswordHash = passwordKey.toString('base64')
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
      masterKey?.fill(0)
      passwordKey?.fill(0)
      request.token = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      if (request.userVerificationToken !== undefined) request.userVerificationToken = ''
    }
  }

  async beginWebAuthnSetup(
    masterPassword: string,
    signal?: AbortSignal
  ): Promise<BitwardenWebAuthnRegistrationSetup> {
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
    let masterPasswordHash = ''
    let setup: BitwardenWebAuthnSetup | null = null
    try {
      if (
        typeof masterPassword !== 'string' ||
        masterPassword.length === 0 ||
        masterPassword.length > MAX_SYNC_SECRET_LENGTH
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      this.requireProfileId()
      const prelogin = await this.http.prelogin(this.email, signal)
      masterKey = await deriveMasterKey(
        masterPassword,
        prelogin.salt ?? this.email,
        kdfFromPrelogin(prelogin)
      )
      passwordKey = await derivePasswordKey(masterKey, masterPassword)
      masterPasswordHash = passwordKey.toString('base64')
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
      masterKey?.fill(0)
      passwordKey?.fill(0)
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
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
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
        if (
          typeof password !== 'string' ||
          password.length === 0 ||
          password.length > MAX_SYNC_SECRET_LENGTH
        ) {
          throw new BitwardenDirectError('INVALID_RESPONSE')
        }
        const prelogin = await this.http.prelogin(this.email, signal)
        masterKey = await deriveMasterKey(
          password,
          prelogin.salt ?? this.email,
          kdfFromPrelogin(prelogin)
        )
        passwordKey = await derivePasswordKey(masterKey, password)
        masterPasswordHash = passwordKey.toString('base64')
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
      masterKey?.fill(0)
      passwordKey?.fill(0)
      masterPasswordHash = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      if (request.userVerificationToken !== undefined) request.userVerificationToken = ''
      clearAccountWebAuthnAttestation(request.attestation)
    }
  }

  async deleteWebAuthnKey(id: number, masterPassword: string, signal?: AbortSignal): Promise<void> {
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
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
      const prelogin = await this.http.prelogin(this.email, signal)
      masterKey = await deriveMasterKey(
        masterPassword,
        prelogin.salt ?? this.email,
        kdfFromPrelogin(prelogin)
      )
      passwordKey = await derivePasswordKey(masterKey, masterPassword)
      masterPasswordHash = passwordKey.toString('base64')
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
      masterKey?.fill(0)
      passwordKey?.fill(0)
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
      const cached = this.decryptSend(raw, userKey)
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
      const created = this.decryptSend(upload.sendResponse, userKey)
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
        ...(confirmed.item.file ? { file: { ...confirmed.item.file } } : {})
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
      const accessType = property(access, 'type')
      const accessFile = recordProperty(access, 'file')
      if (accessId !== cached.item.id || accessType !== 1 || !accessFile) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const fileId = requiredStringProperty(accessFile, 'id')
      const encryptedFileName = requiredStringProperty(accessFile, 'fileName')
      const fileName = decryptBitwardenString(encryptedFileName, sendKey)
      const sizeValue = property(accessFile, 'size')
      const size =
        typeof sizeValue === 'string' && /^\d+$/u.test(sizeValue)
          ? Number(sizeValue)
          : typeof sizeValue === 'number' && Number.isSafeInteger(sizeValue)
            ? sizeValue
            : NaN
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
      const next = this.decryptSend(raw, userKey)
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
      const next = this.decryptSend(raw, this.requireUserKey())
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
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
    let masterPasswordHash = ''
    try {
      if (
        typeof masterPassword !== 'string' ||
        masterPassword.length === 0 ||
        masterPassword.length > MAX_SYNC_SECRET_LENGTH
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const prelogin = await this.http.prelogin(this.email, signal)
      masterKey = await deriveMasterKey(
        masterPassword,
        prelogin.salt ?? this.email,
        kdfFromPrelogin(prelogin)
      )
      passwordKey = await derivePasswordKey(masterKey, masterPassword)
      masterPasswordHash = passwordKey.toString('base64')
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
      masterKey?.fill(0)
      passwordKey?.fill(0)
      masterPasswordHash = ''
    }
  }

  async resendNewDeviceOtp(masterPassword: string, signal?: AbortSignal): Promise<void> {
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
    let masterPasswordHash = ''
    try {
      if (
        typeof masterPassword !== 'string' ||
        masterPassword.length === 0 ||
        masterPassword.length > MAX_SYNC_SECRET_LENGTH
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const prelogin = await this.http.prelogin(this.email, signal)
      masterKey = await deriveMasterKey(
        masterPassword,
        prelogin.salt ?? this.email,
        kdfFromPrelogin(prelogin)
      )
      passwordKey = await derivePasswordKey(masterKey, masterPassword)
      masterPasswordHash = passwordKey.toString('base64')
      if (signal?.aborted) throw new BitwardenDirectError('ABORTED')
      await this.http.resendNewDeviceOtp({ email: this.email, masterPasswordHash }, signal)
    } catch (error) {
      throw this.mapError(error)
    } finally {
      masterPassword = ''
      masterKey?.fill(0)
      passwordKey?.fill(0)
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
    let invalidResponseStage: BitwardenSyncInvalidResponseStage | null = 'access-token'
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
      const domains = property(payload, 'domains')
      const nextEquivalentDomainSettings = parseSyncEquivalentDomainSettings(domains)
      invalidResponseStage = 'account'
      const profile = recordProperty(payload, 'profile')
      if (!profile) throw new BitwardenDirectError('INVALID_RESPONSE')
      const profileId = requiredStringProperty(profile, 'id')
      const securityStamp = nullableStringProperty(profile, 'securityStamp')
      accountIdentityChange = this.accountIdentityChange(profileId, securityStamp)
      if (accountIdentityChange) throw new BitwardenDirectError('ACCOUNT_CHANGED')
      const nextUserDecryptionCapabilities = this.parseUserDecryptionCapabilities(payload)
      let nextPolicySet: BitwardenPolicySet
      try {
        nextPolicySet = parseBitwardenPolicySync(payload)
      } catch (error) {
        if (!(error instanceof BitwardenPolicyParseError)) throw error
        nextPolicySet = {
          source: 'none',
          policies: [],
          parseFailure:
            error.code === 'POLICY_LIMIT_EXCEEDED' ? 'limit-exceeded' : 'invalid-response'
        }
      }

      const wrappedUserKey = this.findWrappedUserKey(payload, profile)
      wrappedKeyFingerprint = createHash('sha256').update(wrappedUserKey, 'utf8').digest()
      const requiresLegacyUserKeyProof =
        pendingMasterKey !== null && isBitwardenLegacyMasterKeyWrappedUserKey(wrappedUserKey)
      let userKey: BitwardenSymmetricKey
      if (pendingMasterKey) {
        userKey = decryptBitwardenMasterKeyWrappedUserKey(wrappedUserKey, pendingMasterKey)
      } else if (this.userKey && this.wrappedUserKeyFingerprint?.equals(wrappedKeyFingerprint)) {
        userKey = cloneBitwardenAccountKey(this.userKey)
      } else if (isBitwardenLegacyMasterKeyWrappedUserKey(wrappedUserKey)) {
        this.clearDecryptedState()
        throw new BitwardenDirectError('AUTH_REQUIRED')
      } else if (this.stretchedKey) {
        const encodedUserKey = decryptBitwardenBytes(wrappedUserKey, this.stretchedKey)
        try {
          userKey = decodeBitwardenUserKey(encodedUserKey)
        } finally {
          encodedUserKey.fill(0)
        }
      } else {
        if (
          !this.wrappedUserKeyFingerprint ||
          !this.wrappedUserKeyFingerprint.equals(wrappedKeyFingerprint)
        ) {
          this.clearDecryptedState()
          throw new BitwardenDirectError('AUTH_REQUIRED')
        }
        userKey = cloneBitwardenAccountKey(this.requireUserKey())
      }
      try {
        await this.validateAccountKeys(profile, userKey)
        if (
          requiresLegacyUserKeyProof &&
          this.resolveAccountPrivateKey(profile, userKey) === null
        ) {
          throw new BitwardenDirectError('INVALID_RESPONSE')
        }
      } catch (error) {
        clearBitwardenSymmetricKey(userKey)
        throw error
      }
      accountKeysValidated = true

      const nextFolders = new Map<string, CachedFolder>()
      const nextLogins = new Map<string, CachedLogin>()
      const nextOrganizations = new Map<string, BitwardenOrganization>()
      const nextCollections = new Map<string, BitwardenCollection>()
      const nextOrganizationCiphers = new Map<string, BitwardenOrganizationCipher>()
      const nextOrganizationCipherRaws = new Map<string, JsonObject>()
      const nextOrganizationKeys = new Map<string, Buffer>()
      const nextSends = new Map<string, CachedSend>()
      const nextIsolatedPersonalCiphers = new Set<string>()
      const organizationKeys = new Map<string, Buffer>()
      try {
        invalidResponseStage = 'folder'
        const folderRows = requiredRemoteArrayProperty(payload, 'folders')
        invalidResponseStage = 'cipher'
        const cipherRows = requiredRemoteArrayProperty(payload, 'ciphers')
        invalidResponseStage = 'collection'
        const collectionRows = optionalRemoteArrayProperty(payload, 'collections')
        invalidResponseStage = 'send'
        const sendRows = optionalRemoteArrayProperty(payload, 'sends')
        invalidResponseStage = 'organization'
        const profileOrganizationsValue = property(profile, 'organizationsNew')
        const rootOrganizationsValue = property(payload, 'organizationsNew')
        const legacyOrganizationsValue = property(profile, 'organizations')
        const organizationRows = (() => {
          if (
            (profileOrganizationsValue !== undefined &&
              profileOrganizationsValue !== null &&
              !Array.isArray(profileOrganizationsValue)) ||
            (rootOrganizationsValue !== undefined &&
              rootOrganizationsValue !== null &&
              !Array.isArray(rootOrganizationsValue)) ||
            (legacyOrganizationsValue !== undefined &&
              legacyOrganizationsValue !== null &&
              !Array.isArray(legacyOrganizationsValue))
          ) {
            throw new BitwardenDirectError('INVALID_RESPONSE')
          }
          const rows =
            profileOrganizationsValue ?? rootOrganizationsValue ?? legacyOrganizationsValue
          if (rows === undefined || rows === null) return []
          if (!Array.isArray(rows) || rows.length > MAX_REMOTE_ENTITIES) {
            throw new BitwardenDirectError('INVALID_RESPONSE')
          }
          return rows
        })()
        const providerOrganizationRows = optionalRemoteArrayProperty(
          profile,
          'providerOrganizations'
        )
        const providerRows = optionalRemoteArrayProperty(profile, 'providers')
        const organizationRowsById = new Map<string, JsonObject>()
        for (const value of organizationRows) {
          if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
          const organization = this.parseOrganization(value)
          if (organizationRowsById.has(organization.id)) {
            throw new BitwardenDirectError('INVALID_RESPONSE')
          }
          organizationRowsById.set(organization.id, value)
          nextOrganizations.set(organization.id, organization)
        }
        const providerOrganizationRowsById = new Map<string, JsonObject>()
        for (const value of providerOrganizationRows) {
          if (!isRecord(value)) {
            throw new BitwardenDirectError(
              'INVALID_RESPONSE',
              undefined,
              undefined,
              undefined,
              'organization-profile'
            )
          }
          const organization = this.parseOrganization(value)
          if (providerOrganizationRowsById.has(organization.id)) {
            throw new BitwardenDirectError(
              'INVALID_RESPONSE',
              undefined,
              undefined,
              undefined,
              'organization-profile'
            )
          }
          providerOrganizationRowsById.set(organization.id, value)
          if (!nextOrganizations.has(organization.id)) {
            nextOrganizations.set(organization.id, organization)
          }
        }
        if (!nextPolicySet.parseFailure && nextPolicySet.policies.length > 0) {
          const applicableOrganizationIds = new Set<string>()
          let allPolicyMembershipsExplicit = true
          for (const organizationId of new Set(
            nextPolicySet.policies.map((policy) => policy.organizationId)
          )) {
            const rawOrganization = organizationRowsById.get(organizationId)
            const usePolicies = rawOrganization
              ? property(rawOrganization, 'usePolicies')
              : undefined
            if (typeof usePolicies !== 'boolean') {
              allPolicyMembershipsExplicit = false
              break
            }
            if (usePolicies) applicableOrganizationIds.add(organizationId)
          }
          if (allPolicyMembershipsExplicit) {
            nextPolicySet = {
              ...nextPolicySet,
              applicableOrganizationIds: [...applicableOrganizationIds].sort()
            }
          }
        }
        const requiredOrganizationIds = new Set<string>()
        const cipherIds = new Set<string>()
        for (const value of cipherRows) {
          invalidResponseStage = 'cipher'
          if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
          const id = assertUuidValue(requiredStringProperty(value, 'id'))
          if (cipherIds.has(id)) throw new BitwardenDirectError('INVALID_RESPONSE')
          cipherIds.add(id)
          const type = remoteCipherType(value)
          const organizationId = property(value, 'organizationId')
          if (
            organizationId !== null &&
            organizationId !== undefined &&
            (typeof organizationId !== 'string' || !UUID_PATTERN.test(organizationId))
          ) {
            throw new BitwardenDirectError('INVALID_RESPONSE')
          }
          if (!isSupportedCipherType(type)) {
            if (organizationId === null || organizationId === undefined) {
              nextIsolatedPersonalCiphers.add(id)
              continue
            }
            // Shared rows are server-authoritative and replace the prior shared snapshot. Until
            // shared-item quarantine can preserve that snapshot by ID, an unknown organization
            // cipher kind must remain fail-closed instead of silently disappearing.
            throw new BitwardenDirectError(
              'INVALID_RESPONSE',
              undefined,
              undefined,
              undefined,
              'unsupported-cipher-type'
            )
          }
          if (organizationId === null || organizationId === undefined) continue
          requiredOrganizationIds.add(organizationId)
        }
        for (const value of collectionRows) {
          invalidResponseStage = 'collection'
          if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
          requiredOrganizationIds.add(
            assertUuidValue(requiredStringProperty(value, 'organizationId'))
          )
        }
        const hasOrganizationEncryptedData = requiredOrganizationIds.size > 0
        invalidResponseStage = 'organization'
        const accountPrivateKey = hasOrganizationEncryptedData
          ? this.resolveAccountPrivateKey(profile, userKey)
          : null
        for (const [organizationId, rawOrganization] of organizationRowsById) {
          if (!requiredOrganizationIds.has(organizationId)) continue
          const encryptedKey = stringProperty(rawOrganization, 'key')
          if (!encryptedKey) continue
          if (!accountPrivateKey) throw new BitwardenDirectError('UNSUPPORTED_ACCOUNT_ENCRYPTION')
          const organizationKey = this.decryptOrganizationKey(
            encryptedKey,
            userKey,
            accountPrivateKey,
            'organization-key'
          )
          organizationKeys.set(organizationId, organizationKey)
        }
        const providerKeys = new Map<string, Buffer>()
        try {
          if (providerOrganizationRowsById.size > 0 && hasOrganizationEncryptedData) {
            if (!accountPrivateKey) {
              throw new BitwardenDirectError(
                'INVALID_RESPONSE',
                undefined,
                undefined,
                undefined,
                'provider-organization-key'
              )
            }
            const requiredProviderIds = new Set<string>()
            for (const [organizationId, rawOrganization] of providerOrganizationRowsById) {
              if (!requiredOrganizationIds.has(organizationId)) continue
              requiredProviderIds.add(
                assertUuidValue(requiredStringProperty(rawOrganization, 'providerId'))
              )
            }
            for (const value of providerRows) {
              if (!isRecord(value)) {
                throw new BitwardenDirectError(
                  'INVALID_RESPONSE',
                  undefined,
                  undefined,
                  undefined,
                  'provider-organization-key'
                )
              }
              const providerId = assertUuidValue(requiredStringProperty(value, 'id'))
              if (!requiredProviderIds.has(providerId)) continue
              if (providerKeys.has(providerId)) {
                throw new BitwardenDirectError(
                  'INVALID_RESPONSE',
                  undefined,
                  undefined,
                  undefined,
                  'provider-organization-key'
                )
              }
              const encryptedProviderKey = requiredStringProperty(value, 'key')
              providerKeys.set(
                providerId,
                this.decryptOrganizationKey(
                  encryptedProviderKey,
                  userKey,
                  accountPrivateKey,
                  'provider-organization-key'
                )
              )
            }
            for (const [organizationId, rawOrganization] of providerOrganizationRowsById) {
              if (!requiredOrganizationIds.has(organizationId)) continue
              const encryptedKey = stringProperty(rawOrganization, 'key')
              if (!encryptedKey) continue
              const providerId = assertUuidValue(
                requiredStringProperty(rawOrganization, 'providerId')
              )
              const providerKey = providerKeys.get(providerId)
              if (!providerKey) {
                throw new BitwardenDirectError(
                  'INVALID_RESPONSE',
                  undefined,
                  undefined,
                  undefined,
                  'provider-organization-key'
                )
              }
              const organizationKey = this.decryptSymmetricWrappedKey(encryptedKey, providerKey)
              const previousKey = organizationKeys.get(organizationId)
              previousKey?.fill(0)
              organizationKeys.set(organizationId, organizationKey)
            }
          }
        } finally {
          for (const providerKey of providerKeys.values()) providerKey.fill(0)
        }
        invalidResponseStage = 'snapshot'
        let aggregateRows = addAggregateRemoteRows(0, folderRows.length)
        aggregateRows = addAggregateRemoteRows(aggregateRows, cipherRows.length)
        aggregateRows = addAggregateRemoteRows(aggregateRows, collectionRows.length)
        aggregateRows = addAggregateRemoteRows(aggregateRows, sendRows.length)
        for (const value of folderRows) {
          invalidResponseStage = 'folder'
          if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
          const item = this.decryptFolder(value, userKey)
          if (nextFolders.has(item.id)) throw new BitwardenDirectError('INVALID_RESPONSE')
          nextFolders.set(item.id, { raw: structuredClone(value), item })
        }
        for (const value of cipherRows) {
          invalidResponseStage = 'cipher'
          if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
          const type = remoteCipherType(value)
          const organizationId = property(value, 'organizationId')
          const rawNestedRows = rawCipherNestedRows(value)
          aggregateRows = addAggregateRemoteRows(aggregateRows, rawNestedRows)
          if (!isSupportedCipherType(type)) {
            if (organizationId !== null && organizationId !== undefined) {
              throw new BitwardenDirectError(
                'INVALID_RESPONSE',
                undefined,
                undefined,
                undefined,
                'unsupported-cipher-type'
              )
            }
            continue
          }
          if (organizationId !== null && organizationId !== undefined) {
            if (typeof organizationId !== 'string' || !UUID_PATTERN.test(organizationId)) {
              throw new BitwardenDirectError('INVALID_RESPONSE')
            }
            const organizationKey = organizationKeys.get(organizationId)
            if (
              !organizationKey ||
              (!organizationRowsById.has(organizationId) &&
                !providerOrganizationRowsById.has(organizationId))
            ) {
              throw new BitwardenDirectError('INVALID_RESPONSE')
            }
            const item = this.decryptLogin(value, organizationKey)
            const organizationCipher = this.organizationCipher(value, item, organizationId)
            nextOrganizationCiphers.set(organizationCipher.id, organizationCipher)
            nextOrganizationCipherRaws.set(organizationCipher.id, structuredClone(value))
            aggregateRows = addAggregateRemoteRows(
              aggregateRows,
              Math.max(0, parsedCipherNestedRows(item) - rawNestedRows)
            )
            continue
          }
          const id = assertUuidValue(requiredStringProperty(value, 'id'))
          validatePersonalCipherSecurityMetadata(value)
          let item: BitwardenLoginItem
          let blobNestedRows = 0
          try {
            item = this.decryptLogin(value, userKey, (rows) => {
              blobNestedRows = rows
            })
          } catch (error) {
            aggregateRows = addAggregateRemoteRows(aggregateRows, blobNestedRows)
            if (!isQuarantinablePersonalCipherError(error)) throw error
            nextIsolatedPersonalCiphers.add(id)
            continue
          }
          aggregateRows = addAggregateRemoteRows(aggregateRows, blobNestedRows)
          aggregateRows = addAggregateRemoteRows(
            aggregateRows,
            Math.max(0, parsedCipherNestedRows(item) - rawNestedRows - blobNestedRows)
          )
          nextLogins.set(item.id, { raw: structuredClone(value), item })
        }
        for (const value of collectionRows) {
          invalidResponseStage = 'collection'
          if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
          const collection = this.decryptCollection(value, organizationKeys)
          if (nextCollections.has(collection.id)) throw new BitwardenDirectError('INVALID_RESPONSE')
          nextCollections.set(collection.id, collection)
        }
        for (const cipher of nextOrganizationCiphers.values()) {
          invalidResponseStage = 'collection'
          for (const collectionId of cipher.collectionIds) {
            const collection = nextCollections.get(collectionId)
            if (!collection || collection.organizationId !== cipher.organizationId) {
              throw new BitwardenDirectError('INVALID_RESPONSE')
            }
          }
        }
        for (const value of sendRows) {
          invalidResponseStage = 'send'
          if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
          const send = this.decryptSend(value, userKey)
          nextSends.set(send.item.id, send)
        }
        for (const [organizationId, organizationKey] of organizationKeys) {
          nextOrganizationKeys.set(organizationId, Buffer.from(organizationKey))
        }
        invalidResponseStage = null
      } catch (error) {
        for (const organizationKey of organizationKeys.values()) organizationKey.fill(0)
        for (const organizationKey of nextOrganizationKeys.values()) organizationKey.fill(0)
        clearBitwardenSymmetricKey(userKey)
        throw error
      }

      for (const organizationKey of organizationKeys.values()) organizationKey.fill(0)

      if (operationGeneration !== this.runtimeGeneration) {
        clearBitwardenSymmetricKey(userKey)
        for (const organizationKey of nextOrganizationKeys.values()) organizationKey.fill(0)
        throw new BitwardenDirectError(this.http.exportSession() ? 'ABORTED' : 'AUTH_REQUIRED')
      }
      this.runtimeGeneration += 1
      clearBitwardenSymmetricKey(this.userKey)
      this.wrappedUserKeyFingerprint?.fill(0)
      this.userKey = userKey
      this.wrappedUserKeyFingerprint = wrappedKeyFingerprint
      wrappedKeyFingerprint = null
      this.folders = nextFolders
      this.logins = nextLogins
      this.organizations = nextOrganizations
      this.collections = nextCollections
      this.organizationCiphers = nextOrganizationCiphers
      this.organizationCipherRaws = nextOrganizationCipherRaws
      for (const organizationKey of this.organizationKeys.values()) organizationKey.fill(0)
      this.organizationKeys = nextOrganizationKeys
      this.sends = nextSends
      this.isolatedPersonalCiphers = nextIsolatedPersonalCiphers
      this.syncedEquivalentDomainSettings = structuredClone(nextEquivalentDomainSettings)
      this.syncedUserDecryptionCapabilities = nextUserDecryptionCapabilities
      this.state.profileId = profileId
      this.state.securityStamp = securityStamp
      this.state.policySet = nextPolicySet
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
          mapped.syncInvalidResponseReason ?? this.defaultSyncInvalidReason(invalidResponseStage)
        )
      }
      throw mapped
    } finally {
      wrappedKeyFingerprint?.fill(0)
      pendingMasterKey?.fill(0)
      if (this.pendingMasterKey === pendingMasterKey) this.pendingMasterKey = null
    }
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
      const request = this.encryptLoginRequest(resolveDraft(draft, null), itemKey, null)
      request.organizationId = organizationId
      request.folderId = null
      request.collectionIds = [...collectionIds]
      request.key = encryptBitwardenBytes(itemKey, organizationKey, 'legacy-key')
      const response = await this.http.createCipher(request, signal)
      const raw = responseEntity(response, 'cipher')
      if (property(raw, 'organizationId') !== organizationId) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const item = this.decryptLogin(raw, organizationKey)
      const parsed = this.organizationCipher(raw, item, organizationId)
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
    const itemKey = this.cipherKey(raw, organizationKey)
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
      const request = this.encryptLoginRequest(resolved, itemKey, raw)
      request.organizationId = cached.organizationId
      request.collectionIds = [...cached.collectionIds]
      const response = await this.http.updateCipher(id, request, signal)
      const nextRaw = responseEntity(response, 'cipher')
      if (
        property(nextRaw, 'organizationId') !== cached.organizationId ||
        requiredStringProperty(nextRaw, 'id') !== id
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const item = this.decryptLogin(nextRaw, organizationKey)
      const parsed = this.organizationCipher(nextRaw, item, cached.organizationId)
      const responseCollectionIds = property(nextRaw, 'collectionIds')
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
    return this.http.listEmergencyAccess(signal)
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
      itemKey = this.cipherKey(cached.raw, userKey)
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
      const metadata = freshAttachmentMetadata(response, attachmentId, expected, itemKey)

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
      itemKey = this.cipherKey(cached.raw, userKey)
      if (!Buffer.isBuffer(itemKey) || itemKey.length !== USER_KEY_BYTES) {
        throw new BitwardenDirectError('UNSUPPORTED_ACCOUNT_ENCRYPTION')
      }
      const response = await this.http.prepareAttachmentDownload(id, attachmentId, signal)
      const metadata = freshAttachmentMetadata(response, attachmentId, expected, itemKey)
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
    if (!cached || cached.item.attachments.length >= MAX_ATTACHMENTS_PER_ITEM) {
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
      itemKey = this.cipherKey(cached.raw, userKey)
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
      const request = this.encryptLoginRequest(resolveDraft(draft, null), itemKey, null)
      request.key = encryptBitwardenBytes(itemKey, userKey, 'legacy-key')
      const response = await this.http.createCipher(request, signal)
      const raw = responseEntity(response, 'cipher')
      const item = this.decryptLogin(raw, userKey)
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
          !isRecord(entry) ||
          typeof entry.localId !== 'string' ||
          !isRecord(entry.draft) ||
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
          const request = this.encryptLoginRequest(resolved, itemKey, null)
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

      let token: string
      do token = randomBytes(PREPARED_IMPORT_TOKEN_BYTES).toString('base64url')
      while (this.preparedLoginImports.has(token))
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
      const marker = property(cached.raw, 'key')
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
    const itemKey = this.cipherKey(cached.raw, userKey)
    try {
      const request = this.encryptLoginRequest(
        resolveDraft(draft, cached.item),
        itemKey,
        cached.raw
      )
      const response = await this.http.updateCipher(id, request, signal)
      const raw = responseEntity(response, 'cipher')
      const item = this.decryptLogin(raw, userKey)
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
      const item = this.decryptLogin(raw, userKey)
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
      const item = this.decryptLogin(raw, userKey)
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
      const item = this.decryptLogin(raw, userKey)
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

  private async deriveAndAuthenticate(
    password: string,
    twoFactor: BitwardenLoginTwoFactor | undefined,
    newDeviceOtp: string | undefined,
    requestToken: boolean,
    signal?: AbortSignal
  ): Promise<void> {
    const operationGeneration = this.runtimeGeneration
    let invalidResponseStage: BitwardenSyncInvalidResponseStage = 'prelogin'
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

  private findWrappedUserKey(payload: JsonObject, profile: JsonObject): string {
    const userDecryption = recordProperty(payload, 'userDecryption')
    const masterPasswordUnlockValue = userDecryption
      ? property(userDecryption, 'masterPasswordUnlock')
      : undefined
    if (
      masterPasswordUnlockValue !== undefined &&
      masterPasswordUnlockValue !== null &&
      !isRecord(masterPasswordUnlockValue)
    ) {
      throw new BitwardenDirectError(
        'INVALID_RESPONSE',
        undefined,
        undefined,
        undefined,
        'user-decryption-data'
      )
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
      throw new BitwardenDirectError(
        'INVALID_RESPONSE',
        undefined,
        undefined,
        undefined,
        'user-decryption-data'
      )
    }
    const modern = encryptedName ?? wrappedName
    const legacy = stringProperty(profile, 'key')
    const wrapped = modern ?? legacy
    if (!wrapped) {
      // `UsesKeyConnector` is an authoritative sync-profile flag. Only map the account to the
      // specific unsupported flow when the server explicitly reports it.
      if (property(profile, 'usesKeyConnector') === true && masterPasswordUnlock === null) {
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
        property(decryptionOptions, 'hasMasterPassword') === false &&
        recordProperty(decryptionOptions, 'masterPasswordUnlock') === null
      ) {
        const keyConnectorOption = recordProperty(decryptionOptions, 'keyConnectorOption')
        const trustedDeviceOption = recordProperty(decryptionOptions, 'trustedDeviceOption')
        const webAuthnPrfOption =
          property(decryptionOptions, 'webAuthnPrfOption') ??
          property(decryptionOptions, 'webAuthnPrfOptions')
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

  private parseUserDecryptionCapabilities(
    payload: JsonObject
  ): BitwardenUserDecryptionCapabilities {
    const raw = property(payload, 'userDecryption')
    if (raw === undefined || raw === null) {
      return {
        hasWebAuthnPrfOptions: false,
        hasV2UpgradeToken: false,
        webAuthnPrfUnlockSupported: false,
        v2AccountUpgradeSupported: false
      }
    }
    if (!isRecord(raw)) {
      throw new BitwardenDirectError(
        'INVALID_RESPONSE',
        undefined,
        undefined,
        undefined,
        'user-decryption-data'
      )
    }
    const prfOptions = property(raw, 'webAuthnPrfOptions')
    if (
      prfOptions !== undefined &&
      prfOptions !== null &&
      (!Array.isArray(prfOptions) ||
        prfOptions.length > MAX_REMOTE_ENTITIES ||
        prfOptions.some((option) => !isRecord(option)))
    ) {
      throw new BitwardenDirectError(
        'INVALID_RESPONSE',
        undefined,
        undefined,
        undefined,
        'user-decryption-data'
      )
    }
    const v2UpgradeToken = property(raw, 'v2UpgradeToken')
    if (v2UpgradeToken !== undefined && v2UpgradeToken !== null && !isRecord(v2UpgradeToken)) {
      throw new BitwardenDirectError(
        'INVALID_RESPONSE',
        undefined,
        undefined,
        undefined,
        'user-decryption-data'
      )
    }
    return {
      hasWebAuthnPrfOptions: Array.isArray(prfOptions) && prfOptions.length > 0,
      hasV2UpgradeToken: isRecord(v2UpgradeToken),
      webAuthnPrfUnlockSupported: false,
      v2AccountUpgradeSupported: false
    }
  }

  private defaultSyncInvalidReason(
    stage: BitwardenSyncInvalidResponseStage
  ): BitwardenSyncInvalidResponseReason {
    switch (stage) {
      case 'prelogin':
      case 'authentication':
      case 'access-token':
      case 'response':
        return 'response-shape'
      case 'account':
        return 'account-profile'
      case 'organization':
        return 'organization-profile'
      case 'folder':
        return 'folder-data'
      case 'cipher':
        return 'cipher-data'
      case 'collection':
        return 'collection-data'
      case 'send':
        return 'send-data'
      case 'snapshot':
        return 'snapshot-limit'
    }
  }

  private async validateAccountKeys(
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
          signedPublicKey: encryptionPair
            ? stringProperty(encryptionPair, 'signedPublicKey')
            : null,
          publicKey: encryptionPair ? stringProperty(encryptionPair, 'publicKey') : null
        },
        userKey
      )
      this.decryptV2AccountPrivateKey(wrappedPrivateKey, userKey)
    } catch {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
  }

  private decryptFolder(raw: JsonObject, userKey: BitwardenSymmetricKey): BitwardenFolder {
    const id = assertUuidValue(requiredStringProperty(raw, 'id'))
    const name = decryptBitwardenString(requiredStringProperty(raw, 'name'), userKey)
    if (!name || name.length > MAX_NAME_LENGTH) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    return {
      id,
      name
    }
  }

  private parseOrganization(raw: JsonObject): BitwardenOrganization {
    const id = assertUuidValue(requiredStringProperty(raw, 'id'))
    const name = requiredStringProperty(raw, 'name')
    if (name.length > MAX_NAME_LENGTH) throw new BitwardenDirectError('INVALID_RESPONSE')
    const statusValue = property(raw, 'status')
    const typeValue = property(raw, 'type')
    const parseOptionalInteger = (value: JsonValue | undefined): number | null => {
      if (value === undefined || value === null) return null
      if (!Number.isSafeInteger(value) || typeof value !== 'number' || value < 0) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      return value
    }
    return {
      id,
      name,
      status: parseOptionalInteger(statusValue),
      type: parseOptionalInteger(typeValue),
      enabled: booleanProperty(raw, 'enabled', true),
      identifier: nullableStringProperty(raw, 'identifier'),
      hasPublicAndPrivateKeys: booleanProperty(raw, 'hasPublicAndPrivateKeys')
    }
  }

  private resolveAccountPrivateKey(
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
      return this.decryptV2AccountPrivateKey(wrappedPrivateKey, userKey)
    }

    const legacyPrivateKey = stringProperty(profile, 'privateKey') ?? wrappedPrivateKey
    if (!legacyPrivateKey || !Buffer.isBuffer(userKey)) return null
    try {
      return this.validateAccountPrivateKey(decryptRsaPrivateKey(legacyPrivateKey, userKey))
    } catch {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
  }

  private decryptV2AccountPrivateKey(
    wrappedPrivateKey: string,
    userKey: BitwardenSymmetricKey
  ): KeyObject {
    const privateKeyBytes = decryptBitwardenBytes(wrappedPrivateKey, userKey)
    try {
      return this.validateAccountPrivateKey(
        createPrivateKey({ key: privateKeyBytes, format: 'der', type: 'pkcs8' })
      )
    } catch {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    } finally {
      privateKeyBytes.fill(0)
    }
  }

  private validateAccountPrivateKey(privateKey: KeyObject): KeyObject {
    if (
      privateKey.type !== 'private' ||
      privateKey.asymmetricKeyType !== 'rsa' ||
      privateKey.asymmetricKeyDetails?.modulusLength !== 2_048
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    return privateKey
  }

  private decryptOrganizationKey(
    encryptedKey: string,
    userKey: BitwardenSymmetricKey,
    privateKey: KeyObject,
    reason: 'organization-key' | 'provider-organization-key'
  ): Buffer {
    try {
      if (!encryptedKey.startsWith('3.') && !encryptedKey.startsWith('4.')) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const plaintext = decryptBitwardenBytes(encryptedKey, userKey, privateKey)
      try {
        // Current Bitwarden clients wrap the encoded organization key as raw bytes.
        if (plaintext.length === USER_KEY_BYTES) return Buffer.from(plaintext)

        // Retain compatibility with legacy payloads that wrapped the same key as Base64 text.
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
        const organizationKey = Buffer.from(encoded, 'base64')
        if (
          organizationKey.length !== USER_KEY_BYTES ||
          organizationKey.toString('base64') !== encoded
        ) {
          organizationKey.fill(0)
          throw new BitwardenDirectError('INVALID_RESPONSE')
        }
        return organizationKey
      } finally {
        plaintext.fill(0)
      }
    } catch (error) {
      if (
        (error instanceof BitwardenDirectError && error.code === 'INVALID_RESPONSE') ||
        error instanceof BitwardenCryptoError
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE', undefined, undefined, undefined, reason)
      }
      throw error
    }
  }

  private decryptSymmetricWrappedKey(encryptedKey: string, wrappingKey: Buffer): Buffer {
    try {
      const plaintext = decryptBitwardenBytes(encryptedKey, wrappingKey)
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
        throw new BitwardenDirectError(
          'INVALID_RESPONSE',
          undefined,
          undefined,
          undefined,
          'provider-organization-key'
        )
      }
      throw error
    }
  }

  private decryptCollection(
    raw: JsonObject,
    organizationKeys: ReadonlyMap<string, Buffer>
  ): BitwardenCollection {
    const id = assertUuidValue(requiredStringProperty(raw, 'id'))
    const organizationId = assertUuidValue(requiredStringProperty(raw, 'organizationId'))
    const organizationKey = organizationKeys.get(organizationId)
    if (!organizationKey) throw new BitwardenDirectError('INVALID_RESPONSE')
    const name = decryptBitwardenString(requiredStringProperty(raw, 'name'), organizationKey)
    if (name.length > MAX_NAME_LENGTH) throw new BitwardenDirectError('INVALID_RESPONSE')
    const type = property(raw, 'type')
    if (
      type !== undefined &&
      type !== null &&
      (typeof type !== 'number' || !Number.isSafeInteger(type) || type < 0)
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    return {
      id,
      organizationId,
      name,
      externalId: nullableStringProperty(raw, 'externalId'),
      readOnly: booleanProperty(raw, 'readOnly'),
      hidePasswords: booleanProperty(raw, 'hidePasswords'),
      manage: booleanProperty(raw, 'manage'),
      type: (type ?? 0) as number,
      assigned: booleanProperty(raw, 'assigned')
    }
  }

  private organizationCipher(
    raw: JsonObject,
    item: BitwardenLoginItem,
    organizationId: string
  ): BitwardenOrganizationCipher {
    const collectionIdsValue = property(raw, 'collectionIds')
    if (
      collectionIdsValue !== undefined &&
      collectionIdsValue !== null &&
      (!Array.isArray(collectionIdsValue) || collectionIdsValue.length > MAX_REMOTE_ENTITIES)
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    const collectionIds = (Array.isArray(collectionIdsValue) ? collectionIdsValue : []).map(
      (value) => {
        if (typeof value !== 'string' || !UUID_PATTERN.test(value)) {
          throw new BitwardenDirectError('INVALID_RESPONSE')
        }
        return value
      }
    )
    if (new Set(collectionIds).size !== collectionIds.length) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    const permissions = recordProperty(raw, 'permissions')
    return {
      ...item,
      organizationId,
      collectionIds,
      edit: booleanProperty(raw, 'edit'),
      viewPassword: booleanProperty(raw, 'viewPassword', true),
      delete: permissions ? booleanProperty(permissions, 'delete') : false,
      restore: permissions ? booleanProperty(permissions, 'restore') : false
    }
  }

  private decryptSend(raw: JsonObject, userKey: BitwardenSymmetricKey): CachedSend {
    const type = property(raw, 'type')
    if (type !== 0 && type !== 1) throw new BitwardenDirectError('INVALID_RESPONSE')
    const id = assertUuidValue(requiredStringProperty(raw, 'id'))
    const accessId = requiredStringProperty(raw, 'accessId')
    if (!/^[A-Za-z0-9_-]{16,128}$/u.test(accessId)) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    const encryptedKey = requiredStringProperty(raw, 'key')
    const seed = decryptBitwardenBytes(encryptedKey, userKey)
    let sendKey: Buffer | null = null
    try {
      if (seed.length !== 16) throw new BitwardenDirectError('INVALID_RESPONSE')
      sendKey = deriveBitwardenSendKey(seed)
      const encryptedName = requiredStringProperty(raw, 'name')
      const notesValue = property(raw, 'notes')
      const text = type === 0 ? recordProperty(raw, 'text') : null
      const file = type === 1 ? recordProperty(raw, 'file') : null
      if ((type === 0 && !text) || (type === 1 && !file)) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const notes =
        notesValue === null || notesValue === undefined
          ? null
          : decryptBitwardenString(requiredStringProperty(raw, 'notes'), sendKey)
      const expirationDate = nullableStringProperty(raw, 'expirationDate')
      const deletionDate = requiredStringProperty(raw, 'deletionDate')
      const revisionDate = requiredStringProperty(raw, 'revisionDate')
      if (
        !Number.isFinite(Date.parse(deletionDate)) ||
        !Number.isFinite(Date.parse(revisionDate)) ||
        (expirationDate !== null && !Number.isFinite(Date.parse(expirationDate)))
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const authTypeValue = property(raw, 'authType')
      const password = nullableStringProperty(raw, 'password')
      const authType =
        authTypeValue === 0 || authTypeValue === 1 || authTypeValue === 2
          ? authTypeValue
          : password
            ? 1
            : 2
      const maxAccessCountValue = property(raw, 'maxAccessCount')
      const maxAccessCount =
        maxAccessCountValue === null || maxAccessCountValue === undefined
          ? null
          : typeof maxAccessCountValue === 'number' &&
              Number.isSafeInteger(maxAccessCountValue) &&
              maxAccessCountValue > 0
            ? maxAccessCountValue
            : (() => {
                throw new BitwardenDirectError('INVALID_RESPONSE')
              })()
      const accessCount = property(raw, 'accessCount')
      if (
        typeof accessCount !== 'number' ||
        !Number.isSafeInteger(accessCount) ||
        accessCount < 0
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      let fileMetadata: BitwardenSendFile | undefined
      let textValue = ''
      if (text) {
        const encryptedText = requiredStringProperty(text, 'text')
        textValue = decryptBitwardenString(encryptedText, sendKey)
      } else if (file) {
        const fileId = requiredStringProperty(file, 'id')
        const fileName = decryptBitwardenString(requiredStringProperty(file, 'fileName'), sendKey)
        const sizeValue = property(file, 'size')
        const size =
          typeof sizeValue === 'string' && /^\d+$/u.test(sizeValue)
            ? Number(sizeValue)
            : typeof sizeValue === 'number' && Number.isSafeInteger(sizeValue)
              ? sizeValue
              : NaN
        const sizeName = nullableStringProperty(file, 'sizeName')
        if (
          fileId.length === 0 ||
          fileId.length > MAX_SEND_FILE_ID_LENGTH ||
          fileName.length === 0 ||
          fileName.length > MAX_SEND_FILE_NAME_LENGTH ||
          !Number.isSafeInteger(size) ||
          size < 1 ||
          size > MAX_SEND_FILE_SIZE ||
          (sizeName !== null && sizeName.length > MAX_SEND_FILE_SIZE_NAME_LENGTH)
        ) {
          throw new BitwardenDirectError('INVALID_RESPONSE')
        }
        fileMetadata = { id: fileId, fileName, size, sizeName }
      }
      return {
        raw: structuredClone(raw),
        item: {
          id,
          accessId,
          type: type === 0 ? 'text' : 'file',
          name: decryptBitwardenString(encryptedName, sendKey),
          notes,
          text: textValue,
          ...(fileMetadata ? { file: fileMetadata } : {}),
          hidden: booleanProperty(text ?? {}, 'hidden'),
          maxAccessCount,
          accessCount,
          revisionDate,
          expirationDate,
          deletionDate,
          disabled: booleanProperty(raw, 'disabled'),
          hideEmail: booleanProperty(raw, 'hideEmail'),
          authType,
          passwordProtected: authType === 1 || Boolean(password)
        }
      }
    } finally {
      seed.fill(0)
      sendKey?.fill(0)
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
      const existingAuthType = existing ? property(existing, 'authType') : undefined
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

  private decryptLogin(
    raw: JsonObject,
    userKey: BitwardenSymmetricKey,
    onBlobNestedRows?: (rows: number) => void
  ): BitwardenLoginItem {
    const wireType = bitwardenCipherType(raw)
    const itemType = ITEM_TYPE_BY_WIRE_TYPE[wireType]
    const key = this.cipherKey(raw, userKey)
    try {
      const attachments = decryptAttachments(raw, key)
      const sealedBlob = opaqueCipherBlob(raw)
      if (sealedBlob !== null) {
        if (!Buffer.isBuffer(key)) throw new BitwardenDirectError('INVALID_RESPONSE')
        const content = decryptBitwardenCipherBlob(sealedBlob, key)
        if (!isRecord(content)) throw new BitwardenDirectError('INVALID_RESPONSE')
        onBlobNestedRows?.(decodedBlobNestedRows(content))
        return this.decryptBlobLogin(raw, content, wireType, attachments)
      }
      const notes = nullableStringProperty(raw, 'notes')
      const item: BitwardenLoginItem = {
        ...emptyVaultItemFields(),
        id: requiredStringProperty(raw, 'id'),
        type: itemType,
        organizationId: null,
        folderId: nullableStringProperty(raw, 'folderId'),
        name: decryptBitwardenString(requiredStringProperty(raw, 'name'), key),
        notes: notes === null ? null : decryptBitwardenString(notes, key),
        favorite: booleanProperty(raw, 'favorite'),
        uris: [],
        customFields: decryptLegacyCustomFields(property(raw, 'fields'), key),
        passkeys: [],
        passwordHistory: decryptLegacyPasswordHistory(property(raw, 'passwordHistory'), key),
        passwordRevisionDate: null,
        autofillOnPageLoad: null,
        attachments,
        creationDate: nullableStringProperty(raw, 'creationDate'),
        revisionDate: nullableStringProperty(raw, 'revisionDate'),
        deletedAt: nullableStringProperty(raw, 'deletedDate'),
        archivedAt: nullableStringProperty(raw, 'archivedDate'),
        reprompt: repromptProperty(raw)
      }

      if (itemType === 'login') {
        const login = recordProperty(raw, 'login')
        if (!login) throw new BitwardenDirectError('INVALID_RESPONSE')
        item.username = decryptOptionalString(login, 'username', key)
        item.password = decryptOptionalString(login, 'password', key)
        item.passwordRevisionDate = nullableIsoDateProperty(login, 'passwordRevisionDate')
        item.autofillOnPageLoad = nullableBooleanProperty(login, 'autofillOnPageLoad')
        item.totp = decryptOptionalString(login, 'totp', key)
        item.passkeys = decryptFido2Credentials(login, key)
        const urisValue = property(login, 'uris')
        if (
          urisValue !== undefined &&
          urisValue !== null &&
          (!Array.isArray(urisValue) || urisValue.length > MAX_LOGIN_URIS)
        ) {
          throw new BitwardenDirectError('INVALID_RESPONSE')
        }
        item.uris = (Array.isArray(urisValue) ? urisValue : []).map((value) => {
          if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
          const encryptedUri = nullableStringProperty(value, 'uri')
          const uri = encryptedUri === null ? '' : decryptBitwardenString(encryptedUri, key)
          if (uri.length > MAX_URI_LENGTH) throw new BitwardenDirectError('INVALID_RESPONSE')
          return {
            uri,
            match: validateUriMatch(property(value, 'match'))
          }
        })
        item.uri = item.uris[0]?.uri ?? null
      } else if (itemType === 'card') {
        const card = recordProperty(raw, 'card')
        if (!card) throw new BitwardenDirectError('INVALID_RESPONSE')
        item.cardholderName = decryptOptionalString(card, 'cardholderName', key)
        item.brand = decryptOptionalString(card, 'brand', key)
        item.number = decryptOptionalString(card, 'number', key)
        item.expMonth = decryptOptionalString(card, 'expMonth', key)
        item.expYear = decryptOptionalString(card, 'expYear', key)
        item.code = decryptOptionalString(card, 'code', key)
      } else if (itemType === 'identity') {
        const identity = recordProperty(raw, 'identity')
        if (!identity) throw new BitwardenDirectError('INVALID_RESPONSE')
        item.title = decryptOptionalString(identity, 'title', key)
        item.firstName = decryptOptionalString(identity, 'firstName', key)
        item.middleName = decryptOptionalString(identity, 'middleName', key)
        item.lastName = decryptOptionalString(identity, 'lastName', key)
        item.address1 = decryptOptionalString(identity, 'address1', key)
        item.address2 = decryptOptionalString(identity, 'address2', key)
        item.address3 = decryptOptionalString(identity, 'address3', key)
        item.city = decryptOptionalString(identity, 'city', key)
        item.state = decryptOptionalString(identity, 'state', key)
        item.postalCode = decryptOptionalString(identity, 'postalCode', key)
        item.country = decryptOptionalString(identity, 'country', key)
        item.company = decryptOptionalString(identity, 'company', key)
        item.email = decryptOptionalString(identity, 'email', key)
        item.phone = decryptOptionalString(identity, 'phone', key)
        item.ssn = decryptOptionalString(identity, 'ssn', key)
        item.identityUsername = decryptOptionalString(identity, 'username', key)
        item.passportNumber = decryptOptionalString(identity, 'passportNumber', key)
        item.licenseNumber = decryptOptionalString(identity, 'licenseNumber', key)
      } else if (itemType === 'secureNote') {
        const secureNote = recordProperty(raw, 'secureNote')
        const secureNoteType = secureNote ? property(secureNote, 'type') : undefined
        if (!Number.isSafeInteger(secureNoteType)) {
          throw new BitwardenDirectError('INVALID_RESPONSE')
        }
      } else {
        const sshKey = recordProperty(raw, 'sshKey')
        if (!sshKey) throw new BitwardenDirectError('INVALID_SSH_KEY')
        item.privateKey = decryptBitwardenString(requiredStringProperty(sshKey, 'privateKey'), key)
        item.publicKey = decryptBitwardenString(requiredStringProperty(sshKey, 'publicKey'), key)
        item.fingerprint = decryptBitwardenString(
          requiredStringProperty(sshKey, 'keyFingerprint'),
          key
        )
      }
      return item
    } finally {
      if (key !== userKey) clearBitwardenSymmetricKey(key)
    }
  }

  private decryptBlobLogin(
    raw: JsonObject,
    content: JsonObject,
    wireType: BitwardenCipherType,
    attachments: BitwardenAttachment[]
  ): BitwardenLoginItem {
    const itemType = ITEM_TYPE_BY_WIRE_TYPE[wireType]
    const typeData = recordProperty(content, 'typeData')
    if (!typeData || stringProperty(typeData, 'type') !== BLOB_TAG_BY_ITEM_TYPE[itemType]) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    const item: BitwardenLoginItem = {
      ...emptyVaultItemFields(),
      id: requiredStringProperty(raw, 'id'),
      type: itemType,
      organizationId: null,
      folderId: nullableStringProperty(raw, 'folderId'),
      name: requiredStringProperty(content, 'name'),
      notes: nullableStringProperty(content, 'notes'),
      favorite: booleanProperty(raw, 'favorite'),
      uris: [],
      customFields: decryptBlobCustomFields(property(content, 'fields')),
      passkeys: [],
      passwordHistory: decryptBlobPasswordHistory(property(content, 'passwordHistory')),
      passwordRevisionDate: null,
      autofillOnPageLoad: null,
      attachments,
      creationDate: nullableStringProperty(raw, 'creationDate'),
      revisionDate: nullableStringProperty(raw, 'revisionDate'),
      deletedAt: nullableStringProperty(raw, 'deletedDate'),
      archivedAt: nullableStringProperty(raw, 'archivedDate'),
      reprompt: repromptProperty(raw)
    }

    if (itemType === 'login') {
      item.username = nullableStringProperty(typeData, 'username') ?? ''
      item.password = nullableStringProperty(typeData, 'password') ?? ''
      item.passwordRevisionDate = nullableIsoDateProperty(typeData, 'passwordRevisionDate')
      item.autofillOnPageLoad = nullableBooleanProperty(typeData, 'autofillOnPageLoad')
      item.totp = nullableStringProperty(typeData, 'totp') ?? ''
      item.passkeys = parseBlobFido2Credentials(typeData)
      const urisValue = property(typeData, 'uris')
      if (
        urisValue !== undefined &&
        urisValue !== null &&
        (!Array.isArray(urisValue) || urisValue.length > MAX_LOGIN_URIS)
      ) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      item.uris = (Array.isArray(urisValue) ? urisValue : []).map((value) => {
        if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
        const uri = nullableStringProperty(value, 'uri') ?? ''
        if (uri.length > MAX_URI_LENGTH) throw new BitwardenDirectError('INVALID_RESPONSE')
        return {
          uri,
          match: validateUriMatch(property(value, 'match'))
        }
      })
      item.uri = item.uris[0]?.uri ?? null
    } else if (itemType === 'card') {
      item.cardholderName = nullableStringProperty(typeData, 'cardholderName') ?? ''
      item.brand = nullableStringProperty(typeData, 'brand') ?? ''
      item.number = nullableStringProperty(typeData, 'number') ?? ''
      item.expMonth = nullableStringProperty(typeData, 'expMonth') ?? ''
      item.expYear = nullableStringProperty(typeData, 'expYear') ?? ''
      item.code = nullableStringProperty(typeData, 'code') ?? ''
    } else if (itemType === 'identity') {
      item.title = nullableStringProperty(typeData, 'title') ?? ''
      item.firstName = nullableStringProperty(typeData, 'firstName') ?? ''
      item.middleName = nullableStringProperty(typeData, 'middleName') ?? ''
      item.lastName = nullableStringProperty(typeData, 'lastName') ?? ''
      item.address1 = nullableStringProperty(typeData, 'address1') ?? ''
      item.address2 = nullableStringProperty(typeData, 'address2') ?? ''
      item.address3 = nullableStringProperty(typeData, 'address3') ?? ''
      item.city = nullableStringProperty(typeData, 'city') ?? ''
      item.state = nullableStringProperty(typeData, 'state') ?? ''
      item.postalCode = nullableStringProperty(typeData, 'postalCode') ?? ''
      item.country = nullableStringProperty(typeData, 'country') ?? ''
      item.company = nullableStringProperty(typeData, 'company') ?? ''
      item.email = nullableStringProperty(typeData, 'email') ?? ''
      item.phone = nullableStringProperty(typeData, 'phone') ?? ''
      item.ssn = nullableStringProperty(typeData, 'ssn') ?? ''
      item.identityUsername = nullableStringProperty(typeData, 'username') ?? ''
      item.passportNumber = nullableStringProperty(typeData, 'passportNumber') ?? ''
      item.licenseNumber = nullableStringProperty(typeData, 'licenseNumber') ?? ''
    } else if (itemType === 'secureNote') {
      if (!Number.isSafeInteger(property(typeData, 'secureNoteType'))) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
    } else {
      item.privateKey = requiredStringProperty(typeData, 'privateKey')
      item.publicKey = requiredStringProperty(typeData, 'publicKey')
      item.fingerprint = requiredStringProperty(typeData, 'fingerprint')
    }
    return item
  }

  private cipherKey(raw: JsonObject, userKey: BitwardenSymmetricKey): BitwardenSymmetricKey {
    const wrappedKey = nullableStringProperty(raw, 'key')
    if (wrappedKey === null) return userKey
    const key = decryptBitwardenWrappedKey(wrappedKey, userKey)
    if (key.length !== USER_KEY_BYTES) {
      key.fill(0)
      throw new BitwardenDirectError('UNSUPPORTED_ACCOUNT_ENCRYPTION')
    }
    return key
  }

  private encryptLoginRequest(
    draft: ResolvedBitwardenDraft,
    key: BitwardenSymmetricKey,
    existing: JsonObject | null
  ): JsonObject {
    const useBlob =
      Buffer.isBuffer(key) &&
      (existing === null ? !Buffer.isBuffer(this.userKey) : opaqueCipherBlob(existing) !== null)
    if (useBlob) return this.encryptBlobLoginRequest(draft, key, existing)

    const wireType = WIRE_TYPE_BY_ITEM_TYPE[draft.type]
    const nestedName = BLOB_TAG_BY_ITEM_TYPE[draft.type]
    const previousType = existing ? property(existing, 'type') : null
    const previousTypeData =
      existing && previousType === wireType ? recordProperty(existing, nestedName) : null
    const typeData: JsonObject = previousTypeData ? structuredClone(previousTypeData) : {}
    const previousFields = existing ? optionalJson(existing, 'fields') : undefined
    const request: JsonObject = {
      type: wireType,
      encryptedFor: this.requireProfileId(),
      organizationId: null,
      folderId: draft.folderId,
      name: encryptBitwardenString(draft.name, key),
      notes: draft.notes === null ? null : encryptBitwardenString(draft.notes, key),
      favorite: draft.favorite,
      archivedDate: draft.archivedAt,
      reprompt: draft.reprompt,
      key: existing ? (property(existing, 'key') ?? null) : null,
      fields:
        existing && !draft.customFieldsChanged
          ? previousFields === undefined
            ? []
            : previousFields
          : encryptLegacyCustomFields(draft.customFields, key),
      login: null,
      secureNote: null,
      card: null,
      identity: null,
      sshKey: null,
      passwordHistory: draft.passwordHistoryChanged
        ? encryptLegacyPasswordHistory(draft.passwordHistory, key)
        : null
    }

    if (draft.type === 'login') {
      typeData.username = encryptBitwardenString(draft.username, key)
      typeData.password = encryptBitwardenString(draft.password, key)
      typeData.passwordRevisionDate = draft.passwordRevisionDate
      typeData.autofillOnPageLoad = draft.autofillOnPageLoad
      if (draft.totpChanged) {
        typeData.totp = draft.totp ? encryptBitwardenString(draft.totp, key) : null
      } else if (!Object.hasOwn(typeData, 'totp')) {
        typeData.totp = null
      }
      if (draft.passkeysChanged) {
        typeData.fido2Credentials = draft.passkeys.map((passkey) =>
          encryptFido2Credential(passkey, key)
        )
      } else if (!Object.hasOwn(typeData, 'fido2Credentials')) {
        typeData.fido2Credentials = []
      }
      typeData.uris = encryptLegacyUris(draft.uris, previousTypeData, key)
    } else if (draft.type === 'card') {
      typeData.cardholderName = encryptBitwardenString(draft.cardholderName, key)
      typeData.brand = encryptBitwardenString(draft.brand, key)
      typeData.number = encryptBitwardenString(draft.number, key)
      typeData.expMonth = encryptBitwardenString(draft.expMonth, key)
      typeData.expYear = encryptBitwardenString(draft.expYear, key)
      typeData.code = encryptBitwardenString(draft.code, key)
    } else if (draft.type === 'identity') {
      typeData.title = encryptBitwardenString(draft.title, key)
      typeData.firstName = encryptBitwardenString(draft.firstName, key)
      typeData.middleName = encryptBitwardenString(draft.middleName, key)
      typeData.lastName = encryptBitwardenString(draft.lastName, key)
      typeData.address1 = encryptBitwardenString(draft.address1, key)
      typeData.address2 = encryptBitwardenString(draft.address2, key)
      typeData.address3 = encryptBitwardenString(draft.address3, key)
      typeData.city = encryptBitwardenString(draft.city, key)
      typeData.state = encryptBitwardenString(draft.state, key)
      typeData.postalCode = encryptBitwardenString(draft.postalCode, key)
      typeData.country = encryptBitwardenString(draft.country, key)
      typeData.company = encryptBitwardenString(draft.company, key)
      typeData.email = encryptBitwardenString(draft.email, key)
      typeData.phone = encryptBitwardenString(draft.phone, key)
      typeData.ssn = encryptBitwardenString(draft.ssn, key)
      typeData.username = encryptBitwardenString(draft.identityUsername, key)
      typeData.passportNumber = encryptBitwardenString(draft.passportNumber, key)
      typeData.licenseNumber = encryptBitwardenString(draft.licenseNumber, key)
    } else if (draft.type === 'secureNote') {
      typeData.type = 0
    } else {
      typeData.privateKey = encryptBitwardenString(draft.privateKey, key)
      typeData.publicKey = encryptBitwardenString(draft.publicKey, key)
      typeData.keyFingerprint = encryptBitwardenString(draft.fingerprint, key)
    }
    request[nestedName] = typeData
    if (existing) {
      setOptional(request, 'lastKnownRevisionDate', optionalJson(existing, 'revisionDate'))
      if (!draft.passwordHistoryChanged) {
        setOptional(request, 'passwordHistory', optionalJson(existing, 'passwordHistory'))
      }
      preservedAttachments(existing, request)
      setOptional(request, 'data', optionalJson(existing, 'data'))
    }
    return request
  }

  private encryptBlobLoginRequest(
    draft: ResolvedBitwardenDraft,
    key: Buffer,
    existing: JsonObject | null
  ): JsonObject {
    let content: JsonObject
    if (existing) {
      const sealedBlob = opaqueCipherBlob(existing)
      if (!sealedBlob) throw new BitwardenDirectError('INVALID_RESPONSE')
      const decrypted = decryptBitwardenCipherBlob(sealedBlob, key)
      if (!isRecord(decrypted)) throw new BitwardenDirectError('INVALID_RESPONSE')
      content = structuredClone(decrypted)
    } else {
      content = {
        name: draft.name,
        notes: draft.notes,
        typeData: {},
        fields: [],
        passwordHistory: []
      }
    }
    const expectedTag = BLOB_TAG_BY_ITEM_TYPE[draft.type]
    const existingTypeData = recordProperty(content, 'typeData')
    const typeData: JsonObject =
      existingTypeData && stringProperty(existingTypeData, 'type') === expectedTag
        ? structuredClone(existingTypeData)
        : {}
    typeData.type = expectedTag

    if (draft.type === 'login') {
      const previousUris = property(typeData, 'uris')
      typeData.username = draft.username
      typeData.password = draft.password
      typeData.passwordRevisionDate = draft.passwordRevisionDate
      typeData.autofillOnPageLoad = draft.autofillOnPageLoad
      if (draft.totpChanged) typeData.totp = draft.totp || null
      if (draft.passkeysChanged) {
        typeData.fido2Credentials = draft.passkeys.map(passkeyToBlob)
      }
      typeData.uris = blobUris(draft.uris, previousUris)
      if (!Object.hasOwn(typeData, 'totp')) typeData.totp = null
      if (!Object.hasOwn(typeData, 'fido2Credentials')) typeData.fido2Credentials = []
    } else if (draft.type === 'card') {
      typeData.cardholderName = draft.cardholderName
      typeData.brand = draft.brand
      typeData.number = draft.number
      typeData.expMonth = draft.expMonth
      typeData.expYear = draft.expYear
      typeData.code = draft.code
    } else if (draft.type === 'identity') {
      typeData.title = draft.title
      typeData.firstName = draft.firstName
      typeData.middleName = draft.middleName
      typeData.lastName = draft.lastName
      typeData.address1 = draft.address1
      typeData.address2 = draft.address2
      typeData.address3 = draft.address3
      typeData.city = draft.city
      typeData.state = draft.state
      typeData.postalCode = draft.postalCode
      typeData.country = draft.country
      typeData.company = draft.company
      typeData.email = draft.email
      typeData.phone = draft.phone
      typeData.ssn = draft.ssn
      typeData.username = draft.identityUsername
      typeData.passportNumber = draft.passportNumber
      typeData.licenseNumber = draft.licenseNumber
    } else if (draft.type === 'secureNote') {
      typeData.secureNoteType = 0
    } else {
      typeData.privateKey = draft.privateKey
      typeData.publicKey = draft.publicKey
      typeData.fingerprint = draft.fingerprint
    }
    content.typeData = typeData
    content.name = draft.name
    content.notes = draft.notes
    if (draft.customFieldsChanged) content.fields = customFieldsToBlob(draft.customFields)
    if (draft.passwordHistoryChanged) {
      content.passwordHistory = passwordHistoryToBlob(draft.passwordHistory)
    }

    const request: JsonObject = {
      type: WIRE_TYPE_BY_ITEM_TYPE[draft.type],
      encryptedFor: this.requireProfileId(),
      organizationId: null,
      folderId: draft.folderId,
      name: encryptBitwardenString('', key),
      notes: null,
      favorite: draft.favorite,
      archivedDate: draft.archivedAt,
      reprompt: draft.reprompt,
      key: existing ? (property(existing, 'key') ?? null) : null,
      fields: null,
      login: null,
      secureNote: null,
      card: null,
      identity: null,
      sshKey: null,
      passwordHistory: null,
      data: encryptBitwardenCipherBlob(content as BitwardenCipherBlobValue, key)
    }
    if (existing) {
      setOptional(request, 'lastKnownRevisionDate', optionalJson(existing, 'revisionDate'))
      preservedAttachments(existing, request)
    }
    return request
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
      if (property(raw, 'organizationId') !== null) {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      }
      const item = this.decryptLogin(raw, userKey)
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
    this.syncedUserDecryptionCapabilities = {
      hasWebAuthnPrfOptions: false,
      hasV2UpgradeToken: false,
      webAuthnPrfUnlockSupported: false,
      v2AccountUpgradeSupported: false
    }
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
