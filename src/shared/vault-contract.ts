export const IPC_CHANNELS = {
  vaultStatus: 'vault:status',
  vaultSetup: 'vault:setup',
  vaultUnlock: 'vault:unlock',
  vaultLock: 'vault:lock',
  vaultLockRequestReady: 'vault:lock-request-ready',
  vaultExport: 'vault:export',
  vaultImport: 'vault:import',
  vaultHealthReport: 'vault:health-report',
  vaultHealthExposedPasswords: 'vault:health-exposed-passwords',
  vaultHealthCancelExposedPasswords: 'vault:health-cancel-exposed-passwords',
  vaultHealthAccountBreaches: 'vault:health-account-breaches',
  vaultHealthCancelAccountBreaches: 'vault:health-cancel-account-breaches',
  vaultHealthOpenHibp: 'vault:health-open-hibp',
  folderList: 'folder:list',
  folderCreate: 'folder:create',
  folderUpdate: 'folder:update',
  folderDelete: 'folder:delete',
  folderReorder: 'folder:reorder',
  loginList: 'login:list',
  loginAuthorize: 'login:authorize',
  loginAuthorizeMany: 'login:authorize-many',
  loginGet: 'login:get',
  loginGetPasswordHistory: 'login:get-password-history',
  attachmentDownload: 'attachment:download',
  attachmentUpload: 'attachment:upload',
  attachmentDelete: 'attachment:delete',
  attachmentFixLegacy: 'attachment:fix-legacy',
  attachmentCancel: 'attachment:cancel',
  loginCreate: 'login:create',
  loginClone: 'login:clone',
  loginArchive: 'login:archive',
  loginArchiveMany: 'login:archive-many',
  loginUnarchive: 'login:unarchive',
  loginUnarchiveMany: 'login:unarchive-many',
  loginUpdate: 'login:update',
  loginDelete: 'login:delete',
  loginDeleteMany: 'login:delete-many',
  loginRestore: 'login:restore',
  loginRestoreMany: 'login:restore-many',
  loginDeletePermanently: 'login:delete-permanently',
  loginDeletePermanentlyMany: 'login:delete-permanently-many',
  loginEmptyTrash: 'login:empty-trash',
  loginSetFavorite: 'login:set-favorite',
  loginMove: 'login:move',
  loginMoveMany: 'login:move-many',
  loginRevealPassword: 'login:reveal-password',
  loginCopyUsername: 'login:copy-username',
  loginCopyPassword: 'login:copy-password',
  loginOpenUri: 'login:open-uri',
  loginGetTotp: 'login:get-totp',
  loginCopyTotp: 'login:copy-totp',
  passkeyDelete: 'passkey:delete',
  passkeyVerifyApproval: 'passkey:verify-approval',
  passkeyRespondApproval: 'passkey:respond-approval',
  loginContextMenu: 'login:context-menu',
  loginWebsiteIcon: 'login:website-icon',
  itemRevealEditorSecrets: 'item:reveal-editor-secrets',
  itemRevealSecret: 'item:reveal-secret',
  itemCopyField: 'item:copy-field',
  itemRevealCustomField: 'item:reveal-custom-field',
  itemCopyCustomField: 'item:copy-custom-field',
  generatorGenerate: 'generator:generate',
  generatorHistoryList: 'generator:history-list',
  generatorHistoryClear: 'generator:history-clear',
  generatorHistoryCopy: 'generator:history-copy',
  sshKeyGenerate: 'ssh-key:generate',
  sshKeyBeginImport: 'ssh-key:begin-import',
  sshKeySubmitImportPassphrase: 'ssh-key:submit-import-passphrase',
  sshKeyCancelImport: 'ssh-key:cancel-import',
  sshKeyCreateImported: 'ssh-key:create-imported',
  sshKeyUpdateImported: 'ssh-key:update-imported',
  sshAgentStatus: 'ssh-agent:status',
  sshAgentRespondApproval: 'ssh-agent:respond-approval',
  settingsGet: 'settings:get',
  settingsUpdate: 'settings:update',
  settingsEnableTouchId: 'settings:enable-touch-id',
  settingsDisableTouchId: 'settings:disable-touch-id',
  settingsUnlockTouchId: 'settings:unlock-touch-id',
  settingsActivity: 'settings:activity',
  syncStatus: 'sync:status',
  syncConnect: 'sync:connect',
  syncUnlock: 'sync:unlock',
  syncNow: 'sync:now',
  syncDisconnect: 'sync:disconnect'
} as const

export const IPC_EVENTS = {
  vaultLocked: 'vault:locked',
  vaultLockRequested: 'vault:lock-requested',
  vaultUnlocked: 'vault:unlocked',
  vaultChanged: 'vault:changed',
  syncChanged: 'sync:changed',
  attachmentProgress: 'attachment:progress',
  passkeyApprovalRequested: 'passkey:approval-requested',
  sshAgentApprovalRequested: 'ssh-agent:approval-requested',
  sshAgentStatusChanged: 'ssh-agent:status-changed'
} as const

export const IPC_ERROR_PREFIX = 'BEARWARDEN:'

export type VaultErrorCode =
  | 'ALREADY_INITIALIZED'
  | 'NOT_INITIALIZED'
  | 'LOCKED'
  | 'INVALID_MASTER_PASSWORD'
  | 'REPROMPT_REQUIRED'
  | 'CORRUPT_VAULT'
  | 'NOT_FOUND'
  | 'DUPLICATE_NAME'
  | 'INVALID_INPUT'
  | 'INVALID_URL'
  | 'SYNC_AUTH_REQUIRED'
  | 'SYNC_NEW_DEVICE_REQUIRED'
  | 'SYNC_UNSUPPORTED_ACCOUNT'
  | 'SYNC_FAILED'
  | 'ATTACHMENT_FAILED'
  | 'ATTACHMENT_TOO_LARGE'
  | 'ATTACHMENT_STORAGE_LIMIT'
  | 'ATTACHMENT_REJECTED'
  | 'ATTACHMENT_CANCELED'
  | 'HEALTH_CHECK_FAILED'
  | 'TOUCH_ID_UNAVAILABLE'
  | 'TOUCH_ID_FAILED'
  | 'INTERNAL_ERROR'

export type VaultState = 'uninitialized' | 'locked' | 'unlocked'

export interface VaultStatus {
  state: VaultState
}

export interface VaultSetupRequest {
  masterPassword: string
}

export interface VaultUnlockRequest {
  masterPassword: string
}

export interface VaultExportRequest {
  /** Proves the currently unlocked vault owner in the main process. */
  masterPassword: string
  /** A portable backup password; it is used only in the main process. */
  password: string
}

export interface VaultImportRequest {
  /** Proves the currently unlocked vault owner in the main process. */
  masterPassword: string
  /** Required for password-protected Bitwarden JSON; omitted for plaintext JSON. */
  password?: string
}

export interface VaultExportResult {
  canceled: boolean
  exportedFolders: number
  exportedItems: number
  skippedTrashItems: number
}

export interface VaultImportResult {
  canceled: boolean
  importedFolders: number
  importedItems: number
  skippedTrashItems: number
}

export interface FolderView {
  id: string
  name: string
  position: number
  createdAt: string
  updatedAt: string
}

export interface FolderCreateRequest {
  name: string
}

export interface FolderUpdateRequest {
  id: string
  name: string
}

export interface FolderDeleteRequest {
  id: string
  /** Item-scoped capabilities for protected items moved out of this folder. */
  authorizationTokens?: Record<string, string>
  /** One capability bound to the exact protected-item set. */
  authorizationToken?: string
}

export interface FolderReorderRequest {
  orderedIds: string[]
}

export type VaultItemType = 'login' | 'card' | 'identity' | 'secureNote' | 'sshKey'

/** Matches Bitwarden's CipherRepromptType wire values. */
export type VaultReprompt = 0 | 1

export type VaultCustomFieldType = 'text' | 'hidden' | 'boolean' | 'linked'

export const VAULT_LINKED_FIELD_IDS_BY_TYPE = {
  login: [100, 101],
  card: [300, 301, 302, 303, 304, 305],
  identity: [
    400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418
  ],
  secureNote: [],
  sshKey: []
} as const satisfies Record<VaultItemType, readonly number[]>

/** Decrypted custom field stored only inside the encrypted vault and main process. */
export interface VaultCustomField {
  name: string
  value: string
  type: VaultCustomFieldType
  linkedId: number | null
}

/** Renderer-safe custom field. Hidden values are omitted until explicitly revealed. */
export interface VaultCustomFieldView {
  name: string
  value: string | null
  type: VaultCustomFieldType
  linkedId: number | null
}

/** Original metadata used to reject stale index-based custom-field edits. */
export interface VaultCustomFieldSource {
  index: number
  name: string
  type: VaultCustomFieldType
  linkedId: number | null
}

export interface VaultCustomFieldUpdate {
  /** Null creates a field; otherwise identifies an existing field in the editor snapshot. */
  source: VaultCustomFieldSource | null
  name: string
  type: VaultCustomFieldType
  /** Null preserves an existing hidden value or represents a linked field without a stored value. */
  value: string | null
  linkedId: number | null
}

export interface VaultItemFields {
  username: string
  password: string
  /** Stored encrypted at rest and never returned in LoginView. */
  totp: string
  uri: string | null
  cardholderName: string
  brand: string
  number: string
  expMonth: string
  expYear: string
  code: string
  title: string
  firstName: string
  middleName: string
  lastName: string
  address1: string
  address2: string
  address3: string
  city: string
  state: string
  postalCode: string
  country: string
  company: string
  email: string
  phone: string
  ssn: string
  identityUsername: string
  passportNumber: string
  licenseNumber: string
  privateKey: string
  publicKey: string
  fingerprint: string
}

/** Bitwarden URI match detection values. Null inherits the account default. */
export type VaultUriMatch = 0 | 1 | 2 | 3 | 4 | 5

export interface VaultLoginUri {
  uri: string
  match: VaultUriMatch | null
}

/** Decrypted password-history entry. Only returned by the narrow, authorized history IPC. */
export interface VaultPasswordHistoryEntry {
  password: string
  lastUsedDate: string
}

export type VaultItemFieldInput = Partial<VaultItemFields>

export interface LoginCreateRequest extends VaultItemFieldInput {
  /** Omitted by older clients; defaults to login. */
  type?: VaultItemType
  name: string
  notes?: string | null
  folderId?: string | null
  favorite?: boolean
  reprompt?: VaultReprompt
  /** Ordered login URI rows. `uri` remains the primary-row compatibility alias. */
  uris?: VaultLoginUri[]
  customFields?: VaultCustomFieldUpdate[]
}

export interface LoginUpdateRequest extends VaultItemFieldInput, LoginAuthorizationRequest {
  id: string
  /** Optional optimistic-concurrency token from the editor snapshot. */
  expectedUpdatedAt?: string
  name?: string
  notes?: string | null
  folderId?: string | null
  favorite?: boolean
  reprompt?: VaultReprompt
  /** Ordered login URI rows. `uri` remains the primary-row compatibility alias. */
  uris?: VaultLoginUri[]
  customFields?: VaultCustomFieldUpdate[]
}

export interface LoginAuthorizationRequest {
  /** Short-lived, item-scoped capability issued by the main process. */
  authorizationToken?: string
}

export interface LoginIdRequest extends LoginAuthorizationRequest {
  id: string
}

export interface PasskeyDeleteRequest extends LoginIdRequest {
  credentialId: string
  /** Optional optimistic-concurrency token from the item snapshot. */
  expectedUpdatedAt?: string
}

export type AttachmentOperationKind = 'download' | 'upload' | 'delete' | 'fix-legacy'

export type AttachmentOperationStage =
  | 'choosing-file'
  | 'reading-file'
  | 'encrypting'
  | 'downloading'
  | 'uploading'
  | 'deleting'
  | 'syncing'

export interface AttachmentProgressEvent {
  operationId: string
  itemId: string
  kind: AttachmentOperationKind
  stage: AttachmentOperationStage
  completedBytes: number
  totalBytes: number | null
}

export interface AttachmentOperationRequest extends LoginIdRequest {
  operationId: string
}

export interface AttachmentTargetRequest extends AttachmentOperationRequest {
  attachmentId: string
}

export type AttachmentDownloadRequest = AttachmentTargetRequest

export interface AttachmentDownloadResult {
  canceled: boolean
  fileName: string
}

export type AttachmentUploadRequest = AttachmentOperationRequest

export interface AttachmentUploadResult {
  canceled: boolean
  attachment: VaultAttachmentView | null
}

export type AttachmentDeleteRequest = AttachmentTargetRequest

export interface AttachmentDeleteResult {
  attachmentId: string
}

export type AttachmentFixLegacyRequest = AttachmentTargetRequest

export interface AttachmentFixLegacyResult {
  attachment: VaultAttachmentView
}

export interface AttachmentCancelRequest {
  operationId: string
}

export interface AttachmentCancelResult {
  canceled: boolean
}

export interface LoginAuthorizeRequest {
  id: string
  masterPassword: string
}

export const MAX_LOGIN_AUTHORIZE_MANY_IDS = 100_000

export interface LoginAuthorizeManyRequest {
  ids: string[]
  masterPassword: string
}

export interface LoginAuthorization {
  token: string
  expiresAt: number
}

export interface LoginFavoriteRequest extends LoginIdRequest {
  favorite: boolean
}

export interface LoginMoveRequest extends LoginIdRequest {
  folderId: string | null
}

export const MAX_LOGIN_BATCH_IDS = 500
export const MAX_LOGIN_MOVE_MANY_IDS = MAX_LOGIN_BATCH_IDS

export interface LoginBatchRequest {
  ids: string[]
  authorizationToken?: string
}

export interface LoginMoveManyRequest {
  ids: string[]
  folderId: string | null
  /** Item-scoped capabilities keyed by item ID. */
  authorizationTokens?: Record<string, string>
  authorizationToken?: string
}

export interface LoginEmptyTrashRequest {
  /** Item-scoped capabilities keyed by protected trash item ID. */
  authorizationTokens?: Record<string, string>
  authorizationToken?: string
}

export type LoginSort = 'recent' | 'name'

export const MAX_LOGIN_SEARCH_QUERY_LENGTH = 1_024

export interface LoginListRequest {
  sort?: LoginSort
  /** Main-process vault search query. Empty text has the same effect as an omitted query. */
  query?: string
  /** Omit to list every folder; use null for unfiled logins. */
  folderId?: string | null
  /** False/omitted lists active items; true lists only items in the trash. */
  deleted?: boolean
  /** True lists non-trash archived items; otherwise they are excluded. */
  archived?: boolean
}

export interface LoginSummary {
  id: string
  type: VaultItemType
  name: string
  subtitle: string
  username: string
  uri: string | null
  /** Ordered URI metadata; empty for protected or trashed summaries. */
  uris: VaultLoginUri[]
  cardBrand?: string
  /** Safe summary metadata; the TOTP secret remains in the encrypted main process. */
  hasTotp?: boolean
  /** Safe summary count; passkey private material is never included. */
  passkeyCount?: number
  /** Safe summary count; history values are only available through an authorized narrow IPC. */
  passwordHistoryCount: number
  /** Safe summary count; attachment names are only available through an authorized item view. */
  attachmentCount: number
  folderId: string | null
  favorite: boolean
  lastUsedAt: string | null
  createdAt: string
  updatedAt: string
  deletedAt: string | null
  archivedAt: string | null
  reprompt: VaultReprompt
}

/**
 * A renderer-safe weak-password finding. Password values and derived password hashes remain in
 * main-process memory inside the decrypted-vault boundary.
 */
export interface VaultHealthWeakFinding {
  id: string
  name: string
  subtitle: string
  score: 0 | 1 | 2
}

/**
 * A renderer-safe reused-password finding. The reused password value never leaves main.
 */
export interface VaultHealthReusedFinding {
  id: string
  name: string
  subtitle: string
  reuseCount: number
}

/**
 * A renderer-safe exposed-password finding. Only the locally matched occurrence count crosses IPC;
 * the password and its complete SHA-1 hash remain in the main process.
 */
export interface VaultHealthExposedFinding {
  id: string
  name: string
  subtitle: string
  exposedCount: number
}

/**
 * Local vault-health results. Protected, archived, and trashed items are deliberately excluded.
 */
export interface VaultHealthReport {
  generatedAt: string
  totals: {
    analyzedCount: number
    weakPasswordCount: number
    reusedPasswordCount: number
    protectedSkippedCount: number
  }
  weakPasswords: VaultHealthWeakFinding[]
  reusedPasswords: VaultHealthReusedFinding[]
}

/**
 * Results from a user-initiated HIBP Pwned Passwords range check. The main process sends only a
 * five-character SHA-1 prefix to HIBP and compares the returned padded range locally.
 */
export interface VaultHealthExposedReport {
  generatedAt: string
  totals: {
    analyzedCount: number
    exposedPasswordCount: number
    protectedSkippedCount: number
  }
  exposedPasswords: VaultHealthExposedFinding[]
}

/** An explicit account-breach query. The complete address is sent through the configured
 * Vaultwarden server to HIBP, so this request must only be created after user confirmation. */
export interface VaultHealthAccountBreachRequest {
  email: string
}

export const MAX_ACCOUNT_BREACH_EMAIL_LENGTH = 254

/** Renderer-safe breach metadata. HIBP's HTML description is deliberately excluded. */
export interface VaultHealthAccountBreachFinding {
  name: string
  title: string
  domain: string
  breachDate: string
  addedDate: string
  pwnCount: number
  dataClasses: string[]
  isVerified: boolean
}

export type VaultHealthAccountBreachReport =
  | {
      generatedAt: string
      status: 'complete'
      breaches: VaultHealthAccountBreachFinding[]
    }
  | {
      generatedAt: string
      status: 'unavailable'
      reason: 'server-hibp-unconfigured'
      breaches: []
    }

export type SyncState = 'unconfigured' | 'locked' | 'ready' | 'syncing' | 'error'

export interface SyncStatus {
  configured: boolean
  state: SyncState
  serverUrl?: string
  email?: string
  lastSyncAt?: string
  lastError?: string
}

export type SyncTwoFactorMethod = '0' | '1' | '3'

export interface SyncConnectRequest {
  serverUrl: string
  email: string
  masterPassword: string
  twoFactorMethod?: SyncTwoFactorMethod
  twoFactorCode?: string
  newDeviceOtp?: string
}

export interface SyncUnlockRequest {
  masterPassword: string
  twoFactorMethod?: SyncTwoFactorMethod
  twoFactorCode?: string
  newDeviceOtp?: string
}

export interface SyncResult extends SyncStatus {
  pulled: number
  pushed: number
  deleted: number
  conflicts: number
}

/** Decrypted non-password fields for a login editor. */
export interface LoginView extends LoginSummary {
  notes: string | null
  hasTotp: boolean
  passkeys: PasskeyView[]
  customFields: VaultCustomFieldView[]
  attachments: VaultAttachmentView[]
  cardholderName: string
  brand: string
  expMonth: string
  expYear: string
  title: string
  firstName: string
  middleName: string
  lastName: string
  address1: string
  address2: string
  address3: string
  city: string
  state: string
  postalCode: string
  country: string
  company: string
  email: string
  phone: string
  identityUsername: string
  publicKey: string
  fingerprint: string
}

/** Renderer-safe attachment metadata. Wrapped keys, URLs, paths, and bytes remain in main. */
export interface VaultAttachmentView {
  id: string
  fileName: string
  size: number
  sizeName: string
  legacy: boolean
}

/** Safe metadata for a synced passkey. Private key material is intentionally omitted. */
export interface PasskeyView {
  credentialId: string
  rpId: string
  rpName: string | null
  userHandle: string | null
  userName: string | null
  userDisplayName: string | null
  discoverable: boolean
  creationDate: string
}

export interface TotpCodeView {
  code: string
  period: number
  remainingSeconds: number
}

export interface LoginContextMenuRequest extends LoginIdRequest {
  x?: number
  y?: number
}

export interface LoginOpenUriRequest extends LoginIdRequest {
  /** Defaults to the primary URI for older callers. */
  uriIndex?: number
}

export type VaultSecretField =
  'password' | 'number' | 'code' | 'ssn' | 'passportNumber' | 'licenseNumber' | 'privateKey'
export type VaultEditorSecretField = VaultSecretField | 'totp'
export type VaultCopyField =
  | VaultSecretField
  | 'username'
  | 'identityUsername'
  | 'uri'
  | 'email'
  | 'phone'
  | 'publicKey'
  | 'fingerprint'

export interface ItemFieldRequest extends LoginIdRequest {
  field: VaultCopyField
  /** Required only to address a non-primary URI; defaults to zero. */
  uriIndex?: number
}

export interface EditorSecretsRequest extends LoginIdRequest {
  expectedUpdatedAt: string
}

export interface EditorSecretsView {
  fields: Partial<Record<VaultEditorSecretField, string>>
  customFields: Array<{ source: VaultCustomFieldSource; value: string }>
}

export interface CustomFieldRequest extends LoginIdRequest {
  expectedUpdatedAt: string
  /** Expected renderer snapshot metadata; main rejects stale index/name/type/link mappings. */
  source: VaultCustomFieldSource
}

export type GeneratorCredentialCategory = 'password' | 'username' | 'email'
export type GeneratorCredentialAlgorithm =
  'password' | 'passphrase' | 'username' | 'subaddress' | 'catchall'

export interface GeneratorPasswordOptions {
  length?: number
  uppercase?: boolean
  lowercase?: boolean
  numbers?: boolean
  special?: boolean
  minUppercase?: number
  minLowercase?: number
  minNumber?: number
  minSpecial?: number
  avoidAmbiguous?: boolean
}

export interface GeneratorPassphraseOptions {
  wordCount?: number
  separator?: string
  capitalize?: boolean
  includeNumber?: boolean
}

export interface GeneratorRandomWordOptions {
  capitalize?: boolean
  includeNumber?: boolean
}

export type CredentialGeneratorRequest =
  | { algorithm: 'password'; options: GeneratorPasswordOptions }
  | { algorithm: 'passphrase'; options: GeneratorPassphraseOptions }
  | { algorithm: 'username'; options: GeneratorRandomWordOptions }
  | { algorithm: 'subaddress'; email: string }
  | { algorithm: 'catchall'; domain: string }

/** Official encrypted local generator-history JSON shape. */
export interface GeneratorHistoryEntry {
  credential: string
  category: GeneratorCredentialCategory
  generationDate: number
  algorithm?: GeneratorCredentialAlgorithm
}

/** Stale-safe reference to one history row; it never accepts credential plaintext. */
export interface GeneratorHistoryLocator {
  index: number
  generationDate: number
  category: GeneratorCredentialCategory
  algorithm?: GeneratorCredentialAlgorithm
}

export interface CredentialGeneratorResult extends GeneratorHistoryEntry {
  algorithm: GeneratorCredentialAlgorithm
  historyLocator: GeneratorHistoryLocator
}

/** Main-process-only SSH key material. This type must never cross the preload bridge. */
export interface SshKeyMaterial {
  privateKey: string
  publicKey: string
  fingerprint: string
}

/** Renderer-safe handle for main-process-only SSH key material. */
export interface SshKeyMaterialSession {
  status: 'ready'
  token: string
  expiresAt: number
  publicKey: string
  fingerprint: string
}

export type SshKeyGenerationResult =
  SshKeyMaterialSession | { status: 'error'; code: 'SessionUnavailable' | 'SessionLimitReached' }

/** Renderer-safe result of an SSH clipboard import. Private key material remains in main only. */
export type SshKeyImportResult =
  | { status: 'awaitingPassphrase'; token: string; expiresAt: number }
  | SshKeyMaterialSession
  | {
      status: 'error'
      code:
        | 'EmptyClipboard'
        | 'ClipboardTooLarge'
        | 'ParsingError'
        | 'UnsupportedKeyType'
        | 'WrongPassword'
        | 'InvalidPassphrase'
        | 'SessionUnavailable'
        | 'SessionLimitReached'
    }

export interface SshKeyImportPassphraseRequest {
  token: string
  passphrase: string
}

export interface SshKeyImportCancelRequest {
  token: string
}

/** The token identifies main-process-only generated or imported material. SSH fields are ignored. */
export interface SshKeyCreateImportedRequest extends LoginCreateRequest {
  importToken: string
}

/** The token identifies main-process-only generated or imported material. SSH fields are ignored. */
export interface SshKeyUpdateImportedRequest extends LoginUpdateRequest {
  importToken: string
}

export type AppTheme = 'system' | 'light' | 'dark'

/** Matches Bitwarden's SSH agent prompt behavior values. */
export type SshAgentPromptBehavior = 'always' | 'never' | 'rememberUntilLock'

/** Stable, renderer-safe SSH agent lifecycle failures. Raw OS errors stay in main. */
export type SshAgentStatusErrorCode =
  | 'SOCKET_IN_USE'
  | 'SOCKET_PATH_UNSAFE'
  | 'SOCKET_PATH_CHANGED'
  | 'SOCKET_PERMISSION_DENIED'
  | 'PIPE_IN_USE'
  | 'START_FAILED'
  | 'STOP_FAILED'

export interface SshAgentStatus {
  enabled: boolean
  running: boolean
  state: 'stopped' | 'starting' | 'ready' | 'error'
  /** Unix socket path or the fixed Windows OpenSSH named pipe. */
  endpoint?: string
  identityCount: number
  lastError?: SshAgentStatusErrorCode
}

/** Public metadata only. The bytes being signed and all key material remain in main. */
export interface SshAgentApprovalPrompt {
  requestId: string
  expiresAt: number
  itemId: string
  itemName: string
  fingerprint: string
  promptBehavior: SshAgentPromptBehavior
  requiresAgentApproval: boolean
  requiresReprompt: boolean
  processName?: string
  forwarded: boolean
  hostFingerprint?: string
  namespace?: 'git' | 'file' | 'unsupported'
  rsaHash?: 'sha256' | 'sha512'
}

export interface SshAgentApprovalResponse {
  requestId: string
  approved: boolean
  /** Existing renderer-bound reprompt capability, never a password or key. */
  authorizationToken?: string
}

export type PasskeyCeremonyKind = 'create' | 'get'
export type PasskeyUserVerificationRequirement = 'required' | 'preferred' | 'discouraged'
export type PasskeyVerificationMethod = 'none' | 'touch-id' | 'master-password'

/** Renderer-safe metadata only. Protocol bytes, credential IDs, and vault revisions stay in main. */
export interface PasskeyApprovalChoice {
  /** Request-local opaque identifier; it is not a WebAuthn credential ID. */
  id: string
  label: string
  detail?: string
  /** Display-only policy metadata. The actual reprompt proof is verified in main. */
  requiresReprompt: boolean
}

export interface PasskeyApprovalPrompt {
  requestId: string
  expiresAt: number
  kind: PasskeyCeremonyKind
  rpId: string
  rpName: string
  userVerification: PasskeyUserVerificationRequirement
  choices: readonly PasskeyApprovalChoice[]
  verificationMethods: readonly Exclude<PasskeyVerificationMethod, 'none'>[]
  userName?: string
  userDisplayName?: string
}

/** Consent and method selection are not proof that user verification succeeded. */
export interface PasskeyApprovalResponse {
  requestId: string
  approved: boolean
  selectedChoiceId?: string
  verificationMethod?: PasskeyVerificationMethod
}

/** Sends a password directly to a request-bound main-process verifier; no capability is returned. */
export interface PasskeyApprovalVerificationRequest {
  requestId: string
  selectedChoiceId?: string
  masterPassword: string
}

export interface AppSettings {
  contentProtection: boolean
  showWebsiteIcons: boolean
  autoLockMinutes: 0 | 1 | 5 | 15 | 30 | 60
  lockOnScreenLock: boolean
  lockOnSuspend: boolean
  clearClipboardSeconds: 0 | 15 | 30 | 60 | 120
  defaultSort: LoginSort
  theme: AppTheme
  /** Whether BearWarden exposes SSH keys through the local SSH agent socket. */
  sshAgentEnabled: boolean
  /** Controls whether individual SSH signing requests require user approval. */
  sshAgentPromptBehavior: SshAgentPromptBehavior
  touchIdAvailable: boolean
  touchIdEnabled: boolean
}

export type AppSettingsUpdate = Partial<Omit<AppSettings, 'touchIdAvailable' | 'touchIdEnabled'>>

export interface TouchIdEnableRequest {
  masterPassword: string
}

export interface BearWardenAPI {
  vault: {
    status: () => Promise<VaultStatus>
    setup: (request: VaultSetupRequest) => Promise<VaultStatus>
    unlock: (request: VaultUnlockRequest) => Promise<VaultStatus>
    lock: () => Promise<VaultStatus>
    setLockRequestReady: (ready: boolean) => void
    onLocked: (listener: () => void) => () => void
    onLockRequested: (listener: () => void) => () => void
    onUnlocked: (listener: () => void) => () => void
    onChanged: (listener: () => void) => () => void
  }
  portability: {
    export: (request: VaultExportRequest) => Promise<VaultExportResult>
    import: (request: VaultImportRequest) => Promise<VaultImportResult>
  }
  health: {
    /** Runs entirely in main; the renderer receives only safe finding metadata. */
    report: () => Promise<VaultHealthReport>
    /** Performs an explicit k-anonymous HIBP range check from the main process. */
    exposedPasswords: () => Promise<VaultHealthExposedReport>
    /** Cancels the active HIBP report, if any. */
    cancelExposedPasswords: () => Promise<boolean>
    /** Sends the complete address through the configured Vaultwarden server to HIBP. */
    accountBreaches: (
      request: VaultHealthAccountBreachRequest
    ) => Promise<VaultHealthAccountBreachReport>
    /** Cancels the active account-breach report, if any. */
    cancelAccountBreaches: () => Promise<boolean>
    /** Opens the fixed HIBP attribution URL in the system browser. */
    openHibpWebsite: () => Promise<void>
  }
  folders: {
    list: () => Promise<FolderView[]>
    create: (request: FolderCreateRequest) => Promise<FolderView>
    update: (request: FolderUpdateRequest) => Promise<FolderView>
    delete: (request: FolderDeleteRequest) => Promise<void>
    reorder: (request: FolderReorderRequest) => Promise<FolderView[]>
  }
  logins: {
    list: (request?: LoginListRequest) => Promise<LoginSummary[]>
    authorize: (request: LoginAuthorizeRequest) => Promise<LoginAuthorization>
    authorizeMany: (request: LoginAuthorizeManyRequest) => Promise<LoginAuthorization>
    get: (request: LoginIdRequest) => Promise<LoginView>
    getPasswordHistory: (request: LoginIdRequest) => Promise<VaultPasswordHistoryEntry[]>
    downloadAttachment: (request: AttachmentDownloadRequest) => Promise<AttachmentDownloadResult>
    uploadAttachment: (request: AttachmentUploadRequest) => Promise<AttachmentUploadResult>
    deleteAttachment: (request: AttachmentDeleteRequest) => Promise<AttachmentDeleteResult>
    fixLegacyAttachment: (request: AttachmentFixLegacyRequest) => Promise<AttachmentFixLegacyResult>
    cancelAttachment: (request: AttachmentCancelRequest) => Promise<AttachmentCancelResult>
    onAttachmentProgress: (listener: (progress: AttachmentProgressEvent) => void) => () => void
    create: (request: LoginCreateRequest) => Promise<LoginView>
    /** Creates an active copy without any passkeys or attachments. */
    clone: (request: LoginIdRequest) => Promise<LoginView>
    archive: (request: LoginIdRequest) => Promise<LoginView>
    archiveMany: (request: LoginBatchRequest) => Promise<LoginSummary[]>
    unarchive: (request: LoginIdRequest) => Promise<LoginView>
    unarchiveMany: (request: LoginBatchRequest) => Promise<LoginSummary[]>
    update: (request: LoginUpdateRequest) => Promise<LoginView>
    /** Move an active item to the trash. */
    delete: (request: LoginIdRequest) => Promise<void>
    /** Move active items to the trash. */
    deleteMany: (request: LoginBatchRequest) => Promise<number>
    restore: (request: LoginIdRequest) => Promise<LoginView>
    restoreMany: (request: LoginBatchRequest) => Promise<LoginSummary[]>
    deletePermanently: (request: LoginIdRequest) => Promise<void>
    deletePermanentlyMany: (request: LoginBatchRequest) => Promise<number>
    emptyTrash: (request?: LoginEmptyTrashRequest) => Promise<number>
    setFavorite: (request: LoginFavoriteRequest) => Promise<LoginSummary>
    move: (request: LoginMoveRequest) => Promise<LoginSummary>
    moveMany: (request: LoginMoveManyRequest) => Promise<LoginSummary[]>
    revealPassword: (request: LoginIdRequest) => Promise<string>
    copyUsername: (request: LoginIdRequest) => Promise<void>
    copyPassword: (request: LoginIdRequest) => Promise<void>
    openUri: (request: LoginOpenUriRequest) => Promise<void>
    getTotp: (request: LoginIdRequest) => Promise<TotpCodeView>
    copyTotp: (request: LoginIdRequest) => Promise<void>
    showContextMenu: (request: LoginContextMenuRequest) => Promise<void>
    getWebsiteIcon: (request: LoginIdRequest) => Promise<string | null>
    revealEditorSecrets: (request: EditorSecretsRequest) => Promise<EditorSecretsView>
    revealSecret: (request: ItemFieldRequest) => Promise<string>
    copyField: (request: ItemFieldRequest) => Promise<void>
    revealCustomField: (request: CustomFieldRequest) => Promise<string>
    copyCustomField: (request: CustomFieldRequest) => Promise<void>
  }
  passkeys: {
    /** Deletes one passkey without exposing its private key material to the renderer. */
    delete: (request: PasskeyDeleteRequest) => Promise<LoginView>
    /** Verifies a master password for one pending ceremony without starting a ceremony. */
    verifyApproval: (request: PasskeyApprovalVerificationRequest) => Promise<void>
    respondApproval: (response: PasskeyApprovalResponse) => Promise<void>
    onApprovalRequested: (listener: (request: PasskeyApprovalPrompt) => void) => () => void
  }
  generator: {
    generate: (request: CredentialGeneratorRequest) => Promise<CredentialGeneratorResult>
    history: () => Promise<GeneratorHistoryEntry[]>
    clearHistory: () => Promise<void>
    copyHistory: (request: GeneratorHistoryLocator) => Promise<void>
  }
  sshKeys: {
    generate: () => Promise<SshKeyGenerationResult>
    beginImport: () => Promise<SshKeyImportResult>
    submitImportPassphrase: (request: SshKeyImportPassphraseRequest) => Promise<SshKeyImportResult>
    cancelImport: (request: SshKeyImportCancelRequest) => Promise<void>
    createImported: (request: SshKeyCreateImportedRequest) => Promise<LoginView>
    updateImported: (request: SshKeyUpdateImportedRequest) => Promise<LoginView>
  }
  sshAgent: {
    status: () => Promise<SshAgentStatus>
    respondApproval: (response: SshAgentApprovalResponse) => Promise<void>
    onApprovalRequested: (listener: (request: SshAgentApprovalPrompt) => void) => () => void
    onStatusChanged: (listener: (status: SshAgentStatus) => void) => () => void
  }
  sync: {
    status: () => Promise<SyncStatus>
    connect: (request: SyncConnectRequest) => Promise<SyncResult>
    unlock: (request: SyncUnlockRequest) => Promise<SyncStatus>
    now: () => Promise<SyncResult>
    disconnect: () => Promise<SyncStatus>
    onChanged: (listener: (status: SyncStatus) => void) => () => void
  }
  settings: {
    get: () => Promise<AppSettings>
    update: (request: AppSettingsUpdate) => Promise<AppSettings>
    enableTouchId: (request: TouchIdEnableRequest) => Promise<AppSettings>
    disableTouchId: () => Promise<AppSettings>
    unlockTouchId: () => Promise<VaultStatus>
    activity: () => Promise<void>
  }
}
