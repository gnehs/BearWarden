export const IPC_CHANNELS = {
  vaultStatus: 'vault:status',
  vaultSetup: 'vault:setup',
  vaultUnlock: 'vault:unlock',
  vaultLock: 'vault:lock',
  folderList: 'folder:list',
  folderCreate: 'folder:create',
  folderUpdate: 'folder:update',
  folderDelete: 'folder:delete',
  folderReorder: 'folder:reorder',
  loginList: 'login:list',
  loginGet: 'login:get',
  loginCreate: 'login:create',
  loginUpdate: 'login:update',
  loginDelete: 'login:delete',
  loginSetFavorite: 'login:set-favorite',
  loginMove: 'login:move',
  loginMoveMany: 'login:move-many',
  loginRevealPassword: 'login:reveal-password',
  loginCopyUsername: 'login:copy-username',
  loginCopyPassword: 'login:copy-password',
  loginOpenUri: 'login:open-uri',
  loginGetTotp: 'login:get-totp',
  loginCopyTotp: 'login:copy-totp',
  loginContextMenu: 'login:context-menu',
  loginWebsiteIcon: 'login:website-icon',
  itemRevealEditorSecrets: 'item:reveal-editor-secrets',
  itemRevealSecret: 'item:reveal-secret',
  itemCopyField: 'item:copy-field',
  itemRevealCustomField: 'item:reveal-custom-field',
  itemCopyCustomField: 'item:copy-custom-field',
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
  vaultUnlocked: 'vault:unlocked',
  vaultChanged: 'vault:changed',
  syncChanged: 'sync:changed'
} as const

export const IPC_ERROR_PREFIX = 'BEARWARDEN:'

export type VaultErrorCode =
  | 'ALREADY_INITIALIZED'
  | 'NOT_INITIALIZED'
  | 'LOCKED'
  | 'INVALID_MASTER_PASSWORD'
  | 'CORRUPT_VAULT'
  | 'NOT_FOUND'
  | 'DUPLICATE_NAME'
  | 'INVALID_INPUT'
  | 'INVALID_URL'
  | 'SYNC_AUTH_REQUIRED'
  | 'SYNC_NEW_DEVICE_REQUIRED'
  | 'SYNC_UNSUPPORTED_ACCOUNT'
  | 'SYNC_FAILED'
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
}

export interface FolderReorderRequest {
  orderedIds: string[]
}

export type VaultItemType = 'login' | 'card' | 'identity' | 'secureNote' | 'sshKey'

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

export type VaultItemFieldInput = Partial<VaultItemFields>

export interface LoginCreateRequest extends VaultItemFieldInput {
  /** Omitted by older clients; defaults to login. */
  type?: VaultItemType
  name: string
  notes?: string | null
  folderId?: string | null
  favorite?: boolean
  customFields?: VaultCustomFieldUpdate[]
}

export interface LoginUpdateRequest extends VaultItemFieldInput {
  id: string
  /** Optional optimistic-concurrency token from the editor snapshot. */
  expectedUpdatedAt?: string
  name?: string
  notes?: string | null
  folderId?: string | null
  favorite?: boolean
  customFields?: VaultCustomFieldUpdate[]
}

export interface LoginIdRequest {
  id: string
}

export interface LoginFavoriteRequest extends LoginIdRequest {
  favorite: boolean
}

export interface LoginMoveRequest extends LoginIdRequest {
  folderId: string | null
}

export const MAX_LOGIN_MOVE_MANY_IDS = 1_000

export interface LoginMoveManyRequest {
  ids: string[]
  folderId: string | null
}

export type LoginSort = 'recent' | 'name'

export interface LoginListRequest {
  sort?: LoginSort
  /** Omit to list every folder; use null for unfiled logins. */
  folderId?: string | null
}

export interface LoginSummary {
  id: string
  type: VaultItemType
  name: string
  subtitle: string
  username: string
  uri: string | null
  cardBrand?: string
  /** Safe summary metadata; the TOTP secret remains in the encrypted main process. */
  hasTotp?: boolean
  /** Safe summary count; passkey private material is never included. */
  passkeyCount?: number
  folderId: string | null
  favorite: boolean
  lastUsedAt: string | null
  createdAt: string
  updatedAt: string
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

export type AppTheme = 'system' | 'light' | 'dark'

export interface AppSettings {
  contentProtection: boolean
  showWebsiteIcons: boolean
  autoLockMinutes: 0 | 1 | 5 | 15 | 30 | 60
  lockOnScreenLock: boolean
  lockOnSuspend: boolean
  clearClipboardSeconds: 0 | 15 | 30 | 60 | 120
  defaultSort: LoginSort
  theme: AppTheme
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
    onLocked: (listener: () => void) => () => void
    onUnlocked: (listener: () => void) => () => void
    onChanged: (listener: () => void) => () => void
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
    get: (request: LoginIdRequest) => Promise<LoginView>
    create: (request: LoginCreateRequest) => Promise<LoginView>
    update: (request: LoginUpdateRequest) => Promise<LoginView>
    delete: (request: LoginIdRequest) => Promise<void>
    setFavorite: (request: LoginFavoriteRequest) => Promise<LoginSummary>
    move: (request: LoginMoveRequest) => Promise<LoginSummary>
    moveMany: (request: LoginMoveManyRequest) => Promise<LoginSummary[]>
    revealPassword: (request: LoginIdRequest) => Promise<string>
    copyUsername: (request: LoginIdRequest) => Promise<void>
    copyPassword: (request: LoginIdRequest) => Promise<void>
    openUri: (request: LoginIdRequest) => Promise<void>
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
