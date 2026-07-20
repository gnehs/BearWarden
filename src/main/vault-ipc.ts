import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { dialog, ipcMain, type BrowserWindow, type IpcMainInvokeEvent } from 'electron'
import {
  IPC_CHANNELS,
  IPC_ERROR_PREFIX,
  IPC_EVENTS,
  ACCOUNT_SESSION_DEAUTHORIZATION_CONFIRMATION,
  MAX_VAULT_TIMEOUT_MINUTES,
  MAX_LOGIN_BATCH_IDS,
  MAX_LOGIN_MOVE_MANY_IDS,
  MAX_LOGIN_PREFETCH_IDS,
  MAX_LOGIN_AUTHORIZE_MANY_IDS,
  MAX_LOGIN_SEARCH_QUERY_LENGTH,
  MAX_ACCOUNT_BREACH_EMAIL_LENGTH,
  MAX_ACCOUNT_PROFILE_NAME_BYTES,
  type AccountMutationResult,
  type AccountProfileAvatarUpdateRequest,
  type AccountProfileNameUpdateRequest,
  type AccountRemoveRequest,
  type AccountReorderRequest,
  type AccountSessionDeauthorizationRequest,
  type LoginApprovalResponse,
  type AccountStatus,
  type AppSettingsUpdate,
  type AccountApiKeyCopyRequest,
  type AccountWebAuthnKeyEnrollmentRequest,
  type AccountWebAuthnKeyRemovalRequest,
  type AccountWebAuthnKeysRequest,
  type AccountWebAuthnKeyView,
  type AccountAuthenticatorCompleteRequest,
  type AccountEmailTwoFactorCompleteRequest,
  type AccountEmailTwoFactorSendRequest,
  type AccountTwoFactorDisableRequest,
  type AttachmentCancelRequest,
  type AttachmentDeleteRequest,
  type AttachmentDownloadRequest,
  type AttachmentFixLegacyRequest,
  type AttachmentProgressEvent,
  type AttachmentUploadRequest,
  type CustomFieldRequest,
  type EditorSecretsRequest,
  type EquivalentDomainSettingsUpdate,
  type EquivalentDomainSettingsView,
  type CredentialGeneratorRequest,
  type FolderCreateRequest,
  type FolderDeleteRequest,
  type FolderReorderRequest,
  type FolderUpdateRequest,
  type GeneratedCredentialCopyRequest,
  type GeneratorHistoryLocator,
  type LoginCreateRequest,
  type LoginAuthorizeRequest,
  type LoginAuthorizeManyRequest,
  type LoginAuthorization,
  type LoginBatchRequest,
  type LoginEmptyTrashRequest,
  type LoginContextMenuRequest,
  type LoginFavoriteRequest,
  type LoginIdRequest,
  type LoginListRequest,
  type SharedLoginListRequest,
  type LoginOpenUriRequest,
  type LoginPrefetchRequest,
  type PasskeyDeleteRequest,
  type PinUnlockEnableRequest,
  type PinUnlockRequest,
  type PasswordHistoryEntryRequest,
  type PasswordHistoryRestoreRequest,
  type LoginMoveRequest,
  type LoginMoveManyRequest,
  type LoginUpdateRequest,
  type MasterPasswordChangeRequest,
  type MasterPasswordChangeResolutionRequest,
  type MasterPasswordChangeStatus,
  type ItemFieldRequest,
  type InactiveTwoFactorDocumentationRequest,
  type InactiveTwoFactorReport,
  type SshKeyImportCancelRequest,
  type SshKeyImportPassphraseRequest,
  type SshKeyCreateImportedRequest,
  type SshKeyUpdateImportedRequest,
  type VaultCustomFieldSource,
  type VaultCustomFieldType,
  type VaultCustomFieldUpdate,
  type VaultItemFields,
  type VaultLoginUri,
  type VaultItemType,
  type SyncConnectRequest,
  type SyncPurgePersonalVaultRequest,
  type SyncResolvePendingImportRequest,
  type SyncStatus,
  type SyncTwoFactorMethod,
  type SyncUnlockRequest,
  type VaultErrorCode,
  type VaultExportRequest,
  type VaultHealthExposedReport,
  type VaultHealthAccountBreachReport,
  type VaultHealthAccountBreachRequest,
  type VaultHealthReport,
  type VaultImportRequest,
  type TouchIdEnableRequest,
  type VaultSetupRequest,
  type VaultUnlockRequest,
  type SendCreateRequest,
  type SendFileCreateRequest,
  type SendFileDownloadRequest,
  type SendUpdateRequest,
  type SendIdRequest
} from '../shared/vault-contract'
import type { AppSettingsService } from './app-settings'
import { ACCOUNT_ID_PATTERN } from './account-paths'
import { ACCOUNT_REGISTRY_MAX_ACCOUNTS } from './account-registry'
import type { AccountSwitchService } from './account-switch-service'
import { accountSwitchVaultError, isVaultError, VaultError } from './vault-errors'
import type { VaultService } from './vault-service'
import type { VaultPortabilityService } from './vault-portability'
import { showItemContextMenu } from './item-context-menu'
import { SshKeyImportSessionStore } from './ssh-key-import-session'
import {
  TwoFactorDirectoryCacheError,
  type TwoFactorDirectoryCache
} from './two-factor-directory-cache'

type RecordValue = Record<string, unknown>

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const MAX_CUSTOM_FIELDS = 1_000
const MAX_CUSTOM_FIELD_STRING_LENGTH = 5_000
const REPROMPT_TOKEN_TTL_MS = 60_000
const MAX_REPROMPT_TOKENS = 128
const MAX_LOGIN_URIS = 1_000
const MAX_URI_LENGTH = 4_096
const MAX_PASSKEY_CREDENTIAL_ID_LENGTH = 4_096
const MAX_ISO_TIMESTAMP_LENGTH = 64
const MAX_SSH_KEY_IMPORT_TOKEN_LENGTH = 128
const MAX_SSH_KEY_IMPORT_PASSPHRASE_BYTES = 1_024
const MAX_EQUIVALENT_DOMAIN_GROUPS = 10_000
const MAX_EQUIVALENT_DOMAINS_PER_GROUP = 1_000
const MAX_EQUIVALENT_DOMAIN_TOTAL = 100_000
const MAX_EQUIVALENT_DOMAIN_LENGTH = 1_024
const MAX_SYNC_RESOLUTION_MASTER_PASSWORD_LENGTH = 1_024

interface RepromptAuthorizationEntry {
  senderId: number
  itemCount: number
  itemSetDigest: Buffer
  generation: number
  expiresAt: number
}

function itemSetDigest(itemIds: readonly string[]): Buffer {
  return createHash('sha256')
    .update([...itemIds].sort().join('\0'), 'utf8')
    .digest()
}

export class RepromptAuthorizationStore {
  private readonly entries = new Map<string, RepromptAuthorizationEntry>()

  constructor(
    private readonly now: () => number = Date.now,
    private readonly createRandomBytes: (size: number) => Buffer = randomBytes
  ) {}

  issue(senderId: number, itemId: string, generation: number): LoginAuthorization {
    return this.issueMany(senderId, [itemId], generation)
  }

  issueMany(senderId: number, itemIds: readonly string[], generation: number): LoginAuthorization {
    this.removeExpired()
    while (this.entries.size >= MAX_REPROMPT_TOKENS) {
      const oldest = this.entries.keys().next().value
      if (oldest === undefined) break
      this.entries.delete(oldest)
    }
    const token = this.createRandomBytes(32).toString('base64url')
    const expiresAt = this.now() + REPROMPT_TOKEN_TTL_MS
    this.entries.set(token, {
      senderId,
      itemCount: itemIds.length,
      itemSetDigest: itemSetDigest(itemIds),
      generation,
      expiresAt
    })
    return { token, expiresAt }
  }

  validate(
    token: string | undefined,
    senderId: number,
    itemId: string,
    generation: number
  ): boolean {
    return this.validateMany(token, senderId, [itemId], generation)
  }

  validateMany(
    token: string | undefined,
    senderId: number,
    itemIds: readonly string[],
    generation: number
  ): boolean {
    this.removeExpired()
    if (!token) return false
    const entry = this.entries.get(token)
    if (
      !entry ||
      entry.senderId !== senderId ||
      entry.generation !== generation ||
      entry.expiresAt <= this.now()
    )
      return false
    if (entry.itemCount !== itemIds.length) return false
    return timingSafeEqual(entry.itemSetDigest, itemSetDigest(itemIds))
  }

  clear(): void {
    this.entries.clear()
  }

  private removeExpired(): void {
    const now = this.now()
    for (const [token, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(token)
    }
  }
}

export interface VaultIpcOptions {
  vault: VaultService
  portability: VaultPortabilityService
  settings: AppSettingsService
  /** Absent only while startup is using the fail-safe legacy storage fallback. */
  accountSwitchService?: AccountSwitchService
  getMainWindow: () => BrowserWindow | null
  /** Injected by the main process so clipboard reads and private material never enter preload. */
  sshKeyImportSessions: SshKeyImportSessionStore
  /** Shared with other main-only authorization boundaries such as the SSH agent. */
  repromptAuthorizations?: RepromptAuthorizationStore
  twoFactorDirectory?: TwoFactorDirectoryCache
  afterSetup?: () => void | Promise<void>
  beforeLock?: () => void | Promise<void>
  /** Always runs after a manual lock attempt, including teardown or lock failures. */
  afterLockAttempt?: () => void
  /** Runs only after a manual lock has succeeded. */
  afterLock?: () => void
  afterUnlock?: (masterPassword: string) => void | Promise<void>
  afterPinUnlock?: () => void | Promise<void>
  afterMasterPasswordChanged?: (status: SyncStatus) => void
  afterMutation?: () => void
  beforeSyncReconfigure?: () => void | Promise<void>
  afterSyncChanged?: (status: SyncStatus) => void
  repromptNow?: () => number
  repromptRandomBytes?: (size: number) => Buffer
}

function parseVaultExport(value: unknown): VaultExportRequest {
  const record = exactDataRecord(value, ['masterPassword', 'password', 'format'])
  if (
    record.format !== undefined &&
    record.format !== 'bitwarden-json' &&
    record.format !== 'bitwarden-csv' &&
    record.format !== 'bitwarden-zip' &&
    record.format !== 'bearwarden-native'
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  const format = record.format ?? 'bitwarden-json'
  if (
    ((format === 'bitwarden-csv' || format === 'bitwarden-zip') && record.password !== undefined) ||
    (format !== 'bitwarden-csv' &&
      format !== 'bitwarden-zip' &&
      typeof record.password !== 'string')
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  const masterPassword = requiredString(record, 'masterPassword')
  if (masterPassword.length === 0 || masterPassword.length > 1_024) {
    throw new VaultError('INVALID_INPUT')
  }
  if (format === 'bitwarden-csv' || format === 'bitwarden-zip') {
    return { masterPassword, format }
  }
  return {
    masterPassword,
    password: record.password as string,
    ...(format === 'bitwarden-json' && record.format === undefined ? {} : { format })
  }
}

function parseVaultImport(value: unknown): VaultImportRequest {
  const record = exactDataRecord(value, ['masterPassword', 'password', 'format'])
  const masterPassword = requiredString(record, 'masterPassword')
  if (
    record.format !== undefined &&
    record.format !== 'portable' &&
    record.format !== 'keepass-xml'
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  if (record.password !== undefined && typeof record.password !== 'string') {
    throw new VaultError('INVALID_INPUT')
  }
  if (record.format === 'keepass-xml') {
    if (record.password !== undefined) throw new VaultError('INVALID_INPUT')
    return { masterPassword, format: 'keepass-xml' }
  }
  return {
    masterPassword,
    ...(record.password === undefined ? {} : { password: record.password }),
    ...(record.format === undefined ? {} : { format: 'portable' as const })
  }
}

function scrubVaultImportSecrets(value: unknown): void {
  if (typeof value !== 'object' || value === null) return
  for (const key of ['masterPassword', 'password'] as const) {
    try {
      const descriptor = Object.getOwnPropertyDescriptor(value, key)
      if (!descriptor || !('value' in descriptor)) continue
      Reflect.defineProperty(value, key, { ...descriptor, value: '' })
    } catch {
      // Secret cleanup is best-effort and must not invoke accessors or mask the intended result.
    }
  }
}

function parseNativeRestorePreview(value: unknown): { password: string } {
  const record = exactRecord(value, ['password'])
  return { password: requiredString(record, 'password') }
}

function parseNativeRestoreStart(value: unknown): { sessionId: string; masterPassword: string } {
  const record = exactRecord(value, ['sessionId', 'masterPassword'])
  const sessionId = requiredString(record, 'sessionId')
  if (!UUID_PATTERN.test(sessionId)) throw new VaultError('INVALID_INPUT')
  return { sessionId, masterPassword: requiredString(record, 'masterPassword') }
}

function parseNativeRestoreSession(value: unknown): { sessionId: string } {
  const record = exactRecord(value, ['sessionId'])
  const sessionId = requiredString(record, 'sessionId')
  if (!UUID_PATTERN.test(sessionId)) throw new VaultError('INVALID_INPUT')
  return { sessionId }
}

function parseSettingsUpdate(value: unknown): AppSettingsUpdate {
  const record = exactDataRecord(value, [
    'contentProtection',
    'showWebsiteIcons',
    'startAtLogin',
    'vaultTimeoutPolicy',
    'lockOnScreenLock',
    'lockOnSuspend',
    'clearClipboardSeconds',
    'defaultSort',
    'theme',
    'sshAgentEnabled',
    'sshAgentPromptBehavior'
  ])
  const result: AppSettingsUpdate = {}
  if (record.contentProtection !== undefined) {
    if (typeof record.contentProtection !== 'boolean') throw new VaultError('INVALID_INPUT')
    result.contentProtection = record.contentProtection
  }
  if (record.showWebsiteIcons !== undefined) {
    if (typeof record.showWebsiteIcons !== 'boolean') throw new VaultError('INVALID_INPUT')
    result.showWebsiteIcons = record.showWebsiteIcons
  }
  if (record.startAtLogin !== undefined) {
    if (typeof record.startAtLogin !== 'boolean') throw new VaultError('INVALID_INPUT')
    result.startAtLogin = record.startAtLogin
  }
  if (record.vaultTimeoutPolicy !== undefined) {
    const policy = exactDataRecord(record.vaultTimeoutPolicy, ['type', 'minutes'])
    if (policy.type === 'onRestart' && Object.keys(policy).length === 1) {
      result.vaultTimeoutPolicy = { type: 'onRestart' }
    } else if (policy.type === 'systemIdle' && Object.keys(policy).length === 1) {
      result.vaultTimeoutPolicy = { type: 'systemIdle' }
    } else if (
      policy.type === 'appInactivity' &&
      Object.keys(policy).length === 2 &&
      typeof policy.minutes === 'number' &&
      Number.isSafeInteger(policy.minutes) &&
      policy.minutes >= 1 &&
      policy.minutes <= MAX_VAULT_TIMEOUT_MINUTES
    ) {
      result.vaultTimeoutPolicy = { type: 'appInactivity', minutes: policy.minutes }
    } else {
      throw new VaultError('INVALID_INPUT')
    }
  }
  for (const key of ['lockOnScreenLock', 'lockOnSuspend'] as const) {
    if (record[key] !== undefined) {
      if (typeof record[key] !== 'boolean') throw new VaultError('INVALID_INPUT')
      result[key] = record[key]
    }
  }
  if (record.clearClipboardSeconds !== undefined) {
    const value = record.clearClipboardSeconds
    if (value !== 0 && value !== 15 && value !== 30 && value !== 60 && value !== 120) {
      throw new VaultError('INVALID_INPUT')
    }
    result.clearClipboardSeconds = value
  }
  if (record.defaultSort !== undefined) {
    if (
      record.defaultSort !== 'recent' &&
      record.defaultSort !== 'name' &&
      record.defaultSort !== 'frequency'
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    result.defaultSort = record.defaultSort
  }
  if (record.theme !== undefined) {
    if (record.theme !== 'system' && record.theme !== 'light' && record.theme !== 'dark') {
      throw new VaultError('INVALID_INPUT')
    }
    result.theme = record.theme
  }
  if (record.sshAgentEnabled !== undefined) {
    if (typeof record.sshAgentEnabled !== 'boolean') throw new VaultError('INVALID_INPUT')
    result.sshAgentEnabled = record.sshAgentEnabled
  }
  if (record.sshAgentPromptBehavior !== undefined) {
    if (
      record.sshAgentPromptBehavior !== 'always' &&
      record.sshAgentPromptBehavior !== 'never' &&
      record.sshAgentPromptBehavior !== 'rememberUntilLock'
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    result.sshAgentPromptBehavior = record.sshAgentPromptBehavior
  }
  return result
}

function parseTouchIdEnable(value: unknown): TouchIdEnableRequest {
  const record = exactRecord(value, ['masterPassword'])
  return { masterPassword: requiredString(record, 'masterPassword') }
}

function parseMasterPasswordChange(value: unknown, includeHint: true): MasterPasswordChangeRequest
function parseMasterPasswordChange(
  value: unknown,
  includeHint: false
): MasterPasswordChangeResolutionRequest
function parseMasterPasswordChange(
  value: unknown,
  includeHint: boolean
): MasterPasswordChangeRequest | MasterPasswordChangeResolutionRequest {
  const allowedKeys = includeHint
    ? ['currentPassword', 'newPassword', 'hint']
    : ['currentPassword', 'newPassword']
  if (!isRecord(value)) throw new VaultError('INVALID_INPUT')
  const keys = Reflect.ownKeys(value)
  if (
    keys.some((key) => typeof key !== 'string' || !allowedKeys.includes(key)) ||
    !Object.hasOwn(value, 'currentPassword') ||
    !Object.hasOwn(value, 'newPassword')
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (!descriptor || !('value' in descriptor)) throw new VaultError('INVALID_INPUT')
  }
  const currentValue = Object.getOwnPropertyDescriptor(value, 'currentPassword')?.value
  const newValue = Object.getOwnPropertyDescriptor(value, 'newPassword')?.value
  const hintValue = Object.getOwnPropertyDescriptor(value, 'hint')?.value
  if (
    typeof currentValue !== 'string' ||
    typeof newValue !== 'string' ||
    (hintValue !== undefined && hintValue !== null && typeof hintValue !== 'string')
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  const currentPassword = currentValue.normalize('NFC')
  const newPassword = newValue.normalize('NFC')
  const hint = includeHint ? hintValue : undefined
  if (
    currentPassword.length < 12 ||
    currentPassword.length > 1_024 ||
    newPassword.length < 12 ||
    newPassword.length > 1_024 ||
    currentPassword === newPassword ||
    (typeof hint === 'string' && hint.length > 50)
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return includeHint
    ? { currentPassword, newPassword, ...(hint === undefined ? {} : { hint }) }
    : { currentPassword, newPassword }
}

function scrubMasterPasswordChangeInput(value: unknown): void {
  if (!isRecord(value)) return
  for (const [key, replacement] of [
    ['currentPassword', ''],
    ['newPassword', ''],
    ['hint', null]
  ] as const) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (descriptor && 'value' in descriptor && descriptor.writable) value[key] = replacement
  }
}

function publicMasterPasswordChangeStatus(status: {
  phase: 'prepared' | 'remote-confirmed' | 'local-rekeyed' | null
}): MasterPasswordChangeStatus {
  if (status.phase === null) return { state: 'idle', requiresReconnect: false }
  if (status.phase === 'prepared') {
    return { state: 'needs-remote-verification', requiresReconnect: true }
  }
  return { state: 'resume-required', requiresReconnect: true }
}

function parsePinEnable(value: unknown): PinUnlockEnableRequest {
  const record = exactRecord(value, ['pin', 'masterPassword'])
  const request = {
    pin: requiredString(record, 'pin'),
    masterPassword: requiredString(record, 'masterPassword')
  }
  if (
    request.pin.normalize('NFC').length < 4 ||
    request.pin.length > 1_024 ||
    request.masterPassword.length === 0 ||
    request.masterPassword.length > 16_384
  ) {
    request.pin = ''
    request.masterPassword = ''
    throw new VaultError('INVALID_INPUT')
  }
  return request
}

function parsePinUnlock(value: unknown): PinUnlockRequest {
  const record = exactRecord(value, ['pin'])
  const request = { pin: requiredString(record, 'pin') }
  if (request.pin.normalize('NFC').length < 4 || request.pin.length > 1_024) {
    request.pin = ''
    throw new VaultError('INVALID_INPUT')
  }
  return request
}

function parseNoInput(value: unknown): void {
  if (value !== undefined) throw new VaultError('INVALID_INPUT')
}

function parseAccountSwitch(value: unknown): string {
  const record = exactRecord(value, ['accountId'])
  const accountId = requiredString(record, 'accountId')
  if (!ACCOUNT_ID_PATTERN.test(accountId)) throw new VaultError('INVALID_INPUT')
  return accountId
}

function strictRequiredDataRecord(value: unknown, requiredKeys: readonly string[]): RecordValue {
  if (!isRecord(value)) throw new VaultError('INVALID_INPUT')
  const descriptors = Object.getOwnPropertyDescriptors(value)
  if (
    Reflect.ownKeys(descriptors).some((key) => typeof key !== 'string') ||
    Object.keys(descriptors).length !== requiredKeys.length
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  const result: RecordValue = {}
  for (const key of requiredKeys) {
    const descriptor = descriptors[key]
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !('value' in descriptor) ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    result[key] = descriptor.value
  }
  return result
}

function strictAccountIdArray(value: unknown): readonly string[] {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length < 1 ||
    value.length > ACCOUNT_REGISTRY_MAX_ACCOUNTS
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== 'string')) {
    throw new VaultError('INVALID_INPUT')
  }
  const result: string[] = []
  const allowedKeys = new Set(['length'])
  for (let index = 0; index < value.length; index += 1) {
    const key = String(index)
    const descriptor = descriptors[key]
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !('value' in descriptor) ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined ||
      typeof descriptor.value !== 'string' ||
      !ACCOUNT_ID_PATTERN.test(descriptor.value)
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    result.push(descriptor.value)
    allowedKeys.add(key)
  }
  if (
    Object.keys(descriptors).some((key) => !allowedKeys.has(key)) ||
    new Set(result).size !== result.length
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return Object.freeze(result)
}

function parseAccountReorder(value: unknown): AccountReorderRequest {
  const record = strictRequiredDataRecord(value, ['accountIds', 'expectedRevision'])
  if (!Number.isSafeInteger(record.expectedRevision) || (record.expectedRevision as number) < 1) {
    throw new VaultError('INVALID_INPUT')
  }
  return {
    accountIds: strictAccountIdArray(record.accountIds),
    expectedRevision: record.expectedRevision as number
  }
}

function parseAccountRemove(value: unknown): AccountRemoveRequest {
  const record = strictRequiredDataRecord(value, ['accountId', 'confirm'])
  if (
    typeof record.accountId !== 'string' ||
    !ACCOUNT_ID_PATTERN.test(record.accountId) ||
    record.confirm !== true
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return { accountId: record.accountId, confirm: true }
}

function publicAccountStatus(status: AccountStatus): AccountStatus {
  return {
    revision: status.revision,
    activeAccountId: status.activeAccountId,
    accounts: status.accounts.map(({ id, active, slot }) => ({ id, active, slot })),
    ...(status.cleanupPending === true ? { cleanupPending: true } : {})
  }
}

function publicAccountMutation(result: AccountMutationResult): AccountMutationResult {
  return {
    kind: result.kind,
    status: publicAccountStatus(result.status),
    ...(result.kind === 'updated' && result.cleanupPending === true ? { cleanupPending: true } : {})
  }
}

function parseAccountApiKeyCopy(value: unknown): AccountApiKeyCopyRequest {
  const record = exactRecord(value, ['masterPassword', 'rotate', 'confirmRotation'])
  const masterPassword = requiredString(record, 'masterPassword')
  if (
    masterPassword.length > 16_384 ||
    typeof record.rotate !== 'boolean' ||
    typeof record.confirmRotation !== 'boolean' ||
    record.confirmRotation !== record.rotate
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return {
    masterPassword,
    rotate: record.rotate,
    confirmRotation: record.confirmRotation
  }
}

function parseAccountProfileNameUpdate(value: unknown): AccountProfileNameUpdateRequest {
  const record = exactDataRecord(value, ['name', 'expectedName'])
  const name = requiredString(record, 'name')
  const expectedName = requiredString(record, 'expectedName')
  if (
    Buffer.byteLength(name, 'utf8') > MAX_ACCOUNT_PROFILE_NAME_BYTES ||
    Buffer.byteLength(expectedName, 'utf8') > MAX_ACCOUNT_PROFILE_NAME_BYTES ||
    /[\0\r\n]/u.test(name) ||
    /[\0\r\n]/u.test(expectedName)
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return { name, expectedName }
}

function parseAccountProfileAvatarUpdate(value: unknown): AccountProfileAvatarUpdateRequest {
  const record = exactDataRecord(value, ['avatarColor', 'expectedAvatarColor'])
  const valid = (color: unknown): color is string | null =>
    color === null || (typeof color === 'string' && /^#[0-9a-f]{6}$/iu.test(color))
  if (!valid(record.avatarColor) || !valid(record.expectedAvatarColor)) {
    throw new VaultError('INVALID_INPUT')
  }
  return {
    avatarColor: record.avatarColor?.toLocaleUpperCase('en-US') ?? null,
    expectedAvatarColor: record.expectedAvatarColor?.toLocaleUpperCase('en-US') ?? null
  }
}

function parseLoginApprovalResponse(value: unknown): LoginApprovalResponse {
  const record = exactDataRecord(value, ['token', 'fingerprint', 'approved'])
  const token = requiredString(record, 'token')
  const fingerprint = requiredString(record, 'fingerprint')
  if (
    !UUID_PATTERN.test(token) ||
    fingerprint.length === 0 ||
    fingerprint.length > 256 ||
    /[\0\r\n]/u.test(fingerprint) ||
    typeof record.approved !== 'boolean'
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return { token, fingerprint, approved: record.approved }
}

function parseAccountSessionDeauthorization(value: unknown): AccountSessionDeauthorizationRequest {
  const record = exactDataRecord(value, ['masterPassword', 'confirmation', 'confirm'])
  const request: AccountSessionDeauthorizationRequest = {
    masterPassword: requiredString(record, 'masterPassword'),
    confirmation: record.confirmation as typeof ACCOUNT_SESSION_DEAUTHORIZATION_CONFIRMATION,
    confirm: record.confirm as true
  }
  if (
    request.masterPassword.length === 0 ||
    request.masterPassword.length > 16_384 ||
    request.confirmation !== ACCOUNT_SESSION_DEAUTHORIZATION_CONFIRMATION ||
    request.confirm !== true
  ) {
    request.masterPassword = ''
    throw new VaultError('INVALID_INPUT')
  }
  return request
}

function scrubAccountSessionDeauthorization(value: unknown): void {
  if (typeof value !== 'object' || value === null) return
  for (const key of ['masterPassword', 'confirmation'] as const) {
    try {
      const descriptor = Object.getOwnPropertyDescriptor(value, key)
      if (!descriptor || !('value' in descriptor)) continue
      Reflect.defineProperty(value, key, { ...descriptor, value: '' })
    } catch {
      // Best-effort cleanup must not invoke accessors or replace the operation result.
    }
  }
}

const MAX_ACCOUNT_WEBAUTHN_KEY_ID = 2_147_483_647
const MAX_ACCOUNT_WEBAUTHN_KEY_NAME_BYTES = 256
const MAX_ACCOUNT_WEBAUTHN_MASTER_PASSWORD_LENGTH = 16_384

function parseAccountWebAuthnKeys(value: unknown): AccountWebAuthnKeysRequest {
  const record = exactRecord(value, ['masterPassword'])
  const request = { masterPassword: requiredString(record, 'masterPassword') }
  if (
    request.masterPassword.length === 0 ||
    request.masterPassword.length > MAX_ACCOUNT_WEBAUTHN_MASTER_PASSWORD_LENGTH
  ) {
    request.masterPassword = ''
    throw new VaultError('INVALID_INPUT')
  }
  return request
}

function parseAccountWebAuthnKeyEnrollment(value: unknown): AccountWebAuthnKeyEnrollmentRequest {
  const record = exactRecord(value, ['masterPassword', 'name'])
  const request = {
    masterPassword: requiredString(record, 'masterPassword'),
    name: requiredString(record, 'name').trim()
  }
  if (
    request.masterPassword.length === 0 ||
    request.masterPassword.length > MAX_ACCOUNT_WEBAUTHN_MASTER_PASSWORD_LENGTH ||
    request.name.length === 0 ||
    Buffer.byteLength(request.name, 'utf8') > MAX_ACCOUNT_WEBAUTHN_KEY_NAME_BYTES ||
    /[\0\r\n]/u.test(request.name)
  ) {
    request.masterPassword = ''
    request.name = ''
    throw new VaultError('INVALID_INPUT')
  }
  return request
}

function parseAccountWebAuthnKeyRemoval(value: unknown): AccountWebAuthnKeyRemovalRequest {
  const record = exactRecord(value, ['id', 'masterPassword', 'confirm'])
  const request = {
    id: record.id,
    masterPassword: requiredString(record, 'masterPassword'),
    confirm: record.confirm
  }
  if (
    typeof request.id !== 'number' ||
    !Number.isSafeInteger(request.id) ||
    request.id < 1 ||
    request.id > MAX_ACCOUNT_WEBAUTHN_KEY_ID ||
    request.masterPassword.length === 0 ||
    request.masterPassword.length > MAX_ACCOUNT_WEBAUTHN_MASTER_PASSWORD_LENGTH ||
    request.confirm !== true
  ) {
    request.masterPassword = ''
    throw new VaultError('INVALID_INPUT')
  }
  return request as AccountWebAuthnKeyRemovalRequest
}

function publicAccountWebAuthnKeys(
  keys: readonly AccountWebAuthnKeyView[]
): AccountWebAuthnKeyView[] {
  return keys.map(({ id, name, migrated }) => ({ id, name, migrated }))
}

function parseGeneratorBooleanOptions(
  record: RecordValue,
  keys: readonly string[]
): Record<string, boolean> {
  const result: Record<string, boolean> = {}
  for (const key of keys) {
    const value = record[key]
    if (value === undefined) continue
    if (typeof value !== 'boolean') throw new VaultError('INVALID_INPUT')
    result[key] = value
  }
  return result
}

function parseGeneratorInteger(
  record: RecordValue,
  key: string,
  minimum: number,
  maximum: number
): number | undefined {
  const value = record[key]
  if (value === undefined) return undefined
  if (
    !Number.isSafeInteger(value) ||
    typeof value !== 'number' ||
    value < minimum ||
    value > maximum
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return value
}

function parseGeneratorRequest(value: unknown): CredentialGeneratorRequest {
  const request = exactRecord(value, ['algorithm', 'options', 'email', 'domain'])
  if (request.algorithm === 'password') {
    if (request.email !== undefined || request.domain !== undefined)
      throw new VaultError('INVALID_INPUT')
    const options = exactRecord(request.options, [
      'length',
      'uppercase',
      'lowercase',
      'numbers',
      'special',
      'minUppercase',
      'minLowercase',
      'minNumber',
      'minSpecial',
      'avoidAmbiguous'
    ])
    return {
      algorithm: 'password',
      options: {
        ...parseGeneratorBooleanOptions(options, [
          'uppercase',
          'lowercase',
          'numbers',
          'special',
          'avoidAmbiguous'
        ]),
        ...optionalDefined('length', parseGeneratorInteger(options, 'length', 5, 128)),
        ...optionalDefined('minUppercase', parseGeneratorInteger(options, 'minUppercase', 0, 128)),
        ...optionalDefined('minLowercase', parseGeneratorInteger(options, 'minLowercase', 0, 128)),
        ...optionalDefined('minNumber', parseGeneratorInteger(options, 'minNumber', 0, 9)),
        ...optionalDefined('minSpecial', parseGeneratorInteger(options, 'minSpecial', 0, 9))
      }
    }
  }
  if (request.algorithm === 'passphrase') {
    if (request.email !== undefined || request.domain !== undefined)
      throw new VaultError('INVALID_INPUT')
    const options = exactRecord(request.options, [
      'wordCount',
      'separator',
      'capitalize',
      'includeNumber'
    ])
    const separator = options.separator
    if (
      separator !== undefined &&
      (typeof separator !== 'string' || separator.length !== 1 || /[\p{Cc}\p{Cf}]/u.test(separator))
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    return {
      algorithm: 'passphrase',
      options: {
        ...parseGeneratorBooleanOptions(options, ['capitalize', 'includeNumber']),
        ...optionalDefined('wordCount', parseGeneratorInteger(options, 'wordCount', 3, 20)),
        ...optionalDefined('separator', separator as string | undefined)
      }
    }
  }
  if (request.algorithm === 'username') {
    if (request.email !== undefined || request.domain !== undefined)
      throw new VaultError('INVALID_INPUT')
    const options = exactRecord(request.options, ['capitalize', 'includeNumber'])
    return {
      algorithm: 'username',
      options: parseGeneratorBooleanOptions(options, ['capitalize', 'includeNumber'])
    }
  }
  if (request.algorithm === 'subaddress') {
    if (request.options !== undefined || request.domain !== undefined)
      throw new VaultError('INVALID_INPUT')
    const email = requiredString(request, 'email')
    if (email.length === 0 || email.length > 254) throw new VaultError('INVALID_INPUT')
    return { algorithm: 'subaddress', email }
  }
  if (request.algorithm === 'catchall') {
    if (request.options !== undefined || request.email !== undefined)
      throw new VaultError('INVALID_INPUT')
    const domain = requiredString(request, 'domain')
    if (domain.length === 0 || domain.length > 254) throw new VaultError('INVALID_INPUT')
    return { algorithm: 'catchall', domain }
  }
  throw new VaultError('INVALID_INPUT')
}

function optionalDefined<Key extends string, Value>(
  key: Key,
  value: Value | undefined
): { [Property in Key]?: Value } {
  return value === undefined ? {} : ({ [key]: value } as { [Property in Key]: Value })
}

function parseGeneratorHistoryLocator(value: unknown): GeneratorHistoryLocator {
  const record = exactRecord(value, ['index', 'generationDate', 'category', 'algorithm'])
  if (
    typeof record.index !== 'number' ||
    !Number.isSafeInteger(record.index) ||
    record.index < 0 ||
    record.index >= 200 ||
    typeof record.generationDate !== 'number' ||
    !Number.isSafeInteger(record.generationDate) ||
    record.generationDate < 0 ||
    record.generationDate > 8_640_000_000_000_000 ||
    (record.category !== 'password' &&
      record.category !== 'username' &&
      record.category !== 'email') ||
    (record.algorithm !== undefined &&
      record.algorithm !== 'password' &&
      record.algorithm !== 'passphrase' &&
      record.algorithm !== 'username' &&
      record.algorithm !== 'subaddress' &&
      record.algorithm !== 'catchall')
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return {
    index: record.index,
    generationDate: record.generationDate,
    category: record.category,
    ...(record.algorithm === undefined ? {} : { algorithm: record.algorithm })
  }
}

function parseGeneratedCredentialCopyRequest(value: unknown): GeneratedCredentialCopyRequest {
  const record = exactRecord(value, ['token'])
  const token = requiredString(record, 'token')
  if (!UUID_PATTERN.test(token)) throw new VaultError('INVALID_INPUT')
  return { token }
}

function isRecord(value: unknown): value is RecordValue {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function exactRecord(value: unknown, allowedKeys: readonly string[]): RecordValue {
  if (!isRecord(value)) throw new VaultError('INVALID_INPUT')
  if (Object.keys(value).some((key) => !allowedKeys.includes(key))) {
    throw new VaultError('INVALID_INPUT')
  }
  return value
}

function exactDataRecord(value: unknown, allowedKeys: readonly string[]): RecordValue {
  if (!isRecord(value)) throw new VaultError('INVALID_INPUT')
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new VaultError('INVALID_INPUT')
  const descriptors = Object.getOwnPropertyDescriptors(value)
  if (
    Reflect.ownKeys(value).some((key) =>
      typeof key !== 'string' ? true : !allowedKeys.includes(key)
    )
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  const result: RecordValue = Object.create(null) as RecordValue
  for (const key of Object.keys(descriptors)) {
    const descriptor = descriptors[key]!
    if (!descriptor.enumerable || !('value' in descriptor)) throw new VaultError('INVALID_INPUT')
    result[key] = descriptor.value
  }
  return result
}

function requiredString(record: RecordValue, key: string): string {
  const value = record[key]
  if (typeof value !== 'string') throw new VaultError('INVALID_INPUT')
  return value
}

function optionalStringOrNull(record: RecordValue, key: string): string | null | undefined {
  const value = record[key]
  if (value === undefined || value === null || typeof value === 'string') return value
  throw new VaultError('INVALID_INPUT')
}

function optionalBoolean(record: RecordValue, key: string): boolean | undefined {
  const value = record[key]
  if (value === undefined || typeof value === 'boolean') return value
  throw new VaultError('INVALID_INPUT')
}

function optionalAuthorizationToken(record: RecordValue): string | undefined {
  const value = record.authorizationToken
  if (value === undefined) return undefined
  if (typeof value !== 'string' || value.length === 0 || value.length > 256) {
    throw new VaultError('INVALID_INPUT')
  }
  return value
}

function authorizationTokens(value: unknown): Record<string, string> | undefined {
  if (value === undefined) return undefined
  if (!isRecord(value) || Object.keys(value).length > MAX_LOGIN_MOVE_MANY_IDS) {
    throw new VaultError('INVALID_INPUT')
  }
  const result: Record<string, string> = {}
  for (const [id, token] of Object.entries(value)) {
    if (
      !UUID_PATTERN.test(id) ||
      typeof token !== 'string' ||
      token.length === 0 ||
      token.length > 256
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    result[id] = token
  }
  return result
}

function customFieldType(value: unknown): VaultCustomFieldType {
  if (value !== 'text' && value !== 'hidden' && value !== 'boolean' && value !== 'linked') {
    throw new VaultError('INVALID_INPUT')
  }
  return value
}

function customFieldLinkedId(value: unknown): number | null {
  if (value === null) return null
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new VaultError('INVALID_INPUT')
  }
  return value
}

function boundedCustomFieldString(value: unknown): string {
  if (typeof value !== 'string' || value.length > MAX_CUSTOM_FIELD_STRING_LENGTH) {
    throw new VaultError('INVALID_INPUT')
  }
  return value
}

function parseCustomFieldSource(value: unknown): VaultCustomFieldSource {
  const record = exactRecord(value, ['index', 'name', 'type', 'linkedId'])
  if (typeof record.index !== 'number' || !Number.isSafeInteger(record.index) || record.index < 0) {
    throw new VaultError('INVALID_INPUT')
  }
  return {
    index: record.index,
    name: boundedCustomFieldString(record.name),
    type: customFieldType(record.type),
    linkedId: customFieldLinkedId(record.linkedId)
  }
}

function parseCustomFields(value: unknown): VaultCustomFieldUpdate[] {
  if (!Array.isArray(value) || value.length > MAX_CUSTOM_FIELDS) {
    throw new VaultError('INVALID_INPUT')
  }
  return value.map((candidate): VaultCustomFieldUpdate => {
    const record = exactRecord(candidate, ['source', 'name', 'type', 'value', 'linkedId'])
    const type = customFieldType(record.type)
    const fieldValue = record.value
    if (
      fieldValue !== null &&
      (typeof fieldValue !== 'string' || fieldValue.length > MAX_CUSTOM_FIELD_STRING_LENGTH)
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    if (type === 'boolean' && fieldValue !== 'true' && fieldValue !== 'false') {
      throw new VaultError('INVALID_INPUT')
    }
    if (type === 'linked' && fieldValue !== null) throw new VaultError('INVALID_INPUT')
    return {
      source: record.source === null ? null : parseCustomFieldSource(record.source),
      name: boundedCustomFieldString(record.name),
      type,
      value: fieldValue,
      linkedId: customFieldLinkedId(record.linkedId)
    }
  })
}

function parseSetup(value: unknown): VaultSetupRequest {
  const record = exactRecord(value, ['masterPassword'])
  return { masterPassword: requiredString(record, 'masterPassword') }
}

function parseUnlock(value: unknown): VaultUnlockRequest {
  return parseSetup(value)
}

function parseFolderCreate(value: unknown): FolderCreateRequest {
  const record = exactRecord(value, ['name'])
  return { name: requiredString(record, 'name') }
}

function parseFolderUpdate(value: unknown): FolderUpdateRequest {
  const record = exactRecord(value, ['id', 'name'])
  return { id: requiredString(record, 'id'), name: requiredString(record, 'name') }
}

function parseId(value: unknown): LoginIdRequest {
  const record = exactRecord(value, ['id', 'authorizationToken'])
  const authorizationToken = optionalAuthorizationToken(record)
  return {
    id: requiredString(record, 'id'),
    ...(authorizationToken ? { authorizationToken } : {})
  }
}

function parsePasswordHistoryEntry(value: unknown): PasswordHistoryEntryRequest {
  const record = exactRecord(value, [
    'id',
    'index',
    'lastUsedDate',
    'expectedUpdatedAt',
    'authorizationToken'
  ])
  const authorizationToken = optionalAuthorizationToken(record)
  const id = requiredString(record, 'id')
  const lastUsedDate = requiredString(record, 'lastUsedDate')
  const expectedUpdatedAt = requiredString(record, 'expectedUpdatedAt')
  if (
    typeof record.index !== 'number' ||
    !Number.isSafeInteger(record.index) ||
    record.index < 0 ||
    record.index >= 5 ||
    lastUsedDate.length > MAX_ISO_TIMESTAMP_LENGTH ||
    expectedUpdatedAt.length > MAX_ISO_TIMESTAMP_LENGTH ||
    !Number.isFinite(Date.parse(lastUsedDate)) ||
    !Number.isFinite(Date.parse(expectedUpdatedAt))
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return {
    id,
    index: record.index,
    lastUsedDate,
    expectedUpdatedAt,
    ...(authorizationToken ? { authorizationToken } : {})
  }
}

const parsePasswordHistoryRestore = parsePasswordHistoryEntry as (
  value: unknown
) => PasswordHistoryRestoreRequest

function parsePasskeyDelete(value: unknown): PasskeyDeleteRequest {
  const record = exactRecord(value, [
    'id',
    'credentialId',
    'expectedUpdatedAt',
    'authorizationToken'
  ])
  const authorizationToken = optionalAuthorizationToken(record)
  const expectedUpdatedAt = optionalStringOrNull(record, 'expectedUpdatedAt')
  const credentialId = requiredString(record, 'credentialId')
  if (
    credentialId.length === 0 ||
    credentialId.length > MAX_PASSKEY_CREDENTIAL_ID_LENGTH ||
    expectedUpdatedAt === null ||
    (expectedUpdatedAt !== undefined && expectedUpdatedAt.length > MAX_ISO_TIMESTAMP_LENGTH)
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return {
    id: requiredString(record, 'id'),
    credentialId,
    ...(expectedUpdatedAt === undefined ? {} : { expectedUpdatedAt }),
    ...(authorizationToken ? { authorizationToken } : {})
  }
}

function requiredOperationId(record: RecordValue): string {
  const operationId = requiredString(record, 'operationId')
  if (!UUID_PATTERN.test(operationId)) throw new VaultError('INVALID_INPUT')
  return operationId
}

function parseAttachmentTarget(value: unknown): AttachmentDownloadRequest {
  const record = exactRecord(value, ['id', 'attachmentId', 'operationId', 'authorizationToken'])
  const authorizationToken = optionalAuthorizationToken(record)
  return {
    id: requiredString(record, 'id'),
    attachmentId: requiredString(record, 'attachmentId'),
    operationId: requiredOperationId(record),
    ...(authorizationToken ? { authorizationToken } : {})
  }
}

function parseAttachmentUpload(value: unknown): AttachmentUploadRequest {
  const record = exactRecord(value, ['id', 'operationId', 'authorizationToken'])
  const authorizationToken = optionalAuthorizationToken(record)
  return {
    id: requiredString(record, 'id'),
    operationId: requiredOperationId(record),
    ...(authorizationToken ? { authorizationToken } : {})
  }
}

function parseAttachmentCancel(value: unknown): AttachmentCancelRequest {
  const record = exactRecord(value, ['operationId'])
  return { operationId: requiredOperationId(record) }
}

function parseLoginAuthorize(value: unknown): LoginAuthorizeRequest {
  const record = exactRecord(value, ['id', 'masterPassword'])
  return {
    id: requiredString(record, 'id'),
    masterPassword: requiredString(record, 'masterPassword')
  }
}

function parseLoginAuthorizeMany(value: unknown): LoginAuthorizeManyRequest {
  const record = exactRecord(value, ['ids', 'masterPassword'])
  if (
    !Array.isArray(record.ids) ||
    record.ids.length === 0 ||
    record.ids.length > MAX_LOGIN_AUTHORIZE_MANY_IDS ||
    record.ids.some((id) => typeof id !== 'string' || !UUID_PATTERN.test(id)) ||
    new Set(record.ids).size !== record.ids.length
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return {
    ids: [...record.ids] as string[],
    masterPassword: requiredString(record, 'masterPassword')
  }
}

function parseContextMenu(value: unknown): LoginContextMenuRequest {
  const record = exactRecord(value, ['id', 'x', 'y', 'authorizationToken'])
  const authorizationToken = optionalAuthorizationToken(record)
  const result: LoginContextMenuRequest = { id: requiredString(record, 'id') }
  if (authorizationToken) result.authorizationToken = authorizationToken
  for (const coordinate of ['x', 'y'] as const) {
    const candidate = record[coordinate]
    if (candidate === undefined) continue
    if (!Number.isSafeInteger(candidate) || typeof candidate !== 'number') {
      throw new VaultError('INVALID_INPUT')
    }
    result[coordinate] = candidate
  }
  if ((result.x === undefined) !== (result.y === undefined)) throw new VaultError('INVALID_INPUT')
  return result
}

function parseFolderDelete(value: unknown): FolderDeleteRequest {
  const record = exactRecord(value, ['id', 'authorizationToken', 'authorizationTokens'])
  const parsedTokens = authorizationTokens(record.authorizationTokens)
  const authorizationToken = optionalAuthorizationToken(record)
  return {
    id: requiredString(record, 'id'),
    ...(authorizationToken ? { authorizationToken } : {}),
    ...(parsedTokens ? { authorizationTokens: parsedTokens } : {})
  }
}

function parseFolderReorder(value: unknown): FolderReorderRequest {
  const record = exactRecord(value, ['orderedIds'])
  if (
    !Array.isArray(record.orderedIds) ||
    record.orderedIds.length > 10_000 ||
    record.orderedIds.some((id) => typeof id !== 'string')
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return { orderedIds: [...record.orderedIds] as string[] }
}

function parseLoginCreate(
  value: unknown,
  allowedAdditionalKeys: readonly string[] = []
): LoginCreateRequest {
  const fieldKeys = [
    'username',
    'password',
    'totp',
    'uri',
    'cardholderName',
    'brand',
    'number',
    'expMonth',
    'expYear',
    'code',
    'title',
    'firstName',
    'middleName',
    'lastName',
    'address1',
    'address2',
    'address3',
    'city',
    'state',
    'postalCode',
    'country',
    'company',
    'email',
    'phone',
    'ssn',
    'identityUsername',
    'passportNumber',
    'licenseNumber',
    'privateKey',
    'publicKey',
    'fingerprint'
  ] as const satisfies readonly (keyof VaultItemFields)[]
  const record = exactRecord(value, [
    'type',
    'name',
    'notes',
    'folderId',
    'favorite',
    'reprompt',
    'customFields',
    'uris',
    ...fieldKeys,
    ...allowedAdditionalKeys
  ])
  const result: LoginCreateRequest = {
    name: requiredString(record, 'name')
  }
  const type = record.type
  if (
    type !== undefined &&
    type !== 'login' &&
    type !== 'card' &&
    type !== 'identity' &&
    type !== 'secureNote' &&
    type !== 'sshKey'
  )
    throw new VaultError('INVALID_INPUT')
  if (type !== undefined) result.type = type as VaultItemType
  for (const key of fieldKeys) {
    const field = optionalStringOrNull(record, key)
    if (field !== undefined) Object.assign(result, { [key]: field ?? '' })
  }
  const notes = optionalStringOrNull(record, 'notes')
  const folderId = optionalStringOrNull(record, 'folderId')
  const favorite = optionalBoolean(record, 'favorite')
  const customFields =
    record.customFields === undefined ? undefined : parseCustomFields(record.customFields)
  if (notes !== undefined) result.notes = notes
  if (folderId !== undefined) result.folderId = folderId
  if (favorite !== undefined) result.favorite = favorite
  if (record.reprompt !== undefined) {
    if (record.reprompt !== 0 && record.reprompt !== 1) throw new VaultError('INVALID_INPUT')
    result.reprompt = record.reprompt
  }
  if (customFields !== undefined) result.customFields = customFields
  if (record.uris !== undefined) result.uris = parseLoginUris(record.uris)
  return result
}

function parseLoginUpdate(
  value: unknown,
  allowedAdditionalKeys: readonly string[] = []
): LoginUpdateRequest {
  const fieldKeys = [
    'username',
    'password',
    'totp',
    'uri',
    'cardholderName',
    'brand',
    'number',
    'expMonth',
    'expYear',
    'code',
    'title',
    'firstName',
    'middleName',
    'lastName',
    'address1',
    'address2',
    'address3',
    'city',
    'state',
    'postalCode',
    'country',
    'company',
    'email',
    'phone',
    'ssn',
    'identityUsername',
    'passportNumber',
    'licenseNumber',
    'privateKey',
    'publicKey',
    'fingerprint'
  ] as const satisfies readonly (keyof VaultItemFields)[]
  const record = exactRecord(value, [
    'id',
    'expectedUpdatedAt',
    'name',
    'notes',
    'folderId',
    'favorite',
    'reprompt',
    'authorizationToken',
    'customFields',
    'uris',
    ...fieldKeys,
    ...allowedAdditionalKeys
  ])
  const result: LoginUpdateRequest = { id: requiredString(record, 'id') }
  const authorizationToken = optionalAuthorizationToken(record)
  if (authorizationToken) result.authorizationToken = authorizationToken
  if (record.expectedUpdatedAt !== undefined) {
    result.expectedUpdatedAt = requiredString(record, 'expectedUpdatedAt')
  }
  for (const key of ['name'] as const) {
    if (record[key] !== undefined) result[key] = requiredString(record, key)
  }
  for (const key of fieldKeys) {
    const field = optionalStringOrNull(record, key)
    if (field !== undefined) Object.assign(result, { [key]: field ?? '' })
  }
  const notes = optionalStringOrNull(record, 'notes')
  const folderId = optionalStringOrNull(record, 'folderId')
  const favorite = optionalBoolean(record, 'favorite')
  const customFields =
    record.customFields === undefined ? undefined : parseCustomFields(record.customFields)
  if (notes !== undefined) result.notes = notes
  if (folderId !== undefined) result.folderId = folderId
  if (favorite !== undefined) result.favorite = favorite
  if (record.reprompt !== undefined) {
    if (record.reprompt !== 0 && record.reprompt !== 1) throw new VaultError('INVALID_INPUT')
    result.reprompt = record.reprompt
  }
  if (customFields !== undefined) result.customFields = customFields
  if (record.uris !== undefined) result.uris = parseLoginUris(record.uris)
  return result
}

function parseSshKeyImportToken(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_SSH_KEY_IMPORT_TOKEN_LENGTH ||
    Buffer.byteLength(value, 'utf8') > MAX_SSH_KEY_IMPORT_TOKEN_LENGTH ||
    !/^[A-Za-z0-9_-]+$/u.test(value)
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return value
}

function parseSshKeyImportPassphrase(value: unknown): SshKeyImportPassphraseRequest {
  const record = exactRecord(value, ['token', 'passphrase'])
  const passphrase = requiredString(record, 'passphrase')
  const bytes = Buffer.byteLength(passphrase, 'utf8')
  if (bytes < 1 || bytes > MAX_SSH_KEY_IMPORT_PASSPHRASE_BYTES) {
    throw new VaultError('INVALID_INPUT')
  }
  return { token: parseSshKeyImportToken(record.token), passphrase }
}

function parseSshKeyImportCancel(value: unknown): SshKeyImportCancelRequest {
  const record = exactRecord(value, ['token'])
  return { token: parseSshKeyImportToken(record.token) }
}

function parseSshKeyCreateImported(value: unknown): SshKeyCreateImportedRequest {
  const request = parseLoginCreate(value, ['importToken'])
  const token = parseSshKeyImportToken((value as RecordValue).importToken)
  return { ...request, importToken: token }
}

function parseSshKeyUpdateImported(value: unknown): SshKeyUpdateImportedRequest {
  const request = parseLoginUpdate(value, ['importToken'])
  const token = parseSshKeyImportToken((value as RecordValue).importToken)
  return { ...request, importToken: token }
}

function parseLoginUris(value: unknown): VaultLoginUri[] {
  if (!Array.isArray(value) || value.length > MAX_LOGIN_URIS) {
    throw new VaultError('INVALID_INPUT')
  }
  return value.map((entry) => {
    const record = exactRecord(entry, ['uri', 'match'])
    if (
      typeof record.uri !== 'string' ||
      record.uri.length > MAX_URI_LENGTH ||
      (record.match !== null &&
        record.match !== 0 &&
        record.match !== 1 &&
        record.match !== 2 &&
        record.match !== 3 &&
        record.match !== 4 &&
        record.match !== 5)
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    return { uri: record.uri, match: record.match }
  })
}

function parseItemField(value: unknown): ItemFieldRequest {
  const record = exactRecord(value, ['id', 'field', 'uriIndex', 'authorizationToken'])
  const field = record.field
  if (
    field !== 'password' &&
    field !== 'number' &&
    field !== 'code' &&
    field !== 'ssn' &&
    field !== 'passportNumber' &&
    field !== 'licenseNumber' &&
    field !== 'privateKey' &&
    field !== 'username' &&
    field !== 'identityUsername' &&
    field !== 'uri' &&
    field !== 'email' &&
    field !== 'phone' &&
    field !== 'publicKey' &&
    field !== 'fingerprint' &&
    field !== 'cardholderName' &&
    field !== 'brand' &&
    field !== 'cardExpiration'
  )
    throw new VaultError('INVALID_INPUT')
  const authorizationToken = optionalAuthorizationToken(record)
  const uriIndex = optionalUriIndex(record.uriIndex)
  if (uriIndex !== undefined && field !== 'uri') throw new VaultError('INVALID_INPUT')
  return {
    id: requiredString(record, 'id'),
    field,
    ...(authorizationToken ? { authorizationToken } : {}),
    ...(uriIndex === undefined ? {} : { uriIndex })
  }
}

function optionalUriIndex(value: unknown): number | undefined {
  if (value === undefined) return undefined
  if (
    !Number.isSafeInteger(value) ||
    typeof value !== 'number' ||
    value < 0 ||
    value >= MAX_LOGIN_URIS
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return value
}

function parseOpenUri(value: unknown): LoginOpenUriRequest {
  const record = exactRecord(value, ['id', 'uriIndex', 'authorizationToken'])
  const authorizationToken = optionalAuthorizationToken(record)
  const uriIndex = optionalUriIndex(record.uriIndex)
  return {
    id: requiredString(record, 'id'),
    ...(authorizationToken ? { authorizationToken } : {}),
    ...(uriIndex === undefined ? {} : { uriIndex })
  }
}

function parseEditorSecretsRequest(value: unknown): EditorSecretsRequest {
  const record = exactRecord(value, ['id', 'expectedUpdatedAt', 'authorizationToken'])
  const authorizationToken = optionalAuthorizationToken(record)
  return {
    id: requiredString(record, 'id'),
    expectedUpdatedAt: requiredString(record, 'expectedUpdatedAt'),
    ...(authorizationToken ? { authorizationToken } : {})
  }
}

function parseCustomFieldRequest(value: unknown): CustomFieldRequest {
  const record = exactRecord(value, ['id', 'expectedUpdatedAt', 'source', 'authorizationToken'])
  const authorizationToken = optionalAuthorizationToken(record)
  return {
    id: requiredString(record, 'id'),
    expectedUpdatedAt: requiredString(record, 'expectedUpdatedAt'),
    source: parseCustomFieldSource(record.source),
    ...(authorizationToken ? { authorizationToken } : {})
  }
}

function parseLoginFavorite(value: unknown): LoginFavoriteRequest {
  const record = exactRecord(value, ['id', 'favorite', 'authorizationToken'])
  if (typeof record.favorite !== 'boolean') throw new VaultError('INVALID_INPUT')
  const authorizationToken = optionalAuthorizationToken(record)
  return {
    id: requiredString(record, 'id'),
    favorite: record.favorite,
    ...(authorizationToken ? { authorizationToken } : {})
  }
}

function parseLoginMove(value: unknown): LoginMoveRequest {
  const record = exactRecord(value, ['id', 'folderId', 'authorizationToken'])
  const folderId = optionalStringOrNull(record, 'folderId')
  if (folderId === undefined) throw new VaultError('INVALID_INPUT')
  const authorizationToken = optionalAuthorizationToken(record)
  return {
    id: requiredString(record, 'id'),
    folderId,
    ...(authorizationToken ? { authorizationToken } : {})
  }
}

function parseLoginBatch(value: unknown): LoginBatchRequest {
  const record = exactRecord(value, ['ids', 'authorizationToken'])
  if (!Array.isArray(record.ids)) throw new VaultError('INVALID_INPUT')
  const ids = record.ids
  if (
    ids.length === 0 ||
    ids.length > MAX_LOGIN_BATCH_IDS ||
    ids.some((id) => typeof id !== 'string' || !UUID_PATTERN.test(id)) ||
    new Set(ids).size !== ids.length
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  const authorizationToken = optionalAuthorizationToken(record)
  return {
    ids: [...ids] as string[],
    ...(authorizationToken ? { authorizationToken } : {})
  }
}

function parseLoginPrefetch(value: unknown): LoginPrefetchRequest {
  const record = exactRecord(value, ['ids'])
  if (!Array.isArray(record.ids)) throw new VaultError('INVALID_INPUT')
  const ids = record.ids
  if (
    ids.length === 0 ||
    ids.length > MAX_LOGIN_PREFETCH_IDS ||
    ids.some((id) => typeof id !== 'string' || !UUID_PATTERN.test(id)) ||
    new Set(ids).size !== ids.length
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return { ids: [...ids] as string[] }
}

function parseLoginMoveMany(value: unknown): LoginMoveManyRequest {
  const record = exactRecord(value, [
    'ids',
    'folderId',
    'authorizationToken',
    'authorizationTokens'
  ])
  const folderId = optionalStringOrNull(record, 'folderId')
  if (folderId === undefined || !Array.isArray(record.ids)) {
    throw new VaultError('INVALID_INPUT')
  }
  const ids = record.ids
  if (
    ids.length === 0 ||
    ids.length > MAX_LOGIN_MOVE_MANY_IDS ||
    ids.some((id) => typeof id !== 'string' || !UUID_PATTERN.test(id)) ||
    new Set(ids).size !== ids.length
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  if (folderId !== null && !UUID_PATTERN.test(folderId)) throw new VaultError('INVALID_INPUT')
  const parsedTokens = authorizationTokens(record.authorizationTokens)
  const authorizationToken = optionalAuthorizationToken(record)
  return {
    ids: [...ids] as string[],
    folderId,
    ...(authorizationToken ? { authorizationToken } : {}),
    ...(parsedTokens ? { authorizationTokens: parsedTokens } : {})
  }
}

function parseEmptyTrash(value: unknown): LoginEmptyTrashRequest {
  const record = exactRecord(value ?? {}, ['authorizationToken', 'authorizationTokens'])
  const parsedTokens = authorizationTokens(record.authorizationTokens)
  const authorizationToken = optionalAuthorizationToken(record)
  return {
    ...(authorizationToken ? { authorizationToken } : {}),
    ...(parsedTokens ? { authorizationTokens: parsedTokens } : {})
  }
}

function parseLoginList(value: unknown): LoginListRequest {
  const record = exactRecord(value ?? {}, ['sort', 'query', 'folderId', 'deleted', 'archived'])
  if (
    record.sort !== undefined &&
    record.sort !== 'recent' &&
    record.sort !== 'name' &&
    record.sort !== 'frequency'
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  if (
    record.query !== undefined &&
    (typeof record.query !== 'string' || record.query.length > MAX_LOGIN_SEARCH_QUERY_LENGTH)
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  const result: LoginListRequest = {}
  const folderId = optionalStringOrNull(record, 'folderId')
  const deleted = optionalBoolean(record, 'deleted')
  const archived = optionalBoolean(record, 'archived')
  if (record.sort !== undefined) result.sort = record.sort
  if (record.query !== undefined) result.query = record.query
  if (folderId !== undefined) result.folderId = folderId
  if (deleted !== undefined) result.deleted = deleted
  if (archived !== undefined) result.archived = archived
  return result
}

function parseSharedLoginList(value: unknown): SharedLoginListRequest {
  if (value === undefined || value === null) return {}
  if (typeof value !== 'object' || Array.isArray(value)) throw new VaultError('INVALID_INPUT')
  const candidate = value as RecordValue
  const result: SharedLoginListRequest = {}
  if (candidate.organizationId !== undefined) {
    if (
      typeof candidate.organizationId !== 'string' ||
      !UUID_PATTERN.test(candidate.organizationId)
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    result.organizationId = candidate.organizationId
  }
  if (candidate.collectionId !== undefined) {
    if (typeof candidate.collectionId !== 'string' || !UUID_PATTERN.test(candidate.collectionId)) {
      throw new VaultError('INVALID_INPUT')
    }
    result.collectionId = candidate.collectionId
  }
  if (candidate.query !== undefined) {
    if (
      typeof candidate.query !== 'string' ||
      candidate.query.length > MAX_LOGIN_SEARCH_QUERY_LENGTH
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    result.query = candidate.query
  }
  if (candidate.sort !== undefined) {
    if (
      candidate.sort !== 'recent' &&
      candidate.sort !== 'name' &&
      candidate.sort !== 'frequency'
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    result.sort = candidate.sort
  }
  return result
}

/** Vault health intentionally accepts only an explicit empty object: no renderer-supplied scope
 * or authorization material may influence which decrypted records are analyzed. */
function parseVaultHealthEmptyRequest(value: unknown): RecordValue {
  return exactRecord(value, [])
}

function parseInactiveTwoFactorEmptyRequest(value: unknown): void {
  if (!isRecord(value) || Reflect.ownKeys(value).length !== 0) {
    throw new VaultError('INVALID_INPUT')
  }
}

function parseInactiveTwoFactorDocumentation(
  value: unknown
): InactiveTwoFactorDocumentationRequest {
  if (!isRecord(value)) throw new VaultError('INVALID_INPUT')
  const keys = Reflect.ownKeys(value)
  if (keys.length !== 1 || keys[0] !== 'matchedDomain' || !Object.hasOwn(value, 'matchedDomain')) {
    throw new VaultError('INVALID_INPUT')
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, 'matchedDomain')
  if (!descriptor || !('value' in descriptor) || typeof descriptor.value !== 'string') {
    throw new VaultError('INVALID_INPUT')
  }
  const matchedDomain = descriptor.value
  const labels = matchedDomain.split('.')
  if (
    matchedDomain.length === 0 ||
    matchedDomain.length > 253 ||
    matchedDomain !== matchedDomain.toLowerCase() ||
    labels.length < 2 ||
    labels.some(
      (label) =>
        label.length === 0 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label)
    )
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return { matchedDomain }
}

function mapTwoFactorDirectoryError(error: unknown): never {
  if (error instanceof TwoFactorDirectoryCacheError) {
    if (error.code === 'DOCUMENTATION_NOT_FOUND') throw new VaultError('NOT_FOUND')
    throw new VaultError('HEALTH_CHECK_FAILED')
  }
  throw error
}

function parseVaultHealthAccountBreachRequest(value: unknown): VaultHealthAccountBreachRequest {
  const record = exactRecord(value, ['email'])
  const email = requiredString(record, 'email').trim()
  if (email.length === 0 || email.length > MAX_ACCOUNT_BREACH_EMAIL_LENGTH) {
    throw new VaultError('INVALID_INPUT')
  }
  return { email }
}

function parseEquivalentDomainSettingsUpdate(value: unknown): EquivalentDomainSettingsUpdate {
  const record = exactRecord(value, [
    'equivalentDomains',
    'excludedGlobalEquivalentDomains',
    'expectedRevision'
  ])
  if (
    !Array.isArray(record.equivalentDomains) ||
    record.equivalentDomains.length > MAX_EQUIVALENT_DOMAIN_GROUPS ||
    !Array.isArray(record.excludedGlobalEquivalentDomains) ||
    record.excludedGlobalEquivalentDomains.length > MAX_EQUIVALENT_DOMAIN_GROUPS ||
    typeof record.expectedRevision !== 'string' ||
    !/^[0-9a-f]{64}$/u.test(record.expectedRevision)
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  let total = 0
  const equivalentDomains = record.equivalentDomains.map((candidate) => {
    if (!Array.isArray(candidate) || candidate.length > MAX_EQUIVALENT_DOMAINS_PER_GROUP) {
      throw new VaultError('INVALID_INPUT')
    }
    total += candidate.length
    if (total > MAX_EQUIVALENT_DOMAIN_TOTAL) throw new VaultError('INVALID_INPUT')
    return candidate.map((domain) => {
      if (typeof domain !== 'string' || domain.length > MAX_EQUIVALENT_DOMAIN_LENGTH) {
        throw new VaultError('INVALID_INPUT')
      }
      return domain
    })
  })
  const excludedGlobalEquivalentDomains = record.excludedGlobalEquivalentDomains.map((type) => {
    if (typeof type !== 'number' || !Number.isInteger(type) || type < 0 || type > 2_147_483_647) {
      throw new VaultError('INVALID_INPUT')
    }
    return type
  })
  return {
    equivalentDomains,
    excludedGlobalEquivalentDomains,
    expectedRevision: record.expectedRevision
  }
}

function parseSendId(value: unknown): SendIdRequest {
  const record = exactRecord(value, ['id'])
  if (typeof record.id !== 'string' || !UUID_PATTERN.test(record.id)) {
    throw new VaultError('INVALID_INPUT')
  }
  return { id: record.id }
}

function parseSendCreate(value: unknown): SendCreateRequest {
  const record = exactRecord(value, [
    'name',
    'notes',
    'text',
    'hidden',
    'maxAccessCount',
    'expirationDate',
    'deletionDate',
    'password',
    'disabled',
    'hideEmail'
  ])
  const result: SendCreateRequest = {
    name: requiredString(record, 'name'),
    text: requiredString(record, 'text')
  }
  const notes = optionalStringOrNull(record, 'notes')
  const expirationDate = optionalStringOrNull(record, 'expirationDate')
  const deletionDate = optionalStringOrNull(record, 'deletionDate')
  const password = optionalStringOrNull(record, 'password')
  if (notes !== undefined) result.notes = notes
  if (expirationDate !== undefined) result.expirationDate = expirationDate
  if (deletionDate !== undefined) result.deletionDate = deletionDate
  if (password !== undefined) result.password = password
  for (const key of ['hidden', 'disabled', 'hideEmail'] as const) {
    if (record[key] !== undefined) {
      if (typeof record[key] !== 'boolean') throw new VaultError('INVALID_INPUT')
      result[key] = record[key]
    }
  }
  if (record.maxAccessCount !== undefined) {
    if (
      record.maxAccessCount !== null &&
      (typeof record.maxAccessCount !== 'number' ||
        !Number.isSafeInteger(record.maxAccessCount) ||
        record.maxAccessCount < 1)
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    result.maxAccessCount = record.maxAccessCount as number | null
  }
  return result
}

function parseSendFileCreate(value: unknown): SendFileCreateRequest {
  const record = exactRecord(value, [
    'operationId',
    'name',
    'notes',
    'maxAccessCount',
    'expirationDate',
    'deletionDate',
    'password',
    'disabled',
    'hideEmail'
  ])
  if (typeof record.operationId !== 'string' || !UUID_PATTERN.test(record.operationId)) {
    throw new VaultError('INVALID_INPUT')
  }
  const result: SendFileCreateRequest = {
    operationId: record.operationId,
    name: requiredString(record, 'name')
  }
  const notes = optionalStringOrNull(record, 'notes')
  const expirationDate = optionalStringOrNull(record, 'expirationDate')
  const deletionDate = optionalStringOrNull(record, 'deletionDate')
  const password = optionalStringOrNull(record, 'password')
  if (notes !== undefined) result.notes = notes
  if (expirationDate !== undefined) result.expirationDate = expirationDate
  if (deletionDate !== undefined) result.deletionDate = deletionDate
  if (password !== undefined) result.password = password
  for (const key of ['disabled', 'hideEmail'] as const) {
    if (record[key] !== undefined) {
      if (typeof record[key] !== 'boolean') throw new VaultError('INVALID_INPUT')
      result[key] = record[key]
    }
  }
  if (record.maxAccessCount !== undefined) {
    if (
      record.maxAccessCount !== null &&
      (typeof record.maxAccessCount !== 'number' ||
        !Number.isSafeInteger(record.maxAccessCount) ||
        record.maxAccessCount < 1)
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    result.maxAccessCount = record.maxAccessCount as number | null
  }
  return result
}

function parseSendFileDownload(value: unknown): SendFileDownloadRequest {
  const record = exactRecord(value, ['id', 'password'])
  if (typeof record.id !== 'string' || !UUID_PATTERN.test(record.id)) {
    throw new VaultError('INVALID_INPUT')
  }
  const password = optionalStringOrNull(record, 'password')
  return { id: record.id, ...(password === undefined ? {} : { password }) }
}

function parseSendUpdate(value: unknown): SendUpdateRequest {
  const record = exactRecord(value, [
    'id',
    'name',
    'notes',
    'text',
    'hidden',
    'maxAccessCount',
    'expirationDate',
    'deletionDate',
    'password',
    'disabled',
    'hideEmail'
  ])
  if (typeof record.id !== 'string' || !UUID_PATTERN.test(record.id)) {
    throw new VaultError('INVALID_INPUT')
  }
  const { id, ...draft } = record
  return { ...parseSendCreate(draft), id }
}

function optionalTwoFactorMethod(
  record: RecordValue,
  key: string
): SyncTwoFactorMethod | undefined {
  const value = record[key]
  if (value === undefined) return undefined
  if (value === '0' || value === '1' || value === '3') return value
  throw new VaultError('INVALID_INPUT')
}

function parseSyncConnect(value: unknown): SyncConnectRequest {
  const record = exactRecord(value, [
    'serverUrl',
    'email',
    'masterPassword',
    'twoFactorMethod',
    'twoFactorCode',
    'webAuthnRemember',
    'newDeviceOtp'
  ])
  const result: SyncConnectRequest = {
    serverUrl: requiredString(record, 'serverUrl'),
    email: requiredString(record, 'email'),
    masterPassword: requiredString(record, 'masterPassword')
  }
  const twoFactorCode = optionalStringOrNull(record, 'twoFactorCode')
  const newDeviceOtp = optionalStringOrNull(record, 'newDeviceOtp')
  const twoFactorMethod = optionalTwoFactorMethod(record, 'twoFactorMethod')
  const webAuthnRemember = optionalBoolean(record, 'webAuthnRemember')
  if (twoFactorCode) result.twoFactorCode = twoFactorCode
  if (twoFactorMethod) result.twoFactorMethod = twoFactorMethod
  if (webAuthnRemember !== undefined) result.webAuthnRemember = webAuthnRemember
  if (newDeviceOtp) result.newDeviceOtp = newDeviceOtp
  return result
}

function parseSyncUnlock(value: unknown): SyncUnlockRequest {
  const record = exactRecord(value, [
    'masterPassword',
    'twoFactorMethod',
    'twoFactorCode',
    'webAuthnRemember',
    'newDeviceOtp'
  ])
  const result: SyncUnlockRequest = {
    masterPassword: requiredString(record, 'masterPassword')
  }
  const twoFactorCode = optionalStringOrNull(record, 'twoFactorCode')
  const twoFactorMethod = optionalTwoFactorMethod(record, 'twoFactorMethod')
  const newDeviceOtp = optionalStringOrNull(record, 'newDeviceOtp')
  const webAuthnRemember = optionalBoolean(record, 'webAuthnRemember')
  if (twoFactorCode) result.twoFactorCode = twoFactorCode
  if (twoFactorMethod) result.twoFactorMethod = twoFactorMethod
  if (webAuthnRemember !== undefined) result.webAuthnRemember = webAuthnRemember
  if (newDeviceOtp) result.newDeviceOtp = newDeviceOtp
  return result
}

function parseSyncResolvePendingImport(value: unknown): SyncResolvePendingImportRequest {
  const record = exactRecord(value, ['masterPassword', 'confirmRetry'])
  const masterPassword = requiredString(record, 'masterPassword')
  if (
    masterPassword.length === 0 ||
    masterPassword.length > MAX_SYNC_RESOLUTION_MASTER_PASSWORD_LENGTH
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  if (record.confirmRetry !== true) throw new VaultError('INVALID_INPUT')
  return { masterPassword, confirmRetry: true }
}

function parseSyncPurgePersonalVault(value: unknown): SyncPurgePersonalVaultRequest {
  if (!isRecord(value)) throw new VaultError('INVALID_INPUT')
  const keys = Reflect.ownKeys(value)
  const allowedKeys = ['masterPassword', 'confirmation', 'confirmPurge']
  if (
    keys.length !== allowedKeys.length ||
    keys.some((key) => typeof key !== 'string' || !allowedKeys.includes(key))
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  if (
    allowedKeys.some((key) => {
      const descriptor = descriptors[key]
      return !descriptor || !('value' in descriptor)
    })
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  const masterPassword = descriptors.masterPassword!.value
  const confirmation = descriptors.confirmation!.value
  const confirmPurge = descriptors.confirmPurge!.value
  if (
    typeof masterPassword !== 'string' ||
    masterPassword.length < 1 ||
    masterPassword.length > MAX_SYNC_RESOLUTION_MASTER_PASSWORD_LENGTH ||
    confirmation !== 'PURGE' ||
    confirmPurge !== true
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return { masterPassword, confirmation, confirmPurge: true }
}

export function isTrustedVaultSender(
  event: IpcMainInvokeEvent,
  mainWindow: BrowserWindow | null
): boolean {
  if (!mainWindow || mainWindow.isDestroyed()) return false
  const webContents = mainWindow.webContents
  const senderFrame = event.senderFrame
  return (
    event.sender === webContents &&
    senderFrame !== null &&
    senderFrame === webContents.mainFrame &&
    senderFrame.url === webContents.getURL()
  )
}

function publicError(code: VaultErrorCode): Error {
  return new Error(`${IPC_ERROR_PREFIX}${code}`)
}

function registerTrustedHandler<T>(
  channel: string,
  getMainWindow: () => BrowserWindow | null,
  handler: (event: IpcMainInvokeEvent, input: unknown) => Promise<T>
): void {
  ipcMain.handle(channel, async (event, input) => {
    if (!isTrustedVaultSender(event, getMainWindow())) {
      throw publicError('INVALID_INPUT')
    }

    try {
      return await handler(event, input)
    } catch (error) {
      if (isVaultError(error)) {
        // Stage-tagged failures carry a static diagnostic label in their message (never paths,
        // secrets, or vault content). Surface it in the main-process log so intermittent faults
        // like CORRUPT_VAULT can be traced to their exact throw site.
        if (error.message !== error.code) console.error(`[vault-ipc] ${channel}: ${error.message}`)
        throw publicError(error.code)
      }
      throw publicError('INTERNAL_ERROR')
    }
  })
}

export function registerVaultIpc(options: VaultIpcOptions): () => void {
  const { vault, portability, settings, getMainWindow } = options
  const accountSwitchService = options.accountSwitchService
  let disposed = false
  let settingsActivityCheck: Promise<void> | null = null
  const registeredChannels = new Set<string>()
  const registerHandler = <T>(
    channel: string,
    windowProvider: () => BrowserWindow | null,
    handler: (event: IpcMainInvokeEvent, input: unknown) => Promise<T>
  ): void => {
    registerTrustedHandler(channel, windowProvider, handler)
    registeredChannels.add(channel)
  }
  const sshKeyImportSessions = options.sshKeyImportSessions
  const authorizations =
    options.repromptAuthorizations ??
    new RepromptAuthorizationStore(options.repromptNow, options.repromptRandomBytes)
  const runAccountOperation = async <T>(
    operation: (service: AccountSwitchService) => Promise<T>
  ): Promise<T> => {
    if (!accountSwitchService) throw new VaultError('ACCOUNT_SWITCH_UNAVAILABLE')
    try {
      return await operation(accountSwitchService)
    } catch (error) {
      throw accountSwitchVaultError(error) ?? error
    }
  }
  const runAuthorizationBoundary = <T>(
    event: IpcMainInvokeEvent,
    token: string | undefined,
    legacyTokens: Readonly<Record<string, string | undefined>>,
    operation: (authorize: (ids: readonly string[]) => void) => Promise<T>
  ): Promise<T> =>
    vault.runAuthorizedOperation((ids, state) => {
      const resolvedToken = token ?? legacyTokens[ids[0]!]
      if (!token && ids.some((id) => legacyTokens[id] !== resolvedToken)) return false
      return authorizations.validateMany(resolvedToken, event.sender.id, ids, state.generation)
    }, operation)
  const runAuthorized = <T>(
    event: IpcMainInvokeEvent,
    request: LoginIdRequest,
    operation: () => Promise<T>
  ): Promise<T> =>
    runAuthorizationBoundary(event, request.authorizationToken, {}, async (authorize) => {
      authorize([request.id])
      return operation()
    })
  const attachmentAuthorization =
    (event: IpcMainInvokeEvent, request: LoginIdRequest) =>
    (ids: readonly string[], state: { generation: number }): boolean =>
      authorizations.validateMany(
        request.authorizationToken,
        event.sender.id,
        ids,
        state.generation
      )
  const notifyMutation = (): void => {
    try {
      options.afterMutation?.()
    } catch {
      // A background sync scheduling failure must not invalidate a persisted local change.
    }
  }
  const afterMutation = async <T>(operation: Promise<T>): Promise<T> => {
    const result = await operation
    notifyMutation()
    return result
  }
  const reconnectStatus = async (
    state: MasterPasswordChangeStatus['state']
  ): Promise<MasterPasswordChangeStatus> => {
    if (disposed) return { state, requiresReconnect: true }
    try {
      const syncStatus = await vault.syncStatus()
      options.afterSyncChanged?.(syncStatus)
    } catch {
      // The transaction result remains authoritative if an auxiliary lifecycle notification fails.
    }
    return { state, requiresReconnect: true }
  }
  const completedMasterPasswordChange = async (): Promise<MasterPasswordChangeStatus> => {
    authorizations.clear()
    await settings.disableTouchId()
    if (disposed) return { state: 'completed', requiresReconnect: true }
    try {
      const syncStatus = await vault.syncStatus()
      options.afterMasterPasswordChanged?.(syncStatus)
    } catch {
      // Touch ID is already invalidated and the completed transaction must remain definitive.
    }
    return { state: 'completed', requiresReconnect: true }
  }
  const failedMasterPasswordChange = async (
    error: unknown
  ): Promise<MasterPasswordChangeStatus> => {
    const vaultStatus = await vault.status()
    if (vaultStatus.state === 'locked') {
      authorizations.clear()
      await settings.disableTouchId()
      return { state: 'needs-remote-verification', requiresReconnect: true }
    }
    const transactionStatus = await vault.masterPasswordChangeStatus()
    if (transactionStatus.phase === 'prepared') {
      authorizations.clear()
      await settings.disableTouchId()
      return { state: 'needs-remote-verification', requiresReconnect: true }
    }
    if (
      transactionStatus.phase === 'remote-confirmed' ||
      transactionStatus.phase === 'local-rekeyed'
    ) {
      authorizations.clear()
      await settings.disableTouchId()
      return { state: 'resume-required', requiresReconnect: true }
    }
    throw error
  }
  registerHandler(IPC_CHANNELS.accountStatus, getMainWindow, async (_event, input) => {
    parseNoInput(input)
    return publicAccountStatus(await runAccountOperation((service) => service.getStatus()))
  })
  registerHandler(IPC_CHANNELS.accountAdd, getMainWindow, async (_event, input) => {
    parseNoInput(input)
    return publicAccountMutation(await runAccountOperation((service) => service.addAccount()))
  })
  registerHandler(IPC_CHANNELS.accountSwitch, getMainWindow, async (_event, input) => {
    const accountId = parseAccountSwitch(input)
    return publicAccountMutation(
      await runAccountOperation((service) => service.switchAccount(accountId))
    )
  })
  registerHandler(IPC_CHANNELS.accountReorder, getMainWindow, async (_event, input) => {
    const request = parseAccountReorder(input)
    return publicAccountMutation(
      await runAccountOperation((service) =>
        service.reorderAccounts(request.accountIds, request.expectedRevision)
      )
    )
  })
  registerHandler(IPC_CHANNELS.accountRemove, getMainWindow, async (_event, input) => {
    const request = parseAccountRemove(input)
    return publicAccountMutation(
      await runAccountOperation((service) => service.removeAccount(request.accountId, true))
    )
  })
  registerHandler(IPC_CHANNELS.vaultStatus, getMainWindow, () => vault.status())
  registerHandler(IPC_CHANNELS.vaultSetup, getMainWindow, async (_event, input) => {
    const request = parseSetup(input)
    authorizations.clear()
    const status = await vault.setup(request.masterPassword)
    await Promise.resolve(options.afterSetup?.()).catch(() => undefined)
    return status
  })
  registerHandler(IPC_CHANNELS.vaultUnlock, getMainWindow, (_event, input) => {
    const request = parseUnlock(input)
    authorizations.clear()
    return vault.unlock(request.masterPassword).then(async (status) => {
      await Promise.resolve(options.afterUnlock?.(request.masterPassword)).catch(() => undefined)
      return status
    })
  })
  registerHandler(IPC_CHANNELS.vaultPinStatus, getMainWindow, async (_event, input) => {
    parseNoInput(input)
    return vault.pinUnlockStatus()
  })
  registerHandler(IPC_CHANNELS.vaultPinEnable, getMainWindow, async (_event, input) => {
    const request = parsePinEnable(input)
    try {
      return await vault.enablePinUnlock(request)
    } finally {
      request.pin = ''
      request.masterPassword = ''
    }
  })
  registerHandler(IPC_CHANNELS.vaultPinDisable, getMainWindow, async (_event, input) => {
    parseNoInput(input)
    return vault.disablePinUnlock()
  })
  registerHandler(IPC_CHANNELS.vaultPinUnlock, getMainWindow, async (_event, input) => {
    const request = parsePinUnlock(input)
    authorizations.clear()
    try {
      const status = await vault.unlockWithPin(request)
      await Promise.resolve(options.afterPinUnlock?.()).catch(() => undefined)
      return status
    } finally {
      request.pin = ''
    }
  })
  registerHandler(
    IPC_CHANNELS.vaultMasterPasswordChangeStatus,
    getMainWindow,
    async (_event, input) => {
      parseNoInput(input)
      const status = await vault.masterPasswordChangeStatus()
      if (status.phase !== null) {
        authorizations.clear()
        await settings.disableTouchId()
      }
      return publicMasterPasswordChangeStatus(status)
    }
  )
  registerHandler(IPC_CHANNELS.vaultMasterPasswordChange, getMainWindow, async (_event, input) => {
    let request: MasterPasswordChangeRequest | null = null
    try {
      request = parseMasterPasswordChange(input, true)
      await Promise.resolve(options.beforeSyncReconfigure?.())
      try {
        await vault.changeMasterPassword(request)
      } catch (error) {
        return await failedMasterPasswordChange(error)
      }
      return await completedMasterPasswordChange()
    } finally {
      if (request) {
        request.currentPassword = ''
        request.newPassword = ''
        request.hint = null
      }
      scrubMasterPasswordChangeInput(input)
    }
  })
  registerHandler(
    IPC_CHANNELS.vaultMasterPasswordChangeResolve,
    getMainWindow,
    async (_event, input) => {
      let request: MasterPasswordChangeResolutionRequest | null = null
      try {
        request = parseMasterPasswordChange(input, false)
        await Promise.resolve(options.beforeSyncReconfigure?.())
        let result: Awaited<ReturnType<VaultService['resolveMasterPasswordChange']>>
        try {
          result = await vault.resolveMasterPasswordChange(request)
        } catch (error) {
          return await failedMasterPasswordChange(error)
        }
        if (result.status === 'resolved') return await completedMasterPasswordChange()
        if (result.status === 'remote-not-changed') {
          return await reconnectStatus('remote-not-changed')
        }
        if (result.status === 'needs-reconnect') return await reconnectStatus('needs-reconnect')
        return await reconnectStatus('indeterminate')
      } finally {
        if (request) {
          request.currentPassword = ''
          request.newPassword = ''
        }
        scrubMasterPasswordChangeInput(input)
      }
    }
  )
  registerHandler(IPC_CHANNELS.vaultLock, getMainWindow, async () => {
    try {
      await Promise.resolve(options.beforeLock?.())
      authorizations.clear()
      const status = await vault.lock()
      options.afterLock?.()
      return status
    } finally {
      // Timer cleanup is defensive bookkeeping; it must not replace the lock outcome.
      try {
        options.afterLockAttempt?.()
      } catch {
        // A failed cleanup callback cannot safely change a successful lock into an IPC error.
      }
    }
  })
  registerHandler(IPC_CHANNELS.vaultExport, getMainWindow, async (_event, input) => {
    const request = parseVaultExport(input)
    try {
      return await portability.exportVault(request)
    } finally {
      request.masterPassword = ''
      if ('password' in request && typeof request.password === 'string') request.password = ''
    }
  })
  registerHandler(IPC_CHANNELS.vaultImport, getMainWindow, async (_event, input) => {
    let request: VaultImportRequest | undefined
    try {
      request = parseVaultImport(input)
      const result = await portability.importVault(request)
      if (!result.canceled && result.importedFolders + result.importedItems > 0) notifyMutation()
      return result
    } finally {
      scrubVaultImportSecrets(request)
      scrubVaultImportSecrets(input)
    }
  })
  registerHandler(IPC_CHANNELS.nativeRestorePreview, getMainWindow, async (event, input) => {
    const request = parseNativeRestorePreview(input)
    try {
      return await portability.previewNativeRestore(event.sender.id, request.password)
    } finally {
      request.password = ''
    }
  })
  registerHandler(IPC_CHANNELS.nativeRestoreStart, getMainWindow, async (event, input) => {
    const request = parseNativeRestoreStart(input)
    try {
      const result = await portability.runNativeRestore(
        event.sender.id,
        request.sessionId,
        request.masterPassword,
        (summary, state) => {
          try {
            if (!event.sender.isDestroyed()) {
              event.sender.send(IPC_EVENTS.nativeRestoreProgress, {
                sessionId: request.sessionId,
                state,
                ...summary
              })
            }
          } catch {
            // Progress is advisory; renderer teardown must not invalidate persisted restore work.
          }
        }
      )
      if (result.state === 'complete') notifyMutation()
      return result
    } finally {
      request.masterPassword = ''
    }
  })
  registerHandler(IPC_CHANNELS.nativeRestoreCancel, getMainWindow, async (event, input) => {
    const request = parseNativeRestoreSession(input)
    await portability.cancelNativeRestore(event.sender.id, request.sessionId)
  })
  registerHandler(IPC_CHANNELS.nativeRestoreClearCompleted, getMainWindow, async (event, input) => {
    const request = parseNativeRestoreSession(input)
    await portability.clearCompletedNativeRestore(event.sender.id, request.sessionId)
  })
  registerHandler(IPC_CHANNELS.folderList, getMainWindow, () => vault.listFolders())
  registerHandler(IPC_CHANNELS.organizationList, getMainWindow, () => vault.listOrganizations())
  registerHandler(IPC_CHANNELS.collectionList, getMainWindow, (_event, input) => {
    if (input === undefined || input === null) return vault.listCollections()
    if (typeof input !== 'string' || !UUID_PATTERN.test(input))
      throw new VaultError('INVALID_INPUT')
    return vault.listCollections(input)
  })
  registerHandler(IPC_CHANNELS.sharedLoginList, getMainWindow, (_event, input) =>
    vault.listSharedLogins(parseSharedLoginList(input))
  )
  registerHandler(IPC_CHANNELS.sharedLoginGet, getMainWindow, (_event, input) => {
    if (!isRecord(input) || typeof input.id !== 'string' || !UUID_PATTERN.test(input.id)) {
      throw new VaultError('INVALID_INPUT')
    }
    return vault.getSharedLogin({ id: input.id })
  })
  registerHandler(IPC_CHANNELS.emergencyAccessList, getMainWindow, () =>
    vault.listEmergencyAccess()
  )
  registerHandler(IPC_CHANNELS.folderCreate, getMainWindow, (_event, input) =>
    afterMutation(vault.createFolder(parseFolderCreate(input)))
  )
  registerHandler(IPC_CHANNELS.folderUpdate, getMainWindow, (_event, input) =>
    afterMutation(vault.updateFolder(parseFolderUpdate(input)))
  )
  registerHandler(IPC_CHANNELS.folderDelete, getMainWindow, (event, input) => {
    const request = parseFolderDelete(input)
    return runAuthorizationBoundary(
      event,
      request.authorizationToken,
      request.authorizationTokens ?? {},
      async (authorize) => {
        const contained = (
          await Promise.all([
            vault.listLogins({ folderId: request.id }),
            vault.listLogins({ folderId: request.id, archived: true }),
            vault.listLogins({ folderId: request.id, deleted: true })
          ])
        ).flat()
        authorize(contained.map((item) => item.id))
        return afterMutation(vault.deleteFolder(request))
      }
    )
  })
  registerHandler(IPC_CHANNELS.folderReorder, getMainWindow, (_event, input) =>
    afterMutation(vault.reorderFolders(parseFolderReorder(input)))
  )
  registerHandler(IPC_CHANNELS.loginList, getMainWindow, (_event, input) =>
    vault.listLogins(parseLoginList(input))
  )
  registerHandler<VaultHealthReport>(
    IPC_CHANNELS.vaultHealthReport,
    getMainWindow,
    (_event, input) => {
      parseVaultHealthEmptyRequest(input)
      return vault.getHealthReport()
    }
  )
  registerHandler<VaultHealthExposedReport>(
    IPC_CHANNELS.vaultHealthExposedPasswords,
    getMainWindow,
    (_event, input) => {
      parseVaultHealthEmptyRequest(input)
      return vault.getExposedPasswordReport()
    }
  )
  registerHandler<boolean>(
    IPC_CHANNELS.vaultHealthCancelExposedPasswords,
    getMainWindow,
    async (_event, input) => {
      parseVaultHealthEmptyRequest(input)
      return vault.cancelExposedPasswordReport()
    }
  )
  registerHandler<VaultHealthAccountBreachReport>(
    IPC_CHANNELS.vaultHealthAccountBreaches,
    getMainWindow,
    (_event, input) => vault.getAccountBreachReport(parseVaultHealthAccountBreachRequest(input))
  )
  registerHandler<boolean>(
    IPC_CHANNELS.vaultHealthCancelAccountBreaches,
    getMainWindow,
    async (_event, input) => {
      parseVaultHealthEmptyRequest(input)
      return vault.cancelAccountBreachReport()
    }
  )
  registerHandler<void>(IPC_CHANNELS.vaultHealthOpenHibp, getMainWindow, async (_event, input) => {
    parseVaultHealthEmptyRequest(input)
    await vault.openHibpWebsite()
  })
  registerHandler<InactiveTwoFactorReport>(
    IPC_CHANNELS.vaultHealthInactiveTwoFactor,
    getMainWindow,
    async (_event, input) => {
      parseInactiveTwoFactorEmptyRequest(input)
      const directory = options.twoFactorDirectory
      if (!directory) throw new VaultError('HEALTH_CHECK_FAILED')
      try {
        const dataset = await directory.getDataset()
        return await vault.getInactiveTwoFactorReport(dataset)
      } catch (error) {
        mapTwoFactorDirectoryError(error)
      }
    }
  )
  registerHandler<void>(
    IPC_CHANNELS.vaultHealthOpenTwoFactorDocumentation,
    getMainWindow,
    async (_event, input) => {
      const request = parseInactiveTwoFactorDocumentation(input)
      const directory = options.twoFactorDirectory
      if (!directory) throw new VaultError('HEALTH_CHECK_FAILED')
      try {
        await directory.openDocumentation(request.matchedDomain)
      } catch (error) {
        mapTwoFactorDirectoryError(error)
      }
    }
  )
  registerHandler(IPC_CHANNELS.loginAuthorize, getMainWindow, async (event, input) => {
    const request = parseLoginAuthorize(input)
    const generation = await vault.authorizeLogin(request)
    return authorizations.issue(event.sender.id, request.id, generation)
  })
  registerHandler(IPC_CHANNELS.loginAuthorizeMany, getMainWindow, async (event, input) => {
    const request = parseLoginAuthorizeMany(input)
    const generation = await vault.authorizeLogins(request)
    return authorizations.issueMany(event.sender.id, request.ids, generation)
  })
  registerHandler(IPC_CHANNELS.loginGet, getMainWindow, (event, input) => {
    const request = parseId(input)
    return runAuthorized(event, request, () => vault.getLogin(request))
  })
  registerHandler(IPC_CHANNELS.loginPrefetch, getMainWindow, (_event, input) =>
    vault.prefetchLogins(parseLoginPrefetch(input))
  )
  registerHandler(IPC_CHANNELS.loginGetPasswordHistory, getMainWindow, (event, input) => {
    const request = parseId(input)
    return vault.getPasswordHistoryView(request, (ids, state) =>
      authorizations.validateMany(
        request.authorizationToken,
        event.sender.id,
        ids,
        state.generation
      )
    )
  })
  registerHandler(IPC_CHANNELS.loginRevealPasswordHistory, getMainWindow, (event, input) => {
    const request = parsePasswordHistoryEntry(input)
    return vault.revealPasswordHistory(request, (ids, state) =>
      authorizations.validateMany(
        request.authorizationToken,
        event.sender.id,
        ids,
        state.generation
      )
    )
  })
  registerHandler(IPC_CHANNELS.loginCopyPasswordHistory, getMainWindow, (event, input) => {
    const request = parsePasswordHistoryEntry(input)
    return vault.copyPasswordHistory(request, (ids, state) =>
      authorizations.validateMany(
        request.authorizationToken,
        event.sender.id,
        ids,
        state.generation
      )
    )
  })
  registerHandler(IPC_CHANNELS.loginRestorePasswordHistory, getMainWindow, (event, input) => {
    const request = parsePasswordHistoryRestore(input)
    return runAuthorized(event, request, () => afterMutation(vault.restorePasswordHistory(request)))
  })
  const attachmentProgress =
    (event: IpcMainInvokeEvent) =>
    (progress: AttachmentProgressEvent): void => {
      if (!event.sender.isDestroyed()) event.sender.send(IPC_EVENTS.attachmentProgress, progress)
    }
  registerHandler(IPC_CHANNELS.attachmentDownload, getMainWindow, (event, input) => {
    const request = parseAttachmentTarget(input)
    return vault.downloadAttachment(
      request,
      attachmentProgress(event),
      attachmentAuthorization(event, request)
    )
  })
  registerHandler(IPC_CHANNELS.attachmentUpload, getMainWindow, (event, input) => {
    const request = parseAttachmentUpload(input)
    return afterMutation(
      vault.uploadAttachment(
        request,
        attachmentProgress(event),
        attachmentAuthorization(event, request)
      )
    )
  })
  registerHandler(IPC_CHANNELS.attachmentDelete, getMainWindow, (event, input) => {
    const request = parseAttachmentTarget(input) as AttachmentDeleteRequest
    return afterMutation(
      vault.deleteAttachment(
        request,
        attachmentProgress(event),
        attachmentAuthorization(event, request)
      )
    )
  })
  registerHandler(IPC_CHANNELS.attachmentFixLegacy, getMainWindow, (event, input) => {
    const request = parseAttachmentTarget(input) as AttachmentFixLegacyRequest
    return afterMutation(
      vault.fixLegacyAttachment(
        request,
        attachmentProgress(event),
        attachmentAuthorization(event, request)
      )
    )
  })
  registerHandler(IPC_CHANNELS.attachmentCancel, getMainWindow, async (_event, input) =>
    vault.cancelAttachmentOperation(parseAttachmentCancel(input))
  )
  registerHandler(IPC_CHANNELS.loginCreate, getMainWindow, (_event, input) =>
    afterMutation(vault.createLogin(parseLoginCreate(input)))
  )
  for (const [channel, operation] of [
    [IPC_CHANNELS.loginClone, (request: LoginIdRequest) => vault.cloneLogin(request)],
    [IPC_CHANNELS.loginArchive, (request: LoginIdRequest) => vault.archiveLogin(request)],
    [IPC_CHANNELS.loginUnarchive, (request: LoginIdRequest) => vault.unarchiveLogin(request)],
    [IPC_CHANNELS.loginDelete, (request: LoginIdRequest) => vault.deleteLogin(request)],
    [IPC_CHANNELS.loginRestore, (request: LoginIdRequest) => vault.restoreLogin(request)],
    [
      IPC_CHANNELS.loginDeletePermanently,
      (request: LoginIdRequest) => vault.deleteLoginPermanently(request)
    ]
  ] as const) {
    registerHandler<unknown>(channel, getMainWindow, (event, input) => {
      const request = parseId(input)
      const invoke = operation as (request: LoginIdRequest) => Promise<unknown>
      return runAuthorized<unknown>(event, request, () => afterMutation<unknown>(invoke(request)))
    })
  }
  for (const [channel, operation] of [
    [IPC_CHANNELS.loginArchiveMany, (request: LoginBatchRequest) => vault.archiveLogins(request)],
    [
      IPC_CHANNELS.loginUnarchiveMany,
      (request: LoginBatchRequest) => vault.unarchiveLogins(request)
    ],
    [IPC_CHANNELS.loginDeleteMany, (request: LoginBatchRequest) => vault.deleteLogins(request)],
    [IPC_CHANNELS.loginRestoreMany, (request: LoginBatchRequest) => vault.restoreLogins(request)],
    [
      IPC_CHANNELS.loginDeletePermanentlyMany,
      (request: LoginBatchRequest) => vault.deleteLoginsPermanently(request)
    ]
  ] as const) {
    registerHandler<unknown>(channel, getMainWindow, (event, input) => {
      const request = parseLoginBatch(input)
      const invoke = operation as (request: LoginBatchRequest) => Promise<unknown>
      return runAuthorizationBoundary(event, request.authorizationToken, {}, async (authorize) => {
        authorize(request.ids)
        return afterMutation(invoke(request))
      })
    })
  }
  registerHandler(IPC_CHANNELS.loginUpdate, getMainWindow, (event, input) => {
    const request = parseLoginUpdate(input)
    return runAuthorized(event, request, () => afterMutation(vault.updateLogin(request)))
  })
  registerHandler(IPC_CHANNELS.passkeyDelete, getMainWindow, (event, input) => {
    const request = parsePasskeyDelete(input)
    return runAuthorized(event, request, () => afterMutation(vault.deletePasskey(request)))
  })
  registerHandler(IPC_CHANNELS.loginEmptyTrash, getMainWindow, (event, input) => {
    const request = parseEmptyTrash(input)
    return runAuthorizationBoundary(
      event,
      request.authorizationToken,
      request.authorizationTokens ?? {},
      async (authorize) => {
        const deleted = await vault.listLogins({ deleted: true })
        authorize(deleted.map((item) => item.id))
        return afterMutation(vault.emptyTrash())
      }
    )
  })
  registerHandler(IPC_CHANNELS.loginSetFavorite, getMainWindow, (event, input) => {
    const request = parseLoginFavorite(input)
    return runAuthorized(event, request, () => afterMutation(vault.setLoginFavorite(request)))
  })
  registerHandler(IPC_CHANNELS.loginMove, getMainWindow, (event, input) => {
    const request = parseLoginMove(input)
    return runAuthorized(event, request, () => afterMutation(vault.moveLogin(request)))
  })
  registerHandler(IPC_CHANNELS.loginMoveMany, getMainWindow, (event, input) => {
    const request = parseLoginMoveMany(input)
    return runAuthorizationBoundary(
      event,
      request.authorizationToken,
      request.authorizationTokens ?? {},
      async (authorize) => {
        authorize(request.ids)
        return afterMutation(vault.moveLogins(request))
      }
    )
  })
  for (const [channel, operation] of [
    [IPC_CHANNELS.loginRevealPassword, (request: LoginIdRequest) => vault.revealPassword(request)],
    [IPC_CHANNELS.loginCopyUsername, (request: LoginIdRequest) => vault.copyUsername(request)],
    [IPC_CHANNELS.loginCopyPassword, (request: LoginIdRequest) => vault.copyPassword(request)],
    [IPC_CHANNELS.loginGetTotp, (request: LoginIdRequest) => vault.getTotp(request)],
    [IPC_CHANNELS.loginCopyTotp, (request: LoginIdRequest) => vault.copyTotp(request)]
  ] as const) {
    registerHandler<unknown>(channel, getMainWindow, (event, input) => {
      const request = parseId(input)
      const invoke = operation as (request: LoginIdRequest) => Promise<unknown>
      return runAuthorized<unknown>(event, request, () => invoke(request))
    })
  }
  registerHandler(IPC_CHANNELS.loginOpenUri, getMainWindow, (event, input) => {
    const request = parseOpenUri(input)
    return runAuthorized(event, request, () => vault.openLoginUri(request))
  })
  registerHandler(IPC_CHANNELS.loginContextMenu, getMainWindow, async (event, input) => {
    const request = parseContextMenu(input)
    const window = getMainWindow()
    if (!window || window.isDestroyed()) throw new VaultError('INVALID_INPUT')
    const item = await runAuthorized(event, request, () => vault.getLogin(request))
    const itemId = item.id
    const itemName = item.reprompt === 1 ? '這個受保護項目' : item.name
    const hasUsername = item.reprompt === 1 ? item.type === 'login' : Boolean(item.username)
    const hasPassword = item.type === 'login'
    const uriLabels =
      item.reprompt === 0
        ? item.uris.map((entry, index) => entry.uri || `網站 ${index + 1}`)
        : item.uris.map(() => '')
    const folderId = item.folderId
    const archivedAt = item.archivedAt
    const folders = await vault.listFolders()
    const notifyChanged = (): void => window.webContents.send(IPC_EVENTS.vaultChanged)
    showItemContextMenu({
      window,
      item: {
        id: itemId,
        // Protected native menus retain only generic action structure. They never retain
        // credential values or URI strings; every callback re-enters the authorization boundary.
        hasUsername,
        hasPassword,
        uriLabels,
        folderId,
        archivedAt
      },
      folders,
      onError: () => {
        if (window.isDestroyed()) return
        void dialog.showMessageBox(window, {
          type: 'error',
          title: '操作失敗',
          message: '無法完成這個動作',
          detail: '請稍後再試；你的密碼庫資料沒有因這次失敗而被移除。'
        })
      },
      ...(request.x === undefined ? {} : { position: { x: request.x, y: request.y! } }),
      callbacks: {
        openInNewWindow: async (_id, uriIndex) => {
          await runAuthorized(event, request, () => vault.openLoginUri({ ...request, uriIndex }))
          notifyChanged()
        },
        copyUsername: async () => {
          await runAuthorized(event, request, () => vault.copyUsername(request))
          notifyChanged()
        },
        copyPassword: async () => {
          await runAuthorized(event, request, () => vault.copyPassword(request))
          notifyChanged()
        },
        copyWebsite: async (_id, uriIndex) => {
          await runAuthorized(event, request, () =>
            vault.copyField({ ...request, field: 'uri', uriIndex })
          )
          notifyChanged()
        },
        moveToFolder: async (_id, folderId) => {
          await runAuthorized(event, request, () => vault.moveLogin({ ...request, folderId }))
          notifyMutation()
          notifyChanged()
        },
        cloneItem: async () => {
          await runAuthorized(event, request, () => vault.cloneLogin(request))
          notifyMutation()
          notifyChanged()
        },
        toggleArchive: async (_id, archived) => {
          await runAuthorized(event, request, () =>
            archived ? vault.unarchiveLogin(request) : vault.archiveLogin(request)
          )
          notifyMutation()
          notifyChanged()
        },
        deleteItem: async () => {
          const confirmation = await dialog.showMessageBox(window, {
            type: 'warning',
            buttons: ['移至垃圾桶', '取消'],
            defaultId: 1,
            cancelId: 1,
            title: '刪除項目',
            message: `確定要刪除「${itemName}」嗎？`,
            detail: '你可以之後從垃圾桶還原這個項目。'
          })
          if (confirmation.response !== 0) return
          await runAuthorized(event, request, () => vault.deleteLogin(request))
          notifyMutation()
          notifyChanged()
        }
      }
    })
  })
  registerHandler(IPC_CHANNELS.loginWebsiteIcon, getMainWindow, async (event, input) => {
    const request = parseId(input)
    if (!settings.websiteIconsEnabled()) return null
    return vault.getWebsiteIcon(request, (ids, state) =>
      authorizations.validateMany(
        request.authorizationToken,
        event.sender.id,
        ids,
        state.generation
      )
    )
  })
  registerHandler(IPC_CHANNELS.itemRevealSecret, getMainWindow, (event, input) => {
    const request = parseItemField(input)
    return runAuthorized(event, request, () => vault.revealSecret(request))
  })
  registerHandler(IPC_CHANNELS.itemRevealEditorSecrets, getMainWindow, (event, input) => {
    const request = parseEditorSecretsRequest(input)
    return runAuthorized(event, request, () => vault.revealEditorSecrets(request))
  })
  registerHandler(IPC_CHANNELS.itemCopyField, getMainWindow, (event, input) => {
    const request = parseItemField(input)
    return runAuthorized(event, request, () => vault.copyField(request))
  })
  registerHandler(IPC_CHANNELS.itemRevealCustomField, getMainWindow, (event, input) => {
    const request = parseCustomFieldRequest(input)
    return runAuthorized(event, request, () => vault.revealCustomField(request))
  })
  registerHandler(IPC_CHANNELS.itemCopyCustomField, getMainWindow, (event, input) => {
    const request = parseCustomFieldRequest(input)
    return runAuthorized(event, request, () => vault.copyCustomField(request))
  })
  registerHandler(IPC_CHANNELS.generatorGenerate, getMainWindow, (_event, input) =>
    vault.generateCredential(parseGeneratorRequest(input))
  )
  registerHandler(IPC_CHANNELS.generatorGeneratedCopy, getMainWindow, (_event, input) =>
    vault.copyGeneratedCredential(parseGeneratedCredentialCopyRequest(input))
  )
  registerHandler(IPC_CHANNELS.generatorHistoryList, getMainWindow, (_event, input) => {
    parseNoInput(input)
    return vault.generatorHistory()
  })
  registerHandler(IPC_CHANNELS.generatorHistoryClear, getMainWindow, (_event, input) => {
    parseNoInput(input)
    return vault.clearGeneratorHistory()
  })
  registerHandler(IPC_CHANNELS.generatorHistoryCopy, getMainWindow, (_event, input) =>
    vault.copyGeneratorHistory(parseGeneratorHistoryLocator(input))
  )
  registerHandler(IPC_CHANNELS.sshKeyGenerate, getMainWindow, async (event, input) => {
    parseNoInput(input)
    const context = await importContext(event)
    const material = await vault.generateSshKey()
    const result = sshKeyImportSessions.stageGenerated(context, material)
    return recheckImportResult(context, result)
  })
  const importContext = async (
    event: IpcMainInvokeEvent
  ): Promise<{ senderId: number; vaultGeneration: number }> => ({
    senderId: event.sender.id,
    vaultGeneration: await vault.unlockedGeneration()
  })
  const recheckImportResult = async <T>(
    context: { senderId: number; vaultGeneration: number },
    result: T
  ): Promise<T> => {
    try {
      await vault.runUnlockedOperation(async (generation) => {
        if (generation !== context.vaultGeneration) throw new VaultError('LOCKED')
      })
      return result
    } catch (error) {
      const token =
        typeof result === 'object' && result !== null && 'token' in result
          ? (result as { token?: unknown }).token
          : undefined
      if (typeof token === 'string') sshKeyImportSessions.cancel(token, context)
      throw error
    }
  }
  registerHandler(IPC_CHANNELS.sshKeyBeginImport, getMainWindow, async (event, input) => {
    parseNoInput(input)
    const context = await importContext(event)
    const result = sshKeyImportSessions.begin(context)
    return recheckImportResult(context, result)
  })
  registerHandler(
    IPC_CHANNELS.sshKeySubmitImportPassphrase,
    getMainWindow,
    async (event, input) => {
      const request = parseSshKeyImportPassphrase(input)
      const context = await importContext(event)
      const result = sshKeyImportSessions.submitPassphrase(
        request.token,
        context,
        request.passphrase
      )
      return recheckImportResult(context, result)
    }
  )
  registerHandler(IPC_CHANNELS.sshKeyCancelImport, getMainWindow, async (event, input) => {
    const request = parseSshKeyImportCancel(input)
    const context = await importContext(event)
    sshKeyImportSessions.cancel(request.token, context)
  })
  registerHandler(IPC_CHANNELS.sshKeyCreateImported, getMainWindow, (event, input) => {
    const request = parseSshKeyCreateImported(input)
    return vault.runUnlockedOperation(async (generation) => {
      const consumed = sshKeyImportSessions.consumeReady(request.importToken, {
        senderId: event.sender.id,
        vaultGeneration: generation
      })
      if (consumed.status !== 'ready') throw new VaultError('INVALID_INPUT')
      const draft = { ...request }
      delete (draft as { importToken?: unknown }).importToken
      return afterMutation(
        vault.createLogin({
          ...draft,
          type: 'sshKey',
          privateKey: consumed.material.privateKey,
          publicKey: consumed.material.publicKey,
          fingerprint: consumed.material.fingerprint
        })
      )
    })
  })
  registerHandler(IPC_CHANNELS.sshKeyUpdateImported, getMainWindow, (event, input) => {
    const request = parseSshKeyUpdateImported(input)
    return runAuthorized(event, request, async () => {
      // An imported update can only replace material on an existing SSH item. Check before
      // consuming the one-time token so a mismatched item cannot burn the imported key.
      const existing = await vault.getLogin(request)
      if (existing.type !== 'sshKey') throw new VaultError('INVALID_INPUT')
      const generation = await vault.unlockedGeneration()
      const consumed = sshKeyImportSessions.consumeReady(request.importToken, {
        senderId: event.sender.id,
        vaultGeneration: generation
      })
      if (consumed.status !== 'ready') throw new VaultError('INVALID_INPUT')
      const draft = { ...request }
      delete (draft as { importToken?: unknown }).importToken
      return afterMutation(
        vault.updateLogin({
          ...draft,
          privateKey: consumed.material.privateKey,
          publicKey: consumed.material.publicKey,
          fingerprint: consumed.material.fingerprint
        })
      )
    })
  })
  registerHandler(IPC_CHANNELS.syncStatus, getMainWindow, () => vault.syncStatus())
  registerHandler(IPC_CHANNELS.syncConnect, getMainWindow, async (_event, input) => {
    await Promise.resolve(options.beforeSyncReconfigure?.())
    const result = await vault.connectSync(parseSyncConnect(input))
    options.afterSyncChanged?.(result)
    return result
  })
  registerHandler(IPC_CHANNELS.syncUnlock, getMainWindow, async (_event, input) => {
    const status = await vault.unlockSync(parseSyncUnlock(input))
    options.afterSyncChanged?.(status)
    return status
  })
  registerHandler(IPC_CHANNELS.syncNow, getMainWindow, async () => {
    try {
      const result = await vault.syncNow()
      options.afterSyncChanged?.(result)
      return result
    } catch (error) {
      try {
        options.afterSyncChanged?.(await vault.syncStatus())
      } catch {
        // Never replace the original sync error with an auxiliary status refresh failure.
      }
      throw error
    }
  })
  registerHandler(IPC_CHANNELS.syncResolvePendingImport, getMainWindow, async (_event, input) => {
    const request = parseSyncResolvePendingImport(input)
    try {
      const status = await vault.resolvePendingLoginImport(request)
      options.afterSyncChanged?.(status)
      return status
    } finally {
      request.masterPassword = ''
    }
  })
  registerHandler(IPC_CHANNELS.syncPurgePersonalVault, getMainWindow, async (_event, input) => {
    const request = parseSyncPurgePersonalVault(input)
    try {
      let result: Awaited<ReturnType<VaultService['purgePersonalVault']>>
      try {
        result = await vault.purgePersonalVault(request)
      } catch (error) {
        try {
          const status = await vault.syncStatus()
          options.afterSyncChanged?.(status)
        } catch {
          // Never replace the original purge/reconciliation error with refresh failure.
        }
        throw error
      }
      notifyMutation()
      try {
        const status = await vault.syncStatus()
        options.afterSyncChanged?.(status)
      } catch {
        // The purge result remains authoritative if an auxiliary lifecycle notification fails.
      }
      return result
    } finally {
      request.masterPassword = ''
      ;(request as { confirmation: string }).confirmation = ''
    }
  })
  registerHandler(IPC_CHANNELS.syncDisconnect, getMainWindow, async () => {
    await Promise.resolve(options.beforeSyncReconfigure?.())
    const status = await vault.disconnectSync()
    options.afterSyncChanged?.(status)
    return status
  })
  registerHandler(IPC_CHANNELS.accountSecurityProfile, getMainWindow, (_event, input) => {
    parseNoInput(input)
    return vault.getAccountSecurityProfile()
  })
  registerHandler(IPC_CHANNELS.accountSecurityUpdateName, getMainWindow, (_event, input) => {
    return vault.updateAccountProfileName(parseAccountProfileNameUpdate(input))
  })
  registerHandler(IPC_CHANNELS.accountSecurityUpdateAvatar, getMainWindow, (_event, input) => {
    return vault.updateAccountAvatarColor(parseAccountProfileAvatarUpdate(input))
  })
  registerHandler(IPC_CHANNELS.accountDevices, getMainWindow, (_event, input) => {
    parseNoInput(input)
    return vault.getAccountDevices()
  })
  registerHandler(IPC_CHANNELS.accountPendingLoginApprovals, getMainWindow, (_event, input) => {
    parseNoInput(input)
    return vault.getPendingLoginApprovals()
  })
  registerHandler(IPC_CHANNELS.accountRespondLoginApproval, getMainWindow, (_event, input) => {
    return vault.respondLoginApproval(parseLoginApprovalResponse(input))
  })
  registerHandler(IPC_CHANNELS.accountDeauthorizeSessions, getMainWindow, async (_event, input) => {
    let request: AccountSessionDeauthorizationRequest | null = null
    try {
      request = parseAccountSessionDeauthorization(input)
      await Promise.resolve(options.beforeSyncReconfigure?.())
      try {
        await vault.deauthorizeAllSessions(request)
      } catch (error) {
        try {
          options.afterSyncChanged?.(await vault.syncStatus())
        } catch {
          // Never replace the mutation result with an auxiliary status refresh failure.
        }
        throw error
      }
      try {
        options.afterSyncChanged?.(await vault.syncStatus())
      } catch {
        // The strict empty mutation response remains authoritative.
      }
    } finally {
      if (request) {
        request.masterPassword = ''
        ;(request as { confirmation: string }).confirmation = ''
      }
      scrubAccountSessionDeauthorization(input)
    }
  })
  registerHandler(IPC_CHANNELS.accountResendVerification, getMainWindow, (_event, input) => {
    parseNoInput(input)
    return vault.resendAccountVerificationEmail()
  })
  registerHandler(IPC_CHANNELS.accountCopyApiClientId, getMainWindow, (_event, input) => {
    parseNoInput(input)
    return vault.copyAccountApiClientId()
  })
  registerHandler(IPC_CHANNELS.accountCopyApiKey, getMainWindow, async (_event, input) => {
    const request = parseAccountApiKeyCopy(input)
    try {
      return await vault.copyPersonalApiKey(request)
    } finally {
      request.masterPassword = ''
    }
  })
  registerHandler(IPC_CHANNELS.accountTwoFactorStatus, getMainWindow, (_event, input) => {
    parseNoInput(input)
    return vault.getTwoFactorStatus()
  })
  registerHandler(
    IPC_CHANNELS.accountSecurityWebAuthnKeys,
    getMainWindow,
    async (_event, input) => {
      const request = parseAccountWebAuthnKeys(input)
      try {
        return publicAccountWebAuthnKeys(await vault.listAccountWebAuthnKeys(request))
      } finally {
        request.masterPassword = ''
      }
    }
  )
  registerHandler(
    IPC_CHANNELS.accountSecurityEnrollWebAuthnKey,
    getMainWindow,
    async (_event, input) => {
      const request = parseAccountWebAuthnKeyEnrollment(input)
      try {
        await vault.enrollAccountWebAuthnKey(request)
      } finally {
        request.masterPassword = ''
        request.name = ''
      }
    }
  )
  registerHandler(
    IPC_CHANNELS.accountSecurityRemoveWebAuthnKey,
    getMainWindow,
    async (_event, input) => {
      const request = parseAccountWebAuthnKeyRemoval(input)
      try {
        await vault.removeAccountWebAuthnKey(request)
      } finally {
        request.masterPassword = ''
      }
    }
  )
  registerHandler(
    IPC_CHANNELS.accountDisableTwoFactorProvider,
    getMainWindow,
    async (_event, input) => {
      const record = exactRecord(input, ['type', 'masterPassword', 'confirm'])
      const request: AccountTwoFactorDisableRequest = {
        type: record.type as 0 | 1 | 2 | 3 | 7,
        masterPassword: requiredString(record, 'masterPassword'),
        confirm: record.confirm as true
      }
      if (
        !([0, 1, 2, 3, 7] as const).includes(request.type) ||
        request.masterPassword.length === 0 ||
        request.masterPassword.length > 16_384 ||
        request.confirm !== true
      ) {
        request.masterPassword = ''
        throw new VaultError('INVALID_INPUT')
      }
      try {
        return await vault.disableTwoFactorProvider(request)
      } finally {
        request.masterPassword = ''
      }
    }
  )
  registerHandler(IPC_CHANNELS.accountCopyRecoveryCode, getMainWindow, async (_event, input) => {
    const record = exactRecord(input, ['masterPassword'])
    const request = { masterPassword: requiredString(record, 'masterPassword') }
    if (request.masterPassword.length === 0 || request.masterPassword.length > 16_384) {
      throw new VaultError('INVALID_INPUT')
    }
    try {
      return await vault.copyTwoFactorRecoveryCode(request)
    } finally {
      request.masterPassword = ''
    }
  })
  registerHandler(
    IPC_CHANNELS.accountBeginAuthenticatorSetup,
    getMainWindow,
    async (_event, input) => {
      const record = exactRecord(input, ['masterPassword'])
      const request = { masterPassword: requiredString(record, 'masterPassword') }
      if (request.masterPassword.length === 0 || request.masterPassword.length > 16_384) {
        throw new VaultError('INVALID_INPUT')
      }
      try {
        return await vault.beginAccountAuthenticatorSetup(request)
      } finally {
        request.masterPassword = ''
      }
    }
  )
  registerHandler(IPC_CHANNELS.accountCopyAuthenticatorKey, getMainWindow, (_event, input) => {
    const record = exactRecord(input, ['sessionId'])
    const sessionId = requiredString(record, 'sessionId')
    if (!UUID_PATTERN.test(sessionId)) throw new VaultError('INVALID_INPUT')
    return vault.copyAccountAuthenticatorKey({ sessionId })
  })
  registerHandler(
    IPC_CHANNELS.accountCompleteAuthenticatorSetup,
    getMainWindow,
    async (_event, input) => {
      const record = exactRecord(input, ['sessionId', 'token', 'masterPassword'])
      const request: AccountAuthenticatorCompleteRequest = {
        sessionId: requiredString(record, 'sessionId'),
        token: requiredString(record, 'token'),
        ...(record.masterPassword === undefined
          ? {}
          : { masterPassword: requiredString(record, 'masterPassword') })
      }
      if (
        !UUID_PATTERN.test(request.sessionId) ||
        !/^\d{6}$/.test(request.token) ||
        (request.masterPassword !== undefined &&
          (request.masterPassword.length === 0 || request.masterPassword.length > 16_384))
      ) {
        if (request.masterPassword !== undefined) request.masterPassword = ''
        request.token = ''
        throw new VaultError('INVALID_INPUT')
      }
      try {
        return await vault.completeAccountAuthenticatorSetup(request)
      } finally {
        request.token = ''
        if (request.masterPassword !== undefined) request.masterPassword = ''
      }
    }
  )
  registerHandler(
    IPC_CHANNELS.accountBeginEmailTwoFactorSetup,
    getMainWindow,
    async (_event, input) => {
      const record = exactRecord(input, ['masterPassword'])
      const request = { masterPassword: requiredString(record, 'masterPassword') }
      if (request.masterPassword.length === 0 || request.masterPassword.length > 16_384) {
        throw new VaultError('INVALID_INPUT')
      }
      try {
        return await vault.beginAccountEmailTwoFactorSetup(request)
      } finally {
        request.masterPassword = ''
      }
    }
  )
  registerHandler(
    IPC_CHANNELS.accountSendEmailTwoFactorSetup,
    getMainWindow,
    async (_event, input) => {
      const record = exactRecord(input, ['sessionId', 'email', 'masterPassword'])
      const request: AccountEmailTwoFactorSendRequest = {
        sessionId: requiredString(record, 'sessionId'),
        email: requiredString(record, 'email'),
        ...(record.masterPassword === undefined
          ? {}
          : { masterPassword: requiredString(record, 'masterPassword') })
      }
      if (
        !UUID_PATTERN.test(request.sessionId) ||
        request.email.length === 0 ||
        request.email.length > 256 ||
        request.email.trim() !== request.email ||
        !/^[^\s@]+@[^\s@]+$/u.test(request.email) ||
        (request.masterPassword !== undefined &&
          (request.masterPassword.length === 0 || request.masterPassword.length > 16_384))
      ) {
        request.email = ''
        if (request.masterPassword !== undefined) request.masterPassword = ''
        throw new VaultError('INVALID_INPUT')
      }
      try {
        return await vault.sendAccountEmailTwoFactorSetup(request)
      } finally {
        request.email = ''
        if (request.masterPassword !== undefined) request.masterPassword = ''
      }
    }
  )
  registerHandler(
    IPC_CHANNELS.accountCompleteEmailTwoFactorSetup,
    getMainWindow,
    async (_event, input) => {
      const record = exactRecord(input, ['sessionId', 'token', 'masterPassword'])
      const request: AccountEmailTwoFactorCompleteRequest = {
        sessionId: requiredString(record, 'sessionId'),
        token: requiredString(record, 'token'),
        ...(record.masterPassword === undefined
          ? {}
          : { masterPassword: requiredString(record, 'masterPassword') })
      }
      if (
        !UUID_PATTERN.test(request.sessionId) ||
        !/^\d{1,50}$/u.test(request.token) ||
        (request.masterPassword !== undefined &&
          (request.masterPassword.length === 0 || request.masterPassword.length > 16_384))
      ) {
        request.token = ''
        if (request.masterPassword !== undefined) request.masterPassword = ''
        throw new VaultError('INVALID_INPUT')
      }
      try {
        return await vault.completeAccountEmailTwoFactorSetup(request)
      } finally {
        request.token = ''
        if (request.masterPassword !== undefined) request.masterPassword = ''
      }
    }
  )
  registerHandler<EquivalentDomainSettingsView>(
    IPC_CHANNELS.domainRulesGet,
    getMainWindow,
    (_event, input) => {
      parseNoInput(input)
      return vault.getEquivalentDomainSettings()
    }
  )
  registerHandler<EquivalentDomainSettingsView>(
    IPC_CHANNELS.domainRulesUpdate,
    getMainWindow,
    (_event, input) =>
      vault.updateEquivalentDomainSettings(parseEquivalentDomainSettingsUpdate(input))
  )
  registerHandler(IPC_CHANNELS.sendList, getMainWindow, (_event, input) => {
    parseNoInput(input)
    return vault.listSends()
  })
  registerHandler(IPC_CHANNELS.sendCreate, getMainWindow, (_event, input) =>
    afterMutation(vault.createSend(parseSendCreate(input)))
  )
  registerHandler(IPC_CHANNELS.sendCreateFile, getMainWindow, (_event, input) =>
    afterMutation(vault.createFileSend(parseSendFileCreate(input)))
  )
  registerHandler(IPC_CHANNELS.sendDownloadFile, getMainWindow, (_event, input) =>
    vault.downloadFileSend(parseSendFileDownload(input))
  )
  registerHandler(IPC_CHANNELS.sendUpdate, getMainWindow, (_event, input) =>
    afterMutation(vault.updateSend(parseSendUpdate(input)))
  )
  registerHandler(IPC_CHANNELS.sendRemovePassword, getMainWindow, (_event, input) =>
    afterMutation(vault.removeSendPassword(parseSendId(input)))
  )
  registerHandler(IPC_CHANNELS.sendDelete, getMainWindow, (_event, input) =>
    afterMutation(vault.deleteSend(parseSendId(input)))
  )
  registerHandler(IPC_CHANNELS.sendCopyLink, getMainWindow, (_event, input) =>
    vault.copySendLink(parseSendId(input))
  )
  registerHandler(IPC_CHANNELS.settingsGet, getMainWindow, (_event, input) => {
    parseNoInput(input)
    return settings.get()
  })
  registerHandler(IPC_CHANNELS.settingsUpdate, getMainWindow, (_event, input) =>
    settings.update(parseSettingsUpdate(input))
  )
  registerHandler(IPC_CHANNELS.settingsEnableTouchId, getMainWindow, (_event, input) =>
    settings.enableTouchId(parseTouchIdEnable(input).masterPassword)
  )
  registerHandler(IPC_CHANNELS.settingsDisableTouchId, getMainWindow, (_event, input) => {
    parseNoInput(input)
    return settings.disableTouchId()
  })
  registerHandler(IPC_CHANNELS.settingsUnlockTouchId, getMainWindow, (_event, input) => {
    parseNoInput(input)
    return settings.unlockTouchId()
  })
  registerHandler(IPC_CHANNELS.settingsActivity, getMainWindow, async (_event, input) => {
    parseNoInput(input)
    if (disposed) return
    if (settingsActivityCheck) return settingsActivityCheck

    const check = (async () => {
      // VaultService.status is exclusive with lock/unlock, so renderer activity is accepted only
      // after the authoritative main-process state has been observed as unlocked.
      if (disposed) return
      const status = await vault.status()
      if (disposed || status.state !== 'unlocked') return
      settings.activity()
    })()
    const sharedCheck = check.finally(() => {
      if (settingsActivityCheck === sharedCheck) settingsActivityCheck = null
    })
    settingsActivityCheck = sharedCheck
    return sharedCheck
  })

  return () => {
    disposed = true
    settingsActivityCheck = null
    authorizations.clear()
    sshKeyImportSessions.clearAll()
    void portability.disposeNativeRestoreSession?.()
    registeredChannels.forEach((channel) => ipcMain.removeHandler(channel))
    registeredChannels.clear()
  }
}
