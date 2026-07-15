import { dialog, ipcMain, type BrowserWindow, type IpcMainInvokeEvent } from 'electron'
import {
  IPC_CHANNELS,
  IPC_ERROR_PREFIX,
  IPC_EVENTS,
  MAX_LOGIN_MOVE_MANY_IDS,
  type AppSettingsUpdate,
  type CustomFieldRequest,
  type EditorSecretsRequest,
  type FolderCreateRequest,
  type FolderDeleteRequest,
  type FolderReorderRequest,
  type FolderUpdateRequest,
  type LoginCreateRequest,
  type LoginContextMenuRequest,
  type LoginFavoriteRequest,
  type LoginIdRequest,
  type LoginListRequest,
  type LoginMoveRequest,
  type LoginMoveManyRequest,
  type LoginUpdateRequest,
  type ItemFieldRequest,
  type VaultCustomFieldSource,
  type VaultCustomFieldType,
  type VaultCustomFieldUpdate,
  type VaultItemFields,
  type VaultItemType,
  type SyncConnectRequest,
  type SyncStatus,
  type SyncTwoFactorMethod,
  type SyncUnlockRequest,
  type VaultErrorCode,
  type TouchIdEnableRequest,
  type VaultSetupRequest,
  type VaultUnlockRequest
} from '../shared/vault-contract'
import type { AppSettingsService } from './app-settings'
import { isVaultError, VaultError } from './vault-errors'
import type { VaultService } from './vault-service'
import { showItemContextMenu } from './item-context-menu'

type RecordValue = Record<string, unknown>

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const MAX_CUSTOM_FIELDS = 1_000
const MAX_CUSTOM_FIELD_STRING_LENGTH = 5_000

export interface VaultIpcOptions {
  vault: VaultService
  settings: AppSettingsService
  getMainWindow: () => BrowserWindow | null
  afterLock?: () => void
  afterUnlock?: (masterPassword: string) => void | Promise<void>
  afterMutation?: () => void
  afterSyncChanged?: (status: SyncStatus) => void
}

function parseSettingsUpdate(value: unknown): AppSettingsUpdate {
  const record = exactRecord(value, [
    'contentProtection',
    'showWebsiteIcons',
    'autoLockMinutes',
    'lockOnScreenLock',
    'lockOnSuspend',
    'clearClipboardSeconds',
    'defaultSort',
    'theme'
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
  if (record.autoLockMinutes !== undefined) {
    const value = record.autoLockMinutes
    if (value !== 0 && value !== 1 && value !== 5 && value !== 15 && value !== 30 && value !== 60) {
      throw new VaultError('INVALID_INPUT')
    }
    result.autoLockMinutes = value
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
    if (record.defaultSort !== 'recent' && record.defaultSort !== 'name') {
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
  return result
}

function parseTouchIdEnable(value: unknown): TouchIdEnableRequest {
  const record = exactRecord(value, ['masterPassword'])
  return { masterPassword: requiredString(record, 'masterPassword') }
}

function parseNoInput(value: unknown): void {
  if (value !== undefined) throw new VaultError('INVALID_INPUT')
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
  const record = exactRecord(value, ['id'])
  return { id: requiredString(record, 'id') }
}

function parseContextMenu(value: unknown): LoginContextMenuRequest {
  const record = exactRecord(value, ['id', 'x', 'y'])
  const result: LoginContextMenuRequest = { id: requiredString(record, 'id') }
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
  return parseId(value)
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

function parseLoginCreate(value: unknown): LoginCreateRequest {
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
    'customFields',
    ...fieldKeys
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
  if (customFields !== undefined) result.customFields = customFields
  return result
}

function parseLoginUpdate(value: unknown): LoginUpdateRequest {
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
    'customFields',
    ...fieldKeys
  ])
  const result: LoginUpdateRequest = { id: requiredString(record, 'id') }
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
  if (customFields !== undefined) result.customFields = customFields
  return result
}

function parseItemField(value: unknown): ItemFieldRequest {
  const record = exactRecord(value, ['id', 'field'])
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
    field !== 'fingerprint'
  )
    throw new VaultError('INVALID_INPUT')
  return { id: requiredString(record, 'id'), field }
}

function parseEditorSecretsRequest(value: unknown): EditorSecretsRequest {
  const record = exactRecord(value, ['id', 'expectedUpdatedAt'])
  return {
    id: requiredString(record, 'id'),
    expectedUpdatedAt: requiredString(record, 'expectedUpdatedAt')
  }
}

function parseCustomFieldRequest(value: unknown): CustomFieldRequest {
  const record = exactRecord(value, ['id', 'expectedUpdatedAt', 'source'])
  return {
    id: requiredString(record, 'id'),
    expectedUpdatedAt: requiredString(record, 'expectedUpdatedAt'),
    source: parseCustomFieldSource(record.source)
  }
}

function parseLoginFavorite(value: unknown): LoginFavoriteRequest {
  const record = exactRecord(value, ['id', 'favorite'])
  if (typeof record.favorite !== 'boolean') throw new VaultError('INVALID_INPUT')
  return { id: requiredString(record, 'id'), favorite: record.favorite }
}

function parseLoginMove(value: unknown): LoginMoveRequest {
  const record = exactRecord(value, ['id', 'folderId'])
  const folderId = optionalStringOrNull(record, 'folderId')
  if (folderId === undefined) throw new VaultError('INVALID_INPUT')
  return { id: requiredString(record, 'id'), folderId }
}

function parseLoginMoveMany(value: unknown): LoginMoveManyRequest {
  const record = exactRecord(value, ['ids', 'folderId'])
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
  return { ids: [...ids] as string[], folderId }
}

function parseLoginList(value: unknown): LoginListRequest {
  const record = exactRecord(value ?? {}, ['sort', 'folderId'])
  if (record.sort !== undefined && record.sort !== 'recent' && record.sort !== 'name') {
    throw new VaultError('INVALID_INPUT')
  }
  const result: LoginListRequest = {}
  const folderId = optionalStringOrNull(record, 'folderId')
  if (record.sort !== undefined) result.sort = record.sort
  if (folderId !== undefined) result.folderId = folderId
  return result
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
  if (twoFactorCode) result.twoFactorCode = twoFactorCode
  if (twoFactorMethod) result.twoFactorMethod = twoFactorMethod
  if (newDeviceOtp) result.newDeviceOtp = newDeviceOtp
  return result
}

function parseSyncUnlock(value: unknown): SyncUnlockRequest {
  const record = exactRecord(value, [
    'masterPassword',
    'twoFactorMethod',
    'twoFactorCode',
    'newDeviceOtp'
  ])
  const result: SyncUnlockRequest = {
    masterPassword: requiredString(record, 'masterPassword')
  }
  const twoFactorCode = optionalStringOrNull(record, 'twoFactorCode')
  const twoFactorMethod = optionalTwoFactorMethod(record, 'twoFactorMethod')
  const newDeviceOtp = optionalStringOrNull(record, 'newDeviceOtp')
  if (twoFactorCode) result.twoFactorCode = twoFactorCode
  if (twoFactorMethod) result.twoFactorMethod = twoFactorMethod
  if (newDeviceOtp) result.newDeviceOtp = newDeviceOtp
  return result
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

function registerHandler<T>(
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
      if (isVaultError(error)) throw publicError(error.code)
      throw publicError('INTERNAL_ERROR')
    }
  })
}

export function registerVaultIpc(options: VaultIpcOptions): () => void {
  const { vault, settings, getMainWindow } = options
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
  registerHandler(IPC_CHANNELS.vaultStatus, getMainWindow, () => vault.status())
  registerHandler(IPC_CHANNELS.vaultSetup, getMainWindow, (_event, input) => {
    const request = parseSetup(input)
    return vault.setup(request.masterPassword)
  })
  registerHandler(IPC_CHANNELS.vaultUnlock, getMainWindow, (_event, input) => {
    const request = parseUnlock(input)
    return vault.unlock(request.masterPassword).then(async (status) => {
      await Promise.resolve(options.afterUnlock?.(request.masterPassword)).catch(() => undefined)
      return status
    })
  })
  registerHandler(IPC_CHANNELS.vaultLock, getMainWindow, async () => {
    const status = await vault.lock()
    options.afterLock?.()
    return status
  })
  registerHandler(IPC_CHANNELS.folderList, getMainWindow, () => vault.listFolders())
  registerHandler(IPC_CHANNELS.folderCreate, getMainWindow, (_event, input) =>
    afterMutation(vault.createFolder(parseFolderCreate(input)))
  )
  registerHandler(IPC_CHANNELS.folderUpdate, getMainWindow, (_event, input) =>
    afterMutation(vault.updateFolder(parseFolderUpdate(input)))
  )
  registerHandler(IPC_CHANNELS.folderDelete, getMainWindow, (_event, input) =>
    afterMutation(vault.deleteFolder(parseFolderDelete(input)))
  )
  registerHandler(IPC_CHANNELS.folderReorder, getMainWindow, (_event, input) =>
    afterMutation(vault.reorderFolders(parseFolderReorder(input)))
  )
  registerHandler(IPC_CHANNELS.loginList, getMainWindow, (_event, input) =>
    vault.listLogins(parseLoginList(input))
  )
  registerHandler(IPC_CHANNELS.loginGet, getMainWindow, (_event, input) =>
    vault.getLogin(parseId(input))
  )
  registerHandler(IPC_CHANNELS.loginCreate, getMainWindow, (_event, input) =>
    afterMutation(vault.createLogin(parseLoginCreate(input)))
  )
  registerHandler(IPC_CHANNELS.loginUpdate, getMainWindow, (_event, input) =>
    afterMutation(vault.updateLogin(parseLoginUpdate(input)))
  )
  registerHandler(IPC_CHANNELS.loginDelete, getMainWindow, (_event, input) =>
    afterMutation(vault.deleteLogin(parseId(input)))
  )
  registerHandler(IPC_CHANNELS.loginSetFavorite, getMainWindow, (_event, input) =>
    afterMutation(vault.setLoginFavorite(parseLoginFavorite(input)))
  )
  registerHandler(IPC_CHANNELS.loginMove, getMainWindow, (_event, input) =>
    afterMutation(vault.moveLogin(parseLoginMove(input)))
  )
  registerHandler(IPC_CHANNELS.loginMoveMany, getMainWindow, (_event, input) =>
    afterMutation(vault.moveLogins(parseLoginMoveMany(input)))
  )
  registerHandler(IPC_CHANNELS.loginRevealPassword, getMainWindow, (_event, input) =>
    vault.revealPassword(parseId(input))
  )
  registerHandler(IPC_CHANNELS.loginCopyUsername, getMainWindow, (_event, input) =>
    vault.copyUsername(parseId(input))
  )
  registerHandler(IPC_CHANNELS.loginCopyPassword, getMainWindow, (_event, input) =>
    vault.copyPassword(parseId(input))
  )
  registerHandler(IPC_CHANNELS.loginOpenUri, getMainWindow, (_event, input) =>
    vault.openLoginUri(parseId(input))
  )
  registerHandler(IPC_CHANNELS.loginGetTotp, getMainWindow, (_event, input) =>
    vault.getTotp(parseId(input))
  )
  registerHandler(IPC_CHANNELS.loginCopyTotp, getMainWindow, (_event, input) =>
    vault.copyTotp(parseId(input))
  )
  registerHandler(IPC_CHANNELS.loginContextMenu, getMainWindow, async (_event, input) => {
    const request = parseContextMenu(input)
    const window = getMainWindow()
    if (!window || window.isDestroyed()) throw new VaultError('INVALID_INPUT')
    const [item, folders] = await Promise.all([vault.getLogin(request), vault.listFolders()])
    const notifyChanged = (): void => window.webContents.send(IPC_EVENTS.vaultChanged)
    showItemContextMenu({
      window,
      item,
      folders,
      onError: () => {
        if (window.isDestroyed()) return
        void dialog.showMessageBox(window, {
          type: 'error',
          title: '操作失敗',
          message: '無法完成這個動作',
          detail: '請稍後再試；你的保管庫資料沒有因這次失敗而被移除。'
        })
      },
      ...(request.x === undefined ? {} : { position: { x: request.x, y: request.y! } }),
      callbacks: {
        openInNewWindow: async () => {
          await vault.openLoginUri(request)
          notifyChanged()
        },
        copyUsername: async () => {
          await vault.copyUsername(request)
          notifyChanged()
        },
        copyWebsite: async () => {
          await vault.copyField({ id: request.id, field: 'uri' })
          notifyChanged()
        },
        moveToFolder: async (_id, folderId) => {
          await vault.moveLogin({ id: request.id, folderId })
          notifyMutation()
          notifyChanged()
        },
        deleteItem: async () => {
          const confirmation = await dialog.showMessageBox(window, {
            type: 'warning',
            buttons: ['刪除', '取消'],
            defaultId: 1,
            cancelId: 1,
            title: '刪除項目',
            message: `確定要刪除「${item.name}」嗎？`,
            detail: '此動作無法復原。'
          })
          if (confirmation.response !== 0) return
          await vault.deleteLogin(request)
          notifyMutation()
          notifyChanged()
        }
      }
    })
  })
  registerHandler(IPC_CHANNELS.loginWebsiteIcon, getMainWindow, async (_event, input) => {
    const request = parseId(input)
    if (!settings.websiteIconsEnabled()) return null
    return vault.getWebsiteIcon(request)
  })
  registerHandler(IPC_CHANNELS.itemRevealSecret, getMainWindow, (_event, input) =>
    vault.revealSecret(parseItemField(input))
  )
  registerHandler(IPC_CHANNELS.itemRevealEditorSecrets, getMainWindow, (_event, input) =>
    vault.revealEditorSecrets(parseEditorSecretsRequest(input))
  )
  registerHandler(IPC_CHANNELS.itemCopyField, getMainWindow, (_event, input) =>
    vault.copyField(parseItemField(input))
  )
  registerHandler(IPC_CHANNELS.itemRevealCustomField, getMainWindow, (_event, input) =>
    vault.revealCustomField(parseCustomFieldRequest(input))
  )
  registerHandler(IPC_CHANNELS.itemCopyCustomField, getMainWindow, (_event, input) =>
    vault.copyCustomField(parseCustomFieldRequest(input))
  )
  registerHandler(IPC_CHANNELS.syncStatus, getMainWindow, () => vault.syncStatus())
  registerHandler(IPC_CHANNELS.syncConnect, getMainWindow, async (_event, input) => {
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
    const result = await vault.syncNow()
    options.afterSyncChanged?.(result)
    return result
  })
  registerHandler(IPC_CHANNELS.syncDisconnect, getMainWindow, async () => {
    const status = await vault.disconnectSync()
    options.afterSyncChanged?.(status)
    return status
  })
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
    settings.activity()
  })

  return () => {
    Object.values(IPC_CHANNELS).forEach((channel) => ipcMain.removeHandler(channel))
  }
}
