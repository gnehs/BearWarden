import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { dialog, ipcMain, type BrowserWindow, type IpcMainInvokeEvent } from 'electron'
import {
  IPC_CHANNELS,
  IPC_ERROR_PREFIX,
  IPC_EVENTS,
  MAX_LOGIN_MOVE_MANY_IDS,
  MAX_LOGIN_AUTHORIZE_MANY_IDS,
  type AppSettingsUpdate,
  type CustomFieldRequest,
  type EditorSecretsRequest,
  type CredentialGeneratorRequest,
  type FolderCreateRequest,
  type FolderDeleteRequest,
  type FolderReorderRequest,
  type FolderUpdateRequest,
  type GeneratorHistoryLocator,
  type LoginCreateRequest,
  type LoginAuthorizeRequest,
  type LoginAuthorizeManyRequest,
  type LoginAuthorization,
  type LoginEmptyTrashRequest,
  type LoginContextMenuRequest,
  type LoginFavoriteRequest,
  type LoginIdRequest,
  type LoginListRequest,
  type LoginOpenUriRequest,
  type LoginMoveRequest,
  type LoginMoveManyRequest,
  type LoginUpdateRequest,
  type ItemFieldRequest,
  type VaultCustomFieldSource,
  type VaultCustomFieldType,
  type VaultCustomFieldUpdate,
  type VaultItemFields,
  type VaultLoginUri,
  type VaultItemType,
  type SyncConnectRequest,
  type SyncStatus,
  type SyncTwoFactorMethod,
  type SyncUnlockRequest,
  type VaultErrorCode,
  type VaultExportRequest,
  type VaultImportRequest,
  type TouchIdEnableRequest,
  type VaultSetupRequest,
  type VaultUnlockRequest
} from '../shared/vault-contract'
import type { AppSettingsService } from './app-settings'
import { isVaultError, VaultError } from './vault-errors'
import type { VaultService } from './vault-service'
import type { VaultPortabilityService } from './vault-portability'
import { showItemContextMenu } from './item-context-menu'

type RecordValue = Record<string, unknown>

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const MAX_CUSTOM_FIELDS = 1_000
const MAX_CUSTOM_FIELD_STRING_LENGTH = 5_000
const REPROMPT_TOKEN_TTL_MS = 60_000
const MAX_REPROMPT_TOKENS = 128
const MAX_LOGIN_URIS = 1_000
const MAX_URI_LENGTH = 4_096

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
  getMainWindow: () => BrowserWindow | null
  afterLock?: () => void
  afterUnlock?: (masterPassword: string) => void | Promise<void>
  afterMutation?: () => void
  afterSyncChanged?: (status: SyncStatus) => void
  repromptNow?: () => number
  repromptRandomBytes?: (size: number) => Buffer
}

function parseVaultExport(value: unknown): VaultExportRequest {
  const record = exactRecord(value, ['masterPassword', 'password'])
  return {
    masterPassword: requiredString(record, 'masterPassword'),
    password: requiredString(record, 'password')
  }
}

function parseVaultImport(value: unknown): VaultImportRequest {
  const record = exactRecord(value, ['masterPassword', 'password'])
  const masterPassword = requiredString(record, 'masterPassword')
  if (record.password !== undefined && typeof record.password !== 'string') {
    throw new VaultError('INVALID_INPUT')
  }
  return {
    masterPassword,
    ...(record.password === undefined ? {} : { password: record.password })
  }
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
    'reprompt',
    'customFields',
    'uris',
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
  if (record.reprompt !== undefined) {
    if (record.reprompt !== 0 && record.reprompt !== 1) throw new VaultError('INVALID_INPUT')
    result.reprompt = record.reprompt
  }
  if (customFields !== undefined) result.customFields = customFields
  if (record.uris !== undefined) result.uris = parseLoginUris(record.uris)
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
    'reprompt',
    'authorizationToken',
    'customFields',
    'uris',
    ...fieldKeys
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
    field !== 'fingerprint'
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
  const record = exactRecord(value ?? {}, ['sort', 'folderId', 'deleted', 'archived'])
  if (record.sort !== undefined && record.sort !== 'recent' && record.sort !== 'name') {
    throw new VaultError('INVALID_INPUT')
  }
  const result: LoginListRequest = {}
  const folderId = optionalStringOrNull(record, 'folderId')
  const deleted = optionalBoolean(record, 'deleted')
  const archived = optionalBoolean(record, 'archived')
  if (record.sort !== undefined) result.sort = record.sort
  if (folderId !== undefined) result.folderId = folderId
  if (deleted !== undefined) result.deleted = deleted
  if (archived !== undefined) result.archived = archived
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
  const { vault, portability, settings, getMainWindow } = options
  const authorizations = new RepromptAuthorizationStore(
    options.repromptNow,
    options.repromptRandomBytes
  )
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
    authorizations.clear()
    return vault.unlock(request.masterPassword).then(async (status) => {
      await Promise.resolve(options.afterUnlock?.(request.masterPassword)).catch(() => undefined)
      return status
    })
  })
  registerHandler(IPC_CHANNELS.vaultLock, getMainWindow, async () => {
    authorizations.clear()
    const status = await vault.lock()
    options.afterLock?.()
    return status
  })
  registerHandler(IPC_CHANNELS.vaultExport, getMainWindow, (_event, input) =>
    portability.exportVault(parseVaultExport(input))
  )
  registerHandler(IPC_CHANNELS.vaultImport, getMainWindow, async (_event, input) => {
    const result = await portability.importVault(parseVaultImport(input))
    if (!result.canceled && result.importedFolders + result.importedItems > 0) notifyMutation()
    return result
  })
  registerHandler(IPC_CHANNELS.folderList, getMainWindow, () => vault.listFolders())
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
  registerHandler(IPC_CHANNELS.loginGetPasswordHistory, getMainWindow, (event, input) => {
    const request = parseId(input)
    return runAuthorized(event, request, () => vault.getPasswordHistory(request))
  })
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
  registerHandler(IPC_CHANNELS.loginUpdate, getMainWindow, (event, input) => {
    const request = parseLoginUpdate(input)
    return runAuthorized(event, request, () => afterMutation(vault.updateLogin(request)))
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
        // Protected native menus retain only generic action structure. They never retain the
        // username or URI strings; every callback re-enters the atomic authorization boundary.
        hasUsername,
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
          detail: '請稍後再試；你的保管庫資料沒有因這次失敗而被移除。'
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
    return runAuthorized(event, request, () => vault.getWebsiteIcon(request))
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
    authorizations.clear()
    Object.values(IPC_CHANNELS).forEach((channel) => ipcMain.removeHandler(channel))
  }
}
