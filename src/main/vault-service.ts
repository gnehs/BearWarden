import { randomUUID } from 'node:crypto'
import type {
  FolderCreateRequest,
  FolderDeleteRequest,
  FolderReorderRequest,
  FolderUpdateRequest,
  CustomFieldRequest,
  ItemFieldRequest,
  FolderView,
  LoginCreateRequest,
  LoginFavoriteRequest,
  LoginIdRequest,
  LoginListRequest,
  LoginMoveRequest,
  LoginMoveManyRequest,
  LoginSummary,
  LoginUpdateRequest,
  LoginView,
  VaultCopyField,
  VaultCustomField,
  VaultCustomFieldSource,
  VaultCustomFieldUpdate,
  VaultCustomFieldView,
  VaultItemFields,
  VaultItemType,
  VaultSecretField,
  SyncConnectRequest,
  SyncResult,
  SyncStatus,
  SyncUnlockRequest,
  TotpCodeView,
  VaultStatus
} from '../shared/vault-contract'
import { MAX_LOGIN_MOVE_MANY_IDS, VAULT_LINKED_FIELD_IDS_BY_TYPE } from '../shared/vault-contract'
import {
  BitwardenDirectError,
  type BitwardenFolder,
  type BitwardenLoginDraft,
  type BitwardenLoginItem,
  type BitwardenDirectState,
  type BitwardenSyncClient,
  type BitwardenTwoFactor
} from './bitwarden-direct'
import { resolveBitwardenUrls } from './bitwarden-http'
import { EncryptedVaultStore } from './encrypted-vault-store'
import {
  completeSyncMetadata,
  legacyCustomFieldBaselineUpgrades,
  planSync,
  type SyncAction,
  type SyncActionResult,
  type SyncFolderReference,
  type SyncLogin,
  type SyncMetadata,
  type SyncSnapshot
} from './sync-merge'
import { VaultError } from './vault-errors'
import { type StoredPasskeyCredential, toPasskeyView } from './passkey'
import { generateTotp } from './totp'
import {
  fetchWebsiteIconDataUrl,
  parseWebsiteHostname,
  resolveWebsiteIconUrl
} from './website-icon'

const LEGACY_DATA_VERSION = 1
const CLI_DATA_VERSION = 2
const ITEM_TYPES_DATA_VERSION = 4
const PASSKEYS_DATA_VERSION = 5
const DATA_VERSION = 6
const MIN_MASTER_PASSWORD_LENGTH = 12
const MAX_MASTER_PASSWORD_LENGTH = 1024
const MAX_NAME_LENGTH = 256
const MAX_USERNAME_LENGTH = 512
const MAX_PASSWORD_LENGTH = 16_384
const MAX_URI_LENGTH = 4096
const MAX_NOTES_LENGTH = 65_536
const MAX_ITEM_FIELD_LENGTH = 4_096
const MAX_CUSTOM_FIELDS = 1_000
const MAX_CUSTOM_FIELD_NAME_LENGTH = 5_000
const MAX_CUSTOM_FIELD_VALUE_LENGTH = 5_000
const MAX_SSH_PRIVATE_KEY_LENGTH = 1024 * 1024
const MAX_SYNC_SECRET_LENGTH = 16_384
const MAX_TWO_FACTOR_CODE_LENGTH = 256
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

interface StoredLogin
  extends Omit<LoginView, 'subtitle' | 'hasTotp' | 'passkeys' | 'customFields'>, VaultItemFields {
  passkeys: StoredPasskeyCredential[]
  customFields: VaultCustomField[]
}

interface SyncEntityMapping {
  localId: string
  remoteId: string
  baseFingerprint: string
}

interface SyncTombstone {
  localId: string
  remoteId: string
  baseFingerprint: string
}

export interface PersistedSyncData {
  provider: 'bitwarden'
  serverUrl: string
  email: string
  state: BitwardenDirectState
  lastSyncAt: string | null
  folderMappings: SyncEntityMapping[]
  loginMappings: SyncEntityMapping[]
  folderTombstones: SyncTombstone[]
  loginTombstones: SyncTombstone[]
}

interface VaultData {
  version: typeof DATA_VERSION
  createdAt: string
  updatedAt: string
  folders: FolderView[]
  logins: StoredLogin[]
  sync: PersistedSyncData | null
}

export interface VaultPlatform {
  copyText: (text: string) => void | Promise<void>
  openExternal: (url: string) => void | Promise<void>
}

export interface VaultServiceOptions {
  now?: () => Date
  createId?: () => string
  createSyncClient?: (sync: PersistedSyncData) => BitwardenSyncClient
  fetch?: typeof fetch
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function assertIsoDate(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) {
    throw new VaultError('CORRUPT_VAULT')
  }
}

function assertUuid(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) {
    throw new VaultError('INVALID_INPUT')
  }
}

function parseFolder(value: unknown): FolderView {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  if (
    typeof value.id !== 'string' ||
    !UUID_PATTERN.test(value.id) ||
    typeof value.name !== 'string' ||
    value.name.length === 0 ||
    value.name.length > MAX_NAME_LENGTH ||
    typeof value.position !== 'number' ||
    !Number.isSafeInteger(value.position) ||
    value.position < 0
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  assertIsoDate(value.createdAt)
  assertIsoDate(value.updatedAt)

  return {
    id: value.id,
    name: value.name,
    position: value.position,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt
  }
}

function parseNullableString(value: unknown, maxLength: number): string | null {
  if (value === null) return null
  if (typeof value !== 'string' || value.length > maxLength) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return value
}

const ITEM_FIELD_NAMES = [
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

type ItemFieldName = (typeof ITEM_FIELD_NAMES)[number]

const ITEM_FIELDS_BY_TYPE: Record<VaultItemType, readonly ItemFieldName[]> = {
  login: ['username', 'password', 'totp', 'uri'],
  card: ['cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code'],
  identity: [
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
    'licenseNumber'
  ],
  secureNote: [],
  sshKey: ['privateKey', 'publicKey', 'fingerprint']
}

const SECRET_FIELDS_BY_TYPE: Record<VaultItemType, readonly VaultSecretField[]> = {
  login: ['password'],
  card: ['number', 'code'],
  identity: ['ssn', 'passportNumber', 'licenseNumber'],
  secureNote: [],
  sshKey: ['privateKey']
}

const COPY_FIELDS_BY_TYPE: Record<VaultItemType, readonly VaultCopyField[]> = {
  login: ['username', 'password', 'uri'],
  card: ['number', 'code'],
  identity: ['email', 'phone', 'ssn', 'identityUsername', 'passportNumber', 'licenseNumber'],
  secureNote: [],
  sshKey: ['privateKey', 'publicKey', 'fingerprint']
}

function emptyItemFields(): VaultItemFields {
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

function normalizeItemFieldsForStorage(input: VaultItemFields): VaultItemFields {
  const fields = emptyItemFields()
  for (const field of ITEM_FIELD_NAMES) {
    const value = input[field]
    if (field === 'uri') {
      fields.uri = normalizeNullableString(value, MAX_URI_LENGTH)
    } else {
      fields[field] = normalizeString(value, maxLengthForItemField(field))
    }
  }
  return fields
}

function maxLengthForItemField(field: ItemFieldName): number {
  if (field === 'password' || field === 'totp') return MAX_PASSWORD_LENGTH
  if (field === 'uri') return MAX_URI_LENGTH
  if (field === 'privateKey') return MAX_SSH_PRIVATE_KEY_LENGTH
  return MAX_ITEM_FIELD_LENGTH
}

function isVaultItemType(value: unknown): value is VaultItemType {
  return (
    value === 'login' ||
    value === 'card' ||
    value === 'identity' ||
    value === 'secureNote' ||
    value === 'sshKey'
  )
}

function parseStoredPasskey(value: unknown): StoredPasskeyCredential {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  const required = [
    'credentialId',
    'keyType',
    'keyAlgorithm',
    'keyCurve',
    'keyValue',
    'rpId',
    'counter',
    'creationDate'
  ] as const
  for (const field of required) {
    if (typeof value[field] !== 'string' || value[field].length > MAX_ITEM_FIELD_LENGTH) {
      throw new VaultError('CORRUPT_VAULT')
    }
  }
  assertIsoDate(value.creationDate)
  if (typeof value.discoverable !== 'boolean') throw new VaultError('CORRUPT_VAULT')
  const optional = (field: string): string | null => {
    const candidate = value[field]
    if (candidate === undefined || candidate === null) return null
    if (typeof candidate !== 'string' || candidate.length > MAX_ITEM_FIELD_LENGTH) {
      throw new VaultError('CORRUPT_VAULT')
    }
    return candidate
  }
  const requiredValue = (field: (typeof required)[number]): string => value[field] as string
  return {
    credentialId: requiredValue('credentialId'),
    keyType: requiredValue('keyType'),
    keyAlgorithm: requiredValue('keyAlgorithm'),
    keyCurve: requiredValue('keyCurve'),
    keyValue: requiredValue('keyValue'),
    rpId: requiredValue('rpId'),
    userHandle: optional('userHandle'),
    userName: optional('userName'),
    counter: requiredValue('counter'),
    rpName: optional('rpName'),
    userDisplayName: optional('userDisplayName'),
    discoverable: value.discoverable,
    creationDate: requiredValue('creationDate')
  }
}

function parseCustomField(value: unknown): VaultCustomField {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  if (
    typeof value.name !== 'string' ||
    value.name.length > MAX_CUSTOM_FIELD_NAME_LENGTH ||
    typeof value.value !== 'string' ||
    value.value.length > MAX_CUSTOM_FIELD_VALUE_LENGTH ||
    (value.type !== 'text' &&
      value.type !== 'hidden' &&
      value.type !== 'boolean' &&
      value.type !== 'linked') ||
    (value.linkedId !== null &&
      (!Number.isSafeInteger(value.linkedId) || (value.linkedId as number) < 0))
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return {
    name: value.name,
    value: value.value,
    type: value.type,
    linkedId: value.linkedId as number | null
  }
}

function cloneCustomFields(fields: readonly VaultCustomField[]): VaultCustomField[] {
  return fields.map((field) => ({ ...field }))
}

function parseStoredLogin(
  value: unknown,
  legacyItemType = false,
  allowMissingExtendedFields = false,
  allowMissingCustomFields = false
): StoredLogin {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  if (
    typeof value.id !== 'string' ||
    !UUID_PATTERN.test(value.id) ||
    typeof value.name !== 'string' ||
    value.name.length === 0 ||
    value.name.length > MAX_NAME_LENGTH ||
    typeof value.username !== 'string' ||
    value.username.length > MAX_USERNAME_LENGTH ||
    typeof value.password !== 'string' ||
    value.password.length > MAX_PASSWORD_LENGTH ||
    typeof value.favorite !== 'boolean'
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }

  const folderId = value.folderId
  const lastUsedAt = value.lastUsedAt
  let parsedFolderId: string | null
  if (folderId === null) {
    parsedFolderId = null
  } else if (typeof folderId === 'string' && UUID_PATTERN.test(folderId)) {
    parsedFolderId = folderId
  } else {
    throw new VaultError('CORRUPT_VAULT')
  }
  let parsedLastUsedAt: string | null
  if (lastUsedAt === null) {
    parsedLastUsedAt = null
  } else {
    assertIsoDate(lastUsedAt)
    parsedLastUsedAt = lastUsedAt
  }
  assertIsoDate(value.createdAt)
  assertIsoDate(value.updatedAt)

  const type = legacyItemType ? 'login' : value.type
  if (!isVaultItemType(type)) throw new VaultError('CORRUPT_VAULT')
  const fields = emptyItemFields()
  for (const field of ITEM_FIELD_NAMES) {
    if (allowMissingExtendedFields && !(field in value)) continue
    const raw = value[field]
    if (field === 'uri') {
      fields.uri = parseNullableString(raw, MAX_URI_LENGTH)
      continue
    }
    if (typeof raw !== 'string' || raw.length > maxLengthForItemField(field)) {
      throw new VaultError('CORRUPT_VAULT')
    }
    fields[field] = raw
  }

  return {
    id: value.id,
    type,
    name: value.name,
    notes: parseNullableString(value.notes, MAX_NOTES_LENGTH),
    folderId: parsedFolderId,
    favorite: value.favorite,
    lastUsedAt: parsedLastUsedAt,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
    passkeys:
      allowMissingExtendedFields || value.passkeys === undefined
        ? []
        : (() => {
            if (!Array.isArray(value.passkeys) || value.passkeys.length > 1000) {
              throw new VaultError('CORRUPT_VAULT')
            }
            return value.passkeys.map(parseStoredPasskey)
          })(),
    customFields:
      allowMissingCustomFields && value.customFields === undefined
        ? []
        : (() => {
            if (
              !Array.isArray(value.customFields) ||
              value.customFields.length > MAX_CUSTOM_FIELDS
            ) {
              throw new VaultError('CORRUPT_VAULT')
            }
            return value.customFields.map(parseCustomField)
          })(),
    ...fields
  }
}

function parseSyncMappings(
  value: unknown,
  localIds: Set<string>,
  label: 'mapping' | 'tombstone'
): SyncEntityMapping[] | SyncTombstone[] {
  if (!Array.isArray(value) || value.length > 100_000) throw new VaultError('CORRUPT_VAULT')
  const remoteIds = new Set<string>()
  const parsed = value.map((entry) => {
    if (!isRecord(entry)) throw new VaultError('CORRUPT_VAULT')
    const remoteId = entry.remoteId
    const baseFingerprint = entry.baseFingerprint
    if (
      typeof remoteId !== 'string' ||
      !UUID_PATTERN.test(remoteId) ||
      typeof baseFingerprint !== 'string' ||
      !/^[0-9a-f]{64}$/.test(baseFingerprint) ||
      remoteIds.has(remoteId)
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    remoteIds.add(remoteId)

    const localId = entry.localId
    if (
      typeof localId !== 'string' ||
      !UUID_PATTERN.test(localId) ||
      (label === 'mapping' && !localIds.has(localId))
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    return { localId, remoteId, baseFingerprint }
  })

  if (label === 'mapping') {
    const mappedLocalIds = new Set((parsed as SyncEntityMapping[]).map((entry) => entry.localId))
    if (mappedLocalIds.size !== parsed.length) throw new VaultError('CORRUPT_VAULT')
  }
  return parsed
}

function parseDirectState(value: unknown): BitwardenDirectState {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  const deviceIdentifier = value.deviceIdentifier
  const profileId = value.profileId
  const securityStamp = value.securityStamp
  if (
    typeof deviceIdentifier !== 'string' ||
    !UUID_PATTERN.test(deviceIdentifier) ||
    (profileId !== null && (typeof profileId !== 'string' || !UUID_PATTERN.test(profileId))) ||
    (securityStamp !== null &&
      (typeof securityStamp !== 'string' || securityStamp.length > MAX_SYNC_SECRET_LENGTH))
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }

  let session: BitwardenDirectState['session'] = null
  if (value.session !== null) {
    if (!isRecord(value.session)) throw new VaultError('CORRUPT_VAULT')
    const { accessToken, refreshToken, expiresAt } = value.session
    if (
      typeof accessToken !== 'string' ||
      accessToken.length === 0 ||
      accessToken.length > MAX_SYNC_SECRET_LENGTH ||
      typeof refreshToken !== 'string' ||
      refreshToken.length === 0 ||
      refreshToken.length > MAX_SYNC_SECRET_LENGTH ||
      typeof expiresAt !== 'number' ||
      !Number.isSafeInteger(expiresAt) ||
      expiresAt <= 0
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    session = { accessToken, refreshToken, expiresAt }
  }

  return { session, deviceIdentifier, profileId, securityStamp }
}

function parseSyncData(
  value: unknown,
  folderIds: Set<string>,
  loginIds: Set<string>,
  isCliData: boolean
): PersistedSyncData | null {
  if (value === null) return null
  if (!isRecord(value) || value.provider !== 'bitwarden') {
    throw new VaultError('CORRUPT_VAULT')
  }
  if (
    typeof value.serverUrl !== 'string' ||
    value.serverUrl.length > MAX_URI_LENGTH ||
    typeof value.email !== 'string' ||
    value.email.length === 0 ||
    value.email.length > MAX_USERNAME_LENGTH
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  try {
    resolveBitwardenUrls(value.serverUrl)
  } catch {
    throw new VaultError('CORRUPT_VAULT')
  }
  if (value.lastSyncAt !== null) assertIsoDate(value.lastSyncAt)

  const folderMappings = parseSyncMappings(
    value.folderMappings,
    folderIds,
    'mapping'
  ) as SyncEntityMapping[]
  const loginMappings = parseSyncMappings(
    value.loginMappings,
    loginIds,
    'mapping'
  ) as SyncEntityMapping[]
  const folderTombstones = parseSyncMappings(
    value.folderTombstones,
    folderIds,
    'tombstone'
  ) as SyncTombstone[]
  const loginTombstones = parseSyncMappings(
    value.loginTombstones,
    loginIds,
    'tombstone'
  ) as SyncTombstone[]
  const mappedFolderRemoteIds = new Set(folderMappings.map((entry) => entry.remoteId))
  const mappedLoginRemoteIds = new Set(loginMappings.map((entry) => entry.remoteId))
  if (
    folderTombstones.some((entry) => mappedFolderRemoteIds.has(entry.remoteId)) ||
    loginTombstones.some((entry) => mappedLoginRemoteIds.has(entry.remoteId))
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }

  return {
    provider: 'bitwarden',
    serverUrl: value.serverUrl,
    email: value.email,
    state: isCliData
      ? {
          session: null,
          deviceIdentifier: randomUUID(),
          profileId: null,
          securityStamp: null
        }
      : parseDirectState(value.state),
    lastSyncAt: value.lastSyncAt,
    folderMappings,
    loginMappings,
    folderTombstones,
    loginTombstones
  }
}

function parseVaultData(value: unknown): VaultData {
  if (
    !isRecord(value) ||
    typeof value.version !== 'number' ||
    ![
      LEGACY_DATA_VERSION,
      CLI_DATA_VERSION,
      3,
      ITEM_TYPES_DATA_VERSION,
      PASSKEYS_DATA_VERSION,
      DATA_VERSION
    ].includes(value.version) ||
    !Array.isArray(value.folders) ||
    !Array.isArray(value.logins)
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  const dataVersion = value.version
  assertIsoDate(value.createdAt)
  assertIsoDate(value.updatedAt)

  const folders = value.folders.map(parseFolder)
  const logins = value.logins.map((login) =>
    parseStoredLogin(
      login,
      dataVersion < ITEM_TYPES_DATA_VERSION,
      dataVersion < PASSKEYS_DATA_VERSION,
      dataVersion < DATA_VERSION
    )
  )
  const folderIds = new Set(folders.map((folder) => folder.id))
  const folderPositions = new Set(folders.map((folder) => folder.position))
  const loginIds = new Set(logins.map((login) => login.id))

  if (
    folderIds.size !== folders.length ||
    folderPositions.size !== folders.length ||
    folders.some((folder) => folder.position >= folders.length) ||
    loginIds.size !== logins.length
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  if (logins.some((login) => login.folderId !== null && !folderIds.has(login.folderId))) {
    throw new VaultError('CORRUPT_VAULT')
  }

  const sync =
    dataVersion === LEGACY_DATA_VERSION
      ? null
      : parseSyncData(value.sync, folderIds, loginIds, dataVersion === CLI_DATA_VERSION)

  return {
    version: DATA_VERSION,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
    folders,
    logins,
    sync
  }
}

function normalizeRequiredString(value: unknown, maxLength: number): string {
  if (typeof value !== 'string') throw new VaultError('INVALID_INPUT')
  const normalized = value.trim()
  if (normalized.length === 0 || normalized.length > maxLength) {
    throw new VaultError('INVALID_INPUT')
  }
  return normalized
}

function normalizeString(value: unknown, maxLength: number): string {
  if (typeof value !== 'string' || value.length > maxLength) {
    throw new VaultError('INVALID_INPUT')
  }
  return value
}

function normalizeSyncPassword(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_SYNC_SECRET_LENGTH) {
    throw new VaultError('INVALID_INPUT')
  }
  return value
}

function normalizeNullableString(value: unknown, maxLength: number): string | null {
  if (value === null || value === undefined || value === '') return null
  if (typeof value !== 'string' || value.length > maxLength) {
    throw new VaultError('INVALID_INPUT')
  }
  return value
}

function normalizeItemType(value: unknown): VaultItemType {
  if (!isVaultItemType(value)) throw new VaultError('INVALID_INPUT')
  return value
}

function applyItemFields(
  target: VaultItemFields,
  input: Partial<VaultItemFields>,
  type: VaultItemType
): void {
  const allowed = new Set(ITEM_FIELDS_BY_TYPE[type])
  for (const field of ITEM_FIELD_NAMES) {
    const value = input[field]
    if (value === undefined) continue
    if (!allowed.has(field)) {
      if (value === '' || value === null) continue
      throw new VaultError('INVALID_INPUT')
    }
    if (field === 'uri') {
      target.uri = normalizeNullableString(value, MAX_URI_LENGTH)
    } else {
      target[field] = normalizeString(value, maxLengthForItemField(field))
    }
  }
}

function normalizeCustomFields(
  existing: readonly VaultCustomField[],
  updates: unknown,
  itemType: VaultItemType
): VaultCustomField[] {
  if (!Array.isArray(updates) || updates.length > MAX_CUSTOM_FIELDS) {
    throw new VaultError('INVALID_INPUT')
  }

  const linkedIds = VAULT_LINKED_FIELD_IDS_BY_TYPE[itemType] as readonly number[]
  const sourceIndexes = new Set<number>()

  return updates.map((candidate): VaultCustomField => {
    if (!isRecord(candidate)) throw new VaultError('INVALID_INPUT')
    const update = candidate as unknown as VaultCustomFieldUpdate
    if (
      typeof update.name !== 'string' ||
      update.name.length > MAX_CUSTOM_FIELD_NAME_LENGTH ||
      (update.type !== 'text' &&
        update.type !== 'hidden' &&
        update.type !== 'boolean' &&
        update.type !== 'linked') ||
      (update.value !== null &&
        (typeof update.value !== 'string' ||
          update.value.length > MAX_CUSTOM_FIELD_VALUE_LENGTH)) ||
      (update.linkedId !== null && (!Number.isSafeInteger(update.linkedId) || update.linkedId < 0))
    ) {
      throw new VaultError('INVALID_INPUT')
    }

    let sourceField: VaultCustomField | null = null
    if (update.source !== null) {
      if (!isRecord(update.source)) throw new VaultError('INVALID_INPUT')
      const { index, name, type, linkedId } = update.source
      if (
        !Number.isSafeInteger(index) ||
        index < 0 ||
        sourceIndexes.has(index) ||
        typeof name !== 'string' ||
        name.length > MAX_CUSTOM_FIELD_NAME_LENGTH ||
        (type !== 'text' && type !== 'hidden' && type !== 'boolean' && type !== 'linked') ||
        (linkedId !== null && (!Number.isSafeInteger(linkedId) || linkedId < 0))
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      sourceIndexes.add(index)
      sourceField = existing[index] ?? null
      if (
        !sourceField ||
        sourceField.name !== name ||
        sourceField.type !== type ||
        sourceField.linkedId !== linkedId
      ) {
        throw new VaultError('INVALID_INPUT')
      }
    }

    if (update.type === 'linked') {
      if (
        update.value !== null ||
        update.linkedId === null ||
        !linkedIds.includes(update.linkedId)
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      return { name: update.name, type: update.type, value: '', linkedId: update.linkedId }
    }
    if (update.linkedId !== null) throw new VaultError('INVALID_INPUT')

    if (update.value === null) {
      if (update.type !== 'hidden' || sourceField?.type !== 'hidden') {
        throw new VaultError('INVALID_INPUT')
      }
      return { name: update.name, type: update.type, value: sourceField.value, linkedId: null }
    }
    if (update.type === 'boolean' && update.value !== 'true' && update.value !== 'false') {
      throw new VaultError('INVALID_INPUT')
    }
    return { name: update.name, type: update.type, value: update.value, linkedId: null }
  })
}

function assertSecretField(type: VaultItemType, field: VaultSecretField): void {
  if (!SECRET_FIELDS_BY_TYPE[type].includes(field)) throw new VaultError('INVALID_INPUT')
}

function assertCopyField(type: VaultItemType, field: VaultCopyField): void {
  if (!COPY_FIELDS_BY_TYPE[type].includes(field)) throw new VaultError('INVALID_INPUT')
}

function customFieldFromSource(
  login: StoredLogin,
  source: VaultCustomFieldSource
): VaultCustomField {
  const { index } = source
  if (!Number.isSafeInteger(index) || index < 0 || index >= login.customFields.length) {
    throw new VaultError('INVALID_INPUT')
  }
  const field = login.customFields[index]!
  if (
    field.name !== source.name ||
    field.type !== source.type ||
    field.linkedId !== source.linkedId
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return field
}

function linkedCustomFieldValue(login: StoredLogin, linkedId: number | null): string {
  if (login.type === 'login') {
    if (linkedId === 100) return login.username
    if (linkedId === 101) return login.password
  } else if (login.type === 'card') {
    const fields: Partial<Record<number, keyof VaultItemFields>> = {
      300: 'cardholderName',
      301: 'expMonth',
      302: 'expYear',
      303: 'code',
      304: 'brand',
      305: 'number'
    }
    const field = linkedId === null ? undefined : fields[linkedId]
    if (field) return String(login[field] ?? '')
  } else if (login.type === 'identity') {
    if (linkedId === 418) {
      return [login.title, login.firstName, login.middleName, login.lastName]
        .filter(Boolean)
        .join(' ')
    }
    const fields: Partial<Record<number, keyof VaultItemFields>> = {
      400: 'title',
      401: 'middleName',
      402: 'address1',
      403: 'address2',
      404: 'address3',
      405: 'city',
      406: 'state',
      407: 'postalCode',
      408: 'country',
      409: 'company',
      410: 'email',
      411: 'phone',
      412: 'ssn',
      413: 'identityUsername',
      414: 'passportNumber',
      415: 'licenseNumber',
      416: 'firstName',
      417: 'lastName'
    }
    const field = linkedId === null ? undefined : fields[linkedId]
    if (field) return String(login[field] ?? '')
  }
  throw new VaultError('INVALID_INPUT')
}

function customFieldValue(login: StoredLogin, field: VaultCustomField): string {
  return field.type === 'linked' ? linkedCustomFieldValue(login, field.linkedId) : field.value
}

function normalizeMasterPassword(value: unknown): string {
  if (typeof value !== 'string') {
    throw new VaultError('INVALID_INPUT')
  }
  const normalized = value.normalize('NFC')
  if (
    normalized.length < MIN_MASTER_PASSWORD_LENGTH ||
    normalized.length > MAX_MASTER_PASSWORD_LENGTH
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return normalized
}

function cloneData(data: VaultData): VaultData {
  return {
    ...data,
    folders: data.folders.map((folder) => ({ ...folder })),
    logins: data.logins.map((login) => ({
      ...login,
      passkeys: login.passkeys.map((passkey) => ({ ...passkey })),
      customFields: cloneCustomFields(login.customFields)
    })),
    sync: data.sync
      ? {
          ...data.sync,
          state: {
            ...data.sync.state,
            session: data.sync.state.session ? { ...data.sync.state.session } : null
          },
          folderMappings: data.sync.folderMappings.map((entry) => ({ ...entry })),
          loginMappings: data.sync.loginMappings.map((entry) => ({ ...entry })),
          folderTombstones: data.sync.folderTombstones.map((entry) => ({ ...entry })),
          loginTombstones: data.sync.loginTombstones.map((entry) => ({ ...entry }))
        }
      : null
  }
}

function recordSyncDeletion(
  sync: PersistedSyncData | null,
  entity: 'folder' | 'login',
  localId: string
): void {
  if (!sync) return
  const mappings = entity === 'folder' ? sync.folderMappings : sync.loginMappings
  const mapping = mappings.find((entry) => entry.localId === localId)
  if (!mapping) return
  const tombstones = entity === 'folder' ? sync.folderTombstones : sync.loginTombstones
  tombstones.push({
    localId: mapping.localId,
    remoteId: mapping.remoteId,
    baseFingerprint: mapping.baseFingerprint
  })
  if (entity === 'folder') {
    sync.folderMappings = sync.folderMappings.filter((entry) => entry.localId !== localId)
  } else {
    sync.loginMappings = sync.loginMappings.filter((entry) => entry.localId !== localId)
  }
}

function toSummary(login: StoredLogin): LoginSummary {
  const notePreview = login.type === 'secureNote' ? summarizeSecureNote(login.notes) : ''
  const subtitle =
    login.type === 'login'
      ? login.username || login.uri || ''
      : login.type === 'card'
        ? login.number.length >= 4
          ? `•••• ${login.number.slice(-4)}`
          : login.brand
        : login.type === 'identity'
          ? [login.firstName, login.lastName].filter(Boolean).join(' ')
          : login.type === 'secureNote'
            ? notePreview
            : login.type === 'sshKey'
              ? login.fingerprint || 'SSH key'
              : ''
  return {
    id: login.id,
    type: login.type,
    name: login.name,
    subtitle,
    username: login.type === 'login' ? login.username : '',
    uri: login.type === 'login' ? login.uri : null,
    ...(login.type === 'card' ? { cardBrand: login.brand } : {}),
    ...(login.type === 'login'
      ? { hasTotp: Boolean(login.totp), passkeyCount: login.passkeys.length }
      : {}),
    folderId: login.folderId,
    favorite: login.favorite,
    lastUsedAt: login.lastUsedAt,
    createdAt: login.createdAt,
    updatedAt: login.updatedAt
  }
}

function summarizeSecureNote(notes: string | null): string {
  const firstLine =
    notes
      ?.split(/\r\n?|\n/u)
      .map((line) => line.trim())
      .find(Boolean) ?? ''
  const graphemes = Array.from(
    new Intl.Segmenter('zh-Hant', { granularity: 'grapheme' }).segment(firstLine),
    (segment) => segment.segment
  )
  if (graphemes.length <= 80) return firstLine
  return `${graphemes.slice(0, 80).join('')}…`
}

function toView(login: StoredLogin): LoginView {
  return {
    ...toSummary(login),
    notes: login.notes,
    hasTotp: Boolean(login.totp),
    passkeys: login.passkeys.map(toPasskeyView),
    customFields: login.customFields.map((field): VaultCustomFieldView => ({
      ...field,
      value: field.type === 'hidden' || field.type === 'linked' ? null : field.value
    })),
    cardholderName: login.cardholderName,
    brand: login.brand,
    expMonth: login.expMonth,
    expYear: login.expYear,
    title: login.title,
    firstName: login.firstName,
    middleName: login.middleName,
    lastName: login.lastName,
    address1: login.address1,
    address2: login.address2,
    address3: login.address3,
    city: login.city,
    state: login.state,
    postalCode: login.postalCode,
    country: login.country,
    company: login.company,
    email: login.email,
    phone: login.phone,
    identityUsername: login.identityUsername,
    publicKey: login.publicKey,
    fingerprint: login.fingerprint
  }
}

function compareText(left: string, right: string): number {
  const normalizedLeft = left.toLocaleLowerCase('en-US')
  const normalizedRight = right.toLocaleLowerCase('en-US')
  if (normalizedLeft < normalizedRight) return -1
  if (normalizedLeft > normalizedRight) return 1
  return 0
}

function validRemoteDate(value: string | null): string | undefined {
  return value && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : undefined
}

export class VaultService {
  private key: Buffer | null = null
  private salt: Buffer | null = null
  private data: VaultData | null = null
  private generation = 0
  private operationQueue: Promise<void> = Promise.resolve()
  private syncClient: BitwardenSyncClient | null = null
  private syncAbort: AbortController | null = null
  private syncInProgress = false
  private syncLastError: string | null = null
  private readonly now: () => Date
  private readonly createId: () => string
  private readonly createSyncClient: (sync: PersistedSyncData) => BitwardenSyncClient
  private readonly fetch: typeof fetch
  private readonly websiteIconCache = new Map<string, string | null>()
  private readonly websiteIconRequests = new Map<string, Promise<string | null>>()

  constructor(
    private readonly store: EncryptedVaultStore<unknown>,
    private readonly platform: VaultPlatform,
    options: VaultServiceOptions = {}
  ) {
    this.now = options.now ?? (() => new Date())
    this.createId = options.createId ?? randomUUID
    this.fetch = options.fetch ?? fetch
    this.createSyncClient =
      options.createSyncClient ??
      (() => {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      })
  }

  status(): Promise<VaultStatus> {
    return this.exclusive(async () => this.currentStatus())
  }

  setup(masterPassword: string): Promise<VaultStatus> {
    return this.exclusive(async () => {
      if (await this.store.exists()) throw new VaultError('ALREADY_INITIALIZED')
      const password = normalizeMasterPassword(masterPassword)
      const now = this.nowIso()
      const initialData: VaultData = {
        version: DATA_VERSION,
        createdAt: now,
        updatedAt: now,
        folders: [],
        logins: [],
        sync: null
      }
      const generation = this.generation
      const material = await this.store.initialize(password, initialData)
      if (generation !== this.generation) {
        material.key.fill(0)
        material.salt.fill(0)
        throw new VaultError('LOCKED')
      }
      this.key = material.key
      this.salt = material.salt
      this.data = initialData
      return { state: 'unlocked' }
    })
  }

  unlock(masterPassword: string): Promise<VaultStatus> {
    return this.exclusive(async () => {
      if (this.data && this.key && this.salt) return { state: 'unlocked' }
      if (!(await this.store.exists())) throw new VaultError('NOT_INITIALIZED')
      const password = normalizeMasterPassword(masterPassword)
      const generation = this.generation
      const unlocked = await this.store.unlock(password)

      try {
        if (generation !== this.generation) throw new VaultError('LOCKED')
        const requiresMigration = isRecord(unlocked.data) && unlocked.data.version !== DATA_VERSION
        this.data = parseVaultData(unlocked.data)
        this.key = unlocked.key
        this.salt = unlocked.salt
        if (requiresMigration) await this.persist(this.data)
        return { state: 'unlocked' }
      } catch (error) {
        unlocked.key.fill(0)
        unlocked.salt.fill(0)
        this.key = null
        this.salt = null
        this.data = null
        throw error
      }
    })
  }

  lock(): Promise<VaultStatus> {
    this.syncAbort?.abort()
    return this.exclusive(async () => {
      try {
        await this.syncClient?.lock()
      } catch {
        // Local vault locking must never depend on the remote connector.
      }
      this.dispose()
      return this.currentStatus()
    })
  }

  dispose(): void {
    this.syncAbort?.abort()
    this.syncAbort = null
    this.syncClient = null
    this.syncInProgress = false
    this.generation += 1
    this.key?.fill(0)
    this.salt?.fill(0)
    this.key = null
    this.salt = null
    this.data = null
    this.websiteIconCache.clear()
    this.websiteIconRequests.clear()
  }

  syncStatus(): Promise<SyncStatus> {
    return this.exclusive(async () => this.currentSyncStatus(true))
  }

  connectSync(request: SyncConnectRequest): Promise<SyncResult> {
    return this.exclusive(async () => {
      const current = this.requireData()
      const serverUrl = this.normalizeSyncServerUrl(request.serverUrl)
      const email = normalizeRequiredString(request.email, MAX_USERNAME_LENGTH)
      const password = normalizeSyncPassword(request.masterPassword)
      const twoFactor = this.normalizeTwoFactor(request.twoFactorMethod, request.twoFactorCode)
      const newDeviceOtp = this.normalizeNewDeviceOtp(request.newDeviceOtp)
      const abort = this.startSyncOperation()

      try {
        const sync: PersistedSyncData = {
          provider: 'bitwarden',
          serverUrl,
          email,
          state: {
            session: null,
            deviceIdentifier: randomUUID(),
            profileId: null,
            securityStamp: null
          },
          lastSyncAt: null,
          folderMappings: [],
          loginMappings: [],
          folderTombstones: [],
          loginTombstones: []
        }
        const client = this.createSyncClient(sync)
        await client.login({ email, password, twoFactor, newDeviceOtp, signal: abort.signal })
        const next = cloneData(current)
        sync.state = client.exportState()
        next.sync = sync
        next.updatedAt = this.nowIso()
        await this.persist(next)
        this.data = next
        this.syncClient = client
        return await this.performSync(next, client, abort.signal)
      } catch (error) {
        await this.persistCurrentClientState().catch(() => undefined)
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
    })
  }

  unlockSync(request: SyncUnlockRequest): Promise<SyncStatus> {
    return this.exclusive(async () => {
      const sync = this.requireSyncData()
      const password = normalizeSyncPassword(request.masterPassword)
      const twoFactor = this.normalizeTwoFactor(request.twoFactorMethod, request.twoFactorCode)
      const newDeviceOtp = this.normalizeNewDeviceOtp(request.newDeviceOtp)
      const client = this.getOrCreateSyncClient(sync)
      const abort = this.startSyncOperation()
      try {
        await client.unlock({ password, twoFactor, newDeviceOtp, signal: abort.signal })
        await this.persistCurrentClientState()
        this.syncLastError = null
        return this.baseSyncStatus(sync, 'ready')
      } catch (error) {
        await this.persistCurrentClientState().catch(() => undefined)
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
    })
  }

  async unlockSyncWithLocalPassword(masterPassword: string): Promise<SyncStatus> {
    const current = await this.syncStatus()
    if (!current.configured || current.state === 'ready') return current
    try {
      return await this.unlockSync({ masterPassword })
    } catch (error) {
      if (
        error instanceof VaultError &&
        (error.code === 'SYNC_AUTH_REQUIRED' || error.code === 'SYNC_NEW_DEVICE_REQUIRED')
      ) {
        return this.exclusive(async () => {
          this.syncLastError = null
          const sync = this.requireData().sync
          return sync
            ? this.baseSyncStatus(sync, 'locked')
            : { configured: false, state: 'unconfigured' }
        })
      }
      throw error
    }
  }

  syncNow(): Promise<SyncResult> {
    return this.exclusive(async () => {
      const data = this.requireData()
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const abort = this.startSyncOperation()
      try {
        return await this.performSync(data, client, abort.signal)
      } catch (error) {
        await this.persistCurrentClientState().catch(() => undefined)
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
    })
  }

  disconnectSync(): Promise<SyncStatus> {
    this.syncAbort?.abort()
    return this.exclusive(async () => {
      const next = cloneData(this.requireData())
      const client = this.syncClient
      this.syncClient = null
      this.syncLastError = null
      try {
        await client?.logout()
      } catch {
        // Clearing local sync configuration must work even when the server is offline.
      }
      next.sync = null
      next.updatedAt = this.nowIso()
      await this.persist(next)
      this.data = next
      return { configured: false, state: 'unconfigured' }
    })
  }

  listFolders(): Promise<FolderView[]> {
    return this.exclusive(async () =>
      this.requireData()
        .folders.map((folder) => ({ ...folder }))
        .sort((left, right) => left.position - right.position || compareText(left.name, right.name))
    )
  }

  createFolder(request: FolderCreateRequest): Promise<FolderView> {
    return this.mutate((data, now) => {
      const name = normalizeRequiredString(request.name, MAX_NAME_LENGTH)
      this.assertUniqueFolderName(data, name)
      const folder: FolderView = {
        id: this.validatedNewId(),
        name,
        position: data.folders.length,
        createdAt: now,
        updatedAt: now
      }
      data.folders.push(folder)
      return { ...folder }
    })
  }

  updateFolder(request: FolderUpdateRequest): Promise<FolderView> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const folder = this.findFolder(data, request.id)
      const name = normalizeRequiredString(request.name, MAX_NAME_LENGTH)
      this.assertUniqueFolderName(data, name, folder.id)
      folder.name = name
      folder.updatedAt = now
      return { ...folder }
    })
  }

  deleteFolder(request: FolderDeleteRequest): Promise<void> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      this.findFolder(data, request.id)
      recordSyncDeletion(data.sync, 'folder', request.id)
      data.folders = data.folders
        .filter((folder) => folder.id !== request.id)
        .sort((left, right) => left.position - right.position)
        .map((folder, position) => ({ ...folder, position }))
      data.logins.forEach((login) => {
        if (login.folderId === request.id) {
          login.folderId = null
          login.updatedAt = now
        }
      })
    })
  }

  reorderFolders(request: FolderReorderRequest): Promise<FolderView[]> {
    return this.mutate((data, now) => {
      if (!Array.isArray(request.orderedIds) || request.orderedIds.length !== data.folders.length) {
        throw new VaultError('INVALID_INPUT')
      }
      request.orderedIds.forEach(assertUuid)
      const uniqueIds = new Set(request.orderedIds)
      if (
        uniqueIds.size !== data.folders.length ||
        data.folders.some((folder) => !uniqueIds.has(folder.id))
      ) {
        throw new VaultError('INVALID_INPUT')
      }

      const foldersById = new Map(data.folders.map((folder) => [folder.id, folder]))
      data.folders = request.orderedIds.map((id, position) => ({
        ...foldersById.get(id)!,
        position,
        updatedAt: now
      }))
      return data.folders.map((folder) => ({ ...folder }))
    })
  }

  listLogins(request: LoginListRequest = {}): Promise<LoginSummary[]> {
    return this.exclusive(async () => {
      const data = this.requireData()
      const sort = request.sort ?? 'recent'
      if (sort !== 'recent' && sort !== 'name') throw new VaultError('INVALID_INPUT')
      if (request.folderId !== undefined && request.folderId !== null) {
        assertUuid(request.folderId)
        this.findFolder(data, request.folderId)
      }

      const filtered = data.logins.filter(
        (login) => request.folderId === undefined || login.folderId === request.folderId
      )
      return filtered.map(toSummary).sort((left, right) => {
        if (sort === 'recent') {
          if (left.lastUsedAt && right.lastUsedAt && left.lastUsedAt !== right.lastUsedAt) {
            return right.lastUsedAt.localeCompare(left.lastUsedAt)
          }
          if (left.lastUsedAt && !right.lastUsedAt) return -1
          if (!left.lastUsedAt && right.lastUsedAt) return 1
        }
        return compareText(left.name, right.name) || left.id.localeCompare(right.id)
      })
    })
  }

  getLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      return toView(this.findLogin(this.requireData(), request.id))
    })
  }

  createLogin(request: LoginCreateRequest): Promise<LoginView> {
    return this.mutate((data, now) => {
      const folderId = this.normalizeFolderId(data, request.folderId)
      const type = normalizeItemType(request.type ?? 'login')
      const fields = emptyItemFields()
      applyItemFields(fields, request, type)
      const customFields = normalizeCustomFields([], request.customFields ?? [], type)
      const login: StoredLogin = {
        id: this.validatedNewId(),
        type,
        name: normalizeRequiredString(request.name, MAX_NAME_LENGTH),
        notes: normalizeNullableString(request.notes, MAX_NOTES_LENGTH),
        folderId,
        favorite: request.favorite ?? false,
        lastUsedAt: null,
        createdAt: now,
        updatedAt: now,
        passkeys: [],
        customFields,
        ...fields
      }
      if (typeof login.favorite !== 'boolean') throw new VaultError('INVALID_INPUT')
      data.logins.push(login)
      return toView(login)
    })
  }

  updateLogin(request: LoginUpdateRequest): Promise<LoginView> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const login = this.findLogin(data, request.id)
      if (
        request.expectedUpdatedAt !== undefined &&
        (typeof request.expectedUpdatedAt !== 'string' ||
          request.expectedUpdatedAt !== login.updatedAt)
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      if (request.name !== undefined)
        login.name = normalizeRequiredString(request.name, MAX_NAME_LENGTH)
      applyItemFields(login, request, login.type)
      if (request.notes !== undefined) {
        login.notes = normalizeNullableString(request.notes, MAX_NOTES_LENGTH)
      }
      if (request.folderId !== undefined) {
        login.folderId = this.normalizeFolderId(data, request.folderId)
      }
      if (request.favorite !== undefined) {
        if (typeof request.favorite !== 'boolean') throw new VaultError('INVALID_INPUT')
        login.favorite = request.favorite
      }
      if (request.customFields !== undefined) {
        login.customFields = normalizeCustomFields(
          login.customFields,
          request.customFields,
          login.type
        )
      }
      login.updatedAt = now
      return toView(login)
    })
  }

  deleteLogin(request: LoginIdRequest): Promise<void> {
    return this.mutate((data) => {
      assertUuid(request.id)
      this.findLogin(data, request.id)
      recordSyncDeletion(data.sync, 'login', request.id)
      data.logins = data.logins.filter((login) => login.id !== request.id)
    })
  }

  setLoginFavorite(request: LoginFavoriteRequest): Promise<LoginSummary> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      if (typeof request.favorite !== 'boolean') throw new VaultError('INVALID_INPUT')
      const login = this.findLogin(data, request.id)
      login.favorite = request.favorite
      login.updatedAt = now
      return toSummary(login)
    })
  }

  moveLogin(request: LoginMoveRequest): Promise<LoginSummary> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const login = this.findLogin(data, request.id)
      login.folderId = this.normalizeFolderId(data, request.folderId)
      login.updatedAt = now
      return toSummary(login)
    })
  }

  moveLogins(request: LoginMoveManyRequest): Promise<LoginSummary[]> {
    return this.mutate((data, now) => {
      if (
        !Array.isArray(request.ids) ||
        request.ids.length === 0 ||
        request.ids.length > MAX_LOGIN_MOVE_MANY_IDS
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      request.ids.forEach(assertUuid)
      if (new Set(request.ids).size !== request.ids.length) {
        throw new VaultError('INVALID_INPUT')
      }

      const folderId = this.normalizeFolderId(data, request.folderId)
      const logins = request.ids.map((id) => this.findLogin(data, id))
      return logins.map((login) => {
        login.folderId = folderId
        login.updatedAt = now
        return toSummary(login)
      })
    })
  }

  revealPassword(request: LoginIdRequest): Promise<string> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      assertSecretField(login.type, 'password')
      return login.password
    })
  }

  revealSecret(request: ItemFieldRequest): Promise<string> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      assertSecretField(login.type, request.field as VaultSecretField)
      return login[request.field] as string
    })
  }

  revealCustomField(request: CustomFieldRequest): Promise<string> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      if (request.expectedUpdatedAt !== login.updatedAt) throw new VaultError('INVALID_INPUT')
      const field = customFieldFromSource(login, request.source)
      if (field.type !== 'hidden') throw new VaultError('INVALID_INPUT')
      return field.value
    })
  }

  copyPassword(request: LoginIdRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      assertSecretField(login.type, 'password')
      await this.platform.copyText(login.password)
    })
  }

  getTotp(request: LoginIdRequest): Promise<TotpCodeView> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      if (login.type !== 'login' || !login.totp) throw new VaultError('INVALID_INPUT')
      return generateTotp(login.totp, this.now())
    })
  }

  copyTotp(request: LoginIdRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      if (login.type !== 'login' || !login.totp) throw new VaultError('INVALID_INPUT')
      await this.platform.copyText(generateTotp(login.totp, this.now()).code)
    })
  }

  copyField(request: ItemFieldRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      assertCopyField(login.type, request.field)
      const value = login[request.field]
      if (typeof value !== 'string' || value.length === 0) throw new VaultError('INVALID_INPUT')
      await this.platform.copyText(value)
    })
  }

  copyCustomField(request: CustomFieldRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      if (request.expectedUpdatedAt !== login.updatedAt) throw new VaultError('INVALID_INPUT')
      const value = customFieldValue(login, customFieldFromSource(login, request.source))
      if (!value) throw new VaultError('INVALID_INPUT')
      await this.platform.copyText(value)
    })
  }

  copyUsername(request: LoginIdRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      assertCopyField(login.type, 'username')
      await this.platform.copyText(login.username)
    })
  }

  openLoginUri(request: LoginIdRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      assertCopyField(login.type, 'uri')
      if (!login.uri) throw new VaultError('INVALID_URL')
      let url: URL
      try {
        url = new URL(login.uri)
      } catch {
        throw new VaultError('INVALID_URL')
      }
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        throw new VaultError('INVALID_URL')
      }
      await this.platform.openExternal(url.toString())
    })
  }

  async getWebsiteIcon(request: LoginIdRequest): Promise<string | null> {
    const iconUrl = await this.exclusive(async () => {
      assertUuid(request.id)
      const data = this.requireData()
      const login = this.findLogin(data, request.id)
      if (login.type !== 'login' || !login.uri || !data.sync) return null
      const hostname = parseWebsiteHostname(login.uri)
      return hostname ? resolveWebsiteIconUrl(data.sync.serverUrl, hostname) : null
    })
    if (!iconUrl) return null

    const cacheKey = iconUrl.toString()
    if (this.websiteIconCache.has(cacheKey)) return this.websiteIconCache.get(cacheKey) ?? null
    const existingRequest = this.websiteIconRequests.get(cacheKey)
    if (existingRequest) return existingRequest

    const generation = this.generation
    const pendingRequest = fetchWebsiteIconDataUrl(iconUrl, this.fetch)
      .then((dataUrl) => {
        if (generation !== this.generation) return null
        if (this.websiteIconCache.size >= 128) {
          const oldestKey = this.websiteIconCache.keys().next().value
          if (oldestKey) this.websiteIconCache.delete(oldestKey)
        }
        this.websiteIconCache.set(cacheKey, dataUrl)
        return dataUrl
      })
      .finally(() => {
        if (this.websiteIconRequests.get(cacheKey) === pendingRequest) {
          this.websiteIconRequests.delete(cacheKey)
        }
      })
    this.websiteIconRequests.set(cacheKey, pendingRequest)
    return pendingRequest
  }

  private async currentSyncStatus(checkConnection: boolean): Promise<SyncStatus> {
    const data = this.requireData()
    if (!data.sync) return { configured: false, state: 'unconfigured' }
    if (this.syncInProgress) return this.baseSyncStatus(data.sync, 'syncing')
    if (this.syncLastError) return this.baseSyncStatus(data.sync, 'error')
    if (!checkConnection) return this.baseSyncStatus(data.sync, 'locked')
    try {
      const client = this.getOrCreateSyncClient(data.sync)
      const status = await client.status()
      return this.baseSyncStatus(data.sync, status.status === 'unlocked' ? 'ready' : 'locked')
    } catch {
      this.syncLastError = 'SYNC_FAILED'
      return this.baseSyncStatus(data.sync, 'error')
    }
  }

  private baseSyncStatus(sync: PersistedSyncData, state: SyncStatus['state']): SyncStatus {
    return {
      configured: true,
      state,
      serverUrl: sync.serverUrl,
      email: sync.email,
      ...(sync.lastSyncAt ? { lastSyncAt: sync.lastSyncAt } : {}),
      ...(this.syncLastError ? { lastError: this.syncLastError } : {})
    }
  }

  private normalizeSyncServerUrl(value: unknown): string {
    if (typeof value !== 'string' || value.length === 0 || value.length > MAX_URI_LENGTH) {
      throw new VaultError('INVALID_URL')
    }
    try {
      const normalized = value.trim()
      resolveBitwardenUrls(normalized)
      return normalized.replace(/\/$/, '')
    } catch {
      throw new VaultError('INVALID_URL')
    }
  }

  private normalizeTwoFactor(
    method: SyncConnectRequest['twoFactorMethod'],
    code: string | undefined
  ): BitwardenTwoFactor | undefined {
    if (method === undefined && code === undefined) return undefined
    if (
      method === undefined ||
      code === undefined ||
      code.length === 0 ||
      code.length > MAX_TWO_FACTOR_CODE_LENGTH
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    return { method: Number(method) as BitwardenTwoFactor['method'], code }
  }

  private normalizeNewDeviceOtp(value: string | undefined): string | undefined {
    if (value === undefined) return undefined
    const normalized = value.trim()
    if (normalized.length === 0 || normalized.length > MAX_TWO_FACTOR_CODE_LENGTH) {
      throw new VaultError('INVALID_INPUT')
    }
    return normalized
  }

  private getOrCreateSyncClient(sync: PersistedSyncData): BitwardenSyncClient {
    this.syncClient ??= this.createSyncClient(sync)
    return this.syncClient
  }

  private requireSyncData(): PersistedSyncData {
    const sync = this.requireData().sync
    if (!sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    return sync
  }

  private startSyncOperation(): AbortController {
    if (this.syncInProgress) throw new VaultError('SYNC_FAILED')
    const abort = new AbortController()
    this.syncAbort = abort
    this.syncInProgress = true
    this.syncLastError = null
    return abort
  }

  private finishSyncOperation(abort: AbortController): void {
    if (this.syncAbort === abort) this.syncAbort = null
    this.syncInProgress = false
  }

  private mapSyncError(error: unknown): VaultError {
    if (error instanceof VaultError) return error
    this.syncLastError = 'SYNC_FAILED'
    if (error instanceof BitwardenDirectError) {
      if (error.code === 'AUTH_REQUIRED' || error.code === 'TWO_FACTOR_REQUIRED') {
        return new VaultError('SYNC_AUTH_REQUIRED')
      }
      if (error.code === 'NEW_DEVICE_REQUIRED') {
        return new VaultError('SYNC_NEW_DEVICE_REQUIRED')
      }
      if (error.code === 'ABORTED') return new VaultError('LOCKED')
      if (error.code === 'UNSUPPORTED_ACCOUNT_ENCRYPTION') {
        this.syncLastError = 'SYNC_UNSUPPORTED_ACCOUNT'
        return new VaultError('SYNC_UNSUPPORTED_ACCOUNT')
      }
    }
    return new VaultError('SYNC_FAILED')
  }

  private async persistCurrentClientState(): Promise<void> {
    const client = this.syncClient
    const current = this.requireData()
    if (!client || !current.sync) return
    const state = client.exportState()
    if (JSON.stringify(state) === JSON.stringify(current.sync.state)) return
    const next = cloneData(current)
    if (!next.sync) return
    next.sync.state = state
    next.updatedAt = this.nowIso()
    await this.persist(next)
    this.data = next
  }

  private async performSync(
    current: VaultData,
    client: BitwardenSyncClient,
    signal: AbortSignal
  ): Promise<SyncResult> {
    const sync = current.sync
    if (!sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    await client.sync(signal)
    const [remoteFolders, remoteLogins] = await Promise.all([
      client.listFolders(signal),
      client.listPersonalLogins(signal)
    ])
    const next = cloneData(current)
    const remoteSnapshot = this.remoteSyncSnapshot(remoteFolders, remoteLogins)
    const syncMetadata = this.syncMetadata(sync)
    for (const upgrade of legacyCustomFieldBaselineUpgrades(
      this.localSyncSnapshot(next),
      remoteSnapshot,
      syncMetadata
    )) {
      this.findLogin(next, upgrade.localId).customFields = cloneCustomFields(upgrade.customFields)
      const mapping = next.sync?.loginMappings.find(
        (entry) => entry.localId === upgrade.localId && entry.remoteId === upgrade.remoteId
      )
      if (mapping) mapping.baseFingerprint = upgrade.baseFingerprint
      const metadataLink = syncMetadata.loginLinks.find(
        (entry) => entry.localId === upgrade.localId && entry.remoteId === upgrade.remoteId
      )
      if (metadataLink) metadataLink.baseFingerprint = upgrade.baseFingerprint
    }
    const plan = planSync(this.localSyncSnapshot(next), remoteSnapshot, syncMetadata)
    const results: SyncActionResult[] = []
    const completed = new Map<string, SyncActionResult>()
    const counts = { pulled: 0, pushed: 0, deleted: 0, conflicts: 0 }

    for (const action of plan.actions) {
      if (signal.aborted) throw new BitwardenDirectError('ABORTED')
      const result = await this.executeSyncAction(next, client, action, completed, signal)
      results.push(result)
      completed.set(action.actionId, result)
      if (action.kind === 'conflict-copy') counts.conflicts += 1
      else if (action.kind === 'delete-local' || action.kind === 'delete-remote')
        counts.deleted += 1
      else if (action.kind.startsWith('pull-')) counts.pulled += 1
      else counts.pushed += 1
    }

    const metadata = completeSyncMetadata(plan, results)
    const syncedAt = this.nowIso()
    next.sync = {
      ...sync,
      state: client.exportState(),
      lastSyncAt: syncedAt,
      folderMappings: metadata.folderLinks.map((link) => ({ ...link })),
      loginMappings: metadata.loginLinks.map((link) => ({ ...link })),
      folderTombstones: [],
      loginTombstones: []
    }
    next.updatedAt = syncedAt
    await this.persist(next)
    this.data = next
    this.syncLastError = null
    return { ...this.baseSyncStatus(next.sync, 'ready'), ...counts }
  }

  private localSyncSnapshot(data: VaultData): SyncSnapshot {
    return {
      folders: data.folders.map((folder) => ({
        id: folder.id,
        name: folder.name,
        updatedAt: folder.updatedAt
      })),
      logins: data.logins.map((login) => ({
        ...login,
        passkeys: login.passkeys.map((passkey) => ({ ...passkey })),
        customFields: cloneCustomFields(login.customFields)
      })),
      tombstones: {
        folders: (data.sync?.folderTombstones ?? []).map((entry) => ({
          id: entry.localId,
          deletedAt: data.updatedAt
        })),
        logins: (data.sync?.loginTombstones ?? []).map((entry) => ({
          id: entry.localId,
          deletedAt: data.updatedAt
        }))
      }
    }
  }

  private remoteSyncSnapshot(
    folders: BitwardenFolder[],
    logins: BitwardenLoginItem[]
  ): SyncSnapshot {
    return {
      folders: folders.map((folder) => ({ id: folder.id, name: folder.name })),
      logins: logins.map((login) => ({
        ...login,
        uri: login.uri ?? login.uris[0]?.uri ?? null,
        createdAt: validRemoteDate(login.creationDate),
        updatedAt: validRemoteDate(login.revisionDate)
      })),
      tombstones: { folders: [], logins: [] }
    }
  }

  private syncMetadata(sync: PersistedSyncData): SyncMetadata {
    return {
      version: 1,
      folderLinks: [...sync.folderMappings, ...sync.folderTombstones].map((entry) => ({
        localId: entry.localId,
        remoteId: entry.remoteId,
        baseFingerprint: entry.baseFingerprint
      })),
      loginLinks: [...sync.loginMappings, ...sync.loginTombstones].map((entry) => ({
        localId: entry.localId,
        remoteId: entry.remoteId,
        baseFingerprint: entry.baseFingerprint
      }))
    }
  }

  private async executeSyncAction(
    data: VaultData,
    client: BitwardenSyncClient,
    action: SyncAction,
    completed: Map<string, SyncActionResult>,
    signal: AbortSignal
  ): Promise<SyncActionResult> {
    const result: SyncActionResult = { actionId: action.actionId }
    if (action.entity === 'folder') {
      if (action.kind === 'push-create') {
        result.remoteId = (await client.createFolder(action.local.name, signal)).id
      } else if (action.kind === 'push-update') {
        await client.editFolder(action.remoteId, action.local.name, signal)
      } else if (action.kind === 'pull-create') {
        result.localId = this.createLocalFolder(data, action.remote.name).id
      } else if (action.kind === 'pull-update') {
        const folder = this.findFolder(data, action.localId)
        folder.name = action.remote.name
        folder.updatedAt = this.nowIso()
      } else if (action.kind === 'delete-local') {
        this.deleteLocalFolder(data, action.localId)
      } else if (action.kind === 'delete-remote') {
        await client.deleteFolder(action.remoteId, signal)
      } else if (action.reason === 'both-modified') {
        if (!action.local || !action.remote) throw new VaultError('SYNC_FAILED')
        this.createLocalFolder(data, action.conflictName)
        const primary = this.findFolder(data, action.local.id)
        primary.name = action.remote.name
        primary.updatedAt = this.nowIso()
      } else if (action.reason === 'remote-deleted') {
        if (!action.local) throw new VaultError('SYNC_FAILED')
        const local = this.findFolder(data, action.local.id)
        local.name = action.conflictName
        local.updatedAt = this.nowIso()
        result.remoteId = (await client.createFolder(action.conflictName, signal)).id
      } else {
        if (!action.remote) throw new VaultError('SYNC_FAILED')
        await client.editFolder(action.remote.id, action.conflictName, signal)
        result.localId = this.createLocalFolder(data, action.conflictName).id
      }
      return result
    }

    if (action.kind === 'push-create') {
      const folderId = this.resolveFolderReference(action.remoteFolder, completed, 'remoteId')
      result.remoteId = (
        await client.createLogin(this.remoteDraft(action.local, folderId), signal)
      ).id
    } else if (action.kind === 'push-update') {
      const folderId = this.resolveFolderReference(action.remoteFolder, completed, 'remoteId')
      await client.editLogin(action.remoteId, this.remoteDraft(action.local, folderId), signal)
    } else if (action.kind === 'pull-create') {
      const folderId = this.resolveFolderReference(action.localFolder, completed, 'localId')
      result.localId = this.createLocalLogin(data, action.remote, folderId).id
    } else if (action.kind === 'pull-update') {
      const folderId = this.resolveFolderReference(action.localFolder, completed, 'localId')
      this.updateLocalLogin(data, action.localId, action.remote, folderId)
    } else if (action.kind === 'delete-local') {
      data.logins = data.logins.filter((login) => login.id !== action.localId)
    } else if (action.kind === 'delete-remote') {
      await client.deleteLogin(action.remoteId, signal)
    } else if (action.reason === 'both-modified') {
      if (!action.local || !action.remote) throw new VaultError('SYNC_FAILED')
      const copyFolderId =
        action.local.folderId && data.folders.some((folder) => folder.id === action.local!.folderId)
          ? action.local.folderId
          : null
      this.createLocalLogin(data, { ...action.local, name: action.conflictName }, copyFolderId)
      const primaryFolderId = this.resolveFolderReference(action.localFolder, completed, 'localId')
      this.updateLocalLogin(data, action.local.id, action.remote, primaryFolderId)
    } else if (action.reason === 'remote-deleted') {
      if (!action.local) throw new VaultError('SYNC_FAILED')
      const local = this.findLogin(data, action.local.id)
      local.name = action.conflictName
      local.updatedAt = this.nowIso()
      const folderId = this.resolveFolderReference(action.remoteFolder, completed, 'remoteId')
      result.remoteId = (
        await client.createLogin(
          this.remoteDraft({ ...action.local, name: action.conflictName }, folderId),
          signal
        )
      ).id
    } else {
      if (!action.remote) throw new VaultError('SYNC_FAILED')
      const remoteFolderId = action.remote.folderId
      await client.editLogin(
        action.remote.id,
        this.remoteDraft({ ...action.remote, name: action.conflictName }, remoteFolderId),
        signal
      )
      const localFolderId = this.resolveFolderReference(action.localFolder, completed, 'localId')
      result.localId = this.createLocalLogin(
        data,
        { ...action.remote, name: action.conflictName },
        localFolderId
      ).id
    }
    return result
  }

  private resolveFolderReference(
    reference: SyncFolderReference,
    completed: Map<string, SyncActionResult>,
    side: 'localId' | 'remoteId'
  ): string | null {
    if (reference.id !== null) return reference.id
    if (!reference.pendingKey) return null
    const id = completed.get(reference.pendingKey)?.[side]
    if (!id) throw new VaultError('SYNC_FAILED')
    return id
  }

  private createLocalFolder(data: VaultData, name: string): FolderView {
    const now = this.nowIso()
    const folder: FolderView = {
      id: this.validatedNewId(),
      name: normalizeRequiredString(name, MAX_NAME_LENGTH),
      position: data.folders.length,
      createdAt: now,
      updatedAt: now
    }
    data.folders.push(folder)
    return folder
  }

  private deleteLocalFolder(data: VaultData, id: string): void {
    data.folders = data.folders
      .filter((folder) => folder.id !== id)
      .sort((left, right) => left.position - right.position)
      .map((folder, position) => ({ ...folder, position }))
    const now = this.nowIso()
    for (const login of data.logins) {
      if (login.folderId === id) {
        login.folderId = null
        login.updatedAt = now
      }
    }
  }

  private createLocalLogin(
    data: VaultData,
    source: SyncLogin,
    folderId: string | null
  ): StoredLogin {
    const now = this.nowIso()
    const createdAt = source.createdAt ?? now
    const updatedAt = source.updatedAt ?? createdAt
    const login: StoredLogin = {
      id: this.validatedNewId(),
      type: normalizeItemType(source.type),
      name: normalizeRequiredString(source.name, MAX_NAME_LENGTH),
      notes: normalizeNullableString(source.notes, MAX_NOTES_LENGTH),
      folderId,
      favorite: source.favorite,
      lastUsedAt: source.lastUsedAt ?? null,
      createdAt,
      updatedAt,
      passkeys: source.passkeys.map((passkey) => ({ ...passkey })),
      customFields: cloneCustomFields(source.customFields),
      ...normalizeItemFieldsForStorage(source)
    }
    data.logins.push(login)
    return login
  }

  private updateLocalLogin(
    data: VaultData,
    id: string,
    source: SyncLogin,
    folderId: string | null
  ): void {
    const login = this.findLogin(data, id)
    login.type = normalizeItemType(source.type)
    login.name = normalizeRequiredString(source.name, MAX_NAME_LENGTH)
    login.notes = normalizeNullableString(source.notes, MAX_NOTES_LENGTH)
    Object.assign(login, normalizeItemFieldsForStorage(source))
    login.passkeys = source.passkeys.map((passkey) => ({ ...passkey }))
    login.customFields = cloneCustomFields(source.customFields)
    login.folderId = folderId
    login.favorite = source.favorite
    if (source.createdAt) login.createdAt = source.createdAt
    login.updatedAt = source.updatedAt ?? this.nowIso()
  }

  private remoteDraft(login: SyncLogin, folderId: string | null): BitwardenLoginDraft {
    return {
      type: login.type,
      name: login.name,
      username: login.username,
      password: login.password,
      totp: login.totp,
      uri: login.uri,
      cardholderName: login.cardholderName,
      brand: login.brand,
      number: login.number,
      expMonth: login.expMonth,
      expYear: login.expYear,
      code: login.code,
      title: login.title,
      firstName: login.firstName,
      middleName: login.middleName,
      lastName: login.lastName,
      address1: login.address1,
      address2: login.address2,
      address3: login.address3,
      city: login.city,
      state: login.state,
      postalCode: login.postalCode,
      country: login.country,
      company: login.company,
      email: login.email,
      phone: login.phone,
      ssn: login.ssn,
      identityUsername: login.identityUsername,
      passportNumber: login.passportNumber,
      licenseNumber: login.licenseNumber,
      privateKey: login.privateKey,
      publicKey: login.publicKey,
      fingerprint: login.fingerprint,
      notes: login.notes,
      folderId,
      favorite: login.favorite,
      passkeys: login.passkeys.map((passkey) => ({ ...passkey })),
      customFields: cloneCustomFields(login.customFields)
    }
  }

  private useLogin<T>(
    request: LoginIdRequest,
    operation: (login: StoredLogin) => Promise<T>
  ): Promise<T> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const current = this.requireData()
      const generation = this.generation
      const currentLogin = this.findLogin(current, request.id)
      const result = await operation(currentLogin)
      const next = cloneData(current)
      const usedLogin = this.findLogin(next, request.id)
      const now = this.nowIso()
      usedLogin.lastUsedAt = now
      next.updatedAt = now
      await this.persist(next)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      this.data = next
      return result
    })
  }

  private mutate<T>(mutation: (data: VaultData, now: string) => T): Promise<T> {
    return this.exclusive(async () => {
      const next = cloneData(this.requireData())
      const generation = this.generation
      const now = this.nowIso()
      const result = mutation(next, now)
      next.updatedAt = now
      await this.persist(next)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      this.data = next
      return result
    })
  }

  private async persist(data: VaultData): Promise<void> {
    if (!this.key || !this.salt) throw new VaultError('LOCKED')
    await this.store.write(data, this.key, this.salt)
  }

  private requireData(): VaultData {
    if (!this.data || !this.key || !this.salt) throw new VaultError('LOCKED')
    return this.data
  }

  private async currentStatus(): Promise<VaultStatus> {
    if (this.data && this.key && this.salt) return { state: 'unlocked' }
    return { state: (await this.store.exists()) ? 'locked' : 'uninitialized' }
  }

  private findFolder(data: VaultData, id: string): FolderView {
    const folder = data.folders.find((candidate) => candidate.id === id)
    if (!folder) throw new VaultError('NOT_FOUND')
    return folder
  }

  private findLogin(data: VaultData, id: string): StoredLogin {
    const login = data.logins.find((candidate) => candidate.id === id)
    if (!login) throw new VaultError('NOT_FOUND')
    return login
  }

  private normalizeFolderId(data: VaultData, folderId: unknown): string | null {
    if (folderId === undefined || folderId === null) return null
    assertUuid(folderId)
    this.findFolder(data, folderId)
    return folderId
  }

  private assertUniqueFolderName(data: VaultData, name: string, excludedId?: string): void {
    const normalized = name.toLocaleLowerCase('en-US')
    if (
      data.folders.some(
        (folder) =>
          folder.id !== excludedId && folder.name.toLocaleLowerCase('en-US') === normalized
      )
    ) {
      throw new VaultError('DUPLICATE_NAME')
    }
  }

  private validatedNewId(): string {
    const id = this.createId()
    assertUuid(id)
    return id
  }

  private nowIso(): string {
    const value = this.now()
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw new VaultError('INTERNAL_ERROR')
    }
    return value.toISOString()
  }

  private async exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.operationQueue
    let release!: () => void
    this.operationQueue = new Promise<void>((resolve) => {
      release = resolve
    })
    await previous
    try {
      return await operation()
    } finally {
      release()
    }
  }
}
