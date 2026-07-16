import { createPrivateKey, randomBytes, randomUUID, type KeyObject } from 'node:crypto'
import {
  BitwardenCryptoError,
  clearBitwardenSymmetricKey,
  decryptBitwardenAttachmentBuffer,
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
  type BitwardenAccountBreachReport,
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
  type BitwardenTwoFactorProvider,
  type BitwardenSession,
  type JsonObject,
  type JsonValue
} from './bitwarden-http'
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
const MINIMUM_CLIENT_VERSION = '2024.12.0'
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu

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

export type BitwardenDirectErrorCode =
  | 'AUTH_REQUIRED'
  | 'TWO_FACTOR_REQUIRED'
  | 'NEW_DEVICE_REQUIRED'
  | 'NETWORK'
  | 'INVALID_RESPONSE'
  | 'CONFLICT'
  | 'ABORTED'
  | 'NOT_FOUND'
  | 'FORBIDDEN'
  | 'TOO_LARGE'
  | 'STORAGE_LIMIT'
  | 'ATTACHMENT_REJECTED'
  | 'UNSUPPORTED_ACCOUNT_ENCRYPTION'
  | 'ACCOUNT_CHANGED'
  | 'USER_VERIFICATION_FAILED'
  | 'API_KEY_ROTATION_UNKNOWN'
  | 'TWO_FACTOR_MUTATION_UNKNOWN'

export class BitwardenDirectError extends Error {
  constructor(readonly code: BitwardenDirectErrorCode) {
    super(`Bitwarden direct sync failed (${code})`)
    this.name = 'BitwardenDirectError'
  }
}

export interface BitwardenTwoFactor {
  method: 0 | 1 | 3
  code: string
}

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
  authType: 1 | 2
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
}

export interface BitwardenLoginRequest {
  email: string
  password: string
  twoFactor?: BitwardenTwoFactor
  newDeviceOtp?: string
  signal?: AbortSignal
}

export interface BitwardenUnlockRequest {
  password: string
  twoFactor?: BitwardenTwoFactor
  newDeviceOtp?: string
  signal?: AbortSignal
}

export interface BitwardenDirectState {
  session: BitwardenSession | null
  deviceIdentifier: string
  profileId: string | null
  securityStamp: string | null
}

export interface BitwardenSyncClient {
  status(signal?: AbortSignal): Promise<{ status: 'unauthenticated' | 'locked' | 'unlocked' }>
  getAccountSecurityProfile?(signal?: AbortSignal): Promise<BitwardenAccountSecurityProfile>
  getAccountDevices?(signal?: AbortSignal): Promise<BitwardenAccountDevice[]>
  resendVerificationEmail?(signal?: AbortSignal): Promise<void>
  getPersonalApiKey?(
    masterPassword: string,
    rotate: boolean,
    signal?: AbortSignal
  ): Promise<{ clientId: string; clientSecret: string; revisionDate: string }>
  getTwoFactorProviders?(signal?: AbortSignal): Promise<BitwardenTwoFactorProvider[]>
  getTwoFactorRecoveryCode?(masterPassword: string, signal?: AbortSignal): Promise<string>
  disableTwoFactorProvider?(
    type: 0 | 1,
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
  /** Authenticated Vaultwarden HIBP account-breach report; it does not require vault decryption. */
  getAccountBreachReport(email: string, signal?: AbortSignal): Promise<BitwardenAccountBreachReport>
  getEquivalentDomainSettings(signal?: AbortSignal): Promise<BitwardenEquivalentDomainSettings>
  updateEquivalentDomainSettings(
    update: BitwardenEquivalentDomainUpdate,
    signal?: AbortSignal
  ): Promise<void>
  listOrganizations?(): Promise<BitwardenOrganization[]>
  listCollections?(): Promise<BitwardenCollection[]>
  listOrganizationCiphers?(): Promise<BitwardenOrganizationCipher[]>
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
  login(request: BitwardenLoginRequest): Promise<void>
  unlock(request: BitwardenUnlockRequest): Promise<void>
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
  editLogin(
    id: string,
    draft: BitwardenLoginDraft,
    signal?: AbortSignal
  ): Promise<BitwardenLoginItem>
  softDeleteLogin(id: string, signal?: AbortSignal): Promise<void>
  restoreLogin(id: string, signal?: AbortSignal): Promise<void>
  archiveLogin(id: string, signal?: AbortSignal): Promise<void>
  unarchiveLogin(id: string, signal?: AbortSignal): Promise<void>
  hardDeleteLogin(id: string, signal?: AbortSignal): Promise<void>
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
  totpChanged: boolean
  customFieldsChanged: boolean
  passkeysChanged: boolean
  passwordHistoryChanged: boolean
}

function isRecord(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
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

function repromptProperty(record: JsonObject): VaultReprompt {
  const value = property(record, 'reprompt')
  if (value === undefined || value === null) return 0
  if (value !== 0 && value !== 1) throw new BitwardenDirectError('INVALID_RESPONSE')
  return value
}

function draftReprompt(value: unknown): VaultReprompt {
  if (value !== 0 && value !== 1) throw new BitwardenDirectError('INVALID_RESPONSE')
  return value
}

function bitwardenCipherType(record: JsonObject): BitwardenCipherType {
  const value = property(record, 'type')
  if (value !== 1 && value !== 2 && value !== 3 && value !== 4 && value !== 5) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
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

function passwordHistoryDate(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value
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

function arrayProperty(record: JsonObject, name: string): JsonValue[] {
  const value = property(record, name)
  if (!Array.isArray(value) || value.length > MAX_REMOTE_ENTITIES) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value
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
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return current + additional
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
  if (!value || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value
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
  private userKey: BitwardenSymmetricKey | null = null
  private folders = new Map<string, CachedFolder>()
  private logins = new Map<string, CachedLogin>()
  private organizations = new Map<string, BitwardenOrganization>()
  private collections = new Map<string, BitwardenCollection>()
  private organizationCiphers = new Map<string, BitwardenOrganizationCipher>()
  private sends = new Map<string, CachedSend>()

  constructor(private readonly options: BitwardenDirectOptions) {
    this.email = normalizeEmail(options.email)
    this.deviceName = options.deviceName ?? 'BearWarden desktop'
    this.deviceType = options.deviceType ?? desktopDeviceType()
    this.state = options.state
      ? {
          session: options.state.session ? { ...options.state.session } : null,
          deviceIdentifier: options.state.deviceIdentifier,
          profileId: options.state.profileId,
          securityStamp: options.state.securityStamp
        }
      : {
          session: null,
          deviceIdentifier: randomUUID(),
          profileId: null,
          securityStamp: null
        }
    this.http =
      options.httpClient ??
      new BitwardenHttpClient({
        server: options.serverUrl,
        clientName: 'desktop',
        clientVersion: protocolClientVersion(options.clientVersion),
        onSessionChanged: async (session) => {
          this.state.session = { ...session }
          await this.notifyStateChanged()
        }
      })
    if (this.state.session) this.http.setSession(this.state.session)
  }

  exportState(): BitwardenDirectState {
    return {
      session: this.http.exportSession(),
      deviceIdentifier: this.state.deviceIdentifier,
      profileId: this.state.profileId,
      securityStamp: this.state.securityStamp
    }
  }

  async status(): Promise<{ status: 'unauthenticated' | 'locked' | 'unlocked' }> {
    if (!this.http.exportSession()) return { status: 'unauthenticated' }
    return { status: this.stretchedKey ? 'unlocked' : 'locked' }
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
    type: 0 | 1,
    masterPassword: string,
    signal?: AbortSignal
  ): Promise<void> {
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
    let masterPasswordHash = ''
    let authenticatorSetup: BitwardenAuthenticatorSetup | null = null
    let emailSetup: BitwardenEmailTwoFactorSetup | null = null
    let mutationStarted = false
    try {
      if (
        (type !== 0 && type !== 1) ||
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
      } else {
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
      }
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
      if (authenticatorSetup) {
        authenticatorSetup.key = ''
        authenticatorSetup.userVerificationToken = null
      }
      if (emailSetup) {
        emailSetup.email = null
        emailSetup.userVerificationToken = null
      }
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

  async getEquivalentDomainSettings(
    signal?: AbortSignal
  ): Promise<BitwardenEquivalentDomainSettings> {
    try {
      return await this.http.getEquivalentDomainSettings(signal)
    } catch (error) {
      throw this.mapError(error)
    }
  }

  async updateEquivalentDomainSettings(
    update: BitwardenEquivalentDomainUpdate,
    signal?: AbortSignal
  ): Promise<void> {
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

  async unlock(request: BitwardenUnlockRequest): Promise<void> {
    await this.deriveAndAuthenticate(
      request.password,
      request.twoFactor,
      request.newDeviceOtp,
      !this.http.exportSession(),
      request.signal
    )
  }

  async sync(signal?: AbortSignal): Promise<void> {
    const stretchedKey = this.requireStretchedKey()
    try {
      const payload = await this.http.sync(signal)
      const profile = recordProperty(payload, 'profile')
      if (!profile) throw new BitwardenDirectError('INVALID_RESPONSE')
      const profileId = requiredStringProperty(profile, 'id')
      const securityStamp = nullableStringProperty(profile, 'securityStamp')
      this.assertAccountIdentity(profileId, securityStamp)

      const wrappedUserKey = this.findWrappedUserKey(payload, profile)
      const encodedUserKey = decryptBitwardenBytes(wrappedUserKey, stretchedKey)
      let userKey: BitwardenSymmetricKey
      try {
        userKey = decodeBitwardenUserKey(encodedUserKey)
      } finally {
        encodedUserKey.fill(0)
      }
      await this.validateAccountKeys(profile, userKey)

      const nextFolders = new Map<string, CachedFolder>()
      const nextLogins = new Map<string, CachedLogin>()
      const nextOrganizations = new Map<string, BitwardenOrganization>()
      const nextCollections = new Map<string, BitwardenCollection>()
      const nextOrganizationCiphers = new Map<string, BitwardenOrganizationCipher>()
      const nextSends = new Map<string, CachedSend>()
      const organizationKeys = new Map<string, Buffer>()
      try {
        const folderRows = arrayProperty(payload, 'folders')
        const cipherRows = arrayProperty(payload, 'ciphers')
        const collectionsValue = property(payload, 'collections')
        const collectionRows =
          collectionsValue === undefined || collectionsValue === null
            ? []
            : arrayProperty(payload, 'collections')
        const sendsValue = property(payload, 'sends')
        const sendRows =
          sendsValue === undefined || sendsValue === null ? [] : arrayProperty(payload, 'sends')
        const organizationsValue = property(profile, 'organizationsNew')
        const legacyOrganizationsValue = property(profile, 'organizations')
        const organizationRows = (() => {
          const rows =
            Array.isArray(organizationsValue) && organizationsValue.length > 0
              ? organizationsValue
              : (legacyOrganizationsValue ?? organizationsValue)
          if (rows === undefined || rows === null) return []
          if (!Array.isArray(rows) || rows.length > MAX_REMOTE_ENTITIES) {
            throw new BitwardenDirectError('INVALID_RESPONSE')
          }
          return rows
        })()
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
        const hasOrganizationCiphers = cipherRows.some((value) => {
          if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
          const organizationId = property(value, 'organizationId')
          return organizationId !== undefined && organizationId !== null
        })
        const hasOrganizationEncryptedData = collectionRows.length > 0 || hasOrganizationCiphers
        const accountPrivateKey = hasOrganizationEncryptedData
          ? this.resolveAccountPrivateKey(profile, userKey)
          : null
        for (const [organizationId, rawOrganization] of organizationRowsById) {
          const encryptedKey = stringProperty(rawOrganization, 'key')
          if (!encryptedKey) continue
          if (!accountPrivateKey) throw new BitwardenDirectError('UNSUPPORTED_ACCOUNT_ENCRYPTION')
          const organizationKey = this.decryptOrganizationKey(
            encryptedKey,
            userKey,
            accountPrivateKey
          )
          organizationKeys.set(organizationId, organizationKey)
        }
        let aggregateRows = addAggregateRemoteRows(0, folderRows.length)
        aggregateRows = addAggregateRemoteRows(aggregateRows, cipherRows.length)
        aggregateRows = addAggregateRemoteRows(aggregateRows, collectionRows.length)
        aggregateRows = addAggregateRemoteRows(aggregateRows, sendRows.length)
        for (const value of folderRows) {
          if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
          const item = this.decryptFolder(value, userKey)
          nextFolders.set(item.id, { raw: structuredClone(value), item })
        }
        for (const value of cipherRows) {
          if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
          const type = property(value, 'type')
          const organizationId = property(value, 'organizationId')
          if (organizationId !== null && organizationId !== undefined) {
            if (typeof organizationId !== 'string' || !UUID_PATTERN.test(organizationId)) {
              throw new BitwardenDirectError('INVALID_RESPONSE')
            }
            const organizationKey = organizationKeys.get(organizationId)
            if (!organizationKey || !organizationRowsById.has(organizationId)) {
              throw new BitwardenDirectError('INVALID_RESPONSE')
            }
            if (
              property(value, 'type') !== 1 &&
              property(value, 'type') !== 2 &&
              property(value, 'type') !== 3 &&
              property(value, 'type') !== 4 &&
              property(value, 'type') !== 5
            ) {
              continue
            }
            const item = this.decryptLogin(value, organizationKey)
            const organizationCipher = this.organizationCipher(value, item, organizationId)
            nextOrganizationCiphers.set(organizationCipher.id, organizationCipher)
            aggregateRows = addAggregateRemoteRows(
              aggregateRows,
              item.uris.length +
                item.passkeys.length +
                item.customFields.length +
                item.passwordHistory.length +
                item.attachments.length
            )
            continue
          }
          if (type !== 1 && type !== 2 && type !== 3 && type !== 4 && type !== 5) continue
          const item = this.decryptLogin(value, userKey)
          aggregateRows = addAggregateRemoteRows(
            aggregateRows,
            item.uris.length +
              item.passkeys.length +
              item.customFields.length +
              item.passwordHistory.length +
              item.attachments.length
          )
          nextLogins.set(item.id, { raw: structuredClone(value), item })
        }
        for (const value of collectionRows) {
          if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
          const collection = this.decryptCollection(value, organizationKeys)
          if (nextCollections.has(collection.id)) throw new BitwardenDirectError('INVALID_RESPONSE')
          nextCollections.set(collection.id, collection)
        }
        for (const cipher of nextOrganizationCiphers.values()) {
          for (const collectionId of cipher.collectionIds) {
            const collection = nextCollections.get(collectionId)
            if (!collection || collection.organizationId !== cipher.organizationId) {
              throw new BitwardenDirectError('INVALID_RESPONSE')
            }
          }
        }
        for (const value of sendRows) {
          if (!isRecord(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
          const send = this.decryptSend(value, userKey)
          nextSends.set(send.item.id, send)
        }
      } catch (error) {
        for (const organizationKey of organizationKeys.values()) organizationKey.fill(0)
        clearBitwardenSymmetricKey(userKey)
        throw error
      }

      for (const organizationKey of organizationKeys.values()) organizationKey.fill(0)

      clearBitwardenSymmetricKey(this.userKey)
      this.userKey = userKey
      this.folders = nextFolders
      this.logins = nextLogins
      this.organizations = nextOrganizations
      this.collections = nextCollections
      this.organizationCiphers = nextOrganizationCiphers
      this.sends = nextSends
      this.state.profileId = profileId
      this.state.securityStamp = securityStamp
      this.state.session = this.http.exportSession()
      await this.notifyStateChanged()
    } catch (error) {
      throw this.mapError(error)
    }
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
    twoFactor: BitwardenTwoFactor | undefined,
    newDeviceOtp: string | undefined,
    requestToken: boolean,
    signal?: AbortSignal
  ): Promise<void> {
    let masterKey: Buffer | null = null
    let passwordKey: Buffer | null = null
    let stretched: ReturnType<typeof stretchMasterKey> | null = null
    try {
      const prelogin = await this.http.prelogin(this.email, signal)
      masterKey = await deriveMasterKey(
        password,
        prelogin.salt ?? this.email,
        kdfFromPrelogin(prelogin)
      )
      passwordKey = await derivePasswordKey(masterKey, password)
      stretched = stretchMasterKey(masterKey)
      if (requestToken) {
        const session = await this.http.passwordToken(
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
                  twoFactorToken: twoFactor.code,
                  twoFactorRemember: true
                }
              : {})
          },
          signal
        )
        this.http.setSession(session)
        this.state.session = { ...session }
      }
      this.stretchedKey?.fill(0)
      this.stretchedKey = stretched.combinedKey
      stretched.combinedKey = Buffer.alloc(0)
      await this.notifyStateChanged()
    } catch (error) {
      throw this.mapError(error)
    } finally {
      masterKey?.fill(0)
      passwordKey?.fill(0)
      stretched?.encKey.fill(0)
      stretched?.macKey.fill(0)
      stretched?.combinedKey.fill(0)
    }
  }

  private findWrappedUserKey(payload: JsonObject, profile: JsonObject): string {
    const userDecryption = recordProperty(payload, 'userDecryption')
    const masterPasswordUnlock = userDecryption
      ? recordProperty(userDecryption, 'masterPasswordUnlock')
      : null
    const modern = masterPasswordUnlock
      ? stringProperty(masterPasswordUnlock, 'masterKeyEncryptedUserKey')
      : null
    const legacy = stringProperty(profile, 'key')
    const wrapped = modern ?? legacy
    if (!wrapped) throw new BitwardenDirectError('UNSUPPORTED_ACCOUNT_ENCRYPTION')
    return wrapped
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
    } catch {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
  }

  private decryptFolder(raw: JsonObject, userKey: BitwardenSymmetricKey): BitwardenFolder {
    return {
      id: requiredStringProperty(raw, 'id'),
      name: decryptBitwardenString(requiredStringProperty(raw, 'name'), userKey)
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
      const privateKeyBytes = decryptBitwardenBytes(wrappedPrivateKey, userKey)
      try {
        return createPrivateKey({ key: privateKeyBytes, format: 'der', type: 'pkcs8' })
      } catch {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      } finally {
        privateKeyBytes.fill(0)
      }
    }

    const legacyPrivateKey = stringProperty(profile, 'privateKey') ?? wrappedPrivateKey
    if (!legacyPrivateKey || !Buffer.isBuffer(userKey)) return null
    try {
      return decryptRsaPrivateKey(legacyPrivateKey, userKey)
    } catch {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
  }

  private decryptOrganizationKey(
    encryptedKey: string,
    userKey: BitwardenSymmetricKey,
    privateKey: KeyObject
  ): Buffer {
    const encoded = decryptBitwardenString(encryptedKey, userKey, privateKey)
    if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(encoded) || encoded.length % 4 !== 0) {
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
      const authType = authTypeValue === 1 || authTypeValue === 2 ? authTypeValue : password ? 1 : 2
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
      const password = preservePassword
        ? existingPassword
        : draft.password?.length
          ? draft.password
          : null
      const authType =
        preservePassword && (existingAuthType === 1 || existingAuthType === 2)
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
        emails: null,
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

  private decryptLogin(raw: JsonObject, userKey: BitwardenSymmetricKey): BitwardenLoginItem {
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
        if (!sshKey) throw new BitwardenDirectError('INVALID_RESPONSE')
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
      if (draft.totpChanged) typeData.totp = draft.totp || null
      if (draft.passkeysChanged) {
        typeData.fido2Credentials = draft.passkeys.map(passkeyToBlob)
      }
      typeData.uris = blobUris(draft.uris, previousUris)
      if (!Object.hasOwn(typeData, 'passwordRevisionDate')) typeData.passwordRevisionDate = null
      if (!Object.hasOwn(typeData, 'totp')) typeData.totp = null
      if (!Object.hasOwn(typeData, 'autofillOnPageLoad')) typeData.autofillOnPageLoad = null
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

  private assertAccountIdentity(profileId: string, securityStamp: string | null): void {
    if (this.state.profileId && this.state.profileId !== profileId) {
      throw new BitwardenDirectError('ACCOUNT_CHANGED')
    }
    if (this.state.securityStamp && securityStamp && this.state.securityStamp !== securityStamp) {
      throw new BitwardenDirectError('ACCOUNT_CHANGED')
    }
  }

  private requireStretchedKey(): Buffer {
    if (!this.stretchedKey) throw new BitwardenDirectError('AUTH_REQUIRED')
    return this.stretchedKey
  }

  private requireUserKey(): BitwardenSymmetricKey {
    if (!this.userKey) throw new BitwardenDirectError('AUTH_REQUIRED')
    return this.userKey
  }

  private requireProfileId(): string {
    if (!this.state.profileId) throw new BitwardenDirectError('AUTH_REQUIRED')
    return this.state.profileId
  }

  private async captureSession(): Promise<void> {
    this.state.session = this.http.exportSession()
    await this.notifyStateChanged()
  }

  private async notifyStateChanged(): Promise<void> {
    await this.options.onStateChanged?.(this.exportState())
  }

  private clearDecryptedState(): void {
    this.stretchedKey?.fill(0)
    clearBitwardenSymmetricKey(this.userKey)
    this.stretchedKey = null
    this.userKey = null
    this.folders.clear()
    this.logins.clear()
    this.organizations.clear()
    this.collections.clear()
    this.organizationCiphers.clear()
    this.sends.clear()
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
      if (error.code === 'AUTH') return new BitwardenDirectError('AUTH_REQUIRED')
      if (error.code === 'TWO_FACTOR') return new BitwardenDirectError('TWO_FACTOR_REQUIRED')
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
      if (error.code === 'INVALID_RESPONSE') return new BitwardenDirectError('INVALID_RESPONSE')
      return new BitwardenDirectError('NETWORK')
    }
    return new BitwardenDirectError('INVALID_RESPONSE')
  }
}
