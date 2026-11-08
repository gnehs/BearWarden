/**
 * Per-row codec for `/sync` and cipher write payloads: decrypts folder, cipher, collection,
 * organization and send rows into vault items, and encrypts drafts back into cipher requests.
 * Rows are read case-insensitively; callers keep the raw row to round-trip unknown fields.
 */
import {
  clearBitwardenSymmetricKey,
  decryptBitwardenBytes,
  decryptBitwardenCipherBlob,
  decryptBitwardenString,
  decryptBitwardenWrappedKey,
  encryptBitwardenCipherBlob,
  encryptBitwardenString,
  deriveBitwardenSendKey,
  type BitwardenCipherBlobValue,
  type BitwardenSymmetricKey
} from './bitwarden-crypto'
import { isJsonObject, type JsonObject, type JsonValue } from './bitwarden-http'
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
import { emptyItemFields, type ItemFieldName } from './vault/item-fields'
import {
  MAX_ATTACHMENTS,
  MAX_ATTACHMENT_FILE_NAME_LENGTH,
  MAX_ATTACHMENT_ID_LENGTH,
  MAX_ATTACHMENT_SIZE_NAME_LENGTH,
  MAX_CUSTOM_FIELDS,
  MAX_LOGIN_URIS,
  MAX_NAME_LENGTH,
  MAX_PASSWORD_HISTORY,
  MAX_PASSWORD_LENGTH,
  MAX_REMOTE_ENTITIES,
  MAX_SEND_FILE_ID_LENGTH,
  MAX_SEND_FILE_NAME_LENGTH,
  MAX_SEND_FILE_SIZE,
  MAX_SEND_FILE_SIZE_NAME_LENGTH,
  MAX_URI_LENGTH
} from './vault/limits'
import { readField } from './bitwarden-fields'
import { UUID_PATTERN } from './validation-primitives'
import { BitwardenDirectError, invalidResponse } from './bitwarden-direct-error'

export const USER_KEY_BYTES = 64
export const MAX_CUSTOM_FIELD_STRING_LENGTH = 5_000
const MAX_PASSKEYS_PER_ITEM = 1_000
const MAX_PASSKEY_FIELD_LENGTH = 4_096
const MAX_AGGREGATE_REMOTE_ROWS = 1_000_000

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

/** Plain string fields of card and identity payloads, as item field and wire property. */
const TYPED_STRING_FIELDS: Record<
  'card' | 'identity',
  ReadonlyArray<readonly [Exclude<ItemFieldName, 'uri'>, string]>
> = {
  card: [
    ['cardholderName', 'cardholderName'],
    ['brand', 'brand'],
    ['number', 'number'],
    ['expMonth', 'expMonth'],
    ['expYear', 'expYear'],
    ['code', 'code']
  ],
  identity: [
    ['title', 'title'],
    ['firstName', 'firstName'],
    ['middleName', 'middleName'],
    ['lastName', 'lastName'],
    ['address1', 'address1'],
    ['address2', 'address2'],
    ['address3', 'address3'],
    ['city', 'city'],
    ['state', 'state'],
    ['postalCode', 'postalCode'],
    ['country', 'country'],
    ['company', 'company'],
    ['email', 'email'],
    ['phone', 'phone'],
    ['ssn', 'ssn'],
    ['identityUsername', 'username'],
    ['passportNumber', 'passportNumber'],
    ['licenseNumber', 'licenseNumber']
  ]
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

export interface CachedFolder {
  raw: JsonObject
  item: BitwardenFolder
}

export interface CachedLogin {
  raw: JsonObject
  item: BitwardenLoginItem
}

export interface CachedSend {
  raw: JsonObject
  item: BitwardenSendItem
}

export interface ResolvedBitwardenDraft extends VaultItemFields {
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

export function recordProperty(record: JsonObject, name: string): JsonObject | null {
  const value = readField(record, name)
  return isJsonObject(value) ? value : null
}

export function stringProperty(record: JsonObject, name: string): string | null {
  const value = readField(record, name)
  return typeof value === 'string' ? value : null
}

export function nullableStringProperty(record: JsonObject, name: string): string | null {
  const value = readField(record, name)
  if (value === null || value === undefined) return null
  if (typeof value !== 'string') throw new BitwardenDirectError('INVALID_RESPONSE')
  return value
}

export function requiredStringProperty(record: JsonObject, name: string): string {
  const value = stringProperty(record, name)
  if (!value) throw new BitwardenDirectError('INVALID_RESPONSE')
  return value
}

export function assertUuidValue(value: string): string {
  if (!UUID_PATTERN.test(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
  return value
}

export function booleanProperty(record: JsonObject, name: string, fallback = false): boolean {
  const value = readField(record, name)
  if (value === undefined || value === null) return fallback
  if (typeof value !== 'boolean') throw new BitwardenDirectError('INVALID_RESPONSE')
  return value
}

function nullableBooleanProperty(record: JsonObject, name: string): boolean | null {
  const value = readField(record, name)
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

export function repromptProperty(record: JsonObject): VaultReprompt {
  const value = readField(record, 'reprompt')
  if (value === undefined || value === null) return 0
  if (value !== 0 && value !== 1) throw new BitwardenDirectError('INVALID_RESPONSE')
  return value
}

export function remoteCipherType(record: JsonObject): number {
  const value = readField(record, 'type')
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > 2_147_483_647
  ) {
    throw invalidResponse('unsupported-cipher-type')
  }
  return value
}

export function isSupportedCipherType(value: number): value is BitwardenCipherType {
  return value === 1 || value === 2 || value === 3 || value === 4 || value === 5
}

function bitwardenCipherType(record: JsonObject): BitwardenCipherType {
  const value = remoteCipherType(record)
  if (!isSupportedCipherType(value)) {
    throw invalidResponse('unsupported-cipher-type')
  }
  return value
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

export function customFieldLinkedId(record: JsonObject): number | null {
  const value = readField(record, 'linkedId')
  if (value === undefined || value === null) return null
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value
}

function nullableCustomFieldString(record: JsonObject, name: string): string | null {
  const value = readField(record, name)
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

/** `decode` decrypts legacy per-field strings, or is the identity for V2 blob content. */
function parseRemoteCustomFields(
  rawFields: JsonValue | undefined,
  decode: (value: string) => string
): VaultCustomField[] {
  return customFieldArray(rawFields).map((rawField) => {
    if (!isJsonObject(rawField)) throw new BitwardenDirectError('INVALID_RESPONSE')
    const name = nullableCustomFieldString(rawField, 'name')
    const value = nullableCustomFieldString(rawField, 'value')
    return {
      name: name === null ? '' : decode(name),
      value: value === null ? '' : decode(value),
      type: customFieldType(readField(rawField, 'type')),
      linkedId: customFieldLinkedId(rawField)
    }
  })
}

function customFieldsToWire(
  fields: VaultCustomField[],
  encode: (value: string) => string
): JsonValue[] {
  return fields.map((field) => ({
    name: encode(field.name),
    value: field.type === 'linked' ? null : encode(field.value),
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

export function normalizedBitwardenTimestamp(value: unknown): string {
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

function checkedHistoryPassword(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_PASSWORD_LENGTH) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value
}

/** `password` reads, and for legacy rows decrypts, the plaintext password of one entry. */
export function parsePasswordHistory(
  value: JsonValue | undefined,
  password: (entry: JsonObject) => unknown
): VaultPasswordHistoryEntry[] {
  return passwordHistoryArray(value).map((raw) => {
    if (!isJsonObject(raw)) throw new BitwardenDirectError('INVALID_RESPONSE')
    return {
      password: checkedHistoryPassword(password(raw)),
      lastUsedDate: normalizedBitwardenTimestamp(readField(raw, 'lastUsedDate'))
    }
  })
}

export function plainHistoryPassword(entry: JsonObject): unknown {
  return readField(entry, 'password')
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

function attachmentSize(record: JsonObject): number {
  const value = readField(record, 'size')
  if (value === undefined || value === null) return 0
  if (typeof value !== 'string' || !/^(0|[1-9]\d*)$/u.test(value)) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  const size = Number(value)
  if (!Number.isSafeInteger(size) || size < 0) throw new BitwardenDirectError('INVALID_RESPONSE')
  return size
}

function attachmentSizeName(record: JsonObject, size: number): string {
  const value = readField(record, 'sizeName')
  if (value === undefined || value === null) return `${size} B`
  if (typeof value !== 'string' || value.length > MAX_ATTACHMENT_SIZE_NAME_LENGTH) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value
}

function decryptAttachments(raw: JsonObject, key: BitwardenSymmetricKey): BitwardenAttachment[] {
  const value = readField(raw, 'attachments')
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
    const attachmentKey = readField(details, 'key')
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
    if (value.length > MAX_ATTACHMENTS) throw new BitwardenDirectError('INVALID_RESPONSE')
    const attachments = value.map((entry) => {
      if (!isJsonObject(entry)) throw new BitwardenDirectError('INVALID_RESPONSE')
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
  if (!isJsonObject(value)) throw new BitwardenDirectError('INVALID_RESPONSE')

  const detailsValue = readField(raw, 'attachments2')
  if (detailsValue !== undefined && detailsValue !== null && !isJsonObject(detailsValue)) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  const entries = Object.entries(value)
  if (entries.length > MAX_ATTACHMENTS) throw new BitwardenDirectError('INVALID_RESPONSE')
  const attachments = entries.map(([id, encryptedFileName]) => {
    if (!id || typeof encryptedFileName !== 'string' || !encryptedFileName) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    const details = detailsValue ? detailsValue[id] : undefined
    if (details !== undefined && !isJsonObject(details))
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
    throw invalidResponse('snapshot-limit')
  }
  return current + additional
}

export function rawCipherNestedRows(raw: JsonObject): number {
  let rows = 0
  const addArray = (value: JsonValue | undefined): void => {
    if (Array.isArray(value)) rows = addAggregateRemoteRows(rows, value.length)
  }
  addArray(readField(raw, 'fields'))
  addArray(readField(raw, 'passwordHistory'))
  addArray(readField(raw, 'collectionIds'))
  const attachments = readField(raw, 'attachments')
  if (Array.isArray(attachments)) {
    rows = addAggregateRemoteRows(rows, attachments.length)
  } else if (isJsonObject(attachments)) {
    rows = addAggregateRemoteRows(rows, Object.keys(attachments).length)
  }
  const attachmentDetails = readField(raw, 'attachments2')
  if (isJsonObject(attachmentDetails)) {
    rows = addAggregateRemoteRows(rows, Object.keys(attachmentDetails).length)
  }
  const login = recordProperty(raw, 'login')
  if (login) {
    addArray(readField(login, 'uris'))
    addArray(readField(login, 'fido2Credentials'))
  }
  return rows
}

export function parsedCipherNestedRows(item: BitwardenLoginItem): number {
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
  addArray(readField(content, 'fields'))
  addArray(readField(content, 'passwordHistory'))
  const typeData = recordProperty(content, 'typeData')
  if (typeData) {
    addArray(readField(typeData, 'uris'))
    addArray(readField(typeData, 'fido2Credentials'))
  }
  return rows
}

/** Send file sizes arrive as a decimal string or a number. NaN marks an invalid value. */
export function sendFileSize(value: JsonValue | undefined): number {
  if (typeof value === 'string' && /^\d+$/u.test(value)) return Number(value)
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value
  return NaN
}

function optionalJson(record: JsonObject, name: string): JsonValue | undefined {
  const value = readField(record, name)
  return value === undefined ? undefined : structuredClone(value)
}

function setOptional(target: JsonObject, name: string, value: JsonValue | undefined): void {
  if (value !== undefined) target[name] = value
}

/**
 * Reuses each unchanged previous URI row verbatim, because a row checksum is valid only for its
 * exact plaintext. New or changed rows come from `newRow` and deliberately omit a checksum.
 */
function preservedUriRows(
  previous: JsonValue | undefined,
  uris: readonly VaultLoginUri[],
  decode: (value: string) => string,
  newRow: (entry: VaultLoginUri) => JsonObject
): JsonValue[] {
  if (
    previous !== null &&
    previous !== undefined &&
    (!Array.isArray(previous) || previous.length > MAX_LOGIN_URIS)
  ) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  const preserved = new Map<string, { rows: JsonObject[]; next: number }>()
  for (const value of Array.isArray(previous) ? previous : []) {
    if (!isJsonObject(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
    const uri = nullableStringProperty(value, 'uri')
    const matchKey = uriRowKey(
      uri === null ? '' : decode(uri),
      validateUriMatch(readField(value, 'match'))
    )
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
    return newRow(entry)
  })
}

/** `decode` decrypts legacy URI strings, or is the identity for V2 blob content. */
function parseRemoteUris(
  value: JsonValue | undefined,
  decode: (value: string) => string
): VaultLoginUri[] {
  if (
    value !== undefined &&
    value !== null &&
    (!Array.isArray(value) || value.length > MAX_LOGIN_URIS)
  ) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return (Array.isArray(value) ? value : []).map((row) => {
    if (!isJsonObject(row)) throw new BitwardenDirectError('INVALID_RESPONSE')
    const encoded = nullableStringProperty(row, 'uri')
    const uri = encoded === null ? '' : decode(encoded)
    if (uri.length > MAX_URI_LENGTH) throw new BitwardenDirectError('INVALID_RESPONSE')
    return { uri, match: validateUriMatch(readField(row, 'match')) }
  })
}

function uriRowKey(uri: string, match: VaultLoginUri['match']): string {
  return `${match === null ? 'null' : match}:${uri}`
}

function preservedAttachments(existing: JsonObject, request: JsonObject): void {
  const value = readField(existing, 'attachments')
  if (value === undefined) return
  if (!Array.isArray(value)) {
    request.attachments = structuredClone(value)
    return
  }
  const revisionDate = optionalJson(existing, 'revisionDate') ?? null
  const attachments: JsonObject = {}
  const attachments2: JsonObject = {}
  for (const entry of value) {
    if (!isJsonObject(entry)) throw new BitwardenDirectError('INVALID_RESPONSE')
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
  const data = readField(record, 'data')
  if (typeof data !== 'string' || !data) return null
  if (data.trimStart().startsWith('{')) {
    let container: unknown
    try {
      container = JSON.parse(data)
    } catch {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    if (!isJsonObject(container) || readField(container, 'format_version') !== 1) return null
    if (
      typeof readField(container, 'wrapped_cek') !== 'string' ||
      typeof readField(container, 'envelope') !== 'string'
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
    creationDate: normalizedBitwardenTimestamp(passkey.creationDate)
  }
}

function decryptFido2Credentials(
  login: JsonObject,
  key: BitwardenSymmetricKey
): StoredPasskeyCredential[] {
  const raw = readField(login, 'fido2Credentials')
  if (raw === null || raw === undefined) return []
  if (!Array.isArray(raw) || raw.length > MAX_PASSKEYS_PER_ITEM) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return raw.map((value) => {
    if (!isJsonObject(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
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
  const raw = readField(typeData, 'fido2Credentials')
  if (raw === null || raw === undefined) return []
  if (!Array.isArray(raw) || raw.length > MAX_PASSKEYS_PER_ITEM) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return raw.map((value) => {
    if (!isJsonObject(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
    const counter = readField(value, 'counter')
    const discoverable = readField(value, 'discoverable')
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

export function decryptFolder(raw: JsonObject, userKey: BitwardenSymmetricKey): BitwardenFolder {
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

export function parseOrganization(raw: JsonObject): BitwardenOrganization {
  const id = assertUuidValue(requiredStringProperty(raw, 'id'))
  const name = requiredStringProperty(raw, 'name')
  if (name.length > MAX_NAME_LENGTH) throw new BitwardenDirectError('INVALID_RESPONSE')
  const statusValue = readField(raw, 'status')
  const typeValue = readField(raw, 'type')
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

export function decryptCollection(
  raw: JsonObject,
  organizationKeys: ReadonlyMap<string, Buffer>
): BitwardenCollection {
  const id = assertUuidValue(requiredStringProperty(raw, 'id'))
  const organizationId = assertUuidValue(requiredStringProperty(raw, 'organizationId'))
  const organizationKey = organizationKeys.get(organizationId)
  if (!organizationKey) throw new BitwardenDirectError('INVALID_RESPONSE')
  const name = decryptBitwardenString(requiredStringProperty(raw, 'name'), organizationKey)
  if (name.length > MAX_NAME_LENGTH) throw new BitwardenDirectError('INVALID_RESPONSE')
  const type = readField(raw, 'type')
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

export function organizationCipher(
  raw: JsonObject,
  item: BitwardenLoginItem,
  organizationId: string
): BitwardenOrganizationCipher {
  const collectionIdsValue = readField(raw, 'collectionIds')
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

export function decryptSend(raw: JsonObject, userKey: BitwardenSymmetricKey): CachedSend {
  const type = readField(raw, 'type')
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
    const notesValue = readField(raw, 'notes')
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
    const authTypeValue = readField(raw, 'authType')
    const password = nullableStringProperty(raw, 'password')
    const authType =
      authTypeValue === 0 || authTypeValue === 1 || authTypeValue === 2
        ? authTypeValue
        : password
          ? 1
          : 2
    const maxAccessCountValue = readField(raw, 'maxAccessCount')
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
    const accessCount = readField(raw, 'accessCount')
    if (typeof accessCount !== 'number' || !Number.isSafeInteger(accessCount) || accessCount < 0) {
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
      const size = sendFileSize(readField(file, 'size'))
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

export function decryptLogin(
  raw: JsonObject,
  userKey: BitwardenSymmetricKey,
  onBlobNestedRows?: (rows: number) => void
): BitwardenLoginItem {
  const wireType = bitwardenCipherType(raw)
  const itemType = ITEM_TYPE_BY_WIRE_TYPE[wireType]
  const key = cipherKey(raw, userKey)
  try {
    const attachments = decryptAttachments(raw, key)
    const sealedBlob = opaqueCipherBlob(raw)
    if (sealedBlob !== null) {
      if (!Buffer.isBuffer(key)) throw new BitwardenDirectError('INVALID_RESPONSE')
      const content = decryptBitwardenCipherBlob(sealedBlob, key)
      if (!isJsonObject(content)) throw new BitwardenDirectError('INVALID_RESPONSE')
      onBlobNestedRows?.(decodedBlobNestedRows(content))
      return decryptBlobLogin(raw, content, wireType, attachments)
    }
    const notes = nullableStringProperty(raw, 'notes')
    const item: BitwardenLoginItem = {
      ...emptyItemFields(),
      id: requiredStringProperty(raw, 'id'),
      type: itemType,
      organizationId: null,
      folderId: nullableStringProperty(raw, 'folderId'),
      name: decryptBitwardenString(requiredStringProperty(raw, 'name'), key),
      notes: notes === null ? null : decryptBitwardenString(notes, key),
      favorite: booleanProperty(raw, 'favorite'),
      uris: [],
      customFields: parseRemoteCustomFields(readField(raw, 'fields'), (value) =>
        decryptBitwardenString(value, key)
      ),
      passkeys: [],
      passwordHistory: parsePasswordHistory(readField(raw, 'passwordHistory'), (entry) =>
        decryptBitwardenString(requiredStringProperty(entry, 'password'), key)
      ),
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
      item.uris = parseRemoteUris(readField(login, 'uris'), (value) =>
        decryptBitwardenString(value, key)
      )
      item.uri = item.uris[0]?.uri ?? null
    } else if (itemType === 'card' || itemType === 'identity') {
      const typed = recordProperty(raw, itemType)
      if (!typed) throw new BitwardenDirectError('INVALID_RESPONSE')
      for (const [field, wireName] of TYPED_STRING_FIELDS[itemType]) {
        item[field] = decryptOptionalString(typed, wireName, key)
      }
    } else if (itemType === 'secureNote') {
      const secureNote = recordProperty(raw, 'secureNote')
      const secureNoteType = secureNote ? readField(secureNote, 'type') : undefined
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

function decryptBlobLogin(
  raw: JsonObject,
  content: JsonObject,
  wireType: BitwardenCipherType,
  attachments: BitwardenAttachment[]
): BitwardenLoginItem {
  const itemType = ITEM_TYPE_BY_WIRE_TYPE[wireType]
  const typeData = recordProperty(content, 'typeData')
  if (!typeData || stringProperty(typeData, 'type') !== itemType) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  const item: BitwardenLoginItem = {
    ...emptyItemFields(),
    id: requiredStringProperty(raw, 'id'),
    type: itemType,
    organizationId: null,
    folderId: nullableStringProperty(raw, 'folderId'),
    name: requiredStringProperty(content, 'name'),
    notes: nullableStringProperty(content, 'notes'),
    favorite: booleanProperty(raw, 'favorite'),
    uris: [],
    customFields: parseRemoteCustomFields(readField(content, 'fields'), (value) => value),
    passkeys: [],
    passwordHistory: parsePasswordHistory(
      readField(content, 'passwordHistory'),
      plainHistoryPassword
    ),
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
    item.uris = parseRemoteUris(readField(typeData, 'uris'), (value) => value)
    item.uri = item.uris[0]?.uri ?? null
  } else if (itemType === 'card' || itemType === 'identity') {
    for (const [field, wireName] of TYPED_STRING_FIELDS[itemType]) {
      item[field] = nullableStringProperty(typeData, wireName) ?? ''
    }
  } else if (itemType === 'secureNote') {
    if (!Number.isSafeInteger(readField(typeData, 'secureNoteType'))) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
  } else {
    item.privateKey = requiredStringProperty(typeData, 'privateKey')
    item.publicKey = requiredStringProperty(typeData, 'publicKey')
    item.fingerprint = requiredStringProperty(typeData, 'fingerprint')
  }
  return item
}

export function cipherKey(raw: JsonObject, userKey: BitwardenSymmetricKey): BitwardenSymmetricKey {
  const wrappedKey = nullableStringProperty(raw, 'key')
  if (wrappedKey === null) return userKey
  const key = decryptBitwardenWrappedKey(wrappedKey, userKey)
  if (key.length !== USER_KEY_BYTES) {
    key.fill(0)
    throw new BitwardenDirectError('UNSUPPORTED_ACCOUNT_ENCRYPTION')
  }
  return key
}

/** The account a login request is encrypted for. A non-legacy user key stores new logins as blobs. */
export interface LoginRequestAccount {
  userKey: BitwardenSymmetricKey | null
  requireProfileId: () => string
}

export function encryptLoginRequest(
  draft: ResolvedBitwardenDraft,
  key: BitwardenSymmetricKey,
  existing: JsonObject | null,
  account: LoginRequestAccount
): JsonObject {
  const useBlob =
    Buffer.isBuffer(key) &&
    (existing === null ? !Buffer.isBuffer(account.userKey) : opaqueCipherBlob(existing) !== null)
  if (useBlob) return encryptBlobLoginRequest(draft, key, existing, account)

  const wireType = WIRE_TYPE_BY_ITEM_TYPE[draft.type]
  const nestedName = draft.type
  const previousType = existing ? readField(existing, 'type') : null
  const previousTypeData =
    existing && previousType === wireType ? recordProperty(existing, nestedName) : null
  const typeData: JsonObject = previousTypeData ? structuredClone(previousTypeData) : {}
  const previousFields = existing ? optionalJson(existing, 'fields') : undefined
  const request: JsonObject = {
    type: wireType,
    encryptedFor: account.requireProfileId(),
    organizationId: null,
    folderId: draft.folderId,
    name: encryptBitwardenString(draft.name, key),
    notes: draft.notes === null ? null : encryptBitwardenString(draft.notes, key),
    favorite: draft.favorite,
    archivedDate: draft.archivedAt,
    reprompt: draft.reprompt,
    key: existing ? (readField(existing, 'key') ?? null) : null,
    fields:
      existing && !draft.customFieldsChanged
        ? previousFields === undefined
          ? []
          : previousFields
        : customFieldsToWire(draft.customFields, (value) => encryptBitwardenString(value, key)),
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
    typeData.uris = preservedUriRows(
      previousTypeData ? readField(previousTypeData, 'uris') : null,
      draft.uris,
      (value) => decryptBitwardenString(value, key),
      (entry) => ({ uri: encryptBitwardenString(entry.uri, key), match: entry.match })
    )
  } else if (draft.type === 'card' || draft.type === 'identity') {
    for (const [field, wireName] of TYPED_STRING_FIELDS[draft.type]) {
      typeData[wireName] = encryptBitwardenString(draft[field], key)
    }
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

function encryptBlobLoginRequest(
  draft: ResolvedBitwardenDraft,
  key: Buffer,
  existing: JsonObject | null,
  account: LoginRequestAccount
): JsonObject {
  let content: JsonObject
  if (existing) {
    const sealedBlob = opaqueCipherBlob(existing)
    if (!sealedBlob) throw new BitwardenDirectError('INVALID_RESPONSE')
    const decrypted = decryptBitwardenCipherBlob(sealedBlob, key)
    if (!isJsonObject(decrypted)) throw new BitwardenDirectError('INVALID_RESPONSE')
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
  const expectedTag = draft.type
  const existingTypeData = recordProperty(content, 'typeData')
  const typeData: JsonObject =
    existingTypeData && stringProperty(existingTypeData, 'type') === expectedTag
      ? structuredClone(existingTypeData)
      : {}
  typeData.type = expectedTag

  if (draft.type === 'login') {
    const previousUris = readField(typeData, 'uris')
    typeData.username = draft.username
    typeData.password = draft.password
    typeData.passwordRevisionDate = draft.passwordRevisionDate
    typeData.autofillOnPageLoad = draft.autofillOnPageLoad
    if (draft.totpChanged) typeData.totp = draft.totp || null
    if (draft.passkeysChanged) {
      typeData.fido2Credentials = draft.passkeys.map(passkeyToBlob)
    }
    typeData.uris = preservedUriRows(
      previousUris,
      draft.uris,
      (value) => value,
      (entry) => ({ uri: entry.uri, match: entry.match })
    )
    if (!Object.hasOwn(typeData, 'totp')) typeData.totp = null
    if (!Object.hasOwn(typeData, 'fido2Credentials')) typeData.fido2Credentials = []
  } else if (draft.type === 'card' || draft.type === 'identity') {
    for (const [field, wireName] of TYPED_STRING_FIELDS[draft.type]) {
      typeData[wireName] = draft[field]
    }
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
  if (draft.customFieldsChanged)
    content.fields = customFieldsToWire(draft.customFields, (value) => value)
  if (draft.passwordHistoryChanged) {
    content.passwordHistory = passwordHistoryToBlob(draft.passwordHistory)
  }

  const request: JsonObject = {
    type: WIRE_TYPE_BY_ITEM_TYPE[draft.type],
    encryptedFor: account.requireProfileId(),
    organizationId: null,
    folderId: draft.folderId,
    name: encryptBitwardenString('', key),
    notes: null,
    favorite: draft.favorite,
    archivedDate: draft.archivedAt,
    reprompt: draft.reprompt,
    key: existing ? (readField(existing, 'key') ?? null) : null,
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
