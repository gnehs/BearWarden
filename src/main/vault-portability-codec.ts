import { randomBytes, randomUUID } from 'node:crypto'
import type {
  VaultCustomField,
  VaultCustomFieldType,
  VaultItemFields,
  VaultItemType,
  VaultLoginUri,
  VaultPasswordHistoryEntry,
  VaultReprompt
} from '../shared/vault-contract'
import { VAULT_LINKED_FIELD_IDS_BY_TYPE } from '../shared/vault-contract'
import {
  decryptBitwardenString,
  deriveMasterKey,
  derivePbkdf2Sha256,
  encryptBitwardenString,
  stretchMasterKey
} from './bitwarden-crypto'
import type { StoredPasskeyCredential } from './passkey'
import type { SyncLogin } from './sync-merge'
import { VaultError } from './vault-errors'

export interface PortableVaultFolder {
  id: string
  name: string
  updatedAt?: string
}

export type PortableVaultItem = SyncLogin

export interface PortableVaultSnapshot {
  folders: PortableVaultFolder[]
  items: PortableVaultItem[]
}

type JsonObject = Record<string, unknown>

const MAX_JSON_BYTES = 64 * 1024 * 1024
const MAX_ENTITIES = 100_000
const MAX_ID_LENGTH = 256
const MAX_NAME_LENGTH = 256
const MAX_USERNAME_LENGTH = 512
const MAX_PASSWORD_LENGTH = 16_384
const MAX_URI_LENGTH = 4_096
const MAX_LOGIN_URIS = 1_000
const MAX_NOTES_LENGTH = 65_536
const MAX_ITEM_FIELD_LENGTH = 4_096
const MAX_CUSTOM_FIELDS = 1_000
const MAX_CUSTOM_FIELD_LENGTH = 5_000
const MAX_PASSKEYS = 1_000
const MAX_PASSKEY_FIELD_LENGTH = 4_096
const MAX_PASSWORD_HISTORY = 5
const MAX_SSH_PRIVATE_KEY_LENGTH = 1024 * 1024
const EXPORT_KDF_ITERATIONS = 600_000
const MIN_PBKDF2_ITERATIONS = 5_000
const MAX_PBKDF2_ITERATIONS = 10_000_000
const MIN_ARGON2_ITERATIONS = 2
const MAX_ARGON2_ITERATIONS = 100
const MIN_ARGON2_MEMORY_MIB = 16
const MAX_ARGON2_MEMORY_MIB = 1_024
const MAX_ARGON2_PARALLELISM = 64
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const WIRE_TYPE_BY_ITEM_TYPE = {
  login: 1,
  secureNote: 2,
  card: 3,
  identity: 4,
  sshKey: 5
} as const satisfies Record<VaultItemType, number>

const ITEM_TYPE_BY_WIRE_TYPE = {
  1: 'login',
  2: 'secureNote',
  3: 'card',
  4: 'identity',
  5: 'sshKey'
} as const

const WIRE_TYPE_BY_CUSTOM_FIELD_TYPE = {
  text: 0,
  hidden: 1,
  boolean: 2,
  linked: 3
} as const satisfies Record<VaultCustomFieldType, number>

const CUSTOM_FIELD_TYPE_BY_WIRE_TYPE = {
  0: 'text',
  1: 'hidden',
  2: 'boolean',
  3: 'linked'
} as const

function invalidInput(): never {
  throw new VaultError('INVALID_INPUT')
}

function isRecord(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function record(value: unknown): JsonObject {
  if (!isRecord(value)) invalidInput()
  return value
}

function array(value: unknown, maximum: number): unknown[] {
  if (!Array.isArray(value) || value.length > maximum) invalidInput()
  return value
}

function string(value: unknown, maximum: number, allowEmpty = true): string {
  if (typeof value !== 'string' || value.length > maximum || (!allowEmpty && value.length === 0)) {
    invalidInput()
  }
  return value
}

function optionalString(value: unknown, maximum: number): string {
  if (value === undefined || value === null) return ''
  return string(value, maximum)
}

function nullableString(value: unknown, maximum: number): string | null {
  if (value === undefined || value === null) return null
  return string(value, maximum)
}

function isoDate(value: unknown): string {
  const result = string(value, 64, false)
  if (!Number.isFinite(Date.parse(result)) || new Date(result).toISOString() !== result) {
    invalidInput()
  }
  return result
}

function optionalIsoDate(value: unknown): string | undefined {
  return value === undefined || value === null ? undefined : isoDate(value)
}

function nullableIsoDate(value: unknown): string | null {
  return value === undefined || value === null ? null : isoDate(value)
}

function boolean(value: unknown, fallback = false): boolean {
  if (value === undefined || value === null) return fallback
  if (typeof value !== 'boolean') invalidInput()
  return value
}

function reprompt(value: unknown): VaultReprompt {
  if (value === undefined || value === null) return 0
  if (value !== 0 && value !== 1) invalidInput()
  return value
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

function parseUris(value: unknown): VaultLoginUri[] {
  if (value === undefined || value === null) return []
  return array(value, MAX_LOGIN_URIS).map((raw) => {
    const uri = record(raw)
    const match = uri.match === undefined || uri.match === null ? null : uri.match
    if (
      match !== null &&
      match !== 0 &&
      match !== 1 &&
      match !== 2 &&
      match !== 3 &&
      match !== 4 &&
      match !== 5
    ) {
      invalidInput()
    }
    return { uri: string(uri.uri, MAX_URI_LENGTH, false), match }
  })
}

function parsePasskeys(value: unknown): StoredPasskeyCredential[] {
  if (value === undefined || value === null) return []
  return array(value, MAX_PASSKEYS).map((raw) => {
    const passkey = record(raw)
    const counter = string(passkey.counter, MAX_PASSKEY_FIELD_LENGTH, false)
    if (!/^\d+$/.test(counter)) invalidInput()
    const discoverable =
      passkey.discoverable === true || passkey.discoverable === 'true'
        ? true
        : passkey.discoverable === false || passkey.discoverable === 'false'
          ? false
          : invalidInput()
    return {
      credentialId: string(passkey.credentialId, MAX_PASSKEY_FIELD_LENGTH, false),
      keyType: string(passkey.keyType, MAX_PASSKEY_FIELD_LENGTH, false),
      keyAlgorithm: string(passkey.keyAlgorithm, MAX_PASSKEY_FIELD_LENGTH, false),
      keyCurve: string(passkey.keyCurve, MAX_PASSKEY_FIELD_LENGTH, false),
      keyValue: string(passkey.keyValue, MAX_PASSKEY_FIELD_LENGTH, false),
      rpId: string(passkey.rpId, MAX_PASSKEY_FIELD_LENGTH, false),
      userHandle: nullableString(passkey.userHandle, MAX_PASSKEY_FIELD_LENGTH),
      userName: nullableString(passkey.userName, MAX_PASSKEY_FIELD_LENGTH),
      counter,
      rpName: nullableString(passkey.rpName, MAX_PASSKEY_FIELD_LENGTH),
      userDisplayName: nullableString(passkey.userDisplayName, MAX_PASSKEY_FIELD_LENGTH),
      discoverable,
      creationDate: isoDate(passkey.creationDate)
    }
  })
}

function parseCustomFields(value: unknown, itemType: VaultItemType): VaultCustomField[] {
  if (value === undefined || value === null) return []
  return array(value, MAX_CUSTOM_FIELDS).map((raw) => {
    const field = record(raw)
    if (field.type !== 0 && field.type !== 1 && field.type !== 2 && field.type !== 3) {
      invalidInput()
    }
    const fieldType = CUSTOM_FIELD_TYPE_BY_WIRE_TYPE[field.type]
    const linkedId = field.linkedId === undefined || field.linkedId === null ? null : field.linkedId
    if (linkedId !== null && (!Number.isSafeInteger(linkedId) || (linkedId as number) < 0)) {
      invalidInput()
    }
    if (
      (fieldType === 'linked' &&
        (linkedId === null ||
          !(VAULT_LINKED_FIELD_IDS_BY_TYPE[itemType] as readonly number[]).includes(
            linkedId as number
          ))) ||
      (fieldType !== 'linked' && linkedId !== null)
    ) {
      invalidInput()
    }
    return {
      name: optionalString(field.name, MAX_CUSTOM_FIELD_LENGTH),
      value: fieldType === 'linked' ? '' : optionalString(field.value, MAX_CUSTOM_FIELD_LENGTH),
      type: fieldType,
      linkedId: linkedId as number | null
    }
  })
}

function parsePasswordHistory(value: unknown): VaultPasswordHistoryEntry[] {
  if (value === undefined || value === null) return []
  return array(value, MAX_PASSWORD_HISTORY).map((raw) => {
    const entry = record(raw)
    return {
      password: string(entry.password, MAX_PASSWORD_LENGTH, false),
      lastUsedDate: isoDate(entry.lastUsedDate)
    }
  })
}

function parseTypeData(
  raw: JsonObject,
  type: VaultItemType
): {
  fields: VaultItemFields
  uris: VaultLoginUri[]
  passkeys: StoredPasskeyCredential[]
} {
  const fields = emptyItemFields()
  let uris: VaultLoginUri[] = []
  let passkeys: StoredPasskeyCredential[] = []
  if (type === 'login') {
    const login = record(raw.login)
    fields.username = optionalString(login.username, MAX_USERNAME_LENGTH)
    fields.password = optionalString(login.password, MAX_PASSWORD_LENGTH)
    fields.totp = optionalString(login.totp, MAX_PASSWORD_LENGTH)
    uris = parseUris(login.uris)
    fields.uri = uris[0]?.uri ?? null
    passkeys = parsePasskeys(login.fido2Credentials)
  } else if (type === 'card') {
    const card = record(raw.card)
    fields.cardholderName = optionalString(card.cardholderName, MAX_ITEM_FIELD_LENGTH)
    fields.brand = optionalString(card.brand, MAX_ITEM_FIELD_LENGTH)
    fields.number = optionalString(card.number, MAX_ITEM_FIELD_LENGTH)
    fields.expMonth = optionalString(card.expMonth, MAX_ITEM_FIELD_LENGTH)
    fields.expYear = optionalString(card.expYear, MAX_ITEM_FIELD_LENGTH)
    fields.code = optionalString(card.code, MAX_ITEM_FIELD_LENGTH)
  } else if (type === 'identity') {
    const identity = record(raw.identity)
    const names = [
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
      'passportNumber',
      'licenseNumber'
    ] as const
    for (const name of names) fields[name] = optionalString(identity[name], MAX_ITEM_FIELD_LENGTH)
    fields.identityUsername = optionalString(identity.username, MAX_USERNAME_LENGTH)
  } else if (type === 'secureNote') {
    const secureNote = record(raw.secureNote)
    if (secureNote.type !== undefined && secureNote.type !== 0) invalidInput()
  } else {
    const sshKey = record(raw.sshKey)
    fields.privateKey = optionalString(sshKey.privateKey, MAX_SSH_PRIVATE_KEY_LENGTH)
    fields.publicKey = optionalString(sshKey.publicKey, MAX_ITEM_FIELD_LENGTH)
    fields.fingerprint = optionalString(sshKey.keyFingerprint, MAX_ITEM_FIELD_LENGTH)
  }
  return { fields, uris, passkeys }
}

function parseItem(rawValue: unknown, folderIds: ReadonlySet<string>): PortableVaultItem | null {
  const raw = record(rawValue)
  const deletedAt = nullableIsoDate(raw.deletedDate)
  if (deletedAt !== null) return null
  if (raw.type !== 1 && raw.type !== 2 && raw.type !== 3 && raw.type !== 4 && raw.type !== 5) {
    invalidInput()
  }
  const type = ITEM_TYPE_BY_WIRE_TYPE[raw.type]
  const id = string(raw.id, MAX_ID_LENGTH, false)
  const folderId = nullableString(raw.folderId, MAX_ID_LENGTH)
  if (folderId !== null && !folderIds.has(folderId)) invalidInput()
  const { fields, uris, passkeys } = parseTypeData(raw, type)
  return {
    ...fields,
    id,
    type,
    name: string(raw.name, MAX_NAME_LENGTH, false),
    notes: nullableString(raw.notes, MAX_NOTES_LENGTH),
    folderId,
    favorite: boolean(raw.favorite),
    createdAt: optionalIsoDate(raw.creationDate),
    updatedAt: optionalIsoDate(raw.revisionDate),
    deletedAt: null,
    archivedAt: nullableIsoDate(raw.archivedDate),
    reprompt: reprompt(raw.reprompt),
    uris,
    passkeys,
    customFields: parseCustomFields(raw.fields, type),
    passwordHistory: parsePasswordHistory(raw.passwordHistory)
  }
}

function parseJson(text: string): unknown {
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > MAX_JSON_BYTES) invalidInput()
  try {
    return JSON.parse(text)
  } catch {
    invalidInput()
  }
}

export function parseBitwardenJson(text: string): {
  snapshot: PortableVaultSnapshot
  skippedTrashItems: number
} {
  const root = record(parseJson(text))
  if (root.encrypted !== false) invalidInput()
  const rawFolders = array(root.folders, MAX_ENTITIES)
  const rawItems = array(root.items, MAX_ENTITIES)
  const folderIds = new Set<string>()
  const folders = rawFolders.map((raw): PortableVaultFolder => {
    const folder = record(raw)
    const id = string(folder.id, MAX_ID_LENGTH, false)
    if (folderIds.has(id)) invalidInput()
    folderIds.add(id)
    return { id, name: string(folder.name, MAX_NAME_LENGTH, false) }
  })
  const items: PortableVaultItem[] = []
  let skippedTrashItems = 0
  for (const raw of rawItems) {
    const item = parseItem(raw, folderIds)
    if (item === null) skippedTrashItems += 1
    else items.push(item)
  }
  return { snapshot: { folders, items }, skippedTrashItems }
}

function exportPasskey(passkey: StoredPasskeyCredential): JsonObject {
  return {
    credentialId: passkey.credentialId,
    keyType: passkey.keyType,
    keyAlgorithm: passkey.keyAlgorithm,
    keyCurve: passkey.keyCurve,
    keyValue: passkey.keyValue,
    rpId: passkey.rpId,
    userHandle: passkey.userHandle,
    userName: passkey.userName,
    counter: passkey.counter,
    rpName: passkey.rpName,
    userDisplayName: passkey.userDisplayName,
    discoverable: String(passkey.discoverable),
    creationDate: passkey.creationDate
  }
}

function exportTypeData(item: PortableVaultItem): JsonObject {
  switch (item.type) {
    case 'login':
      return {
        login: {
          uris: item.uris.map((uri) => ({ uri: uri.uri, match: uri.match })),
          username: item.username,
          password: item.password,
          totp: item.totp,
          fido2Credentials: item.passkeys.map(exportPasskey)
        }
      }
    case 'secureNote':
      return { secureNote: { type: 0 } }
    case 'card':
      return {
        card: {
          cardholderName: item.cardholderName,
          brand: item.brand,
          number: item.number,
          expMonth: item.expMonth,
          expYear: item.expYear,
          code: item.code
        }
      }
    case 'identity':
      return {
        identity: {
          title: item.title,
          firstName: item.firstName,
          middleName: item.middleName,
          lastName: item.lastName,
          address1: item.address1,
          address2: item.address2,
          address3: item.address3,
          city: item.city,
          state: item.state,
          postalCode: item.postalCode,
          country: item.country,
          company: item.company,
          email: item.email,
          phone: item.phone,
          ssn: item.ssn,
          username: item.identityUsername,
          passportNumber: item.passportNumber,
          licenseNumber: item.licenseNumber
        }
      }
    case 'sshKey':
      return {
        sshKey: {
          privateKey: item.privateKey,
          publicKey: item.publicKey,
          keyFingerprint: item.fingerprint
        }
      }
  }
}

function exportItem(item: PortableVaultItem): JsonObject {
  if (item.uri !== (item.uris[0]?.uri ?? null)) invalidInput()
  return {
    id: item.id,
    organizationId: null,
    folderId: item.folderId,
    type: WIRE_TYPE_BY_ITEM_TYPE[item.type],
    reprompt: item.reprompt,
    name: item.name,
    notes: item.notes,
    favorite: item.favorite,
    fields: item.customFields.map((field) => ({
      name: field.name,
      value: field.type === 'linked' ? null : field.value,
      type: WIRE_TYPE_BY_CUSTOM_FIELD_TYPE[field.type],
      linkedId: field.linkedId
    })),
    ...exportTypeData(item),
    passwordHistory: item.passwordHistory.map((entry) => ({
      password: entry.password,
      lastUsedDate: entry.lastUsedDate
    })),
    revisionDate: item.updatedAt,
    creationDate: item.createdAt,
    deletedDate: null,
    archivedDate: item.archivedAt,
    collectionIds: null
  }
}

export function buildBitwardenJson(snapshot: PortableVaultSnapshot): string {
  if (!isRecord(snapshot)) invalidInput()
  const folders = array(snapshot.folders, MAX_ENTITIES).map((raw) => {
    const folder = record(raw)
    return {
      id: string(folder.id, MAX_ID_LENGTH, false),
      name: string(folder.name, MAX_NAME_LENGTH, false)
    }
  })
  const folderIds = new Set<string>()
  for (const folder of folders) {
    if (folderIds.has(folder.id)) invalidInput()
    folderIds.add(folder.id)
  }
  const items = array(snapshot.items, MAX_ENTITIES)
    .map((raw) => record(raw) as unknown as PortableVaultItem)
    .filter((item) => {
      if (item.deletedAt === null) return true
      isoDate(item.deletedAt)
      return false
    })
    .map(exportItem)
  // Validate our runtime input and its relationships before returning a portable backup.
  const result = JSON.stringify({ encrypted: false, folders, items }, null, '  ')
  parseBitwardenJson(result)
  return result
}

function canonicalSalt(value: unknown): { encoded: string; bytes: Buffer } {
  const encoded = string(value, 24, false)
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
    invalidInput()
  }
  const bytes = Buffer.from(encoded, 'base64')
  if (bytes.length !== 16 || bytes.toString('base64') !== encoded) {
    bytes.fill(0)
    invalidInput()
  }
  return { encoded, bytes }
}

export async function encryptBitwardenPasswordProtectedJson(
  clearText: string,
  password: string
): Promise<string> {
  if (typeof password !== 'string' || password.length === 0 || password.length > 1_024)
    invalidInput()
  if (typeof clearText !== 'string' || Buffer.byteLength(clearText, 'utf8') > MAX_JSON_BYTES)
    invalidInput()
  const saltBytes = randomBytes(16)
  const salt = saltBytes.toString('base64')
  let masterKey: Buffer | undefined
  let encKey: Buffer | undefined
  let macKey: Buffer | undefined
  let combinedKey: Buffer | undefined
  try {
    masterKey = await derivePbkdf2Sha256(password, salt, EXPORT_KDF_ITERATIONS)
    ;({ encKey, macKey, combinedKey } = stretchMasterKey(masterKey))
    return JSON.stringify(
      {
        encrypted: true,
        passwordProtected: true,
        salt,
        kdfType: 0,
        kdfIterations: EXPORT_KDF_ITERATIONS,
        encKeyValidation_DO_NOT_EDIT: encryptBitwardenString(randomUUID(), combinedKey),
        data: encryptBitwardenString(clearText, combinedKey)
      },
      null,
      '  '
    )
  } catch (error) {
    if (error instanceof VaultError) throw error
    return invalidInput()
  } finally {
    saltBytes.fill(0)
    masterKey?.fill(0)
    encKey?.fill(0)
    macKey?.fill(0)
    combinedKey?.fill(0)
  }
}

export async function decryptBitwardenPasswordProtectedJson(
  text: string,
  password: string
): Promise<string> {
  let saltBytes: Buffer | undefined
  let masterKey: Buffer | undefined
  let encKey: Buffer | undefined
  let macKey: Buffer | undefined
  let combinedKey: Buffer | undefined
  try {
    if (typeof password !== 'string' || password.length === 0 || password.length > 1_024)
      invalidInput()
    const outer = record(parseJson(text))
    if (
      outer.encrypted !== true ||
      outer.passwordProtected !== true ||
      (outer.kdfType !== 0 && outer.kdfType !== 1)
    ) {
      invalidInput()
    }
    if (
      !Number.isSafeInteger(outer.kdfIterations) ||
      (outer.kdfType === 0 &&
        ((outer.kdfIterations as number) < MIN_PBKDF2_ITERATIONS ||
          (outer.kdfIterations as number) > MAX_PBKDF2_ITERATIONS)) ||
      (outer.kdfType === 1 &&
        ((outer.kdfIterations as number) < MIN_ARGON2_ITERATIONS ||
          (outer.kdfIterations as number) > MAX_ARGON2_ITERATIONS))
    ) {
      invalidInput()
    }
    const salt = canonicalSalt(outer.salt)
    saltBytes = salt.bytes
    const validationCipher = string(outer.encKeyValidation_DO_NOT_EDIT, MAX_JSON_BYTES, false)
    const dataCipher = string(outer.data, MAX_JSON_BYTES, false)
    if (outer.kdfType === 0) {
      masterKey = await derivePbkdf2Sha256(password, salt.encoded, outer.kdfIterations as number)
    } else {
      if (
        !Number.isSafeInteger(outer.kdfMemory) ||
        (outer.kdfMemory as number) < MIN_ARGON2_MEMORY_MIB ||
        (outer.kdfMemory as number) > MAX_ARGON2_MEMORY_MIB ||
        !Number.isSafeInteger(outer.kdfParallelism) ||
        (outer.kdfParallelism as number) < 1 ||
        (outer.kdfParallelism as number) > MAX_ARGON2_PARALLELISM
      ) {
        invalidInput()
      }
      masterKey = await deriveMasterKey(password, salt.encoded, {
        type: 'argon2id',
        iterations: outer.kdfIterations as number,
        memoryMiB: outer.kdfMemory as number,
        parallelism: outer.kdfParallelism as number
      })
    }
    ;({ encKey, macKey, combinedKey } = stretchMasterKey(masterKey))
    const validation = decryptBitwardenString(validationCipher, combinedKey)
    if (!UUID_PATTERN.test(validation)) invalidInput()
    const clearText = decryptBitwardenString(dataCipher, combinedKey)
    if (Buffer.byteLength(clearText, 'utf8') > MAX_JSON_BYTES) invalidInput()
    return clearText
  } catch {
    return invalidInput()
  } finally {
    saltBytes?.fill(0)
    masterKey?.fill(0)
    encKey?.fill(0)
    macKey?.fill(0)
    combinedKey?.fill(0)
  }
}
