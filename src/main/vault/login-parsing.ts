import type { FolderView } from '../../shared/vault-contract'
import { VaultError } from '../vault-errors'
import {
  MAX_CUSTOM_FIELDS,
  MAX_NAME_LENGTH,
  MAX_NOTES_LENGTH,
  MAX_PASSWORD_LENGTH,
  MAX_REMOTE_ENTITIES,
  MAX_URI_LENGTH,
  MAX_USERNAME_LENGTH,
  UUID_PATTERN
} from './limits'
import { assertIsoDate, isRecord, parseNullableString } from './parse-primitives'
import {
  ITEM_FIELD_NAMES,
  emptyItemFields,
  isVaultItemType,
  maxLengthForItemField
} from './item-fields'
import { parseStoredLoginUris, uriAlias } from './login-uris'
import { parsePasswordHistory } from './password-history'
import { parseCustomField } from './custom-fields'
import { parseStoredAttachments } from './attachments-parsing'
import { parseStoredPasskey } from './passkey-parsing'
import type { StoredLogin, StoredSharedLogin } from './types'

export function parseFolder(value: unknown): FolderView {
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

export function cloneItemName(name: string): string {
  const suffix = ' - Clone'
  const codePoints = Array.from(name)
  while (codePoints.join('').length > MAX_NAME_LENGTH - suffix.length) codePoints.pop()
  return `${codePoints.join('')}${suffix}`
}

export function parseStoredLogin(
  value: unknown,
  legacyItemType = false,
  allowMissingExtendedFields = false,
  allowMissingCustomFields = false,
  allowMissingDeletedAt = false,
  allowMissingArchivedAt = false,
  allowMissingReprompt = false,
  allowMissingUris = false,
  allowMissingPasswordHistory = false,
  allowMissingAttachments = false,
  allowMissingLoginWireMetadata = false,
  allowMissingUsageCount = false
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
  const usageCount = allowMissingUsageCount && value.usageCount === undefined ? 0 : value.usageCount
  if (typeof usageCount !== 'number' || !Number.isSafeInteger(usageCount) || usageCount < 0) {
    throw new VaultError('CORRUPT_VAULT')
  }
  assertIsoDate(value.createdAt)
  assertIsoDate(value.updatedAt)
  let deletedAt: string | null
  if (allowMissingDeletedAt && value.deletedAt === undefined) {
    deletedAt = null
  } else if (value.deletedAt === null) {
    deletedAt = null
  } else {
    assertIsoDate(value.deletedAt)
    deletedAt = value.deletedAt
  }
  let archivedAt: string | null
  if (allowMissingArchivedAt && value.archivedAt === undefined) {
    archivedAt = null
  } else if (value.archivedAt === null) {
    archivedAt = null
  } else {
    assertIsoDate(value.archivedAt)
    archivedAt = value.archivedAt
  }
  const reprompt =
    allowMissingReprompt && value.reprompt === undefined
      ? 0
      : value.reprompt === 0 || value.reprompt === 1
        ? value.reprompt
        : null
  if (reprompt === null) throw new VaultError('CORRUPT_VAULT')

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
  const uris = allowMissingUris
    ? fields.uri === null
      ? []
      : [{ uri: fields.uri, match: null }]
    : parseStoredLoginUris(value.uris)
  if (fields.uri !== uriAlias(uris)) throw new VaultError('CORRUPT_VAULT')
  let passwordRevisionDate: string | null
  if (allowMissingLoginWireMetadata && value.passwordRevisionDate === undefined) {
    passwordRevisionDate = null
  } else if (value.passwordRevisionDate === null) {
    passwordRevisionDate = null
  } else {
    assertIsoDate(value.passwordRevisionDate)
    passwordRevisionDate = value.passwordRevisionDate
  }
  let autofillOnPageLoad: boolean | null
  if (allowMissingLoginWireMetadata && value.autofillOnPageLoad === undefined) {
    autofillOnPageLoad = null
  } else if (value.autofillOnPageLoad === null || typeof value.autofillOnPageLoad === 'boolean') {
    autofillOnPageLoad = value.autofillOnPageLoad
  } else {
    throw new VaultError('CORRUPT_VAULT')
  }
  if (type !== 'login' && (passwordRevisionDate !== null || autofillOnPageLoad !== null)) {
    throw new VaultError('CORRUPT_VAULT')
  }

  return {
    id: value.id,
    type,
    name: value.name,
    notes: parseNullableString(value.notes, MAX_NOTES_LENGTH),
    folderId: parsedFolderId,
    favorite: value.favorite,
    usageCount,
    lastUsedAt: parsedLastUsedAt,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
    deletedAt,
    archivedAt,
    reprompt,
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
    passwordHistory: allowMissingPasswordHistory ? [] : parsePasswordHistory(value.passwordHistory),
    passwordRevisionDate,
    autofillOnPageLoad,
    attachments: allowMissingAttachments ? [] : parseStoredAttachments(value.attachments),
    uris,
    ...fields
  }
}

export function parseStoredSharedLogin(
  value: unknown,
  allowMissingLoginWireMetadata = false,
  allowMissingUsageCount = false
): StoredSharedLogin {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  const login = parseStoredLogin(
    value,
    false,
    false,
    false,
    false,
    false,
    false,
    false,
    false,
    false,
    allowMissingLoginWireMetadata,
    allowMissingUsageCount
  )
  const {
    organizationId,
    collectionIds,
    shared,
    edit,
    viewPassword,
    delete: canDelete,
    restore
  } = value
  if (
    typeof organizationId !== 'string' ||
    !UUID_PATTERN.test(organizationId) ||
    !Array.isArray(collectionIds) ||
    collectionIds.length > MAX_REMOTE_ENTITIES ||
    collectionIds.some((id) => typeof id !== 'string' || !UUID_PATTERN.test(id)) ||
    new Set(collectionIds).size !== collectionIds.length ||
    shared !== true ||
    typeof edit !== 'boolean' ||
    typeof viewPassword !== 'boolean' ||
    typeof canDelete !== 'boolean' ||
    typeof restore !== 'boolean'
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return {
    ...login,
    organizationId,
    collectionIds: [...collectionIds],
    shared,
    edit,
    viewPassword,
    delete: canDelete,
    restore
  }
}
