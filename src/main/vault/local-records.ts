import type { VaultClock } from './core'
import type { FolderView } from '../../shared/vault-contract'
import { type BitwardenOrganizationCipher } from '../bitwarden-direct'
import { type SyncLogin } from '../sync-merge'
import { VaultError } from '../vault-errors'
import { MAX_NAME_LENGTH, MAX_NOTES_LENGTH } from './limits'
import { normalizeRequiredString, normalizeNullableString } from './parse-primitives'
import { validateRemotePasskeys } from './passkey-parsing'
import { cloneCustomFields } from './custom-fields'
import { uriAlias, remoteLoginUris } from './login-uris'
import { normalizeItemFieldsForStorage, normalizeItemType } from './item-fields'
import { validateRemoteAttachments } from './attachments-parsing'
import { clonePasswordHistory } from './password-history'
import type { StoredLogin, StoredSharedLogin, VaultData } from './types'
import { findLogin } from './data-lookup'
import { remoteSyncSnapshot } from './sync-snapshots'

export function createLocalLogin(
  clock: VaultClock,
  data: VaultData,
  source: SyncLogin,
  folderId: string | null
): StoredLogin {
  const now = clock.nowIso()
  const createdAt = source.createdAt ?? now
  const updatedAt = source.updatedAt ?? createdAt
  const login: StoredLogin = {
    id: clock.validatedNewId(),
    type: normalizeItemType(source.type),
    name: normalizeRequiredString(source.name, MAX_NAME_LENGTH),
    notes: normalizeNullableString(source.notes, MAX_NOTES_LENGTH),
    folderId,
    favorite: source.favorite,
    usageCount: 0,
    lastUsedAt: source.lastUsedAt ?? null,
    createdAt,
    updatedAt,
    deletedAt: source.deletedAt,
    archivedAt: source.archivedAt,
    reprompt: source.reprompt,
    passkeys: validateRemotePasskeys(source.passkeys),
    customFields: cloneCustomFields(source.customFields),
    passwordHistory: clonePasswordHistory(source.passwordHistory),
    passwordRevisionDate: source.passwordRevisionDate,
    autofillOnPageLoad: source.autofillOnPageLoad,
    attachments: [],
    uris: remoteLoginUris(source),
    ...normalizeItemFieldsForStorage(source)
  }
  data.logins.push(login)
  return login
}

export function sharedLoginFromRemote(
  clock: VaultClock,
  source: BitwardenOrganizationCipher
): StoredSharedLogin {
  const normalized = remoteSyncSnapshot([], [{ ...source, organizationId: null }]).logins[0]
  if (!normalized) throw new VaultError('SYNC_FAILED')
  return {
    id: source.id,
    type: normalizeItemType(normalized.type),
    name: normalizeRequiredString(normalized.name, MAX_NAME_LENGTH),
    notes: normalizeNullableString(normalized.notes, MAX_NOTES_LENGTH),
    folderId: null,
    favorite: normalized.favorite,
    usageCount: 0,
    lastUsedAt: null,
    createdAt: normalized.createdAt ?? clock.nowIso(),
    updatedAt: normalized.updatedAt ?? clock.nowIso(),
    deletedAt: normalized.deletedAt,
    archivedAt: normalized.archivedAt,
    reprompt: normalized.reprompt,
    passkeys: validateRemotePasskeys(normalized.passkeys),
    customFields: cloneCustomFields(normalized.customFields),
    passwordHistory: clonePasswordHistory(normalized.passwordHistory),
    passwordRevisionDate: normalized.passwordRevisionDate,
    autofillOnPageLoad: normalized.autofillOnPageLoad,
    attachments: validateRemoteAttachments(source.attachments),
    uris: remoteLoginUris(normalized),
    ...normalizeItemFieldsForStorage(normalized),
    organizationId: source.organizationId,
    collectionIds: [...source.collectionIds],
    shared: true,
    edit: source.edit,
    viewPassword: source.viewPassword,
    delete: source.delete,
    restore: source.restore
  }
}

export function updateLocalLogin(
  clock: VaultClock,
  data: VaultData,
  id: string,
  source: SyncLogin,
  folderId: string | null
): void {
  const login = findLogin(data, id)
  login.type = normalizeItemType(source.type)
  login.name = normalizeRequiredString(source.name, MAX_NAME_LENGTH)
  login.notes = normalizeNullableString(source.notes, MAX_NOTES_LENGTH)
  Object.assign(login, normalizeItemFieldsForStorage(source))
  login.uris = remoteLoginUris(source)
  login.uri = uriAlias(login.uris)
  login.passkeys = validateRemotePasskeys(source.passkeys)
  login.customFields = cloneCustomFields(source.customFields)
  login.passwordHistory = clonePasswordHistory(source.passwordHistory)
  login.passwordRevisionDate = source.passwordRevisionDate
  login.autofillOnPageLoad = source.autofillOnPageLoad
  login.folderId = folderId
  login.favorite = source.favorite
  login.deletedAt = source.deletedAt
  login.archivedAt = source.archivedAt
  login.reprompt = source.reprompt
  if (source.createdAt) login.createdAt = source.createdAt
  login.updatedAt = source.updatedAt ?? clock.nowIso()
}

export function createLocalFolder(clock: VaultClock, data: VaultData, name: string): FolderView {
  const now = clock.nowIso()
  const folder: FolderView = {
    id: clock.validatedNewId(),
    name: normalizeRequiredString(name, MAX_NAME_LENGTH),
    position: data.folders.length,
    createdAt: now,
    updatedAt: now
  }
  data.folders.push(folder)
  return folder
}

export function deleteLocalFolder(clock: VaultClock, data: VaultData, id: string): void {
  data.folders = data.folders
    .filter((folder) => folder.id !== id)
    .sort((left, right) => left.position - right.position)
    .map((folder, position) => ({ ...folder, position }))
  const now = clock.nowIso()
  for (const login of data.logins) {
    if (login.folderId === id) {
      login.folderId = null
      login.updatedAt = now
    }
  }
}
