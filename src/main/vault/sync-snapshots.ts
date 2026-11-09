import {
  BitwardenDirectError,
  type BitwardenFolder,
  type BitwardenLoginDraft,
  type BitwardenLoginItem,
  type BitwardenSyncClient
} from '../bitwarden-direct'
import { type BitwardenEquivalentDomainSettings } from '../bitwarden-http'
import {
  fingerprintFolder,
  fingerprintLogin,
  type SyncAction,
  type SyncActionResult,
  type SyncFolderReference,
  type SyncLink,
  type SyncLogin,
  type SyncMetadata,
  type SyncSnapshot
} from '../sync-merge'
import { VaultError } from '../vault-errors'
import {
  validRemoteDate,
  validRemoteDeletedDate,
  validRemoteArchivedDate,
  sameLoginContentExceptFolder
} from './views'
import { validateRemotePasskeys } from './passkey-parsing'
import { cloneCustomFields } from './custom-fields'
import { cloneLoginUris, uriAlias } from './login-uris'
import { cloneEquivalentDomainSettings } from './equivalent-domains'
import { cloneAttachments, validateRemoteAttachments } from './attachments-parsing'
import { clonePasswordHistory } from './password-history'
import type { SyncEntityMapping, SyncTombstone, PersistedSyncData, VaultData } from './types'

export type BulkRemoteLoginMutation =
  'soft-delete' | 'restore' | 'move' | 'archive' | 'unarchive' | 'hard-delete'

export const MAX_REMOTE_LOGIN_BATCH_IDS = 500

export interface BulkRemoteLoginCandidate {
  action: Extract<SyncAction, { entity: 'login' }>
  mutation: BulkRemoteLoginMutation
  remoteId: string
  folderId: string | null
}

export interface LoginImportCandidate {
  action: Extract<SyncAction, { entity: 'login'; kind: 'push-create' }>
  remoteFolderId: string | null
  baseFingerprint: string
}

export function localSyncSnapshot(data: VaultData): SyncSnapshot {
  return {
    folders: data.folders.map((folder) => ({
      id: folder.id,
      name: folder.name,
      updatedAt: folder.updatedAt
    })),
    logins: data.logins.map((login) => ({
      ...login,
      uris: cloneLoginUris(login.uris),
      passkeys: login.passkeys.map((passkey) => ({ ...passkey })),
      customFields: cloneCustomFields(login.customFields),
      passwordHistory: clonePasswordHistory(login.passwordHistory),
      attachments: cloneAttachments(login.attachments)
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

export function remoteSyncSnapshot(
  folders: BitwardenFolder[],
  logins: BitwardenLoginItem[]
): SyncSnapshot {
  return {
    folders: folders.map((folder) => ({ id: folder.id, name: folder.name })),
    logins: logins.map((login) => ({
      ...login,
      uris: cloneLoginUris(login.uris),
      passkeys: validateRemotePasskeys(login.passkeys),
      passwordHistory: clonePasswordHistory(login.passwordHistory),
      uri: uriAlias(login.uris),
      // Wire metadata is login-only upstream (vaultwarden nests it under the login object).
      // Null it for other item types here, mirroring the upload path, so a quirky server
      // cannot persist a combination the vault schema rejects at the next unlock.
      passwordRevisionDate: login.type === 'login' ? login.passwordRevisionDate : null,
      autofillOnPageLoad: login.type === 'login' ? login.autofillOnPageLoad : null,
      createdAt: validRemoteDate(login.creationDate),
      updatedAt: validRemoteDate(login.revisionDate),
      deletedAt: validRemoteDeletedDate(login.deletedAt),
      archivedAt: validRemoteArchivedDate(login.archivedAt)
    })),
    tombstones: { folders: [], logins: [] }
  }
}

export function syncMetadataOf(sync: PersistedSyncData): SyncMetadata {
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

export function withoutProtectedLoginSnapshot(
  snapshot: SyncSnapshot,
  protectedLocalIds: ReadonlySet<string>
): SyncSnapshot {
  if (protectedLocalIds.size === 0) return snapshot
  return {
    ...snapshot,
    logins: snapshot.logins.filter((login) => !protectedLocalIds.has(login.id)),
    tombstones: {
      ...snapshot.tombstones,
      logins: snapshot.tombstones.logins.filter((tombstone) => !protectedLocalIds.has(tombstone.id))
    }
  }
}

export function reattachProtectedLoginLinks(
  completedLinks: readonly SyncLink[],
  protectedMappings: readonly SyncEntityMapping[],
  protectedTombstones: readonly SyncTombstone[]
): { loginMappings: SyncEntityMapping[]; loginTombstones: SyncTombstone[] } {
  const loginMappings: SyncEntityMapping[] = []
  const loginTombstones: SyncTombstone[] = []
  const attached: Array<{
    kind: 'mapping' | 'tombstone'
    link: SyncEntityMapping | SyncTombstone
  }> = []
  const attach = (kind: 'mapping' | 'tombstone', link: SyncEntityMapping | SyncTombstone): void => {
    const duplicate = attached.find(
      (entry) => entry.link.localId === link.localId || entry.link.remoteId === link.remoteId
    )
    if (duplicate) {
      if (
        duplicate.kind === kind &&
        duplicate.link.localId === link.localId &&
        duplicate.link.remoteId === link.remoteId &&
        duplicate.link.baseFingerprint === link.baseFingerprint
      ) {
        return
      }
      throw new VaultError('SYNC_FAILED')
    }
    const cloned = { ...link }
    attached.push({ kind, link: cloned })
    if (kind === 'mapping') loginMappings.push(cloned)
    else loginTombstones.push(cloned)
  }

  for (const link of completedLinks) attach('mapping', link)
  for (const link of protectedMappings) attach('mapping', link)
  for (const link of protectedTombstones) attach('tombstone', link)
  return { loginMappings, loginTombstones }
}

export function getAuthoritativeEquivalentDomainSettings(
  client: BitwardenSyncClient,
  signal?: AbortSignal
): Promise<BitwardenEquivalentDomainSettings> {
  const getter =
    client.getAuthoritativeEquivalentDomainSettings ?? client.getEquivalentDomainSettings
  return getter.call(client, signal)
}

export async function getSyncEquivalentDomainSettings(
  client: BitwardenSyncClient,
  lastKnownGood: BitwardenEquivalentDomainSettings,
  signal?: AbortSignal
): Promise<BitwardenEquivalentDomainSettings> {
  try {
    return await getAuthoritativeEquivalentDomainSettings(client, signal)
  } catch (error) {
    if (
      error instanceof BitwardenDirectError &&
      (error.code === 'INVALID_RESPONSE' ||
        error.code === 'TOO_LARGE' ||
        error.code === 'NOT_FOUND')
    ) {
      // Equivalent-domain rules are ancillary matching hints. A malformed self-hosted setting
      // must not block vault data, but it also must not replace the last authoritative snapshot.
      return cloneEquivalentDomainSettings(lastKnownGood)
    }
    throw error
  }
}

export function isolatedPersonalCipherIdsOf(client: BitwardenSyncClient): ReadonlySet<string> {
  return new Set(client.isolatedPersonalCipherIds?.() ?? [])
}

export function findNewlyIsolatedMappedRemoteIds(
  isolatedRemoteIds: ReadonlySet<string>,
  links: readonly { remoteId: string }[],
  protectedRemoteIds: ReadonlySet<string>
): ReadonlySet<string> {
  return new Set(
    links.flatMap((link) =>
      isolatedRemoteIds.has(link.remoteId) && !protectedRemoteIds.has(link.remoteId)
        ? [link.remoteId]
        : []
    )
  )
}

export function supportsLoginImport(client: BitwardenSyncClient): boolean {
  return (
    client.prepareLoginImport !== undefined &&
    client.executePreparedLoginImport !== undefined &&
    client.reconcileLoginImportMarkers !== undefined &&
    client.discardPreparedLoginImport !== undefined
  )
}

export function supportsBulkRemoteLoginMutation(
  client: BitwardenSyncClient,
  mutation: BulkRemoteLoginMutation
): boolean {
  if (mutation === 'soft-delete') return client.softDeleteLogins !== undefined
  if (mutation === 'restore') return client.restoreLogins !== undefined
  if (mutation === 'move') return client.moveLogins !== undefined
  if (mutation === 'archive') return client.archiveLogins !== undefined
  if (mutation === 'unarchive') return client.unarchiveLogins !== undefined
  return client.hardDeleteLogins !== undefined
}

export function bulkRemoteLoginMutationApplied(
  candidate: BulkRemoteLoginCandidate,
  remote: ReadonlyMap<string, BitwardenLoginItem>
): boolean {
  const current = remote.get(candidate.remoteId)
  if (candidate.mutation === 'hard-delete') return current === undefined
  if (!current) return false
  if (candidate.mutation === 'soft-delete') return current.deletedAt !== null
  if (candidate.mutation === 'restore') return current.deletedAt === null
  if (candidate.mutation === 'archive') return current.archivedAt !== null
  if (candidate.mutation === 'unarchive') return current.archivedAt === null
  return current.folderId === candidate.folderId
}

export function resolveFolderReference(
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

export function remoteDraft(login: SyncLogin, folderId: string | null): BitwardenLoginDraft {
  return {
    type: login.type,
    name: login.name,
    username: login.username,
    password: login.password,
    totp: login.totp,
    uri: login.uri,
    uris: cloneLoginUris(login.uris),
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
    archivedAt: login.archivedAt,
    reprompt: login.reprompt,
    passkeys: login.passkeys.map((passkey) => ({ ...passkey })),
    customFields: cloneCustomFields(login.customFields),
    passwordHistory: clonePasswordHistory(login.passwordHistory),
    passwordRevisionDate: login.passwordRevisionDate,
    autofillOnPageLoad: login.autofillOnPageLoad
  }
}

export function hasPendingLocalSyncWork(data: VaultData): boolean {
  const sync = data.sync
  if (!sync) return true
  if (
    sync.requiresFullSyncAfterCipherIsolation === true ||
    sync.pendingLoginMutation ||
    sync.pendingLoginImport ||
    sync.pendingPersonalVaultPurge ||
    sync.folderTombstones.length > 0 ||
    sync.loginTombstones.length > 0
  ) {
    return true
  }

  const folderMappings = new Map(sync.folderMappings.map((entry) => [entry.localId, entry]))
  const mappedRemoteFolderIds = new Set(sync.folderMappings.map((entry) => entry.remoteId))
  if (
    folderMappings.size !== sync.folderMappings.length ||
    mappedRemoteFolderIds.size !== sync.folderMappings.length ||
    folderMappings.size !== data.folders.length
  ) {
    return true
  }
  for (const folder of data.folders) {
    if (folderMappings.get(folder.id)?.baseFingerprint !== fingerprintFolder(folder)) return true
  }

  const loginMappings = new Map(sync.loginMappings.map((entry) => [entry.localId, entry]))
  const mappedRemoteLoginIds = new Set(sync.loginMappings.map((entry) => entry.remoteId))
  if (
    loginMappings.size !== sync.loginMappings.length ||
    mappedRemoteLoginIds.size !== sync.loginMappings.length ||
    loginMappings.size !== data.logins.length
  ) {
    return true
  }
  const folderNames = new Map(data.folders.map((folder) => [folder.id, folder.name]))
  for (const login of localSyncSnapshot(data).logins) {
    const canonicalFolder =
      login.folderId === null
        ? null
        : (folderNames.get(login.folderId) ?? `missing:${login.folderId}`)
    if (loginMappings.get(login.id)?.baseFingerprint !== fingerprintLogin(login, canonicalFolder)) {
      return true
    }
  }
  return false
}

export function reconcileServerAuthoritativeAttachments(
  data: VaultData,
  links: readonly SyncLink[],
  remoteFolders: readonly BitwardenFolder[],
  remoteLogins: readonly BitwardenLoginItem[]
): void {
  const remoteById = new Map(remoteLogins.map((login) => [login.id, login]))
  if (remoteById.size !== remoteLogins.length) throw new VaultError('SYNC_FAILED')
  const remoteSnapshotById = new Map(
    remoteSyncSnapshot([], [...remoteLogins]).logins.map((login) => [login.id, login])
  )
  const remoteFolderNames = new Map(remoteFolders.map((folder) => [folder.id, folder.name]))
  if (remoteFolderNames.size !== remoteFolders.length) throw new VaultError('SYNC_FAILED')

  for (const link of links) {
    const local = data.logins.find((login) => login.id === link.localId)
    const remote = remoteById.get(link.remoteId)
    const remoteSnapshot = remoteSnapshotById.get(link.remoteId)
    if (
      !local ||
      !remote ||
      !remoteSnapshot ||
      fingerprintLogin(
        remoteSnapshot,
        remoteSnapshot.folderId === null
          ? null
          : (remoteFolderNames.get(remoteSnapshot.folderId) ?? `missing:${remoteSnapshot.folderId}`)
      ) !== link.baseFingerprint
    ) {
      throw new VaultError('SYNC_FAILED')
    }
    local.attachments = validateRemoteAttachments(remote.attachments)
    const revisionDate = validRemoteDate(remote.revisionDate)
    if (revisionDate) local.updatedAt = revisionDate
  }
}

export function loginImportCandidate(
  action: SyncAction,
  completed: Map<string, SyncActionResult>,
  skipLocalIds: ReadonlySet<string>
): LoginImportCandidate | null {
  if (
    action.entity !== 'login' ||
    action.kind !== 'push-create' ||
    action.local.deletedAt !== null ||
    skipLocalIds.has(action.local.id) ||
    typeof action.baseFingerprint !== 'string' ||
    !/^[0-9a-f]{64}$/u.test(action.baseFingerprint)
  ) {
    return null
  }
  return {
    action,
    remoteFolderId: resolveFolderReference(action.remoteFolder, completed, 'remoteId'),
    baseFingerprint: action.baseFingerprint
  }
}

export function bulkRemoteLoginCandidate(
  action: SyncAction,
  completed: Map<string, SyncActionResult>
): BulkRemoteLoginCandidate | null {
  if (action.entity !== 'login') return null
  if (action.kind === 'delete-remote') {
    return {
      action,
      mutation: 'hard-delete',
      remoteId: action.remoteId,
      folderId: null
    }
  }
  if (action.kind !== 'push-update') return null

  const desiredDeleted = action.local.deletedAt !== null
  const currentDeleted = action.remote.deletedAt !== null
  const desiredArchived = action.local.archivedAt !== null
  const currentArchived = action.remote.archivedAt !== null
  if (!action.contentChanged) {
    const mutations: BulkRemoteLoginMutation[] = []
    if (currentDeleted && !desiredDeleted) mutations.push('restore')
    if (currentArchived && !desiredArchived) mutations.push('unarchive')
    if (desiredArchived && !currentArchived) mutations.push('archive')
    if (desiredDeleted && !currentDeleted) mutations.push('soft-delete')
    return mutations.length === 1
      ? {
          action,
          mutation: mutations[0]!,
          remoteId: action.remoteId,
          folderId: null
        }
      : null
  }

  if (
    desiredDeleted !== currentDeleted ||
    desiredArchived !== currentArchived ||
    !sameLoginContentExceptFolder(action.local, action.remote)
  ) {
    return null
  }
  const folderId = resolveFolderReference(action.remoteFolder, completed, 'remoteId')
  if (folderId === action.remote.folderId) return null
  return { action, mutation: 'move', remoteId: action.remoteId, folderId }
}

export async function updateRemoteLogin(
  client: BitwardenSyncClient,
  remoteId: string,
  desired: SyncLogin,
  current: SyncLogin,
  folderId: string | null,
  contentChanged: boolean,
  signal: AbortSignal
): Promise<void> {
  const desiredDeleted = desired.deletedAt !== null
  const currentDeleted = current.deletedAt !== null
  const desiredArchived = desired.archivedAt !== null
  const currentArchived = current.archivedAt !== null

  if (currentDeleted && (!desiredDeleted || contentChanged)) {
    await client.restoreLogin(remoteId, signal)
  }
  // Vaultwarden treats archivedDate: null in an ordinary cipher update as "leave unchanged",
  // so an explicit unarchive route is required even when a content edit follows.
  if (currentArchived && !desiredArchived) {
    await client.unarchiveLogin(remoteId, signal)
  }
  if (contentChanged) {
    await client.editLogin(remoteId, remoteDraft(desired, folderId), signal)
  }
  if (!contentChanged && desiredArchived && !currentArchived) {
    await client.archiveLogin(remoteId, signal)
  }
  if (desiredDeleted && (!currentDeleted || contentChanged)) {
    await client.softDeleteLogin(remoteId, signal)
  }
}

export function throwSharedSnapshotError(
  error: unknown,
  stage: 'organization' | 'collection' | 'cipher'
): never {
  if (error instanceof BitwardenDirectError) {
    if (error.code !== 'INVALID_RESPONSE' || error.syncInvalidResponseStage) throw error
    throw new BitwardenDirectError('INVALID_RESPONSE', undefined, stage)
  }
  throw new BitwardenDirectError('INVALID_RESPONSE', undefined, stage)
}

/** Compares the parts of two snapshots the vault screens render; sync bookkeeping is ignored. */
export function visibleVaultContentChanged(
  before: VaultData | null,
  after: VaultData | null
): boolean {
  if (before === after) return false
  if (!before || !after) return true
  return JSON.stringify(visibleVaultContent(before)) !== JSON.stringify(visibleVaultContent(after))
}

function visibleVaultContent(data: VaultData): unknown[] {
  return [
    data.logins,
    data.folders,
    data.sharedLogins,
    data.organizations,
    data.collections,
    data.sends
  ]
}
