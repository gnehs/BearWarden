import { createHash } from 'node:crypto'
import type {
  VaultCustomField,
  VaultItemFields,
  VaultItemType,
  VaultLoginUri,
  VaultPasswordHistoryEntry,
  VaultReprompt
} from '../shared/vault-contract'
import type { StoredPasskeyCredential } from './passkey'

export interface SyncFolder {
  id: string
  name: string
  updatedAt?: string
}

export interface SyncLogin extends VaultItemFields {
  id: string
  type: VaultItemType
  name: string
  notes: string | null
  folderId: string | null
  favorite: boolean
  lastUsedAt?: string | null
  createdAt?: string
  updatedAt?: string
  deletedAt: string | null
  archivedAt: string | null
  reprompt: VaultReprompt
  uris: VaultLoginUri[]
  passkeys: StoredPasskeyCredential[]
  customFields: VaultCustomField[]
  passwordHistory: VaultPasswordHistoryEntry[]
  passwordRevisionDate: string | null
  autofillOnPageLoad: boolean | null
}

export interface SyncTombstone {
  id: string
  deletedAt: string
}

export interface SyncSnapshot {
  folders: readonly SyncFolder[]
  logins: readonly SyncLogin[]
  tombstones: {
    folders: readonly SyncTombstone[]
    logins: readonly SyncTombstone[]
  }
}

export interface SyncLink {
  localId: string
  remoteId: string
  baseFingerprint: string
}

export interface SyncMetadata {
  version: 1
  folderLinks: readonly SyncLink[]
  loginLinks: readonly SyncLink[]
}

export interface SyncFolderReference {
  id: string | null
  /** Resolve this folder create action before applying the login action. */
  pendingKey?: string
}

interface ActionBase {
  actionId: string
  pendingKey?: string
  baseFingerprint?: string
}

export type SyncAction =
  | (ActionBase & { kind: 'push-create'; entity: 'folder'; local: SyncFolder })
  | (ActionBase & {
      kind: 'push-update'
      entity: 'folder'
      local: SyncFolder
      remoteId: string
    })
  | (ActionBase & { kind: 'pull-create'; entity: 'folder'; remote: SyncFolder })
  | (ActionBase & {
      kind: 'pull-update'
      entity: 'folder'
      localId: string
      remote: SyncFolder
    })
  | (ActionBase & { kind: 'delete-local'; entity: 'folder'; localId: string })
  | (ActionBase & { kind: 'delete-remote'; entity: 'folder'; remoteId: string })
  | (ActionBase & {
      kind: 'conflict-copy'
      entity: 'folder'
      reason: 'both-modified' | 'local-deleted' | 'remote-deleted'
      resolution: 'remote-primary-local-copy' | 'deleted-primary-linked-conflict-copy'
      local: SyncFolder | null
      remote: SyncFolder | null
      conflictName: string
      conflictFingerprint: string
    })
  | (ActionBase & {
      kind: 'push-create'
      entity: 'login'
      local: SyncLogin
      remoteFolder: SyncFolderReference
    })
  | (ActionBase & {
      kind: 'push-update'
      entity: 'login'
      local: SyncLogin
      remote: SyncLogin
      remoteId: string
      remoteFolder: SyncFolderReference
      contentChanged: boolean
      resumeFingerprints: readonly string[]
    })
  | (ActionBase & {
      kind: 'pull-create'
      entity: 'login'
      remote: SyncLogin
      localFolder: SyncFolderReference
    })
  | (ActionBase & {
      kind: 'pull-update'
      entity: 'login'
      localId: string
      remote: SyncLogin
      localFolder: SyncFolderReference
    })
  | (ActionBase & { kind: 'delete-local'; entity: 'login'; localId: string })
  | (ActionBase & { kind: 'delete-remote'; entity: 'login'; remoteId: string })
  | (ActionBase & {
      kind: 'conflict-copy'
      entity: 'login'
      reason: 'both-modified' | 'local-deleted' | 'remote-deleted'
      resolution: 'remote-primary-local-copy' | 'deleted-primary-linked-conflict-copy'
      local: SyncLogin | null
      remote: SyncLogin | null
      conflictName: string
      conflictFingerprint: string
      localFolder: SyncFolderReference
      remoteFolder: SyncFolderReference
    })

export interface SyncPlan {
  actions: readonly SyncAction[]
  /** Contains every link whose two IDs are already known. */
  nextMetadata: SyncMetadata
}

export interface SyncActionResult {
  actionId: string
  /** ID created by a pull-create or conflict-copy on the local side. */
  localId?: string
  /** ID created by a push-create or conflict-copy on the remote side. */
  remoteId?: string
  /** Optional actual post-write fingerprint; the planned fingerprint is used otherwise. */
  fingerprint?: string
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  const record = value as Record<string, unknown>
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(',')}}`
}

function sha256(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex')
}

export function fingerprintFolder(folder: SyncFolder): string {
  return sha256({ name: folder.name })
}

function loginFingerprintContent(
  login: SyncLogin,
  canonicalFolder: string | null = login.folderId
): Record<string, unknown> {
  return {
    type: login.type,
    favorite: login.favorite,
    reprompt: login.reprompt,
    folder: canonicalFolder,
    name: login.name,
    notes: login.notes,
    fields: {
      username: login.username,
      password: login.password,
      passwordRevisionDate: login.passwordRevisionDate,
      autofillOnPageLoad: login.autofillOnPageLoad,
      totp: login.totp,
      uris: login.uris,
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
      fingerprint: login.fingerprint
    },
    passkeys: login.passkeys
  }
}

/** Content fingerprint intentionally excludes IDs, timestamps, and lastUsedAt. */
export function fingerprintLogin(
  login: SyncLogin,
  canonicalFolder: string | null = login.folderId
): string {
  return sha256({
    ...loginFingerprintContent(login, canonicalFolder),
    // Preserve pre-trash fingerprints for active items while tracking the trash state. The
    // server owns the exact deletion timestamp, so two non-null timestamps are equivalent.
    ...(login.deletedAt ? { deletedAt: true } : {}),
    // As with deletion, archive timestamps are server-owned state. Only the boolean affects
    // convergence so a server revision does not create a false conflict.
    ...(login.archivedAt ? { archivedAt: true } : {}),
    // Keep the pre-custom-field fingerprint stable for items without custom fields. This lets
    // existing sync links upgrade without falsely treating every item as modified on both sides.
    ...(login.customFields?.length > 0 ? { customFields: login.customFields } : {}),
    ...(login.passwordHistory?.length > 0 ? { passwordHistory: login.passwordHistory } : {})
  })
}

function preV11LoginFingerprintContent(
  login: SyncLogin,
  canonicalFolder: string | null = login.folderId
): Record<string, unknown> {
  const current = loginFingerprintContent(login, canonicalFolder)
  const fields = current.fields as Record<string, unknown>
  const withoutReprompt = { ...current }
  const withoutUris = { ...fields }
  delete withoutReprompt.reprompt
  delete withoutUris.uris
  delete withoutUris.passwordRevisionDate
  delete withoutUris.autofillOnPageLoad
  return {
    ...withoutReprompt,
    fields: { ...withoutUris, uri: login.uri }
  }
}

/** Fingerprint written before ordered URI rows and reprompt were part of sync convergence. */
export function legacyLoginFingerprint(
  login: SyncLogin,
  canonicalFolder: string | null = login.folderId
): string {
  return sha256(preV11LoginFingerprintContent(login, canonicalFolder))
}

function legacyLoginFingerprintCandidates(
  login: SyncLogin,
  canonicalFolder: string | null
): Set<string> {
  const oldest = preV11LoginFingerprintContent(login, canonicalFolder)
  const withReprompt = { ...oldest, reprompt: login.reprompt }
  const lifecycle = {
    ...(login.deletedAt ? { deletedAt: true } : {}),
    ...(login.archivedAt ? { archivedAt: true } : {})
  }
  const custom = login.customFields.length > 0 ? { customFields: login.customFields } : {}
  const currentWithoutCustom = loginFingerprintContent(login, canonicalFolder)
  const fieldsWithoutWireMetadata = {
    ...(currentWithoutCustom.fields as Record<string, unknown>)
  }
  delete fieldsWithoutWireMetadata.passwordRevisionDate
  delete fieldsWithoutWireMetadata.autofillOnPageLoad
  const preWireMetadata = { ...currentWithoutCustom, fields: fieldsWithoutWireMetadata }
  return new Set(
    [oldest, withReprompt, preWireMetadata, currentWithoutCustom].flatMap((content) => [
      sha256(content),
      sha256({ ...content, ...lifecycle }),
      sha256({ ...content, ...custom }),
      sha256({ ...content, ...lifecycle, ...custom })
    ])
  )
}

function indexUnique<T extends { id: string }>(
  values: readonly T[],
  label: string
): Map<string, T> {
  const result = new Map<string, T>()
  for (const value of values) {
    if (!value.id || result.has(value.id)) throw new Error(`Invalid ${label} snapshot`)
    result.set(value.id, value)
  }
  return result
}

function indexLinks(links: readonly SyncLink[], label: string): Map<string, SyncLink> {
  const local = new Set<string>()
  const remote = new Set<string>()
  const result = new Map<string, SyncLink>()
  for (const link of links) {
    if (local.has(link.localId) || remote.has(link.remoteId))
      throw new Error(`Invalid ${label} links`)
    local.add(link.localId)
    remote.add(link.remoteId)
    result.set(link.localId, link)
  }
  return result
}

function uniqueFingerprintPairs<T>(
  local: readonly T[],
  remote: readonly T[],
  fingerprintLocal: (value: T) => string,
  fingerprintRemote: (value: T) => string
): Array<{ local: T; remote: T; fingerprint: string }> {
  const localGroups = new Map<string, T[]>()
  const remoteGroups = new Map<string, T[]>()
  for (const value of local) {
    const fingerprint = fingerprintLocal(value)
    localGroups.set(fingerprint, [...(localGroups.get(fingerprint) ?? []), value])
  }
  for (const value of remote) {
    const fingerprint = fingerprintRemote(value)
    remoteGroups.set(fingerprint, [...(remoteGroups.get(fingerprint) ?? []), value])
  }
  return [...localGroups.entries()].flatMap(([fingerprint, localValues]) => {
    const remoteValues = remoteGroups.get(fingerprint)
    return localValues.length === 1 && remoteValues?.length === 1
      ? [{ local: localValues[0]!, remote: remoteValues[0]!, fingerprint }]
      : []
  })
}

function conflictName(name: string): string {
  return `${name} (BearWarden conflict)`
}

interface FolderMapping {
  localToRemote: Map<string, SyncFolderReference>
  remoteToLocal: Map<string, SyncFolderReference>
}

function planFolders(
  localSnapshot: SyncSnapshot,
  remoteSnapshot: SyncSnapshot,
  metadata: SyncMetadata,
  actions: SyncAction[],
  nextLinks: SyncLink[]
): FolderMapping {
  const local = indexUnique(localSnapshot.folders, 'local folder')
  const remote = indexUnique(remoteSnapshot.folders, 'remote folder')
  const localTombstones = new Set(localSnapshot.tombstones.folders.map((value) => value.id))
  const links = indexLinks(metadata.folderLinks, 'folder')
  const remoteLinked = new Set(metadata.folderLinks.map((link) => link.remoteId))
  const localToRemote = new Map<string, SyncFolderReference>()
  const remoteToLocal = new Map<string, SyncFolderReference>()

  for (const link of links.values()) {
    const localFolder = local.get(link.localId)
    const remoteFolder = remote.get(link.remoteId)
    if (localFolder && remoteFolder) {
      const localFingerprint = fingerprintFolder(localFolder)
      const remoteFingerprint = fingerprintFolder(remoteFolder)
      localToRemote.set(link.localId, { id: link.remoteId })
      remoteToLocal.set(link.remoteId, { id: link.localId })
      if (localFingerprint === remoteFingerprint) {
        nextLinks.push({ ...link, baseFingerprint: localFingerprint })
      } else if (localFingerprint === link.baseFingerprint) {
        const actionId = `folder:pull-update:${link.localId}`
        actions.push({
          kind: 'pull-update',
          entity: 'folder',
          actionId,
          localId: link.localId,
          remote: remoteFolder,
          baseFingerprint: remoteFingerprint
        })
        nextLinks.push({ ...link, baseFingerprint: remoteFingerprint })
      } else if (remoteFingerprint === link.baseFingerprint) {
        const actionId = `folder:push-update:${link.remoteId}`
        actions.push({
          kind: 'push-update',
          entity: 'folder',
          actionId,
          local: localFolder,
          remoteId: link.remoteId,
          baseFingerprint: localFingerprint
        })
        nextLinks.push({ ...link, baseFingerprint: localFingerprint })
      } else {
        const copyName = conflictName(localFolder.name)
        actions.push({
          kind: 'conflict-copy',
          entity: 'folder',
          actionId: `folder:conflict:${link.localId}`,
          reason: 'both-modified',
          resolution: 'remote-primary-local-copy',
          local: localFolder,
          remote: remoteFolder,
          conflictName: copyName,
          conflictFingerprint: fingerprintFolder({ ...localFolder, name: copyName }),
          baseFingerprint: remoteFingerprint
        })
        nextLinks.push({ ...link, baseFingerprint: remoteFingerprint })
      }
      local.delete(link.localId)
      remote.delete(link.remoteId)
    } else if (localFolder) {
      const localFingerprint = fingerprintFolder(localFolder)
      if (localFingerprint === link.baseFingerprint) {
        actions.push({
          kind: 'delete-local',
          entity: 'folder',
          actionId: `folder:delete-local:${link.localId}`,
          localId: link.localId
        })
      } else {
        const copyName = conflictName(localFolder.name)
        const actionId = `folder:conflict-remote-deleted:${link.localId}`
        actions.push({
          kind: 'conflict-copy',
          entity: 'folder',
          actionId,
          pendingKey: actionId,
          reason: 'remote-deleted',
          resolution: 'deleted-primary-linked-conflict-copy',
          local: localFolder,
          remote: null,
          conflictName: copyName,
          conflictFingerprint: fingerprintFolder({ ...localFolder, name: copyName })
        })
      }
      local.delete(link.localId)
    } else if (remoteFolder) {
      const remoteFingerprint = fingerprintFolder(remoteFolder)
      if (localTombstones.has(link.localId) && remoteFingerprint === link.baseFingerprint) {
        actions.push({
          kind: 'delete-remote',
          entity: 'folder',
          actionId: `folder:delete-remote:${link.remoteId}`,
          remoteId: link.remoteId
        })
      } else if (localTombstones.has(link.localId)) {
        const copyName = conflictName(remoteFolder.name)
        const actionId = `folder:conflict-local-deleted:${link.remoteId}`
        actions.push({
          kind: 'conflict-copy',
          entity: 'folder',
          actionId,
          pendingKey: actionId,
          reason: 'local-deleted',
          resolution: 'deleted-primary-linked-conflict-copy',
          local: null,
          remote: remoteFolder,
          conflictName: copyName,
          conflictFingerprint: fingerprintFolder({ ...remoteFolder, name: copyName })
        })
      } else {
        const actionId = `folder:pull-create:${link.remoteId}`
        actions.push({
          kind: 'pull-create',
          entity: 'folder',
          actionId,
          pendingKey: actionId,
          remote: remoteFolder,
          baseFingerprint: remoteFingerprint
        })
        remoteToLocal.set(link.remoteId, { id: null, pendingKey: actionId })
      }
      remote.delete(link.remoteId)
    }
  }

  const pairs = uniqueFingerprintPairs(
    [...local.values()],
    [...remote.values()],
    fingerprintFolder,
    fingerprintFolder
  )
  for (const pair of pairs) {
    local.delete(pair.local.id)
    remote.delete(pair.remote.id)
    localToRemote.set(pair.local.id, { id: pair.remote.id })
    remoteToLocal.set(pair.remote.id, { id: pair.local.id })
    nextLinks.push({
      localId: pair.local.id,
      remoteId: pair.remote.id,
      baseFingerprint: pair.fingerprint
    })
  }
  for (const folder of local.values()) {
    const actionId = `folder:push-create:${folder.id}`
    actions.push({
      kind: 'push-create',
      entity: 'folder',
      actionId,
      pendingKey: actionId,
      local: folder,
      baseFingerprint: fingerprintFolder(folder)
    })
    localToRemote.set(folder.id, { id: null, pendingKey: actionId })
  }
  for (const folder of remote.values()) {
    if (remoteLinked.has(folder.id)) continue
    const actionId = `folder:pull-create:${folder.id}`
    actions.push({
      kind: 'pull-create',
      entity: 'folder',
      actionId,
      pendingKey: actionId,
      remote: folder,
      baseFingerprint: fingerprintFolder(folder)
    })
    remoteToLocal.set(folder.id, { id: null, pendingKey: actionId })
  }
  return { localToRemote, remoteToLocal }
}

function folderName(folderId: string | null, folders: Map<string, SyncFolder>): string | null {
  if (folderId === null) return null
  return folders.get(folderId)?.name ?? `missing:${folderId}`
}

export interface LegacyCustomFieldBaselineUpgrade {
  localId: string
  remoteId: string
  customFields: VaultCustomField[]
  uris?: VaultLoginUri[]
  reprompt?: VaultReprompt
  passwordHistory?: VaultPasswordHistoryEntry[]
  passwordRevisionDate?: string | null
  autofillOnPageLoad?: boolean | null
  baseFingerprint: string
}

function hasDistinctPostLegacyState(login: SyncLogin, other: SyncLogin): boolean {
  const hasNonDefaultUris =
    login.uri === null
      ? login.uris.length > 0
      : !(
          login.uris.length === 1 &&
          login.uris[0]?.uri === login.uri &&
          login.uris[0]?.match === null
        )
  return (
    (hasNonDefaultUris && canonicalJson(login.uris) !== canonicalJson(other.uris)) ||
    (login.reprompt !== 0 && login.reprompt !== other.reprompt) ||
    (login.customFields.length > 0 &&
      canonicalJson(login.customFields) !== canonicalJson(other.customFields)) ||
    (login.passwordHistory.length > 0 &&
      canonicalJson(login.passwordHistory) !== canonicalJson(other.passwordHistory)) ||
    (login.passwordRevisionDate !== null &&
      login.passwordRevisionDate !== other.passwordRevisionDate) ||
    (login.autofillOnPageLoad !== null && login.autofillOnPageLoad !== other.autofillOnPageLoad)
  )
}

/**
 * Detects pre-custom-field sync links whose remote fields were previously invisible locally.
 * Adopting those fields and advancing the base avoids a false conflict while preserving any
 * unrelated local edit made before the first upgraded sync.
 */
export function legacyCustomFieldBaselineUpgrades(
  localSnapshot: SyncSnapshot,
  remoteSnapshot: SyncSnapshot,
  metadata: SyncMetadata
): LegacyCustomFieldBaselineUpgrade[] {
  const local = indexUnique(localSnapshot.logins, 'local login')
  const remote = indexUnique(remoteSnapshot.logins, 'remote login')
  const localFolders = indexUnique(localSnapshot.folders, 'local folder')
  const remoteFolders = indexUnique(remoteSnapshot.folders, 'remote folder')
  const upgrades: LegacyCustomFieldBaselineUpgrade[] = []

  for (const link of metadata.loginLinks) {
    const localLogin = local.get(link.localId)
    const remoteLogin = remote.get(link.remoteId)
    if (!localLogin || !remoteLogin) continue
    const canonicalFolder = folderName(remoteLogin.folderId, remoteFolders)
    const localCanonicalFolder = folderName(localLogin.folderId, localFolders)
    const localHash = fingerprintLogin(localLogin, localCanonicalFolder)
    const remoteHash = fingerprintLogin(remoteLogin, canonicalFolder)
    // Modern links already handled by the ordinary planner must never be reinterpreted as legacy;
    // in particular lifecycle-only changes (trash/archive) need to remain pull/push operations.
    if (localHash === link.baseFingerprint || remoteHash === link.baseFingerprint) continue
    const localMatches = legacyLoginFingerprintCandidates(localLogin, localCanonicalFolder).has(
      link.baseFingerprint
    )
    const remoteMatches = legacyLoginFingerprintCandidates(remoteLogin, canonicalFolder).has(
      link.baseFingerprint
    )
    if (!localMatches && !remoteMatches) continue

    // If only the local legacy representation still equals the baseline, advance it to the
    // current local format so the ordinary planner recognizes a remote-only change and pulls it.
    if (!remoteMatches) {
      upgrades.push({
        localId: link.localId,
        remoteId: link.remoteId,
        customFields: cloneCustomFieldsForUpgrade(localLogin.customFields),
        baseFingerprint: fingerprintLogin(localLogin, localCanonicalFolder)
      })
      continue
    }

    if (localMatches && localHash === remoteHash) continue
    // The legacy hash cannot tell which side authored ignored new fields. If both sides now have
    // different non-default state, advancing either baseline would silently overwrite the other;
    // leave the old base in place so the ordinary planner creates a conflict copy.
    if (
      hasDistinctPostLegacyState(localLogin, remoteLogin) &&
      hasDistinctPostLegacyState(remoteLogin, localLogin)
    ) {
      continue
    }

    const upgrade: LegacyCustomFieldBaselineUpgrade = {
      localId: link.localId,
      remoteId: link.remoteId,
      customFields:
        localLogin.customFields.length === 0 && remoteLogin.customFields.length > 0
          ? cloneCustomFieldsForUpgrade(remoteLogin.customFields)
          : cloneCustomFieldsForUpgrade(localLogin.customFields),
      baseFingerprint: remoteHash
    }
    // A migrated pre-V11 local row has exactly the primary alias. Remote-only additional rows
    // were previously invisible and can be safely adopted; locally added/reordered rows remain.
    if (
      localLogin.uris.length <= 1 &&
      remoteLogin.uris.length > localLogin.uris.length &&
      localLogin.uri === remoteLogin.uri
    ) {
      upgrade.uris = remoteLogin.uris.map((entry) => ({ ...entry }))
    }
    // Pre-reprompt baselines could not represent a remote enable. Zero is the migration default,
    // so only that one-way default transition is adopted when both legacy hashes still match.
    if (localLogin.reprompt === 0 && remoteLogin.reprompt === 1) {
      upgrade.reprompt = remoteLogin.reprompt
    }
    if (localLogin.passwordHistory.length === 0 && remoteLogin.passwordHistory.length > 0) {
      upgrade.passwordHistory = remoteLogin.passwordHistory.map((entry) => ({ ...entry }))
    }
    if (localLogin.passwordRevisionDate === null && remoteLogin.passwordRevisionDate !== null) {
      upgrade.passwordRevisionDate = remoteLogin.passwordRevisionDate
    }
    if (localLogin.autofillOnPageLoad === null && remoteLogin.autofillOnPageLoad !== null) {
      upgrade.autofillOnPageLoad = remoteLogin.autofillOnPageLoad
    }
    upgrades.push(upgrade)
  }
  return upgrades
}

function cloneCustomFieldsForUpgrade(fields: readonly VaultCustomField[]): VaultCustomField[] {
  return fields.map((field) => ({ ...field }))
}

export function planSync(
  localSnapshot: SyncSnapshot,
  remoteSnapshot: SyncSnapshot,
  metadata: SyncMetadata = { version: 1, folderLinks: [], loginLinks: [] }
): SyncPlan {
  if (metadata.version !== 1) throw new Error('Unsupported sync metadata version')
  const actions: SyncAction[] = []
  const folderLinks: SyncLink[] = []
  const folderMapping = planFolders(localSnapshot, remoteSnapshot, metadata, actions, folderLinks)
  const localFolders = indexUnique(localSnapshot.folders, 'local folder')
  const remoteFolders = indexUnique(remoteSnapshot.folders, 'remote folder')
  const local = indexUnique(localSnapshot.logins, 'local login')
  const remote = indexUnique(remoteSnapshot.logins, 'remote login')
  const localTombstones = new Set(localSnapshot.tombstones.logins.map((value) => value.id))
  const links = indexLinks(metadata.loginLinks, 'login')
  const remoteLinked = new Set(metadata.loginLinks.map((link) => link.remoteId))
  const loginLinks: SyncLink[] = []
  const localFingerprint = (login: SyncLogin): string =>
    fingerprintLogin(login, folderName(login.folderId, localFolders))
  const remoteFingerprint = (login: SyncLogin): string =>
    fingerprintLogin(login, folderName(login.folderId, remoteFolders))
  const localContentFingerprint = (login: SyncLogin): string =>
    fingerprintLogin(
      { ...login, deletedAt: null, archivedAt: null },
      folderName(login.folderId, localFolders)
    )
  const remoteContentFingerprint = (login: SyncLogin): string =>
    fingerprintLogin(
      { ...login, deletedAt: null, archivedAt: null },
      folderName(login.folderId, remoteFolders)
    )

  for (const link of links.values()) {
    const localLogin = local.get(link.localId)
    const remoteLogin = remote.get(link.remoteId)
    if (localLogin && remoteLogin) {
      const localHash = localFingerprint(localLogin)
      const remoteHash = remoteFingerprint(remoteLogin)
      if (localHash === remoteHash) {
        loginLinks.push({ ...link, baseFingerprint: localHash })
      } else if (localHash === link.baseFingerprint) {
        actions.push({
          kind: 'pull-update',
          entity: 'login',
          actionId: `login:pull-update:${link.localId}`,
          localId: link.localId,
          remote: remoteLogin,
          localFolder:
            remoteLogin.folderId === null
              ? { id: null }
              : (folderMapping.remoteToLocal.get(remoteLogin.folderId) ?? { id: null }),
          baseFingerprint: remoteHash
        })
        loginLinks.push({ ...link, baseFingerprint: remoteHash })
      } else if (remoteHash === link.baseFingerprint) {
        const contentChanged =
          localContentFingerprint(localLogin) !== remoteContentFingerprint(remoteLogin)
        const resumeFingerprints = new Set<string>([remoteHash])
        const desiredDeleted = localLogin.deletedAt !== null
        const currentDeleted = remoteLogin.deletedAt !== null
        const desiredArchived = localLogin.archivedAt !== null
        const currentArchived = remoteLogin.archivedAt !== null
        let remoteStage = remoteLogin
        if (currentDeleted && (!desiredDeleted || contentChanged)) {
          remoteStage = { ...remoteStage, deletedAt: null }
          resumeFingerprints.add(
            fingerprintLogin(remoteStage, folderName(remoteLogin.folderId, remoteFolders))
          )
        }
        if (currentArchived && !desiredArchived) {
          remoteStage = { ...remoteStage, archivedAt: null }
          resumeFingerprints.add(
            fingerprintLogin(remoteStage, folderName(remoteLogin.folderId, remoteFolders))
          )
        }
        if (contentChanged) {
          resumeFingerprints.add(
            fingerprintLogin(
              { ...localLogin, deletedAt: null },
              folderName(localLogin.folderId, localFolders)
            )
          )
        }
        resumeFingerprints.add(localHash)
        actions.push({
          kind: 'push-update',
          entity: 'login',
          actionId: `login:push-update:${link.remoteId}`,
          local: localLogin,
          remote: remoteLogin,
          remoteId: link.remoteId,
          remoteFolder:
            localLogin.folderId === null
              ? { id: null }
              : (folderMapping.localToRemote.get(localLogin.folderId) ?? { id: null }),
          contentChanged,
          resumeFingerprints: [...resumeFingerprints],
          baseFingerprint: localHash
        })
        loginLinks.push({ ...link, baseFingerprint: localHash })
      } else {
        const copyName = conflictName(localLogin.name)
        actions.push({
          kind: 'conflict-copy',
          entity: 'login',
          actionId: `login:conflict:${link.localId}`,
          reason: 'both-modified',
          resolution: 'remote-primary-local-copy',
          local: localLogin,
          remote: remoteLogin,
          conflictName: copyName,
          conflictFingerprint: localFingerprint({ ...localLogin, name: copyName }),
          localFolder:
            remoteLogin.folderId === null
              ? { id: null }
              : (folderMapping.remoteToLocal.get(remoteLogin.folderId) ?? { id: null }),
          remoteFolder:
            localLogin.folderId === null
              ? { id: null }
              : (folderMapping.localToRemote.get(localLogin.folderId) ?? { id: null }),
          baseFingerprint: remoteHash
        })
        loginLinks.push({ ...link, baseFingerprint: remoteHash })
      }
      local.delete(link.localId)
      remote.delete(link.remoteId)
    } else if (localLogin) {
      const hash = localFingerprint(localLogin)
      // A soft-deleted item has no content worth resurrecting when the linked remote item was
      // permanently deleted. Let the irreversible deletion win even though the trash-state bit
      // necessarily differs from the last active baseline.
      if (localLogin.deletedAt !== null || hash === link.baseFingerprint) {
        actions.push({
          kind: 'delete-local',
          entity: 'login',
          actionId: `login:delete-local:${link.localId}`,
          localId: link.localId
        })
      } else {
        const copyName = conflictName(localLogin.name)
        const actionId = `login:conflict-remote-deleted:${link.localId}`
        actions.push({
          kind: 'conflict-copy',
          entity: 'login',
          actionId,
          pendingKey: actionId,
          reason: 'remote-deleted',
          resolution: 'deleted-primary-linked-conflict-copy',
          local: localLogin,
          remote: null,
          conflictName: copyName,
          conflictFingerprint: localFingerprint({ ...localLogin, name: copyName }),
          localFolder: { id: null },
          remoteFolder:
            localLogin.folderId === null
              ? { id: null }
              : (folderMapping.localToRemote.get(localLogin.folderId) ?? { id: null })
        })
      }
      local.delete(link.localId)
    } else if (remoteLogin) {
      const hash = remoteFingerprint(remoteLogin)
      if (
        localTombstones.has(link.localId) &&
        (remoteLogin.deletedAt !== null || hash === link.baseFingerprint)
      ) {
        actions.push({
          kind: 'delete-remote',
          entity: 'login',
          actionId: `login:delete-remote:${link.remoteId}`,
          remoteId: link.remoteId
        })
      } else if (localTombstones.has(link.localId)) {
        const copyName = conflictName(remoteLogin.name)
        const actionId = `login:conflict-local-deleted:${link.remoteId}`
        actions.push({
          kind: 'conflict-copy',
          entity: 'login',
          actionId,
          pendingKey: actionId,
          reason: 'local-deleted',
          resolution: 'deleted-primary-linked-conflict-copy',
          local: null,
          remote: remoteLogin,
          conflictName: copyName,
          conflictFingerprint: remoteFingerprint({ ...remoteLogin, name: copyName }),
          localFolder:
            remoteLogin.folderId === null
              ? { id: null }
              : (folderMapping.remoteToLocal.get(remoteLogin.folderId) ?? { id: null }),
          remoteFolder: { id: null }
        })
      } else {
        const actionId = `login:pull-create:${link.remoteId}`
        actions.push({
          kind: 'pull-create',
          entity: 'login',
          actionId,
          pendingKey: actionId,
          remote: remoteLogin,
          localFolder:
            remoteLogin.folderId === null
              ? { id: null }
              : (folderMapping.remoteToLocal.get(remoteLogin.folderId) ?? { id: null }),
          baseFingerprint: hash
        })
      }
      remote.delete(link.remoteId)
    }
  }

  const pairs = uniqueFingerprintPairs(
    [...local.values()],
    [...remote.values()],
    localFingerprint,
    remoteFingerprint
  )
  for (const pair of pairs) {
    local.delete(pair.local.id)
    remote.delete(pair.remote.id)
    loginLinks.push({
      localId: pair.local.id,
      remoteId: pair.remote.id,
      baseFingerprint: pair.fingerprint
    })
  }
  for (const login of local.values()) {
    // A locally-created item deleted before its first successful sync has no remote lifecycle to
    // preserve. Uploading it would require create -> soft-delete and could expose or duplicate the
    // secret if the second request fails.
    if (login.deletedAt !== null) continue
    const actionId = `login:push-create:${login.id}`
    actions.push({
      kind: 'push-create',
      entity: 'login',
      actionId,
      pendingKey: actionId,
      local: login,
      remoteFolder:
        login.folderId === null
          ? { id: null }
          : (folderMapping.localToRemote.get(login.folderId) ?? { id: null }),
      baseFingerprint: localFingerprint(login)
    })
  }
  for (const login of remote.values()) {
    if (remoteLinked.has(login.id)) continue
    const actionId = `login:pull-create:${login.id}`
    actions.push({
      kind: 'pull-create',
      entity: 'login',
      actionId,
      pendingKey: actionId,
      remote: login,
      localFolder:
        login.folderId === null
          ? { id: null }
          : (folderMapping.remoteToLocal.get(login.folderId) ?? { id: null }),
      baseFingerprint: remoteFingerprint(login)
    })
  }
  return { actions, nextMetadata: { version: 1, folderLinks, loginLinks } }
}

export function completeSyncMetadata(
  plan: SyncPlan,
  results: readonly SyncActionResult[]
): SyncMetadata {
  const byAction = new Map(results.map((result) => [result.actionId, result]))
  const deletedLocalFolders = new Set(
    plan.actions.flatMap((action) =>
      action.kind === 'delete-local' && action.entity === 'folder' ? [action.localId] : []
    )
  )
  const deletedRemoteFolders = new Set(
    plan.actions.flatMap((action) =>
      action.kind === 'delete-remote' && action.entity === 'folder' ? [action.remoteId] : []
    )
  )
  const deletedLocalLogins = new Set(
    plan.actions.flatMap((action) =>
      action.kind === 'delete-local' && action.entity === 'login' ? [action.localId] : []
    )
  )
  const deletedRemoteLogins = new Set(
    plan.actions.flatMap((action) =>
      action.kind === 'delete-remote' && action.entity === 'login' ? [action.remoteId] : []
    )
  )
  const folderLinks = plan.nextMetadata.folderLinks.filter(
    (link) => !deletedLocalFolders.has(link.localId) && !deletedRemoteFolders.has(link.remoteId)
  )
  const loginLinks = plan.nextMetadata.loginLinks.filter(
    (link) => !deletedLocalLogins.has(link.localId) && !deletedRemoteLogins.has(link.remoteId)
  )
  const addLink = (target: SyncLink[], link: SyncLink): void => {
    const duplicate = target.find(
      (candidate) => candidate.localId === link.localId || candidate.remoteId === link.remoteId
    )
    if (duplicate) {
      if (
        duplicate.localId !== link.localId ||
        duplicate.remoteId !== link.remoteId ||
        duplicate.baseFingerprint !== link.baseFingerprint
      ) {
        throw new Error('Conflicting sync action results')
      }
      return
    }
    target.push(link)
  }
  for (const action of plan.actions) {
    const result = byAction.get(action.actionId)
    if (action.kind === 'push-create' || action.kind === 'pull-create') {
      if (!result) continue
      const localId = action.kind === 'push-create' ? action.local.id : result.localId
      const remoteId = action.kind === 'pull-create' ? action.remote.id : result.remoteId
      if (!localId || !remoteId || !action.baseFingerprint) continue
      const link = {
        localId,
        remoteId,
        baseFingerprint: result.fingerprint ?? action.baseFingerprint
      }
      addLink(action.entity === 'folder' ? folderLinks : loginLinks, link)
      continue
    }
    if ((action.kind === 'push-update' || action.kind === 'pull-update') && result?.fingerprint) {
      const localId = action.kind === 'push-update' ? action.local.id : action.localId
      const remoteId = action.kind === 'pull-update' ? action.remote.id : action.remoteId
      const target = action.entity === 'folder' ? folderLinks : loginLinks
      const index = target.findIndex(
        (link) => link.localId === localId && link.remoteId === remoteId
      )
      if (index >= 0) target[index] = { localId, remoteId, baseFingerprint: result.fingerprint }
      continue
    }
    if (action.kind !== 'conflict-copy' || !result) continue

    let localId = result.localId
    let remoteId = result.remoteId
    if (action.reason === 'local-deleted') remoteId ??= action.remote?.id
    if (action.reason === 'remote-deleted') localId ??= action.local?.id
    if (!localId || !remoteId) continue
    addLink(action.entity === 'folder' ? folderLinks : loginLinks, {
      localId,
      remoteId,
      baseFingerprint: result.fingerprint ?? action.conflictFingerprint
    })
  }
  return { version: 1, folderLinks, loginLinks }
}
