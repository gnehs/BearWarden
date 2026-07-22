import { randomUUID } from 'node:crypto'
import type { BitwardenDirectState } from '../bitwarden-direct'
import { resolveBitwardenUrls } from '../bitwarden-http'
import { VaultError } from '../vault-errors'
import {
  MAX_PENDING_LOGIN_IMPORT_ENTRIES,
  MAX_PENDING_LOGIN_IMPORT_MARKER_LENGTH,
  MAX_REMOTE_ENTITIES,
  MAX_SYNC_SECRET_LENGTH,
  MAX_URI_LENGTH,
  MAX_USERNAME_LENGTH,
  UUID_PATTERN
} from './limits'
import { assertIsoDate, isRecord } from './parse-primitives'
import { parseStoredEquivalentDomainSettings } from './equivalent-domains'
import type {
  PendingLoginImport,
  PendingLoginImportEntry,
  PendingLoginMutation,
  PendingPersonalVaultPurge,
  PersistedSyncData,
  SyncEntityMapping,
  SyncTombstone
} from './types'

export function parseSyncMappings(
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

export function parseDirectState(value: unknown): BitwardenDirectState {
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

  // parseVaultData replaces this migration-safe default with the strictly parsed stored policy
  // snapshot. Keeping the default here also covers legacy and CLI-imported state.
  return {
    session,
    deviceIdentifier,
    profileId,
    securityStamp,
    policySet: { source: 'none', policies: [] }
  }
}

export function parseSyncData(
  value: unknown,
  folderIds: Set<string>,
  loginIds: Set<string>,
  isCliData: boolean,
  allowMissingPendingMutation: boolean,
  allowMissingPendingImport: boolean,
  allowMissingPendingPurge: boolean,
  allowMissingDomainSettings: boolean
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

  let pendingLoginMutation: PendingLoginMutation | null = null
  if (value.pendingLoginMutation !== null && value.pendingLoginMutation !== undefined) {
    const pending = value.pendingLoginMutation
    if (
      !isRecord(pending) ||
      (pending.intent !== 'converge' && pending.intent !== 'hard-delete') ||
      typeof pending.localId !== 'string' ||
      !UUID_PATTERN.test(pending.localId) ||
      typeof pending.remoteId !== 'string' ||
      !UUID_PATTERN.test(pending.remoteId) ||
      (pending.remoteFolderId !== null &&
        (typeof pending.remoteFolderId !== 'string' ||
          !UUID_PATTERN.test(pending.remoteFolderId))) ||
      !Array.isArray(pending.expectedRemoteFingerprints) ||
      pending.expectedRemoteFingerprints.length === 0 ||
      pending.expectedRemoteFingerprints.length > 5 ||
      pending.expectedRemoteFingerprints.some(
        (fingerprint) => typeof fingerprint !== 'string' || !/^[0-9a-f]{64}$/.test(fingerprint)
      ) ||
      new Set(pending.expectedRemoteFingerprints).size !==
        pending.expectedRemoteFingerprints.length ||
      !(pending.intent === 'converge'
        ? loginMappings.some(
            (mapping) =>
              mapping.localId === pending.localId && mapping.remoteId === pending.remoteId
          )
        : loginTombstones.some(
            (tombstone) =>
              tombstone.localId === pending.localId && tombstone.remoteId === pending.remoteId
          ))
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    pendingLoginMutation = {
      intent: pending.intent,
      localId: pending.localId,
      remoteId: pending.remoteId,
      remoteFolderId: pending.remoteFolderId,
      expectedRemoteFingerprints: [...pending.expectedRemoteFingerprints]
    }
  } else if (!allowMissingPendingMutation && value.pendingLoginMutation === undefined) {
    throw new VaultError('CORRUPT_VAULT')
  }

  let pendingLoginImport: PendingLoginImport | null = null
  if (value.pendingLoginImport !== null && value.pendingLoginImport !== undefined) {
    const pending = value.pendingLoginImport
    if (
      !isRecord(pending) ||
      Reflect.ownKeys(pending).length !== 3 ||
      !Object.hasOwn(pending, 'phase') ||
      !Object.hasOwn(pending, 'startedAt') ||
      !Object.hasOwn(pending, 'entries') ||
      (pending.phase !== 'prepared' &&
        pending.phase !== 'dispatched' &&
        pending.phase !== 'retry-approved') ||
      typeof pending.startedAt !== 'string' ||
      !Number.isFinite(Date.parse(pending.startedAt)) ||
      !Array.isArray(pending.entries) ||
      pending.entries.length < 1 ||
      (pending.phase === 'prepared' && pending.entries.length < 2) ||
      pending.entries.length > MAX_PENDING_LOGIN_IMPORT_ENTRIES
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    const entries: PendingLoginImportEntry[] = []
    const localIds = new Set<string>()
    const markers = new Set<string>()
    for (const entry of pending.entries) {
      if (
        !isRecord(entry) ||
        Reflect.ownKeys(entry).length !== 4 ||
        !Object.hasOwn(entry, 'localId') ||
        !Object.hasOwn(entry, 'marker') ||
        !Object.hasOwn(entry, 'remoteFolderId') ||
        !Object.hasOwn(entry, 'baseFingerprint') ||
        typeof entry.localId !== 'string' ||
        !UUID_PATTERN.test(entry.localId) ||
        !loginIds.has(entry.localId) ||
        localIds.has(entry.localId) ||
        loginMappings.some((mapping) => mapping.localId === entry.localId) ||
        loginTombstones.some((tombstone) => tombstone.localId === entry.localId) ||
        typeof entry.marker !== 'string' ||
        entry.marker.length === 0 ||
        entry.marker.length > MAX_PENDING_LOGIN_IMPORT_MARKER_LENGTH ||
        /[\0\r\n]/u.test(entry.marker) ||
        markers.has(entry.marker) ||
        typeof entry.baseFingerprint !== 'string' ||
        !/^[0-9a-f]{64}$/u.test(entry.baseFingerprint) ||
        (entry.remoteFolderId !== null &&
          (typeof entry.remoteFolderId !== 'string' || !UUID_PATTERN.test(entry.remoteFolderId)))
      ) {
        throw new VaultError('CORRUPT_VAULT')
      }
      localIds.add(entry.localId)
      markers.add(entry.marker)
      entries.push({
        localId: entry.localId,
        marker: entry.marker,
        remoteFolderId: entry.remoteFolderId,
        baseFingerprint: entry.baseFingerprint
      })
    }
    pendingLoginImport = {
      phase: pending.phase,
      startedAt: new Date(pending.startedAt).toISOString(),
      entries
    }
  } else if (!allowMissingPendingImport && value.pendingLoginImport === undefined) {
    throw new VaultError('CORRUPT_VAULT')
  }
  if (pendingLoginMutation && pendingLoginImport) throw new VaultError('CORRUPT_VAULT')

  let pendingPersonalVaultPurge: PendingPersonalVaultPurge | null = null
  if (value.pendingPersonalVaultPurge !== null && value.pendingPersonalVaultPurge !== undefined) {
    const pending = value.pendingPersonalVaultPurge
    if (
      !isRecord(pending) ||
      Reflect.ownKeys(pending).length !== 4 ||
      !Object.hasOwn(pending, 'phase') ||
      !Object.hasOwn(pending, 'startedAt') ||
      !Object.hasOwn(pending, 'remainingItems') ||
      !Object.hasOwn(pending, 'remainingFolders') ||
      (pending.phase !== 'prepared' && pending.phase !== 'dispatched') ||
      typeof pending.startedAt !== 'string' ||
      !Number.isFinite(Date.parse(pending.startedAt)) ||
      new Date(pending.startedAt).toISOString() !== pending.startedAt ||
      !Number.isSafeInteger(pending.remainingItems) ||
      (pending.remainingItems as number) < 0 ||
      (pending.remainingItems as number) > MAX_REMOTE_ENTITIES ||
      !Number.isSafeInteger(pending.remainingFolders) ||
      (pending.remainingFolders as number) < 0 ||
      (pending.remainingFolders as number) > MAX_REMOTE_ENTITIES
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    pendingPersonalVaultPurge = {
      phase: pending.phase,
      startedAt: pending.startedAt,
      remainingItems: pending.remainingItems as number,
      remainingFolders: pending.remainingFolders as number
    }
  } else if (!allowMissingPendingPurge && value.pendingPersonalVaultPurge === undefined) {
    throw new VaultError('CORRUPT_VAULT')
  }
  if (pendingPersonalVaultPurge && (pendingLoginMutation !== null || pendingLoginImport !== null)) {
    throw new VaultError('CORRUPT_VAULT')
  }

  const domainSettings =
    value.domainSettings === undefined && allowMissingDomainSettings
      ? null
      : value.domainSettings === null
        ? null
        : parseStoredEquivalentDomainSettings(value.domainSettings)

  return {
    provider: 'bitwarden',
    serverUrl: value.serverUrl,
    email: value.email,
    state: isCliData
      ? {
          session: null,
          deviceIdentifier: randomUUID(),
          profileId: null,
          securityStamp: null,
          policySet: { source: 'none', policies: [] }
        }
      : parseDirectState(value.state),
    lastSyncAt: value.lastSyncAt,
    folderMappings,
    loginMappings,
    folderTombstones,
    loginTombstones,
    pendingLoginMutation,
    pendingLoginImport,
    pendingPersonalVaultPurge,
    domainSettings
  }
}

export function recordSyncDeletion(
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
    if (sync.pendingLoginMutation?.localId === localId) {
      sync.pendingLoginMutation.intent = 'hard-delete'
    }
  }
}

export function assertNoPendingLoginImport(sync: PersistedSyncData | null): void {
  if (sync?.pendingLoginImport) throw new VaultError('SYNC_FAILED')
}

export function assertNoPendingPersonalVaultPurge(sync: PersistedSyncData | null): void {
  if (sync?.pendingPersonalVaultPurge) throw new VaultError('SYNC_FAILED')
}
