import type { VaultCore } from './core'
import type { PinUnlockInvalidator } from './pin-unlock-state'
import type { VaultSyncSession } from './sync-session'
import type {
  OrganizationView,
  CollectionView,
  SyncPurgePersonalVaultResult,
  SyncResult
} from '../../shared/vault-contract'
import {
  BitwardenDirectError,
  type BitwardenFolder,
  type BitwardenLoginItem,
  type BitwardenSendItem,
  type BitwardenSyncClient
} from '../bitwarden-direct'
import { BITWARDEN_POLICY_TYPE } from '../bitwarden-policy'
import {
  completeSyncMetadata,
  fingerprintLogin,
  legacyCustomFieldBaselineUpgrades,
  planSync,
  type SyncAction,
  type SyncActionResult,
  type SyncLink
} from '../sync-merge'
import { VaultError } from '../vault-errors'
import { MAX_PENDING_LOGIN_IMPORT_ENTRIES, MAX_PENDING_LOGIN_IMPORT_MARKER_LENGTH } from './limits'
import { cloneData } from './vault-data-parsing'
import { isCompositeRemoteLoginUpdate } from './views'
import { sendViewFromRemote } from './send-parsing'
import { cloneCustomFields } from './custom-fields'
import { cloneLoginUris, uriAlias } from './login-uris'
import {
  cloneEquivalentDomainSettings,
  validateRemoteEquivalentDomainSettings
} from './equivalent-domains'
import { parseStoredOrganization, parseStoredCollection } from './org-collection-parsing'
import { clonePasswordHistory } from './password-history'
import type { StoredSharedLogin, VaultData } from './types'
import { UUID_PATTERN, isRecord } from '../validation-primitives'
import { findFolder, findLogin } from './data-lookup'
import { bitwardenPolicyDecision } from './policy'
import {
  localSyncSnapshot,
  remoteSyncSnapshot,
  syncMetadataOf,
  withoutProtectedLoginSnapshot,
  reattachProtectedLoginLinks,
  getSyncEquivalentDomainSettings,
  isolatedPersonalCipherIdsOf,
  findNewlyIsolatedMappedRemoteIds,
  supportsLoginImport,
  supportsBulkRemoteLoginMutation,
  bulkRemoteLoginMutationApplied,
  resolveFolderReference,
  remoteDraft,
  hasPendingLocalSyncWork,
  reconcileServerAuthoritativeAttachments,
  loginImportCandidate,
  bulkRemoteLoginCandidate,
  updateRemoteLogin,
  throwSharedSnapshotError,
  MAX_REMOTE_LOGIN_BATCH_IDS,
  type BulkRemoteLoginCandidate,
  type LoginImportCandidate
} from './sync-snapshots'
import {
  createLocalLogin,
  sharedLoginFromRemote,
  updateLocalLogin,
  createLocalFolder,
  deleteLocalFolder
} from './local-records'

function changesRemote(action: SyncAction): boolean {
  if (action.kind === 'conflict-copy') return action.reason !== 'both-modified'
  return (
    action.kind === 'push-create' ||
    action.kind === 'push-update' ||
    action.kind === 'delete-remote'
  )
}

/**
 * The sync engine: one authoritative two-way merge between the local vault and the Bitwarden
 * account, including the resumable login-mutation, login-import and personal-vault-purge journals.
 * Callers hold the sync-operation lease and the vault mutex for the whole run.
 */
export class VaultSyncEngine {
  constructor(
    private readonly core: VaultCore,
    private readonly syncSession: VaultSyncSession,
    private readonly pinUnlock: PinUnlockInvalidator
  ) {}

  async performSync(
    current: VaultData,
    client: BitwardenSyncClient,
    signal: AbortSignal
  ): Promise<SyncResult> {
    const syncStartedAt = this.core.nowIso()
    let source = current
    const pendingPurge = source.sync?.pendingPersonalVaultPurge
    if (pendingPurge?.phase === 'prepared') {
      const cleared = cloneData(source)
      if (!cleared.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
      cleared.sync.pendingPersonalVaultPurge = null
      cleared.updatedAt = this.core.nowIso()
      await this.core.commit(cleared)
      source = cleared
    } else if (pendingPurge?.phase === 'dispatched') {
      const reconciled = await this.reconcilePersonalVaultPurge(client)
      if (reconciled.status === 'pending') throw new VaultError('SYNC_FAILED')
      const completedSync = this.syncSession.requireSyncData()
      return {
        ...this.syncSession.baseSyncStatus(completedSync, 'ready'),
        pulled: 0,
        pushed: 0,
        deleted: reconciled.removedItems + reconciled.removedFolders,
        conflicts: 0
      }
    }
    let sync = source.sync
    if (!sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    const unchanged = await this.skipUnchangedRemoteSync(source, client, signal, syncStartedAt)
    if (unchanged) return unchanged
    await client.sync(signal)
    const initialIsolatedPersonalCipherIds = isolatedPersonalCipherIdsOf(client)
    if (initialIsolatedPersonalCipherIds.size > 0) {
      // Persist the full-sync requirement before any later parsing, shared-vault read, or mutation
      // can fail. Otherwise a revision fast path could hide the quarantined personal ciphers.
      await this.persistCipherIsolationRecovery([], initialIsolatedPersonalCipherIds)
      source = this.core.requireData()
      sync = source.sync
      if (!sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    }
    const protectedLoginMappings = sync.loginMappings.filter((entry) =>
      initialIsolatedPersonalCipherIds.has(entry.remoteId)
    )
    const protectedLoginTombstones = sync.loginTombstones.filter((entry) =>
      initialIsolatedPersonalCipherIds.has(entry.remoteId)
    )
    const protectedLocalLoginIds = new Set(
      [...protectedLoginMappings, ...protectedLoginTombstones].map((entry) => entry.localId)
    )
    const protectedRemoteLoginIds = new Set(
      [...protectedLoginMappings, ...protectedLoginTombstones].map((entry) => entry.remoteId)
    )
    const mappedLoginLinksBeforeActions = [...sync.loginMappings, ...sync.loginTombstones]
    const sharedSnapshot = await this.fetchSharedSnapshot(client)
    const initialRemote = await Promise.all([
      client.listFolders(signal),
      client.listPersonalLogins(signal),
      getSyncEquivalentDomainSettings(
        client,
        sync.domainSettings ?? { equivalentDomains: [], globalEquivalentDomains: [] },
        signal
      ),
      client.listSends?.(signal) ?? Promise.resolve([] as BitwardenSendItem[])
    ])
    let remoteFolders = initialRemote[0]
    let remoteLogins = initialRemote[1]
    validateRemoteEquivalentDomainSettings(initialRemote[2])
    let remoteSends = initialRemote[3]
    const next = cloneData(source)
    if (sharedSnapshot) {
      next.organizations = sharedSnapshot.organizations
      next.collections = sharedSnapshot.collections
      next.sharedLogins = sharedSnapshot.sharedLogins
    }
    if (
      next.sync?.pendingLoginMutation &&
      initialIsolatedPersonalCipherIds.has(next.sync.pendingLoginMutation.remoteId)
    ) {
      // A pending mutation is an unresolved remote operation, so quarantine leaves its outcome
      // ambiguous. Keep the durable journal intact and retry only after the cipher is readable.
      throw new VaultError('SYNC_FAILED')
    }
    if (next.sync?.pendingLoginMutation) {
      await this.resumePendingLoginMutation(next, client, remoteFolders, remoteLogins, signal)
      await client.sync(signal)
      const refreshedIsolatedPersonalCipherIds = isolatedPersonalCipherIdsOf(client)
      if (refreshedIsolatedPersonalCipherIds.size > 0) {
        await this.persistCipherIsolationRecovery([], refreshedIsolatedPersonalCipherIds)
        if (next.sync) next.sync.requiresFullSyncAfterCipherIsolation = true
      }
      const newlyIsolatedPendingRemoteIds = findNewlyIsolatedMappedRemoteIds(
        refreshedIsolatedPersonalCipherIds,
        [...(next.sync?.loginMappings ?? []), ...(next.sync?.loginTombstones ?? [])],
        protectedRemoteLoginIds
      )
      if (newlyIsolatedPendingRemoteIds.size > 0) {
        throw new VaultError('SYNC_FAILED')
      }
      const refreshed = await Promise.all([
        client.listFolders(signal),
        client.listPersonalLogins(signal),
        client.listSends?.(signal) ?? Promise.resolve([] as BitwardenSendItem[])
      ])
      remoteFolders = refreshed[0]
      remoteLogins = refreshed[1]
      remoteSends = refreshed[2]
    }
    const skipBulkImportLocalIds = new Set<string>()
    if (next.sync?.pendingLoginImport) {
      const pendingImportPhase = next.sync.pendingLoginImport.phase
      const unmatched = await this.reconcilePendingLoginImport(
        next,
        client,
        remoteFolders,
        remoteLogins,
        signal
      )
      if (unmatched.length > 0) {
        if (pendingImportPhase === 'dispatched') {
          throw new VaultError('SYNC_FAILED')
        }
        for (const localId of unmatched) skipBulkImportLocalIds.add(localId)
      }
    }
    const remoteSnapshot = remoteSyncSnapshot(remoteFolders, remoteLogins)
    const syncMetadata = syncMetadataOf(next.sync ?? sync)
    syncMetadata.loginLinks = syncMetadata.loginLinks.filter(
      (entry) => !initialIsolatedPersonalCipherIds.has(entry.remoteId)
    )
    for (const upgrade of legacyCustomFieldBaselineUpgrades(
      withoutProtectedLoginSnapshot(localSyncSnapshot(next), protectedLocalLoginIds),
      remoteSnapshot,
      syncMetadata
    )) {
      const upgradedLogin = findLogin(next, upgrade.localId)
      upgradedLogin.customFields = cloneCustomFields(upgrade.customFields)
      if (upgrade.uris) {
        upgradedLogin.uris = cloneLoginUris(upgrade.uris)
        upgradedLogin.uri = uriAlias(upgradedLogin.uris)
      }
      if (upgrade.reprompt !== undefined) upgradedLogin.reprompt = upgrade.reprompt
      if (upgrade.passwordHistory) {
        upgradedLogin.passwordHistory = clonePasswordHistory(upgrade.passwordHistory)
      }
      if (upgrade.passwordRevisionDate !== undefined) {
        upgradedLogin.passwordRevisionDate = upgrade.passwordRevisionDate
      }
      if (upgrade.autofillOnPageLoad !== undefined) {
        upgradedLogin.autofillOnPageLoad = upgrade.autofillOnPageLoad
      }
      const mapping = next.sync?.loginMappings.find(
        (entry) => entry.localId === upgrade.localId && entry.remoteId === upgrade.remoteId
      )
      if (mapping) mapping.baseFingerprint = upgrade.baseFingerprint
      const metadataLink = syncMetadata.loginLinks.find(
        (entry) => entry.localId === upgrade.localId && entry.remoteId === upgrade.remoteId
      )
      if (metadataLink) metadataLink.baseFingerprint = upgrade.baseFingerprint
    }
    const plan = planSync(
      withoutProtectedLoginSnapshot(localSyncSnapshot(next), protectedLocalLoginIds),
      remoteSnapshot,
      syncMetadata
    )
    const results: SyncActionResult[] = []
    const completed = new Map<string, SyncActionResult>()
    const counts = { pulled: 0, pushed: 0, deleted: 0, conflicts: 0 }

    for (let actionIndex = 0; actionIndex < plan.actions.length; actionIndex += 1) {
      const action = plan.actions[actionIndex]!
      if (signal.aborted) throw new BitwardenDirectError('ABORTED')
      const importCandidate = loginImportCandidate(action, completed, skipBulkImportLocalIds)
      if (importCandidate && supportsLoginImport(client)) {
        const batch: LoginImportCandidate[] = [importCandidate]
        for (let nextIndex = actionIndex + 1; nextIndex < plan.actions.length; nextIndex += 1) {
          if (batch.length === MAX_PENDING_LOGIN_IMPORT_ENTRIES) break
          const candidate = loginImportCandidate(
            plan.actions[nextIndex]!,
            completed,
            skipBulkImportLocalIds
          )
          if (candidate === null) break
          batch.push(candidate)
        }
        if (batch.length > 1) {
          const remoteIds = await this.executeLoginImportBatch(next, client, batch, signal)
          for (const candidate of batch) {
            const remoteId = remoteIds.get(candidate.action.actionId)
            if (!remoteId) throw new VaultError('SYNC_FAILED')
            const result: SyncActionResult = {
              actionId: candidate.action.actionId,
              remoteId
            }
            results.push(result)
            completed.set(candidate.action.actionId, result)
            counts.pushed += 1
          }
          actionIndex += batch.length - 1
          continue
        }
      }
      const batchCandidate = bulkRemoteLoginCandidate(action, completed)
      if (batchCandidate && supportsBulkRemoteLoginMutation(client, batchCandidate.mutation)) {
        const batch: BulkRemoteLoginCandidate[] = [batchCandidate]
        for (let nextIndex = actionIndex + 1; nextIndex < plan.actions.length; nextIndex += 1) {
          if (batch.length === MAX_REMOTE_LOGIN_BATCH_IDS) break
          const candidate = bulkRemoteLoginCandidate(plan.actions[nextIndex]!, completed)
          if (
            candidate === null ||
            candidate.mutation !== batchCandidate.mutation ||
            candidate.folderId !== batchCandidate.folderId
          ) {
            break
          }
          batch.push(candidate)
        }
        if (batch.length > 1) {
          await this.executeBulkRemoteLoginMutation(client, batch, signal)
          for (const candidate of batch) {
            const result: SyncActionResult = { actionId: candidate.action.actionId }
            results.push(result)
            completed.set(candidate.action.actionId, result)
            if (candidate.action.kind === 'delete-remote') counts.deleted += 1
            else counts.pushed += 1
          }
          actionIndex += batch.length - 1
          continue
        }
      }
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
    const completedLoginLinks = reattachProtectedLoginLinks(
      metadata.loginLinks,
      protectedLoginMappings,
      protectedLoginTombstones
    )
    // A plan that only touched local data leaves the server as the last download saw it.
    if (plan.actions.some(changesRemote)) await client.sync(signal)
    const finalIsolatedPersonalCipherIds = isolatedPersonalCipherIdsOf(client)
    const newlyIsolatedMappedRemoteIds = findNewlyIsolatedMappedRemoteIds(
      finalIsolatedPersonalCipherIds,
      [
        ...mappedLoginLinksBeforeActions,
        ...completedLoginLinks.loginMappings,
        ...completedLoginLinks.loginTombstones
      ],
      protectedRemoteLoginIds
    )
    if (
      finalIsolatedPersonalCipherIds.size > 0 &&
      (initialIsolatedPersonalCipherIds.size === 0 || newlyIsolatedMappedRemoteIds.size > 0)
    ) {
      await this.persistCipherIsolationRecovery(metadata.loginLinks, newlyIsolatedMappedRemoteIds)
      if (next.sync) next.sync.requiresFullSyncAfterCipherIsolation = true
    }
    if (newlyIsolatedMappedRemoteIds.size > 0) {
      throw new VaultError('SYNC_FAILED')
    }
    const [finalRemoteFolders, finalRemoteLogins, finalDomainSettings] = await Promise.all([
      client.listFolders(signal),
      client.listPersonalLogins(signal),
      getSyncEquivalentDomainSettings(client, initialRemote[2], signal)
    ])
    const finalSharedSnapshot = await this.fetchSharedSnapshot(client)
    const finalRemoteSends = client.listSends ? await client.listSends(signal) : remoteSends
    reconcileServerAuthoritativeAttachments(
      next,
      metadata.loginLinks,
      finalRemoteFolders,
      finalRemoteLogins
    )
    next.sends = finalRemoteSends.map(sendViewFromRemote)
    if (finalSharedSnapshot) {
      next.organizations = finalSharedSnapshot.organizations
      next.collections = finalSharedSnapshot.collections
      next.sharedLogins = finalSharedSnapshot.sharedLogins
    }
    const syncedAt = syncStartedAt
    next.sync = {
      ...sync,
      state: client.exportState(),
      lastSyncAt: syncedAt,
      requiresFullSyncAfterCipherIsolation:
        initialIsolatedPersonalCipherIds.size > 0 || finalIsolatedPersonalCipherIds.size > 0,
      folderMappings: metadata.folderLinks.map((link) => ({ ...link })),
      loginMappings: completedLoginLinks.loginMappings,
      folderTombstones: [],
      loginTombstones: completedLoginLinks.loginTombstones,
      pendingLoginMutation: next.sync?.pendingLoginMutation ?? null,
      pendingLoginImport: null,
      pendingPersonalVaultPurge: null,
      domainSettings: cloneEquivalentDomainSettings(
        validateRemoteEquivalentDomainSettings(finalDomainSettings)
      )
    }
    next.updatedAt = syncedAt
    await this.core.commit(next)
    this.applyBitwardenPolicyRuntimeState(next)
    this.syncSession.clearSyncErrorState()
    return { ...this.syncSession.baseSyncStatus(next.sync, 'ready'), ...counts }
  }

  private async skipUnchangedRemoteSync(
    source: VaultData,
    client: BitwardenSyncClient,
    signal: AbortSignal,
    syncStartedAt: string
  ): Promise<SyncResult | null> {
    const sync = source.sync
    if (!sync?.lastSyncAt || !Number.isFinite(Date.parse(sync.lastSyncAt))) return null
    if (hasPendingLocalSyncWork(source)) return null
    const revisionDate = client.revisionDate
    if (!revisionDate) return null

    let remoteRevision: string
    try {
      remoteRevision = await revisionDate.call(client, signal)
    } catch {
      // The revision endpoint is an optimization. A full sync remains the authoritative fallback.
      return null
    }
    if (
      !Number.isFinite(Date.parse(remoteRevision)) ||
      Date.parse(remoteRevision) > Date.parse(sync.lastSyncAt)
    ) {
      return null
    }

    const completed = cloneData(source)
    if (!completed.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    completed.sync.state = client.exportState()
    completed.sync.lastSyncAt = syncStartedAt
    completed.updatedAt = syncStartedAt
    await this.core.commit(completed)
    this.applyBitwardenPolicyRuntimeState(completed)
    this.syncSession.clearSyncErrorState()
    return {
      ...this.syncSession.baseSyncStatus(completed.sync, 'ready'),
      pulled: 0,
      pushed: 0,
      deleted: 0,
      conflicts: 0
    }
  }

  private async fetchSharedSnapshot(client: BitwardenSyncClient): Promise<{
    organizations: OrganizationView[]
    collections: CollectionView[]
    sharedLogins: StoredSharedLogin[]
  } | null> {
    if (!client.listOrganizations || !client.listCollections || !client.listOrganizationCiphers) {
      return null
    }
    const [organizations, collections, sharedLogins] = await Promise.all([
      client.listOrganizations().catch((error) => throwSharedSnapshotError(error, 'organization')),
      client.listCollections().catch((error) => throwSharedSnapshotError(error, 'collection')),
      client.listOrganizationCiphers().catch((error) => throwSharedSnapshotError(error, 'cipher'))
    ])
    let parsedOrganizations: OrganizationView[]
    try {
      parsedOrganizations = organizations.map(parseStoredOrganization)
    } catch (error) {
      throwSharedSnapshotError(error, 'organization')
    }
    const organizationIds = new Set(parsedOrganizations.map((organization) => organization.id))
    if (organizationIds.size !== parsedOrganizations.length) {
      throw new BitwardenDirectError('INVALID_RESPONSE', undefined, 'organization')
    }
    let parsedCollections: CollectionView[]
    try {
      parsedCollections = collections.map(parseStoredCollection)
    } catch (error) {
      throwSharedSnapshotError(error, 'collection')
    }
    const collectionIds = new Set(parsedCollections.map((collection) => collection.id))
    if (
      collectionIds.size !== parsedCollections.length ||
      parsedCollections.some((collection) => !organizationIds.has(collection.organizationId))
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE', undefined, 'collection')
    }
    let parsedSharedLogins: StoredSharedLogin[]
    try {
      parsedSharedLogins = sharedLogins.map((login) => sharedLoginFromRemote(this.core, login))
    } catch (error) {
      throwSharedSnapshotError(error, 'cipher')
    }
    const sharedIds = new Set(parsedSharedLogins.map((login) => login.id))
    if (
      sharedIds.size !== parsedSharedLogins.length ||
      parsedSharedLogins.some(
        (login) =>
          !organizationIds.has(login.organizationId) ||
          login.collectionIds.some(
            (id) =>
              !collectionIds.has(id) ||
              parsedCollections.find((collection) => collection.id === id)?.organizationId !==
                login.organizationId
          )
      )
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE', undefined, 'cipher')
    }
    return {
      organizations: parsedOrganizations,
      collections: parsedCollections,
      sharedLogins: parsedSharedLogins
    }
  }

  private async resumePendingLoginMutation(
    data: VaultData,
    client: BitwardenSyncClient,
    remoteFolders: BitwardenFolder[],
    remoteLogins: BitwardenLoginItem[],
    signal: AbortSignal
  ): Promise<void> {
    const pending = data.sync?.pendingLoginMutation
    if (!pending || !data.sync) return
    const desired = localSyncSnapshot(data).logins.find((login) => login.id === pending.localId)
    const current = remoteSyncSnapshot(remoteFolders, remoteLogins).logins.find(
      (login) => login.id === pending.remoteId
    )

    if (pending.intent === 'hard-delete') {
      if (current) await client.hardDeleteLogin(pending.remoteId, signal)
      data.sync.pendingLoginMutation = null
      await this.core.commit(cloneData(data))
      return
    }

    if (desired && current) {
      const desiredFolderName =
        desired.folderId === null
          ? null
          : (data.folders.find((folder) => folder.id === desired.folderId)?.name ?? null)
      const currentFolderName =
        current.folderId === null
          ? null
          : (remoteFolders.find((folder) => folder.id === current.folderId)?.name ?? null)
      const currentFingerprint = fingerprintLogin(current, currentFolderName)
      const liveRemoteFolderIds = new Set(remoteFolders.map((folder) => folder.id))
      const mappedRemoteFolderId =
        desired.folderId === null
          ? null
          : data.sync.folderMappings.find(
              (mapping) =>
                mapping.localId === desired.folderId && liveRemoteFolderIds.has(mapping.remoteId)
            )?.remoteId
      const remoteFolderId =
        desired.folderId === null
          ? null
          : mappedRemoteFolderId !== undefined
            ? mappedRemoteFolderId
            : pending.remoteFolderId && liveRemoteFolderIds.has(pending.remoteFolderId)
              ? pending.remoteFolderId
              : undefined
      if (
        remoteFolderId !== undefined &&
        pending.expectedRemoteFingerprints.includes(currentFingerprint)
      ) {
        const contentChanged =
          fingerprintLogin({ ...desired, deletedAt: null, archivedAt: null }, desiredFolderName) !==
          fingerprintLogin({ ...current, deletedAt: null, archivedAt: null }, currentFolderName)
        await updateRemoteLogin(
          client,
          pending.remoteId,
          desired,
          current,
          remoteFolderId,
          contentChanged,
          signal
        )
      }
    }

    data.sync.pendingLoginMutation = null
    await this.core.commit(cloneData(data))
  }

  private async persistCipherIsolationRecovery(
    completedLinks: readonly SyncLink[],
    newlyIsolatedRemoteIds: ReadonlySet<string>
  ): Promise<void> {
    const recovery = cloneData(this.core.requireData())
    if (!recovery.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    recovery.sync.requiresFullSyncAfterCipherIsolation = true

    for (const link of completedLinks) {
      if (
        !newlyIsolatedRemoteIds.has(link.remoteId) ||
        !recovery.logins.some((login) => login.id === link.localId)
      ) {
        continue
      }
      const duplicate = [...recovery.sync.loginMappings, ...recovery.sync.loginTombstones].find(
        (entry) => entry.localId === link.localId || entry.remoteId === link.remoteId
      )
      if (duplicate) {
        if (duplicate.localId === link.localId && duplicate.remoteId === link.remoteId) continue
        throw new VaultError('SYNC_FAILED')
      }
      // A create reached the server before its final authoritative snapshot quarantined the new
      // cipher. Persisting the assigned remote ID prevents retry from creating a duplicate.
      recovery.sync.loginMappings.push({ ...link })
    }
    recovery.updatedAt = this.core.nowIso()
    await this.core.commit(recovery)
  }

  private async executeLoginImportBatch(
    data: VaultData,
    client: BitwardenSyncClient,
    batch: readonly LoginImportCandidate[],
    signal: AbortSignal
  ): Promise<Map<string, string>> {
    if (!data.sync || !supportsLoginImport(client) || batch.length < 2) {
      throw new VaultError('SYNC_FAILED')
    }
    const preparedValue: unknown = await client.prepareLoginImport!(
      batch.map((candidate) => ({
        localId: candidate.action.local.id,
        draft: remoteDraft(candidate.action.local, candidate.remoteFolderId)
      }))
    )
    const expected = new Map(batch.map((candidate) => [candidate.action.local.id, candidate]))
    const discardToken =
      isRecord(preparedValue) &&
      typeof preparedValue.token === 'string' &&
      preparedValue.token.length > 0 &&
      preparedValue.token.length <= 256
        ? preparedValue.token
        : null
    if (
      !isRecord(preparedValue) ||
      Reflect.ownKeys(preparedValue).length !== 2 ||
      discardToken === null ||
      !Array.isArray(preparedValue.entries) ||
      preparedValue.entries.length !== batch.length ||
      preparedValue.entries.some(
        (entry) =>
          !isRecord(entry) ||
          Reflect.ownKeys(entry).length !== 3 ||
          !Object.hasOwn(entry, 'localId') ||
          !Object.hasOwn(entry, 'marker') ||
          !Object.hasOwn(entry, 'remoteFolderId')
      )
    ) {
      if (discardToken) {
        await client.discardPreparedLoginImport!(discardToken).catch(() => undefined)
      }
      throw new VaultError('SYNC_FAILED')
    }
    const preparedEntries = preparedValue.entries as Array<{
      localId: string
      marker: string
      remoteFolderId: string | null
    }>
    if (
      new Set(preparedEntries.map((entry) => entry.localId)).size !== batch.length ||
      new Set(preparedEntries.map((entry) => entry.marker)).size !== batch.length ||
      preparedEntries.some((entry) => {
        const candidate = expected.get(entry.localId)
        return (
          !candidate ||
          typeof entry.localId !== 'string' ||
          !UUID_PATTERN.test(entry.localId) ||
          entry.remoteFolderId !== candidate.remoteFolderId ||
          typeof entry.marker !== 'string' ||
          entry.marker.length === 0 ||
          entry.marker.length > MAX_PENDING_LOGIN_IMPORT_MARKER_LENGTH ||
          /[\0\r\n]/u.test(entry.marker)
        )
      })
    ) {
      await client.discardPreparedLoginImport!(discardToken).catch(() => undefined)
      throw new VaultError('SYNC_FAILED')
    }

    data.sync.pendingLoginImport = {
      phase: 'prepared',
      startedAt: this.core.nowIso(),
      entries: preparedEntries.map((entry) => {
        const candidate = expected.get(entry.localId)!
        return {
          localId: entry.localId,
          marker: entry.marker,
          remoteFolderId: entry.remoteFolderId,
          baseFingerprint: candidate.baseFingerprint
        }
      })
    }
    data.updatedAt = this.core.nowIso()
    try {
      await this.core.commit(cloneData(data))
    } catch (error) {
      await client.discardPreparedLoginImport!(discardToken).catch(() => undefined)
      throw error
    }

    if (signal.aborted) {
      await client.discardPreparedLoginImport!(discardToken).catch(() => undefined)
      throw new BitwardenDirectError('ABORTED')
    }
    data.sync.pendingLoginImport.phase = 'dispatched'
    data.updatedAt = this.core.nowIso()
    try {
      await this.core.commit(cloneData(data))
    } catch (error) {
      // A lock that raced this write leaves 'dispatched' on disk; the abort path reverts it.
      if (!signal.aborted) {
        await client.discardPreparedLoginImport!(discardToken).catch(() => undefined)
        throw error
      }
    }

    if (signal.aborted) {
      try {
        data.sync.pendingLoginImport.phase = 'prepared'
        data.updatedAt = this.core.nowIso()
        await this.core.commit(cloneData(data))
      } finally {
        await client.discardPreparedLoginImport!(discardToken).catch(() => undefined)
      }
      throw new BitwardenDirectError('ABORTED')
    }
    let mutationError: unknown = null
    try {
      await client.executePreparedLoginImport!(discardToken, signal)
    } catch (error) {
      mutationError = error
    }
    if (signal.aborted) throw new BitwardenDirectError('ABORTED')

    let remoteFolders: BitwardenFolder[]
    let remoteLogins: BitwardenLoginItem[]
    try {
      await client.sync(signal)
      ;[remoteFolders, remoteLogins] = await Promise.all([
        client.listFolders(signal),
        client.listPersonalLogins(signal)
      ])
    } catch (error) {
      if (signal.aborted) throw new BitwardenDirectError('ABORTED')
      throw mutationError ?? error
    }
    const unmatched = await this.reconcilePendingLoginImport(
      data,
      client,
      remoteFolders,
      remoteLogins,
      signal
    )
    const remoteIds = new Map<string, string>()
    for (const candidate of batch) {
      const mapping = data.sync.loginMappings.find(
        (entry) => entry.localId === candidate.action.local.id
      )
      if (mapping) remoteIds.set(candidate.action.actionId, mapping.remoteId)
    }

    if (unmatched.length > 0) throw mutationError ?? new VaultError('SYNC_FAILED')
    return remoteIds
  }

  private async reconcilePendingLoginImport(
    data: VaultData,
    client: BitwardenSyncClient,
    remoteFolders: readonly BitwardenFolder[],
    remoteLogins: readonly BitwardenLoginItem[],
    signal: AbortSignal
  ): Promise<string[]> {
    const pending = data.sync?.pendingLoginImport
    if (!data.sync || !pending || !client.reconcileLoginImportMarkers) {
      if (pending) throw new VaultError('SYNC_FAILED')
      return []
    }
    if (signal.aborted) throw new BitwardenDirectError('ABORTED')
    const matches = await client.reconcileLoginImportMarkers(
      pending.entries.map((entry) => entry.marker)
    )
    if (signal.aborted) throw new BitwardenDirectError('ABORTED')
    const pendingByMarker = new Map(pending.entries.map((entry) => [entry.marker, entry]))
    const remoteById = new Map(remoteLogins.map((login) => [login.id, login]))
    const remoteFolderNames = new Map(remoteFolders.map((folder) => [folder.id, folder.name]))
    const remoteSnapshotById = new Map(
      remoteSyncSnapshot([...remoteFolders], [...remoteLogins]).logins.map((login) => [
        login.id,
        login
      ])
    )
    const matchedMarkers = new Set<string>()
    const matchedRemoteIds = new Set<string>()
    if (remoteById.size !== remoteLogins.length) throw new VaultError('SYNC_FAILED')
    for (const match of matches) {
      const entry = pendingByMarker.get(match.marker)
      if (
        !entry ||
        matchedMarkers.has(match.marker) ||
        matchedRemoteIds.has(match.remoteId) ||
        !remoteById.has(match.remoteId) ||
        !remoteSnapshotById.has(match.remoteId) ||
        data.sync.loginMappings.some(
          (mapping) => mapping.localId === entry.localId || mapping.remoteId === match.remoteId
        ) ||
        data.sync.loginTombstones.some(
          (tombstone) =>
            tombstone.localId === entry.localId || tombstone.remoteId === match.remoteId
        )
      ) {
        throw new VaultError('SYNC_FAILED')
      }
      const remote = remoteSnapshotById.get(match.remoteId)!
      const remoteFingerprint = fingerprintLogin(
        remote,
        remote.folderId === null
          ? null
          : (remoteFolderNames.get(remote.folderId) ?? `missing:${remote.folderId}`)
      )
      if (remote.folderId !== entry.remoteFolderId || remoteFingerprint !== entry.baseFingerprint) {
        throw new VaultError('SYNC_FAILED')
      }
      matchedMarkers.add(match.marker)
      matchedRemoteIds.add(match.remoteId)
      data.sync.loginMappings.push({
        localId: entry.localId,
        remoteId: match.remoteId,
        baseFingerprint: entry.baseFingerprint
      })
    }
    const unmatchedEntries = pending.entries.filter((entry) => !matchedMarkers.has(entry.marker))
    const unmatched = unmatchedEntries.map((entry) => entry.localId)
    data.sync.pendingLoginImport =
      pending.phase === 'prepared' || unmatchedEntries.length === 0
        ? null
        : { ...pending, entries: unmatchedEntries.map((entry) => ({ ...entry })) }
    data.updatedAt = this.core.nowIso()
    await this.core.commit(cloneData(data))
    return unmatched
  }

  private async executeBulkRemoteLoginMutation(
    client: BitwardenSyncClient,
    batch: readonly BulkRemoteLoginCandidate[],
    signal: AbortSignal
  ): Promise<void> {
    const mutation = batch[0]?.mutation
    if (!mutation || batch.some((candidate) => candidate.mutation !== mutation)) {
      throw new VaultError('SYNC_FAILED')
    }
    const ids = batch.map((candidate) => candidate.remoteId)
    let isolatedDuringReconciliation = new Set<string>()
    try {
      if (mutation === 'soft-delete') await client.softDeleteLogins!(ids, signal)
      else if (mutation === 'restore') await client.restoreLogins!(ids, signal)
      else if (mutation === 'move') await client.moveLogins!(ids, batch[0]!.folderId, signal)
      else if (mutation === 'archive') await client.archiveLogins!(ids, signal)
      else if (mutation === 'unarchive') await client.unarchiveLogins!(ids, signal)
      else await client.hardDeleteLogins!(ids, signal)
    } catch (error) {
      if (signal.aborted) throw error
      try {
        await client.sync(signal)
        const isolated = isolatedPersonalCipherIdsOf(client)
        isolatedDuringReconciliation = new Set(
          batch.flatMap((candidate) =>
            isolated.has(candidate.remoteId) ? [candidate.remoteId] : []
          )
        )
        const remote = new Map(
          (await client.listPersonalLogins(signal)).map((login) => [login.id, login])
        )
        if (
          batch.every(
            (candidate) =>
              !isolated.has(candidate.remoteId) && bulkRemoteLoginMutationApplied(candidate, remote)
          )
        ) {
          return
        }
      } catch (reconciliationError) {
        if (
          reconciliationError instanceof BitwardenDirectError &&
          (reconciliationError.code === 'AUTH_REQUIRED' ||
            reconciliationError.code === 'ACCOUNT_CHANGED' ||
            reconciliationError.code === 'ABORTED')
        ) {
          throw reconciliationError
        }
        // The original mutation error is the most useful failure. A later sync retries safely
        // from the server's authoritative state instead of assuming this batch was atomic.
      }
      if (signal.aborted) throw new BitwardenDirectError('ABORTED')
      if (isolatedDuringReconciliation.size > 0) {
        await this.persistCipherIsolationRecovery([], isolatedDuringReconciliation)
      }
      throw error
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
        result.localId = createLocalFolder(this.core, data, action.remote.name).id
      } else if (action.kind === 'pull-update') {
        const folder = findFolder(data, action.localId)
        folder.name = action.remote.name
        folder.updatedAt = this.core.nowIso()
      } else if (action.kind === 'delete-local') {
        deleteLocalFolder(this.core, data, action.localId)
      } else if (action.kind === 'delete-remote') {
        await client.deleteFolder(action.remoteId, signal)
      } else if (action.reason === 'both-modified') {
        if (!action.local || !action.remote) throw new VaultError('SYNC_FAILED')
        createLocalFolder(this.core, data, action.conflictName)
        const primary = findFolder(data, action.local.id)
        primary.name = action.remote.name
        primary.updatedAt = this.core.nowIso()
      } else if (action.reason === 'remote-deleted') {
        if (!action.local) throw new VaultError('SYNC_FAILED')
        const local = findFolder(data, action.local.id)
        local.name = action.conflictName
        local.updatedAt = this.core.nowIso()
        result.remoteId = (await client.createFolder(action.conflictName, signal)).id
      } else {
        if (!action.remote) throw new VaultError('SYNC_FAILED')
        await client.editFolder(action.remote.id, action.conflictName, signal)
        result.localId = createLocalFolder(this.core, data, action.conflictName).id
      }
      return result
    }

    if (action.kind === 'push-create') {
      const folderId = resolveFolderReference(action.remoteFolder, completed, 'remoteId')
      const created = await client.createLogin(remoteDraft(action.local, folderId), signal)
      result.remoteId = created.id
      if (action.local.deletedAt !== null) await client.softDeleteLogin(created.id, signal)
    } else if (action.kind === 'push-update') {
      const folderId = resolveFolderReference(action.remoteFolder, completed, 'remoteId')
      const composite = isCompositeRemoteLoginUpdate(
        action.local,
        action.remote,
        action.contentChanged
      )
      if (composite) {
        if (!data.sync) throw new VaultError('SYNC_FAILED')
        data.sync.pendingLoginMutation = {
          intent: 'converge',
          localId: action.local.id,
          remoteId: action.remoteId,
          remoteFolderId: folderId,
          expectedRemoteFingerprints: [...action.resumeFingerprints]
        }
        await this.core.commit(cloneData(data))
      }
      await updateRemoteLogin(
        client,
        action.remoteId,
        action.local,
        action.remote,
        folderId,
        action.contentChanged,
        signal
      )
      if (composite) {
        if (!data.sync) throw new VaultError('SYNC_FAILED')
        data.sync.pendingLoginMutation = null
        await this.core.commit(cloneData(data))
      }
    } else if (action.kind === 'pull-create') {
      const folderId = resolveFolderReference(action.localFolder, completed, 'localId')
      result.localId = createLocalLogin(this.core, data, action.remote, folderId).id
    } else if (action.kind === 'pull-update') {
      const folderId = resolveFolderReference(action.localFolder, completed, 'localId')
      updateLocalLogin(this.core, data, action.localId, action.remote, folderId)
    } else if (action.kind === 'delete-local') {
      data.logins = data.logins.filter((login) => login.id !== action.localId)
    } else if (action.kind === 'delete-remote') {
      await client.hardDeleteLogin(action.remoteId, signal)
    } else if (action.reason === 'both-modified') {
      if (!action.local || !action.remote) throw new VaultError('SYNC_FAILED')
      const copyFolderId =
        action.local.folderId && data.folders.some((folder) => folder.id === action.local!.folderId)
          ? action.local.folderId
          : null
      createLocalLogin(
        this.core,
        data,
        { ...action.local, name: action.conflictName },
        copyFolderId
      )
      const primaryFolderId = resolveFolderReference(action.localFolder, completed, 'localId')
      updateLocalLogin(this.core, data, action.local.id, action.remote, primaryFolderId)
    } else if (action.reason === 'remote-deleted') {
      if (!action.local) throw new VaultError('SYNC_FAILED')
      const local = findLogin(data, action.local.id)
      local.name = action.conflictName
      local.updatedAt = this.core.nowIso()
      const folderId = resolveFolderReference(action.remoteFolder, completed, 'remoteId')
      result.remoteId = (
        await client.createLogin(
          remoteDraft({ ...action.local, name: action.conflictName }, folderId),
          signal
        )
      ).id
      if (action.local.deletedAt !== null) await client.softDeleteLogin(result.remoteId, signal)
    } else {
      if (!action.remote) throw new VaultError('SYNC_FAILED')
      const remoteFolderId = action.remote.folderId
      await updateRemoteLogin(
        client,
        action.remote.id,
        { ...action.remote, name: action.conflictName },
        action.remote,
        remoteFolderId,
        true,
        signal
      )
      const localFolderId = resolveFolderReference(action.localFolder, completed, 'localId')
      result.localId = createLocalLogin(
        this.core,
        data,
        { ...action.remote, name: action.conflictName },
        localFolderId
      ).id
    }
    return result
  }

  private applyBitwardenPolicyRuntimeState(data: VaultData): void {
    if (
      bitwardenPolicyDecision(BITWARDEN_POLICY_TYPE.RemoveUnlockWithPin, data).state !==
      'not-applicable'
    ) {
      this.pinUnlock.invalidate()
    }
  }

  async reconcilePersonalVaultPurge(
    client: BitwardenSyncClient
  ): Promise<SyncPurgePersonalVaultResult> {
    const current = this.core.requireData()
    const journal = current.sync?.pendingPersonalVaultPurge
    if (journal?.phase !== 'dispatched') throw new VaultError('SYNC_FAILED')
    try {
      // Do not reuse the mutation signal: cancellation after dispatch must not suppress the
      // authoritative read that distinguishes a completed purge from an unknown partial result.
      await client.sync()
      const isolatedPersonalCipherIds = isolatedPersonalCipherIdsOf(client)
      const [remoteFolders, remoteLogins] = await Promise.all([
        client.listFolders(),
        client.listPersonalLogins()
      ])
      if (
        remoteFolders.length === 0 &&
        remoteLogins.length === 0 &&
        isolatedPersonalCipherIds.size === 0
      ) {
        return await this.finalizePersonalVaultPurge(current, client)
      }
      const pending = cloneData(current)
      if (!pending.sync?.pendingPersonalVaultPurge) throw new VaultError('SYNC_FAILED')
      pending.sync.pendingPersonalVaultPurge.phase = 'dispatched'
      pending.sync.pendingPersonalVaultPurge.remainingItems =
        remoteLogins.length + isolatedPersonalCipherIds.size
      pending.sync.pendingPersonalVaultPurge.remainingFolders = remoteFolders.length
      pending.sync.state = client.exportState()
      pending.sync.lastSyncAt = this.core.nowIso()
      pending.updatedAt = pending.sync.lastSyncAt
      await this.core.commit(pending)
      this.syncSession.clearSyncErrorState()
      return {
        status: 'pending',
        remainingItems: remoteLogins.length + isolatedPersonalCipherIds.size,
        remainingFolders: remoteFolders.length,
        startedAt: journal.startedAt
      }
    } catch (error) {
      // The dispatched journal remains the sole source of truth when the authoritative read fails.
      if (error instanceof VaultError) throw error
      if (error instanceof BitwardenDirectError) throw error
      throw new VaultError('SYNC_FAILED')
    }
  }

  private async finalizePersonalVaultPurge(
    current: VaultData,
    client: BitwardenSyncClient
  ): Promise<{ status: 'complete'; removedItems: number; removedFolders: number }> {
    if (current.sync?.pendingPersonalVaultPurge?.phase !== 'dispatched') {
      throw new VaultError('SYNC_FAILED')
    }
    const removedItems = current.logins.length
    const removedFolders = current.folders.length
    const complete = cloneData(current)
    complete.logins = []
    complete.folders = []
    complete.nativeAttachmentRestore = null
    if (!complete.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    complete.sync.folderMappings = []
    complete.sync.loginMappings = []
    complete.sync.folderTombstones = []
    complete.sync.loginTombstones = []
    complete.sync.pendingLoginMutation = null
    complete.sync.pendingLoginImport = null
    complete.sync.pendingPersonalVaultPurge = null
    complete.sync.requiresFullSyncAfterCipherIsolation = false
    complete.sync.state = client.exportState()
    complete.sync.lastSyncAt = this.core.nowIso()
    complete.updatedAt = complete.sync.lastSyncAt
    await this.core.commit(complete)
    this.syncSession.clearSyncErrorState()
    return { status: 'complete', removedItems, removedFolders }
  }

  async restorePreDispatchPurge(original: VaultData): Promise<void> {
    const restored = cloneData(original)
    restored.updatedAt = this.core.nowIso()
    await this.core.commit(restored)
  }
}
