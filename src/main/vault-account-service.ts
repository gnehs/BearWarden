import { randomUUID } from 'node:crypto'
import type {
  EquivalentDomainSettingsUpdate,
  EquivalentDomainSettingsView,
  SyncConnectRequest,
  SyncEmailTwoFactorCodeRequest,
  SyncPurgePersonalVaultRequest,
  SyncPurgePersonalVaultResult,
  SyncResult,
  SyncStatus,
  SyncUnlockRequest
} from '../shared/vault-contract'
import { BitwardenDirectError, type BitwardenSyncClient } from './bitwarden-direct'
import { VaultError } from './vault-errors'
import { MAX_MASTER_PASSWORD_LENGTH, MAX_USERNAME_LENGTH } from './vault/limits'
import { normalizeRequiredString, normalizeSyncPassword } from './vault/parse-primitives'
import { cloneData } from './vault/vault-data-parsing'
import { assertNoPendingPersonalVaultPurge } from './vault/sync-data-parsing'
import {
  cloneEquivalentDomainSettings,
  validateRemoteEquivalentDomainSettings,
  equivalentDomainRevision,
  equivalentDomainSettingsView,
  normalizeEquivalentDomainUpdate
} from './vault/equivalent-domains'
import type { PersistedSyncData, VaultData } from './vault/types'
import { VaultServiceBase } from './vault-service-base'
import { isRecord } from './validation-primitives'
import { getAuthoritativeEquivalentDomainSettings } from './vault/sync-snapshots'

function initialSyncData(serverUrl: string, email: string): PersistedSyncData {
  return {
    provider: 'bitwarden',
    serverUrl,
    email,
    state: {
      session: null,
      deviceIdentifier: randomUUID(),
      profileId: null,
      securityStamp: null
    },
    unlockMaterial: null,
    lastSyncAt: null,
    folderMappings: [],
    loginMappings: [],
    folderTombstones: [],
    loginTombstones: [],
    pendingLoginMutation: null,
    pendingLoginImport: null,
    pendingPersonalVaultPurge: null,
    domainSettings: null
  }
}

/** Account security, authentication, and public synchronization operations. */
export class VaultAccountService extends VaultServiceBase {
  syncStatus(): Promise<SyncStatus> {
    return this.core.exclusive(async () => this.syncSession.currentSyncStatus())
  }

  /** Applies a trusted authenticated LogOut notification without deleting sync mappings. */
  remoteLogoutSync(): Promise<SyncStatus> {
    return this.core.exclusive(async () => {
      const current = this.core.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      this.pinUnlock.invalidate()
      this.syncSession.abortSyncOperation()
      this.syncSession.abortNotificationTokenLeases()
      this.syncSession.abortAccountSecurityRequests()
      this.syncSession.abortNativeAttachmentBackups()
      this.syncSession.abortNativeAttachmentRestores()
      this.health.cancelAccountBreachReport()
      if (!current.sync) return { configured: false, state: 'unconfigured' }
      const client = this.syncSession.dropSyncClient()
      this.syncSession.clearSyncErrorState()
      try {
        await client?.logout()
      } catch {
        // A server-directed logout is fail-closed locally even if connector cleanup fails.
      }
      const next = cloneData(current)
      if (!next.sync) return { configured: false, state: 'unconfigured' }
      next.sync.state = {
        ...(client?.exportState() ?? next.sync.state),
        session: null
      }
      next.updatedAt = this.core.nowIso()
      await this.core.commit(next)
      return this.syncSession.baseSyncStatus(next.sync, 'locked')
    })
  }

  connectSync(request: SyncConnectRequest): Promise<SyncResult> {
    this.pinUnlock.invalidate()
    return this.core.exclusive(async () => {
      const current = this.core.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      const serverUrl = this.syncSession.normalizeSyncServerUrl(request.serverUrl)
      const email = normalizeRequiredString(request.email, MAX_USERNAME_LENGTH)
      const password = normalizeSyncPassword(request.masterPassword)
      const twoFactor = this.syncSession.normalizeTwoFactor(
        request.twoFactorMethod,
        request.twoFactorCode
      )
      const newDeviceOtp = this.syncSession.normalizeNewDeviceOtp(request.newDeviceOtp)
      const abort = this.syncSession.startSyncOperation()

      try {
        const sync = initialSyncData(serverUrl, email)
        const client = this.syncSession.createDetachedClient(sync)
        await this.syncSession.authenticateSyncWithWebAuthnRetry(
          (retryTwoFactor) =>
            client.login({
              email,
              password,
              twoFactor: retryTwoFactor,
              newDeviceOtp,
              signal: abort.signal
            }),
          twoFactor,
          request.webAuthnRemember,
          sync.serverUrl,
          abort.signal
        )
        const next = cloneData(current)
        sync.state = client.exportState()
        const unlockMaterial = client.pinUnlockMaterial?.()
        try {
          sync.unlockMaterial = unlockMaterial
            ? {
                accountKey: unlockMaterial.accountKey.toString('base64'),
                wrappedKeyFingerprint: unlockMaterial.wrappedKeyFingerprint.toString('base64')
              }
            : null
        } finally {
          unlockMaterial?.accountKey.fill(0)
          unlockMaterial?.wrappedKeyFingerprint.fill(0)
        }
        next.sync = sync
        next.updatedAt = this.core.nowIso()
        await this.core.commit(next)
        this.syncSession.setSyncClient(client)
        return await this.syncEngine.performSync(next, client, abort.signal)
      } catch (error) {
        await this.syncSession.persistCurrentClientState().catch(() => undefined)
        throw this.syncSession.mapSyncError(error)
      } finally {
        this.syncSession.finishSyncOperation(abort)
      }
    })
  }

  sendSyncEmailTwoFactorCode(request: SyncEmailTwoFactorCodeRequest): Promise<void> {
    return this.core.exclusive(async () => {
      this.core.requireData()
      const serverUrl = this.syncSession.normalizeSyncServerUrl(request.serverUrl)
      const email = normalizeRequiredString(request.email, MAX_USERNAME_LENGTH)
      const password = normalizeSyncPassword(request.masterPassword)
      const client = this.syncSession.createDetachedClient(initialSyncData(serverUrl, email))
      if (!client.sendEmailTwoFactorLoginCode) throw new VaultError('SYNC_FAILED')
      const abort = this.syncSession.startSyncOperation()
      try {
        await client.sendEmailTwoFactorLoginCode(password, abort.signal)
      } catch (error) {
        throw this.syncSession.mapSyncError(error)
      } finally {
        request.masterPassword = ''
        this.syncSession.finishSyncOperation(abort)
      }
    })
  }

  private async authenticateConfiguredSync(
    request: SyncUnlockRequest,
    sync: PersistedSyncData,
    client: BitwardenSyncClient,
    signal: AbortSignal
  ): Promise<void> {
    const password = normalizeSyncPassword(request.masterPassword)
    const twoFactor = this.syncSession.normalizeTwoFactor(
      request.twoFactorMethod,
      request.twoFactorCode
    )
    const newDeviceOtp = this.syncSession.normalizeNewDeviceOtp(request.newDeviceOtp)
    await this.syncSession.authenticateSyncWithWebAuthnRetry(
      (retryTwoFactor) =>
        client.unlock({
          password,
          twoFactor: retryTwoFactor,
          newDeviceOtp,
          signal
        }),
      twoFactor,
      request.webAuthnRemember,
      sync.serverUrl,
      signal
    )
  }

  unlockSync(request: SyncUnlockRequest): Promise<SyncStatus> {
    return this.core.exclusive(async () => {
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      const abort = this.syncSession.startSyncOperation()
      try {
        await this.authenticateConfiguredSync(request, sync, client, abort.signal)
        await this.syncSession.persistCurrentClientState()
        this.syncSession.clearSyncErrorState()
        return this.syncSession.baseSyncStatus(sync, 'ready')
      } catch (error) {
        await this.syncSession.persistCurrentClientState().catch(() => undefined)
        throw this.syncSession.mapSyncError(error)
      } finally {
        this.syncSession.finishSyncOperation(abort)
      }
    })
  }

  /** Authenticates and completes the first sync before publishing a ready state. */
  unlockAndSync(request: SyncUnlockRequest): Promise<SyncResult> {
    return this.core.exclusive(async () => {
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      const abort = this.syncSession.startSyncOperation()
      try {
        await this.authenticateConfiguredSync(request, sync, client, abort.signal)
        await this.syncSession.persistCurrentClientState()
        return await this.syncEngine.performSync(this.core.requireData(), client, abort.signal)
      } catch (error) {
        await this.syncSession.persistCurrentClientState().catch(() => undefined)
        throw this.syncSession.mapSyncError(error)
      } finally {
        this.syncSession.finishSyncOperation(abort)
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
        return this.core.exclusive(async () => {
          this.syncSession.clearSyncErrorState()
          const sync = this.core.requireData().sync
          return sync
            ? this.syncSession.baseSyncStatus(sync, 'locked')
            : { configured: false, state: 'unconfigured' }
        })
      }
      throw error
    }
  }

  syncNow(): Promise<SyncResult> {
    return this.core.exclusive(async () => {
      const data = this.core.requireData()
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      const abort = this.syncSession.startSyncOperation()
      try {
        return await this.syncEngine.performSync(data, client, abort.signal)
      } catch (error) {
        await this.syncSession.persistCurrentClientState().catch(() => undefined)
        throw this.syncSession.mapSyncError(error)
      } finally {
        this.syncSession.finishSyncOperation(abort)
      }
    })
  }

  disconnectSync(): Promise<SyncStatus> {
    return this.core.exclusive(async () => {
      const current = this.core.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      this.pinUnlock.invalidate()
      this.syncSession.abortSyncOperation()
      this.syncSession.abortNotificationTokenLeases()
      this.syncSession.abortAccountSecurityRequests()
      this.syncSession.abortNativeAttachmentBackups()
      this.syncSession.abortNativeAttachmentRestores()
      this.health.cancelAccountBreachReport()
      const next = cloneData(current)
      const client = this.syncSession.dropSyncClient()
      this.syncSession.clearSyncErrorState()
      try {
        await client?.logout()
      } catch {
        // Clearing local sync configuration must work even when the server is offline.
      }
      next.sync = null
      next.updatedAt = this.core.nowIso()
      await this.core.commit(next)
      return { configured: false, state: 'unconfigured' }
    })
  }

  resolvePendingLoginImport(request: {
    masterPassword: string
    confirmRetry: true
  }): Promise<SyncStatus> {
    return this.core.exclusive(async () => {
      if (request.confirmRetry !== true) throw new VaultError('INVALID_INPUT')
      await this.core.assertMasterPassword(request.masterPassword)
      const current = this.core.requireData()
      if (!current.sync?.pendingLoginImport) throw new VaultError('INVALID_INPUT')
      if (current.sync.pendingLoginImport.phase === 'prepared') {
        throw new VaultError('SYNC_FAILED')
      }
      const next = cloneData(current)
      if (!next.sync?.pendingLoginImport) throw new VaultError('SYNC_FAILED')
      next.sync.pendingLoginImport.phase = 'retry-approved'
      next.updatedAt = this.core.nowIso()
      await this.core.commit(next)
      this.syncSession.clearSyncErrorState()
      return await this.syncSession.currentSyncStatus()
    })
  }

  purgePersonalVault(
    request: SyncPurgePersonalVaultRequest
  ): Promise<SyncPurgePersonalVaultResult> {
    return this.core.exclusive(async () => {
      let abort: AbortController | undefined
      let didDispatch = false
      let original: VaultData | undefined
      let operationGeneration = -1
      try {
        if (
          !isRecord(request) ||
          (Object.getPrototypeOf(request) !== Object.prototype &&
            Object.getPrototypeOf(request) !== null) ||
          Reflect.ownKeys(request).length !== 3 ||
          !Object.hasOwn(request, 'masterPassword') ||
          !Object.hasOwn(request, 'confirmation') ||
          !Object.hasOwn(request, 'confirmPurge') ||
          typeof request.masterPassword !== 'string' ||
          request.masterPassword.length === 0 ||
          request.masterPassword.length > MAX_MASTER_PASSWORD_LENGTH ||
          request.confirmation !== 'PURGE' ||
          request.confirmPurge !== true
        ) {
          throw new VaultError('INVALID_INPUT')
        }

        const current = this.core.requireData()
        operationGeneration = this.core.generation
        original = cloneData(current)
        if (
          current.sync?.pendingLoginMutation ||
          current.sync?.pendingLoginImport ||
          current.nativeAttachmentRestore ||
          current.masterPasswordChange ||
          this.syncSession.activeAttachmentOperation ||
          this.syncSession.nativeAttachmentBackupAborts.size > 0 ||
          this.syncSession.nativeAttachmentRestoreAborts.size > 0
        ) {
          throw new VaultError('SYNC_FAILED')
        }
        const sync = this.syncSession.requireSyncData()
        const client = this.syncSession.getOrCreateSyncClient(sync)
        if (!client.purgePersonalVault) throw new VaultError('SYNC_FAILED')
        const remoteStatus = await client.status()
        if (remoteStatus.status !== 'unlocked') throw new VaultError('SYNC_AUTH_REQUIRED')

        // A prepared record proves the request was never durably marked as dispatched. It is safe
        // to discard before this separately authorized attempt. A dispatched record is retried only
        // here, never by ordinary synchronization.
        if (current.sync?.pendingPersonalVaultPurge?.phase === 'prepared') {
          const cleared = cloneData(current)
          if (!cleared.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
          cleared.sync.pendingPersonalVaultPurge = null
          cleared.updatedAt = this.core.nowIso()
          await this.core.commit(cleared)
          original = cloneData(cleared)
        }

        const active = this.core.requireData()
        const retryingDispatched = active.sync?.pendingPersonalVaultPurge?.phase === 'dispatched'
        if (retryingDispatched) {
          // Never downgrade an earlier unknown outcome to prepared: a crash at that point would
          // make unlock recovery erase the only durable evidence that a purge may have run.
          didDispatch = true
        } else {
          const startedAt = this.core.nowIso()
          const prepared = cloneData(active)
          if (!prepared.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
          prepared.sync.pendingPersonalVaultPurge = {
            phase: 'prepared',
            startedAt,
            remainingItems: active.logins.length,
            remainingFolders: active.folders.length
          }
          prepared.updatedAt = this.core.nowIso()
          await this.core.commit(prepared)

          const dispatched = cloneData(prepared)
          if (!dispatched.sync?.pendingPersonalVaultPurge) throw new VaultError('SYNC_FAILED')
          dispatched.sync.pendingPersonalVaultPurge.phase = 'dispatched'
          dispatched.updatedAt = this.core.nowIso()
          try {
            await this.core.commit(dispatched)
          } catch (error) {
            await this.syncEngine.restorePreDispatchPurge(original).catch(() => undefined)
            throw error
          }
          didDispatch = true
        }
        abort = this.syncSession.startSyncOperation()

        let remoteError: unknown
        try {
          await client.purgePersonalVault(request.masterPassword, abort.signal)
        } catch (error) {
          remoteError = error
        }
        if (abort.signal.aborted || operationGeneration !== this.core.generation) {
          // Locking wins over a potentially slow reconciliation. The dispatched journal remains
          // durable, so the next explicitly unlocked generic sync can reconcile without replaying.
          throw new VaultError('LOCKED')
        }
        if (
          remoteError instanceof BitwardenDirectError &&
          remoteError.code === 'USER_VERIFICATION_FAILED'
        ) {
          await this.syncEngine.restorePreDispatchPurge(original)
          throw new VaultError('INVALID_MASTER_PASSWORD')
        }

        const reconciled = await this.syncEngine.reconcilePersonalVaultPurge(client)
        if (reconciled.status === 'complete') return reconciled
        // A dispatched failure is intentionally surfaced as pending after an authoritative read.
        // The caller may start one fresh, explicitly confirmed attempt; generic sync never replays.
        return reconciled
      } catch (error) {
        if (!didDispatch && original) {
          await this.syncEngine.restorePreDispatchPurge(original).catch(() => undefined)
        }
        if (error instanceof VaultError) throw error
        throw this.syncSession.mapSyncError(error)
      } finally {
        if (abort) this.syncSession.finishSyncOperation(abort)
        try {
          request.masterPassword = ''
          request.confirmation = '' as 'PURGE'
        } catch {
          // Validation rejects frozen/exotic inputs; never replace the intended service error.
        }
      }
    })
  }

  getEquivalentDomainSettings(): Promise<EquivalentDomainSettingsView> {
    return this.core.exclusive(async () => {
      const current = this.core.requireData()
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      const abort = this.syncSession.startSyncOperation()
      try {
        const settings = validateRemoteEquivalentDomainSettings(
          await getAuthoritativeEquivalentDomainSettings(client, abort.signal)
        )
        if (abort.signal.aborted) throw new BitwardenDirectError('ABORTED')
        const next = cloneData(current)
        if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
        next.sync.domainSettings = cloneEquivalentDomainSettings(settings)
        next.sync.state = client.exportState()
        next.updatedAt = this.core.nowIso()
        await this.core.commit(next)
        this.syncSession.clearSyncErrorState()
        return equivalentDomainSettingsView(settings)
      } catch (error) {
        throw this.syncSession.mapSyncError(error)
      } finally {
        this.syncSession.finishSyncOperation(abort)
      }
    })
  }

  updateEquivalentDomainSettings(
    request: EquivalentDomainSettingsUpdate
  ): Promise<EquivalentDomainSettingsView> {
    return this.core.exclusive(async () => {
      if (!/^[0-9a-f]{64}$/u.test(request.expectedRevision)) {
        throw new VaultError('INVALID_INPUT')
      }
      const update = normalizeEquivalentDomainUpdate(request)
      const current = this.core.requireData()
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      const abort = this.syncSession.startSyncOperation()
      try {
        const serverSettings = validateRemoteEquivalentDomainSettings(
          await getAuthoritativeEquivalentDomainSettings(client, abort.signal)
        )
        if (equivalentDomainRevision(serverSettings) !== request.expectedRevision) {
          throw new VaultError('SYNC_CONFLICT')
        }
        const globalTypes = new Set(serverSettings.globalEquivalentDomains.map(({ type }) => type))
        if (update.excludedGlobalEquivalentDomains.some((type) => !globalTypes.has(type))) {
          throw new VaultError('INVALID_INPUT')
        }
        await client.updateEquivalentDomainSettings(update, abort.signal)
        const confirmed = validateRemoteEquivalentDomainSettings(
          await getAuthoritativeEquivalentDomainSettings(client, abort.signal)
        )
        if (abort.signal.aborted) throw new BitwardenDirectError('ABORTED')
        const next = cloneData(current)
        if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
        next.sync.domainSettings = cloneEquivalentDomainSettings(confirmed)
        next.sync.state = client.exportState()
        next.updatedAt = this.core.nowIso()
        await this.core.commit(next)
        this.syncSession.clearSyncErrorState()
        return equivalentDomainSettingsView(confirmed)
      } catch (error) {
        if (error instanceof BitwardenDirectError && error.code === 'NOT_FOUND') {
          throw new VaultError('NOT_FOUND')
        }
        throw this.syncSession.mapSyncError(error)
      } finally {
        this.syncSession.finishSyncOperation(abort)
      }
    })
  }
}
