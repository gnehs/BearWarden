import type { VaultCore } from './core'
import type { PinUnlockInvalidator } from './pin-unlock-state'
import type { VaultSyncSession } from './sync-session'
import { BitwardenDirectError } from '../bitwarden-direct'
import { VaultError } from '../vault-errors'
import { normalizeMasterPassword } from './parse-primitives'
import { cloneData } from './vault-data-parsing'
import { assertNoPendingPersonalVaultPurge } from './sync-data-parsing'
import type {
  PersistedSyncData,
  VaultMasterPasswordChangeStatus,
  VaultMasterPasswordChangeRequest,
  VaultMasterPasswordChangeResolutionRequest,
  VaultMasterPasswordChangeResolution
} from './types'
import {
  masterPasswordChangeAccountFingerprint,
  assertMasterPasswordChangeAccount
} from './master-password-change'

/**
 * Master password change: the remote change, the local re-key and the journal that lets an
 * interrupted change resume, or be resolved by proving which password the server accepts, without
 * replaying a mutation whose outcome is unknown.
 */
export class VaultMasterPasswordChange {
  constructor(
    private readonly core: VaultCore,
    private readonly syncSession: VaultSyncSession,
    private readonly pinUnlock: PinUnlockInvalidator
  ) {}

  masterPasswordChangeStatus(): Promise<VaultMasterPasswordChangeStatus> {
    return this.core.exclusive(async () => {
      const data = this.core.requireData()
      assertMasterPasswordChangeAccount(data)
      const journal = data.masterPasswordChange
      return {
        phase: journal?.phase ?? null,
        needsReconnect: false,
        needsRemoteVerification: journal?.phase === 'prepared'
      }
    })
  }

  changeMasterPassword(request: VaultMasterPasswordChangeRequest): Promise<void> {
    return this.core.exclusive(async () => {
      let currentPassword = ''
      let newPassword = ''
      let remoteRequest:
        | { currentPassword: string; newPassword: string; hint: string | null; signal: AbortSignal }
        | undefined
      let abort: AbortController | undefined
      try {
        currentPassword = normalizeMasterPassword(request.currentPassword)
        newPassword = normalizeMasterPassword(request.newPassword)
        if (currentPassword === newPassword) throw new VaultError('INVALID_INPUT')
        const hint = request.hint ?? null
        if (hint !== null && (typeof hint !== 'string' || hint.length > 50)) {
          throw new VaultError('INVALID_INPUT')
        }
        const current = this.core.requireData()
        assertNoPendingPersonalVaultPurge(current.sync)
        assertMasterPasswordChangeAccount(current)
        const existing = current.masterPasswordChange
        if (existing?.phase === 'prepared') {
          // A prepared mutation has an ambiguous remote outcome. Resolution must use the separate,
          // non-mutating password-proof API and must never replay the mutation.
          throw new VaultError('SYNC_FAILED')
        }
        if (existing?.phase === 'local-rekeyed') {
          await this.finishMasterPasswordChange(currentPassword, newPassword)
          return
        }

        if (!existing) {
          const sync = this.syncSession.requireSyncData()
          const client = this.syncSession.getOrCreateSyncClient(sync)
          if (!client.changeMasterPassword) throw new VaultError('SYNC_FAILED')
          const now = this.core.nowIso()
          const prepared = cloneData(current)
          prepared.masterPasswordChange = {
            phase: 'prepared',
            startedAt: now,
            updatedAt: now,
            accountFingerprint: masterPasswordChangeAccountFingerprint(sync)
          }
          prepared.updatedAt = now
          await this.core.commit(prepared)

          abort = this.syncSession.startSyncOperation()
          remoteRequest = { currentPassword, newPassword, hint, signal: abort.signal }
          try {
            await client.changeMasterPassword(remoteRequest)
          } catch (error) {
            if (
              error instanceof BitwardenDirectError &&
              error.code === 'MASTER_PASSWORD_CHANGE_UNKNOWN'
            ) {
              this.core.advanceGeneration()
              this.pinUnlock.invalidate()
              this.syncSession.dropSyncClient()
              this.core.teardown()
              throw new VaultError('SYNC_FAILED')
            }
            const cleared = cloneData(this.core.requireData())
            cleared.masterPasswordChange = null
            cleared.updatedAt = this.core.nowIso()
            await this.core.commit(cleared)
            throw this.syncSession.mapSyncError(error)
          }

          const confirmed = cloneData(this.core.requireData())
          if (!confirmed.masterPasswordChange) throw new VaultError('SYNC_FAILED')
          confirmed.masterPasswordChange.phase = 'remote-confirmed'
          confirmed.masterPasswordChange.updatedAt = this.core.nowIso()
          if (confirmed.sync) {
            confirmed.sync.state = { ...client.exportState(), session: null }
          }
          confirmed.updatedAt = confirmed.masterPasswordChange.updatedAt
          try {
            await this.core.commit(confirmed)
          } catch (error) {
            this.core.advanceGeneration()
            this.pinUnlock.invalidate()
            this.core.teardown()
            throw error
          }
        }

        await this.finishMasterPasswordChange(currentPassword, newPassword)
      } finally {
        if (abort) this.syncSession.finishSyncOperation(abort)
        request.currentPassword = ''
        request.newPassword = ''
        request.hint = null
        currentPassword = ''
        newPassword = ''
        if (remoteRequest) {
          remoteRequest.currentPassword = ''
          remoteRequest.newPassword = ''
          remoteRequest.hint = null
        }
      }
    })
  }

  resolveMasterPasswordChange(
    request: VaultMasterPasswordChangeResolutionRequest
  ): Promise<VaultMasterPasswordChangeResolution> {
    return this.core.exclusive(async () => {
      let currentPassword = ''
      let newPassword = ''
      let abort: AbortController | undefined
      try {
        currentPassword = normalizeMasterPassword(request.currentPassword)
        newPassword = normalizeMasterPassword(request.newPassword)
        if (currentPassword === newPassword) throw new VaultError('INVALID_INPUT')
        const current = this.core.requireData()
        assertMasterPasswordChangeAccount(current)
        if (current.masterPasswordChange?.phase !== 'prepared') {
          throw new VaultError('INVALID_INPUT')
        }
        const sync = this.syncSession.requireSyncData()
        abort = this.syncSession.startSyncOperation()
        const newPasswordProof = await this.proveRemotePassword(sync, newPassword, abort.signal)
        if (newPasswordProof === 'needs-reconnect') return { status: 'needs-reconnect' }
        if (newPasswordProof === 'rejected') {
          const currentPasswordProof = await this.proveRemotePassword(
            sync,
            currentPassword,
            abort.signal
          )
          if (currentPasswordProof === 'needs-reconnect') return { status: 'needs-reconnect' }
          if (currentPasswordProof === 'rejected') return { status: 'indeterminate' }

          const cleared = cloneData(this.core.requireData())
          assertMasterPasswordChangeAccount(cleared)
          if (cleared.masterPasswordChange?.phase !== 'prepared') {
            throw new VaultError('SYNC_FAILED')
          }
          cleared.masterPasswordChange = null
          if (cleared.sync) cleared.sync.state.session = null
          cleared.updatedAt = this.core.nowIso()
          await this.core.commit(cleared)
          this.syncSession.dropSyncClient()
          return { status: 'remote-not-changed' }
        }

        const confirmed = cloneData(this.core.requireData())
        assertMasterPasswordChangeAccount(confirmed)
        if (confirmed.masterPasswordChange?.phase !== 'prepared') {
          throw new VaultError('SYNC_FAILED')
        }
        confirmed.masterPasswordChange.phase = 'remote-confirmed'
        confirmed.masterPasswordChange.updatedAt = this.core.nowIso()
        if (confirmed.sync) confirmed.sync.state.session = null
        confirmed.updatedAt = confirmed.masterPasswordChange.updatedAt
        await this.core.commit(confirmed)
        this.syncSession.dropSyncClient()
        await this.finishMasterPasswordChange(currentPassword, newPassword)
        return { status: 'resolved' }
      } finally {
        if (abort) this.syncSession.finishSyncOperation(abort)
        request.currentPassword = ''
        request.newPassword = ''
        currentPassword = ''
        newPassword = ''
      }
    })
  }

  private async finishMasterPasswordChange(
    currentPassword: string,
    newPassword: string
  ): Promise<void> {
    const current = this.core.requireData()
    assertMasterPasswordChangeAccount(current)
    if (
      current.masterPasswordChange?.phase !== 'remote-confirmed' &&
      current.masterPasswordChange?.phase !== 'local-rekeyed'
    ) {
      throw new VaultError('SYNC_FAILED')
    }
    await this.core.rekey(currentPassword, newPassword)

    const generation = this.core.advanceGeneration()
    this.pinUnlock.invalidate()
    this.syncSession.abortSyncOperation()
    this.syncSession.abortNotificationTokenLeases()
    this.syncSession.abortAccountSecurityRequests()
    this.syncSession.dropSyncClient()
    const localRekeyed = cloneData(this.core.requireData())
    if (!localRekeyed.masterPasswordChange) throw new VaultError('SYNC_FAILED')
    localRekeyed.masterPasswordChange.phase = 'local-rekeyed'
    localRekeyed.masterPasswordChange.updatedAt = this.core.nowIso()
    if (localRekeyed.sync) localRekeyed.sync.state.session = null
    localRekeyed.updatedAt = localRekeyed.masterPasswordChange.updatedAt
    await this.core.commit(localRekeyed, generation)

    const complete = cloneData(localRekeyed)
    complete.masterPasswordChange = null
    complete.updatedAt = this.core.nowIso()
    await this.core.commit(complete, generation)
  }

  private async proveRemotePassword(
    sync: PersistedSyncData,
    password: string,
    signal: AbortSignal
  ): Promise<'accepted' | 'rejected' | 'needs-reconnect'> {
    const verificationSync = structuredClone(sync)
    verificationSync.state.session = null
    const verifier = this.syncSession.createDetachedClient(verificationSync)
    try {
      await verifier.login({ email: sync.email, password, signal })
      return 'accepted'
    } catch (error) {
      if (error instanceof BitwardenDirectError && error.code === 'AUTH_REQUIRED') {
        return 'rejected'
      }
      if (
        error instanceof BitwardenDirectError &&
        (error.code === 'TWO_FACTOR_REQUIRED' || error.code === 'NEW_DEVICE_REQUIRED')
      ) {
        return 'needs-reconnect'
      }
      throw this.syncSession.mapSyncError(error)
    } finally {
      try {
        await verifier.logout()
      } catch {
        // Best-effort cleanup of the isolated proof session.
      }
    }
  }
}
