import { randomUUID } from 'node:crypto'
import type {
  EquivalentDomainSettingsUpdate,
  EquivalentDomainSettingsView,
  AccountSessionDeauthorizationRequest,
  LoginApprovalPrompt,
  LoginApprovalResponse,
  SyncConnectRequest,
  SyncPurgePersonalVaultRequest,
  SyncPurgePersonalVaultResult,
  SyncResult,
  SyncStatus,
  SyncUnlockRequest
} from '../shared/vault-contract'
import {
  MAX_ACCOUNT_PROFILE_NAME_BYTES,
  ACCOUNT_SESSION_DEAUTHORIZATION_CONFIRMATION
} from '../shared/vault-contract'
import {
  BitwardenDirectError,
  type BitwardenDirectState,
  type BitwardenSyncClient,
  type BitwardenWebAuthnRegistrationRequest,
  type BitwardenWebAuthnRegistrationSetup
} from './bitwarden-direct'
import { resolveBitwardenUrls } from './bitwarden-http'
import type { BitwardenNotificationConnectionInfo } from './bitwarden-notifications'
import { VaultError } from './vault-errors'
import type { AccountWebAuthnAttestation } from './account-webauthn-registration-codec'
import {
  MAX_MASTER_PASSWORD_LENGTH,
  MAX_NAME_LENGTH,
  MAX_USERNAME_LENGTH,
  MAX_PASSWORD_LENGTH,
  AUTHENTICATOR_SETUP_TTL_MS,
  MAX_AUTHENTICATOR_SETUP_SESSIONS,
  EMAIL_TWO_FACTOR_SETUP_TTL_MS,
  MAX_EMAIL_TWO_FACTOR_SETUP_SESSIONS,
  MAX_SYNC_SECRET_LENGTH
} from './vault/limits'
import { isRecord, normalizeRequiredString, normalizeSyncPassword } from './vault/parse-primitives'
import { cloneData } from './vault/vault-data-parsing'
import { assertNoPendingPersonalVaultPurge } from './vault/sync-data-parsing'
import {
  cloneEquivalentDomainSettings,
  validateRemoteEquivalentDomainSettings,
  equivalentDomainRevision,
  equivalentDomainSettingsView,
  normalizeEquivalentDomainUpdate
} from './vault/equivalent-domains'
import type {
  PersistedSyncData,
  VaultData,
  VaultAccountWebAuthnRegistrationRequester
} from './vault/types'
import {
  clearAccountWebAuthnRegistrationSetup,
  clearAccountWebAuthnAttestation,
  scrubAccountSessionDeauthorizationRequest,
  type EmailTwoFactorSetupSession,
  type AccountWebAuthnOperationLease
} from './vault-service-base'
import { VaultServiceBase } from './vault-service-base'

/** Account security, authentication, and public synchronization operations. */
export class VaultAccountService extends VaultServiceBase {
  syncStatus(): Promise<SyncStatus> {
    return this.exclusive(async () => this.currentSyncStatus(true))
  }

  async getAccountSecurityProfile(): Promise<
    import('../shared/vault-contract').AccountSecurityProfile
  > {
    const lease = await this.exclusive(async () => {
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.getAccountSecurityProfile) throw new VaultError('SYNC_FAILED')
      const abort = new AbortController()
      this.accountSecurityAborts.add(abort)
      return {
        generation: this.generation,
        client,
        email: sync.email,
        request: client.getAccountSecurityProfile.bind(client),
        abort
      }
    })
    try {
      const profile = await lease.request(lease.abort.signal)
      return await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        const state = lease.client.exportState()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !state.session ||
          state.profileId !== profile.id ||
          profile.email.toLowerCase() !== lease.email.toLowerCase()
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.persistCurrentClientState()
        return {
          name: profile.name,
          email: profile.email,
          avatarColor: profile.avatarColor,
          emailVerified: profile.emailVerified,
          twoFactorEnabled: profile.twoFactorEnabled
        }
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    }
  }

  async updateAccountProfileName(request: {
    name: string
    expectedName: string
  }): Promise<import('../shared/vault-contract').AccountSecurityProfile> {
    if (
      typeof request.name !== 'string' ||
      typeof request.expectedName !== 'string' ||
      Buffer.byteLength(request.name, 'utf8') > MAX_ACCOUNT_PROFILE_NAME_BYTES ||
      Buffer.byteLength(request.expectedName, 'utf8') > MAX_ACCOUNT_PROFILE_NAME_BYTES ||
      /[\0\r\n]/u.test(request.name) ||
      /[\0\r\n]/u.test(request.expectedName)
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    return this.updateAccountProfile((client, signal) => {
      if (!client.updateAccountProfileName) throw new VaultError('SYNC_FAILED')
      return client.updateAccountProfileName(request.name, request.expectedName, signal)
    })
  }

  async updateAccountAvatarColor(request: {
    avatarColor: string | null
    expectedAvatarColor: string | null
  }): Promise<import('../shared/vault-contract').AccountSecurityProfile> {
    const validColor = (value: unknown): value is string | null =>
      value === null || (typeof value === 'string' && /^#[0-9a-f]{6}$/iu.test(value))
    if (!validColor(request.avatarColor) || !validColor(request.expectedAvatarColor)) {
      throw new VaultError('INVALID_INPUT')
    }
    const avatarColor = request.avatarColor?.toLocaleUpperCase('en-US') ?? null
    const expectedAvatarColor = request.expectedAvatarColor?.toLocaleUpperCase('en-US') ?? null
    return this.updateAccountProfile((client, signal) => {
      if (!client.updateAccountAvatarColor) throw new VaultError('SYNC_FAILED')
      return client.updateAccountAvatarColor(avatarColor, expectedAvatarColor, signal)
    })
  }

  private async updateAccountProfile(
    request: (
      client: BitwardenSyncClient,
      signal: AbortSignal
    ) => Promise<import('./bitwarden-http').BitwardenAccountSecurityProfile>
  ): Promise<import('../shared/vault-contract').AccountSecurityProfile> {
    const lease = await this.exclusive(async () => {
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.exportState().session) throw new VaultError('SYNC_AUTH_REQUIRED')
      const abort = new AbortController()
      this.accountSecurityAborts.add(abort)
      return { generation: this.generation, client, email: sync.email, abort }
    })
    try {
      const profile = await request(lease.client, lease.abort.signal)
      return await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        const state = lease.client.exportState()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !state.session ||
          state.profileId !== profile.id ||
          profile.email.toLowerCase() !== lease.email.toLowerCase()
        ) {
          throw new VaultError('ACCOUNT_PROFILE_MUTATION_UNKNOWN')
        }
        await this.persistCurrentClientState()
        return {
          name: profile.name,
          email: profile.email,
          avatarColor: profile.avatarColor,
          emailVerified: profile.emailVerified,
          twoFactorEnabled: profile.twoFactorEnabled
        }
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof BitwardenDirectError) {
          if (error.code === 'ACCOUNT_PROFILE_STALE') {
            throw new VaultError('ACCOUNT_PROFILE_STALE')
          }
          if (error.code === 'ACCOUNT_PROFILE_MUTATION_UNKNOWN') {
            throw new VaultError('ACCOUNT_PROFILE_MUTATION_UNKNOWN')
          }
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    }
  }

  async getAccountDevices(): Promise<import('../shared/vault-contract').AccountDevicesResult> {
    const lease = await this.exclusive(async () => {
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.exportState().session) throw new VaultError('SYNC_AUTH_REQUIRED')
      const abort = new AbortController()
      this.accountSecurityAborts.add(abort)
      return {
        generation: this.generation,
        client,
        request: client.getAccountDevices?.bind(client) ?? null,
        abort
      }
    })
    try {
      const devices = lease.request ? await lease.request(lease.abort.signal) : null
      return await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        if (!devices) return { status: 'unavailable' }
        await this.persistCurrentClientState().catch(() => undefined)
        return {
          status: 'available',
          devices: devices.map((device) => ({
            name: device.name,
            type: device.type,
            createdAt: device.createdAt,
            lastActivityAt: device.lastActivityAt,
            current: device.current,
            trusted: device.trusted,
            pendingAuthRequest: device.pendingAuthRequest
          }))
        }
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (this.syncClient !== lease.client || !lease.client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        if (error instanceof BitwardenDirectError && error.code === 'NOT_FOUND') {
          return { status: 'unavailable' }
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    }
  }

  /** Main-process entry point used by a trusted type-15 SignalR notification. */
  async prepareLoginApproval(requestId: string): Promise<LoginApprovalPrompt | null> {
    const lease = await this.exclusive(async () => {
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.exportState().session) throw new VaultError('SYNC_AUTH_REQUIRED')
      const request = client.getLoginRequest?.bind(client)
      if (!request) return null
      const abort = new AbortController()
      this.accountSecurityAborts.add(abort)
      return { generation: this.generation, client, request, abort }
    })
    if (!lease) return null
    try {
      const pending = await lease.request(requestId, lease.abort.signal)
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.assertLoginApprovalLease(lease)
        return this.issueLoginApproval(pending, lease.client, lease.generation)
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) return null
        if (error instanceof BitwardenDirectError && error.code === 'NOT_FOUND') return null
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    }
  }

  async getPendingLoginApprovals(): Promise<LoginApprovalPrompt[]> {
    const lease = await this.exclusive(async () => {
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.exportState().session) throw new VaultError('SYNC_AUTH_REQUIRED')
      const request = client.listPendingLoginRequests?.bind(client)
      if (!request) return null
      const abort = new AbortController()
      this.accountSecurityAborts.add(abort)
      return { generation: this.generation, client, request, abort }
    })
    if (!lease) return []
    try {
      const pending = await lease.request(lease.abort.signal)
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.assertLoginApprovalLease(lease)
        return pending
          .map((request) => this.issueLoginApproval(request, lease.client, lease.generation))
          .filter((prompt): prompt is LoginApprovalPrompt => prompt !== null)
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof BitwardenDirectError && error.code === 'NOT_FOUND') return []
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    }
  }

  async respondLoginApproval(response: LoginApprovalResponse): Promise<void> {
    const lease = await this.exclusive(async () => {
      const session = this.loginApprovalSessions.get(response.token)
      this.loginApprovalSessions.delete(response.token)
      if (
        !session ||
        session.generation !== this.generation ||
        session.client !== this.syncClient ||
        session.expiresAt <= this.now().getTime() ||
        session.fingerprint !== response.fingerprint ||
        !session.client.exportState().session
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const request = session.client.respondLoginRequest?.bind(session.client)
      if (!request) throw new VaultError('SYNC_FAILED')
      const abort = new AbortController()
      this.accountSecurityAborts.add(abort)
      return { ...session, request, abort }
    })
    try {
      await lease.request(lease.requestId, lease.fingerprint, response.approved, lease.abort.signal)
      await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.assertLoginApprovalLease(lease)
        for (const [token, session] of this.loginApprovalSessions) {
          if (session.requestId === lease.requestId) this.loginApprovalSessions.delete(token)
        }
        await this.persistCurrentClientState().catch(() => undefined)
      })
    } catch (error) {
      await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    }
  }

  async deauthorizeAllSessions(request: AccountSessionDeauthorizationRequest): Promise<SyncStatus> {
    let lease: {
      generation: number
      client: BitwardenSyncClient
      request: NonNullable<BitwardenSyncClient['deauthorizeAllSessions']>
      abort: AbortController
      masterPassword: string
      originalState: BitwardenDirectState
    }
    try {
      lease = await this.exclusive(async () => {
        const descriptors =
          typeof request === 'object' && request !== null
            ? Object.getOwnPropertyDescriptors(request)
            : Object.create(null)
        const masterPassword = descriptors.masterPassword?.value
        const confirmation = descriptors.confirmation?.value
        const confirm = descriptors.confirm?.value
        if (
          !isRecord(request) ||
          (Object.getPrototypeOf(request) !== Object.prototype &&
            Object.getPrototypeOf(request) !== null) ||
          Reflect.ownKeys(request).length !== 3 ||
          !descriptors.masterPassword?.enumerable ||
          !('value' in descriptors.masterPassword) ||
          !descriptors.confirmation?.enumerable ||
          !('value' in descriptors.confirmation) ||
          !descriptors.confirm?.enumerable ||
          !('value' in descriptors.confirm) ||
          typeof masterPassword !== 'string' ||
          masterPassword.length === 0 ||
          masterPassword.length > MAX_SYNC_SECRET_LENGTH ||
          confirmation !== ACCOUNT_SESSION_DEAUTHORIZATION_CONFIRMATION ||
          confirm !== true
        ) {
          throw new VaultError('INVALID_INPUT')
        }

        const current = this.requireData()
        if (
          this.syncInProgress ||
          current.sync?.pendingLoginMutation ||
          current.sync?.pendingLoginImport ||
          current.sync?.pendingPersonalVaultPurge ||
          current.nativeAttachmentRestore ||
          current.masterPasswordChange ||
          this.activeAttachmentOperation ||
          this.activeAccountBreachOperation ||
          this.notificationTokenAborts.size > 0 ||
          this.accountSecurityAborts.size > 0 ||
          this.nativeAttachmentBackupAborts.size > 0 ||
          this.nativeAttachmentRestoreAborts.size > 0
        ) {
          throw new VaultError('SYNC_FAILED')
        }
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        if (!client.deauthorizeAllSessions || !client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        const abort = new AbortController()
        const originalState = client.exportState()
        const failClosed = cloneData(current)
        if (!failClosed.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
        failClosed.sync.state = {
          ...originalState,
          session: null,
          securityStamp: null
        }
        failClosed.updatedAt = this.nowIso()
        this.sessionDeauthorizationInProgress = true
        this.abortNotificationTokenLeases()
        try {
          await this.persist(failClosed)
        } catch {
          this.sessionDeauthorizationInProgress = false
          throw new VaultError('SYNC_FAILED')
        }
        this.data = failClosed
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          request: client.deauthorizeAllSessions.bind(client),
          abort,
          masterPassword,
          originalState
        }
      })
    } catch (error) {
      scrubAccountSessionDeauthorizationRequest(request)
      throw error
    }

    scrubAccountSessionDeauthorizationRequest(request)
    let operationError: unknown = null
    try {
      await lease.request(lease.masterPassword, lease.abort.signal)
    } catch (error) {
      operationError = error
    }

    try {
      return await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        try {
          const current = this.requireData()
          if (lease.abort.signal.aborted || lease.generation !== this.generation) {
            throw new VaultError('LOCKED')
          }
          if (this.syncClient !== lease.client) throw new VaultError('SYNC_AUTH_REQUIRED')

          if (operationError) {
            if (operationError instanceof BitwardenDirectError) {
              if (operationError.code === 'SESSION_DEAUTHORIZATION_UNKNOWN') {
                const state = lease.client.exportState()
                if (state.session || state.securityStamp !== null) {
                  throw new VaultError('SYNC_FAILED')
                }
                this.abortNotificationTokenLeases()
                this.syncLastError = null
                throw new VaultError('SESSION_DEAUTHORIZATION_UNKNOWN')
              }
            }
            if (operationError instanceof VaultError) throw operationError

            const restored = cloneData(current)
            if (!restored.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
            restored.sync.state = lease.originalState
            restored.updatedAt = this.nowIso()
            try {
              await this.persist(restored)
              this.data = restored
            } catch {
              this.syncClient = null
              await lease.client.logout().catch(() => undefined)
              throw new VaultError('SYNC_FAILED')
            }
            if (
              operationError instanceof BitwardenDirectError &&
              operationError.code === 'USER_VERIFICATION_FAILED'
            ) {
              throw new VaultError('INVALID_MASTER_PASSWORD')
            }
            throw this.mapSyncError(operationError)
          }

          const state = lease.client.exportState()
          if (state.session || state.securityStamp !== null) throw new VaultError('SYNC_FAILED')
          this.abortNotificationTokenLeases()
          this.syncLastError = null
          const sync = this.requireSyncData()
          return this.baseSyncStatus(sync, 'locked')
        } finally {
          this.sessionDeauthorizationInProgress = false
        }
      })
    } finally {
      scrubAccountSessionDeauthorizationRequest(request)
      lease.masterPassword = ''
    }
  }

  async resendAccountVerificationEmail(): Promise<void> {
    const lease = await this.exclusive(async () => {
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.resendVerificationEmail) throw new VaultError('SYNC_FAILED')
      const abort = new AbortController()
      this.accountSecurityAborts.add(abort)
      return {
        generation: this.generation,
        client,
        request: client.resendVerificationEmail.bind(client),
        abort
      }
    })
    try {
      await lease.request(lease.abort.signal)
      await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.persistCurrentClientState()
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    }
  }

  copyAccountApiClientId(): Promise<void> {
    return this.exclusive(async () => {
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const state = client.exportState()
      if (!state.session || !state.profileId) throw new VaultError('SYNC_AUTH_REQUIRED')
      await this.platform.copyText(`user.${state.profileId}`)
    })
  }

  async copyPersonalApiKey(request: {
    masterPassword: string
    rotate: boolean
    confirmRotation: boolean
  }): Promise<{ rotated: boolean; revisionDate: string }> {
    if (
      typeof request.masterPassword !== 'string' ||
      request.masterPassword.length === 0 ||
      request.masterPassword.length > MAX_PASSWORD_LENGTH ||
      typeof request.rotate !== 'boolean' ||
      typeof request.confirmRotation !== 'boolean' ||
      request.confirmRotation !== request.rotate
    ) {
      request.masterPassword = ''
      throw new VaultError('INVALID_INPUT')
    }
    const copySensitiveText = this.platform.copySensitiveText
    if (!copySensitiveText) {
      request.masterPassword = ''
      throw new VaultError('INTERNAL_ERROR')
    }
    let lease: {
      generation: number
      client: BitwardenSyncClient
      request: NonNullable<BitwardenSyncClient['getPersonalApiKey']>
      abort: AbortController
    }
    try {
      lease = await this.exclusive(async () => {
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        if (!client.getPersonalApiKey) throw new VaultError('SYNC_FAILED')
        const state = client.exportState()
        if (!state.session || !state.profileId) throw new VaultError('SYNC_AUTH_REQUIRED')
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          request: client.getPersonalApiKey.bind(client),
          abort
        }
      })
    } catch (error) {
      request.masterPassword = ''
      throw error
    }
    let result: Awaited<ReturnType<NonNullable<BitwardenSyncClient['getPersonalApiKey']>>> | null =
      null
    try {
      result = await lease.request(request.masterPassword, request.rotate, lease.abort.signal)
      return await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await copySensitiveText(result!.clientSecret, 30)
        await this.persistCurrentClientState().catch(() => undefined)
        return { rotated: request.rotate, revisionDate: result!.revisionDate }
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof BitwardenDirectError) {
          if (error.code === 'USER_VERIFICATION_FAILED') {
            throw new VaultError('INVALID_MASTER_PASSWORD')
          }
          if (error.code === 'API_KEY_ROTATION_UNKNOWN') {
            throw new VaultError('API_KEY_ROTATION_UNKNOWN')
          }
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    } finally {
      request.masterPassword = ''
      if (result) result.clientSecret = ''
    }
  }

  async getTwoFactorStatus(): Promise<{ type: number; enabled: boolean }[]> {
    const lease = await this.exclusive(async () => {
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.getTwoFactorProviders) throw new VaultError('SYNC_FAILED')
      const abort = new AbortController()
      this.accountSecurityAborts.add(abort)
      return {
        generation: this.generation,
        client,
        request: client.getTwoFactorProviders.bind(client),
        abort
      }
    })
    try {
      const providers = await lease.request(lease.abort.signal)
      return await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.persistCurrentClientState().catch(() => undefined)
        return providers.map((provider) => ({ ...provider }))
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    }
  }

  async disableTwoFactorProvider(request: {
    type: 0 | 1 | 2 | 3 | 7
    masterPassword: string
    confirm: true
  }): Promise<void> {
    if (
      !([0, 1, 2, 3, 7] as const).includes(request.type) ||
      request.confirm !== true ||
      typeof request.masterPassword !== 'string' ||
      request.masterPassword.length === 0 ||
      request.masterPassword.length > MAX_PASSWORD_LENGTH
    ) {
      request.masterPassword = ''
      throw new VaultError('INVALID_INPUT')
    }
    let lease: {
      generation: number
      client: BitwardenSyncClient
      request: NonNullable<BitwardenSyncClient['disableTwoFactorProvider']>
      abort: AbortController
    }
    try {
      lease = await this.exclusive(async () => {
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        if (!client.disableTwoFactorProvider || !client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          request: client.disableTwoFactorProvider.bind(client),
          abort
        }
      })
    } catch (error) {
      request.masterPassword = ''
      throw error
    }
    const mutation = { type: request.type, masterPassword: request.masterPassword }
    request.masterPassword = ''
    try {
      await lease.request(mutation.type, mutation.masterPassword, lease.abort.signal)
      await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.persistCurrentClientState().catch(() => undefined)
      })
    } catch (error) {
      await this.exclusive(async () => this.accountSecurityAborts.delete(lease.abort))
      if (lease.abort.signal.aborted || lease.generation !== this.generation) {
        throw new VaultError('LOCKED')
      }
      if (error instanceof BitwardenDirectError) {
        if (error.code === 'USER_VERIFICATION_FAILED') {
          throw new VaultError('INVALID_MASTER_PASSWORD')
        }
        if (error.code === 'TWO_FACTOR_MUTATION_UNKNOWN') {
          throw new VaultError('TWO_FACTOR_MUTATION_UNKNOWN')
        }
      }
      if (error instanceof VaultError) throw error
      throw this.mapSyncError(error)
    } finally {
      request.masterPassword = ''
      mutation.type = -1 as 0 | 1 | 2 | 3 | 7
      mutation.masterPassword = ''
    }
  }

  async copyTwoFactorRecoveryCode(request: { masterPassword: string }): Promise<void> {
    if (
      typeof request.masterPassword !== 'string' ||
      request.masterPassword.length === 0 ||
      request.masterPassword.length > MAX_PASSWORD_LENGTH
    ) {
      request.masterPassword = ''
      throw new VaultError('INVALID_INPUT')
    }
    const copySensitiveText = this.platform.copySensitiveText
    if (!copySensitiveText) {
      request.masterPassword = ''
      throw new VaultError('INTERNAL_ERROR')
    }
    let lease: {
      generation: number
      client: BitwardenSyncClient
      request: NonNullable<BitwardenSyncClient['getTwoFactorRecoveryCode']>
      abort: AbortController
    }
    try {
      lease = await this.exclusive(async () => {
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        if (!client.getTwoFactorRecoveryCode) throw new VaultError('SYNC_FAILED')
        if (!client.exportState().session) throw new VaultError('SYNC_AUTH_REQUIRED')
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          request: client.getTwoFactorRecoveryCode.bind(client),
          abort
        }
      })
    } catch (error) {
      request.masterPassword = ''
      throw error
    }
    let code = ''
    try {
      code = await lease.request(request.masterPassword, lease.abort.signal)
      await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await copySensitiveText(code, 30)
        await this.persistCurrentClientState().catch(() => undefined)
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof BitwardenDirectError && error.code === 'USER_VERIFICATION_FAILED') {
          throw new VaultError('INVALID_MASTER_PASSWORD')
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    } finally {
      request.masterPassword = ''
      code = ''
    }
  }

  async beginAccountAuthenticatorSetup(request: { masterPassword: string }): Promise<{
    sessionId: string
    key: string
    requiresMasterPassword: boolean
    expiresAt: number
  }> {
    if (
      typeof request.masterPassword !== 'string' ||
      request.masterPassword.length === 0 ||
      request.masterPassword.length > MAX_PASSWORD_LENGTH
    ) {
      request.masterPassword = ''
      throw new VaultError('INVALID_INPUT')
    }
    let lease: {
      generation: number
      client: BitwardenSyncClient
      request: NonNullable<BitwardenSyncClient['beginAuthenticatorSetup']>
      abort: AbortController
    }
    try {
      lease = await this.exclusive(async () => {
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        if (!client.beginAuthenticatorSetup || !client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          request: client.beginAuthenticatorSetup.bind(client),
          abort
        }
      })
    } catch (error) {
      request.masterPassword = ''
      throw error
    }
    try {
      const setup = await lease.request(request.masterPassword, lease.abort.signal)
      return await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        if (setup.enabled || !/^[A-Z2-7]{32}$/.test(setup.key)) {
          throw new VaultError('INVALID_INPUT')
        }
        this.evictExpiredAuthenticatorSetupSessions()
        while (this.authenticatorSetupSessions.size >= MAX_AUTHENTICATOR_SETUP_SESSIONS) {
          const oldest = this.authenticatorSetupSessions.keys().next().value
          if (typeof oldest !== 'string') break
          this.deleteAuthenticatorSetupSession(oldest)
        }
        const sessionId = randomUUID()
        const expiresAt = this.now().getTime() + AUTHENTICATOR_SETUP_TTL_MS
        this.authenticatorSetupSessions.set(sessionId, {
          generation: lease.generation,
          client: lease.client,
          key: setup.key,
          verificationMode: setup.verificationMode,
          userVerificationToken: setup.userVerificationToken ?? null,
          expiresAt
        })
        await this.persistCurrentClientState().catch(() => undefined)
        return {
          sessionId,
          key: setup.key,
          requiresMasterPassword: setup.verificationMode === 'master-password',
          expiresAt
        }
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof BitwardenDirectError && error.code === 'USER_VERIFICATION_FAILED') {
          throw new VaultError('INVALID_MASTER_PASSWORD')
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    } finally {
      request.masterPassword = ''
    }
  }

  async copyAccountAuthenticatorKey(request: { sessionId: string }): Promise<void> {
    const copySensitiveText = this.platform.copySensitiveText
    if (!copySensitiveText) throw new VaultError('INTERNAL_ERROR')
    await this.exclusive(async () => {
      const session = this.requireAuthenticatorSetupSession(request.sessionId)
      await copySensitiveText(session.key, 30)
    })
  }

  async completeAccountAuthenticatorSetup(request: {
    sessionId: string
    token: string
    masterPassword?: string
  }): Promise<void> {
    if (!/^\d{6}$/.test(request.token)) {
      if (request.masterPassword !== undefined) request.masterPassword = ''
      throw new VaultError('INVALID_INPUT')
    }
    let lease: {
      generation: number
      client: BitwardenSyncClient
      request: NonNullable<BitwardenSyncClient['completeAuthenticatorSetup']>
      key: string
      verificationMode: 'server-token' | 'master-password'
      userVerificationToken: string | null
      abort: AbortController
    }
    try {
      lease = await this.exclusive(async () => {
        const session = this.requireAuthenticatorSetupSession(request.sessionId)
        if (!session.client.completeAuthenticatorSetup) throw new VaultError('SYNC_FAILED')
        if (session.verificationMode === 'server-token' && request.masterPassword !== undefined) {
          throw new VaultError('INVALID_INPUT')
        }
        if (
          session.verificationMode === 'master-password' &&
          (typeof request.masterPassword !== 'string' ||
            request.masterPassword.length === 0 ||
            request.masterPassword.length > MAX_PASSWORD_LENGTH)
        ) {
          throw new VaultError('INVALID_INPUT')
        }
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        const result = {
          generation: session.generation,
          client: session.client,
          request: session.client.completeAuthenticatorSetup.bind(session.client),
          key: session.key,
          verificationMode: session.verificationMode,
          userVerificationToken: session.userVerificationToken,
          abort
        }
        session.key = ''
        session.userVerificationToken = null
        this.authenticatorSetupSessions.delete(request.sessionId)
        return result
      })
    } catch (error) {
      request.token = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      throw error
    }
    const completion = {
      key: lease.key,
      token: request.token,
      verificationMode: lease.verificationMode,
      ...(lease.userVerificationToken
        ? { userVerificationToken: lease.userVerificationToken }
        : {}),
      ...(lease.verificationMode === 'master-password'
        ? { masterPassword: request.masterPassword }
        : {})
    }
    try {
      await lease.request(completion, lease.abort.signal)
      await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.persistCurrentClientState().catch(() => undefined)
      })
    } catch (error) {
      await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
      })
      if (lease.abort.signal.aborted || lease.generation !== this.generation) {
        throw new VaultError('LOCKED')
      }
      if (error instanceof BitwardenDirectError) {
        if (error.code === 'USER_VERIFICATION_FAILED') {
          throw new VaultError('INVALID_MASTER_PASSWORD')
        }
        if (error.code === 'TWO_FACTOR_MUTATION_UNKNOWN') {
          throw new VaultError('TWO_FACTOR_MUTATION_UNKNOWN')
        }
      }
      if (error instanceof VaultError) throw error
      throw this.mapSyncError(error)
    } finally {
      request.token = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      completion.key = ''
      completion.token = ''
      if ('masterPassword' in completion) completion.masterPassword = ''
      if ('userVerificationToken' in completion) completion.userVerificationToken = ''
      lease.key = ''
      lease.userVerificationToken = null
    }
  }

  async beginAccountEmailTwoFactorSetup(request: { masterPassword: string }): Promise<{
    sessionId: string
    requiresMasterPassword: boolean
    expiresAt: number
  }> {
    if (
      typeof request.masterPassword !== 'string' ||
      request.masterPassword.length === 0 ||
      request.masterPassword.length > MAX_PASSWORD_LENGTH
    ) {
      request.masterPassword = ''
      throw new VaultError('INVALID_INPUT')
    }
    let lease: {
      generation: number
      client: BitwardenSyncClient
      request: NonNullable<BitwardenSyncClient['beginEmailTwoFactorSetup']>
      abort: AbortController
    }
    try {
      lease = await this.exclusive(async () => {
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        if (!client.beginEmailTwoFactorSetup || !client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          request: client.beginEmailTwoFactorSetup.bind(client),
          abort
        }
      })
    } catch (error) {
      request.masterPassword = ''
      throw error
    }
    try {
      const setup = await lease.request(request.masterPassword, lease.abort.signal)
      return await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        if (setup.enabled) throw new VaultError('INVALID_INPUT')
        this.evictExpiredEmailTwoFactorSetupSessions()
        while (this.emailTwoFactorSetupSessions.size >= MAX_EMAIL_TWO_FACTOR_SETUP_SESSIONS) {
          const oldest = this.emailTwoFactorSetupSessions.keys().next().value
          if (typeof oldest !== 'string') break
          this.deleteEmailTwoFactorSetupSession(oldest)
        }
        const sessionId = randomUUID()
        const expiresAt = this.now().getTime() + EMAIL_TWO_FACTOR_SETUP_TTL_MS
        this.emailTwoFactorSetupSessions.set(sessionId, {
          generation: lease.generation,
          client: lease.client,
          verificationMode: setup.verificationMode,
          userVerificationToken: setup.userVerificationToken ?? null,
          phase: 'ready-to-send',
          email: null,
          expiresAt
        })
        await this.persistCurrentClientState().catch(() => undefined)
        return {
          sessionId,
          requiresMasterPassword: setup.verificationMode === 'master-password',
          expiresAt
        }
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof BitwardenDirectError && error.code === 'USER_VERIFICATION_FAILED') {
          throw new VaultError('INVALID_MASTER_PASSWORD')
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    } finally {
      request.masterPassword = ''
    }
  }

  async sendAccountEmailTwoFactorSetup(request: {
    sessionId: string
    email: string
    masterPassword?: string
  }): Promise<void> {
    if (
      typeof request.email !== 'string' ||
      request.email.length === 0 ||
      request.email.length > 256 ||
      request.email.trim() !== request.email ||
      /[\0\r\n]/u.test(request.email) ||
      !/^[^\s@]+@[^\s@]+$/u.test(request.email)
    ) {
      request.email = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      throw new VaultError('INVALID_INPUT')
    }
    let lease: EmailTwoFactorSetupSession & {
      request: NonNullable<BitwardenSyncClient['sendEmailTwoFactorSetup']>
      abort: AbortController
      emailForSetup: string
    }
    try {
      lease = await this.exclusive(async () => {
        const session = this.requireEmailTwoFactorSetupSession(request.sessionId, 'ready-to-send')
        if (!session.client.sendEmailTwoFactorSetup) throw new VaultError('SYNC_FAILED')
        this.validateEmailTwoFactorSetupPassword(session, request.masterPassword)
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        const result = {
          ...session,
          request: session.client.sendEmailTwoFactorSetup.bind(session.client),
          abort,
          emailForSetup: request.email
        }
        this.deleteEmailTwoFactorSetupSession(request.sessionId)
        return result
      })
    } catch (error) {
      request.email = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      throw error
    }
    const mutation = {
      email: lease.emailForSetup,
      verificationMode: lease.verificationMode,
      ...(lease.userVerificationToken
        ? { userVerificationToken: lease.userVerificationToken }
        : {}),
      ...(lease.verificationMode === 'master-password'
        ? { masterPassword: request.masterPassword }
        : {})
    }
    try {
      await lease.request(mutation, lease.abort.signal)
      await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session ||
          lease.expiresAt <= this.now().getTime()
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        this.evictExpiredEmailTwoFactorSetupSessions()
        while (this.emailTwoFactorSetupSessions.size >= MAX_EMAIL_TWO_FACTOR_SETUP_SESSIONS) {
          const oldest = this.emailTwoFactorSetupSessions.keys().next().value
          if (typeof oldest !== 'string') break
          this.deleteEmailTwoFactorSetupSession(oldest)
        }
        this.emailTwoFactorSetupSessions.set(request.sessionId, {
          generation: lease.generation,
          client: lease.client,
          verificationMode: lease.verificationMode,
          userVerificationToken: lease.userVerificationToken,
          phase: 'awaiting-code',
          email: lease.emailForSetup,
          expiresAt: lease.expiresAt
        })
        await this.persistCurrentClientState().catch(() => undefined)
      })
    } catch (error) {
      await this.exclusive(async () => this.accountSecurityAborts.delete(lease.abort))
      this.throwEmailTwoFactorSetupError(error, lease)
    } finally {
      request.email = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      mutation.email = ''
      if ('masterPassword' in mutation) mutation.masterPassword = ''
      if ('userVerificationToken' in mutation) mutation.userVerificationToken = ''
      lease.emailForSetup = ''
      lease.userVerificationToken = null
    }
  }

  async completeAccountEmailTwoFactorSetup(request: {
    sessionId: string
    token: string
    masterPassword?: string
  }): Promise<void> {
    if (!/^\d{1,50}$/u.test(request.token)) {
      request.token = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      throw new VaultError('INVALID_INPUT')
    }
    let lease: EmailTwoFactorSetupSession & {
      request: NonNullable<BitwardenSyncClient['completeEmailTwoFactorSetup']>
      abort: AbortController
      emailForSetup: string
    }
    try {
      lease = await this.exclusive(async () => {
        const session = this.requireEmailTwoFactorSetupSession(request.sessionId, 'awaiting-code')
        if (!session.client.completeEmailTwoFactorSetup || !session.email) {
          throw new VaultError('SYNC_FAILED')
        }
        this.validateEmailTwoFactorSetupPassword(session, request.masterPassword)
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        const result = {
          ...session,
          request: session.client.completeEmailTwoFactorSetup.bind(session.client),
          abort,
          emailForSetup: session.email
        }
        this.deleteEmailTwoFactorSetupSession(request.sessionId)
        return result
      })
    } catch (error) {
      request.token = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      throw error
    }
    const mutation = {
      email: lease.emailForSetup,
      token: request.token,
      verificationMode: lease.verificationMode,
      ...(lease.userVerificationToken
        ? { userVerificationToken: lease.userVerificationToken }
        : {}),
      ...(lease.verificationMode === 'master-password'
        ? { masterPassword: request.masterPassword }
        : {})
    }
    try {
      await lease.request(mutation, lease.abort.signal)
      await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.persistCurrentClientState().catch(() => undefined)
      })
    } catch (error) {
      await this.exclusive(async () => this.accountSecurityAborts.delete(lease.abort))
      this.throwEmailTwoFactorSetupError(error, lease)
    } finally {
      request.token = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      mutation.email = ''
      mutation.token = ''
      if ('masterPassword' in mutation) mutation.masterPassword = ''
      if ('userVerificationToken' in mutation) mutation.userVerificationToken = ''
      lease.emailForSetup = ''
      lease.userVerificationToken = null
    }
  }

  async listAccountWebAuthnKeys(request: {
    masterPassword: string
  }): Promise<{ id: number; name: string; migrated: boolean }[]> {
    let masterPassword = ''
    let setup: BitwardenWebAuthnRegistrationSetup | null = null
    let lease:
      | (AccountWebAuthnOperationLease & {
          begin: NonNullable<BitwardenSyncClient['beginWebAuthnSetup']>
        })
      | null = null
    try {
      masterPassword = normalizeSyncPassword(request.masterPassword)
      request.masterPassword = ''
      lease = await this.exclusive(async () => {
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        if (!client.beginWebAuthnSetup || !client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          abort,
          begin: client.beginWebAuthnSetup.bind(client)
        }
      })
      setup = await lease.begin(masterPassword, lease.abort.signal)
      masterPassword = ''
      const keys = setup.keys.map(({ id, name, migrated }) => ({ id, name, migrated }))
      await this.finishAccountWebAuthnOperation(lease, true)
      lease = null
      return keys
    } catch (error) {
      if (lease) {
        await this.releaseAccountWebAuthnOperation(lease)
        this.throwAccountWebAuthnOperationError(error, lease)
      }
      if (error instanceof VaultError) throw error
      throw this.mapSyncError(error)
    } finally {
      request.masterPassword = ''
      masterPassword = ''
      clearAccountWebAuthnRegistrationSetup(setup)
    }
  }

  async enrollAccountWebAuthnKey(request: { masterPassword: string; name: string }): Promise<void> {
    let masterPassword = ''
    let name = ''
    let setup: BitwardenWebAuthnRegistrationSetup | null = null
    let attestation: AccountWebAuthnAttestation | null = null
    let mutation: BitwardenWebAuthnRegistrationRequest | null = null
    let lease:
      | (AccountWebAuthnOperationLease & {
          webVaultUrl: string
          begin: NonNullable<BitwardenSyncClient['beginWebAuthnSetup']>
          complete: NonNullable<BitwardenSyncClient['completeWebAuthnSetup']>
          register: VaultAccountWebAuthnRegistrationRequester
        })
      | null = null
    try {
      masterPassword = normalizeSyncPassword(request.masterPassword)
      name = normalizeRequiredString(request.name, MAX_NAME_LENGTH)
      request.masterPassword = ''
      request.name = ''
      lease = await this.exclusive(async () => {
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        const register = this.requestAccountWebAuthnRegistration
        if (
          !client.beginWebAuthnSetup ||
          !client.completeWebAuthnSetup ||
          !client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        if (!register) throw new VaultError('SYNC_FAILED')
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          abort,
          webVaultUrl: resolveBitwardenUrls(sync.serverUrl).webVaultUrl,
          begin: client.beginWebAuthnSetup.bind(client),
          complete: client.completeWebAuthnSetup.bind(client),
          register
        }
      })

      setup = await lease.begin(masterPassword, lease.abort.signal)
      await this.assertAccountWebAuthnOperationCurrent(lease)
      attestation = structuredClone(
        await lease.register({
          webVaultUrl: lease.webVaultUrl,
          challenge: setup.registrationChallenge,
          signal: lease.abort.signal
        })
      )
      await this.assertAccountWebAuthnOperationCurrent(lease)
      mutation = {
        id: setup.registrationId,
        name,
        attestation,
        verificationMode: setup.verificationMode,
        ...(setup.userVerificationToken
          ? { userVerificationToken: setup.userVerificationToken }
          : {}),
        ...(setup.verificationMode === 'master-password' ? { masterPassword } : {})
      }
      await lease.complete(mutation, lease.abort.signal)
      await this.finishAccountWebAuthnOperation(lease, true)
      lease = null
    } catch (error) {
      if (lease) {
        await this.releaseAccountWebAuthnOperation(lease)
        this.throwAccountWebAuthnOperationError(error, lease)
      }
      if (error instanceof VaultError) throw error
      throw this.mapSyncError(error)
    } finally {
      request.masterPassword = ''
      request.name = ''
      masterPassword = ''
      name = ''
      clearAccountWebAuthnRegistrationSetup(setup)
      clearAccountWebAuthnAttestation(attestation)
      if (mutation) {
        mutation.name = ''
        if (mutation.masterPassword !== undefined) mutation.masterPassword = ''
        if (mutation.userVerificationToken !== undefined) mutation.userVerificationToken = ''
      }
    }
  }

  async removeAccountWebAuthnKey(request: {
    id: number
    masterPassword: string
    confirm: true
  }): Promise<void> {
    let masterPassword = ''
    let id = 0
    let lease:
      | (AccountWebAuthnOperationLease & {
          remove: NonNullable<BitwardenSyncClient['deleteWebAuthnKey']>
        })
      | null = null
    try {
      if (!Number.isSafeInteger(request.id) || request.id < 1 || request.confirm !== true) {
        throw new VaultError('INVALID_INPUT')
      }
      id = request.id
      masterPassword = normalizeSyncPassword(request.masterPassword)
      request.masterPassword = ''
      lease = await this.exclusive(async () => {
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        if (!client.deleteWebAuthnKey || !client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          abort,
          remove: client.deleteWebAuthnKey.bind(client)
        }
      })
      await lease.remove(id, masterPassword, lease.abort.signal)
      await this.finishAccountWebAuthnOperation(lease, true)
      lease = null
    } catch (error) {
      if (lease) {
        await this.releaseAccountWebAuthnOperation(lease)
        this.throwAccountWebAuthnOperationError(error, lease)
      }
      if (error instanceof VaultError) throw error
      throw this.mapSyncError(error)
    } finally {
      request.masterPassword = ''
      id = 0
      masterPassword = ''
    }
  }

  /** Main-process-only notification credentials. Never expose this through IPC or renderer state. */
  async notificationConnectionInfo(): Promise<BitwardenNotificationConnectionInfo | null> {
    const lease = await this.exclusive(async () => {
      const sync = this.requireData().sync
      if (!sync) return null
      const client = this.getOrCreateSyncClient(sync)
      const status = await client.status()
      if (status.status !== 'unlocked') return null
      const state = client.exportState()
      const notificationAccessToken = client.notificationAccessToken?.bind(client)
      if (!state.session || !state.profileId || !notificationAccessToken) return null
      const abort = new AbortController()
      this.notificationTokenAborts.add(abort)
      return {
        client,
        notificationAccessToken,
        generation: this.generation,
        abort,
        notificationsUrl: resolveBitwardenUrls(sync.serverUrl).notificationsUrl,
        userId: state.profileId,
        deviceIdentifier: state.deviceIdentifier
      }
    })
    if (!lease) return null

    let accessToken: string
    try {
      accessToken = await lease.notificationAccessToken(lease.abort.signal)
    } catch {
      await this.exclusive(async () => {
        this.notificationTokenAborts.delete(lease.abort)
      })
      if (lease.abort.signal.aborted) return null
      throw new Error('NOTIFICATION_TOKEN_UNAVAILABLE')
    }

    return this.exclusive(async () => {
      this.notificationTokenAborts.delete(lease.abort)
      const current = this.requireData()
      if (
        lease.abort.signal.aborted ||
        lease.generation !== this.generation ||
        lease.client !== this.syncClient ||
        this.sessionDeauthorizationInProgress ||
        !current.sync
      ) {
        return null
      }
      const state = lease.client.exportState()
      if (
        !state.session ||
        state.session.accessToken !== accessToken ||
        state.profileId !== lease.userId
      ) {
        return null
      }
      if (JSON.stringify(state) !== JSON.stringify(current.sync.state)) {
        const next = cloneData(current)
        if (!next.sync) return null
        next.sync.state = state
        next.updatedAt = this.nowIso()
        await this.persist(next)
        this.data = next
      }
      return {
        notificationsUrl: lease.notificationsUrl,
        accessToken,
        userId: lease.userId,
        deviceIdentifier: lease.deviceIdentifier
      }
    })
  }

  /** Applies a trusted authenticated LogOut notification without deleting sync mappings. */
  remoteLogoutSync(): Promise<SyncStatus> {
    return this.exclusive(async () => {
      const current = this.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      this.invalidatePinUnlockCapability()
      this.syncAbort?.abort()
      this.abortNotificationTokenLeases()
      this.abortAccountSecurityRequests()
      this.abortNativeAttachmentBackups()
      this.abortNativeAttachmentRestores()
      this.activeAccountBreachOperation?.abort.abort()
      if (!current.sync) return { configured: false, state: 'unconfigured' }
      const client = this.syncClient
      this.syncClient = null
      this.syncLastError = null
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
      next.updatedAt = this.nowIso()
      await this.persist(next)
      this.data = next
      return this.baseSyncStatus(next.sync, 'locked')
    })
  }

  connectSync(request: SyncConnectRequest): Promise<SyncResult> {
    this.invalidatePinUnlockCapability()
    return this.exclusive(async () => {
      const current = this.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      const serverUrl = this.normalizeSyncServerUrl(request.serverUrl)
      const email = normalizeRequiredString(request.email, MAX_USERNAME_LENGTH)
      const password = normalizeSyncPassword(request.masterPassword)
      const twoFactor = this.normalizeTwoFactor(request.twoFactorMethod, request.twoFactorCode)
      const newDeviceOtp = this.normalizeNewDeviceOtp(request.newDeviceOtp)
      const abort = this.startSyncOperation()

      try {
        const sync: PersistedSyncData = {
          provider: 'bitwarden',
          serverUrl,
          email,
          state: {
            session: null,
            deviceIdentifier: randomUUID(),
            profileId: null,
            securityStamp: null
          },
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
        const client = this.createSyncClient(sync)
        await this.authenticateSyncWithWebAuthnRetry(
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
        next.sync = sync
        next.updatedAt = this.nowIso()
        await this.persist(next)
        this.data = next
        this.syncClient = client
        return await this.performSync(next, client, abort.signal)
      } catch (error) {
        await this.persistCurrentClientState().catch(() => undefined)
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
    })
  }

  unlockSync(request: SyncUnlockRequest): Promise<SyncStatus> {
    return this.exclusive(async () => {
      const sync = this.requireSyncData()
      const password = normalizeSyncPassword(request.masterPassword)
      const twoFactor = this.normalizeTwoFactor(request.twoFactorMethod, request.twoFactorCode)
      const newDeviceOtp = this.normalizeNewDeviceOtp(request.newDeviceOtp)
      const client = this.getOrCreateSyncClient(sync)
      const abort = this.startSyncOperation()
      try {
        await this.authenticateSyncWithWebAuthnRetry(
          (retryTwoFactor) =>
            client.unlock({
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
        await this.persistCurrentClientState()
        this.syncLastError = null
        return this.baseSyncStatus(sync, 'ready')
      } catch (error) {
        await this.persistCurrentClientState().catch(() => undefined)
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
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
        return this.exclusive(async () => {
          this.syncLastError = null
          const sync = this.requireData().sync
          return sync
            ? this.baseSyncStatus(sync, 'locked')
            : { configured: false, state: 'unconfigured' }
        })
      }
      throw error
    }
  }

  syncNow(): Promise<SyncResult> {
    return this.exclusive(async () => {
      const data = this.requireData()
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const abort = this.startSyncOperation()
      try {
        return await this.performSync(data, client, abort.signal)
      } catch (error) {
        await this.persistCurrentClientState().catch(() => undefined)
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
    })
  }

  disconnectSync(): Promise<SyncStatus> {
    return this.exclusive(async () => {
      const current = this.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      this.invalidatePinUnlockCapability()
      this.syncAbort?.abort()
      this.abortNotificationTokenLeases()
      this.abortAccountSecurityRequests()
      this.abortNativeAttachmentBackups()
      this.abortNativeAttachmentRestores()
      this.activeAccountBreachOperation?.abort.abort()
      const next = cloneData(current)
      const client = this.syncClient
      this.syncClient = null
      this.syncLastError = null
      try {
        await client?.logout()
      } catch {
        // Clearing local sync configuration must work even when the server is offline.
      }
      next.sync = null
      next.updatedAt = this.nowIso()
      await this.persist(next)
      this.data = next
      return { configured: false, state: 'unconfigured' }
    })
  }

  resolvePendingLoginImport(request: {
    masterPassword: string
    confirmRetry: true
  }): Promise<SyncStatus> {
    return this.exclusive(async () => {
      if (request.confirmRetry !== true) throw new VaultError('INVALID_INPUT')
      await this.assertMasterPassword(request.masterPassword)
      const current = this.requireData()
      if (!current.sync?.pendingLoginImport) throw new VaultError('INVALID_INPUT')
      if (current.sync.pendingLoginImport.phase === 'prepared') {
        throw new VaultError('SYNC_FAILED')
      }
      const next = cloneData(current)
      if (!next.sync?.pendingLoginImport) throw new VaultError('SYNC_FAILED')
      next.sync.pendingLoginImport.phase = 'retry-approved'
      next.updatedAt = this.nowIso()
      await this.persist(next)
      this.data = next
      this.syncLastError = null
      return await this.currentSyncStatus(true)
    })
  }

  purgePersonalVault(
    request: SyncPurgePersonalVaultRequest
  ): Promise<SyncPurgePersonalVaultResult> {
    return this.exclusive(async () => {
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

        const current = this.requireData()
        operationGeneration = this.generation
        original = cloneData(current)
        if (
          current.sync?.pendingLoginMutation ||
          current.sync?.pendingLoginImport ||
          current.nativeAttachmentRestore ||
          current.masterPasswordChange ||
          this.activeAttachmentOperation ||
          this.nativeAttachmentBackupAborts.size > 0 ||
          this.nativeAttachmentRestoreAborts.size > 0
        ) {
          throw new VaultError('SYNC_FAILED')
        }
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
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
          cleared.updatedAt = this.nowIso()
          await this.persist(cleared)
          this.data = cleared
          original = cloneData(cleared)
        }

        const active = this.requireData()
        const retryingDispatched = active.sync?.pendingPersonalVaultPurge?.phase === 'dispatched'
        if (retryingDispatched) {
          // Never downgrade an earlier unknown outcome to prepared: a crash at that point would
          // make unlock recovery erase the only durable evidence that a purge may have run.
          didDispatch = true
        } else {
          const startedAt = this.nowIso()
          const prepared = cloneData(active)
          if (!prepared.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
          prepared.sync.pendingPersonalVaultPurge = {
            phase: 'prepared',
            startedAt,
            remainingItems: active.logins.length,
            remainingFolders: active.folders.length
          }
          prepared.updatedAt = this.nowIso()
          await this.persist(prepared)
          this.data = prepared

          const dispatched = cloneData(prepared)
          if (!dispatched.sync?.pendingPersonalVaultPurge) throw new VaultError('SYNC_FAILED')
          dispatched.sync.pendingPersonalVaultPurge.phase = 'dispatched'
          dispatched.updatedAt = this.nowIso()
          try {
            await this.persist(dispatched)
            this.data = dispatched
          } catch (error) {
            await this.restorePreDispatchPurge(original).catch(() => undefined)
            throw error
          }
          didDispatch = true
        }
        abort = this.startSyncOperation()

        let remoteError: unknown
        try {
          await client.purgePersonalVault(request.masterPassword, abort.signal)
        } catch (error) {
          remoteError = error
        }
        if (abort.signal.aborted || operationGeneration !== this.generation) {
          // Locking wins over a potentially slow reconciliation. The dispatched journal remains
          // durable, so the next explicitly unlocked generic sync can reconcile without replaying.
          throw new VaultError('LOCKED')
        }
        if (
          remoteError instanceof BitwardenDirectError &&
          remoteError.code === 'USER_VERIFICATION_FAILED'
        ) {
          await this.restorePreDispatchPurge(original)
          throw new VaultError('INVALID_MASTER_PASSWORD')
        }

        const reconciled = await this.reconcilePersonalVaultPurge(client)
        if (reconciled.status === 'complete') return reconciled
        // A dispatched failure is intentionally surfaced as pending after an authoritative read.
        // The caller may start one fresh, explicitly confirmed attempt; generic sync never replays.
        return reconciled
      } catch (error) {
        if (!didDispatch && original) {
          await this.restorePreDispatchPurge(original).catch(() => undefined)
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      } finally {
        if (abort) this.finishSyncOperation(abort)
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
    return this.exclusive(async () => {
      const current = this.requireData()
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const abort = this.startSyncOperation()
      try {
        const settings = validateRemoteEquivalentDomainSettings(
          await client.getEquivalentDomainSettings(abort.signal)
        )
        if (abort.signal.aborted) throw new BitwardenDirectError('ABORTED')
        const next = cloneData(current)
        if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
        next.sync.domainSettings = cloneEquivalentDomainSettings(settings)
        next.sync.state = client.exportState()
        next.updatedAt = this.nowIso()
        await this.persist(next)
        if (abort.signal.aborted) throw new BitwardenDirectError('ABORTED')
        this.data = next
        this.syncLastError = null
        return equivalentDomainSettingsView(settings)
      } catch (error) {
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
    })
  }

  updateEquivalentDomainSettings(
    request: EquivalentDomainSettingsUpdate
  ): Promise<EquivalentDomainSettingsView> {
    return this.exclusive(async () => {
      if (!/^[0-9a-f]{64}$/u.test(request.expectedRevision)) {
        throw new VaultError('INVALID_INPUT')
      }
      const update = normalizeEquivalentDomainUpdate(request)
      const current = this.requireData()
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const abort = this.startSyncOperation()
      try {
        const serverSettings = validateRemoteEquivalentDomainSettings(
          await client.getEquivalentDomainSettings(abort.signal)
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
          await client.getEquivalentDomainSettings(abort.signal)
        )
        if (abort.signal.aborted) throw new BitwardenDirectError('ABORTED')
        const next = cloneData(current)
        if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
        next.sync.domainSettings = cloneEquivalentDomainSettings(confirmed)
        next.sync.state = client.exportState()
        next.updatedAt = this.nowIso()
        await this.persist(next)
        if (abort.signal.aborted) throw new BitwardenDirectError('ABORTED')
        this.data = next
        this.syncLastError = null
        return equivalentDomainSettingsView(confirmed)
      } catch (error) {
        if (error instanceof BitwardenDirectError && error.code === 'NOT_FOUND') {
          throw new VaultError('NOT_FOUND')
        }
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
    })
  }
}
