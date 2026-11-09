import type { VaultCore } from './core'
import type { AccountBreachReports } from './health'
import type { VaultSyncSession } from './sync-session'
import { randomUUID } from 'node:crypto'
import type {
  LoginApprovalPrompt,
  AccountSessionDeauthorizationRequest,
  LoginApprovalResponse,
  SyncStatus,
  AccountDevicesResult,
  AccountSecurityProfile
} from '../../shared/vault-contract'
import {
  BitwardenDirectError,
  type BitwardenLoginApprovalRequest,
  type BitwardenSyncClient,
  type BitwardenWebAuthnRegistrationSetup,
  type BitwardenDirectState,
  type BitwardenWebAuthnRegistrationRequest
} from '../bitwarden-direct'
import { VaultError } from '../vault-errors'
import type { AccountWebAuthnAttestation } from '../account-webauthn-registration-codec'
import {
  MAX_PASSWORD_LENGTH,
  MAX_NAME_LENGTH,
  AUTHENTICATOR_SETUP_TTL_MS,
  MAX_AUTHENTICATOR_SETUP_SESSIONS,
  EMAIL_TWO_FACTOR_SETUP_TTL_MS,
  MAX_EMAIL_TWO_FACTOR_SETUP_SESSIONS,
  MAX_SYNC_SECRET_LENGTH
} from './limits'
import { normalizeRequiredString, normalizeSyncPassword } from './parse-primitives'
import { cloneData } from './vault-data-parsing'
import type { VaultPlatform, VaultAccountWebAuthnRegistrationRequester } from './types'
import { isRecord } from '../validation-primitives'
import { type AuthenticatorSetupSession, type EmailTwoFactorSetupSession } from './sync-session'
import {
  MAX_ACCOUNT_PROFILE_NAME_BYTES,
  ACCOUNT_SESSION_DEAUTHORIZATION_CONFIRMATION
} from '../../shared/vault-contract'
import { resolveBitwardenUrls } from '../bitwarden-http'
import type { BitwardenNotificationConnectionInfo } from '../bitwarden-notifications'
import type { BitwardenAccountSecurityProfile } from '../bitwarden-http'

interface AccountWebAuthnOperationLease {
  readonly generation: number
  readonly client: BitwardenSyncClient
  readonly abort: AbortController
}

const LOGIN_APPROVAL_TTL_MS = 15 * 60 * 1_000

const MAX_LOGIN_APPROVAL_SESSIONS = 64

function clearAccountWebAuthnRegistrationSetup(
  setup: BitwardenWebAuthnRegistrationSetup | null
): void {
  if (!setup) return
  setup.userVerificationToken = null
  setup.keys.splice(0)
}

function clearAccountWebAuthnAttestation(attestation: AccountWebAuthnAttestation | null): void {
  if (!attestation) return
  attestation.id = ''
  attestation.rawId = ''
  attestation.response.clientDataJSON = ''
  attestation.response.attestationObject = ''
  attestation.clientExtensionResults = {}
  attestation.authenticatorAttachment = null
}

function scrubAccountSessionDeauthorizationRequest(value: unknown): void {
  if (typeof value !== 'object' || value === null) return
  for (const key of ['masterPassword', 'confirmation'] as const) {
    try {
      const descriptor = Object.getOwnPropertyDescriptor(value, key)
      if (!descriptor || !('value' in descriptor)) continue
      Reflect.defineProperty(value, key, { ...descriptor, value: '' })
    } catch {
      // Cleanup is best-effort and must not invoke accessors or replace the intended result.
    }
  }
}

/**
 * Bitwarden account security: profile, devices, login approvals, session deauthorization, API
 * keys, two-step login providers and account WebAuthn keys. Server calls hold account-scoped
 * leases on the sync session, so they end with it.
 */
export class VaultAccountSecurity {
  constructor(
    private readonly core: VaultCore,
    private readonly syncSession: VaultSyncSession,
    private readonly health: AccountBreachReports,
    private readonly platform: VaultPlatform,
    private readonly requestAccountWebAuthnRegistration: VaultAccountWebAuthnRegistrationRequester | null
  ) {}

  async getAccountSecurityProfile(): Promise<AccountSecurityProfile> {
    const lease = await this.core.exclusive(async () => {
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      if (!client.getAccountSecurityProfile) throw new VaultError('SYNC_FAILED')
      const abort = new AbortController()
      this.syncSession.accountSecurityAborts.add(abort)
      return {
        generation: this.core.generation,
        client,
        email: sync.email,
        request: client.getAccountSecurityProfile.bind(client),
        abort
      }
    })
    try {
      const profile = await lease.request(lease.abort.signal)
      return await this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        this.core.requireData()
        const state = lease.client.exportState()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.core.generation ||
          this.syncSession.syncClient !== lease.client ||
          !state.session ||
          state.profileId !== profile.id ||
          profile.email.toLowerCase() !== lease.email.toLowerCase()
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.syncSession.persistCurrentClientState()
        return {
          name: profile.name,
          email: profile.email,
          avatarColor: profile.avatarColor,
          emailVerified: profile.emailVerified,
          twoFactorEnabled: profile.twoFactorEnabled
        }
      })
    } catch (error) {
      return this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof VaultError) throw error
        throw this.syncSession.mapSyncError(error)
      })
    }
  }

  async updateAccountProfileName(request: {
    name: string
    expectedName: string
  }): Promise<AccountSecurityProfile> {
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
  }): Promise<AccountSecurityProfile> {
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
    ) => Promise<BitwardenAccountSecurityProfile>
  ): Promise<AccountSecurityProfile> {
    const lease = await this.core.exclusive(async () => {
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      if (!client.exportState().session) throw new VaultError('SYNC_AUTH_REQUIRED')
      const abort = new AbortController()
      this.syncSession.accountSecurityAborts.add(abort)
      return { generation: this.core.generation, client, email: sync.email, abort }
    })
    try {
      const profile = await request(lease.client, lease.abort.signal)
      return await this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        this.core.requireData()
        const state = lease.client.exportState()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.core.generation ||
          this.syncSession.syncClient !== lease.client ||
          !state.session ||
          state.profileId !== profile.id ||
          profile.email.toLowerCase() !== lease.email.toLowerCase()
        ) {
          throw new VaultError('ACCOUNT_PROFILE_MUTATION_UNKNOWN')
        }
        await this.syncSession.persistCurrentClientState()
        return {
          name: profile.name,
          email: profile.email,
          avatarColor: profile.avatarColor,
          emailVerified: profile.emailVerified,
          twoFactorEnabled: profile.twoFactorEnabled
        }
      })
    } catch (error) {
      return this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
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
        throw this.syncSession.mapSyncError(error)
      })
    }
  }

  async getAccountDevices(): Promise<AccountDevicesResult> {
    const lease = await this.core.exclusive(async () => {
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      if (!client.exportState().session) throw new VaultError('SYNC_AUTH_REQUIRED')
      const abort = new AbortController()
      this.syncSession.accountSecurityAborts.add(abort)
      return {
        generation: this.core.generation,
        client,
        request: client.getAccountDevices?.bind(client) ?? null,
        abort
      }
    })
    try {
      const devices = lease.request ? await lease.request(lease.abort.signal) : null
      return await this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        this.core.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.core.generation ||
          this.syncSession.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        if (!devices) return { status: 'unavailable' }
        await this.syncSession.persistCurrentClientState().catch(() => undefined)
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
      return this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
          throw new VaultError('LOCKED')
        }
        if (this.syncSession.syncClient !== lease.client || !lease.client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        if (error instanceof BitwardenDirectError && error.code === 'NOT_FOUND') {
          return { status: 'unavailable' }
        }
        if (error instanceof VaultError) throw error
        throw this.syncSession.mapSyncError(error)
      })
    }
  }

  /** Main-process entry point used by a trusted type-15 SignalR notification. */
  async prepareLoginApproval(requestId: string): Promise<LoginApprovalPrompt | null> {
    const lease = await this.core.exclusive(async () => {
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      if (!client.exportState().session) throw new VaultError('SYNC_AUTH_REQUIRED')
      const request = client.getLoginRequest?.bind(client)
      if (!request) return null
      const abort = new AbortController()
      this.syncSession.accountSecurityAborts.add(abort)
      return { generation: this.core.generation, client, request, abort }
    })
    if (!lease) return null
    try {
      const pending = await lease.request(requestId, lease.abort.signal)
      return this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        this.assertLoginApprovalLease(lease)
        return this.issueLoginApproval(pending, lease.client, lease.generation)
      })
    } catch (error) {
      return this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.core.generation) return null
        if (error instanceof BitwardenDirectError && error.code === 'NOT_FOUND') return null
        if (error instanceof VaultError) throw error
        throw this.syncSession.mapSyncError(error)
      })
    }
  }

  async getPendingLoginApprovals(): Promise<LoginApprovalPrompt[]> {
    const lease = await this.core.exclusive(async () => {
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      if (!client.exportState().session) throw new VaultError('SYNC_AUTH_REQUIRED')
      const request = client.listPendingLoginRequests?.bind(client)
      if (!request) return null
      const abort = new AbortController()
      this.syncSession.accountSecurityAborts.add(abort)
      return { generation: this.core.generation, client, request, abort }
    })
    if (!lease) return []
    try {
      const pending = await lease.request(lease.abort.signal)
      return this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        this.assertLoginApprovalLease(lease)
        return pending
          .map((request) => this.issueLoginApproval(request, lease.client, lease.generation))
          .filter((prompt): prompt is LoginApprovalPrompt => prompt !== null)
      })
    } catch (error) {
      return this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof BitwardenDirectError && error.code === 'NOT_FOUND') return []
        if (error instanceof VaultError) throw error
        throw this.syncSession.mapSyncError(error)
      })
    }
  }

  async respondLoginApproval(response: LoginApprovalResponse): Promise<void> {
    const lease = await this.core.exclusive(async () => {
      const session = this.syncSession.loginApprovalSessions.get(response.token)
      this.syncSession.loginApprovalSessions.delete(response.token)
      if (
        !session ||
        session.generation !== this.core.generation ||
        session.client !== this.syncSession.syncClient ||
        session.expiresAt <= this.core.now().getTime() ||
        session.fingerprint !== response.fingerprint ||
        !session.client.exportState().session
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const request = session.client.respondLoginRequest?.bind(session.client)
      if (!request) throw new VaultError('SYNC_FAILED')
      const abort = new AbortController()
      this.syncSession.accountSecurityAborts.add(abort)
      return { ...session, request, abort }
    })
    try {
      await lease.request(lease.requestId, lease.fingerprint, response.approved, lease.abort.signal)
      await this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        this.assertLoginApprovalLease(lease)
        for (const [token, session] of this.syncSession.loginApprovalSessions) {
          if (session.requestId === lease.requestId)
            this.syncSession.loginApprovalSessions.delete(token)
        }
        await this.syncSession.persistCurrentClientState().catch(() => undefined)
      })
    } catch (error) {
      await this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof VaultError) throw error
        throw this.syncSession.mapSyncError(error)
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
      lease = await this.core.exclusive(async () => {
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

        const current = this.core.requireData()
        if (
          this.syncSession.syncInProgress ||
          current.sync?.pendingLoginMutation ||
          current.sync?.pendingLoginImport ||
          current.sync?.pendingPersonalVaultPurge ||
          current.nativeAttachmentRestore ||
          current.masterPasswordChange ||
          this.syncSession.activeAttachmentOperation ||
          this.health.hasActiveAccountBreachReport() ||
          this.syncSession.notificationTokenAborts.size > 0 ||
          this.syncSession.accountSecurityAborts.size > 0 ||
          this.syncSession.nativeAttachmentBackupAborts.size > 0 ||
          this.syncSession.nativeAttachmentRestoreAborts.size > 0
        ) {
          throw new VaultError('SYNC_FAILED')
        }
        const sync = this.syncSession.requireSyncData()
        const client = this.syncSession.getOrCreateSyncClient(sync)
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
        failClosed.updatedAt = this.core.nowIso()
        this.syncSession.beginSessionDeauthorization()
        this.syncSession.abortNotificationTokenLeases()
        try {
          await this.core.commit(failClosed)
        } catch {
          this.syncSession.endSessionDeauthorization()
          throw new VaultError('SYNC_FAILED')
        }
        this.syncSession.accountSecurityAborts.add(abort)
        return {
          generation: this.core.generation,
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
      return await this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        try {
          const current = this.core.requireData()
          if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
            throw new VaultError('LOCKED')
          }
          if (this.syncSession.syncClient !== lease.client)
            throw new VaultError('SYNC_AUTH_REQUIRED')

          if (operationError) {
            if (operationError instanceof BitwardenDirectError) {
              if (operationError.code === 'SESSION_DEAUTHORIZATION_UNKNOWN') {
                const state = lease.client.exportState()
                if (state.session || state.securityStamp !== null) {
                  throw new VaultError('SYNC_FAILED')
                }
                this.syncSession.abortNotificationTokenLeases()
                this.syncSession.clearSyncErrorState()
                throw new VaultError('SESSION_DEAUTHORIZATION_UNKNOWN')
              }
            }
            if (operationError instanceof VaultError) throw operationError

            const restored = cloneData(current)
            if (!restored.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
            restored.sync.state = lease.originalState
            restored.updatedAt = this.core.nowIso()
            try {
              await this.core.commit(restored)
            } catch {
              this.syncSession.dropSyncClient()
              await lease.client.logout().catch(() => undefined)
              throw new VaultError('SYNC_FAILED')
            }
            if (
              operationError instanceof BitwardenDirectError &&
              operationError.code === 'USER_VERIFICATION_FAILED'
            ) {
              throw new VaultError('INVALID_MASTER_PASSWORD')
            }
            throw this.syncSession.mapSyncError(operationError)
          }

          const state = lease.client.exportState()
          if (state.session || state.securityStamp !== null) throw new VaultError('SYNC_FAILED')
          this.syncSession.abortNotificationTokenLeases()
          this.syncSession.clearSyncErrorState()
          const sync = this.syncSession.requireSyncData()
          return this.syncSession.baseSyncStatus(sync, 'locked')
        } finally {
          this.syncSession.endSessionDeauthorization()
        }
      })
    } finally {
      scrubAccountSessionDeauthorizationRequest(request)
      lease.masterPassword = ''
    }
  }

  async resendAccountVerificationEmail(): Promise<void> {
    const lease = await this.core.exclusive(async () => {
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      if (!client.resendVerificationEmail) throw new VaultError('SYNC_FAILED')
      const abort = new AbortController()
      this.syncSession.accountSecurityAborts.add(abort)
      return {
        generation: this.core.generation,
        client,
        request: client.resendVerificationEmail.bind(client),
        abort
      }
    })
    try {
      await lease.request(lease.abort.signal)
      await this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        this.core.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.core.generation ||
          this.syncSession.syncClient !== lease.client
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.syncSession.persistCurrentClientState()
      })
    } catch (error) {
      return this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof VaultError) throw error
        throw this.syncSession.mapSyncError(error)
      })
    }
  }

  copyAccountApiClientId(): Promise<void> {
    return this.core.exclusive(async () => {
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
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
      lease = await this.core.exclusive(async () => {
        const sync = this.syncSession.requireSyncData()
        const client = this.syncSession.getOrCreateSyncClient(sync)
        if (!client.getPersonalApiKey) throw new VaultError('SYNC_FAILED')
        const state = client.exportState()
        if (!state.session || !state.profileId) throw new VaultError('SYNC_AUTH_REQUIRED')
        const abort = new AbortController()
        this.syncSession.accountSecurityAborts.add(abort)
        return {
          generation: this.core.generation,
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
      return await this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        this.core.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.core.generation ||
          this.syncSession.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await copySensitiveText(result!.clientSecret, 30)
        await this.syncSession.persistCurrentClientState().catch(() => undefined)
        return { rotated: request.rotate, revisionDate: result!.revisionDate }
      })
    } catch (error) {
      return this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
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
        throw this.syncSession.mapSyncError(error)
      })
    } finally {
      request.masterPassword = ''
      if (result) result.clientSecret = ''
    }
  }

  async getTwoFactorStatus(): Promise<{ type: number; enabled: boolean }[]> {
    const lease = await this.core.exclusive(async () => {
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      if (!client.getTwoFactorProviders) throw new VaultError('SYNC_FAILED')
      const abort = new AbortController()
      this.syncSession.accountSecurityAborts.add(abort)
      return {
        generation: this.core.generation,
        client,
        request: client.getTwoFactorProviders.bind(client),
        abort
      }
    })
    try {
      const providers = await lease.request(lease.abort.signal)
      return await this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        this.core.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.core.generation ||
          this.syncSession.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.syncSession.persistCurrentClientState().catch(() => undefined)
        return providers.map((provider) => ({ ...provider }))
      })
    } catch (error) {
      return this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof VaultError) throw error
        throw this.syncSession.mapSyncError(error)
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
      lease = await this.core.exclusive(async () => {
        const sync = this.syncSession.requireSyncData()
        const client = this.syncSession.getOrCreateSyncClient(sync)
        if (!client.disableTwoFactorProvider || !client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        const abort = new AbortController()
        this.syncSession.accountSecurityAborts.add(abort)
        return {
          generation: this.core.generation,
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
      await this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        this.core.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.core.generation ||
          this.syncSession.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.syncSession.persistCurrentClientState().catch(() => undefined)
      })
    } catch (error) {
      await this.core.exclusive(async () =>
        this.syncSession.accountSecurityAborts.delete(lease.abort)
      )
      this.throwTwoFactorMutationError(error, lease)
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
      lease = await this.core.exclusive(async () => {
        const sync = this.syncSession.requireSyncData()
        const client = this.syncSession.getOrCreateSyncClient(sync)
        if (!client.getTwoFactorRecoveryCode) throw new VaultError('SYNC_FAILED')
        if (!client.exportState().session) throw new VaultError('SYNC_AUTH_REQUIRED')
        const abort = new AbortController()
        this.syncSession.accountSecurityAborts.add(abort)
        return {
          generation: this.core.generation,
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
      await this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        this.core.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.core.generation ||
          this.syncSession.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await copySensitiveText(code, 30)
        await this.syncSession.persistCurrentClientState().catch(() => undefined)
      })
    } catch (error) {
      return this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof BitwardenDirectError && error.code === 'USER_VERIFICATION_FAILED') {
          throw new VaultError('INVALID_MASTER_PASSWORD')
        }
        if (error instanceof VaultError) throw error
        throw this.syncSession.mapSyncError(error)
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
      lease = await this.core.exclusive(async () => {
        const sync = this.syncSession.requireSyncData()
        const client = this.syncSession.getOrCreateSyncClient(sync)
        if (!client.beginAuthenticatorSetup || !client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        const abort = new AbortController()
        this.syncSession.accountSecurityAborts.add(abort)
        return {
          generation: this.core.generation,
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
      return await this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        this.core.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.core.generation ||
          this.syncSession.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        if (setup.enabled || !/^[A-Z2-7]{32}$/.test(setup.key)) {
          throw new VaultError('INVALID_INPUT')
        }
        this.evictExpiredAuthenticatorSetupSessions()
        while (
          this.syncSession.authenticatorSetupSessions.size >= MAX_AUTHENTICATOR_SETUP_SESSIONS
        ) {
          const oldest = this.syncSession.authenticatorSetupSessions.keys().next().value
          if (typeof oldest !== 'string') break
          this.syncSession.deleteAuthenticatorSetupSession(oldest)
        }
        const sessionId = randomUUID()
        const expiresAt = this.core.now().getTime() + AUTHENTICATOR_SETUP_TTL_MS
        this.syncSession.authenticatorSetupSessions.set(sessionId, {
          generation: lease.generation,
          client: lease.client,
          key: setup.key,
          verificationMode: setup.verificationMode,
          userVerificationToken: setup.userVerificationToken ?? null,
          expiresAt
        })
        await this.syncSession.persistCurrentClientState().catch(() => undefined)
        return {
          sessionId,
          key: setup.key,
          requiresMasterPassword: setup.verificationMode === 'master-password',
          expiresAt
        }
      })
    } catch (error) {
      return this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof BitwardenDirectError && error.code === 'USER_VERIFICATION_FAILED') {
          throw new VaultError('INVALID_MASTER_PASSWORD')
        }
        if (error instanceof VaultError) throw error
        throw this.syncSession.mapSyncError(error)
      })
    } finally {
      request.masterPassword = ''
    }
  }

  async copyAccountAuthenticatorKey(request: { sessionId: string }): Promise<void> {
    const copySensitiveText = this.platform.copySensitiveText
    if (!copySensitiveText) throw new VaultError('INTERNAL_ERROR')
    await this.core.exclusive(async () => {
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
      lease = await this.core.exclusive(async () => {
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
        this.syncSession.accountSecurityAborts.add(abort)
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
        this.syncSession.authenticatorSetupSessions.delete(request.sessionId)
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
      await this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        this.core.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.core.generation ||
          this.syncSession.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.syncSession.persistCurrentClientState().catch(() => undefined)
      })
    } catch (error) {
      await this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
      })
      this.throwTwoFactorMutationError(error, lease)
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
      lease = await this.core.exclusive(async () => {
        const sync = this.syncSession.requireSyncData()
        const client = this.syncSession.getOrCreateSyncClient(sync)
        if (!client.beginEmailTwoFactorSetup || !client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        const abort = new AbortController()
        this.syncSession.accountSecurityAborts.add(abort)
        return {
          generation: this.core.generation,
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
      return await this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        this.core.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.core.generation ||
          this.syncSession.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        if (setup.enabled) throw new VaultError('INVALID_INPUT')
        this.evictExpiredEmailTwoFactorSetupSessions()
        while (
          this.syncSession.emailTwoFactorSetupSessions.size >= MAX_EMAIL_TWO_FACTOR_SETUP_SESSIONS
        ) {
          const oldest = this.syncSession.emailTwoFactorSetupSessions.keys().next().value
          if (typeof oldest !== 'string') break
          this.syncSession.deleteEmailTwoFactorSetupSession(oldest)
        }
        const sessionId = randomUUID()
        const expiresAt = this.core.now().getTime() + EMAIL_TWO_FACTOR_SETUP_TTL_MS
        this.syncSession.emailTwoFactorSetupSessions.set(sessionId, {
          generation: lease.generation,
          client: lease.client,
          verificationMode: setup.verificationMode,
          userVerificationToken: setup.userVerificationToken ?? null,
          phase: 'ready-to-send',
          email: null,
          expiresAt
        })
        await this.syncSession.persistCurrentClientState().catch(() => undefined)
        return {
          sessionId,
          requiresMasterPassword: setup.verificationMode === 'master-password',
          expiresAt
        }
      })
    } catch (error) {
      return this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof BitwardenDirectError && error.code === 'USER_VERIFICATION_FAILED') {
          throw new VaultError('INVALID_MASTER_PASSWORD')
        }
        if (error instanceof VaultError) throw error
        throw this.syncSession.mapSyncError(error)
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
      lease = await this.core.exclusive(async () => {
        const session = this.requireEmailTwoFactorSetupSession(request.sessionId, 'ready-to-send')
        if (!session.client.sendEmailTwoFactorSetup) throw new VaultError('SYNC_FAILED')
        this.validateEmailTwoFactorSetupPassword(session, request.masterPassword)
        const abort = new AbortController()
        this.syncSession.accountSecurityAborts.add(abort)
        const result = {
          ...session,
          request: session.client.sendEmailTwoFactorSetup.bind(session.client),
          abort,
          emailForSetup: request.email
        }
        this.syncSession.deleteEmailTwoFactorSetupSession(request.sessionId)
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
      await this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        this.core.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.core.generation ||
          this.syncSession.syncClient !== lease.client ||
          !lease.client.exportState().session ||
          lease.expiresAt <= this.core.now().getTime()
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        this.evictExpiredEmailTwoFactorSetupSessions()
        while (
          this.syncSession.emailTwoFactorSetupSessions.size >= MAX_EMAIL_TWO_FACTOR_SETUP_SESSIONS
        ) {
          const oldest = this.syncSession.emailTwoFactorSetupSessions.keys().next().value
          if (typeof oldest !== 'string') break
          this.syncSession.deleteEmailTwoFactorSetupSession(oldest)
        }
        this.syncSession.emailTwoFactorSetupSessions.set(request.sessionId, {
          generation: lease.generation,
          client: lease.client,
          verificationMode: lease.verificationMode,
          userVerificationToken: lease.userVerificationToken,
          phase: 'awaiting-code',
          email: lease.emailForSetup,
          expiresAt: lease.expiresAt
        })
        await this.syncSession.persistCurrentClientState().catch(() => undefined)
      })
    } catch (error) {
      await this.core.exclusive(async () =>
        this.syncSession.accountSecurityAborts.delete(lease.abort)
      )
      this.throwTwoFactorMutationError(error, lease)
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
      lease = await this.core.exclusive(async () => {
        const session = this.requireEmailTwoFactorSetupSession(request.sessionId, 'awaiting-code')
        if (!session.client.completeEmailTwoFactorSetup || !session.email) {
          throw new VaultError('SYNC_FAILED')
        }
        this.validateEmailTwoFactorSetupPassword(session, request.masterPassword)
        const abort = new AbortController()
        this.syncSession.accountSecurityAborts.add(abort)
        const result = {
          ...session,
          request: session.client.completeEmailTwoFactorSetup.bind(session.client),
          abort,
          emailForSetup: session.email
        }
        this.syncSession.deleteEmailTwoFactorSetupSession(request.sessionId)
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
      await this.core.exclusive(async () => {
        this.syncSession.accountSecurityAborts.delete(lease.abort)
        this.core.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.core.generation ||
          this.syncSession.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.syncSession.persistCurrentClientState().catch(() => undefined)
      })
    } catch (error) {
      await this.core.exclusive(async () =>
        this.syncSession.accountSecurityAborts.delete(lease.abort)
      )
      this.throwTwoFactorMutationError(error, lease)
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
      lease = await this.core.exclusive(async () => {
        const sync = this.syncSession.requireSyncData()
        const client = this.syncSession.getOrCreateSyncClient(sync)
        if (!client.beginWebAuthnSetup || !client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        const abort = new AbortController()
        this.syncSession.accountSecurityAborts.add(abort)
        return {
          generation: this.core.generation,
          client,
          abort,
          begin: client.beginWebAuthnSetup.bind(client)
        }
      })
      setup = await lease.begin(masterPassword, lease.abort.signal)
      masterPassword = ''
      const keys = setup.keys.map(({ id, name, migrated }) => ({ id, name, migrated }))
      await this.finishAccountWebAuthnOperation(lease)
      lease = null
      return keys
    } catch (error) {
      if (lease) {
        await this.releaseAccountWebAuthnOperation(lease)
        this.throwAccountWebAuthnOperationError(error, lease)
      }
      if (error instanceof VaultError) throw error
      throw this.syncSession.mapSyncError(error)
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
      lease = await this.core.exclusive(async () => {
        const sync = this.syncSession.requireSyncData()
        const client = this.syncSession.getOrCreateSyncClient(sync)
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
        this.syncSession.accountSecurityAborts.add(abort)
        return {
          generation: this.core.generation,
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
      await this.finishAccountWebAuthnOperation(lease)
      lease = null
    } catch (error) {
      if (lease) {
        await this.releaseAccountWebAuthnOperation(lease)
        this.throwAccountWebAuthnOperationError(error, lease)
      }
      if (error instanceof VaultError) throw error
      throw this.syncSession.mapSyncError(error)
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
      lease = await this.core.exclusive(async () => {
        const sync = this.syncSession.requireSyncData()
        const client = this.syncSession.getOrCreateSyncClient(sync)
        if (!client.deleteWebAuthnKey || !client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        const abort = new AbortController()
        this.syncSession.accountSecurityAborts.add(abort)
        return {
          generation: this.core.generation,
          client,
          abort,
          remove: client.deleteWebAuthnKey.bind(client)
        }
      })
      await lease.remove(id, masterPassword, lease.abort.signal)
      await this.finishAccountWebAuthnOperation(lease)
      lease = null
    } catch (error) {
      if (lease) {
        await this.releaseAccountWebAuthnOperation(lease)
        this.throwAccountWebAuthnOperationError(error, lease)
      }
      if (error instanceof VaultError) throw error
      throw this.syncSession.mapSyncError(error)
    } finally {
      request.masterPassword = ''
      id = 0
      masterPassword = ''
    }
  }

  /** Main-process-only notification credentials. Never expose this through IPC or renderer state. */
  async notificationConnectionInfo(): Promise<BitwardenNotificationConnectionInfo | null> {
    const lease = await this.core.exclusive(async () => {
      const sync = this.core.requireData().sync
      if (!sync) return null
      const client = this.syncSession.getOrCreateSyncClient(sync)
      const status = await client.status()
      if (status.status !== 'unlocked') return null
      const state = client.exportState()
      const notificationAccessToken = client.notificationAccessToken?.bind(client)
      if (!state.session || !state.profileId || !notificationAccessToken) return null
      const abort = new AbortController()
      this.syncSession.notificationTokenAborts.add(abort)
      return {
        client,
        notificationAccessToken,
        generation: this.core.generation,
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
      await this.core.exclusive(async () => {
        this.syncSession.notificationTokenAborts.delete(lease.abort)
      })
      if (lease.abort.signal.aborted) return null
      throw new Error('NOTIFICATION_TOKEN_UNAVAILABLE')
    }

    return this.core.exclusive(async () => {
      this.syncSession.notificationTokenAborts.delete(lease.abort)
      const current = this.core.requireData()
      if (
        lease.abort.signal.aborted ||
        lease.generation !== this.core.generation ||
        lease.client !== this.syncSession.syncClient ||
        this.syncSession.sessionDeauthorizationInProgress ||
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
        next.updatedAt = this.core.nowIso()
        await this.core.commit(next)
      }
      return {
        notificationsUrl: lease.notificationsUrl,
        accessToken,
        userId: lease.userId,
        deviceIdentifier: lease.deviceIdentifier
      }
    })
  }

  private assertAccountWebAuthnOperationCurrent(
    lease: AccountWebAuthnOperationLease
  ): Promise<void> {
    return this.core.exclusive(async () => {
      this.core.requireData()
      if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
        throw new VaultError('LOCKED')
      }
      if (this.syncSession.syncClient !== lease.client || !lease.client.exportState().session) {
        throw new VaultError('SYNC_AUTH_REQUIRED')
      }
    })
  }

  private finishAccountWebAuthnOperation(lease: AccountWebAuthnOperationLease): Promise<void> {
    return this.core.exclusive(async () => {
      this.core.requireData()
      if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
        throw new VaultError('LOCKED')
      }
      if (this.syncSession.syncClient !== lease.client || !lease.client.exportState().session) {
        throw new VaultError('SYNC_AUTH_REQUIRED')
      }
      await this.syncSession.persistCurrentClientState()
      if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
        throw new VaultError('LOCKED')
      }
      if (this.syncSession.syncClient !== lease.client || !lease.client.exportState().session) {
        throw new VaultError('SYNC_AUTH_REQUIRED')
      }
      this.syncSession.accountSecurityAborts.delete(lease.abort)
    })
  }

  private releaseAccountWebAuthnOperation(lease: AccountWebAuthnOperationLease): Promise<void> {
    return this.core.exclusive(async () => {
      this.syncSession.accountSecurityAborts.delete(lease.abort)
    })
  }

  private throwAccountWebAuthnOperationError(
    error: unknown,
    lease: AccountWebAuthnOperationLease
  ): never {
    if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
      throw new VaultError('LOCKED')
    }
    if (this.syncSession.syncClient !== lease.client || !lease.client.exportState().session) {
      throw new VaultError('SYNC_AUTH_REQUIRED')
    }
    if (error instanceof BitwardenDirectError) {
      if (error.code === 'USER_VERIFICATION_FAILED') {
        throw new VaultError('INVALID_MASTER_PASSWORD')
      }
      if (error.code === 'TWO_FACTOR_MUTATION_UNKNOWN') {
        throw new VaultError('TWO_FACTOR_MUTATION_UNKNOWN')
      }
      if (error.code === 'NOT_FOUND') throw new VaultError('NOT_FOUND')
    }
    if (error instanceof VaultError) throw error
    throw this.syncSession.mapSyncError(error)
  }

  private assertLoginApprovalLease(lease: {
    generation: number
    client: BitwardenSyncClient
    abort: AbortController
  }): void {
    if (
      lease.abort.signal.aborted ||
      lease.generation !== this.core.generation ||
      lease.client !== this.syncSession.syncClient ||
      !lease.client.exportState().session
    ) {
      throw new VaultError('SYNC_AUTH_REQUIRED')
    }
  }

  private issueLoginApproval(
    request: BitwardenLoginApprovalRequest,
    client: BitwardenSyncClient,
    generation: number
  ): LoginApprovalPrompt | null {
    const now = this.core.now().getTime()
    const expiresAt = Date.parse(request.createdAt) + LOGIN_APPROVAL_TTL_MS
    for (const [token, session] of this.syncSession.loginApprovalSessions) {
      if (
        session.expiresAt <= now ||
        session.generation !== this.core.generation ||
        session.client !== this.syncSession.syncClient
      ) {
        this.syncSession.loginApprovalSessions.delete(token)
        continue
      }
      if (
        session.requestId === request.id &&
        session.fingerprint === request.fingerprint &&
        session.client === client &&
        session.generation === generation
      ) {
        return {
          token,
          fingerprint: session.fingerprint,
          requestDeviceType: session.requestDeviceType,
          createdAt: session.createdAt,
          expiresAt: new Date(session.expiresAt).toISOString()
        }
      }
    }
    if (!Number.isFinite(expiresAt) || expiresAt <= now) return null
    while (this.syncSession.loginApprovalSessions.size >= MAX_LOGIN_APPROVAL_SESSIONS) {
      const oldest = this.syncSession.loginApprovalSessions.keys().next().value
      if (oldest === undefined) break
      this.syncSession.loginApprovalSessions.delete(oldest)
    }
    const token = randomUUID()
    this.syncSession.loginApprovalSessions.set(token, {
      generation,
      client,
      requestId: request.id,
      fingerprint: request.fingerprint,
      requestDeviceType: request.requestDeviceType,
      createdAt: request.createdAt,
      expiresAt
    })
    return {
      token,
      fingerprint: request.fingerprint,
      requestDeviceType: request.requestDeviceType,
      createdAt: request.createdAt,
      expiresAt: new Date(expiresAt).toISOString()
    }
  }

  private evictExpiredAuthenticatorSetupSessions(): void {
    const now = this.core.now().getTime()
    for (const [sessionId, session] of this.syncSession.authenticatorSetupSessions) {
      if (session.expiresAt <= now) this.syncSession.deleteAuthenticatorSetupSession(sessionId)
    }
  }

  private requireAuthenticatorSetupSession(sessionId: string): AuthenticatorSetupSession {
    this.evictExpiredAuthenticatorSetupSessions()
    const session = this.syncSession.authenticatorSetupSessions.get(sessionId)
    if (
      !session ||
      session.generation !== this.core.generation ||
      session.client !== this.syncSession.syncClient ||
      !session.client.exportState().session
    ) {
      if (session) this.syncSession.deleteAuthenticatorSetupSession(sessionId)
      throw new VaultError('INVALID_INPUT')
    }
    return session
  }

  private evictExpiredEmailTwoFactorSetupSessions(): void {
    const now = this.core.now().getTime()
    for (const [sessionId, session] of this.syncSession.emailTwoFactorSetupSessions) {
      if (session.expiresAt <= now) this.syncSession.deleteEmailTwoFactorSetupSession(sessionId)
    }
  }

  private requireEmailTwoFactorSetupSession(
    sessionId: string,
    phase: EmailTwoFactorSetupSession['phase']
  ): EmailTwoFactorSetupSession {
    this.evictExpiredEmailTwoFactorSetupSessions()
    const session = this.syncSession.emailTwoFactorSetupSessions.get(sessionId)
    if (!session) throw new VaultError('INVALID_INPUT')
    if (
      session.generation !== this.core.generation ||
      session.client !== this.syncSession.syncClient ||
      !session.client.exportState().session
    ) {
      this.syncSession.deleteEmailTwoFactorSetupSession(sessionId)
      throw new VaultError('INVALID_INPUT')
    }
    if (session.phase !== phase) throw new VaultError('INVALID_INPUT')
    return session
  }

  private validateEmailTwoFactorSetupPassword(
    session: EmailTwoFactorSetupSession,
    masterPassword: string | undefined
  ): void {
    if (session.verificationMode === 'server-token') {
      if (masterPassword !== undefined) throw new VaultError('INVALID_INPUT')
      return
    }
    if (
      typeof masterPassword !== 'string' ||
      masterPassword.length === 0 ||
      masterPassword.length > MAX_PASSWORD_LENGTH
    ) {
      throw new VaultError('INVALID_INPUT')
    }
  }

  private throwTwoFactorMutationError(
    error: unknown,
    lease: { abort: AbortController; generation: number }
  ): never {
    if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
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
    throw this.syncSession.mapSyncError(error)
  }
}
