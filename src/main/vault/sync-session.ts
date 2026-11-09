import type {
  SyncConnectRequest,
  SyncErrorCode,
  SyncInvalidResponseReason,
  SyncInvalidResponseStage,
  SyncStatus,
  SyncTwoFactorProvider
} from '../../shared/vault-contract'
import {
  BitwardenDirectError,
  type BitwardenLoginTwoFactor,
  type BitwardenSyncClient,
  type BitwardenTwoFactor
} from '../bitwarden-direct'
import { resolveBitwardenUrls } from '../bitwarden-http'
import { SyncTwoFactorRequiredError, VaultError } from '../vault-errors'
import type { AccountWebAuthnAssertion } from '../account-webauthn-codec'
import { MAX_URI_LENGTH, MAX_TWO_FACTOR_CODE_LENGTH } from './limits'
import { assertUuid } from './parse-primitives'
import { cloneData } from './vault-data-parsing'
import type { PinSyncKeyMaterial } from '../pin-unlock'
import type { VaultCore } from './core'
import type { PersistedSyncData, VaultAccountWebAuthnAssertionRequester } from './types'

export interface AuthenticatorSetupSession {
  readonly generation: number
  readonly client: BitwardenSyncClient
  key: string
  readonly verificationMode: 'server-token' | 'master-password'
  userVerificationToken: string | null
  readonly expiresAt: number
}

export interface EmailTwoFactorSetupSession {
  readonly generation: number
  readonly client: BitwardenSyncClient
  readonly verificationMode: 'server-token' | 'master-password'
  userVerificationToken: string | null
  phase: 'ready-to-send' | 'awaiting-code'
  email: string | null
  readonly expiresAt: number
}

export interface LoginApprovalSession {
  readonly generation: number
  readonly client: BitwardenSyncClient
  readonly requestId: string
  readonly fingerprint: string
  readonly requestDeviceType: string
  readonly createdAt: string
  readonly expiresAt: number
}

export interface AttachmentOperation {
  readonly operationId: string
  readonly abort: AbortController
  canceledByUser: boolean
  committed: boolean
}

/**
 * Owns the Bitwarden account session: the connector, the single sync-operation lease, the last
 * sync error, and the account-scoped background leases that end with the session.
 */
export class VaultSyncSession {
  private connector: BitwardenSyncClient | null = null
  private operationAbort: AbortController | null = null
  private operationInProgress = false
  private deauthorizationInProgress = false
  private attachmentOperation: AttachmentOperation | null = null
  private syncLastError: SyncErrorCode | null = null
  private syncLastErrorAt: string | null = null
  private syncLastErrorDetail: SyncInvalidResponseStage | null = null
  private syncLastErrorReason: SyncInvalidResponseReason | null = null
  readonly notificationTokenAborts = new Set<AbortController>()
  readonly accountSecurityAborts = new Set<AbortController>()
  readonly nativeAttachmentBackupAborts = new Set<AbortController>()
  readonly nativeAttachmentRestoreAborts = new Set<AbortController>()
  readonly authenticatorSetupSessions = new Map<string, AuthenticatorSetupSession>()
  readonly emailTwoFactorSetupSessions = new Map<string, EmailTwoFactorSetupSession>()
  readonly loginApprovalSessions = new Map<string, LoginApprovalSession>()

  constructor(
    private readonly core: VaultCore,
    private readonly createSyncClient: (sync: PersistedSyncData) => BitwardenSyncClient,
    private readonly requestAccountWebAuthnAssertion: VaultAccountWebAuthnAssertionRequester | null
  ) {
    core.registerResource({
      abort: () => {
        this.operationAbort?.abort()
        this.abortNotificationTokenLeases()
        this.abortAccountSecurityRequests()
        this.abortNativeAttachmentBackups()
        this.abortNativeAttachmentRestores()
      },
      clear: () => {
        this.operationAbort = null
        this.attachmentOperation = null
        this.operationInProgress = false
        this.deauthorizationInProgress = false
      },
      discard: () => {
        this.connector = null
      }
    })
  }

  get syncClient(): BitwardenSyncClient | null {
    return this.connector
  }

  get syncInProgress(): boolean {
    return this.operationInProgress
  }

  get sessionDeauthorizationInProgress(): boolean {
    return this.deauthorizationInProgress
  }

  get activeAttachmentOperation(): AttachmentOperation | null {
    return this.attachmentOperation
  }

  /** Builds a connector that is not installed as the session connector. */
  createDetachedClient(sync: PersistedSyncData): BitwardenSyncClient {
    return this.createSyncClient(sync)
  }

  setSyncClient(client: BitwardenSyncClient): void {
    this.connector = client
  }

  /** Drops the session connector and returns it so the caller can log it out. */
  dropSyncClient(): BitwardenSyncClient | null {
    const client = this.connector
    this.connector = null
    return client
  }

  /** Starts the connector after a key-material unlock, restoring the account key it carries. */
  restoreSyncClient(sync: PersistedSyncData, material: PinSyncKeyMaterial): void {
    this.connector ??= this.createSyncClient(sync)
    this.connector.restorePinUnlockMaterial?.(material)
  }

  abortSyncOperation(): void {
    this.operationAbort?.abort()
  }

  /** Blocks every new sync operation and connector use until `endSessionDeauthorization`. */
  beginSessionDeauthorization(): void {
    this.deauthorizationInProgress = true
  }

  endSessionDeauthorization(): void {
    this.deauthorizationInProgress = false
  }

  getOrCreateSyncClient(sync: PersistedSyncData): BitwardenSyncClient {
    if (this.deauthorizationInProgress) throw new VaultError('SYNC_FAILED')
    if (!this.connector) {
      const client = this.createSyncClient(sync)
      const stored = sync.unlockMaterial
      if (stored && client.restorePinUnlockMaterial) {
        const accountKey = Buffer.from(stored.accountKey, 'base64')
        const wrappedKeyFingerprint = Buffer.from(stored.wrappedKeyFingerprint, 'base64')
        try {
          client.restorePinUnlockMaterial({ accountKey, wrappedKeyFingerprint })
        } finally {
          accountKey.fill(0)
          wrappedKeyFingerprint.fill(0)
        }
      }
      this.connector = client
    }
    return this.connector
  }

  requireSyncData(): PersistedSyncData {
    const sync = this.core.requireData().sync
    if (!sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    return sync
  }

  startSyncOperation(): AbortController {
    if (this.operationInProgress || this.deauthorizationInProgress) {
      throw new VaultError('SYNC_FAILED')
    }
    this.abortAccountSecurityRequests()
    const abort = new AbortController()
    this.operationAbort = abort
    this.operationInProgress = true
    this.clearSyncErrorState()
    return abort
  }

  finishSyncOperation(abort: AbortController): void {
    if (this.operationAbort === abort) this.operationAbort = null
    this.operationInProgress = false
  }

  startAttachmentOperation(operationId: string): {
    operationId: string
    abort: AbortController
    canceledByUser: boolean
    committed: boolean
  } {
    assertUuid(operationId)
    if (this.attachmentOperation) throw new VaultError('SYNC_FAILED')
    const operation = {
      operationId,
      abort: this.startSyncOperation(),
      canceledByUser: false,
      committed: false
    }
    this.attachmentOperation = operation
    return operation
  }

  finishAttachmentOperation(operation: { operationId: string; abort: AbortController }): void {
    if (this.attachmentOperation?.operationId === operation.operationId) {
      this.attachmentOperation = null
    }
    this.finishSyncOperation(operation.abort)
  }

  commitAttachmentOperation(operation: { operationId: string; committed: boolean }): void {
    if (this.attachmentOperation?.operationId === operation.operationId) {
      operation.committed = true
    }
  }

  abortNotificationTokenLeases(): void {
    for (const abort of this.notificationTokenAborts) abort.abort()
    this.notificationTokenAborts.clear()
  }

  abortAccountSecurityRequests(): void {
    for (const abort of this.accountSecurityAborts) abort.abort()
    this.accountSecurityAborts.clear()
    this.loginApprovalSessions.clear()
    for (const sessionId of this.authenticatorSetupSessions.keys()) {
      this.deleteAuthenticatorSetupSession(sessionId)
    }
    for (const sessionId of this.emailTwoFactorSetupSessions.keys()) {
      this.deleteEmailTwoFactorSetupSession(sessionId)
    }
  }

  deleteAuthenticatorSetupSession(sessionId: string): void {
    const session = this.authenticatorSetupSessions.get(sessionId)
    if (!session) return
    session.key = ''
    session.userVerificationToken = null
    this.authenticatorSetupSessions.delete(sessionId)
  }

  deleteEmailTwoFactorSetupSession(sessionId: string): void {
    const session = this.emailTwoFactorSetupSessions.get(sessionId)
    if (!session) return
    session.userVerificationToken = null
    session.email = null
    this.emailTwoFactorSetupSessions.delete(sessionId)
  }

  abortNativeAttachmentBackups(): void {
    for (const abort of this.nativeAttachmentBackupAborts) abort.abort()
    this.nativeAttachmentBackupAborts.clear()
  }

  abortNativeAttachmentRestores(): void {
    for (const abort of this.nativeAttachmentRestoreAborts) abort.abort()
    this.nativeAttachmentRestoreAborts.clear()
  }

  mapSyncError(error: unknown): VaultError {
    if (error instanceof VaultError) {
      if (
        error.code === 'SYNC_AUTH_REQUIRED' ||
        error.code === 'SYNC_NEW_DEVICE_REQUIRED' ||
        error.code === 'SYNC_SSO_REQUIRED' ||
        error.code === 'SYNC_DUO_UNSUPPORTED' ||
        error.code === 'SYNC_KEY_CONNECTOR_UNSUPPORTED' ||
        error.code === 'SYNC_TRUSTED_DEVICE_UNSUPPORTED' ||
        error.code === 'SYNC_UNSUPPORTED_ACCOUNT' ||
        error.code === 'SYNC_NETWORK' ||
        error.code === 'SYNC_INVALID_RESPONSE' ||
        error.code === 'SYNC_INVALID_SSH_KEY' ||
        error.code === 'SYNC_CONFLICT' ||
        error.code === 'SYNC_FAILED'
      ) {
        this.recordSyncError(error.code)
      }
      return error
    }
    if (error instanceof BitwardenDirectError) {
      const directCode: string = error.code
      if (directCode === 'SSO_REQUIRED') {
        this.recordSyncError('SYNC_SSO_REQUIRED')
        return new VaultError('SYNC_SSO_REQUIRED')
      }
      if (directCode === 'KEY_CONNECTOR_UNSUPPORTED') {
        this.recordSyncError('SYNC_KEY_CONNECTOR_UNSUPPORTED')
        return new VaultError('SYNC_KEY_CONNECTOR_UNSUPPORTED')
      }
      if (directCode === 'TRUSTED_DEVICE_UNSUPPORTED') {
        this.recordSyncError('SYNC_TRUSTED_DEVICE_UNSUPPORTED')
        return new VaultError('SYNC_TRUSTED_DEVICE_UNSUPPORTED')
      }
      if (error.code === 'AUTH_REQUIRED') {
        this.recordSyncError('SYNC_AUTH_REQUIRED')
        return new VaultError('SYNC_AUTH_REQUIRED')
      }
      if (error.code === 'TWO_FACTOR_REQUIRED') {
        const rawProviders = error.twoFactorProviders ?? []
        if (
          rawProviders.length > 0 &&
          rawProviders.every((provider) => provider === 2 || provider === 6)
        ) {
          this.recordSyncError('SYNC_DUO_UNSUPPORTED')
          return new VaultError('SYNC_DUO_UNSUPPORTED')
        }
        this.recordSyncError('SYNC_AUTH_REQUIRED')
        const providers = rawProviders.flatMap((provider) =>
          Number.isInteger(provider) && provider >= 0 && provider <= 8
            ? [String(provider) as SyncTwoFactorProvider]
            : []
        )
        return new SyncTwoFactorRequiredError(providers)
      }
      if (error.code === 'NEW_DEVICE_REQUIRED') {
        this.recordSyncError('SYNC_NEW_DEVICE_REQUIRED')
        return new VaultError('SYNC_NEW_DEVICE_REQUIRED')
      }
      if (error.code === 'NETWORK') {
        this.recordSyncError('SYNC_NETWORK')
        return new VaultError('SYNC_NETWORK')
      }
      if (error.code === 'INVALID_RESPONSE') {
        this.recordSyncError(
          'SYNC_INVALID_RESPONSE',
          error.syncInvalidResponseStage,
          error.syncInvalidResponseReason
        )
        return new VaultError('SYNC_INVALID_RESPONSE')
      }
      if (error.code === 'INVALID_SSH_KEY') {
        this.recordSyncError('SYNC_INVALID_SSH_KEY')
        return new VaultError('SYNC_INVALID_SSH_KEY')
      }
      if (error.code === 'CONFLICT') {
        this.recordSyncError('SYNC_CONFLICT')
        return new VaultError('SYNC_CONFLICT')
      }
      if (error.code === 'ABORTED') return new VaultError('LOCKED')
      if (error.code === 'UNSUPPORTED_ACCOUNT_ENCRYPTION') {
        this.recordSyncError('SYNC_UNSUPPORTED_ACCOUNT')
        return new VaultError('SYNC_UNSUPPORTED_ACCOUNT')
      }
    }
    this.recordSyncError('SYNC_FAILED')
    return new VaultError('SYNC_FAILED')
  }

  private recordSyncError(
    code: SyncErrorCode,
    detail?: SyncInvalidResponseStage,
    reason?: SyncInvalidResponseReason
  ): void {
    this.syncLastError = code
    this.syncLastErrorAt = this.core.nowIso()
    this.syncLastErrorDetail = code === 'SYNC_INVALID_RESPONSE' ? (detail ?? null) : null
    this.syncLastErrorReason = code === 'SYNC_INVALID_RESPONSE' ? (reason ?? null) : null
  }

  clearSyncErrorState(): void {
    this.syncLastError = null
    this.syncLastErrorAt = null
    this.syncLastErrorDetail = null
    this.syncLastErrorReason = null
  }

  async currentSyncStatus(): Promise<SyncStatus> {
    const data = this.core.requireData()
    if (!data.sync) {
      return this.syncLastError
        ? { configured: false, state: 'error', ...this.syncErrorStatusFields() }
        : { configured: false, state: 'unconfigured' }
    }
    if (this.operationInProgress) return this.baseSyncStatus(data.sync, 'syncing')
    if (this.syncLastError) return this.baseSyncStatus(data.sync, 'error')
    try {
      const client = this.getOrCreateSyncClient(data.sync)
      const status = await client.status()
      return this.baseSyncStatus(data.sync, status.status === 'unlocked' ? 'ready' : 'locked')
    } catch {
      this.recordSyncError('SYNC_FAILED')
      return this.baseSyncStatus(data.sync, 'error')
    }
  }

  baseSyncStatus(sync: PersistedSyncData, state: SyncStatus['state']): SyncStatus {
    return {
      configured: true,
      state,
      serverUrl: sync.serverUrl,
      email: sync.email,
      ...(sync.lastSyncAt ? { lastSyncAt: sync.lastSyncAt } : {}),
      ...this.syncErrorStatusFields(),
      ...(sync.pendingLoginImport?.phase === 'dispatched'
        ? {
            pendingImport: {
              count: sync.pendingLoginImport.entries.length,
              startedAt: sync.pendingLoginImport.startedAt
            }
          }
        : {}),
      ...(sync.pendingPersonalVaultPurge?.phase === 'dispatched'
        ? {
            pendingPurge: {
              remainingItems: sync.pendingPersonalVaultPurge.remainingItems,
              remainingFolders: sync.pendingPersonalVaultPurge.remainingFolders,
              startedAt: sync.pendingPersonalVaultPurge.startedAt
            }
          }
        : {})
    }
  }

  private syncErrorStatusFields(): Partial<SyncStatus> {
    return {
      ...(this.syncLastError ? { lastError: this.syncLastError } : {}),
      ...(this.syncLastError && this.syncLastErrorAt ? { lastErrorAt: this.syncLastErrorAt } : {}),
      ...(this.syncLastError === 'SYNC_INVALID_RESPONSE' && this.syncLastErrorDetail
        ? { lastErrorDetail: this.syncLastErrorDetail }
        : {}),
      ...(this.syncLastError === 'SYNC_INVALID_RESPONSE' && this.syncLastErrorReason
        ? { lastErrorReason: this.syncLastErrorReason }
        : {})
    }
  }

  async persistCurrentClientState(): Promise<void> {
    const client = this.connector
    const current = this.core.requireData()
    if (!client || !current.sync) return
    const state = client.exportState()
    const material = client.pinUnlockMaterial?.() ?? null
    const unlockMaterial = material
      ? {
          accountKey: material.accountKey.toString('base64'),
          wrappedKeyFingerprint: material.wrappedKeyFingerprint.toString('base64')
        }
      : null
    material?.accountKey.fill(0)
    material?.wrappedKeyFingerprint.fill(0)
    if (
      JSON.stringify(state) === JSON.stringify(current.sync.state) &&
      JSON.stringify(unlockMaterial) === JSON.stringify(current.sync.unlockMaterial)
    ) {
      return
    }
    const next = cloneData(current)
    if (!next.sync) return
    next.sync.state = state
    next.sync.unlockMaterial = unlockMaterial
    next.updatedAt = this.core.nowIso()
    await this.core.commit(next)
  }

  normalizeSyncServerUrl(value: unknown): string {
    if (typeof value !== 'string' || value.length === 0 || value.length > MAX_URI_LENGTH) {
      throw new VaultError('INVALID_URL')
    }
    try {
      const normalized = value.trim()
      resolveBitwardenUrls(normalized)
      return normalized.replace(/\/$/, '')
    } catch {
      throw new VaultError('INVALID_URL')
    }
  }

  normalizeTwoFactor(
    method: SyncConnectRequest['twoFactorMethod'],
    code: string | undefined
  ): BitwardenTwoFactor | undefined {
    if (method === undefined && code === undefined) return undefined
    if (
      method === undefined ||
      code === undefined ||
      code.length === 0 ||
      code.length > MAX_TWO_FACTOR_CODE_LENGTH
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    return { method: Number(method) as BitwardenTwoFactor['method'], code }
  }

  normalizeNewDeviceOtp(value: string | undefined): string | undefined {
    if (value === undefined) return undefined
    const normalized = value.trim()
    if (normalized.length === 0 || normalized.length > MAX_TWO_FACTOR_CODE_LENGTH) {
      throw new VaultError('INVALID_INPUT')
    }
    return normalized
  }

  async authenticateSyncWithWebAuthnRetry(
    authenticate: (twoFactor: BitwardenLoginTwoFactor | undefined) => Promise<void>,
    initialTwoFactor: BitwardenTwoFactor | undefined,
    webAuthnRemember: unknown,
    serverUrl: string,
    signal: AbortSignal
  ): Promise<void> {
    try {
      await authenticate(initialTwoFactor)
    } catch (error) {
      if (signal.aborted) throw new BitwardenDirectError('ABORTED')
      if (
        !(error instanceof BitwardenDirectError) ||
        error.code !== 'TWO_FACTOR_REQUIRED' ||
        error.webAuthnChallenge === undefined ||
        initialTwoFactor !== undefined ||
        typeof webAuthnRemember !== 'boolean' ||
        this.requestAccountWebAuthnAssertion === null
      ) {
        throw error
      }

      let assertion: AccountWebAuthnAssertion
      try {
        assertion = await this.requestAccountWebAuthnAssertion(
          Object.freeze({
            webVaultUrl: resolveBitwardenUrls(serverUrl).webVaultUrl,
            challenge: error.webAuthnChallenge,
            remember: webAuthnRemember,
            signal
          })
        )
      } catch {
        // Connector cancellation, timeout, and remote details collapse to stable public errors.
        throw new BitwardenDirectError(signal.aborted ? 'ABORTED' : 'INVALID_RESPONSE')
      }
      if (signal.aborted) throw new BitwardenDirectError('ABORTED')

      // This is the only retry. A second provider-7 challenge propagates to the normal mapper.
      await authenticate({ method: 7, assertion, remember: webAuthnRemember })
    }
  }
}
