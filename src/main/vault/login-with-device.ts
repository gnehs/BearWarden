import type { VaultCore } from './core'
import type { VaultSyncEngine } from './sync-engine'
import type { VaultSyncSession } from './sync-session'
import type {
  SyncLoginWithDeviceCompleteRequest,
  SyncLoginWithDeviceStart,
  SyncResult
} from '../../shared/vault-contract'
import { BitwardenDirectError, type BitwardenSyncClient } from '../bitwarden-direct'
import { resolveBitwardenUrls } from '../bitwarden-http'
import { DEVICE_LOGIN_VALIDITY_MS, type DeviceLoginRequest } from '../bitwarden-device-login'
import type {
  AuthRequestResponseNudge,
  AuthRequestResponseNudgeFactory
} from '../bitwarden-anonymous-hub'
import { SyncTwoFactorRequiredError, VaultError } from '../vault-errors'

const POLL_INTERVAL_MS = 4_000

/** One begin-to-outcome run, bound to the unlocked-vault epoch and connector it started on. */
interface Attempt {
  readonly abort: AbortController
  readonly generation: number
  readonly client: DeviceLoginClient
  readonly notificationsUrl: string
  canceledByUser: boolean
}

type DeviceLoginClient = BitwardenSyncClient &
  Required<
    Pick<
      BitwardenSyncClient,
      | 'requestDeviceLogin'
      | 'pollDeviceLogin'
      | 'loginWithDevice'
      | 'sendEmailTwoFactorDeviceLoginCode'
    >
  >

/**
 * `completing` means a completion call owns the request: it first waits for the approval that
 * `awaiting-approval` started polling for, then signs in. A two-step challenge after approval
 * parks the approved request in `awaiting-two-factor` for the next completion call. Done and
 * failed outcomes dispose the request and return to `idle`.
 */
type LoginWithDevicePhase =
  | { readonly kind: 'idle' }
  | { readonly kind: 'requesting'; readonly attempt: Attempt }
  | {
      readonly kind: 'awaiting-approval'
      readonly attempt: Attempt
      readonly request: DeviceLoginRequest
      readonly approval: Promise<void>
    }
  | {
      readonly kind: 'completing'
      readonly attempt: Attempt
      readonly request: DeviceLoginRequest
    }
  | {
      readonly kind: 'awaiting-two-factor'
      readonly attempt: Attempt
      readonly request: DeviceLoginRequest
    }

export interface VaultLoginWithDeviceOptions {
  nudges: AuthRequestResponseNudgeFactory
  now?: () => number
  pollIntervalMs?: number
}

function supportsDeviceLogin(client: BitwardenSyncClient): client is DeviceLoginClient {
  return (
    typeof client.requestDeviceLogin === 'function' &&
    typeof client.pollDeviceLogin === 'function' &&
    typeof client.loginWithDevice === 'function' &&
    typeof client.sendEmailTwoFactorDeviceLoginCode === 'function'
  )
}

/**
 * Re-authenticates the configured sync account through another device's approval instead of the
 * master password. Servers accept a request only from a device identifier already registered to
 * the account, so this runs on the persisted connector, never on a fresh first connection.
 */
export class VaultLoginWithDevice {
  private phase: LoginWithDevicePhase = { kind: 'idle' }
  private readonly now: () => number
  private readonly pollIntervalMs: number

  constructor(
    private readonly core: VaultCore,
    private readonly syncSession: VaultSyncSession,
    private readonly syncEngine: VaultSyncEngine,
    private readonly options: VaultLoginWithDeviceOptions
  ) {
    this.now = options.now ?? Date.now
    this.pollIntervalMs = options.pollIntervalMs ?? POLL_INTERVAL_MS
    // Lock, account switch, and app shutdown all abort registered session resources.
    core.registerResource({ abort: () => this.abortAttempt(false) })
  }

  get phaseKind(): LoginWithDevicePhase['kind'] {
    return this.phase.kind
  }

  begin(): Promise<SyncLoginWithDeviceStart> {
    this.abortAttempt(true)
    return this.core.exclusive(async () => {
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      if (!supportsDeviceLogin(client)) throw new VaultError('SYNC_LOGIN_WITH_DEVICE_UNSUPPORTED')
      const attempt: Attempt = {
        abort: new AbortController(),
        generation: this.core.generation,
        client,
        notificationsUrl: resolveBitwardenUrls(sync.serverUrl).notificationsUrl,
        canceledByUser: false
      }
      this.phase = { kind: 'requesting', attempt }
      let request: DeviceLoginRequest
      try {
        request = await client.requestDeviceLogin(attempt.abort.signal)
      } catch (error) {
        this.finish(attempt)
        throw this.outcomeError(error, attempt)
      }
      if (this.phase.kind !== 'requesting' || this.phase.attempt !== attempt) {
        request.dispose()
        throw this.outcomeError(new BitwardenDirectError('ABORTED'), attempt)
      }
      const approval = this.waitForApproval(attempt, request)
      // A completion call observes this promise; until then a rejection is not unhandled.
      approval.catch(() => undefined)
      this.phase = { kind: 'awaiting-approval', attempt, request, approval }
      return { fingerprint: request.fingerprint }
    })
  }

  async complete(input: SyncLoginWithDeviceCompleteRequest): Promise<SyncResult> {
    const phase = this.phase
    if (phase.kind !== 'awaiting-approval' && phase.kind !== 'awaiting-two-factor') {
      throw new VaultError('INVALID_INPUT')
    }
    const { attempt, request } = phase
    this.phase = { kind: 'completing', attempt, request }
    try {
      const twoFactor = this.syncSession.normalizeTwoFactor(
        input.twoFactorMethod,
        input.twoFactorCode
      )
      const interactive = this.syncSession.normalizeInteractiveTwoFactor(input, twoFactor)
      const newDeviceOtp = this.syncSession.normalizeNewDeviceOtp(input.newDeviceOtp)
      if (phase.kind === 'awaiting-approval') await phase.approval
      const result = await this.core.exclusive(async () => {
        if (
          attempt.abort.signal.aborted ||
          this.core.generation !== attempt.generation ||
          this.syncSession.syncClient !== attempt.client
        ) {
          throw new BitwardenDirectError('ABORTED')
        }
        const sync = this.syncSession.requireSyncData()
        const operation = this.syncSession.startSyncOperation()
        const abortOperation = (): void => operation.abort()
        attempt.abort.signal.addEventListener('abort', abortOperation)
        try {
          await this.syncSession.authenticateSyncWithInteractiveTwoFactor(
            (retryTwoFactor) =>
              attempt.client.loginWithDevice({
                request,
                twoFactor: retryTwoFactor,
                newDeviceOtp,
                signal: operation.signal
              }),
            twoFactor,
            interactive,
            sync.serverUrl,
            operation.signal
          )
          await this.syncSession.persistCurrentClientState()
          return await this.syncEngine.performSync(
            this.core.requireData(),
            attempt.client,
            operation.signal
          )
        } catch (error) {
          await this.syncSession.persistCurrentClientState().catch(() => undefined)
          throw this.syncSession.mapSyncError(error)
        } finally {
          attempt.abort.signal.removeEventListener('abort', abortOperation)
          this.syncSession.finishSyncOperation(operation)
        }
      })
      this.finish(attempt)
      return result
    } catch (error) {
      if (
        error instanceof SyncTwoFactorRequiredError &&
        this.phase.kind === 'completing' &&
        this.phase.attempt === attempt &&
        !attempt.abort.signal.aborted
      ) {
        this.phase = { kind: 'awaiting-two-factor', attempt, request }
        throw error
      }
      if (
        error instanceof VaultError &&
        error.code === 'INVALID_INPUT' &&
        this.phase.kind === 'completing' &&
        this.phase.attempt === attempt
      ) {
        // Malformed two-step input leaves the request usable for a corrected retry.
        this.phase = phase
        throw error
      }
      this.finish(attempt)
      throw this.outcomeError(error, attempt)
    }
  }

  /** Sends the Email two-step code for an approved request, proven by its access code. */
  async sendEmailCode(): Promise<void> {
    const phase = this.phase
    if (phase.kind !== 'awaiting-two-factor') throw new VaultError('INVALID_INPUT')
    try {
      await phase.attempt.client.sendEmailTwoFactorDeviceLoginCode(
        phase.request,
        phase.attempt.abort.signal
      )
    } catch (error) {
      throw this.outcomeError(error, phase.attempt)
    }
  }

  cancel(): void {
    this.abortAttempt(true)
  }

  private abortAttempt(canceledByUser: boolean): void {
    const phase = this.phase
    if (phase.kind === 'idle') return
    phase.attempt.canceledByUser = canceledByUser
    phase.attempt.abort.abort()
    // A completion call in flight disposes its own request when its abort lands.
    if (phase.kind !== 'completing') this.finish(phase.attempt)
  }

  private finish(attempt: Attempt): void {
    const phase = this.phase
    if (phase.kind === 'idle' || phase.attempt !== attempt) return
    if (phase.kind !== 'requesting') phase.request.dispose()
    this.phase = { kind: 'idle' }
  }

  private outcomeError(error: unknown, attempt: Attempt): VaultError {
    if (attempt.abort.signal.aborted) {
      return new VaultError(attempt.canceledByUser ? 'SYNC_LOGIN_WITH_DEVICE_CANCELED' : 'LOCKED')
    }
    return this.syncSession.mapSyncError(error)
  }

  /** Polls until approval, denial, or the server's request lifetime runs out. */
  private async waitForApproval(attempt: Attempt, request: DeviceLoginRequest): Promise<void> {
    const signal = attempt.abort.signal
    const deadline = request.createdAt + DEVICE_LOGIN_VALIDITY_MS
    let nudge: AuthRequestResponseNudge | null = null
    try {
      nudge = this.options.nudges(attempt.notificationsUrl, request.id)
    } catch {
      // The poll alone is sufficient.
    }
    try {
      for (;;) {
        if (signal.aborted) throw new BitwardenDirectError('ABORTED')
        try {
          if (await attempt.client.pollDeviceLogin(request, signal)) return
        } catch (error) {
          // A dropped connection is retried until the deadline; every other answer is final.
          if (!(error instanceof BitwardenDirectError) || error.code !== 'NETWORK') throw error
        }
        const remaining = deadline - this.now()
        if (remaining <= 0) throw new BitwardenDirectError('DEVICE_LOGIN_EXPIRED')
        await this.pause(Math.min(this.pollIntervalMs, remaining), signal, nudge)
      }
    } finally {
      nudge?.close()
    }
  }

  private pause(
    delayMs: number,
    signal: AbortSignal,
    nudge: AuthRequestResponseNudge | null
  ): Promise<void> {
    return new Promise<void>((resolve) => {
      const done = (): void => {
        clearTimeout(timer)
        signal.removeEventListener('abort', done)
        resolve()
      }
      const timer = setTimeout(done, delayMs)
      signal.addEventListener('abort', done, { once: true })
      void nudge?.next().then(done)
    })
  }
}
