import type { SyncResult, SyncStatus } from '../shared/vault-contract'

const DEFAULT_AUTO_SYNC_DELAY_MS = 10 * 60 * 1_000
const DEFAULT_SAFETY_MIN_DELAY_MS = 10 * 60 * 1_000
const DEFAULT_SAFETY_MAX_DELAY_MS = 10 * 60 * 1_000
const DEFAULT_RETRY_BASE_DELAY_MS = 10 * 60 * 1_000
const DEFAULT_RETRY_MAX_DELAY_MS = 10 * 60 * 1_000

type Timer = ReturnType<typeof setTimeout>
type TimerKind = 'request' | 'safety' | 'retry'

export interface AutoSyncVault {
  syncStatus: () => Promise<SyncStatus>
  syncNow: () => Promise<SyncResult>
}

export interface AutoSyncCoordinatorOptions {
  vault: AutoSyncVault
  onSyncChanged: (status: SyncStatus) => void
  onVaultChanged: () => void
  delayMs?: number
  safetyMinDelayMs?: number
  safetyMaxDelayMs?: number
  retryBaseDelayMs?: number
  retryMaxDelayMs?: number
  random?: () => number
  setTimeout?: (callback: () => void, delayMs: number) => Timer
  clearTimeout?: (timer: Timer) => void
}

export class AutoSyncCoordinator {
  private timer: Timer | null = null
  private timerKind: TimerKind | null = null
  private requested = false
  private requestIsImmediate = false
  private running = false
  private disposed = false
  private eligibleForFallback = false
  private consecutiveFailures = 0
  private epoch = 0
  private readonly delayMs: number
  private readonly safetyMinDelayMs: number
  private readonly safetyMaxDelayMs: number
  private readonly retryBaseDelayMs: number
  private readonly retryMaxDelayMs: number
  private readonly random: () => number
  private readonly scheduleTimeout: (callback: () => void, delayMs: number) => Timer
  private readonly cancelTimeout: (timer: Timer) => void

  constructor(private readonly options: AutoSyncCoordinatorOptions) {
    this.delayMs = this.validDelay(options.delayMs, DEFAULT_AUTO_SYNC_DELAY_MS)
    this.safetyMinDelayMs = this.validDelay(options.safetyMinDelayMs, DEFAULT_SAFETY_MIN_DELAY_MS)
    this.safetyMaxDelayMs = Math.max(
      this.safetyMinDelayMs,
      this.validDelay(options.safetyMaxDelayMs, DEFAULT_SAFETY_MAX_DELAY_MS)
    )
    this.retryBaseDelayMs = this.validDelay(options.retryBaseDelayMs, DEFAULT_RETRY_BASE_DELAY_MS)
    this.retryMaxDelayMs = Math.max(
      this.retryBaseDelayMs,
      this.validDelay(options.retryMaxDelayMs, DEFAULT_RETRY_MAX_DELAY_MS)
    )
    this.random = options.random ?? Math.random
    this.scheduleTimeout = options.setTimeout ?? setTimeout
    this.cancelTimeout = options.clearTimeout ?? clearTimeout
  }

  /** Coalesces background invalidations into the periodic ten-minute cadence. */
  request(): void {
    this.queueRequest(false)
  }

  /** Foreground, resume, and unlock boundaries should not wait for the debounce window. */
  requestImmediate(): void {
    this.queueRequest(true)
  }

  /** Keeps the fallback timer aligned with externally initiated manual sync and lock state. */
  updateStatus(status: SyncStatus): void {
    if (this.disposed) return

    if (status.state === 'ready' || status.state === 'error') {
      this.eligibleForFallback = true
      // Manual/external completion establishes a new polling epoch. Never retain an almost-due
      // fallback timer that was calculated from state preceding that completion.
      if (this.timerKind === 'safety' || this.timerKind === 'retry') this.clearTimer()
      if (status.state === 'ready') this.consecutiveFailures = 0
      else if (!this.running) this.recordFailure()
      if (!this.running && !this.requested) this.scheduleFallback()
      return
    }

    this.eligibleForFallback = false
    if (status.state === 'syncing') {
      if (this.timerKind === 'safety' || this.timerKind === 'retry') this.clearTimer()
      return
    }

    // Locked and disconnected vaults must not retain any request that could replay after unlock.
    this.cancel()
  }

  cancel(): void {
    this.epoch += 1
    this.requested = false
    this.requestIsImmediate = false
    this.eligibleForFallback = false
    this.consecutiveFailures = 0
    this.clearTimer()
  }

  dispose(): void {
    this.disposed = true
    this.cancel()
  }

  private queueRequest(immediate: boolean): void {
    if (this.disposed) return

    // A remote invalidation must not restart or accelerate an already scheduled background poll.
    // Local mutations use requestImmediate() and intentionally preempt this timer.
    if (!immediate && (this.timerKind === 'safety' || this.timerKind === 'retry')) return

    this.requested = true
    this.requestIsImmediate ||= immediate

    if (this.running) return
    if (this.timerKind === 'request' && !this.requestIsImmediate) return

    this.clearTimer()
    this.scheduleRequest()
  }

  private scheduleRequest(): void {
    if (this.disposed || this.running || this.timer || !this.requested) return
    const delay = this.requestIsImmediate ? 0 : this.delayMs
    this.setTimer('request', delay)
  }

  private scheduleFallback(): void {
    if (
      this.disposed ||
      this.running ||
      this.timer ||
      this.requested ||
      !this.eligibleForFallback
    ) {
      return
    }

    if (this.consecutiveFailures > 0) {
      const exponential = Math.min(
        this.retryMaxDelayMs,
        this.retryBaseDelayMs * 2 ** Math.min(this.consecutiveFailures - 1, 30)
      )
      // Equal jitter avoids synchronized retry storms without allowing a zero-delay retry loop.
      this.setTimer('retry', Math.floor(exponential * (0.5 + 0.5 * this.normalizedRandom())))
      return
    }

    const spread = Math.max(0, this.safetyMaxDelayMs - this.safetyMinDelayMs)
    this.setTimer('safety', this.safetyMinDelayMs + Math.floor(spread * this.normalizedRandom()))
  }

  private setTimer(kind: TimerKind, delayMs: number): void {
    const scheduledEpoch = this.epoch
    this.timerKind = kind
    this.timer = this.scheduleTimeout(
      () => {
        if (this.disposed || scheduledEpoch !== this.epoch) return
        this.timer = null
        this.timerKind = null
        this.requested = true
        this.requestIsImmediate = true
        void this.run(scheduledEpoch)
      },
      Math.max(0, delayMs)
    )
    this.timer.unref?.()
  }

  private clearTimer(): void {
    if (this.timer) this.cancelTimeout(this.timer)
    this.timer = null
    this.timerKind = null
  }

  private async run(runEpoch: number): Promise<void> {
    if (this.disposed || runEpoch !== this.epoch || this.running || !this.requested) return
    this.requested = false
    this.requestIsImmediate = false
    this.running = true

    try {
      const status = await this.options.vault.syncStatus()
      if (this.disposed || runEpoch !== this.epoch) return

      if (status.state === 'syncing') {
        // A manual sync may be in progress while an invalidation arrives. Preserve the request,
        // but never overlap syncNow calls.
        this.requested = true
        this.notifySyncChanged(status)
        return
      }
      if (status.state !== 'ready' && status.state !== 'error') {
        this.eligibleForFallback = false
        this.notifySyncChanged(status)
        return
      }

      this.eligibleForFallback = true
      const syncingStatus: SyncStatus = { ...status, state: 'syncing' }
      delete syncingStatus.lastError
      delete syncingStatus.lastErrorAt
      delete syncingStatus.lastErrorDetail
      this.notifySyncChanged(syncingStatus)
      const result = await this.options.vault.syncNow()
      if (this.disposed || runEpoch !== this.epoch) return
      this.notifySyncChanged(result)
      this.notifyVaultChanged()

      if (result.state === 'error') this.recordFailure()
      else this.consecutiveFailures = 0
    } catch {
      this.recordFailure()
      try {
        const status = await this.options.vault.syncStatus()
        if (this.disposed || runEpoch !== this.epoch) return
        this.eligibleForFallback = status.state === 'ready' || status.state === 'error'
        this.notifySyncChanged(status)
      } catch {
        // Automatic sync is best-effort and must never reject a successful local change.
      }
    } finally {
      this.running = false
      if (!this.disposed) {
        if (runEpoch !== this.epoch) {
          // A new lifecycle epoch may have queued work while the cancelled run was settling.
          if (this.requested) this.scheduleRequest()
          else this.scheduleFallback()
        } else if (this.requested) this.scheduleRequest()
        else this.scheduleFallback()
      }
    }
  }

  private recordFailure(): void {
    this.consecutiveFailures = Math.min(this.consecutiveFailures + 1, 31)
  }

  private normalizedRandom(): number {
    const value = this.random()
    if (!Number.isFinite(value)) return 0
    return Math.min(1, Math.max(0, value))
  }

  private validDelay(value: number | undefined, fallback: number): number {
    return value !== undefined && Number.isFinite(value) && value >= 0 ? value : fallback
  }

  private notifySyncChanged(status: SyncStatus): void {
    try {
      this.options.onSyncChanged(status)
    } catch {
      // Renderer notifications must not block or fail synchronization.
    }
  }

  private notifyVaultChanged(): void {
    try {
      this.options.onVaultChanged()
    } catch {
      // Renderer notifications must not block or fail synchronization.
    }
  }
}
