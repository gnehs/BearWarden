import { MAX_VAULT_TIMEOUT_MINUTES, type VaultTimeoutPolicy } from '../shared/vault-contract'

const MAX_TIMER_DELAY_MS = 2_147_483_647

export interface VaultTimeoutLockBarrier {
  /**
   * Must fail closed before resolving. The coordinator intentionally does not
   * recover from a rejected lock operation: doing so could leave a vault
   * unlocked after its timeout has elapsed.
   */
  lockVault: () => Promise<void>
}

export interface VaultTimeoutCoordinatorOptions {
  /** Test seam for deadline accounting; production uses the wall clock. */
  now?: () => number
  /** Node clamps delays larger than this value; production uses Node's maximum. */
  maxTimerDelayMs?: number
}

/**
 * Owns the main-process timeout lifecycle. Renderers may report activity, but
 * never own a timer or perform a timeout lock themselves.
 */
export class VaultTimeoutCoordinator {
  private policy: VaultTimeoutPolicy = { type: 'onRestart' }
  private timer: NodeJS.Timeout | null = null
  private deadline: number | null = null
  private epoch = 0
  private lockOperation: Promise<void> | null = null
  private pendingEpoch: number | null = null
  private disposed = false

  private readonly now: () => number
  private readonly maxTimerDelayMs: number

  constructor(
    private readonly lockBarrier: VaultTimeoutLockBarrier,
    options: VaultTimeoutCoordinatorOptions = {}
  ) {
    this.now = options.now ?? (() => Date.now())
    this.maxTimerDelayMs = options.maxTimerDelayMs ?? MAX_TIMER_DELAY_MS
  }

  updatePolicy(policy: VaultTimeoutPolicy): void {
    if (this.disposed) return
    this.policy = policy
    this.resetTimer()
  }

  activity(): void {
    if (this.disposed) return
    this.resetTimer()
  }

  /** Invalidates a scheduled timeout without changing its configured policy. */
  cancel(): void {
    this.epoch += 1
    this.pendingEpoch = null
    this.deadline = null
    if (this.timer) clearTimeout(this.timer)
    this.timer = null
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.cancel()
  }

  private resetTimer(): void {
    this.cancel()
    if (this.policy.type === 'onRestart') return

    const timerEpoch = this.epoch
    this.deadline = this.now() + Math.min(this.policy.minutes, MAX_VAULT_TIMEOUT_MINUTES) * 60_000
    this.scheduleDeadline(timerEpoch)
  }

  private scheduleDeadline(timerEpoch: number): void {
    if (this.disposed || timerEpoch !== this.epoch || this.deadline === null) return
    const remaining = this.deadline - this.now()
    if (remaining <= 0) {
      this.timer = null
      // The main-process barrier has already failed closed before any rejection can reach here.
      // A post-lock observer must not become an unhandled timer rejection.
      void this.lockIfCurrent(timerEpoch).catch(() => undefined)
      return
    }
    this.timer = setTimeout(
      () => {
        this.timer = null
        this.scheduleDeadline(timerEpoch)
      },
      Math.min(remaining, this.maxTimerDelayMs)
    )
    this.timer.unref()
  }

  private lockIfCurrent(timerEpoch: number): Promise<void> {
    if (this.disposed || timerEpoch !== this.epoch) return Promise.resolve()
    if (this.lockOperation) {
      // Keep one current expiry behind an in-flight fail-closed barrier. This is deliberately
      // bounded: repeated renderer activity replaces the epoch, rather than growing a queue.
      this.pendingEpoch = timerEpoch
      return this.lockOperation
    }

    const operation = this.lockBarrier.lockVault().finally(() => {
      if (this.lockOperation !== operation) return
      this.lockOperation = null
      const pendingEpoch = this.pendingEpoch
      this.pendingEpoch = null
      if (this.disposed || pendingEpoch === null || pendingEpoch !== this.epoch) return
      // The timer callback cannot await a later epoch. Start it after this barrier settles and
      // give it the same rejection containment as a direct timer callback.
      void this.lockIfCurrent(pendingEpoch).catch(() => undefined)
    })
    this.lockOperation = operation
    return operation
  }
}
