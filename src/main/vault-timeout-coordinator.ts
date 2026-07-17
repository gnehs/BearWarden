/** The persisted timeout values currently supported by the desktop client. */
export type VaultAutoLockMinutes = 0 | 1 | 5 | 15 | 30 | 60

export interface VaultTimeoutLockBarrier {
  /**
   * Must fail closed before resolving. The coordinator intentionally does not
   * recover from a rejected lock operation: doing so could leave a vault
   * unlocked after its timeout has elapsed.
   */
  lockVault: () => Promise<void>
}

/**
 * Owns the main-process timeout lifecycle. Renderers may report activity, but
 * never own a timer or perform a timeout lock themselves.
 */
export class VaultTimeoutCoordinator {
  private autoLockMinutes: VaultAutoLockMinutes = 0
  private timer: NodeJS.Timeout | null = null
  private epoch = 0
  private lockOperation: Promise<void> | null = null
  private pendingEpoch: number | null = null
  private disposed = false

  constructor(private readonly lockBarrier: VaultTimeoutLockBarrier) {}

  updatePolicy(autoLockMinutes: VaultAutoLockMinutes): void {
    if (this.disposed) return
    this.autoLockMinutes = autoLockMinutes
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
    if (this.autoLockMinutes === 0) return

    const timerEpoch = this.epoch
    this.timer = setTimeout(() => {
      if (this.disposed || timerEpoch !== this.epoch) return
      this.timer = null
      // The main-process barrier has already failed closed before any rejection can reach here.
      // A post-lock observer must not become an unhandled timer rejection.
      void this.lockIfCurrent(timerEpoch).catch(() => undefined)
    }, this.autoLockMinutes * 60_000)
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
