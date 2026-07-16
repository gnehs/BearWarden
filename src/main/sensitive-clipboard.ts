import { createHash, timingSafeEqual } from 'node:crypto'

export interface ClipboardAdapter {
  writeText: (text: string) => void
  readText: () => string
  clear: () => void
}

/** Clears only clipboard content still owned by this process. */
export class SensitiveClipboard {
  private fingerprint: Buffer | null = null
  private clearTimer: NodeJS.Timeout | null = null
  private clearDelayMs = 30_000
  private activeDeadlineMs: number | null = null

  constructor(private readonly clipboard: ClipboardAdapter) {}

  setClearDelay(seconds: 0 | 15 | 30 | 60 | 120): void {
    this.clearDelayMs = seconds * 1_000
    this.clearTimerIfNeeded()
    if (this.fingerprint && this.effectiveDelayMs() > 0) this.scheduleClear()
  }

  write(text: string, maxLifetimeSeconds?: number): void {
    if (
      maxLifetimeSeconds !== undefined &&
      (!Number.isSafeInteger(maxLifetimeSeconds) ||
        maxLifetimeSeconds < 1 ||
        maxLifetimeSeconds > 3_600)
    ) {
      throw new RangeError('Invalid clipboard lifetime')
    }
    this.clearTimerIfNeeded()
    this.fingerprint?.fill(0)
    this.clipboard.writeText(text)
    this.fingerprint = this.digest(text)
    this.activeDeadlineMs =
      maxLifetimeSeconds === undefined ? null : Date.now() + maxLifetimeSeconds * 1_000
    this.scheduleClear()
  }

  clearIfOwned(): void {
    this.clearTimerIfNeeded()
    const expected = this.fingerprint
    this.fingerprint = null
    this.activeDeadlineMs = null
    if (!expected) return

    let current: Buffer | null = null
    try {
      current = this.digest(this.clipboard.readText())
      if (timingSafeEqual(expected, current)) this.clipboard.clear()
    } finally {
      expected.fill(0)
      current?.fill(0)
    }
  }

  private effectiveDelayMs(): number {
    if (this.activeDeadlineMs === null) return this.clearDelayMs
    const remaining = Math.max(0, this.activeDeadlineMs - Date.now())
    if (this.clearDelayMs === 0) return remaining
    return Math.min(this.clearDelayMs, remaining)
  }

  private clearTimerIfNeeded(): void {
    if (this.clearTimer) clearTimeout(this.clearTimer)
    this.clearTimer = null
  }

  private scheduleClear(): void {
    const delay = this.effectiveDelayMs()
    if (!this.fingerprint) return
    if (delay === 0) {
      this.clearIfOwned()
      return
    }
    this.clearTimer = setTimeout(() => this.clearIfOwned(), delay)
    this.clearTimer.unref()
  }

  private digest(value: string): Buffer {
    return createHash('sha256').update(value, 'utf8').digest()
  }
}
