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
    this.scheduleClear()
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

  /** Milliseconds until the content must be cleared, or `null` when nothing bounds its lifetime. */
  private effectiveDelayMs(): number | null {
    const remaining =
      this.activeDeadlineMs === null ? null : Math.max(0, this.activeDeadlineMs - Date.now())
    if (this.clearDelayMs === 0) return remaining
    return remaining === null ? this.clearDelayMs : Math.min(this.clearDelayMs, remaining)
  }

  private clearTimerIfNeeded(): void {
    if (this.clearTimer) clearTimeout(this.clearTimer)
    this.clearTimer = null
  }

  private scheduleClear(): void {
    if (!this.fingerprint) return
    const delay = this.effectiveDelayMs()
    if (delay === null) return
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
