interface MemoryCacheEntry<T> {
  value: T
  size: number
  expiresAt: number
}

/** Size- and count-bounded LRU with per-entry expiry, for decoded images kept in main memory. */
export class ImageMemoryCache<T> {
  private readonly entries = new Map<string, MemoryCacheEntry<T>>()
  private totalSize = 0

  constructor(
    private readonly options: { maxEntries: number; maxSize: number; now?: () => number }
  ) {}

  private now(): number {
    return this.options.now?.() ?? Date.now()
  }

  /** Returns the cached value and marks it most recently used; expired entries are dropped. */
  get(key: string): { value: T } | null {
    const entry = this.entries.get(key)
    if (!entry) return null
    this.entries.delete(key)
    if (entry.expiresAt <= this.now()) {
      this.totalSize -= entry.size
      return null
    }
    this.entries.set(key, entry)
    return { value: entry.value }
  }

  set(key: string, value: T, options: { size: number; ttlMs: number }): void {
    this.delete(key)
    if (options.size > this.options.maxSize) return
    this.entries.set(key, { value, size: options.size, expiresAt: this.now() + options.ttlMs })
    this.totalSize += options.size
    while (this.entries.size > this.options.maxEntries || this.totalSize > this.options.maxSize) {
      const oldestKey = this.entries.keys().next().value
      if (oldestKey === undefined) break
      this.delete(oldestKey)
    }
  }

  delete(key: string): void {
    const entry = this.entries.get(key)
    if (!entry) return
    this.entries.delete(key)
    this.totalSize -= entry.size
  }

  clear(): void {
    this.entries.clear()
    this.totalSize = 0
  }

  get size(): number {
    return this.entries.size
  }
}

/** Runs at most `limit` tasks at once, starting queued tasks in request order. */
export class ConcurrencyLimiter {
  private active = 0
  private readonly queue: (() => void)[] = []

  constructor(private readonly limit: number) {}

  async run<T>(task: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    if (signal?.aborted) throw signal.reason ?? new Error('ABORTED')
    if (this.active >= this.limit) {
      // A finishing task hands its slot directly to the next waiter, so `active` is not
      // incremented here and no newcomer can overtake the queue.
      await new Promise<void>((resolve, reject) => {
        const start = (): void => {
          signal?.removeEventListener('abort', abort)
          resolve()
        }
        const abort = (): void => {
          const index = this.queue.indexOf(start)
          if (index >= 0) this.queue.splice(index, 1)
          reject(signal?.reason ?? new Error('ABORTED'))
        }
        signal?.addEventListener('abort', abort, { once: true })
        this.queue.push(start)
      })
    } else {
      this.active += 1
    }
    try {
      return await task()
    } finally {
      const next = this.queue.shift()
      if (next) next()
      else this.active -= 1
    }
  }
}
