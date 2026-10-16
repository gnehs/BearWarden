import { describe, expect, it } from 'vitest'
import { ConcurrencyLimiter, ImageMemoryCache } from './image-memory-cache'

describe('ImageMemoryCache', () => {
  it('evicts the least recently used entry when over capacity', () => {
    const cache = new ImageMemoryCache<string>({ maxEntries: 2, maxSize: 100 })
    cache.set('a', 'A', { size: 1, ttlMs: 1000 })
    cache.set('b', 'B', { size: 1, ttlMs: 1000 })
    expect(cache.get('a')).toEqual({ value: 'A' })
    cache.set('c', 'C', { size: 1, ttlMs: 1000 })

    expect(cache.get('b')).toBeNull()
    expect(cache.get('a')).toEqual({ value: 'A' })
    expect(cache.get('c')).toEqual({ value: 'C' })
  })

  it('bounds the total size and drops expired entries', () => {
    let now = 0
    const cache = new ImageMemoryCache<string | null>({
      maxEntries: 10,
      maxSize: 10,
      now: () => now
    })
    cache.set('big', 'x', { size: 11, ttlMs: 1000 })
    expect(cache.get('big')).toBeNull()
    cache.set('a', null, { size: 6, ttlMs: 50 })
    cache.set('b', 'B', { size: 6, ttlMs: 1000 })
    expect(cache.get('a')).toBeNull()
    expect(cache.size).toBe(1)

    now = 1000
    expect(cache.get('b')).toBeNull()
    expect(cache.size).toBe(0)
  })
})

describe('ConcurrencyLimiter', () => {
  it('never runs more than the limit and hands slots over in order', async () => {
    const limiter = new ConcurrencyLimiter(2)
    let running = 0
    let peak = 0
    const order: number[] = []
    const releases: (() => void)[] = []
    const tasks = [0, 1, 2, 3].map((index) =>
      limiter.run(async () => {
        running += 1
        peak = Math.max(peak, running)
        order.push(index)
        await new Promise<void>((resolve) => releases.push(resolve))
        running -= 1
      })
    )
    await Promise.resolve()
    expect(order).toEqual([0, 1])
    releases.shift()!()
    await new Promise((resolve) => setTimeout(resolve, 0))
    // A newcomer must not overtake the queued task 2.
    const late = limiter.run(async () => order.push(4))
    while (releases.length > 0 || order.length < 5) {
      releases.shift()?.()
      await new Promise((resolve) => setTimeout(resolve, 0))
    }
    await Promise.all([...tasks, late])
    expect(peak).toBe(2)
    expect(order).toEqual([0, 1, 2, 3, 4])
  })

  it('drops an aborted waiter from the queue', async () => {
    const limiter = new ConcurrencyLimiter(1)
    let release!: () => void
    const first = limiter.run(() => new Promise<void>((resolve) => (release = resolve)))
    const abort = new AbortController()
    const waiting = limiter.run(async () => 'never', abort.signal)
    abort.abort(new Error('stop'))
    await expect(waiting).rejects.toThrow('stop')
    release()
    await first
    await expect(limiter.run(async () => 'next')).resolves.toBe('next')
  })
})
