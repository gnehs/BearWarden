import { afterEach, describe, expect, it, vi } from 'vitest'
import type { VaultTimeoutPolicy } from '../shared/vault-contract'
import { VaultTimeoutCoordinator } from './vault-timeout-coordinator'

const inactivity = (minutes: number): VaultTimeoutPolicy => ({ type: 'appInactivity', minutes })
const onRestart: VaultTimeoutPolicy = { type: 'onRestart' }
const systemIdle: VaultTimeoutPolicy = { type: 'systemIdle' }

describe('VaultTimeoutCoordinator', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('resets the main-process timer when the renderer reports activity', async () => {
    vi.useFakeTimers()
    const lockVault = vi.fn().mockResolvedValue(undefined)
    const coordinator = new VaultTimeoutCoordinator({ lockVault })

    coordinator.updatePolicy(inactivity(1))
    await vi.advanceTimersByTimeAsync(30_000)
    coordinator.activity()
    await vi.advanceTimersByTimeAsync(59_999)
    expect(lockVault).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(1)
    expect(lockVault).toHaveBeenCalledOnce()
  })

  it('does not schedule a timer for the restart-only policy', async () => {
    vi.useFakeTimers()
    const lockVault = vi.fn().mockResolvedValue(undefined)
    const coordinator = new VaultTimeoutCoordinator({ lockVault })

    coordinator.updatePolicy(onRestart)
    coordinator.activity()
    await vi.advanceTimersByTimeAsync(7 * 24 * 60 * 60_000)
    expect(lockVault).not.toHaveBeenCalled()
  })

  it('cancels the stale timer when the policy changes', async () => {
    vi.useFakeTimers()
    const lockVault = vi.fn().mockResolvedValue(undefined)
    const coordinator = new VaultTimeoutCoordinator({ lockVault })

    coordinator.updatePolicy(inactivity(1))
    coordinator.updatePolicy(inactivity(5))
    await vi.advanceTimersByTimeAsync(60_000)
    expect(lockVault).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(4 * 60_000)
    expect(lockVault).toHaveBeenCalledOnce()

    coordinator.updatePolicy(onRestart)
    await vi.advanceTimersByTimeAsync(60 * 60_000)
    expect(lockVault).toHaveBeenCalledOnce()
  })

  it('uses deadline chunks rather than an overflowing Node timeout', async () => {
    vi.useFakeTimers()
    const lockVault = vi.fn().mockResolvedValue(undefined)
    let now = 0
    const coordinator = new VaultTimeoutCoordinator(
      { lockVault },
      { maxTimerDelayMs: 60_000, now: () => now }
    )

    coordinator.updatePolicy(inactivity(3))
    now = 60_000
    await vi.advanceTimersByTimeAsync(60_000)
    expect(lockVault).not.toHaveBeenCalled()
    now = 120_000
    await vi.advanceTimersByTimeAsync(60_000)
    expect(lockVault).not.toHaveBeenCalled()
    now = 179_999
    await vi.advanceTimersByTimeAsync(59_999)
    expect(lockVault).not.toHaveBeenCalled()
    now = 180_000
    await vi.advanceTimersByTimeAsync(1)
    expect(lockVault).toHaveBeenCalledOnce()
  })

  it('does not let a stale deadline chunk lock after a policy replacement', async () => {
    vi.useFakeTimers()
    const lockVault = vi.fn().mockResolvedValue(undefined)
    const coordinator = new VaultTimeoutCoordinator({ lockVault }, { maxTimerDelayMs: 60_000 })

    coordinator.updatePolicy(inactivity(3))
    await vi.advanceTimersByTimeAsync(60_000)
    coordinator.updatePolicy(onRestart)
    await vi.advanceTimersByTimeAsync(10 * 60_000)
    expect(lockVault).not.toHaveBeenCalled()
  })

  it('runs the current expired epoch after an in-flight post-lock observer settles', async () => {
    vi.useFakeTimers()
    let finishLock: (() => void) | undefined
    const lockVault = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          finishLock = resolve
        })
    )
    const coordinator = new VaultTimeoutCoordinator({ lockVault })

    coordinator.updatePolicy(inactivity(1))
    await vi.advanceTimersByTimeAsync(60_000)
    expect(lockVault).toHaveBeenCalledOnce()

    coordinator.activity()
    await vi.advanceTimersByTimeAsync(60_000)
    expect(lockVault).toHaveBeenCalledOnce()

    finishLock?.()
    await Promise.resolve()
    expect(lockVault).toHaveBeenCalledTimes(2)
  })

  it('does not replay a pending expiry after cancellation or disposal', async () => {
    vi.useFakeTimers()
    let finishLock: (() => void) | undefined
    const lockVault = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          finishLock = resolve
        })
    )
    const coordinator = new VaultTimeoutCoordinator({ lockVault })

    coordinator.updatePolicy(inactivity(1))
    await vi.advanceTimersByTimeAsync(60_000)
    coordinator.activity()
    await vi.advanceTimersByTimeAsync(60_000)
    coordinator.cancel()
    finishLock?.()
    await Promise.resolve()
    expect(lockVault).toHaveBeenCalledOnce()

    coordinator.updatePolicy(inactivity(1))
    await vi.advanceTimersByTimeAsync(60_000)
    coordinator.activity()
    await vi.advanceTimersByTimeAsync(60_000)
    coordinator.dispose()
    finishLock?.()
    await Promise.resolve()
    expect(lockVault).toHaveBeenCalledTimes(2)
  })

  it('releases a rejected post-lock observer so a later timer generation can lock', async () => {
    vi.useFakeTimers()
    const lockVault = vi
      .fn<() => Promise<void>>()
      .mockRejectedValueOnce(new Error('post-lock observer failed'))
      .mockResolvedValueOnce(undefined)
    const coordinator = new VaultTimeoutCoordinator({ lockVault })

    coordinator.updatePolicy(inactivity(1))
    await vi.advanceTimersByTimeAsync(60_000)
    expect(lockVault).toHaveBeenCalledOnce()

    coordinator.activity()
    await vi.advanceTimersByTimeAsync(60_000)
    expect(lockVault).toHaveBeenCalledTimes(2)
  })

  it('replaces a pending expiry when the timeout policy changes', async () => {
    vi.useFakeTimers()
    let finishLock: (() => void) | undefined
    const lockVault = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          finishLock = resolve
        })
    )
    const coordinator = new VaultTimeoutCoordinator({ lockVault })

    coordinator.updatePolicy(inactivity(1))
    await vi.advanceTimersByTimeAsync(60_000)
    coordinator.activity()
    await vi.advanceTimersByTimeAsync(60_000)
    coordinator.updatePolicy(inactivity(5))
    finishLock?.()
    await Promise.resolve()
    expect(lockVault).toHaveBeenCalledOnce()

    await vi.advanceTimersByTimeAsync(5 * 60_000)
    expect(lockVault).toHaveBeenCalledTimes(2)
    finishLock?.()
  })

  it('cancels a scheduled timeout when lock or account-switch teardown invalidates it', async () => {
    vi.useFakeTimers()
    const lockVault = vi.fn().mockResolvedValue(undefined)
    const coordinator = new VaultTimeoutCoordinator({ lockVault })

    coordinator.updatePolicy(inactivity(1))
    coordinator.cancel()
    await vi.advanceTimersByTimeAsync(60_000)
    expect(lockVault).not.toHaveBeenCalled()

    coordinator.updatePolicy(inactivity(1))
    coordinator.dispose()
    coordinator.activity()
    coordinator.updatePolicy(inactivity(5))
    await vi.advanceTimersByTimeAsync(60 * 60_000)
    expect(lockVault).not.toHaveBeenCalled()
  })

  it('locks at 300 system-idle seconds, but not at 299', async () => {
    vi.useFakeTimers()
    let idleSeconds = 299
    const lockVault = vi.fn().mockResolvedValue(undefined)
    const coordinator = new VaultTimeoutCoordinator(
      { lockVault },
      { getSystemIdleTime: () => idleSeconds }
    )

    coordinator.updatePolicy(systemIdle)
    expect(lockVault).not.toHaveBeenCalled()

    idleSeconds = 300
    await vi.advanceTimersByTimeAsync(30_000)
    expect(lockVault).toHaveBeenCalledOnce()
  })

  it('locks only once per idle period and rearms after the system becomes active', async () => {
    vi.useFakeTimers()
    let idleSeconds = 300
    const lockVault = vi.fn().mockResolvedValue(undefined)
    const coordinator = new VaultTimeoutCoordinator(
      { lockVault },
      { getSystemIdleTime: () => idleSeconds }
    )

    coordinator.updatePolicy(systemIdle)
    await vi.advanceTimersByTimeAsync(5 * 30_000)
    expect(lockVault).toHaveBeenCalledOnce()

    idleSeconds = 0
    await vi.advanceTimersByTimeAsync(30_000)
    idleSeconds = 300
    await vi.advanceTimersByTimeAsync(30_000)
    expect(lockVault).toHaveBeenCalledTimes(2)
  })

  it('clears stale idle polls when the policy changes, is canceled, or is disposed', async () => {
    vi.useFakeTimers()
    let idleSeconds = 0
    const lockVault = vi.fn().mockResolvedValue(undefined)
    const coordinator = new VaultTimeoutCoordinator(
      { lockVault },
      { getSystemIdleTime: () => idleSeconds }
    )

    coordinator.updatePolicy(systemIdle)
    coordinator.updatePolicy(onRestart)
    idleSeconds = 300
    await vi.advanceTimersByTimeAsync(30_000)
    expect(lockVault).not.toHaveBeenCalled()

    idleSeconds = 0
    coordinator.updatePolicy(systemIdle)
    coordinator.cancel()
    idleSeconds = 300
    coordinator.resume()
    await vi.advanceTimersByTimeAsync(30_000)
    expect(lockVault).not.toHaveBeenCalled()

    idleSeconds = 0
    coordinator.updatePolicy(systemIdle)
    coordinator.dispose()
    idleSeconds = 300
    await vi.advanceTimersByTimeAsync(30_000)
    expect(lockVault).not.toHaveBeenCalled()
  })

  it('rechecks an armed idle policy immediately on resume without reviving a canceled one', () => {
    let idleSeconds = 0
    const lockVault = vi.fn().mockResolvedValue(undefined)
    const coordinator = new VaultTimeoutCoordinator(
      { lockVault },
      { getSystemIdleTime: () => idleSeconds }
    )

    coordinator.updatePolicy(systemIdle)
    idleSeconds = 300
    coordinator.resume()
    expect(lockVault).toHaveBeenCalledOnce()

    coordinator.cancel()
    coordinator.resume()
    expect(lockVault).toHaveBeenCalledOnce()
  })

  it('rearms a canceled system-idle poll when an unlocked renderer reports activity', async () => {
    vi.useFakeTimers()
    let idleSeconds = 0
    const lockVault = vi.fn().mockResolvedValue(undefined)
    const coordinator = new VaultTimeoutCoordinator(
      { lockVault },
      { getSystemIdleTime: () => idleSeconds }
    )

    coordinator.updatePolicy(systemIdle)
    coordinator.cancel()
    coordinator.activity()

    idleSeconds = 300
    await vi.advanceTimersByTimeAsync(30_000)
    expect(lockVault).toHaveBeenCalledOnce()
  })

  it.each([
    [
      'throwing',
      () => {
        throw new Error('idle sensor failed')
      }
    ],
    ['NaN', () => Number.NaN],
    ['infinite', () => Number.POSITIVE_INFINITY],
    ['negative', () => -1]
  ])('fails closed once when the system-idle sensor is %s', async (_label, getSystemIdleTime) => {
    vi.useFakeTimers()
    const lockVault = vi.fn().mockResolvedValue(undefined)
    const coordinator = new VaultTimeoutCoordinator({ lockVault }, { getSystemIdleTime })

    coordinator.updatePolicy(systemIdle)
    await vi.advanceTimersByTimeAsync(3 * 30_000)
    expect(lockVault).toHaveBeenCalledOnce()
  })
})
