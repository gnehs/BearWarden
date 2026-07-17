import { afterEach, describe, expect, it, vi } from 'vitest'
import type { VaultTimeoutPolicy } from '../shared/vault-contract'
import { VaultTimeoutCoordinator } from './vault-timeout-coordinator'

const inactivity = (minutes: number): VaultTimeoutPolicy => ({ type: 'appInactivity', minutes })
const onRestart: VaultTimeoutPolicy = { type: 'onRestart' }

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
})
