import { afterEach, describe, expect, it, vi } from 'vitest'
import { VaultTimeoutCoordinator } from './vault-timeout-coordinator'

describe('VaultTimeoutCoordinator', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('resets the main-process timer when the renderer reports activity', async () => {
    vi.useFakeTimers()
    const lockVault = vi.fn().mockResolvedValue(undefined)
    const coordinator = new VaultTimeoutCoordinator({ lockVault })

    coordinator.updatePolicy(1)
    await vi.advanceTimersByTimeAsync(30_000)
    coordinator.activity()
    await vi.advanceTimersByTimeAsync(59_999)
    expect(lockVault).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(1)
    expect(lockVault).toHaveBeenCalledOnce()
  })

  it('cancels the stale timer when the policy changes or timeout is disabled', async () => {
    vi.useFakeTimers()
    const lockVault = vi.fn().mockResolvedValue(undefined)
    const coordinator = new VaultTimeoutCoordinator({ lockVault })

    coordinator.updatePolicy(1)
    coordinator.updatePolicy(5)
    await vi.advanceTimersByTimeAsync(60_000)
    expect(lockVault).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(4 * 60_000)
    expect(lockVault).toHaveBeenCalledOnce()

    coordinator.updatePolicy(1)
    coordinator.updatePolicy(0)
    await vi.advanceTimersByTimeAsync(60 * 60_000)
    expect(lockVault).toHaveBeenCalledOnce()
  })

  it('runs the current expired epoch after an in-flight post-lock observer settles', async () => {
    vi.useFakeTimers()
    let finishLock: (() => void) | undefined
    let vaultUnlocked = false
    const lockVault = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          vaultUnlocked = false
          finishLock = resolve
        })
    )
    const coordinator = new VaultTimeoutCoordinator({ lockVault })

    coordinator.updatePolicy(1)
    await vi.advanceTimersByTimeAsync(60_000)
    expect(lockVault).toHaveBeenCalledOnce()

    coordinator.activity()
    await vi.advanceTimersByTimeAsync(60_000)
    expect(lockVault).toHaveBeenCalledOnce()
    vaultUnlocked = true

    finishLock?.()
    await Promise.resolve()
    expect(lockVault).toHaveBeenCalledTimes(2)
    expect(vaultUnlocked).toBe(false)

    finishLock?.()
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

    coordinator.updatePolicy(1)
    await vi.advanceTimersByTimeAsync(60_000)
    coordinator.activity()
    await vi.advanceTimersByTimeAsync(60_000)
    coordinator.cancel()
    finishLock?.()
    await Promise.resolve()
    expect(lockVault).toHaveBeenCalledOnce()

    coordinator.updatePolicy(1)
    await vi.advanceTimersByTimeAsync(60_000)
    coordinator.activity()
    await vi.advanceTimersByTimeAsync(60_000)
    coordinator.dispose()
    finishLock?.()
    await Promise.resolve()
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

    coordinator.updatePolicy(1)
    await vi.advanceTimersByTimeAsync(60_000)
    coordinator.activity()
    await vi.advanceTimersByTimeAsync(60_000)
    coordinator.updatePolicy(5)
    finishLock?.()
    await Promise.resolve()
    expect(lockVault).toHaveBeenCalledOnce()

    await vi.advanceTimersByTimeAsync(5 * 60_000)
    expect(lockVault).toHaveBeenCalledTimes(2)
    finishLock?.()
  })

  it('releases a rejected post-lock observer so a later timer generation can lock', async () => {
    vi.useFakeTimers()
    const lockVault = vi
      .fn<() => Promise<void>>()
      .mockRejectedValueOnce(new Error('post-lock observer failed'))
      .mockResolvedValueOnce(undefined)
    const coordinator = new VaultTimeoutCoordinator({ lockVault })

    coordinator.updatePolicy(1)
    await vi.advanceTimersByTimeAsync(60_000)
    expect(lockVault).toHaveBeenCalledOnce()

    coordinator.activity()
    await vi.advanceTimersByTimeAsync(60_000)
    expect(lockVault).toHaveBeenCalledTimes(2)
  })

  it('cancels a scheduled timeout when a lock or account-switch teardown invalidates it', async () => {
    vi.useFakeTimers()
    const lockVault = vi.fn().mockResolvedValue(undefined)
    const coordinator = new VaultTimeoutCoordinator({ lockVault })

    coordinator.updatePolicy(1)
    coordinator.cancel()
    await vi.advanceTimersByTimeAsync(60_000)
    expect(lockVault).not.toHaveBeenCalled()

    coordinator.updatePolicy(1)
    coordinator.dispose()
    coordinator.activity()
    coordinator.updatePolicy(5)
    await vi.advanceTimersByTimeAsync(60 * 60_000)
    expect(lockVault).not.toHaveBeenCalled()
  })
})
