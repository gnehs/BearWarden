import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { SyncResult, SyncStatus } from '../shared/vault-contract'
import {
  AutoSyncCoordinator,
  type AutoSyncCoordinatorOptions,
  type AutoSyncVault
} from './auto-sync-coordinator'

const READY_STATUS: SyncStatus = {
  configured: true,
  state: 'ready',
  serverUrl: 'https://vault.example.invalid',
  lastSyncAt: '2026-07-15T00:00:00.000Z'
}

const SYNC_RESULT: SyncResult = {
  ...READY_STATUS,
  pulled: 1,
  pushed: 2,
  deleted: 0,
  conflicts: 0
}

function createDeferred<T>(): {
  promise: Promise<T>
  resolve: (value: T) => void
} {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((promiseResolve) => {
    resolve = promiseResolve
  })
  return { promise, resolve }
}

function createHarness(
  delayMs = 250,
  overrides: Partial<
    Omit<AutoSyncCoordinatorOptions, 'vault' | 'onSyncChanged' | 'onVaultChanged'>
  > = {}
): {
  coordinator: AutoSyncCoordinator
  vault: AutoSyncVault
  syncStatus: ReturnType<typeof vi.fn>
  syncNow: ReturnType<typeof vi.fn>
  onSyncChanged: ReturnType<typeof vi.fn>
  onVaultChanged: ReturnType<typeof vi.fn>
} {
  const syncStatus = vi.fn<AutoSyncVault['syncStatus']>().mockResolvedValue(READY_STATUS)
  const syncNow = vi.fn<AutoSyncVault['syncNow']>().mockResolvedValue(SYNC_RESULT)
  const onSyncChanged = vi.fn<(status: SyncStatus) => void>()
  const onVaultChanged = vi.fn<() => void>()
  const vault = { syncStatus, syncNow }
  const coordinator = new AutoSyncCoordinator({
    vault,
    onSyncChanged,
    onVaultChanged,
    delayMs,
    ...overrides
  })

  return { coordinator, vault, syncStatus, syncNow, onSyncChanged, onVaultChanged }
}

describe('AutoSyncCoordinator', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('coalesces consecutive requests into one sync', async () => {
    const { coordinator, syncStatus, syncNow } = createHarness()

    coordinator.request()
    coordinator.request()
    coordinator.request()

    await vi.advanceTimersByTimeAsync(250)

    expect(syncStatus).toHaveBeenCalledTimes(1)
    expect(syncNow).toHaveBeenCalledTimes(1)
  })

  it('runs foreground and unlock requests immediately without changing invalidation debounce', async () => {
    const { coordinator, syncNow } = createHarness()

    coordinator.requestImmediate()
    await vi.advanceTimersByTimeAsync(0)
    expect(syncNow).toHaveBeenCalledOnce()

    coordinator.request()
    await vi.advanceTimersByTimeAsync(249)
    expect(syncNow).toHaveBeenCalledOnce()
    await vi.advanceTimersByTimeAsync(1)
    expect(syncNow).toHaveBeenCalledTimes(2)
  })

  it('reports syncing and the result, then announces the changed vault when ready', async () => {
    const events: string[] = []
    const { coordinator, onSyncChanged, onVaultChanged } = createHarness()
    onSyncChanged.mockImplementation((status: SyncStatus) => events.push(`sync:${status.state}`))
    onVaultChanged.mockImplementation(() => events.push('vault:changed'))

    coordinator.request()
    await vi.advanceTimersByTimeAsync(250)

    expect(onSyncChanged).toHaveBeenNthCalledWith(1, {
      ...READY_STATUS,
      state: 'syncing'
    })
    expect(onSyncChanged).toHaveBeenNthCalledWith(2, SYNC_RESULT)
    expect(events).toEqual(['sync:syncing', 'sync:ready', 'vault:changed'])
  })

  it('reports a locked status without syncing', async () => {
    const { coordinator, syncStatus, syncNow, onSyncChanged, onVaultChanged } = createHarness()
    const lockedStatus: SyncStatus = { configured: true, state: 'locked' }
    syncStatus.mockResolvedValue(lockedStatus)

    coordinator.request()
    await vi.advanceTimersByTimeAsync(250)

    expect(onSyncChanged).toHaveBeenCalledOnce()
    expect(onSyncChanged).toHaveBeenCalledWith(lockedStatus)
    expect(syncNow).not.toHaveBeenCalled()
    expect(onVaultChanged).not.toHaveBeenCalled()
  })

  it('keeps a remote invalidation pending while a manual sync is running', async () => {
    const { coordinator, syncStatus, syncNow, onSyncChanged } = createHarness()
    syncStatus
      .mockResolvedValueOnce({ configured: true, state: 'syncing' })
      .mockResolvedValueOnce(READY_STATUS)

    coordinator.request()
    await vi.advanceTimersByTimeAsync(250)
    expect(syncNow).not.toHaveBeenCalled()
    expect(onSyncChanged).toHaveBeenCalledWith({ configured: true, state: 'syncing' })

    await vi.advanceTimersByTimeAsync(250)
    expect(syncNow).toHaveBeenCalledOnce()
  })

  it('contains sync failures and reports the resulting error status', async () => {
    const { coordinator, syncStatus, syncNow, onSyncChanged, onVaultChanged } = createHarness()
    const errorStatus: SyncStatus = {
      configured: true,
      state: 'error',
      lastError: 'SYNC_FAILED'
    }
    syncStatus.mockResolvedValueOnce(READY_STATUS).mockResolvedValueOnce(errorStatus)
    syncNow.mockRejectedValueOnce(new Error('Test sync failed'))

    coordinator.request()
    // Advancing the timer also drains the rejected sync promise; this await would reject if it leaked.
    await vi.advanceTimersByTimeAsync(250)

    expect(syncStatus).toHaveBeenCalledTimes(2)
    expect(onSyncChanged).toHaveBeenNthCalledWith(1, { ...READY_STATUS, state: 'syncing' })
    expect(onSyncChanged).toHaveBeenNthCalledWith(2, errorStatus)
    expect(onVaultChanged).not.toHaveBeenCalled()
  })

  it('keeps low-frequency safety polling active even when push notifications are available', async () => {
    const { coordinator, syncNow } = createHarness(250, {
      safetyMinDelayMs: 1_000,
      safetyMaxDelayMs: 2_000,
      random: () => 0.5
    })

    coordinator.updateStatus(READY_STATUS)
    await vi.advanceTimersByTimeAsync(1_499)
    expect(syncNow).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    expect(syncNow).toHaveBeenCalledOnce()

    await vi.advanceTimersByTimeAsync(1_500)
    expect(syncNow).toHaveBeenCalledTimes(2)
  })

  it('backs off transient failures with capped jitter and resets after recovery', async () => {
    const { coordinator, syncStatus, syncNow, onSyncChanged } = createHarness(250, {
      safetyMinDelayMs: 10_000,
      safetyMaxDelayMs: 10_000,
      retryBaseDelayMs: 1_000,
      retryMaxDelayMs: 2_000,
      random: () => 1
    })
    const errorStatus: SyncStatus = {
      configured: true,
      state: 'error',
      lastError: 'SYNC_INVALID_RESPONSE',
      lastErrorAt: '2026-07-18T02:03:04.000Z',
      lastErrorDetail: 'response'
    }
    syncNow
      .mockRejectedValueOnce(new Error('offline'))
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce(SYNC_RESULT)
    syncStatus
      .mockResolvedValueOnce(READY_STATUS)
      .mockResolvedValueOnce(errorStatus)
      .mockResolvedValueOnce(errorStatus)
      .mockResolvedValueOnce(errorStatus)
      .mockResolvedValueOnce(errorStatus)

    coordinator.requestImmediate()
    await vi.advanceTimersByTimeAsync(0)
    expect(syncNow).toHaveBeenCalledTimes(1)

    await vi.advanceTimersByTimeAsync(999)
    expect(syncNow).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(1)
    expect(syncNow).toHaveBeenCalledTimes(2)

    await vi.advanceTimersByTimeAsync(1_999)
    expect(syncNow).toHaveBeenCalledTimes(2)
    await vi.advanceTimersByTimeAsync(1)
    expect(syncNow).toHaveBeenCalledTimes(3)
    expect(
      onSyncChanged.mock.calls
        .map(([status]) => status)
        .filter((status) => status.state === 'syncing')
        .every(
          (status) =>
            !('lastError' in status) && !('lastErrorAt' in status) && !('lastErrorDetail' in status)
        )
    ).toBe(true)

    // A successful online sync resets to the normal safety cadence instead of retrying again.
    await vi.advanceTimersByTimeAsync(9_999)
    expect(syncNow).toHaveBeenCalledTimes(3)
    await vi.advanceTimersByTimeAsync(1)
    expect(syncNow).toHaveBeenCalledTimes(4)
  })

  it('restarts normal safety timing when manual success supersedes an active retry', async () => {
    const { coordinator, syncNow } = createHarness(250, {
      safetyMinDelayMs: 10_000,
      safetyMaxDelayMs: 10_000,
      retryBaseDelayMs: 1_000,
      retryMaxDelayMs: 1_000,
      random: () => 1
    })

    coordinator.updateStatus({ configured: true, state: 'error', lastError: 'SYNC_NETWORK' })
    await vi.advanceTimersByTimeAsync(500)
    coordinator.updateStatus(READY_STATUS)

    // The old retry would have fired here, but manual success starts a fresh safety interval.
    await vi.advanceTimersByTimeAsync(500)
    expect(syncNow).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(9_499)
    expect(syncNow).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    expect(syncNow).toHaveBeenCalledOnce()
  })

  it('restarts an active safety interval from external ready completion', async () => {
    const { coordinator, syncNow } = createHarness(250, {
      safetyMinDelayMs: 10_000,
      safetyMaxDelayMs: 10_000
    })

    coordinator.updateStatus(READY_STATUS)
    await vi.advanceTimersByTimeAsync(6_000)
    coordinator.updateStatus(READY_STATUS)

    await vi.advanceTimersByTimeAsync(4_000)
    expect(syncNow).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(5_999)
    expect(syncNow).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    expect(syncNow).toHaveBeenCalledOnce()
  })

  it('replaces an active safety interval with backoff after external error', async () => {
    const { coordinator, syncNow } = createHarness(250, {
      safetyMinDelayMs: 10_000,
      safetyMaxDelayMs: 10_000,
      retryBaseDelayMs: 2_000,
      retryMaxDelayMs: 2_000,
      random: () => 1
    })

    coordinator.updateStatus(READY_STATUS)
    await vi.advanceTimersByTimeAsync(1_000)
    coordinator.updateStatus({ configured: true, state: 'error', lastError: 'SYNC_NETWORK' })

    await vi.advanceTimersByTimeAsync(1_999)
    expect(syncNow).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    expect(syncNow).toHaveBeenCalledOnce()
  })

  it('normalizes non-finite, negative, and inverted timer boundaries', async () => {
    const delays: number[] = []
    const capturingSetTimeout = (
      callback: () => void,
      delayMs: number
    ): ReturnType<typeof setTimeout> => {
      delays.push(delayMs)
      return setTimeout(callback, delayMs)
    }
    const invalid = createHarness(Number.POSITIVE_INFINITY, {
      safetyMinDelayMs: -1,
      safetyMaxDelayMs: Number.POSITIVE_INFINITY,
      random: () => Number.NaN,
      setTimeout: capturingSetTimeout
    })

    invalid.coordinator.request()
    expect(delays.at(-1)).toBe(250)
    invalid.coordinator.cancel()
    invalid.coordinator.updateStatus(READY_STATUS)
    expect(delays.at(-1)).toBe(5 * 60 * 1_000)

    const inverted = createHarness(250, {
      safetyMinDelayMs: 2_000,
      safetyMaxDelayMs: 1_000,
      retryBaseDelayMs: 2_000,
      retryMaxDelayMs: 1_000,
      random: () => Number.POSITIVE_INFINITY,
      setTimeout: capturingSetTimeout
    })
    inverted.coordinator.updateStatus(READY_STATUS)
    expect(delays.at(-1)).toBe(2_000)
    inverted.coordinator.cancel()
    inverted.coordinator.updateStatus({
      configured: true,
      state: 'error',
      lastError: 'SYNC_NETWORK'
    })
    expect(delays.at(-1)).toBe(1_000)

    const negativeRandom = createHarness(250, {
      safetyMinDelayMs: 3_000,
      safetyMaxDelayMs: 4_000,
      random: () => -10,
      setTimeout: capturingSetTimeout
    })
    negativeRandom.coordinator.updateStatus(READY_STATUS)
    expect(delays.at(-1)).toBe(3_000)
    expect(delays.every((delay) => Number.isFinite(delay) && delay >= 0)).toBe(true)
  })

  it('retries a configured error state so transient failures can recover', async () => {
    const { coordinator, syncStatus, syncNow, onSyncChanged, onVaultChanged } = createHarness()
    syncStatus.mockResolvedValue({
      configured: true,
      state: 'error',
      lastError: 'SYNC_NETWORK'
    })

    coordinator.request()
    await vi.advanceTimersByTimeAsync(250)

    expect(syncNow).toHaveBeenCalledOnce()
    expect(onSyncChanged).toHaveBeenNthCalledWith(1, {
      configured: true,
      state: 'syncing'
    })
    expect(onSyncChanged).toHaveBeenNthCalledWith(2, SYNC_RESULT)
    expect(onVaultChanged).toHaveBeenCalledOnce()
  })

  it('runs one more sync when a request arrives while syncing', async () => {
    const firstSync = createDeferred<SyncResult>()
    const { coordinator, syncStatus, syncNow } = createHarness()
    syncNow.mockReturnValueOnce(firstSync.promise).mockResolvedValueOnce(SYNC_RESULT)

    coordinator.request()
    await vi.advanceTimersByTimeAsync(250)
    expect(syncNow).toHaveBeenCalledTimes(1)

    coordinator.request()
    coordinator.request()
    firstSync.resolve(SYNC_RESULT)
    await vi.advanceTimersByTimeAsync(0)

    expect(syncStatus).toHaveBeenCalledTimes(1)
    expect(syncNow).toHaveBeenCalledTimes(1)

    await vi.advanceTimersByTimeAsync(250)

    expect(syncStatus).toHaveBeenCalledTimes(2)
    expect(syncNow).toHaveBeenCalledTimes(2)
  })

  it('does not overlap a manual sync and retains one coalesced request', async () => {
    const { coordinator, syncStatus, syncNow } = createHarness()
    syncStatus
      .mockResolvedValueOnce({ configured: true, state: 'syncing' })
      .mockResolvedValueOnce({ configured: true, state: 'syncing' })
      .mockResolvedValueOnce(READY_STATUS)

    coordinator.requestImmediate()
    coordinator.request()
    await vi.advanceTimersByTimeAsync(0)
    expect(syncNow).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(250)
    expect(syncNow).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(250)
    expect(syncNow).toHaveBeenCalledOnce()
  })

  it('cancels fallback work for locked or disconnected status and restarts after unlock', async () => {
    const { coordinator, syncNow } = createHarness(250, {
      safetyMinDelayMs: 1_000,
      safetyMaxDelayMs: 1_000
    })

    coordinator.updateStatus(READY_STATUS)
    coordinator.updateStatus({ configured: true, state: 'locked' })
    await vi.advanceTimersByTimeAsync(2_000)
    expect(syncNow).not.toHaveBeenCalled()

    coordinator.updateStatus({ configured: false, state: 'unconfigured' })
    coordinator.updateStatus(READY_STATUS)
    await vi.advanceTimersByTimeAsync(1_000)
    expect(syncNow).toHaveBeenCalledOnce()
  })

  it('uses epochs to prevent an in-flight sync from restarting timers after cancel or dispose', async () => {
    const pending = createDeferred<SyncResult>()
    const cancelled = createHarness(250, {
      safetyMinDelayMs: 1_000,
      safetyMaxDelayMs: 1_000
    })
    cancelled.syncNow.mockReturnValueOnce(pending.promise)
    cancelled.coordinator.requestImmediate()
    await vi.advanceTimersByTimeAsync(0)
    cancelled.coordinator.cancel()
    pending.resolve(SYNC_RESULT)
    await vi.advanceTimersByTimeAsync(2_000)
    expect(cancelled.syncNow).toHaveBeenCalledOnce()

    const disposedPending = createDeferred<SyncResult>()
    const disposed = createHarness(250, {
      safetyMinDelayMs: 1_000,
      safetyMaxDelayMs: 1_000
    })
    disposed.syncNow.mockReturnValueOnce(disposedPending.promise)
    disposed.coordinator.requestImmediate()
    await vi.advanceTimersByTimeAsync(0)
    disposed.coordinator.dispose()
    disposedPending.resolve(SYNC_RESULT)
    await vi.advanceTimersByTimeAsync(2_000)
    expect(disposed.syncNow).toHaveBeenCalledOnce()
  })

  it('honors a new-epoch request queued while a cancelled run is still settling', async () => {
    const pending = createDeferred<SyncResult>()
    const { coordinator, syncNow } = createHarness()
    syncNow.mockReturnValueOnce(pending.promise).mockResolvedValueOnce(SYNC_RESULT)

    coordinator.requestImmediate()
    await vi.advanceTimersByTimeAsync(0)
    coordinator.cancel()
    coordinator.requestImmediate()

    pending.resolve(SYNC_RESULT)
    await vi.advanceTimersByTimeAsync(0)
    expect(syncNow).toHaveBeenCalledTimes(2)
  })

  it('contains renderer callback failures without interrupting periodic synchronization', async () => {
    const { coordinator, syncNow, onSyncChanged, onVaultChanged } = createHarness(250, {
      safetyMinDelayMs: 1_000,
      safetyMaxDelayMs: 1_000
    })
    onSyncChanged.mockImplementation(() => {
      throw new Error('renderer unavailable')
    })
    onVaultChanged.mockImplementation(() => {
      throw new Error('renderer unavailable')
    })

    coordinator.updateStatus(READY_STATUS)
    await vi.advanceTimersByTimeAsync(2_000)
    expect(syncNow).toHaveBeenCalledTimes(2)
  })

  it('cancel and dispose clear scheduled syncs', async () => {
    const cancelled = createHarness()
    cancelled.coordinator.request()
    cancelled.coordinator.cancel()

    const disposed = createHarness()
    disposed.coordinator.request()
    disposed.coordinator.dispose()
    disposed.coordinator.request()

    await vi.advanceTimersByTimeAsync(1_000)

    expect(cancelled.syncStatus).not.toHaveBeenCalled()
    expect(cancelled.syncNow).not.toHaveBeenCalled()
    expect(disposed.syncStatus).not.toHaveBeenCalled()
    expect(disposed.syncNow).not.toHaveBeenCalled()
  })
})
