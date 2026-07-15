import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { SyncResult, SyncStatus } from '../shared/vault-contract'
import { AutoSyncCoordinator, type AutoSyncVault } from './auto-sync-coordinator'

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

function createHarness(delayMs = 250): {
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
    delayMs
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

  it('contains sync failures and reports the resulting error status', async () => {
    const { coordinator, syncStatus, syncNow, onSyncChanged, onVaultChanged } = createHarness()
    const errorStatus: SyncStatus = {
      configured: true,
      state: 'error',
      lastError: 'Test sync failed'
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

  it('retries a configured error state so transient failures can recover', async () => {
    const { coordinator, syncStatus, syncNow, onSyncChanged, onVaultChanged } = createHarness()
    syncStatus.mockResolvedValue({
      configured: true,
      state: 'error',
      lastError: 'Previous transient failure'
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
