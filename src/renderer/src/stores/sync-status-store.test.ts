import { describe, expect, it, vi } from 'vitest'
import type { SyncStatus } from '../../../shared/vault-contract'
import {
  createSyncStatusStore,
  startSyncStatusSubscription,
  type SyncStatusSubscriptionApi
} from './sync-status-store'

const initialStatus: SyncStatus = { configured: false, state: 'unconfigured' }
const readyStatus: SyncStatus = { configured: true, state: 'ready', lastSyncAt: '2026-07-22' }

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

describe('sync status store', () => {
  it('starts unloaded and resets to the unconfigured state', () => {
    const store = createSyncStatusStore()
    const firstInitialStatus = store.getState().status

    expect(store.getState()).toMatchObject({ status: initialStatus, loaded: false })

    store.getState().setStatus(readyStatus)
    expect(store.getState()).toMatchObject({ status: readyStatus, loaded: true })

    store.getState().reset()
    expect(store.getState()).toMatchObject({ status: initialStatus, loaded: false })
    expect(store.getState().status).not.toBe(firstInitialStatus)
  })

  it('subscribes before reading the snapshot and accepts the snapshot without an event', async () => {
    const store = createSyncStatusStore()
    const calls: string[] = []
    const api: SyncStatusSubscriptionApi = {
      onChanged: vi.fn(() => {
        calls.push('subscribe')
        return vi.fn()
      }),
      status: vi.fn(async () => {
        calls.push('snapshot')
        return readyStatus
      })
    }

    const cleanup = startSyncStatusSubscription(store, api)
    await Promise.resolve()

    expect(calls).toEqual(['subscribe', 'snapshot'])
    expect(store.getState()).toMatchObject({ status: readyStatus, loaded: true })
    cleanup()
  })

  it('keeps an event delivered synchronously while subscribing', async () => {
    const store = createSyncStatusStore()
    const eventStatus: SyncStatus = { configured: true, state: 'locked' }
    const api: SyncStatusSubscriptionApi = {
      onChanged: vi.fn((listener) => {
        listener(eventStatus)
        return vi.fn()
      }),
      status: vi.fn(async () => readyStatus)
    }

    const cleanup = startSyncStatusSubscription(store, api)
    await Promise.resolve()

    expect(store.getState()).toMatchObject({ status: eventStatus, loaded: true })
    cleanup()
  })

  it('keeps an event that races ahead of a later snapshot', async () => {
    const store = createSyncStatusStore()
    const snapshot = deferred<SyncStatus>()
    let listener!: (status: SyncStatus) => void
    const api: SyncStatusSubscriptionApi = {
      onChanged: vi.fn((nextListener) => {
        listener = nextListener
        return vi.fn()
      }),
      status: vi.fn(() => snapshot.promise)
    }
    const eventStatus: SyncStatus = { configured: true, state: 'syncing' }

    const cleanup = startSyncStatusSubscription(store, api)
    listener(eventStatus)
    snapshot.resolve(readyStatus)
    await snapshot.promise
    await Promise.resolve()

    expect(store.getState()).toMatchObject({ status: eventStatus, loaded: true })
    cleanup()
  })

  it('rejects event and snapshot writes after cleanup', async () => {
    const store = createSyncStatusStore()
    const snapshot = deferred<SyncStatus>()
    const unsubscribe = vi.fn()
    let listener!: (status: SyncStatus) => void
    const api: SyncStatusSubscriptionApi = {
      onChanged: vi.fn((nextListener) => {
        listener = nextListener
        return unsubscribe
      }),
      status: vi.fn(() => snapshot.promise)
    }

    const cleanup = startSyncStatusSubscription(store, api)
    cleanup()
    cleanup()
    listener({ configured: true, state: 'syncing' })
    snapshot.resolve(readyStatus)
    await snapshot.promise
    await Promise.resolve()

    expect(unsubscribe).toHaveBeenCalledOnce()
    expect(store.getState()).toMatchObject({ status: initialStatus, loaded: false })
  })

  it('rejects a manual refresh from a disposed session after reactivation', async () => {
    const store = createSyncStatusStore()
    const snapshot = deferred<SyncStatus>()

    store.getState().activate()
    const refresh = store.getState().refreshStatus(() => snapshot.promise)
    store.getState().dispose()
    store.getState().activate()
    snapshot.resolve(readyStatus)
    await refresh

    expect(store.getState()).toMatchObject({ status: initialStatus, loaded: false })
  })
})
