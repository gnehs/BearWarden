import type { SyncStatus } from '../../../shared/vault-contract'
import { createStore, type StoreApi } from 'zustand/vanilla'

export interface SyncStatusState {
  status: SyncStatus
  loaded: boolean
}

export interface SyncStatusActions {
  setStatus: (status: SyncStatus) => void
  refreshStatus: (read: () => Promise<SyncStatus>) => Promise<void>
  reset: () => void
  activate: () => void
  dispose: () => void
}

export type SyncStatusStore = SyncStatusState & SyncStatusActions
export type SyncStatusStoreApi = StoreApi<SyncStatusStore>

export interface SyncStatusSubscriptionApi {
  status: () => Promise<SyncStatus>
  onChanged: (listener: (status: SyncStatus) => void) => () => void
}

function createInitialState(): SyncStatusState {
  return {
    status: { configured: false, state: 'unconfigured' },
    loaded: false
  }
}

export function createSyncStatusStore(): SyncStatusStoreApi {
  return createStore<SyncStatusStore>()((set) => {
    let active = true
    let generation = 0

    const setStatus = (status: SyncStatus): void => {
      if (active) set({ status, loaded: true })
    }

    return {
      ...createInitialState(),
      setStatus,
      refreshStatus: async (read) => {
        const requestGeneration = generation
        const status = await Promise.resolve().then(read)
        if (active && requestGeneration === generation) setStatus(status)
      },
      reset: () => set(createInitialState()),
      activate: () => {
        active = true
        generation += 1
      },
      dispose: () => {
        active = false
        generation += 1
        set(createInitialState())
      }
    }
  })
}

export function startSyncStatusSubscription(
  store: SyncStatusStoreApi,
  api: SyncStatusSubscriptionApi
): () => void {
  let active = true
  let eventReceived = false
  store.getState().activate()

  const unsubscribe = api.onChanged((status) => {
    if (!active) return
    eventReceived = true
    store.getState().setStatus(status)
  })

  try {
    void api.status().then(
      (status) => {
        if (!active || eventReceived) return
        store.getState().setStatus(status)
      },
      () => undefined
    )
  } catch {
    // A synchronous snapshot failure must not tear down the event subscription.
  }

  return () => {
    if (!active) return
    active = false
    unsubscribe()
    store.getState().dispose()
  }
}
