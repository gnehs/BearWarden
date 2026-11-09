import { useCallback, useEffect, useState } from 'react'
import { useStore } from 'zustand'
import type { SyncStatus } from '../../../shared/vault-contract'
import {
  createSyncStatusStore,
  startSyncStatusSubscription
} from '@renderer/stores/sync-status-store'

export interface SyncStatusState {
  status: SyncStatus
  loaded: boolean
  setStatus: (status: SyncStatus) => void
  refresh: () => Promise<void>
}

/** Sync status for the vault session, kept current by the main process's change events. */
export function useSyncStatus(): SyncStatusState {
  const [store] = useState(() => createSyncStatusStore())
  useEffect(() => startSyncStatusSubscription(store, window.bearwarden.sync), [store])
  const status = useStore(store, (state) => state.status)
  const loaded = useStore(store, (state) => state.loaded)
  const setStatus = useStore(store, (state) => state.setStatus)
  const refresh = useCallback(
    () => store.getState().refreshStatus(() => window.bearwarden.sync.status()),
    [store]
  )
  return { status, loaded, setStatus, refresh }
}
