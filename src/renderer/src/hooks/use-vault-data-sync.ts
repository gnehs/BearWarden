import { useEffect, useEffectEvent, useState } from 'react'
import type { LoginDetailCache } from '../components/vault-detail-cache'
import type { VaultAuthorization } from '@renderer/stores/vault-authorization-store'
import {
  createVaultDataSync,
  type VaultDataSync,
  type VaultDataSyncEvents
} from '@renderer/stores/vault-data-sync'
import { useVaultSessionStoreApi } from '@renderer/stores/vault-session-store'

/**
 * Loads the vault lists when the session mounts and again on every `vault:changed`
 * broadcast. Components read the lists from the session store and call `refreshItems`
 * after a mutation instead of listing through IPC themselves.
 */
export function useVaultDataSync(
  authorization: VaultAuthorization,
  detailCache: LoginDetailCache,
  events: VaultDataSyncEvents
): VaultDataSync {
  const session = useVaultSessionStoreApi()
  const [sync] = useState(() =>
    createVaultDataSync({
      api: window.bearwarden,
      session,
      detailCache,
      hasAuthorization: (id) => Boolean(authorization.token(id))
    })
  )
  const selectedDetailInvalidated = useEffectEvent(events.selectedDetailInvalidated)
  const loadStarted = useEffectEvent(events.loadStarted)
  const loadFailed = useEffectEvent(events.loadFailed)
  useEffect(() => {
    const unsubscribeEvents = sync.subscribe({
      selectedDetailInvalidated: () => selectedDetailInvalidated(),
      loadStarted: () => loadStarted(),
      loadFailed: (error) => loadFailed(error)
    })
    queueMicrotask(() => void sync.load())
    const unsubscribeChanges = window.bearwarden.vault.onChanged(() => void sync.load())
    return () => {
      unsubscribeChanges()
      unsubscribeEvents()
      sync.dispose()
    }
  }, [sync])
  return sync
}
