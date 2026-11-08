import { useEffect, useState } from 'react'
import type { LoginView } from '../../../shared/vault-contract'
import { createLoginDetailCache, type LoginDetailCache } from '../components/vault-detail-cache'
import type { VaultAuthorization } from '@renderer/stores/vault-authorization-store'
import { findVaultItem, useVaultSessionStoreApi } from '@renderer/stores/vault-session-store'

/**
 * The session's decrypted-detail cache. It forgets an item as soon as its authorization is
 * revoked and empties itself when the vault session unmounts.
 */
export function useLoginDetailCache(
  authorization: VaultAuthorization,
  onPrefetched: (login: LoginView) => void
): LoginDetailCache {
  const sessionStore = useVaultSessionStoreApi()
  const [cache] = useState(() =>
    createLoginDetailCache({
      logins: window.bearwarden.logins,
      sharedLogins: window.bearwarden.sharedLogins,
      authorization,
      findItem: (id) => findVaultItem(sessionStore.getState(), id),
      selectedId: () => sessionStore.getState().selectedId,
      onPrefetched
    })
  )
  useEffect(() => {
    const unsubscribe = authorization.subscribeRevoked((id) => cache.invalidate([id]))
    return () => {
      unsubscribe()
      cache.clear()
    }
  }, [authorization, cache])
  return cache
}
