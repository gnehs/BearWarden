import { useEffect, useState } from 'react'
import { useStore } from 'zustand'
import {
  createVaultAuthorization,
  type VaultAuthorization,
  type VaultAuthorizationState
} from '@renderer/stores/vault-authorization-store'
import { findVaultItem, useVaultSessionStoreApi } from '@renderer/stores/vault-session-store'

/** Reprompt authorization scoped to the mounted vault session. */
export function useVaultAuthorization(): VaultAuthorizationState & {
  authorization: VaultAuthorization
} {
  const sessionStore = useVaultSessionStoreApi()
  const [authorization] = useState(() =>
    createVaultAuthorization({
      authorizeMany: (request) => window.bearwarden.logins.authorizeMany(request),
      findItem: (id) => findVaultItem(sessionStore.getState(), id)
    })
  )
  useEffect(() => {
    authorization.activate()
    return () => authorization.dispose()
  }, [authorization])
  const state = useStore(authorization.store)
  return { authorization, ...state }
}
