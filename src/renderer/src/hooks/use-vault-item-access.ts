import { useState } from 'react'
import { createVaultItemAccess, type VaultItemAccess } from '../components/vault-item-access'
import type { VaultAuthorization } from '@renderer/stores/vault-authorization-store'

/** Ownership-routed secret access for the session's items; see `createVaultItemAccess`. */
export function useVaultItemAccess(authorization: VaultAuthorization): VaultItemAccess {
  const [access] = useState(() =>
    createVaultItemAccess({
      logins: window.bearwarden.logins,
      sharedLogins: window.bearwarden.sharedLogins,
      authorization
    })
  )
  return access
}
