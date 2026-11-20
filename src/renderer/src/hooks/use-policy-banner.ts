import { useCallback } from 'react'
import { useStore } from 'zustand'
import type { PolicyBannerView } from '../../../shared/vault-contract'
import { useVaultSessionStoreApi } from '@renderer/stores/vault-session-store'

export interface PolicyBannerState {
  banner: PolicyBannerView | null
  dismiss: () => void
}

/**
 * Exposes the organization banner the session store loaded and dismisses it. The banner leaves
 * the screen immediately; main persists the dismissal against the exact revision the user saw,
 * so a newer revision loaded in the meantime is not hidden by this click.
 */
export function usePolicyBanner(): PolicyBannerState {
  const session = useVaultSessionStoreApi()
  const banner = useStore(session, (state) => state.policyBanner)
  const dismiss = useCallback(() => {
    const current = session.getState().policyBanner
    if (current === null) return
    session.getState().setPolicyBanner((shown) => (shown?.key === current.key ? null : shown))
    void window.bearwarden.policyBanner.dismiss({ key: current.key }).catch(() => undefined)
  }, [session])
  return { banner, dismiss }
}
