import { create } from 'zustand'
import type { VaultState } from '../../../shared/vault-contract'

export type AppVaultState = VaultState | 'loading' | 'unavailable'

interface VaultRuntimeState {
  vaultState: AppVaultState
  statusAttempt: number
  applyVaultState: (vaultState: AppVaultState) => void
  retryVaultStatus: () => void
}

export const useVaultRuntimeStore = create<VaultRuntimeState>()((set) => ({
  vaultState: 'loading',
  statusAttempt: 0,
  applyVaultState: (vaultState) => set({ vaultState }),
  retryVaultStatus: () =>
    set((state) => ({
      vaultState: 'loading',
      statusAttempt: state.statusAttempt + 1
    }))
}))
