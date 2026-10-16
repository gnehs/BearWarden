import type { LoginView } from '../../../shared/vault-contract'
import { useVaultImageStore } from '../stores/vault-image-store'

interface CardCoverPreviews {
  previews: ReadonlyMap<string, string>
  clear: () => void
  invalidate: (itemId: string) => void
  prefetch: (login: LoginView) => void
  remember: (login: LoginView, attachmentId: string, dataUrl: string) => void
}

/**
 * Card faces for the vault list and card details. Entries are keyed by the item's `updatedAt`
 * and cover attachment id, so list refreshes keep them and a replaced cover reloads.
 */
export function useCardCoverPreviews(): CardCoverPreviews {
  const previews = useVaultImageStore((state) => state.cardCovers)
  const clear = useVaultImageStore((state) => state.clear)
  const invalidate = useVaultImageStore((state) => state.invalidateCardCover)
  const prefetch = useVaultImageStore((state) => state.prefetchCardCover)
  const remember = useVaultImageStore((state) => state.rememberCardCover)
  return { previews, clear, invalidate, prefetch, remember }
}
