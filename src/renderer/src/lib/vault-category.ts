import type { LoginSummary, VaultItemType } from '../../../shared/vault-contract'

export type VaultCategoryFilter = VaultItemType | 'all' | 'totp' | 'passkey'

/** Passkeys and TOTP are derived views of login items, never standalone item types. */
export function matchesVaultCategory(
  item: Pick<LoginSummary, 'type' | 'hasTotp' | 'passkeyCount'>,
  category: VaultCategoryFilter
): boolean {
  if (category === 'all') return true
  if (category === 'totp') return item.type === 'login' && Boolean(item.hasTotp)
  if (category === 'passkey') return item.type === 'login' && Boolean(item.passkeyCount)
  return item.type === category
}
