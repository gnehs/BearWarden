import type { LoginSummary, SharedLoginSummary } from '../../../shared/vault-contract'

export function isSharedLoginSummary(item: LoginSummary): item is SharedLoginSummary {
  return 'shared' in item && item.shared === true
}
