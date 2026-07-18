import type { LoginSummary } from '../../../shared/vault-contract'

export type VaultSortMode = 'title' | 'recent' | 'frequency' | 'modified'

function compareNullableDate(left: string | null, right: string | null): number {
  if (left === right) return 0
  if (left === null) return 1
  if (right === null) return -1
  return Date.parse(right) - Date.parse(left)
}

export function sortVaultItems(items: LoginSummary[], mode: VaultSortMode): LoginSummary[] {
  const collator = new Intl.Collator('zh-Hant', { numeric: true, sensitivity: 'base' })
  return [...items].sort((left, right) => {
    let result = 0
    if (mode === 'frequency') {
      result = right.usageCount - left.usageCount
      if (result === 0) result = compareNullableDate(left.lastUsedAt, right.lastUsedAt)
    }
    if (mode === 'recent') result = compareNullableDate(left.lastUsedAt, right.lastUsedAt)
    if (mode === 'modified') result = Date.parse(right.updatedAt) - Date.parse(left.updatedAt)
    if (result !== 0) return result
    const nameResult = collator.compare(left.name, right.name)
    return nameResult || left.id.localeCompare(right.id)
  })
}
