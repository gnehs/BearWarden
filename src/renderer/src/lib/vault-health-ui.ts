import type { LoginSummary, VaultHealthWeakFinding } from '../../../shared/vault-contract'

export function weakPasswordLabel(score: VaultHealthWeakFinding['score']): string {
  return score <= 1 ? '非常弱' : '弱'
}

export function vaultHealthRevision(items: readonly LoginSummary[]): string {
  return items
    .map((item) =>
      [
        item.id,
        item.type,
        item.updatedAt,
        item.deletedAt ?? '',
        item.archivedAt ?? '',
        String(item.reprompt)
      ].join('\0')
    )
    .sort()
    .join('\n')
}
