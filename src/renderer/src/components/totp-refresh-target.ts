interface TotpRefreshSource {
  id: string
  hasTotp: boolean
  updatedAt: string
  deletedAt: string | null
}

export interface TotpRefreshTarget {
  itemId: string
  sourceRevision: string
}

export function resolveTotpRefreshTarget(
  login: TotpRefreshSource | null,
  selectedId: string | null,
  editorMode: boolean
): TotpRefreshTarget | null {
  if (!login?.hasTotp || login.deletedAt || login.id !== selectedId || editorMode) return null
  return { itemId: login.id, sourceRevision: login.updatedAt }
}
