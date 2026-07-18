import type { LoginSummary } from '../../../shared/vault-contract'

export function hasTrashPasswordHistory(summary: LoginSummary): boolean {
  return summary.deletedAt !== null && summary.passwordHistoryCount > 0
}

export function canUseCachedLoginDetail(
  summary: LoginSummary | undefined,
  cachedReprompt: 0 | 1,
  hasAuthorization: boolean
): boolean {
  return Boolean(
    summary && summary.deletedAt === null && (cachedReprompt === 0 || hasAuthorization)
  )
}

export function protectedDetailInvalidationIds(
  summaries: readonly LoginSummary[],
  hasAuthorization: (id: string) => boolean
): Set<string> {
  return new Set(
    summaries
      .filter(
        (summary) =>
          summary.deletedAt !== null || (summary.reprompt === 1 && !hasAuthorization(summary.id))
      )
      .map((summary) => summary.id)
  )
}

export function isCurrentVaultLoad(requestId: number, currentRequestId: number): boolean {
  return requestId === currentRequestId
}

export function isCurrentSelectedDetailResponse(input: {
  id: string
  selectedId: string | null
  requestGeneration: number
  currentGeneration: number
  reprompt: 0 | 1
  authorizationToken: string | undefined
}): boolean {
  return (
    input.id === input.selectedId &&
    input.requestGeneration === input.currentGeneration &&
    (input.reprompt === 0 || Boolean(input.authorizationToken))
  )
}
