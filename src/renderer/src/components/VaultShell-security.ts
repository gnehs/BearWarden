import type { LoginSummary } from '../../../shared/vault-contract'

export function protectedDetailInvalidationIds(
  summaries: readonly LoginSummary[],
  hasAuthorization: (id: string) => boolean
): Set<string> {
  return new Set(
    summaries
      .filter((summary) => summary.reprompt === 1 && !hasAuthorization(summary.id))
      .map((summary) => summary.id)
  )
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
