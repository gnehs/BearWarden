import {
  MAX_LOGIN_SEARCH_QUERY_LENGTH,
  type LoginListRequest,
  type LoginSummary
} from '../../../shared/vault-contract'

export const MAX_VAULT_SEARCH_QUERY_LENGTH = MAX_LOGIN_SEARCH_QUERY_LENGTH
export const VAULT_SEARCH_DEBOUNCE_MS = 100

export interface VaultSearchMatches {
  query: string
  ids: ReadonlySet<string>
}

export function boundedVaultSearchQuery(value: string): string {
  return value.slice(0, MAX_VAULT_SEARCH_QUERY_LENGTH)
}

export function normalizedVaultSearchQuery(value: string): string {
  return boundedVaultSearchQuery(value).trim()
}

export function vaultSearchListRequests(
  query: string
): readonly [LoginListRequest, LoginListRequest, LoginListRequest] {
  const normalizedQuery = normalizedVaultSearchQuery(query)
  return [
    { sort: 'name', query: normalizedQuery },
    { sort: 'name', archived: true, query: normalizedQuery },
    { sort: 'name', deleted: true, query: normalizedQuery }
  ]
}

export function filterVaultSearchMatches(
  items: readonly LoginSummary[],
  query: string,
  matches: VaultSearchMatches | null
): LoginSummary[] {
  const normalizedQuery = normalizedVaultSearchQuery(query)
  if (!normalizedQuery) return [...items]
  if (matches?.query !== normalizedQuery) return []
  return items.filter((item) => matches.ids.has(item.id))
}

export function isCurrentVaultSearchResponse(input: {
  requestId: number
  currentRequestId: number
  query: string
  currentQuery: string
}): boolean {
  return (
    input.requestId === input.currentRequestId &&
    normalizedVaultSearchQuery(input.query) === normalizedVaultSearchQuery(input.currentQuery)
  )
}
