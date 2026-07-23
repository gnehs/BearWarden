import {
  MAX_LOGIN_SEARCH_QUERY_LENGTH,
  type LoginListRequest,
  type LoginSummary,
  type SharedLoginSummary
} from '../../../shared/vault-contract'
import { matchesVaultCategory, type VaultCategoryFilter } from './vault-category'

export const MAX_VAULT_SEARCH_QUERY_LENGTH = MAX_LOGIN_SEARCH_QUERY_LENGTH
export const VAULT_SEARCH_DEBOUNCE_MS = 100

export interface VaultSearchMatches {
  query: string
  ids: ReadonlySet<string>
}

export type VaultSearchNavigationScope =
  | { kind: 'all' }
  | { kind: 'favorites' }
  | { kind: 'folder'; folderId: string }
  | { kind: 'unfiled' }
  | { kind: 'shared' }
  | { kind: 'organization'; organizationId: string }
  | { kind: 'collection'; organizationId: string; collectionId: string }
  | { kind: 'archive' }
  | { kind: 'trash' }

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

export function matchesVaultSearchNavigation(
  item: LoginSummary,
  query: string,
  scope: VaultSearchNavigationScope,
  category: VaultCategoryFilter
): boolean {
  if (scope.kind === 'trash') {
    if (!item.deletedAt) return false
  } else if (scope.kind === 'archive') {
    if (item.deletedAt || !item.archivedAt) return false
  } else if (item.deletedAt || item.archivedAt) {
    return false
  }

  if (normalizedVaultSearchQuery(query)) return true
  const sharedItem =
    'shared' in item && item.shared === true && 'organizationId' in item && 'collectionIds' in item
      ? (item as unknown as SharedLoginSummary)
      : null
  if (scope.kind === 'shared' && !sharedItem) return false
  if (scope.kind === 'organization' && sharedItem?.organizationId !== scope.organizationId)
    return false
  if (
    scope.kind === 'collection' &&
    (sharedItem?.organizationId !== scope.organizationId ||
      !sharedItem.collectionIds.includes(scope.collectionId))
  )
    return false
  if (scope.kind === 'favorites' && !item.favorite) return false
  if (scope.kind === 'folder' && item.folderId !== scope.folderId) return false
  if (scope.kind === 'unfiled' && item.folderId !== null) return false
  return matchesVaultCategory(item, category)
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
