import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { Dispatch, RefObject, SetStateAction } from 'react'
import type { LoginSummary } from '../../../shared/vault-contract'
import type { VaultCategoryFilter } from '@renderer/lib/vault-category'
import {
  boundedVaultSearchQuery,
  filterVaultSearchMatches,
  isCurrentVaultSearchResponse,
  matchesVaultSearchNavigation,
  normalizedVaultSearchQuery,
  VAULT_SEARCH_DEBOUNCE_MS,
  vaultSearchListRequests,
  type VaultSearchMatches,
  type VaultSearchNavigationScope
} from '@renderer/lib/vault-search-ui'
import { sortVaultItems, type VaultSortMode } from '@renderer/lib/vault-sort'

interface UseVaultSearchOptions {
  items: LoginSummary[]
  scope: VaultSearchNavigationScope
  typeFilter: VaultCategoryFilter
  sortMode: VaultSortMode
  query: string
  setQuery: Dispatch<SetStateAction<string>>
  describeError: (error: unknown) => string
  onError: (message: string) => void
}

interface VaultSearchState {
  searchOpen: boolean
  searchRef: RefObject<HTMLInputElement | null>
  scopedItems: LoginSummary[]
  updateQuery: (value: string) => void
  setSearchOpen: Dispatch<SetStateAction<boolean>>
}

export function useVaultSearch({
  items,
  scope,
  typeFilter,
  sortMode,
  query,
  setQuery,
  describeError,
  onError
}: UseVaultSearchOptions): VaultSearchState {
  const [searchMatches, setSearchMatches] = useState<VaultSearchMatches | null>(null)
  const [searchOpen, setSearchOpen] = useState(false)
  const searchRef = useRef<HTMLInputElement>(null)
  const queryRef = useRef(query)
  const searchRequestIdRef = useRef(0)

  const updateQuery = useCallback(
    (value: string): void => {
      const bounded = boundedVaultSearchQuery(value)
      queryRef.current = bounded
      setQuery(bounded)
    },
    [setQuery]
  )

  useEffect(() => {
    queryRef.current = query
  }, [query])

  useEffect(() => {
    const searchQuery = normalizedVaultSearchQuery(query)
    const requestId = ++searchRequestIdRef.current
    if (!searchQuery) return

    const timeout = window.setTimeout(() => {
      const [activeRequest, archivedRequest, deletedRequest] = vaultSearchListRequests(searchQuery)
      void Promise.all([
        window.bearwarden.logins.list(activeRequest),
        window.bearwarden.logins.list(archivedRequest),
        window.bearwarden.logins.list(deletedRequest)
      ]).then(
        ([activeItems, archivedItems, deletedItems]) => {
          if (
            !isCurrentVaultSearchResponse({
              requestId,
              currentRequestId: searchRequestIdRef.current,
              query: searchQuery,
              currentQuery: queryRef.current
            })
          ) {
            return
          }
          setSearchMatches({
            query: searchQuery,
            ids: new Set([...activeItems, ...archivedItems, ...deletedItems].map((item) => item.id))
          })
        },
        (searchError) => {
          if (
            !isCurrentVaultSearchResponse({
              requestId,
              currentRequestId: searchRequestIdRef.current,
              query: searchQuery,
              currentQuery: queryRef.current
            })
          ) {
            return
          }
          setSearchMatches({ query: searchQuery, ids: new Set() })
          onError(describeError(searchError))
        }
      )
    }, VAULT_SEARCH_DEBOUNCE_MS)

    return () => window.clearTimeout(timeout)
  }, [describeError, items, onError, query])

  const scopedItems = useMemo(() => {
    const matchedItems = filterVaultSearchMatches(items, query, searchMatches)
    const scoped = matchedItems.filter((item) =>
      matchesVaultSearchNavigation(item, query, scope, typeFilter)
    )
    return sortVaultItems(scoped, scope.kind === 'recent' ? 'recent' : sortMode)
  }, [items, query, scope, searchMatches, sortMode, typeFilter])

  return { searchOpen, searchRef, scopedItems, updateQuery, setSearchOpen }
}
