import { describe, expect, it } from 'vitest'
import type { LoginSummary } from '../../../shared/vault-contract'
import {
  boundedVaultSearchQuery,
  filterVaultSearchMatches,
  isCurrentVaultSearchResponse,
  MAX_VAULT_SEARCH_QUERY_LENGTH,
  vaultSearchListRequests
} from './vault-search-ui'

function summary(id: string): LoginSummary {
  return {
    id,
    type: 'login',
    name: id,
    subtitle: '',
    username: '',
    uri: null,
    uris: [],
    hasTotp: false,
    passkeyCount: 0,
    passwordHistoryCount: 0,
    attachmentCount: 0,
    folderId: null,
    favorite: false,
    lastUsedAt: null,
    createdAt: '2026-07-16T00:00:00.000Z',
    updatedAt: '2026-07-16T00:00:00.000Z',
    deletedAt: null,
    archivedAt: null,
    reprompt: 0
  }
}

describe('vault search renderer policy', () => {
  it('shows only main-process matches and fails closed while a newer query is pending', () => {
    const items = [summary('one'), summary('two')]
    expect(filterVaultSearchMatches(items, '', null)).toEqual(items)
    expect(filterVaultSearchMatches(items, 'new', { query: 'old', ids: new Set(['one']) })).toEqual(
      []
    )
    expect(
      filterVaultSearchMatches(items, ' new ', { query: 'new', ids: new Set(['two']) })
    ).toEqual([items[1]])
  })

  it('rejects stale or same-query responses from an older request generation', () => {
    expect(
      isCurrentVaultSearchResponse({
        requestId: 4,
        currentRequestId: 4,
        query: '  vault ',
        currentQuery: 'vault'
      })
    ).toBe(true)
    expect(
      isCurrentVaultSearchResponse({
        requestId: 3,
        currentRequestId: 4,
        query: 'vault',
        currentQuery: 'vault'
      })
    ).toBe(false)
    expect(
      isCurrentVaultSearchResponse({
        requestId: 4,
        currentRequestId: 4,
        query: 'old',
        currentQuery: 'new'
      })
    ).toBe(false)
  })

  it('bounds renderer input to the main-process contract limit', () => {
    expect(boundedVaultSearchQuery('x'.repeat(MAX_VAULT_SEARCH_QUERY_LENGTH + 10))).toHaveLength(
      MAX_VAULT_SEARCH_QUERY_LENGTH
    )
  })

  it('searches active, archived, and deleted scopes through the main process', () => {
    expect(vaultSearchListRequests('  github  ')).toEqual([
      { sort: 'name', query: 'github' },
      { sort: 'name', archived: true, query: 'github' },
      { sort: 'name', deleted: true, query: 'github' }
    ])
  })
})
