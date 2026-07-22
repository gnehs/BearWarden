import { describe, expect, it } from 'vitest'
import type { LoginSummary } from '../../../shared/vault-contract'
import {
  boundedVaultSearchQuery,
  filterVaultSearchMatches,
  isCurrentVaultSearchResponse,
  MAX_VAULT_SEARCH_QUERY_LENGTH,
  matchesVaultSearchNavigation,
  vaultSearchListRequests
} from './vault-search-ui'

function summary(id: string, overrides: Partial<LoginSummary> = {}): LoginSummary {
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
    usageCount: 0,
    lastUsedAt: null,
    createdAt: '2026-07-16T00:00:00.000Z',
    updatedAt: '2026-07-16T00:00:00.000Z',
    deletedAt: null,
    archivedAt: null,
    reprompt: 0,
    ...overrides
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

  it('does not restrict active header search results to the current navigation filter', () => {
    const item = summary('card', {
      type: 'card',
      folderId: 'other-folder',
      favorite: false,
      lastUsedAt: null
    })

    expect(
      matchesVaultSearchNavigation(
        item,
        ' card ',
        { kind: 'folder', folderId: 'selected' },
        'login'
      )
    ).toBe(true)
    expect(matchesVaultSearchNavigation(item, 'card', { kind: 'favorites' }, 'totp')).toBe(true)
    expect(matchesVaultSearchNavigation(item, 'card', { kind: 'all' }, 'passkey')).toBe(true)
  })

  it('keeps lifecycle boundaries while searching globally across categories', () => {
    const active = summary('active')
    const archived = summary('archived', { archivedAt: '2026-07-17T00:00:00.000Z' })
    const deleted = summary('deleted', { deletedAt: '2026-07-17T00:00:00.000Z' })

    expect(matchesVaultSearchNavigation(active, 'vault', { kind: 'all' }, 'card')).toBe(true)
    expect(matchesVaultSearchNavigation(archived, 'vault', { kind: 'all' }, 'all')).toBe(false)
    expect(matchesVaultSearchNavigation(deleted, 'vault', { kind: 'all' }, 'all')).toBe(false)
    expect(matchesVaultSearchNavigation(archived, 'vault', { kind: 'archive' }, 'card')).toBe(true)
    expect(matchesVaultSearchNavigation(deleted, 'vault', { kind: 'trash' }, 'card')).toBe(true)
  })

  it('preserves navigation filtering for empty and whitespace-only searches', () => {
    const card = summary('card', { type: 'card', folderId: 'other-folder' })

    expect(
      matchesVaultSearchNavigation(card, '', { kind: 'folder', folderId: 'selected' }, 'all')
    ).toBe(false)
    expect(matchesVaultSearchNavigation(card, '   ', { kind: 'all' }, 'login')).toBe(false)
    expect(matchesVaultSearchNavigation(card, '   ', { kind: 'all' }, 'card')).toBe(true)
  })
})
