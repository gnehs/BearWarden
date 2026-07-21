import { describe, expect, it } from 'vitest'
import type { LoginSummary } from '../../../shared/vault-contract'
import {
  cacheLoginDetail,
  firstAuthorizationToken,
  mergeCachedSummary,
  mergeLoginSummary,
  toLoginSummary
} from './vault-detail-cache'
import { makeLoginView } from './vault-detail-test-fixtures'

describe('mergeLoginSummary', () => {
  it('does not replace protected detail fields with redacted summary values', () => {
    const login = makeLoginView()
    const summary: LoginSummary = {
      ...toLoginSummary(login),
      name: 'Renamed item',
      username: '',
      uri: null,
      uris: [],
      favorite: true,
      reprompt: 1
    }

    const merged = mergeLoginSummary(login, summary)

    expect(merged.name).toBe('Renamed item')
    expect(merged.favorite).toBe(true)
    expect(merged.reprompt).toBe(1)
    expect(merged.username).toBe('sample-user')
    expect(merged.uri).toBe('https://example.invalid')
    expect(merged.uris).toEqual([{ uri: 'https://example.invalid', match: null }])
  })

  it('accepts complete public and deleted summaries', () => {
    const login = makeLoginView()
    const publicSummary = { ...toLoginSummary(login), username: 'updated-user' }
    const deletedSummary = {
      ...toLoginSummary(login),
      username: '',
      uris: [],
      deletedAt: '2026-07-17T00:00:00.000Z',
      reprompt: 1 as const
    }

    expect(mergeLoginSummary(login, publicSummary).username).toBe('updated-user')
    expect(mergeLoginSummary(login, deletedSummary).username).toBe('')
    expect(mergeLoginSummary(login, deletedSummary).uris).toEqual([])
  })
})

describe('detail cache helpers', () => {
  it('updates cached summaries without adding missing detail entries', () => {
    const cache = new Map([['item-id', makeLoginView()]])

    mergeCachedSummary(cache, { ...toLoginSummary(makeLoginView()), name: 'Updated name' })
    mergeCachedSummary(cache, toLoginSummary(makeLoginView({ id: 'missing' })))

    expect(cache.get('item-id')?.name).toBe('Updated name')
    expect(cache.has('missing')).toBe(false)
  })

  it('refreshes recency and evicts the oldest detail at the cache limit', () => {
    const cache = new Map<string, ReturnType<typeof makeLoginView>>()
    for (let index = 0; index < 48; index += 1) {
      cacheLoginDetail(cache, makeLoginView({ id: `item-${index}` }))
    }

    cacheLoginDetail(cache, makeLoginView({ id: 'item-0', name: 'Recently used' }))
    cacheLoginDetail(cache, makeLoginView({ id: 'item-48' }))

    expect(cache.size).toBe(48)
    expect(cache.get('item-0')?.name).toBe('Recently used')
    expect(cache.has('item-1')).toBe(false)
    expect(cache.has('item-48')).toBe(true)
  })
})

describe('summary and authorization projections', () => {
  it('creates an independent URI summary and preserves optional fields', () => {
    const login = makeLoginView({ cardBrand: 'visa', passkeyCount: 2 })
    const summary = toLoginSummary(login)

    expect(summary.cardBrand).toBe('visa')
    expect(summary.passkeyCount).toBe(2)
    expect(summary.uris).toEqual(login.uris)
    expect(summary.uris).not.toBe(login.uris)
    expect(summary.uris[0]).not.toBe(login.uris[0])
  })

  it('returns the first available authorization token in item order', () => {
    const tokens = new Map([
      ['second', 'second-token'],
      ['third', 'third-token']
    ])

    expect(firstAuthorizationToken(['first', 'second', 'third'], (id) => tokens.get(id))).toBe(
      'second-token'
    )
    expect(firstAuthorizationToken(['first'], (id) => tokens.get(id))).toBeUndefined()
  })
})
