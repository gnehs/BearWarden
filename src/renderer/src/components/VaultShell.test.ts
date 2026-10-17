import { describe, expect, it } from 'vitest'
import type { LoginSummary } from '../../../shared/vault-contract'
import {
  canUseCachedLoginDetail,
  hasTrashPasswordHistory,
  isCurrentPrefetchedDetailResponse,
  isCurrentVaultLoad,
  isCurrentSelectedDetailResponse,
  protectedDetailInvalidationIds
} from './VaultShell-security'

function summary(id: string, reprompt: 0 | 1): LoginSummary {
  return {
    id,
    type: 'login',
    name: id,
    subtitle: '',
    username: reprompt ? '' : 'user',
    uri: reprompt ? null : 'https://example.invalid',
    uris: reprompt ? [] : [{ uri: 'https://example.invalid', match: null }],
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
    reprompt
  }
}

describe('protectedDetailInvalidationIds', () => {
  it('immediately identifies protected summaries that no longer have a valid capability', () => {
    const summaries = [
      summary('newly-protected', 1),
      summary('authorized', 1),
      summary('public', 0)
    ]
    expect(protectedDetailInvalidationIds(summaries, (id) => id === 'authorized')).toEqual(
      new Set(['newly-protected'])
    )
  })

  it('treats every trashed summary as protected even when item reprompt is disabled', () => {
    const trashed = { ...summary('trashed', 0), deletedAt: '2026-07-17T00:00:00.000Z' }

    expect(protectedDetailInvalidationIds([trashed], () => false)).toEqual(new Set(['trashed']))
    expect(protectedDetailInvalidationIds([trashed], () => true)).toEqual(new Set(['trashed']))
    expect(canUseCachedLoginDetail(trashed, 0, true)).toBe(false)
    expect(hasTrashPasswordHistory(trashed)).toBe(false)
    expect(hasTrashPasswordHistory({ ...trashed, passwordHistoryCount: 1 })).toBe(true)
  })
})

describe('isCurrentVaultLoad', () => {
  it('accepts only the latest list request', () => {
    expect(isCurrentVaultLoad(4, 4)).toBe(true)
    expect(isCurrentVaultLoad(4, 5)).toBe(false)
  })
})

describe('isCurrentSelectedDetailResponse', () => {
  const current = {
    id: 'protected',
    selectedId: 'protected',
    requestGeneration: 7,
    currentGeneration: 7,
    reprompt: 1 as const,
    authorizationToken: 'short-lived' as string | undefined
  }

  it('accepts an authorized response for the selected item in the current generation', () => {
    expect(isCurrentSelectedDetailResponse(current)).toBe(true)
  })

  it.each([
    ['the selection changed', { selectedId: 'other' }],
    ['the detail generation advanced', { currentGeneration: 8 }],
    ['the reprompt capability expired', { authorizationToken: undefined }]
  ])('discards a deferred response after %s', (_reason, change) => {
    expect(isCurrentSelectedDetailResponse({ ...current, ...change })).toBe(false)
  })
})

describe('isCurrentPrefetchedDetailResponse', () => {
  it('accepts only an unchanged, active, unprotected item', () => {
    expect(
      isCurrentPrefetchedDetailResponse({
        requestGeneration: 4,
        currentGeneration: 4,
        response: summary('visible', 0),
        summary: summary('visible', 0)
      })
    ).toBe(true)

    expect(
      isCurrentPrefetchedDetailResponse({
        requestGeneration: 4,
        currentGeneration: 5,
        response: summary('stale', 0),
        summary: summary('stale', 0)
      })
    ).toBe(false)
    expect(
      isCurrentPrefetchedDetailResponse({
        requestGeneration: 4,
        currentGeneration: 4,
        response: summary('protected', 1),
        summary: summary('protected', 1)
      })
    ).toBe(false)
    expect(
      isCurrentPrefetchedDetailResponse({
        requestGeneration: 4,
        currentGeneration: 4,
        response: summary('archived', 0),
        summary: { ...summary('archived', 0), archivedAt: '2026-07-18T00:00:00.000Z' }
      })
    ).toBe(false)
    expect(
      isCurrentPrefetchedDetailResponse({
        requestGeneration: 4,
        currentGeneration: 4,
        response: { ...summary('changed', 0), updatedAt: '2026-07-18T00:00:01.000Z' },
        summary: summary('changed', 0)
      })
    ).toBe(false)
  })
})
