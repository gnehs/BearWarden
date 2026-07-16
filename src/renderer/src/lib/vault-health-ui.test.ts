import { describe, expect, it } from 'vitest'
import type { LoginSummary } from '../../../shared/vault-contract'
import { vaultHealthRevision, weakPasswordLabel } from './vault-health-ui'

function summary(overrides: Partial<LoginSummary> = {}): LoginSummary {
  return {
    id: '11111111-1111-4111-8111-111111111111',
    type: 'login',
    name: 'Example',
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
    reprompt: 0,
    ...overrides
  }
}

describe('vault health renderer policy', () => {
  it('uses the official weak report labels', () => {
    expect(weakPasswordLabel(0)).toBe('非常弱')
    expect(weakPasswordLabel(1)).toBe('非常弱')
    expect(weakPasswordLabel(2)).toBe('弱')
  })

  it('changes the report revision for lifecycle, reprompt, and content updates', () => {
    const original = summary()
    const originalRevision = vaultHealthRevision([original])

    expect(vaultHealthRevision([{ ...original, updatedAt: '2026-07-16T00:00:01.000Z' }])).not.toBe(
      originalRevision
    )
    expect(vaultHealthRevision([{ ...original, archivedAt: '2026-07-16T00:00:01.000Z' }])).not.toBe(
      originalRevision
    )
    expect(vaultHealthRevision([{ ...original, reprompt: 1 }])).not.toBe(originalRevision)
  })

  it('is deterministic regardless of the current list sort order', () => {
    const first = summary()
    const second = summary({ id: '22222222-2222-4222-8222-222222222222' })
    expect(vaultHealthRevision([first, second])).toBe(vaultHealthRevision([second, first]))
  })
})
