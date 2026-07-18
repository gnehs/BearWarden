import { describe, expect, it } from 'vitest'
import type { LoginSummary } from '../../../shared/vault-contract'
import { sortVaultItems } from './vault-sort'

function summary(
  id: string,
  name: string,
  usageCount: number,
  lastUsedAt: string | null
): LoginSummary {
  return {
    id,
    type: 'login',
    name,
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
    usageCount,
    lastUsedAt,
    createdAt: '2026-07-18T00:00:00.000Z',
    updatedAt: '2026-07-18T00:00:00.000Z',
    deletedAt: null,
    archivedAt: null,
    reprompt: 0
  }
}

describe('sortVaultItems', () => {
  it('sorts frequency descending, then recent use, name, and id without mutating input', () => {
    const input = [
      summary('d', 'Zero', 0, null),
      summary('c', 'Beta', 2, '2026-07-17T00:00:00.000Z'),
      summary('b', 'Alpha', 2, '2026-07-18T00:00:00.000Z'),
      summary('a', 'Alpha', 2, '2026-07-18T00:00:00.000Z'),
      summary('e', 'Most', 3, '2026-07-16T00:00:00.000Z')
    ]

    expect(sortVaultItems(input, 'frequency').map((item) => item.id)).toEqual([
      'e',
      'a',
      'b',
      'c',
      'd'
    ])
    expect(input.map((item) => item.id)).toEqual(['d', 'c', 'b', 'a', 'e'])
  })
})
