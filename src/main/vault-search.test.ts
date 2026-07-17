import { describe, expect, it } from 'vitest'
import { searchVaultItems, type VaultSearchItem } from './vault-search'

function item(overrides: Partial<VaultSearchItem> = {}): VaultSearchItem {
  return {
    id: '12345678-1234-1234-1234-123456789abc',
    type: 'login',
    name: 'Primary account',
    subtitle: 'person@example.com',
    username: 'person@example.com',
    uri: 'https://accounts.example.com/private/reset-token',
    uris: [{ uri: 'https://accounts.example.com/private/reset-token' }],
    notes: 'Recovery phrase stored offline',
    customFields: [],
    attachments: [],
    reprompt: 0,
    ...overrides
  }
}

function ids(results: readonly VaultSearchItem[]): string[] {
  return results.map((entry) => entry.id)
}

describe('vault search', () => {
  it('returns a new list containing every item for a whitespace-only query', () => {
    const items = [item(), item({ id: '87654321-bbbb-cccc-dddd-eeeeeeeeeeee' })]
    const result = searchVaultItems(items, ' \n\t ')

    expect(result).toEqual(items)
    expect(result).not.toBe(items)
  })

  it('ANDs normalized basic terms across the official basic fields', () => {
    const matching = item({ id: 'aaaaaaaa-1111-2222-3333-444444444444', name: 'Caf\u00e9 Account' })
    const wrongHost = item({
      id: 'bbbbbbbb-1111-2222-3333-444444444444',
      name: 'Cafe Account',
      uri: 'https://different.test/private',
      uris: [{ uri: 'https://different.test/private' }]
    })

    expect(ids(searchVaultItems([matching, wrongHost], 'CAFE accounts.example.com'))).toEqual([
      matching.id
    ])
    expect(ids(searchVaultItems([matching], 'phrase account'))).toEqual([matching.id])
    expect(searchVaultItems([matching], 'phrase missing')).toEqual([])
  })

  it('supports one-character CJK substring searches', () => {
    const chinese = item({ name: '私人保險庫' })
    expect(searchVaultItems([chinese], '險')).toEqual([chinese])
  })

  it('searches only an eight-or-more-character short ID in basic mode', () => {
    const matching = item({ id: 'deadbeef-1111-2222-3333-444444444444', name: 'Unrelated' })
    expect(searchVaultItems([matching], 'dead')).toEqual([])
    expect(searchVaultItems([matching], 'DEADBEEF')).toEqual([matching])
  })

  it('indexes URI hostnames but not URI secret paths in basic mode', () => {
    const matching = item({ subtitle: 'https://accounts.example.com/private/reset-token' })
    expect(searchVaultItems([matching], 'accounts.example.com')).toEqual([matching])
    expect(searchVaultItems([matching], 'reset-token')).toEqual([])
  })

  it('indexes notes in basic mode but custom fields and attachments only in advanced mode', () => {
    const matching = item({
      id: 'cafebabe-1111-2222-3333-444444444444',
      notes: 'annual renewal',
      customFields: [{ name: 'Account alias', value: 'blue-orchid', type: 'text' }],
      attachments: [{ fileName: 'emergency-kit.pdf' }]
    })

    expect(searchVaultItems([matching], 'annual')).toEqual([matching])
    expect(searchVaultItems([matching], 'blue-orchid')).toEqual([])
    expect(searchVaultItems([matching], 'emergency-kit')).toEqual([])
    expect(searchVaultItems([matching], '>fields:blue-orchid')).toEqual([matching])
    expect(searchVaultItems([matching], '>attachments:emergency-kit.pdf')).toEqual([matching])
  })

  it('supports upstream advanced field and wildcard syntax', () => {
    const first = item({
      id: '11111111-1111-2222-3333-444444444444',
      username: 'alice@example.com'
    })
    const second = item({
      id: '22222222-1111-2222-3333-444444444444',
      username: 'bob@example.com'
    })

    expect(ids(searchVaultItems([first, second], '>login.username:ali*'))).toEqual([first.id])
    expect(ids(searchVaultItems([first, second], '>shortid:2222*'))).toEqual([second.id])
  })

  it('returns no result instead of throwing for malformed advanced syntax', () => {
    const matching = item()
    expect(searchVaultItems([matching], '>unknown:value')).toEqual([])
    expect(searchVaultItems([matching], '>name:')).toEqual([])
    expect(searchVaultItems([matching], '>')).toEqual([])
  })

  it('never indexes protected secret-bearing fields in either search mode', () => {
    const protectedItem = item({
      id: 'feedface-1111-2222-3333-444444444444',
      name: 'Visible protected name',
      subtitle: 'subtitle-secret',
      username: 'username-secret',
      uri: 'https://uri-secret.example/private',
      notes: 'notes-secret',
      customFields: [{ name: 'field-secret-name', value: 'field-secret-value', type: 'text' }],
      attachments: [{ fileName: 'attachment-secret.pdf' }],
      reprompt: 1
    })

    expect(searchVaultItems([protectedItem], 'visible')).toEqual([protectedItem])
    expect(searchVaultItems([protectedItem], 'feedface')).toEqual([protectedItem])
    for (const secret of [
      'subtitle-secret',
      'username-secret',
      'uri-secret',
      'notes-secret',
      'field-secret-value',
      'attachment-secret'
    ]) {
      expect(searchVaultItems([protectedItem], secret)).toEqual([])
      expect(searchVaultItems([protectedItem], `>${secret}*`)).toEqual([])
    }
  })

  it('excludes hidden, linked, and malformed custom fields in their entirety', () => {
    const protectedFields = item({
      customFields: [
        { name: 'hidden-name-secret', value: 'hidden-value-secret', type: 'hidden' },
        { name: 'linked-name-secret', value: 'linked-value-secret', type: 'linked' },
        { name: 'boolean-name-secret', value: 'true', type: 'boolean' }
      ]
    })

    for (const secret of ['hidden-name-secret', 'hidden-value-secret', 'linked-name-secret']) {
      expect(searchVaultItems([protectedFields], `>fields:${secret}`)).toEqual([])
    }
  })

  it('ignores inherited and accessor-backed data and fails protected flags closed', () => {
    const inherited = Object.assign(Object.create({ notes: 'prototype-secret' }), {
      id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      type: 'login',
      name: 'Inherited prototype'
    }) as VaultSearchItem
    const accessor = item({ id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' }) as unknown as Record<
      string,
      unknown
    >
    Object.defineProperty(accessor, 'reprompt', { get: () => 0, enumerable: true })
    Object.defineProperty(accessor, 'notes', {
      get: () => {
        throw new Error('must not invoke secret accessor')
      },
      enumerable: true
    })

    expect(searchVaultItems([inherited], 'prototype-secret')).toEqual([])
    expect(
      searchVaultItems([accessor as unknown as VaultSearchItem], 'person@example.com')
    ).toEqual([])
    expect(searchVaultItems([accessor as unknown as VaultSearchItem], 'primary')).toEqual([
      accessor
    ])
  })

  it('does not mutate items or nested search data', () => {
    const source = item({
      name: 'Caf\u00e9',
      customFields: [{ name: 'Alias', value: 'Blue', type: 'text' }],
      attachments: [{ fileName: 'Document.PDF' }]
    })
    const before = structuredClone(source)

    searchVaultItems([source], '>name:cafe')
    searchVaultItems([source], 'CAFE')

    expect(source).toEqual(before)
  })

  it('fails closed when query or collection bounds are exceeded', () => {
    expect(searchVaultItems([item()], 'x'.repeat(1_025))).toEqual([])

    const oversizedUris = Array.from({ length: 1_001 }, (_, index) => ({
      uri: `https://${index}.example.com`
    }))
    expect(searchVaultItems([item({ uris: oversizedUris })], 'example.com')).toEqual([])
  })

  it('searches advanced queries across a 50,001-item batch boundary', () => {
    const filler: VaultSearchItem = {
      id: '00000000-0000-0000-0000-000000000000',
      type: 'login',
      name: 'Ordinary account'
    }
    const first = item({
      id: '11111111-1111-1111-1111-111111111111',
      name: 'Cross-batch marker'
    })
    const last = item({
      id: '22222222-2222-2222-2222-222222222222',
      name: 'Cross-batch marker'
    })
    const items = Array<VaultSearchItem>(50_001).fill(filler)
    items[0] = first
    items[50_000] = last

    expect(ids(searchVaultItems(items, '>+name:cross +name:batch +name:marker'))).toEqual([
      first.id,
      last.id
    ])
  }, 30_000)

  it('searches across the 32 MiB indexed-character batch budget', () => {
    const largeNote = 'padding '.repeat(8_192)
    const filler = item({
      id: '00000000-0000-0000-0000-000000000000',
      name: 'Ordinary account',
      subtitle: '',
      username: '',
      uri: null,
      uris: [],
      notes: largeNote
    })
    const matching = item({
      id: '33333333-3333-3333-3333-333333333333',
      name: 'After indexed budget boundary',
      subtitle: '',
      username: '',
      uri: null,
      uris: [],
      notes: largeNote
    })
    const items = Array<VaultSearchItem>(513).fill(filler)
    items[512] = matching

    expect(searchVaultItems(items, 'indexed boundary')).toEqual([matching])
  }, 30_000)
})
