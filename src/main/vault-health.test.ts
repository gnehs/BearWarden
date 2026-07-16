import { describe, expect, it } from 'vitest'
import {
  analyzeVaultHealth,
  type VaultHealthAnalysis,
  type VaultHealthItem,
  type VaultHealthProtectedItem,
  type VaultHealthUnprotectedItem
} from './vault-health'

function item(overrides: Partial<VaultHealthUnprotectedItem> = {}): VaultHealthUnprotectedItem {
  return {
    id: '11111111-1111-1111-1111-111111111111',
    type: 'login',
    name: 'Primary account',
    password: 'correcthorsebatterystaple',
    username: 'person@example.com',
    reprompt: 0,
    ...overrides
  }
}

function protectedItem(
  overrides: Partial<VaultHealthProtectedItem> = {}
): VaultHealthProtectedItem {
  return {
    id: '99999999-9999-9999-9999-999999999999',
    type: 'login',
    name: 'Protected account',
    reprompt: 1,
    ...overrides
  }
}

function findingShape(analysis: VaultHealthAnalysis): unknown {
  return {
    weak: analysis.weakPasswords.map((finding) => Object.keys(finding).sort()),
    reused: analysis.reusedPasswords.map((finding) => Object.keys(finding).sort()),
    unsecured: analysis.unsecuredWebsites.map((finding) => Object.keys(finding).sort())
  }
}

function collectKeys(value: unknown, keys: Set<string> = new Set()): Set<string> {
  if (Array.isArray(value)) {
    for (const entry of value) collectKeys(entry, keys)
    return keys
  }
  if (value === null || typeof value !== 'object') return keys
  for (const [key, entry] of Object.entries(value)) {
    keys.add(key.toLowerCase())
    collectKeys(entry, keys)
  }
  return keys
}

describe('vault health', () => {
  it('uses the official zxcvbn 0-4 thresholds and reports only scores at or below two', () => {
    const analysis = analyzeVaultHealth([
      item({ id: 'score-0', name: 'Score zero', password: 'password' }),
      item({ id: 'score-1', name: 'Score one', password: 'dragon2026' }),
      item({ id: 'score-2', name: 'Score two', password: 'Tr0ub4dour&3' }),
      item({
        id: 'score-3',
        name: 'Score three',
        password: 'gnehs!2026',
        username: 'different@example.com'
      }),
      item({ id: 'score-4', name: 'Score four' })
    ])

    expect(analysis.analyzedCount).toBe(5)
    expect(analysis.weakPasswords.map(({ id, score }) => ({ id, score }))).toEqual([
      { id: 'score-0', score: 0 },
      { id: 'score-1', score: 1 },
      { id: 'score-2', score: 2 }
    ])
    expect(analysis.weakPasswordCount).toBe(3)
  })

  it('sorts very weak scores before weak scores and names deterministically with stable ties', () => {
    const analysis = analyzeVaultHealth([
      item({ id: 'tie-first', name: 'Álpha', password: 'dragon2026' }),
      item({ id: 'score-two', name: 'Aardvark', password: 'Tr0ub4dour&3' }),
      item({ id: 'score-zero', name: 'Zulu', password: 'password' }),
      item({ id: 'tie-second', name: 'alpha', password: 'computer1!' })
    ])

    expect(analysis.weakPasswords.map(({ id }) => id)).toEqual([
      'score-zero',
      'tie-first',
      'tie-second',
      'score-two'
    ])
  })

  it('detects exact password reuse and returns each affected item with its reuse count', () => {
    const analysis = analyzeVaultHealth([
      item({ id: 'z', name: 'Zulu', password: 'shared-secret' }),
      item({ id: 'b', name: 'Beta', password: 'unique-secret' }),
      item({ id: 'a1', name: 'Álpha', password: 'shared-secret' }),
      item({ id: 'a2', name: 'alpha', password: 'shared-secret' })
    ])

    expect(analysis.reusedPasswords).toEqual([
      { id: 'a1', name: 'Álpha', reuseCount: 3 },
      { id: 'a2', name: 'alpha', reuseCount: 3 },
      { id: 'z', name: 'Zulu', reuseCount: 3 }
    ])
    expect(analysis.reusedPasswordCount).toBe(3)
  })

  it('skips protected candidates without using them for strength or reuse', () => {
    const analysis = analyzeVaultHealth([
      item({ id: 'visible', password: 'shared-secret' }),
      protectedItem({ id: 'protected' }),
      protectedItem({ id: 'protected-weak' })
    ])

    expect(analysis).toMatchObject({
      analyzedCount: 1,
      protectedSkippedCount: 2,
      reusedPasswordCount: 0
    })
    expect(analysis.weakPasswords.every(({ id }) => id !== 'protected-weak')).toBe(true)
  })

  it('reports each active login whose stored URI begins with the official http:// prefix', () => {
    const analysis = analyzeVaultHealth([
      item({
        id: 'localhost',
        name: 'Localhost',
        password: '',
        uris: [{ uri: 'http://localhost:8080/private?token=must-not-leak' }]
      }),
      item({
        id: 'onion',
        name: 'Onion',
        uris: [
          { uri: 'https://secure.example' },
          { uri: 'http://examplehiddenservice.onion/login' }
        ]
      }),
      item({ id: 'secure', name: 'Secure', uris: [{ uri: 'https://example.com' }] }),
      item({ id: 'embedded', name: 'Embedded', uris: [{ uri: 'x-http://example.com' }] }),
      item({ id: 'uppercase', name: 'Uppercase', uris: [{ uri: 'HTTP://example.com' }] }),
      item({ id: 'space', name: 'Space', uris: [{ uri: ' http://example.com' }] })
    ])

    expect(analysis.unsecuredWebsites).toEqual([
      { id: 'localhost', name: 'Localhost' },
      { id: 'onion', name: 'Onion' }
    ])
    expect(analysis.unsecuredWebsiteCount).toBe(2)
    expect(JSON.stringify(analysis)).not.toContain('localhost:8080')
    expect(JSON.stringify(analysis)).not.toContain('must-not-leak')
  })

  it('excludes protected, trashed, archived, and non-login items from unsecured findings', () => {
    const httpUris = [{ uri: 'http://private.example/query?secret=value' }]
    const analysis = analyzeVaultHealth([
      protectedItem({ id: 'protected', uris: httpUris } as Partial<VaultHealthProtectedItem>),
      item({ id: 'trash-http', uris: httpUris, deletedAt: '2026-01-01T00:00:00.000Z' }),
      item({ id: 'archive-http', uris: httpUris, archivedAt: '2026-01-01T00:00:00.000Z' }),
      item({ id: 'card-http', type: 'card', uris: httpUris })
    ])

    expect(analysis.unsecuredWebsites).toEqual([])
    expect(analysis.unsecuredWebsiteCount).toBe(0)
    expect(analysis.protectedSkippedCount).toBe(1)
  })

  it('excludes trash, archived, non-login, and empty-password items', () => {
    const analysis = analyzeVaultHealth([
      item({ id: 'active' }),
      item({ id: 'trash', password: 'password', deletedAt: '2026-01-01T00:00:00.000Z' }),
      item({ id: 'archive', password: 'password', archivedAt: '2026-01-01T00:00:00.000Z' }),
      item({ id: 'card', type: 'card', password: 'password' }),
      item({ id: 'empty', password: '' }),
      protectedItem({ id: 'trash-protected', deletedAt: '2026-01-01T00:00:00.000Z' }),
      protectedItem({ id: 'non-login-protected', type: 'card' })
    ])

    expect(analysis).toEqual({
      analyzedCount: 1,
      protectedSkippedCount: 0,
      weakPasswordCount: 0,
      reusedPasswordCount: 0,
      unsecuredWebsiteCount: 0,
      weakPasswords: [],
      reusedPasswords: [],
      unsecuredWebsites: []
    })
  })

  it('uses filtered username tokens and BearWarden brand terms as zxcvbn user input', () => {
    const matchingUsername = analyzeVaultHealth([
      item({ id: 'matching', password: 'gnehs!2026', username: ' GNEHS.staff@example.com ' })
    ])
    const unrelatedUsername = analyzeVaultHealth([
      item({ id: 'unrelated', password: 'gnehs!2026', username: 'different@example.com' })
    ])
    const branded = analyzeVaultHealth([
      item({ id: 'brand', password: 'bearwarden', username: '' })
    ])

    expect(matchingUsername.weakPasswords).toEqual([
      { id: 'matching', name: 'Primary account', score: 2 }
    ])
    expect(unrelatedUsername.weakPasswords).toEqual([])
    expect(branded.weakPasswords).toEqual([{ id: 'brand', name: 'Primary account', score: 0 }])
  })

  it('never returns passwords, hashes, usernames, or URIs', () => {
    const secret = 'unique-secret-value'
    const source = {
      ...item({ id: 'first', password: secret, username: 'private-user' }),
      uri: 'https://private.example/secret'
    }
    const analysis = analyzeVaultHealth([
      source,
      item({ id: 'second', password: secret, username: 'private-user' })
    ])

    expect(findingShape(analysis)).toEqual({
      weak: analysis.weakPasswords.map(() => ['id', 'name', 'score']),
      reused: analysis.reusedPasswords.map(() => ['id', 'name', 'reuseCount']),
      unsecured: analysis.unsecuredWebsites.map(() => ['id', 'name'])
    })
    expect(JSON.stringify(analysis)).not.toContain(secret)
    expect(JSON.stringify(analysis)).not.toContain('private-user')
    expect(JSON.stringify(analysis)).not.toContain('private.example')
    const resultKeys = collectKeys(analysis)
    for (const forbidden of ['password', 'hash', 'username', 'uri']) {
      expect(resultKeys.has(forbidden)).toBe(false)
    }
  })

  it('does not mutate source items', () => {
    const source = [
      item({ id: 'first', name: 'Álpha', password: 'shared-secret' }),
      item({ id: 'second', name: 'Beta', password: 'shared-secret' })
    ]
    const before = structuredClone(source)

    analyzeVaultHealth(source)

    expect(source).toEqual(before)
  })

  it('ignores inherited and accessor-backed secrets without invoking getters', () => {
    const inherited = Object.assign(Object.create({ password: 'prototype-secret' }), {
      id: 'inherited',
      type: 'login',
      name: 'Inherited',
      username: '',
      reprompt: 0,
      deletedAt: null,
      archivedAt: null
    }) as VaultHealthItem
    const accessor = item({ id: 'accessor' }) as unknown as Record<string, unknown>
    Object.defineProperty(accessor, 'password', {
      get: () => {
        throw new Error('must not read password accessor')
      },
      enumerable: true
    })
    Object.defineProperty(accessor, 'uris', {
      get: () => {
        throw new Error('must not read URI accessor')
      },
      enumerable: true
    })
    const protectedAccessor = protectedItem({ id: 'protected-accessor' }) as unknown as Record<
      string,
      unknown
    >
    Object.defineProperty(protectedAccessor, 'password', {
      get: () => {
        throw new Error('must not read protected password accessor')
      },
      enumerable: true
    })
    Object.defineProperty(protectedAccessor, 'username', {
      get: () => {
        throw new Error('must not read protected username accessor')
      },
      enumerable: true
    })

    const analysis = analyzeVaultHealth([
      inherited,
      accessor as unknown as VaultHealthItem,
      protectedAccessor as unknown as VaultHealthItem
    ])

    expect(analysis.analyzedCount).toBe(0)
    expect(analysis.protectedSkippedCount).toBe(1)
  })

  it('fails closed when collection or secret bounds are exceeded', () => {
    const tooMany = Array.from({ length: 50_001 }, (_, index) =>
      item({ id: `item-${index}`, password: 'password' })
    )
    const oversizedPassword = item({ password: 'x'.repeat(16_385) })

    expect(analyzeVaultHealth(tooMany)).toEqual({
      analyzedCount: 0,
      protectedSkippedCount: 0,
      weakPasswordCount: 0,
      reusedPasswordCount: 0,
      unsecuredWebsiteCount: 0,
      weakPasswords: [],
      reusedPasswords: [],
      unsecuredWebsites: []
    })
    expect(analyzeVaultHealth([oversizedPassword]).analyzedCount).toBe(0)
  })
})
