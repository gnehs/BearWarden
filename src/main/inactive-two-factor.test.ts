import { describe, expect, it } from 'vitest'
import {
  analyzeInactiveTwoFactor,
  InactiveTwoFactorError,
  loadTwoFactorDirectoryTotpJson,
  parseTwoFactorDirectoryTotpData,
  TWO_FACTOR_DIRECTORY_API_VERSION,
  TWO_FACTOR_DIRECTORY_TOTP_URL,
  type InactiveTwoFactorInput
} from './inactive-two-factor'

function dataset(): ReturnType<typeof parseTwoFactorDirectoryTotpData> {
  return parseTwoFactorDirectoryTotpData({
    'example.com': {
      methods: ['totp', 'u2f'],
      documentation: 'https://help.example.com/security/2fa'
    },
    'example.co.uk': { methods: ['totp'] },
    'accounts.specific.test': {
      methods: ['totp'],
      documentation: 'http://legacy.specific.test/2fa'
    },
    'tenant.github.io': { methods: ['totp'] }
  })
}

function item(overrides: Partial<InactiveTwoFactorInput> = {}): InactiveTwoFactorInput {
  return {
    id: '11111111-1111-1111-1111-111111111111',
    name: 'Example account',
    hasTotp: false,
    isDeleted: false,
    isArchived: false,
    uris: ['https://login.example.com/account'],
    ...overrides
  }
}

function expectCode(run: () => unknown, code: InactiveTwoFactorError['code']): void {
  expect(run).toThrowError(expect.objectContaining({ code }))
}

describe('inactive two-factor dataset loader', () => {
  it('pins the official v4 TOTP endpoint and parses a compact cached fixture', () => {
    expect(TWO_FACTOR_DIRECTORY_API_VERSION).toBe(4)
    expect(TWO_FACTOR_DIRECTORY_TOTP_URL).toBe('https://api.2fa.directory/v4/totp.json')
    const parsed = loadTwoFactorDirectoryTotpJson(
      JSON.stringify({
        'example.com': {
          methods: ['email', 'totp'],
          documentation: 'https://help.example.com/2fa'
        }
      })
    )

    expect(parsed).toEqual({
      apiVersion: 4,
      entries: [{ domain: 'example.com', documentationUrl: 'https://help.example.com/2fa' }]
    })
    expect(Object.isFrozen(parsed)).toBe(true)
    expect(Object.isFrozen(parsed.entries)).toBe(true)
  })

  it('rejects unsupported versions, unknown fields, missing TOTP, duplicates, and ICANN suffixes', () => {
    expectCode(() => loadTwoFactorDirectoryTotpJson('{}', 3), 'UNSUPPORTED_DATASET_VERSION')
    expectCode(
      () =>
        parseTwoFactorDirectoryTotpData({
          'example.com': { methods: ['totp'], surprise: true }
        }),
      'INVALID_DATASET'
    )
    expectCode(
      () => parseTwoFactorDirectoryTotpData({ 'example.com': { methods: ['sms'] } }),
      'INVALID_DATASET'
    )
    expectCode(
      () =>
        parseTwoFactorDirectoryTotpData({
          'EXAMPLE.com': { methods: ['totp'] },
          'example.com': { methods: ['totp'] }
        }),
      'INVALID_DATASET'
    )
    expectCode(
      () => parseTwoFactorDirectoryTotpData({ 'co.uk': { methods: ['totp'] } }),
      'INVALID_DATASET'
    )
  })

  it('rejects inherited properties, accessors, sparse arrays, and oversized serialized input', () => {
    expectCode(
      () =>
        parseTwoFactorDirectoryTotpData(
          Object.assign(Object.create({ 'evil.example': { methods: ['totp'] } }), {
            'example.com': { methods: ['totp'] }
          })
        ),
      'INVALID_DATASET'
    )

    const accessor = Object.create(null) as Record<string, unknown>
    Object.defineProperty(accessor, 'methods', { enumerable: true, get: () => ['totp'] })
    expectCode(
      () => parseTwoFactorDirectoryTotpData({ 'example.com': accessor }),
      'INVALID_DATASET'
    )

    const sparse = Array(2) as string[]
    sparse[1] = 'totp'
    expectCode(
      () => parseTwoFactorDirectoryTotpData({ 'example.com': { methods: sparse } }),
      'INVALID_DATASET'
    )

    expectCode(
      () => loadTwoFactorDirectoryTotpJson(' '.repeat(4 * 1024 * 1024 + 1)),
      'DATASET_TOO_LARGE'
    )
  })

  it('exposes only normalized HTTPS documentation and rejects unsafe URLs', () => {
    const parsed = parseTwoFactorDirectoryTotpData({
      'safe.example': {
        methods: ['totp'],
        documentation: 'https://help.safe.example:8443/2fa#setup'
      },
      'http.example': { methods: ['totp'], documentation: 'http://help.http.example/2fa' }
    })

    expect(parsed.entries).toEqual([
      { domain: 'http.example', documentationUrl: null },
      {
        domain: 'safe.example',
        documentationUrl: 'https://help.safe.example:8443/2fa#setup'
      }
    ])
    expectCode(
      () =>
        parseTwoFactorDirectoryTotpData({
          'credentials.example': {
            methods: ['totp'],
            documentation: 'https://user:secret@help.credentials.example/2fa'
          }
        }),
      'INVALID_DATASET'
    )
    expectCode(
      () =>
        parseTwoFactorDirectoryTotpData({
          'local.example': { methods: ['totp'], documentation: 'https://127.0.0.1/2fa' }
        }),
      'INVALID_DATASET'
    )
    expectCode(
      () =>
        parseTwoFactorDirectoryTotpData({
          'malformed.example': { methods: ['totp'], documentation: 'not a URL' }
        }),
      'INVALID_DATASET'
    )
  })
})

describe('inactive two-factor analysis', () => {
  it('matches exact domains and subdomains without matching lookalike suffixes', () => {
    const report = analyzeInactiveTwoFactor(
      [
        item({ id: 'exact', name: 'Exact', uris: ['https://example.com'] }),
        item({ id: 'subdomain', name: 'Subdomain', uris: ['https://deep.login.example.com'] }),
        item({ id: 'lookalike', name: 'Lookalike', uris: ['https://example.com.evil.test'] }),
        item({ id: 'prefix', name: 'Prefix', uris: ['https://notexample.com'] })
      ],
      dataset()
    )

    expect(report.findings.map(({ id, matchedDomain }) => ({ id, matchedDomain }))).toEqual([
      { id: 'exact', matchedDomain: 'example.com' },
      { id: 'subdomain', matchedDomain: 'example.com' }
    ])
    expect(JSON.stringify(report)).not.toContain('deep.login.example.com')
  })

  it('respects public suffix boundaries and preserves subdomain-specific services', () => {
    const withPrivateSuffix = parseTwoFactorDirectoryTotpData({
      ...Object.fromEntries(
        dataset().entries.map((entry) => [entry.domain, { methods: ['totp'] }])
      ),
      'github.io': { methods: ['totp'] }
    })
    const report = analyzeInactiveTwoFactor(
      [
        item({ id: 'uk', name: 'UK', uris: ['https://signin.example.co.uk'] }),
        item({ id: 'private', name: 'Private suffix', uris: ['https://app.tenant.github.io'] }),
        item({
          id: 'specific',
          name: 'Specific',
          uris: ['https://login.accounts.specific.test']
        }),
        item({ id: 'parent', name: 'Parent', uris: ['https://specific.test'] })
      ],
      withPrivateSuffix
    )

    expect(
      report.findings.map(({ id, matchedDomain, documentationUrl }) => ({
        id,
        matchedDomain,
        documentationUrl
      }))
    ).toEqual([
      {
        id: 'private',
        matchedDomain: 'tenant.github.io',
        documentationUrl: null
      },
      {
        id: 'specific',
        matchedDomain: 'accounts.specific.test',
        documentationUrl: null
      },
      { id: 'uk', matchedDomain: 'example.co.uk', documentationUrl: null }
    ])
    expect(report.findings.some(({ id }) => id === 'parent')).toBe(false)
    expect(
      analyzeInactiveTwoFactor(
        [
          item({ id: 'private-root', uris: ['https://github.io'] }),
          item({ id: 'private-tenant', uris: ['https://unlisted.github.io'] })
        ],
        withPrivateSuffix
      ).findings.map(({ id }) => id)
    ).toEqual(['private-root'])
  })

  it('accepts bounded bare hosts and HTTP(S), but rejects credentials and other schemes', () => {
    const report = analyzeInactiveTwoFactor(
      [
        item({ id: 'bare', name: 'Bare', uris: ['example.com'] }),
        item({ id: 'http', name: 'HTTP', uris: ['http://example.com/login'] }),
        item({
          id: 'credentials',
          name: 'Credentials',
          uris: ['https://user:secret@example.com']
        }),
        item({ id: 'ftp', name: 'FTP', uris: ['ftp://example.com'] }),
        item({ id: 'javascript', name: 'JS', uris: ['javascript://example.com'] }),
        item({ id: 'data', name: 'Data', uris: ['data:text/plain,example.com'] })
      ],
      dataset()
    )

    expect(report.findings.map(({ id }) => id)).toEqual(['bare', 'http'])
  })

  it('uses explicit lifecycle/TOTP flags and does not inspect excluded item domains', () => {
    const report = analyzeInactiveTwoFactor(
      [
        item({ id: 'active', name: 'Active' }),
        item({ id: 'totp', name: 'TOTP', hasTotp: true }),
        item({ id: 'deleted', name: 'Deleted', isDeleted: true }),
        item({ id: 'archived', name: 'Archived', isArchived: true })
      ],
      dataset()
    )

    expect(report).toMatchObject({
      analyzedCount: 1,
      excludedTotpCount: 1,
      excludedDeletedCount: 1,
      excludedArchivedCount: 1
    })
    expect(report.findings.map(({ id }) => id)).toEqual(['active'])
  })

  it('rejects malformed item prototypes, extra fields, sparse URI arrays, and item bounds', () => {
    expectCode(() => analyzeInactiveTwoFactor([Object.create(item())], dataset()), 'INVALID_INPUT')
    expectCode(
      () =>
        analyzeInactiveTwoFactor([{ ...item(), password: 'must-not-cross-boundary' }], dataset()),
      'INVALID_INPUT'
    )
    const sparse = Array(2) as string[]
    sparse[1] = 'example.com'
    expectCode(() => analyzeInactiveTwoFactor([item({ uris: sparse })], dataset()), 'INVALID_INPUT')
    expectCode(
      () => analyzeInactiveTwoFactor([item({ uris: ['x'.repeat(4_097)] })], dataset()),
      'INVALID_INPUT'
    )
  })

  it('does not trust a hand-crafted dataset that bypasses the loader', () => {
    const entries = Array(1)
    Object.defineProperty(entries, '0', {
      enumerable: true,
      get: () => ({ domain: 'example.com', documentationUrl: null })
    })
    expectCode(
      () =>
        analyzeInactiveTwoFactor([item()], {
          apiVersion: 4,
          entries
        }),
      'INVALID_DATASET'
    )

    const forged = Object.create({ apiVersion: 4, entries: [] })
    expectCode(() => analyzeInactiveTwoFactor([item()], forged), 'INVALID_DATASET')
  })

  it('sorts findings deterministically without returning vault URIs', () => {
    const report = analyzeInactiveTwoFactor(
      [
        item({ id: 'z', name: 'Zulu', uris: ['https://private.example.com/secret'] }),
        item({ id: 'a1', name: 'Álpha' }),
        item({ id: 'a2', name: 'alpha' })
      ],
      dataset()
    )

    expect(report.findings.map(({ id }) => id)).toEqual(['a1', 'a2', 'z'])
    expect(JSON.stringify(report)).not.toContain('private.example.com')
    expect(JSON.stringify(report)).not.toContain('/secret')
  })
})
