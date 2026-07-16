import { describe, expect, it } from 'vitest'
import {
  createUriMatchBudget,
  equivalentDomainsForTarget,
  loginUriMatches,
  loginUrisMatch
} from './uri-matcher'

const settings = {
  equivalentDomains: [
    ['example.com', 'example.net'],
    ['google.com', 'script.google.com']
  ],
  globalEquivalentDomains: [
    { domains: ['enabled.test', 'enabled.net'], excluded: false },
    { domains: ['disabled.test', 'disabled.net'], excluded: true }
  ]
}

describe('Bitwarden URI matching', () => {
  it('uses registrable and enabled equivalent domains without naive suffix matching', () => {
    expect(equivalentDomainsForTarget('https://login.example.net/path', settings)).toEqual(
      new Set(['example.net', 'example.com'])
    )
    expect(
      loginUriMatches({ uri: 'https://vault.example.com', match: 0 }, 'example.net', settings)
    ).toBe(true)
    expect(
      loginUriMatches({ uri: 'https://enabled.net', match: 0 }, 'enabled.test', settings)
    ).toBe(true)
    expect(
      loginUriMatches({ uri: 'https://disabled.net', match: 0 }, 'disabled.test', settings)
    ).toBe(false)
    expect(loginUriMatches({ uri: 'https://ample.net', match: 0 }, 'example.net', settings)).toBe(
      false
    )
  })

  it('implements Host, StartsWith, Exact, Regex, Never, and a Domain default', () => {
    expect(
      loginUriMatches(
        { uri: 'https://example.com:8443/a', match: 1 },
        'https://example.com:8443/b',
        null
      )
    ).toBe(true)
    expect(
      loginUriMatches({ uri: 'https://example.com', match: 1 }, 'https://sub.example.com', null)
    ).toBe(false)
    expect(
      loginUriMatches(
        { uri: 'https://example.com/app', match: 2 },
        'https://example.com/application',
        null
      )
    ).toBe(true)
    expect(
      loginUriMatches({ uri: 'https://example.com', match: 3 }, 'https://example.com/', null)
    ).toBe(false)
    expect(
      loginUriMatches(
        { uri: '^https://(www\\.)?example\\.com/', match: 4 },
        'HTTPS://www.example.com/path',
        null
      )
    ).toBe(true)
    expect(loginUriMatches({ uri: '[invalid', match: 4 }, 'https://example.com', null)).toBe(false)
    expect(
      loginUriMatches({ uri: 'https://example.com', match: 5 }, 'https://example.com', null)
    ).toBe(false)
    expect(
      loginUriMatches({ uri: 'https://login.example.com', match: null }, 'example.com', null)
    ).toBe(true)
  })

  it('preserves the google.com script host blacklist and bounds hostile regex work', () => {
    expect(loginUriMatches({ uri: 'google.com', match: 0 }, 'script.google.com', settings)).toBe(
      false
    )
    expect(loginUriMatches({ uri: 'google.com', match: 0 }, 'mail.google.com', settings)).toBe(true)
    expect(loginUriMatches({ uri: '^(a+)+$', match: 4 }, `${'a'.repeat(253)}!`, null)).toBe(false)
    const budget = createUriMatchBudget(Date.now(), 100, 1)
    expect(loginUriMatches({ uri: 'example', match: 4 }, 'example', null, 0, budget)).toBe(true)
    expect(loginUriMatches({ uri: 'example', match: 4 }, 'example', null, 0, budget)).toBe(false)
  })

  it('matches any URI while respecting an explicit default strategy', () => {
    expect(
      loginUrisMatch(
        [
          { uri: 'never.example', match: 5 },
          { uri: 'https://example.com/app', match: null }
        ],
        'https://example.com/application',
        null,
        2
      )
    ).toBe(true)
  })
})
