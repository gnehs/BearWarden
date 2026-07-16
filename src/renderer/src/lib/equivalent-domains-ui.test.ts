import { describe, expect, it } from 'vitest'
import {
  equivalentDomainErrorMessage,
  equivalentDomainRows,
  isEquivalentDomainSettingsView,
  parseEquivalentDomainDraft
} from './equivalent-domains-ui'

const settings = {
  equivalentDomains: [['example.com', 'example.net']],
  globalEquivalentDomains: [{ type: 1, domains: ['google.com', 'gmail.com'], excluded: false }],
  revision: 'a'.repeat(64)
}

describe('equivalent domain UI boundary', () => {
  it('accepts only bounded, unique global settings with an exact renderer shape', () => {
    expect(isEquivalentDomainSettingsView(settings)).toBe(true)
    expect(isEquivalentDomainSettingsView({ ...settings, extra: true })).toBe(false)
    expect(
      isEquivalentDomainSettingsView({
        ...settings,
        globalEquivalentDomains: [
          settings.globalEquivalentDomains[0],
          { ...settings.globalEquivalentDomains[0], excluded: true }
        ]
      })
    ).toBe(false)
    expect(
      isEquivalentDomainSettingsView({ ...settings, equivalentDomains: [['bad,domain']] })
    ).toBe(false)
    const hostile = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error('hostile ownKeys')
        }
      }
    )
    expect(isEquivalentDomainSettingsView(hostile)).toBe(false)
    const hostileGetter = Object.create(null, {
      equivalentDomains: {
        enumerable: true,
        get() {
          throw new Error('hostile getter')
        }
      },
      globalEquivalentDomains: { enumerable: true, value: [] },
      revision: { enumerable: true, value: 'a'.repeat(64) }
    })
    expect(isEquivalentDomainSettingsView(hostileGetter)).toBe(false)
  })

  it('parses comma and newline rows, removes empty values, and preserves one-domain groups', () => {
    expect(
      parseEquivalentDomainDraft([' example.com, example.net\nexample.com ', '', 'solo.test'])
    ).toEqual({
      groups: [['example.com', 'example.net'], ['solo.test']],
      singleDomainGroupCount: 1
    })
    expect(equivalentDomainRows(settings)).toEqual(['example.com, example.net'])
  })

  it('rejects oversized entries and maps actionable service errors', () => {
    expect(() => parseEquivalentDomainDraft(['x'.repeat(1025)])).toThrow('INVALID_INPUT')
    expect(equivalentDomainErrorMessage(new Error('BEARWARDEN:SYNC_CONFLICT'))).toContain(
      '其他裝置'
    )
    expect(equivalentDomainErrorMessage(new Error('BEARWARDEN:SYNC_AUTH_REQUIRED'))).toContain(
      '重新登入'
    )
    expect(equivalentDomainErrorMessage(new Error('BEARWARDEN:LOCKED'))).toContain('鎖定')
  })
})
