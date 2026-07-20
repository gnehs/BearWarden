import { describe, expect, it } from 'vitest'
import type {
  LoginSummary,
  VaultHealthAccountBreachReport,
  VaultHealthExposedReport
} from '../../../shared/vault-contract'
import {
  beginAccountBreachCheck,
  beginExposedPasswordCheck,
  cancelAccountBreachCheck,
  cancelExposedPasswordCheck,
  createAccountBreachIdleState,
  createExposedPasswordIdleState,
  failAccountBreachCheck,
  failExposedPasswordCheck,
  invalidateAccountBreachCheck,
  invalidateExposedPasswordCheck,
  isVaultHealthAccountBreachReport,
  isVaultHealthExposedReport,
  resolveAccountBreachCheck,
  resolveExposedPasswordCheck,
  vaultHealthRevision,
  weakPasswordLabel
} from './vault-health-ui'

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

function exposedReport(
  overrides: Partial<VaultHealthExposedReport> = {}
): VaultHealthExposedReport {
  return {
    generatedAt: '2026-07-16T01:00:00.000Z',
    totals: {
      analyzedCount: 2,
      exposedPasswordCount: 1,
      protectedSkippedCount: 1
    },
    exposedPasswords: [
      {
        id: '11111111-1111-4111-8111-111111111111',
        name: 'Example',
        subtitle: '登入項目',
        exposedCount: 42
      }
    ],
    ...overrides
  }
}

function accountBreachReport(
  overrides: Partial<Extract<VaultHealthAccountBreachReport, { status: 'complete' }>> = {}
): Extract<VaultHealthAccountBreachReport, { status: 'complete' }> {
  return {
    generatedAt: '2026-07-16T01:00:00.000Z',
    status: 'complete',
    breaches: [
      {
        name: 'ExampleBreach',
        title: 'Example Breach',
        domain: 'example.invalid',
        breachDate: '2025-01-01',
        addedDate: '2025-01-02T00:00:00.000Z',
        pwnCount: 42,
        dataClasses: ['Email addresses'],
        isVerified: true
      }
    ],
    ...overrides
  }
}

describe('vault health renderer policy', () => {
  it('uses the official weak report labels', () => {
    expect(weakPasswordLabel(0)).toBe('極弱')
    expect(weakPasswordLabel(1)).toBe('極弱')
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

  it('starts exposed-password checks idle until an explicit action begins a request', () => {
    const idle = createExposedPasswordIdleState('revision-a')
    expect(idle).toEqual({ status: 'idle', revision: 'revision-a' })

    expect(beginExposedPasswordCheck('revision-a', 1)).toEqual({
      status: 'loading',
      revision: 'revision-a',
      requestId: 1
    })
  })

  it('accepts only bounded, internally consistent exposed-password reports', () => {
    expect(isVaultHealthExposedReport(exposedReport())).toBe(true)
    expect(
      isVaultHealthExposedReport(
        exposedReport({
          totals: {
            analyzedCount: 2,
            exposedPasswordCount: 0,
            protectedSkippedCount: 1
          }
        })
      )
    ).toBe(false)
    expect(
      isVaultHealthExposedReport({ ...exposedReport(), password: 'must-not-cross-renderer' })
    ).toBe(false)
    expect(
      isVaultHealthExposedReport(
        exposedReport({
          exposedPasswords: [
            {
              id: '11111111-1111-4111-8111-111111111111',
              name: 'Example',
              subtitle: '',
              exposedCount: 0
            }
          ]
        })
      )
    ).toBe(false)

    const finding = exposedReport().exposedPasswords[0]!
    const largeValidReport = exposedReport({
      totals: {
        analyzedCount: 10_001,
        exposedPasswordCount: 10_001,
        protectedSkippedCount: 0
      },
      exposedPasswords: Array(10_001).fill(finding)
    })
    expect(isVaultHealthExposedReport(largeValidReport)).toBe(true)
    expect(
      isVaultHealthExposedReport({
        ...largeValidReport,
        totals: {
          analyzedCount: 50_001,
          exposedPasswordCount: 50_001,
          protectedSkippedCount: 0
        },
        exposedPasswords: Array(50_001).fill(finding)
      })
    ).toBe(false)

    const hostilePrototype = new Proxy(
      {},
      {
        getPrototypeOf: () => {
          throw new Error('prototype denied')
        }
      }
    )
    expect(isVaultHealthExposedReport(hostilePrototype)).toBe(false)
  })

  it('does not let stale request or revision responses overwrite current state', () => {
    const current = beginExposedPasswordCheck('revision-b', 2)
    const report = exposedReport()

    expect(resolveExposedPasswordCheck(current, 'revision-b', 1, report)).toBe(current)
    expect(resolveExposedPasswordCheck(current, 'revision-a', 2, report)).toBe(current)
    expect(failExposedPasswordCheck(current, 'revision-b', 1)).toBe(current)
    expect(resolveExposedPasswordCheck(current, 'revision-b', 2, report)).toEqual({
      status: 'success',
      revision: 'revision-b',
      requestId: 2,
      report
    })
  })

  it('treats malformed or failed checks as unknown instead of a successful empty report', () => {
    const loading = beginExposedPasswordCheck('revision-a', 3)
    const malformed = { ...exposedReport(), exposedPasswords: [] }

    expect(resolveExposedPasswordCheck(loading, 'revision-a', 3, malformed)).toEqual({
      status: 'failed',
      revision: 'revision-a',
      requestId: 3
    })
    expect(failExposedPasswordCheck(loading, 'revision-a', 3)).toEqual({
      status: 'failed',
      revision: 'revision-a',
      requestId: 3
    })
  })

  it('invalidates results on vault revision changes and keeps cancellation non-failing', () => {
    const report = exposedReport()
    const success = resolveExposedPasswordCheck(
      beginExposedPasswordCheck('revision-a', 4),
      'revision-a',
      4,
      report
    )

    expect(invalidateExposedPasswordCheck(success, 'revision-a')).toBe(success)
    expect(invalidateExposedPasswordCheck(success, 'revision-b')).toEqual({
      status: 'idle',
      revision: 'revision-b'
    })
    expect(cancelExposedPasswordCheck('revision-b')).toEqual({
      status: 'idle',
      revision: 'revision-b'
    })
  })

  it('keeps account-breach checks idle until explicit email submission', () => {
    expect(createAccountBreachIdleState('revision-a')).toEqual({
      status: 'idle',
      revision: 'revision-a'
    })
    expect(beginAccountBreachCheck('revision-a', 1, 'person@example.invalid')).toEqual({
      status: 'loading',
      revision: 'revision-a',
      requestId: 1,
      email: 'person@example.invalid'
    })
  })

  it('accepts only bounded renderer-safe account-breach reports', () => {
    expect(isVaultHealthAccountBreachReport(accountBreachReport())).toBe(true)
    expect(isVaultHealthAccountBreachReport(accountBreachReport({ breaches: [] }))).toBe(true)
    expect(
      isVaultHealthAccountBreachReport({
        generatedAt: '2026-07-16T01:00:00.000Z',
        status: 'unavailable',
        reason: 'server-hibp-unconfigured',
        breaches: []
      })
    ).toBe(true)
    expect(
      isVaultHealthAccountBreachReport({
        ...accountBreachReport(),
        breaches: [
          {
            ...accountBreachReport().breaches[0],
            description: '<img src=x onerror=alert(1)>'
          }
        ]
      })
    ).toBe(false)
    expect(
      isVaultHealthAccountBreachReport({
        ...accountBreachReport(),
        breaches: [
          {
            ...accountBreachReport().breaches[0],
            breachDate: '2025-02-30'
          }
        ]
      })
    ).toBe(false)
    expect(
      isVaultHealthAccountBreachReport({
        generatedAt: '2026-07-16T01:00:00.000Z',
        status: 'unavailable',
        reason: 'server-hibp-unconfigured',
        breaches: [accountBreachReport().breaches[0]]
      })
    ).toBe(false)
    const hostileOwnKeys = new Proxy(
      {
        generatedAt: '2026-07-16T01:00:00.000Z',
        status: 'complete',
        breaches: []
      },
      {
        ownKeys: () => {
          throw new Error('keys denied')
        }
      }
    )
    expect(isVaultHealthAccountBreachReport(hostileOwnKeys)).toBe(false)
  })

  it('does not let stale, malformed, failed, or cancelled account-breach responses imply safety', () => {
    const loading = beginAccountBreachCheck('revision-b', 2, 'person@example.invalid')
    const report = accountBreachReport({ breaches: [] })

    expect(resolveAccountBreachCheck(loading, 'revision-b', 1, report)).toBe(loading)
    expect(resolveAccountBreachCheck(loading, 'revision-a', 2, report)).toBe(loading)
    expect(
      resolveAccountBreachCheck(loading, 'revision-b', 2, { status: 'complete', breaches: [] })
    ).toEqual({
      status: 'failed',
      revision: 'revision-b',
      requestId: 2,
      email: 'person@example.invalid'
    })
    expect(failAccountBreachCheck(loading, 'revision-b', 2)).toEqual({
      status: 'failed',
      revision: 'revision-b',
      requestId: 2,
      email: 'person@example.invalid'
    })
    expect(resolveAccountBreachCheck(loading, 'revision-b', 2, report)).toEqual({
      status: 'success',
      revision: 'revision-b',
      requestId: 2,
      email: 'person@example.invalid',
      report
    })
    expect(invalidateAccountBreachCheck(loading, 'revision-c')).toEqual({
      status: 'idle',
      revision: 'revision-c'
    })
    expect(cancelAccountBreachCheck('revision-c')).toEqual({
      status: 'idle',
      revision: 'revision-c'
    })
  })
})
