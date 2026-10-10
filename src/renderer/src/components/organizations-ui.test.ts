import { describe, expect, it } from 'vitest'
import type { SharedLoginSummary } from '../../../shared/vault-contract'
import { createLatestRequestGuard, isSharedLoginSummary } from './organizations-ui'

describe('shared item summaries', () => {
  it('distinguishes shared summaries before routing item actions', () => {
    const shared = {
      id: 'shared',
      shared: true,
      organizationId: '60000000-0000-4000-8000-000000000001',
      collectionIds: ['70000000-0000-4000-8000-000000000001']
    } as SharedLoginSummary

    expect(isSharedLoginSummary(shared)).toBe(true)
    expect(
      isSharedLoginSummary({ ...shared, shared: false } as unknown as SharedLoginSummary)
    ).toBe(false)
  })
})

describe('latest organization item request guard', () => {
  it('rejects an older response after a newer selection starts', () => {
    const guard = createLatestRequestGuard()
    const first = guard.next()
    const second = guard.next()

    expect(guard.isCurrent(first)).toBe(false)
    expect(guard.isCurrent(second)).toBe(true)
  })

  it('rejects an in-flight response when the current filter clears selection', () => {
    const guard = createLatestRequestGuard()
    const request = guard.next()
    guard.invalidate()

    expect(guard.isCurrent(request)).toBe(false)
  })
})
