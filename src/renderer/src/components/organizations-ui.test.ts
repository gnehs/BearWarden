import { describe, expect, it } from 'vitest'
import type { SharedLoginSummary } from '../../../shared/vault-contract'
import { isSharedLoginSummary } from './organizations-ui'

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
