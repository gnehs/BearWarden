import { describe, expect, it, vi } from 'vitest'

vi.mock('./components/AuthScreen', () => ({ default: () => null }))
vi.mock('./components/PasskeyApprovalDialog', () => ({ default: () => null }))
vi.mock('./components/SshAgentApprovalDialog', () => ({ default: () => null }))
vi.mock('./components/VaultShell', () => ({ default: () => null }))

import { nextVaultActivityTimestamp } from './App'

describe('vault activity reporting', () => {
  it('throttles ordinary activity for ten seconds', () => {
    expect(nextVaultActivityTimestamp(10_001, 10_000)).toBeNull()
    expect(nextVaultActivityTimestamp(20_000, 10_000)).toBe(20_000)
  })

  it('reports immediately after a quick lock then unlock', () => {
    const firstReportAt = 10_000
    const quickLockAt = 10_001
    const lastActivityAfterLockCleanup = 0

    expect(nextVaultActivityTimestamp(quickLockAt, firstReportAt)).toBeNull()
    expect(nextVaultActivityTimestamp(quickLockAt, lastActivityAfterLockCleanup, true)).toBe(
      quickLockAt
    )
  })
})
