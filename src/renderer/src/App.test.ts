import { describe, expect, it, vi } from 'vitest'

vi.mock('./components/AuthScreen', () => ({ default: () => null }))
vi.mock('./components/PasskeyApprovalDialog', () => ({ default: () => null }))
vi.mock('./components/SshAgentApprovalDialog', () => ({ default: () => null }))
vi.mock('./components/VaultShell', () => ({ default: () => null }))

import { nextVaultActivityTimestamp, shouldRenderVault, vaultNavigationTarget } from './App'
import { shouldPromptSyncSetup, shouldShowSyncSetupPrompt } from './lib/sync-setup-prompt'

describe('new vault sync invitation', () => {
  it('prompts only after creating a new local vault', () => {
    expect(shouldPromptSyncSetup('setup')).toBe(true)
    expect(shouldPromptSyncSetup('unlock')).toBe(false)
  })

  it('waits until the sync service has returned a status', () => {
    expect(shouldShowSyncSetupPrompt(true, false)).toBe(false)
    expect(shouldShowSyncSetupPrompt(true, true)).toBe(true)
    expect(shouldShowSyncSetupPrompt(false, true)).toBe(false)
  })
})

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

describe('vault route guard', () => {
  it.each([
    '/vault',
    '/vault/settings',
    '/vault/health',
    '/vault/sends',
    '/vault/organizations',
    '/vault/emergency-access'
  ])('preserves unlocked vault route %s', (pathname) => {
    expect(vaultNavigationTarget('unlocked', pathname)).toBeNull()
  })

  it('preserves a supported unlocked vault route with a trailing slash', () => {
    expect(vaultNavigationTarget('unlocked', '/vault/sends/')).toBeNull()
  })

  it.each(['/unlock', '/', '/vault-evil', '/vault/unknown'])(
    'sends unlocked non-vault route %s to the vault',
    (pathname) => {
      expect(vaultNavigationTarget('unlocked', pathname)).toBe('/vault')
    }
  )

  it('waits for the vault route match before rendering route-bound vault hooks', () => {
    expect(shouldRenderVault('unlocked', false)).toBe(false)
    expect(shouldRenderVault('unlocked', true)).toBe(true)
    expect(shouldRenderVault('locked', true)).toBe(false)
  })

  it.each(['locked', 'unavailable'] as const)(
    'sends %s vault state to unlock from nested vault routes',
    (state) => {
      expect(vaultNavigationTarget(state, '/vault/settings')).toBe('/unlock')
      expect(vaultNavigationTarget(state, '/unlock')).toBeNull()
    }
  )

  it('does not redirect while vault state is loading', () => {
    expect(vaultNavigationTarget('loading', '/vault/settings')).toBeNull()
  })
})
