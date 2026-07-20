import { describe, expect, it, vi } from 'vitest'
import type { VaultPagePath } from '../router'
import { nextVaultPagePath, vaultPagePathFromPathname } from './vault-route-state'

vi.mock('../router', () => ({ vaultRoute: {} }))

describe('vaultPagePathFromPathname', () => {
  it.each<VaultPagePath>([
    '/vault',
    '/vault/settings',
    '/vault/health',
    '/vault/sends',
    '/vault/organizations',
    '/vault/emergency-access'
  ])('derives the auxiliary page directly from %s', (pathname) => {
    expect(vaultPagePathFromPathname(pathname)).toBe(pathname)
  })

  it('falls back to the vault for an unmatched pathname', () => {
    expect(vaultPagePathFromPathname('/vault/not-a-page')).toBe('/vault')
  })

  it('accepts a trailing slash on a deep link', () => {
    expect(vaultPagePathFromPathname('/vault/emergency-access/')).toBe('/vault/emergency-access')
  })

  it('reflects back-forward pathname changes without retained local state', () => {
    const history = ['/vault/settings', '/vault/health', '/vault/settings']

    expect(history.map(vaultPagePathFromPathname)).toEqual([
      '/vault/settings',
      '/vault/health',
      '/vault/settings'
    ])
  })
})

describe('nextVaultPagePath', () => {
  it('opens the requested page directly from another auxiliary page', () => {
    expect(nextVaultPagePath('/vault/health', '/vault/settings', true)).toBe('/vault/settings')
  })

  it('closes the current page back to the vault and ignores no-op updates', () => {
    expect(nextVaultPagePath('/vault/sends', '/vault/sends', false)).toBe('/vault')
    expect(nextVaultPagePath('/vault', '/vault/sends', false)).toBeNull()
  })

  it('supports functional boolean updates', () => {
    expect(nextVaultPagePath('/vault/organizations', '/vault/organizations', (open) => !open)).toBe(
      '/vault'
    )
  })
})
