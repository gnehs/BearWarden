import { describe, expect, it } from 'vitest'
import { matchesVaultCategory } from './vault-category'

describe('matchesVaultCategory', () => {
  it('treats passkeys and TOTP as derived login filters', () => {
    expect(matchesVaultCategory({ type: 'login', hasTotp: true }, 'totp')).toBe(true)
    expect(matchesVaultCategory({ type: 'login', passkeyCount: 2 }, 'passkey')).toBe(true)
    expect(matchesVaultCategory({ type: 'login', hasTotp: false }, 'totp')).toBe(false)
    expect(matchesVaultCategory({ type: 'login', passkeyCount: 0 }, 'passkey')).toBe(false)

    expect(matchesVaultCategory({ type: 'card', hasTotp: true }, 'totp')).toBe(false)
    expect(matchesVaultCategory({ type: 'identity', passkeyCount: 1 }, 'passkey')).toBe(false)
  })

  it('matches regular item types without changing their meaning', () => {
    expect(matchesVaultCategory({ type: 'card' }, 'card')).toBe(true)
    expect(matchesVaultCategory({ type: 'card' }, 'login')).toBe(false)
    expect(matchesVaultCategory({ type: 'sshKey' }, 'all')).toBe(true)
  })
})
