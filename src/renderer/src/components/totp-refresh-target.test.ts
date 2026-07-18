import { describe, expect, it } from 'vitest'
import { resolveTotpRefreshTarget } from './totp-refresh-target'

const login = {
  id: 'item-a',
  hasTotp: true,
  updatedAt: '2026-07-19T00:00:00.000Z',
  deletedAt: null
}

describe('resolveTotpRefreshTarget', () => {
  it('keeps the same target when unrelated usage metadata refreshes', () => {
    const before = resolveTotpRefreshTarget(login, login.id, false)
    const refreshedLogin = {
      ...login,
      usageCount: 2,
      lastUsedAt: '2026-07-19T00:01:00.000Z'
    }
    const after = resolveTotpRefreshTarget(refreshedLogin, login.id, false)

    expect(after).toEqual(before)
  })

  it('changes the target revision when the item content changes', () => {
    expect(
      resolveTotpRefreshTarget({ ...login, updatedAt: '2026-07-19T00:01:00.000Z' }, login.id, false)
    ).not.toEqual(resolveTotpRefreshTarget(login, login.id, false))
  })

  it('disables refresh without an active TOTP source', () => {
    expect(resolveTotpRefreshTarget({ ...login, hasTotp: false }, login.id, false)).toBeNull()
    expect(
      resolveTotpRefreshTarget({ ...login, deletedAt: login.updatedAt }, login.id, false)
    ).toBeNull()
    expect(resolveTotpRefreshTarget(login, 'item-b', false)).toBeNull()
    expect(resolveTotpRefreshTarget(login, login.id, true)).toBeNull()
  })
})
