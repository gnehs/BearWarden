import { describe, expect, it } from 'vitest'
import { buildSyncTwoFactorRequest, WEB_AUTHN_TWO_FACTOR_METHOD } from './sync-two-factor-request'

describe('SyncDialog WebAuthn request boundary', () => {
  it('keeps legacy two-factor requests free of the WebAuthn remember flag', () => {
    const request = buildSyncTwoFactorRequest({
      twoFactorMethod: '0',
      twoFactorCode: '  123456  ',
      webAuthnRemember: false
    })

    expect(request).toEqual({ twoFactorMethod: '0', twoFactorCode: '123456' })
    expect(request).not.toHaveProperty('webAuthnRemember')
  })

  it.each([false, true])(
    'sends an explicit remember value for the local security-key choice (%s)',
    (webAuthnRemember) => {
      const request = buildSyncTwoFactorRequest({
        twoFactorMethod: WEB_AUTHN_TWO_FACTOR_METHOD,
        twoFactorCode: 'legacy-code-must-not-leave-the-renderer',
        webAuthnRemember
      })

      expect(request).toEqual({ webAuthnRemember })
      expect(request).not.toHaveProperty('twoFactorMethod')
      expect(request).not.toHaveProperty('twoFactorCode')
    }
  )

  it('does not model WebAuthn ceremony data in the main application request', () => {
    expect(
      JSON.stringify(
        buildSyncTwoFactorRequest({
          twoFactorMethod: WEB_AUTHN_TWO_FACTOR_METHOD,
          twoFactorCode: '',
          webAuthnRemember: false
        })
      )
    ).not.toMatch(/challenge|assertion/i)
  })
})
