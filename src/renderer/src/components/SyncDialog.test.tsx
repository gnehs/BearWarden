import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { PendingImportWarning } from './PendingImportWarning'
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

describe('SyncDialog pending import resolution', () => {
  it('shows aggregate uncertainty, duplicate risk, password proof, and the safe disconnect exit', () => {
    const markup = renderToStaticMarkup(
      <PendingImportWarning
        count={3}
        startedAt="2026-07-17T00:00:00.000Z"
        masterPassword=""
        showPassword={false}
        busy={false}
        onMasterPasswordChange={() => undefined}
        onTogglePassword={() => undefined}
        onConfirm={() => undefined}
      />
    )

    expect(markup).toContain('批次匯入的伺服器結果未知')
    expect(markup).toContain('這 3 筆項目')
    expect(markup).toContain('不會自動重送')
    expect(markup).toContain('可能出現重複項目')
    expect(markup).toContain('本機保管庫資料會保留')
    expect(markup).toContain('我了解風險，允許重新傳送')
    expect(markup).toContain('type="password"')
    expect(markup).toContain('maxLength="1024"')
    expect(markup).not.toMatch(/marker|localId/i)
  })
})
