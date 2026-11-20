import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { LoginWithDevicePanel } from './LoginWithDevicePanel'

const FINGERPRINT = 'alpha-bravo-charlie-delta-echo-foxtrot'

describe('LoginWithDevicePanel', () => {
  it('shows the fingerprint phrase while waiting and offers the master password instead', () => {
    const markup = renderToStaticMarkup(
      <LoginWithDevicePanel
        state={{ phase: 'awaiting-approval', fingerprint: FINGERPRINT }}
        onUseMasterPassword={() => undefined}
      />
    )
    expect(markup).toContain(FINGERPRINT)
    expect(markup).toContain('驗證片語')
    expect(markup).toContain('正在等待核准')
    expect(markup).toContain('改用主密碼')
  })

  it('withholds the phrase until the server accepted the request', () => {
    const markup = renderToStaticMarkup(
      <LoginWithDevicePanel state={{ phase: 'requesting' }} onUseMasterPassword={() => undefined} />
    )
    expect(markup).not.toContain(FINGERPRINT)
    expect(markup).toContain('正在傳送登入要求')
  })

  it('asks for two-step verification after approval', () => {
    const markup = renderToStaticMarkup(
      <LoginWithDevicePanel
        state={{ phase: 'two-factor', fingerprint: FINGERPRINT }}
        onUseMasterPassword={() => undefined}
      />
    )
    expect(markup).toContain('已核准')
    expect(markup).toContain(FINGERPRINT)
  })
})
