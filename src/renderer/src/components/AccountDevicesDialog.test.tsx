import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import {
  DEAUTHORIZE_SESSIONS_CONFIRMATION,
  DeauthorizeSessionsForm,
  deauthorizeSessionsError,
  executeDeauthorizeSessions
} from './AccountDevicesDialog'

function request(password: string): {
  masterPassword: string
  confirmation: typeof DEAUTHORIZE_SESSIONS_CONFIRMATION
  confirm: true
} {
  return {
    masterPassword: password,
    confirmation: DEAUTHORIZE_SESSIONS_CONFIRMATION,
    confirm: true
  }
}

describe('AccountDevicesDialog session deauthorization boundary', () => {
  it('admits only one destructive request and wipes both request copies', async () => {
    let resolveRequest!: () => void
    const deferred = new Promise<void>((resolve) => {
      resolveRequest = resolve
    })
    const deauthorize = vi.fn(() => deferred)
    const onAcquired = vi.fn()
    const lease = { current: false }
    const firstRequest = request('first-password')
    const secondRequest = request('second-password')

    const first = executeDeauthorizeSessions({
      lease,
      request: firstRequest,
      deauthorize,
      onAcquired
    })
    const second = executeDeauthorizeSessions({
      lease,
      request: secondRequest,
      deauthorize,
      onAcquired
    })

    await expect(second).resolves.toBe(false)
    expect(deauthorize).toHaveBeenCalledOnce()
    expect(onAcquired).toHaveBeenCalledOnce()
    expect(secondRequest).toEqual({ masterPassword: '', confirmation: '', confirm: true })

    resolveRequest()
    await expect(first).resolves.toBe(true)
    expect(firstRequest).toEqual({ masterPassword: '', confirmation: '', confirm: true })
    expect(lease.current).toBe(false)
  })

  it('wipes secrets and releases its lease when the server result is unknown', async () => {
    const original = new Error('BEARWARDEN:SESSION_DEAUTHORIZATION_UNKNOWN')
    const deauthorizationRequest = request('fresh-password')
    const lease = { current: false }

    await expect(
      executeDeauthorizeSessions({
        lease,
        request: deauthorizationRequest,
        deauthorize: vi.fn(async () => {
          throw original
        }),
        onAcquired: () => undefined
      })
    ).rejects.toBe(original)

    expect(deauthorizationRequest).toEqual({ masterPassword: '', confirmation: '', confirm: true })
    expect(lease.current).toBe(false)
    expect(deauthorizeSessionsError(original)).toContain('結果無法判定')
    expect(deauthorizeSessionsError(original)).toContain('可能已成功')
    expect(deauthorizeSessionsError(original)).toContain('不要直接重試')
  })

  it('does not expose backend detail and requires fresh proof after a password failure', () => {
    const message = deauthorizeSessionsError(
      new Error('BEARWARDEN:INVALID_MASTER_PASSWORD: sensitive server detail')
    )

    expect(message).toContain('主密碼驗證失敗')
    expect(message).toContain('重新輸入')
    expect(message).not.toContain('sensitive server detail')
  })

  it('renders the full destructive scope and exact two-part confirmation', () => {
    const markup = renderToStaticMarkup(
      <form>
        <DeauthorizeSessionsForm
          masterPassword=""
          confirmation=""
          busy={false}
          error=""
          onMasterPasswordChange={() => undefined}
          onConfirmationChange={() => undefined}
          onCancel={() => undefined}
        />
      </form>
    )

    expect(markup).toContain('包含目前裝置')
    expect(markup).toContain('重新登入')
    expect(markup).toContain('雙重驗證')
    expect(markup).toContain('最長約一小時')
    expect(markup).toContain('保留這台電腦上的本機加密 vault')
    expect(markup).toContain(`輸入「${DEAUTHORIZE_SESSIONS_CONFIRMATION}」確認`)
    expect(markup).toContain('type="password"')
    expect(markup).toContain('maxLength="1024"')
    expect(markup).toContain('disabled=""')
  })

  it('enables the destructive submit only for exact confirmation and a fresh password', () => {
    const markup = renderToStaticMarkup(
      <form>
        <DeauthorizeSessionsForm
          masterPassword="fresh-password"
          confirmation={DEAUTHORIZE_SESSIONS_CONFIRMATION}
          busy={false}
          error=""
          onMasterPasswordChange={() => undefined}
          onConfirmationChange={() => undefined}
          onCancel={() => undefined}
        />
      </form>
    )

    const destructiveButton = markup.match(/<button[^>]*>.*?取消所有工作階段<\/button>/u)?.[0]
    expect(destructiveButton).toBeDefined()
    expect(destructiveButton).not.toContain('disabled=""')
  })
})
