import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import TotpCountdownIndicator from './TotpCountdownIndicator'

describe('TotpCountdownIndicator', () => {
  it('renders the remaining seconds as an accessible circular progress indicator', () => {
    const markup = renderToStaticMarkup(<TotpCountdownIndicator remainingSeconds={8} period={30} />)

    expect(markup).toContain('role="progressbar"')
    expect(markup).toContain('aria-valuemax="30"')
    expect(markup).toContain('aria-valuenow="8"')
    expect(markup).toContain('aria-valuetext="剩餘 8 秒"')
    expect(markup).toContain('ring-2 ring-white')
    expect(markup).toContain('stroke-dashoffset:73.333')
    expect(markup).toContain('>8</span>')
  })

  it('shows a non-numeric loading state without exposing a false current value', () => {
    const markup = renderToStaticMarkup(
      <TotpCountdownIndicator remainingSeconds={null} period={30} />
    )

    expect(markup).toContain('aria-valuetext="正在取得驗證碼"')
    expect(markup).not.toContain('aria-valuenow')
    expect(markup).toContain('>…</span>')
  })
})
