import { renderToStaticMarkup } from 'react-dom/server'
import { RotateCw } from 'lucide-react'
import { describe, expect, it } from 'vitest'
import { CopyFeedbackIcon } from './CopyFeedbackIcon'

describe('CopyFeedbackIcon', () => {
  it('renders both icons and selects the copy state before success', () => {
    const markup = renderToStaticMarkup(<CopyFeedbackIcon copied={false} />)

    expect(markup).toContain('class="t-icon-swap"')
    expect(markup).toContain('data-state="a"')
    expect(markup).toContain('data-icon="a"')
    expect(markup).toContain('data-icon="b"')
  })

  it('selects the check state after success and supports another idle action icon', () => {
    const markup = renderToStaticMarkup(
      <CopyFeedbackIcon copied idleIcon={RotateCw} placement="inline-start" />
    )

    expect(markup).toContain('data-state="b"')
    expect(markup).toContain('data-icon="inline-start"')
    expect(markup).toContain('lucide-rotate-cw')
    expect(markup).toContain('lucide-check')
  })
})
