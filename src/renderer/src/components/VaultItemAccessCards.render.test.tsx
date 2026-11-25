import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import { VaultItemTotpRow } from './VaultItemAccessCards'

vi.mock('@number-flow/react', () => ({
  default: ({ value }: { value: number }) => <span>{String(value)}</span>
}))
vi.mock('./PaymentCardBrandMark', () => ({ default: () => <span /> }))
vi.mock('./WebsiteIcon', () => ({ default: () => <span /> }))

function renderTotpRow(
  code: { code: string } | null,
  generationError: 'unsupported' | null
): string {
  return renderToStaticMarkup(
    <VaultItemTotpRow
      code={code ? { ...code, period: 30, remainingSeconds: 12 } : null}
      generationError={generationError}
      revealReady
      showSkeleton={false}
      codeCycle={1}
      showCountdown={false}
      copied={false}
      defaultCountdownPeriodSeconds={30}
      onCopy={vi.fn()}
    />
  )
}

describe('VaultItemTotpRow copy targets', () => {
  it('renders the current code as a copy button grouped into two halves', () => {
    const markup = renderTotpRow({ code: '123456' }, null)

    expect(markup).toMatch(
      /<button[^>]*data-field-copy-value=""[^>]*aria-label="[^"]+"[^>]*>.*123.*456.*<\/button>/s
    )
  })

  it('does not render a value copy button while there is no code', () => {
    expect(renderTotpRow(null, null)).not.toMatch(/data-field-copy-value=""/)
    expect(renderTotpRow(null, 'unsupported')).not.toMatch(/data-field-copy-value=""/)
  })
})
