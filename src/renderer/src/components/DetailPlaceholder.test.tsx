import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import type { LoginSummary } from '../../../shared/vault-contract'
import { DetailPlaceholder } from './VaultShell-primitives'

vi.mock('./PaymentCardBrandMark', () => ({ default: () => <span /> }))
vi.mock('./WebsiteIcon', () => ({ default: () => <span /> }))

function renderPlaceholder(item: Partial<LoginSummary>): string {
  return renderToStaticMarkup(
    <DetailPlaceholder
      item={{ id: 'item-1', type: 'login', name: 'Example', ...item } as LoginSummary}
      showWebsiteIcons={false}
      onBack={vi.fn()}
    />
  )
}

describe('DetailPlaceholder', () => {
  it('shows the item name and announces loading while the details load', () => {
    const markup = renderPlaceholder({ name: 'Home Assistant Cloud', type: 'card' })

    expect(markup).toContain('aria-busy="true"')
    expect(markup).toMatch(/<h2[^>]*>Home Assistant Cloud<\/h2>/)
    expect(markup).toMatch(/<span class="sr-only" role="status">[^<]+<\/span>/)
  })

  it('keeps a way back to the list for the compact layout', () => {
    expect(renderPlaceholder({})).toContain('data-detail-back=""')
  })
})
