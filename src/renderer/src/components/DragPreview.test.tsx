import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import type { LoginSummary } from '../../../shared/vault-contract'
import { ItemDragPreview } from './DragPreview'

vi.mock('./PaymentCardBrandMark', () => ({ default: () => <span /> }))
vi.mock('./WebsiteIcon', () => ({ default: () => <span /> }))

const item: LoginSummary = {
  id: 'preview-item',
  type: 'secureNote',
  name: '預覽項目',
  subtitle: '',
  username: '',
  uri: null,
  uris: [],
  hasTotp: false,
  passkeyCount: 0,
  passwordHistoryCount: 0,
  attachmentCount: 0,
  folderId: null,
  favorite: false,
  usageCount: 0,
  lastUsedAt: null,
  createdAt: '2026-07-19T00:00:00.000Z',
  updatedAt: '2026-07-19T00:00:00.000Z',
  deletedAt: null,
  archivedAt: null,
  reprompt: 0
}

describe('ItemDragPreview', () => {
  it('renders a compact, standalone preview for every drop destination', () => {
    const markup = renderToStaticMarkup(
      <ItemDragPreview item={item} count={1} showWebsiteIcons={false} />
    )

    expect(markup).toContain('w-full')
    expect(markup).toContain('max-w-[calc(100vw-24px)]')
    expect(markup).toContain('安全筆記 · 拖曳以移動')
    expect(markup).toContain('aria-hidden="true"')
    expect(markup).not.toContain('data-drag-preview-layer')
  })

  it('shows the current drop action when a destination is active', () => {
    const markup = renderToStaticMarkup(
      <ItemDragPreview
        item={item}
        count={1}
        showWebsiteIcons={false}
        destinationDescription="移動到「工作」"
      />
    )

    expect(markup).toContain('移動到「工作」')
    expect(markup).not.toContain('拖曳以移動')
  })

  it('shows an explicit cancel action outside a destination', () => {
    const markup = renderToStaticMarkup(
      <ItemDragPreview
        item={item}
        count={1}
        showWebsiteIcons={false}
        destinationDescription="放開以取消移動"
      />
    )

    expect(markup).toContain('放開以取消移動')
  })

  it('stacks card layers behind the active item when multiple items are dragged', () => {
    const twoItemMarkup = renderToStaticMarkup(
      <ItemDragPreview item={item} count={2} showWebsiteIcons={false} />
    )
    const manyItemMarkup = renderToStaticMarkup(
      <ItemDragPreview item={item} count={5} showWebsiteIcons={false} />
    )

    expect(twoItemMarkup.match(/data-drag-preview-layer=/g)).toHaveLength(1)
    expect(manyItemMarkup.match(/data-drag-preview-layer=/g)).toHaveLength(2)
    expect(manyItemMarkup).toContain('與其他 4 個項目一起移動')
    expect(manyItemMarkup).toContain('>5</span>')
  })
})
