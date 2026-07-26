import { DndContext } from '@dnd-kit/core'
import { SortableContext } from '@dnd-kit/sortable'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import type { FolderView, LoginSummary, TotpCodeView } from '../../../shared/vault-contract'
import { FolderRow, ItemRow } from './DndRows'

vi.mock('./PaymentCardBrandMark', () => ({
  default: ({ imageSrc }: { imageSrc?: string }) => (
    <span data-card-cover-image-src={imageSrc ?? ''} />
  )
}))
vi.mock('./WebsiteIcon', () => ({ default: () => <span /> }))

const item: LoginSummary = {
  id: 'totp-item',
  type: 'login',
  name: 'TOTP item',
  subtitle: 'Account',
  username: 'user',
  uri: null,
  uris: [],
  hasTotp: true,
  passkeyCount: 0,
  passwordHistoryCount: 0,
  attachmentCount: 0,
  folderId: null,
  favorite: false,
  usageCount: 0,
  lastUsedAt: null,
  createdAt: '2026-07-20T00:00:00.000Z',
  updatedAt: '2026-07-20T00:00:00.000Z',
  deletedAt: null,
  archivedAt: null,
  reprompt: 0
}

const code: TotpCodeView = {
  code: '310622',
  period: 30,
  remainingSeconds: 8
}

describe('ItemRow TOTP countdown', () => {
  it('leaves the shared countdown out of individual code rows', () => {
    const markup = renderToStaticMarkup(
      <DndContext>
        <ItemRow
          item={item}
          selected={false}
          onSelect={vi.fn()}
          onFavorite={vi.fn()}
          onContextMenu={vi.fn()}
          showWebsiteIcons={false}
          showTotpCode
          totpCodes={new Map([[item.id, code]])}
        />
      </DndContext>
    )

    expect(markup).toContain('grid-cols-1')
    expect(markup).not.toContain('grid-cols-[minmax(0,1fr)_28px]')
    expect(markup).not.toContain('role="progressbar"')
    expect(markup).not.toContain('>8s<')
  })
})

describe('ItemRow status', () => {
  it('does not describe a read-only shared item as deleted', () => {
    const markup = renderToStaticMarkup(
      <DndContext>
        <ItemRow
          item={item}
          selected={false}
          readOnly
          onSelect={vi.fn()}
          onFavorite={vi.fn()}
          onContextMenu={vi.fn()}
          showWebsiteIcons={false}
        />
      </DndContext>
    )

    expect(markup).toContain('>Account</')
    expect(markup).not.toContain('已刪除的項目')
  })

  it('describes an item as deleted only when it has a deletion timestamp', () => {
    const markup = renderToStaticMarkup(
      <DndContext>
        <ItemRow
          item={{ ...item, deletedAt: '2026-07-23T00:00:00.000Z' }}
          selected={false}
          readOnly
          onSelect={vi.fn()}
          onFavorite={vi.fn()}
          onContextMenu={vi.fn()}
          showWebsiteIcons={false}
        />
      </DndContext>
    )

    expect(markup).toContain('已刪除的項目')
  })
})

describe('ItemRow card cover', () => {
  it('passes the cached card cover preview to the card brand mark', () => {
    const markup = renderToStaticMarkup(
      <DndContext>
        <ItemRow
          item={{ ...item, type: 'card', cardBrand: 'mastercard' }}
          cardCoverImageSrc="data:image/webp;base64,UklGRg=="
          selected={false}
          onSelect={vi.fn()}
          onFavorite={vi.fn()}
          onContextMenu={vi.fn()}
          showWebsiteIcons={false}
        />
      </DndContext>
    )

    expect(markup).toContain('data-card-cover-image-src="data:image/webp;base64,UklGRg=="')
  })
})

describe('FolderRow hierarchy', () => {
  it('shows the leaf label while retaining the complete path for assistive text and actions', () => {
    const folder: FolderView = {
      id: 'bank',
      name: '金融/銀行',
      position: 0,
      createdAt: '2026-07-22T00:00:00.000Z',
      updatedAt: '2026-07-22T00:00:00.000Z'
    }
    const markup = renderToStaticMarkup(
      <DndContext>
        <SortableContext items={[folder.id]}>
          <FolderRow
            folder={folder}
            label="銀行"
            depth={1}
            selected={false}
            count={2}
            onSelect={vi.fn()}
            onEdit={vi.fn()}
          />
        </SortableContext>
      </DndContext>
    )

    expect(markup).toContain('padding-inline-start:28px')
    expect(markup).toContain('aria-label="金融/銀行"')
    expect(markup).toContain('cursor-grab')
    expect(markup).toContain('>銀行</span>')
    expect(markup).not.toContain('>金融/銀行</span>')
    expect(markup).not.toContain('lucide-grip-vertical')
  })

  it('exposes expansion state on the full folder action only for folders with children', () => {
    const folder: FolderView = {
      id: 'finance',
      name: '金融',
      position: 0,
      createdAt: '2026-07-22T00:00:00.000Z',
      updatedAt: '2026-07-22T00:00:00.000Z'
    }
    const parentMarkup = renderToStaticMarkup(
      <DndContext>
        <SortableContext items={[folder.id]}>
          <FolderRow
            folder={folder}
            hasChildren
            expanded={false}
            selected={false}
            count={7}
            onToggle={vi.fn()}
            onSelect={vi.fn()}
            onEdit={vi.fn()}
          />
        </SortableContext>
      </DndContext>
    )
    const leafMarkup = renderToStaticMarkup(
      <DndContext>
        <SortableContext items={[folder.id]}>
          <FolderRow
            folder={folder}
            selected={false}
            count={2}
            onSelect={vi.fn()}
            onEdit={vi.fn()}
          />
        </SortableContext>
      </DndContext>
    )

    expect(parentMarkup).toContain('aria-expanded="false"')
    expect(parentMarkup).toContain('padding-inline-start:12px')
    expect(parentMarkup).toContain('>7</small>')
    expect(parentMarkup).toContain('lucide-folders')
    expect(parentMarkup).not.toContain('lucide-chevron-right')
    expect(leafMarkup).not.toContain('aria-expanded=')
    expect(leafMarkup).toContain('>2</small>')
  })

  it('uses an open folder icon for expanded parent folders', () => {
    const folder: FolderView = {
      id: 'finance',
      name: '金融',
      position: 0,
      createdAt: '2026-07-22T00:00:00.000Z',
      updatedAt: '2026-07-22T00:00:00.000Z'
    }
    const markup = renderToStaticMarkup(
      <DndContext>
        <SortableContext items={[folder.id]}>
          <FolderRow
            folder={folder}
            hasChildren
            expanded
            selected={false}
            count={7}
            onToggle={vi.fn()}
            onSelect={vi.fn()}
            onEdit={vi.fn()}
          />
        </SortableContext>
      </DndContext>
    )

    expect(markup).toContain('aria-expanded="true"')
    expect(markup).toContain('lucide-folder-open')
    expect(markup).not.toContain('lucide-chevron-right')
  })
})
