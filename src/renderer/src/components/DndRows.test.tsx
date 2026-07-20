import { DndContext } from '@dnd-kit/core'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import type { LoginSummary, TotpCodeView } from '../../../shared/vault-contract'
import { ItemRow } from './DndRows'

vi.mock('./PaymentCardBrandMark', () => ({ default: () => <span /> }))
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
