import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import { ItemHistoryRows } from './ItemHistoryRows'

const baseItem = {
  updatedAt: '2026-07-17T01:00:00.000Z',
  createdAt: '2026-07-16T01:00:00.000Z',
  passwordUpdatedAt: null,
  passwordHistoryCount: 0
}

describe('ItemHistoryRows', () => {
  it('shows the real password revision date when the authorized view provides it', () => {
    const formatDate = vi.fn((value: string | null) => `formatted:${value}`)
    const markup = renderToStaticMarkup(
      <ItemHistoryRows
        item={{ ...baseItem, passwordUpdatedAt: '2026-07-17T00:30:00.000Z' }}
        formatDate={formatDate}
      />
    )

    expect(markup).toContain('密碼上次更新時間')
    expect(markup).toContain('formatted:2026-07-17T00:30:00.000Z')
  })

  it('does not invent a password history row when no revision date is available', () => {
    const markup = renderToStaticMarkup(
      <ItemHistoryRows item={baseItem} formatDate={(value) => String(value)} />
    )

    expect(markup).not.toContain('密碼上次更新時間')
    expect(markup).toContain('上次編輯')
    expect(markup).toContain('已建立')
  })

  it('renders the existing unknown-date label for invalid revision metadata', () => {
    const markup = renderToStaticMarkup(
      <ItemHistoryRows item={{ ...baseItem, passwordUpdatedAt: 'not-a-date' }} />
    )

    expect(markup).toContain('密碼上次更新時間')
    expect(markup).toContain('未知')
  })

  it('shows a password history row with count and view action when history exists', () => {
    const markup = renderToStaticMarkup(
      <ItemHistoryRows
        item={{ ...baseItem, passwordHistoryCount: 3 }}
        onViewPasswordHistory={() => undefined}
      />
    )

    expect(markup).toContain('密碼歷程')
    expect(markup).toContain('3 筆記錄')
    expect(markup).toContain('檢視密碼歷程')
  })

  it('hides the password history row when there is no history', () => {
    const markup = renderToStaticMarkup(
      <ItemHistoryRows item={baseItem} onViewPasswordHistory={() => undefined} />
    )

    expect(markup).not.toContain('密碼歷程')
  })
})
