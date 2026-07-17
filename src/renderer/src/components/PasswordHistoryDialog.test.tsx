import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { PasswordHistoryRestoreButton } from './Dialogs'

describe('PasswordHistoryDialog trash boundary', () => {
  it('renders no restore action in read-only trash mode', () => {
    const markup = renderToStaticMarkup(<PasswordHistoryRestoreButton busy={false} />)

    expect(markup).toBe('')
    expect(markup).not.toContain('套用為目前密碼')
  })

  it('keeps the restore action for active items', () => {
    const markup = renderToStaticMarkup(
      <PasswordHistoryRestoreButton busy={false} onRestore={() => undefined} />
    )

    expect(markup).toContain('套用為目前密碼')
  })
})
