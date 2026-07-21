import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import AutofillShortcut from './AutofillShortcut'

describe('AutofillShortcut', () => {
  it('renders Ctrl and one backslash as separate keyboard keys', () => {
    const markup = renderToStaticMarkup(<AutofillShortcut shortcut={'Control+\\'} />)

    expect(markup.match(/data-slot="kbd"/g)).toHaveLength(2)
    expect(markup).toContain('>Ctrl</kbd>')
    expect(markup).toContain('>\\</kbd>')
    expect(markup).not.toContain('>\\\\</kbd>')
  })

  it('renders a multi-modifier preset accessibly', () => {
    const markup = renderToStaticMarkup(<AutofillShortcut shortcut="Command+Control+K" />)

    expect(markup.match(/data-slot="kbd"/g)).toHaveLength(3)
    expect(markup).toContain('>⌘</kbd>')
    expect(markup).toContain('>Ctrl</kbd>')
    expect(markup).toContain('>K</kbd>')
    expect(markup).toContain('aria-label="Command 加 Control 加 K"')
  })
})
