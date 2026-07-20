import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import AutofillShortcut from './AutofillShortcut'

describe('AutofillShortcut', () => {
  it('renders Ctrl and one backslash as separate keyboard keys', () => {
    const markup = renderToStaticMarkup(<AutofillShortcut />)

    expect(markup.match(/data-slot="kbd"/g)).toHaveLength(2)
    expect(markup).toContain('>Ctrl</kbd>')
    expect(markup).toContain('>\\</kbd>')
    expect(markup).not.toContain('>\\\\</kbd>')
  })
})
