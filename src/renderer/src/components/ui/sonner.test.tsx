import { renderToStaticMarkup } from 'react-dom/server'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { Toaster } from './sonner'

const { renderSonner } = vi.hoisted(() => ({
  renderSonner: vi.fn<(props: import('sonner').ToasterProps) => null>(() => null)
}))

vi.mock('sonner', () => ({ Toaster: renderSonner }))

describe('Toaster', () => {
  beforeEach(() => {
    renderSonner.mockClear()
    vi.stubGlobal('document', {
      documentElement: {
        classList: { contains: () => false },
        dataset: {}
      }
    })
  })

  it('keeps the close button above actions instead of centering both on the right', () => {
    renderToStaticMarkup(<Toaster />)

    const props = renderSonner.mock.calls[0]?.[0]
    const toastClassName = props?.toastOptions?.classNames?.toast
    const closeButtonClassName = props?.toastOptions?.classNames?.closeButton

    expect(toastClassName).toContain('has-[.cn-toast-close-button]:!pr-10')
    expect(closeButtonClassName).toContain('!top-2.5')
    expect(closeButtonClassName).not.toContain('!top-1/2')
    expect(closeButtonClassName).not.toContain('!-translate-y-1/2')
  })
})
