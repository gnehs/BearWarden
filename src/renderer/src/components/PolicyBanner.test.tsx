import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import type { PolicyBannerView } from '../../../shared/vault-contract'
import { PolicyBannerNotice } from './PolicyBanner'

function view(overrides: Partial<PolicyBannerView> = {}): PolicyBannerView {
  return {
    key: 'org:policy:revision',
    header: 'Heads up',
    description: 'Rotate your credentials',
    buttonText: null,
    showAfterEveryLogin: false,
    ...overrides
  }
}

function render(banner: PolicyBannerView): string {
  return renderToStaticMarkup(<PolicyBannerNotice banner={banner} onDismiss={() => undefined} />)
}

describe('PolicyBannerNotice', () => {
  it('shows the header and description with an accessible close control', () => {
    const markup = render(view())
    expect(markup).toContain('Heads up')
    expect(markup).toContain('Rotate your credentials')
    expect(markup).toContain('role="status"')
    expect(markup).toContain('aria-label=')
    expect(markup).toContain('data-slot="alert-action"')
  })

  it('renders organization text as plain text, never as markup or a link', () => {
    const markup = render(
      view({
        header: '<img src=x onerror=alert(1)>',
        description: '<a href="https://evil.example">click</a> **bold** [x](https://evil.example)'
      })
    )
    expect(markup).not.toContain('<img')
    expect(markup).not.toContain('<a ')
    expect(markup).not.toContain('<strong')
    expect(markup).toContain('&lt;img src=x onerror=alert(1)&gt;')
    expect(markup).toContain('**bold**')
  })

  it('replaces the close control with the acknowledge button when a header and label exist', () => {
    const markup = render(view({ buttonText: 'Got it' }))
    expect(markup).toContain('Got it')
    expect(markup).not.toContain('data-slot="alert-action"')
  })

  it('ignores a button label that has no header, matching the official clients', () => {
    const markup = render(view({ header: null, buttonText: 'Got it' }))
    expect(markup).not.toContain('Got it')
    expect(markup).not.toContain('data-slot="alert-title"')
    expect(markup).toContain('data-slot="alert-action"')
  })
})
