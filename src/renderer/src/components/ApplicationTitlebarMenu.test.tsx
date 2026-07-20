import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { shouldUseApplicationTitlebarMenu } from '../lib/application-titlebar-menu'
import ApplicationTitlebarMenu from './ApplicationTitlebarMenu'

describe('ApplicationTitlebarMenu', () => {
  it('uses custom titlebar menus on Windows and Linux but not macOS', () => {
    expect(shouldUseApplicationTitlebarMenu('Mozilla/5.0 (Windows NT 10.0; Win64; x64)')).toBe(true)
    expect(shouldUseApplicationTitlebarMenu('Mozilla/5.0 (X11; Linux x86_64)')).toBe(true)
    expect(shouldUseApplicationTitlebarMenu('Mozilla/5.0 (Macintosh; Intel Mac OS X)')).toBe(false)
  })

  it('renders the desktop application menu triggers', () => {
    const markup = renderToStaticMarkup(<ApplicationTitlebarMenu />)

    expect(markup).toContain('aria-label="應用程式選單"')
    expect(markup).toContain('檔案')
    expect(markup).toContain('保管庫')
    expect(markup).toContain('編輯')
    expect(markup).toContain('檢視')
    expect(markup).toContain('視窗')
  })
})
