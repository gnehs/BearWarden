import { i18n } from '@lingui/core'
import { I18nProvider } from '@lingui/react'
import { createElement, type ReactNode } from 'react'
import { vi } from 'vitest'
import { messages } from '../locales/zh-TW/messages.po'

i18n.loadAndActivate({ locale: 'zh-TW', messages })

// Existing renderer tests intentionally exercise components in isolation through server rendering.
// Mirror the application root so Lingui macros receive the same provider without adding boilerplate
// to every test case.
vi.mock('react-dom/server', async (importOriginal) => {
  const server = await importOriginal<typeof import('react-dom/server')>()
  const withI18n = (node: ReactNode): ReactNode => createElement(I18nProvider, { i18n }, node)

  return {
    ...server,
    renderToStaticMarkup: (
      node: ReactNode,
      options?: Parameters<typeof server.renderToStaticMarkup>[1]
    ) => server.renderToStaticMarkup(withI18n(node), options),
    renderToString: (node: ReactNode, options?: Parameters<typeof server.renderToString>[1]) =>
      server.renderToString(withI18n(node), options)
  }
})
