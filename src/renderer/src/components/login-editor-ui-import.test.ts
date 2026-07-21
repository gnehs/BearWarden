import { afterEach, describe, expect, it, vi } from 'vitest'

afterEach(() => {
  vi.doUnmock('@lingui/core')
  vi.resetModules()
})

describe('login-editor-ui module initialization', () => {
  it('does not translate messages before the locale is activated', async () => {
    const translate = vi.fn(() => {
      throw new Error('translation called during module initialization')
    })
    vi.resetModules()
    vi.doMock('@lingui/core', () => ({ i18n: { _: translate } }))

    await expect(import('./login-editor-ui')).resolves.toBeDefined()
    expect(translate).not.toHaveBeenCalled()
  })
})
