import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest'

const detectedLocale = vi.hoisted(() => ({ value: 'en-US' as string | undefined }))

vi.mock('@lingui/detect-locale', () => ({
  fromNavigator: () => detectedLocale.value
}))

import { activateLanguagePreference, handleSystemLanguageChange, i18n } from './i18n'

describe('runtime language preference', () => {
  beforeEach(() => {
    detectedLocale.value = 'en-US'
    vi.stubGlobal('document', { documentElement: { lang: '' } })
  })

  afterAll(() => {
    vi.unstubAllGlobals()
  })

  it('activates an explicit language and keeps it when the system language changes', async () => {
    await activateLanguagePreference('zh-TW')

    expect(i18n.locale).toBe('zh-TW')
    expect(document.documentElement.lang).toBe('zh-TW')

    detectedLocale.value = 'ja-JP'
    await handleSystemLanguageChange()

    expect(i18n.locale).toBe('zh-TW')
    expect(document.documentElement.lang).toBe('zh-TW')
  })

  it('tracks system language changes while the system preference is active', async () => {
    detectedLocale.value = 'zh-Hans-CN'
    await activateLanguagePreference('system')

    expect(i18n.locale).toBe('zh-CN')
    expect(document.documentElement.lang).toBe('zh-CN')

    detectedLocale.value = 'ja-JP'
    await handleSystemLanguageChange()

    expect(i18n.locale).toBe('ja')
    expect(document.documentElement.lang).toBe('ja')
  })
})
