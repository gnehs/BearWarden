import { describe, expect, it, vi } from 'vitest'
import { initialLanguagePreference, localeForPreference, normalizeLocale } from './locale'

describe('normalizeLocale', () => {
  it.each([
    ['en-US', 'en'],
    ['en_GB', 'en'],
    ['zh-CN', 'zh-CN'],
    ['zh-Hans-SG', 'zh-CN'],
    ['zh-TW', 'zh-TW'],
    ['zh-Hant-HK', 'zh-TW'],
    ['ja-JP', 'ja'],
    ['fr-FR', 'en'],
    [undefined, 'en']
  ])('maps %s to %s', (input, expected) => {
    expect(normalizeLocale(input)).toBe(expected)
  })
})

describe('localeForPreference', () => {
  it('follows the current system locale for the system preference', () => {
    expect(localeForPreference('system', 'zh-Hant-HK')).toBe('zh-TW')
    expect(localeForPreference('system', 'ja-JP')).toBe('ja')
  })

  it('keeps an explicit language independent of the system locale', () => {
    expect(localeForPreference('en', 'zh-TW')).toBe('en')
    expect(localeForPreference('zh-CN', 'ja-JP')).toBe('zh-CN')
  })
})

describe('initialLanguagePreference', () => {
  it('uses the persisted preference when settings load succeeds', async () => {
    await expect(
      initialLanguagePreference(vi.fn(async () => ({ language: 'ja' as const })))
    ).resolves.toBe('ja')
  })

  it('falls back to the system preference when settings load fails', async () => {
    await expect(
      initialLanguagePreference(vi.fn(async () => Promise.reject(new Error('IPC unavailable'))))
    ).resolves.toBe('system')
  })
})
