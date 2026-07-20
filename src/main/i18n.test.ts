import { afterEach, describe, expect, it } from 'vitest'
import { initializeMainI18n, mainI18n, normalizeMainLocale, translateMain } from './i18n'

describe('main-process i18n', () => {
  afterEach(() => {
    initializeMainI18n('en')
  })

  it.each([
    ['en-US', 'en'],
    ['ja_JP', 'ja'],
    ['zh', 'zh-CN'],
    ['zh-Hans-CN', 'zh-CN'],
    ['zh-SG', 'zh-CN'],
    ['zh-Hant-HK', 'zh-TW'],
    ['zh_MO', 'zh-TW'],
    ['fr-FR', 'en'],
    ['', 'en'],
    [undefined, 'en']
  ] as const)('normalizes %s to %s', (input, expected) => {
    expect(normalizeMainLocale(input)).toBe(expected)
  })

  it('activates all bundled catalogs without relying on renderer resources', () => {
    expect(initializeMainI18n('en-US')).toBe('en')
    expect(translateMain('applicationMenu.vault')).toBe('Vault')

    expect(initializeMainI18n('zh-CN')).toBe('zh-CN')
    expect(translateMain('applicationMenu.vault')).toBe('密码库')

    expect(initializeMainI18n('zh-TW')).toBe('zh-TW')
    expect(translateMain('applicationMenu.vault')).toBe('密碼庫')

    expect(initializeMainI18n('ja-JP')).toBe('ja')
    expect(translateMain('applicationMenu.vault')).toBe('保管庫')
    expect(mainI18n.locale).toBe('ja')
  })
})
