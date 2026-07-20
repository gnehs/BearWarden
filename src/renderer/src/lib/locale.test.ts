import { describe, expect, it } from 'vitest'
import { normalizeLocale } from './locale'

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
