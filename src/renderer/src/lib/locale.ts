export const supportedLocales = ['en', 'zh-CN', 'zh-TW', 'ja'] as const

export type SupportedLocale = (typeof supportedLocales)[number]

export const defaultLocale: SupportedLocale = 'en'

/** Maps browser and operating-system locale variants onto the catalogs shipped by BearWarden. */
export function normalizeLocale(locale: string | null | undefined): SupportedLocale {
  if (!locale) return defaultLocale

  const normalized = locale.replaceAll('_', '-').toLowerCase()
  if (normalized === 'zh' || normalized.startsWith('zh-cn') || normalized.startsWith('zh-sg')) {
    return 'zh-CN'
  }
  if (normalized.startsWith('zh-hans')) return 'zh-CN'
  if (
    normalized.startsWith('zh-tw') ||
    normalized.startsWith('zh-hk') ||
    normalized.startsWith('zh-mo') ||
    normalized.startsWith('zh-hant')
  ) {
    return 'zh-TW'
  }
  if (normalized.startsWith('ja')) return 'ja'
  if (normalized.startsWith('en')) return 'en'
  return defaultLocale
}
