import type { AppLanguagePreference } from '../../../shared/vault-contract'

export const supportedLocales = ['en', 'zh-CN', 'zh-TW', 'ja'] as const

export type SupportedLocale = (typeof supportedLocales)[number]

export const defaultLocale: SupportedLocale = 'en'

/** Reads the persisted preference without allowing settings IPC failure to block application boot. */
export async function initialLanguagePreference(
  readSettings: () => Promise<{ language: AppLanguagePreference }>
): Promise<AppLanguagePreference> {
  try {
    return (await readSettings()).language
  } catch {
    return 'system'
  }
}

/** Resolves a persisted preference to the catalog that should be active right now. */
export function localeForPreference(
  preference: AppLanguagePreference,
  systemLocale: string | null | undefined
): SupportedLocale {
  return preference === 'system' ? normalizeLocale(systemLocale) : preference
}

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
