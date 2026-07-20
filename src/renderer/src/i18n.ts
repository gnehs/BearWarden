import { i18n } from '@lingui/core'
import { fromNavigator } from '@lingui/detect-locale'
import type { Messages } from '@lingui/core'
import { normalizeLocale, type SupportedLocale } from './lib/locale'

const catalogLoaders: Record<SupportedLocale, () => Promise<{ messages: Messages }>> = {
  en: () => import('./locales/en/messages.po'),
  'zh-CN': () => import('./locales/zh-CN/messages.po'),
  'zh-TW': () => import('./locales/zh-TW/messages.po'),
  ja: () => import('./locales/ja/messages.po')
}

export { i18n }

export function detectSystemLocale(): SupportedLocale {
  return normalizeLocale(fromNavigator())
}

export async function activateLocale(locale: SupportedLocale): Promise<void> {
  const { messages } = await catalogLoaders[locale]()
  i18n.loadAndActivate({ locale, messages })
  document.documentElement.lang = locale
}
