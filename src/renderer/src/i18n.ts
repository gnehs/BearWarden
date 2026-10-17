import { i18n } from '@lingui/core'
import type { Messages } from '@lingui/core'
import type { AppLanguagePreference } from '../../shared/vault-contract'
import { localeForPreference, normalizeLocale, type SupportedLocale } from './lib/locale'

const catalogLoaders: Record<SupportedLocale, () => Promise<{ messages: Messages }>> = {
  en: () => import('./locales/en/messages.po'),
  'zh-CN': () => import('./locales/zh-CN/messages.po'),
  'zh-TW': () => import('./locales/zh-TW/messages.po'),
  ja: () => import('./locales/ja/messages.po')
}

export { i18n }

let activeLanguagePreference: AppLanguagePreference = 'system'
let activationEpoch = 0

async function activateLocale(locale: SupportedLocale): Promise<void> {
  const epoch = ++activationEpoch
  const { messages } = await catalogLoaders[locale]()
  if (epoch !== activationEpoch) return
  i18n.loadAndActivate({ locale, messages })
  document.documentElement.lang = locale
}

export async function activateLanguagePreference(preference: AppLanguagePreference): Promise<void> {
  activeLanguagePreference = preference
  await activateLocale(localeForPreference(preference, navigator.language))
}

/** Applies an OS language change only while the user is following the system language. */
export async function handleSystemLanguageChange(): Promise<void> {
  if (activeLanguagePreference !== 'system') return
  await activateLocale(normalizeLocale(navigator.language))
}
