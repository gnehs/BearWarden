import { msg } from '@lingui/core/macro'
import { i18n } from '../i18n'

export function formatVaultDate(value: string | null): string {
  if (!value) return i18n._(msg`Never used`)
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return i18n._(msg`Unknown`)
  return new Intl.DateTimeFormat(i18n.locale || 'en', {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(date)
}
