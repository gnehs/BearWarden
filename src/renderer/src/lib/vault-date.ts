import { msg } from '@lingui/core/macro'
import { i18n } from '../i18n'

export function formatDateTime(value: string | null | undefined): string | null {
  if (!value) return null
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return null
  return new Intl.DateTimeFormat(i18n.locale || 'en', {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(date)
}

export function formatVaultDate(value: string | null): string {
  if (!value) return i18n._(msg`Never used`)
  return formatDateTime(value) ?? i18n._(msg`Unknown`)
}
