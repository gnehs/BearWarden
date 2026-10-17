import { i18n } from '@lingui/core'
import { msg } from '@lingui/core/macro'
import { format } from 'date-fns'
import type { SendView } from '../../../shared/vault-contract'

export type SendStatusKey =
  | 'password'
  | 'email-verification'
  | 'disabled'
  | 'expired'
  | 'max-access-reached'
  | 'pending-deletion'
  | 'hidden-text'
  | 'hidden-email'

type SendWithForwardCompatibleAuth = Omit<SendView, 'authType'> & { authType: string }

function hasElapsed(value: string | null, now: Date): boolean {
  if (!value) return false
  const timestamp = Date.parse(value)
  return Number.isFinite(timestamp) && timestamp <= now.getTime()
}

export function usesEmailVerification(
  send: Pick<SendWithForwardCompatibleAuth, 'authType'>
): boolean {
  return send.authType === 'email'
}

export function sendStatuses(
  send: SendWithForwardCompatibleAuth,
  now: Date = new Date()
): SendStatusKey[] {
  const statuses: SendStatusKey[] = []

  if (send.passwordProtected || send.authType === 'password') statuses.push('password')
  if (usesEmailVerification(send)) statuses.push('email-verification')
  if (send.disabled) statuses.push('disabled')
  if (hasElapsed(send.expirationDate, now)) statuses.push('expired')
  if (send.maxAccessCount !== null && send.accessCount >= send.maxAccessCount) {
    statuses.push('max-access-reached')
  }
  if (hasElapsed(send.deletionDate, now)) statuses.push('pending-deletion')
  if (send.type === 'text' && send.hidden) statuses.push('hidden-text')
  if (send.hideEmail) statuses.push('hidden-email')

  return statuses
}

export function formatSendDate(value: string | null, locale = i18n.locale || 'en'): string {
  if (!value) return i18n._(msg`Not set`)
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return i18n._(msg`Invalid date`)
  return new Intl.DateTimeFormat(locale, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  }).format(date)
}

export function dateTimeLocalValue(value: string | null): string {
  if (!value) return ''
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return ''
  return format(date, "yyyy-MM-dd'T'HH:mm")
}

export function dateTimeLocalToIso(value: string): string | null {
  if (value.length === 0) return null
  const date = new Date(value)
  return Number.isFinite(date.getTime()) ? date.toISOString() : null
}

export function maxAccessCountValidationMessage(value: number | null | undefined): string | null {
  if (value === null || value === undefined) return null
  return Number.isSafeInteger(value) && value > 0 && value <= 2_147_483_647
    ? null
    : i18n._(msg`Maximum access count must be an integer between 1 and 2,147,483,647.`)
}
