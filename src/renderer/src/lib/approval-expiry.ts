import { msg } from '@lingui/core/macro'
import { i18n } from '../i18n'

export function approvalExpiryMessage(expiresAt: number, now: number): string {
  const remainingSeconds = Math.max(0, Math.ceil((expiresAt - now) / 1_000))
  const formattedRemainingSeconds = new Intl.NumberFormat(i18n.locale).format(remainingSeconds)
  return remainingSeconds > 0
    ? i18n._(msg`This request expires in about ${formattedRemainingSeconds} seconds.`)
    : i18n._(msg`This request has expired.`)
}
