import type { SendView } from '../../../shared/vault-contract'

export interface SendStatus {
  key:
    | 'password'
    | 'email-verification'
    | 'disabled'
    | 'expired'
    | 'max-access-reached'
    | 'pending-deletion'
    | 'hidden-text'
    | 'hidden-email'
  label: string
}

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
): SendStatus[] {
  const statuses: SendStatus[] = []

  if (send.passwordProtected || send.authType === 'password') {
    statuses.push({ key: 'password', label: '需要密碼' })
  }
  if (usesEmailVerification(send)) {
    statuses.push({ key: 'email-verification', label: 'Email 驗證' })
  }
  if (send.disabled) statuses.push({ key: 'disabled', label: '已停用' })
  if (hasElapsed(send.expirationDate, now)) {
    statuses.push({ key: 'expired', label: '已過期' })
  }
  if (send.maxAccessCount !== null && send.accessCount >= send.maxAccessCount) {
    statuses.push({ key: 'max-access-reached', label: '已達存取上限' })
  }
  if (hasElapsed(send.deletionDate, now)) {
    statuses.push({ key: 'pending-deletion', label: '待刪除' })
  }
  if (send.type === 'text' && send.hidden) {
    statuses.push({ key: 'hidden-text', label: '預設隱藏文字' })
  }
  if (send.hideEmail) statuses.push({ key: 'hidden-email', label: '隱藏寄件者 Email' })

  return statuses
}

export function formatSendDate(value: string | null, locale = 'zh-TW'): string {
  if (!value) return '未設定'
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return '日期格式無效'
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
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000)
  return local.toISOString().slice(0, 16)
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
    : '最大存取次數必須是 1 到 2,147,483,647 之間的整數'
}
