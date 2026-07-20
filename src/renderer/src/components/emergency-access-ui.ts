import { i18n } from '@lingui/core'
import { msg } from '@lingui/core/macro'
import type { EmergencyAccessView } from '../../../shared/vault-contract'

const statusLabels = {
  0: msg`Invited`,
  1: msg`Invitation accepted`,
  2: msg`Confirmed`,
  3: msg`Access requested`,
  4: msg`Access approved`
} satisfies Record<EmergencyAccessView['status'], ReturnType<typeof msg>>

function creationDateFormatter(): Intl.DateTimeFormat {
  return new Intl.DateTimeFormat(i18n.locale || 'en', {
    dateStyle: 'medium',
    timeStyle: 'short'
  })
}

export function emergencyAccessStatusLabel(status: EmergencyAccessView['status']): string {
  return i18n._(statusLabels[status])
}

export function emergencyAccessTypeLabel(type: number): string {
  return type === 0
    ? i18n._(msg`View`)
    : type === 1
      ? i18n._(msg`Takeover`)
      : i18n._(msg`Unknown type (${type})`)
}

export function emergencyAccessDisplayName(
  entry: Pick<EmergencyAccessView, 'name' | 'email'>
): string {
  return entry.name?.trim() || entry.email
}

export function emergencyAccessInitial(entry: Pick<EmergencyAccessView, 'name' | 'email'>): string {
  return (
    Array.from(emergencyAccessDisplayName(entry))[0]?.toLocaleUpperCase(i18n.locale || 'en') ?? '?'
  )
}

export function emergencyAccessCreationLabel(creationDate: string | null): string | null {
  if (creationDate === null) return null
  const parsed = new Date(creationDate)
  return Number.isFinite(parsed.getTime()) ? creationDateFormatter().format(parsed) : null
}

export function safeEmergencyAccessAvatarColor(avatarColor: string | null): string | undefined {
  return avatarColor && /^#[0-9a-f]{6}$/i.test(avatarColor) ? avatarColor : undefined
}
