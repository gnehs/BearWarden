import type { EmergencyAccessView } from '../../../shared/vault-contract'

const statusLabels: Record<EmergencyAccessView['status'], string> = {
  0: '已邀請',
  1: '已接受邀請',
  2: '已確認',
  3: '已提出存取要求',
  4: '已核准存取'
}

const creationDateFormatter = new Intl.DateTimeFormat('zh-TW', {
  dateStyle: 'medium',
  timeStyle: 'short'
})

export function emergencyAccessStatusLabel(status: EmergencyAccessView['status']): string {
  return statusLabels[status]
}

export function emergencyAccessTypeLabel(type: number): string {
  return type === 0 ? '檢視' : type === 1 ? '接管' : `未知類型（${type}）`
}

export function emergencyAccessDisplayName(
  entry: Pick<EmergencyAccessView, 'name' | 'email'>
): string {
  return entry.name?.trim() || entry.email
}

export function emergencyAccessInitial(entry: Pick<EmergencyAccessView, 'name' | 'email'>): string {
  return Array.from(emergencyAccessDisplayName(entry))[0]?.toLocaleUpperCase('zh-TW') ?? '?'
}

export function emergencyAccessCreationLabel(creationDate: string | null): string | null {
  if (creationDate === null) return null
  const parsed = new Date(creationDate)
  return Number.isFinite(parsed.getTime()) ? creationDateFormatter.format(parsed) : null
}

export function safeEmergencyAccessAvatarColor(avatarColor: string | null): string | undefined {
  return avatarColor && /^#[0-9a-f]{6}$/i.test(avatarColor) ? avatarColor : undefined
}
