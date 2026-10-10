import type { EmergencyAccessView } from '../../../shared/vault-contract'
import { formatDateTime } from '../lib/vault-date'

export function emergencyAccessDisplayName(
  entry: Pick<EmergencyAccessView, 'name' | 'email'>
): string {
  return entry.name?.trim() || entry.email
}

export function emergencyAccessCreationLabel(creationDate: string | null): string | null {
  return formatDateTime(creationDate)
}

export function safeEmergencyAccessAvatarColor(avatarColor: string | null): string | undefined {
  return avatarColor && /^#[0-9a-f]{6}$/i.test(avatarColor) ? avatarColor : undefined
}
