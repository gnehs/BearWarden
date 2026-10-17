import type { EmergencyAccessView } from '../../../shared/vault-contract'

export function emergencyAccessDisplayName(
  entry: Pick<EmergencyAccessView, 'name' | 'email'>
): string {
  return entry.name?.trim() || entry.email
}

export function safeEmergencyAccessAvatarColor(avatarColor: string | null): string | undefined {
  return avatarColor && /^#[0-9a-f]{6}$/i.test(avatarColor) ? avatarColor : undefined
}
