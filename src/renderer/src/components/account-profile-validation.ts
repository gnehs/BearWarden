import { MAX_ACCOUNT_PROFILE_NAME_BYTES } from '../../../shared/vault-contract'

export function profileNameValidationError(name: string): string | null {
  if (/\0|\r|\n/.test(name)) return '顯示名稱不可包含換行或空字元。'
  if (new TextEncoder().encode(name).byteLength > MAX_ACCOUNT_PROFILE_NAME_BYTES)
    return '顯示名稱不可超過 50 個 UTF-8 位元組。'
  return null
}

export function isAvatarColor(value: string): boolean {
  return /^#[0-9A-Fa-f]{6}$/.test(value)
}
