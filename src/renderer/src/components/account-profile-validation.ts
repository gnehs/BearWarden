import { i18n } from '@lingui/core'
import { msg } from '@lingui/core/macro'
import { MAX_ACCOUNT_PROFILE_NAME_BYTES } from '../../../shared/vault-contract'

export function profileNameValidationError(name: string): string | null {
  if (/\0|\r|\n/.test(name))
    return i18n._(msg`The display name cannot contain newlines or null characters.`)
  if (new TextEncoder().encode(name).byteLength > MAX_ACCOUNT_PROFILE_NAME_BYTES)
    return i18n._(msg`The display name cannot exceed 50 UTF-8 bytes.`)
  return null
}

export function isAvatarColor(value: string): boolean {
  return /^#[0-9A-Fa-f]{6}$/.test(value)
}
