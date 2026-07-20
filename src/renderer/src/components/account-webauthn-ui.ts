import { i18n } from '@lingui/core'
import { msg } from '@lingui/core/macro'
import type {
  AccountTwoFactorProvider,
  AccountWebAuthnKeyView
} from '../../../shared/vault-contract'

export type DisableablePersonalProvider = 0 | 1 | 2 | 3 | 7

export function isDisableablePersonalProvider(type: number): type is DisableablePersonalProvider {
  return type === 0 || type === 1 || type === 2 || type === 3 || type === 7
}

export function enabledPersonalTwoFactorMethodCount(
  providers: readonly AccountTwoFactorProvider[]
): number {
  return providers.filter(
    ({ type, enabled }) => enabled && (isDisableablePersonalProvider(type) || type === 4)
  ).length
}

export function isLastVisiblePersonalTwoFactorMethod(
  providers: readonly AccountTwoFactorProvider[],
  target: DisableablePersonalProvider
): boolean {
  return (
    providers.some((provider) => provider.type === target && provider.enabled) &&
    enabledPersonalTwoFactorMethodCount(providers) === 1
  )
}

export function hiddenProviderEscapeTargets(
  providers: readonly AccountTwoFactorProvider[]
): Array<2 | 3> {
  return ([2, 3] as const).filter(
    (type) => !providers.some((provider) => provider.type === type && provider.enabled)
  )
}

export type AccountWebAuthnAction = 'list' | 'enroll' | 'remove'

export interface AccountWebAuthnKeyPresentation {
  /** Server-selected numeric slot, used only for React's local list identity. */
  id: number
  name: string
  migrated: boolean
}

export function webAuthnKeyPresentation(
  keys: readonly AccountWebAuthnKeyView[]
): AccountWebAuthnKeyPresentation[] {
  return keys.map((key) => ({
    id: key.id,
    name: safeWebAuthnKeyName(key.name),
    migrated: key.migrated
  }))
}

export function canEnrollWebAuthnKey(busy: boolean, name: string, masterPassword: string): boolean {
  return !busy && name.trim().length > 0 && masterPassword.length > 0
}

export function canRemoveWebAuthnKey(busy: boolean, keyCount: number): boolean {
  return !busy && keyCount > 1
}

export function isWebAuthnMutationOutcomeUnknown(error: unknown): boolean {
  return error instanceof Error && error.message.includes('TWO_FACTOR_MUTATION_UNKNOWN')
}

export function webAuthnActionError(error: unknown, action: AccountWebAuthnAction): string {
  if (error instanceof Error && error.message.includes('INVALID_MASTER_PASSWORD')) {
    return i18n._(
      msg`Master password verification failed. Enter your master password again to retry.`
    )
  }
  if (isWebAuthnMutationOutcomeUnknown(error)) {
    return i18n._(
      msg`The ${webAuthnActionLabel(action)} result is unknown. The status has been refreshed. Verify your current keys before retrying.`
    )
  }
  if (error instanceof Error && error.message.includes('SYNC_AUTH_REQUIRED')) {
    return i18n._(msg`Your sync session has expired. Sign in again first.`)
  }
  return i18n._(msg`Unable to ${webAuthnActionLabel(action)} the security key. Try again later.`)
}

function safeWebAuthnKeyName(value: string): string {
  const name = [...value]
    .filter((character) => {
      const codePoint = character.codePointAt(0) ?? 0
      return codePoint >= 32 && codePoint !== 127
    })
    .join('')
    .trim()
  return name.length > 0 ? name.slice(0, 256) : i18n._(msg`Unnamed security key`)
}

function webAuthnActionLabel(action: AccountWebAuthnAction): string {
  switch (action) {
    case 'list':
      return i18n._(msg`load`)
    case 'enroll':
      return i18n._(msg`add`)
    case 'remove':
      return i18n._(msg`remove`)
  }
}
