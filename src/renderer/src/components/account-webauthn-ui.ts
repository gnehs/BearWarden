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
    return '主密碼驗證失敗；若要再試，請重新輸入主密碼。'
  }
  if (isWebAuthnMutationOutcomeUnknown(error)) {
    return `${webAuthnActionLabel(action)}結果不明；已重新整理狀態。請先確認目前金鑰，勿直接重試。`
  }
  if (error instanceof Error && error.message.includes('SYNC_AUTH_REQUIRED')) {
    return '同步登入已失效，請先重新登入。'
  }
  return `無法${webAuthnActionLabel(action)}安全金鑰，請稍後再試。`
}

function safeWebAuthnKeyName(value: string): string {
  const name = [...value]
    .filter((character) => {
      const codePoint = character.codePointAt(0) ?? 0
      return codePoint >= 32 && codePoint !== 127
    })
    .join('')
    .trim()
  return name.length > 0 ? name.slice(0, 256) : '未命名的安全金鑰'
}

function webAuthnActionLabel(action: AccountWebAuthnAction): string {
  switch (action) {
    case 'list':
      return '讀取'
    case 'enroll':
      return '新增'
    case 'remove':
      return '移除'
  }
}
