import type { AccountMutationResult, AccountStatusEntry } from '../../../shared/vault-contract'

export const MAX_LOCAL_ACCOUNTS = 5

export type AccountConfirmationAction =
  | { readonly kind: 'add' }
  | { readonly kind: 'switch'; readonly accountId: string; readonly slot: number }
  | { readonly kind: 'remove'; readonly accountId: string; readonly slot: number }

export type AccountMoveDirection = 'up' | 'down'

export class AccountMutationGate {
  private active = false

  tryEnter(): boolean {
    if (this.active) return false
    this.active = true
    return true
  }

  leave(): void {
    this.active = false
  }
}

export function isCurrentAccountRefresh(
  mutationRequestId: number,
  currentMutationRequestId: number,
  statusRequestId: number,
  currentStatusRequestId: number
): boolean {
  return (
    mutationRequestId === currentMutationRequestId && statusRequestId === currentStatusRequestId
  )
}

export function localAccountLabel(slot: number): string {
  return `帳號 ${slot}`
}

export function localAccountCode(accountId: string): string {
  return accountId.slice(0, 8).toUpperCase()
}

export function localAccountPresentation(account: AccountStatusEntry): {
  label: string
  description: string
  active: boolean
} {
  return {
    label: localAccountLabel(account.slot),
    description: `${account.active ? '目前使用中的本機帳號' : '可切換至這個本機帳號'} · 本機代碼 ${localAccountCode(account.id)}`,
    active: account.active
  }
}

export function accountConfirmationContent(action: AccountConfirmationAction): {
  title: string
  description: string
  actionLabel: string
  destructive: boolean
} {
  if (action.kind === 'remove') {
    return {
      title: `移除${localAccountLabel(action.slot)}？`,
      description:
        '這會永久刪除這台裝置上的加密密碼庫、設定與生物辨識資料，且無法復原；不會刪除 Bitwarden 或 Vaultwarden 伺服器上的帳號與資料。',
      actionLabel: '永久移除本機資料',
      destructive: true
    }
  }
  const target = action.kind === 'add' ? '新增本機帳號' : `切換至${localAccountLabel(action.slot)}`
  return {
    title: `${target}？`,
    description: '這會先鎖定密碼庫，然後安全地重新啟動 BearWarden。未儲存的變更不會保留。',
    actionLabel: '鎖定並重新啟動',
    destructive: false
  }
}

export function accountMutationError(error: unknown): string {
  const message = error instanceof Error ? error.message : ''
  if (message.includes('ACCOUNT_LIMIT_REACHED')) return '本機帳號已達上限，最多可保留 5 個。'
  if (message.includes('ACCOUNT_NOT_FOUND') || message.includes('NOT_FOUND')) {
    return '找不到指定的本機帳號，請重新整理後再試。'
  }
  if (message.includes('ACCOUNT_ACTIVE_REMOVAL_FORBIDDEN')) {
    return '目前使用中的帳號不能移除，請先切換到另一個帳號。'
  }
  if (message.includes('ACCOUNT_STALE_STATE')) {
    return '本機帳號清單已變更，請重新整理後再試。'
  }
  if (message.includes('ACCOUNT_SWITCH_UNAVAILABLE') || message.includes('SWITCH_UNAVAILABLE')) {
    return '本機帳號管理目前不可用，請稍後再試。'
  }
  if (message.includes('ACCOUNT_SWITCH_IN_PROGRESS') || message.includes('IN_PROGRESS')) {
    return '已有本機帳號切換正在處理，請等待 BearWarden 重新啟動。'
  }
  if (message.includes('ACCOUNT_SWITCH_RESULT_UNKNOWN') || message.includes('RESULT_UNKNOWN')) {
    return '帳號操作結果無法確認。請重新啟動 BearWarden 後確認目前狀態。'
  }
  return '無法完成本機帳號操作，請稍後再試。'
}

export function accountSwitchButtonDisabled(account: AccountStatusEntry, busy: boolean): boolean {
  return busy || account.active
}

export function accountMutationKeepsBusy(result: AccountMutationResult): boolean {
  return result.kind === 'relaunch-required'
}

export function accountMoveButtonDisabled(
  index: number,
  accountCount: number,
  direction: AccountMoveDirection,
  busy: boolean
): boolean {
  return busy || accountCount < 2 || (direction === 'up' ? index <= 0 : index >= accountCount - 1)
}

export function accountRemoveButtonDisabled(
  account: AccountStatusEntry,
  accountCount: number,
  busy: boolean
): boolean {
  return busy || account.active || accountCount <= 1
}

export function moveAccountIds(
  accounts: readonly AccountStatusEntry[],
  accountId: string,
  direction: AccountMoveDirection
): readonly string[] | null {
  const index = accounts.findIndex((account) => account.id === accountId)
  const target = direction === 'up' ? index - 1 : index + 1
  if (index < 0 || target < 0 || target >= accounts.length) return null
  const orderedIds = accounts.map((account) => account.id)
  const currentId = orderedIds[index]!
  orderedIds[index] = orderedIds[target]!
  orderedIds[target] = currentId
  return orderedIds
}

export function requestAccountAction(
  requestEditorTransition: (action: () => void) => void,
  action: () => void
): void {
  requestEditorTransition(action)
}
