import type { AccountStatusEntry } from '../../../shared/vault-contract'

export const MAX_LOCAL_ACCOUNTS = 5

export type AccountConfirmationAction =
  | { readonly kind: 'add' }
  | { readonly kind: 'switch'; readonly accountId: string; readonly slot: number }

export function localAccountLabel(slot: number): string {
  return `帳號 ${slot}`
}

export function localAccountPresentation(account: AccountStatusEntry): {
  label: string
  description: string
  active: boolean
} {
  return {
    label: localAccountLabel(account.slot),
    description: account.active ? '目前使用中的本機帳號。' : '可切換至這個本機帳號。',
    active: account.active
  }
}

export function accountConfirmationContent(action: AccountConfirmationAction): {
  title: string
  description: string
} {
  const target = action.kind === 'add' ? '新增本機帳號' : `切換至${localAccountLabel(action.slot)}`
  return {
    title: `${target}？`,
    description: '這會先鎖定保管庫，然後安全地重新啟動 BearWarden。未儲存的變更不會保留。'
  }
}

export function accountMutationError(error: unknown): string {
  const message = error instanceof Error ? error.message : ''
  if (message.includes('ACCOUNT_LIMIT_REACHED')) return '本機帳號已達上限，最多可保留 5 個。'
  if (message.includes('ACCOUNT_NOT_FOUND') || message.includes('NOT_FOUND')) {
    return '找不到要切換的本機帳號，請重新整理後再試。'
  }
  if (message.includes('ACCOUNT_SWITCH_UNAVAILABLE') || message.includes('SWITCH_UNAVAILABLE')) {
    return '本機帳號切換目前不可用，請稍後再試。'
  }
  if (message.includes('ACCOUNT_SWITCH_IN_PROGRESS') || message.includes('IN_PROGRESS')) {
    return '已有本機帳號切換正在處理，請等待 BearWarden 重新啟動。'
  }
  if (message.includes('ACCOUNT_SWITCH_RESULT_UNKNOWN') || message.includes('RESULT_UNKNOWN')) {
    return '切換結果無法確認。請重新啟動 BearWarden 後確認目前帳號。'
  }
  return '無法完成本機帳號切換，請稍後再試。'
}

export function accountSwitchButtonDisabled(account: AccountStatusEntry, busy: boolean): boolean {
  return busy || account.active
}

export function requestAccountAction(
  requestEditorTransition: (action: () => void) => void,
  action: () => void
): void {
  requestEditorTransition(action)
}
