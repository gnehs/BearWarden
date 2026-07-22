import { i18n } from '@lingui/core'
import { msg } from '@lingui/core/macro'
import { arrayMove } from '@dnd-kit/sortable'
import type { AccountMutationResult, AccountStatusEntry } from '../../../shared/vault-contract'

export const MAX_LOCAL_ACCOUNTS = 5

export type AccountConfirmationAction =
  | { readonly kind: 'add' }
  | {
      readonly kind: 'switch'
      readonly accountId: string
      readonly slot: number
      readonly displayName?: string
    }
  | {
      readonly kind: 'remove'
      readonly accountId: string
      readonly slot: number
      readonly displayName?: string
    }

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
  return i18n._(msg`Account ${slot}`)
}

export function localAccountCode(accountId: string): string {
  return accountId.slice(0, 8).toUpperCase()
}

export function localAccountDisplayLabel(account: AccountStatusEntry): string {
  return account.displayName?.trim() || localAccountLabel(account.slot)
}

export function localAccountPresentation(account: AccountStatusEntry): {
  label: string
  description: string
  active: boolean
} {
  const code = localAccountCode(account.id)
  const label = localAccountDisplayLabel(account)
  return {
    label,
    description: i18n._(
      account.active
        ? msg`Current local account · Local code ${code}`
        : msg`Switch to this local account · Local code ${code}`
    ),
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
      title: i18n._(msg`Remove ${action.displayName?.trim() || localAccountLabel(action.slot)}?`),
      description: i18n._(
        msg`This permanently deletes the encrypted vault, settings, and biometric data on this device and cannot be undone. It does not delete your account or data on the Bitwarden or Vaultwarden server.`
      ),
      actionLabel: i18n._(msg`Permanently remove local data`),
      destructive: true
    }
  }
  return {
    title:
      action.kind === 'add'
        ? i18n._(msg`Add a local account?`)
        : i18n._(msg`Switch to ${action.displayName?.trim() || localAccountLabel(action.slot)}?`),
    description: i18n._(
      msg`This locks the vault, then safely restarts BearWarden. Unsaved changes will not be kept.`
    ),
    actionLabel: i18n._(msg`Lock and restart`),
    destructive: false
  }
}

export function accountMutationError(error: unknown): string {
  const message = error instanceof Error ? error.message : ''
  if (message.includes('ACCOUNT_LIMIT_REACHED'))
    return i18n._(msg`The local account limit has been reached. You can keep up to 5 accounts.`)
  if (message.includes('ACCOUNT_NOT_FOUND') || message.includes('NOT_FOUND')) {
    return i18n._(msg`The requested local account was not found. Refresh and try again.`)
  }
  if (message.includes('ACCOUNT_ACTIVE_REMOVAL_FORBIDDEN')) {
    return i18n._(msg`The current account cannot be removed. Switch to another account first.`)
  }
  if (message.includes('ACCOUNT_STALE_STATE')) {
    return i18n._(msg`The local account list has changed. Refresh and try again.`)
  }
  if (message.includes('ACCOUNT_SWITCH_UNAVAILABLE') || message.includes('SWITCH_UNAVAILABLE')) {
    return i18n._(msg`Local account management is currently unavailable. Try again later.`)
  }
  if (message.includes('ACCOUNT_SWITCH_IN_PROGRESS') || message.includes('IN_PROGRESS')) {
    return i18n._(
      msg`A local account switch is already in progress. Wait for BearWarden to restart.`
    )
  }
  if (message.includes('ACCOUNT_SWITCH_RESULT_UNKNOWN') || message.includes('RESULT_UNKNOWN')) {
    return i18n._(
      msg`The account operation result could not be confirmed. Restart BearWarden and verify the current status.`
    )
  }
  return i18n._(msg`The local account operation could not be completed. Try again later.`)
}

export function accountSwitchButtonDisabled(account: AccountStatusEntry, busy: boolean): boolean {
  return busy || account.active
}

export function accountMutationKeepsBusy(result: AccountMutationResult): boolean {
  return result.kind === 'relaunch-required'
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
  activeId: string,
  overId: string
): readonly string[] | null {
  const oldIndex = accounts.findIndex((account) => account.id === activeId)
  const newIndex = accounts.findIndex((account) => account.id === overId)
  if (oldIndex < 0 || newIndex < 0 || oldIndex === newIndex) return null

  return arrayMove(
    accounts.map((account) => account.id),
    oldIndex,
    newIndex
  )
}

export function requestAccountAction(
  requestEditorTransition: (action: () => void) => void,
  action: () => void
): void {
  requestEditorTransition(action)
}
