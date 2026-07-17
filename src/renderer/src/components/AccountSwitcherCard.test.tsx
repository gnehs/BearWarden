import type { AccountStatusEntry } from '../../../shared/vault-contract'
import { describe, expect, it, vi } from 'vitest'
import {
  accountConfirmationContent,
  accountMoveButtonDisabled,
  accountMutationKeepsBusy,
  accountMutationError,
  accountRemoveButtonDisabled,
  accountSwitchButtonDisabled,
  localAccountCode,
  localAccountPresentation,
  localAccountLabel,
  MAX_LOCAL_ACCOUNTS,
  moveAccountIds,
  requestAccountAction
} from './account-switcher-ui'

function account(overrides: Partial<AccountStatusEntry> = {}): AccountStatusEntry {
  return {
    id: '11111111-1111-4111-8111-111111111111',
    active: false,
    slot: 2,
    ...overrides
  }
}

describe('AccountSwitcherCard presentation helpers', () => {
  it('builds slot-only account presentation with active state, limit, and actions', () => {
    const firstId = '11111111-1111-4111-8111-111111111111'
    const secondId = '22222222-2222-4222-8222-222222222222'
    const active = localAccountPresentation(account({ id: firstId, active: true, slot: 1 }))
    const inactive = localAccountPresentation(account({ id: secondId, slot: 2 }))

    expect(active).toEqual({
      label: '帳號 1',
      description: '目前使用中的本機帳號 · 本機代碼 11111111',
      active: true
    })
    expect(inactive).toEqual({
      label: '帳號 2',
      description: '可切換至這個本機帳號 · 本機代碼 22222222',
      active: false
    })
    expect(JSON.stringify([active, inactive])).not.toContain(firstId)
    expect(JSON.stringify([active, inactive])).not.toContain(secondId)
    expect(MAX_LOCAL_ACCOUNTS).toBe(5)
  })

  it('labels accounts by local slot without exposing opaque account identifiers', () => {
    const opaqueId = account().id
    expect(localAccountLabel(account().slot)).toBe('帳號 2')
    expect(localAccountLabel(account().slot)).not.toContain(opaqueId)
    expect(localAccountCode(opaqueId)).toBe('11111111')
  })

  it('disables the active account switch and adding after the local limit', () => {
    expect(accountSwitchButtonDisabled(account({ active: true }), false)).toBe(true)
    expect(accountSwitchButtonDisabled(account(), false)).toBe(false)
    expect(MAX_LOCAL_ACCOUNTS).toBe(5)
  })

  it('keeps busy only while a relaunch-producing mutation is pending', () => {
    const status = { revision: 1, activeAccountId: account().id, accounts: [account()] }
    expect(accountMutationKeepsBusy({ kind: 'relaunch-required', status })).toBe(true)
    expect(accountMutationKeepsBusy({ kind: 'updated', status })).toBe(false)
    expect(accountMutationKeepsBusy({ kind: 'unchanged', status })).toBe(false)
  })

  it('uses an explicit lock-and-restart confirmation for additions and switches', () => {
    for (const action of [
      { kind: 'add' as const },
      { kind: 'switch' as const, accountId: account().id, slot: account().slot }
    ]) {
      const confirmation = accountConfirmationContent(action)
      expect(confirmation.description).toContain('鎖定保管庫')
      expect(confirmation.description).toContain('重新啟動')
      expect(confirmation.destructive).toBe(false)
    }
  })

  it('builds a destructive local-only removal confirmation', () => {
    const confirmation = accountConfirmationContent({
      kind: 'remove',
      accountId: account().id,
      slot: account().slot
    })

    expect(confirmation.title).toBe('移除帳號 2？')
    expect(confirmation.actionLabel).toBe('永久移除本機資料')
    expect(confirmation.description).toContain('無法復原')
    expect(confirmation.description).toContain('不會刪除 Bitwarden 或 Vaultwarden 伺服器')
    expect(confirmation.destructive).toBe(true)
    expect(JSON.stringify(confirmation)).not.toContain(account().id)
  })

  it('moves only adjacent account IDs and disables unavailable row actions', () => {
    const accounts = [
      account({ id: '11111111-1111-4111-8111-111111111111', slot: 1, active: true }),
      account({ id: '22222222-2222-4222-8222-222222222222', slot: 2 }),
      account({ id: '33333333-3333-4333-8333-333333333333', slot: 3 })
    ]

    expect(moveAccountIds(accounts, accounts[1]!.id, 'up')).toEqual([
      accounts[1]!.id,
      accounts[0]!.id,
      accounts[2]!.id
    ])
    expect(moveAccountIds(accounts, accounts[1]!.id, 'down')).toEqual([
      accounts[0]!.id,
      accounts[2]!.id,
      accounts[1]!.id
    ])
    expect(moveAccountIds(accounts, accounts[0]!.id, 'up')).toBeNull()
    expect(accountMoveButtonDisabled(0, 3, 'up', false)).toBe(true)
    expect(accountMoveButtonDisabled(1, 3, 'up', false)).toBe(false)
    expect(accountMoveButtonDisabled(2, 3, 'down', false)).toBe(true)
    expect(accountRemoveButtonDisabled(accounts[0]!, 3, false)).toBe(true)
    expect(accountRemoveButtonDisabled(accounts[1]!, 3, false)).toBe(false)
    expect(accountRemoveButtonDisabled(accounts[1]!, 1, false)).toBe(true)
  })

  it.each([
    ['ACCOUNT_LIMIT_REACHED', '本機帳號已達上限'],
    ['ACCOUNT_NOT_FOUND', '找不到指定的本機帳號'],
    ['ACCOUNT_ACTIVE_REMOVAL_FORBIDDEN', '目前使用中的帳號不能移除'],
    ['ACCOUNT_STALE_STATE', '本機帳號清單已變更'],
    ['ACCOUNT_SWITCH_UNAVAILABLE', '本機帳號管理目前不可用'],
    ['ACCOUNT_SWITCH_IN_PROGRESS', '已有本機帳號切換正在處理'],
    ['ACCOUNT_SWITCH_RESULT_UNKNOWN', '帳號操作結果無法確認']
  ])('maps %s to a safe renderer message', (code, expected) => {
    const message = accountMutationError(new Error(`BEARWARDEN:${code}: internal detail`))
    expect(message).toContain(expected)
    expect(message).not.toContain('internal detail')
  })
})

describe('VaultShell account transition', () => {
  it('defers the account action through the existing dirty-editor transition', () => {
    let deferredAction: (() => void) | undefined
    const requestEditorTransition = vi.fn((action: () => void) => {
      deferredAction = action
    })
    const accountAction = vi.fn()

    requestAccountAction(requestEditorTransition, accountAction)

    expect(requestEditorTransition).toHaveBeenCalledWith(accountAction)
    expect(accountAction).not.toHaveBeenCalled()
    deferredAction?.()
    expect(accountAction).toHaveBeenCalledOnce()
  })
})
