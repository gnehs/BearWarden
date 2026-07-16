import type { AccountStatusEntry } from '../../../shared/vault-contract'
import { describe, expect, it, vi } from 'vitest'
import {
  accountConfirmationContent,
  accountMutationError,
  accountSwitchButtonDisabled,
  localAccountPresentation,
  localAccountLabel,
  MAX_LOCAL_ACCOUNTS,
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
      description: '目前使用中的本機帳號。',
      active: true
    })
    expect(inactive).toEqual({
      label: '帳號 2',
      description: '可切換至這個本機帳號。',
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
  })

  it('disables the active account switch and adding after the local limit', () => {
    expect(accountSwitchButtonDisabled(account({ active: true }), false)).toBe(true)
    expect(accountSwitchButtonDisabled(account(), false)).toBe(false)
    expect(MAX_LOCAL_ACCOUNTS).toBe(5)
  })

  it('uses an explicit lock-and-restart confirmation for additions and switches', () => {
    for (const action of [
      { kind: 'add' as const },
      { kind: 'switch' as const, accountId: account().id, slot: account().slot }
    ]) {
      const confirmation = accountConfirmationContent(action)
      expect(confirmation.description).toContain('鎖定保管庫')
      expect(confirmation.description).toContain('重新啟動')
    }
  })

  it.each([
    ['ACCOUNT_LIMIT_REACHED', '本機帳號已達上限'],
    ['ACCOUNT_NOT_FOUND', '找不到要切換的本機帳號'],
    ['ACCOUNT_SWITCH_UNAVAILABLE', '本機帳號切換目前不可用'],
    ['ACCOUNT_SWITCH_IN_PROGRESS', '已有本機帳號切換正在處理'],
    ['ACCOUNT_SWITCH_RESULT_UNKNOWN', '切換結果無法確認']
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
