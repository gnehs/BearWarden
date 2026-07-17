import { describe, expect, it, vi } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { executePersonalVaultPurge, PersonalVaultPurgeForm } from './PersonalVaultPurgeDialog'

function purgeRequest(password: string): {
  masterPassword: string
  confirmation: 'PURGE'
  confirmPurge: true
} {
  return { masterPassword: password, confirmation: 'PURGE', confirmPurge: true }
}

describe('PersonalVaultPurgeDialog warning boundary', () => {
  it('uses a synchronous lease to admit only one same-render deferred submission', async () => {
    let resolvePurge!: (result: {
      status: 'complete'
      removedItems: number
      removedFolders: number
    }) => void
    const deferred = new Promise<{
      status: 'complete'
      removedItems: number
      removedFolders: number
    }>((resolve) => {
      resolvePurge = resolve
    })
    const purge = vi.fn(() => deferred)
    const refresh = vi.fn()
    const onAcquired = vi.fn()
    const lease = { current: false }
    const firstRequest = purgeRequest('first-password')
    const secondRequest = purgeRequest('second-password')

    const first = executePersonalVaultPurge({
      lease,
      request: firstRequest,
      purge,
      refresh,
      onAcquired
    })
    const second = executePersonalVaultPurge({
      lease,
      request: secondRequest,
      purge,
      refresh,
      onAcquired
    })

    await expect(second).resolves.toEqual({ acquired: false })
    expect(purge).toHaveBeenCalledOnce()
    expect(onAcquired).toHaveBeenCalledOnce()
    expect(secondRequest).toEqual({ masterPassword: '', confirmation: '', confirmPurge: true })

    resolvePurge({ status: 'complete', removedItems: 2, removedFolders: 1 })
    await expect(first).resolves.toEqual({
      acquired: true,
      result: { status: 'complete', removedItems: 2, removedFolders: 1 }
    })
    expect(refresh).toHaveBeenCalledOnce()
    expect(firstRequest).toEqual({ masterPassword: '', confirmation: '', confirmPurge: true })
    expect(lease.current).toBe(false)
  })

  it('refreshes after rejection before preserving the original error and pending presentation', async () => {
    const original = new Error('BEARWARDEN:SYNC_FAILED')
    let pending: { startedAt: string; remainingItems: number; remainingFolders: number } | undefined
    const refresh = vi.fn(() => {
      pending = {
        startedAt: '2026-07-17T00:00:00.000Z',
        remainingItems: 4,
        remainingFolders: 2
      }
    })
    const request = purgeRequest('remote-password')

    await expect(
      executePersonalVaultPurge({
        lease: { current: false },
        request,
        purge: vi.fn(async () => {
          throw original
        }),
        refresh,
        onAcquired: () => undefined
      })
    ).rejects.toBe(original)
    expect(refresh).toHaveBeenCalledOnce()
    expect(request).toEqual({ masterPassword: '', confirmation: '', confirmPurge: true })

    const markup = renderToStaticMarkup(
      <PersonalVaultPurgeForm
        pendingPurge={pending}
        masterPassword=""
        confirmation=""
        showPassword={false}
        busy={false}
        error="無法確認清除結果。"
        onMasterPasswordChange={() => undefined}
        onConfirmationChange={() => undefined}
        onTogglePassword={() => undefined}
      />
    )
    expect(markup).toContain('上次清除的結果未知')
    expect(markup).toContain('4 個個人物件')
    expect(markup).toContain('無法確認清除結果')
  })

  it('does not replace the original rejection when renderer refresh throws synchronously', async () => {
    const original = new Error('BEARWARDEN:SYNC_FAILED')

    await expect(
      executePersonalVaultPurge({
        lease: { current: false },
        request: purgeRequest('remote-password'),
        purge: vi.fn(async () => {
          throw original
        }),
        refresh: () => {
          throw new Error('refresh unavailable')
        },
        onAcquired: () => undefined
      })
    ).rejects.toBe(original)
  })

  it('explains the destructive scope, preservation, backup, and exact confirmations', () => {
    const markup = renderToStaticMarkup(
      <PersonalVaultPurgeForm
        masterPassword=""
        confirmation=""
        showPassword={false}
        busy={false}
        error=""
        onMasterPasswordChange={() => undefined}
        onConfirmationChange={() => undefined}
        onTogglePassword={() => undefined}
      />
    )

    expect(markup).toContain('個人物件、資料夾與附件')
    expect(markup).toContain('垃圾桶與封存項目')
    expect(markup).toContain('無法復原')
    expect(markup).toContain('共享組織的項目會保留')
    expect(markup).toContain('建議先匯出備份')
    expect(markup).toContain('遠端主密碼')
    expect(markup).toContain('輸入 PURGE 確認')
    expect(markup).toContain('type="password"')
    expect(markup).toContain('maxLength="1024"')
  })

  it('shows only aggregate remaining counts and promises no automatic resend', () => {
    const markup = renderToStaticMarkup(
      <PersonalVaultPurgeForm
        pendingPurge={{
          startedAt: '2026-07-17T00:00:00.000Z',
          remainingItems: 3,
          remainingFolders: 2
        }}
        masterPassword=""
        confirmation=""
        showPassword={false}
        busy={false}
        error=""
        onMasterPasswordChange={() => undefined}
        onConfirmationChange={() => undefined}
        onTogglePassword={() => undefined}
      />
    )

    expect(markup).toContain('上次清除的結果未知')
    expect(markup).toContain('3 個個人物件')
    expect(markup).toContain('2 個資料夾')
    expect(markup).toContain('不會自動重送')
    expect(markup).not.toMatch(/journal|marker|localId/iu)
  })
})
