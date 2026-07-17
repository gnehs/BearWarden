import { beforeEach, describe, expect, it, vi } from 'vitest'

const electronMock = vi.hoisted(() => ({
  handlers: new Map<string, (event: unknown, input: unknown) => Promise<unknown>>(),
  removeHandler: vi.fn()
}))

vi.mock('electron', () => ({
  dialog: {},
  ipcMain: {
    handle: vi.fn(
      (channel: string, handler: (event: unknown, input: unknown) => Promise<unknown>) => {
        electronMock.handlers.set(channel, handler)
      }
    ),
    removeHandler: electronMock.removeHandler
  },
  Menu: { buildFromTemplate: vi.fn() }
}))

import {
  IPC_CHANNELS,
  IPC_EVENTS,
  type VaultExportRequest,
  type VaultImportRequest
} from '../shared/vault-contract'
import type { AppSettingsService } from './app-settings'
import {
  AccountRelaunchResultUnknownError,
  AccountSwitchServiceError,
  type AccountSwitchService
} from './account-switch-service'
import { VaultError } from './vault-errors'
import { registerVaultIpc, RepromptAuthorizationStore } from './vault-ipc'
import type { VaultService } from './vault-service'
import { SshKeyImportSessionStore } from './ssh-key-import-session'
import { SshKeyImportError } from './ssh-key-import'
import { TwoFactorDirectoryCacheError } from './two-factor-directory-cache'

beforeEach(() => {
  electronMock.handlers.clear()
  electronMock.removeHandler.mockClear()
})

describe('registerVaultIpc lifecycle', () => {
  it('removes only the handlers owned by the vault IPC registration', () => {
    const dispose = registerVaultIpc({
      vault: {} as VaultService,
      portability: {} as Parameters<typeof registerVaultIpc>[0]['portability'],
      settings: {} as AppSettingsService,
      sshKeyImportSessions: new SshKeyImportSessionStore({ readClipboard: () => '' }),
      getMainWindow: () => null
    })
    const ownedChannels = new Set(electronMock.handlers.keys())

    expect(ownedChannels.has(IPC_CHANNELS.passkeyVerifyApproval)).toBe(false)
    expect(ownedChannels.has(IPC_CHANNELS.sshAgentStatus)).toBe(false)

    dispose()
    dispose()

    expect(new Set(electronMock.removeHandler.mock.calls.map(([channel]) => channel))).toEqual(
      ownedChannels
    )
    expect(electronMock.removeHandler).toHaveBeenCalledTimes(ownedChannels.size)
  })
})

describe('registerVaultIpc personal vault purge boundary', () => {
  function purgeHarness(
    purgePersonalVault: ReturnType<typeof vi.fn> = vi.fn(async (request: unknown) => {
      void request
      return {
        status: 'complete' as const,
        removedItems: 2,
        removedFolders: 1
      }
    })
  ): {
    event: unknown
    purgePersonalVault: typeof purgePersonalVault
    syncStatus: ReturnType<typeof vi.fn>
    afterSyncChanged: ReturnType<typeof vi.fn>
    afterMutation: ReturnType<typeof vi.fn>
  } {
    const mainFrame = { url: 'app://bearwarden/index.html' }
    const webContents = {
      id: 101,
      mainFrame,
      getURL: () => mainFrame.url,
      send: vi.fn(),
      isDestroyed: () => false
    }
    const syncStatus = vi.fn(async () => ({ configured: true, state: 'ready' as const }))
    const afterSyncChanged = vi.fn()
    const afterMutation = vi.fn()
    registerVaultIpc({
      vault: { purgePersonalVault, syncStatus } as unknown as VaultService,
      portability: {} as Parameters<typeof registerVaultIpc>[0]['portability'],
      settings: {} as AppSettingsService,
      sshKeyImportSessions: new SshKeyImportSessionStore({ readClipboard: () => '' }),
      getMainWindow: () => ({ isDestroyed: () => false, webContents }) as never,
      afterSyncChanged,
      afterMutation
    })
    return {
      event: { sender: webContents, senderFrame: mainFrame },
      purgePersonalVault,
      syncStatus,
      afterSyncChanged,
      afterMutation
    }
  }

  it('requires exact explicit confirmation, scrubs parsed secrets, and publishes both changes', async () => {
    let captured: { masterPassword: string; confirmation: string } | undefined
    const purgePersonalVault = vi.fn(async (request) => {
      captured = request
      return { status: 'complete' as const, removedItems: 2, removedFolders: 1 }
    })
    const harness = purgeHarness(purgePersonalVault)

    await expect(
      electronMock.handlers.get(IPC_CHANNELS.syncPurgePersonalVault)!(harness.event, {
        masterPassword: 'remote-master-password',
        confirmation: 'PURGE',
        confirmPurge: true
      })
    ).resolves.toEqual({ status: 'complete', removedItems: 2, removedFolders: 1 })

    expect(purgePersonalVault).toHaveBeenCalledOnce()
    expect(captured).toEqual({ masterPassword: '', confirmation: '', confirmPurge: true })
    expect(harness.syncStatus).toHaveBeenCalledOnce()
    expect(harness.afterSyncChanged).toHaveBeenCalledWith({ configured: true, state: 'ready' })
    expect(harness.afterMutation).toHaveBeenCalledOnce()
  })

  it.each([
    {},
    { masterPassword: '', confirmation: 'PURGE', confirmPurge: true },
    { masterPassword: 'p'.repeat(1_025), confirmation: 'PURGE', confirmPurge: true },
    { masterPassword: 'password', confirmation: 'purge', confirmPurge: true },
    { masterPassword: 'password', confirmation: 'PURGE', confirmPurge: false },
    { masterPassword: 'password', confirmation: 'PURGE', confirmPurge: true, extra: true },
    Object.assign(
      { masterPassword: 'password', confirmation: 'PURGE', confirmPurge: true },
      { [Symbol('extra')]: true }
    )
  ])('rejects malformed purge requests without calling the service', async (request) => {
    const harness = purgeHarness()

    await expect(
      electronMock.handlers.get(IPC_CHANNELS.syncPurgePersonalVault)!(harness.event, request)
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(harness.purgePersonalVault).not.toHaveBeenCalled()
  })

  it('rejects accessors without evaluating secret getters', async () => {
    const harness = purgeHarness()
    const getter = vi.fn(() => 'remote-master-password')
    const request = { confirmation: 'PURGE', confirmPurge: true } as Record<string, unknown>
    Object.defineProperty(request, 'masterPassword', { enumerable: true, get: getter })

    await expect(
      electronMock.handlers.get(IPC_CHANNELS.syncPurgePersonalVault)!(harness.event, request)
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(getter).not.toHaveBeenCalled()
    expect(harness.purgePersonalVault).not.toHaveBeenCalled()
  })

  it('keeps the committed purge result authoritative when status notification fails', async () => {
    const harness = purgeHarness()
    harness.syncStatus.mockRejectedValueOnce(new Error('status unavailable'))

    await expect(
      electronMock.handlers.get(IPC_CHANNELS.syncPurgePersonalVault)!(harness.event, {
        masterPassword: 'remote-master-password',
        confirmation: 'PURGE',
        confirmPurge: true
      })
    ).resolves.toEqual({ status: 'complete', removedItems: 2, removedFolders: 1 })
    expect(harness.afterMutation).toHaveBeenCalledOnce()
    expect(harness.afterSyncChanged).not.toHaveBeenCalled()
  })

  it('scrubs parsed secrets when the service rejects the attempt', async () => {
    let captured: { masterPassword: string; confirmation: string } | undefined
    const purgePersonalVault = vi.fn(async (request) => {
      captured = request
      throw new VaultError('INVALID_MASTER_PASSWORD')
    })
    const harness = purgeHarness(purgePersonalVault)

    await expect(
      electronMock.handlers.get(IPC_CHANNELS.syncPurgePersonalVault)!(harness.event, {
        masterPassword: 'wrong-remote-password',
        confirmation: 'PURGE',
        confirmPurge: true
      })
    ).rejects.toThrow('BEARWARDEN:INVALID_MASTER_PASSWORD')
    expect(captured).toEqual({ masterPassword: '', confirmation: '', confirmPurge: true })
    expect(harness.afterMutation).not.toHaveBeenCalled()
  })

  it('publishes a pending journal status after purge reconciliation rejects', async () => {
    let captured: { masterPassword: string; confirmation: string } | undefined
    const purgePersonalVault = vi.fn(async (request) => {
      captured = request
      throw new VaultError('SYNC_FAILED')
    })
    const harness = purgeHarness(purgePersonalVault)
    const pendingStatus = {
      configured: true,
      state: 'error' as const,
      pendingPurge: {
        startedAt: '2026-07-17T00:00:00.000Z',
        remainingItems: 4,
        remainingFolders: 2
      }
    }
    harness.syncStatus.mockResolvedValueOnce(pendingStatus)

    await expect(
      electronMock.handlers.get(IPC_CHANNELS.syncPurgePersonalVault)!(harness.event, {
        masterPassword: 'remote-master-password',
        confirmation: 'PURGE',
        confirmPurge: true
      })
    ).rejects.toThrow('BEARWARDEN:SYNC_FAILED')
    expect(harness.afterSyncChanged).toHaveBeenCalledWith(pendingStatus)
    expect(captured).toEqual({ masterPassword: '', confirmation: '', confirmPurge: true })
    expect(harness.afterMutation).not.toHaveBeenCalled()
  })

  it('does not replace the original purge error when rejection status refresh also fails', async () => {
    const harness = purgeHarness(
      vi.fn(async () => {
        throw new VaultError('SYNC_FAILED')
      })
    )
    harness.syncStatus.mockRejectedValueOnce(new Error('status unavailable'))

    await expect(
      electronMock.handlers.get(IPC_CHANNELS.syncPurgePersonalVault)!(harness.event, {
        masterPassword: 'remote-master-password',
        confirmation: 'PURGE',
        confirmPurge: true
      })
    ).rejects.toThrow('BEARWARDEN:SYNC_FAILED')
    expect(harness.afterSyncChanged).not.toHaveBeenCalled()
  })
})

describe('registerVaultIpc account boundary', () => {
  const accountA = '11111111-1111-4111-8111-111111111111'
  const accountB = '22222222-2222-4222-8222-222222222222'

  function accountHarness(service?: Partial<AccountSwitchService>): {
    event: unknown
    untrustedEvent: unknown
  } {
    const mainFrame = { url: 'app://bearwarden/index.html' }
    const webContents = {
      id: 92,
      mainFrame,
      getURL: () => mainFrame.url,
      send: vi.fn(),
      isDestroyed: () => false
    }
    registerVaultIpc({
      vault: {} as VaultService,
      portability: {} as Parameters<typeof registerVaultIpc>[0]['portability'],
      settings: {} as AppSettingsService,
      sshKeyImportSessions: new SshKeyImportSessionStore({ readClipboard: () => '' }),
      getMainWindow: () => ({ isDestroyed: () => false, webContents }) as never,
      ...(service === undefined ? {} : { accountSwitchService: service as AccountSwitchService })
    })
    return {
      event: { sender: webContents, senderFrame: mainFrame },
      untrustedEvent: {
        sender: webContents,
        senderFrame: { url: 'https://untrusted.example.invalid' }
      }
    }
  }

  it('projects exact renderer-safe status and mutation fields', async () => {
    const status = {
      revision: 7,
      activeAccountId: accountA,
      cleanupPending: true as const,
      accounts: [
        {
          id: accountA,
          active: true,
          slot: 1,
          identityHash: 'a'.repeat(64),
          path: '/private/account-a'
        },
        { id: accountB, active: false, slot: 2, email: 'private@example.invalid' }
      ],
      registryPath: '/private/registry.json'
    }
    const service = {
      getStatus: vi.fn(async () => status),
      addAccount: vi.fn(async () => ({ kind: 'relaunch-required' as const, status }))
    }
    const { event } = accountHarness(service)

    await expect(
      electronMock.handlers.get(IPC_CHANNELS.accountStatus)!(event, undefined)
    ).resolves.toEqual({
      revision: 7,
      activeAccountId: accountA,
      cleanupPending: true,
      accounts: [
        { id: accountA, active: true, slot: 1 },
        { id: accountB, active: false, slot: 2 }
      ]
    })
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.accountAdd)!(event, undefined)
    ).resolves.toEqual({
      kind: 'relaunch-required',
      status: {
        revision: 7,
        activeAccountId: accountA,
        cleanupPending: true,
        accounts: [
          { id: accountA, active: true, slot: 1 },
          { id: accountB, active: false, slot: 2 }
        ]
      }
    })
    expect(JSON.stringify(await service.getStatus())).toContain('/private/account-a')
  })

  it('uses the trusted sender gate and exact no-input/switch parsers', async () => {
    const service = {
      getStatus: vi.fn(async () => ({ revision: 1, activeAccountId: accountA, accounts: [] })),
      addAccount: vi.fn(),
      switchAccount: vi.fn(async () => ({
        kind: 'unchanged' as const,
        status: { revision: 1, activeAccountId: accountA, accounts: [] }
      }))
    }
    const { event, untrustedEvent } = accountHarness(service)
    const status = electronMock.handlers.get(IPC_CHANNELS.accountStatus)!
    const add = electronMock.handlers.get(IPC_CHANNELS.accountAdd)!
    const switchAccount = electronMock.handlers.get(IPC_CHANNELS.accountSwitch)!

    await expect(status(untrustedEvent, undefined)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    await expect(status(event, {})).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    await expect(add(event, {})).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(service.getStatus).not.toHaveBeenCalled()
    expect(service.addAccount).not.toHaveBeenCalled()

    for (const input of [
      { accountId: '../vault' },
      { accountId: 'a'.repeat(64) },
      { accountId: 'private@example.invalid' },
      { accountId: 'https://vault.example.invalid' },
      { accountId: 2 },
      { slot: 2 },
      { accountId: accountB, extra: true }
    ]) {
      await expect(switchAccount(event, input)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(service.switchAccount).not.toHaveBeenCalled()

    await expect(switchAccount(event, { accountId: accountB })).resolves.toMatchObject({
      kind: 'unchanged'
    })
    expect(service.switchAccount).toHaveBeenCalledWith(accountB)
  })

  it('strictly validates reorder and explicit destructive removal payloads', async () => {
    const accountC = '33333333-3333-4333-8333-333333333333'
    const status = {
      revision: 8,
      activeAccountId: accountA,
      accounts: [
        { id: accountB, active: false, slot: 1 },
        { id: accountA, active: true, slot: 2 }
      ]
    }
    const service = {
      reorderAccounts: vi.fn(async () => ({ kind: 'updated' as const, status })),
      removeAccount: vi.fn(async () => ({
        kind: 'updated' as const,
        status: { ...status, revision: 9, accounts: status.accounts.slice(1) },
        cleanupPending: true,
        privatePath: '/private/account-b'
      }))
    }
    const { event, untrustedEvent } = accountHarness(service)
    const reorder = electronMock.handlers.get(IPC_CHANNELS.accountReorder)!
    const remove = electronMock.handlers.get(IPC_CHANNELS.accountRemove)!

    await expect(
      reorder(event, { accountIds: [accountB, accountA], expectedRevision: 7 })
    ).resolves.toEqual({ kind: 'updated', status })
    expect(service.reorderAccounts).toHaveBeenCalledWith([accountB, accountA], 7)
    await expect(remove(event, { accountId: accountB, confirm: true })).resolves.toEqual({
      kind: 'updated',
      cleanupPending: true,
      status: { ...status, revision: 9, accounts: status.accounts.slice(1) }
    })
    expect(service.removeAccount).toHaveBeenCalledWith(accountB, true)

    await expect(
      reorder(untrustedEvent, { accountIds: [accountA, accountB], expectedRevision: 8 })
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    const sparse = [accountA, accountB]
    delete sparse[0]
    const accessor = [accountA, accountB]
    Object.defineProperty(accessor, '1', { enumerable: true, get: () => accountB })
    for (const input of [
      undefined,
      {},
      { accountIds: [], expectedRevision: 7 },
      { accountIds: [accountA, accountA], expectedRevision: 7 },
      { accountIds: [accountA, '../vault'], expectedRevision: 7 },
      { accountIds: [accountA, accountB, accountC, accountA], expectedRevision: 7 },
      { accountIds: [accountA, accountB], expectedRevision: 0 },
      { accountIds: [accountA, accountB], expectedRevision: 7, path: '/private' },
      { accountIds: sparse, expectedRevision: 7 },
      { accountIds: accessor, expectedRevision: 7 }
    ]) {
      await expect(reorder(event, input)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    for (const input of [
      undefined,
      {},
      { accountId: accountB },
      { accountId: accountB, confirm: false },
      { accountId: '../vault', confirm: true },
      { accountId: accountB, confirm: true, path: '/private' }
    ]) {
      await expect(remove(event, input)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
  })

  it('keeps legacy fallback unavailable and maps membership failures without leaking causes', async () => {
    const legacy = accountHarness()
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.accountStatus)!(legacy.event, undefined)
    ).rejects.toThrow('BEARWARDEN:ACCOUNT_SWITCH_UNAVAILABLE')

    const membershipFailure = new AccountSwitchServiceError('ACCOUNT_NOT_REGISTERED')
    const privateFailure = new AccountSwitchServiceError('ACCOUNT_ACTIVATION_FAILED') as Error & {
      cause?: unknown
    }
    privateFailure.cause = new Error('/private/accounts private@example.invalid')
    const service = {
      switchAccount: vi
        .fn()
        .mockRejectedValueOnce(membershipFailure)
        .mockRejectedValueOnce(privateFailure)
    }
    const { event } = accountHarness(service)
    const switchAccount = electronMock.handlers.get(IPC_CHANNELS.accountSwitch)!

    await expect(switchAccount(event, { accountId: accountB })).rejects.toThrow(
      'BEARWARDEN:ACCOUNT_NOT_FOUND'
    )
    let error: unknown
    try {
      await switchAccount(event, { accountId: accountB })
    } catch (caught) {
      error = caught
    }
    expect(String(error)).toBe('Error: BEARWARDEN:ACCOUNT_SWITCH_UNAVAILABLE')
    expect(String(error)).not.toContain('/private')
    expect(String(error)).not.toContain('@')
  })

  it.each([
    [new AccountSwitchServiceError('INVALID_ACCOUNT_SWITCH_REQUEST'), 'INVALID_INPUT'],
    [new AccountSwitchServiceError('ACCOUNT_LIMIT_REACHED'), 'ACCOUNT_LIMIT_REACHED'],
    [
      new AccountSwitchServiceError('ACCOUNT_ACTIVE_REMOVAL_FORBIDDEN'),
      'ACCOUNT_ACTIVE_REMOVAL_FORBIDDEN'
    ],
    [new AccountSwitchServiceError('ACCOUNT_STALE_REORDER_REQUEST'), 'ACCOUNT_STALE_STATE'],
    [new AccountSwitchServiceError('ACCOUNT_SWITCH_IN_PROGRESS'), 'ACCOUNT_SWITCH_IN_PROGRESS'],
    [
      new AccountSwitchServiceError('ACCOUNT_REGISTRY_UPDATE_RESULT_UNKNOWN'),
      'ACCOUNT_SWITCH_RESULT_UNKNOWN'
    ],
    [
      new AccountRelaunchResultUnknownError({
        revision: 1,
        activeAccountId: accountA,
        accounts: []
      }),
      'ACCOUNT_SWITCH_RESULT_UNKNOWN'
    ]
  ])('maps account mutation failures to stable public codes', async (failure, publicCode) => {
    const { event } = accountHarness({ addAccount: vi.fn().mockRejectedValue(failure) })
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.accountAdd)!(event, undefined)
    ).rejects.toThrow(`BEARWARDEN:${publicCode}`)
  })
})

describe('registerVaultIpc account WebAuthn enrollment boundary', () => {
  function accountWebAuthnHarness(vault: Partial<VaultService>): {
    event: unknown
    untrustedEvent: unknown
  } {
    const mainFrame = { url: 'app://bearwarden/index.html' }
    const webContents = {
      id: 89,
      mainFrame,
      getURL: () => mainFrame.url,
      send: vi.fn(),
      isDestroyed: () => false
    }
    registerVaultIpc({
      vault: vault as VaultService,
      portability: {} as Parameters<typeof registerVaultIpc>[0]['portability'],
      settings: {} as AppSettingsService,
      sshKeyImportSessions: new SshKeyImportSessionStore({ readClipboard: () => '' }),
      getMainWindow: () => ({ isDestroyed: () => false, webContents }) as never
    })
    return {
      event: { sender: webContents, senderFrame: mainFrame },
      untrustedEvent: {
        sender: webContents,
        senderFrame: { url: 'https://untrusted.example.invalid' }
      }
    }
  }

  it('projects only server key metadata and clears all renderer request secrets', async () => {
    let listInput: unknown
    let enrollInput: unknown
    let removeInput: unknown
    const vault = {
      listAccountWebAuthnKeys: vi.fn(async (request) => {
        listInput = { ...request }
        return [
          {
            id: 1,
            name: 'USB key',
            migrated: false,
            credentialId: 'never-in-renderer',
            userVerificationToken: 'main-only'
          }
        ]
      }),
      enrollAccountWebAuthnKey: vi.fn(async (request) => {
        enrollInput = { ...request }
      }),
      removeAccountWebAuthnKey: vi.fn(async (request) => {
        removeInput = { ...request }
      })
    }
    const { event } = accountWebAuthnHarness(vault)

    await expect(
      electronMock.handlers.get(IPC_CHANNELS.accountSecurityWebAuthnKeys)!(event, {
        masterPassword: 'test-master-password'
      })
    ).resolves.toEqual([{ id: 1, name: 'USB key', migrated: false }])
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.accountSecurityEnrollWebAuthnKey)!(event, {
        masterPassword: 'test-master-password',
        name: '  USB key  '
      })
    ).resolves.toBeUndefined()
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.accountSecurityRemoveWebAuthnKey)!(event, {
        id: 2,
        masterPassword: 'test-master-password',
        confirm: true
      })
    ).resolves.toBeUndefined()

    expect(listInput).toEqual({ masterPassword: 'test-master-password' })
    expect(enrollInput).toEqual({ masterPassword: 'test-master-password', name: 'USB key' })
    expect(removeInput).toEqual({ id: 2, masterPassword: 'test-master-password', confirm: true })
    expect(vault.listAccountWebAuthnKeys.mock.calls[0]?.[0]).toEqual({ masterPassword: '' })
    expect(vault.enrollAccountWebAuthnKey.mock.calls[0]?.[0]).toEqual({
      masterPassword: '',
      name: ''
    })
    expect(vault.removeAccountWebAuthnKey.mock.calls[0]?.[0]).toEqual({
      id: 2,
      masterPassword: '',
      confirm: true
    })
  })

  it('accepts only exact, bounded WebAuthn key requests from a trusted renderer', async () => {
    const vault = {
      listAccountWebAuthnKeys: vi.fn(),
      enrollAccountWebAuthnKey: vi.fn(),
      removeAccountWebAuthnKey: vi.fn()
    }
    const { event, untrustedEvent } = accountWebAuthnHarness(vault)
    const list = electronMock.handlers.get(IPC_CHANNELS.accountSecurityWebAuthnKeys)!
    const enroll = electronMock.handlers.get(IPC_CHANNELS.accountSecurityEnrollWebAuthnKey)!
    const remove = electronMock.handlers.get(IPC_CHANNELS.accountSecurityRemoveWebAuthnKey)!

    await expect(list(untrustedEvent, { masterPassword: 'test-master-password' })).rejects.toThrow(
      'BEARWARDEN:INVALID_INPUT'
    )
    for (const input of [
      undefined,
      {},
      { masterPassword: '' },
      { masterPassword: 'x'.repeat(16_385) },
      { masterPassword: 'test-master-password', extra: true }
    ]) {
      await expect(list(event, input)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    for (const input of [
      { masterPassword: 'test-master-password' },
      { masterPassword: 'test-master-password', name: ' \t ' },
      { masterPassword: 'test-master-password', name: 'line\nbreak' },
      { masterPassword: 'test-master-password', name: '\0' },
      { masterPassword: 'test-master-password', name: '你'.repeat(86) },
      { masterPassword: 'test-master-password', name: 'USB key', extra: true }
    ]) {
      await expect(enroll(event, input)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    for (const input of [
      { id: 0, masterPassword: 'test-master-password', confirm: true },
      { id: 2_147_483_648, masterPassword: 'test-master-password', confirm: true },
      { id: 1.5, masterPassword: 'test-master-password', confirm: true },
      { id: 1, masterPassword: 'test-master-password', confirm: false },
      { id: 1, masterPassword: 'test-master-password', confirm: true, extra: true }
    ]) {
      await expect(remove(event, input)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(vault.listAccountWebAuthnKeys).not.toHaveBeenCalled()
    expect(vault.enrollAccountWebAuthnKey).not.toHaveBeenCalled()
    expect(vault.removeAccountWebAuthnKey).not.toHaveBeenCalled()
  })
})

describe('registerVaultIpc settings validation', () => {
  function settingsHarness(): {
    event: unknown
    settings: { update: ReturnType<typeof vi.fn> }
  } {
    const mainFrame = { url: 'app://bearwarden/index.html' }
    const webContents = {
      id: 91,
      mainFrame,
      getURL: () => mainFrame.url,
      send: vi.fn(),
      isDestroyed: () => false
    }
    const settings = { update: vi.fn(async (update) => update), get: vi.fn() }
    registerVaultIpc({
      vault: {} as VaultService,
      portability: {} as Parameters<typeof registerVaultIpc>[0]['portability'],
      settings: settings as unknown as AppSettingsService,
      sshKeyImportSessions: new SshKeyImportSessionStore({ readClipboard: () => '' }),
      getMainWindow: () =>
        ({ isDestroyed: () => false, webContents }) as unknown as ReturnType<
          Parameters<typeof registerVaultIpc>[0]['getMainWindow']
        >
    })
    return { event: { sender: webContents, senderFrame: mainFrame }, settings }
  }

  it('whitelists and validates SSH agent settings before they reach persistence', async () => {
    const { event, settings } = settingsHarness()
    const update = electronMock.handlers.get(IPC_CHANNELS.settingsUpdate)!

    await expect(
      update(event, { sshAgentEnabled: true, sshAgentPromptBehavior: 'rememberUntilLock' })
    ).resolves.toEqual({ sshAgentEnabled: true, sshAgentPromptBehavior: 'rememberUntilLock' })
    expect(settings.update).toHaveBeenCalledWith({
      sshAgentEnabled: true,
      sshAgentPromptBehavior: 'rememberUntilLock'
    })

    for (const invalid of [
      { sshAgentEnabled: 'true' },
      { sshAgentPromptBehavior: 'ask-every-time' },
      { sshAgentPromptBehavior: null },
      { sshAgentEnabled: true, privateKey: 'must-not-be-accepted' }
    ]) {
      await expect(update(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(settings.update).toHaveBeenCalledTimes(1)
  })

  it('whitelists and validates the start-at-login preference', async () => {
    const { event, settings } = settingsHarness()
    const update = electronMock.handlers.get(IPC_CHANNELS.settingsUpdate)!

    await expect(update(event, { startAtLogin: true })).resolves.toEqual({ startAtLogin: true })
    expect(settings.update).toHaveBeenCalledWith({ startAtLogin: true })

    for (const invalid of [{ startAtLogin: 'true' }, { startAtLogin: null }]) {
      await expect(update(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(settings.update).toHaveBeenCalledTimes(1)
  })
})

describe('RepromptAuthorizationStore', () => {
  it('binds an opaque token to sender, item, vault generation, and expiry', () => {
    let now = 1_000
    let byte = 1
    const store = new RepromptAuthorizationStore(
      () => now,
      (size) => Buffer.alloc(size, byte++)
    )
    const authorization = store.issue(7, 'item-a', 3)

    expect(authorization.token).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(authorization.expiresAt).toBe(61_000)
    expect(store.validate(authorization.token, 7, 'item-a', 3)).toBe(true)
    expect(store.validate(authorization.token, 8, 'item-a', 3)).toBe(false)
    expect(store.validate(authorization.token, 7, 'item-b', 3)).toBe(false)
    expect(store.validate(authorization.token, 7, 'item-a', 4)).toBe(false)

    now = authorization.expiresAt
    expect(store.validate(authorization.token, 7, 'item-a', 3)).toBe(false)
  })

  it('invalidates every issued token when cleared', () => {
    const store = new RepromptAuthorizationStore(
      () => 0,
      (size) => Buffer.alloc(size, 9)
    )
    const authorization = store.issue(1, 'item-a', 1)
    store.clear()
    expect(store.validate(authorization.token, 1, 'item-a', 1)).toBe(false)
  })

  it.each([129, 1_001])('binds one constant-size capability to an exact %i-item set', (count) => {
    const store = new RepromptAuthorizationStore(
      () => 5_000,
      (size) => Buffer.alloc(size, 3)
    )
    const ids = Array.from(
      { length: count },
      (_, index) => `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`
    )
    const authorization = store.issueMany(9, ids, 4)
    expect(store.validateMany(authorization.token, 9, [...ids].reverse(), 4)).toBe(true)
    expect(store.validateMany(authorization.token, 9, ids.slice(1), 4)).toBe(false)
    expect(store.validateMany(authorization.token, 8, ids, 4)).toBe(false)
    expect(store.validateMany(authorization.token, 9, ids, 5)).toBe(false)
  })
})

describe('registerVaultIpc shared main-process hooks', () => {
  function registerHarness(options: {
    vault: Partial<VaultService>
    repromptAuthorizations?: RepromptAuthorizationStore
    afterSetup?: () => void | Promise<void>
  }): { event: unknown } {
    const mainFrame = { url: 'app://bearwarden/index.html' }
    const webContents = {
      id: 73,
      mainFrame,
      getURL: () => mainFrame.url,
      send: vi.fn(),
      isDestroyed: () => false
    }
    registerVaultIpc({
      vault: options.vault as VaultService,
      portability: {} as Parameters<typeof registerVaultIpc>[0]['portability'],
      settings: {} as AppSettingsService,
      sshKeyImportSessions: new SshKeyImportSessionStore({ readClipboard: () => '' }),
      getMainWindow: () => ({ isDestroyed: () => false, webContents }) as never,
      ...(options.repromptAuthorizations === undefined
        ? {}
        : { repromptAuthorizations: options.repromptAuthorizations }),
      ...(options.afterSetup === undefined ? {} : { afterSetup: options.afterSetup })
    })
    return { event: { sender: webContents, senderFrame: mainFrame } }
  }

  it('issues renderer reprompt capabilities from the injected store', async () => {
    const itemId = '00000000-0000-4000-8000-000000000001'
    const store = new RepromptAuthorizationStore(
      () => 2_000,
      (size) => Buffer.alloc(size, 4)
    )
    const { event } = registerHarness({
      vault: { authorizeLogin: vi.fn().mockResolvedValue(9) },
      repromptAuthorizations: store
    })
    const authorize = electronMock.handlers.get(IPC_CHANNELS.loginAuthorize)!
    const result = (await authorize(event, { id: itemId, masterPassword: 'test-only' })) as {
      token: string
    }
    expect(store.validate(result.token, 73, itemId, 9)).toBe(true)
  })

  it('runs the successful setup hook without turning auxiliary failures into setup failures', async () => {
    const afterSetup = vi.fn().mockRejectedValue(new Error('agent unavailable'))
    const setup = vi.fn().mockResolvedValue({ state: 'unlocked' })
    const { event } = registerHarness({ vault: { setup }, afterSetup })
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.vaultSetup)!(event, { masterPassword: 'test-only' })
    ).resolves.toEqual({ state: 'unlocked' })
    expect(setup).toHaveBeenCalledWith('test-only')
    expect(afterSetup).toHaveBeenCalledOnce()
  })
})

describe('registerVaultIpc master-password transaction', () => {
  function harness(vaultOverrides: Partial<VaultService> = {}): {
    event: unknown
    vault: Record<string, ReturnType<typeof vi.fn>>
    settings: { disableTouchId: ReturnType<typeof vi.fn> }
    beforeSyncReconfigure: ReturnType<typeof vi.fn>
    afterSyncChanged: ReturnType<typeof vi.fn>
    afterMasterPasswordChanged: ReturnType<typeof vi.fn>
    dispose: () => void
  } {
    const mainFrame = { url: 'app://bearwarden/index.html' }
    const webContents = {
      id: 74,
      mainFrame,
      getURL: () => mainFrame.url,
      send: vi.fn(),
      isDestroyed: () => false
    }
    const vault = {
      masterPasswordChangeStatus: vi.fn(async () => ({
        phase: null,
        needsReconnect: false,
        needsRemoteVerification: false
      })),
      changeMasterPassword: vi.fn(async () => undefined),
      resolveMasterPasswordChange: vi.fn(async () => ({ status: 'resolved' as const })),
      syncStatus: vi.fn(async () => ({ configured: true, state: 'locked' as const })),
      status: vi.fn(async () => ({ state: 'unlocked' as const })),
      ...vaultOverrides
    } as unknown as Record<string, ReturnType<typeof vi.fn>>
    const settings = { disableTouchId: vi.fn(async () => ({ touchIdEnabled: false })) }
    const beforeSyncReconfigure = vi.fn(async () => undefined)
    const afterSyncChanged = vi.fn()
    const afterMasterPasswordChanged = vi.fn()
    const dispose = registerVaultIpc({
      vault: vault as unknown as VaultService,
      portability: {} as Parameters<typeof registerVaultIpc>[0]['portability'],
      settings: settings as unknown as AppSettingsService,
      sshKeyImportSessions: new SshKeyImportSessionStore({ readClipboard: () => '' }),
      getMainWindow: () => ({ isDestroyed: () => false, webContents }) as never,
      beforeSyncReconfigure,
      afterSyncChanged,
      afterMasterPasswordChanged
    })
    return {
      event: { sender: webContents, senderFrame: mainFrame },
      vault,
      settings,
      beforeSyncReconfigure,
      afterSyncChanged,
      afterMasterPasswordChanged,
      dispose
    }
  }

  it('validates exact bounded input, scrubs it, clears Touch ID, and requires reconnect', async () => {
    const h = harness()
    const input = {
      currentPassword: 'correct horse battery staple',
      newPassword: 'replacement horse battery staple',
      hint: 'safe hint'
    }

    await expect(
      electronMock.handlers.get(IPC_CHANNELS.vaultMasterPasswordChange)!(h.event, input)
    ).resolves.toEqual({ state: 'completed', requiresReconnect: true })
    expect(h.vault.changeMasterPassword).toHaveBeenCalledWith({
      currentPassword: '',
      newPassword: '',
      hint: null
    })
    expect(input).toEqual({ currentPassword: '', newPassword: '', hint: null })
    expect(h.beforeSyncReconfigure).toHaveBeenCalledOnce()
    expect(h.settings.disableTouchId).toHaveBeenCalledOnce()
    expect(h.afterMasterPasswordChanged).toHaveBeenCalledWith({
      configured: true,
      state: 'locked'
    })

    for (const invalid of [
      {
        currentPassword: 'correct horse battery staple',
        newPassword: 'replacement horse battery staple',
        extra: 'not allowed'
      },
      { currentPassword: 'too short', newPassword: 'replacement horse battery staple' },
      {
        currentPassword: 'correct horse battery staple',
        newPassword: 'replacement horse battery staple',
        hint: 'x'.repeat(51)
      },
      {
        currentPassword: 'correct horse battery staple',
        newPassword: 'correct horse battery staple'
      }
    ]) {
      await expect(
        electronMock.handlers.get(IPC_CHANNELS.vaultMasterPasswordChange)!(h.event, invalid)
      ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
      expect(invalid.currentPassword).toBe('')
      expect(invalid.newPassword).toBe('')
    }
    expect(h.vault.changeMasterPassword).toHaveBeenCalledTimes(1)
  })

  it('returns a typed verification state for an unknown result without replaying and clears Touch ID fail-closed', async () => {
    const changeMasterPassword = vi.fn(async () => {
      throw new VaultError('SYNC_FAILED')
    })
    const h = harness({
      changeMasterPassword,
      status: vi.fn(async () => ({ state: 'locked' as const }))
    })
    const input = {
      currentPassword: 'correct horse battery staple',
      newPassword: 'replacement horse battery staple'
    }

    await expect(
      electronMock.handlers.get(IPC_CHANNELS.vaultMasterPasswordChange)!(h.event, input)
    ).resolves.toEqual({ state: 'needs-remote-verification', requiresReconnect: true })
    expect(changeMasterPassword).toHaveBeenCalledOnce()
    expect(h.settings.disableTouchId).toHaveBeenCalledOnce()
    expect(input).toEqual({ currentPassword: '', newPassword: '' })
  })

  it('rejects accessors and symbol keys without invoking getters, and compares NFC passwords', async () => {
    const h = harness()
    let getterCalls = 0
    const accessorInput = Object.defineProperties(
      {},
      {
        currentPassword: {
          enumerable: true,
          get: () => {
            getterCalls += 1
            return 'correct horse battery staple'
          }
        },
        newPassword: {
          enumerable: true,
          value: 'replacement horse battery staple',
          writable: true
        }
      }
    )
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.vaultMasterPasswordChange)!(h.event, accessorInput)
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(getterCalls).toBe(0)

    const symbolInput = {
      currentPassword: 'correct horse battery staple',
      newPassword: 'replacement horse battery staple',
      [Symbol('hidden')]: 'not allowed'
    }
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.vaultMasterPasswordChange)!(h.event, symbolInput)
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')

    const nfcInput = {
      currentPassword: 'correct horse caf\u00e9',
      newPassword: 'correct horse cafe\u0301'
    }
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.vaultMasterPasswordChange)!(h.event, nfcInput)
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(h.vault.changeMasterPassword).not.toHaveBeenCalled()
  })

  it('preserves valid whitespace password material while normalizing to NFC', async () => {
    const observed: Array<{ currentPassword: string; newPassword: string }> = []
    const h = harness({
      changeMasterPassword: vi.fn(async (request) => {
        observed.push({
          currentPassword: request.currentPassword,
          newPassword: request.newPassword
        })
      })
    })
    await electronMock.handlers.get(IPC_CHANNELS.vaultMasterPasswordChange)!(h.event, {
      currentPassword: '            ',
      newPassword: '             '
    })
    expect(observed).toEqual([{ currentPassword: '            ', newPassword: '             ' }])
  })

  it.each(['change', 'resolve'] as const)(
    'clears Touch ID and returns resume-required when %s fails after remote confirmation',
    async (operation) => {
      const failure = vi.fn(async () => {
        throw new Error('injected post-confirmation failure')
      })
      const h = harness({
        ...(operation === 'change'
          ? { changeMasterPassword: failure }
          : { resolveMasterPasswordChange: failure }),
        masterPasswordChangeStatus: vi.fn(async () => ({
          phase: 'remote-confirmed' as const,
          needsReconnect: false,
          needsRemoteVerification: false
        }))
      })
      const channel =
        operation === 'change'
          ? IPC_CHANNELS.vaultMasterPasswordChange
          : IPC_CHANNELS.vaultMasterPasswordChangeResolve

      await expect(
        electronMock.handlers.get(channel)!(h.event, {
          currentPassword: 'correct horse battery staple',
          newPassword: 'replacement horse battery staple'
        })
      ).resolves.toEqual({ state: 'resume-required', requiresReconnect: true })
      expect(failure).toHaveBeenCalledOnce()
      expect(h.settings.disableTouchId).toHaveBeenCalledOnce()
    }
  )

  it.each([
    ['prepared', 'needs-remote-verification'],
    ['remote-confirmed', 'resume-required'],
    ['local-rekeyed', 'resume-required']
  ] as const)(
    'invalidates a persisted Touch ID capsule on restart status %s and exposes no journal metadata',
    async (phase, state) => {
      const h = harness({
        masterPasswordChangeStatus: vi.fn(async () => ({
          phase,
          needsReconnect: false,
          needsRemoteVerification: phase === 'prepared'
        }))
      })
      const response = await electronMock.handlers.get(
        IPC_CHANNELS.vaultMasterPasswordChangeStatus
      )!(h.event, undefined)

      expect(response).toEqual({ state, requiresReconnect: true })
      expect(Object.keys(response as object).sort()).toEqual(['requiresReconnect', 'state'])
      expect(h.settings.disableTouchId).toHaveBeenCalledOnce()
    }
  )

  it.each([
    ['remote-not-changed', 'remote-not-changed'],
    ['needs-reconnect', 'needs-reconnect'],
    ['indeterminate', 'indeterminate']
  ] as const)(
    'maps safe resolution %s without exposing transaction metadata',
    async (result, state) => {
      const h = harness({
        resolveMasterPasswordChange: vi.fn(async () => ({ status: result }))
      })
      const input = {
        currentPassword: 'correct horse battery staple',
        newPassword: 'replacement horse battery staple'
      }
      const response = await electronMock.handlers.get(
        IPC_CHANNELS.vaultMasterPasswordChangeResolve
      )!(h.event, input)

      expect(response).toEqual({ state, requiresReconnect: true })
      expect(JSON.stringify(response)).not.toContain('fingerprint')
      expect(JSON.stringify(response)).not.toContain('startedAt')
      expect(h.settings.disableTouchId).not.toHaveBeenCalled()
      expect(h.afterSyncChanged).toHaveBeenCalledOnce()
      expect(input).toEqual({ currentPassword: '', newPassword: '' })
    }
  )

  it('suppresses lifecycle callbacks after disposal while still invalidating Touch ID on completion', async () => {
    let finish!: () => void
    const pending = new Promise<void>((resolve) => {
      finish = resolve
    })
    const h = harness({ changeMasterPassword: vi.fn(() => pending) })
    const handler = electronMock.handlers.get(IPC_CHANNELS.vaultMasterPasswordChange)!
    const operation = handler(h.event, {
      currentPassword: 'correct horse battery staple',
      newPassword: 'replacement horse battery staple'
    })
    await vi.waitFor(() => expect(h.vault.changeMasterPassword).toHaveBeenCalledOnce())
    h.dispose()
    finish()

    await expect(operation).resolves.toEqual({ state: 'completed', requiresReconnect: true })
    expect(h.settings.disableTouchId).toHaveBeenCalledOnce()
    expect(h.afterMasterPasswordChanged).not.toHaveBeenCalled()
  })
})

describe('registerVaultIpc inactive two-factor privacy boundary', () => {
  function harness(): {
    event: unknown
    vault: { getInactiveTwoFactorReport: ReturnType<typeof vi.fn> }
    directory: {
      getDataset: ReturnType<typeof vi.fn>
      openDocumentation: ReturnType<typeof vi.fn>
    }
  } {
    const mainFrame = { url: 'app://bearwarden/index.html' }
    const webContents = {
      id: 75,
      mainFrame,
      getURL: () => mainFrame.url,
      send: vi.fn(),
      isDestroyed: () => false
    }
    const dataset = Object.freeze({ apiVersion: 4 as const, entries: Object.freeze([]) })
    const vault = {
      getInactiveTwoFactorReport: vi.fn(async () => ({
        analyzedCount: 1,
        excludedTotpCount: 0,
        excludedDeletedCount: 0,
        excludedArchivedCount: 0,
        findings: [
          {
            id: 'public-item-id',
            name: 'Example',
            matchedDomain: 'example.com',
            documentationUrl: 'https://help.example.com/2fa'
          }
        ]
      }))
    }
    const directory = {
      getDataset: vi.fn(async () => dataset),
      openDocumentation: vi.fn(async () => undefined)
    }
    registerVaultIpc({
      vault: vault as unknown as VaultService,
      portability: {} as Parameters<typeof registerVaultIpc>[0]['portability'],
      settings: {} as AppSettingsService,
      twoFactorDirectory: directory as unknown as NonNullable<
        Parameters<typeof registerVaultIpc>[0]['twoFactorDirectory']
      >,
      sshKeyImportSessions: new SshKeyImportSessionStore({ readClipboard: () => '' }),
      getMainWindow: () => ({ isDestroyed: () => false, webContents }) as never
    })
    return { event: { sender: webContents, senderFrame: mainFrame }, vault, directory }
  }

  it('returns only the service safe report and never accepts vault domains from the renderer', async () => {
    const h = harness()
    const response = await electronMock.handlers.get(IPC_CHANNELS.vaultHealthInactiveTwoFactor)!(
      h.event,
      {}
    )

    expect(h.directory.getDataset).toHaveBeenCalledOnce()
    expect(h.vault.getInactiveTwoFactorReport).toHaveBeenCalledOnce()
    expect(response).toMatchObject({
      findings: [{ id: 'public-item-id', matchedDomain: 'example.com' }]
    })
    expect(Object.keys(response as object).sort()).toEqual([
      'analyzedCount',
      'excludedArchivedCount',
      'excludedDeletedCount',
      'excludedTotpCount',
      'findings'
    ])
    expect(Object.keys((response as { findings: object[] }).findings[0]!).sort()).toEqual([
      'documentationUrl',
      'id',
      'matchedDomain',
      'name'
    ])
    expect(JSON.stringify(response)).not.toContain('login.private-vault.example')
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.vaultHealthInactiveTwoFactor)!(h.event, undefined)
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.vaultHealthInactiveTwoFactor)!(h.event, {
        [Symbol('hidden')]: true
      })
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.vaultHealthInactiveTwoFactor)!(h.event, {
        hostname: 'login.private-vault.example'
      })
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
  })

  it('opens documentation using only a dataset domain and rejects URL-shaped or accessor input', async () => {
    const h = harness()
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.vaultHealthOpenTwoFactorDocumentation)!(h.event, {
        matchedDomain: 'example.com'
      })
    ).resolves.toBeUndefined()
    expect(h.directory.openDocumentation).toHaveBeenCalledWith('example.com')

    for (const invalid of [
      { matchedDomain: 'https://help.example.com/2fa' },
      { matchedDomain: 'example.com', url: 'https://attacker.invalid' },
      { matchedDomain: 'EXAMPLE.COM' },
      { matchedDomain: 'example..com' },
      { matchedDomain: '-example.com' },
      { matchedDomain: 'example-.com' },
      { matchedDomain: `${'a'.repeat(64)}.com` },
      { matchedDomain: `${'a'.repeat(250)}.com` }
    ]) {
      await expect(
        electronMock.handlers.get(IPC_CHANNELS.vaultHealthOpenTwoFactorDocumentation)!(
          h.event,
          invalid
        )
      ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }

    let getterCalls = 0
    const accessor = Object.defineProperty({}, 'matchedDomain', {
      enumerable: true,
      get: () => {
        getterCalls += 1
        return 'example.com'
      }
    })
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.vaultHealthOpenTwoFactorDocumentation)!(
        h.event,
        accessor
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(getterCalls).toBe(0)
    expect(h.directory.openDocumentation).toHaveBeenCalledOnce()
  })

  it('maps missing, unavailable, and missing-documentation backends to public errors', async () => {
    const unavailable = harness()
    unavailable.directory.getDataset.mockRejectedValueOnce(
      new TwoFactorDirectoryCacheError('UNAVAILABLE')
    )
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.vaultHealthInactiveTwoFactor)!(unavailable.event, {})
    ).rejects.toThrow('BEARWARDEN:HEALTH_CHECK_FAILED')

    const missingDocumentation = harness()
    missingDocumentation.directory.openDocumentation.mockRejectedValueOnce(
      new TwoFactorDirectoryCacheError('DOCUMENTATION_NOT_FOUND')
    )
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.vaultHealthOpenTwoFactorDocumentation)!(
        missingDocumentation.event,
        { matchedDomain: 'example.com' }
      )
    ).rejects.toThrow('BEARWARDEN:NOT_FOUND')

    const absent = harness()
    const event = absent.event as {
      sender: { isDestroyed: () => boolean }
      senderFrame: { url: string }
    }
    registerVaultIpc({
      vault: absent.vault as unknown as VaultService,
      portability: {} as Parameters<typeof registerVaultIpc>[0]['portability'],
      settings: {} as AppSettingsService,
      sshKeyImportSessions: new SshKeyImportSessionStore({ readClipboard: () => '' }),
      getMainWindow: () => ({ isDestroyed: () => false, webContents: event.sender }) as never
    })
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.vaultHealthInactiveTwoFactor)!(absent.event, {})
    ).rejects.toThrow('BEARWARDEN:HEALTH_CHECK_FAILED')
  })
})

describe('registerVaultIpc reprompt gate', () => {
  const operationId = '70000000-0000-4000-8000-000000000001'
  function harness(): {
    event: unknown
    vault: Record<string, ReturnType<typeof vi.fn>>
    portability: {
      exportVault: ReturnType<typeof vi.fn>
      importVault: ReturnType<typeof vi.fn>
      previewNativeRestore: ReturnType<typeof vi.fn>
      runNativeRestore: ReturnType<typeof vi.fn>
      cancelNativeRestore: ReturnType<typeof vi.fn>
      clearCompletedNativeRestore: ReturnType<typeof vi.fn>
      disposeNativeRestoreSession: ReturnType<typeof vi.fn>
    }
    afterMutation: ReturnType<typeof vi.fn>
    beforeSyncReconfigure: ReturnType<typeof vi.fn>
    afterSyncChanged: ReturnType<typeof vi.fn>
    setAuthorizationState: (state: { reprompt: 0 | 1; generation: number }) => void
  } {
    const mainFrame = { url: 'app://bearwarden/index.html' }
    const webContents = {
      id: 7,
      mainFrame,
      getURL: () => mainFrame.url,
      send: vi.fn(),
      isDestroyed: () => false
    }
    const event = { sender: webContents, senderFrame: mainFrame }
    let authorizationState: { reprompt: 0 | 1; generation: number } = {
      reprompt: 1,
      generation: 3
    }
    const requireAttachmentAuthorization = (
      request: { id: string },
      validate?: (ids: readonly string[], state: { generation: number }) => boolean
    ): void => {
      if (
        authorizationState.reprompt === 1 &&
        !validate?.([request.id], { generation: authorizationState.generation })
      ) {
        throw new VaultError('REPROMPT_REQUIRED')
      }
    }
    const vault: Record<string, ReturnType<typeof vi.fn>> = {
      pinUnlockStatus: vi.fn(() => ({ available: true, remainingAttempts: 5 })),
      enablePinUnlock: vi.fn(async (request: { pin: string; masterPassword: string }) => {
        if (request.pin !== 'bear-2026' || request.masterPassword !== 'master password') {
          throw new Error('missing PIN proof')
        }
        return { available: true, remainingAttempts: 5 }
      }),
      disablePinUnlock: vi.fn(() => ({ available: false, remainingAttempts: 0 })),
      unlockWithPin: vi.fn(async (request: { pin: string }) => {
        if (request.pin !== 'bear-2026') throw new Error('missing PIN')
        return { state: 'unlocked' }
      }),
      loginAuthorizationState: vi.fn(async () => authorizationState),
      authorizeLogin: vi.fn(async ({ masterPassword }: { masterPassword: string }) => {
        if (masterPassword !== 'correct horse battery staple') {
          throw new VaultError('INVALID_MASTER_PASSWORD')
        }
        return 3
      }),
      authorizeLogins: vi.fn(async () => 3),
      getLogin: vi.fn(async () => ({ id: 'item-a' })),
      getPasswordHistory: vi.fn(async () => [
        { password: 'old-secret', lastUsedDate: '2026-07-14T00:00:00.000Z' }
      ]),
      restorePasswordHistory: vi.fn(async () => ({ id: 'item-a' })),
      downloadAttachment: vi.fn(async (request, _report, validate) => {
        requireAttachmentAuthorization(request, validate)
        return { canceled: false, fileName: 'document.txt' }
      }),
      uploadAttachment: vi.fn(async (request, _report, validate) => {
        requireAttachmentAuthorization(request, validate)
        return {
          canceled: false,
          attachment: {
            id: 'new-attachment',
            fileName: 'upload.txt',
            size: 12,
            sizeName: '12 B',
            legacy: false
          }
        }
      }),
      deleteAttachment: vi.fn(async (request, _report, validate) => {
        requireAttachmentAuthorization(request, validate)
        return { attachmentId: 'attachment-a' }
      }),
      fixLegacyAttachment: vi.fn(async (request, _report, validate) => {
        requireAttachmentAuthorization(request, validate)
        return {
          attachment: {
            id: 'fixed-attachment',
            fileName: 'legacy.txt',
            size: 12,
            sizeName: '12 B',
            legacy: false
          }
        }
      }),
      cancelAttachmentOperation: vi.fn(async () => ({ canceled: true })),
      listLogins: vi.fn(async () => []),
      getHealthReport: vi.fn(async () => ({
        generatedAt: '2026-07-16T00:00:00.000Z',
        totals: {
          analyzedCount: 1,
          weakPasswordCount: 1,
          reusedPasswordCount: 0,
          unsecuredWebsiteCount: 1,
          protectedSkippedCount: 1
        },
        weakPasswords: [{ id: 'item-a', name: 'Example', subtitle: '', score: 0 }],
        reusedPasswords: [],
        unsecuredWebsites: [{ id: 'item-http', name: 'Local router' }]
      })),
      getExposedPasswordReport: vi.fn(async () => ({
        generatedAt: '2026-07-16T00:00:00.000Z',
        totals: {
          analyzedCount: 2,
          exposedPasswordCount: 1,
          protectedSkippedCount: 1
        },
        exposedPasswords: [{ id: 'item-a', name: 'Example', subtitle: '', exposedCount: 42 }]
      })),
      cancelExposedPasswordReport: vi.fn(() => true),
      getAccountBreachReport: vi.fn(async () => ({
        generatedAt: '2026-07-16T00:00:00.000Z',
        status: 'complete' as const,
        breaches: []
      })),
      cancelAccountBreachReport: vi.fn(() => true),
      openHibpWebsite: vi.fn(async () => undefined),
      getAccountSecurityProfile: vi.fn(async () => ({
        name: 'Sync User',
        email: 'sync@example.invalid',
        emailVerified: false,
        twoFactorEnabled: true
      })),
      getAccountDevices: vi.fn(async () => ({
        status: 'available' as const,
        devices: [
          {
            name: 'Personal Mac',
            type: 7,
            createdAt: '2026-07-01T00:00:00.000Z',
            lastActivityAt: '2026-07-17T01:02:03.000Z',
            current: true,
            trusted: true,
            pendingAuthRequest: false
          }
        ]
      })),
      resendAccountVerificationEmail: vi.fn(async () => undefined),
      copyAccountApiClientId: vi.fn(async () => undefined),
      copyPersonalApiKey: vi.fn(async (request: { masterPassword: string; rotate: boolean }) => {
        if (request.masterPassword !== 'remote master password') throw new Error('missing proof')
        return {
          rotated: request.rotate,
          revisionDate: '2026-07-16T00:00:00Z'
        }
      }),
      getTwoFactorStatus: vi.fn(async () => [{ type: 0, enabled: true }]),
      disableTwoFactorProvider: vi.fn(
        async (request: { type: 0 | 1; masterPassword: string; confirm: true }) => {
          if (request.masterPassword !== 'remote master password') throw new Error('missing proof')
        }
      ),
      copyTwoFactorRecoveryCode: vi.fn(async (request: { masterPassword: string }) => {
        if (request.masterPassword !== 'remote master password') throw new Error('missing proof')
      }),
      beginAccountAuthenticatorSetup: vi.fn(async (request: { masterPassword: string }) => {
        if (request.masterPassword !== 'remote master password') throw new Error('missing proof')
        return {
          sessionId: '10000000-0000-4000-8000-000000000001',
          key: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
          requiresMasterPassword: true,
          expiresAt: 1_784_236_800_000
        }
      }),
      copyAccountAuthenticatorKey: vi.fn(async () => undefined),
      completeAccountAuthenticatorSetup: vi.fn(async () => undefined),
      beginAccountEmailTwoFactorSetup: vi.fn(async (request: { masterPassword: string }) => {
        if (request.masterPassword !== 'remote master password') throw new Error('missing proof')
        return {
          sessionId: '20000000-0000-4000-8000-000000000002',
          requiresMasterPassword: true,
          expiresAt: 1_784_236_800_000
        }
      }),
      sendAccountEmailTwoFactorSetup: vi.fn(async () => undefined),
      completeAccountEmailTwoFactorSetup: vi.fn(async () => undefined),
      getEquivalentDomainSettings: vi.fn(async () => ({
        equivalentDomains: [['first.example', 'second.example']],
        globalEquivalentDomains: [
          { type: 1, domains: ['google.com', 'gmail.com'], excluded: false }
        ],
        revision: 'a'.repeat(64)
      })),
      updateEquivalentDomainSettings: vi.fn(async () => ({
        equivalentDomains: [['first.example', 'second.example']],
        globalEquivalentDomains: [
          { type: 1, domains: ['google.com', 'gmail.com'], excluded: true }
        ],
        revision: 'b'.repeat(64)
      })),
      connectSync: vi.fn(async () => ({ configured: true, state: 'ready' })),
      unlockSync: vi.fn(async () => ({ configured: true, state: 'ready' })),
      resolvePendingLoginImport: vi.fn(async () => ({ configured: true, state: 'ready' })),
      disconnectSync: vi.fn(async () => ({ configured: false, state: 'unconfigured' })),
      createLogin: vi.fn(async (request) => ({ id: 'created', ...request })),
      cloneLogin: vi.fn(async () => ({ id: 'clone' })),
      archiveLogins: vi.fn(async ({ ids }: { ids: string[] }) => ids.map((id) => ({ id }))),
      unarchiveLogins: vi.fn(async ({ ids }: { ids: string[] }) => ids.map((id) => ({ id }))),
      deleteLogins: vi.fn(async ({ ids }: { ids: string[] }) => ids.length),
      restoreLogins: vi.fn(async ({ ids }: { ids: string[] }) => ids.map((id) => ({ id }))),
      deleteLoginsPermanently: vi.fn(async ({ ids }: { ids: string[] }) => ids.length),
      updateLogin: vi.fn(async () => ({ id: 'item-a' })),
      deleteLogin: vi.fn(async () => undefined),
      deletePasskey: vi.fn(async () => ({ id: 'item-a', passkeys: [] })),
      setLoginFavorite: vi.fn(async () => ({ id: 'item-a' })),
      moveLogin: vi.fn(async () => ({ id: 'item-a' })),
      getTotp: vi.fn(async () => ({ code: '123456', period: 30, remainingSeconds: 12 })),
      copyTotp: vi.fn(async () => undefined),
      revealSecret: vi.fn(async () => 'secret'),
      copyField: vi.fn(async () => undefined),
      revealEditorSecrets: vi.fn(async () => ({ fields: {}, customFields: [] })),
      openLoginUri: vi.fn(async () => undefined),
      generateCredential: vi.fn(async (request) => ({
        credential: 'generated-value',
        category: 'password',
        generationDate: 1,
        algorithm: 'password',
        historyLocator: {
          index: 0,
          generationDate: 1,
          category: 'password',
          algorithm: 'password'
        },
        request
      })),
      generateSshKey: vi.fn(async () => ({
        privateKey: 'private-key',
        publicKey: 'ssh-ed25519 public-key',
        fingerprint: 'SHA256:fingerprint'
      })),
      generatorHistory: vi.fn(async () => []),
      clearGeneratorHistory: vi.fn(async () => undefined),
      copyGeneratorHistory: vi.fn(async () => undefined)
    }
    vault.runAuthorizedOperation = vi.fn(
      async (
        validate: (ids: readonly string[], state: { generation: number }) => boolean,
        operation: (authorize: (ids: readonly string[]) => void) => Promise<unknown>
      ) =>
        operation((ids) => {
          if (authorizationState.reprompt === 1 && !validate(ids, authorizationState)) {
            throw new VaultError('REPROMPT_REQUIRED')
          }
        })
    )
    vault.unlockedGeneration = vi.fn(async () => authorizationState.generation)
    vault.runUnlockedOperation = vi.fn(async (operation: (generation: number) => unknown) =>
      operation(authorizationState.generation)
    )
    const portability = {
      exportVault: vi.fn(async (request?: unknown) => {
        void request
        return {
          canceled: false,
          exportedFolders: 1,
          exportedItems: 2,
          skippedTrashItems: 1
        }
      }),
      importVault: vi.fn(async () => ({
        canceled: false,
        importedFolders: 1,
        importedItems: 2,
        skippedTrashItems: 0
      })),
      previewNativeRestore: vi.fn(async () => ({
        canceled: false,
        sessionId: '70000000-0000-4000-8000-000000000099',
        expiresAt: 301_000,
        createdAt: '2026-07-17T00:00:00.000Z',
        folderCount: 1,
        itemCount: 2,
        attachmentCount: 1,
        attachmentBytes: 23,
        resumePhase: null
      })),
      runNativeRestore: vi.fn(async (_ownerId, _sessionId, _masterPassword, progress) => {
        const summary = {
          phase: 'complete' as const,
          totalItems: 2,
          mappedItems: 2,
          totalAttachments: 1,
          uploadedAttachments: 1,
          needsReconciliationAttachments: 0,
          totalBytes: 23,
          completedBytes: 23
        }
        progress(summary, 'complete')
        return { state: 'complete' as const, summary }
      }),
      cancelNativeRestore: vi.fn(async () => undefined),
      clearCompletedNativeRestore: vi.fn(async () => undefined),
      disposeNativeRestoreSession: vi.fn(async () => undefined)
    }
    const afterMutation = vi.fn()
    const beforeSyncReconfigure = vi.fn(async () => undefined)
    const afterSyncChanged = vi.fn()
    registerVaultIpc({
      vault: vault as unknown as VaultService,
      portability: portability as unknown as Parameters<typeof registerVaultIpc>[0]['portability'],
      settings: {} as AppSettingsService,
      sshKeyImportSessions: new SshKeyImportSessionStore({ readClipboard: () => '' }),
      getMainWindow: () =>
        ({ isDestroyed: () => false, webContents }) as unknown as ReturnType<
          Parameters<typeof registerVaultIpc>[0]['getMainWindow']
        >,
      repromptNow: () => 1_000,
      repromptRandomBytes: (size) => Buffer.alloc(size, 5),
      afterMutation,
      beforeSyncReconfigure,
      afterSyncChanged
    })
    return {
      event,
      vault,
      portability,
      afterMutation,
      beforeSyncReconfigure,
      afterSyncChanged,
      setAuthorizationState: (state) => {
        authorizationState = state
      }
    }
  }

  it('invalidates the old notification lease before connect and disconnect reconfiguration', async () => {
    const { event, vault, beforeSyncReconfigure } = harness()
    const order: string[] = []
    beforeSyncReconfigure.mockImplementation(async () => {
      order.push('before')
    })
    vault.connectSync.mockImplementation(async () => {
      order.push('connect')
      return { configured: true, state: 'ready' }
    })
    vault.disconnectSync.mockImplementation(async () => {
      order.push('disconnect')
      return { configured: false, state: 'unconfigured' }
    })

    await electronMock.handlers.get(IPC_CHANNELS.syncConnect)!(event, {
      serverUrl: 'https://vault.example.invalid',
      email: 'person@example.invalid',
      masterPassword: 'remote password'
    })
    await electronMock.handlers.get(IPC_CHANNELS.syncDisconnect)!(event, undefined)

    expect(order).toEqual(['before', 'connect', 'before', 'disconnect'])
    expect(beforeSyncReconfigure).toHaveBeenCalledTimes(2)
  })

  it('validates and clears the master password before resolving an unknown import result', async () => {
    const { event, vault, afterSyncChanged } = harness()
    const resolve = electronMock.handlers.get(IPC_CHANNELS.syncResolvePendingImport)!
    let received: { masterPassword: string; confirmRetry: true } | undefined
    const status = {
      configured: true,
      state: 'ready',
      pendingImport: { count: 2, startedAt: '2026-07-17T00:00:00.000Z' }
    }
    vault.resolvePendingLoginImport.mockImplementation(
      async (request: { masterPassword: string; confirmRetry: true }) => {
        received = request
        expect(request).toEqual({ masterPassword: 'remote master password', confirmRetry: true })
        return status
      }
    )

    await expect(
      resolve(event, { masterPassword: 'remote master password', confirmRetry: true })
    ).resolves.toEqual(status)
    expect(afterSyncChanged).toHaveBeenCalledWith(status)
    expect(received).toEqual({ masterPassword: '', confirmRetry: true })

    for (const invalid of [
      undefined,
      {},
      { masterPassword: '', confirmRetry: true },
      { masterPassword: 'x'.repeat(1_025), confirmRetry: true },
      { masterPassword: 'remote master password' },
      { masterPassword: 'remote master password', confirmRetry: false },
      {
        masterPassword: 'remote master password',
        confirmRetry: true,
        marker: 'must-not-cross-ipc'
      },
      {
        masterPassword: 'remote master password',
        confirmRetry: true,
        localIds: ['must-not-cross-ipc']
      }
    ]) {
      await expect(resolve(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(vault.resolvePendingLoginImport).toHaveBeenCalledTimes(1)

    vault.resolvePendingLoginImport.mockImplementation(
      async (request: { masterPassword: string; confirmRetry: true }) => {
        received = request
        throw new VaultError('INVALID_MASTER_PASSWORD')
      }
    )
    await expect(
      resolve(event, { masterPassword: 'wrong password', confirmRetry: true })
    ).rejects.toThrow('BEARWARDEN:INVALID_MASTER_PASSWORD')
    expect(received).toEqual({ masterPassword: '', confirmRetry: true })
  })

  it('accepts only the explicit WebAuthn remember flag for sync connect and unlock', async () => {
    const { event, vault } = harness()
    const connect = electronMock.handlers.get(IPC_CHANNELS.syncConnect)!
    const unlock = electronMock.handlers.get(IPC_CHANNELS.syncUnlock)!
    const connectRequest = {
      serverUrl: 'https://vault.example.invalid',
      email: 'person@example.invalid',
      masterPassword: 'remote password',
      webAuthnRemember: false
    }
    const unlockRequest = { masterPassword: 'remote password', webAuthnRemember: true }

    await connect(event, connectRequest)
    await unlock(event, unlockRequest)

    expect(vault.connectSync).toHaveBeenCalledWith(connectRequest)
    expect(vault.unlockSync).toHaveBeenCalledWith(unlockRequest)

    for (const invalid of [
      { ...connectRequest, webAuthnRemember: 'false' },
      { ...connectRequest, webAuthnRemember: null },
      { ...connectRequest, twoFactorMethod: '7' },
      { ...connectRequest, challenge: 'must-not-cross-ipc' },
      { ...connectRequest, assertion: 'must-not-cross-ipc' }
    ]) {
      await expect(connect(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }

    for (const invalid of [
      { ...unlockRequest, webAuthnRemember: 1 },
      { ...unlockRequest, twoFactorMethod: '7' },
      { ...unlockRequest, challenge: 'must-not-cross-ipc' },
      { ...unlockRequest, assertion: 'must-not-cross-ipc' }
    ]) {
      await expect(unlock(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
  })

  it('keeps portability IPC path-free, exact, and password-proof scoped', async () => {
    const { event, portability } = harness()
    const observedRequests: VaultExportRequest[] = []
    const observedImportRequests: VaultImportRequest[] = []
    const requestReferences: VaultExportRequest[] = []
    const importRequestReferences: VaultImportRequest[] = []
    portability.exportVault.mockImplementation(async (value?: unknown) => {
      const request = value as VaultExportRequest
      observedRequests.push({ ...request } as VaultExportRequest)
      requestReferences.push(request)
      return {
        canceled: false,
        exportedFolders: 1,
        exportedItems: 2,
        skippedTrashItems: 1
      }
    })
    portability.importVault.mockImplementation(async (value?: unknown) => {
      const request = value as VaultImportRequest
      observedImportRequests.push({ ...request } as VaultImportRequest)
      importRequestReferences.push(request)
      return {
        canceled: false,
        importedFolders: 1,
        importedItems: 2,
        skippedTrashItems: 0
      }
    })
    const exportVault = electronMock.handlers.get(IPC_CHANNELS.vaultExport)!
    const importVault = electronMock.handlers.get(IPC_CHANNELS.vaultImport)!
    await expect(
      exportVault(event, {
        masterPassword: 'correct horse battery staple',
        password: 'portable backup password'
      })
    ).resolves.toMatchObject({ exportedItems: 2 })
    expect(observedRequests.at(-1)).toEqual({
      masterPassword: 'correct horse battery staple',
      password: 'portable backup password'
    })
    await exportVault(event, {
      masterPassword: 'correct horse battery staple',
      password: 'portable backup password',
      format: 'bearwarden-native'
    })
    expect(observedRequests.at(-1)).toEqual({
      masterPassword: 'correct horse battery staple',
      password: 'portable backup password',
      format: 'bearwarden-native'
    })
    await exportVault(event, {
      masterPassword: 'correct horse battery staple',
      format: 'bitwarden-zip'
    })
    expect(observedRequests.at(-1)).toEqual({
      masterPassword: 'correct horse battery staple',
      format: 'bitwarden-zip'
    })
    await exportVault(event, {
      masterPassword: 'correct horse battery staple',
      format: 'bitwarden-csv'
    })
    expect(observedRequests.at(-1)).toEqual({
      masterPassword: 'correct horse battery staple',
      format: 'bitwarden-csv'
    })
    const portableImportInput = {
      masterPassword: 'correct horse battery staple',
      password: 'portable backup password',
      format: 'portable'
    }
    await expect(importVault(event, portableImportInput)).resolves.toMatchObject({
      importedItems: 2
    })
    expect(observedImportRequests.at(-1)).toEqual({
      masterPassword: 'correct horse battery staple',
      password: 'portable backup password',
      format: 'portable'
    })
    expect(portableImportInput).toEqual({ masterPassword: '', password: '', format: 'portable' })
    await expect(
      importVault(event, {
        masterPassword: 'correct horse battery staple',
        format: 'keepass-xml'
      })
    ).resolves.toMatchObject({ importedItems: 2 })
    expect(observedImportRequests.at(-1)).toEqual({
      masterPassword: 'correct horse battery staple',
      format: 'keepass-xml'
    })
    await expect(
      importVault(event, {
        masterPassword: 'correct horse battery staple'
      })
    ).resolves.toMatchObject({ importedItems: 2 })
    expect(observedImportRequests.at(-1)).toEqual({
      masterPassword: 'correct horse battery staple'
    })

    let rejectedImportRequest: VaultImportRequest | undefined
    portability.importVault.mockImplementationOnce(async (value?: unknown) => {
      rejectedImportRequest = value as VaultImportRequest
      throw new Error('intended import failure')
    })
    const rejectedImportInput = {
      masterPassword: 'rejected-owner-proof',
      password: 'rejected-backup-secret',
      format: 'portable'
    }
    await expect(importVault(event, rejectedImportInput)).rejects.toThrow(
      'BEARWARDEN:INTERNAL_ERROR'
    )
    expect(rejectedImportInput).toEqual({ masterPassword: '', password: '', format: 'portable' })
    expect(rejectedImportRequest).toEqual({
      masterPassword: '',
      password: '',
      format: 'portable'
    })

    for (const invalid of [
      { password: 'portable backup password' },
      { masterPassword: 'correct horse battery staple' },
      {
        masterPassword: 'correct horse battery staple',
        password: 'portable backup password',
        path: '/tmp/renderer-controlled.json'
      },
      {
        masterPassword: 'correct horse battery staple',
        password: 'portable backup password',
        format: 'unknown'
      },
      {
        masterPassword: 'correct horse battery staple',
        password: 'must-not-be-used-for-plaintext',
        format: 'bitwarden-zip'
      },
      {
        masterPassword: 'correct horse battery staple',
        password: 'must-not-be-used-for-plaintext',
        format: 'bitwarden-csv'
      }
    ]) {
      await expect(exportVault(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    let getterCalls = 0
    const accessor = Object.defineProperty({}, 'masterPassword', {
      enumerable: true,
      get: () => {
        getterCalls += 1
        return 'must-not-be-read'
      }
    })
    await expect(exportVault(event, accessor)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(getterCalls).toBe(0)
    await expect(
      exportVault(event, {
        masterPassword: 'correct horse battery staple',
        format: 'bitwarden-csv',
        [Symbol('secret')]: 'must-not-cross-ipc'
      })
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    const invalidImportInputs: Array<Record<PropertyKey, unknown>> = [
      {
        masterPassword: 'wrong-type-owner-proof',
        password: 123
      },
      {
        masterPassword: 'unknown-format-owner-proof',
        password: 'unknown-format-backup-secret',
        format: 'unknown'
      },
      {
        masterPassword: 'keepass-owner-proof',
        password: 'keepass-must-not-accept-password',
        format: 'keepass-xml'
      },
      {
        masterPassword: 'extra-key-owner-proof',
        password: 'extra-key-backup-secret',
        format: 'portable',
        path: '/tmp/renderer-controlled.xml'
      }
    ]
    for (const invalid of invalidImportInputs) {
      await expect(importVault(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    for (const invalid of invalidImportInputs) {
      expect(Object.getOwnPropertyDescriptor(invalid, 'masterPassword')?.value).toBe('')
      expect(Object.getOwnPropertyDescriptor(invalid, 'password')?.value).toBe('')
    }

    let importGetterCalls = 0
    const importAccessor = Object.defineProperties(
      {},
      {
        masterPassword: {
          enumerable: true,
          get: () => {
            importGetterCalls += 1
            return 'must-not-be-read'
          }
        },
        password: {
          enumerable: true,
          configurable: true,
          writable: true,
          value: 'accessor-shape-backup-secret'
        },
        format: { enumerable: true, value: 'portable' }
      }
    )
    await expect(importVault(event, importAccessor)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(importGetterCalls).toBe(0)
    expect(Object.getOwnPropertyDescriptor(importAccessor, 'masterPassword')).toHaveProperty('get')
    expect(Object.getOwnPropertyDescriptor(importAccessor, 'password')?.value).toBe('')

    const importSymbol = Symbol('unexpected-import-key')
    const importWithSymbol = {
      masterPassword: 'symbol-owner-proof',
      password: 'symbol-backup-secret',
      format: 'portable',
      [importSymbol]: true
    }
    await expect(importVault(event, importWithSymbol)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(importWithSymbol).toMatchObject({ masterPassword: '', password: '' })

    const importWithPrototype = Object.assign(Object.create({ inherited: true }), {
      masterPassword: 'prototype-owner-proof',
      password: 'prototype-backup-secret',
      format: 'portable'
    }) as Record<string, unknown>
    await expect(importVault(event, importWithPrototype)).rejects.toThrow(
      'BEARWARDEN:INVALID_INPUT'
    )
    expect(importWithPrototype).toMatchObject({ masterPassword: '', password: '' })

    const frozenImport = Object.freeze({
      masterPassword: 'frozen-owner-proof',
      password: 'frozen-backup-secret',
      format: 'unknown'
    })
    await expect(importVault(event, frozenImport)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(frozenImport.masterPassword).toBe('frozen-owner-proof')
    expect(frozenImport.password).toBe('frozen-backup-secret')
    expect(requestReferences).toHaveLength(4)
    expect(
      requestReferences.every(
        (request) =>
          request.masterPassword === '' &&
          (!('password' in request) || request.password === undefined || request.password === '')
      )
    ).toBe(true)
    expect(importRequestReferences).toHaveLength(3)
    expect(importRequestReferences).toEqual([
      { masterPassword: '', password: '', format: 'portable' },
      { masterPassword: '', format: 'keepass-xml' },
      { masterPassword: '' }
    ])
  })

  it('keeps native restore sessions exact, sender-bound, progress-only, and secret-free', async () => {
    const { event, portability, afterMutation } = harness()
    const preview = electronMock.handlers.get(IPC_CHANNELS.nativeRestorePreview)!
    const start = electronMock.handlers.get(IPC_CHANNELS.nativeRestoreStart)!
    const cancel = electronMock.handlers.get(IPC_CHANNELS.nativeRestoreCancel)!
    const clear = electronMock.handlers.get(IPC_CHANNELS.nativeRestoreClearCompleted)!
    const sessionId = '70000000-0000-4000-8000-000000000099'
    await expect(preview(event, { password: 'portable backup password' })).resolves.toMatchObject({
      canceled: false,
      sessionId,
      attachmentCount: 1,
      attachmentBytes: 23
    })
    expect(portability.previewNativeRestore).toHaveBeenCalledWith(7, 'portable backup password')
    const result = await start(event, {
      sessionId,
      masterPassword: 'correct horse battery staple'
    })
    expect(result).toMatchObject({ state: 'complete', summary: { completedBytes: 23 } })
    expect(portability.runNativeRestore).toHaveBeenCalledWith(
      7,
      sessionId,
      'correct horse battery staple',
      expect.any(Function)
    )
    expect(
      (event as { sender: { send: ReturnType<typeof vi.fn> } }).sender.send
    ).toHaveBeenCalledWith(
      IPC_EVENTS.nativeRestoreProgress,
      expect.objectContaining({ sessionId, state: 'complete', completedBytes: 23 })
    )
    expect(JSON.stringify(result)).not.toContain('correct horse battery staple')
    expect(JSON.stringify(result)).not.toContain('portable backup password')
    expect(afterMutation).toHaveBeenCalledOnce()
    ;(event as { sender: { send: ReturnType<typeof vi.fn> } }).sender.send.mockImplementationOnce(
      () => {
        throw new Error('renderer closed')
      }
    )
    await expect(
      start(event, { sessionId, masterPassword: 'correct horse battery staple' })
    ).resolves.toMatchObject({ state: 'complete' })
    await cancel(event, { sessionId })
    await clear(event, { sessionId })
    expect(portability.cancelNativeRestore).toHaveBeenCalledWith(7, sessionId)
    expect(portability.clearCompletedNativeRestore).toHaveBeenCalledWith(7, sessionId)

    for (const invalid of [
      { password: 'portable backup password', path: '/tmp/secret.bwbackup' },
      {
        sessionId,
        masterPassword: 'correct horse battery staple',
        archiveFingerprint: 'a'.repeat(64)
      },
      { sessionId: 'not-a-capability' }
    ]) {
      const handler = 'password' in invalid ? preview : 'masterPassword' in invalid ? start : cancel
      await expect(handler(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
  })

  it('accepts a bounded empty vault query and rejects malformed list requests', async () => {
    const { event, vault } = harness()
    const list = electronMock.handlers.get(IPC_CHANNELS.loginList)!

    await expect(list(event, { query: '' })).resolves.toEqual([])
    expect(vault.listLogins).toHaveBeenCalledWith({ query: '' })
    const maximumQuery = 'x'.repeat(1_024)
    await expect(list(event, { query: maximumQuery })).resolves.toEqual([])
    expect(vault.listLogins).toHaveBeenLastCalledWith({ query: maximumQuery })

    for (const invalid of [
      { query: 'x'.repeat(1_025) },
      { query: 7 },
      { query: 'example', unknown: true }
    ]) {
      await expect(list(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(vault.listLogins).toHaveBeenCalledTimes(2)
  })

  it('exposes vault health through an exact empty request without a reprompt capability', async () => {
    const { event, vault } = harness()
    const health = electronMock.handlers.get(IPC_CHANNELS.vaultHealthReport)!

    await expect(health(event, {})).resolves.toEqual({
      generatedAt: '2026-07-16T00:00:00.000Z',
      totals: {
        analyzedCount: 1,
        weakPasswordCount: 1,
        reusedPasswordCount: 0,
        unsecuredWebsiteCount: 1,
        protectedSkippedCount: 1
      },
      weakPasswords: [{ id: 'item-a', name: 'Example', subtitle: '', score: 0 }],
      reusedPasswords: [],
      unsecuredWebsites: [{ id: 'item-http', name: 'Local router' }]
    })
    expect(vault.getHealthReport).toHaveBeenCalledWith()

    for (const invalid of [
      undefined,
      null,
      [],
      { authorizationToken: 'not-accepted' },
      { scope: 'all' }
    ]) {
      await expect(health(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(vault.getHealthReport).toHaveBeenCalledOnce()
  })

  it('exposes and cancels the explicit HIBP report only through exact empty requests', async () => {
    const { event, vault } = harness()
    const exposed = electronMock.handlers.get(IPC_CHANNELS.vaultHealthExposedPasswords)!
    const cancel = electronMock.handlers.get(IPC_CHANNELS.vaultHealthCancelExposedPasswords)!

    await expect(exposed(event, {})).resolves.toEqual({
      generatedAt: '2026-07-16T00:00:00.000Z',
      totals: {
        analyzedCount: 2,
        exposedPasswordCount: 1,
        protectedSkippedCount: 1
      },
      exposedPasswords: [{ id: 'item-a', name: 'Example', subtitle: '', exposedCount: 42 }]
    })
    expect(vault.getExposedPasswordReport).toHaveBeenCalledWith()
    await expect(cancel(event, {})).resolves.toBe(true)
    expect(vault.cancelExposedPasswordReport).toHaveBeenCalledWith()

    for (const invalid of [undefined, null, [], { password: 'must-not-be-accepted' }]) {
      await expect(exposed(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
      await expect(cancel(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(vault.getExposedPasswordReport).toHaveBeenCalledOnce()
    expect(vault.cancelExposedPasswordReport).toHaveBeenCalledOnce()
  })

  it('accepts only a bounded email for the explicit account-breach report', async () => {
    const { event, vault } = harness()
    const account = electronMock.handlers.get(IPC_CHANNELS.vaultHealthAccountBreaches)!
    const cancel = electronMock.handlers.get(IPC_CHANNELS.vaultHealthCancelAccountBreaches)!

    await expect(account(event, { email: '  member@example.invalid  ' })).resolves.toEqual({
      generatedAt: '2026-07-16T00:00:00.000Z',
      status: 'complete',
      breaches: []
    })
    expect(vault.getAccountBreachReport).toHaveBeenCalledWith({
      email: 'member@example.invalid'
    })
    await expect(cancel(event, {})).resolves.toBe(true)
    expect(vault.cancelAccountBreachReport).toHaveBeenCalledWith()

    for (const invalid of [
      undefined,
      null,
      {},
      { email: '' },
      { email: 'x'.repeat(255) },
      { email: 'member@example.invalid', authorizationToken: 'not-accepted' }
    ]) {
      await expect(account(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    for (const invalid of [undefined, null, [], { email: 'must-not-be-accepted' }]) {
      await expect(cancel(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(vault.getAccountBreachReport).toHaveBeenCalledOnce()
    expect(vault.cancelAccountBreachReport).toHaveBeenCalledOnce()
  })

  it('opens only the fixed HIBP attribution target through an empty request', async () => {
    const { event, vault } = harness()
    const open = electronMock.handlers.get(IPC_CHANNELS.vaultHealthOpenHibp)!

    await expect(open(event, {})).resolves.toBeUndefined()
    expect(vault.openHibpWebsite).toHaveBeenCalledWith()
    for (const invalid of [undefined, null, [], { url: 'https://example.invalid' }]) {
      await expect(open(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(vault.openHibpWebsite).toHaveBeenCalledOnce()
  })

  it('validates equivalent-domain reads and bounded replacement writes', async () => {
    const { event, vault } = harness()
    const get = electronMock.handlers.get(IPC_CHANNELS.domainRulesGet)!
    const update = electronMock.handlers.get(IPC_CHANNELS.domainRulesUpdate)!

    await expect(get(event, undefined)).resolves.toMatchObject({ revision: 'a'.repeat(64) })
    expect(vault.getEquivalentDomainSettings).toHaveBeenCalledWith()
    const request = {
      equivalentDomains: [['first.example', 'second.example']],
      excludedGlobalEquivalentDomains: [1],
      expectedRevision: 'a'.repeat(64)
    }
    await expect(update(event, request)).resolves.toMatchObject({ revision: 'b'.repeat(64) })
    expect(vault.updateEquivalentDomainSettings).toHaveBeenCalledWith(request)

    for (const invalid of [
      undefined,
      null,
      {},
      { ...request, extra: true },
      { ...request, expectedRevision: 'short' },
      { ...request, equivalentDomains: [['x'.repeat(1025)]] },
      { ...request, excludedGlobalEquivalentDomains: [-1] }
    ]) {
      await expect(update(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    for (const invalid of [null, [], {}, { extra: true }]) {
      await expect(get(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(vault.updateEquivalentDomainSettings).toHaveBeenCalledOnce()
    expect(vault.getEquivalentDomainSettings).toHaveBeenCalledOnce()
  })

  it('keeps account security actions on exact empty IPC requests', async () => {
    const { event, vault } = harness()
    const profile = electronMock.handlers.get(IPC_CHANNELS.accountSecurityProfile)!
    const devices = electronMock.handlers.get(IPC_CHANNELS.accountDevices)!
    const resend = electronMock.handlers.get(IPC_CHANNELS.accountResendVerification)!

    await expect(profile(event, undefined)).resolves.toMatchObject({
      email: 'sync@example.invalid',
      emailVerified: false
    })
    await expect(devices(event, undefined)).resolves.toEqual({
      status: 'available',
      devices: [expect.objectContaining({ name: 'Personal Mac', current: true, trusted: true })]
    })
    await expect(resend(event, undefined)).resolves.toBeUndefined()
    for (const invalid of [null, {}, [], { email: 'must-not-cross-this-boundary' }]) {
      await expect(profile(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
      await expect(devices(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
      await expect(resend(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(vault.getAccountSecurityProfile).toHaveBeenCalledOnce()
    expect(vault.getAccountDevices).toHaveBeenCalledOnce()
    expect(vault.resendAccountVerificationEmail).toHaveBeenCalledOnce()
  })

  it('keeps PIN capability IPC exact and clears all copied secrets', async () => {
    const { event, vault } = harness()
    const status = electronMock.handlers.get(IPC_CHANNELS.vaultPinStatus)!
    const enable = electronMock.handlers.get(IPC_CHANNELS.vaultPinEnable)!
    const disable = electronMock.handlers.get(IPC_CHANNELS.vaultPinDisable)!
    const unlock = electronMock.handlers.get(IPC_CHANNELS.vaultPinUnlock)!

    await expect(status(event, undefined)).resolves.toEqual({
      available: true,
      remainingAttempts: 5
    })
    await expect(
      enable(event, { pin: 'bear-2026', masterPassword: 'master password' })
    ).resolves.toEqual({ available: true, remainingAttempts: 5 })
    expect(vault.enablePinUnlock).toHaveBeenCalledWith({ pin: '', masterPassword: '' })
    await expect(unlock(event, { pin: 'bear-2026' })).resolves.toEqual({ state: 'unlocked' })
    expect(vault.unlockWithPin).toHaveBeenCalledWith({ pin: '' })
    await expect(disable(event, undefined)).resolves.toEqual({
      available: false,
      remainingAttempts: 0
    })

    for (const invalid of [null, {}, [], { extra: true }]) {
      await expect(status(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
      await expect(disable(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    for (const invalid of [
      undefined,
      null,
      {},
      { pin: '123', masterPassword: 'master password' },
      { pin: 'bear-2026', masterPassword: '' },
      { pin: 'bear-2026', masterPassword: 'master password', persist: true }
    ]) {
      await expect(enable(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    for (const invalid of [undefined, null, {}, { pin: '123' }, { pin: 'bear-2026', id: 'x' }]) {
      await expect(unlock(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(vault.enablePinUnlock).toHaveBeenCalledOnce()
    expect(vault.unlockWithPin).toHaveBeenCalledOnce()
  })

  it('never returns an API key secret across IPC and gates rotation confirmation', async () => {
    const { event, vault } = harness()
    const copyClientId = electronMock.handlers.get(IPC_CHANNELS.accountCopyApiClientId)!
    const copyApiKey = electronMock.handlers.get(IPC_CHANNELS.accountCopyApiKey)!

    await expect(copyClientId(event, undefined)).resolves.toBeUndefined()
    const request = {
      masterPassword: 'remote master password',
      rotate: false,
      confirmRotation: false
    }
    await expect(copyApiKey(event, request)).resolves.toEqual({
      rotated: false,
      revisionDate: '2026-07-16T00:00:00Z'
    })
    expect(JSON.stringify(await copyApiKey(event, { ...request }))).not.toContain('secret')
    expect(vault.copyPersonalApiKey).toHaveBeenCalledWith({
      masterPassword: '',
      rotate: false,
      confirmRotation: false
    })

    for (const invalid of [
      undefined,
      null,
      {},
      { ...request, rotate: true },
      { ...request, confirmRotation: true },
      { ...request, clientSecret: 'renderer-supplied-secret' }
    ]) {
      await expect(copyApiKey(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(vault.copyPersonalApiKey).toHaveBeenCalledTimes(2)
  })

  it('keeps recovery codes out of IPC responses and rejects extra fields', async () => {
    const { event, vault } = harness()
    const status = electronMock.handlers.get(IPC_CHANNELS.accountTwoFactorStatus)!
    const recovery = electronMock.handlers.get(IPC_CHANNELS.accountCopyRecoveryCode)!

    await expect(status(event, undefined)).resolves.toEqual([{ type: 0, enabled: true }])
    await expect(
      recovery(event, { masterPassword: 'remote master password' })
    ).resolves.toBeUndefined()
    expect(vault.copyTwoFactorRecoveryCode).toHaveBeenCalledWith({ masterPassword: '' })
    for (const invalid of [
      undefined,
      null,
      {},
      { masterPassword: '' },
      { masterPassword: 'password', recoveryCode: 'renderer-value' }
    ]) {
      await expect(recovery(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
  })

  it('validates destructive 2FA disable requests and returns no secrets', async () => {
    const { event, vault } = harness()
    const disable = electronMock.handlers.get(IPC_CHANNELS.accountDisableTwoFactorProvider)!
    const request = {
      type: 0,
      masterPassword: 'remote master password',
      confirm: true
    }

    await expect(disable(event, request)).resolves.toBeUndefined()
    expect(String(await disable(event, { ...request, type: 1 }))).not.toContain(
      'remote master password'
    )
    expect(vault.disableTwoFactorProvider).toHaveBeenNthCalledWith(1, {
      type: 0,
      masterPassword: '',
      confirm: true
    })
    expect(vault.disableTwoFactorProvider).toHaveBeenNthCalledWith(2, {
      type: 1,
      masterPassword: '',
      confirm: true
    })

    for (const invalid of [
      undefined,
      null,
      {},
      { ...request, type: 2 },
      { ...request, confirm: false },
      { ...request, masterPassword: '' },
      { ...request, providerName: 'renderer-supplied-name' }
    ]) {
      await expect(disable(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(vault.disableTwoFactorProvider).toHaveBeenCalledTimes(2)
  })

  it('keeps authenticator setup capabilities in main and validates the one-time session boundary', async () => {
    const { event, vault } = harness()
    const begin = electronMock.handlers.get(IPC_CHANNELS.accountBeginAuthenticatorSetup)!
    const copyKey = electronMock.handlers.get(IPC_CHANNELS.accountCopyAuthenticatorKey)!
    const complete = electronMock.handlers.get(IPC_CHANNELS.accountCompleteAuthenticatorSetup)!
    const sessionId = '10000000-0000-4000-8000-000000000001'

    const setup = await begin(event, { masterPassword: 'remote master password' })
    expect(setup).toEqual({
      sessionId,
      key: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
      requiresMasterPassword: true,
      expiresAt: 1_784_236_800_000
    })
    expect(JSON.stringify(setup)).not.toContain('userVerificationToken')
    expect(vault.beginAccountAuthenticatorSetup).toHaveBeenCalledWith({ masterPassword: '' })

    await expect(copyKey(event, { sessionId })).resolves.toBeUndefined()
    await expect(
      complete(event, {
        sessionId,
        token: '123456',
        masterPassword: 'remote master password'
      })
    ).resolves.toBeUndefined()
    expect(vault.completeAccountAuthenticatorSetup).toHaveBeenCalledWith({
      sessionId,
      token: '',
      masterPassword: ''
    })

    for (const invalid of [
      undefined,
      {},
      { sessionId: 'not-a-uuid' },
      { sessionId, key: 'renderer-supplied-key' }
    ]) {
      await expect(copyKey(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    for (const invalid of [
      undefined,
      {},
      { sessionId, token: '12345' },
      { sessionId, token: '123456', userVerificationToken: 'must-not-cross' }
    ]) {
      await expect(complete(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
  })

  it('keeps Email 2FA capabilities in main across the two mutation phases', async () => {
    const { event, vault } = harness()
    const begin = electronMock.handlers.get(IPC_CHANNELS.accountBeginEmailTwoFactorSetup)!
    const send = electronMock.handlers.get(IPC_CHANNELS.accountSendEmailTwoFactorSetup)!
    const complete = electronMock.handlers.get(IPC_CHANNELS.accountCompleteEmailTwoFactorSetup)!
    const sessionId = '20000000-0000-4000-8000-000000000002'

    const setup = await begin(event, { masterPassword: 'remote master password' })
    expect(setup).toEqual({
      sessionId,
      requiresMasterPassword: true,
      expiresAt: 1_784_236_800_000
    })
    expect(JSON.stringify(setup)).not.toContain('userVerificationToken')
    expect(vault.beginAccountEmailTwoFactorSetup).toHaveBeenCalledWith({ masterPassword: '' })

    await expect(
      send(event, {
        sessionId,
        email: 'factor@example.test',
        masterPassword: 'remote master password'
      })
    ).resolves.toBeUndefined()
    expect(vault.sendAccountEmailTwoFactorSetup).toHaveBeenCalledWith({
      sessionId,
      email: '',
      masterPassword: ''
    })
    await expect(
      complete(event, {
        sessionId,
        token: '123456',
        masterPassword: 'remote master password'
      })
    ).resolves.toBeUndefined()
    expect(vault.completeAccountEmailTwoFactorSetup).toHaveBeenCalledWith({
      sessionId,
      token: '',
      masterPassword: ''
    })

    await expect(
      send(event, { sessionId, email: 'factor@example.test', userVerificationToken: 'forbidden' })
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    await expect(complete(event, { sessionId, token: 'not-numeric' })).rejects.toThrow(
      'BEARWARDEN:INVALID_INPUT'
    )
  })

  it.each([
    [IPC_CHANNELS.loginGet, 'getLogin', { id: 'item-a' }],
    [IPC_CHANNELS.loginGetPasswordHistory, 'getPasswordHistory', { id: 'item-a' }],
    [
      IPC_CHANNELS.loginRestorePasswordHistory,
      'restorePasswordHistory',
      {
        id: 'item-a',
        index: 0,
        lastUsedDate: '2026-07-14T00:00:00.000Z',
        expectedUpdatedAt: '2026-07-16T00:00:00.000Z'
      }
    ],
    [IPC_CHANNELS.loginClone, 'cloneLogin', { id: 'item-a' }],
    [IPC_CHANNELS.loginUpdate, 'updateLogin', { id: 'item-a', name: 'Updated' }],
    [IPC_CHANNELS.loginDelete, 'deleteLogin', { id: 'item-a' }],
    [IPC_CHANNELS.passkeyDelete, 'deletePasskey', { id: 'item-a', credentialId: 'credential-a' }],
    [IPC_CHANNELS.loginSetFavorite, 'setLoginFavorite', { id: 'item-a', favorite: true }],
    [IPC_CHANNELS.loginMove, 'moveLogin', { id: 'item-a', folderId: null }],
    [IPC_CHANNELS.loginGetTotp, 'getTotp', { id: 'item-a' }],
    [IPC_CHANNELS.loginCopyTotp, 'copyTotp', { id: 'item-a' }],
    [IPC_CHANNELS.itemRevealSecret, 'revealSecret', { id: 'item-a', field: 'password' }],
    [
      IPC_CHANNELS.itemRevealEditorSecrets,
      'revealEditorSecrets',
      { id: 'item-a', expectedUpdatedAt: '2026-07-16T00:00:00.000Z' }
    ],
    [IPC_CHANNELS.loginOpenUri, 'openLoginUri', { id: 'item-a' }]
  ])('blocks %s before invoking %s without an item token', async (channel, method, input) => {
    const { event, vault } = harness()
    await expect(electronMock.handlers.get(channel)!(event, input)).rejects.toThrow(
      'BEARWARDEN:REPROMPT_REQUIRED'
    )
    expect(vault[method]).not.toHaveBeenCalled()
  })

  it.each([
    [
      IPC_CHANNELS.attachmentDownload,
      'downloadAttachment',
      { id: 'item-a', attachmentId: 'attachment-a', operationId }
    ],
    [IPC_CHANNELS.attachmentUpload, 'uploadAttachment', { id: 'item-a', operationId }],
    [
      IPC_CHANNELS.attachmentDelete,
      'deleteAttachment',
      { id: 'item-a', attachmentId: 'attachment-a', operationId }
    ],
    [
      IPC_CHANNELS.attachmentFixLegacy,
      'fixLegacyAttachment',
      { id: 'item-a', attachmentId: 'attachment-a', operationId }
    ]
  ])(
    'lets the attachment service reject %s without holding the IPC authorization mutex',
    async (channel, method, input) => {
      const { event, vault } = harness()
      await expect(electronMock.handlers.get(channel)!(event, input)).rejects.toThrow(
        'BEARWARDEN:REPROMPT_REQUIRED'
      )
      expect(vault[method]).toHaveBeenCalledWith(input, expect.any(Function), expect.any(Function))
      expect(vault.runAuthorizedOperation).not.toHaveBeenCalled()
    }
  )

  it('issues proof only after password verification and rejects wrong item or epoch', async () => {
    const { event, setAuthorizationState } = harness()
    const authorize = electronMock.handlers.get(IPC_CHANNELS.loginAuthorize)!
    await expect(
      authorize(event, { id: 'item-a', masterPassword: 'wrong password' })
    ).rejects.toThrow('BEARWARDEN:INVALID_MASTER_PASSWORD')

    const authorization = (await authorize(event, {
      id: 'item-a',
      masterPassword: 'correct horse battery staple'
    })) as { token: string }
    const get = electronMock.handlers.get(IPC_CHANNELS.loginGet)!
    const getHistory = electronMock.handlers.get(IPC_CHANNELS.loginGetPasswordHistory)!
    const getTotp = electronMock.handlers.get(IPC_CHANNELS.loginGetTotp)!
    const copyTotp = electronMock.handlers.get(IPC_CHANNELS.loginCopyTotp)!
    await expect(
      get(event, { id: 'item-a', authorizationToken: authorization.token })
    ).resolves.toEqual({ id: 'item-a' })
    await expect(
      getTotp(event, { id: 'item-a', authorizationToken: authorization.token })
    ).resolves.toEqual({ code: '123456', period: 30, remainingSeconds: 12 })
    await expect(
      copyTotp(event, { id: 'item-a', authorizationToken: authorization.token })
    ).resolves.toBeUndefined()

    await expect(
      get(event, { id: 'item-b', authorizationToken: authorization.token })
    ).rejects.toThrow('BEARWARDEN:REPROMPT_REQUIRED')
    await expect(
      getHistory(event, { id: 'item-b', authorizationToken: authorization.token })
    ).rejects.toThrow('BEARWARDEN:REPROMPT_REQUIRED')
    await expect(
      getTotp(event, { id: 'item-b', authorizationToken: authorization.token })
    ).rejects.toThrow('BEARWARDEN:REPROMPT_REQUIRED')
    setAuthorizationState({ reprompt: 1, generation: 4 })
    await expect(
      get(event, { id: 'item-a', authorizationToken: authorization.token })
    ).rejects.toThrow('BEARWARDEN:REPROMPT_REQUIRED')
    await expect(
      getHistory(event, { id: 'item-a', authorizationToken: authorization.token })
    ).rejects.toThrow('BEARWARDEN:REPROMPT_REQUIRED')
  })

  it('accepts only narrow exact TOTP requests', async () => {
    const { event, vault, setAuthorizationState } = harness()
    setAuthorizationState({ reprompt: 0, generation: 3 })
    for (const [channel, method] of [
      [IPC_CHANNELS.loginGetTotp, 'getTotp'],
      [IPC_CHANNELS.loginCopyTotp, 'copyTotp']
    ] as const) {
      const handler = electronMock.handlers.get(channel)!
      await expect(handler(event, { id: 'item-a', extra: true })).rejects.toThrow(
        'BEARWARDEN:INVALID_INPUT'
      )
      expect(vault[method]).not.toHaveBeenCalled()
      await handler(event, { id: 'item-a' })
      expect(vault[method]).toHaveBeenCalledOnce()
      expect(vault[method]).toHaveBeenCalledWith({ id: 'item-a' })
    }
  })

  it('validates and authorizes exact passkey deletion requests before notifying mutations', async () => {
    const { event, vault, afterMutation, setAuthorizationState } = harness()
    setAuthorizationState({ reprompt: 0, generation: 3 })
    const handler = electronMock.handlers.get(IPC_CHANNELS.passkeyDelete)!
    const request = {
      id: 'item-a',
      credentialId: 'credential-a',
      expectedUpdatedAt: '2026-07-16T00:00:00.000Z'
    }

    await expect(handler(event, request)).resolves.toEqual({ id: 'item-a', passkeys: [] })
    expect(vault.deletePasskey).toHaveBeenCalledWith(request)
    expect(afterMutation).toHaveBeenCalledOnce()

    for (const invalid of [
      { ...request, extra: true },
      { ...request, credentialId: 7 },
      { ...request, credentialId: 'x'.repeat(4_097) },
      { ...request, expectedUpdatedAt: null }
    ]) {
      await expect(handler(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(vault.deletePasskey).toHaveBeenCalledOnce()
    expect(afterMutation).toHaveBeenCalledOnce()
  })

  const batchOperations = [
    [IPC_CHANNELS.loginArchiveMany, 'archiveLogins'],
    [IPC_CHANNELS.loginUnarchiveMany, 'unarchiveLogins'],
    [IPC_CHANNELS.loginDeleteMany, 'deleteLogins'],
    [IPC_CHANNELS.loginRestoreMany, 'restoreLogins'],
    [IPC_CHANNELS.loginDeletePermanentlyMany, 'deleteLoginsPermanently']
  ] as const
  const batchIds = ['10000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000002']

  it.each(batchOperations)(
    'binds %s to the exact batch set and invokes %s only once',
    async (channel, method) => {
      const { event, vault, afterMutation } = harness()
      const authorization = (await electronMock.handlers.get(IPC_CHANNELS.loginAuthorizeMany)!(
        event,
        { ids: batchIds, masterPassword: 'correct horse battery staple' }
      )) as { token: string }
      const handler = electronMock.handlers.get(channel)!
      const request = {
        ids: [...batchIds].reverse(),
        authorizationToken: authorization.token
      }

      await expect(handler(event, request)).resolves.toBeDefined()
      expect(vault[method]).toHaveBeenCalledTimes(1)
      expect(vault[method]).toHaveBeenCalledWith(request)
      expect(afterMutation).toHaveBeenCalledTimes(1)

      await expect(
        handler(event, {
          ids: [batchIds[0], '10000000-0000-4000-8000-000000000003'],
          authorizationToken: authorization.token
        })
      ).rejects.toThrow('BEARWARDEN:REPROMPT_REQUIRED')
      expect(vault[method]).toHaveBeenCalledTimes(1)
      expect(afterMutation).toHaveBeenCalledTimes(1)
    }
  )

  it.each(batchOperations)(
    'blocks protected %s before invoking %s without a batch token',
    async (channel, method) => {
      const { event, vault } = harness()
      await expect(electronMock.handlers.get(channel)!(event, { ids: batchIds })).rejects.toThrow(
        'BEARWARDEN:REPROMPT_REQUIRED'
      )
      expect(vault[method]).not.toHaveBeenCalled()
    }
  )

  it.each(batchOperations)(
    'rejects malformed exact batch requests on %s',
    async (channel, method) => {
      const { event, vault, setAuthorizationState } = harness()
      setAuthorizationState({ reprompt: 0, generation: 3 })
      const ids501 = Array.from(
        { length: 501 },
        (_, index) => `20000000-0000-4000-8000-${String(index).padStart(12, '0')}`
      )
      const handler = electronMock.handlers.get(channel)!
      for (const invalid of [
        { ids: [] },
        { ids: ids501 },
        { ids: [batchIds[0], batchIds[0]] },
        { ids: ['not-a-uuid'] },
        { ids: batchIds, extra: true }
      ]) {
        await expect(handler(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
      }
      expect(vault[method]).not.toHaveBeenCalled()
    }
  )

  it('uses a narrow exact history request and propagates the trash rejection', async () => {
    const { event, vault, setAuthorizationState } = harness()
    setAuthorizationState({ reprompt: 0, generation: 3 })
    const getHistory = electronMock.handlers.get(IPC_CHANNELS.loginGetPasswordHistory)!
    await expect(getHistory(event, { id: 'item-a', future: true })).rejects.toThrow(
      'BEARWARDEN:INVALID_INPUT'
    )
    vault.getPasswordHistory.mockRejectedValueOnce(new VaultError('INVALID_INPUT'))
    await expect(getHistory(event, { id: 'item-a' })).rejects.toThrow('BEARWARDEN:INVALID_INPUT')

    const restore = electronMock.handlers.get(IPC_CHANNELS.loginRestorePasswordHistory)!
    const request = {
      id: 'item-a',
      index: 0,
      lastUsedDate: '2026-07-14T00:00:00.000Z',
      expectedUpdatedAt: '2026-07-16T00:00:00.000Z'
    }
    await expect(restore(event, request)).resolves.toEqual({ id: 'item-a' })
    expect(vault.restorePasswordHistory).toHaveBeenCalledWith(request)
    for (const invalid of [
      { ...request, index: -1 },
      { ...request, index: 5 },
      { ...request, lastUsedDate: 'not-a-date' },
      { ...request, expectedUpdatedAt: 'not-a-date' },
      { ...request, password: 'renderer-secret' }
    ]) {
      await expect(restore(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
  })

  it('keeps attachment download paths out of renderer IPC', async () => {
    const { event, vault, setAuthorizationState } = harness()
    setAuthorizationState({ reprompt: 0, generation: 3 })
    const download = electronMock.handlers.get(IPC_CHANNELS.attachmentDownload)!
    await expect(
      download(event, {
        id: 'item-a',
        attachmentId: 'attachment-a',
        operationId,
        path: '/tmp/renderer-controlled.txt'
      })
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    await expect(
      download(event, { id: 'item-a', attachmentId: 'attachment-a', operationId })
    ).resolves.toEqual({ canceled: false, fileName: 'document.txt' })
    expect(vault.downloadAttachment).toHaveBeenCalledWith(
      { id: 'item-a', attachmentId: 'attachment-a', operationId },
      expect.any(Function),
      expect.any(Function)
    )
  })

  it('forwards only structured attachment progress to the invoking renderer', async () => {
    const { event, vault, setAuthorizationState } = harness()
    setAuthorizationState({ reprompt: 0, generation: 3 })
    const progress = {
      operationId,
      itemId: 'item-a',
      kind: 'download' as const,
      stage: 'downloading' as const,
      completedBytes: 6,
      totalBytes: 12
    }
    vault.downloadAttachment.mockImplementation(async (_request, report) => {
      report(progress)
      return { canceled: false, fileName: 'document.txt' }
    })

    await expect(
      electronMock.handlers.get(IPC_CHANNELS.attachmentDownload)!(event, {
        id: 'item-a',
        attachmentId: 'attachment-a',
        operationId
      })
    ).resolves.toEqual({ canceled: false, fileName: 'document.txt' })
    expect(
      (event as { sender: { send: ReturnType<typeof vi.fn> } }).sender.send
    ).toHaveBeenCalledWith(IPC_EVENTS.attachmentProgress, progress)
  })

  it('keeps upload paths, bytes, names, and sizes out of renderer IPC', async () => {
    const { event, vault, setAuthorizationState } = harness()
    setAuthorizationState({ reprompt: 0, generation: 3 })
    const upload = electronMock.handlers.get(IPC_CHANNELS.attachmentUpload)!
    for (const forbidden of [
      { path: '/tmp/private.txt' },
      { bytes: [1, 2, 3] },
      { fileName: 'private.txt' },
      { size: 3 }
    ]) {
      await expect(upload(event, { id: 'item-a', operationId, ...forbidden })).rejects.toThrow(
        'BEARWARDEN:INVALID_INPUT'
      )
    }
    await expect(upload(event, { id: 'item-a', operationId })).resolves.toMatchObject({
      canceled: false,
      attachment: { fileName: 'upload.txt' }
    })
    expect(vault.uploadAttachment).toHaveBeenCalledWith(
      { id: 'item-a', operationId },
      expect.any(Function),
      expect.any(Function)
    )
  })

  it('validates operation ids and exposes cancel only to the trusted exact channel', async () => {
    const { event, vault } = harness()
    const cancel = electronMock.handlers.get(IPC_CHANNELS.attachmentCancel)!
    await expect(cancel(event, { operationId: 'not-a-uuid' })).rejects.toThrow(
      'BEARWARDEN:INVALID_INPUT'
    )
    await expect(cancel(event, { operationId, extra: true })).rejects.toThrow(
      'BEARWARDEN:INVALID_INPUT'
    )
    await expect(cancel(event, { operationId })).resolves.toEqual({ canceled: true })
    expect(vault.cancelAttachmentOperation).toHaveBeenCalledWith({ operationId })
  })

  it.each([
    [
      { algorithm: 'password', options: { length: 20, minNumber: 2 } },
      { algorithm: 'password', options: { length: 20, minNumber: 2 } }
    ],
    [
      { algorithm: 'passphrase', options: { wordCount: 8, separator: ' ', capitalize: true } },
      { algorithm: 'passphrase', options: { wordCount: 8, separator: ' ', capitalize: true } }
    ],
    [
      { algorithm: 'username', options: { includeNumber: true } },
      { algorithm: 'username', options: { includeNumber: true } }
    ],
    [
      { algorithm: 'subaddress', email: 'bear@example.invalid' },
      { algorithm: 'subaddress', email: 'bear@example.invalid' }
    ],
    [
      { algorithm: 'catchall', domain: 'example.invalid' },
      { algorithm: 'catchall', domain: 'example.invalid' }
    ]
  ])('parses an exact generator request %#', async (input, expected) => {
    const { event, vault } = harness()
    const generate = electronMock.handlers.get(IPC_CHANNELS.generatorGenerate)!
    await generate(event, input)
    expect(vault.generateCredential).toHaveBeenLastCalledWith(expected)
  })

  it.each([
    { algorithm: 'password', options: { length: 4 } },
    { algorithm: 'password', options: { minNumber: 10 } },
    { algorithm: 'password', options: { future: true } },
    { algorithm: 'password', options: {}, email: 'bear@example.invalid' },
    { algorithm: 'passphrase', options: { separator: '🙂' } },
    { algorithm: 'username', options: { includeNumber: 'yes' } },
    { algorithm: 'subaddress', email: 'x'.repeat(255) },
    { algorithm: 'catchall', domain: 'x'.repeat(255) },
    { algorithm: 'forwarder', options: {} }
  ])('rejects an oversized or non-exact generator request %#', async (input) => {
    const { event, vault } = harness()
    const generate = electronMock.handlers.get(IPC_CHANNELS.generatorGenerate)!
    await expect(generate(event, input)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(vault.generateCredential).not.toHaveBeenCalled()
  })

  it('keeps generator history IPC narrow and rejects stale-shaped copy locators', async () => {
    const { event, vault } = harness()
    const history = electronMock.handlers.get(IPC_CHANNELS.generatorHistoryList)!
    const clear = electronMock.handlers.get(IPC_CHANNELS.generatorHistoryClear)!
    const copy = electronMock.handlers.get(IPC_CHANNELS.generatorHistoryCopy)!
    await expect(history(event, undefined)).resolves.toEqual([])
    await expect(clear(event, undefined)).resolves.toBeUndefined()
    await copy(event, {
      index: 0,
      generationDate: 1,
      category: 'password',
      algorithm: 'password'
    })
    expect(vault.copyGeneratorHistory).toHaveBeenCalledWith({
      index: 0,
      generationDate: 1,
      category: 'password',
      algorithm: 'password'
    })
    for (const invalid of [
      { index: 200, generationDate: 1, category: 'password', algorithm: 'password' },
      {
        index: 0,
        generationDate: 1,
        category: 'password',
        algorithm: 'password',
        credential: 'renderer-secret'
      },
      { index: 0, generationDate: 1, category: 'password', algorithm: 'future' }
    ]) {
      await expect(copy(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    await expect(history(event, {})).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    await expect(clear(event, {})).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
  })

  it('stages generated SSH private material in main and returns only a one-time handle', async () => {
    const { event, vault } = harness()
    const generate = electronMock.handlers.get(IPC_CHANNELS.sshKeyGenerate)!
    const create = electronMock.handlers.get(IPC_CHANNELS.sshKeyCreateImported)!

    const ready = await generate(event, undefined)
    expect(ready).toEqual({
      status: 'ready',
      token: expect.any(String),
      expiresAt: expect.any(Number),
      publicKey: 'ssh-ed25519 public-key',
      fingerprint: 'SHA256:fingerprint'
    })
    expect(JSON.stringify(ready)).not.toContain('private-key')
    expect(vault.generateSshKey).toHaveBeenCalledOnce()

    await expect(
      create(event, { name: 'Generated key', importToken: (ready as { token: string }).token })
    ).resolves.toMatchObject({ id: 'created', type: 'sshKey' })
    expect(vault.createLogin).toHaveBeenCalledWith(
      expect.objectContaining({
        privateKey: 'private-key',
        publicKey: 'ssh-ed25519 public-key',
        fingerprint: 'SHA256:fingerprint'
      })
    )
    await expect(
      create(event, { name: 'Replay', importToken: (ready as { token: string }).token })
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')

    await expect(
      generate(
        {
          ...(event as Record<string, unknown>),
          senderFrame: { url: 'https://untrusted.example.invalid' }
        },
        undefined
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')

    for (const invalid of [null, {}, { algorithm: 'ED25519' }]) {
      await expect(generate(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(vault.generateSshKey).toHaveBeenCalledOnce()
  })

  it('parses ordered URI match rows and indexed copy/open requests', async () => {
    const { event, vault, setAuthorizationState } = harness()
    setAuthorizationState({ reprompt: 0, generation: 3 })
    const create = electronMock.handlers.get(IPC_CHANNELS.loginCreate)!
    await create(event, {
      name: 'Multiple URIs',
      uri: 'https://primary.example.invalid',
      uris: [
        { uri: 'https://primary.example.invalid', match: null },
        { uri: '^https://secondary\\.example\\.invalid/', match: 4 }
      ]
    })
    expect(vault.createLogin).toHaveBeenCalledWith(
      expect.objectContaining({
        uris: [
          { uri: 'https://primary.example.invalid', match: null },
          { uri: '^https://secondary\\.example\\.invalid/', match: 4 }
        ]
      })
    )

    const copy = electronMock.handlers.get(IPC_CHANNELS.itemCopyField)!
    await copy(event, { id: 'item-a', field: 'uri', uriIndex: 1, authorizationToken: 'token' })
    expect(vault.copyField).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'item-a', field: 'uri', uriIndex: 1 })
    )
    const open = electronMock.handlers.get(IPC_CHANNELS.loginOpenUri)!
    await open(event, { id: 'item-a', uriIndex: 1, authorizationToken: 'token' })
    expect(vault.openLoginUri).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'item-a', uriIndex: 1 })
    )
    await expect(
      create(event, { name: 'Invalid match', uris: [{ uri: 'x', match: 6 }] })
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
  })

  it('issues one batch capability for 1,001 validated item IDs', async () => {
    const { event, vault } = harness()
    const ids = Array.from(
      { length: 1_001 },
      (_, index) => `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`
    )
    const authorizeMany = electronMock.handlers.get(IPC_CHANNELS.loginAuthorizeMany)!
    await expect(
      authorizeMany(event, { ids, masterPassword: 'correct horse battery staple' })
    ).resolves.toMatchObject({ token: expect.any(String), expiresAt: 61_000 })
    expect(vault.authorizeLogins).toHaveBeenCalledWith({
      ids,
      masterPassword: 'correct horse battery staple'
    })
  })
})

describe('registerVaultIpc SSH clipboard imports', () => {
  function harness(): {
    event: { sender: { id: number }; senderFrame: { url: string } }
    secondEvent: { sender: { id: number }; senderFrame: { url: string } }
    useSecondSender: () => void
    vault: Record<string, ReturnType<typeof vi.fn>>
    setGeneration: (generation: number) => void
    setTargetType: (type: 'login' | 'sshKey') => void
    reads: () => number
    beforeLock: ReturnType<typeof vi.fn>
    afterMutation: ReturnType<typeof vi.fn>
  } {
    let reads = 0
    let generation = 9
    let targetType: 'login' | 'sshKey' = 'sshKey'
    let currentWindow: { isDestroyed: () => boolean; webContents: unknown }
    const mainFrame = { url: 'app://bearwarden/index.html' }
    const webContents = {
      id: 17,
      mainFrame,
      getURL: () => mainFrame.url,
      isDestroyed: () => false
    }
    const secondFrame = { url: 'app://bearwarden/index.html' }
    const secondWebContents = {
      id: 18,
      mainFrame: secondFrame,
      getURL: () => secondFrame.url,
      isDestroyed: () => false
    }
    currentWindow = { isDestroyed: () => false, webContents }
    const event = { sender: webContents, senderFrame: mainFrame }
    const secondEvent = { sender: secondWebContents, senderFrame: secondFrame }
    const sessions = new SshKeyImportSessionStore({
      readClipboard: () => {
        reads += 1
        return 'encrypted'
      },
      parser: {
        importSshKey: (key, password) => {
          if (key.toString('utf8') !== 'encrypted') throw new SshKeyImportError('ParsingError')
          if (!password) throw new SshKeyImportError('PasswordRequired')
          if (password.toString('utf8') !== 'correct passphrase') {
            throw new SshKeyImportError('WrongPassword')
          }
          return {
            privateKey: 'main-process-private-key',
            publicKey: 'ssh-ed25519 public-key',
            fingerprint: 'SHA256:main-process-fingerprint'
          }
        }
      }
    })
    const vault: Record<string, ReturnType<typeof vi.fn>> = {
      unlockedGeneration: vi.fn(async () => generation),
      runUnlockedOperation: vi.fn(async (operation) => operation(generation)),
      authorizeLogin: vi.fn(async () => generation),
      getLogin: vi.fn(async () => ({ type: targetType })),
      runAuthorizedOperation: vi.fn(async (validate, operation) =>
        operation((ids: readonly string[]) => {
          if (!validate(ids, { generation })) throw new VaultError('REPROMPT_REQUIRED')
        })
      ),
      createLogin: vi.fn(async (request) => ({
        id: 'created',
        type: request.type,
        publicKey: request.publicKey,
        fingerprint: request.fingerprint
      })),
      updateLogin: vi.fn(async (request) => ({
        id: request.id,
        type: 'sshKey',
        publicKey: request.publicKey,
        fingerprint: request.fingerprint
      })),
      lock: vi.fn(async () => ({ state: 'locked' }))
    }
    const beforeLock = vi.fn(() => sessions.clearAll())
    const afterMutation = vi.fn()
    registerVaultIpc({
      vault: vault as unknown as VaultService,
      portability: {} as Parameters<typeof registerVaultIpc>[0]['portability'],
      settings: {} as AppSettingsService,
      getMainWindow: () => currentWindow as never,
      sshKeyImportSessions: sessions,
      beforeLock,
      afterMutation,
      repromptNow: () => 1_000,
      repromptRandomBytes: (size) => Buffer.alloc(size, 1)
    })
    return {
      event,
      secondEvent,
      useSecondSender: () => {
        currentWindow = { isDestroyed: () => false, webContents: secondWebContents }
      },
      vault,
      setGeneration: (next) => {
        generation = next
      },
      setTargetType: (type) => {
        targetType = type
      },
      reads: () => reads,
      beforeLock,
      afterMutation
    }
  }

  it('reads the clipboard once and never returns imported private material to the renderer', async () => {
    const { event, reads, vault, afterMutation } = harness()
    const begin = electronMock.handlers.get(IPC_CHANNELS.sshKeyBeginImport)!
    const submit = electronMock.handlers.get(IPC_CHANNELS.sshKeySubmitImportPassphrase)!
    const create = electronMock.handlers.get(IPC_CHANNELS.sshKeyCreateImported)!

    await expect(
      begin(
        {
          ...(event as Record<string, unknown>),
          senderFrame: { url: 'https://untrusted.example.invalid' }
        },
        undefined
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(reads()).toBe(0)

    const awaiting = (await begin(event, undefined)) as { status: string; token: string }
    expect(reads()).toBe(1)
    expect(awaiting).toMatchObject({ status: 'awaitingPassphrase' })
    expect(awaiting).not.toHaveProperty('privateKey')

    await expect(
      submit(event, { token: awaiting.token, passphrase: 'incorrect passphrase' })
    ).resolves.toEqual({ status: 'error', code: 'WrongPassword' })
    const ready = (await submit(event, {
      token: awaiting.token,
      passphrase: 'correct passphrase'
    })) as { status: string; token: string; publicKey: string; fingerprint: string }
    expect(ready).toMatchObject({
      status: 'ready',
      publicKey: 'ssh-ed25519 public-key',
      fingerprint: 'SHA256:main-process-fingerprint'
    })
    expect(ready).not.toHaveProperty('privateKey')

    const created = await create(event, {
      importToken: ready.token,
      name: 'Imported SSH key',
      type: 'login',
      privateKey: 'renderer-controlled-private-key',
      publicKey: 'renderer-controlled-public-key',
      fingerprint: 'renderer-controlled-fingerprint'
    })
    expect(vault.createLogin).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'sshKey',
        privateKey: 'main-process-private-key',
        publicKey: 'ssh-ed25519 public-key',
        fingerprint: 'SHA256:main-process-fingerprint'
      })
    )
    expect(created).not.toHaveProperty('privateKey')
    expect(afterMutation).toHaveBeenCalledTimes(1)
    await expect(create(event, { importToken: ready.token, name: 'Again' })).rejects.toThrow(
      'BEARWARDEN:INVALID_INPUT'
    )
  })

  it('strictly validates passphrases and binds sessions to the trusted sender and vault generation', async () => {
    const { event, secondEvent, useSecondSender, setGeneration } = harness()
    const begin = electronMock.handlers.get(IPC_CHANNELS.sshKeyBeginImport)!
    const submit = electronMock.handlers.get(IPC_CHANNELS.sshKeySubmitImportPassphrase)!
    const awaiting = (await begin(event, undefined)) as { token: string }

    await expect(submit(event, { token: awaiting.token, passphrase: '' })).rejects.toThrow(
      'BEARWARDEN:INVALID_INPUT'
    )
    useSecondSender()
    await expect(
      submit(secondEvent, { token: awaiting.token, passphrase: 'correct passphrase' })
    ).resolves.toEqual({ status: 'error', code: 'SessionUnavailable' })

    const next = (await begin(secondEvent, undefined)) as { token: string }
    setGeneration(10)
    await expect(
      submit(secondEvent, { token: next.token, passphrase: 'correct passphrase' })
    ).resolves.toEqual({ status: 'error', code: 'SessionUnavailable' })
  })

  it('clears import sessions before locking and keeps update reprompt authorization and mutation sync', async () => {
    const { event, vault, beforeLock, afterMutation } = harness()
    const begin = electronMock.handlers.get(IPC_CHANNELS.sshKeyBeginImport)!
    const submit = electronMock.handlers.get(IPC_CHANNELS.sshKeySubmitImportPassphrase)!
    const lock = electronMock.handlers.get(IPC_CHANNELS.vaultLock)!
    const authorize = electronMock.handlers.get(IPC_CHANNELS.loginAuthorize)!
    const update = electronMock.handlers.get(IPC_CHANNELS.sshKeyUpdateImported)!

    const awaiting = (await begin(event, undefined)) as { token: string }
    const ready = (await submit(event, {
      token: awaiting.token,
      passphrase: 'correct passphrase'
    })) as { token: string }
    const authorization = (await authorize(event, {
      id: '70000000-0000-4000-8000-000000000001',
      masterPassword: 'correct horse battery staple'
    })) as { token: string }
    await expect(
      update(event, {
        id: '70000000-0000-4000-8000-000000000001',
        importToken: ready.token,
        authorizationToken: authorization.token,
        expectedUpdatedAt: '2026-07-16T00:00:00.000Z'
      })
    ).resolves.toMatchObject({ type: 'sshKey' })
    expect(vault.updateLogin).toHaveBeenCalledWith(
      expect.objectContaining({
        privateKey: 'main-process-private-key',
        publicKey: 'ssh-ed25519 public-key',
        fingerprint: 'SHA256:main-process-fingerprint'
      })
    )
    expect(afterMutation).toHaveBeenCalledTimes(1)

    const secondAwaiting = (await begin(event, undefined)) as { token: string }
    const secondReady = (await submit(event, {
      token: secondAwaiting.token,
      passphrase: 'correct passphrase'
    })) as { token: string }
    await lock(event, undefined)
    expect(beforeLock).toHaveBeenCalledTimes(1)
    const authorizationAfterLock = (await authorize(event, {
      id: '70000000-0000-4000-8000-000000000001',
      masterPassword: 'correct horse battery staple'
    })) as { token: string }
    await expect(
      update(event, {
        id: '70000000-0000-4000-8000-000000000001',
        importToken: secondReady.token,
        authorizationToken: authorizationAfterLock.token,
        expectedUpdatedAt: '2026-07-16T00:00:00.000Z'
      })
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(vault.updateLogin).toHaveBeenCalledTimes(1)
    expect(afterMutation).toHaveBeenCalledTimes(1)
  })

  it('rejects a non-SSH update before consuming the imported token', async () => {
    const { event, setTargetType, afterMutation } = harness()
    const begin = electronMock.handlers.get(IPC_CHANNELS.sshKeyBeginImport)!
    const submit = electronMock.handlers.get(IPC_CHANNELS.sshKeySubmitImportPassphrase)!
    const authorize = electronMock.handlers.get(IPC_CHANNELS.loginAuthorize)!
    const update = electronMock.handlers.get(IPC_CHANNELS.sshKeyUpdateImported)!
    const id = '70000000-0000-4000-8000-000000000001'
    const awaiting = (await begin(event, undefined)) as { token: string }
    const ready = (await submit(event, {
      token: awaiting.token,
      passphrase: 'correct passphrase'
    })) as { token: string }
    const authorization = (await authorize(event, {
      id,
      masterPassword: 'correct horse battery staple'
    })) as { token: string }

    setTargetType('login')
    await expect(
      update(event, { id, importToken: ready.token, authorizationToken: authorization.token })
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(afterMutation).not.toHaveBeenCalled()

    setTargetType('sshKey')
    await expect(
      update(event, { id, importToken: ready.token, authorizationToken: authorization.token })
    ).resolves.toMatchObject({ type: 'sshKey' })
    expect(afterMutation).toHaveBeenCalledTimes(1)
  })
})
