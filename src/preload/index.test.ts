import { beforeAll, describe, expect, it, vi } from 'vitest'

const electronMock = vi.hoisted(() => {
  let exposed: unknown
  return {
    invoke: vi.fn(async () => undefined),
    on: vi.fn(),
    removeListener: vi.fn(),
    exposeInMainWorld: vi.fn((_name: string, value: unknown) => {
      exposed = value
    }),
    exposed: () => exposed
  }
})

vi.mock('electron', () => ({
  contextBridge: { exposeInMainWorld: electronMock.exposeInMainWorld },
  ipcRenderer: {
    invoke: electronMock.invoke,
    send: vi.fn(),
    on: electronMock.on,
    removeListener: electronMock.removeListener
  }
}))

import { IPC_CHANNELS, IPC_EVENTS, type BearWardenAPI } from '../shared/vault-contract'

beforeAll(async () => {
  Object.defineProperty(process, 'contextIsolated', { configurable: true, value: true })
  await import('./index')
})

describe('preload AutoFill settings API', () => {
  it('exposes narrow status and explicit permission-request calls', async () => {
    electronMock.invoke.mockClear()
    const api = electronMock.exposed() as BearWardenAPI

    await api.autofill.status()
    await api.autofill.requestAccessibility()

    expect(electronMock.invoke.mock.calls).toEqual([
      [IPC_CHANNELS.autofillStatus],
      [IPC_CHANNELS.autofillRequestAccessibility]
    ])
    electronMock.invoke.mockClear()
  })
})

describe('preload account API', () => {
  it('exposes the typed namespace with only narrow account IPC payloads', async () => {
    const api: BearWardenAPI = electronMock.exposed() as BearWardenAPI
    const accountId = '22222222-2222-4222-8222-222222222222'

    const accountIds = [accountId, '33333333-3333-4333-8333-333333333333']

    expect(Object.keys(api.accounts)).toEqual(['status', 'add', 'switch', 'reorder', 'remove'])
    await api.accounts.status()
    await api.accounts.add()
    await api.accounts.switch(accountId)
    await api.accounts.reorder(accountIds, 7)
    await api.accounts.remove(accountId, true)

    expect(electronMock.invoke.mock.calls).toEqual([
      [IPC_CHANNELS.accountStatus],
      [IPC_CHANNELS.accountAdd],
      [IPC_CHANNELS.accountSwitch, { accountId }],
      [IPC_CHANNELS.accountReorder, { accountIds, expectedRevision: 7 }],
      [IPC_CHANNELS.accountRemove, { accountId, confirm: true }]
    ])
  })

  it('exposes only data-only profile mutation requests', async () => {
    electronMock.invoke.mockClear()
    const api: BearWardenAPI = electronMock.exposed() as BearWardenAPI
    const nameRequest = { name: '', expectedName: 'Before' }
    const avatarRequest = { avatarColor: '#AABBCC', expectedAvatarColor: null }

    await api.accountSecurity.updateName(nameRequest)
    await api.accountSecurity.updateAvatar(avatarRequest)

    expect(electronMock.invoke.mock.calls).toEqual([
      [IPC_CHANNELS.accountSecurityUpdateName, nameRequest],
      [IPC_CHANNELS.accountSecurityUpdateAvatar, avatarRequest]
    ])
  })

  it('forwards only the explicit session deauthorization request', async () => {
    electronMock.invoke.mockClear()
    const api: BearWardenAPI = electronMock.exposed() as BearWardenAPI
    const request = {
      masterPassword: 'test-master-password',
      confirmation: '取消所有工作階段' as const,
      confirm: true as const
    }

    await api.accountSecurity.deauthorizeSessions(request)

    expect(electronMock.invoke).toHaveBeenCalledWith(
      IPC_CHANNELS.accountDeauthorizeSessions,
      request
    )
  })

  it('exposes short-lived login approval operations and a removable event listener', async () => {
    electronMock.invoke.mockClear()
    electronMock.on.mockClear()
    electronMock.removeListener.mockClear()
    const api: BearWardenAPI = electronMock.exposed() as BearWardenAPI
    const response = {
      token: '22222222-2222-4222-8222-222222222222',
      fingerprint: 'alpha-bravo-charlie-delta-echo-foxtrot',
      approved: false
    }
    const listener = vi.fn()

    await api.accountSecurity.pendingLoginApprovals()
    await api.accountSecurity.respondLoginApproval(response)
    const unsubscribe = api.accountSecurity.onLoginApprovalRequested(listener)

    expect(electronMock.invoke.mock.calls).toEqual([
      [IPC_CHANNELS.accountPendingLoginApprovals],
      [IPC_CHANNELS.accountRespondLoginApproval, response]
    ])
    expect(electronMock.on).toHaveBeenCalledWith(
      IPC_EVENTS.loginApprovalRequested,
      expect.any(Function)
    )
    unsubscribe()
    expect(electronMock.removeListener).toHaveBeenCalledWith(
      IPC_EVENTS.loginApprovalRequested,
      expect.any(Function)
    )
  })

  it('exposes only the narrow account WebAuthn enrollment operations', async () => {
    electronMock.invoke.mockClear()
    const api: BearWardenAPI = electronMock.exposed() as BearWardenAPI
    const listRequest = { masterPassword: 'test-master-password' }
    const enrollRequest = { masterPassword: 'test-master-password', name: 'USB key' }
    const removeRequest = { id: 1, masterPassword: 'test-master-password', confirm: true as const }

    await api.accountSecurity.listWebAuthnKeys(listRequest)
    await api.accountSecurity.enrollWebAuthnKey(enrollRequest)
    await api.accountSecurity.removeWebAuthnKey(removeRequest)

    expect(electronMock.invoke.mock.calls).toEqual([
      [IPC_CHANNELS.accountSecurityWebAuthnKeys, listRequest],
      [IPC_CHANNELS.accountSecurityEnrollWebAuthnKey, enrollRequest],
      [IPC_CHANNELS.accountSecurityRemoveWebAuthnKey, removeRequest]
    ])
    expect(Object.keys(api.accountSecurity)).toContain('listWebAuthnKeys')
    expect(Object.keys(api.accountSecurity)).toContain('enrollWebAuthnKey')
    expect(Object.keys(api.accountSecurity)).toContain('removeWebAuthnKey')
  })
})

describe('preload pending import API', () => {
  it('exposes one narrow request-response method', async () => {
    electronMock.invoke.mockClear()
    const api: BearWardenAPI = electronMock.exposed() as BearWardenAPI
    const request = { masterPassword: 'test-master-password', confirmRetry: true as const }

    await api.sync.resolvePendingImport(request)

    expect(electronMock.invoke).toHaveBeenCalledWith(IPC_CHANNELS.syncResolvePendingImport, request)
    expect(Object.keys(api.sync)).toEqual([
      'status',
      'connect',
      'unlock',
      'now',
      'resolvePendingImport',
      'purgePersonalVault',
      'disconnect',
      'onChanged'
    ])
  })
})

describe('preload visible detail prefetch API', () => {
  it('forwards one bounded data-only request through its dedicated channel', async () => {
    electronMock.invoke.mockClear()
    const api: BearWardenAPI = electronMock.exposed() as BearWardenAPI
    const request = { ids: ['10000000-0000-4000-8000-000000000001'] }

    await api.logins.prefetch(request)

    expect(electronMock.invoke).toHaveBeenCalledWith(IPC_CHANNELS.loginPrefetch, request)
  })
})

describe('preload password history API', () => {
  it('forwards only narrow metadata, reveal, copy, and restore requests', async () => {
    electronMock.invoke.mockClear()
    const api: BearWardenAPI = electronMock.exposed() as BearWardenAPI
    const id = '10000000-0000-4000-8000-000000000001'
    const locator = {
      id,
      index: 0,
      lastUsedDate: '2026-07-14T00:00:00.000Z',
      expectedUpdatedAt: '2026-07-16T00:00:00.000Z'
    }

    await api.logins.getPasswordHistory({ id })
    await api.logins.revealPasswordHistory(locator)
    await api.logins.copyPasswordHistory(locator)
    await api.logins.restorePasswordHistory(locator)

    expect(electronMock.invoke.mock.calls).toEqual([
      [IPC_CHANNELS.loginGetPasswordHistory, { id }],
      [IPC_CHANNELS.loginRevealPasswordHistory, locator],
      [IPC_CHANNELS.loginCopyPasswordHistory, locator],
      [IPC_CHANNELS.loginRestorePasswordHistory, locator]
    ])
  })
})

describe('preload portability API', () => {
  it('forwards only the passwordless Bitwarden CSV request object', async () => {
    electronMock.invoke.mockClear()
    const api: BearWardenAPI = electronMock.exposed() as BearWardenAPI
    const request = {
      masterPassword: 'test-master-password',
      format: 'bitwarden-csv' as const
    }

    await api.portability.export(request)

    expect(electronMock.invoke).toHaveBeenCalledWith(IPC_CHANNELS.vaultExport, request)
  })
})

describe('preload personal vault purge API', () => {
  it('passes only the typed request through its dedicated channel', async () => {
    electronMock.invoke.mockClear()
    const api: BearWardenAPI = electronMock.exposed() as BearWardenAPI
    const request = {
      masterPassword: 'test-master-password',
      confirmation: 'PURGE' as const,
      confirmPurge: true as const
    }

    await api.sync.purgePersonalVault(request)

    expect(electronMock.invoke).toHaveBeenCalledWith(IPC_CHANNELS.syncPurgePersonalVault, request)
  })
})

describe('preload application menu API', () => {
  it('forwards only a typed application-menu command', async () => {
    electronMock.invoke.mockClear()
    const api: BearWardenAPI = electronMock.exposed() as BearWardenAPI

    await api.applicationMenu.execute('toggle-full-screen')

    expect(Object.keys(api.applicationMenu)).toEqual(['execute'])
    expect(electronMock.invoke).toHaveBeenCalledWith(
      IPC_CHANNELS.applicationMenuExecute,
      'toggle-full-screen'
    )
  })
})

describe('preload updater API', () => {
  it('exposes only narrow commands and a removable renderer-safe state listener', async () => {
    electronMock.invoke.mockClear()
    electronMock.on.mockClear()
    electronMock.removeListener.mockClear()
    const api: BearWardenAPI = electronMock.exposed() as BearWardenAPI
    const listener = vi.fn()

    expect(Object.keys(api.updater)).toEqual([
      'state',
      'check',
      'download',
      'install',
      'openReleasePage',
      'openRepositoryPage',
      'onStateChanged'
    ])
    await api.updater.state()
    await api.updater.check()
    await api.updater.download()
    await api.updater.install()
    await api.updater.openReleasePage()
    await api.updater.openRepositoryPage()
    const unsubscribe = api.updater.onStateChanged(listener)

    expect(electronMock.invoke.mock.calls).toEqual([
      [IPC_CHANNELS.appUpdateState],
      [IPC_CHANNELS.appUpdateCheck],
      [IPC_CHANNELS.appUpdateDownload],
      [IPC_CHANNELS.appUpdateInstall],
      [IPC_CHANNELS.appUpdateOpenReleasePage],
      [IPC_CHANNELS.appUpdateOpenRepositoryPage]
    ])
    expect(electronMock.on).toHaveBeenCalledWith('app-update:state-changed', expect.any(Function))

    const wrappedListener = electronMock.on.mock.calls[0]?.[1] as (
      event: unknown,
      state: unknown
    ) => void
    const state = {
      status: 'downloading',
      currentVersion: '0.1.1',
      availableVersion: '0.2.0',
      progress: 42,
      canAutoInstall: true
    }
    wrappedListener({}, state)
    expect(listener).toHaveBeenCalledWith(state)

    unsubscribe()
    expect(electronMock.removeListener).toHaveBeenCalledWith(
      'app-update:state-changed',
      wrappedListener
    )
  })
})
