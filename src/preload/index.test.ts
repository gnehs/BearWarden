import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

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

let api: BearWardenAPI

beforeAll(async () => {
  Object.defineProperty(process, 'contextIsolated', { configurable: true, value: true })
  await import('./index')
  api = electronMock.exposed() as BearWardenAPI
})

beforeEach(() => {
  electronMock.invoke.mockClear()
  electronMock.on.mockClear()
  electronMock.removeListener.mockClear()
})

const remoteCredentials = {
  serverUrl: 'https://vault.example.invalid',
  email: 'person@example.invalid',
  masterPassword: 'remote password'
}
const deauthorizeRequest = {
  masterPassword: 'test-master-password',
  confirmation: 'deauthorize all sessions' as const,
  confirm: true as const
}
const pendingImportRequest = { masterPassword: 'test-master-password', confirmRetry: true as const }
const prefetchRequest = { ids: ['10000000-0000-4000-8000-000000000001'] }
const csvExportRequest = {
  masterPassword: 'test-master-password',
  format: 'bitwarden-csv' as const
}
const purgeRequest = {
  masterPassword: 'test-master-password',
  confirmation: 'PURGE' as const,
  confirmPurge: true as const
}

describe('preload request forwarding', () => {
  it.each<[string, () => Promise<unknown>, unknown[][]]>([
    [
      'AutoFill status and explicit permission request',
      async () => {
        await api.autofill.status()
        await api.autofill.requestAccessibility()
      },
      [[IPC_CHANNELS.autofillStatus], [IPC_CHANNELS.autofillRequestAccessibility]]
    ],
    [
      'error-log file-manager action',
      () => api.settings.showErrorLog(),
      [[IPC_CHANNELS.settingsShowErrorLog]]
    ],
    [
      'email two-factor code request',
      () => api.sync.sendEmailTwoFactorCode(remoteCredentials),
      [[IPC_CHANNELS.syncSendEmailTwoFactorCode, remoteCredentials]]
    ],
    [
      'new-device OTP resend request',
      () => api.sync.resendNewDeviceOtp(remoteCredentials),
      [[IPC_CHANNELS.syncResendNewDeviceOtp, remoteCredentials]]
    ],
    [
      'session deauthorization request',
      () => api.accountSecurity.deauthorizeSessions(deauthorizeRequest),
      [[IPC_CHANNELS.accountDeauthorizeSessions, deauthorizeRequest]]
    ],
    [
      'pending import resolution request',
      () => api.sync.resolvePendingImport(pendingImportRequest),
      [[IPC_CHANNELS.syncResolvePendingImport, pendingImportRequest]]
    ],
    [
      'bounded visible-detail prefetch request',
      () => api.logins.prefetch(prefetchRequest),
      [[IPC_CHANNELS.loginPrefetch, prefetchRequest]]
    ],
    [
      'passwordless Bitwarden CSV export request',
      () => api.portability.export(csvExportRequest),
      [[IPC_CHANNELS.vaultExport, csvExportRequest]]
    ],
    [
      'personal vault purge request',
      () => api.sync.purgePersonalVault(purgeRequest),
      [[IPC_CHANNELS.syncPurgePersonalVault, purgeRequest]]
    ]
  ])('forwards only the %s through its dedicated channel', async (_label, call, expected) => {
    await call()

    expect(electronMock.invoke.mock.calls).toEqual(expected)
  })
})

describe('preload account API', () => {
  it('exposes the typed namespace with only narrow account IPC payloads', async () => {
    const accountId = '22222222-2222-4222-8222-222222222222'
    const accountIds = [accountId, '33333333-3333-4333-8333-333333333333']

    expect(Object.keys(api.accounts)).toEqual([
      'status',
      'add',
      'switch',
      'rename',
      'reorder',
      'remove'
    ])
    await api.accounts.status()
    await api.accounts.add()
    await api.accounts.switch(accountId)
    await api.accounts.rename(accountId, 'Work', 6)
    await api.accounts.reorder(accountIds, 7)
    await api.accounts.remove(accountId, true)

    expect(electronMock.invoke.mock.calls).toEqual([
      [IPC_CHANNELS.accountStatus],
      [IPC_CHANNELS.accountAdd],
      [IPC_CHANNELS.accountSwitch, { accountId }],
      [IPC_CHANNELS.accountRename, { accountId, displayName: 'Work', expectedRevision: 6 }],
      [IPC_CHANNELS.accountReorder, { accountIds, expectedRevision: 7 }],
      [IPC_CHANNELS.accountRemove, { accountId, confirm: true }]
    ])
  })

  it('exposes only data-only profile mutation requests', async () => {
    const nameRequest = { name: '', expectedName: 'Before' }
    const avatarRequest = { avatarColor: '#AABBCC', expectedAvatarColor: null }

    await api.accountSecurity.updateName(nameRequest)
    await api.accountSecurity.updateAvatar(avatarRequest)

    expect(electronMock.invoke.mock.calls).toEqual([
      [IPC_CHANNELS.accountSecurityUpdateName, nameRequest],
      [IPC_CHANNELS.accountSecurityUpdateAvatar, avatarRequest]
    ])
  })

  it('exposes short-lived login approval operations and a removable event listener', async () => {
    const response = {
      token: '22222222-2222-4222-8222-222222222222',
      fingerprint: 'alpha-bravo-charlie-delta-echo-foxtrot',
      approved: false
    }

    await api.accountSecurity.pendingLoginApprovals()
    await api.accountSecurity.respondLoginApproval(response)
    const unsubscribe = api.accountSecurity.onLoginApprovalRequested(vi.fn())

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
  })
})

describe('preload sync API', () => {
  it('exposes exactly the sync namespace methods', () => {
    expect(Object.keys(api.sync)).toEqual([
      'status',
      'connect',
      'unlock',
      'sendEmailTwoFactorCode',
      'resendNewDeviceOtp',
      'now',
      'resolvePendingImport',
      'purgePersonalVault',
      'disconnect',
      'onChanged'
    ])
  })
})

describe('preload shared login read API', () => {
  it('forwards read-only shared actions through dedicated channels', async () => {
    const id = '80000000-0000-4000-8000-000000000001'
    const fieldRequest = { id, field: 'password' as const }
    const customFieldRequest = {
      id,
      expectedUpdatedAt: '2026-07-16T00:00:00.000Z',
      source: { index: 0, name: 'PIN', type: 'hidden' as const, linkedId: null }
    }
    const uriRequest = { id, uriIndex: 1 }
    const editorRequest = { id, expectedUpdatedAt: '2026-07-16T00:00:00.000Z' }
    const updateRequest = { ...editorRequest, name: 'Updated shared item' }

    await api.sharedLogins.update(updateRequest)
    await api.sharedLogins.revealEditorSecrets(editorRequest)
    await api.sharedLogins.revealSecret(fieldRequest)
    await api.sharedLogins.copyField(fieldRequest)
    await api.sharedLogins.revealCustomField(customFieldRequest)
    await api.sharedLogins.copyCustomField(customFieldRequest)
    await api.sharedLogins.getTotp({ id })
    await api.sharedLogins.copyTotp({ id })
    await api.sharedLogins.openUri(uriRequest)

    expect(electronMock.invoke.mock.calls).toEqual([
      [IPC_CHANNELS.sharedLoginUpdate, updateRequest],
      [IPC_CHANNELS.sharedLoginRevealEditorSecrets, editorRequest],
      [IPC_CHANNELS.sharedLoginRevealSecret, fieldRequest],
      [IPC_CHANNELS.sharedLoginCopyField, fieldRequest],
      [IPC_CHANNELS.sharedLoginRevealCustomField, customFieldRequest],
      [IPC_CHANNELS.sharedLoginCopyCustomField, customFieldRequest],
      [IPC_CHANNELS.sharedLoginGetTotp, { id }],
      [IPC_CHANNELS.sharedLoginCopyTotp, { id }],
      [IPC_CHANNELS.sharedLoginOpenUri, uriRequest]
    ])
  })
})

describe('preload password history API', () => {
  it('forwards only narrow metadata, reveal, copy, and restore requests', async () => {
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

describe('preload application menu API', () => {
  it('forwards typed application-menu commands and exposes a removable copy listener', async () => {
    const listener = vi.fn()

    await api.applicationMenu.execute('toggle-full-screen')
    const unsubscribe = api.applicationMenu.onCopySelectedItem(listener)
    const wrapped = electronMock.on.mock.calls.at(-1)?.[1] as (
      event: unknown,
      command: unknown
    ) => void
    wrapped({}, 'password')
    unsubscribe()

    expect(Object.keys(api.applicationMenu)).toEqual(['execute', 'onCopySelectedItem'])
    expect(electronMock.invoke).toHaveBeenCalledWith(
      IPC_CHANNELS.applicationMenuExecute,
      'toggle-full-screen'
    )
    expect(electronMock.on).toHaveBeenCalledWith(
      IPC_EVENTS.applicationMenuCopySelectedItem,
      expect.any(Function)
    )
    expect(listener).toHaveBeenCalledWith('password')
    expect(electronMock.removeListener).toHaveBeenCalledWith(
      IPC_EVENTS.applicationMenuCopySelectedItem,
      wrapped
    )
  })
})

describe('preload updater API', () => {
  it('exposes only narrow commands and a removable renderer-safe state listener', async () => {
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
      canAutoInstall: true,
      manualUpdateSource: 'github'
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
