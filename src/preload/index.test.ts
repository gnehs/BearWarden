import { beforeAll, describe, expect, it, vi } from 'vitest'

const electronMock = vi.hoisted(() => {
  let exposed: unknown
  return {
    invoke: vi.fn(async () => undefined),
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
    on: vi.fn(),
    removeListener: vi.fn()
  }
}))

import { IPC_CHANNELS, type BearWardenAPI } from '../shared/vault-contract'

beforeAll(async () => {
  Object.defineProperty(process, 'contextIsolated', { configurable: true, value: true })
  await import('./index')
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
