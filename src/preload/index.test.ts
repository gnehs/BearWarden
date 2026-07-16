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

    expect(Object.keys(api.accounts)).toEqual(['status', 'add', 'switch'])
    await api.accounts.status()
    await api.accounts.add()
    await api.accounts.switch(accountId)

    expect(electronMock.invoke.mock.calls).toEqual([
      [IPC_CHANNELS.accountStatus],
      [IPC_CHANNELS.accountAdd],
      [IPC_CHANNELS.accountSwitch, { accountId }]
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
