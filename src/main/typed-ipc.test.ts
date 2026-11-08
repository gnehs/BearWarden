import { beforeEach, describe, expect, expectTypeOf, it, vi } from 'vitest'

const electronMock = vi.hoisted(() => ({
  handlers: new Map<string, (event: unknown, input: unknown) => Promise<unknown>>(),
  removeHandler: vi.fn()
}))

vi.mock('electron', () => ({
  ipcMain: {
    handle: vi.fn(
      (channel: string, handler: (event: unknown, input: unknown) => Promise<unknown>) =>
        electronMock.handlers.set(channel, handler)
    ),
    removeHandler: electronMock.removeHandler
  }
}))

import type { IpcRequest, IpcResponse } from '../shared/ipc-api'
import type { VaultStatus } from '../shared/vault-contract'
import { createTrustedIpc, parseNoInput, type IpcInvokeHandler } from './typed-ipc'
import { VaultError } from './vault-errors'

const mainFrame = { url: 'app://bearwarden/index.html' }
const webContents = { id: 7, mainFrame, getURL: () => mainFrame.url }
const trustedEvent = { sender: webContents, senderFrame: mainFrame }
const getMainWindow = (): never => ({ isDestroyed: () => false, webContents }) as never

beforeEach(() => {
  electronMock.handlers.clear()
  electronMock.removeHandler.mockClear()
})

describe('typed IPC contract', () => {
  it('types handlers by channel request and response', () => {
    expectTypeOf<IpcRequest<'vault:status'>>().toEqualTypeOf<void>()
    expectTypeOf<IpcResponse<'vault:status'>>().toEqualTypeOf<VaultStatus>()
    expectTypeOf<IpcRequest<'account:switch'>>().toEqualTypeOf<{ readonly accountId: string }>()

    // @ts-expect-error a vault:status handler must resolve to VaultStatus
    const wrongResponse: IpcInvokeHandler<'vault:status'> = async () => ({ state: 'open' })
    expect(wrongResponse).toBeTypeOf('function')
  })
})

describe('createTrustedIpc', () => {
  it('rejects other senders before parsing and logs only the public code', async () => {
    const recordMainError = vi.fn()
    const parse = vi.fn(parseNoInput)
    const ipc = createTrustedIpc({ getMainWindow, errorLog: { recordMainError } })
    ipc.handle('vault:status', parse, async () => ({ state: 'locked' }) as VaultStatus)

    await expect(
      electronMock.handlers.get('vault:status')!({ sender: {}, senderFrame: mainFrame }, undefined)
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(parse).not.toHaveBeenCalled()
    expect(recordMainError).toHaveBeenCalledWith('ipc-error', expect.any(Error), {
      channel: 'vault:status',
      code: 'INVALID_INPUT'
    })
  })

  it('maps vault errors to their code and every other failure to INTERNAL_ERROR', async () => {
    const ipc = createTrustedIpc({ getMainWindow })
    ipc.handle('vault:status', parseNoInput, async () => {
      throw new VaultError('LOCKED')
    })
    ipc.handle('vault:lock', parseNoInput, async () => {
      throw new Error('/private/path leaked')
    })

    await expect(electronMock.handlers.get('vault:status')!(trustedEvent, {})).rejects.toThrow(
      'BEARWARDEN:INVALID_INPUT'
    )
    await expect(
      electronMock.handlers.get('vault:status')!(trustedEvent, undefined)
    ).rejects.toThrow('BEARWARDEN:LOCKED')
    await expect(electronMock.handlers.get('vault:lock')!(trustedEvent, undefined)).rejects.toThrow(
      /^BEARWARDEN:INTERNAL_ERROR$/
    )
  })

  it('scrubs the raw payload even when parsing rejects it', async () => {
    const ipc = createTrustedIpc({ getMainWindow })
    const handler = vi.fn()
    ipc.handle(
      'vault:setup',
      () => {
        throw new VaultError('INVALID_INPUT')
      },
      handler,
      {
        scrubInput: (input) => {
          ;(input as { masterPassword: string }).masterPassword = ''
        }
      }
    )
    const input = { masterPassword: 'secret', extra: true }

    await expect(electronMock.handlers.get('vault:setup')!(trustedEvent, input)).rejects.toThrow(
      'BEARWARDEN:INVALID_INPUT'
    )
    expect(input.masterPassword).toBe('')
    expect(handler).not.toHaveBeenCalled()
  })

  it('removes each registered handler once', () => {
    const ipc = createTrustedIpc({ getMainWindow })
    ipc.handle('vault:status', parseNoInput, async () => ({ state: 'locked' }) as VaultStatus)
    ipc.handle('vault:lock', parseNoInput, async () => ({ state: 'locked' }) as VaultStatus)

    ipc.dispose()
    ipc.dispose()

    expect(electronMock.removeHandler.mock.calls).toEqual([['vault:status'], ['vault:lock']])
  })
})
