import { beforeEach, describe, expect, it, vi } from 'vitest'

const electronMock = vi.hoisted(() => ({
  handle: vi.fn()
}))
const executeApplicationMenuCommand = vi.hoisted(() => vi.fn())

vi.mock('electron', () => ({
  ipcMain: { handle: electronMock.handle }
}))
vi.mock('./application-menu', () => ({ executeApplicationMenuCommand }))

import { IPC_CHANNELS } from '../shared/vault-contract'
import { isApplicationMenuCommand, registerApplicationMenuIpc } from './application-menu-ipc'

describe('application menu IPC', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('accepts every supported command and rejects arbitrary input', () => {
    expect(isApplicationMenuCommand('copy')).toBe(true)
    expect(isApplicationMenuCommand('copy-selected-password')).toBe(true)
    expect(isApplicationMenuCommand('toggle-developer-tools')).toBe(true)
    expect(isApplicationMenuCommand('toggle-maximize-window')).toBe(true)
    expect(isApplicationMenuCommand('open-devtools')).toBe(false)
    expect(isApplicationMenuCommand({ command: 'copy' })).toBe(false)
  })

  it('executes a command only for the current main renderer', () => {
    const sender = { id: 1 }
    const window = { isDestroyed: () => false, webContents: sender }
    registerApplicationMenuIpc({ getMainWindow: () => window as never })
    expect(electronMock.handle).toHaveBeenCalledWith(
      IPC_CHANNELS.applicationMenuExecute,
      expect.any(Function)
    )
    const handler = electronMock.handle.mock.calls[0]?.[1] as (
      event: { sender: unknown },
      command: unknown
    ) => void

    handler({ sender }, 'copy')

    expect(executeApplicationMenuCommand).toHaveBeenCalledWith(window, 'copy')
    expect(() => handler({ sender: { id: 2 } }, 'copy')).toThrow('Invalid application menu request')
    expect(() => handler({ sender }, 'open-devtools')).toThrow('Invalid application menu request')
  })
})
