import { beforeEach, describe, expect, it, vi } from 'vitest'

const electronMock = vi.hoisted(() => ({
  handle: vi.fn(),
  removeHandler: vi.fn()
}))
const executeApplicationMenuCommand = vi.hoisted(() => vi.fn())

vi.mock('electron', () => ({
  ipcMain: { handle: electronMock.handle, removeHandler: electronMock.removeHandler }
}))
vi.mock('./application-menu', () => ({ executeApplicationMenuCommand }))

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

  it('executes a command only for the current main renderer', async () => {
    const mainFrame = { url: 'file:///index.html' }
    const sender = { id: 1, mainFrame, getURL: () => mainFrame.url }
    const window = { isDestroyed: () => false, webContents: sender }
    const dispose = registerApplicationMenuIpc({ getMainWindow: () => window as never })
    expect(electronMock.handle).toHaveBeenCalledWith(
      'application-menu:execute',
      expect.any(Function)
    )
    const handler = electronMock.handle.mock.calls[0]?.[1] as (
      event: { sender: unknown; senderFrame?: unknown },
      command: unknown
    ) => Promise<void>

    await handler({ sender, senderFrame: mainFrame }, 'copy')

    expect(executeApplicationMenuCommand).toHaveBeenCalledWith(window, 'copy')
    await expect(handler({ sender: { id: 2 } }, 'copy')).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    await expect(handler({ sender, senderFrame: { url: mainFrame.url } }, 'copy')).rejects.toThrow(
      'BEARWARDEN:INVALID_INPUT'
    )
    await expect(handler({ sender, senderFrame: mainFrame }, 'open-devtools')).rejects.toThrow(
      'BEARWARDEN:INVALID_INPUT'
    )
    expect(executeApplicationMenuCommand).toHaveBeenCalledOnce()

    dispose()
    dispose()
    expect(electronMock.removeHandler).toHaveBeenCalledOnce()
    expect(electronMock.removeHandler).toHaveBeenCalledWith('application-menu:execute')
  })
})
