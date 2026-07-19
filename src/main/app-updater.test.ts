import { beforeEach, describe, expect, it, vi } from 'vitest'

const harness = vi.hoisted(() => {
  const ipcHandlers = new Map<string, (event: { sender: unknown }) => unknown>()
  const updaterListeners = new Map<string, (...args: never[]) => void>()
  const updater = {
    autoDownload: true,
    autoInstallOnAppQuit: false,
    on: vi.fn((event: string, listener: (...args: never[]) => void) => {
      updaterListeners.set(event, listener)
      return updater
    }),
    removeListener: vi.fn((event: string, listener: (...args: never[]) => void) => {
      if (updaterListeners.get(event) === listener) updaterListeners.delete(event)
      return updater
    }),
    checkForUpdates: vi.fn(async () => null),
    downloadUpdate: vi.fn(async () => ['/private/update.pkg']),
    quitAndInstall: vi.fn()
  }

  return {
    ipcHandlers,
    updaterListeners,
    updater,
    app: { isPackaged: true, getVersion: vi.fn(() => '0.1.1') },
    handle: vi.fn((channel: string, handler: (event: { sender: unknown }) => unknown) => {
      ipcHandlers.set(channel, handler)
    }),
    removeHandler: vi.fn((channel: string) => ipcHandlers.delete(channel))
  }
})

vi.mock('electron', () => ({
  app: harness.app,
  ipcMain: { handle: harness.handle, removeHandler: harness.removeHandler },
  shell: { openExternal: vi.fn() }
}))

vi.mock('electron-updater', () => ({
  default: { autoUpdater: harness.updater }
}))

import { IPC_CHANNELS, IPC_EVENTS } from '../shared/vault-contract'
import { AppUpdaterController } from './app-updater'

function emitUpdaterEvent(event: string, value?: unknown): void {
  const listener = harness.updaterListeners.get(event)
  if (!listener) throw new Error(`Missing updater listener: ${event}`)
  listener(value as never)
}

function createWindow(): {
  window: {
    isDestroyed: ReturnType<typeof vi.fn>
    webContents: {
      isDestroyed: ReturnType<typeof vi.fn>
      send: ReturnType<typeof vi.fn>
    }
  }
  sender: unknown
} {
  const webContents = { isDestroyed: vi.fn(() => false), send: vi.fn() }
  return {
    window: { isDestroyed: vi.fn(() => false), webContents },
    sender: webContents
  }
}

describe('AppUpdaterController', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    harness.ipcHandlers.clear()
    harness.updaterListeners.clear()
    harness.updater.autoDownload = true
    harness.updater.autoInstallOnAppQuit = false
    harness.updater.checkForUpdates.mockResolvedValue(null)
    harness.updater.downloadUpdate.mockResolvedValue(['/private/update.pkg'])
  })

  it('stays disabled outside packaged applications without activating electron-updater', async () => {
    const controller = new AppUpdaterController({
      updater: harness.updater as never,
      isPackaged: false,
      currentVersion: '0.1.1'
    })
    const { window, sender } = createWindow()
    controller.attachWindow(window as never)

    const check = harness.ipcHandlers.get(IPC_CHANNELS.appUpdateCheck)
    expect(await check?.({ sender })).toEqual({
      status: 'disabled',
      currentVersion: '0.1.1',
      availableVersion: null,
      progress: null,
      canAutoInstall: false
    })
    expect(harness.updater.on).not.toHaveBeenCalled()
    expect(harness.updater.checkForUpdates).not.toHaveBeenCalled()
    expect(window.webContents.send).toHaveBeenCalledWith(IPC_EVENTS.appUpdateStateChanged, {
      status: 'disabled',
      currentVersion: '0.1.1',
      availableVersion: null,
      progress: null,
      canAutoInstall: false
    })
  })

  it('configures manual download and emits only renderer-safe state fields', async () => {
    const controller = new AppUpdaterController({
      updater: harness.updater as never,
      isPackaged: true,
      currentVersion: '0.1.1',
      platform: 'win32'
    })
    const { window } = createWindow()
    controller.attachWindow(window as never)

    expect(harness.updater.autoDownload).toBe(false)
    expect(harness.updater.autoInstallOnAppQuit).toBe(true)

    emitUpdaterEvent('update-available', {
      version: '0.2.0',
      files: [{ url: 'https://updates.example.invalid/private.pkg', sha512: 'secret' }],
      releaseNotes: 'untrusted notes'
    })
    emitUpdaterEvent('download-progress', {
      percent: 42.5,
      transferred: 425,
      total: 1_000,
      bytesPerSecond: 10,
      delta: 5
    })
    emitUpdaterEvent('update-downloaded', {
      version: '0.2.0',
      downloadedFile: '/private/update.pkg'
    })

    expect(controller.state).toEqual({
      status: 'downloaded',
      currentVersion: '0.1.1',
      availableVersion: '0.2.0',
      progress: 100,
      canAutoInstall: true
    })
    for (const [, state] of window.webContents.send.mock.calls) {
      expect(Object.keys(state as object).sort()).toEqual([
        'availableVersion',
        'canAutoInstall',
        'currentVersion',
        'progress',
        'status'
      ])
      expect(JSON.stringify(state)).not.toContain('updates.example.invalid')
      expect(JSON.stringify(state)).not.toContain('/private/update.pkg')
      expect(JSON.stringify(state)).not.toContain('secret')
    }
  })

  it('checks, downloads, and installs through authenticated no-payload IPC commands', async () => {
    const controller = new AppUpdaterController({
      updater: harness.updater as never,
      isPackaged: true,
      currentVersion: '0.1.1',
      platform: 'win32'
    })
    const { window, sender } = createWindow()
    controller.attachWindow(window as never)

    const check = harness.ipcHandlers.get(IPC_CHANNELS.appUpdateCheck)
    const download = harness.ipcHandlers.get(IPC_CHANNELS.appUpdateDownload)
    const install = harness.ipcHandlers.get(IPC_CHANNELS.appUpdateInstall)
    await check?.({ sender })
    expect(harness.updater.checkForUpdates).toHaveBeenCalledOnce()

    emitUpdaterEvent('update-available', { version: '0.2.0' })
    await download?.({ sender })
    expect(harness.updater.downloadUpdate).toHaveBeenCalledOnce()
    expect(controller.state.status).toBe('downloading')

    emitUpdaterEvent('update-downloaded', {
      version: '0.2.0',
      downloadedFile: '/private/update.pkg'
    })
    await install?.({ sender })
    expect(harness.updater.quitAndInstall).toHaveBeenCalledOnce()
  })

  it('rejects IPC from any renderer other than the attached window', async () => {
    const controller = new AppUpdaterController({
      updater: harness.updater as never,
      isPackaged: true,
      currentVersion: '0.1.1',
      platform: 'win32'
    })
    const { window } = createWindow()
    controller.attachWindow(window as never)
    const check = harness.ipcHandlers.get(IPC_CHANNELS.appUpdateCheck)

    expect(() => check?.({ sender: { id: 999 } })).toThrow('Invalid app update request')
    expect(harness.updater.checkForUpdates).not.toHaveBeenCalled()
  })

  it('contains raw updater errors and removes handlers and listeners on disposal', async () => {
    const controller = new AppUpdaterController({
      updater: harness.updater as never,
      isPackaged: true,
      currentVersion: '0.1.1',
      platform: 'win32'
    })
    const { window, sender } = createWindow()
    controller.attachWindow(window as never)
    harness.updater.checkForUpdates.mockRejectedValueOnce(
      new Error('token=private https://updates.example.invalid/feed.yml')
    )

    const check = harness.ipcHandlers.get(IPC_CHANNELS.appUpdateCheck)
    expect(await check?.({ sender })).toEqual({
      status: 'error',
      currentVersion: '0.1.1',
      availableVersion: null,
      progress: null,
      canAutoInstall: true
    })
    expect(JSON.stringify(window.webContents.send.mock.calls)).not.toContain('token=private')

    controller.dispose()
    expect(harness.removeHandler).toHaveBeenCalledTimes(4)
    expect(harness.updater.removeListener).toHaveBeenCalledTimes(6)
  })

  it('checks on macOS but refuses download and install, and opens only the fixed release page', async () => {
    const openExternal = vi.fn(async () => undefined)
    const controller = new AppUpdaterController({
      updater: harness.updater as never,
      isPackaged: true,
      currentVersion: '0.1.1',
      platform: 'darwin',
      openExternal
    })
    const { window, sender } = createWindow()
    controller.attachWindow(window as never)
    const check = harness.ipcHandlers.get(IPC_CHANNELS.appUpdateCheck)
    const download = harness.ipcHandlers.get(IPC_CHANNELS.appUpdateDownload)
    const install = harness.ipcHandlers.get(IPC_CHANNELS.appUpdateInstall)
    const openReleasePage = harness.ipcHandlers.get(IPC_CHANNELS.appUpdateOpenReleasePage)

    await check?.({ sender })
    expect(harness.updater.checkForUpdates).toHaveBeenCalledOnce()
    expect(controller.state.canAutoInstall).toBe(false)
    expect(harness.updater.autoDownload).toBe(false)
    expect(harness.updater.autoInstallOnAppQuit).toBe(false)

    emitUpdaterEvent('update-available', { version: '0.2.0' })
    await expect(download?.({ sender })).rejects.toThrow(
      'Automatic updates are unavailable on this platform'
    )
    expect(() => install?.({ sender })).toThrow(
      'Automatic updates are unavailable on this platform'
    )
    expect(harness.updater.downloadUpdate).not.toHaveBeenCalled()
    expect(harness.updater.quitAndInstall).not.toHaveBeenCalled()

    await openReleasePage?.({ sender })
    expect(openExternal).toHaveBeenCalledWith('https://github.com/gnehs/BearWarden/releases/latest')
  })

  it('keeps non-AppImage Linux packages on the manual release flow', () => {
    const controller = new AppUpdaterController({
      updater: harness.updater as never,
      isPackaged: true,
      currentVersion: '0.1.1',
      platform: 'linux',
      isAppImage: false
    })

    expect(controller.state.canAutoInstall).toBe(false)
    expect(harness.updater.autoInstallOnAppQuit).toBe(false)
  })
})
