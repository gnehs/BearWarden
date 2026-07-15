import { createHash, timingSafeEqual } from 'node:crypto'
import { join } from 'node:path'
import { app, BrowserWindow, clipboard, ipcMain, powerMonitor, session, shell } from 'electron'
import { electronApp, is } from '@electron-toolkit/utils'
import { IPC_CHANNELS, IPC_EVENTS, type SyncStatus } from '../shared/vault-contract'
import { BitwardenDirectClient } from './bitwarden-direct'
import { AutoSyncCoordinator } from './auto-sync-coordinator'
import { AppSettingsService } from './app-settings'
import { EncryptedVaultStore } from './encrypted-vault-store'
import { FocusTouchIdUnlockController } from './focus-touch-id-unlock'
import { installApplicationMenu } from './application-menu'
import { registerVaultIpc } from './vault-ipc'
import { VaultService } from './vault-service'
import icon from '../../resources/icon.png?asset'

const hasSingleInstanceLock = app.requestSingleInstanceLock()
if (!hasSingleInstanceLock) app.quit()
app.enableSandbox()

let mainWindow: BrowserWindow | null = null
let vault: VaultService | null = null
let settings: AppSettingsService | null = null
let autoSync: AutoSyncCoordinator | null = null
let contentProtectionEnabled = true
let vaultLockGeneration = 0
let rendererHandlesLockRequests = false

class SensitiveClipboard {
  private fingerprint: Buffer | null = null
  private clearTimer: NodeJS.Timeout | null = null
  private clearDelayMs = 30_000

  setClearDelay(seconds: 0 | 15 | 30 | 60 | 120): void {
    this.clearDelayMs = seconds * 1_000
    this.clearTimerIfNeeded()
    if (this.fingerprint && this.clearDelayMs > 0) {
      this.scheduleClear()
    }
  }

  write(text: string): void {
    this.clearTimerIfNeeded()
    this.fingerprint?.fill(0)
    clipboard.writeText(text)
    this.fingerprint = this.digest(text)
    this.scheduleClear()
  }

  clearIfOwned(): void {
    this.clearTimerIfNeeded()
    const expected = this.fingerprint
    this.fingerprint = null
    if (!expected) return

    let current: Buffer | null = null
    try {
      current = this.digest(clipboard.readText())
      if (timingSafeEqual(expected, current)) clipboard.clear()
    } finally {
      expected.fill(0)
      current?.fill(0)
    }
  }

  private clearTimerIfNeeded(): void {
    if (this.clearTimer) clearTimeout(this.clearTimer)
    this.clearTimer = null
  }

  private scheduleClear(): void {
    if (this.clearDelayMs === 0 || !this.fingerprint) return
    this.clearTimer = setTimeout(() => this.clearIfOwned(), this.clearDelayMs)
    this.clearTimer.unref()
  }

  private digest(value: string): Buffer {
    return createHash('sha256').update(value, 'utf8').digest()
  }
}

const sensitiveClipboard = new SensitiveClipboard()
const focusTouchIdUnlockControllers = new WeakMap<BrowserWindow, FocusTouchIdUnlockController>()

function parseAllowedExternalUrl(value: string): URL | null {
  try {
    const url = new URL(value)
    return url.protocol === 'http:' || url.protocol === 'https:' ? url : null
  } catch {
    return null
  }
}

async function openAllowedExternalUrl(value: string): Promise<void> {
  const url = parseAllowedExternalUrl(value)
  if (!url) return
  await shell.openExternal(url.toString())
}

function notifyVaultLocked(): void {
  sensitiveClipboard.clearIfOwned()
  const window = mainWindow
  if (!window || window.isDestroyed()) return
  window.webContents.send(IPC_EVENTS.vaultLocked)
  setTimeout(() => {
    if (!window.isDestroyed()) window.webContents.reload()
  }, 0)
}

function notifyVaultUnlocked(): void {
  const window = mainWindow
  if (!window || window.isDestroyed()) return
  window.webContents.send(IPC_EVENTS.vaultUnlocked)
}

function notifySyncChanged(status: SyncStatus): void {
  const window = mainWindow
  if (!window || window.isDestroyed()) return
  window.webContents.send(IPC_EVENTS.syncChanged, status)
}

function notifyVaultChanged(): void {
  const window = mainWindow
  if (!window || window.isDestroyed()) return
  window.webContents.send(IPC_EVENTS.vaultChanged)
}

async function unlockSyncWithLocalPassword(masterPassword: string): Promise<void> {
  if (!vault) return
  const status = await vault.unlockSyncWithLocalPassword(masterPassword)
  notifySyncChanged(status)
  if (status.state === 'ready') autoSync?.request()
}

async function lockVault(): Promise<void> {
  if (!vault) return
  autoSync?.cancel()
  vaultLockGeneration += 1
  await vault.lock()
  notifyVaultLocked()
}

async function lockVaultForInactivity(): Promise<void> {
  await lockVault()
  const window = mainWindow
  if (!window || window.isDestroyed()) return
  await focusTouchIdUnlockControllers.get(window)?.lockedWhileFocused()
}

async function lockVaultFailClosed(): Promise<void> {
  await lockVault().catch(() => {
    vault?.dispose()
    notifyVaultLocked()
  })
}

function requestSystemLock(): void {
  void lockVaultFailClosed()
}

function requestMenuLock(): void {
  const window = mainWindow
  if (
    rendererHandlesLockRequests &&
    window &&
    !window.isDestroyed() &&
    !window.webContents.isDestroyed()
  ) {
    window.webContents.send(IPC_EVENTS.vaultLockRequested)
    return
  }
  requestSystemLock()
}

function createWindow(): BrowserWindow {
  const window = new BrowserWindow({
    width: 1100,
    height: 760,
    minHeight: 600,
    minWidth: 800,
    show: false,
    autoHideMenuBar: process.platform === 'darwin',
    ...(process.platform === 'linux' ? { icon } : {}),
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      nodeIntegrationInSubFrames: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      navigateOnDragDrop: false,
      spellcheck: false
    },
    vibrancy: 'fullscreen-ui',
    backgroundMaterial: 'mica',
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 10, y: 20 }
  })

  window.setContentProtection(contentProtectionEnabled)
  window.webContents.on('did-start-loading', () => {
    rendererHandlesLockRequests = false
  })
  window.on('ready-to-show', () => window.show())
  window.on('close', requestSystemLock)
  window.on('closed', () => {
    focusTouchIdUnlockControllers.delete(window)
    if (mainWindow === window) mainWindow = null
  })
  window.webContents.on('will-navigate', (event) => event.preventDefault())
  window.webContents.on('will-attach-webview', (event) => event.preventDefault())
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))

  const focusTouchIdUnlock = new FocusTouchIdUnlockController({
    isActive: () => app.isActive(),
    isFocused: () => window.isFocused(),
    isDestroyed: () => window.isDestroyed(),
    lockGeneration: () => vaultLockGeneration,
    vaultStatus: async () => vault?.status() ?? { state: 'uninitialized' },
    settings: async () => {
      if (!settings) throw new Error('Settings service unavailable')
      return settings.get()
    },
    unlock: async () => {
      if (!settings) throw new Error('Settings service unavailable')
      return settings.unlockTouchId()
    },
    lock: lockVaultFailClosed,
    notifyUnlocked: notifyVaultUnlocked
  })
  focusTouchIdUnlockControllers.set(window, focusTouchIdUnlock)
  window.on('focus', () => void focusTouchIdUnlock.focus())
  window.on('blur', () => focusTouchIdUnlock.blur())

  if (is.dev && process.env['ELECTRON_RENDERER_URL']) {
    void window.loadURL(process.env['ELECTRON_RENDERER_URL'])
  } else {
    void window.loadFile(join(__dirname, '../renderer/index.html'))
  }

  return window
}

if (hasSingleInstanceLock)
  app.whenReady().then(async () => {
    electronApp.setAppUserModelId('com.bearwarden.app')
    session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => {
      callback(false)
    })
    session.defaultSession.setPermissionCheckHandler(() => false)

    const store = new EncryptedVaultStore<unknown>(
      join(app.getPath('userData'), 'vault', 'vault.json')
    )
    vault = new VaultService(
      store,
      {
        copyText: (text) => sensitiveClipboard.write(text),
        openExternal: openAllowedExternalUrl
      },
      {
        createSyncClient: (sync) =>
          new BitwardenDirectClient({
            serverUrl: sync.serverUrl,
            email: sync.email,
            clientVersion: app.getVersion(),
            state: sync.state
          })
      }
    )
    autoSync = new AutoSyncCoordinator({
      vault,
      onSyncChanged: notifySyncChanged,
      onVaultChanged: notifyVaultChanged
    })

    settings = new AppSettingsService(
      join(app.getPath('userData'), 'settings.json'),
      join(app.getPath('userData'), 'vault', 'touch-id.bin'),
      store,
      {
        applyContentProtection: (enabled) => {
          contentProtectionEnabled = enabled
          if (mainWindow && !mainWindow.isDestroyed()) mainWindow.setContentProtection(enabled)
        },
        applyClipboardTimeout: (seconds) => sensitiveClipboard.setClearDelay(seconds),
        lockVault: lockVaultForInactivity,
        unlockVault: async (masterPassword) => {
          if (!vault) throw new Error('Vault service unavailable')
          const status = await vault.unlock(masterPassword)
          await unlockSyncWithLocalPassword(masterPassword).catch(() => undefined)
          return status
        }
      }
    )
    await settings.initialize()

    registerVaultIpc({
      vault,
      settings,
      getMainWindow: () => mainWindow,
      afterLock: () => {
        autoSync?.cancel()
        vaultLockGeneration += 1
        notifyVaultLocked()
      },
      afterUnlock: unlockSyncWithLocalPassword,
      afterMutation: () => autoSync?.request(),
      afterSyncChanged: (status) => {
        autoSync?.cancel()
        notifySyncChanged(status)
      }
    })
    ipcMain.on(IPC_CHANNELS.vaultLockRequestReady, (event, ready: unknown) => {
      const window = mainWindow
      if (!window || event.sender !== window.webContents || typeof ready !== 'boolean') return
      rendererHandlesLockRequests = ready
    })

    powerMonitor.on('lock-screen', () => {
      if (settings?.shouldLockOnScreenLock()) requestSystemLock()
    })
    powerMonitor.on('suspend', () => {
      if (settings?.shouldLockOnSuspend()) requestSystemLock()
    })

    mainWindow = createWindow()
    installApplicationMenu({
      isMac: process.platform === 'darwin',
      onLockVault: requestMenuLock
    })

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) mainWindow = createWindow()
    })
  })

app.on('before-quit', () => {
  sensitiveClipboard.clearIfOwned()
  autoSync?.dispose()
  vault?.dispose()
  settings?.dispose()
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})

app.setAboutPanelOptions({
  applicationName: 'BearWarden',
  applicationVersion: app.getVersion()
})
