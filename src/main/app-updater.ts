import { app, ipcMain, shell, type BrowserWindow, type IpcMainInvokeEvent } from 'electron'
import electronUpdater, {
  type AppUpdater as ElectronAppUpdater,
  type ProgressInfo,
  type UpdateDownloadedEvent,
  type UpdateInfo
} from 'electron-updater'
import {
  IPC_CHANNELS,
  IPC_EVENTS,
  type AppUpdateState,
  type AppUpdateStatus
} from '../shared/vault-contract'

// electron-updater is CommonJS. Its documented TypeScript ESM interop uses a default import.
const { autoUpdater } = electronUpdater
const RELEASE_PAGE_URL = 'https://github.com/gnehs/BearWarden/releases/latest'

export interface AppUpdaterControllerOptions {
  updater?: ElectronAppUpdater
  isPackaged?: boolean
  currentVersion?: string
  platform?: NodeJS.Platform
  isAppImage?: boolean
  openExternal?: (url: string) => Promise<unknown>
}

/** Owns the main-only updater and exposes a narrow, renderer-safe IPC boundary. */
export class AppUpdaterController {
  private readonly updater: ElectronAppUpdater
  private readonly enabled: boolean
  private readonly canAutoInstall: boolean
  private readonly openExternal: (url: string) => Promise<unknown>
  private attachedWindow: BrowserWindow | null = null
  private disposed = false
  private stateValue: AppUpdateState

  private readonly onCheckingForUpdate = (): void => {
    this.setState('checking', null, null)
  }

  private readonly onUpdateAvailable = (info: UpdateInfo): void => {
    this.setState('available', info.version, null)
  }

  private readonly onUpdateNotAvailable = (): void => {
    this.setState('idle', null, null)
  }

  private readonly onDownloadProgress = (info: ProgressInfo): void => {
    const percent = Number.isFinite(info.percent) ? Math.min(100, Math.max(0, info.percent)) : 0
    this.setState('downloading', this.stateValue.availableVersion, percent)
  }

  private readonly onUpdateDownloaded = (info: UpdateDownloadedEvent): void => {
    this.setState('downloaded', info.version, 100)
  }

  private readonly onUpdaterError = (): void => {
    this.setState('error', this.stateValue.availableVersion, this.stateValue.progress)
  }

  constructor(options: AppUpdaterControllerOptions = {}) {
    this.updater = options.updater ?? autoUpdater
    this.enabled = options.isPackaged ?? app.isPackaged
    const platform = options.platform ?? process.platform
    const isAppImage = options.isAppImage ?? Boolean(process.env['APPIMAGE'])
    this.canAutoInstall =
      this.enabled && (platform === 'win32' || (platform === 'linux' && isAppImage))
    this.openExternal = options.openExternal ?? ((url) => shell.openExternal(url))
    this.stateValue = Object.freeze({
      status: this.enabled ? 'idle' : 'disabled',
      currentVersion: options.currentVersion ?? app.getVersion(),
      availableVersion: null,
      progress: null,
      canAutoInstall: this.canAutoInstall
    })

    if (this.enabled) {
      this.updater.autoDownload = false
      this.updater.autoInstallOnAppQuit = this.canAutoInstall
      this.updater.on('checking-for-update', this.onCheckingForUpdate)
      this.updater.on('update-available', this.onUpdateAvailable)
      this.updater.on('update-not-available', this.onUpdateNotAvailable)
      this.updater.on('download-progress', this.onDownloadProgress)
      this.updater.on('update-downloaded', this.onUpdateDownloaded)
      this.updater.on('error', this.onUpdaterError)
    }

    ipcMain.handle(IPC_CHANNELS.appUpdateCheck, (event) => this.handleCheck(event))
    ipcMain.handle(IPC_CHANNELS.appUpdateDownload, (event) => this.handleDownload(event))
    ipcMain.handle(IPC_CHANNELS.appUpdateInstall, (event) => this.handleInstall(event))
    ipcMain.handle(IPC_CHANNELS.appUpdateOpenReleasePage, (event) =>
      this.handleOpenReleasePage(event)
    )
  }

  get state(): AppUpdateState {
    return { ...this.stateValue }
  }

  attachWindow(window: BrowserWindow | null): void {
    this.attachedWindow = window
    this.notifyStateChanged()
  }

  async check(): Promise<AppUpdateState> {
    if (!this.enabled || this.disposed) return this.state
    if (this.stateValue.status === 'downloading' || this.stateValue.status === 'downloaded') {
      return this.state
    }

    this.setState('checking', null, null)
    try {
      await this.updater.checkForUpdates()
    } catch {
      this.onUpdaterError()
    }
    return this.state
  }

  async download(): Promise<AppUpdateState> {
    if (!this.enabled || this.disposed) return this.state
    if (!this.canAutoInstall) throw new Error('Automatic updates are unavailable on this platform')
    if (this.stateValue.status !== 'available') return this.state

    this.setState('downloading', this.stateValue.availableVersion, 0)
    try {
      // The resolved file paths are intentionally discarded and never cross IPC.
      await this.updater.downloadUpdate()
    } catch {
      this.onUpdaterError()
    }
    return this.state
  }

  quitAndInstall(): void {
    if (!this.enabled || this.disposed) return
    if (!this.canAutoInstall) throw new Error('Automatic updates are unavailable on this platform')
    if (this.stateValue.status !== 'downloaded') return
    this.updater.quitAndInstall()
  }

  async openReleasePage(): Promise<void> {
    try {
      await this.openExternal(RELEASE_PAGE_URL)
    } catch {
      throw new Error('Unable to open release page')
    }
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.attachedWindow = null
    ipcMain.removeHandler(IPC_CHANNELS.appUpdateCheck)
    ipcMain.removeHandler(IPC_CHANNELS.appUpdateDownload)
    ipcMain.removeHandler(IPC_CHANNELS.appUpdateInstall)
    ipcMain.removeHandler(IPC_CHANNELS.appUpdateOpenReleasePage)

    if (!this.enabled) return
    this.updater.removeListener('checking-for-update', this.onCheckingForUpdate)
    this.updater.removeListener('update-available', this.onUpdateAvailable)
    this.updater.removeListener('update-not-available', this.onUpdateNotAvailable)
    this.updater.removeListener('download-progress', this.onDownloadProgress)
    this.updater.removeListener('update-downloaded', this.onUpdateDownloaded)
    this.updater.removeListener('error', this.onUpdaterError)
  }

  private assertAttachedRenderer(event: IpcMainInvokeEvent): void {
    const window = this.attachedWindow
    if (!window || window.isDestroyed() || event.sender !== window.webContents) {
      throw new Error('Invalid app update request')
    }
  }

  private handleCheck(event: IpcMainInvokeEvent): Promise<AppUpdateState> {
    this.assertAttachedRenderer(event)
    return this.check()
  }

  private handleDownload(event: IpcMainInvokeEvent): Promise<AppUpdateState> {
    this.assertAttachedRenderer(event)
    return this.download()
  }

  private handleInstall(event: IpcMainInvokeEvent): void {
    this.assertAttachedRenderer(event)
    this.quitAndInstall()
  }

  private handleOpenReleasePage(event: IpcMainInvokeEvent): Promise<void> {
    this.assertAttachedRenderer(event)
    return this.openReleasePage()
  }

  private setState(
    status: AppUpdateStatus,
    availableVersion: string | null,
    progress: number | null
  ): void {
    this.stateValue = Object.freeze({
      status,
      currentVersion: this.stateValue.currentVersion,
      availableVersion,
      progress,
      canAutoInstall: this.canAutoInstall
    })
    this.notifyStateChanged()
  }

  private notifyStateChanged(): void {
    const window = this.attachedWindow
    if (!window || window.isDestroyed() || window.webContents.isDestroyed()) return
    window.webContents.send(IPC_EVENTS.appUpdateStateChanged, this.state)
  }
}
