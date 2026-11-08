import { app, shell, type BrowserWindow, type IpcMainInvokeEvent } from 'electron'
import electronUpdater, {
  type AppUpdater as ElectronAppUpdater,
  type ProgressInfo,
  type UpdateDownloadedEvent,
  type UpdateInfo
} from 'electron-updater'
import type { IpcInvokeChannel, IpcResponse } from '../shared/ipc-api'
import type {
  AppUpdateState,
  AppUpdateStatus,
  AppManualUpdateSource
} from '../shared/vault-contract'
import { handleIpc, isTrustedVaultSender, sendIpcEvent, type IpcDisposer } from './typed-ipc'

// electron-updater is CommonJS. Its documented TypeScript ESM interop uses a default import.
const { autoUpdater } = electronUpdater
const REPOSITORY_PAGE_URL = 'https://github.com/gnehs/BearWarden'
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
  private readonly manualUpdateSource: AppManualUpdateSource
  private readonly openExternal: (url: string) => Promise<unknown>
  private attachedWindow: BrowserWindow | null = null
  private disposed = false
  private readonly ipcDisposers: IpcDisposer[]
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
    this.manualUpdateSource = this.enabled && platform === 'darwin' ? 'homebrew' : 'github'
    this.openExternal = options.openExternal ?? ((url) => shell.openExternal(url))
    this.stateValue = Object.freeze({
      status: this.enabled ? 'idle' : 'disabled',
      currentVersion: options.currentVersion ?? app.getVersion(),
      availableVersion: null,
      progress: null,
      canAutoInstall: this.canAutoInstall,
      manualUpdateSource: this.manualUpdateSource
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

    this.ipcDisposers = [
      this.handleAttached('app-update:check', () => this.check()),
      this.handleAttached('app-update:download', () => this.download()),
      this.handleAttached('app-update:install', () => this.quitAndInstall()),
      this.handleAttached('app-update:open-release-page', () => this.openReleasePage()),
      this.handleAttached('app-update:open-repository-page', () => this.openRepositoryPage()),
      this.handleAttached('app-update:state', () => this.state)
    ]
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

  async openRepositoryPage(): Promise<void> {
    try {
      await this.openExternal(REPOSITORY_PAGE_URL)
    } catch {
      throw new Error('Unable to open repository page')
    }
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.attachedWindow = null
    this.ipcDisposers.forEach((dispose) => dispose())

    if (!this.enabled) return
    this.updater.removeListener('checking-for-update', this.onCheckingForUpdate)
    this.updater.removeListener('update-available', this.onUpdateAvailable)
    this.updater.removeListener('update-not-available', this.onUpdateNotAvailable)
    this.updater.removeListener('download-progress', this.onDownloadProgress)
    this.updater.removeListener('update-downloaded', this.onUpdateDownloaded)
    this.updater.removeListener('error', this.onUpdaterError)
  }

  /** Updater commands take no payload and answer only the renderer this controller is attached to. */
  private handleAttached<Channel extends IpcInvokeChannel>(
    channel: Channel,
    run: () => IpcResponse<Channel> | Promise<IpcResponse<Channel>>
  ): IpcDisposer {
    return handleIpc(channel, (event: IpcMainInvokeEvent, input) => {
      if (!isTrustedVaultSender(event, this.attachedWindow) || input !== undefined) {
        throw new Error('Invalid app update request')
      }
      return run()
    })
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
      canAutoInstall: this.canAutoInstall,
      manualUpdateSource: this.manualUpdateSource
    })
    this.notifyStateChanged()
  }

  private notifyStateChanged(): void {
    const window = this.attachedWindow
    if (!window || window.isDestroyed() || window.webContents.isDestroyed()) return
    sendIpcEvent(window.webContents, 'app-update:state-changed', this.state)
  }
}
