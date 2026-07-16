import { join } from 'node:path'
import {
  app,
  BrowserWindow,
  clipboard,
  dialog,
  ipcMain,
  powerMonitor,
  session,
  shell
} from 'electron'
import { electronApp, is } from '@electron-toolkit/utils'
import {
  IPC_CHANNELS,
  IPC_EVENTS,
  type SshAgentPromptBehavior,
  type SshAgentStatus,
  type SshAgentStatusErrorCode,
  type SyncStatus
} from '../shared/vault-contract'
import { BitwardenDirectClient } from './bitwarden-direct'
import { AutoSyncCoordinator } from './auto-sync-coordinator'
import { BitwardenNotificationCoordinator } from './bitwarden-notifications'
import { AppSettingsService } from './app-settings'
import { EncryptedVaultStore } from './encrypted-vault-store'
import { FocusTouchIdUnlockController } from './focus-touch-id-unlock'
import { installApplicationMenu } from './application-menu'
import { registerVaultIpc, RepromptAuthorizationStore } from './vault-ipc'
import { VaultService } from './vault-service'
import { VaultAttachmentFileService } from './vault-attachment-files'
import { VaultPortabilityService } from './vault-portability'
import { SshKeyImportSessionStore } from './ssh-key-import-session'
import { SshAgentCoordinator } from './ssh-agent-coordinator'
import { SshAgentRendererBridge } from './ssh-agent-renderer-bridge'
import { SshAgentServer } from './ssh-agent-server'
import { PasskeyCeremonyService } from './passkey-ceremony-service'
import { PasskeyRendererBridge } from './passkey-renderer-bridge'
import { SensitiveClipboard } from './sensitive-clipboard'
import icon from '../../resources/icon.png?asset'

const hasSingleInstanceLock = app.requestSingleInstanceLock()
if (!hasSingleInstanceLock) app.quit()
app.enableSandbox()

let mainWindow: BrowserWindow | null = null
let vault: VaultService | null = null
let settings: AppSettingsService | null = null
let autoSync: AutoSyncCoordinator | null = null
let serverNotifications: BitwardenNotificationCoordinator | null = null
let sshKeyImportSessions: SshKeyImportSessionStore | null = null
let sshAgentCoordinator: SshAgentCoordinator | null = null
let sshAgentBridge: SshAgentRendererBridge | null = null
let sshAgentServer: SshAgentServer | null = null
let passkeyCeremonyService: PasskeyCeremonyService | null = null
let passkeyRendererBridge: PasskeyRendererBridge | null = null
let repromptAuthorizations: RepromptAuthorizationStore | null = null
let contentProtectionEnabled = true
let vaultLockGeneration = 0
let rendererHandlesLockRequests = false
let sshAgentEnabled = false
let sshAgentPromptBehavior: SshAgentPromptBehavior = 'always'
let sshAgentLifecycleState: SshAgentStatus['state'] = 'stopped'
let sshAgentLastError: SshAgentStatusErrorCode | undefined
let sshAgentLifecycle = Promise.resolve()
let sshAgentLifecycleEpoch = 0
let shutdownPending: Promise<void> | null = null
let shutdownComplete = false
let servicesDisposed = false
const sshAgentRuntime = {
  applySettings(settings: { enabled: boolean; promptBehavior: SshAgentPromptBehavior }): void {
    sshAgentEnabled = settings.enabled
    sshAgentPromptBehavior = settings.promptBehavior
    sshAgentLifecycleEpoch += 1
    if (!settings.enabled) {
      sshAgentBridge?.cancelAll()
      sshAgentCoordinator?.reset()
    }
    publishSshAgentStatus()
    scheduleSshAgentLifecycle()
  }
}

function sshAgentErrorCode(error: unknown, operation: 'start' | 'stop'): SshAgentStatusErrorCode {
  const code = error instanceof Error ? (error as NodeJS.ErrnoException).code : undefined
  const message = error instanceof Error ? error.message : ''
  if (message === 'SSH_AGENT_SOCKET_IN_USE') return 'SOCKET_IN_USE'
  if (message === 'SSH_AGENT_SOCKET_PATH_UNSAFE') return 'SOCKET_PATH_UNSAFE'
  if (
    message === 'SSH_AGENT_SOCKET_PATH_CHANGED' ||
    message === 'SSH_AGENT_SOCKET_REPLACEMENT_RESTORE_FAILED'
  ) {
    return 'SOCKET_PATH_CHANGED'
  }
  if (code === 'EACCES' || code === 'EPERM') return 'SOCKET_PERMISSION_DENIED'
  if (process.platform === 'win32' && code === 'EADDRINUSE') return 'PIPE_IN_USE'
  return operation === 'start' ? 'START_FAILED' : 'STOP_FAILED'
}

function publishSshAgentStatus(): void {
  const serverStatus = sshAgentServer?.status
  sshAgentBridge?.updateStatus({
    enabled: sshAgentEnabled,
    running: serverStatus?.running ?? false,
    state: sshAgentLifecycleState,
    ...(serverStatus?.socketPath === undefined ? {} : { endpoint: serverStatus.socketPath }),
    identityCount: sshAgentCoordinator?.identityCount ?? 0,
    ...(sshAgentLastError === undefined ? {} : { lastError: sshAgentLastError })
  })
}

function scheduleSshAgentLifecycle(): void {
  const lifecycleEpoch = sshAgentLifecycleEpoch
  sshAgentLifecycle = sshAgentLifecycle
    .then(async () => {
      if (lifecycleEpoch !== sshAgentLifecycleEpoch) return
      const server = sshAgentServer
      const currentVault = vault
      if (!server || !currentVault) return
      const vaultStatus = await currentVault.status()
      if (lifecycleEpoch !== sshAgentLifecycleEpoch) return
      const shouldRun = sshAgentEnabled && vaultStatus.state !== 'uninitialized'
      if (!shouldRun) {
        sshAgentBridge?.cancelAll()
        sshAgentCoordinator?.reset()
        try {
          await server.stop()
          sshAgentLifecycleState = 'stopped'
          sshAgentLastError = undefined
        } catch (error) {
          if (lifecycleEpoch !== sshAgentLifecycleEpoch) return
          sshAgentLifecycleState = 'error'
          sshAgentLastError = sshAgentErrorCode(error, 'stop')
        } finally {
          // A refresh that raced with teardown must not leave an AFU public cache behind.
          sshAgentCoordinator?.reset()
        }
        if (lifecycleEpoch !== sshAgentLifecycleEpoch) return
        publishSshAgentStatus()
        return
      }

      sshAgentLifecycleState = 'starting'
      sshAgentLastError = undefined
      publishSshAgentStatus()
      try {
        if (vaultStatus.state === 'unlocked') await sshAgentCoordinator?.onUnlocked()
        if (lifecycleEpoch !== sshAgentLifecycleEpoch) return
        await server.start()
        if (lifecycleEpoch !== sshAgentLifecycleEpoch) return
        sshAgentLifecycleState = 'ready'
      } catch (error) {
        if (lifecycleEpoch !== sshAgentLifecycleEpoch) return
        sshAgentLifecycleState = 'error'
        sshAgentLastError = sshAgentErrorCode(error, 'start')
      }
      publishSshAgentStatus()
    })
    .catch(() => {
      if (lifecycleEpoch !== sshAgentLifecycleEpoch) return
      sshAgentLifecycleState = 'error'
      sshAgentLastError = 'START_FAILED'
      publishSshAgentStatus()
    })
}

function focusMainWindow(): void {
  const window = mainWindow
  if (!window || window.isDestroyed()) return
  if (window.isMinimized()) window.restore()
  if (!window.isVisible()) window.show()
  if (!window.isFocused()) {
    window.flashFrame(true)
    window.once('focus', () => {
      if (!window.isDestroyed()) window.flashFrame(false)
    })
  }
  window.focus()
}

async function refreshSshAgentAfterUnlock(): Promise<void> {
  const coordinator = sshAgentCoordinator
  if (!coordinator) return
  if (!sshAgentEnabled) {
    sshAgentBridge?.notifyUnlocked()
    return
  }
  try {
    await coordinator.onUnlocked()
    publishSshAgentStatus()
  } finally {
    sshAgentBridge?.notifyUnlocked()
  }
}

function refreshSshAgentAfterVaultChange(): void {
  const coordinator = sshAgentCoordinator
  if (!coordinator || !sshAgentEnabled) return
  void coordinator
    .refreshIdentities()
    .then(() => publishSshAgentStatus())
    .catch(() => undefined)
}

const sensitiveClipboard = new SensitiveClipboard(clipboard)
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
  refreshSshAgentAfterVaultChange()
  const window = mainWindow
  if (!window || window.isDestroyed()) return
  window.webContents.send(IPC_EVENTS.vaultChanged)
}

function notifyExternalVaultChanged(): void {
  passkeyCeremonyService?.onVaultMutation()
  notifyVaultChanged()
}

function refreshServerNotifications(): void {
  void serverNotifications?.refresh().catch(() => undefined)
}

function stopServerNotifications(): Promise<void> {
  return serverNotifications?.stop().catch(() => undefined) ?? Promise.resolve()
}

function handleSyncChanged(status: SyncStatus): void {
  notifySyncChanged(status)
  if (status.state === 'ready' || status.state === 'error') refreshServerNotifications()
  else if (status.state === 'locked' || status.state === 'unconfigured') {
    autoSync?.cancel()
    void stopServerNotifications()
  }
}

async function handleRemoteSyncLogout(): Promise<void> {
  autoSync?.cancel()
  const currentVault = vault
  if (!currentVault) return
  try {
    handleSyncChanged(await currentVault.remoteLogoutSync())
  } catch {
    const status = await currentVault.syncStatus().catch(() => null)
    if (status) handleSyncChanged(status)
  }
}

async function unlockSyncWithLocalPassword(masterPassword: string): Promise<void> {
  if (!vault) return
  const status = await vault.unlockSyncWithLocalPassword(masterPassword)
  passkeyCeremonyService?.onVaultMutation()
  handleSyncChanged(status)
  if (status.state === 'ready') autoSync?.request()
}

async function beforeVaultLock(): Promise<void> {
  passkeyCeremonyService?.onLocked()
  passkeyRendererBridge?.cancelAll()
  autoSync?.cancel()
  await stopServerNotifications()
  vaultLockGeneration += 1
  sshKeyImportSessions?.clearAll()
  sshAgentCoordinator?.onLocked()
  sshAgentBridge?.cancelAll()
  repromptAuthorizations?.clear()
  publishSshAgentStatus()
}

async function lockVault(): Promise<void> {
  if (!vault) return
  await beforeVaultLock()
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
  sshAgentBridge?.attachWindow(window)
  passkeyRendererBridge?.attachWindow(window)
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
    const attachmentFiles = new VaultAttachmentFileService({
      chooseOpenFile: async () => {
        const options = {
          title: '上傳附件',
          buttonLabel: '選擇',
          filters: [{ name: '所有檔案', extensions: ['*'] }],
          // Preserve macOS aliases so the main-only lstat boundary can reject
          // them instead of silently accepting the resolved target.
          properties: ['openFile' as const, 'noResolveAliases' as const]
        }
        const result = mainWindow
          ? await dialog.showOpenDialog(mainWindow, options)
          : await dialog.showOpenDialog(options)
        return result.canceled || result.filePaths.length !== 1 ? null : result.filePaths[0]!
      },
      chooseSavePath: async (defaultName) => {
        const options = {
          title: '下載附件',
          defaultPath: defaultName,
          buttonLabel: '儲存',
          filters: [{ name: '所有檔案', extensions: ['*'] }],
          properties: ['showOverwriteConfirmation' as const]
        }
        const result = mainWindow
          ? await dialog.showSaveDialog(mainWindow, options)
          : await dialog.showSaveDialog(options)
        return result.canceled || !result.filePath ? null : result.filePath
      }
    })
    vault = new VaultService(
      store,
      {
        copyText: (text) => sensitiveClipboard.write(text),
        copySensitiveText: (text, maxLifetimeSeconds) =>
          sensitiveClipboard.write(text, maxLifetimeSeconds),
        openExternal: openAllowedExternalUrl
      },
      {
        createSyncClient: (sync) =>
          new BitwardenDirectClient({
            serverUrl: sync.serverUrl,
            email: sync.email,
            clientVersion: app.getVersion(),
            state: sync.state
          }),
        attachmentFiles
      }
    )
    repromptAuthorizations = new RepromptAuthorizationStore()
    sshAgentBridge = new SshAgentRendererBridge({
      getMainWindow: () => mainWindow,
      focusWindow: () => focusMainWindow()
    })
    sshAgentCoordinator = new SshAgentCoordinator({
      vault,
      waitForUnlock: (signal) => sshAgentBridge?.waitForUnlock(signal) ?? Promise.resolve(false),
      focusWindow: focusMainWindow,
      getSettings: () => ({ sshAgentPromptBehavior }),
      requestRendererApproval: (request, signal) => {
        const bridge = sshAgentBridge
        if (!bridge) return Promise.reject(new Error('SSH_AGENT_BRIDGE_UNAVAILABLE'))
        return bridge.requestApproval(request, signal)
      },
      validateAuthorizationToken: (token, itemId, generation) => {
        const window = mainWindow
        return Boolean(
          repromptAuthorizations &&
          window &&
          !window.isDestroyed() &&
          !window.webContents.isDestroyed() &&
          repromptAuthorizations.validate(token, window.webContents.id, itemId, generation)
        )
      }
    })
    sshAgentServer = new SshAgentServer({
      provider: {
        listIdentities: async (request) => {
          if (!sshAgentEnabled) return []
          const identities = await sshAgentCoordinator!.provider.listIdentities(request)
          return sshAgentEnabled ? identities : []
        },
        sign: async (request) => {
          if (!sshAgentEnabled) return undefined
          const signature = await sshAgentCoordinator!.provider.sign(request)
          return sshAgentEnabled ? signature : undefined
        }
      },
      approvalHandler: {
        approveSign: async (request) => {
          if (!sshAgentEnabled) return false
          const approved = await sshAgentCoordinator!.approvalHandler.approveSign(request)
          return sshAgentEnabled && approved
        }
      },
      onRuntimeError: (error) => {
        sshAgentLifecycleEpoch += 1
        sshAgentLifecycleState = 'error'
        sshAgentLastError = sshAgentErrorCode(error, 'start')
        publishSshAgentStatus()
        // The server also schedules fail-closed teardown. This queued stop lets status publish
        // again after the endpoint and connection set have actually been released.
        void sshAgentServer
          ?.stop()
          .catch(() => undefined)
          .finally(() => publishSshAgentStatus())
      }
    })
    const portability = new VaultPortabilityService(vault, {
      chooseExportPath: async (defaultName) => {
        const options = {
          title: '匯出加密保管庫',
          defaultPath: defaultName,
          buttonLabel: '匯出',
          filters: [{ name: 'Bitwarden JSON', extensions: ['json'] }],
          properties: ['showOverwriteConfirmation' as const]
        }
        const result = mainWindow
          ? await dialog.showSaveDialog(mainWindow, options)
          : await dialog.showSaveDialog(options)
        return result.canceled || !result.filePath ? null : result.filePath
      },
      chooseImportPath: async () => {
        const options = {
          title: '匯入密碼資料',
          buttonLabel: '匯入',
          filters: [
            { name: 'Bitwarden JSON', extensions: ['json'] },
            { name: 'Bitwarden 或 Chrome CSV', extensions: ['csv'] },
            { name: '所有檔案', extensions: ['*'] }
          ],
          properties: ['openFile' as const]
        }
        const result = mainWindow
          ? await dialog.showOpenDialog(mainWindow, options)
          : await dialog.showOpenDialog(options)
        return result.canceled || result.filePaths.length !== 1 ? null : result.filePaths[0]!
      }
    })
    autoSync = new AutoSyncCoordinator({
      vault,
      onSyncChanged: handleSyncChanged,
      onVaultChanged: notifyExternalVaultChanged
    })
    serverNotifications = new BitwardenNotificationCoordinator({
      source: vault,
      onSyncRequested: () => autoSync?.request(),
      onRemoteLogout: handleRemoteSyncLogout
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
        applySshAgentSettings: (next) => {
          sshAgentRuntime.applySettings(next)
        },
        getStartAtLoginStatus: () => {
          const available =
            app.isPackaged && (process.platform === 'darwin' || process.platform === 'win32')
          if (!available) return { available: false, enabled: false, needsApproval: false }
          try {
            const loginItem = app.getLoginItemSettings()
            return {
              available: true,
              enabled: loginItem.openAtLogin,
              needsApproval: loginItem.status === 'requires-approval'
            }
          } catch {
            return { available: false, enabled: false, needsApproval: false }
          }
        },
        setStartAtLogin: (enabled) => {
          if (!app.isPackaged || (process.platform !== 'darwin' && process.platform !== 'win32')) {
            return false
          }
          try {
            app.setLoginItemSettings({ openAtLogin: enabled })
            return app.getLoginItemSettings().openAtLogin === enabled
          } catch {
            return false
          }
        },
        lockVault: lockVaultForInactivity,
        unlockVault: async (masterPassword) => {
          if (!vault) throw new Error('Vault service unavailable')
          const status = await vault.unlock(masterPassword)
          await unlockSyncWithLocalPassword(masterPassword).catch(() => undefined)
          await refreshSshAgentAfterUnlock().catch(() => undefined)
          scheduleSshAgentLifecycle()
          return status
        }
      }
    )
    await settings.initialize()

    passkeyRendererBridge = new PasskeyRendererBridge({
      getMainWindow: () => mainWindow,
      focusWindow: () => focusMainWindow(),
      getVerificationMethods: async () => {
        const current = await settings?.get().catch(() => undefined)
        return current?.touchIdAvailable && current.touchIdEnabled
          ? ['touch-id', 'master-password']
          : ['master-password']
      },
      verifyMasterPassword: (requestId, selectedChoiceId, masterPassword, signal) => {
        const service = passkeyCeremonyService
        if (!service) return Promise.reject(new Error('PASSKEY_SERVICE_UNAVAILABLE'))
        return service.verifyMasterPassword(requestId, selectedChoiceId, masterPassword, signal)
      }
    })
    passkeyCeremonyService = new PasskeyCeremonyService({
      vault,
      rendererBridge: passkeyRendererBridge,
      settings,
      onVaultMutation: () => {
        autoSync?.request()
        notifyVaultChanged()
      }
    })

    sshKeyImportSessions = new SshKeyImportSessionStore({
      readClipboard: () => clipboard.readText()
    })

    registerVaultIpc({
      vault,
      portability,
      settings,
      getMainWindow: () => mainWindow,
      sshKeyImportSessions,
      repromptAuthorizations,
      afterSetup: async () => {
        passkeyCeremonyService?.onVaultMutation()
        await refreshSshAgentAfterUnlock().catch(() => undefined)
        scheduleSshAgentLifecycle()
      },
      beforeLock: beforeVaultLock,
      afterLock: () => {
        autoSync?.cancel()
        notifyVaultLocked()
      },
      afterUnlock: async (masterPassword) => {
        await unlockSyncWithLocalPassword(masterPassword).catch(() => undefined)
        await refreshSshAgentAfterUnlock().catch(() => undefined)
        scheduleSshAgentLifecycle()
      },
      afterMutation: () => {
        passkeyCeremonyService?.onVaultMutation()
        autoSync?.request()
        refreshSshAgentAfterVaultChange()
      },
      beforeSyncReconfigure: async () => {
        autoSync?.cancel()
        await stopServerNotifications()
      },
      afterSyncChanged: (status) => {
        passkeyCeremonyService?.onVaultMutation()
        handleSyncChanged(status)
        refreshSshAgentAfterVaultChange()
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
      void stopServerNotifications()
      if (settings?.shouldLockOnSuspend()) requestSystemLock()
    })
    powerMonitor.on('resume', () => refreshServerNotifications())

    mainWindow = createWindow()
    installApplicationMenu({
      isMac: process.platform === 'darwin',
      onLockVault: requestMenuLock
    })

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) mainWindow = createWindow()
    })
  })

function disposeServices(): void {
  if (servicesDisposed) return
  servicesDisposed = true
  sensitiveClipboard.clearIfOwned()
  sshKeyImportSessions?.clearAll()
  void serverNotifications?.dispose().catch(() => undefined)
  serverNotifications = null
  autoSync?.dispose()
  passkeyCeremonyService?.dispose()
  passkeyRendererBridge?.dispose()
  vault?.dispose()
  settings?.dispose()
}

app.on('before-quit', (event) => {
  if (shutdownComplete) {
    disposeServices()
    return
  }
  event.preventDefault()
  if (shutdownPending) return

  sshAgentEnabled = false
  sshAgentLifecycleEpoch += 1
  passkeyCeremonyService?.onLocked()
  passkeyRendererBridge?.cancelAll()
  sshAgentBridge?.cancelAll()
  sshAgentCoordinator?.reset()
  repromptAuthorizations?.clear()
  shutdownPending = Promise.all([
    (sshAgentServer?.stop() ?? Promise.resolve()).catch(() => undefined),
    (serverNotifications?.dispose() ?? Promise.resolve()).catch(() => undefined)
  ]).then(() => {
    sshAgentBridge?.dispose()
    disposeServices()
    shutdownComplete = true
    app.quit()
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})

app.setAboutPanelOptions({
  applicationName: 'BearWarden',
  applicationVersion: app.getVersion()
})
