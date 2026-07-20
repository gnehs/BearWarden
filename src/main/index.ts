import { join } from 'node:path'
import {
  app,
  BrowserWindow,
  clipboard,
  dialog,
  globalShortcut,
  ipcMain,
  Notification,
  powerMonitor,
  screen,
  session,
  shell
} from 'electron'
import { electronApp, is } from '@electron-toolkit/utils'
import {
  IPC_CHANNELS,
  IPC_EVENTS,
  type AutofillFeatureStatus,
  type SshAgentPromptBehavior,
  type SshAgentStatus,
  type SshAgentStatusErrorCode,
  type SyncStatus
} from '../shared/vault-contract'
import { BitwardenDirectClient } from './bitwarden-direct'
import { AutoSyncCoordinator } from './auto-sync-coordinator'
import {
  BitwardenNotificationCoordinator,
  type BitwardenAuthRequestNotification
} from './bitwarden-notifications'
import { AppSettingsService } from './app-settings'
import { AppUpdaterController } from './app-updater'
import { EncryptedVaultStore } from './encrypted-vault-store'
import { FocusTouchIdUnlockController } from './focus-touch-id-unlock'
import { installApplicationMenu } from './application-menu'
import { registerApplicationMenuIpc } from './application-menu-ipc'
import { initializeMainI18n, translateMain } from './i18n'
import { windowChromeOptions } from './window-chrome'
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
import { AccountWebAuthnWindowController } from './account-webauthn-window'
import { AccountWebAuthnRegistrationWindowController } from './account-webauthn-registration-window'
import { SensitiveClipboard } from './sensitive-clipboard'
import { TwoFactorDirectoryCache } from './two-factor-directory-cache'
import { bootstrapAccountStorage } from './account-storage-bootstrap'
import { AccountRegistryStore } from './account-registry'
import { AccountSwitchService } from './account-switch-service'
import { AccountRemovalJournal } from './account-removal-journal'
import { clearPendingInitializationMarker } from './account-storage-initialization-marker'
import { VaultTimeoutCoordinator } from './vault-timeout-coordinator'
import { AutofillCoordinator } from './autofill-coordinator'
import { MacOSAutofillAdapter } from './macos-autofill-adapter'
import { prepareDevelopmentUserData } from './development-user-data'
import icon from '../../resources/icon.png?asset'

if (!app.isPackaged) {
  // Keep development vaults, Chromium state, and the single-instance lock isolated from an
  // installed BearWarden. Electron requires an overridden userData directory to exist first.
  const developmentUserData = `${app.getPath('userData')}-development`
  prepareDevelopmentUserData(developmentUserData)
  app.setPath('userData', developmentUserData)
  // Never copy the old path automatically: it may contain a real packaged vault.
  console.warn(
    '[BearWarden dev] Using isolated development data. Existing non-development data was not migrated.'
  )
}

const hasSingleInstanceLock = app.requestSingleInstanceLock()
if (!hasSingleInstanceLock) app.quit()
else app.on('second-instance', () => showOrCreateMainWindow())
app.enableSandbox()

let mainWindow: BrowserWindow | null = null
let mainInitializationComplete = false
let pendingMainWindowRequest = false
let vault: VaultService | null = null
let portability: VaultPortabilityService | null = null
let settings: AppSettingsService | null = null
let appUpdater: AppUpdaterController | null = null
let vaultTimeoutCoordinator: VaultTimeoutCoordinator | null = null
let autoSync: AutoSyncCoordinator | null = null
let serverNotifications: BitwardenNotificationCoordinator | null = null
let sshKeyImportSessions: SshKeyImportSessionStore | null = null
let sshAgentCoordinator: SshAgentCoordinator | null = null
let sshAgentBridge: SshAgentRendererBridge | null = null
let sshAgentServer: SshAgentServer | null = null
let passkeyCeremonyService: PasskeyCeremonyService | null = null
let passkeyRendererBridge: PasskeyRendererBridge | null = null
let accountWebAuthnController: AccountWebAuthnWindowController | null = null
let accountWebAuthnRegistrationController: AccountWebAuthnRegistrationWindowController | null = null
let autofillCoordinator: AutofillCoordinator | null = null
let autofillAdapter: MacOSAutofillAdapter | null = null
let autofillWindow: BrowserWindow | null = null
let autofillEnabled = false
let autofillShortcutRegistered = false
let repromptAuthorizations: RepromptAuthorizationStore | null = null
let twoFactorDirectory: TwoFactorDirectoryCache | null = null
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
const SHUTDOWN_GRACE_PERIOD_MS = 3_000
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

function applyAutofillEnabled(enabled: boolean): void {
  autofillEnabled = process.platform === 'darwin' && enabled
  if (!autofillEnabled) {
    autofillCoordinator?.cancel()
    globalShortcut.unregister('Control+\\')
    autofillShortcutRegistered = false
    return
  }
  if (autofillShortcutRegistered) return
  autofillShortcutRegistered = globalShortcut.register('Control+\\', () => {
    void autofillCoordinator?.trigger()
  })
}

async function getAutofillFeatureStatus(prompt = false): Promise<AutofillFeatureStatus> {
  const available = process.platform === 'darwin'
  // A conflicting app may release Ctrl+\\ after BearWarden starts; status refresh doubles as a
  // safe retry so the user does not have to toggle the feature off and on again.
  if (available && autofillEnabled && !autofillShortcutRegistered) {
    applyAutofillEnabled(true)
  }
  let accessibilityTrusted = false
  if (available && autofillAdapter) {
    accessibilityTrusted = await autofillAdapter.permission(prompt).catch(() => false)
  }
  return {
    available,
    enabled: available && autofillEnabled,
    shortcutRegistered: available && autofillShortcutRegistered,
    accessibilityTrusted
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

function showOrCreateMainWindow(): void {
  if (!mainInitializationComplete) {
    pendingMainWindowRequest = true
    return
  }
  if (!mainWindow || mainWindow.isDestroyed()) mainWindow = createWindow()
  focusMainWindow()
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

function cancelAccountWebAuthnCeremony(): void {
  accountWebAuthnController?.cancel()
  accountWebAuthnRegistrationController?.cancel()
}

function hideAutofillWindow(): void {
  const window = autofillWindow
  if (window && !window.isDestroyed()) window.hide()
}

function showAutofillWindow(): void {
  const window = getOrCreateAutofillWindow()
  const display = screen.getDisplayNearestPoint(screen.getCursorScreenPoint())
  const { x, y, width } = display.workArea
  const [windowWidth] = window.getSize()
  window.setPosition(Math.round(x + (width - windowWidth) / 2), y + 72, false)
  window.show()
  window.focus()
}

function getOrCreateAutofillWindow(): BrowserWindow {
  const existing = autofillWindow
  if (existing && !existing.isDestroyed()) return existing
  const window = new BrowserWindow({
    width: 620,
    height: 430,
    minWidth: 520,
    minHeight: 320,
    maxWidth: 720,
    maxHeight: 560,
    show: false,
    frame: false,
    transparent: true,
    resizable: true,
    maximizable: false,
    minimizable: false,
    fullscreenable: false,
    skipTaskbar: true,
    alwaysOnTop: true,
    hasShadow: true,
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
    }
  })
  window.setAlwaysOnTop(true, 'floating')
  window.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true })
  window.setContentProtection(!is.dev && contentProtectionEnabled)
  window.webContents.on('will-navigate', (event) => event.preventDefault())
  window.webContents.on('will-attach-webview', (event) => event.preventDefault())
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))
  window.on('blur', () => {
    if (autofillCoordinator?.current()?.status !== 'filling') autofillCoordinator?.cancel()
  })
  window.on('closed', () => {
    if (autofillWindow === window) autofillWindow = null
  })
  if (is.dev && process.env['ELECTRON_RENDERER_URL']) {
    const url = new URL(process.env['ELECTRON_RENDERER_URL'])
    url.searchParams.set('mode', 'autofill')
    void window.loadURL(url.toString())
  } else {
    void window.loadFile(join(__dirname, '../renderer/index.html'), {
      query: { mode: 'autofill' }
    })
  }
  autofillWindow = window
  return window
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
  autoSync?.updateStatus(status)
  notifySyncChanged(status)
  if (status.state === 'ready' || status.state === 'error') refreshServerNotifications()
  else if (status.state === 'locked' || status.state === 'unconfigured') {
    autoSync?.cancel()
    void stopServerNotifications()
  }
}

async function handleRemoteSyncLogout(): Promise<void> {
  cancelAccountWebAuthnCeremony()
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

async function handleAuthRequestNotification(
  notification: BitwardenAuthRequestNotification
): Promise<void> {
  const currentVault = vault
  if (!currentVault) return
  const prompt = await currentVault.prepareLoginApproval(notification.id).catch(() => null)
  if (!prompt) return
  const window = mainWindow
  if (!window || window.isDestroyed()) return
  window.webContents.send(IPC_EVENTS.loginApprovalRequested, prompt)
  if (window.isVisible() && window.isFocused()) return
  if (!Notification.isSupported()) return
  const systemNotification = new Notification({
    title: translateMain('authRequest.title'),
    body: translateMain('authRequest.body')
  })
  systemNotification.once('click', focusMainWindow)
  systemNotification.show()
}

async function unlockSyncWithLocalPassword(masterPassword: string): Promise<void> {
  if (!vault) return
  const status = await vault.unlockSyncWithLocalPassword(masterPassword)
  passkeyCeremonyService?.onVaultMutation()
  handleSyncChanged(status)
  // Opening the vault is the first safe point at which startup can pull remote changes.
  if (status.state === 'ready' || status.state === 'error') autoSync?.requestImmediate()
}

async function beforeVaultLock(): Promise<void> {
  vaultLockGeneration += 1
  vaultTimeoutCoordinator?.cancel()
  autofillCoordinator?.cancel()
  cancelAccountWebAuthnCeremony()
  passkeyCeremonyService?.onLocked()
  passkeyRendererBridge?.cancelAll()
  autoSync?.cancel()
  await stopServerNotifications()
  await portability?.disposeNativeRestoreSession()
  sshKeyImportSessions?.clearAll()
  sshAgentCoordinator?.onLocked()
  sshAgentBridge?.cancelAll()
  repromptAuthorizations?.clear()
  publishSshAgentStatus()
}

async function lockVault(): Promise<void> {
  try {
    if (!vault) return
    await beforeVaultLock()
    await vault.lock()
    notifyVaultLocked()
  } finally {
    // Activity can arrive while asynchronous teardown runs; never leave that timer armed.
    vaultTimeoutCoordinator?.cancel()
  }
}

async function lockVaultForInactivity(): Promise<void> {
  const currentVault = vault
  if (!currentVault) return
  let unlocked = false
  try {
    unlocked = (await currentVault.status()).state === 'unlocked'
  } catch {
    // If the authoritative state cannot be read, force the same fail-closed lock barrier.
    await lockVaultFailClosed()
    return
  }
  if (!unlocked) {
    vaultTimeoutCoordinator?.cancel()
    return
  }
  await lockVaultFailClosed()
  const window = mainWindow
  if (!window || window.isDestroyed()) return
  // This only offers Touch ID after the fail-closed lock; it cannot affect the locked state.
  await focusTouchIdUnlockControllers
    .get(window)
    ?.lockedWhileFocused()
    .catch(() => undefined)
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
  const isMac = process.platform === 'darwin'
  const window = new BrowserWindow({
    width: 1100,
    height: 760,
    minHeight: 600,
    minWidth: 800,
    // Development must stay visible even when Windows never emits ready-to-show. Production
    // remains hidden until the renderer is ready to avoid a white startup flash.
    show: is.dev,
    autoHideMenuBar: isMac,
    ...(!isMac ? { icon } : {}),
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
    ...windowChromeOptions(process.platform)
  })
  if (!isMac) window.setMenuBarVisibility(false)

  // WDA_EXCLUDEFROMCAPTURE can make a window disappear entirely in captured or virtualized
  // Windows development sessions. Keep the production protection while leaving dev inspectable.
  window.setContentProtection(!is.dev && contentProtectionEnabled)
  sshAgentBridge?.attachWindow(window)
  passkeyRendererBridge?.attachWindow(window)
  window.webContents.on('did-start-loading', () => {
    rendererHandlesLockRequests = false
  })
  const showWhenLoaded = (): void => {
    if (!window.isDestroyed() && !window.isVisible()) window.show()
  }
  window.on('ready-to-show', showWhenLoaded)
  // ready-to-show is not guaranteed to fire on every Windows graphics configuration. The
  // renderer completing its main-frame load is a safe fallback that prevents a healthy dev
  // window from remaining permanently hidden behind its taskbar icon.
  window.webContents.on('did-finish-load', showWhenLoaded)
  window.on('close', requestSystemLock)
  window.on('closed', () => {
    // The connector deliberately has no relationship with the primary renderer. If its owner
    // window goes away, abort the native ceremony rather than leaving an orphaned prompt alive.
    cancelAccountWebAuthnCeremony()
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
  appUpdater?.attachWindow(window)
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
    initializeMainI18n(app.getLocale())
    electronApp.setAppUserModelId('com.bearwarden.app')
    if (process.platform === 'darwin' && !app.isPackaged) app.dock?.setIcon(icon)
    session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => {
      callback(false)
    })
    session.defaultSession.setPermissionCheckHandler(() => false)

    const userDataDirectory = app.getPath('userData')
    const accountRegistryStore = new AccountRegistryStore(userDataDirectory)
    const accountRemovalJournal = new AccountRemovalJournal(userDataDirectory)
    let accountRemovalCleanupPending = false
    try {
      await accountRemovalJournal.recover({
        loadAuthoritativeRegistry: () => accountRegistryStore.loadPrimary(),
        checkpointRegistry: async (registry) => {
          await accountRegistryStore.checkpoint(registry, registry.revision)
        }
      })
    } catch {
      // An inactive account cleanup must not make the active vault unavailable. Preserve the
      // journal and expose a renderer-safe pending flag so the user is not told cleanup finished.
      accountRemovalCleanupPending = true
    }
    const activeStorage = await bootstrapAccountStorage(userDataDirectory, {
      registryStore: accountRegistryStore
    })
    const store = new EncryptedVaultStore<unknown>(activeStorage.paths.vaultPath, {
      ...(activeStorage.mode === 'account'
        ? {
            afterAtomicCommit: () =>
              clearPendingInitializationMarker(activeStorage.paths.initializationMarkerPath)
          }
        : {})
    })
    const attachmentFiles = new VaultAttachmentFileService({
      chooseOpenFile: async () => {
        const options = {
          title: translateMain('attachment.uploadTitle'),
          buttonLabel: translateMain('attachment.select'),
          filters: [{ name: translateMain('attachment.allFiles'), extensions: ['*'] }],
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
          title: translateMain('attachment.downloadTitle'),
          defaultPath: defaultName,
          buttonLabel: translateMain('attachment.save'),
          filters: [{ name: translateMain('attachment.allFiles'), extensions: ['*'] }],
          properties: ['showOverwriteConfirmation' as const]
        }
        const result = mainWindow
          ? await dialog.showSaveDialog(mainWindow, options)
          : await dialog.showSaveDialog(options)
        return result.canceled || !result.filePath ? null : result.filePath
      }
    })

    // This controller owns its private IPC endpoints and native connector windows. Construct it
    // before the sync service can request provider-7 WebAuthn, but never route ceremony data via
    // the primary renderer. A construction failure must not prevent use of the local vault: the
    // stable requester below rejects and VaultService maps it to its generic sync failure.
    let capturedAccountWebAuthnController: AccountWebAuthnWindowController | null = null
    try {
      capturedAccountWebAuthnController = new AccountWebAuthnWindowController()
      accountWebAuthnController = capturedAccountWebAuthnController
    } catch {
      // Keep the local vault usable without exposing native WebAuthn initialization details.
    }
    let capturedAccountWebAuthnRegistrationController: AccountWebAuthnRegistrationWindowController | null =
      null
    try {
      capturedAccountWebAuthnRegistrationController =
        new AccountWebAuthnRegistrationWindowController()
      accountWebAuthnRegistrationController = capturedAccountWebAuthnRegistrationController
    } catch {
      // Registration is optional; a connector failure must not block the local vault.
    }
    const activeVault = new VaultService(
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
        attachmentFiles,
        requestAccountWebAuthnAssertion: ({ webVaultUrl, challenge, signal }) => {
          const controller = capturedAccountWebAuthnController
          if (!controller) return Promise.reject(new Error('ACCOUNT_WEBAUTHN_UNAVAILABLE'))
          return controller.run({ webVaultUrl, challenge, signal })
        },
        requestAccountWebAuthnRegistration: ({ webVaultUrl, challenge, signal }) => {
          const controller = capturedAccountWebAuthnRegistrationController
          if (!controller) {
            return Promise.reject(new Error('ACCOUNT_WEBAUTHN_REGISTRATION_UNAVAILABLE'))
          }
          return controller.run({ webVaultUrl, challenge, signal })
        }
      }
    )
    vault = activeVault
    const accountSwitchService =
      activeStorage.mode === 'account'
        ? new AccountSwitchService(userDataDirectory, {
            registryStore: accountRegistryStore,
            removalJournal: accountRemovalJournal,
            initialCleanupPending: accountRemovalCleanupPending,
            beforeActivation: async () => {
              try {
                await beforeVaultLock()
                await activeVault.lock()
              } finally {
                vaultTimeoutCoordinator?.cancel()
              }
            },
            afterCommitRelaunch: () => {
              app.relaunch()
              app.quit()
            }
          })
        : undefined
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
    portability = new VaultPortabilityService(vault, {
      chooseExportPath: async (defaultName) => {
        const native = defaultName.endsWith('.bwbackup')
        const zip = defaultName.endsWith('.zip')
        const csv = defaultName.endsWith('.csv')
        const options = {
          title: zip
            ? translateMain('export.bitwardenZipTitle')
            : csv
              ? translateMain('export.bitwardenCsvTitle')
              : translateMain('export.encryptedVaultTitle'),
          defaultPath: defaultName,
          buttonLabel: translateMain('export.button'),
          filters: [
            native
              ? {
                  name: translateMain('export.nativeBackupFilter'),
                  extensions: ['bwbackup']
                }
              : zip
                ? { name: translateMain('export.bitwardenZipFilter'), extensions: ['zip'] }
                : csv
                  ? { name: translateMain('export.bitwardenCsvFilter'), extensions: ['csv'] }
                  : { name: translateMain('export.bitwardenJsonFilter'), extensions: ['json'] }
          ],
          properties: ['showOverwriteConfirmation' as const]
        }
        const result = mainWindow
          ? await dialog.showSaveDialog(mainWindow, options)
          : await dialog.showSaveDialog(options)
        return result.canceled || !result.filePath ? null : result.filePath
      },
      chooseImportPath: async (format) => {
        const native = format === 'bearwarden-native'
        const keepass = format === 'keepass-xml'
        const options = {
          title: native
            ? translateMain('import.nativeBackupTitle')
            : keepass
              ? translateMain('import.keepassTitle')
              : translateMain('import.passwordDataTitle'),
          buttonLabel: translateMain('import.button'),
          filters: native
            ? [
                {
                  name: translateMain('export.nativeBackupFilter'),
                  extensions: ['bwbackup']
                }
              ]
            : keepass
              ? [{ name: translateMain('import.keepassFilter'), extensions: ['xml'] }]
              : [
                  { name: translateMain('export.bitwardenJsonFilter'), extensions: ['json'] },
                  { name: translateMain('import.passwordCsvFilter'), extensions: ['csv'] }
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
      onSyncRequested: () => autoSync?.requestImmediate(),
      onAuthRequest: handleAuthRequestNotification,
      onRemoteLogout: handleRemoteSyncLogout
    })
    twoFactorDirectory = new TwoFactorDirectoryCache(
      join(app.getPath('userData'), 'cache', '2fa-directory-totp-v4.json'),
      { openExternal: (url) => shell.openExternal(url) }
    )

    vaultTimeoutCoordinator = new VaultTimeoutCoordinator(
      { lockVault: lockVaultForInactivity },
      { getSystemIdleTime: () => powerMonitor.getSystemIdleTime() }
    )

    settings = new AppSettingsService(
      activeStorage.paths.settingsPath,
      activeStorage.paths.touchIdPath,
      store,
      {
        applyContentProtection: (enabled) => {
          contentProtectionEnabled = enabled
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.setContentProtection(!is.dev && enabled)
          }
        },
        applyClipboardTimeout: (seconds) => sensitiveClipboard.setClearDelay(seconds),
        applyAutofillEnabled,
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
        unlockVault: async (masterPassword) => {
          if (!vault) throw new Error('Vault service unavailable')
          const status = await vault.unlock(masterPassword)
          await unlockSyncWithLocalPassword(masterPassword).catch(() => undefined)
          await refreshSshAgentAfterUnlock().catch(() => undefined)
          scheduleSshAgentLifecycle()
          return status
        }
      },
      vaultTimeoutCoordinator
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
        autoSync?.requestImmediate()
        notifyVaultChanged()
      }
    })

    if (process.platform === 'darwin') {
      const adapter = new MacOSAutofillAdapter()
      autofillAdapter = adapter
      autofillCoordinator = new AutofillCoordinator({
        vault,
        platform: adapter,
        publish: (prompt) => {
          const window = autofillWindow
          if (!window || window.isDestroyed() || window.webContents.isDestroyed()) return
          window.webContents.send(IPC_EVENTS.autofillPromptChanged, prompt)
        },
        showPicker: showAutofillWindow,
        hidePicker: hideAutofillWindow,
        openMain: () => focusMainWindow()
      })
      const trustedAutofillSender = (event: Electron.IpcMainInvokeEvent): boolean => {
        const window = autofillWindow
        return Boolean(
          window &&
          !window.isDestroyed() &&
          event.sender === window.webContents &&
          event.senderFrame === window.webContents.mainFrame
        )
      }
      ipcMain.handle(IPC_CHANNELS.autofillCurrent, (event) => {
        if (!trustedAutofillSender(event)) return null
        return autofillCoordinator?.current() ?? null
      })
      ipcMain.handle(IPC_CHANNELS.autofillSelect, async (event, input: unknown) => {
        if (!trustedAutofillSender(event) || !input || typeof input !== 'object') return
        const value = input as Record<string, unknown>
        if (
          Object.keys(value).length !== 2 ||
          typeof value.requestId !== 'string' ||
          typeof value.itemId !== 'string'
        ) {
          return
        }
        await autofillCoordinator?.select({ requestId: value.requestId, itemId: value.itemId })
      })
      ipcMain.handle(IPC_CHANNELS.autofillCancel, (event, input: unknown) => {
        if (!trustedAutofillSender(event) || !input || typeof input !== 'object') return
        const value = input as Record<string, unknown>
        if (Object.keys(value).length !== 1 || typeof value.requestId !== 'string') return
        autofillCoordinator?.cancel(value.requestId)
      })
      ipcMain.handle(IPC_CHANNELS.autofillOpenMain, (event, input: unknown) => {
        if (!trustedAutofillSender(event) || !input || typeof input !== 'object') return
        const value = input as Record<string, unknown>
        if (Object.keys(value).length !== 1 || typeof value.requestId !== 'string') return
        autofillCoordinator?.openMain(value.requestId)
      })
    }

    const trustedAutofillSettingsSender = (event: Electron.IpcMainInvokeEvent): boolean => {
      const window = mainWindow
      return Boolean(
        window &&
        !window.isDestroyed() &&
        event.sender === window.webContents &&
        event.senderFrame === window.webContents.mainFrame
      )
    }
    const trustedAutofillPermissionSender = (event: Electron.IpcMainInvokeEvent): boolean => {
      const window = mainWindow
      return Boolean(
        trustedAutofillSettingsSender(event) &&
        window?.isVisible() &&
        window.isFocused() &&
        app.isActive()
      )
    }
    const unavailableAutofillStatus: AutofillFeatureStatus = {
      available: false,
      enabled: false,
      shortcutRegistered: false,
      accessibilityTrusted: false
    }
    ipcMain.handle(IPC_CHANNELS.autofillStatus, (event) =>
      trustedAutofillSettingsSender(event)
        ? getAutofillFeatureStatus(false)
        : unavailableAutofillStatus
    )
    ipcMain.handle(IPC_CHANNELS.autofillRequestAccessibility, (event) => {
      if (!trustedAutofillPermissionSender(event) || !autofillEnabled) {
        return unavailableAutofillStatus
      }
      return getAutofillFeatureStatus(true)
    })

    sshKeyImportSessions = new SshKeyImportSessionStore({
      readClipboard: () => clipboard.readText()
    })

    registerVaultIpc({
      vault,
      portability,
      settings,
      ...(accountSwitchService ? { accountSwitchService } : {}),
      getMainWindow: () => mainWindow,
      sshKeyImportSessions,
      repromptAuthorizations,
      twoFactorDirectory,
      afterSetup: async () => {
        passkeyCeremonyService?.onVaultMutation()
        await refreshSshAgentAfterUnlock().catch(() => undefined)
        scheduleSshAgentLifecycle()
      },
      beforeLock: beforeVaultLock,
      afterLock: () => {
        vaultTimeoutCoordinator?.cancel()
        autoSync?.cancel()
        notifyVaultLocked()
      },
      afterLockAttempt: () => vaultTimeoutCoordinator?.cancel(),
      afterUnlock: async (masterPassword) => {
        await unlockSyncWithLocalPassword(masterPassword).catch(() => undefined)
        await refreshSshAgentAfterUnlock().catch(() => undefined)
        scheduleSshAgentLifecycle()
      },
      afterPinUnlock: async () => {
        autoSync?.requestImmediate()
        await refreshSshAgentAfterUnlock().catch(() => undefined)
        scheduleSshAgentLifecycle()
      },
      afterMasterPasswordChanged: (status) => {
        passkeyCeremonyService?.onVaultMutation()
        handleSyncChanged(status)
        notifyVaultChanged()
      },
      afterMutation: () => {
        passkeyCeremonyService?.onVaultMutation()
        autoSync?.requestImmediate()
        refreshSshAgentAfterVaultChange()
      },
      beforeSyncReconfigure: async () => {
        cancelAccountWebAuthnCeremony()
        autoSync?.cancel()
        await stopServerNotifications()
      },
      afterSyncChanged: (status) => {
        passkeyCeremonyService?.onVaultMutation()
        handleSyncChanged(status)
        refreshSshAgentAfterVaultChange()
      }
    })
    registerApplicationMenuIpc({
      getMainWindow: () => mainWindow
    })
    ipcMain.on(IPC_CHANNELS.vaultLockRequestReady, (event, ready: unknown) => {
      const window = mainWindow
      if (!window || event.sender !== window.webContents || typeof ready !== 'boolean') return
      rendererHandlesLockRequests = ready
    })

    powerMonitor.on('lock-screen', () => {
      cancelAccountWebAuthnCeremony()
      if (settings?.shouldLockOnScreenLock()) requestSystemLock()
    })
    powerMonitor.on('suspend', () => {
      cancelAccountWebAuthnCeremony()
      void stopServerNotifications()
      if (settings?.shouldLockOnSuspend()) requestSystemLock()
    })
    powerMonitor.on('resume', () => {
      vaultTimeoutCoordinator?.resume()
      refreshServerNotifications()
      autoSync?.requestImmediate()
    })

    appUpdater = new AppUpdaterController()
    mainWindow = createWindow()
    mainInitializationComplete = true
    if (pendingMainWindowRequest) {
      pendingMainWindowRequest = false
      focusMainWindow()
    }
    installApplicationMenu({
      isMac: process.platform === 'darwin',
      onLockVault: requestMenuLock
    })
    if (process.platform !== 'darwin') mainWindow.setMenuBarVisibility(false)

    app.on('activate', () => {
      showOrCreateMainWindow()
      autoSync?.requestImmediate()
    })
  })

function disposeServices(): void {
  if (servicesDisposed) return
  servicesDisposed = true
  sensitiveClipboard.clearIfOwned()
  globalShortcut.unregister('Control+\\')
  autofillShortcutRegistered = false
  autofillEnabled = false
  autofillCoordinator?.dispose()
  autofillCoordinator = null
  autofillAdapter = null
  const quickWindow = autofillWindow
  autofillWindow = null
  if (quickWindow && !quickWindow.isDestroyed()) quickWindow.destroy()
  sshKeyImportSessions?.clearAll()
  void serverNotifications?.dispose().catch(() => undefined)
  serverNotifications = null
  autoSync?.dispose()
  void portability?.disposeNativeRestoreSession()
  portability = null
  passkeyCeremonyService?.dispose()
  passkeyRendererBridge?.dispose()
  const controller = accountWebAuthnController
  accountWebAuthnController = null
  controller?.dispose()
  const registrationController = accountWebAuthnRegistrationController
  accountWebAuthnRegistrationController = null
  registrationController?.dispose()
  twoFactorDirectory?.dispose()
  twoFactorDirectory = null
  vaultTimeoutCoordinator?.dispose()
  vaultTimeoutCoordinator = null
  vault?.dispose()
  settings?.dispose()
  appUpdater?.dispose()
  appUpdater = null
}

async function waitForShutdownTasks(tasks: Array<() => void | Promise<unknown>>): Promise<void> {
  let deadline: ReturnType<typeof setTimeout> | undefined
  try {
    await Promise.race([
      Promise.allSettled(tasks.map((task) => Promise.resolve().then(task))).then(() => undefined),
      new Promise<void>((resolve) => {
        deadline = setTimeout(resolve, SHUTDOWN_GRACE_PERIOD_MS)
      })
    ])
  } finally {
    if (deadline) clearTimeout(deadline)
  }
}

function finishShutdown(): void {
  try {
    sshAgentBridge?.dispose()
    disposeServices()
  } catch {
    // Teardown is best-effort once the deadline has elapsed; never trap the process in before-quit.
  } finally {
    shutdownComplete = true
    app.quit()
  }
}

app.on('before-quit', (event) => {
  if (shutdownComplete) {
    disposeServices()
    return
  }
  event.preventDefault()
  if (shutdownPending) return

  try {
    sshAgentEnabled = false
    sshAgentLifecycleEpoch += 1
    cancelAccountWebAuthnCeremony()
    autofillCoordinator?.cancel()
    passkeyCeremonyService?.onLocked()
    passkeyRendererBridge?.cancelAll()
    sshAgentBridge?.cancelAll()
    sshAgentCoordinator?.reset()
    repromptAuthorizations?.clear()
  } catch {
    // Continue into the bounded shutdown even if a best-effort cancellation hook fails.
  }
  const agentServer = sshAgentServer
  const notifications = serverNotifications
  const restoreService = portability
  sshAgentServer = null
  serverNotifications = null
  portability = null
  shutdownPending = waitForShutdownTasks([
    () => agentServer?.stop(),
    () => notifications?.dispose(),
    () => restoreService?.disposeNativeRestoreSession()
  ]).then(finishShutdown, finishShutdown)
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})

app.setAboutPanelOptions({
  applicationName: 'BearWarden',
  applicationVersion: app.getVersion()
})
