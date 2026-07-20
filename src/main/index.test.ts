/* eslint-disable @typescript-eslint/no-empty-function -- Minimal Electron and service test doubles. */
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { join } from 'node:path'

const harness = vi.hoisted(() => {
  const appListeners = new Map<string, (...args: never[]) => void>()
  let userDataPath = '/tmp/bearwarden-index-test'
  const appLifecycleOrder: string[] = []
  const appSetPath = vi.fn((name: string, path: string) => {
    appLifecycleOrder.push(`setPath:${name}`)
    if (name === 'userData') userDataPath = path
  })
  const requestSingleInstanceLock = vi.fn(() => {
    appLifecycleOrder.push('requestSingleInstanceLock')
    return true
  })
  const powerMonitorListeners = new Map<string, (...args: never[]) => void>()
  const windows: FakeWindow[] = []
  let vaultOptions: Record<string, unknown> | null = null
  let vaultIpcOptions: Record<string, unknown> | null = null
  let storePath: string | null = null
  let storeOptions: Record<string, unknown> | null = null
  let settingsPaths: { settingsPath: string; touchIdPath: string } | null = null
  let twoFactorDirectoryPath: string | null = null
  let registryStorePath: string | null = null
  let registryStore: unknown = null
  let bootstrapRegistryStore: unknown = null
  let accountSwitchRoot: string | null = null
  let accountSwitchOptions: Record<string, unknown> | null = null
  let accountSwitchService: unknown = null
  let serverNotificationOptions: Record<string, unknown> | null = null
  let focusTouchIdUnlockOptions: Record<string, unknown> | null = null
  let vaultTimeoutBarrier: Record<string, unknown> | null = null
  let vaultTimeoutOptions: Record<string, unknown> | null = null
  let vaultState: 'uninitialized' | 'locked' | 'unlocked' = 'unlocked'
  let systemIdleTime = 0
  let windowVisible = true
  let windowFocused = true
  let loginApprovalPrompt: Record<string, unknown> | null = null
  const shownNotifications: Record<string, unknown>[] = []
  const autoSyncRequest = vi.fn()
  const autoSyncRequestImmediate = vi.fn()
  const autoSyncUpdateStatus = vi.fn()
  const autoSyncCancel = vi.fn()
  const vaultTimeoutCancel = vi.fn()
  const vaultTimeoutDispose = vi.fn()
  const vaultTimeoutResume = vi.fn()
  const lockedWhileFocused = vi.fn(() => Promise.resolve())
  const lifecycleEvents: string[] = []
  const stopServerNotifications = vi.fn(() => {
    lifecycleEvents.push('notifications.stop')
    return Promise.resolve()
  })
  const disposeServerNotifications = vi.fn(() => Promise.resolve())
  const stopSshAgentServer = vi.fn(() => Promise.resolve())
  const disposeNativeRestoreSession = vi.fn(() => {
    lifecycleEvents.push('portability.dispose')
    return Promise.resolve()
  })
  const vaultLock = vi.fn(() => {
    lifecycleEvents.push('vault.lock')
    return Promise.resolve()
  })
  const appQuit = vi.fn(() => lifecycleEvents.push('app.quit'))
  const appRelaunch = vi.fn(() => lifecycleEvents.push('app.relaunch'))
  const controller = {
    cancel: vi.fn(),
    dispose: vi.fn(),
    run: vi.fn(async () => ({ assertion: true }))
  }
  const registrationController = {
    cancel: vi.fn(),
    dispose: vi.fn(),
    run: vi.fn(async () => ({ attestation: true }))
  }

  class FakeWebContents {
    readonly id = 1
    readonly mainFrame = { url: 'app://bearwarden/index.html' }
    readonly send = vi.fn()
    readonly reload = vi.fn()

    on(): this {
      return this
    }

    setWindowOpenHandler(): void {}

    isDestroyed(): boolean {
      return false
    }
  }

  class FakeWindow {
    static getAllWindows(): FakeWindow[] {
      return windows
    }

    readonly webContents = new FakeWebContents()
    private readonly listeners = new Map<string, (...args: never[]) => void>()

    constructor() {
      windows.push(this)
    }

    on(event: string, listener: (...args: never[]) => void): this {
      this.listeners.set(event, listener)
      return this
    }

    once(event: string, listener: (...args: never[]) => void): this {
      this.listeners.set(event, listener)
      return this
    }

    emit(event: string): void {
      this.listeners.get(event)?.()
    }

    setContentProtection(): void {}
    setMenuBarVisibility(): void {}
    isDestroyed(): boolean {
      return false
    }
    isMinimized(): boolean {
      return false
    }
    isVisible(): boolean {
      return windowVisible
    }
    isFocused(): boolean {
      return windowFocused
    }
    restore(): void {}
    show(): void {}
    focus = vi.fn()
    flashFrame(): void {}
    loadFile = vi.fn(async () => undefined)
  }

  class FakeNotification {
    private readonly options: Record<string, unknown>

    constructor(options: Record<string, unknown>) {
      this.options = options
    }

    static isSupported(): boolean {
      return true
    }
    once(): this {
      return this
    }
    show(): void {
      shownNotifications.push(this.options)
    }
  }

  return {
    appListeners,
    powerMonitorListeners,
    windows,
    FakeWindow,
    FakeNotification,
    controller,
    registrationController,
    get vaultOptions(): Record<string, unknown> | null {
      return vaultOptions
    },
    setVaultOptions: (value: Record<string, unknown>) => {
      vaultOptions = value
    },
    get vaultIpcOptions(): Record<string, unknown> | null {
      return vaultIpcOptions
    },
    setVaultIpcOptions: (value: Record<string, unknown>) => {
      vaultIpcOptions = value
    },
    get storePath(): string | null {
      return storePath
    },
    setStorePath: (value: string) => {
      storePath = value
    },
    get storeOptions(): Record<string, unknown> | null {
      return storeOptions
    },
    setStoreOptions: (value: Record<string, unknown>) => {
      storeOptions = value
    },
    get settingsPaths(): { settingsPath: string; touchIdPath: string } | null {
      return settingsPaths
    },
    setSettingsPaths: (value: { settingsPath: string; touchIdPath: string }) => {
      settingsPaths = value
    },
    get twoFactorDirectoryPath(): string | null {
      return twoFactorDirectoryPath
    },
    setTwoFactorDirectoryPath: (value: string) => {
      twoFactorDirectoryPath = value
    },
    get registryStorePath(): string | null {
      return registryStorePath
    },
    get registryStore(): unknown {
      return registryStore
    },
    setRegistryStore: (path: string, value: unknown) => {
      registryStorePath = path
      registryStore = value
    },
    get bootstrapRegistryStore(): unknown {
      return bootstrapRegistryStore
    },
    setBootstrapRegistryStore: (value: unknown) => {
      bootstrapRegistryStore = value
    },
    get accountSwitchRoot(): string | null {
      return accountSwitchRoot
    },
    get accountSwitchOptions(): Record<string, unknown> | null {
      return accountSwitchOptions
    },
    get accountSwitchService(): unknown {
      return accountSwitchService
    },
    setAccountSwitchService: (root: string, options: Record<string, unknown>, value: unknown) => {
      accountSwitchRoot = root
      accountSwitchOptions = options
      accountSwitchService = value
    },
    get serverNotificationOptions(): Record<string, unknown> | null {
      return serverNotificationOptions
    },
    setServerNotificationOptions: (value: Record<string, unknown>) => {
      serverNotificationOptions = value
    },
    get focusTouchIdUnlockOptions(): Record<string, unknown> | null {
      return focusTouchIdUnlockOptions
    },
    setFocusTouchIdUnlockOptions: (value: Record<string, unknown>) => {
      focusTouchIdUnlockOptions = value
    },
    get vaultTimeoutBarrier(): Record<string, unknown> | null {
      return vaultTimeoutBarrier
    },
    get vaultTimeoutOptions(): Record<string, unknown> | null {
      return vaultTimeoutOptions
    },
    setVaultTimeoutConstructor: (
      barrier: Record<string, unknown>,
      options: Record<string, unknown>
    ) => {
      vaultTimeoutBarrier = barrier
      vaultTimeoutOptions = options
    },
    get vaultState(): 'uninitialized' | 'locked' | 'unlocked' {
      return vaultState
    },
    setVaultState: (state: 'uninitialized' | 'locked' | 'unlocked') => {
      vaultState = state
    },
    get systemIdleTime(): number {
      return systemIdleTime
    },
    setSystemIdleTime: (seconds: number) => {
      systemIdleTime = seconds
    },
    setWindowState: (visible: boolean, focused: boolean) => {
      windowVisible = visible
      windowFocused = focused
    },
    get loginApprovalPrompt(): Record<string, unknown> | null {
      return loginApprovalPrompt
    },
    setLoginApprovalPrompt: (prompt: Record<string, unknown> | null) => {
      loginApprovalPrompt = prompt
    },
    shownNotifications,
    autoSyncRequest,
    autoSyncRequestImmediate,
    autoSyncUpdateStatus,
    autoSyncCancel,
    vaultTimeoutCancel,
    vaultTimeoutDispose,
    vaultTimeoutResume,
    lockedWhileFocused,
    stopServerNotifications,
    disposeServerNotifications,
    stopSshAgentServer,
    disposeNativeRestoreSession,
    vaultLock,
    lifecycleEvents,
    appQuit,
    appRelaunch,
    appSetPath,
    requestSingleInstanceLock,
    appLifecycleOrder,
    get userDataPath(): string {
      return userDataPath
    }
  }
})

vi.mock('electron', () => ({
  app: {
    requestSingleInstanceLock: harness.requestSingleInstanceLock,
    quit: harness.appQuit,
    relaunch: harness.appRelaunch,
    enableSandbox: vi.fn(),
    whenReady: () => Promise.resolve(),
    on: (event: string, listener: (...args: never[]) => void) =>
      harness.appListeners.set(event, listener),
    isActive: () => true,
    getPath: () => harness.userDataPath,
    getVersion: () => 'test',
    isPackaged: false,
    setPath: harness.appSetPath,
    setAboutPanelOptions: vi.fn()
  },
  BrowserWindow: harness.FakeWindow,
  Notification: harness.FakeNotification,
  clipboard: { readText: () => '' },
  dialog: {},
  globalShortcut: { register: vi.fn(() => true), unregister: vi.fn() },
  ipcMain: { on: vi.fn(), handle: vi.fn() },
  powerMonitor: {
    getSystemIdleTime: () => harness.systemIdleTime,
    on: (event: string, listener: (...args: never[]) => void) =>
      harness.powerMonitorListeners.set(event, listener)
  },
  session: {
    defaultSession: {
      setPermissionRequestHandler: vi.fn(),
      setPermissionCheckHandler: vi.fn()
    }
  },
  screen: {
    getCursorScreenPoint: () => ({ x: 0, y: 0 }),
    getDisplayNearestPoint: () => ({ workArea: { x: 0, y: 0, width: 1200, height: 800 } })
  },
  shell: { openExternal: vi.fn() }
}))

vi.mock('@electron-toolkit/utils', () => ({
  electronApp: { setAppUserModelId: vi.fn() },
  is: { dev: false }
}))
vi.mock('../../resources/icon.png?asset', () => ({ default: 'icon' }))
vi.mock('./bitwarden-direct', () => ({ BitwardenDirectClient: class {} }))
vi.mock('./auto-sync-coordinator', () => ({
  AutoSyncCoordinator: class {
    cancel = harness.autoSyncCancel
    dispose(): void {}
    request = harness.autoSyncRequest
    requestImmediate = harness.autoSyncRequestImmediate
    updateStatus = harness.autoSyncUpdateStatus
  }
}))
vi.mock('./autofill-coordinator', () => ({
  AutofillCoordinator: class {
    cancel(): void {}
    dispose(): void {}
    current(): null {
      return null
    }
    select(): Promise<void> {
      return Promise.resolve()
    }
    openMain(): void {}
    trigger(): Promise<void> {
      return Promise.resolve()
    }
  }
}))
vi.mock('./macos-autofill-adapter', () => ({ MacOSAutofillAdapter: class {} }))
vi.mock('./bitwarden-notifications', () => ({
  BitwardenNotificationCoordinator: class {
    constructor(options: Record<string, unknown>) {
      harness.setServerNotificationOptions(options)
    }

    refresh(): Promise<void> {
      return Promise.resolve()
    }
    stop(): Promise<void> {
      return harness.stopServerNotifications()
    }
    dispose(): Promise<void> {
      return harness.disposeServerNotifications()
    }
  }
}))
vi.mock('./app-settings', () => ({
  AppSettingsService: class {
    constructor(settingsPath: string, touchIdPath: string) {
      harness.setSettingsPaths({ settingsPath, touchIdPath })
    }

    initialize(): Promise<void> {
      return Promise.resolve()
    }
    shouldLockOnSuspend(): boolean {
      return false
    }
    shouldLockOnScreenLock(): boolean {
      return false
    }
    dispose(): void {}
  }
}))
vi.mock('./app-updater', () => ({
  AppUpdaterController: class {
    attachWindow(): void {}
    dispose(): void {}
  }
}))
vi.mock('./vault-timeout-coordinator', () => ({
  VaultTimeoutCoordinator: class {
    constructor(barrier: Record<string, unknown>, options: Record<string, unknown>) {
      harness.setVaultTimeoutConstructor(barrier, options)
    }
    cancel = harness.vaultTimeoutCancel
    dispose = harness.vaultTimeoutDispose
    resume = harness.vaultTimeoutResume
  }
}))
vi.mock('./encrypted-vault-store', () => ({
  EncryptedVaultStore: class {
    constructor(filePath: string, options: Record<string, unknown>) {
      harness.setStorePath(filePath)
      harness.setStoreOptions(options)
    }
  }
}))
vi.mock('./account-registry', () => ({
  AccountRegistryStore: class {
    constructor(path: string) {
      harness.setRegistryStore(path, this)
    }
  }
}))
vi.mock('./account-switch-service', () => ({
  AccountSwitchService: class {
    constructor(root: string, options: Record<string, unknown>) {
      harness.setAccountSwitchService(root, options, this)
    }
  }
}))
vi.mock('./account-removal-journal', () => ({
  AccountRemovalJournal: class {
    recover(): Promise<'none'> {
      return Promise.resolve('none')
    }
  }
}))
vi.mock('./account-storage-bootstrap', () => ({
  bootstrapAccountStorage: vi.fn(async (root: string, options: { registryStore: unknown }) => {
    harness.setBootstrapRegistryStore(options.registryStore)
    return {
      mode: 'account',
      activeAccountId: '11111111-1111-4111-8111-111111111111',
      paths: {
        vaultPath: `${root}/accounts/11111111-1111-4111-8111-111111111111/vault/vault.json`,
        settingsPath: `${root}/accounts/11111111-1111-4111-8111-111111111111/account-settings.json`,
        touchIdPath: `${root}/accounts/11111111-1111-4111-8111-111111111111/touch-id.bin`
      }
    }
  })
}))
vi.mock('./focus-touch-id-unlock', () => ({
  FocusTouchIdUnlockController: class {
    constructor(options: Record<string, unknown>) {
      harness.setFocusTouchIdUnlockOptions(options)
    }
    lockedWhileFocused = harness.lockedWhileFocused
  }
}))
vi.mock('./application-menu', () => ({ installApplicationMenu: vi.fn() }))
vi.mock('./application-menu-ipc', () => ({ registerApplicationMenuIpc: vi.fn() }))
vi.mock('./window-chrome', () => ({ windowChromeOptions: vi.fn(() => ({})) }))
vi.mock('./vault-ipc', () => ({
  RepromptAuthorizationStore: class {
    clear(): void {}
  },
  registerVaultIpc: (options: Record<string, unknown>) => harness.setVaultIpcOptions(options)
}))
vi.mock('./vault-service', () => ({
  VaultService: class {
    constructor(_store: unknown, _platform: unknown, options: Record<string, unknown>) {
      harness.setVaultOptions(options)
    }
    lock(): Promise<void> {
      return harness.vaultLock()
    }
    status(): Promise<{ state: 'uninitialized' | 'locked' | 'unlocked' }> {
      return Promise.resolve({ state: harness.vaultState })
    }
    unlockSyncWithLocalPassword(): Promise<import('../shared/vault-contract').SyncStatus> {
      return Promise.resolve({
        configured: true,
        state: 'ready',
        serverUrl: 'https://vault.example.invalid'
      })
    }
    prepareLoginApproval(): Promise<Record<string, unknown> | null> {
      return Promise.resolve(harness.loginApprovalPrompt)
    }
    dispose(): void {}
  }
}))
vi.mock('./vault-attachment-files', () => ({ VaultAttachmentFileService: class {} }))
vi.mock('./vault-portability', () => ({
  VaultPortabilityService: class {
    disposeNativeRestoreSession(): Promise<void> {
      return harness.disposeNativeRestoreSession()
    }
  }
}))
vi.mock('./ssh-key-import-session', () => ({
  SshKeyImportSessionStore: class {
    clearAll(): void {}
  }
}))
vi.mock('./ssh-agent-coordinator', () => ({
  SshAgentCoordinator: class {
    onLocked(): void {}
    reset(): void {}
  }
}))
vi.mock('./ssh-agent-renderer-bridge', () => ({
  SshAgentRendererBridge: class {
    attachWindow(): void {}
    cancelAll(): void {}
    dispose(): void {}
    updateStatus(): void {}
  }
}))
vi.mock('./ssh-agent-server', () => ({
  SshAgentServer: class {
    stop(): Promise<void> {
      return harness.stopSshAgentServer()
    }
  }
}))
vi.mock('./passkey-ceremony-service', () => ({
  PasskeyCeremonyService: class {
    onVaultMutation(): void {}
    onLocked(): void {}
    dispose(): void {}
  }
}))
vi.mock('./passkey-renderer-bridge', () => ({
  PasskeyRendererBridge: class {
    attachWindow(): void {}
    cancelAll(): void {}
    dispose(): void {}
  }
}))
vi.mock('./account-webauthn-window', () => ({
  AccountWebAuthnWindowController: class {
    cancel = harness.controller.cancel
    dispose = harness.controller.dispose
    run = harness.controller.run
  }
}))
vi.mock('./account-webauthn-registration-window', () => ({
  AccountWebAuthnRegistrationWindowController: class {
    cancel = harness.registrationController.cancel
    dispose = harness.registrationController.dispose
    run = harness.registrationController.run
  }
}))
vi.mock('./sensitive-clipboard', () => ({
  SensitiveClipboard: class {
    clearIfOwned(): void {}
    write(): void {}
    setClearDelay(): void {}
  }
}))
vi.mock('./two-factor-directory-cache', () => ({
  TwoFactorDirectoryCache: class {
    constructor(path: string) {
      harness.setTwoFactorDirectoryPath(path)
    }

    dispose(): void {}
  }
}))

beforeAll(async () => {
  await import('./index')
  await vi.waitFor(() => expect(harness.vaultOptions).not.toBeNull())
})

describe('main WebAuthn lifecycle wiring', () => {
  it('wires vault secrets to the active storage while keeping the 2FA cache global', () => {
    const developmentRoot = '/tmp/bearwarden-index-test-development'
    expect(harness.appSetPath).toHaveBeenCalledWith('userData', developmentRoot)
    expect(harness.appLifecycleOrder.slice(0, 2)).toEqual([
      'setPath:userData',
      'requestSingleInstanceLock'
    ])
    expect(harness.storePath).toBe(
      `${developmentRoot}/accounts/11111111-1111-4111-8111-111111111111/vault/vault.json`
    )
    expect(harness.storeOptions).toMatchObject({ afterAtomicCommit: expect.any(Function) })
    expect(harness.settingsPaths).toEqual({
      settingsPath: `${developmentRoot}/accounts/11111111-1111-4111-8111-111111111111/account-settings.json`,
      touchIdPath: `${developmentRoot}/accounts/11111111-1111-4111-8111-111111111111/touch-id.bin`
    })
    expect(harness.twoFactorDirectoryPath).toBe(
      join(developmentRoot, 'cache', '2fa-directory-totp-v4.json')
    )
    expect(harness.registryStorePath).toBe(developmentRoot)
    expect(harness.bootstrapRegistryStore).toBe(harness.registryStore)
    expect(harness.accountSwitchRoot).toBe(developmentRoot)
    expect(harness.accountSwitchOptions?.registryStore).toBe(harness.registryStore)
    expect(harness.accountSwitchOptions?.removalJournal).toBeDefined()
    expect(harness.accountSwitchOptions?.initialCleanupPending).toBe(false)
    expect(harness.vaultIpcOptions?.accountSwitchService).toBe(harness.accountSwitchService)
  })

  it('locks through the teardown barrier without notifying the renderer, then relaunches once', async () => {
    const beforeActivation = harness.accountSwitchOptions!.beforeActivation as () => Promise<void>
    const afterCommitRelaunch = harness.accountSwitchOptions!.afterCommitRelaunch as () => void
    const webContents = harness.windows[0]!.webContents
    harness.lifecycleEvents.length = 0
    harness.vaultTimeoutCancel.mockClear()
    webContents.send.mockClear()
    webContents.reload.mockClear()

    await beforeActivation()
    expect(harness.vaultTimeoutCancel).toHaveBeenCalledTimes(2)
    expect(harness.lifecycleEvents).toEqual([
      'notifications.stop',
      'portability.dispose',
      'vault.lock'
    ])
    expect(webContents.send).not.toHaveBeenCalled()
    expect(webContents.reload).not.toHaveBeenCalled()

    harness.lifecycleEvents.length = 0
    harness.appRelaunch.mockClear()
    harness.appQuit.mockClear()
    afterCommitRelaunch()
    expect(harness.lifecycleEvents).toEqual(['app.relaunch', 'app.quit'])
    expect(harness.appRelaunch).toHaveBeenCalledOnce()
    expect(harness.appQuit).toHaveBeenCalledOnce()
  })

  it('invalidates a pending timeout before every vault lock teardown', async () => {
    harness.vaultTimeoutCancel.mockClear()

    await (harness.vaultIpcOptions!.beforeLock as () => Promise<void>)()

    expect(harness.vaultTimeoutCancel).toHaveBeenCalledOnce()
  })

  it('cancels timeout activity after an account-switch lock failure', async () => {
    const beforeActivation = harness.accountSwitchOptions!.beforeActivation as () => Promise<void>
    harness.vaultTimeoutCancel.mockClear()
    harness.vaultLock.mockRejectedValueOnce(new Error('lock failed'))

    await expect(beforeActivation()).rejects.toThrow('lock failed')

    expect(harness.vaultTimeoutCancel).toHaveBeenCalledTimes(2)
  })

  it('wires manual locks to cancel timers after both success-only and attempt callbacks', () => {
    const afterLock = harness.vaultIpcOptions!.afterLock as () => void
    const afterLockAttempt = harness.vaultIpcOptions!.afterLockAttempt as () => void
    harness.vaultTimeoutCancel.mockClear()

    afterLock()
    expect(harness.vaultTimeoutCancel).toHaveBeenCalledOnce()
    afterLockAttempt()
    expect(harness.vaultTimeoutCancel).toHaveBeenCalledTimes(2)
  })

  it('invalidates the Touch ID generation before asynchronous teardown can reject', async () => {
    const lockGeneration = harness.focusTouchIdUnlockOptions!.lockGeneration as () => number
    const initialGeneration = lockGeneration()
    let rejectTeardown!: (reason: Error) => void
    harness.disposeNativeRestoreSession.mockImplementationOnce(
      () =>
        new Promise<void>((_resolve, reject) => {
          rejectTeardown = reject
        })
    )
    const beforeLock = harness.vaultIpcOptions!.beforeLock as () => Promise<void>

    const locking = beforeLock()
    expect(lockGeneration()).toBe(initialGeneration + 1)
    await vi.waitFor(() => expect(rejectTeardown).toBeTypeOf('function'))
    rejectTeardown(new Error('teardown failed'))

    await expect(locking).rejects.toThrow('teardown failed')
  })

  it('cancels timeout activity again after a lock teardown completes', async () => {
    harness.vaultTimeoutCancel.mockClear()

    harness.windows[0]!.emit('close')

    await vi.waitFor(() => expect(harness.vaultTimeoutCancel).toHaveBeenCalledTimes(2))
  })

  it('uses the authoritative system idle clock and never timeout-locks an already locked vault', async () => {
    harness.setSystemIdleTime(300)
    const getSystemIdleTime = harness.vaultTimeoutOptions!.getSystemIdleTime as () => number
    expect(getSystemIdleTime()).toBe(300)

    harness.vaultLock.mockClear()
    harness.vaultTimeoutCancel.mockClear()
    harness.lockedWhileFocused.mockClear()
    harness.setVaultState('locked')
    await (harness.vaultTimeoutBarrier!.lockVault as () => Promise<void>)()
    expect(harness.vaultLock).not.toHaveBeenCalled()
    expect(harness.lockedWhileFocused).not.toHaveBeenCalled()
    expect(harness.vaultTimeoutCancel).toHaveBeenCalledOnce()

    harness.setVaultState('unlocked')
    await (harness.vaultTimeoutBarrier!.lockVault as () => Promise<void>)()
    expect(harness.vaultLock).toHaveBeenCalledOnce()
    expect(harness.lockedWhileFocused).toHaveBeenCalledOnce()

    harness.powerMonitorListeners.get('resume')!()
    expect(harness.vaultTimeoutResume).toHaveBeenCalledOnce()
  })

  it('delivers login approvals and keeps the native notification non-sensitive', async () => {
    const prompt = {
      token: '50000000-0000-4000-8000-000000000005',
      fingerprint: 'alpha-bravo-charlie-delta-echo-foxtrot',
      requestDeviceType: 'Firefox',
      createdAt: '2026-07-20T04:00:00.000Z',
      expiresAt: '2026-07-20T04:15:00.000Z'
    }
    const webContents = harness.windows[0]!.webContents
    webContents.send.mockClear()
    harness.shownNotifications.length = 0
    harness.setLoginApprovalPrompt(prompt)
    harness.setWindowState(false, false)

    await (
      harness.serverNotificationOptions!.onAuthRequest as (notification: {
        id: string
        userId: string
      }) => Promise<void>
    )({ id: '40000000-0000-4000-8000-000000000004', userId: 'user-id' })

    expect(webContents.send).toHaveBeenCalledWith(
      'account-security:login-approval-requested',
      prompt
    )
    expect(harness.shownNotifications).toEqual([
      {
        title: '收到 Bitwarden 登入要求',
        body: '另一部裝置要求登入。請開啟 BearWarden 並核對驗證詞組。'
      }
    ])
    expect(JSON.stringify(harness.shownNotifications)).not.toContain(prompt.fingerprint)
    expect(JSON.stringify(harness.shownNotifications)).not.toContain(prompt.token)

    harness.setLoginApprovalPrompt(null)
    harness.setWindowState(true, true)
  })

  it('keeps the account connector main-only and bounds application teardown', async () => {
    harness.controller.cancel.mockClear()
    harness.registrationController.cancel.mockClear()
    const request = harness.vaultOptions!.requestAccountWebAuthnAssertion as (
      input: unknown
    ) => Promise<unknown>
    const input = {
      webVaultUrl: 'https://vault.example/',
      challenge: { opaque: true },
      signal: new AbortController().signal
    }

    await expect(request(input)).resolves.toEqual({ assertion: true })
    expect(harness.controller.run).toHaveBeenCalledWith(input)

    const requestRegistration = harness.vaultOptions!.requestAccountWebAuthnRegistration as (
      input: unknown
    ) => Promise<unknown>
    await expect(requestRegistration(input)).resolves.toEqual({ attestation: true })
    expect(harness.registrationController.run).toHaveBeenCalledWith(input)

    await (harness.vaultIpcOptions!.beforeLock as () => Promise<void>)()
    await (harness.vaultIpcOptions!.beforeSyncReconfigure as () => Promise<void>)()
    harness.powerMonitorListeners.get('lock-screen')!()
    harness.powerMonitorListeners.get('suspend')!()
    harness.windows[0]!.emit('closed')
    expect(harness.controller.cancel).toHaveBeenCalledTimes(5)
    expect(harness.registrationController.cancel).toHaveBeenCalledTimes(5)

    vi.useFakeTimers()
    harness.appQuit.mockClear()
    harness.stopSshAgentServer.mockClear()
    harness.disposeServerNotifications.mockClear()
    harness.disposeNativeRestoreSession.mockClear()
    harness.stopSshAgentServer.mockImplementationOnce(() => new Promise<void>(() => undefined))
    harness.disposeServerNotifications.mockImplementationOnce(() => {
      throw new Error('notification teardown failed')
    })

    const quitEvent = { preventDefault: vi.fn() }
    const beforeQuit = harness.appListeners.get('before-quit')!
    beforeQuit(quitEvent as never)
    expect(quitEvent.preventDefault).toHaveBeenCalledOnce()
    await vi.advanceTimersByTimeAsync(0)
    expect(harness.stopSshAgentServer).toHaveBeenCalledOnce()
    expect(harness.disposeServerNotifications).toHaveBeenCalledOnce()
    expect(harness.disposeNativeRestoreSession).toHaveBeenCalledOnce()

    const repeatedQuitEvent = { preventDefault: vi.fn() }
    beforeQuit(repeatedQuitEvent as never)
    expect(repeatedQuitEvent.preventDefault).toHaveBeenCalledOnce()
    expect(harness.stopSshAgentServer).toHaveBeenCalledOnce()
    expect(harness.disposeServerNotifications).toHaveBeenCalledOnce()
    expect(harness.disposeNativeRestoreSession).toHaveBeenCalledOnce()
    expect(harness.appQuit).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(2_999)
    expect(harness.appQuit).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    await vi.waitFor(() => expect(harness.controller.dispose).toHaveBeenCalledOnce())
    expect(harness.registrationController.dispose).toHaveBeenCalledOnce()
    expect(harness.appQuit).toHaveBeenCalledOnce()

    const finalQuitEvent = { preventDefault: vi.fn() }
    beforeQuit(finalQuitEvent as never)
    expect(finalQuitEvent.preventDefault).not.toHaveBeenCalled()
    expect(harness.appQuit).toHaveBeenCalledOnce()
    vi.useRealTimers()
  })

  it('syncs server invalidations and lifecycle boundaries immediately', async () => {
    harness.autoSyncRequest.mockClear()
    harness.autoSyncRequestImmediate.mockClear()
    harness.autoSyncUpdateStatus.mockClear()

    ;(harness.serverNotificationOptions!.onSyncRequested as () => void)()
    expect(harness.autoSyncRequest).not.toHaveBeenCalled()
    expect(harness.autoSyncRequestImmediate).toHaveBeenCalledOnce()

    expect(harness.serverNotificationOptions!.onAuthRequest).toEqual(expect.any(Function))
    ;(
      harness.serverNotificationOptions!.onAuthRequest as (notification: {
        id: string
        userId: string
      }) => void
    )({ id: '40000000-0000-4000-8000-000000000004', userId: 'user-id' })
    expect(harness.autoSyncRequestImmediate).toHaveBeenCalledOnce()

    harness.powerMonitorListeners.get('resume')!()
    harness.appListeners.get('activate')!()
    await (harness.vaultIpcOptions!.afterPinUnlock as () => Promise<void>)()
    await (harness.vaultIpcOptions!.afterUnlock as (masterPassword: string) => Promise<void>)(
      'test-master-password'
    )
    expect(harness.autoSyncRequest).not.toHaveBeenCalled()
    expect(harness.autoSyncRequestImmediate).toHaveBeenCalledTimes(5)
    expect(harness.appListeners.has('browser-window-focus')).toBe(false)

    ;(harness.vaultIpcOptions!.afterMutation as () => void)()
    expect(harness.autoSyncRequestImmediate).toHaveBeenCalledTimes(6)

    const ready: import('../shared/vault-contract').SyncStatus = {
      configured: true,
      state: 'ready',
      serverUrl: 'https://vault.example.invalid'
    }
    ;(harness.vaultIpcOptions!.afterSyncChanged as (status: typeof ready) => void)(ready)
    expect(harness.autoSyncUpdateStatus).toHaveBeenCalledWith(ready)
  })

  it('recreates and focuses the main window when a second instance arrives after close', () => {
    const previousWindow = harness.windows.at(-1)!
    previousWindow.emit('closed')
    const previousCount = harness.windows.length

    harness.appListeners.get('second-instance')!()

    expect(harness.windows).toHaveLength(previousCount + 1)
    expect(harness.windows.at(-1)!.focus).toHaveBeenCalledOnce()
  })
})
