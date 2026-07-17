/* eslint-disable @typescript-eslint/no-empty-function -- Minimal Electron and service test doubles. */
import { beforeAll, describe, expect, it, vi } from 'vitest'

const harness = vi.hoisted(() => {
  const appListeners = new Map<string, (...args: never[]) => void>()
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
  const lifecycleEvents: string[] = []
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
    isDestroyed(): boolean {
      return false
    }
    isMinimized(): boolean {
      return false
    }
    isVisible(): boolean {
      return true
    }
    isFocused(): boolean {
      return true
    }
    restore(): void {}
    show(): void {}
    focus(): void {}
    flashFrame(): void {}
    loadFile = vi.fn(async () => undefined)
  }

  return {
    appListeners,
    powerMonitorListeners,
    windows,
    FakeWindow,
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
    lifecycleEvents,
    appQuit,
    appRelaunch
  }
})

vi.mock('electron', () => ({
  app: {
    requestSingleInstanceLock: () => true,
    quit: harness.appQuit,
    relaunch: harness.appRelaunch,
    enableSandbox: vi.fn(),
    whenReady: () => Promise.resolve(),
    on: (event: string, listener: (...args: never[]) => void) =>
      harness.appListeners.set(event, listener),
    isActive: () => true,
    getPath: () => '/tmp/bearwarden-index-test',
    getVersion: () => 'test',
    isPackaged: false,
    setAboutPanelOptions: vi.fn()
  },
  BrowserWindow: harness.FakeWindow,
  clipboard: { readText: () => '' },
  dialog: {},
  ipcMain: { on: vi.fn() },
  powerMonitor: {
    on: (event: string, listener: (...args: never[]) => void) =>
      harness.powerMonitorListeners.set(event, listener)
  },
  session: {
    defaultSession: {
      setPermissionRequestHandler: vi.fn(),
      setPermissionCheckHandler: vi.fn()
    }
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
    cancel(): void {}
    dispose(): void {}
    request(): void {}
  }
}))
vi.mock('./bitwarden-notifications', () => ({
  BitwardenNotificationCoordinator: class {
    refresh(): Promise<void> {
      return Promise.resolve()
    }
    stop(): Promise<void> {
      harness.lifecycleEvents.push('notifications.stop')
      return Promise.resolve()
    }
    dispose(): Promise<void> {
      return Promise.resolve()
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
  bootstrapAccountStorage: vi.fn(async (_root: string, options: { registryStore: unknown }) => {
    harness.setBootstrapRegistryStore(options.registryStore)
    return {
      mode: 'account',
      activeAccountId: '11111111-1111-4111-8111-111111111111',
      paths: {
        vaultPath:
          '/tmp/bearwarden-index-test/accounts/11111111-1111-4111-8111-111111111111/vault/vault.json',
        settingsPath:
          '/tmp/bearwarden-index-test/accounts/11111111-1111-4111-8111-111111111111/account-settings.json',
        touchIdPath:
          '/tmp/bearwarden-index-test/accounts/11111111-1111-4111-8111-111111111111/touch-id.bin'
      }
    }
  })
}))
vi.mock('./focus-touch-id-unlock', () => ({ FocusTouchIdUnlockController: class {} }))
vi.mock('./application-menu', () => ({ installApplicationMenu: vi.fn() }))
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
      harness.lifecycleEvents.push('vault.lock')
      return Promise.resolve()
    }
    dispose(): void {}
  }
}))
vi.mock('./vault-attachment-files', () => ({ VaultAttachmentFileService: class {} }))
vi.mock('./vault-portability', () => ({
  VaultPortabilityService: class {
    disposeNativeRestoreSession(): Promise<void> {
      harness.lifecycleEvents.push('portability.dispose')
      return Promise.resolve()
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
      return Promise.resolve()
    }
  }
}))
vi.mock('./passkey-ceremony-service', () => ({
  PasskeyCeremonyService: class {
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
    expect(harness.storePath).toBe(
      '/tmp/bearwarden-index-test/accounts/11111111-1111-4111-8111-111111111111/vault/vault.json'
    )
    expect(harness.storeOptions).toMatchObject({ afterAtomicCommit: expect.any(Function) })
    expect(harness.settingsPaths).toEqual({
      settingsPath:
        '/tmp/bearwarden-index-test/accounts/11111111-1111-4111-8111-111111111111/account-settings.json',
      touchIdPath:
        '/tmp/bearwarden-index-test/accounts/11111111-1111-4111-8111-111111111111/touch-id.bin'
    })
    expect(harness.twoFactorDirectoryPath).toBe(
      '/tmp/bearwarden-index-test/cache/2fa-directory-totp-v4.json'
    )
    expect(harness.registryStorePath).toBe('/tmp/bearwarden-index-test')
    expect(harness.bootstrapRegistryStore).toBe(harness.registryStore)
    expect(harness.accountSwitchRoot).toBe('/tmp/bearwarden-index-test')
    expect(harness.accountSwitchOptions?.registryStore).toBe(harness.registryStore)
    expect(harness.accountSwitchOptions?.removalJournal).toBeDefined()
    expect(harness.vaultIpcOptions?.accountSwitchService).toBe(harness.accountSwitchService)
  })

  it('locks through the teardown barrier without notifying the renderer, then relaunches once', async () => {
    const beforeActivation = harness.accountSwitchOptions!.beforeActivation as () => Promise<void>
    const afterCommitRelaunch = harness.accountSwitchOptions!.afterCommitRelaunch as () => void
    const webContents = harness.windows[0]!.webContents
    harness.lifecycleEvents.length = 0
    webContents.send.mockClear()
    webContents.reload.mockClear()

    await beforeActivation()
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

  it('keeps the account connector main-only and cancels it at every teardown boundary', async () => {
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

    const quitEvent = { preventDefault: vi.fn() }
    harness.appListeners.get('before-quit')!(quitEvent as never)
    await vi.waitFor(() => expect(harness.controller.dispose).toHaveBeenCalledOnce())
    expect(harness.registrationController.dispose).toHaveBeenCalledOnce()
  })
})
