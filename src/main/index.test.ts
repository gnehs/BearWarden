/* eslint-disable @typescript-eslint/no-empty-function -- Minimal Electron and service test doubles. */
import { beforeAll, describe, expect, it, vi } from 'vitest'

const harness = vi.hoisted(() => {
  const appListeners = new Map<string, (...args: never[]) => void>()
  const powerMonitorListeners = new Map<string, (...args: never[]) => void>()
  const windows: FakeWindow[] = []
  let vaultOptions: Record<string, unknown> | null = null
  let vaultIpcOptions: Record<string, unknown> | null = null
  const controller = {
    cancel: vi.fn(),
    dispose: vi.fn(),
    run: vi.fn(async () => ({ assertion: true }))
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
    }
  }
})

vi.mock('electron', () => ({
  app: {
    requestSingleInstanceLock: () => true,
    quit: vi.fn(),
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
      return Promise.resolve()
    }
    dispose(): Promise<void> {
      return Promise.resolve()
    }
  }
}))
vi.mock('./app-settings', () => ({
  AppSettingsService: class {
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
vi.mock('./encrypted-vault-store', () => ({ EncryptedVaultStore: class {} }))
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
    dispose(): void {}
  }
}))
vi.mock('./vault-attachment-files', () => ({ VaultAttachmentFileService: class {} }))
vi.mock('./vault-portability', () => ({
  VaultPortabilityService: class {
    disposeNativeRestoreSession(): Promise<void> {
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
vi.mock('./sensitive-clipboard', () => ({
  SensitiveClipboard: class {
    clearIfOwned(): void {}
    write(): void {}
    setClearDelay(): void {}
  }
}))
vi.mock('./two-factor-directory-cache', () => ({
  TwoFactorDirectoryCache: class {
    dispose(): void {}
  }
}))

beforeAll(async () => {
  await import('./index')
  await vi.waitFor(() => expect(harness.vaultOptions).not.toBeNull())
})

describe('main WebAuthn lifecycle wiring', () => {
  it('keeps the account connector main-only and cancels it at every teardown boundary', async () => {
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

    await (harness.vaultIpcOptions!.beforeLock as () => Promise<void>)()
    await (harness.vaultIpcOptions!.beforeSyncReconfigure as () => Promise<void>)()
    harness.powerMonitorListeners.get('lock-screen')!()
    harness.powerMonitorListeners.get('suspend')!()
    harness.windows[0]!.emit('closed')
    expect(harness.controller.cancel).toHaveBeenCalledTimes(5)

    const quitEvent = { preventDefault: vi.fn() }
    harness.appListeners.get('before-quit')!(quitEvent as never)
    await vi.waitFor(() => expect(harness.controller.dispose).toHaveBeenCalledOnce())
  })
})
