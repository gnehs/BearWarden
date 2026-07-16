import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const electronMock = vi.hoisted(() => {
  class FakeEmitter {
    private readonly listeners = new Map<string, Set<(...args: never[]) => void>>()

    on(event: string, listener: (...args: never[]) => void): this {
      const listeners = this.listeners.get(event) ?? new Set()
      listeners.add(listener)
      this.listeners.set(event, listeners)
      return this
    }

    removeListener(event: string, listener: (...args: never[]) => void): this {
      this.listeners.get(event)?.delete(listener)
      return this
    }

    emit(event: string, ...args: unknown[]): boolean {
      const listeners = [...(this.listeners.get(event) ?? [])]
      for (const listener of listeners) listener(...(args as never[]))
      return listeners.length > 0
    }
  }

  const state = {
    windows: [] as FakeBrowserWindow[],
    sessions: [] as FakeSession[],
    handlers: new Map<string, (event: unknown, value: unknown) => unknown>(),
    listeners: new Map<string, (event: unknown, value: unknown) => void>()
  }

  class FakeWebContents extends FakeEmitter {
    readonly mainFrame = { url: '' }
    openHandler: ((details: unknown) => unknown) | null = null

    getURL(): string {
      return this.mainFrame.url
    }

    setWindowOpenHandler(handler: (details: unknown) => unknown): void {
      this.openHandler = handler
    }
  }

  class FakeBrowserWindow extends FakeEmitter {
    readonly options: Record<string, unknown>
    readonly webContents = new FakeWebContents()
    readonly setContentProtection = vi.fn()
    readonly show = vi.fn()
    readonly focus = vi.fn()
    destroyed = false

    constructor(options: Record<string, unknown>) {
      super()
      this.options = options
      state.windows.push(this)
    }

    loadURL = vi.fn(async (url: string) => {
      this.webContents.mainFrame.url = url
    })

    isDestroyed(): boolean {
      return this.destroyed
    }

    destroy(): void {
      if (this.destroyed) return
      this.destroyed = true
      this.emit('closed')
    }
  }

  class FakeSession extends FakeEmitter {
    readonly partition: string
    readonly options: Record<string, unknown>
    permissionRequest:
      | ((webContents: unknown, permission: string, callback: (allowed: boolean) => void) => void)
      | null = null
    permissionCheck: (() => boolean) | null = null
    beforeRequest:
      ((details: Record<string, unknown>, callback: (result: unknown) => void) => void) | null =
      null
    headersReceived:
      ((details: Record<string, unknown>, callback: (result: unknown) => void) => void) | null =
      null
    readonly clearStorageData = vi.fn(async () => undefined)
    readonly clearCache = vi.fn(async () => undefined)
    readonly setPermissionRequestHandler = vi.fn(
      (
        handler: (
          webContents: unknown,
          permission: string,
          callback: (allowed: boolean) => void
        ) => void
      ) => {
        this.permissionRequest = handler
      }
    )
    readonly setPermissionCheckHandler = vi.fn((handler: () => boolean) => {
      this.permissionCheck = handler
    })
    readonly webRequest = {
      onBeforeRequest: vi.fn(
        (
          handler:
            ((details: Record<string, unknown>, callback: (result: unknown) => void) => void) | null
        ) => {
          this.beforeRequest = handler
        }
      ),
      onHeadersReceived: vi.fn(
        (
          handler:
            ((details: Record<string, unknown>, callback: (result: unknown) => void) => void) | null
        ) => {
          this.headersReceived = handler
        }
      )
    }

    constructor(partition: string, options: Record<string, unknown>) {
      super()
      this.partition = partition
      this.options = options
      state.sessions.push(this)
    }
  }

  return { ...state, FakeBrowserWindow, FakeSession }
})

vi.mock('electron', () => ({
  BrowserWindow: electronMock.FakeBrowserWindow,
  ipcMain: {
    handle: vi.fn((channel: string, handler: (event: unknown, value: unknown) => unknown) => {
      electronMock.handlers.set(channel, handler)
    }),
    on: vi.fn((channel: string, listener: (event: unknown, value: unknown) => void) => {
      electronMock.listeners.set(channel, listener)
    }),
    removeHandler: vi.fn((channel: string) => electronMock.handlers.delete(channel)),
    removeListener: vi.fn((channel: string, listener: unknown) => {
      if (electronMock.listeners.get(channel) === listener) electronMock.listeners.delete(channel)
    })
  },
  session: {
    fromPartition: vi.fn(
      (partition: string, options: Record<string, unknown>) =>
        new electronMock.FakeSession(partition, options)
    )
  }
}))

import {
  ACCOUNT_WEBAUTHN_REGISTRATION_CAPABILITY_ARGUMENT,
  ACCOUNT_WEBAUTHN_REGISTRATION_EPOCH_ARGUMENT,
  ACCOUNT_WEBAUTHN_REGISTRATION_EVENT_CHANNEL,
  ACCOUNT_WEBAUTHN_REGISTRATION_INIT_CHANNEL
} from './account-webauthn-registration-window-protocol'
import { AccountWebAuthnRegistrationWindowController } from './account-webauthn-registration-window'

const CAPABILITY = 'A'.repeat(43)
const controllers: AccountWebAuthnRegistrationWindowController[] = []

function registrationChallenge(): Record<string, unknown> {
  return {
    rp: { id: 'vault.example.com', name: 'Example Vault' },
    user: { id: Buffer.from('user').toString('base64url'), name: 'person', displayName: 'Person' },
    challenge: Buffer.alloc(32, 1).toString('base64url'),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    excludeCredentials: [],
    authenticatorSelection: {},
    attestation: 'none',
    extensions: {}
  }
}

function identity(window: InstanceType<typeof electronMock.FakeBrowserWindow>): {
  epoch: number
  capability: string
} {
  const preferences = window.options.webPreferences as { additionalArguments: string[] }
  const value = (prefix: string): string =>
    preferences.additionalArguments
      .find((argument) => argument.startsWith(prefix))!
      .slice(prefix.length)
  return {
    epoch: Number(value(ACCOUNT_WEBAUTHN_REGISTRATION_EPOCH_ARGUMENT)),
    capability: value(ACCOUNT_WEBAUTHN_REGISTRATION_CAPABILITY_ARGUMENT)
  }
}

beforeEach(() => {
  electronMock.windows.splice(0)
  electronMock.sessions.splice(0)
  electronMock.handlers.clear()
  electronMock.listeners.clear()
  vi.clearAllMocks()
})

afterEach(() => {
  for (const controller of controllers.splice(0)) controller.dispose()
})

describe('AccountWebAuthnRegistrationWindowController', () => {
  it('uses a focused hardened top-level window and exact ephemeral network boundary', async () => {
    const controller = new AccountWebAuthnRegistrationWindowController({
      randomToken: () => CAPABILITY
    })
    controllers.push(controller)
    const operation = controller.run({
      webVaultUrl: 'https://vault.example.com/',
      challenge: registrationChallenge()
    })
    const result = operation.catch((error) => error)
    const window = electronMock.windows[0]!
    const isolatedSession = electronMock.sessions[0]!
    const preferences = window.options.webPreferences as Record<string, unknown>

    expect(window.options.show).toBe(true)
    expect(window.show).toHaveBeenCalledOnce()
    expect(window.focus).toHaveBeenCalledOnce()
    expect(window.setContentProtection).toHaveBeenCalledWith(true)
    expect(preferences).toMatchObject({
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      webviewTag: false,
      devTools: false,
      javascript: true
    })
    expect(isolatedSession.partition).toBe('bearwarden-webauthn-registration-1')
    expect(isolatedSession.partition.startsWith('persist:')).toBe(false)

    let blocked: unknown
    isolatedSession.beforeRequest!(
      { resourceType: 'script', url: 'https://vault.example.com/app.js' },
      (result) => {
        blocked = result
      }
    )
    expect(blocked).toEqual({ cancel: true })
    expect(window.webContents.openHandler!({})).toEqual({ action: 'deny' })

    controller.cancel()
    await expect(result).resolves.toMatchObject({ code: 'CANCELLED' })
  })

  it('requires exact sender, frame, URL, epoch, and random capability before one-shot success', async () => {
    const controller = new AccountWebAuthnRegistrationWindowController({
      randomToken: () => CAPABILITY
    })
    controllers.push(controller)
    const operation = controller.run({
      webVaultUrl: 'https://vault.example.com/',
      challenge: registrationChallenge()
    })
    const window = electronMock.windows[0]!
    await window.loadURL.mock.results[0]!.value
    const exactIdentity = identity(window)
    const trusted = { sender: window.webContents, senderFrame: window.webContents.mainFrame }
    const init = electronMock.handlers.get(ACCOUNT_WEBAUTHN_REGISTRATION_INIT_CHANNEL)!

    expect(
      init({ sender: {}, senderFrame: window.webContents.mainFrame }, exactIdentity)
    ).toBeNull()
    const configuration = init(trusted, exactIdentity) as {
      connectorUrl: string
      challenge: unknown
    }
    expect(configuration.connectorUrl).toBe('https://vault.example.com/webauthn-connector.html')
    expect(configuration.challenge).toBeDefined()
    expect(init(trusted, exactIdentity)).toBeNull()

    const deliver = electronMock.listeners.get(ACCOUNT_WEBAUTHN_REGISTRATION_EVENT_CHANNEL)!
    const attestation = {
      id: Buffer.from('credential').toString('base64url'),
      rawId: Buffer.from('credential').toString('base64url'),
      type: 'public-key',
      response: {
        clientDataJSON: Buffer.from('{}').toString('base64url'),
        attestationObject: Buffer.from([1, 2, 3]).toString('base64url')
      },
      clientExtensionResults: {}
    }
    deliver(trusted, {
      ...exactIdentity,
      capability: 'B'.repeat(43),
      type: 'success',
      attestation
    })
    deliver(trusted, { ...exactIdentity, type: 'success', attestation })
    deliver(trusted, { ...exactIdentity, type: 'success', attestation })

    await expect(operation).resolves.toMatchObject({ id: attestation.id })
    expect(window.destroyed).toBe(true)
    expect(electronMock.sessions[0]!.clearStorageData).toHaveBeenCalledOnce()
    expect(electronMock.sessions[0]!.clearCache).toHaveBeenCalledOnce()
  })
})
