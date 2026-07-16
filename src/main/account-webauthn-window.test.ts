import { pathToFileURL } from 'node:url'
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
    ipcHandlers: new Map<string, (event: unknown, input: unknown) => unknown>(),
    ipcListeners: new Map<string, (event: unknown, input: unknown) => void>()
  }

  class FakeWebContents extends FakeEmitter {
    readonly id: number
    readonly mainFrame = { url: '' }
    windowOpenHandler: ((details: Record<string, unknown>) => Record<string, unknown>) | null = null

    constructor() {
      super()
      this.id = state.windows.length + 100
    }

    getURL(): string {
      return this.mainFrame.url
    }

    setWindowOpenHandler(
      handler: (details: Record<string, unknown>) => Record<string, unknown>
    ): void {
      this.windowOpenHandler = handler
    }
  }

  class FakeBrowserWindow extends FakeEmitter {
    readonly options: Record<string, unknown>
    readonly webContents = new FakeWebContents()
    readonly setContentProtection = vi.fn()
    destroyed = false

    constructor(options: Record<string, unknown> = {}) {
      super()
      this.options = options
      state.windows.push(this)
    }

    loadURL = vi.fn(async (url: string): Promise<void> => {
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

    closeFromUser(): void {
      this.destroy()
    }
  }

  class FakeSession extends FakeEmitter {
    readonly partition: string
    readonly options: Record<string, unknown>
    permissionRequestHandler:
      | ((webContents: unknown, permission: string, callback: (allowed: boolean) => void) => void)
      | null = null
    permissionCheckHandler: ((...args: unknown[]) => boolean) | null = null
    headersReceivedHandler:
      ((details: Record<string, unknown>, callback: (response: unknown) => void) => void) | null =
      null
    readonly setPermissionRequestHandler = vi.fn(
      (
        handler: (
          webContents: unknown,
          permission: string,
          callback: (allowed: boolean) => void
        ) => void
      ) => {
        this.permissionRequestHandler = handler
      }
    )
    readonly setPermissionCheckHandler = vi.fn((handler: (...args: unknown[]) => boolean) => {
      this.permissionCheckHandler = handler
    })
    readonly clearStorageData = vi.fn(async () => undefined)
    readonly clearCache = vi.fn(async () => undefined)
    readonly webRequest = {
      onHeadersReceived: vi.fn(
        (
          handler:
            | ((details: Record<string, unknown>, callback: (response: unknown) => void) => void)
            | null
        ) => {
          this.headersReceivedHandler = handler
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
    handle: vi.fn((channel: string, handler: (event: unknown, input: unknown) => unknown) => {
      electronMock.ipcHandlers.set(channel, handler)
    }),
    removeHandler: vi.fn((channel: string) => electronMock.ipcHandlers.delete(channel)),
    on: vi.fn((channel: string, listener: (event: unknown, input: unknown) => void) => {
      electronMock.ipcListeners.set(channel, listener)
    }),
    removeListener: vi.fn((channel: string, listener: unknown) => {
      if (electronMock.ipcListeners.get(channel) === listener)
        electronMock.ipcListeners.delete(channel)
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
  ACCOUNT_WEBAUTHN_CAPABILITY_ARGUMENT,
  ACCOUNT_WEBAUTHN_EPOCH_ARGUMENT,
  ACCOUNT_WEBAUTHN_WRAPPER_EVENT_CHANNEL,
  ACCOUNT_WEBAUTHN_WRAPPER_INIT_CHANNEL,
  type AccountWebAuthnWrapperConfiguration
} from './account-webauthn-window-protocol'
import { AccountWebAuthnWindowController } from './account-webauthn-window'
import { startAccountWebAuthnWrapper } from '../preload/account-webauthn-wrapper-runtime'

const WRAPPER_PATH = '/tmp/BearWarden/account-webauthn-wrapper.html'
const CAPABILITY = 'A'.repeat(43)
const CHALLENGE = Buffer.alloc(32, 0x31).toString('base64url')
const CREDENTIAL_ID = Buffer.alloc(32, 0x32).toString('base64url')
const CLIENT_DATA = Buffer.from('{"type":"webauthn.get"}').toString('base64url')
const AUTHENTICATOR_DATA = Buffer.alloc(37, 1).toString('base64url')
const SIGNATURE = Buffer.alloc(70, 2).toString('base64url')
const CHILD_FRAME_NAME = 'bearwarden-account-webauthn-connector'

type FakeWindow = InstanceType<typeof electronMock.FakeBrowserWindow>
type FakeSession = InstanceType<typeof electronMock.FakeSession>

function challenge(): Record<string, unknown> {
  return {
    challenge: CHALLENGE,
    rpId: 'vault.example.com',
    allowCredentials: [{ id: CREDENTIAL_ID, type: 'public-key' }],
    timeout: 60_000,
    userVerification: 'preferred',
    extensions: { uvm: true }
  }
}

function successMessage(): string {
  return `success|${JSON.stringify({
    id: CREDENTIAL_ID,
    rawId: CREDENTIAL_ID,
    type: 'public-key',
    extensions: { appid: false },
    response: {
      authenticatorData: AUTHENTICATOR_DATA,
      clientDataJson: CLIENT_DATA,
      signature: SIGNATURE
    }
  })}`
}

function argumentValue(wrapper: FakeWindow, prefix: string): string {
  const webPreferences = wrapper.options.webPreferences as { additionalArguments: string[] }
  return webPreferences.additionalArguments
    .find((argument) => argument.startsWith(prefix))!
    .slice(prefix.length)
}

function preventableEvent(): { preventDefault: ReturnType<typeof vi.fn> } {
  return { preventDefault: vi.fn() }
}

interface MainHarness {
  controller: AccountWebAuthnWindowController
  operation: Promise<unknown>
  wrapper: FakeWindow
  isolatedSession: FakeSession
  identity: { epoch: number; capability: string }
  trustedEvent: {
    sender: FakeWindow['webContents']
    senderFrame: FakeWindow['webContents']['mainFrame']
  }
}

const controllers: AccountWebAuthnWindowController[] = []

function createHarness(options: { timeoutMs?: number; signal?: AbortSignal } = {}): MainHarness {
  const windowIndex = electronMock.windows.length
  const sessionIndex = electronMock.sessions.length
  const controller = new AccountWebAuthnWindowController({
    wrapperFilePath: WRAPPER_PATH,
    randomToken: () => CAPABILITY,
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs })
  })
  controllers.push(controller)
  const operation = controller.run({
    webVaultUrl: 'https://vault.example.com/',
    challenge: challenge(),
    ...(options.signal === undefined ? {} : { signal: options.signal })
  })
  const wrapper = electronMock.windows[windowIndex]!
  const isolatedSession = electronMock.sessions[sessionIndex]!
  const identity = {
    epoch: Number(argumentValue(wrapper, ACCOUNT_WEBAUTHN_EPOCH_ARGUMENT)),
    capability: argumentValue(wrapper, ACCOUNT_WEBAUTHN_CAPABILITY_ARGUMENT)
  }
  return {
    controller,
    operation,
    wrapper,
    isolatedSession,
    identity,
    trustedEvent: { sender: wrapper.webContents, senderFrame: wrapper.webContents.mainFrame }
  }
}

function initialize(harness: MainHarness): AccountWebAuthnWrapperConfiguration {
  const init = electronMock.ipcHandlers.get(ACCOUNT_WEBAUTHN_WRAPPER_INIT_CHANNEL)!
  return init(harness.trustedEvent, harness.identity) as AccountWebAuthnWrapperConfiguration
}

function openConnectorChild(
  harness: MainHarness,
  config: AccountWebAuthnWrapperConfiguration
): FakeWindow {
  const open = harness.wrapper.webContents.windowOpenHandler!
  const decision = open({ url: config.connectorUrl, frameName: CHILD_FRAME_NAME }) as {
    action: string
    overrideBrowserWindowOptions: Record<string, unknown>
  }
  expect(decision.action).toBe('allow')
  const child = new electronMock.FakeBrowserWindow(decision.overrideBrowserWindowOptions)
  harness.wrapper.webContents.emit('did-create-window', child, {
    url: config.connectorUrl,
    frameName: CHILD_FRAME_NAME
  })
  return child
}

beforeEach(() => {
  electronMock.windows.splice(0)
  electronMock.sessions.splice(0)
  electronMock.ipcHandlers.clear()
  electronMock.ipcListeners.clear()
  vi.clearAllMocks()
})

afterEach(async () => {
  for (const controller of controllers.splice(0)) controller.dispose()
  await Promise.resolve()
  vi.useRealTimers()
})

describe('account WebAuthn wrapper preload', () => {
  it('authenticates the exact child WindowProxy, origin, parent, epoch, and capability locally', async () => {
    const wrapperUrl = pathToFileURL(WRAPPER_PATH).href
    const connectorUrl = `https://vault.example.com/webauthn-connector.html?${new URLSearchParams({
      v: '1',
      data: 'challenge-data',
      parent: wrapperUrl
    })}`
    const identity = { epoch: 4, capability: CAPABILITY }
    const child = {} as Window
    let messageListener: ((event: MessageEvent) => void) | null = null
    const wrapperWindow = {
      location: { href: wrapperUrl },
      addEventListener: vi.fn((_type: string, listener: (event: MessageEvent) => void) => {
        messageListener = listener
      }),
      removeEventListener: vi.fn(),
      open: vi.fn(() => child)
    }
    const ipc = {
      invoke: vi.fn(async () => ({
        ...identity,
        wrapperUrl,
        connectorUrl,
        connectorOrigin: 'https://vault.example.com'
      })),
      send: vi.fn()
    }

    const stop = await startAccountWebAuthnWrapper(ipc, wrapperWindow as never, identity)
    expect(wrapperWindow.open).toHaveBeenCalledWith(
      connectorUrl,
      CHILD_FRAME_NAME,
      'popup,width=520,height=680,resizable=yes'
    )

    messageListener!({
      source: {},
      origin: 'https://vault.example.com',
      data: 'info|ready'
    } as never)
    messageListener!({ source: child, origin: 'https://evil.example', data: 'info|ready' } as never)
    messageListener!({
      source: child,
      origin: 'https://vault.example.com',
      data: 'info|ready'
    } as never)
    messageListener!({
      source: child,
      origin: 'https://vault.example.com',
      data: 'info|ready'
    } as never)
    messageListener!({
      source: child,
      origin: 'https://vault.example.com',
      data: 'success|ok'
    } as never)
    messageListener!({
      source: child,
      origin: 'https://vault.example.com',
      data: 'error|late'
    } as never)

    expect(ipc.send).toHaveBeenCalledTimes(2)
    expect(ipc.send).toHaveBeenNthCalledWith(1, ACCOUNT_WEBAUTHN_WRAPPER_EVENT_CHANNEL, {
      ...identity,
      type: 'message',
      data: 'info|ready'
    })
    expect(ipc.send).toHaveBeenNthCalledWith(2, ACCOUNT_WEBAUTHN_WRAPPER_EVENT_CHANNEL, {
      ...identity,
      type: 'message',
      data: 'success|ok'
    })
    stop()
    expect(wrapperWindow.removeEventListener).toHaveBeenCalledWith('message', messageListener)
  })

  it('fails closed without opening when main does not bind the exact wrapper parent', async () => {
    const identity = { epoch: 4, capability: CAPABILITY }
    const wrapperUrl = pathToFileURL(WRAPPER_PATH).href
    const ipc = {
      invoke: vi.fn(async () => ({
        ...identity,
        wrapperUrl,
        connectorUrl:
          'https://vault.example.com/webauthn-connector.html?v=1&data=x&parent=file%3A%2F%2Fevil%2Fwrapper.html',
        connectorOrigin: 'https://vault.example.com'
      })),
      send: vi.fn()
    }
    const wrapperWindow = {
      location: { href: wrapperUrl },
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      open: vi.fn()
    }

    await startAccountWebAuthnWrapper(ipc, wrapperWindow as never, identity)

    expect(wrapperWindow.open).not.toHaveBeenCalled()
    expect(ipc.send).toHaveBeenCalledWith(ACCOUNT_WEBAUTHN_WRAPPER_EVENT_CHANNEL, {
      ...identity,
      type: 'cancel'
    })
  })
})

describe('AccountWebAuthnWindowController hardening', () => {
  it('uses hardened flags, an ephemeral partition, exact parent, and strict private IPC identity', async () => {
    const harness = createHarness()
    const { wrapper, isolatedSession, identity, trustedEvent } = harness
    const webPreferences = wrapper.options.webPreferences as Record<string, unknown>
    expect(webPreferences).toMatchObject({
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      nodeIntegrationInSubFrames: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      devTools: false
    })
    expect(isolatedSession.partition).toMatch(/^bearwarden-webauthn-1-/u)
    expect(isolatedSession.partition).not.toMatch(/^persist:/u)
    expect(isolatedSession.options).toEqual({ cache: false })

    const init = electronMock.ipcHandlers.get(ACCOUNT_WEBAUTHN_WRAPPER_INIT_CHANNEL)!
    expect(init({ sender: {}, senderFrame: trustedEvent.senderFrame }, identity)).toBeNull()
    expect(init({ sender: wrapper.webContents, senderFrame: {} }, identity)).toBeNull()
    expect(init(trustedEvent, { ...identity, epoch: identity.epoch + 1 })).toBeNull()
    expect(init(trustedEvent, { ...identity, capability: 'B'.repeat(43) })).toBeNull()
    const config = init(trustedEvent, identity) as AccountWebAuthnWrapperConfiguration
    expect(config.wrapperUrl).toBe(pathToFileURL(WRAPPER_PATH).href)
    expect(new URL(config.connectorUrl).searchParams.get('parent')).toBe(config.wrapperUrl)
    expect(new URL(config.connectorUrl).origin).toBe(config.connectorOrigin)
    expect(init(trustedEvent, identity)).toBeNull()

    let allowed: boolean | undefined
    isolatedSession.permissionRequestHandler!({}, 'notifications', (value) => {
      allowed = value
    })
    expect(allowed).toBe(false)
    expect(isolatedSession.permissionCheckHandler!()).toBe(false)
    const download = preventableEvent()
    isolatedSession.emit('will-download', download)
    expect(download.preventDefault).toHaveBeenCalledOnce()

    let headers: unknown
    isolatedSession.headersReceivedHandler!(
      { url: config.wrapperUrl, responseHeaders: { Existing: ['value'] } },
      (response) => {
        headers = response
      }
    )
    expect(headers).toMatchObject({
      responseHeaders: {
        Existing: ['value'],
        'Content-Security-Policy': [
          expect.stringContaining("script-src 'none'; connect-src 'none'")
        ]
      }
    })
    expect(JSON.stringify(headers)).toContain(`navigate-to ${config.connectorOrigin}`)

    harness.controller.cancel()
    await expect(harness.operation).rejects.toMatchObject({ code: 'CANCELLED' })
  })

  it('allows only the one exact connector child and denies navigation, webviews, and popups', async () => {
    const harness = createHarness()
    const config = initialize(harness)
    const open = harness.wrapper.webContents.windowOpenHandler!
    expect(open({ url: 'https://evil.example/', frameName: CHILD_FRAME_NAME })).toEqual({
      action: 'deny'
    })
    expect(open({ url: config.connectorUrl, frameName: 'wrong-frame' })).toEqual({ action: 'deny' })
    const child = openConnectorChild(harness, config)
    expect(open({ url: config.connectorUrl, frameName: CHILD_FRAME_NAME })).toEqual({
      action: 'deny'
    })

    const childPreferences = child.options.webPreferences as Record<string, unknown>
    expect(childPreferences).toMatchObject({
      partition: harness.isolatedSession.partition,
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      nodeIntegrationInSubFrames: false,
      webSecurity: true,
      webviewTag: false,
      devTools: false
    })

    for (const webContents of [harness.wrapper.webContents, child.webContents]) {
      const navigation = preventableEvent()
      webContents.emit('will-navigate', navigation, 'https://evil.example/')
      expect(navigation.preventDefault).toHaveBeenCalledOnce()
      const redirect = preventableEvent()
      webContents.emit('will-redirect', redirect, 'https://evil.example/')
      expect(redirect.preventDefault).toHaveBeenCalledOnce()
      const webview = preventableEvent()
      webContents.emit('will-attach-webview', webview)
      expect(webview.preventDefault).toHaveBeenCalledOnce()
    }
    expect(child.webContents.windowOpenHandler!({ url: 'https://evil.example/' })).toEqual({
      action: 'deny'
    })

    harness.controller.cancel()
    await expect(harness.operation).rejects.toMatchObject({ code: 'CANCELLED' })
  })

  it('settles once only after exact epoch/capability/sender/frame and ignores duplicate or late input', async () => {
    const harness = createHarness()
    const config = initialize(harness)
    openConnectorChild(harness, config)
    const deliver = electronMock.ipcListeners.get(ACCOUNT_WEBAUTHN_WRAPPER_EVENT_CHANNEL)!
    const terminal = successMessage()

    deliver(harness.trustedEvent, {
      ...harness.identity,
      epoch: harness.identity.epoch + 1,
      type: 'message',
      data: terminal
    })
    deliver(harness.trustedEvent, {
      ...harness.identity,
      capability: 'B'.repeat(43),
      type: 'message',
      data: terminal
    })
    deliver(
      { sender: {}, senderFrame: harness.trustedEvent.senderFrame },
      { ...harness.identity, type: 'message', data: terminal }
    )
    deliver(harness.trustedEvent, {
      ...harness.identity,
      type: 'message',
      data: 'info|ready'
    })
    deliver(harness.trustedEvent, {
      ...harness.identity,
      type: 'message',
      data: terminal
    })
    deliver(harness.trustedEvent, {
      ...harness.identity,
      type: 'message',
      data: 'error|late'
    })

    await expect(harness.operation).resolves.toMatchObject({ id: CREDENTIAL_ID })
    await vi.waitFor(() => expect(harness.wrapper.destroyed).toBe(true))
    expect(harness.isolatedSession.clearStorageData).toHaveBeenCalledOnce()
    expect(harness.isolatedSession.clearCache).toHaveBeenCalledOnce()
  })

  it.each([
    ['wrapper close', (harness: MainHarness) => harness.wrapper.closeFromUser()],
    [
      'child close',
      (harness: MainHarness) => {
        const config = initialize(harness)
        openConnectorChild(harness, config).closeFromUser()
      }
    ]
  ])('%s cancels the one-shot ceremony', async (_name, terminate) => {
    const harness = createHarness()
    const result = harness.operation.catch((error) => error)
    terminate(harness)
    await expect(result).resolves.toMatchObject({ code: 'CANCELLED' })
  })

  it('fails closed on renderer loss, timeout, abort, cancel, and dispose', async () => {
    vi.useFakeTimers()
    const gone = createHarness({ timeoutMs: 50 })
    const goneResult = gone.operation.catch((error) => error)
    gone.wrapper.webContents.emit('render-process-gone')
    await expect(goneResult).resolves.toMatchObject({ code: 'DISPOSED' })
    gone.controller.dispose()

    const timedOut = createHarness({ timeoutMs: 25 })
    const timeoutResult = timedOut.operation.catch((error) => error)
    await vi.advanceTimersByTimeAsync(25)
    await expect(timeoutResult).resolves.toMatchObject({ code: 'TIMEOUT' })
    timedOut.controller.dispose()

    const abort = new AbortController()
    const aborted = createHarness({ timeoutMs: 50, signal: abort.signal })
    const abortResult = aborted.operation.catch((error) => error)
    abort.abort()
    await expect(abortResult).resolves.toMatchObject({ code: 'ABORTED' })
    aborted.controller.dispose()

    const cancelled = createHarness({ timeoutMs: 50 })
    const cancelResult = cancelled.operation.catch((error) => error)
    cancelled.controller.cancel()
    await expect(cancelResult).resolves.toMatchObject({ code: 'CANCELLED' })
    cancelled.controller.dispose()

    const disposed = createHarness({ timeoutMs: 50 })
    const disposeResult = disposed.operation.catch((error) => error)
    disposed.controller.dispose()
    await expect(disposeResult).resolves.toMatchObject({ code: 'DISPOSED' })
    expect(electronMock.ipcHandlers.has(ACCOUNT_WEBAUTHN_WRAPPER_INIT_CHANNEL)).toBe(false)
    expect(electronMock.ipcListeners.has(ACCOUNT_WEBAUTHN_WRAPPER_EVENT_CHANNEL)).toBe(false)
  })
})
