import { randomBytes } from 'node:crypto'
import { existsSync } from 'node:fs'
import { isAbsolute, join } from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  BrowserWindow,
  ipcMain,
  session as electronSession,
  type IpcMainEvent,
  type IpcMainInvokeEvent,
  type Session
} from 'electron'
import {
  AccountWebAuthnConnectorError,
  createAccountWebAuthnConnectorSession,
  type AccountWebAuthnConnectorSession
} from './account-webauthn-connector'
import type { AccountWebAuthnAssertion } from './account-webauthn-codec'
import {
  ACCOUNT_WEBAUTHN_CAPABILITY_ARGUMENT,
  ACCOUNT_WEBAUTHN_EPOCH_ARGUMENT,
  ACCOUNT_WEBAUTHN_WRAPPER_EVENT_CHANNEL,
  ACCOUNT_WEBAUTHN_WRAPPER_INIT_CHANNEL,
  type AccountWebAuthnWrapperConfiguration,
  type AccountWebAuthnWrapperEvent,
  type AccountWebAuthnWrapperIdentity
} from './account-webauthn-window-protocol'

const CAPABILITY_PATTERN = /^[A-Za-z0-9_-]{32,128}$/u
const CHILD_FRAME_NAME = 'bearwarden-account-webauthn-connector'
const WRAPPER_CSP_BASE =
  "default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; media-src 'none'; font-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"

export interface AccountWebAuthnWindowRunOptions {
  readonly webVaultUrl: string
  readonly challenge: unknown
  readonly signal?: AbortSignal
}

export interface AccountWebAuthnWindowControllerOptions {
  /** Absolute production renderer path; injectable only for deterministic tests. */
  readonly wrapperFilePath?: string
  readonly timeoutMs?: number
  readonly randomToken?: () => string
}

interface ActiveWindowSession {
  readonly epoch: number
  ipcCapability: string
  readonly partition: string
  readonly wrapperUrl: string
  connectorUrl: string
  readonly connectorOrigin: string
  sourceProof: object | null
  coreCapability: object | null
  readonly connector: AccountWebAuthnConnectorSession
  readonly isolatedSession: Session
  readonly wrapper: BrowserWindow
  child: BrowserWindow | null
  initConsumed: boolean
  popupConsumed: boolean
  cleaning: boolean
  readonly handleDownload: (event: Electron.Event) => void
}

function strictRecord(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
  try {
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) return null
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const ownKeys = Reflect.ownKeys(descriptors)
    if (
      ownKeys.length !== keys.length ||
      ownKeys.some(
        (key) => typeof key !== 'string' || !keys.includes(key) || !('value' in descriptors[key]!)
      )
    ) {
      return null
    }
    const snapshot = Object.create(null) as Record<string, unknown>
    for (const key of keys) snapshot[key] = descriptors[key]!.value
    return snapshot
  } catch {
    return null
  }
}

function parseIdentity(value: unknown): AccountWebAuthnWrapperIdentity | null {
  const record = strictRecord(value, ['epoch', 'capability'])
  if (
    record === null ||
    typeof record.epoch !== 'number' ||
    !Number.isSafeInteger(record.epoch) ||
    record.epoch < 0 ||
    typeof record.capability !== 'string' ||
    !CAPABILITY_PATTERN.test(record.capability)
  ) {
    return null
  }
  return { epoch: record.epoch, capability: record.capability }
}

function parseWrapperEvent(value: unknown): AccountWebAuthnWrapperEvent | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
  let type: unknown
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, 'type')
    if (!descriptor || !('value' in descriptor)) return null
    type = descriptor.value
  } catch {
    return null
  }
  const keys =
    type === 'message' ? ['epoch', 'capability', 'type', 'data'] : ['epoch', 'capability', 'type']
  const record = strictRecord(value, keys)
  if (
    record === null ||
    (record.type !== 'message' && record.type !== 'cancel') ||
    typeof record.epoch !== 'number' ||
    !Number.isSafeInteger(record.epoch) ||
    record.epoch < 0 ||
    typeof record.capability !== 'string' ||
    !CAPABILITY_PATTERN.test(record.capability)
  ) {
    return null
  }
  if (record.type === 'message') {
    if (typeof record.data !== 'string') return null
    return {
      epoch: record.epoch,
      capability: record.capability,
      type: 'message',
      data: record.data
    }
  }
  return { epoch: record.epoch, capability: record.capability, type: 'cancel' }
}

function preventNonExactNavigation(
  expectedUrl: string
): (event: Electron.Event, url: string) => void {
  return (event, url) => {
    if (url !== expectedUrl) event.preventDefault()
  }
}

function secureWebPreferences(partition: string): Electron.WebPreferences {
  return {
    partition,
    sandbox: true,
    contextIsolation: true,
    nodeIntegration: false,
    nodeIntegrationInWorker: false,
    nodeIntegrationInSubFrames: false,
    webSecurity: true,
    allowRunningInsecureContent: false,
    webviewTag: false,
    devTools: false,
    javascript: true,
    plugins: false,
    experimentalFeatures: false,
    navigateOnDragDrop: false,
    spellcheck: false,
    disableDialogs: true,
    additionalArguments: []
  }
}

function defaultRandomToken(): string {
  return randomBytes(32).toString('base64url')
}

function defaultWrapperFilePath(): string {
  const builtWrapper = join(__dirname, '../renderer/account-webauthn-wrapper.html')
  if (existsSync(builtWrapper)) return builtWrapper
  // electron-vite serves renderer entries from memory in development. This wrapper has no Vite
  // script imports, so loading the fixed source HTML preserves a local file:// parent there too.
  return join(__dirname, '../../src/renderer/account-webauthn-wrapper.html')
}

/**
 * Main-only controller for one native account WebAuthn connector ceremony at a time.
 * Challenge and assertion data are confined to this controller, its dedicated wrapper preload,
 * and the remote connector child; the primary BearWarden renderer is never an IPC participant.
 */
export class AccountWebAuthnWindowController {
  private readonly wrapperFilePath: string
  private readonly timeoutMs: number | undefined
  private readonly randomToken: () => string
  private active: ActiveWindowSession | null = null
  private epoch = 0
  private disposed = false

  constructor(options: AccountWebAuthnWindowControllerOptions = {}) {
    this.wrapperFilePath = options.wrapperFilePath ?? defaultWrapperFilePath()
    this.timeoutMs = options.timeoutMs
    this.randomToken = options.randomToken ?? defaultRandomToken
    if (!isAbsolute(this.wrapperFilePath)) {
      throw new AccountWebAuthnConnectorError('INVALID_CONFIGURATION')
    }
    ipcMain.handle(ACCOUNT_WEBAUTHN_WRAPPER_INIT_CHANNEL, this.handleInit)
    ipcMain.on(ACCOUNT_WEBAUTHN_WRAPPER_EVENT_CHANNEL, this.handleWrapperEvent)
  }

  run(options: AccountWebAuthnWindowRunOptions): Promise<AccountWebAuthnAssertion> {
    if (this.disposed) {
      return Promise.reject(new AccountWebAuthnConnectorError('DISPOSED'))
    }
    if (this.active !== null || this.epoch === Number.MAX_SAFE_INTEGER) {
      return Promise.reject(new AccountWebAuthnConnectorError('INVALID_CONFIGURATION'))
    }

    const ipcCapability = this.randomToken()
    if (!CAPABILITY_PATTERN.test(ipcCapability)) {
      return Promise.reject(new AccountWebAuthnConnectorError('INVALID_CONFIGURATION'))
    }
    const epoch = ++this.epoch
    const partition = `bearwarden-webauthn-${epoch}-${ipcCapability}`
    const wrapperUrl = pathToFileURL(this.wrapperFilePath).href
    const sourceProof = Object.freeze({})
    const coreCapability = Object.freeze({})
    const connector = createAccountWebAuthnConnectorSession({
      webVaultUrl: options.webVaultUrl,
      parentUrl: wrapperUrl,
      challenge: options.challenge,
      expectedSource: sourceProof,
      epoch,
      capability: coreCapability,
      ...(this.timeoutMs === undefined ? {} : { timeoutMs: this.timeoutMs }),
      ...(options.signal === undefined ? {} : { signal: options.signal })
    })
    if (!connector.active) return connector.result

    const connectorUrl = connector.connectorUrl!
    const connectorOrigin = connector.origin
    let isolatedSession: Session | null = null
    const handleDownload = (event: Electron.Event): void => event.preventDefault()
    try {
      isolatedSession = electronSession.fromPartition(partition, { cache: false })
      isolatedSession.setPermissionRequestHandler((_webContents, _permission, callback) => {
        callback(false)
      })
      isolatedSession.setPermissionCheckHandler(() => false)
      isolatedSession.on('will-download', handleDownload)

      const wrapperCsp = `${WRAPPER_CSP_BASE}; navigate-to ${connectorOrigin}`
      isolatedSession.webRequest.onHeadersReceived((details, callback) => {
        if (details.url === wrapperUrl) {
          callback({
            responseHeaders: {
              ...details.responseHeaders,
              'Content-Security-Policy': [wrapperCsp]
            }
          })
          return
        }
        callback({ responseHeaders: details.responseHeaders })
      })
    } catch {
      if (isolatedSession !== null) {
        this.releaseIsolatedSession(isolatedSession, handleDownload)
      }
      connector.dispose()
      return connector.result
    }
    if (isolatedSession === null) {
      connector.dispose()
      return connector.result
    }

    let wrapper: BrowserWindow
    try {
      wrapper = new BrowserWindow({
        width: 1,
        height: 1,
        show: false,
        frame: false,
        resizable: false,
        minimizable: false,
        maximizable: false,
        fullscreenable: false,
        skipTaskbar: true,
        autoHideMenuBar: true,
        webPreferences: {
          ...secureWebPreferences(partition),
          preload: join(__dirname, '../preload/account-webauthn-wrapper.js'),
          additionalArguments: [
            `${ACCOUNT_WEBAUTHN_EPOCH_ARGUMENT}${epoch}`,
            `${ACCOUNT_WEBAUTHN_CAPABILITY_ARGUMENT}${ipcCapability}`
          ]
        }
      })
    } catch {
      connector.dispose()
      this.releaseIsolatedSession(isolatedSession, handleDownload)
      return connector.result
    }

    const active: ActiveWindowSession = {
      epoch,
      ipcCapability,
      partition,
      wrapperUrl,
      connectorUrl,
      connectorOrigin,
      sourceProof,
      coreCapability,
      connector,
      isolatedSession,
      wrapper,
      child: null,
      initConsumed: false,
      popupConsumed: false,
      cleaning: false,
      handleDownload
    }
    this.active = active
    void connector.result.then(
      () => this.cleanup(active),
      () => this.cleanup(active)
    )
    try {
      wrapper.setContentProtection(true)
      this.hardenWrapper(active)
      void wrapper.loadURL(wrapperUrl).catch(() => connector.dispose())
    } catch {
      connector.dispose()
    }
    return connector.result
  }

  cancel(): void {
    this.active?.connector.cancel()
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.active?.connector.dispose()
    ipcMain.removeHandler(ACCOUNT_WEBAUTHN_WRAPPER_INIT_CHANNEL)
    ipcMain.removeListener(ACCOUNT_WEBAUTHN_WRAPPER_EVENT_CHANNEL, this.handleWrapperEvent)
  }

  private readonly handleInit = (
    event: IpcMainInvokeEvent,
    value: unknown
  ): AccountWebAuthnWrapperConfiguration | null => {
    const active = this.active
    const identity = parseIdentity(value)
    if (
      !active ||
      active.initConsumed ||
      !identity ||
      !this.isTrustedWrapperEvent(event, active, identity)
    ) {
      return null
    }
    active.initConsumed = true
    return {
      epoch: active.epoch,
      capability: active.ipcCapability,
      wrapperUrl: active.wrapperUrl,
      connectorUrl: active.connectorUrl,
      connectorOrigin: active.connectorOrigin
    }
  }

  private readonly handleWrapperEvent = (event: IpcMainEvent, value: unknown): void => {
    const active = this.active
    const wrapperEvent = parseWrapperEvent(value)
    if (
      !active ||
      !active.initConsumed ||
      !wrapperEvent ||
      !this.isTrustedWrapperEvent(event, active, wrapperEvent)
    ) {
      return
    }
    if (wrapperEvent.type === 'cancel') {
      active.connector.cancel()
      return
    }
    if (active.child === null || active.child.isDestroyed()) return
    active.connector.handleMessage(wrapperEvent.data, {
      origin: active.connectorOrigin,
      source: active.sourceProof!,
      epoch: active.epoch,
      capability: active.coreCapability!
    })
  }

  private isTrustedWrapperEvent(
    event: IpcMainEvent | IpcMainInvokeEvent,
    active: ActiveWindowSession,
    identity: AccountWebAuthnWrapperIdentity
  ): boolean {
    if (
      active.cleaning ||
      identity.epoch !== active.epoch ||
      identity.capability !== active.ipcCapability ||
      active.wrapper.isDestroyed() ||
      event.sender !== active.wrapper.webContents ||
      event.senderFrame !== active.wrapper.webContents.mainFrame ||
      event.senderFrame.url !== active.wrapperUrl
    ) {
      return false
    }
    try {
      return event.sender.getURL() === active.wrapperUrl
    } catch {
      return false
    }
  }

  private hardenWrapper(active: ActiveWindowSession): void {
    const { wrapper, connectorUrl, partition } = active
    const preventWrapperNavigation = preventNonExactNavigation(active.wrapperUrl)
    wrapper.webContents.on('will-navigate', preventWrapperNavigation)
    wrapper.webContents.on('will-redirect', preventWrapperNavigation)
    wrapper.webContents.on('will-attach-webview', (event) => event.preventDefault())
    wrapper.webContents.on('render-process-gone', () => active.connector.dispose())
    wrapper.on('closed', () => {
      if (!active.cleaning) active.connector.cancel()
    })

    wrapper.webContents.setWindowOpenHandler((details) => {
      if (
        active.cleaning ||
        !active.connector.active ||
        active.popupConsumed ||
        details.url !== connectorUrl ||
        details.frameName !== CHILD_FRAME_NAME
      ) {
        return { action: 'deny' }
      }
      active.popupConsumed = true
      return {
        action: 'allow',
        outlivesOpener: false,
        overrideBrowserWindowOptions: {
          width: 520,
          height: 680,
          show: true,
          autoHideMenuBar: true,
          fullscreenable: false,
          webPreferences: secureWebPreferences(partition)
        }
      }
    })

    wrapper.webContents.on('did-create-window', (child, details) => {
      if (
        active.cleaning ||
        !active.connector.active ||
        !active.popupConsumed ||
        active.child !== null ||
        details.url !== connectorUrl ||
        details.frameName !== CHILD_FRAME_NAME
      ) {
        child.destroy()
        active.connector.dispose()
        return
      }
      active.child = child
      child.setContentProtection(true)
      const preventChildNavigation = preventNonExactNavigation(connectorUrl)
      child.webContents.on('will-navigate', preventChildNavigation)
      child.webContents.on('will-redirect', preventChildNavigation)
      child.webContents.on('will-attach-webview', (event) => event.preventDefault())
      child.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))
      child.webContents.on('render-process-gone', () => active.connector.dispose())
      child.on('closed', () => {
        if (!active.cleaning) active.connector.cancel()
      })
    })
  }

  private cleanup(active: ActiveWindowSession): void {
    if (active.cleaning) return
    active.cleaning = true
    if (this.active === active) this.active = null
    active.sourceProof = null
    active.coreCapability = null
    active.ipcCapability = ''
    active.connectorUrl = ''
    try {
      active.isolatedSession.webRequest.onHeadersReceived(null)
    } catch {
      // Continue fail-closed teardown even if Electron has already released the session.
    }
    try {
      active.isolatedSession.removeListener('will-download', active.handleDownload)
    } catch {
      // Continue closing both native windows.
    }
    try {
      if (active.child && !active.child.isDestroyed()) active.child.destroy()
    } catch {
      // Continue closing the wrapper.
    }
    try {
      if (!active.wrapper.isDestroyed()) active.wrapper.destroy()
    } catch {
      // The connector is already terminal and all capabilities have been cleared.
    }
    this.clearIsolatedSession(active.isolatedSession)
  }

  private releaseIsolatedSession(
    isolatedSession: Session,
    handleDownload: (event: Electron.Event) => void
  ): void {
    try {
      isolatedSession.webRequest.onHeadersReceived(null)
    } catch {
      // Best-effort listener release for a failed BrowserWindow construction.
    }
    try {
      isolatedSession.removeListener('will-download', handleDownload)
    } catch {
      // Continue clearing in-memory storage.
    }
    this.clearIsolatedSession(isolatedSession)
  }

  private clearIsolatedSession(isolatedSession: Session): void {
    const operations: Promise<unknown>[] = []
    try {
      operations.push(isolatedSession.clearStorageData())
    } catch {
      // Session is in-memory and uniquely partitioned; no reference is retained.
    }
    try {
      operations.push(isolatedSession.clearCache())
    } catch {
      // Session is in-memory and uniquely partitioned; no reference is retained.
    }
    void Promise.allSettled(operations)
  }
}
