import { randomBytes } from 'node:crypto'
import { join } from 'node:path'
import {
  BrowserWindow,
  ipcMain,
  session as electronSession,
  type IpcMainEvent,
  type IpcMainInvokeEvent,
  type Session
} from 'electron'
import {
  parseAccountWebAuthnRegistrationChallenge,
  serializeAccountWebAuthnAttestation,
  type AccountWebAuthnAttestation,
  type AccountWebAuthnRegistrationChallenge
} from './account-webauthn-registration-codec'
import {
  ACCOUNT_WEBAUTHN_REGISTRATION_CAPABILITY_ARGUMENT,
  ACCOUNT_WEBAUTHN_REGISTRATION_EPOCH_ARGUMENT,
  ACCOUNT_WEBAUTHN_REGISTRATION_EVENT_CHANNEL,
  ACCOUNT_WEBAUTHN_REGISTRATION_INIT_CHANNEL,
  type AccountWebAuthnRegistrationFailureReason,
  type AccountWebAuthnRegistrationWindowConfiguration,
  type AccountWebAuthnRegistrationWindowEvent,
  type AccountWebAuthnRegistrationWindowIdentity
} from './account-webauthn-registration-window-protocol'

const CAPABILITY_PATTERN = /^[A-Za-z0-9_-]{32,128}$/u
const CONNECTOR_PATH = '/webauthn-connector.html'
const MAX_WEB_VAULT_URL_LENGTH = 4_096
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1_000
const MAX_TIMEOUT_MS = 10 * 60 * 1_000
const CONNECTOR_CSP =
  "default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; media-src 'none'; font-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'; navigate-to 'none'; frame-ancestors 'none'"

export type AccountWebAuthnRegistrationWindowErrorCode =
  'INVALID_CONFIGURATION' | 'CEREMONY_FAILED' | 'TIMEOUT' | 'ABORTED' | 'CANCELLED' | 'DISPOSED'

/** Stable errors deliberately never echo the origin, challenge, credential, or remote content. */
export class AccountWebAuthnRegistrationWindowError extends Error {
  constructor(
    readonly code: AccountWebAuthnRegistrationWindowErrorCode,
    readonly reason?: AccountWebAuthnRegistrationFailureReason
  ) {
    super(`ACCOUNT_WEBAUTHN_REGISTRATION_${code}`)
    this.name = 'AccountWebAuthnRegistrationWindowError'
  }
}

export interface AccountWebAuthnRegistrationWindowRunOptions {
  readonly webVaultUrl: string
  readonly challenge: unknown
  readonly signal?: AbortSignal
}

export interface AccountWebAuthnRegistrationWindowControllerOptions {
  readonly timeoutMs?: number
  readonly randomToken?: () => string
}

interface ActiveRegistration {
  readonly epoch: number
  ipcCapability: string
  readonly connectorUrl: string
  readonly partition: string
  challenge: AccountWebAuthnRegistrationChallenge | null
  readonly isolatedSession: Session
  readonly window: BrowserWindow
  readonly resolve: (attestation: AccountWebAuthnAttestation) => void
  readonly reject: (error: AccountWebAuthnRegistrationWindowError) => void
  readonly handleDownload: (event: Electron.Event) => void
  readonly abortSignal: AbortSignal | undefined
  readonly handleAbort: () => void
  readonly timer: ReturnType<typeof setTimeout>
  initConsumed: boolean
  terminal: boolean
  cleaning: boolean
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

function parseIdentity(value: unknown): AccountWebAuthnRegistrationWindowIdentity | null {
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

function parseWindowEvent(value: unknown): AccountWebAuthnRegistrationWindowEvent | null {
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
    type === 'success'
      ? ['epoch', 'capability', 'type', 'attestation']
      : ['epoch', 'capability', 'type', 'reason']
  const record = strictRecord(value, keys)
  const identity = parseIdentity(
    record === null ? null : { epoch: record.epoch, capability: record.capability }
  )
  if (record === null || identity === null) return null
  if (record.type === 'success') {
    return { ...identity, type: 'success', attestation: record.attestation }
  }
  const allowedReasons = new Set<AccountWebAuthnRegistrationFailureReason>([
    'aborted',
    'invalid-state',
    'not-allowed',
    'not-supported',
    'security',
    'unknown'
  ])
  if (
    record.type !== 'failure' ||
    typeof record.reason !== 'string' ||
    !allowedReasons.has(record.reason as AccountWebAuthnRegistrationFailureReason)
  ) {
    return null
  }
  return {
    ...identity,
    type: 'failure',
    reason: record.reason as AccountWebAuthnRegistrationFailureReason
  }
}

function containsUnsafePathSyntax(raw: string): boolean {
  return /(?:^|\/)(?:\.{1,2})(?:\/|$)|%2e|%2f|%5c|\\/iu.test(raw)
}

function connectorUrlFor(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_WEB_VAULT_URL_LENGTH ||
    value.trim() !== value ||
    containsUnsafePathSyntax(value)
  ) {
    throw new AccountWebAuthnRegistrationWindowError('INVALID_CONFIGURATION')
  }
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new AccountWebAuthnRegistrationWindowError('INVALID_CONFIGURATION')
  }
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    url.pathname !== '/' ||
    url.search !== '' ||
    url.hash !== ''
  ) {
    throw new AccountWebAuthnRegistrationWindowError('INVALID_CONFIGURATION')
  }
  return `${url.origin}${CONNECTOR_PATH}`
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
    // The isolated preload needs JavaScript to call navigator.credentials.create(). The injected
    // CSP blocks every remote page script, while contextIsolation keeps the ceremony out of the
    // page world.
    javascript: true,
    images: false,
    plugins: false,
    experimentalFeatures: false,
    navigateOnDragDrop: false,
    spellcheck: false,
    disableDialogs: true,
    safeDialogs: true,
    backgroundThrottling: false,
    focusOnNavigation: true,
    additionalArguments: []
  }
}

function defaultRandomToken(): string {
  return randomBytes(32).toString('base64url')
}

function normalizeAttestation(value: unknown): AccountWebAuthnAttestation {
  const serialized = serializeAccountWebAuthnAttestation(value)
  const wire = JSON.parse(serialized) as {
    id: string
    rawId: string
    type: 'public-key'
    extensions: AccountWebAuthnAttestation['clientExtensionResults']
    response: { AttestationObject: string; clientDataJson: string }
  }
  const normalized: AccountWebAuthnAttestation = {
    id: wire.id,
    rawId: wire.rawId,
    type: wire.type,
    response: {
      clientDataJSON: wire.response.clientDataJson,
      attestationObject: wire.response.AttestationObject
    },
    clientExtensionResults: wire.extensions
  }
  if (serializeAccountWebAuthnAttestation(normalized) !== serialized) {
    throw new AccountWebAuthnRegistrationWindowError('CEREMONY_FAILED')
  }
  return Object.freeze({
    ...normalized,
    response: Object.freeze(normalized.response),
    clientExtensionResults: Object.freeze(normalized.clientExtensionResults)
  })
}

/**
 * Main-process-only owner for native credential creation. The primary renderer is never an IPC
 * participant and neither the challenge nor attestation is placed in a URL or page-world object.
 */
export class AccountWebAuthnRegistrationWindowController {
  private readonly timeoutMs: number
  private readonly randomToken: () => string
  private active: ActiveRegistration | null = null
  private epoch = 0
  private disposed = false

  constructor(options: AccountWebAuthnRegistrationWindowControllerOptions = {}) {
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
      throw new AccountWebAuthnRegistrationWindowError('INVALID_CONFIGURATION')
    }
    this.timeoutMs = timeoutMs
    this.randomToken = options.randomToken ?? defaultRandomToken
    ipcMain.handle(ACCOUNT_WEBAUTHN_REGISTRATION_INIT_CHANNEL, this.handleInit)
    ipcMain.on(ACCOUNT_WEBAUTHN_REGISTRATION_EVENT_CHANNEL, this.handleWindowEvent)
  }

  run(options: AccountWebAuthnRegistrationWindowRunOptions): Promise<AccountWebAuthnAttestation> {
    if (this.disposed) {
      return Promise.reject(new AccountWebAuthnRegistrationWindowError('DISPOSED'))
    }
    if (this.active !== null || this.epoch === Number.MAX_SAFE_INTEGER) {
      return Promise.reject(new AccountWebAuthnRegistrationWindowError('INVALID_CONFIGURATION'))
    }
    if (options.signal?.aborted) {
      return Promise.reject(new AccountWebAuthnRegistrationWindowError('ABORTED'))
    }

    let challenge: AccountWebAuthnRegistrationChallenge
    let connectorUrl: string
    let ipcCapability: string
    try {
      challenge = parseAccountWebAuthnRegistrationChallenge(options.challenge)
      connectorUrl = connectorUrlFor(options.webVaultUrl)
      ipcCapability = this.randomToken()
      if (!CAPABILITY_PATTERN.test(ipcCapability)) {
        throw new AccountWebAuthnRegistrationWindowError('INVALID_CONFIGURATION')
      }
    } catch {
      return Promise.reject(new AccountWebAuthnRegistrationWindowError('INVALID_CONFIGURATION'))
    }

    const epoch = ++this.epoch
    // Epochs are never reused by this controller, so the session stays unique without embedding
    // the IPC capability in a longer-lived partition identifier.
    const partition = `bearwarden-webauthn-registration-${epoch}`
    const handleDownload = (event: Electron.Event): void => event.preventDefault()
    let isolatedSession: Session | null = null
    try {
      isolatedSession = electronSession.fromPartition(partition, { cache: false })
      isolatedSession.setPermissionRequestHandler((_webContents, _permission, callback) => {
        callback(false)
      })
      isolatedSession.setPermissionCheckHandler(() => false)
      isolatedSession.on('will-download', handleDownload)
      isolatedSession.webRequest.onBeforeRequest((details, callback) => {
        callback({
          cancel: details.resourceType !== 'mainFrame' || details.url !== connectorUrl
        })
      })
      isolatedSession.webRequest.onHeadersReceived((details, callback) => {
        if (details.url !== connectorUrl || details.resourceType !== 'mainFrame') {
          callback({ cancel: true })
          return
        }
        const responseHeaders = Object.fromEntries(
          Object.entries(details.responseHeaders ?? {}).filter(
            ([name]) => name.toLowerCase() !== 'content-security-policy'
          )
        )
        callback({
          responseHeaders: {
            ...responseHeaders,
            'Content-Security-Policy': [CONNECTOR_CSP]
          }
        })
      })
    } catch {
      if (isolatedSession !== null) this.releaseIsolatedSession(isolatedSession, handleDownload)
      return Promise.reject(new AccountWebAuthnRegistrationWindowError('INVALID_CONFIGURATION'))
    }
    if (isolatedSession === null) {
      return Promise.reject(new AccountWebAuthnRegistrationWindowError('INVALID_CONFIGURATION'))
    }

    let registrationWindow: BrowserWindow
    try {
      registrationWindow = new BrowserWindow({
        width: 520,
        height: 680,
        show: true,
        title: 'BearWarden',
        backgroundColor: '#ffffff',
        frame: true,
        resizable: false,
        minimizable: false,
        maximizable: false,
        fullscreenable: false,
        autoHideMenuBar: true,
        webPreferences: {
          ...secureWebPreferences(partition),
          preload: join(__dirname, '../preload/account-webauthn-registration.js'),
          additionalArguments: [
            `${ACCOUNT_WEBAUTHN_REGISTRATION_EPOCH_ARGUMENT}${epoch}`,
            `${ACCOUNT_WEBAUTHN_REGISTRATION_CAPABILITY_ARGUMENT}${ipcCapability}`
          ]
        }
      })
    } catch {
      this.releaseIsolatedSession(isolatedSession, handleDownload)
      return Promise.reject(new AccountWebAuthnRegistrationWindowError('INVALID_CONFIGURATION'))
    }

    let resolve!: (attestation: AccountWebAuthnAttestation) => void
    let reject!: (error: AccountWebAuthnRegistrationWindowError) => void
    const result = new Promise<AccountWebAuthnAttestation>((resolvePromise, rejectPromise) => {
      resolve = resolvePromise
      reject = rejectPromise
    })
    const handleAbort = (): void => {
      const active = this.active
      if (active?.epoch === epoch) {
        this.finishFailure(active, new AccountWebAuthnRegistrationWindowError('ABORTED'))
      }
    }
    const timer = setTimeout(() => {
      const active = this.active
      if (active?.epoch === epoch) {
        this.finishFailure(active, new AccountWebAuthnRegistrationWindowError('TIMEOUT'))
      }
    }, this.timeoutMs)
    const active: ActiveRegistration = {
      epoch,
      ipcCapability,
      connectorUrl,
      partition,
      challenge,
      isolatedSession,
      window: registrationWindow,
      resolve,
      reject,
      handleDownload,
      abortSignal: options.signal,
      handleAbort,
      timer,
      initConsumed: false,
      terminal: false,
      cleaning: false
    }
    this.active = active
    options.signal?.addEventListener('abort', handleAbort, { once: true })
    // Close the check/listener race if the caller aborted while native resources were created.
    if (options.signal?.aborted) handleAbort()
    if (active.terminal) return result

    try {
      registrationWindow.setContentProtection(true)
      this.hardenWindow(active)
      registrationWindow.show()
      registrationWindow.focus()
      void registrationWindow.loadURL(connectorUrl).catch(() => {
        this.finishFailure(active, new AccountWebAuthnRegistrationWindowError('DISPOSED'))
      })
    } catch {
      this.finishFailure(active, new AccountWebAuthnRegistrationWindowError('DISPOSED'))
    }
    return result
  }

  cancel(): void {
    if (this.active !== null) {
      this.finishFailure(this.active, new AccountWebAuthnRegistrationWindowError('CANCELLED'))
    }
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    if (this.active !== null) {
      this.finishFailure(this.active, new AccountWebAuthnRegistrationWindowError('DISPOSED'))
    }
    ipcMain.removeHandler(ACCOUNT_WEBAUTHN_REGISTRATION_INIT_CHANNEL)
    ipcMain.removeListener(ACCOUNT_WEBAUTHN_REGISTRATION_EVENT_CHANNEL, this.handleWindowEvent)
  }

  private readonly handleInit = (
    event: IpcMainInvokeEvent,
    value: unknown
  ): AccountWebAuthnRegistrationWindowConfiguration | null => {
    const active = this.active
    const identity = parseIdentity(value)
    if (
      active === null ||
      active.initConsumed ||
      active.challenge === null ||
      identity === null ||
      !this.isTrustedEvent(event, active, identity)
    ) {
      return null
    }
    active.initConsumed = true
    const challenge = active.challenge
    active.challenge = null
    return {
      epoch: active.epoch,
      capability: active.ipcCapability,
      connectorUrl: active.connectorUrl,
      challenge
    }
  }

  private readonly handleWindowEvent = (event: IpcMainEvent, value: unknown): void => {
    const active = this.active
    const registrationEvent = parseWindowEvent(value)
    if (
      active === null ||
      !active.initConsumed ||
      registrationEvent === null ||
      !this.isTrustedEvent(event, active, registrationEvent)
    ) {
      return
    }
    if (registrationEvent.type === 'failure') {
      this.finishFailure(
        active,
        new AccountWebAuthnRegistrationWindowError('CEREMONY_FAILED', registrationEvent.reason)
      )
      return
    }
    try {
      this.finishSuccess(active, normalizeAttestation(registrationEvent.attestation))
    } catch {
      this.finishFailure(active, new AccountWebAuthnRegistrationWindowError('CEREMONY_FAILED'))
    }
  }

  private isTrustedEvent(
    event: IpcMainEvent | IpcMainInvokeEvent,
    active: ActiveRegistration,
    identity: AccountWebAuthnRegistrationWindowIdentity
  ): boolean {
    if (
      active.cleaning ||
      active.terminal ||
      identity.epoch !== active.epoch ||
      identity.capability !== active.ipcCapability ||
      active.window.isDestroyed() ||
      event.sender !== active.window.webContents ||
      event.senderFrame !== active.window.webContents.mainFrame ||
      event.senderFrame.url !== active.connectorUrl
    ) {
      return false
    }
    try {
      return event.sender.getURL() === active.connectorUrl
    } catch {
      return false
    }
  }

  private hardenWindow(active: ActiveRegistration): void {
    const { window } = active
    const preventNonExactNavigation = (event: Electron.Event, url: string): void => {
      if (url === active.connectorUrl) return
      event.preventDefault()
      this.finishFailure(active, new AccountWebAuthnRegistrationWindowError('DISPOSED'))
    }
    window.webContents.on('will-navigate', preventNonExactNavigation)
    window.webContents.on('will-redirect', preventNonExactNavigation)
    window.webContents.on('did-navigate-in-page', () => {
      this.finishFailure(active, new AccountWebAuthnRegistrationWindowError('DISPOSED'))
    })
    window.webContents.on('will-attach-webview', (event) => event.preventDefault())
    window.webContents.on('content-bounds-updated', (event) => event.preventDefault())
    window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))
    window.webContents.on('render-process-gone', () => {
      this.finishFailure(active, new AccountWebAuthnRegistrationWindowError('DISPOSED'))
    })
    window.webContents.on('unresponsive', () => {
      this.finishFailure(active, new AccountWebAuthnRegistrationWindowError('DISPOSED'))
    })
    window.webContents.on('did-finish-load', () => {
      if (this.active !== active || active.terminal || window.isDestroyed()) return
      try {
        if (
          window.webContents.getURL() !== active.connectorUrl ||
          window.webContents.mainFrame.url !== active.connectorUrl
        ) {
          this.finishFailure(active, new AccountWebAuthnRegistrationWindowError('DISPOSED'))
          return
        }
        // WebAuthn user verification requires a visible, focusable top-level document.
        window.show()
        window.focus()
      } catch {
        this.finishFailure(active, new AccountWebAuthnRegistrationWindowError('DISPOSED'))
      }
    })
    window.on('closed', () => {
      if (!active.cleaning) {
        this.finishFailure(active, new AccountWebAuthnRegistrationWindowError('CANCELLED'))
      }
    })
  }

  private finishSuccess(active: ActiveRegistration, attestation: AccountWebAuthnAttestation): void {
    if (active.terminal) return
    active.terminal = true
    this.cleanup(active)
    active.resolve(attestation)
  }

  private finishFailure(
    active: ActiveRegistration,
    error: AccountWebAuthnRegistrationWindowError
  ): void {
    if (active.terminal) return
    active.terminal = true
    this.cleanup(active)
    active.reject(error)
  }

  private cleanup(active: ActiveRegistration): void {
    if (active.cleaning) return
    active.cleaning = true
    if (this.active === active) this.active = null
    clearTimeout(active.timer)
    active.abortSignal?.removeEventListener('abort', active.handleAbort)
    active.challenge = null
    active.ipcCapability = ''
    try {
      active.isolatedSession.webRequest.onBeforeRequest(null)
      active.isolatedSession.webRequest.onHeadersReceived(null)
    } catch {
      // Continue fail-closed teardown if Electron has already released the session.
    }
    try {
      active.isolatedSession.removeListener('will-download', active.handleDownload)
    } catch {
      // Continue closing the native window.
    }
    try {
      if (!active.window.isDestroyed()) active.window.destroy()
    } catch {
      // Capabilities and challenge references have already been cleared.
    }
    this.clearIsolatedSession(active.isolatedSession)
  }

  private releaseIsolatedSession(
    isolatedSession: Session,
    handleDownload: (event: Electron.Event) => void
  ): void {
    try {
      isolatedSession.webRequest.onBeforeRequest(null)
      isolatedSession.webRequest.onHeadersReceived(null)
    } catch {
      // Best-effort listener release after failed BrowserWindow construction.
    }
    try {
      isolatedSession.removeListener('will-download', handleDownload)
    } catch {
      // Continue clearing the uniquely partitioned in-memory session.
    }
    this.clearIsolatedSession(isolatedSession)
  }

  private clearIsolatedSession(isolatedSession: Session): void {
    const operations: Promise<unknown>[] = []
    try {
      operations.push(isolatedSession.clearStorageData())
    } catch {
      // No reference to this in-memory partition is retained.
    }
    try {
      operations.push(isolatedSession.clearCache())
    } catch {
      // No reference to this in-memory partition is retained.
    }
    void Promise.allSettled(operations)
  }
}
