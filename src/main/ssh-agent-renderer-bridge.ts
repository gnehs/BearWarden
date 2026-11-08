import type { BrowserWindow, IpcMainInvokeEvent } from 'electron'
import type {
  SshAgentApprovalPrompt,
  SshAgentApprovalResponse,
  SshAgentStatus
} from '../shared/vault-contract'
import type {
  SshAgentRendererApprovalRequest,
  SshAgentRendererApprovalResult
} from './ssh-agent-coordinator'
import { exactRecord, publicInvalidInput } from './renderer-bridge-input'
import { handleIpc, isTrustedVaultSender, sendIpcEvent, type IpcDisposer } from './typed-ipc'

const DEFAULT_APPROVAL_TIMEOUT_MS = 60_000
const DEFAULT_MAX_PENDING_APPROVALS = 16
const MAX_REQUEST_ID_LENGTH = 128
const MAX_AUTHORIZATION_TOKEN_LENGTH = 128

interface PendingApproval {
  resolve: (result: SshAgentRendererApprovalResult) => void
  reject: (error: Error) => void
  timer: NodeJS.Timeout
  signal: AbortSignal
  onAbort: () => void
}

interface UnlockWaiter {
  resolve: (unlocked: boolean) => void
  signal: AbortSignal
  onAbort: () => void
}

export interface SshAgentRendererBridgeOptions {
  getMainWindow: () => BrowserWindow | null
  focusWindow: (window: BrowserWindow) => void | Promise<void>
  approvalTimeoutMs?: number
  maxPendingApprovals?: number
}

function abortError(): Error {
  const error = new Error('SSH_AGENT_RENDERER_REQUEST_ABORTED')
  error.name = 'AbortError'
  return error
}

function parseApprovalResponse(value: unknown): SshAgentApprovalResponse {
  const record = exactRecord(value, ['requestId', 'approved', 'authorizationToken'])
  if (
    typeof record.requestId !== 'string' ||
    record.requestId.length === 0 ||
    record.requestId.length > MAX_REQUEST_ID_LENGTH ||
    typeof record.approved !== 'boolean'
  ) {
    throw publicInvalidInput()
  }
  const authorizationToken = record.authorizationToken
  if (
    authorizationToken !== undefined &&
    (typeof authorizationToken !== 'string' ||
      authorizationToken.length === 0 ||
      authorizationToken.length > MAX_AUTHORIZATION_TOKEN_LENGTH)
  ) {
    throw publicInvalidInput()
  }
  if (!record.approved && authorizationToken !== undefined) throw publicInvalidInput()
  return {
    requestId: record.requestId,
    approved: record.approved,
    ...(authorizationToken === undefined ? {} : { authorizationToken })
  }
}

function rendererSafePrompt(
  request: SshAgentRendererApprovalRequest,
  expiresAt: number
): SshAgentApprovalPrompt {
  return {
    requestId: request.requestId,
    expiresAt,
    itemId: request.itemId,
    itemName: request.itemName,
    fingerprint: request.fingerprint,
    promptBehavior: request.promptBehavior,
    requiresAgentApproval: request.requiresAgentApproval,
    requiresReprompt: request.requiresReprompt,
    ...(request.processName === undefined ? {} : { processName: request.processName }),
    forwarded: request.forwarded,
    ...(request.hostFingerprint === undefined ? {} : { hostFingerprint: request.hostFingerprint }),
    ...(request.namespace === undefined ? {} : { namespace: request.namespace }),
    ...(request.rsaHash === undefined ? {} : { rsaHash: request.rsaHash })
  }
}

function cloneStatus(status: SshAgentStatus): SshAgentStatus {
  return {
    enabled: status.enabled,
    running: status.running,
    state: status.state,
    ...(status.endpoint === undefined ? {} : { endpoint: status.endpoint }),
    identityCount: status.identityCount,
    ...(status.lastError === undefined ? {} : { lastError: status.lastError })
  }
}

/**
 * The only SSH-agent bridge allowed to cross Electron's context-isolated boundary. It emits
 * explicitly selected public metadata and binds every one-shot response to the current main
 * frame. Private keys, public key blobs, and bytes-to-sign never enter this class's payloads.
 */
export class SshAgentRendererBridge {
  private readonly approvalTimeoutMs: number
  private readonly maxPendingApprovals: number
  private readonly pending = new Map<string, PendingApproval>()
  private readonly unlockWaiters = new Set<UnlockWaiter>()
  private statusValue: SshAgentStatus = {
    enabled: false,
    running: false,
    state: 'stopped',
    identityCount: 0
  }
  private attachedWindow: BrowserWindow | null = null
  private disposed = false
  private readonly ipcDisposers: IpcDisposer[]

  private readonly handleRendererReset = (): void => this.cancelAll()

  constructor(private readonly options: SshAgentRendererBridgeOptions) {
    this.approvalTimeoutMs = options.approvalTimeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS
    this.maxPendingApprovals = options.maxPendingApprovals ?? DEFAULT_MAX_PENDING_APPROVALS
    if (!Number.isSafeInteger(this.approvalTimeoutMs) || this.approvalTimeoutMs < 1) {
      throw new Error('INVALID_SSH_AGENT_APPROVAL_TIMEOUT')
    }
    if (!Number.isSafeInteger(this.maxPendingApprovals) || this.maxPendingApprovals < 1) {
      throw new Error('INVALID_SSH_AGENT_MAX_PENDING_APPROVALS')
    }

    this.ipcDisposers = [
      handleIpc('ssh-agent:status', (event, input) => {
        this.assertTrustedSender(event)
        if (input !== undefined) throw publicInvalidInput()
        return cloneStatus(this.statusValue)
      }),
      handleIpc('ssh-agent:respond-approval', (event, input) => {
        this.assertTrustedSender(event)
        this.respond(parseApprovalResponse(input))
      })
    ]
  }

  attachWindow(window: BrowserWindow): void {
    if (this.attachedWindow === window) return
    if (this.attachedWindow) this.cancelAll()
    this.detachWindow()
    this.attachedWindow = window
    window.webContents.on('did-start-loading', this.handleRendererReset)
    window.webContents.on('render-process-gone', this.handleRendererReset)
    window.webContents.on('destroyed', this.handleRendererReset)
  }

  updateStatus(status: SshAgentStatus): void {
    if (this.disposed) return
    this.statusValue = cloneStatus(status)
    const window = this.options.getMainWindow()
    if (!window || window.isDestroyed() || window.webContents.isDestroyed()) return
    sendIpcEvent(window.webContents, 'ssh-agent:status-changed', cloneStatus(this.statusValue))
  }

  async requestApproval(
    request: SshAgentRendererApprovalRequest,
    signal: AbortSignal
  ): Promise<SshAgentRendererApprovalResult> {
    if (this.disposed || signal.aborted) throw abortError()
    if (
      typeof request.requestId !== 'string' ||
      request.requestId.length === 0 ||
      request.requestId.length > MAX_REQUEST_ID_LENGTH ||
      this.pending.has(request.requestId) ||
      this.pending.size >= this.maxPendingApprovals
    ) {
      throw new Error('SSH_AGENT_APPROVAL_UNAVAILABLE')
    }
    const window = this.options.getMainWindow()
    if (!window || window.isDestroyed() || window.webContents.isDestroyed()) throw abortError()
    this.attachWindow(window)

    return new Promise<SshAgentRendererApprovalResult>((resolve, reject) => {
      const onAbort = (): void => this.rejectPending(request.requestId)
      const expiresAt = Date.now() + this.approvalTimeoutMs
      const timer = setTimeout(() => this.rejectPending(request.requestId), this.approvalTimeoutMs)
      timer.unref()
      this.pending.set(request.requestId, { resolve, reject, timer, signal, onAbort })
      signal.addEventListener('abort', onAbort, { once: true })

      Promise.resolve(this.options.focusWindow(window))
        .then(() => {
          if (!this.pending.has(request.requestId) || window.webContents.isDestroyed()) return
          sendIpcEvent(
            window.webContents,
            'ssh-agent:approval-requested',
            rendererSafePrompt(request, expiresAt)
          )
        })
        .catch(() => this.rejectPending(request.requestId))
    })
  }

  waitForUnlock(signal: AbortSignal): Promise<boolean> {
    if (this.disposed || signal.aborted) return Promise.reject(abortError())
    return new Promise<boolean>((resolve) => {
      const waiter: UnlockWaiter = {
        resolve,
        signal,
        onAbort: () => this.finishUnlockWaiter(waiter, false)
      }
      this.unlockWaiters.add(waiter)
      signal.addEventListener('abort', waiter.onAbort, { once: true })
    })
  }

  notifyUnlocked(): void {
    for (const waiter of [...this.unlockWaiters]) this.finishUnlockWaiter(waiter, true)
  }

  cancelAll(): void {
    for (const requestId of [...this.pending.keys()]) {
      this.rejectPending(requestId)
    }
    for (const waiter of [...this.unlockWaiters]) this.finishUnlockWaiter(waiter, false)
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.cancelAll()
    this.detachWindow()
    this.ipcDisposers.forEach((dispose) => dispose())
  }

  private assertTrustedSender(event: IpcMainInvokeEvent): void {
    if (this.disposed || !isTrustedVaultSender(event, this.options.getMainWindow())) {
      throw publicInvalidInput()
    }
  }

  private respond(response: SshAgentApprovalResponse): void {
    const pending = this.pending.get(response.requestId)
    if (!pending) throw publicInvalidInput()
    this.pending.delete(response.requestId)
    clearTimeout(pending.timer)
    pending.signal.removeEventListener('abort', pending.onAbort)
    pending.resolve({
      approved: response.approved,
      ...(response.authorizationToken === undefined
        ? {}
        : { authorizationToken: response.authorizationToken })
    })
  }

  private rejectPending(requestId: string): void {
    const pending = this.pending.get(requestId)
    if (!pending) return
    this.pending.delete(requestId)
    clearTimeout(pending.timer)
    pending.signal.removeEventListener('abort', pending.onAbort)
    pending.reject(abortError())
  }

  private finishUnlockWaiter(waiter: UnlockWaiter, result: boolean): void {
    if (!this.unlockWaiters.delete(waiter)) return
    waiter.signal.removeEventListener('abort', waiter.onAbort)
    waiter.resolve(result)
  }

  private detachWindow(): void {
    const window = this.attachedWindow
    this.attachedWindow = null
    if (!window || window.isDestroyed() || window.webContents.isDestroyed()) return
    window.webContents.removeListener('did-start-loading', this.handleRendererReset)
    window.webContents.removeListener('render-process-gone', this.handleRendererReset)
    window.webContents.removeListener('destroyed', this.handleRendererReset)
  }
}
