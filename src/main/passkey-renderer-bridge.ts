import { ipcMain, type BrowserWindow, type IpcMainInvokeEvent } from 'electron'
import {
  IPC_CHANNELS,
  IPC_ERROR_PREFIX,
  IPC_EVENTS,
  type PasskeyApprovalPrompt,
  type PasskeyApprovalResponse,
  type PasskeyApprovalVerificationRequest,
  type PasskeyVerificationMethod
} from '../shared/vault-contract'
import type { PasskeyRendererSafePrompt } from './passkey-request-coordinator'
import { isTrustedVaultSender } from './vault-ipc'

const DEFAULT_APPROVAL_TIMEOUT_MS = 60_000
const DEFAULT_MAX_PENDING_APPROVALS = 16
const MAX_REQUEST_ID_LENGTH = 128
const MAX_CHOICE_ID_LENGTH = 128
const MAX_MASTER_PASSWORD_LENGTH = 1_024

type AvailableVerificationMethod = Exclude<PasskeyVerificationMethod, 'none'>

interface PendingApproval {
  prompt: PasskeyApprovalPrompt
  resolve: (result: PasskeyApprovalResponse) => void
  reject: (error: Error) => void
  timer: NodeJS.Timeout
  signal: AbortSignal
  onAbort: () => void
  verifyingPassword: boolean
}

interface MasterPasswordProof {
  senderId: number
  selectedChoiceId: string | undefined
  generation: number
  expiresAt: number
  timer: NodeJS.Timeout
}

export interface PasskeyRendererBridgeOptions {
  getMainWindow: () => BrowserWindow | null
  focusWindow: (window: BrowserWindow) => void | Promise<void>
  getVerificationMethods: () =>
    readonly AvailableVerificationMethod[] | Promise<readonly AvailableVerificationMethod[]>
  verifyMasterPassword: (
    requestId: string,
    selectedChoiceId: string | undefined,
    masterPassword: string,
    signal: AbortSignal
  ) => Promise<number>
  approvalTimeoutMs?: number
  maxPendingApprovals?: number
  now?: () => number
}

export interface PasskeyPasswordProofBinding {
  requestId: string
  selectedChoiceId?: string
  vaultGeneration: number
}

function abortError(): Error {
  const error = new Error('PASSKEY_RENDERER_REQUEST_ABORTED')
  error.name = 'AbortError'
  return error
}

function publicInvalidInput(): Error {
  return new Error(`${IPC_ERROR_PREFIX}INVALID_INPUT`)
}

function exactRecord(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw publicInvalidInput()
  }
  const record = value as Record<string, unknown>
  if (Object.keys(record).some((key) => !allowed.includes(key))) throw publicInvalidInput()
  return record
}

function boundedString(value: unknown, maximumLength: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maximumLength
}

function parseApprovalResponse(value: unknown): PasskeyApprovalResponse {
  const record = exactRecord(value, [
    'requestId',
    'approved',
    'selectedChoiceId',
    'verificationMethod'
  ])
  if (
    !boundedString(record.requestId, MAX_REQUEST_ID_LENGTH) ||
    typeof record.approved !== 'boolean' ||
    (record.selectedChoiceId !== undefined &&
      !boundedString(record.selectedChoiceId, MAX_CHOICE_ID_LENGTH)) ||
    (record.verificationMethod !== undefined &&
      record.verificationMethod !== 'none' &&
      record.verificationMethod !== 'touch-id' &&
      record.verificationMethod !== 'master-password')
  ) {
    throw publicInvalidInput()
  }
  if (
    !record.approved &&
    (record.selectedChoiceId !== undefined || record.verificationMethod !== undefined)
  ) {
    throw publicInvalidInput()
  }
  return {
    requestId: record.requestId,
    approved: record.approved,
    ...(record.selectedChoiceId === undefined ? {} : { selectedChoiceId: record.selectedChoiceId }),
    ...(record.verificationMethod === undefined
      ? {}
      : { verificationMethod: record.verificationMethod })
  }
}

function parseVerificationRequest(value: unknown): PasskeyApprovalVerificationRequest {
  const record = exactRecord(value, ['requestId', 'selectedChoiceId', 'masterPassword'])
  if (
    !boundedString(record.requestId, MAX_REQUEST_ID_LENGTH) ||
    (record.selectedChoiceId !== undefined &&
      !boundedString(record.selectedChoiceId, MAX_CHOICE_ID_LENGTH)) ||
    typeof record.masterPassword !== 'string' ||
    record.masterPassword.length === 0 ||
    record.masterPassword.length > MAX_MASTER_PASSWORD_LENGTH
  ) {
    throw publicInvalidInput()
  }
  return {
    requestId: record.requestId,
    ...(record.selectedChoiceId === undefined ? {} : { selectedChoiceId: record.selectedChoiceId }),
    masterPassword: record.masterPassword
  }
}

function validMethods(
  value: readonly AvailableVerificationMethod[]
): AvailableVerificationMethod[] {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.length > 2 ||
    new Set(value).size !== value.length ||
    value.some((method) => method !== 'touch-id' && method !== 'master-password')
  ) {
    throw new Error('PASSKEY_VERIFICATION_METHODS_UNAVAILABLE')
  }
  return [...value]
}

function rendererSafePrompt(
  request: PasskeyRendererSafePrompt,
  expiresAt: number,
  verificationMethods: readonly AvailableVerificationMethod[]
): PasskeyApprovalPrompt {
  return Object.freeze({
    requestId: request.requestId,
    expiresAt,
    kind: request.kind,
    rpId: request.rpId,
    rpName: request.rpName,
    userVerification: request.userVerification,
    choices: Object.freeze(
      request.choices.map((choice) =>
        Object.freeze({
          id: choice.id,
          label: choice.label,
          ...(choice.detail === undefined ? {} : { detail: choice.detail }),
          requiresReprompt: choice.requiresReprompt === true
        })
      )
    ),
    verificationMethods: Object.freeze([...verificationMethods]),
    ...(request.userName === undefined ? {} : { userName: request.userName }),
    ...(request.userDisplayName === undefined ? {} : { userDisplayName: request.userDisplayName })
  })
}

/**
 * Renderer-only consent bridge. It cannot start a WebAuthn ceremony and never receives protocol
 * bytes. Master-password proof is held in main, bound to one request and renderer, and consumed
 * separately by the coordinator's main-only verifier callback.
 */
export class PasskeyRendererBridge {
  private readonly approvalTimeoutMs: number
  private readonly maxPendingApprovals: number
  private readonly now: () => number
  private readonly pending = new Map<string, PendingApproval>()
  private readonly reservedRequestIds = new Set<string>()
  private readonly passwordProofs = new Map<string, MasterPasswordProof>()
  private attachedWindow: BrowserWindow | null = null
  private rendererEpoch = 0
  private disposed = false

  private readonly handleRendererReset = (): void => this.cancelAll()

  constructor(private readonly options: PasskeyRendererBridgeOptions) {
    this.approvalTimeoutMs = options.approvalTimeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS
    this.maxPendingApprovals = options.maxPendingApprovals ?? DEFAULT_MAX_PENDING_APPROVALS
    this.now = options.now ?? Date.now
    if (!Number.isSafeInteger(this.approvalTimeoutMs) || this.approvalTimeoutMs < 1) {
      throw new Error('INVALID_PASSKEY_APPROVAL_TIMEOUT')
    }
    if (!Number.isSafeInteger(this.maxPendingApprovals) || this.maxPendingApprovals < 1) {
      throw new Error('INVALID_PASSKEY_MAX_PENDING_APPROVALS')
    }

    ipcMain.handle(IPC_CHANNELS.passkeyVerifyApproval, async (event, input) => {
      try {
        await this.verifyApproval(event, parseVerificationRequest(input))
      } catch {
        throw publicInvalidInput()
      }
    })
    ipcMain.handle(IPC_CHANNELS.passkeyRespondApproval, (event, input) => {
      try {
        this.assertTrustedSender(event)
        this.respond(event, parseApprovalResponse(input))
      } catch {
        throw publicInvalidInput()
      }
    })
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

  async requestConsent(
    request: PasskeyRendererSafePrompt,
    signal: AbortSignal
  ): Promise<PasskeyApprovalResponse> {
    if (this.disposed || signal.aborted) throw abortError()
    if (
      !boundedString(request.requestId, MAX_REQUEST_ID_LENGTH) ||
      this.pending.has(request.requestId) ||
      this.reservedRequestIds.has(request.requestId) ||
      this.passwordProofs.has(request.requestId) ||
      this.pending.size + this.reservedRequestIds.size >= this.maxPendingApprovals
    ) {
      throw new Error('PASSKEY_APPROVAL_UNAVAILABLE')
    }
    const window = this.options.getMainWindow()
    if (!window || window.isDestroyed() || window.webContents.isDestroyed()) throw abortError()
    this.attachWindow(window)
    const rendererEpoch = this.rendererEpoch

    this.reservedRequestIds.add(request.requestId)
    let methods: AvailableVerificationMethod[]
    try {
      const needsReprompt = request.choices.some((choice) => choice.requiresReprompt === true)
      methods =
        request.userVerification === 'discouraged'
          ? needsReprompt
            ? ['master-password']
            : []
          : validMethods(await this.options.getVerificationMethods())
    } finally {
      this.reservedRequestIds.delete(request.requestId)
    }
    if (
      this.disposed ||
      signal.aborted ||
      window.webContents.isDestroyed() ||
      rendererEpoch !== this.rendererEpoch
    ) {
      throw abortError()
    }
    if (this.pending.has(request.requestId) || this.passwordProofs.has(request.requestId)) {
      throw new Error('PASSKEY_APPROVAL_UNAVAILABLE')
    }
    const now = this.now()
    if (!Number.isSafeInteger(request.expiresAt) || request.expiresAt <= now) throw abortError()
    const expiresAt = Math.min(request.expiresAt, now + this.approvalTimeoutMs)
    const timeoutMs = expiresAt - now
    const prompt = rendererSafePrompt(request, expiresAt, methods)

    return new Promise<PasskeyApprovalResponse>((resolve, reject) => {
      const onAbort = (): void => this.rejectPending(request.requestId, abortError())
      const timer = setTimeout(() => this.rejectPending(request.requestId, abortError()), timeoutMs)
      timer.unref()
      this.pending.set(request.requestId, {
        prompt,
        resolve,
        reject,
        timer,
        signal,
        onAbort,
        verifyingPassword: false
      })
      signal.addEventListener('abort', onAbort, { once: true })

      Promise.resolve(this.options.focusWindow(window))
        .then(() => {
          if (!this.pending.has(request.requestId) || window.webContents.isDestroyed()) return
          window.webContents.send(IPC_EVENTS.passkeyApprovalRequested, prompt)
        })
        .catch(() => this.rejectPending(request.requestId, abortError()))
    })
  }

  /** Checks proof for WebAuthn UV without consuming a proof still needed by item reprompt. */
  validateMasterPasswordProof(request: PasskeyPasswordProofBinding): boolean {
    return this.matchesMasterPasswordProof(request, false)
  }

  /** Consumes one request-bound proof at the atomic Vault reprompt boundary. */
  consumeMasterPasswordProof(request: PasskeyPasswordProofBinding): boolean {
    return this.matchesMasterPasswordProof(request, true)
  }

  discardMasterPasswordProof(requestId: string): void {
    this.deleteProof(requestId)
  }

  private matchesMasterPasswordProof(
    request: PasskeyPasswordProofBinding,
    consume: boolean
  ): boolean {
    const proof = this.passwordProofs.get(request.requestId)
    if (!proof) return false
    if (consume) this.deleteProof(request.requestId)
    const window = this.options.getMainWindow()
    return Boolean(
      !this.disposed &&
      proof.expiresAt > this.now() &&
      window &&
      !window.isDestroyed() &&
      !window.webContents.isDestroyed() &&
      proof.senderId === window.webContents.id &&
      proof.selectedChoiceId === request.selectedChoiceId &&
      proof.generation === request.vaultGeneration
    )
  }

  cancelAll(): void {
    this.rendererEpoch += 1
    for (const requestId of [...this.pending.keys()]) {
      this.rejectPending(requestId, abortError())
    }
    for (const requestId of [...this.passwordProofs.keys()]) this.deleteProof(requestId)
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.cancelAll()
    this.detachWindow()
    ipcMain.removeHandler(IPC_CHANNELS.passkeyVerifyApproval)
    ipcMain.removeHandler(IPC_CHANNELS.passkeyRespondApproval)
  }

  private assertTrustedSender(event: IpcMainInvokeEvent): void {
    if (this.disposed || !isTrustedVaultSender(event, this.options.getMainWindow())) {
      throw publicInvalidInput()
    }
  }

  private async verifyApproval(
    event: IpcMainInvokeEvent,
    request: PasskeyApprovalVerificationRequest
  ): Promise<void> {
    this.assertTrustedSender(event)
    const pending = this.pending.get(request.requestId)
    if (
      !pending ||
      pending.verifyingPassword ||
      pending.signal.aborted ||
      !pending.prompt.verificationMethods.includes('master-password') ||
      pending.prompt.expiresAt <= this.now() ||
      !this.validSelectedChoice(pending.prompt, request.selectedChoiceId) ||
      (pending.prompt.userVerification === 'discouraged' &&
        !this.selectedChoiceRequiresReprompt(pending.prompt, request.selectedChoiceId))
    ) {
      throw publicInvalidInput()
    }
    pending.verifyingPassword = true
    try {
      const generation = await this.options.verifyMasterPassword(
        request.requestId,
        request.selectedChoiceId,
        request.masterPassword,
        pending.signal
      )
      if (
        this.pending.get(request.requestId) !== pending ||
        pending.signal.aborted ||
        !Number.isSafeInteger(generation) ||
        generation < 0
      ) {
        throw publicInvalidInput()
      }
      this.deleteProof(request.requestId)
      const proofTimer = setTimeout(
        () => this.deleteProof(request.requestId),
        Math.max(1, pending.prompt.expiresAt - this.now())
      )
      proofTimer.unref()
      this.passwordProofs.set(request.requestId, {
        senderId: event.sender.id,
        selectedChoiceId: request.selectedChoiceId,
        generation,
        expiresAt: pending.prompt.expiresAt,
        timer: proofTimer
      })
    } finally {
      if (this.pending.get(request.requestId) === pending) pending.verifyingPassword = false
    }
  }

  private validSelectedChoice(
    prompt: PasskeyApprovalPrompt,
    selectedChoiceId: string | undefined
  ): boolean {
    return prompt.choices.length === 0
      ? selectedChoiceId === undefined
      : selectedChoiceId !== undefined &&
          prompt.choices.some((choice) => choice.id === selectedChoiceId)
  }

  private selectedChoiceRequiresReprompt(
    prompt: PasskeyApprovalPrompt,
    selectedChoiceId: string | undefined
  ): boolean {
    return prompt.choices.some(
      (choice) => choice.id === selectedChoiceId && choice.requiresReprompt
    )
  }

  private respond(event: IpcMainInvokeEvent, response: PasskeyApprovalResponse): void {
    const pending = this.pending.get(response.requestId)
    if (
      !pending ||
      pending.verifyingPassword ||
      pending.prompt.expiresAt <= this.now() ||
      event.sender.id !== this.attachedWindow?.webContents.id
    ) {
      throw publicInvalidInput()
    }
    if (!response.approved) {
      this.deleteProof(response.requestId)
      this.resolvePending(pending, response)
      return
    }
    const choices = pending.prompt.choices
    if (
      (choices.length === 0 && response.selectedChoiceId !== undefined) ||
      (choices.length > 0 &&
        (response.selectedChoiceId === undefined ||
          !choices.some((choice) => choice.id === response.selectedChoiceId)))
    ) {
      throw publicInvalidInput()
    }
    const method = response.verificationMethod ?? 'none'
    if (pending.prompt.userVerification === 'discouraged') {
      if (method !== 'none') throw publicInvalidInput()
      if (this.selectedChoiceRequiresReprompt(pending.prompt, response.selectedChoiceId)) {
        const proof = this.passwordProofs.get(response.requestId)
        if (!proof || proof.selectedChoiceId !== response.selectedChoiceId) {
          throw publicInvalidInput()
        }
      } else {
        this.deleteProof(response.requestId)
      }
    } else {
      if (method === 'none' || !pending.prompt.verificationMethods.includes(method)) {
        throw publicInvalidInput()
      }
      if (method === 'master-password') {
        const proof = this.passwordProofs.get(response.requestId)
        if (!proof || proof.selectedChoiceId !== response.selectedChoiceId) {
          throw publicInvalidInput()
        }
      } else {
        if (this.selectedChoiceRequiresReprompt(pending.prompt, response.selectedChoiceId)) {
          const proof = this.passwordProofs.get(response.requestId)
          if (!proof || proof.selectedChoiceId !== response.selectedChoiceId) {
            throw publicInvalidInput()
          }
        } else {
          this.deleteProof(response.requestId)
        }
      }
    }
    this.resolvePending(pending, response)
  }

  private resolvePending(pending: PendingApproval, response: PasskeyApprovalResponse): void {
    if (this.pending.get(response.requestId) !== pending) return
    this.pending.delete(response.requestId)
    clearTimeout(pending.timer)
    pending.signal.removeEventListener('abort', pending.onAbort)
    pending.resolve(response)
  }

  private rejectPending(requestId: string, error: Error): void {
    const pending = this.pending.get(requestId)
    if (!pending) return
    this.pending.delete(requestId)
    clearTimeout(pending.timer)
    pending.signal.removeEventListener('abort', pending.onAbort)
    this.deleteProof(requestId)
    pending.reject(error)
  }

  private deleteProof(requestId: string): void {
    const proof = this.passwordProofs.get(requestId)
    if (!proof) return
    this.passwordProofs.delete(requestId)
    clearTimeout(proof.timer)
  }

  private detachWindow(): void {
    const window = this.attachedWindow
    this.attachedWindow = null
    if (!window || window.webContents.isDestroyed()) return
    window.webContents.removeListener('did-start-loading', this.handleRendererReset)
    window.webContents.removeListener('render-process-gone', this.handleRendererReset)
    window.webContents.removeListener('destroyed', this.handleRendererReset)
  }
}
