import { randomUUID } from 'node:crypto'

const DEFAULT_REQUEST_TIMEOUT_MS = 60_000
const DEFAULT_MAX_PENDING_REQUESTS = 16
const MAX_REQUEST_ID_LENGTH = 128
const MAX_PEER_BINDING_LENGTH = 256
const MAX_RP_ID_LENGTH = 253
const MAX_ORIGIN_LENGTH = 2_048
const MAX_TEXT_LENGTH = 1_024
const MAX_CHALLENGE_BYTES = 1_024
const CLIENT_DATA_HASH_BYTES = 32
const REQUEST_DIGEST_BYTES = 32
const MAX_USER_HANDLE_BYTES = 64
const MAX_CREDENTIAL_ID_BYTES = 1_023
const MAX_CREDENTIAL_DESCRIPTORS = 128
const MAX_PROMPT_CHOICES = 100
const MAX_PROMPT_CHOICE_ID_LENGTH = 128

export type PasskeyCeremonyKind = 'create' | 'get'
export type PasskeyUserVerificationRequirement = 'required' | 'preferred' | 'discouraged'
export type PasskeyVerificationMethod = 'none' | 'touch-id' | 'master-password'

export type PasskeyRequestCoordinatorErrorCode =
  | 'INVALID_REQUEST'
  | 'REQUEST_UNAVAILABLE'
  | 'REQUEST_EXPIRED'
  | 'REQUEST_ABORTED'
  | 'REQUEST_DENIED'
  | 'USER_VERIFICATION_FAILED'
  | 'REQUEST_INVALIDATED'

/**
 * Errors intentionally reveal no request, credential, challenge, or key data. An ingress adapter
 * maps these to the appropriate native/WebAuthn error without involving the renderer.
 */
export class PasskeyRequestCoordinatorError extends Error {
  constructor(public readonly code: PasskeyRequestCoordinatorErrorCode) {
    super(code)
    this.name = 'PasskeyRequestCoordinatorError'
  }
}

/** A pre-sanitized choice supplied by a trusted ingress/vault adapter for an approval prompt. */
export interface PasskeyPromptChoice {
  id: string
  label: string
  detail?: string
  /** Safe policy metadata; it never grants access or proves that a reprompt succeeded. */
  requiresReprompt?: boolean
}

interface PasskeyTrustedRequestBase {
  kind: PasskeyCeremonyKind
  /** An adapter-authenticated browser/OS peer identity; never a renderer supplied value. */
  peerBinding: string
  /** Changes whenever that authenticated peer reconnects or its trust context changes. */
  peerEpoch: number
  /** The unlocked vault generation observed by the ingress adapter. */
  vaultGeneration: number
  /** SHA-256 of the canonical, adapter-validated WebAuthn ceremony request. */
  requestDigest: Uint8Array
  /** Never sent to the renderer; passed only to the final main-process operation. */
  clientDataHash: Uint8Array
  /** Never sent to the renderer. It is retained so an operation can audit the bound ceremony. */
  challenge: Uint8Array
  /** Canonical origin already validated by the trusted ingress adapter. */
  origin: string
  rpId: string
  rpName: string
  userVerification: PasskeyUserVerificationRequirement
  choices?: readonly PasskeyPromptChoice[]
}

export interface PasskeyTrustedCreateRequest extends PasskeyTrustedRequestBase {
  kind: 'create'
  userHandle: Uint8Array
  userName: string
  userDisplayName: string
  discoverable: boolean
  excludeCredentialIds: readonly Uint8Array[]
}

export interface PasskeyTrustedGetRequest extends PasskeyTrustedRequestBase {
  kind: 'get'
  allowCredentialIds: readonly Uint8Array[]
}

/**
 * A trusted ingress may call `start`, but this object must never be created from renderer IPC.
 * The coordinator snapshots every field before it asks for user consent.
 */
export type PasskeyTrustedRequest = PasskeyTrustedCreateRequest | PasskeyTrustedGetRequest

/** The sole prompt shape that may cross a renderer bridge. */
export interface PasskeyRendererSafePrompt {
  requestId: string
  expiresAt: number
  kind: PasskeyCeremonyKind
  rpId: string
  rpName: string
  userVerification: PasskeyUserVerificationRequirement
  choices: readonly PasskeyPromptChoice[]
  /** Present only for registration; the opaque user handle never crosses this boundary. */
  userName?: string
  /** Present only for registration; the opaque user handle never crosses this boundary. */
  userDisplayName?: string
}

/** Renderer consent is not a UV assertion. The coordinator obtains UV separately in main. */
export interface PasskeyApprovalResponse {
  requestId: string
  approved: boolean
  selectedChoiceId?: string
  verificationMethod?: PasskeyVerificationMethod
}

export interface PasskeyVerificationRequest {
  requestId: string
  kind: PasskeyCeremonyKind
  method: Exclude<PasskeyVerificationMethod, 'none'>
  selectedChoiceId?: string
  peerBinding: string
  peerEpoch: number
  vaultGeneration: number
  lockEpoch: number
  mutationEpoch: number
  requestDigest: readonly number[]
  origin: string
}

export interface PasskeyFrozenRequestBase {
  readonly kind: PasskeyCeremonyKind
  readonly peerBinding: string
  readonly peerEpoch: number
  readonly vaultGeneration: number
  readonly requestDigest: readonly number[]
  readonly clientDataHash: readonly number[]
  readonly challenge: readonly number[]
  readonly origin: string
  readonly rpId: string
  readonly rpName: string
  readonly userVerification: PasskeyUserVerificationRequirement
  readonly choices: readonly PasskeyPromptChoice[]
}

export interface PasskeyFrozenCreateRequest extends PasskeyFrozenRequestBase {
  readonly kind: 'create'
  readonly userHandle: readonly number[]
  readonly userName: string
  readonly userDisplayName: string
  readonly discoverable: boolean
  readonly excludeCredentialIds: readonly (readonly number[])[]
}

export interface PasskeyFrozenGetRequest extends PasskeyFrozenRequestBase {
  readonly kind: 'get'
  readonly allowCredentialIds: readonly (readonly number[])[]
}

export type PasskeyFrozenRequest = PasskeyFrozenCreateRequest | PasskeyFrozenGetRequest

/**
 * A fresh, immutable request snapshot is delivered only after consent and (when requested)
 * successful main-process user verification. `userPresent` is deliberately not caller supplied.
 */
export interface PasskeyExecutionContext {
  readonly requestId: string
  readonly request: PasskeyFrozenRequest
  readonly selectedChoiceId?: string
  readonly userPresent: true
  readonly userVerified: boolean
  readonly peerBinding: string
  readonly peerEpoch: number
  readonly vaultGeneration: number
  readonly lockEpoch: number
  readonly mutationEpoch: number
  readonly requestDigest: readonly number[]
  readonly origin: string
  readonly signal: AbortSignal
}

export interface PasskeyRequestCoordinatorOptions {
  /**
   * The bridge owns UI delivery and must reject on renderer reload/crash. Its return value is
   * parsed defensively because it is ultimately renderer controlled.
   */
  requestConsent: (prompt: PasskeyRendererSafePrompt, signal: AbortSignal) => Promise<unknown>
  /**
   * Main-process only. A `true` result means Touch ID or a master-password proof has actually
   * succeeded for this request; the renderer can never set the UV bit by itself.
   */
  verifyUser: (request: PasskeyVerificationRequest, signal: AbortSignal) => Promise<boolean>
  now?: () => number
  requestId?: () => string
  requestTimeoutMs?: number
  maxPendingRequests?: number
}

type PasskeyOperation<TResult> = (context: PasskeyExecutionContext) => Promise<TResult> | TResult

interface PendingRequest<TResult> {
  requestId: string
  request: PasskeyFrozenRequest
  operation: PasskeyOperation<TResult>
  controller: AbortController
  expiresAt: number
  lockEpoch: number
  mutationEpoch: number
  consumed: boolean
  timeout: NodeJS.Timeout
  externalSignal: AbortSignal | undefined
  onExternalAbort: (() => void) | undefined
  resolve: (result: TResult) => void
  reject: (error: unknown) => void
}

function coordinatorError(
  code: PasskeyRequestCoordinatorErrorCode
): PasskeyRequestCoordinatorError {
  return new PasskeyRequestCoordinatorError(code)
}

function validBoundedString(
  value: unknown,
  maximumLength: number,
  allowEmpty = false
): value is string {
  return (
    typeof value === 'string' && value.length <= maximumLength && (allowEmpty || value.length > 0)
  )
}

function validSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function frozenBytes(value: unknown, minimum: number, maximum: number): readonly number[] {
  if (!(value instanceof Uint8Array) || value.byteLength < minimum || value.byteLength > maximum) {
    throw coordinatorError('INVALID_REQUEST')
  }
  return Object.freeze(Array.from(value))
}

function frozenCredentialIds(value: unknown): readonly (readonly number[])[] {
  if (!Array.isArray(value) || value.length > MAX_CREDENTIAL_DESCRIPTORS) {
    throw coordinatorError('INVALID_REQUEST')
  }
  return Object.freeze(value.map((entry) => frozenBytes(entry, 1, MAX_CREDENTIAL_ID_BYTES)))
}

function frozenChoices(value: unknown): readonly PasskeyPromptChoice[] {
  if (value === undefined) return Object.freeze([])
  if (!Array.isArray(value) || value.length > MAX_PROMPT_CHOICES) {
    throw coordinatorError('INVALID_REQUEST')
  }
  const ids = new Set<string>()
  const choices = value.map((candidate): PasskeyPromptChoice => {
    if (typeof candidate !== 'object' || candidate === null || Array.isArray(candidate)) {
      throw coordinatorError('INVALID_REQUEST')
    }
    const record = candidate as Record<string, unknown>
    if (
      Object.keys(record).some(
        (key) => key !== 'id' && key !== 'label' && key !== 'detail' && key !== 'requiresReprompt'
      )
    ) {
      throw coordinatorError('INVALID_REQUEST')
    }
    if (
      !validBoundedString(record.id, MAX_PROMPT_CHOICE_ID_LENGTH) ||
      !validBoundedString(record.label, MAX_TEXT_LENGTH) ||
      (record.detail !== undefined && !validBoundedString(record.detail, MAX_TEXT_LENGTH, true)) ||
      (record.requiresReprompt !== undefined && typeof record.requiresReprompt !== 'boolean') ||
      ids.has(record.id)
    ) {
      throw coordinatorError('INVALID_REQUEST')
    }
    ids.add(record.id)
    return Object.freeze({
      id: record.id,
      label: record.label,
      ...(record.detail === undefined ? {} : { detail: record.detail }),
      ...(record.requiresReprompt === undefined
        ? {}
        : { requiresReprompt: record.requiresReprompt })
    })
  })
  return Object.freeze(choices)
}

function userVerificationRequirement(value: unknown): PasskeyUserVerificationRequirement {
  if (value === 'required' || value === 'preferred' || value === 'discouraged') return value
  throw coordinatorError('INVALID_REQUEST')
}

function frozenBase(request: PasskeyTrustedRequestBase): PasskeyFrozenRequestBase {
  if (
    !validBoundedString(request.peerBinding, MAX_PEER_BINDING_LENGTH) ||
    !validSafeInteger(request.peerEpoch) ||
    !validSafeInteger(request.vaultGeneration) ||
    !validBoundedString(request.rpId, MAX_RP_ID_LENGTH) ||
    !validBoundedString(request.rpName, MAX_TEXT_LENGTH) ||
    !validBoundedString(request.origin, MAX_ORIGIN_LENGTH)
  ) {
    throw coordinatorError('INVALID_REQUEST')
  }
  return Object.freeze({
    kind: request.kind,
    peerBinding: request.peerBinding,
    peerEpoch: request.peerEpoch,
    vaultGeneration: request.vaultGeneration,
    requestDigest: frozenBytes(request.requestDigest, REQUEST_DIGEST_BYTES, REQUEST_DIGEST_BYTES),
    clientDataHash: frozenBytes(
      request.clientDataHash,
      CLIENT_DATA_HASH_BYTES,
      CLIENT_DATA_HASH_BYTES
    ),
    challenge: frozenBytes(request.challenge, 1, MAX_CHALLENGE_BYTES),
    origin: request.origin,
    rpId: request.rpId,
    rpName: request.rpName,
    userVerification: userVerificationRequirement(request.userVerification),
    choices: frozenChoices(request.choices)
  })
}

function freezeRequest(request: PasskeyTrustedRequest): PasskeyFrozenRequest {
  if (request === null || typeof request !== 'object') throw coordinatorError('INVALID_REQUEST')
  const base = frozenBase(request)
  if (request.kind === 'create') {
    if (
      !validBoundedString(request.userName, MAX_TEXT_LENGTH) ||
      !validBoundedString(request.userDisplayName, MAX_TEXT_LENGTH) ||
      typeof request.discoverable !== 'boolean'
    ) {
      throw coordinatorError('INVALID_REQUEST')
    }
    return Object.freeze({
      ...base,
      kind: 'create' as const,
      userHandle: frozenBytes(request.userHandle, 1, MAX_USER_HANDLE_BYTES),
      userName: request.userName,
      userDisplayName: request.userDisplayName,
      discoverable: request.discoverable,
      excludeCredentialIds: frozenCredentialIds(request.excludeCredentialIds)
    })
  }
  if (request.kind === 'get') {
    return Object.freeze({
      ...base,
      kind: 'get' as const,
      allowCredentialIds: frozenCredentialIds(request.allowCredentialIds)
    })
  }
  throw coordinatorError('INVALID_REQUEST')
}

function safePrompt(
  requestId: string,
  expiresAt: number,
  request: PasskeyFrozenRequest
): PasskeyRendererSafePrompt {
  return Object.freeze({
    requestId,
    expiresAt,
    kind: request.kind,
    rpId: request.rpId,
    rpName: request.rpName,
    userVerification: request.userVerification,
    choices: request.choices,
    ...(request.kind === 'create'
      ? { userName: request.userName, userDisplayName: request.userDisplayName }
      : {})
  })
}

function parseApproval(value: unknown): PasskeyApprovalResponse {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw coordinatorError('REQUEST_DENIED')
  }
  const record = value as Record<string, unknown>
  if (
    Object.keys(record).some(
      (key) =>
        key !== 'requestId' &&
        key !== 'approved' &&
        key !== 'selectedChoiceId' &&
        key !== 'verificationMethod'
    ) ||
    !validBoundedString(record.requestId, MAX_REQUEST_ID_LENGTH) ||
    typeof record.approved !== 'boolean' ||
    (record.selectedChoiceId !== undefined &&
      !validBoundedString(record.selectedChoiceId, MAX_PROMPT_CHOICE_ID_LENGTH)) ||
    (record.verificationMethod !== undefined &&
      record.verificationMethod !== 'none' &&
      record.verificationMethod !== 'touch-id' &&
      record.verificationMethod !== 'master-password')
  ) {
    throw coordinatorError('REQUEST_DENIED')
  }
  if (
    !record.approved &&
    (record.selectedChoiceId !== undefined || record.verificationMethod !== undefined)
  ) {
    throw coordinatorError('REQUEST_DENIED')
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

function validGeneratedRequestId(value: unknown): value is string {
  return validBoundedString(value, MAX_REQUEST_ID_LENGTH)
}

/**
 * Main-only coordinator for a single external WebAuthn ceremony. It receives only already
 * authenticated ingress requests. Browser/OS peer authentication is intentionally outside this
 * class; renderer IPC cannot construct a trusted request or call the final operation.
 */
export class PasskeyRequestCoordinator {
  private readonly now: () => number
  private readonly nextRequestId: () => string
  private readonly timeoutMs: number
  private readonly maxPendingRequests: number
  private readonly pending = new Map<string, PendingRequest<unknown>>()
  private lockEpoch = 0
  private mutationEpoch = 0
  private disposed = false

  constructor(private readonly options: PasskeyRequestCoordinatorOptions) {
    this.now = options.now ?? Date.now
    this.nextRequestId = options.requestId ?? randomUUID
    this.timeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS
    this.maxPendingRequests = options.maxPendingRequests ?? DEFAULT_MAX_PENDING_REQUESTS
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1) {
      throw new Error('INVALID_PASSKEY_REQUEST_TIMEOUT')
    }
    if (!Number.isSafeInteger(this.maxPendingRequests) || this.maxPendingRequests < 1) {
      throw new Error('INVALID_PASSKEY_MAX_PENDING_REQUESTS')
    }
  }

  get activeRequestCount(): number {
    return this.pending.size
  }

  start<TResult>(
    request: PasskeyTrustedRequest,
    operation: PasskeyOperation<TResult>,
    externalSignal?: AbortSignal
  ): Promise<TResult> {
    if (this.disposed || this.pending.size >= this.maxPendingRequests) {
      return Promise.reject(coordinatorError('REQUEST_UNAVAILABLE'))
    }
    if (typeof operation !== 'function') return Promise.reject(coordinatorError('INVALID_REQUEST'))

    let snapshot: PasskeyFrozenRequest
    try {
      snapshot = freezeRequest(request)
    } catch (error) {
      return Promise.reject(error)
    }
    const requestId = this.nextRequestId()
    if (!validGeneratedRequestId(requestId) || this.pending.has(requestId)) {
      return Promise.reject(coordinatorError('REQUEST_UNAVAILABLE'))
    }

    return new Promise<TResult>((resolve, reject) => {
      const controller = new AbortController()
      const pending = {
        requestId,
        request: snapshot,
        operation,
        controller,
        expiresAt: this.now() + this.timeoutMs,
        lockEpoch: this.lockEpoch,
        mutationEpoch: this.mutationEpoch,
        consumed: false,
        timeout: undefined as unknown as NodeJS.Timeout,
        externalSignal,
        onExternalAbort: undefined as (() => void) | undefined,
        resolve: resolve as (result: unknown) => void,
        reject
      } satisfies PendingRequest<unknown>
      pending.timeout = setTimeout(() => {
        this.fail(pending, coordinatorError('REQUEST_EXPIRED'))
      }, this.timeoutMs)
      pending.timeout.unref()
      if (externalSignal) {
        pending.onExternalAbort = () => this.fail(pending, coordinatorError('REQUEST_ABORTED'))
        externalSignal.addEventListener('abort', pending.onExternalAbort, { once: true })
      }
      this.pending.set(requestId, pending)
      if (externalSignal?.aborted) {
        this.fail(pending, coordinatorError('REQUEST_ABORTED'))
        return
      }
      void this.run(pending)
    })
  }

  /** Lock invalidates every request, including an operation that has not yet honored its signal. */
  onLocked(): void {
    this.lockEpoch += 1
    this.invalidateAll()
  }

  /** A vault/sync mutation invalidates ceremony snapshots and all unconsumed approvals. */
  onVaultMutation(): void {
    this.mutationEpoch += 1
    this.invalidateAll()
  }

  /** Call when an authenticated native/browser peer disconnects or changes identity. */
  invalidatePeer(peerBinding: string): void {
    for (const pending of [...this.pending.values()]) {
      if (pending.request.peerBinding === peerBinding) {
        this.fail(pending, coordinatorError('REQUEST_INVALIDATED'))
      }
    }
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.invalidateAll()
  }

  private async run(pending: PendingRequest<unknown>): Promise<void> {
    try {
      const approval = parseApproval(
        await this.options.requestConsent(
          safePrompt(pending.requestId, pending.expiresAt, pending.request),
          pending.controller.signal
        )
      )
      this.assertCurrent(pending)
      if (approval.requestId !== pending.requestId || !approval.approved) {
        throw coordinatorError('REQUEST_DENIED')
      }
      const selectedChoiceId = this.selectedChoice(pending, approval.selectedChoiceId)
      const userVerified = await this.verifyUser(
        pending,
        selectedChoiceId,
        approval.verificationMethod ?? 'none'
      )
      this.assertCurrent(pending)
      const context = this.consume(pending, selectedChoiceId, userVerified)
      const result = await pending.operation(context)
      this.assertCurrent(pending)
      this.succeed(pending, result)
    } catch (error) {
      this.fail(pending, error)
    }
  }

  private selectedChoice(
    pending: PendingRequest<unknown>,
    selectedChoiceId: string | undefined
  ): string | undefined {
    const choices = pending.request.choices
    if (choices.length === 0) {
      if (selectedChoiceId !== undefined) throw coordinatorError('REQUEST_DENIED')
      return undefined
    }
    if (
      selectedChoiceId === undefined ||
      !choices.some((choice) => choice.id === selectedChoiceId)
    ) {
      throw coordinatorError('REQUEST_DENIED')
    }
    return selectedChoiceId
  }

  private async verifyUser(
    pending: PendingRequest<unknown>,
    selectedChoiceId: string | undefined,
    method: PasskeyVerificationMethod
  ): Promise<boolean> {
    const requirement = pending.request.userVerification
    if (requirement === 'discouraged') {
      if (method !== 'none') throw coordinatorError('REQUEST_DENIED')
      return false
    }
    if (method === 'none') throw coordinatorError('USER_VERIFICATION_FAILED')
    const verified = await this.options.verifyUser(
      Object.freeze({
        requestId: pending.requestId,
        kind: pending.request.kind,
        method,
        ...(selectedChoiceId === undefined ? {} : { selectedChoiceId }),
        peerBinding: pending.request.peerBinding,
        peerEpoch: pending.request.peerEpoch,
        vaultGeneration: pending.request.vaultGeneration,
        lockEpoch: pending.lockEpoch,
        mutationEpoch: pending.mutationEpoch,
        requestDigest: pending.request.requestDigest,
        origin: pending.request.origin
      }),
      pending.controller.signal
    )
    this.assertCurrent(pending)
    if (verified !== true) throw coordinatorError('USER_VERIFICATION_FAILED')
    return true
  }

  /** Consume before handing any request data to the irreversible vault operation. */
  private consume(
    pending: PendingRequest<unknown>,
    selectedChoiceId: string | undefined,
    userVerified: boolean
  ): PasskeyExecutionContext {
    this.assertCurrent(pending)
    if (pending.consumed) throw coordinatorError('REQUEST_INVALIDATED')
    pending.consumed = true
    return Object.freeze({
      requestId: pending.requestId,
      request: pending.request,
      ...(selectedChoiceId === undefined ? {} : { selectedChoiceId }),
      userPresent: true as const,
      userVerified,
      peerBinding: pending.request.peerBinding,
      peerEpoch: pending.request.peerEpoch,
      vaultGeneration: pending.request.vaultGeneration,
      lockEpoch: pending.lockEpoch,
      mutationEpoch: pending.mutationEpoch,
      requestDigest: pending.request.requestDigest,
      origin: pending.request.origin,
      signal: pending.controller.signal
    })
  }

  private assertCurrent(pending: PendingRequest<unknown>): void {
    if (
      this.pending.get(pending.requestId) !== pending ||
      pending.controller.signal.aborted ||
      pending.lockEpoch !== this.lockEpoch ||
      pending.mutationEpoch !== this.mutationEpoch ||
      this.disposed
    ) {
      throw coordinatorError('REQUEST_INVALIDATED')
    }
  }

  private invalidateAll(): void {
    for (const pending of [...this.pending.values()]) {
      this.fail(pending, coordinatorError('REQUEST_INVALIDATED'))
    }
  }

  private succeed(pending: PendingRequest<unknown>, result: unknown): void {
    if (this.pending.get(pending.requestId) !== pending) return
    this.cleanup(pending)
    pending.resolve(result)
  }

  private fail(pending: PendingRequest<unknown>, error: unknown): void {
    if (this.pending.get(pending.requestId) !== pending) return
    this.cleanup(pending)
    pending.reject(error)
  }

  private cleanup(pending: PendingRequest<unknown>): void {
    this.pending.delete(pending.requestId)
    clearTimeout(pending.timeout)
    if (pending.externalSignal && pending.onExternalAbort) {
      pending.externalSignal.removeEventListener('abort', pending.onExternalAbort)
    }
    if (!pending.controller.signal.aborted) pending.controller.abort()
  }
}
