import { createHash, randomUUID } from 'node:crypto'
import type {
  PasskeyIngressCreateSnapshot,
  PasskeyIngressGetSnapshot,
  PasskeyIngressPeer,
  PasskeyIngressSnapshot
} from './passkey-ingress'
import {
  PasskeyRequestCoordinator,
  PasskeyRequestCoordinatorError,
  type PasskeyExecutionContext,
  type PasskeyRendererSafePrompt,
  type PasskeyVerificationRequest
} from './passkey-request-coordinator'
import type { PasskeyPasswordProofBinding } from './passkey-renderer-bridge'
import type {
  PasskeyVaultAssertionRequest,
  PasskeyVaultAssertionResult,
  PasskeyVaultAuthorizationValidator,
  PasskeyVaultCreateRequest,
  PasskeyVaultCreateResult,
  PasskeyVaultCreationTargetDiscoveryResult,
  PasskeyVaultDiscoveryRequest,
  PasskeyVaultDiscoveryResult
} from './vault-service'

const MAX_PENDING_REQUESTS = 16
const MAX_CHOICES_PER_REQUEST = 100
const MAX_ACTIVE_CHOICES = MAX_PENDING_REQUESTS * MAX_CHOICES_PER_REQUEST
const MAX_CHOICE_ID_LENGTH = 128

type CeremonyErrorCode = ConstructorParameters<typeof PasskeyRequestCoordinatorError>[0]

export interface PasskeyCeremonyVault {
  discoverPasskeyCreationTargets(): Promise<PasskeyVaultCreationTargetDiscoveryResult>
  discoverPasskeyCredentials(
    request: PasskeyVaultDiscoveryRequest
  ): Promise<PasskeyVaultDiscoveryResult>
  createPasskey(
    request: PasskeyVaultCreateRequest,
    validateAuthorization: PasskeyVaultAuthorizationValidator
  ): Promise<PasskeyVaultCreateResult>
  getPasskeyAssertion(
    request: PasskeyVaultAssertionRequest,
    validateAuthorization: PasskeyVaultAuthorizationValidator
  ): Promise<PasskeyVaultAssertionResult>
  authorizeLogin(request: { id: string; masterPassword: string }): Promise<number>
}

export interface PasskeyCeremonyRendererBridge {
  requestConsent(prompt: PasskeyRendererSafePrompt, signal: AbortSignal): Promise<unknown>
  validateMasterPasswordProof(binding: PasskeyPasswordProofBinding): boolean
  consumeMasterPasswordProof(binding: PasskeyPasswordProofBinding): boolean
  discardMasterPasswordProof(requestId: string): void
}

export interface PasskeyCeremonySettings {
  verifyTouchIdOperation(operation: 'createPasskey' | 'usePasskey'): Promise<void>
}

export interface PasskeyCeremonyServiceOptions {
  vault: PasskeyCeremonyVault
  rendererBridge: PasskeyCeremonyRendererBridge
  settings: PasskeyCeremonySettings
  createChoiceId?: () => string
  /** Called only after the vault operation committed and the coordinator removed this request. */
  onVaultMutation?: () => void | Promise<void>
  requestId?: () => string
  now?: () => number
  requestTimeoutMs?: number
}

export interface PasskeyCreateCeremonyResponse {
  readonly type: 'public-key'
  readonly credentialId: Uint8Array
  readonly rawId: Uint8Array
  readonly clientDataJSON: Uint8Array
  readonly attestationObject: Uint8Array
  readonly authenticatorData: Uint8Array
  readonly publicKey: Uint8Array
  readonly publicKeyAlgorithm: -7
  readonly alg: -7
}

export interface PasskeyGetCeremonyResponse {
  readonly type: 'public-key'
  readonly credentialId: Uint8Array
  readonly rawId: Uint8Array
  readonly clientDataJSON: Uint8Array
  readonly authenticatorData: Uint8Array
  readonly signature: Uint8Array
  readonly userHandle: Uint8Array | null
}

interface ChoiceMappingBase {
  readonly choiceId: string
  readonly itemId: string
  readonly expectedUpdatedAt: string
  readonly requiresReprompt: boolean
}

interface CreateChoiceMapping extends ChoiceMappingBase {
  readonly kind: 'create'
  readonly replaceExisting: boolean
}

interface GetChoiceMapping extends ChoiceMappingBase {
  readonly kind: 'get'
  readonly credentialId: readonly number[]
}

type ChoiceMapping = CreateChoiceMapping | GetChoiceMapping

interface RequestState {
  readonly kind: 'create' | 'get'
  readonly generation: number
  readonly peerBinding: string
  readonly clientDataJSON: readonly number[]
  readonly choices: ReadonlyMap<string, ChoiceMapping>
  requestId: string | undefined
  coordinatorSignal: AbortSignal | undefined
  cleaned: boolean
}

interface GetOperationResult {
  readonly response: PasskeyGetCeremonyResponse
  readonly didPersistCounter: boolean
}

function ceremonyError(code: CeremonyErrorCode): PasskeyRequestCoordinatorError {
  return new PasskeyRequestCoordinatorError(code)
}

function assertNotAborted(signal: AbortSignal): void {
  if (signal.aborted) throw ceremonyError('REQUEST_ABORTED')
}

function frozenBytes(bytes: ArrayLike<number>): readonly number[] {
  return Object.freeze(Array.from(bytes))
}

function copiedBytes(bytes: readonly number[] | Uint8Array): Uint8Array {
  return Uint8Array.from(bytes)
}

function equalBytes(left: ArrayLike<number>, right: ArrayLike<number>): boolean {
  if (left.length !== right.length) return false
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false
  }
  return true
}

function peerBinding(peer: PasskeyIngressPeer): string {
  if (
    typeof peer?.provider !== 'string' ||
    peer.provider.length === 0 ||
    typeof peer.binding !== 'string' ||
    peer.binding.length === 0
  ) {
    throw ceremonyError('INVALID_REQUEST')
  }
  const digest = createHash('sha256')
    .update(peer.provider, 'utf8')
    .update('\0', 'utf8')
    .update(peer.binding, 'utf8')
    .digest('base64url')
  return `passkey:${digest}`
}

function validGeneration(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0
}

function safeDetail(primary: string | null, secondary: string | null, fallback: string): string {
  return primary && primary.length > 0
    ? primary
    : secondary && secondary.length > 0
      ? secondary
      : fallback
}

/**
 * Main-process-only adapter between an authenticated ingress snapshot, renderer consent, and the
 * atomic vault passkey APIs. It intentionally exposes no renderer ceremony ingress.
 */
export class PasskeyCeremonyService {
  private readonly coordinator: PasskeyRequestCoordinator
  private readonly nextChoiceId: () => string
  private readonly activeChoices = new Map<string, RequestState>()
  private readonly issuedChoiceIds = new Set<string>()
  private readonly requests = new Map<string, RequestState>()
  private readonly states = new Set<RequestState>()
  private activeSlots = 0
  private disposed = false

  constructor(private readonly options: PasskeyCeremonyServiceOptions) {
    this.nextChoiceId = options.createChoiceId ?? randomUUID
    this.coordinator = new PasskeyRequestCoordinator({
      requestConsent: (prompt, signal) => this.requestConsent(prompt, signal),
      verifyUser: (request, signal) => this.verifyUser(request, signal),
      ...(options.requestId === undefined ? {} : { requestId: options.requestId }),
      ...(options.now === undefined ? {} : { now: options.now }),
      ...(options.requestTimeoutMs === undefined
        ? {}
        : { requestTimeoutMs: options.requestTimeoutMs }),
      maxPendingRequests: MAX_PENDING_REQUESTS
    })
  }

  get activeRequestCount(): number {
    return this.coordinator.activeRequestCount
  }

  async create(snapshot: PasskeyIngressCreateSnapshot): Promise<PasskeyCreateCeremonyResponse> {
    if (snapshot?.kind !== 'create') throw ceremonyError('INVALID_REQUEST')
    this.reserveSlot()
    let state: RequestState | undefined
    try {
      assertNotAborted(snapshot.signal)
      const discovery = await this.options.vault.discoverPasskeyCreationTargets()
      assertNotAborted(snapshot.signal)
      if (!validGeneration(discovery.generation)) throw ceremonyError('INVALID_REQUEST')
      if (discovery.targets.length === 0) throw ceremonyError('REQUEST_UNAVAILABLE')

      const mappings = discovery.targets.map((target): ChoiceMapping => {
        const choiceId = this.createOpaqueChoiceId([target.itemId, target.itemUpdatedAt])
        return Object.freeze({
          kind: 'create' as const,
          choiceId,
          itemId: target.itemId,
          expectedUpdatedAt: target.itemUpdatedAt,
          requiresReprompt: target.reprompt === 1,
          replaceExisting: target.existingPasskeyCount === 1
        })
      })
      state = this.registerState(snapshot, discovery.generation, mappings)

      const result = await this.coordinator.start(
        {
          kind: 'create',
          peerBinding: state.peerBinding,
          peerEpoch: snapshot.peer.epoch,
          vaultGeneration: discovery.generation,
          requestDigest: copiedBytes(snapshot.requestDigest),
          clientDataHash: copiedBytes(snapshot.clientDataHash),
          challenge: copiedBytes(snapshot.challenge),
          origin: snapshot.origin,
          rpId: snapshot.rpId,
          rpName: snapshot.options.rp.name,
          userVerification: snapshot.options.authenticatorSelection.userVerification,
          choices: discovery.targets.map((target, index) =>
            Object.freeze({
              id: mappings[index]!.choiceId,
              label: target.itemName,
              detail:
                target.existingPasskeyCount === 1 ? 'Replace existing passkey' : 'Add passkey',
              requiresReprompt: target.reprompt === 1
            })
          ),
          userHandle: copiedBytes(snapshot.options.user.id),
          userName: snapshot.options.user.name,
          userDisplayName: snapshot.options.user.displayName,
          discoverable: snapshot.discoverable,
          excludeCredentialIds: snapshot.options.excludeCredentials.map((entry) =>
            copiedBytes(entry.id)
          )
        },
        (context) => this.performCreate(context, state!),
        snapshot.signal
      )
      this.cleanupState(state)
      this.publishVaultMutation()
      return result
    } finally {
      if (state) this.cleanupState(state)
      this.releaseSlot()
    }
  }

  async get(snapshot: PasskeyIngressGetSnapshot): Promise<PasskeyGetCeremonyResponse> {
    if (snapshot?.kind !== 'get') throw ceremonyError('INVALID_REQUEST')
    this.reserveSlot()
    let state: RequestState | undefined
    try {
      assertNotAborted(snapshot.signal)
      const allowCredentialIds = snapshot.options.allowCredentials.map((entry) =>
        copiedBytes(entry.id)
      )
      const discovery = await this.options.vault.discoverPasskeyCredentials({
        rpId: snapshot.rpId,
        allowCredentialIds
      })
      assertNotAborted(snapshot.signal)
      if (!validGeneration(discovery.generation)) throw ceremonyError('INVALID_REQUEST')
      if (discovery.credentials.length === 0) throw ceremonyError('REQUEST_UNAVAILABLE')

      const mappings = discovery.credentials.map((candidate): ChoiceMapping => {
        const credentialId = frozenBytes(candidate.credentialId)
        const choiceId = this.createOpaqueChoiceId([
          candidate.itemId,
          candidate.itemUpdatedAt,
          Buffer.from(credentialId).toString('base64url')
        ])
        return Object.freeze({
          kind: 'get' as const,
          choiceId,
          itemId: candidate.itemId,
          expectedUpdatedAt: candidate.itemUpdatedAt,
          requiresReprompt: candidate.reprompt === 1,
          credentialId
        })
      })
      state = this.registerState(snapshot, discovery.generation, mappings)

      const result = await this.coordinator.start(
        {
          kind: 'get',
          peerBinding: state.peerBinding,
          peerEpoch: snapshot.peer.epoch,
          vaultGeneration: discovery.generation,
          requestDigest: copiedBytes(snapshot.requestDigest),
          clientDataHash: copiedBytes(snapshot.clientDataHash),
          challenge: copiedBytes(snapshot.challenge),
          origin: snapshot.origin,
          rpId: snapshot.rpId,
          rpName: snapshot.rpId,
          userVerification: snapshot.options.userVerification,
          choices: discovery.credentials.map((candidate, index) =>
            Object.freeze({
              id: mappings[index]!.choiceId,
              label: candidate.itemName,
              detail: safeDetail(candidate.userDisplayName, candidate.userName, 'Passkey'),
              requiresReprompt: candidate.reprompt === 1
            })
          ),
          allowCredentialIds
        },
        (context) => this.performGet(context, state!),
        snapshot.signal
      )
      this.cleanupState(state)
      if (result.didPersistCounter) this.publishVaultMutation()
      return result.response
    } finally {
      if (state) this.cleanupState(state)
      this.releaseSlot()
    }
  }

  async verifyMasterPassword(
    requestId: string,
    selectedChoiceId: string | undefined,
    masterPassword: string,
    signal: AbortSignal
  ): Promise<number> {
    assertNotAborted(signal)
    const state = this.requests.get(requestId)
    const mapping =
      selectedChoiceId === undefined ? undefined : state?.choices.get(selectedChoiceId)
    if (
      !state ||
      state.cleaned ||
      state.requestId !== requestId ||
      state.coordinatorSignal !== signal ||
      !mapping ||
      this.activeChoices.get(selectedChoiceId!) !== state
    ) {
      throw ceremonyError('REQUEST_INVALIDATED')
    }
    const generation = await this.options.vault.authorizeLogin({
      id: mapping.itemId,
      masterPassword
    })
    assertNotAborted(signal)
    if (
      generation !== state.generation ||
      this.requests.get(requestId) !== state ||
      state.cleaned
    ) {
      throw ceremonyError('REQUEST_INVALIDATED')
    }
    return generation
  }

  onLocked(): void {
    this.coordinator.onLocked()
    this.cleanupAllStates()
  }

  onVaultMutation(): void {
    this.coordinator.onVaultMutation()
    this.cleanupAllStates()
  }

  invalidatePeer(peer: PasskeyIngressPeer): void
  invalidatePeer(provider: string, binding: string): void
  invalidatePeer(coordinatorPeerBinding: string): void
  invalidatePeer(peerOrProvider: PasskeyIngressPeer | string, binding?: string): void {
    const bound =
      typeof peerOrProvider === 'string'
        ? binding === undefined
          ? peerOrProvider
          : peerBinding({ provider: peerOrProvider, binding, epoch: 0 })
        : peerBinding(peerOrProvider)
    this.coordinator.invalidatePeer(bound)
    for (const state of [...this.states]) {
      if (state.peerBinding === bound) this.cleanupState(state)
    }
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.coordinator.dispose()
    this.cleanupAllStates()
  }

  private reserveSlot(): void {
    if (this.disposed || this.activeSlots >= MAX_PENDING_REQUESTS) {
      throw ceremonyError('REQUEST_UNAVAILABLE')
    }
    this.activeSlots += 1
  }

  private releaseSlot(): void {
    this.activeSlots = Math.max(0, this.activeSlots - 1)
  }

  private createOpaqueChoiceId(sensitiveValues: readonly string[]): string {
    const id = this.nextChoiceId()
    if (
      typeof id !== 'string' ||
      id.length === 0 ||
      id.length > MAX_CHOICE_ID_LENGTH ||
      this.issuedChoiceIds.has(id) ||
      sensitiveValues.some((value) => value.length > 0 && id.includes(value))
    ) {
      throw ceremonyError('INVALID_REQUEST')
    }
    this.issuedChoiceIds.add(id)
    return id
  }

  private registerState(
    snapshot: PasskeyIngressSnapshot,
    generation: number,
    mappings: readonly ChoiceMapping[]
  ): RequestState {
    if (
      mappings.length === 0 ||
      mappings.length > MAX_CHOICES_PER_REQUEST ||
      this.activeChoices.size + mappings.length > MAX_ACTIVE_CHOICES ||
      new Set(mappings.map((mapping) => mapping.choiceId)).size !== mappings.length
    ) {
      throw ceremonyError('INVALID_REQUEST')
    }
    const choices = new Map(mappings.map((mapping) => [mapping.choiceId, mapping]))
    const state: RequestState = {
      kind: snapshot.kind,
      generation,
      peerBinding: peerBinding(snapshot.peer),
      clientDataJSON: frozenBytes(snapshot.clientDataJSON),
      choices,
      requestId: undefined,
      coordinatorSignal: undefined,
      cleaned: false
    }
    for (const mapping of mappings) this.activeChoices.set(mapping.choiceId, state)
    this.states.add(state)
    return state
  }

  private async requestConsent(
    prompt: PasskeyRendererSafePrompt,
    signal: AbortSignal
  ): Promise<unknown> {
    assertNotAborted(signal)
    const firstChoiceId = prompt.choices[0]?.id
    const state = firstChoiceId === undefined ? undefined : this.activeChoices.get(firstChoiceId)
    if (
      !state ||
      state.cleaned ||
      state.requestId !== undefined ||
      state.coordinatorSignal !== undefined ||
      state.kind !== prompt.kind ||
      prompt.choices.length !== state.choices.size ||
      prompt.choices.some(
        (choice) => !state.choices.has(choice.id) || this.activeChoices.get(choice.id) !== state
      ) ||
      this.requests.has(prompt.requestId)
    ) {
      throw ceremonyError('REQUEST_INVALIDATED')
    }
    state.requestId = prompt.requestId
    state.coordinatorSignal = signal
    this.requests.set(prompt.requestId, state)
    return this.options.rendererBridge.requestConsent(prompt, signal)
  }

  private async verifyUser(
    request: PasskeyVerificationRequest,
    signal: AbortSignal
  ): Promise<boolean> {
    const state = this.requests.get(request.requestId)
    if (
      !state ||
      state.cleaned ||
      state.kind !== request.kind ||
      state.generation !== request.vaultGeneration ||
      state.peerBinding !== request.peerBinding ||
      state.coordinatorSignal !== signal ||
      request.selectedChoiceId === undefined ||
      !state.choices.has(request.selectedChoiceId)
    ) {
      return false
    }
    assertNotAborted(signal)
    if (request.method === 'master-password') {
      return this.options.rendererBridge.validateMasterPasswordProof(
        this.proofBinding(state, request.selectedChoiceId)
      )
    }
    try {
      await this.options.settings.verifyTouchIdOperation(
        request.kind === 'create' ? 'createPasskey' : 'usePasskey'
      )
    } catch {
      return false
    }
    assertNotAborted(signal)
    return this.requests.get(request.requestId) === state && !state.cleaned
  }

  private selectedMapping(
    context: PasskeyExecutionContext,
    state: RequestState,
    kind: ChoiceMapping['kind']
  ): ChoiceMapping {
    const choiceId = context.selectedChoiceId
    const mapping = choiceId === undefined ? undefined : state.choices.get(choiceId)
    if (
      !mapping ||
      mapping.kind !== kind ||
      state.cleaned ||
      state.requestId !== context.requestId ||
      this.requests.get(context.requestId) !== state ||
      this.activeChoices.get(choiceId!) !== state ||
      context.request.kind !== kind ||
      context.vaultGeneration !== state.generation ||
      context.peerBinding !== state.peerBinding ||
      context.signal !== state.coordinatorSignal ||
      context.signal.aborted
    ) {
      throw ceremonyError('REQUEST_INVALIDATED')
    }
    return mapping
  }

  private authorizationValidator(
    context: PasskeyExecutionContext,
    state: RequestState,
    mapping: ChoiceMapping
  ): PasskeyVaultAuthorizationValidator {
    return (ids, vaultState): boolean => {
      const exactBinding =
        !state.cleaned &&
        state.requestId === context.requestId &&
        this.requests.get(context.requestId) === state &&
        state.choices.get(mapping.choiceId) === mapping &&
        this.activeChoices.get(mapping.choiceId) === state &&
        context.signal === state.coordinatorSignal &&
        context.vaultGeneration === state.generation &&
        vaultState.generation === state.generation &&
        ids.length === 1 &&
        ids[0] === mapping.itemId &&
        !context.signal.aborted
      if (!exactBinding) return false
      if (!mapping.requiresReprompt) return true
      return this.options.rendererBridge.consumeMasterPasswordProof(
        this.proofBinding(state, mapping.choiceId)
      )
    }
  }

  private async performCreate(
    context: PasskeyExecutionContext,
    state: RequestState
  ): Promise<PasskeyCreateCeremonyResponse> {
    const mapping = this.selectedMapping(context, state, 'create') as CreateChoiceMapping
    const request = context.request
    if (request.kind !== 'create') throw ceremonyError('REQUEST_INVALIDATED')
    const result = await this.options.vault.createPasskey(
      {
        itemId: mapping.itemId,
        expectedUpdatedAt: mapping.expectedUpdatedAt,
        expectedGeneration: state.generation,
        rpId: request.rpId,
        rpName: request.rpName,
        userHandle: copiedBytes(request.userHandle),
        userName: request.userName,
        userDisplayName: request.userDisplayName,
        discoverable: request.discoverable,
        excludeCredentialIds: request.excludeCredentialIds.map(copiedBytes),
        replaceExisting: mapping.replaceExisting,
        requireUserVerification: request.userVerification !== 'discouraged',
        userVerified: context.userVerified
      },
      this.authorizationValidator(context, state, mapping)
    )
    assertNotAborted(context.signal)
    if (result.generation !== state.generation || result.item.id !== mapping.itemId) {
      throw ceremonyError('REQUEST_INVALIDATED')
    }
    const credentialId = copiedBytes(result.credentialId)
    return {
      type: 'public-key',
      credentialId,
      rawId: copiedBytes(credentialId),
      clientDataJSON: copiedBytes(state.clientDataJSON),
      attestationObject: copiedBytes(result.attestationObject),
      authenticatorData: copiedBytes(result.authenticatorData),
      publicKey: copiedBytes(result.publicKey),
      publicKeyAlgorithm: result.publicKeyAlgorithm,
      alg: result.publicKeyAlgorithm
    }
  }

  private async performGet(
    context: PasskeyExecutionContext,
    state: RequestState
  ): Promise<GetOperationResult> {
    const mapping = this.selectedMapping(context, state, 'get') as GetChoiceMapping
    const request = context.request
    if (request.kind !== 'get') throw ceremonyError('REQUEST_INVALIDATED')
    const result = await this.options.vault.getPasskeyAssertion(
      {
        itemId: mapping.itemId,
        credentialId: copiedBytes(mapping.credentialId),
        expectedUpdatedAt: mapping.expectedUpdatedAt,
        expectedGeneration: state.generation,
        rpId: request.rpId,
        clientDataHash: copiedBytes(request.clientDataHash),
        allowCredentialIds: request.allowCredentialIds.map(copiedBytes),
        requireUserVerification: request.userVerification !== 'discouraged',
        userVerified: context.userVerified
      },
      this.authorizationValidator(context, state, mapping)
    )
    assertNotAborted(context.signal)
    if (
      result.generation !== state.generation ||
      result.itemId !== mapping.itemId ||
      !equalBytes(result.credentialId, mapping.credentialId)
    ) {
      throw ceremonyError('REQUEST_INVALIDATED')
    }
    const credentialId = copiedBytes(result.credentialId)
    return {
      response: {
        type: 'public-key',
        credentialId,
        rawId: copiedBytes(credentialId),
        clientDataJSON: copiedBytes(state.clientDataJSON),
        authenticatorData: copiedBytes(result.authenticatorData),
        signature: copiedBytes(result.signature),
        userHandle: result.userHandle === null ? null : copiedBytes(result.userHandle)
      },
      didPersistCounter: result.didPersistCounter
    }
  }

  private proofBinding(state: RequestState, selectedChoiceId: string): PasskeyPasswordProofBinding {
    if (state.requestId === undefined) throw ceremonyError('REQUEST_INVALIDATED')
    return {
      requestId: state.requestId,
      selectedChoiceId,
      vaultGeneration: state.generation
    }
  }

  private cleanupState(state: RequestState): void {
    if (state.cleaned) return
    state.cleaned = true
    for (const choiceId of state.choices.keys()) {
      if (this.activeChoices.get(choiceId) === state) this.activeChoices.delete(choiceId)
      this.issuedChoiceIds.delete(choiceId)
    }
    this.states.delete(state)
    if (state.requestId !== undefined) {
      if (this.requests.get(state.requestId) === state) this.requests.delete(state.requestId)
      try {
        this.options.rendererBridge.discardMasterPasswordProof(state.requestId)
      } catch {
        // Proof disposal is best-effort only after the binding has already been removed locally.
      }
    }
  }

  private cleanupAllStates(): void {
    for (const state of [...this.states]) this.cleanupState(state)
  }

  private publishVaultMutation(): void {
    this.onVaultMutation()
    try {
      const notification = this.options.onVaultMutation?.()
      if (notification) void Promise.resolve(notification).catch(() => undefined)
    } catch {
      // A notification failure must not turn an already-committed credential into a retry.
    }
  }
}
