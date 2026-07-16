import { describe, expect, it, vi } from 'vitest'
import {
  PasskeyRequestCoordinator,
  PasskeyRequestCoordinatorError,
  type PasskeyExecutionContext,
  type PasskeyRendererSafePrompt,
  type PasskeyTrustedCreateRequest,
  type PasskeyTrustedGetRequest
} from './passkey-request-coordinator'

const REQUEST_DIGEST = Uint8Array.from({ length: 32 }, (_, index) => index)
const CLIENT_DATA_HASH = Uint8Array.from({ length: 32 }, (_, index) => 255 - index)
const CHALLENGE = Uint8Array.from([1, 2, 3, 4])

function createRequest(
  overrides: Partial<PasskeyTrustedCreateRequest> = {}
): PasskeyTrustedCreateRequest {
  return {
    kind: 'create',
    peerBinding: 'native-peer:browser-profile-a',
    peerEpoch: 4,
    vaultGeneration: 8,
    requestDigest: REQUEST_DIGEST.slice(),
    clientDataHash: CLIENT_DATA_HASH.slice(),
    challenge: CHALLENGE.slice(),
    origin: 'https://login.example.test',
    rpId: 'login.example.test',
    rpName: 'Example Test',
    userVerification: 'preferred',
    choices: [
      {
        id: 'login-a',
        label: 'Example login',
        detail: 'example-user',
        requiresReprompt: true
      }
    ],
    userHandle: Uint8Array.from([9, 8, 7]),
    userName: 'example-user',
    userDisplayName: 'Example User',
    discoverable: true,
    excludeCredentialIds: [],
    ...overrides
  }
}

function getRequest(overrides: Partial<PasskeyTrustedGetRequest> = {}): PasskeyTrustedGetRequest {
  return {
    kind: 'get',
    peerBinding: 'native-peer:browser-profile-a',
    peerEpoch: 4,
    vaultGeneration: 8,
    requestDigest: REQUEST_DIGEST.slice(),
    clientDataHash: CLIENT_DATA_HASH.slice(),
    challenge: CHALLENGE.slice(),
    origin: 'https://login.example.test',
    rpId: 'login.example.test',
    rpName: 'Example Test',
    userVerification: 'preferred',
    choices: [],
    allowCredentialIds: [Uint8Array.from([1, 2, 3])],
    ...overrides
  }
}

function errorCode(error: unknown): string | undefined {
  return error instanceof PasskeyRequestCoordinatorError ? error.code : undefined
}

function harness(options: { timeoutMs?: number; requestId?: () => string } = {}): {
  coordinator: PasskeyRequestCoordinator
  requestConsent: ReturnType<typeof vi.fn>
  verifyUser: ReturnType<typeof vi.fn>
} {
  const requestConsent = vi.fn(async (prompt: PasskeyRendererSafePrompt) => ({
    requestId: prompt.requestId,
    approved: true,
    ...(prompt.choices.length === 0 ? {} : { selectedChoiceId: prompt.choices[0]!.id }),
    verificationMethod: prompt.userVerification === 'discouraged' ? 'none' : 'touch-id'
  }))
  const verifyUser = vi.fn(async () => true)
  const coordinator = new PasskeyRequestCoordinator({
    requestConsent,
    verifyUser,
    ...(options.timeoutMs === undefined ? {} : { requestTimeoutMs: options.timeoutMs }),
    ...(options.requestId === undefined ? {} : { requestId: options.requestId })
  })
  return { coordinator, requestConsent, verifyUser }
}

describe('PasskeyRequestCoordinator', () => {
  it('only publishes renderer-safe metadata and gives the operation an immutable main-only snapshot', async () => {
    const { coordinator, requestConsent } = harness({ requestId: () => 'request-1' })
    const request = createRequest({ userVerification: 'discouraged' })
    let context: PasskeyExecutionContext | undefined

    const result = coordinator.start(request, (current) => {
      context = current
      return 'created'
    })
    await expect(result).resolves.toBe('created')

    const prompt = requestConsent.mock.calls[0]![0] as PasskeyRendererSafePrompt
    expect(prompt).toEqual({
      requestId: 'request-1',
      expiresAt: expect.any(Number),
      kind: 'create',
      rpId: 'login.example.test',
      rpName: 'Example Test',
      userVerification: 'discouraged',
      choices: [
        {
          id: 'login-a',
          label: 'Example login',
          detail: 'example-user',
          requiresReprompt: true
        }
      ],
      userName: 'example-user',
      userDisplayName: 'Example User'
    })
    for (const secret of [
      'requestDigest',
      'clientDataHash',
      'challenge',
      'origin',
      'userHandle',
      'excludeCredentialIds',
      'peerBinding',
      'vaultGeneration'
    ]) {
      expect(prompt).not.toHaveProperty(secret)
    }

    expect(context).toMatchObject({
      requestId: 'request-1',
      userPresent: true,
      userVerified: false,
      selectedChoiceId: 'login-a',
      peerBinding: 'native-peer:browser-profile-a',
      peerEpoch: 4,
      vaultGeneration: 8,
      lockEpoch: 0,
      mutationEpoch: 0,
      origin: 'https://login.example.test'
    })
    expect(context?.request).toMatchObject({
      kind: 'create',
      userHandle: [9, 8, 7],
      requestDigest: [...REQUEST_DIGEST],
      clientDataHash: [...CLIENT_DATA_HASH],
      challenge: [...CHALLENGE],
      origin: 'https://login.example.test'
    })
    expect(Object.isFrozen(context?.request)).toBe(true)
    expect(Object.isFrozen(context?.request.requestDigest)).toBe(true)
    expect(
      Object.isFrozen(
        context?.request.kind === 'create' ? context.request.excludeCredentialIds : []
      )
    ).toBe(true)
  })

  it('snapshots mutable ingress bytes before consent and binds the verifier to peer, vault, epoch, and digest', async () => {
    const { coordinator, verifyUser } = harness({ requestId: () => 'request-2' })
    const request = createRequest({ userVerification: 'required' })
    const expectedDigest = [...request.requestDigest]
    const expectedHash = [...request.clientDataHash]
    const expectedHandle = [...request.userHandle]
    let operationContext: PasskeyExecutionContext | undefined
    const operation = vi.fn((context: PasskeyExecutionContext) => {
      operationContext = context
      return 'signed'
    })

    const result = coordinator.start(request, operation)
    request.requestDigest.fill(99)
    request.clientDataHash.fill(98)
    request.userHandle.fill(97)
    await expect(result).resolves.toBe('signed')

    expect(verifyUser).toHaveBeenCalledWith(
      expect.objectContaining({
        requestId: 'request-2',
        kind: 'create',
        method: 'touch-id',
        selectedChoiceId: 'login-a',
        peerBinding: 'native-peer:browser-profile-a',
        peerEpoch: 4,
        vaultGeneration: 8,
        lockEpoch: 0,
        mutationEpoch: 0,
        requestDigest: expectedDigest,
        origin: 'https://login.example.test'
      }),
      expect.any(AbortSignal)
    )
    const context = operationContext
    expect(context).toBeDefined()
    const captured = context!
    expect(captured.request.requestDigest).toEqual(expectedDigest)
    expect(captured.request.clientDataHash).toEqual(expectedHash)
    expect(captured.request.kind === 'create' ? captured.request.userHandle : []).toEqual(
      expectedHandle
    )
    expect(captured.userVerified).toBe(true)
  })

  it('implements required, preferred, and discouraged UV without accepting a renderer-supplied boolean', async () => {
    const required = harness({ requestId: () => 'required' })
    required.requestConsent.mockResolvedValue({
      requestId: 'required',
      approved: true,
      selectedChoiceId: 'login-a',
      verificationMethod: 'none'
    })
    await expect(
      required.coordinator.start(createRequest({ userVerification: 'required' }), () => 'never')
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'USER_VERIFICATION_FAILED')
    expect(required.verifyUser).not.toHaveBeenCalled()

    const preferredWithoutUv = harness({ requestId: () => 'preferred-without-uv' })
    preferredWithoutUv.requestConsent.mockResolvedValue({
      requestId: 'preferred-without-uv',
      approved: true,
      selectedChoiceId: 'login-a',
      verificationMethod: 'none'
    })
    await expect(
      preferredWithoutUv.coordinator.start(
        createRequest({ userVerification: 'preferred' }),
        () => 'never'
      )
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'USER_VERIFICATION_FAILED')
    expect(preferredWithoutUv.verifyUser).not.toHaveBeenCalled()

    const preferred = harness({ requestId: () => 'preferred' })
    preferred.requestConsent.mockResolvedValue({
      requestId: 'preferred',
      approved: true,
      selectedChoiceId: 'login-a',
      verificationMethod: 'touch-id'
    })
    let preferredContext: PasskeyExecutionContext | undefined
    await expect(
      preferred.coordinator.start(createRequest({ userVerification: 'preferred' }), (context) => {
        preferredContext = context
        return 'ok'
      })
    ).resolves.toBe('ok')
    expect(preferredContext?.userPresent).toBe(true)
    expect(preferredContext?.userVerified).toBe(true)
    expect(preferred.verifyUser).toHaveBeenCalledOnce()

    const discouraged = harness({ requestId: () => 'discouraged' })
    discouraged.requestConsent.mockResolvedValue({
      requestId: 'discouraged',
      approved: true,
      selectedChoiceId: 'login-a',
      verificationMethod: 'touch-id'
    })
    await expect(
      discouraged.coordinator.start(
        createRequest({ userVerification: 'discouraged' }),
        () => 'never'
      )
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'REQUEST_DENIED')
    expect(discouraged.verifyUser).not.toHaveBeenCalled()
  })

  it('sets UV only after the main-only verifier succeeds and fails closed on rejection', async () => {
    const success = harness({ requestId: () => 'verified' })
    success.requestConsent.mockResolvedValue({
      requestId: 'verified',
      approved: true,
      selectedChoiceId: 'login-a',
      verificationMethod: 'master-password'
    })
    success.verifyUser.mockResolvedValue(true)
    let context: PasskeyExecutionContext | undefined
    await expect(
      success.coordinator.start(createRequest({ userVerification: 'required' }), (current) => {
        context = current
        return 'ok'
      })
    ).resolves.toBe('ok')
    expect(context?.userVerified).toBe(true)

    const rejected = harness({ requestId: () => 'rejected' })
    rejected.requestConsent.mockResolvedValue({
      requestId: 'rejected',
      approved: true,
      selectedChoiceId: 'login-a',
      verificationMethod: 'master-password'
    })
    rejected.verifyUser.mockResolvedValue(false)
    const operation = vi.fn(() => 'never')
    await expect(
      rejected.coordinator.start(createRequest({ userVerification: 'required' }), operation)
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'USER_VERIFICATION_FAILED')
    expect(operation).not.toHaveBeenCalled()
  })

  it('requires exactly one valid choice and an exactly matching response request id', async () => {
    const invalidChoice = harness({ requestId: () => 'choice' })
    invalidChoice.requestConsent.mockResolvedValue({
      requestId: 'choice',
      approved: true,
      selectedChoiceId: 'not-listed',
      verificationMethod: 'touch-id'
    })
    await expect(invalidChoice.coordinator.start(createRequest(), () => 'never')).rejects.toSatisfy(
      (error: unknown) => errorCode(error) === 'REQUEST_DENIED'
    )

    const staleResponse = harness({ requestId: () => 'current' })
    staleResponse.requestConsent.mockResolvedValue({
      requestId: 'other',
      approved: true,
      selectedChoiceId: 'login-a',
      verificationMethod: 'touch-id'
    })
    await expect(staleResponse.coordinator.start(createRequest(), () => 'never')).rejects.toSatisfy(
      (error: unknown) => errorCode(error) === 'REQUEST_DENIED'
    )

    const get = harness({ requestId: () => 'get' })
    get.requestConsent.mockResolvedValue({
      requestId: 'get',
      approved: true,
      verificationMethod: 'touch-id'
    })
    await expect(get.coordinator.start(getRequest(), () => 'asserted')).resolves.toBe('asserted')
    const getPrompt = get.requestConsent.mock.calls[0]![0] as PasskeyRendererSafePrompt
    expect(getPrompt).not.toHaveProperty('userName')
    expect(getPrompt).not.toHaveProperty('userDisplayName')
    expect(getPrompt).not.toHaveProperty('allowCredentialIds')
  })

  it('rejects malformed approval payloads and never invokes the operation', async () => {
    const { coordinator, requestConsent } = harness({ requestId: () => 'malformed' })
    requestConsent.mockResolvedValue({
      requestId: 'malformed',
      approved: true,
      selectedChoiceId: 'login-a',
      verificationMethod: 'touch-id',
      userVerified: true
    })
    const operation = vi.fn(() => 'never')
    await expect(coordinator.start(createRequest(), operation)).rejects.toSatisfy(
      (error: unknown) => errorCode(error) === 'REQUEST_DENIED'
    )
    expect(operation).not.toHaveBeenCalled()
  })

  it('bounds concurrent requests and refuses a duplicate generated request id before execution', async () => {
    let resolveConsent!: (value: unknown) => void
    const { coordinator, requestConsent } = harness({ requestId: () => 'same' })
    requestConsent.mockImplementationOnce(
      () =>
        new Promise<unknown>((resolve) => {
          resolveConsent = resolve
        })
    )
    const first = coordinator.start(createRequest(), () => 'first')
    await vi.waitFor(() => expect(requestConsent).toHaveBeenCalledOnce())
    await expect(coordinator.start(createRequest(), () => 'second')).rejects.toSatisfy(
      (error: unknown) => errorCode(error) === 'REQUEST_UNAVAILABLE'
    )
    resolveConsent({
      requestId: 'same',
      approved: true,
      selectedChoiceId: 'login-a',
      verificationMethod: 'touch-id'
    })
    await expect(first).resolves.toBe('first')
  })

  it('expires and aborts a pending request before any user verification or operation', async () => {
    vi.useFakeTimers()
    try {
      const { coordinator, requestConsent, verifyUser } = harness({
        timeoutMs: 1_000,
        requestId: () => 'expired'
      })
      requestConsent.mockImplementationOnce(() => new Promise<unknown>(() => undefined))
      const operation = vi.fn(() => 'never')
      const result = coordinator.start(createRequest(), operation)
      const expectedFailure = expect(result).rejects.toSatisfy(
        (error: unknown) => errorCode(error) === 'REQUEST_EXPIRED'
      )
      await vi.advanceTimersByTimeAsync(1_000)
      await expectedFailure
      expect(verifyUser).not.toHaveBeenCalled()
      expect(operation).not.toHaveBeenCalled()
      expect(coordinator.activeRequestCount).toBe(0)
    } finally {
      vi.useRealTimers()
    }
  })

  it('invalidates on external abort, vault mutation, peer loss, and lock', async () => {
    const cases: Array<{
      label: string
      invalidate: (coordinator: PasskeyRequestCoordinator, abort: AbortController) => void
      code: string
    }> = [
      {
        label: 'external abort',
        invalidate: (_coordinator, abort) => abort.abort(),
        code: 'REQUEST_ABORTED'
      },
      {
        label: 'vault mutation',
        invalidate: (coordinator) => coordinator.onVaultMutation(),
        code: 'REQUEST_INVALIDATED'
      },
      {
        label: 'peer loss',
        invalidate: (coordinator) => coordinator.invalidatePeer('native-peer:browser-profile-a'),
        code: 'REQUEST_INVALIDATED'
      },
      {
        label: 'vault lock',
        invalidate: (coordinator) => coordinator.onLocked(),
        code: 'REQUEST_INVALIDATED'
      }
    ]
    for (const current of cases) {
      let resolveConsent!: (value: unknown) => void
      const { coordinator, requestConsent, verifyUser } = harness({
        requestId: () => current.label
      })
      requestConsent.mockImplementationOnce(
        () =>
          new Promise<unknown>((resolve) => {
            resolveConsent = resolve
          })
      )
      const abort = new AbortController()
      const operation = vi.fn(() => 'never')
      const result = coordinator.start(createRequest(), operation, abort.signal)
      await vi.waitFor(() => expect(requestConsent).toHaveBeenCalledOnce())
      current.invalidate(coordinator, abort)
      await expect(result).rejects.toSatisfy((error: unknown) => errorCode(error) === current.code)
      resolveConsent({
        requestId: current.label,
        approved: true,
        selectedChoiceId: 'login-a',
        verificationMethod: 'touch-id'
      })
      await Promise.resolve()
      expect(verifyUser).not.toHaveBeenCalled()
      expect(operation).not.toHaveBeenCalled()
      expect(coordinator.activeRequestCount).toBe(0)
    }
  })

  it('consumes the grant before execution and aborts an executing operation on lock', async () => {
    const { coordinator } = harness({ requestId: () => 'executing' })
    let executionContext!: PasskeyExecutionContext
    let releaseExecution!: () => void
    const operation = vi.fn(
      (context: PasskeyExecutionContext) =>
        new Promise<string>((resolve) => {
          executionContext = context
          releaseExecution = () => resolve('late')
        })
    )
    const result = coordinator.start(createRequest(), operation)
    await vi.waitFor(() => expect(operation).toHaveBeenCalledOnce())
    expect(executionContext.userPresent).toBe(true)
    expect(executionContext.signal.aborted).toBe(false)
    coordinator.onLocked()
    await expect(result).rejects.toSatisfy(
      (error: unknown) => errorCode(error) === 'REQUEST_INVALIDATED'
    )
    expect(executionContext.signal.aborted).toBe(true)
    releaseExecution()
    await Promise.resolve()
  })

  it('does not retry or roll back an operation that commits before its peer aborts', async () => {
    const { coordinator } = harness({ requestId: () => 'committed-then-aborted' })
    const peerAbort = new AbortController()
    let committedWrites = 0
    const operation = vi.fn(() => {
      committedWrites += 1
      // A real atomic vault operation may commit in the same turn that the native caller closes.
      peerAbort.abort()
      return 'committed'
    })

    await expect(coordinator.start(createRequest(), operation, peerAbort.signal)).rejects.toSatisfy(
      (error: unknown) => errorCode(error) === 'REQUEST_ABORTED'
    )
    // The coordinator owns no vault rollback primitive. Retrying or best-effort deletion here
    // would be a separate, non-atomic mutation and is therefore intentionally forbidden.
    expect(committedWrites).toBe(1)
    expect(operation).toHaveBeenCalledOnce()
  })

  it('rejects malformed trusted inputs before any prompt is published', async () => {
    const { coordinator, requestConsent } = harness()
    const invalid = createRequest({
      requestDigest: Uint8Array.from([1]),
      rpId: '',
      origin: '',
      excludeCredentialIds: Array.from({ length: 129 }, () => Uint8Array.from([1]))
    })
    await expect(coordinator.start(invalid, () => 'never')).rejects.toSatisfy(
      (error: unknown) => errorCode(error) === 'INVALID_REQUEST'
    )
    expect(requestConsent).not.toHaveBeenCalled()
  })
})
