import { describe, expect, it, vi } from 'vitest'
import type { PasskeyIngressCreateSnapshot, PasskeyIngressGetSnapshot } from './passkey-ingress'
import type {
  PasskeyApprovalResponse,
  PasskeyRendererSafePrompt
} from './passkey-request-coordinator'
import {
  PasskeyCeremonyService,
  type PasskeyCeremonyRendererBridge,
  type PasskeyCeremonySettings,
  type PasskeyCeremonyVault
} from './passkey-ceremony-service'
import type { PasskeyPasswordProofBinding } from './passkey-renderer-bridge'
import type {
  PasskeyVaultAssertionResult,
  PasskeyVaultCreateResult,
  PasskeyVaultCreationTarget,
  PasskeyVaultCredentialCandidate
} from './vault-service'

const RP_ID = 'login.example.test'
const ORIGIN = 'https://login.example.test'
const GENERATION = 7
const ITEM_ID = '10000000-0000-4000-8000-000000000001'
const ITEM_REVISION = '2026-07-16T00:00:00.000Z'
const CREDENTIAL_ID = Uint8Array.from([0xf1, 0x00, 0xa5, 0x7c])
const CLIENT_DATA_JSON = Uint8Array.from(
  Buffer.from('{ "type" : "webauthn.get", "challenge" : "exact" }')
)

function createSnapshot(
  userVerification: 'required' | 'preferred' | 'discouraged' = 'discouraged'
): PasskeyIngressCreateSnapshot {
  const controller = new AbortController()
  return {
    version: 1,
    kind: 'create',
    peer: { provider: 'browser-extension', binding: 'native-session-1', epoch: 3 },
    signal: controller.signal,
    clientDataJSON: [...CLIENT_DATA_JSON],
    clientDataHash: Array.from({ length: 32 }, (_, index) => index),
    requestDigest: Array.from({ length: 32 }, (_, index) => 255 - index),
    challenge: Array.from({ length: 32 }, () => 0x42),
    origin: ORIGIN,
    rpId: RP_ID,
    discoverable: true,
    options: {
      challenge: Array.from({ length: 32 }, () => 0x42),
      rp: { id: RP_ID, name: 'Example Login' },
      user: {
        id: [0x75, 0x73, 0x65, 0x72],
        name: 'alice',
        displayName: 'Alice'
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      excludeCredentials: [],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'required',
        requireResidentKey: true,
        userVerification
      },
      attestation: 'none',
      extensions: {}
    }
  }
}

function getSnapshot(
  userVerification: 'required' | 'preferred' | 'discouraged' = 'discouraged',
  allowCredentialIds: readonly Uint8Array[] = [CREDENTIAL_ID]
): PasskeyIngressGetSnapshot {
  const controller = new AbortController()
  return {
    version: 1,
    kind: 'get',
    peer: { provider: 'browser-extension', binding: 'native-session-1', epoch: 3 },
    signal: controller.signal,
    clientDataJSON: [...CLIENT_DATA_JSON],
    clientDataHash: Array.from({ length: 32 }, (_, index) => index),
    requestDigest: Array.from({ length: 32 }, (_, index) => 255 - index),
    challenge: Array.from({ length: 32 }, () => 0x42),
    origin: ORIGIN,
    rpId: RP_ID,
    options: {
      challenge: Array.from({ length: 32 }, () => 0x42),
      rpId: RP_ID,
      allowCredentials: allowCredentialIds.map((id) => ({
        type: 'public-key' as const,
        id: [...id],
        transports: ['internal' as const]
      })),
      userVerification,
      mediation: 'required',
      extensions: {}
    }
  }
}

function target(overrides: Partial<PasskeyVaultCreationTarget> = {}): PasskeyVaultCreationTarget {
  return {
    itemId: ITEM_ID,
    itemName: 'Personal login',
    itemUpdatedAt: ITEM_REVISION,
    reprompt: 0,
    existingPasskeyCount: 0,
    ...overrides
  }
}

function candidate(
  overrides: Partial<PasskeyVaultCredentialCandidate> = {}
): PasskeyVaultCredentialCandidate {
  return {
    itemId: ITEM_ID,
    itemName: 'Personal login',
    itemUpdatedAt: ITEM_REVISION,
    reprompt: 0,
    credentialId: Uint8Array.from(CREDENTIAL_ID),
    rpId: RP_ID,
    userHandle: 'b64.dXNlcg',
    userName: 'alice',
    userDisplayName: 'Alice',
    discoverable: false,
    ...overrides
  }
}

interface HarnessOptions {
  targets?: PasskeyVaultCreationTarget[]
  credentials?: PasskeyVaultCredentialCandidate[]
  didPersistCounter?: boolean
  choiceIds?: string[]
  onVaultMutation?: () => void
}

function createHarness(options: HarnessOptions = {}): {
  service: PasskeyCeremonyService
  vault: PasskeyCeremonyVault & Record<string, ReturnType<typeof vi.fn>>
  bridge: PasskeyCeremonyRendererBridge & Record<string, ReturnType<typeof vi.fn>>
  settings: PasskeyCeremonySettings & Record<string, ReturnType<typeof vi.fn>>
  prompts: PasskeyRendererSafePrompt[]
  setConsent: (
    consent: (prompt: PasskeyRendererSafePrompt, signal: AbortSignal) => Promise<unknown>
  ) => void
  setProof: (proof: PasskeyPasswordProofBinding | undefined) => void
} {
  let proof: PasskeyPasswordProofBinding | undefined
  let consent: (
    prompt: PasskeyRendererSafePrompt,
    signal: AbortSignal
  ) => Promise<unknown> = async (prompt): Promise<PasskeyApprovalResponse> => ({
    requestId: prompt.requestId,
    approved: true,
    selectedChoiceId: prompt.choices[0]!.id,
    verificationMethod: 'none'
  })
  const prompts: PasskeyRendererSafePrompt[] = []
  const targets = options.targets ?? [target()]
  const credentials = options.credentials ?? [candidate()]
  const sameProof = (binding: PasskeyPasswordProofBinding): boolean =>
    proof !== undefined &&
    proof.requestId === binding.requestId &&
    proof.selectedChoiceId === binding.selectedChoiceId &&
    proof.vaultGeneration === binding.vaultGeneration

  const vault = {
    discoverPasskeyCreationTargets: vi.fn(async () => ({ generation: GENERATION, targets })),
    discoverPasskeyCredentials: vi.fn(async () => ({ generation: GENERATION, credentials })),
    authorizeLogin: vi.fn(async () => GENERATION),
    createPasskey: vi.fn(async (request, validateAuthorization) => {
      if (!validateAuthorization([request.itemId], { generation: GENERATION })) {
        throw new Error('REPROMPT_REQUIRED')
      }
      return {
        item: { id: request.itemId } as PasskeyVaultCreateResult['item'],
        generation: GENERATION,
        credentialId: Uint8Array.from([1, 2, 3, 4]),
        attestationObject: Uint8Array.from([5, 6]),
        authenticatorData: Uint8Array.from([7, 8]),
        publicKey: Uint8Array.from([9, 10]),
        publicKeyAlgorithm: -7,
        privateKey: 'must-never-escape',
        keyValue: 'must-never-escape'
      } as PasskeyVaultCreateResult
    }),
    getPasskeyAssertion: vi.fn(async (request, validateAuthorization) => {
      if (!validateAuthorization([request.itemId], { generation: GENERATION })) {
        throw new Error('REPROMPT_REQUIRED')
      }
      return {
        itemId: request.itemId,
        generation: GENERATION,
        credentialId: Uint8Array.from(request.credentialId),
        userHandle: Uint8Array.from([0x75, 0x73, 0x65, 0x72]),
        authenticatorData: Uint8Array.from([11, 12]),
        signature: Uint8Array.from([13, 14]),
        counter: options.didPersistCounter ? '1' : '0',
        didPersistCounter: options.didPersistCounter ?? false
      } satisfies PasskeyVaultAssertionResult
    })
  } as unknown as PasskeyCeremonyVault & Record<string, ReturnType<typeof vi.fn>>

  const bridge = {
    requestConsent: vi.fn(async (prompt: PasskeyRendererSafePrompt, signal: AbortSignal) => {
      prompts.push(prompt)
      return consent(prompt, signal)
    }),
    validateMasterPasswordProof: vi.fn((binding: PasskeyPasswordProofBinding) =>
      sameProof(binding)
    ),
    consumeMasterPasswordProof: vi.fn((binding: PasskeyPasswordProofBinding) => {
      const valid = sameProof(binding)
      proof = undefined
      return valid
    }),
    discardMasterPasswordProof: vi.fn((requestId: string) => {
      if (proof?.requestId === requestId) proof = undefined
    })
  } as PasskeyCeremonyRendererBridge & Record<string, ReturnType<typeof vi.fn>>
  const settings = {
    verifyTouchIdOperation: vi.fn(async () => undefined)
  } as PasskeyCeremonySettings & Record<string, ReturnType<typeof vi.fn>>
  let choiceIndex = 0
  const choiceIds = options.choiceIds ?? []
  const service = new PasskeyCeremonyService({
    vault,
    rendererBridge: bridge,
    settings,
    createChoiceId: () => choiceIds[choiceIndex++] ?? `opaque-choice-${choiceIndex}`,
    requestId: () => `request-${choiceIndex}`,
    onVaultMutation: options.onVaultMutation
  })
  return {
    service,
    vault,
    bridge,
    settings,
    prompts,
    setConsent: (next) => {
      consent = next
    },
    setProof: (next) => {
      proof = next
    }
  }
}

describe('PasskeyCeremonyService', () => {
  it('maps a replacement choice in main and redacts item revision and credential material', async () => {
    const replacement = target({ existingPasskeyCount: 1, reprompt: 1 })
    const harness = createHarness({ targets: [replacement], choiceIds: ['opaque-create-choice'] })
    harness.setConsent(async (prompt) => {
      harness.setProof({
        requestId: prompt.requestId,
        selectedChoiceId: prompt.choices[0]!.id,
        vaultGeneration: GENERATION
      })
      return {
        requestId: prompt.requestId,
        approved: true,
        selectedChoiceId: prompt.choices[0]!.id,
        verificationMethod: 'none'
      }
    })

    const response = await harness.service.create(createSnapshot())
    const prompt = harness.prompts[0]!
    const serializedPrompt = JSON.stringify(prompt)
    expect(prompt.choices).toEqual([
      {
        id: 'opaque-create-choice',
        label: replacement.itemName,
        detail: 'Replace existing passkey',
        requiresReprompt: true
      }
    ])
    expect(serializedPrompt).not.toContain(replacement.itemId)
    expect(serializedPrompt).not.toContain(replacement.itemUpdatedAt)
    expect(serializedPrompt).not.toContain(Buffer.from(CREDENTIAL_ID).toString('base64url'))
    expect(harness.vault.discoverPasskeyCreationTargets).toHaveBeenCalledWith({
      rpId: RP_ID,
      origin: ORIGIN
    })
    expect(harness.vault.createPasskey).toHaveBeenCalledWith(
      expect.objectContaining({
        itemId: replacement.itemId,
        expectedUpdatedAt: replacement.itemUpdatedAt,
        replaceExisting: true,
        requireUserVerification: false,
        userVerified: false
      }),
      expect.any(Function)
    )
    expect(response.rawId).toEqual(response.credentialId)
    expect(response.rawId).not.toBe(response.credentialId)
    expect(JSON.stringify(response)).not.toContain('privateKey')
    expect(JSON.stringify(response)).not.toContain('keyValue')
    expect(harness.bridge.discardMasterPasswordProof).toHaveBeenCalledWith(prompt.requestId)
  })

  it('discovers exact RP/allow IDs and maps the selected opaque choice to exact credential bytes', async () => {
    const allowed = Uint8Array.from([0xde, 0xad, 0xbe, 0xef])
    const selected = candidate({ credentialId: allowed, userDisplayName: 'Selected account' })
    const harness = createHarness({ credentials: [selected] })
    harness.setConsent(async (prompt) => ({
      requestId: prompt.requestId,
      approved: true,
      selectedChoiceId: prompt.choices[0]!.id,
      verificationMethod: 'touch-id'
    }))

    const response = await harness.service.get(getSnapshot('required', [allowed]))
    expect(harness.vault.discoverPasskeyCredentials).toHaveBeenCalledWith({
      rpId: RP_ID,
      allowCredentialIds: [allowed]
    })
    expect(harness.vault.getPasskeyAssertion).toHaveBeenCalledWith(
      expect.objectContaining({
        itemId: selected.itemId,
        expectedUpdatedAt: selected.itemUpdatedAt,
        credentialId: allowed,
        allowCredentialIds: [allowed],
        rpId: RP_ID,
        requireUserVerification: true,
        userVerified: true
      }),
      expect.any(Function)
    )
    expect(harness.settings.verifyTouchIdOperation).toHaveBeenCalledWith('usePasskey')
    expect(response.credentialId).toEqual(allowed)
    expect(response.clientDataJSON).toEqual(CLIENT_DATA_JSON)
    expect(response).not.toHaveProperty('didPersistCounter')
  })

  it.each([
    {
      title: 'master-password UV consumes a separate protected-item proof',
      uv: 'required' as const,
      method: 'master-password' as const,
      reprompt: 1 as const,
      expectsTouch: false,
      expectsValidate: true,
      expectsConsume: true
    },
    {
      title: 'Touch ID UV still consumes a separate protected-item proof',
      uv: 'preferred' as const,
      method: 'touch-id' as const,
      reprompt: 1 as const,
      expectsTouch: true,
      expectsValidate: false,
      expectsConsume: true
    },
    {
      title: 'discouraged UV still consumes a protected-item proof',
      uv: 'discouraged' as const,
      method: 'none' as const,
      reprompt: 1 as const,
      expectsTouch: false,
      expectsValidate: false,
      expectsConsume: true
    },
    {
      title: 'discouraged UV needs no proof for an unprotected item',
      uv: 'discouraged' as const,
      method: 'none' as const,
      reprompt: 0 as const,
      expectsTouch: false,
      expectsValidate: false,
      expectsConsume: false
    }
  ])('$title', async ({ uv, method, reprompt, expectsTouch, expectsValidate, expectsConsume }) => {
    const harness = createHarness({ targets: [target({ reprompt })] })
    harness.setConsent(async (prompt, signal) => {
      if (reprompt === 1) {
        const generation = await harness.service.verifyMasterPassword(
          prompt.requestId,
          prompt.choices[0]!.id,
          'correct horse battery staple',
          signal
        )
        harness.setProof({
          requestId: prompt.requestId,
          selectedChoiceId: prompt.choices[0]!.id,
          vaultGeneration: generation
        })
      }
      return {
        requestId: prompt.requestId,
        approved: true,
        selectedChoiceId: prompt.choices[0]!.id,
        verificationMethod: method
      }
    })

    await harness.service.create(createSnapshot(uv))
    expect(harness.settings.verifyTouchIdOperation).toHaveBeenCalledTimes(expectsTouch ? 1 : 0)
    expect(harness.bridge.validateMasterPasswordProof).toHaveBeenCalledTimes(
      expectsValidate ? 1 : 0
    )
    expect(harness.bridge.consumeMasterPasswordProof).toHaveBeenCalledTimes(expectsConsume ? 1 : 0)
    if (reprompt === 1) {
      expect(harness.vault.authorizeLogin).toHaveBeenCalledWith({
        id: ITEM_ID,
        masterPassword: 'correct horse battery staple'
      })
    }
  })

  it('rejects wrong request/choice/generation proof bindings and accepts only the exact mapping', async () => {
    const harness = createHarness({ targets: [target({ reprompt: 1 })] })
    harness.setConsent(async (prompt, signal) => {
      await expect(
        harness.service.verifyMasterPassword(
          prompt.requestId,
          prompt.choices[0]!.id,
          'password',
          new AbortController().signal
        )
      ).rejects.toMatchObject({ code: 'REQUEST_INVALIDATED' })
      await expect(
        harness.service.verifyMasterPassword(
          'wrong-request',
          prompt.choices[0]!.id,
          'password',
          signal
        )
      ).rejects.toMatchObject({ code: 'REQUEST_INVALIDATED' })
      await expect(
        harness.service.verifyMasterPassword(prompt.requestId, 'wrong-choice', 'password', signal)
      ).rejects.toMatchObject({ code: 'REQUEST_INVALIDATED' })
      vi.mocked(harness.vault.authorizeLogin).mockResolvedValueOnce(GENERATION + 1)
      await expect(
        harness.service.verifyMasterPassword(
          prompt.requestId,
          prompt.choices[0]!.id,
          'password',
          signal
        )
      ).rejects.toMatchObject({ code: 'REQUEST_INVALIDATED' })
      vi.mocked(harness.vault.authorizeLogin).mockResolvedValueOnce(GENERATION)
      const generation = await harness.service.verifyMasterPassword(
        prompt.requestId,
        prompt.choices[0]!.id,
        'password',
        signal
      )
      harness.setProof({
        requestId: prompt.requestId,
        selectedChoiceId: prompt.choices[0]!.id,
        vaultGeneration: generation
      })
      return {
        requestId: prompt.requestId,
        approved: true,
        selectedChoiceId: prompt.choices[0]!.id,
        verificationMethod: 'none'
      }
    })

    await expect(harness.service.create(createSnapshot())).resolves.toMatchObject({
      type: 'public-key'
    })
  })

  it('rejects a proof whose bridge generation does not match discovery', async () => {
    const harness = createHarness({ targets: [target({ reprompt: 1 })] })
    harness.setConsent(async (prompt) => {
      harness.setProof({
        requestId: prompt.requestId,
        selectedChoiceId: prompt.choices[0]!.id,
        vaultGeneration: GENERATION + 1
      })
      return {
        requestId: prompt.requestId,
        approved: true,
        selectedChoiceId: prompt.choices[0]!.id,
        verificationMethod: 'master-password'
      }
    })

    await expect(harness.service.create(createSnapshot('required'))).rejects.toMatchObject({
      code: 'USER_VERIFICATION_FAILED'
    })
    expect(harness.vault.createPasskey).not.toHaveBeenCalled()
    expect(harness.bridge.discardMasterPasswordProof).toHaveBeenCalledTimes(1)
  })

  it('rejects stale vault result mappings instead of publishing a response or mutation', async () => {
    const notification = vi.fn()
    const harness = createHarness({ onVaultMutation: notification })
    vi.mocked(harness.vault.createPasskey).mockResolvedValueOnce({
      item: { id: '20000000-0000-4000-8000-000000000002' } as PasskeyVaultCreateResult['item'],
      generation: GENERATION,
      credentialId: Uint8Array.from([1]),
      attestationObject: Uint8Array.from([2]),
      authenticatorData: Uint8Array.from([3]),
      publicKey: Uint8Array.from([4]),
      publicKeyAlgorithm: -7
    })

    await expect(harness.service.create(createSnapshot())).rejects.toMatchObject({
      code: 'REQUEST_INVALIDATED'
    })
    expect(notification).not.toHaveBeenCalled()
  })

  it('notifies only persisted mutations, after coordinator cleanup and vault commit', async () => {
    let committed = false
    let service: PasskeyCeremonyService
    const notification = vi.fn(() => {
      expect(committed).toBe(true)
      expect(service.activeRequestCount).toBe(0)
    })
    const createHarnessResult = createHarness({ onVaultMutation: notification })
    service = createHarnessResult.service
    vi.mocked(createHarnessResult.vault.createPasskey).mockImplementationOnce(
      async (request, validateAuthorization) => {
        expect(validateAuthorization([request.itemId], { generation: GENERATION })).toBe(true)
        committed = true
        return {
          item: { id: request.itemId } as PasskeyVaultCreateResult['item'],
          generation: GENERATION,
          credentialId: Uint8Array.from([1]),
          attestationObject: Uint8Array.from([2]),
          authenticatorData: Uint8Array.from([3]),
          publicKey: Uint8Array.from([4]),
          publicKeyAlgorithm: -7
        }
      }
    )
    await service.create(createSnapshot())
    expect(notification).toHaveBeenCalledTimes(1)

    const zeroCounter = createHarness({ didPersistCounter: false, onVaultMutation: notification })
    await zeroCounter.service.get(getSnapshot())
    expect(notification).toHaveBeenCalledTimes(1)
    const nonzeroCounter = createHarness({ didPersistCounter: true, onVaultMutation: notification })
    service = nonzeroCounter.service
    await nonzeroCounter.service.get(getSnapshot())
    expect(notification).toHaveBeenCalledTimes(2)
  })

  it('aborts pending ceremonies on lock and peer invalidation', async () => {
    let releaseConsent: (() => void) | undefined
    const locked = createHarness()
    locked.setConsent(
      (prompt) =>
        new Promise((resolve) => {
          releaseConsent = () =>
            resolve({
              requestId: prompt.requestId,
              approved: true,
              selectedChoiceId: prompt.choices[0]!.id,
              verificationMethod: 'none'
            })
        })
    )
    const lockedRequest = locked.service.get(getSnapshot())
    await vi.waitFor(() => expect(locked.prompts).toHaveLength(1))
    locked.service.onLocked()
    await expect(lockedRequest).rejects.toMatchObject({ code: 'REQUEST_INVALIDATED' })
    releaseConsent?.()

    const invalidated = createHarness()
    invalidated.setConsent(() => new Promise(() => undefined))
    const invalidatedRequest = invalidated.service.get(getSnapshot())
    await vi.waitFor(() => expect(invalidated.prompts).toHaveLength(1))
    invalidated.service.invalidatePeer({
      provider: 'browser-extension',
      binding: 'native-session-1',
      epoch: 3
    })
    await expect(invalidatedRequest).rejects.toMatchObject({ code: 'REQUEST_INVALIDATED' })
  })

  it('fails closed on empty discovery, duplicate choices, and wrong ceremony kind', async () => {
    const emptyTargets = createHarness({ targets: [] })
    await expect(emptyTargets.service.create(createSnapshot())).rejects.toMatchObject({
      code: 'REQUEST_UNAVAILABLE'
    })
    const emptyCredentials = createHarness({ credentials: [] })
    await expect(emptyCredentials.service.get(getSnapshot())).rejects.toMatchObject({
      code: 'REQUEST_UNAVAILABLE'
    })
    const duplicate = createHarness({
      targets: [target(), target({ itemId: `${ITEM_ID.slice(0, -1)}2` })],
      choiceIds: ['duplicate', 'duplicate']
    })
    await expect(duplicate.service.create(createSnapshot())).rejects.toMatchObject({
      code: 'INVALID_REQUEST'
    })
    await expect(
      duplicate.service.create(getSnapshot() as unknown as PasskeyIngressCreateSnapshot)
    ).rejects.toMatchObject({ code: 'INVALID_REQUEST' })

    const tooMany = createHarness({
      targets: Array.from({ length: 101 }, (_, index) =>
        target({ itemId: `item-${index}`, itemUpdatedAt: `revision-${index}` })
      )
    })
    await expect(tooMany.service.create(createSnapshot())).rejects.toMatchObject({
      code: 'INVALID_REQUEST'
    })

    const embeddedIdentifier = createHarness({
      choiceIds: [`opaque-${ITEM_ID}-choice`]
    })
    await expect(embeddedIdentifier.service.create(createSnapshot())).rejects.toMatchObject({
      code: 'INVALID_REQUEST'
    })
  })

  it('allows a retired opaque ID to be reused without retaining unbounded request history', async () => {
    const harness = createHarness({ choiceIds: ['retired-choice', 'retired-choice'] })
    await expect(harness.service.create(createSnapshot())).resolves.toMatchObject({
      type: 'public-key'
    })
    await expect(harness.service.create(createSnapshot())).resolves.toMatchObject({
      type: 'public-key'
    })
  })

  it('caps pending ceremonies at sixteen and dispose aborts every admitted request', async () => {
    const harness = createHarness()
    harness.setConsent(() => new Promise(() => undefined))
    const pending = Array.from({ length: 16 }, () => harness.service.get(getSnapshot()))
    await vi.waitFor(() => expect(harness.prompts).toHaveLength(16))
    await expect(harness.service.get(getSnapshot())).rejects.toMatchObject({
      code: 'REQUEST_UNAVAILABLE'
    })
    harness.service.dispose()
    const results = await Promise.allSettled(pending)
    expect(results).toHaveLength(16)
    expect(results.every((result) => result.status === 'rejected')).toBe(true)
    expect(harness.service.activeRequestCount).toBe(0)
  })

  it('returns independent exact-byte snapshots without private vault material', async () => {
    const harness = createHarness()
    const response = await harness.service.create(createSnapshot())
    expect(response.clientDataJSON).toEqual(CLIENT_DATA_JSON)
    const originalCredentialId = [...response.credentialId]
    response.rawId[0] = 0xff
    response.clientDataJSON[0] = 0xff
    expect([...response.credentialId]).toEqual(originalCredentialId)
    expect(harness.prompts[0]).not.toHaveProperty('clientDataJSON')
    expect(harness.prompts[0]).not.toHaveProperty('credentialId')
    expect(JSON.stringify(response)).not.toContain('must-never-escape')
  })
})
