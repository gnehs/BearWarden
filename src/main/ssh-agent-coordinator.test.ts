import { describe, expect, it, vi } from 'vitest'
import type { SshAgentPromptBehavior } from '../shared/vault-contract'
import type { SshAgentVaultIdentity } from './vault-service'
import {
  SshAgentCoordinator,
  type SshAgentCoordinatorOptions,
  type SshAgentCoordinatorVault,
  type SshAgentRendererApprovalResult
} from './ssh-agent-coordinator'
import type {
  SshAgentApprovalRequest,
  SshAgentConnectionContext,
  SshAgentSignRequest
} from './ssh-agent-server'

const ITEM_ID = '11111111-1111-4111-8111-111111111111'
const KEY_BLOB = Buffer.from('public-key-blob')

function identity(overrides: Partial<SshAgentVaultIdentity> = {}): SshAgentVaultIdentity {
  return {
    itemId: ITEM_ID,
    name: 'Work SSH key',
    publicKeyBlob: Buffer.from(KEY_BLOB),
    fingerprint: 'SHA256:public-fingerprint',
    reprompt: 0,
    generation: 3,
    ...overrides
  }
}

function connection(forwarded = false, hostFingerprint?: string): SshAgentConnectionContext {
  return {
    processName: 'ssh',
    session: { forwarded, hostFingerprint }
  }
}

function approvalRequest(
  requestId: string,
  options: {
    key?: Buffer
    forwarded?: boolean
    hostFingerprint?: string
    signal?: AbortSignal
  } = {}
): SshAgentApprovalRequest {
  return {
    requestId,
    publicKeyBlob: Buffer.from(options.key ?? KEY_BLOB),
    flags: 0,
    rsaHash: undefined,
    namespace: 'git',
    connection: connection(options.forwarded, options.hostFingerprint),
    signal: options.signal ?? new AbortController().signal
  }
}

function signRequest(
  requestId: string,
  options: { key?: Buffer; forwarded?: boolean; hostFingerprint?: string } = {}
): SshAgentSignRequest {
  return {
    ...approvalRequest(requestId, options),
    data: Buffer.from('payload')
  }
}

interface Harness {
  coordinator: SshAgentCoordinator
  vault: SshAgentCoordinatorVault
  identities: SshAgentVaultIdentity[]
  setPromptBehavior: (value: SshAgentPromptBehavior) => void
  setApprovalResult: (value: SshAgentRendererApprovalResult) => void
  focusWindow: ReturnType<typeof vi.fn>
  waitForUnlock: ReturnType<typeof vi.fn>
  requestRendererApproval: ReturnType<typeof vi.fn>
  validateAuthorizationToken: ReturnType<typeof vi.fn>
}

function harness(initialIdentity = identity()): Harness {
  const identities = [initialIdentity]
  let promptBehavior: SshAgentPromptBehavior = 'always'
  let approvalResult: SshAgentRendererApprovalResult = { approved: true }
  const focusWindow = vi.fn()
  const waitForUnlock = vi.fn(async () => true)
  const requestRendererApproval = vi.fn(async () => approvalResult)
  const validateAuthorizationToken = vi.fn(
    (token: string, itemId: string, generation: number) => token === `token:${itemId}:${generation}`
  )
  const vault: SshAgentCoordinatorVault = {
    listSshAgentIdentities: vi.fn(async () => identities.map((entry) => identity(entry))),
    signSshAgentRequest: vi.fn(async (request, validate) => {
      const current = identities.find((entry) => entry.publicKeyBlob.equals(request.publicKeyBlob))
      if (!current || current.generation !== request.expectedGeneration) throw new Error('LOCKED')
      if (
        current.reprompt === 1 &&
        !validate([current.itemId], { generation: current.generation })
      ) {
        throw new Error('REPROMPT_REQUIRED')
      }
      return {
        itemId: current.itemId,
        generation: current.generation,
        algorithm: 'ssh-ed25519',
        signature: Buffer.alloc(64, 7)
      }
    })
  }
  const options: SshAgentCoordinatorOptions = {
    vault,
    focusWindow,
    waitForUnlock,
    getSettings: () => ({ sshAgentPromptBehavior: promptBehavior }),
    requestRendererApproval,
    validateAuthorizationToken
  }
  return {
    coordinator: new SshAgentCoordinator(options),
    vault,
    identities,
    setPromptBehavior: (value) => {
      promptBehavior = value
    },
    setApprovalResult: (value) => {
      approvalResult = value
    },
    focusWindow,
    waitForUnlock,
    requestRendererApproval,
    validateAuthorizationToken
  }
}

describe('SshAgentCoordinator', () => {
  it('waits for first unlock, then serves only cached public identities after lock', async () => {
    const current = harness()
    const signal = new AbortController().signal

    await expect(
      current.coordinator.provider.listIdentities({ connection: connection(), signal })
    ).resolves.toEqual([{ keyBlob: KEY_BLOB, comment: 'Work SSH key' }])
    expect(current.focusWindow).toHaveBeenCalledOnce()
    expect(current.waitForUnlock).toHaveBeenCalledOnce()

    current.coordinator.onLocked()
    await expect(
      current.coordinator.provider.listIdentities({ connection: connection(), signal })
    ).resolves.toEqual([{ keyBlob: KEY_BLOB, comment: 'Work SSH key' }])
    expect(current.waitForUnlock).toHaveBeenCalledOnce()
    expect(current.vault.listSshAgentIdentities).toHaveBeenCalledOnce()
  })

  it('rejects an unknown AFU key without focusing or opening an approval dialog', async () => {
    const current = harness()
    await current.coordinator.onUnlocked()
    current.coordinator.onLocked()
    const approved = await current.coordinator.approvalHandler.approveSign(
      approvalRequest('unknown', { key: Buffer.from('unknown') })
    )

    expect(approved).toBe(false)
    expect(current.focusWindow).not.toHaveBeenCalled()
    expect(current.waitForUnlock).not.toHaveBeenCalled()
    expect(current.requestRendererApproval).not.toHaveBeenCalled()
  })

  it('implements always and never policies without weakening vault reprompt', async () => {
    const current = harness()
    await current.coordinator.onUnlocked()

    expect(await current.coordinator.approvalHandler.approveSign(approvalRequest('always'))).toBe(
      true
    )
    expect(current.requestRendererApproval).toHaveBeenCalledOnce()
    const rendererPayload = current.requestRendererApproval.mock.calls[0]![0]
    expect(rendererPayload).toMatchObject({
      itemId: ITEM_ID,
      itemName: 'Work SSH key',
      fingerprint: 'SHA256:public-fingerprint',
      requiresAgentApproval: true,
      requiresReprompt: false,
      namespace: 'git'
    })
    expect(rendererPayload).not.toHaveProperty('data')
    expect(rendererPayload).not.toHaveProperty('privateKey')
    await expect(current.coordinator.provider.sign(signRequest('always'))).resolves.toMatchObject({
      algorithm: 'ssh-ed25519'
    })

    current.setPromptBehavior('never')
    expect(await current.coordinator.approvalHandler.approveSign(approvalRequest('never'))).toBe(
      true
    )
    expect(current.requestRendererApproval).toHaveBeenCalledOnce()
    await expect(current.coordinator.provider.sign(signRequest('never'))).resolves.toBeDefined()
  })

  it('remembers approvals by item and local or verified forwarding host until lock', async () => {
    const current = harness()
    current.setPromptBehavior('rememberUntilLock')
    await current.coordinator.onUnlocked()

    for (const requestId of ['local-1', 'local-2']) {
      expect(
        await current.coordinator.approvalHandler.approveSign(approvalRequest(requestId))
      ).toBe(true)
      await current.coordinator.provider.sign(signRequest(requestId))
    }
    expect(current.requestRendererApproval).toHaveBeenCalledTimes(1)

    for (const requestId of ['host-a-1', 'host-a-2']) {
      const context = { forwarded: true, hostFingerprint: 'SHA256:host-a' }
      expect(
        await current.coordinator.approvalHandler.approveSign(approvalRequest(requestId, context))
      ).toBe(true)
      await current.coordinator.provider.sign(signRequest(requestId, context))
    }
    expect(current.requestRendererApproval).toHaveBeenCalledTimes(2)

    expect(
      await current.coordinator.approvalHandler.approveSign(
        approvalRequest('host-b', { forwarded: true, hostFingerprint: 'SHA256:host-b' })
      )
    ).toBe(true)
    await current.coordinator.provider.sign(
      signRequest('host-b', { forwarded: true, hostFingerprint: 'SHA256:host-b' })
    )

    for (const requestId of ['unverified-1', 'unverified-2']) {
      expect(
        await current.coordinator.approvalHandler.approveSign(
          approvalRequest(requestId, { forwarded: true })
        )
      ).toBe(true)
      await current.coordinator.provider.sign(signRequest(requestId, { forwarded: true }))
    }
    expect(current.requestRendererApproval).toHaveBeenCalledTimes(5)

    current.coordinator.onLocked()
    current.setPromptBehavior('rememberUntilLock')
    expect(
      await current.coordinator.approvalHandler.approveSign(approvalRequest('after-lock'))
    ).toBe(true)
    expect(current.requestRendererApproval).toHaveBeenCalledTimes(6)
  })

  it('requires a renderer-issued master-password capability even under never policy', async () => {
    const protectedIdentity = identity({ reprompt: 1 })
    const current = harness(protectedIdentity)
    current.setPromptBehavior('never')
    current.setApprovalResult({
      approved: true,
      authorizationToken: `token:${ITEM_ID}:${protectedIdentity.generation}`
    })
    await current.coordinator.onUnlocked()

    expect(await current.coordinator.approvalHandler.approveSign(approvalRequest('reprompt'))).toBe(
      true
    )
    expect(current.requestRendererApproval).toHaveBeenCalledWith(
      expect.objectContaining({ requiresAgentApproval: false, requiresReprompt: true }),
      expect.any(AbortSignal)
    )
    await expect(current.coordinator.provider.sign(signRequest('reprompt'))).resolves.toBeDefined()
    expect(current.validateAuthorizationToken).toHaveBeenCalledWith(
      `token:${ITEM_ID}:${protectedIdentity.generation}`,
      ITEM_ID,
      protectedIdentity.generation
    )

    current.setApprovalResult({ approved: true })
    await expect(
      current.coordinator.approvalHandler.approveSign(approvalRequest('missing-token'))
    ).resolves.toBe(false)
  })

  it('fails closed when sync enables reprompt after agent approval', async () => {
    const current = harness()
    await current.coordinator.onUnlocked()
    expect(
      await current.coordinator.approvalHandler.approveSign(approvalRequest('reprompt-race'))
    ).toBe(true)

    current.identities[0] = identity({ reprompt: 1 })
    await expect(
      current.coordinator.provider.sign(signRequest('reprompt-race'))
    ).resolves.toBeUndefined()
    expect(current.vault.signSshAgentRequest).toHaveBeenCalledOnce()
  })

  it('consumes request grants once and rejects duplicate concurrent request IDs', async () => {
    const current = harness()
    await current.coordinator.onUnlocked()
    let resolveApproval!: (value: SshAgentRendererApprovalResult) => void
    current.requestRendererApproval.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveApproval = resolve
        })
    )

    const first = current.coordinator.approvalHandler.approveSign(approvalRequest('same'))
    await Promise.resolve()
    await expect(
      current.coordinator.approvalHandler.approveSign(approvalRequest('same'))
    ).resolves.toBe(false)
    resolveApproval({ approved: true })
    await expect(first).resolves.toBe(true)

    await expect(current.coordinator.provider.sign(signRequest('same'))).resolves.toBeDefined()
    await expect(current.coordinator.provider.sign(signRequest('same'))).resolves.toBeUndefined()
    expect(current.vault.signSshAgentRequest).toHaveBeenCalledOnce()
  })

  it('invalidates pending work on abort, lock, reset, cache changes, and generation changes', async () => {
    const current = harness()
    await current.coordinator.onUnlocked()

    const abort = new AbortController()
    let resolveApproval!: (value: SshAgentRendererApprovalResult) => void
    current.requestRendererApproval.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveApproval = resolve
        })
    )
    const aborted = current.coordinator.approvalHandler.approveSign(
      approvalRequest('aborted', { signal: abort.signal })
    )
    abort.abort()
    await expect(aborted).resolves.toBe(false)
    resolveApproval({ approved: true })
    await Promise.resolve()
    await expect(current.coordinator.provider.sign(signRequest('aborted'))).resolves.toBeUndefined()

    current.requestRendererApproval.mockResolvedValue({ approved: true })
    expect(await current.coordinator.approvalHandler.approveSign(approvalRequest('locked'))).toBe(
      true
    )
    current.coordinator.onLocked()
    await expect(current.coordinator.provider.sign(signRequest('locked'))).resolves.toBeUndefined()

    await current.coordinator.onUnlocked()
    expect(
      await current.coordinator.approvalHandler.approveSign(approvalRequest('refreshed'))
    ).toBe(true)
    await current.coordinator.refreshIdentities()
    await expect(
      current.coordinator.provider.sign(signRequest('refreshed'))
    ).resolves.toBeUndefined()

    expect(await current.coordinator.approvalHandler.approveSign(approvalRequest('stale'))).toBe(
      true
    )
    current.identities[0] = identity({ generation: 99 })
    await expect(current.coordinator.provider.sign(signRequest('stale'))).resolves.toBeUndefined()

    current.coordinator.reset()
    current.identities.length = 0
    const listSignal = new AbortController().signal
    await expect(
      current.coordinator.provider.listIdentities({ connection: connection(), signal: listSignal })
    ).resolves.toEqual([])
    expect(current.waitForUnlock).toHaveBeenCalled()
  })
})
