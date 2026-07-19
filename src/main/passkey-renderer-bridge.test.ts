import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const electronMock = vi.hoisted(() => ({
  handlers: new Map<string, (event: never, input?: unknown) => unknown>(),
  removeHandler: vi.fn()
}))

vi.mock('electron', () => ({
  ipcMain: {
    handle: vi.fn((channel: string, handler: (event: never, input?: unknown) => unknown) => {
      electronMock.handlers.set(channel, handler)
    }),
    removeHandler: electronMock.removeHandler
  }
}))

import { IPC_CHANNELS, IPC_EVENTS } from '../shared/vault-contract'
import type {
  PasskeyRendererSafePrompt,
  PasskeyVerificationRequest
} from './passkey-request-coordinator'
import { PasskeyRendererBridge } from './passkey-renderer-bridge'

class FakeWebContents extends EventEmitter {
  readonly id = 29
  readonly mainFrame = { url: 'app://bearwarden/index.html' }
  readonly send = vi.fn()
  destroyed = false

  getURL(): string {
    return this.mainFrame.url
  }

  isDestroyed(): boolean {
    return this.destroyed
  }
}

function safePrompt(overrides: Partial<PasskeyRendererSafePrompt> = {}): PasskeyRendererSafePrompt {
  return {
    requestId: 'request-1',
    expiresAt: Date.now() + 60_000,
    kind: 'get',
    rpId: 'login.example.invalid',
    rpName: 'Example',
    userVerification: 'required',
    choices: [
      { id: '00000000-0000-4000-8000-000000000001', label: 'Personal account' },
      {
        id: '00000000-0000-4000-8000-000000000002',
        label: 'Work account',
        detail: 'work-user'
      }
    ],
    ...overrides
  }
}

function verificationRequest(
  overrides: Partial<PasskeyVerificationRequest> = {}
): PasskeyVerificationRequest {
  return {
    requestId: 'request-1',
    kind: 'get',
    method: 'master-password',
    selectedChoiceId: '00000000-0000-4000-8000-000000000002',
    peerBinding: 'authenticated-peer',
    peerEpoch: 3,
    vaultGeneration: 7,
    lockEpoch: 1,
    mutationEpoch: 2,
    requestDigest: Object.freeze(Array(32).fill(0x42)),
    origin: 'https://login.example.invalid',
    ...overrides
  }
}

function harness(options: { timeout?: number; max?: number; now?: () => number } = {}): {
  bridge: PasskeyRendererBridge
  webContents: FakeWebContents
  window: { webContents: FakeWebContents; isDestroyed: () => boolean }
  trustedEvent: { sender: FakeWebContents; senderFrame: FakeWebContents['mainFrame'] }
  focusWindow: ReturnType<typeof vi.fn>
  getVerificationMethods: ReturnType<typeof vi.fn>
  verifyMasterPassword: ReturnType<typeof vi.fn>
} {
  const webContents = new FakeWebContents()
  const window = { webContents, isDestroyed: () => false }
  const focusWindow = vi.fn()
  const getVerificationMethods = vi.fn(() => ['touch-id', 'master-password'] as const)
  const verifyMasterPassword = vi.fn(async () => 7)
  const bridge = new PasskeyRendererBridge({
    getMainWindow: () => window as never,
    focusWindow,
    getVerificationMethods,
    verifyMasterPassword,
    ...(options.timeout === undefined ? {} : { approvalTimeoutMs: options.timeout }),
    ...(options.max === undefined ? {} : { maxPendingApprovals: options.max }),
    ...(options.now === undefined ? {} : { now: options.now })
  })
  bridge.attachWindow(window as never)
  return {
    bridge,
    webContents,
    window,
    trustedEvent: { sender: webContents, senderFrame: webContents.mainFrame },
    focusWindow,
    getVerificationMethods,
    verifyMasterPassword
  }
}

beforeEach(() => {
  electronMock.handlers.clear()
  electronMock.removeHandler.mockClear()
})

afterEach(() => vi.useRealTimers())

describe('PasskeyRendererBridge', () => {
  it('publishes only renderer-safe prompt metadata through the current main frame', async () => {
    const { bridge, webContents, trustedEvent } = harness()
    const operation = bridge.requestConsent(safePrompt(), new AbortController().signal)
    await vi.waitFor(() => expect(webContents.send).toHaveBeenCalledOnce())

    const [eventName, prompt] = webContents.send.mock.calls[0]!
    expect(eventName).toBe(IPC_EVENTS.passkeyApprovalRequested)
    expect(prompt).toMatchObject({
      requestId: 'request-1',
      kind: 'get',
      rpId: 'login.example.invalid',
      verificationMethods: ['touch-id', 'master-password']
    })
    expect(prompt).not.toHaveProperty('origin')
    expect(prompt).not.toHaveProperty('challenge')
    expect(prompt).not.toHaveProperty('clientDataHash')
    expect(prompt).not.toHaveProperty('requestDigest')
    expect(prompt).not.toHaveProperty('peerBinding')
    expect(prompt).not.toHaveProperty('vaultGeneration')
    expect(JSON.stringify(prompt)).not.toContain('credentialId')
    expect(JSON.stringify(prompt)).not.toContain('userHandle')

    const respond = electronMock.handlers.get(IPC_CHANNELS.passkeyRespondApproval)!
    await respond(trustedEvent as never, {
      requestId: 'request-1',
      approved: true,
      selectedChoiceId: '00000000-0000-4000-8000-000000000001',
      verificationMethod: 'touch-id'
    })
    await expect(operation).resolves.toMatchObject({ verificationMethod: 'touch-id' })
    bridge.dispose()
  })

  it('verifies a password in main and consumes its request-bound proof exactly once', async () => {
    const { bridge, trustedEvent, verifyMasterPassword } = harness()
    const operation = bridge.requestConsent(safePrompt(), new AbortController().signal)
    await Promise.resolve()
    const verifyApproval = electronMock.handlers.get(IPC_CHANNELS.passkeyVerifyApproval)!
    const respond = electronMock.handlers.get(IPC_CHANNELS.passkeyRespondApproval)!
    const selectedChoiceId = '00000000-0000-4000-8000-000000000002'

    await verifyApproval(trustedEvent as never, {
      requestId: 'request-1',
      selectedChoiceId,
      masterPassword: 'correct horse battery staple'
    })
    expect(verifyMasterPassword).toHaveBeenCalledWith(
      'request-1',
      selectedChoiceId,
      'correct horse battery staple',
      expect.any(AbortSignal)
    )
    await respond(trustedEvent as never, {
      requestId: 'request-1',
      approved: true,
      selectedChoiceId,
      verificationMethod: 'master-password'
    })
    await expect(operation).resolves.toEqual({
      requestId: 'request-1',
      approved: true,
      selectedChoiceId,
      verificationMethod: 'master-password'
    })

    expect(bridge.validateMasterPasswordProof(verificationRequest())).toBe(true)
    expect(bridge.validateMasterPasswordProof(verificationRequest())).toBe(true)
    expect(bridge.consumeMasterPasswordProof(verificationRequest())).toBe(true)
    expect(bridge.consumeMasterPasswordProof(verificationRequest())).toBe(false)
    bridge.dispose()
  })

  it('binds password proof to the selected choice, vault generation, renderer, and expiry', async () => {
    let now = 1_000
    const { bridge, trustedEvent } = harness({ now: () => now })
    const operation = bridge.requestConsent(safePrompt(), new AbortController().signal)
    await Promise.resolve()
    const verifyApproval = electronMock.handlers.get(IPC_CHANNELS.passkeyVerifyApproval)!
    const respond = electronMock.handlers.get(IPC_CHANNELS.passkeyRespondApproval)!
    const selectedChoiceId = '00000000-0000-4000-8000-000000000001'

    await verifyApproval(trustedEvent as never, {
      requestId: 'request-1',
      selectedChoiceId,
      masterPassword: 'master password'
    })
    await respond(trustedEvent as never, {
      requestId: 'request-1',
      approved: true,
      selectedChoiceId,
      verificationMethod: 'master-password'
    })
    await operation
    expect(
      bridge.consumeMasterPasswordProof(
        verificationRequest({ selectedChoiceId, vaultGeneration: 8 })
      )
    ).toBe(false)

    const second = bridge.requestConsent(
      safePrompt({ requestId: 'request-2' }),
      new AbortController().signal
    )
    await Promise.resolve()
    await verifyApproval(trustedEvent as never, {
      requestId: 'request-2',
      selectedChoiceId,
      masterPassword: 'master password'
    })
    await respond(trustedEvent as never, {
      requestId: 'request-2',
      approved: true,
      selectedChoiceId,
      verificationMethod: 'master-password'
    })
    await second
    now += 60_001
    expect(
      bridge.consumeMasterPasswordProof(
        verificationRequest({ requestId: 'request-2', selectedChoiceId })
      )
    ).toBe(false)
    bridge.dispose()
  })

  it('does not treat renderer method selection or a forged UV boolean as verification', async () => {
    const { bridge, trustedEvent } = harness()
    const operation = bridge.requestConsent(safePrompt(), new AbortController().signal)
    await Promise.resolve()
    const respond = electronMock.handlers.get(IPC_CHANNELS.passkeyRespondApproval)!

    await expect(
      Promise.resolve().then(() =>
        respond(trustedEvent as never, {
          requestId: 'request-1',
          approved: true,
          selectedChoiceId: '00000000-0000-4000-8000-000000000001',
          verificationMethod: 'master-password'
        })
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    await expect(
      Promise.resolve().then(() =>
        respond(trustedEvent as never, {
          requestId: 'request-1',
          approved: true,
          selectedChoiceId: '00000000-0000-4000-8000-000000000001',
          verificationMethod: 'touch-id',
          userVerified: true
        })
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')

    await respond(trustedEvent as never, {
      requestId: 'request-1',
      approved: false
    })
    await expect(operation).resolves.toEqual({ requestId: 'request-1', approved: false })
    bridge.dispose()
  })

  it('uses no UV method for discouraged requests and refuses password verification', async () => {
    const { bridge, webContents, trustedEvent, getVerificationMethods } = harness()
    const operation = bridge.requestConsent(
      safePrompt({ userVerification: 'discouraged' }),
      new AbortController().signal
    )
    await vi.waitFor(() => expect(webContents.send).toHaveBeenCalledOnce())
    expect(webContents.send.mock.calls[0]![1]).toMatchObject({ verificationMethods: [] })
    expect(getVerificationMethods).not.toHaveBeenCalled()

    const verifyApproval = electronMock.handlers.get(IPC_CHANNELS.passkeyVerifyApproval)!
    await expect(
      Promise.resolve().then(() =>
        verifyApproval(trustedEvent as never, {
          requestId: 'request-1',
          selectedChoiceId: '00000000-0000-4000-8000-000000000001',
          masterPassword: 'master password'
        })
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')

    const respond = electronMock.handlers.get(IPC_CHANNELS.passkeyRespondApproval)!
    await respond(trustedEvent as never, {
      requestId: 'request-1',
      approved: true,
      selectedChoiceId: '00000000-0000-4000-8000-000000000001',
      verificationMethod: 'none'
    })
    await expect(operation).resolves.toMatchObject({ verificationMethod: 'none' })
    bridge.dispose()
  })

  it('keeps discouraged UV false while requiring a separate proof for a protected choice', async () => {
    const selectedChoiceId = '00000000-0000-4000-8000-000000000001'
    const { bridge, webContents, trustedEvent, getVerificationMethods } = harness()
    const operation = bridge.requestConsent(
      safePrompt({
        userVerification: 'discouraged',
        choices: [
          {
            id: selectedChoiceId,
            label: 'Protected account',
            requiresReprompt: true
          }
        ]
      }),
      new AbortController().signal
    )
    await vi.waitFor(() => expect(webContents.send).toHaveBeenCalledOnce())
    expect(webContents.send.mock.calls[0]![1]).toMatchObject({
      userVerification: 'discouraged',
      verificationMethods: ['master-password'],
      choices: [{ id: selectedChoiceId, requiresReprompt: true }]
    })
    expect(getVerificationMethods).not.toHaveBeenCalled()

    const verifyApproval = electronMock.handlers.get(IPC_CHANNELS.passkeyVerifyApproval)!
    const respond = electronMock.handlers.get(IPC_CHANNELS.passkeyRespondApproval)!
    await expect(
      Promise.resolve().then(() =>
        respond(trustedEvent as never, {
          requestId: 'request-1',
          approved: true,
          selectedChoiceId,
          verificationMethod: 'none'
        })
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')

    await verifyApproval(trustedEvent as never, {
      requestId: 'request-1',
      selectedChoiceId,
      masterPassword: 'master password'
    })
    await respond(trustedEvent as never, {
      requestId: 'request-1',
      approved: true,
      selectedChoiceId,
      verificationMethod: 'none'
    })
    await expect(operation).resolves.toMatchObject({ verificationMethod: 'none' })
    expect(
      bridge.consumeMasterPasswordProof({
        requestId: 'request-1',
        selectedChoiceId,
        vaultGeneration: 7
      })
    ).toBe(true)
    bridge.dispose()
  })

  it('preserves a protected-choice password proof while Touch ID performs separate UV', async () => {
    const selectedChoiceId = '00000000-0000-4000-8000-000000000001'
    const { bridge, trustedEvent } = harness()
    const operation = bridge.requestConsent(
      safePrompt({
        userVerification: 'required',
        choices: [
          {
            id: selectedChoiceId,
            label: 'Protected account',
            requiresReprompt: true
          }
        ]
      }),
      new AbortController().signal
    )
    await Promise.resolve()
    const verifyApproval = electronMock.handlers.get(IPC_CHANNELS.passkeyVerifyApproval)!
    const respond = electronMock.handlers.get(IPC_CHANNELS.passkeyRespondApproval)!

    await expect(
      Promise.resolve().then(() =>
        respond(trustedEvent as never, {
          requestId: 'request-1',
          approved: true,
          selectedChoiceId,
          verificationMethod: 'touch-id'
        })
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    await verifyApproval(trustedEvent as never, {
      requestId: 'request-1',
      selectedChoiceId,
      masterPassword: 'master password'
    })
    await respond(trustedEvent as never, {
      requestId: 'request-1',
      approved: true,
      selectedChoiceId,
      verificationMethod: 'touch-id'
    })
    await expect(operation).resolves.toMatchObject({ verificationMethod: 'touch-id' })
    expect(
      bridge.consumeMasterPasswordProof({
        requestId: 'request-1',
        selectedChoiceId,
        vaultGeneration: 7
      })
    ).toBe(true)
    bridge.dispose()
  })

  it('rejects untrusted frames, malformed responses, and stale choices', async () => {
    const { bridge, webContents, trustedEvent } = harness()
    const operation = bridge.requestConsent(safePrompt(), new AbortController().signal)
    await Promise.resolve()
    const respond = electronMock.handlers.get(IPC_CHANNELS.passkeyRespondApproval)!

    await expect(
      Promise.resolve().then(() =>
        respond({ sender: {}, senderFrame: webContents.mainFrame } as never, {
          requestId: 'request-1',
          approved: false
        })
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    await expect(
      Promise.resolve().then(() =>
        respond(trustedEvent as never, {
          requestId: 'request-1',
          approved: false,
          verificationMethod: 'none'
        })
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    await expect(
      Promise.resolve().then(() =>
        respond(trustedEvent as never, {
          requestId: 'request-1',
          approved: true,
          selectedChoiceId: 'stale-choice',
          verificationMethod: 'touch-id'
        })
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')

    await respond(trustedEvent as never, { requestId: 'request-1', approved: false })
    await operation
    bridge.dispose()
  })

  it('bounds pending prompts and fails closed on timeout, abort, reload, and disposal', async () => {
    vi.useFakeTimers()
    const { bridge, webContents } = harness({ timeout: 1_000, max: 1 })
    const first = bridge.requestConsent(safePrompt(), new AbortController().signal)
    const expired = expect(first).rejects.toMatchObject({ name: 'AbortError' })
    await expect(
      bridge.requestConsent(safePrompt({ requestId: 'request-2' }), new AbortController().signal)
    ).rejects.toThrow('PASSKEY_APPROVAL_UNAVAILABLE')
    await vi.advanceTimersByTimeAsync(1_000)
    await expired

    const controller = new AbortController()
    const aborted = bridge.requestConsent(safePrompt({ requestId: 'request-3' }), controller.signal)
    const abortedResult = expect(aborted).rejects.toMatchObject({ name: 'AbortError' })
    controller.abort()
    await abortedResult

    const reloaded = bridge.requestConsent(
      safePrompt({ requestId: 'request-4' }),
      new AbortController().signal
    )
    const reloadResult = expect(reloaded).rejects.toMatchObject({ name: 'AbortError' })
    await vi.runAllTicks()
    webContents.emit('did-start-loading')
    await reloadResult
    bridge.dispose()
    expect(electronMock.removeHandler).toHaveBeenCalledWith(IPC_CHANNELS.passkeyVerifyApproval)
    expect(electronMock.removeHandler).toHaveBeenCalledWith(IPC_CHANNELS.passkeyRespondApproval)
  })

  it('disposes safely after the attached window has already been destroyed', () => {
    const { bridge, window } = harness()
    window.isDestroyed = () => true
    Object.defineProperty(window, 'webContents', {
      get: () => {
        throw new TypeError('Object has been destroyed')
      }
    })

    expect(() => bridge.dispose()).not.toThrow()
  })

  it('drops a password proof if the request is aborted while verification is in flight', async () => {
    const { bridge, trustedEvent, verifyMasterPassword } = harness()
    let resolvePassword!: (generation: number) => void
    verifyMasterPassword.mockImplementationOnce(
      () => new Promise<number>((resolve) => (resolvePassword = resolve))
    )
    const controller = new AbortController()
    const operation = bridge.requestConsent(safePrompt(), controller.signal)
    await Promise.resolve()
    const verifyApproval = electronMock.handlers.get(IPC_CHANNELS.passkeyVerifyApproval)!
    const verifying = Promise.resolve(
      verifyApproval(trustedEvent as never, {
        requestId: 'request-1',
        selectedChoiceId: '00000000-0000-4000-8000-000000000001',
        masterPassword: 'master password'
      })
    )
    controller.abort()
    resolvePassword(7)

    await expect(operation).rejects.toMatchObject({ name: 'AbortError' })
    await expect(verifying).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(
      bridge.consumeMasterPasswordProof(
        verificationRequest({ selectedChoiceId: '00000000-0000-4000-8000-000000000001' })
      )
    ).toBe(false)
    bridge.dispose()
  })
})
