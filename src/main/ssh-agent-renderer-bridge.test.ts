import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const electronMock = vi.hoisted(() => ({
  handlers: new Map<string, (event: unknown, input?: unknown) => unknown>(),
  removeHandler: vi.fn()
}))

vi.mock('electron', () => ({
  ipcMain: {
    handle: vi.fn((channel: string, handler: (event: unknown, input?: unknown) => unknown) => {
      electronMock.handlers.set(channel, handler)
    }),
    removeHandler: electronMock.removeHandler
  }
}))

import { IPC_CHANNELS, IPC_EVENTS } from '../shared/vault-contract'
import type { SshAgentRendererApprovalRequest } from './ssh-agent-coordinator'
import { SshAgentRendererBridge } from './ssh-agent-renderer-bridge'

class FakeWebContents extends EventEmitter {
  readonly id = 17
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

function harness(options: { timeout?: number; max?: number } = {}): {
  bridge: SshAgentRendererBridge
  webContents: FakeWebContents
  window: { webContents: FakeWebContents; isDestroyed: () => boolean }
  focusWindow: ReturnType<typeof vi.fn>
  trustedEvent: {
    sender: FakeWebContents
    senderFrame: FakeWebContents['mainFrame']
  }
} {
  const webContents = new FakeWebContents()
  const window = {
    webContents,
    isDestroyed: () => false
  }
  const focusWindow = vi.fn()
  const bridge = new SshAgentRendererBridge({
    getMainWindow: () => window as never,
    focusWindow,
    ...(options.timeout === undefined ? {} : { approvalTimeoutMs: options.timeout }),
    ...(options.max === undefined ? {} : { maxPendingApprovals: options.max })
  })
  bridge.attachWindow(window as never)
  const trustedEvent = { sender: webContents, senderFrame: webContents.mainFrame }
  return { bridge, webContents, window, focusWindow, trustedEvent }
}

function approval(requestId = 'request-1'): SshAgentRendererApprovalRequest {
  return {
    requestId,
    itemId: '00000000-0000-4000-8000-000000000001',
    itemName: 'Production key',
    fingerprint: 'SHA256:public-fingerprint',
    promptBehavior: 'always',
    requiresAgentApproval: true,
    requiresReprompt: false,
    processName: undefined,
    forwarded: false,
    hostFingerprint: undefined,
    namespace: 'git',
    rsaHash: undefined
  }
}

beforeEach(() => {
  electronMock.handlers.clear()
  electronMock.removeHandler.mockClear()
})

afterEach(() => vi.useRealTimers())

describe('SshAgentRendererBridge', () => {
  it('accepts one response only from the current main frame and emits no signing bytes or keys', async () => {
    const { bridge, webContents, trustedEvent } = harness()
    const resultPromise = bridge.requestApproval(approval(), new AbortController().signal)
    await Promise.resolve()

    expect(webContents.send).toHaveBeenCalledOnce()
    const [eventName, payload] = webContents.send.mock.calls[0]!
    expect(eventName).toBe(IPC_EVENTS.sshAgentApprovalRequested)
    expect(payload).toMatchObject({
      requestId: 'request-1',
      itemName: 'Production key',
      fingerprint: 'SHA256:public-fingerprint',
      namespace: 'git'
    })
    expect(payload).toHaveProperty('expiresAt')
    expect(payload).not.toHaveProperty('data')
    expect(payload).not.toHaveProperty('privateKey')
    expect(payload).not.toHaveProperty('publicKeyBlob')

    const respond = electronMock.handlers.get(IPC_CHANNELS.sshAgentRespondApproval)!
    await expect(
      Promise.resolve().then(() =>
        respond(
          { sender: {}, senderFrame: webContents.mainFrame },
          { requestId: 'request-1', approved: true }
        )
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')

    await respond(trustedEvent, { requestId: 'request-1', approved: true })
    await expect(resultPromise).resolves.toEqual({ approved: true })
    await expect(
      Promise.resolve().then(() =>
        respond(trustedEvent, { requestId: 'request-1', approved: true })
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    bridge.dispose()
  })

  it('rejects unknown fields, invalid denial tokens, and renderer reload replays', async () => {
    const { bridge, webContents, trustedEvent } = harness()
    const respond = electronMock.handlers.get(IPC_CHANNELS.sshAgentRespondApproval)!
    const operation = bridge.requestApproval(approval(), new AbortController().signal)
    await Promise.resolve()

    await expect(
      Promise.resolve().then(() =>
        respond(trustedEvent, { requestId: 'request-1', approved: true, secret: 'nope' })
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    await expect(
      Promise.resolve().then(() =>
        respond(trustedEvent, {
          requestId: 'request-1',
          approved: false,
          authorizationToken: 'must-not-be-used'
        })
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')

    const canceled = expect(operation).rejects.toMatchObject({ name: 'AbortError' })
    webContents.emit('did-start-loading')
    await canceled
    await expect(
      Promise.resolve().then(() =>
        respond(trustedEvent, { requestId: 'request-1', approved: true })
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    bridge.dispose()
  })

  it('bounds pending requests and expires or aborts them', async () => {
    vi.useFakeTimers()
    const { bridge } = harness({ timeout: 1_000, max: 1 })
    const first = bridge.requestApproval(approval('first'), new AbortController().signal)
    const expired = expect(first).rejects.toMatchObject({ name: 'AbortError' })
    await expect(
      bridge.requestApproval(approval('second'), new AbortController().signal)
    ).rejects.toThrow('SSH_AGENT_APPROVAL_UNAVAILABLE')

    await vi.advanceTimersByTimeAsync(1_000)
    await expired

    const controller = new AbortController()
    const aborted = bridge.requestApproval(approval('third'), controller.signal)
    const abortedResult = expect(aborted).rejects.toMatchObject({ name: 'AbortError' })
    controller.abort()
    await abortedResult
    bridge.dispose()
  })

  it('publishes a safe status snapshot and rejects untrusted status callers', async () => {
    const { bridge, webContents, trustedEvent } = harness()
    bridge.updateStatus({
      enabled: true,
      running: true,
      state: 'ready',
      endpoint: '/tmp/bearwarden-agent.sock',
      identityCount: 3
    })
    expect(webContents.send).toHaveBeenLastCalledWith(IPC_EVENTS.sshAgentStatusChanged, {
      enabled: true,
      running: true,
      state: 'ready',
      endpoint: '/tmp/bearwarden-agent.sock',
      identityCount: 3
    })

    const status = electronMock.handlers.get(IPC_CHANNELS.sshAgentStatus)!
    await expect(Promise.resolve(status(trustedEvent))).resolves.toEqual({
      enabled: true,
      running: true,
      state: 'ready',
      endpoint: '/tmp/bearwarden-agent.sock',
      identityCount: 3
    })
    await expect(
      Promise.resolve().then(() => status({ sender: webContents, senderFrame: null }))
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    bridge.dispose()
  })

  it('wakes unlock waiters once and cancels them on lock or disposal', async () => {
    const { bridge } = harness()
    const first = bridge.waitForUnlock(new AbortController().signal)
    bridge.notifyUnlocked()
    await expect(first).resolves.toBe(true)

    const second = bridge.waitForUnlock(new AbortController().signal)
    bridge.cancelAll()
    await expect(second).resolves.toBe(false)
    bridge.dispose()
    await expect(bridge.waitForUnlock(new AbortController().signal)).rejects.toMatchObject({
      name: 'AbortError'
    })
  })
})
