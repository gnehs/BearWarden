import { HubConnectionState } from '@microsoft/signalr'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  BitwardenNotificationCoordinator,
  type BitwardenNotificationConnectionInfo
} from './bitwarden-notifications'

const USER_ID = '10000000-0000-4000-8000-000000000001'
const DEVICE_ID = '20000000-0000-4000-8000-000000000002'
const OTHER_DEVICE_ID = '30000000-0000-4000-8000-000000000003'

function info(
  overrides: Partial<BitwardenNotificationConnectionInfo> = {}
): BitwardenNotificationConnectionInfo {
  return {
    notificationsUrl: 'https://vault.example.invalid/base/notifications',
    accessToken: 'test-access-token',
    userId: USER_ID,
    deviceIdentifier: DEVICE_ID,
    ...overrides
  }
}

interface FactoryOptions {
  notificationsUrl: string
  accessToken: () => string | Promise<string>
}

class FakeConnection {
  state: HubConnectionState = HubConnectionState.Disconnected
  readonly tokens: string[] = []
  failStarts = 0
  private readonly handlers = new Map<string, (payload: unknown) => void>()
  private closeHandler: ((error?: Error) => void) | null = null

  constructor(private readonly options: FactoryOptions) {}

  readonly start = vi.fn(async () => {
    this.state = HubConnectionState.Connecting
    this.tokens.push(await this.options.accessToken())
    if (this.failStarts > 0) {
      this.failStarts -= 1
      this.state = HubConnectionState.Disconnected
      throw new Error('expected fake start failure')
    }
    this.state = HubConnectionState.Connected
  })

  readonly stop = vi.fn(async () => {
    const wasDisconnected = this.state === HubConnectionState.Disconnected
    this.state = HubConnectionState.Disconnected
    if (!wasDisconnected) this.closeHandler?.()
  })

  on(methodName: string, handler: (payload: unknown) => void): void {
    this.handlers.set(methodName, handler)
  }

  onclose(handler: (error?: Error) => void): void {
    this.closeHandler = handler
  }

  emit(payload: unknown): void {
    this.handlers.get('ReceiveMessage')?.(payload)
  }

  close(): void {
    this.state = HubConnectionState.Disconnected
    this.closeHandler?.()
  }
}

function harness(
  initial = info(),
  configureConnection?: (connection: FakeConnection) => void
): {
  coordinator: BitwardenNotificationCoordinator
  connections: FakeConnection[]
  source: ReturnType<typeof vi.fn>
  onSyncRequested: ReturnType<typeof vi.fn>
  onRemoteLogout: ReturnType<typeof vi.fn>
  setInfo: (next: BitwardenNotificationConnectionInfo | null) => void
} {
  let current: BitwardenNotificationConnectionInfo | null = initial
  const source = vi.fn(async () => (current ? { ...current } : null))
  const connections: FakeConnection[] = []
  const onSyncRequested = vi.fn()
  const onRemoteLogout = vi.fn(async () => undefined)
  const coordinator = new BitwardenNotificationCoordinator({
    source: { notificationConnectionInfo: source },
    onSyncRequested,
    onRemoteLogout,
    random: () => 0,
    connectionFactory: (options) => {
      const connection = new FakeConnection(options)
      configureConnection?.(connection)
      connections.push(connection)
      return connection
    }
  })
  return {
    coordinator,
    connections,
    source,
    onSyncRequested,
    onRemoteLogout,
    setInfo: (next) => {
      current = next
    }
  }
}

async function waitForConnected(connection: FakeConnection): Promise<void> {
  await vi.waitFor(() => expect(connection.state).toBe(HubConnectionState.Connected))
}

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('BitwardenNotificationCoordinator', () => {
  it('starts one MessagePack hub connection and requests a catch-up sync', async () => {
    const { coordinator, connections, source, onSyncRequested } = harness()
    await coordinator.refresh()
    expect(connections).toHaveLength(1)
    await waitForConnected(connections[0]!)

    expect(source).toHaveBeenCalledTimes(2)
    expect(connections[0]!.tokens).toEqual(['test-access-token'])
    expect(onSyncRequested).toHaveBeenCalledOnce()

    await coordinator.refresh()
    expect(connections).toHaveLength(1)
    expect(connections[0]!.start).toHaveBeenCalledOnce()
    await coordinator.dispose()
  })

  it('accepts supported invalidations but ignores self, wrong-account, unsupported, and malformed events', async () => {
    const { coordinator, connections, onSyncRequested } = harness()
    await coordinator.refresh()
    const connection = connections[0]!
    await waitForConnected(connection)
    onSyncRequested.mockClear()

    for (const type of [0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 17, 18, 19, 25]) {
      connection.emit({
        ContextId: OTHER_DEVICE_ID,
        Type: type,
        Payload: { UserId: USER_ID }
      })
    }
    expect(onSyncRequested).toHaveBeenCalledTimes(14)

    connection.emit({ ContextId: DEVICE_ID, Type: 0, Payload: { UserId: USER_ID } })
    connection.emit({ ContextId: OTHER_DEVICE_ID, Type: 0, Payload: { UserId: DEVICE_ID } })
    connection.emit({ ContextId: OTHER_DEVICE_ID, Type: 12, Payload: { UserId: USER_ID } })
    connection.emit({ ContextId: OTHER_DEVICE_ID, Type: 101, Payload: { UserId: USER_ID } })
    connection.emit({ ContextId: 42, Type: 0, Payload: { UserId: USER_ID } })
    connection.emit({ ContextId: OTHER_DEVICE_ID, Type: 0, Payload: [] })
    expect(onSyncRequested).toHaveBeenCalledTimes(14)

    connection.emit({
      contextId: OTHER_DEVICE_ID,
      type: 0,
      payload: JSON.stringify({ userId: USER_ID })
    })
    expect(onSyncRequested).toHaveBeenCalledTimes(15)
    await coordinator.dispose()
  })

  it('stops before applying a validated remote logout and rejects ambiguous logout payloads', async () => {
    const { coordinator, connections, onRemoteLogout } = harness()
    await coordinator.refresh()
    const connection = connections[0]!
    await waitForConnected(connection)

    connection.emit({ ContextId: OTHER_DEVICE_ID, Type: 11, Payload: {} })
    connection.emit({ ContextId: OTHER_DEVICE_ID, Type: 11, Payload: { UserId: DEVICE_ID } })
    expect(onRemoteLogout).not.toHaveBeenCalled()

    connection.emit({ ContextId: OTHER_DEVICE_ID, Type: 11, Payload: { UserId: USER_ID } })
    await vi.waitFor(() => expect(onRemoteLogout).toHaveBeenCalledOnce())
    expect(connection.stop).toHaveBeenCalled()
    connection.emit({ ContextId: OTHER_DEVICE_ID, Type: 11, Payload: { UserId: USER_ID } })
    expect(onRemoteLogout).toHaveBeenCalledOnce()
    await coordinator.dispose()
  })

  it('retries initial and closed connections with one upstream-compatible jitter timer', async () => {
    vi.useFakeTimers()
    let firstConnection = true
    const { coordinator, connections, onSyncRequested } = harness(info(), (connection) => {
      if (firstConnection) {
        connection.failStarts = 1
        firstConnection = false
      }
    })
    await coordinator.refresh()
    const retrying = connections[0]!
    await vi.advanceTimersByTimeAsync(0)
    expect(retrying.start).toHaveBeenCalledOnce()
    expect(onSyncRequested).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(119_999)
    expect(retrying.start).toHaveBeenCalledOnce()
    await vi.advanceTimersByTimeAsync(1)
    expect(retrying.start).toHaveBeenCalledTimes(2)
    expect(onSyncRequested).toHaveBeenCalledOnce()

    retrying.close()
    retrying.close()
    await vi.advanceTimersByTimeAsync(120_000)
    expect(retrying.start).toHaveBeenCalledTimes(3)
    expect(onSyncRequested).toHaveBeenCalledTimes(2)
    await coordinator.dispose()
  })

  it('fetches a current token on reconnect and closes the disconnected blind interval', async () => {
    vi.useFakeTimers()
    const { coordinator, connections, onSyncRequested, setInfo } = harness()
    await coordinator.refresh()
    const connection = connections[0]!
    await vi.advanceTimersByTimeAsync(0)
    expect(connection.tokens).toEqual(['test-access-token'])
    onSyncRequested.mockClear()

    connection.close()
    setInfo(info({ accessToken: 'rotated-access-token' }))
    await vi.advanceTimersByTimeAsync(120_000)
    expect(connection.tokens).toEqual(['test-access-token', 'rotated-access-token'])
    expect(onSyncRequested).toHaveBeenCalledOnce()
    await coordinator.dispose()
  })

  it('reconnects after an organization-key sync and never revives a stopped generation', async () => {
    const { coordinator, connections, onSyncRequested } = harness()
    await coordinator.refresh()
    const first = connections[0]!
    await waitForConnected(first)
    onSyncRequested.mockClear()

    first.emit({ ContextId: OTHER_DEVICE_ID, Type: 6, Payload: { UserId: USER_ID } })
    expect(onSyncRequested).toHaveBeenCalledOnce()
    await coordinator.refresh()
    expect(connections).toHaveLength(2)
    await waitForConnected(connections[1]!)
    expect(first.stop).toHaveBeenCalled()

    await coordinator.stop()
    const syncCount = onSyncRequested.mock.calls.length
    first.emit({ ContextId: OTHER_DEVICE_ID, Type: 0, Payload: { UserId: USER_ID } })
    first.close()
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(onSyncRequested).toHaveBeenCalledTimes(syncCount)
    expect(connections).toHaveLength(2)
    await coordinator.dispose()
  })

  it('invalidates immediately while a token source is still pending', async () => {
    let release!: () => void
    const pendingSource = new Promise<void>((resolve) => {
      release = resolve
    })
    const connections: FakeConnection[] = []
    const coordinator = new BitwardenNotificationCoordinator({
      source: {
        notificationConnectionInfo: async () => {
          await pendingSource
          return info()
        }
      },
      onSyncRequested: vi.fn(),
      onRemoteLogout: vi.fn(),
      connectionFactory: (options) => {
        const connection = new FakeConnection(options)
        connections.push(connection)
        return connection
      }
    })

    const refresh = coordinator.refresh()
    await Promise.resolve()
    await expect(coordinator.stop()).resolves.toBeUndefined()
    release()
    await expect(refresh).resolves.toBeUndefined()
    expect(connections).toHaveLength(0)
    await coordinator.dispose()
  })

  it('bounds disposal while SignalR start and stop remain pending during connection', async () => {
    vi.useFakeTimers()
    const { coordinator, connections } = harness(info(), (connection) => {
      connection.start.mockImplementation(async () => {
        connection.state = HubConnectionState.Connecting
        await new Promise<void>(() => undefined)
      })
      connection.stop.mockImplementation(async () => {
        await new Promise<void>(() => undefined)
      })
    })

    await coordinator.refresh()
    const connection = connections[0]!
    await vi.advanceTimersByTimeAsync(0)
    expect(connection.state).toBe(HubConnectionState.Connecting)

    let disposed = false
    const disposal = coordinator.dispose().then(() => {
      disposed = true
    })
    expect(connection.stop).toHaveBeenCalledOnce()

    await vi.advanceTimersByTimeAsync(999)
    expect(disposed).toBe(false)
    await vi.advanceTimersByTimeAsync(1)
    await expect(disposal).resolves.toBeUndefined()
    expect(disposed).toBe(true)
  })

  it('accepts HTTP only for loopback notification fixtures', async () => {
    const loopback = harness(info({ notificationsUrl: 'http://127.0.0.1:8080/bw/notifications' }))
    await expect(loopback.coordinator.refresh()).resolves.toBeUndefined()
    await loopback.coordinator.dispose()

    const insecure = harness(
      info({ notificationsUrl: 'http://vault.example.invalid/notifications' })
    )
    await expect(insecure.coordinator.refresh()).rejects.toThrow('INVALID_NOTIFICATION_CONNECTION')
    expect(insecure.connections).toHaveLength(0)
    await insecure.coordinator.dispose()
  })
})
