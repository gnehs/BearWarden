import {
  HttpTransportType,
  HubConnectionBuilder,
  HubConnectionState,
  LogLevel,
  type HubConnection
} from '@microsoft/signalr'
import { MessagePackHubProtocol } from '@microsoft/signalr-protocol-msgpack'

const MIN_RECONNECT_DELAY_MS = 2 * 60 * 1_000
const MAX_RECONNECT_DELAY_MS = 5 * 60 * 1_000
const STOP_CONNECTION_TIMEOUT_MS = 1_000
const MAX_ACCESS_TOKEN_LENGTH = 64 * 1_024
const MAX_NOTIFICATION_PAYLOAD_LENGTH = 1024 * 1_024
const MAX_URL_LENGTH = 2_048
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu

// These notification types mutate data BearWarden currently understands. A full sync is
// deliberate: the local-first merge engine remains the single authority for conflict handling,
// tombstones, attachment metadata, and equivalent-domain settings.
const FULL_SYNC_NOTIFICATION_TYPES = new Set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 17, 18, 19, 25])
const RECONNECT_AFTER_SYNC_NOTIFICATION_TYPE = 6
const LOG_OUT_NOTIFICATION_TYPE = 11
const AUTH_REQUEST_NOTIFICATION_TYPE = 15
const MAX_SEEN_AUTH_REQUESTS = 256
const AUTH_REQUEST_DEDUPLICATION_WINDOW_MS = 5 * 60 * 1_000

export interface BitwardenNotificationConnectionInfo {
  notificationsUrl: string
  accessToken: string
  userId: string
  deviceIdentifier: string
}

export interface BitwardenNotificationSource {
  notificationConnectionInfo: () => Promise<BitwardenNotificationConnectionInfo | null>
}

export interface BitwardenAuthRequestNotification {
  id: string
  userId: string
}

interface NotificationConnection {
  readonly state: HubConnectionState
  start: () => Promise<void>
  stop: () => Promise<void>
  on: (methodName: string, handler: (payload: unknown) => void) => void
  onclose: (handler: (error?: Error) => void) => void
}

interface NotificationConnectionFactoryOptions {
  notificationsUrl: string
  accessToken: () => string | Promise<string>
}

type NotificationConnectionFactory = (
  options: NotificationConnectionFactoryOptions
) => NotificationConnection

interface TimerApi {
  setTimeout: (callback: () => void, delayMs: number) => ReturnType<typeof setTimeout>
  clearTimeout: (timer: ReturnType<typeof setTimeout>) => void
}

export interface BitwardenNotificationCoordinatorOptions {
  source: BitwardenNotificationSource
  onSyncRequested: () => void
  onAuthRequest: (notification: BitwardenAuthRequestNotification) => void | Promise<void>
  onRemoteLogout: () => void | Promise<void>
  connectionFactory?: NotificationConnectionFactory
  timerApi?: TimerApi
  random?: () => number
}

interface ParsedNotification {
  type: number
  contextId: string | null
  payloadUserId: string | null
  authRequest: BitwardenAuthRequestNotification | null
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function property(record: Record<string, unknown>, lower: string, upper: string): unknown {
  return record[upper] ?? record[lower]
}

function parsePayload(value: unknown): Record<string, unknown> | null {
  if (isRecord(value)) return value
  if (typeof value !== 'string' || value.length > MAX_NOTIFICATION_PAYLOAD_LENGTH) return null
  try {
    const parsed: unknown = JSON.parse(value)
    return isRecord(parsed) ? parsed : null
  } catch {
    return null
  }
}

function parseNotification(value: unknown): ParsedNotification | null {
  if (!isRecord(value)) return null
  const type = property(value, 'type', 'Type')
  const contextId = property(value, 'contextId', 'ContextId')
  const payload = parsePayload(property(value, 'payload', 'Payload'))
  if (!Number.isSafeInteger(type) || typeof type !== 'number' || type < 0 || type > 100) return null
  if (contextId !== null && contextId !== undefined && typeof contextId !== 'string') return null
  if (typeof contextId === 'string' && contextId.length > 128) return null
  if (!payload) return null

  const payloadUserId = property(payload, 'userId', 'UserId')
  if (payloadUserId !== null && payloadUserId !== undefined && typeof payloadUserId !== 'string') {
    return null
  }
  if (typeof payloadUserId === 'string' && payloadUserId.length > 128) return null
  let authRequest: BitwardenAuthRequestNotification | null = null
  if (type === AUTH_REQUEST_NOTIFICATION_TYPE) {
    const id = property(payload, 'id', 'Id')
    if (
      typeof id !== 'string' ||
      !UUID_PATTERN.test(id) ||
      typeof payloadUserId !== 'string' ||
      !UUID_PATTERN.test(payloadUserId)
    ) {
      return null
    }
    authRequest = { id, userId: payloadUserId }
  }
  return {
    type,
    contextId: typeof contextId === 'string' ? contextId : null,
    payloadUserId: typeof payloadUserId === 'string' ? payloadUserId : null,
    authRequest
  }
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLocaleLowerCase('en-US')
  return (
    normalized === 'localhost' ||
    normalized === '::1' ||
    normalized === '[::1]' ||
    /^127(?:\.[0-9]{1,3}){3}$/u.test(normalized)
  )
}

function validateConnectionInfo(
  value: BitwardenNotificationConnectionInfo
): BitwardenNotificationConnectionInfo {
  if (
    typeof value.accessToken !== 'string' ||
    value.accessToken.length === 0 ||
    value.accessToken.length > MAX_ACCESS_TOKEN_LENGTH ||
    !UUID_PATTERN.test(value.userId) ||
    !UUID_PATTERN.test(value.deviceIdentifier) ||
    typeof value.notificationsUrl !== 'string' ||
    value.notificationsUrl.length === 0 ||
    value.notificationsUrl.length > MAX_URL_LENGTH
  ) {
    throw new Error('INVALID_NOTIFICATION_CONNECTION')
  }
  const url = new URL(value.notificationsUrl)
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('INVALID_NOTIFICATION_CONNECTION')
  }
  if (
    url.protocol !== 'https:' &&
    !(url.protocol === 'http:' && isLoopbackHostname(url.hostname))
  ) {
    throw new Error('INVALID_NOTIFICATION_CONNECTION')
  }
  return {
    ...value,
    notificationsUrl: url.toString().replace(/\/$/u, '')
  }
}

function createSignalRConnection({
  notificationsUrl,
  accessToken
}: NotificationConnectionFactoryOptions): NotificationConnection {
  const connection: HubConnection = new HubConnectionBuilder()
    .withUrl(`${notificationsUrl}/hub`, {
      accessTokenFactory: accessToken,
      skipNegotiation: true,
      transport: HttpTransportType.WebSockets
    })
    .withHubProtocol(new MessagePackHubProtocol())
    // SignalR errors can contain the access_token query parameter. Keep this transport silent;
    // connection failures are expected on servers with notifications disabled.
    .configureLogging(LogLevel.None)
    .build()
  return connection
}

export class BitwardenNotificationCoordinator {
  private connection: NotificationConnection | null = null
  private connectionInfo: BitwardenNotificationConnectionInfo | null = null
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private generation = 0
  private disposed = false
  private reconnectAfterRefresh = false
  private readonly seenAuthRequestIds = new Map<string, number>()
  private operationQueue: Promise<void> = Promise.resolve()
  private readonly connectionFactory: NotificationConnectionFactory
  private readonly timerApi: TimerApi
  private readonly random: () => number

  constructor(private readonly options: BitwardenNotificationCoordinatorOptions) {
    this.connectionFactory = options.connectionFactory ?? createSignalRConnection
    this.timerApi = options.timerApi ?? {
      setTimeout: (callback, delayMs) => setTimeout(callback, delayMs),
      clearTimeout: (timer) => clearTimeout(timer)
    }
    this.random = options.random ?? Math.random
  }

  refresh(): Promise<void> {
    const generation = this.generation
    return this.enqueue(async () => {
      if (this.disposed || generation !== this.generation) return
      const next = await this.options.source.notificationConnectionInfo()
      if (this.disposed || generation !== this.generation) return
      if (!next) {
        await this.invalidateAndStop()
        return
      }
      await this.applyConnectionInfo(validateConnectionInfo(next))
    })
  }

  stop(): Promise<void> {
    return this.invalidateAndStop()
  }

  dispose(): Promise<void> {
    this.disposed = true
    return this.invalidateAndStop()
  }

  private enqueue(operation: () => Promise<void>): Promise<void> {
    const result = this.operationQueue.then(operation, operation)
    this.operationQueue = result.catch(() => undefined)
    return result
  }

  private async applyConnectionInfo(next: BitwardenNotificationConnectionInfo): Promise<void> {
    const current = this.connectionInfo
    const sameConnection =
      current?.notificationsUrl === next.notificationsUrl &&
      current.userId === next.userId &&
      current.deviceIdentifier === next.deviceIdentifier
    const tokenChanged = current?.accessToken !== next.accessToken
    const forceReconnect = this.reconnectAfterRefresh
    this.reconnectAfterRefresh = false
    this.connectionInfo = next

    if (sameConnection && this.connection && !forceReconnect) {
      if (
        tokenChanged &&
        this.connection.state === HubConnectionState.Disconnected &&
        this.reconnectTimer
      ) {
        this.clearReconnectTimer()
        void this.startCurrent(this.generation)
      }
      return
    }

    await this.stopConnectionOnly()
    if (this.disposed || this.connectionInfo !== next) return
    const generation = ++this.generation
    const connection = this.connectionFactory({
      notificationsUrl: next.notificationsUrl,
      accessToken: () => this.accessTokenForConnection(generation, next)
    })
    this.connection = connection
    connection.on('ReceiveMessage', (payload) => this.receive(generation, payload))
    connection.onclose(() => this.scheduleReconnect(generation))
    void this.startCurrent(generation)
  }

  private async accessTokenForConnection(
    generation: number,
    expected: BitwardenNotificationConnectionInfo
  ): Promise<string> {
    const refreshed = await this.options.source.notificationConnectionInfo()
    if (!refreshed) throw new Error('NOTIFICATION_TOKEN_UNAVAILABLE')
    const next = validateConnectionInfo(refreshed)
    if (
      this.disposed ||
      generation !== this.generation ||
      this.connectionInfo?.notificationsUrl !== expected.notificationsUrl ||
      next.notificationsUrl !== expected.notificationsUrl ||
      next.userId !== expected.userId ||
      next.deviceIdentifier !== expected.deviceIdentifier
    ) {
      throw new Error('NOTIFICATION_CONNECTION_CHANGED')
    }
    this.connectionInfo = next
    return next.accessToken
  }

  private async startCurrent(generation: number): Promise<void> {
    const connection = this.connection
    if (
      this.disposed ||
      !connection ||
      generation !== this.generation ||
      connection.state !== HubConnectionState.Disconnected
    ) {
      return
    }
    try {
      await connection.start()
      if (this.disposed || generation !== this.generation || connection !== this.connection) {
        await connection.stop().catch(() => undefined)
        return
      }
      // The socket has a blind interval while disconnected. A normal full sync is coalesced by
      // AutoSyncCoordinator and closes that gap after both first connect and reconnect.
      this.requestSync()
    } catch {
      if (!this.disposed && generation === this.generation && connection === this.connection) {
        this.scheduleReconnect(generation)
      }
    }
  }

  private receive(generation: number, value: unknown): void {
    if (this.disposed || generation !== this.generation) return
    const current = this.connectionInfo
    const notification = parseNotification(value)
    if (!current || !notification || notification.contextId === current.deviceIdentifier) return
    if (notification.payloadUserId && notification.payloadUserId !== current.userId) return

    if (notification.type === LOG_OUT_NOTIFICATION_TYPE) {
      // Logout is security-sensitive: unlike ordinary sync hints, require an explicit account ID.
      if (notification.payloadUserId !== current.userId) return
      if (generation !== this.generation) return
      void this.invalidateAndStop()
        .then(() => this.options.onRemoteLogout())
        .catch(() => undefined)
      return
    }
    if (notification.type === AUTH_REQUEST_NOTIFICATION_TYPE) {
      const authRequest = notification.authRequest
      if (!authRequest || authRequest.userId !== current.userId) return
      const now = Date.now()
      const seenAt = this.seenAuthRequestIds.get(authRequest.id)
      if (seenAt !== undefined && now - seenAt < AUTH_REQUEST_DEDUPLICATION_WINDOW_MS) return
      this.seenAuthRequestIds.delete(authRequest.id)
      this.seenAuthRequestIds.set(authRequest.id, now)
      if (this.seenAuthRequestIds.size > MAX_SEEN_AUTH_REQUESTS) {
        const oldest = this.seenAuthRequestIds.keys().next().value
        if (oldest) this.seenAuthRequestIds.delete(oldest)
      }
      try {
        void Promise.resolve(this.options.onAuthRequest(authRequest)).catch(() => undefined)
      } catch {
        // A notification handler failure must not tear down the authenticated socket.
      }
      return
    }
    if (FULL_SYNC_NOTIFICATION_TYPES.has(notification.type)) {
      if (notification.type === RECONNECT_AFTER_SYNC_NOTIFICATION_TYPE) {
        this.reconnectAfterRefresh = true
      }
      this.requestSync()
    }
  }

  private requestSync(): void {
    try {
      this.options.onSyncRequested()
    } catch {
      // A renderer or scheduling failure must not tear down the authenticated socket.
    }
  }

  private scheduleReconnect(generation: number): void {
    if (
      this.disposed ||
      generation !== this.generation ||
      !this.connectionInfo ||
      !this.connection ||
      this.connection.state !== HubConnectionState.Disconnected ||
      this.reconnectTimer
    ) {
      return
    }
    const unit = Math.max(0, Math.min(1, this.random()))
    const delay = Math.floor(
      MIN_RECONNECT_DELAY_MS + unit * (MAX_RECONNECT_DELAY_MS - MIN_RECONNECT_DELAY_MS)
    )
    const timer = this.timerApi.setTimeout(() => {
      if (this.reconnectTimer !== timer) return
      this.reconnectTimer = null
      void this.startCurrent(generation)
    }, delay)
    timer.unref?.()
    this.reconnectTimer = timer
  }

  private async invalidateAndStop(): Promise<void> {
    this.connectionInfo = null
    this.reconnectAfterRefresh = false
    this.seenAuthRequestIds.clear()
    this.generation += 1
    await this.stopConnectionOnly()
  }

  private async stopConnectionOnly(): Promise<void> {
    this.clearReconnectTimer()
    const connection = this.connection
    this.connection = null
    if (!connection) return

    // SignalR waits for an in-flight start() before stop() can settle. Its WebSocket transport has
    // no connection deadline, so a socket stuck in Connecting must not become an application-exit
    // barrier. Still ask SignalR to stop first, then bound how long teardown waits for it.
    let timeout: ReturnType<typeof setTimeout> | null = null
    const deadline = new Promise<void>((resolve) => {
      timeout = this.timerApi.setTimeout(resolve, STOP_CONNECTION_TIMEOUT_MS)
      timeout.unref?.()
    })
    let stopping: Promise<void>
    try {
      stopping = connection.stop().catch(() => undefined)
    } catch {
      stopping = Promise.resolve()
    }
    try {
      await Promise.race([stopping, deadline])
    } finally {
      if (timeout) this.timerApi.clearTimeout(timeout)
    }
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) this.timerApi.clearTimeout(this.reconnectTimer)
    this.reconnectTimer = null
  }
}
