import { randomUUID } from 'node:crypto'
import { chmod, lstat, rename, unlink } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { createConnection, createServer, type Server, type Socket } from 'node:net'
import { type Duplex } from 'node:stream'
import {
  SSH_AGENT_SESSION_BIND,
  SshAgentFrameDecoder,
  applySshAgentSessionBind,
  buildSshAgentFailure,
  buildSshAgentIdentitiesAnswer,
  buildSshAgentSignResponse,
  buildSshAgentSuccess,
  detectSshSigNamespace,
  frameSshAgentMessage,
  parseSshAgentMessage,
  type SshAgentIdentity,
  type SshAgentRsaHash,
  type SshAgentSessionBindState,
  type SshSigNamespace,
  SSH_AGENT_MAX_MESSAGE_LENGTH
} from './ssh-agent-protocol'

export const BEARWARDEN_SSH_AUTH_SOCK = 'BEARWARDEN_SSH_AUTH_SOCK'
export const BEARWARDEN_SSH_AGENT_SOCKET_NAME = '.bearwarden-ssh-agent.sock'
export const OPENSSH_AGENT_PIPE_NAME = '\\\\.\\pipe\\openssh-ssh-agent'

const DEFAULT_MAX_CONNECTIONS = 32
const DEFAULT_IDLE_TIMEOUT_MS = 60_000
const DEFAULT_REQUEST_TIMEOUT_MS = 60_000
const MAX_MESSAGES_PER_READ = 64
const SOCKET_PROBE_TIMEOUT_MS = 500

type SshAgentSocket = Duplex & {
  destroyed: boolean
  destroy(error?: Error): SshAgentSocket
  pause(): SshAgentSocket
  resume(): SshAgentSocket
  setTimeout?(timeout: number, callback?: () => void): SshAgentSocket
}

export interface SshAgentConnectionContext {
  /** Node does not expose Unix peer credentials, so this is currently unavailable. */
  processName: string | undefined
  /** This is populated only after a verified session-bind extension request. */
  session: Readonly<SshAgentSessionBindState>
}

export interface SshAgentListRequest {
  connection: SshAgentConnectionContext
  signal: AbortSignal
}

/** Public data only. Private SSH material must never enter the transport layer. */
export interface SshAgentSignRequest {
  /** Correlates one approved request with exactly one provider signing call. */
  requestId: string
  publicKeyBlob: Buffer
  data: Buffer
  flags: number
  rsaHash: SshAgentRsaHash | undefined
  namespace: SshSigNamespace | undefined
  connection: SshAgentConnectionContext
  signal: AbortSignal
}

/** The approval surface intentionally does not receive the bytes being signed. */
export interface SshAgentApprovalRequest {
  /** Correlates one approval with exactly one provider signing call. */
  requestId: string
  publicKeyBlob: Buffer
  flags: number
  rsaHash: SshAgentRsaHash | undefined
  namespace: SshSigNamespace | undefined
  connection: SshAgentConnectionContext
  signal: AbortSignal
}

export interface SshAgentSignature {
  algorithm: string
  signature: Buffer
}

export interface SshAgentProvider {
  listIdentities(request: SshAgentListRequest): Promise<readonly SshAgentIdentity[]>
  sign(request: SshAgentSignRequest): Promise<SshAgentSignature | undefined>
}

export interface SshAgentApprovalHandler {
  approveSign(request: SshAgentApprovalRequest): Promise<boolean>
}

export interface SshAgentConnectionHandlerOptions {
  provider: SshAgentProvider
  approvalHandler: SshAgentApprovalHandler
  requestTimeoutMs?: number
  idleTimeoutMs?: number
}

export interface SshAgentServerOptions extends SshAgentConnectionHandlerOptions {
  /** Testing/integration override. Production uses BEARWARDEN_SSH_AUTH_SOCK first. */
  socketPath?: string
  environment?: NodeJS.ProcessEnv
  getHomeDirectory?: () => string
  platform?: NodeJS.Platform
  maxConnections?: number
  /** Main-process-only lifecycle signal. Callers must map raw OS errors before publishing. */
  onRuntimeError?: (error: Error) => void
  /** @internal Deterministic lifecycle seam for transport race-condition tests. */
  testHooks?: {
    afterListeningBeforeSocketOwnership?: (socketPath: string) => void | Promise<void>
    captureListeningServer?: (server: Server) => void
    createServer?: (connectionListener: (socket: Socket) => void) => Server
  }
}

export interface SshAgentServerStatus {
  running: boolean
  socketPath: string | undefined
  activeConnections: number
  /** Changes at each start/stop boundary, so stale work cannot write a response. */
  epoch: number
}

interface OwnedSocket {
  path: string
  dev: number | bigint
  ino: number | bigint
}

function isNodeError(value: unknown): value is NodeJS.ErrnoException {
  return value instanceof Error
}

function isNotFound(error: unknown): boolean {
  return isNodeError(error) && error.code === 'ENOENT'
}

function socketError(code: string): Error {
  return new Error(code)
}

function resolvedPlatform(options: SshAgentServerOptions): NodeJS.Platform {
  return options.platform ?? process.platform
}

export function resolveSshAgentSocketPath(
  options: Pick<
    SshAgentServerOptions,
    'socketPath' | 'environment' | 'getHomeDirectory' | 'platform'
  > = {}
): string {
  if ((options.platform ?? process.platform) === 'win32') return OPENSSH_AGENT_PIPE_NAME
  if (options.socketPath) return options.socketPath
  const fromEnvironment = (options.environment ?? process.env)[BEARWARDEN_SSH_AUTH_SOCK]
  if (fromEnvironment) return fromEnvironment
  return join((options.getHomeDirectory ?? homedir)(), BEARWARDEN_SSH_AGENT_SOCKET_NAME)
}

async function statSocket(path: string): Promise<Awaited<ReturnType<typeof lstat>> | undefined> {
  try {
    return await lstat(path)
  } catch (error) {
    if (isNotFound(error)) return undefined
    throw error
  }
}

function hasSameFileIdentity(
  left: Awaited<ReturnType<typeof lstat>>,
  right: Awaited<ReturnType<typeof lstat>>
): boolean {
  return left.dev === right.dev && left.ino === right.ino
}

async function probeUnixSocket(path: string): Promise<'active' | 'stale'> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ path })
    let completed = false
    const finish = (result: 'active' | 'stale'): void => {
      if (completed) return
      completed = true
      socket.destroy()
      resolve(result)
    }
    socket.once('connect', () => finish('active'))
    socket.once('error', (error: NodeJS.ErrnoException) => {
      if (completed) return
      completed = true
      socket.destroy()
      if (error.code === 'ECONNREFUSED' || error.code === 'ENOENT') resolve('stale')
      else reject(error)
    })
    // A Unix connect normally succeeds or fails immediately. Bound this defensive probe so a
    // malformed endpoint cannot indefinitely block startup while stale-path ownership is checked.
    socket.setTimeout(SOCKET_PROBE_TIMEOUT_MS, () => {
      if (completed) return
      completed = true
      socket.destroy()
      reject(socketError('SSH_AGENT_SOCKET_PROBE_TIMEOUT'))
    })
  })
}

/**
 * Removes only a confirmed dead Unix-domain socket. A symlink or normal file is never
 * unlinked: an attacker must not be able to turn agent startup into arbitrary file deletion.
 */
async function removeConfirmedStaleSocket(path: string): Promise<void> {
  const initial = await statSocket(path)
  if (!initial) return
  if (!initial.isSocket() || initial.isSymbolicLink())
    throw socketError('SSH_AGENT_SOCKET_PATH_UNSAFE')
  if ((await probeUnixSocket(path)) === 'active') throw socketError('SSH_AGENT_SOCKET_IN_USE')

  const beforeUnlink = await statSocket(path)
  if (!beforeUnlink || !beforeUnlink.isSocket() || !hasSameFileIdentity(initial, beforeUnlink)) {
    throw socketError('SSH_AGENT_SOCKET_PATH_CHANGED')
  }
  await unlink(path)
}

async function captureOwnedSocket(path: string): Promise<OwnedSocket> {
  const stat = await statSocket(path)
  if (!stat?.isSocket()) throw socketError('SSH_AGENT_SOCKET_NOT_CREATED')
  return { path, dev: stat.dev, ino: stat.ino }
}

interface PreservedReplacement {
  originalPath: string
  preservedPath: string
}

/**
 * Node's public `server.close()` unlinks the pathname it was given, even if another process has
 * replaced that path since we bound it. Unlink our own socket before close; otherwise park and
 * restore the replacement so shutting down BearWarden never deletes somebody else's endpoint.
 */
async function prepareSocketPathForClose(
  path: string,
  owned: OwnedSocket | undefined
): Promise<PreservedReplacement | undefined> {
  const current = await statSocket(path)
  if (!current) return undefined
  if (owned && current.isSocket() && current.dev === owned.dev && current.ino === owned.ino) {
    await unlink(path)
    return undefined
  }

  const preservedPath = `${path}.bearwarden-preserve-${randomUUID()}`
  await rename(path, preservedPath)
  return { originalPath: path, preservedPath }
}

async function restoreReplacement(replacement: PreservedReplacement | undefined): Promise<void> {
  if (!replacement) return
  try {
    await rename(replacement.preservedPath, replacement.originalPath)
  } catch {
    throw socketError('SSH_AGENT_SOCKET_REPLACEMENT_RESTORE_FAILED')
  }
}

async function writeFrame(socket: SshAgentSocket, response: Buffer): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    socket.write(frameSshAgentMessage(response), (error) => {
      if (error) reject(error)
      else resolve()
    })
  })
}

function defaultSessionState(): SshAgentSessionBindState {
  return { forwarded: false, hostFingerprint: undefined }
}

/**
 * Dispatches a single connection sequentially. Its provider boundary contains only public
 * key data and request bytes; private material remains exclusively in the vault service.
 */
export class SshAgentConnectionHandler {
  private readonly abortController = new AbortController()
  private readonly requestTimeoutMs: number
  private readonly idleTimeoutMs: number
  private readonly decoder = new SshAgentFrameDecoder()
  private started = false
  private handling = false
  private session = defaultSessionState()

  constructor(
    private readonly socket: SshAgentSocket,
    private readonly options: SshAgentConnectionHandlerOptions
  ) {
    this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS
    this.idleTimeoutMs = options.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS
    if (!Number.isSafeInteger(this.requestTimeoutMs) || this.requestTimeoutMs < 1) {
      throw new Error('INVALID_SSH_AGENT_REQUEST_TIMEOUT')
    }
    if (!Number.isSafeInteger(this.idleTimeoutMs) || this.idleTimeoutMs < 1) {
      throw new Error('INVALID_SSH_AGENT_IDLE_TIMEOUT')
    }
  }

  start(): void {
    if (this.started) return
    this.started = true
    this.socket.on('error', () => undefined)
    this.socket.once('close', () => this.abortController.abort())
    this.socket.setTimeout?.(this.idleTimeoutMs, () => this.socket.destroy())
    this.socket.on('data', (chunk: Buffer) => this.receive(chunk))
  }

  stop(): void {
    this.abortController.abort()
    if (!this.socket.destroyed) this.socket.destroy()
  }

  private connectionContext(): SshAgentConnectionContext {
    return {
      processName: undefined,
      session: { ...this.session }
    }
  }

  private receive(chunk: Buffer): void {
    if (this.handling || this.abortController.signal.aborted) {
      this.socket.destroy()
      return
    }
    this.handling = true
    this.socket.pause()
    void this.handleChunk(Buffer.from(chunk))
  }

  private async handleChunk(chunk: Buffer): Promise<void> {
    try {
      const messages = this.decoder.push(chunk)
      if (messages.length > MAX_MESSAGES_PER_READ) {
        throw new Error('Too many SSH agent messages in one read')
      }
      for (const message of messages) {
        if (this.abortController.signal.aborted || this.socket.destroyed) return
        // OpenSSH deliberately ignores empty frames rather than treating them as a protocol
        // failure; keep the connection usable for clients that emit one while reconnecting.
        if (message.length === 0) continue
        let response: Buffer | undefined
        try {
          response = await this.dispatch(message)
        } catch {
          response = buildSshAgentFailure()
        }
        if (!response || this.abortController.signal.aborted || this.socket.destroyed) return
        if (response.length > SSH_AGENT_MAX_MESSAGE_LENGTH) response = buildSshAgentFailure()
        await writeFrame(this.socket, response)
      }
    } catch {
      // Oversized framing is a connection-level violation. Ordinary malformed protocol bodies
      // receive SSH_AGENT_FAILURE from dispatch and leave the connection usable.
      this.socket.destroy()
    } finally {
      this.handling = false
      if (!this.abortController.signal.aborted && !this.socket.destroyed) this.socket.resume()
    }
  }

  private async dispatch(body: Buffer): Promise<Buffer | undefined> {
    let message
    try {
      message = parseSshAgentMessage(body)
    } catch {
      return buildSshAgentFailure()
    }

    if (message.type === 'request-identities') {
      const identities = await this.withDeadline((signal) =>
        this.options.provider.listIdentities({ connection: this.connectionContext(), signal })
      )
      return identities ? buildSshAgentIdentitiesAnswer(identities) : buildSshAgentFailure()
    }

    if (message.type === 'extension') {
      if (message.name !== SSH_AGENT_SESSION_BIND) return buildSshAgentFailure()
      const updated = applySshAgentSessionBind(this.session, message.payload)
      if (!updated) return buildSshAgentFailure()
      this.session = updated
      return buildSshAgentSuccess()
    }

    if (message.type === 'unknown') return buildSshAgentFailure()

    const connection = this.connectionContext()
    const requestId = randomUUID()
    const approval = await this.withDeadline((signal) =>
      this.options.approvalHandler.approveSign({
        requestId,
        publicKeyBlob: Buffer.from(message.keyBlob),
        flags: message.flags,
        rsaHash: message.rsaHash,
        namespace: detectSshSigNamespace(message.data),
        connection,
        signal
      })
    )
    if (!approval) return buildSshAgentFailure()

    const signature = await this.withDeadline((signal) =>
      this.options.provider.sign({
        requestId,
        publicKeyBlob: Buffer.from(message.keyBlob),
        data: Buffer.from(message.data),
        flags: message.flags,
        rsaHash: message.rsaHash,
        namespace: detectSshSigNamespace(message.data),
        connection,
        signal
      })
    )
    if (!signature || !isValidSignature(signature)) return buildSshAgentFailure()
    return buildSshAgentSignResponse(signature.algorithm, signature.signature)
  }

  private async withDeadline<T>(
    operation: (signal: AbortSignal) => Promise<T>
  ): Promise<T | undefined> {
    if (this.abortController.signal.aborted) return undefined
    const requestAbort = new AbortController()
    const abortRequest = (): void => requestAbort.abort()
    this.abortController.signal.addEventListener('abort', abortRequest, { once: true })
    const timeout = setTimeout(() => requestAbort.abort(), this.requestTimeoutMs)
    try {
      const result = await Promise.race([
        Promise.resolve()
          .then(() => operation(requestAbort.signal))
          .catch(() => undefined),
        new Promise<undefined>((resolve) => {
          requestAbort.signal.addEventListener('abort', () => resolve(undefined), { once: true })
        })
      ])
      return result
    } finally {
      clearTimeout(timeout)
      this.abortController.signal.removeEventListener('abort', abortRequest)
    }
  }
}

function isValidSignature(value: SshAgentSignature): boolean {
  return (
    typeof value.algorithm === 'string' &&
    value.algorithm.length > 0 &&
    Buffer.byteLength(value.algorithm, 'utf8') === value.algorithm.length &&
    Buffer.isBuffer(value.signature) &&
    value.signature.length <= SSH_AGENT_MAX_MESSAGE_LENGTH
  )
}

export class SshAgentServer {
  private readonly platform: NodeJS.Platform
  private readonly maxConnections: number
  private readonly handlers = new Set<SshAgentConnectionHandler>()
  private lifecycle = Promise.resolve()
  private server: Server | undefined
  private ownedSocket: OwnedSocket | undefined
  private endpoint: string | undefined
  private running = false
  private currentEpoch = 0

  constructor(private readonly options: SshAgentServerOptions) {
    this.platform = resolvedPlatform(options)
    this.maxConnections = options.maxConnections ?? DEFAULT_MAX_CONNECTIONS
    if (!Number.isInteger(this.maxConnections) || this.maxConnections < 1) {
      throw new Error('INVALID_SSH_AGENT_MAX_CONNECTIONS')
    }
  }

  get status(): SshAgentServerStatus {
    return {
      running: this.running,
      socketPath: this.endpoint,
      activeConnections: this.handlers.size,
      epoch: this.currentEpoch
    }
  }

  start(): Promise<SshAgentServerStatus> {
    return this.schedule(async () => {
      if (this.running) return this.status
      return this.startCurrent()
    })
  }

  stop(): Promise<void> {
    return this.schedule(() => this.stopCurrent())
  }

  restart(): Promise<SshAgentServerStatus> {
    return this.schedule(async () => {
      await this.stopCurrent()
      return this.startCurrent()
    })
  }

  private schedule<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.lifecycle.then(operation, operation)
    this.lifecycle = result.then(
      () => undefined,
      () => undefined
    )
    return result
  }

  private async startCurrent(): Promise<SshAgentServerStatus> {
    const endpoint = resolveSshAgentSocketPath({
      socketPath: this.options.socketPath,
      environment: this.options.environment,
      getHomeDirectory: this.options.getHomeDirectory,
      platform: this.platform
    })
    if (this.platform !== 'win32') await removeConfirmedStaleSocket(endpoint)

    const epoch = ++this.currentEpoch
    const connectionListener = (socket: Socket): void => this.accept(socket, epoch)
    const server =
      this.options.testHooks?.createServer?.(connectionListener) ??
      createServer({ allowHalfOpen: false }, connectionListener)
    server.maxConnections = this.maxConnections
    this.server = server
    this.endpoint = endpoint
    this.running = true
    let createdOwnedSocket: OwnedSocket | undefined
    let didListen = false
    try {
      await new Promise<void>((resolve, reject) => {
        const onError = (error: Error): void => {
          server.removeListener('listening', onListening)
          reject(error)
        }
        const onListening = (): void => {
          server.removeListener('error', onError)
          didListen = true
          resolve()
        }
        server.once('error', onError)
        server.once('listening', onListening)
        server.listen(endpoint)
      })
      if (this.platform !== 'win32') {
        await this.options.testHooks?.afterListeningBeforeSocketOwnership?.(endpoint)
        // Capture ownership before chmod. If chmod fails, cleanup can still identify exactly
        // the inode created by this listener and cannot unlink a later replacement.
        createdOwnedSocket = await captureOwnedSocket(endpoint)
        await chmod(endpoint, 0o600)
        this.ownedSocket = createdOwnedSocket
      }
    } catch (error) {
      let replacement: PreservedReplacement | undefined
      // An unsuccessful listen (for example EADDRINUSE) never owns this path. Once this
      // listener did bind, Node close would unlink any path replacement, so preserve it even if
      // capture failed before this listener's inode could be recorded.
      if (this.platform !== 'win32' && didListen) {
        replacement = await prepareSocketPathForClose(endpoint, createdOwnedSocket)
      }
      await closeServer(server)
      if (this.platform !== 'win32') await restoreReplacement(replacement)
      this.server = undefined
      this.endpoint = undefined
      this.running = false
      throw error
    }

    server.on('error', (error) => {
      if (this.server !== server) return
      try {
        this.options.onRuntimeError?.(error)
      } catch {
        // Observability must not prevent fail-closed listener teardown.
      }
      void this.stop()
    })
    this.options.testHooks?.captureListeningServer?.(server)
    return this.status
  }

  private accept(socket: Socket, epoch: number): void {
    if (!this.running || epoch !== this.currentEpoch) {
      socket.destroy()
      return
    }
    const handler = new SshAgentConnectionHandler(socket, this.options)
    this.handlers.add(handler)
    socket.once('close', () => this.handlers.delete(handler))
    handler.start()
  }

  private async stopCurrent(): Promise<void> {
    if (!this.server) return
    const server = this.server
    this.running = false
    this.currentEpoch += 1
    for (const handler of this.handlers) handler.stop()
    this.handlers.clear()
    const ownedSocket = this.ownedSocket
    let replacement: PreservedReplacement | undefined
    try {
      replacement =
        this.platform === 'win32' || !ownedSocket
          ? undefined
          : await prepareSocketPathForClose(ownedSocket.path, ownedSocket)
    } catch (error) {
      // The listener is still alive. Preserve its ownership state so a later stop can retry
      // rather than risking deletion of the replacement path.
      this.running = true
      throw error
    }
    this.server = undefined
    this.endpoint = undefined
    this.ownedSocket = undefined

    await closeServer(server)
    if (this.platform !== 'win32') await restoreReplacement(replacement)
  }
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve) => {
    server.close(() => resolve())
  })
}
