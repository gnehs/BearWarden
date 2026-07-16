import { generateKeyPairSync } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { lstat, mkdtemp, readFile, rm, unlink, writeFile } from 'node:fs/promises'
import { createConnection, createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Duplex } from 'node:stream'
import { describe, expect, it, vi } from 'vitest'
import { utils, type ParsedKey } from 'ssh2'
import {
  SSH_AGENT_EXTENSION,
  SSH_AGENT_FAILURE,
  SSH_AGENT_REQUEST_IDENTITIES,
  SSH_AGENT_SESSION_BIND,
  SSH_AGENT_SIGN_REQUEST,
  SshAgentFrameDecoder,
  frameSshAgentMessage
} from './ssh-agent-protocol'
import { formatSshKeyMaterial } from './ssh-key-format'
import {
  OPENSSH_AGENT_PIPE_NAME,
  SshAgentConnectionHandler,
  SshAgentServer,
  resolveSshAgentSocketPath,
  type SshAgentApprovalHandler,
  type SshAgentProvider
} from './ssh-agent-server'

function sshString(value: Buffer | string): Buffer {
  const bytes = typeof value === 'string' ? Buffer.from(value) : value
  const length = Buffer.alloc(4)
  length.writeUInt32BE(bytes.length)
  return Buffer.concat([length, bytes])
}

function uint32(value: number): Buffer {
  const result = Buffer.alloc(4)
  result.writeUInt32BE(value)
  return result
}

function signRequest(keyBlob: Buffer, data = Buffer.from('payload'), flags = 0): Buffer {
  return Buffer.concat([
    Buffer.from([SSH_AGENT_SIGN_REQUEST]),
    sshString(keyBlob),
    sshString(data),
    uint32(flags)
  ])
}

function frames(chunks: readonly Buffer[]): Buffer[] {
  const decoder = new SshAgentFrameDecoder()
  return decoder.push(Buffer.concat(chunks))
}

class FakeSocket extends Duplex {
  readonly outgoing: Buffer[] = []

  _read(): void {
    // Input is pushed explicitly through receive() by each test.
  }

  _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.outgoing.push(Buffer.from(chunk))
    callback()
  }

  receive(chunk: Buffer): void {
    this.push(chunk)
  }
}

class FakeListeningServer extends EventEmitter {
  maxConnections = 0

  listen(): this {
    queueMicrotask(() => this.emit('listening'))
    return this
  }

  close(callback?: () => void): this {
    queueMicrotask(() => callback?.())
    return this
  }
}

function publicKeyBlob(): Buffer {
  const generated = generateKeyPairSync('ed25519')
  const parsed = utils.parseKey(formatSshKeyMaterial(generated.privateKey).privateKey)
  if (parsed instanceof Error || Array.isArray(parsed)) throw parsed
  return parsed.getPublicSSH()
}

function parsedEd25519Key(): ParsedKey {
  const generated = generateKeyPairSync('ed25519')
  const parsed = utils.parseKey(formatSshKeyMaterial(generated.privateKey).privateKey)
  if (parsed instanceof Error || Array.isArray(parsed)) throw parsed
  return parsed
}

function sessionBindPayload(key: ParsedKey, sessionId: Buffer): Buffer {
  const signature = key.sign(sessionId)
  return Buffer.concat([
    sshString(key.getPublicSSH()),
    sshString(sessionId),
    sshString(Buffer.concat([sshString('ssh-ed25519'), sshString(signature)])),
    Buffer.from([1])
  ])
}

function stubProvider(keyBlob = publicKeyBlob()): SshAgentProvider {
  return {
    listIdentities: async () => [{ keyBlob, comment: 'Test key' }],
    sign: async () => ({ algorithm: 'ssh-ed25519', signature: Buffer.alloc(64, 7) })
  }
}

const allowApproval: SshAgentApprovalHandler = { approveSign: async () => true }

async function eventually(assertion: () => void): Promise<void> {
  let lastError: unknown
  for (let attempt = 0; attempt < 40; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5))
    try {
      assertion()
      return
    } catch (error) {
      lastError = error
    }
  }
  throw lastError
}

describe('SSH agent endpoint selection', () => {
  it('uses the environment override on Unix and OpenSSH fixed pipe on Windows', () => {
    expect(
      resolveSshAgentSocketPath({
        platform: 'linux',
        environment: { BEARWARDEN_SSH_AUTH_SOCK: '/tmp/bearwarden-test.sock' }
      })
    ).toBe('/tmp/bearwarden-test.sock')
    expect(
      resolveSshAgentSocketPath({
        platform: 'linux',
        getHomeDirectory: () => '/test-home'
      })
    ).toBe('/test-home/.bearwarden-ssh-agent.sock')
    expect(
      resolveSshAgentSocketPath({
        platform: 'win32',
        socketPath: '/ignored-on-windows'
      })
    ).toBe(OPENSSH_AGENT_PIPE_NAME)
  })
})

describe('SshAgentConnectionHandler', () => {
  it('silently ignores zero-length frames like the OpenSSH agent connection loop', async () => {
    const socket = new FakeSocket()
    const handler = new SshAgentConnectionHandler(socket, {
      provider: stubProvider(),
      approvalHandler: allowApproval
    })
    handler.start()
    socket.receive(
      Buffer.concat([
        frameSshAgentMessage(Buffer.alloc(0)),
        frameSshAgentMessage(Buffer.from([SSH_AGENT_REQUEST_IDENTITIES]))
      ])
    )

    await eventually(() => expect(socket.outgoing).toHaveLength(1))
    expect(frames(socket.outgoing)[0]?.[0]).toBe(12)
  })

  it('answers identities and signs only after approval', async () => {
    const socket = new FakeSocket()
    const keyBlob = publicKeyBlob()
    const approvals: Buffer[] = []
    let approvedRequestId: string | undefined
    let signedRequestId: string | undefined
    const handler = new SshAgentConnectionHandler(socket, {
      provider: {
        ...stubProvider(keyBlob),
        sign: async (request) => {
          signedRequestId = request.requestId
          return { algorithm: 'ssh-ed25519', signature: Buffer.alloc(64, 7) }
        }
      },
      approvalHandler: {
        approveSign: async (request) => {
          approvals.push(request.publicKeyBlob)
          approvedRequestId = request.requestId
          expect(request).not.toHaveProperty('data')
          return true
        }
      }
    })
    handler.start()

    socket.receive(
      Buffer.concat([
        frameSshAgentMessage(Buffer.from([SSH_AGENT_REQUEST_IDENTITIES])),
        frameSshAgentMessage(signRequest(keyBlob))
      ])
    )

    await eventually(() => expect(socket.outgoing).toHaveLength(2))
    const responses = frames(socket.outgoing)
    expect(responses[0]?.[0]).toBe(12)
    expect(responses[1]?.[0]).toBe(14)
    expect(approvals).toEqual([keyBlob])
    expect(approvedRequestId).toMatch(/^[0-9a-f-]{36}$/u)
    expect(signedRequestId).toBe(approvedRequestId)
  })

  it('dispatches coalesced requests sequentially to preserve approvals and response order', async () => {
    const socket = new FakeSocket()
    const keyBlob = publicKeyBlob()
    let releaseFirst: (() => void) | undefined
    const first = new Promise<void>((resolve) => {
      releaseFirst = resolve
    })
    let signCalls = 0
    const handler = new SshAgentConnectionHandler(socket, {
      provider: {
        listIdentities: async () => [],
        sign: async () => {
          signCalls += 1
          if (signCalls === 1) await first
          return { algorithm: 'ssh-ed25519', signature: Buffer.alloc(64, signCalls) }
        }
      },
      approvalHandler: allowApproval
    })
    handler.start()
    socket.receive(
      Buffer.concat([
        frameSshAgentMessage(signRequest(keyBlob, Buffer.from('one'))),
        frameSshAgentMessage(signRequest(keyBlob, Buffer.from('two')))
      ])
    )

    await eventually(() => expect(signCalls).toBe(1))
    expect(socket.outgoing).toHaveLength(0)
    releaseFirst?.()
    await eventually(() => {
      expect(signCalls).toBe(2)
      expect(socket.outgoing).toHaveLength(2)
    })
  })

  it('returns FAILURE for malformed, unknown, denied, and unsupported extension messages', async () => {
    const socket = new FakeSocket()
    const handler = new SshAgentConnectionHandler(socket, {
      provider: stubProvider(),
      approvalHandler: { approveSign: async () => false }
    })
    handler.start()
    socket.receive(
      Buffer.concat([
        frameSshAgentMessage(Buffer.from([255])),
        frameSshAgentMessage(Buffer.from([SSH_AGENT_SIGN_REQUEST, 0, 0, 0, 8])),
        frameSshAgentMessage(
          Buffer.concat([Buffer.from([SSH_AGENT_EXTENSION]), sshString('other')])
        ),
        frameSshAgentMessage(signRequest(publicKeyBlob()))
      ])
    )

    await eventually(() => expect(socket.outgoing).toHaveLength(4))
    expect(frames(socket.outgoing).map((response) => response[0])).toEqual([
      SSH_AGENT_FAILURE,
      SSH_AGENT_FAILURE,
      SSH_AGENT_FAILURE,
      SSH_AGENT_FAILURE
    ])
  })

  it('carries a verified session-bind context to approval and signing', async () => {
    const socket = new FakeSocket()
    const hostKey = parsedEd25519Key()
    const keyBlob = publicKeyBlob()
    let approvalFingerprint: string | undefined
    let signingForwarded = false
    const handler = new SshAgentConnectionHandler(socket, {
      provider: {
        listIdentities: async () => [],
        sign: async (request) => {
          signingForwarded = request.connection.session.forwarded
          expect(request.connection.session.hostFingerprint).toMatch(/^SHA256:/)
          return { algorithm: 'ssh-ed25519', signature: Buffer.alloc(64, 2) }
        }
      },
      approvalHandler: {
        approveSign: async (request) => {
          approvalFingerprint = request.connection.session.hostFingerprint
          return true
        }
      }
    })
    handler.start()
    socket.receive(
      Buffer.concat([
        frameSshAgentMessage(
          Buffer.concat([
            Buffer.from([SSH_AGENT_EXTENSION]),
            sshString(SSH_AGENT_SESSION_BIND),
            sessionBindPayload(hostKey, Buffer.alloc(32, 3))
          ])
        ),
        frameSshAgentMessage(signRequest(keyBlob))
      ])
    )

    await eventually(() => expect(socket.outgoing).toHaveLength(2))
    expect(frames(socket.outgoing).map((response) => response[0])).toEqual([6, 14])
    expect(approvalFingerprint).toMatch(/^SHA256:/)
    expect(signingForwarded).toBe(true)
  })

  it('closes on oversized framing and fails a request whose deadline expires', async () => {
    const oversized = new FakeSocket()
    const oversizedHandler = new SshAgentConnectionHandler(oversized, {
      provider: stubProvider(),
      approvalHandler: allowApproval
    })
    oversizedHandler.start()
    oversized.receive(uint32(256 * 1024 + 1))
    await eventually(() => expect(oversized.destroyed).toBe(true))

    const timedOut = new FakeSocket()
    let observedAbort = false
    const timeoutHandler = new SshAgentConnectionHandler(timedOut, {
      provider: {
        listIdentities: async ({ signal }) =>
          new Promise((resolve) => {
            signal.addEventListener(
              'abort',
              () => {
                observedAbort = true
                resolve([])
              },
              { once: true }
            )
          }),
        sign: async () => undefined
      },
      approvalHandler: allowApproval,
      requestTimeoutMs: 10
    })
    timeoutHandler.start()
    timedOut.receive(frameSshAgentMessage(Buffer.from([SSH_AGENT_REQUEST_IDENTITIES])))
    await eventually(() => {
      expect(observedAbort).toBe(true)
      expect(frames(timedOut.outgoing)[0]).toEqual(Buffer.from([SSH_AGENT_FAILURE]))
    })
  })

  it('aborts pending provider work when the transport is stopped', async () => {
    const socket = new FakeSocket()
    let providerStarted = false
    let providerAborted = false
    const handler = new SshAgentConnectionHandler(socket, {
      provider: {
        listIdentities: async ({ signal }) => {
          providerStarted = true
          return new Promise((resolve) => {
            signal.addEventListener(
              'abort',
              () => {
                providerAborted = true
                resolve([])
              },
              { once: true }
            )
          })
        },
        sign: async () => undefined
      },
      approvalHandler: allowApproval
    })
    handler.start()
    socket.receive(frameSshAgentMessage(Buffer.from([SSH_AGENT_REQUEST_IDENTITIES])))
    await eventually(() => expect(providerStarted).toBe(true))
    handler.stop()
    await eventually(() => {
      expect(providerAborted).toBe(true)
      expect(socket.destroyed).toBe(true)
    })
  })
})

async function requestAgent(path: string, body: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ path })
    const decoder = new SshAgentFrameDecoder()
    socket.once('error', reject)
    socket.once('connect', () => socket.write(frameSshAgentMessage(body)))
    socket.on('data', (chunk) => {
      const response = decoder.push(chunk)
      if (response[0]) {
        socket.end()
        resolve(response[0])
      }
    })
  })
}

const unixTest = process.platform === 'win32' ? it.skip : it

describe('SshAgentServer listener lifecycle', () => {
  it('reports a post-listen runtime error and tears the endpoint down', async () => {
    const onRuntimeError = vi.fn()
    const fakeServer = new FakeListeningServer()
    const server = new SshAgentServer({
      provider: stubProvider(),
      approvalHandler: allowApproval,
      platform: 'win32',
      onRuntimeError,
      testHooks: {
        createServer: () => fakeServer as unknown as ReturnType<typeof createServer>
      }
    })
    try {
      await server.start()
      const runtimeError = new Error('raw OS detail stays in main')
      fakeServer.emit('error', runtimeError)

      await eventually(() => {
        expect(onRuntimeError).toHaveBeenCalledOnce()
        expect(onRuntimeError).toHaveBeenCalledWith(runtimeError)
        expect(server.status.running).toBe(false)
        expect(server.status.socketPath).toBeUndefined()
      })
    } finally {
      await server.stop()
    }
  })

  unixTest('serves its private socket and removes only that socket on stop', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-ssh-agent-'))
    const socketPath = join(directory, 'agent.sock')
    const server = new SshAgentServer({
      provider: stubProvider(),
      approvalHandler: allowApproval,
      socketPath,
      platform: process.platform
    })
    try {
      const status = await server.start()
      expect(status).toMatchObject({ running: true, socketPath, activeConnections: 0 })
      expect((await lstat(socketPath)).mode & 0o777).toBe(0o600)
      expect((await requestAgent(socketPath, Buffer.from([SSH_AGENT_REQUEST_IDENTITIES])))[0]).toBe(
        12
      )
      expect(server.status.epoch).toBe(status.epoch)
      await server.stop()
      await expect(lstat(socketPath)).rejects.toMatchObject({ code: 'ENOENT' })
    } finally {
      await server.stop()
      await rm(directory, { recursive: true, force: true })
    }
  })

  unixTest('refuses to unlink a normal file or an active foreign socket', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-ssh-agent-'))
    const filePath = join(directory, 'not-a-socket')
    const livePath = join(directory, 'live.sock')
    await writeFile(filePath, 'do not delete')
    const server = new SshAgentServer({
      provider: stubProvider(),
      approvalHandler: allowApproval,
      socketPath: filePath,
      platform: process.platform
    })
    const foreign = createServer()
    try {
      await expect(server.start()).rejects.toThrow('SSH_AGENT_SOCKET_PATH_UNSAFE')
      await expect(lstat(filePath)).resolves.toBeDefined()
      await new Promise<void>((resolve, reject) => {
        foreign.once('error', reject)
        foreign.listen(livePath, resolve)
      })
      const contested = new SshAgentServer({
        provider: stubProvider(),
        approvalHandler: allowApproval,
        socketPath: livePath,
        platform: process.platform
      })
      await expect(contested.start()).rejects.toThrow('SSH_AGENT_SOCKET_IN_USE')
    } finally {
      await new Promise<void>((resolve) => foreign.close(() => resolve()))
      await rm(directory, { recursive: true, force: true })
    }
  })

  unixTest('preserves a path replaced after startup when closing the Node listener', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-ssh-agent-'))
    const socketPath = join(directory, 'agent.sock')
    const server = new SshAgentServer({
      provider: stubProvider(),
      approvalHandler: allowApproval,
      socketPath,
      platform: process.platform
    })
    try {
      await server.start()
      await unlink(socketPath)
      await writeFile(socketPath, 'replacement endpoint')
      await server.stop()
      await expect(readFile(socketPath, 'utf8')).resolves.toBe('replacement endpoint')
    } finally {
      await server.stop()
      await rm(directory, { recursive: true, force: true })
    }
  })

  unixTest('preserves a replacement when startup fails before socket inode capture', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-ssh-agent-'))
    const socketPath = join(directory, 'agent.sock')
    const server = new SshAgentServer({
      provider: stubProvider(),
      approvalHandler: allowApproval,
      socketPath,
      platform: process.platform,
      testHooks: {
        afterListeningBeforeSocketOwnership: async (path) => {
          await unlink(path)
          await writeFile(path, 'replacement before capture')
        }
      }
    })
    try {
      await expect(server.start()).rejects.toThrow('SSH_AGENT_SOCKET_NOT_CREATED')
      await expect(readFile(socketPath, 'utf8')).resolves.toBe('replacement before capture')
      expect(server.status.running).toBe(false)
    } finally {
      await server.stop()
      await rm(directory, { recursive: true, force: true })
    }
  })
})
