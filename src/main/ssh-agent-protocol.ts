import { createHash } from 'node:crypto'
import { utils, type ParsedKey } from 'ssh2'

export const SSH_AGENT_MAX_MESSAGE_LENGTH = 256 * 1024

export const SSH_AGENT_FAILURE = 5
export const SSH_AGENT_SUCCESS = 6
export const SSH_AGENT_REQUEST_IDENTITIES = 11
export const SSH_AGENT_IDENTITIES_ANSWER = 12
export const SSH_AGENT_SIGN_REQUEST = 13
export const SSH_AGENT_SIGN_RESPONSE = 14
export const SSH_AGENT_EXTENSION = 27

export const SSH_AGENT_RSA_SHA2_256 = 2
export const SSH_AGENT_RSA_SHA2_512 = 4
export const SSH_AGENT_SESSION_BIND = 'session-bind@openssh.com'

export type SshAgentRsaHash = 'sha256' | 'sha512'

export type SshAgentMessage =
  | { type: 'request-identities' }
  | {
      type: 'sign-request'
      keyBlob: Buffer
      data: Buffer
      flags: number
      rsaHash: SshAgentRsaHash | undefined
    }
  | { type: 'extension'; name: string; payload: Buffer }
  | { type: 'unknown'; messageType: number }

export interface SshAgentIdentity {
  keyBlob: Buffer
  comment: string
}

export interface SshAgentSessionBindState {
  forwarded: boolean
  hostFingerprint: string | undefined
}

export type SshSigNamespace = 'git' | 'file' | 'unsupported'

export class SshAgentProtocolError extends Error {}

function readUint32(buffer: Buffer, offset: number): number {
  if (offset + 4 > buffer.length) {
    throw new SshAgentProtocolError('Truncated uint32')
  }
  return buffer.readUInt32BE(offset)
}

function readSshString(buffer: Buffer, offset: number): { value: Buffer; offset: number } {
  const length = readUint32(buffer, offset)
  const start = offset + 4
  const end = start + length
  if (end > buffer.length || end < start) {
    throw new SshAgentProtocolError('Truncated SSH string')
  }
  return { value: buffer.subarray(start, end), offset: end }
}

function encodeSshString(value: Buffer | string): Buffer {
  const bytes = typeof value === 'string' ? Buffer.from(value, 'utf8') : value
  const result = Buffer.allocUnsafe(4 + bytes.length)
  result.writeUInt32BE(bytes.length, 0)
  bytes.copy(result, 4)
  return result
}

function decodeUtf8(value: Buffer): string {
  const decoded = value.toString('utf8')
  if (!Buffer.from(decoded, 'utf8').equals(value)) {
    throw new SshAgentProtocolError('Invalid UTF-8 string')
  }
  return decoded
}

export function frameSshAgentMessage(body: Buffer): Buffer {
  if (body.length > SSH_AGENT_MAX_MESSAGE_LENGTH) {
    throw new SshAgentProtocolError('SSH agent message exceeds maximum length')
  }
  const result = Buffer.allocUnsafe(4 + body.length)
  result.writeUInt32BE(body.length, 0)
  body.copy(result, 4)
  return result
}

export class SshAgentFrameDecoder {
  private buffered = Buffer.alloc(0)

  push(chunk: Buffer): Buffer[] {
    if (chunk.length === 0) return []
    this.buffered =
      this.buffered.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.buffered, chunk])

    const messages: Buffer[] = []
    while (this.buffered.length >= 4) {
      const length = this.buffered.readUInt32BE(0)
      if (length > SSH_AGENT_MAX_MESSAGE_LENGTH) {
        this.buffered = Buffer.alloc(0)
        throw new SshAgentProtocolError('SSH agent message exceeds maximum length')
      }
      if (this.buffered.length < 4 + length) break
      messages.push(Buffer.from(this.buffered.subarray(4, 4 + length)))
      this.buffered = this.buffered.subarray(4 + length)
    }
    return messages
  }

  clear(): void {
    this.buffered = Buffer.alloc(0)
  }
}

export function parseSshAgentMessage(body: Buffer): SshAgentMessage {
  if (body.length === 0) {
    throw new SshAgentProtocolError('Empty SSH agent message')
  }

  const messageType = body[0]
  if (messageType === SSH_AGENT_REQUEST_IDENTITIES) {
    return { type: 'request-identities' }
  }
  if (messageType === SSH_AGENT_SIGN_REQUEST) {
    const key = readSshString(body, 1)
    const data = readSshString(body, key.offset)
    const flags = data.offset === body.length ? 0 : readUint32(body, data.offset)
    if (data.offset !== body.length && data.offset + 4 !== body.length) {
      throw new SshAgentProtocolError('Unexpected sign request data')
    }
    return {
      type: 'sign-request',
      keyBlob: Buffer.from(key.value),
      data: Buffer.from(data.value),
      flags,
      rsaHash:
        flags & SSH_AGENT_RSA_SHA2_256
          ? 'sha256'
          : flags & SSH_AGENT_RSA_SHA2_512
            ? 'sha512'
            : undefined
    }
  }
  if (messageType === SSH_AGENT_EXTENSION) {
    const name = readSshString(body, 1)
    return {
      type: 'extension',
      name: decodeUtf8(name.value),
      payload: Buffer.from(body.subarray(name.offset))
    }
  }
  return { type: 'unknown', messageType }
}

export function buildSshAgentFailure(): Buffer {
  return Buffer.from([SSH_AGENT_FAILURE])
}

export function buildSshAgentSuccess(): Buffer {
  return Buffer.from([SSH_AGENT_SUCCESS])
}

export function buildSshAgentIdentitiesAnswer(identities: readonly SshAgentIdentity[]): Buffer {
  const count = Buffer.allocUnsafe(4)
  count.writeUInt32BE(identities.length, 0)
  return Buffer.concat([
    Buffer.from([SSH_AGENT_IDENTITIES_ANSWER]),
    count,
    ...identities.flatMap((identity) => [
      encodeSshString(identity.keyBlob),
      encodeSshString(identity.comment)
    ])
  ])
}

export function buildSshAgentSignResponse(algorithm: string, signature: Buffer): Buffer {
  const signatureBlob = Buffer.concat([encodeSshString(algorithm), encodeSshString(signature)])
  return Buffer.concat([Buffer.from([SSH_AGENT_SIGN_RESPONSE]), encodeSshString(signatureBlob)])
}

export function detectSshSigNamespace(data: Buffer): SshSigNamespace | undefined {
  if (!data.subarray(0, 6).equals(Buffer.from('SSHSIG'))) return undefined
  if (data.length < 14) return 'unsupported'
  try {
    const namespace = readSshString(data, 10)
    const value = decodeUtf8(namespace.value)
    return value === 'git' || value === 'file' ? value : 'unsupported'
  } catch {
    return 'unsupported'
  }
}

function parsePublicKey(keyBlob: Buffer): ParsedKey | undefined {
  try {
    const algorithm = readSshString(keyBlob, 0)
    const parsed = utils.parseKey(
      `${decodeUtf8(algorithm.value)} ${keyBlob.toString('base64')} bearwarden-session-bind`
    )
    if (parsed instanceof Error || Array.isArray(parsed)) return undefined
    return parsed.getPublicSSH().equals(keyBlob) ? parsed : undefined
  } catch {
    return undefined
  }
}

function verifySessionBindSignature(
  publicKey: ParsedKey,
  algorithm: string,
  sessionId: Buffer,
  signature: Buffer
): boolean {
  if (publicKey.type === 'ssh-ed25519') {
    if (algorithm !== 'ssh-ed25519') return false
    return publicKey.verify(sessionId, signature) === true
  }
  if (publicKey.type === 'ssh-rsa') {
    if (algorithm !== 'rsa-sha2-256' && algorithm !== 'rsa-sha2-512') return false
    return publicKey.verify(sessionId, signature, algorithm) === true
  }
  return false
}

export function applySshAgentSessionBind(
  current: Readonly<SshAgentSessionBindState>,
  payload: Buffer
): SshAgentSessionBindState | undefined {
  try {
    const hostKey = readSshString(payload, 0)
    const sessionId = readSshString(payload, hostKey.offset)
    const outerSignature = readSshString(payload, sessionId.offset)
    const forwardingByte = payload[outerSignature.offset] ?? 0

    const signatureAlgorithm = readSshString(outerSignature.value, 0)
    const signature = readSshString(outerSignature.value, signatureAlgorithm.offset)
    const publicKey = parsePublicKey(hostKey.value)
    if (
      !publicKey ||
      !verifySessionBindSignature(
        publicKey,
        decodeUtf8(signatureAlgorithm.value),
        sessionId.value,
        signature.value
      )
    ) {
      return undefined
    }

    const digest = createHash('sha256').update(hostKey.value).digest('base64').replace(/=+$/, '')
    return {
      forwarded: current.forwarded || forwardingByte === 1,
      hostFingerprint: `SHA256:${digest}`
    }
  } catch {
    return undefined
  }
}
