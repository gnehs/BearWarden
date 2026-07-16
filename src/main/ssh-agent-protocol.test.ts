import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { utils, type ParsedKey } from 'ssh2'
import { formatSshKeyMaterial } from './ssh-key-format'
import {
  SSH_AGENT_EXTENSION,
  SSH_AGENT_FAILURE,
  SSH_AGENT_IDENTITIES_ANSWER,
  SSH_AGENT_MAX_MESSAGE_LENGTH,
  SSH_AGENT_REQUEST_IDENTITIES,
  SSH_AGENT_SESSION_BIND,
  SSH_AGENT_SIGN_RESPONSE,
  SshAgentFrameDecoder,
  SshAgentProtocolError,
  applySshAgentSessionBind,
  buildSshAgentFailure,
  buildSshAgentIdentitiesAnswer,
  buildSshAgentSignResponse,
  detectSshSigNamespace,
  frameSshAgentMessage,
  parseSshAgentMessage
} from './ssh-agent-protocol'

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

function parsedPrivateKey(type: 'ed25519' | 'rsa' = 'ed25519'): ParsedKey {
  const generated =
    type === 'rsa'
      ? generateKeyPairSync('rsa', { modulusLength: 2048 })
      : generateKeyPairSync('ed25519')
  const parsed = utils.parseKey(formatSshKeyMaterial(generated.privateKey).privateKey)
  if (parsed instanceof Error || Array.isArray(parsed)) throw parsed
  return parsed
}

function sessionBindPayload(
  key: ParsedKey,
  sessionId: Buffer,
  forwarded: boolean,
  algorithm = key.type === 'ssh-rsa' ? 'rsa-sha2-256' : key.type
): Buffer {
  const signature =
    key.type === 'ssh-ed25519' || key.type.startsWith('ecdsa-')
      ? key.sign(sessionId)
      : key.sign(sessionId, algorithm === 'ssh-rsa' ? 'sha1' : algorithm)
  return Buffer.concat([
    sshString(key.getPublicSSH()),
    sshString(sessionId),
    sshString(Buffer.concat([sshString(algorithm), sshString(signature)])),
    Buffer.from([forwarded ? 1 : 0])
  ])
}

describe('SSH agent framing', () => {
  it('decodes fragmented and coalesced messages in order', () => {
    const decoder = new SshAgentFrameDecoder()
    const first = frameSshAgentMessage(Buffer.from([SSH_AGENT_REQUEST_IDENTITIES]))
    const second = frameSshAgentMessage(Buffer.from([99]))

    expect(decoder.push(first.subarray(0, 2))).toEqual([])
    expect(decoder.push(Buffer.concat([first.subarray(2), second]))).toEqual([
      Buffer.from([SSH_AGENT_REQUEST_IDENTITIES]),
      Buffer.from([99])
    ])
  })

  it('rejects an oversized length before buffering its body', () => {
    const decoder = new SshAgentFrameDecoder()
    expect(() => decoder.push(uint32(SSH_AGENT_MAX_MESSAGE_LENGTH + 1))).toThrow(
      SshAgentProtocolError
    )
  })

  it('rejects framing an oversized body', () => {
    expect(() => frameSshAgentMessage(Buffer.alloc(SSH_AGENT_MAX_MESSAGE_LENGTH + 1))).toThrow(
      SshAgentProtocolError
    )
  })
})

describe('SSH agent messages', () => {
  it('parses identity, sign, extension, and unknown requests', () => {
    expect(parseSshAgentMessage(Buffer.from([SSH_AGENT_REQUEST_IDENTITIES]))).toEqual({
      type: 'request-identities'
    })

    const keyBlob = parsedPrivateKey().getPublicSSH()
    const data = Buffer.from('payload')
    expect(
      parseSshAgentMessage(
        Buffer.concat([Buffer.from([13]), sshString(keyBlob), sshString(data), uint32(4)])
      )
    ).toEqual({ type: 'sign-request', keyBlob, data, flags: 4, rsaHash: 'sha512' })

    expect(
      parseSshAgentMessage(
        Buffer.concat([
          Buffer.from([SSH_AGENT_EXTENSION]),
          sshString(SSH_AGENT_SESSION_BIND),
          Buffer.from('extension payload')
        ])
      )
    ).toEqual({
      type: 'extension',
      name: SSH_AGENT_SESSION_BIND,
      payload: Buffer.from('extension payload')
    })
    expect(parseSshAgentMessage(Buffer.from([255]))).toEqual({
      type: 'unknown',
      messageType: 255
    })
  })

  it('uses rsa-sha2-256 when both standard RSA flags are set', () => {
    const keyBlob = parsedPrivateKey('rsa').getPublicSSH()
    const parsed = parseSshAgentMessage(
      Buffer.concat([Buffer.from([13]), sshString(keyBlob), sshString('data'), uint32(6)])
    )
    expect(parsed).toMatchObject({ type: 'sign-request', flags: 6, rsaHash: 'sha256' })
  })

  it('rejects empty, truncated, and trailing sign request fields', () => {
    expect(() => parseSshAgentMessage(Buffer.alloc(0))).toThrow(SshAgentProtocolError)
    expect(() => parseSshAgentMessage(Buffer.from([13, 0, 0, 0, 20]))).toThrow(
      SshAgentProtocolError
    )
    expect(() =>
      parseSshAgentMessage(
        Buffer.concat([
          Buffer.from([13]),
          sshString('key'),
          sshString('data'),
          uint32(0),
          uint32(0)
        ])
      )
    ).toThrow(SshAgentProtocolError)
  })

  it('builds failure, identities, and nested signature responses', () => {
    const keyBlob = parsedPrivateKey().getPublicSSH()
    expect(buildSshAgentFailure()).toEqual(Buffer.from([SSH_AGENT_FAILURE]))

    const identities = buildSshAgentIdentitiesAnswer([{ keyBlob, comment: 'Work key' }])
    expect(identities[0]).toBe(SSH_AGENT_IDENTITIES_ANSWER)
    expect(identities.readUInt32BE(1)).toBe(1)
    expect(identities.subarray(9, 9 + keyBlob.length)).toEqual(keyBlob)

    const response = buildSshAgentSignResponse('ssh-ed25519', Buffer.alloc(64, 7))
    expect(response[0]).toBe(SSH_AGENT_SIGN_RESPONSE)
    expect(response.readUInt32BE(1)).toBe(response.length - 5)
  })

  it('detects supported and unsupported SSHSIG namespaces', () => {
    const sshsig = (namespace: string): Buffer =>
      Buffer.concat([Buffer.from('SSHSIG'), uint32(1), sshString(namespace)])
    expect(detectSshSigNamespace(Buffer.from('regular ssh data'))).toBeUndefined()
    expect(detectSshSigNamespace(sshsig('git'))).toBe('git')
    expect(detectSshSigNamespace(sshsig('file'))).toBe('file')
    expect(detectSshSigNamespace(sshsig('custom'))).toBe('unsupported')
    expect(detectSshSigNamespace(Buffer.from('SSHSIG'))).toBe('unsupported')
  })
})

describe('OpenSSH session-bind extension', () => {
  it.each(['ed25519', 'rsa'] as const)('verifies %s host signatures', (type) => {
    const key = parsedPrivateKey(type)
    const state = applySshAgentSessionBind(
      { forwarded: false, hostFingerprint: undefined },
      sessionBindPayload(key, Buffer.alloc(32, 3), false)
    )
    expect(state).toEqual({
      forwarded: false,
      hostFingerprint: expect.stringMatching(/^SHA256:/)
    })
  })

  it('latches forwarding and updates the verified host fingerprint', () => {
    const first = parsedPrivateKey()
    const second = parsedPrivateKey()
    const initial = applySshAgentSessionBind(
      { forwarded: false, hostFingerprint: undefined },
      sessionBindPayload(first, Buffer.alloc(32, 1), true)
    )!
    const rebound = applySshAgentSessionBind(
      initial,
      sessionBindPayload(second, Buffer.alloc(32, 2), false)
    )!
    expect(rebound.forwarded).toBe(true)
    expect(rebound.hostFingerprint).not.toBe(initial.hostFingerprint)
  })

  it('rejects tampering, RSA SHA-1, ECDSA, and truncated payloads without state changes', () => {
    const current = { forwarded: true, hostFingerprint: 'SHA256:existing' }
    const key = parsedPrivateKey()
    const tampered = sessionBindPayload(key, Buffer.alloc(32, 4), false)
    tampered[tampered.length - 2] ^= 0xff
    expect(applySshAgentSessionBind(current, tampered)).toBeUndefined()

    const rsa = parsedPrivateKey('rsa')
    expect(
      applySshAgentSessionBind(
        current,
        sessionBindPayload(rsa, Buffer.alloc(32, 5), false, 'ssh-rsa')
      )
    ).toBeUndefined()
    expect(applySshAgentSessionBind(current, Buffer.from([0, 0, 0, 10]))).toBeUndefined()

    const ecdsa = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const parsed = utils.parseKey(formatSshKeyMaterial(ecdsa.privateKey).privateKey)
    if (parsed instanceof Error || Array.isArray(parsed)) throw parsed
    expect(
      applySshAgentSessionBind(
        current,
        sessionBindPayload(parsed, Buffer.alloc(32, 6), false, parsed.type)
      )
    ).toBeUndefined()
  })
})
