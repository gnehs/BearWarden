import { utils, type ParsedKey } from 'ssh2'
import type { SshAgentRsaHash } from './ssh-agent-protocol'

export interface SshAgentSignature {
  algorithm: string
  signature: Buffer
}

export class SshAgentSigningError extends Error {}

function readDerLength(buffer: Buffer, offset: number): { length: number; offset: number } {
  const first = buffer[offset]
  if (first === undefined) throw new SshAgentSigningError('Truncated DER length')
  if ((first & 0x80) === 0) return { length: first, offset: offset + 1 }
  const octets = first & 0x7f
  if (octets === 0 || octets > 4 || offset + 1 + octets > buffer.length) {
    throw new SshAgentSigningError('Invalid DER length')
  }
  let length = 0
  for (let index = 0; index < octets; index += 1) {
    length = length * 256 + buffer[offset + 1 + index]!
  }
  if (length < 128) throw new SshAgentSigningError('Non-canonical DER length')
  return { length, offset: offset + 1 + octets }
}

function readDerInteger(buffer: Buffer, offset: number): { value: Buffer; offset: number } {
  if (buffer[offset] !== 0x02) throw new SshAgentSigningError('Expected DER integer')
  const decoded = readDerLength(buffer, offset + 1)
  const end = decoded.offset + decoded.length
  if (decoded.length === 0 || end > buffer.length) {
    throw new SshAgentSigningError('Truncated DER integer')
  }
  const value = buffer.subarray(decoded.offset, end)
  if ((value[0]! & 0x80) !== 0) throw new SshAgentSigningError('Negative DER integer')
  if (value.length > 1 && value[0] === 0 && (value[1]! & 0x80) === 0) {
    throw new SshAgentSigningError('Non-canonical DER integer')
  }
  return { value, offset: end }
}

function encodeSshString(value: Buffer): Buffer {
  const length = Buffer.allocUnsafe(4)
  length.writeUInt32BE(value.length)
  return Buffer.concat([length, value])
}

function ecdsaDerToSsh(signature: Buffer): Buffer {
  if (signature[0] !== 0x30) throw new SshAgentSigningError('Expected DER sequence')
  const sequence = readDerLength(signature, 1)
  if (sequence.offset + sequence.length !== signature.length) {
    throw new SshAgentSigningError('Invalid DER sequence length')
  }
  const r = readDerInteger(signature, sequence.offset)
  const s = readDerInteger(signature, r.offset)
  if (s.offset !== signature.length) throw new SshAgentSigningError('Unexpected DER signature data')
  return Buffer.concat([encodeSshString(r.value), encodeSshString(s.value)])
}

function parsePrivateKey(privateKey: string): ParsedKey {
  const parsed = utils.parseKey(privateKey)
  if (parsed instanceof Error || Array.isArray(parsed) || !parsed.isPrivateKey()) {
    throw new SshAgentSigningError('Invalid SSH private key')
  }
  return parsed
}

function signWithParsedKey(parsed: ParsedKey, data: Buffer, algorithm?: string): Buffer {
  const signature = algorithm === undefined ? parsed.sign(data) : parsed.sign(data, algorithm)
  if (!Buffer.isBuffer(signature) || signature.length === 0) {
    throw new SshAgentSigningError('SSH key signing failed')
  }
  return signature
}

export function signSshAgentData(
  privateKey: string,
  expectedPublicKeyBlob: Buffer,
  data: Buffer,
  rsaHash: SshAgentRsaHash | undefined
): SshAgentSignature {
  const parsed = parsePrivateKey(privateKey)
  if (!parsed.getPublicSSH().equals(expectedPublicKeyBlob)) {
    throw new SshAgentSigningError('SSH public key does not match private key')
  }

  if (parsed.type === 'ssh-ed25519') {
    return { algorithm: parsed.type, signature: signWithParsedKey(parsed, data) }
  }
  if (parsed.type === 'ssh-rsa') {
    if (rsaHash === undefined) {
      throw new SshAgentSigningError('RSA SHA-2 flag is required')
    }
    const algorithm = rsaHash === 'sha256' ? 'rsa-sha2-256' : 'rsa-sha2-512'
    return { algorithm, signature: signWithParsedKey(parsed, data, algorithm) }
  }
  if (
    parsed.type === 'ecdsa-sha2-nistp256' ||
    parsed.type === 'ecdsa-sha2-nistp384' ||
    parsed.type === 'ecdsa-sha2-nistp521'
  ) {
    return {
      algorithm: parsed.type,
      signature: ecdsaDerToSsh(signWithParsedKey(parsed, data))
    }
  }
  throw new SshAgentSigningError('Unsupported SSH key type')
}
