import { createHash } from 'node:crypto'
import { utils } from 'ssh2'
import { SSH_AGENT_MAX_MESSAGE_LENGTH } from '../ssh-agent-protocol'

export function parseSupportedSshAgentPublicKeyBlob(publicKey: string): Buffer | null {
  const parsed = utils.parseKey(publicKey)
  if (parsed instanceof Error || Array.isArray(parsed) || parsed.isPrivateKey()) return null
  if (
    parsed.type !== 'ssh-ed25519' &&
    parsed.type !== 'ssh-rsa' &&
    parsed.type !== 'ecdsa-sha2-nistp256' &&
    parsed.type !== 'ecdsa-sha2-nistp384' &&
    parsed.type !== 'ecdsa-sha2-nistp521'
  ) {
    return null
  }
  const blob = parsed.getPublicSSH()
  return blob.length === 0 || blob.length > SSH_AGENT_MAX_MESSAGE_LENGTH ? null : Buffer.from(blob)
}

export function sshAgentFingerprint(publicKeyBlob: Buffer): string {
  return `SHA256:${createHash('sha256').update(publicKeyBlob).digest('base64').replace(/=+$/u, '')}`
}
