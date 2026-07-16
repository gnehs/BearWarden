import { generateKeyPairSync } from 'node:crypto'
import type { SshKeyMaterial } from '../shared/vault-contract'
import { formatSshKeyMaterial } from './ssh-key-format'

export type { SshKeyMaterial } from '../shared/vault-contract'

export function generateSshKeyMaterial(): SshKeyMaterial {
  try {
    return formatSshKeyMaterial(generateKeyPairSync('ed25519').privateKey)
  } catch {
    throw new Error('SSH_KEY_GENERATION_FAILED')
  }
}
