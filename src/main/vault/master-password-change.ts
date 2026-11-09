import { createHash } from 'node:crypto'
import { resolveBitwardenUrls } from '../bitwarden-http'
import { VaultError } from '../vault-errors'
import type { PersistedSyncData, VaultData } from './types'
import { UUID_PATTERN } from '../validation-primitives'

export function masterPasswordChangeAccountFingerprint(sync: PersistedSyncData): string {
  const profileId = sync.state.profileId
  if (!profileId || !UUID_PATTERN.test(profileId)) {
    throw new VaultError('CORRUPT_VAULT', 'CORRUPT_VAULT:sync-profile-id')
  }
  const canonicalAccount = JSON.stringify({
    provider: sync.provider,
    serverUrl: resolveBitwardenUrls(sync.serverUrl).apiUrl,
    profileId
  })
  return createHash('sha256').update(canonicalAccount, 'utf8').digest('hex')
}

export function assertMasterPasswordChangeAccount(data: VaultData): void {
  const journal = data.masterPasswordChange
  if (!journal) return
  if (
    !data.sync ||
    journal.accountFingerprint !== masterPasswordChangeAccountFingerprint(data.sync)
  ) {
    throw new VaultError('CORRUPT_VAULT', 'CORRUPT_VAULT:password-change-account')
  }
}
