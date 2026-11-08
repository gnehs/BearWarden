import type { BitwardenTwoFactorProviderId } from './bitwarden-http'
import type { SyncInvalidResponseReason, SyncInvalidResponseStage } from '../shared/vault-contract'
import type { AccountWebAuthnChallenge } from './account-webauthn-codec'

export type BitwardenDirectErrorCode =
  | 'AUTH_REQUIRED'
  | 'TWO_FACTOR_REQUIRED'
  | 'NEW_DEVICE_REQUIRED'
  | 'SSO_REQUIRED'
  | 'NETWORK'
  | 'INVALID_RESPONSE'
  | 'INVALID_SSH_KEY'
  | 'CONFLICT'
  | 'ABORTED'
  | 'NOT_FOUND'
  | 'FORBIDDEN'
  | 'TOO_LARGE'
  | 'STORAGE_LIMIT'
  | 'ATTACHMENT_REJECTED'
  | 'UNSUPPORTED_ACCOUNT_ENCRYPTION'
  | 'KEY_CONNECTOR_UNSUPPORTED'
  | 'TRUSTED_DEVICE_UNSUPPORTED'
  | 'ACCOUNT_CHANGED'
  | 'USER_VERIFICATION_FAILED'
  | 'API_KEY_ROTATION_UNKNOWN'
  | 'TWO_FACTOR_MUTATION_UNKNOWN'
  | 'MASTER_PASSWORD_CHANGE_UNKNOWN'
  | 'SESSION_DEAUTHORIZATION_UNKNOWN'
  | 'VAULT_PURGE_UNKNOWN'
  | 'ACCOUNT_PROFILE_STALE'
  | 'ACCOUNT_PROFILE_MUTATION_UNKNOWN'
  | 'STATE_PERSISTENCE_FAILED'

export class BitwardenDirectError extends Error {
  constructor(
    readonly code: BitwardenDirectErrorCode,
    /** Main-process-only, strictly normalized provider-7 request options. */
    readonly webAuthnChallenge?: AccountWebAuthnChallenge,
    /** Fixed, value-free location for sync response diagnostics. */
    readonly syncInvalidResponseStage?: SyncInvalidResponseStage,
    /** Main-process-only, bounded provider ids from the token challenge. */
    readonly twoFactorProviders?: readonly BitwardenTwoFactorProviderId[],
    /** Fixed, value-free reason suitable for renderer diagnostics. */
    readonly syncInvalidResponseReason?: SyncInvalidResponseReason
  ) {
    super(`Bitwarden direct sync failed (${code})`)
    this.name = 'BitwardenDirectError'
  }
}

export function invalidResponse(reason: SyncInvalidResponseReason): BitwardenDirectError {
  return new BitwardenDirectError('INVALID_RESPONSE', undefined, undefined, undefined, reason)
}
