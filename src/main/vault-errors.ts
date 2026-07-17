import type { VaultErrorCode } from '../shared/vault-contract'
import {
  AccountRelaunchResultUnknownError,
  AccountSwitchServiceError
} from './account-switch-service'

export class VaultError extends Error {
  readonly code: VaultErrorCode

  constructor(code: VaultErrorCode, message = code) {
    super(message)
    this.name = 'VaultError'
    this.code = code
  }
}

export function isVaultError(error: unknown): error is VaultError {
  return error instanceof VaultError
}

/** Maps main-only account switching failures to stable codes without retaining causes or paths. */
export function accountSwitchVaultError(error: unknown): VaultError | null {
  if (error instanceof AccountRelaunchResultUnknownError) {
    return new VaultError('ACCOUNT_SWITCH_RESULT_UNKNOWN')
  }
  if (!(error instanceof AccountSwitchServiceError)) return null

  switch (error.code) {
    case 'INVALID_ACCOUNT_SWITCH_REQUEST':
      return new VaultError('INVALID_INPUT')
    case 'ACCOUNT_LIMIT_REACHED':
      return new VaultError('ACCOUNT_LIMIT_REACHED')
    case 'ACCOUNT_NOT_REGISTERED':
      return new VaultError('ACCOUNT_NOT_FOUND')
    case 'ACCOUNT_ACTIVE_REMOVAL_FORBIDDEN':
      return new VaultError('ACCOUNT_ACTIVE_REMOVAL_FORBIDDEN')
    case 'ACCOUNT_STALE_REORDER_REQUEST':
      return new VaultError('ACCOUNT_STALE_STATE')
    case 'ACCOUNT_REGISTRY_UPDATE_RESULT_UNKNOWN':
      return new VaultError('ACCOUNT_SWITCH_RESULT_UNKNOWN')
    case 'ACCOUNT_SWITCH_IN_PROGRESS':
      return new VaultError('ACCOUNT_SWITCH_IN_PROGRESS')
    case 'ACCOUNT_REGISTRY_UNAVAILABLE':
    case 'ACCOUNT_ID_GENERATION_FAILED':
    case 'ACCOUNT_STORAGE_PREPARATION_FAILED':
    case 'ACCOUNT_STORAGE_UNAVAILABLE':
    case 'ACCOUNT_REMOVAL_UNAVAILABLE':
    case 'ACCOUNT_REMOVAL_PREPARATION_FAILED':
    case 'ACCOUNT_ACTIVATION_FAILED':
    case 'ACCOUNT_REGISTRY_UPDATE_FAILED':
      return new VaultError('ACCOUNT_SWITCH_UNAVAILABLE')
  }
}
