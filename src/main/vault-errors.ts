import type { VaultErrorCode } from '../shared/vault-contract'

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
