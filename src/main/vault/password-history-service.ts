import type { VaultCore } from './core'
import type {
  LoginIdRequest,
  PasswordHistoryEntryRequest,
  PasswordHistoryRestoreRequest,
  LoginView,
  VaultPasswordHistoryEntry,
  VaultPasswordHistoryView
} from '../../shared/vault-contract'
import { VaultError } from '../vault-errors'
import { MAX_PASSWORD_HISTORY } from './limits'
import { assertUuid } from './parse-primitives'
import { toView } from './views'
import { clonePasswordHistory } from './password-history'
import type { ItemReadAuthorizationValidator, StoredLogin, VaultPlatform } from './types'
import { findLogin, assertActiveLogin } from './data-lookup'

/** Per-item password history: listing, reveal, copy and restore. */
export class VaultPasswordHistory {
  constructor(
    private readonly core: VaultCore,
    private readonly platform: VaultPlatform
  ) {}

  async getPasswordHistory(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<VaultPasswordHistoryEntry[]> {
    const login = this.passwordHistoryLogin(request, validateAuthorization)
    return clonePasswordHistory(login.passwordHistory)
  }

  async getPasswordHistoryView(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<VaultPasswordHistoryView> {
    const login = this.passwordHistoryLogin(request, validateAuthorization)
    return {
      expectedUpdatedAt: login.updatedAt,
      entries: login.passwordHistory.map(({ lastUsedDate }) => ({ lastUsedDate }))
    }
  }

  async revealPasswordHistory(
    request: PasswordHistoryEntryRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<string> {
    return this.passwordHistoryEntry(request, validateAuthorization).password
  }

  async copyPasswordHistory(
    request: PasswordHistoryEntryRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<void> {
    const entry = this.passwordHistoryEntry(request, validateAuthorization)
    await this.platform.copyText(entry.password)
  }

  private passwordHistoryLogin(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): StoredLogin {
    assertUuid(request.id)
    // History is cloned synchronously from the last committed snapshot so a background sync
    // cannot leave the explicit reveal action waiting behind network I/O. Lock starts by
    // blocking fast reads, and authorization is validated before this turn can yield.
    const login = findLogin(this.core.requireFastReadData(), request.id)
    if (
      (login.reprompt === 1 || login.deletedAt !== null) &&
      !validateAuthorization?.([login.id], { generation: this.core.generation })
    ) {
      throw new VaultError('REPROMPT_REQUIRED')
    }
    return login
  }

  private passwordHistoryEntry(
    request: PasswordHistoryEntryRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): VaultPasswordHistoryEntry {
    if (
      !Number.isSafeInteger(request.index) ||
      request.index < 0 ||
      request.index >= MAX_PASSWORD_HISTORY ||
      typeof request.lastUsedDate !== 'string' ||
      !Number.isFinite(Date.parse(request.lastUsedDate)) ||
      typeof request.expectedUpdatedAt !== 'string' ||
      !Number.isFinite(Date.parse(request.expectedUpdatedAt))
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    const login = this.passwordHistoryLogin(request, validateAuthorization)
    if (login.updatedAt !== request.expectedUpdatedAt) throw new VaultError('INVALID_INPUT')
    const entry = login.passwordHistory[request.index]
    if (!entry || entry.lastUsedDate !== request.lastUsedDate) {
      throw new VaultError('INVALID_INPUT')
    }
    return entry
  }

  restorePasswordHistory(request: PasswordHistoryRestoreRequest): Promise<LoginView> {
    return this.core.mutate((data, now) => {
      assertUuid(request.id)
      if (
        !Number.isSafeInteger(request.index) ||
        request.index < 0 ||
        request.index >= MAX_PASSWORD_HISTORY ||
        typeof request.lastUsedDate !== 'string' ||
        !Number.isFinite(Date.parse(request.lastUsedDate)) ||
        typeof request.expectedUpdatedAt !== 'string'
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      if (login.type !== 'login' || login.updatedAt !== request.expectedUpdatedAt) {
        throw new VaultError('INVALID_INPUT')
      }
      const entry = login.passwordHistory[request.index]
      if (
        !entry ||
        entry.lastUsedDate !== request.lastUsedDate ||
        entry.password === login.password
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const previousPassword = login.password
      const previousHistory = clonePasswordHistory(login.passwordHistory)
      login.password = entry.password
      login.passwordHistory = (
        previousPassword.length > 0
          ? [{ password: previousPassword, lastUsedDate: now }, ...previousHistory]
          : previousHistory
      ).slice(0, MAX_PASSWORD_HISTORY)
      login.passwordRevisionDate = now
      login.updatedAt = now
      return toView(login)
    })
  }
}
