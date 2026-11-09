import type { VaultCore } from './core'
import type { LoginAuthorizeRequest, LoginAuthorizeManyRequest } from '../../shared/vault-contract'
import { MAX_LOGIN_AUTHORIZE_MANY_IDS } from '../../shared/vault-contract'
import { VaultError } from '../vault-errors'
import { MAX_MASTER_PASSWORD_LENGTH } from './limits'
import { assertUuid } from './parse-primitives'
import { findLogin } from './data-lookup'

/** Master-password reprompt for protected items: one-shot item authorization and the authorized-operation gate that integrations run their credential reads through. */
export class VaultItemAuthorization {
  constructor(private readonly core: VaultCore) {}

  /**
   * Main-process authorization boundary. The validator must be synchronous: keeping it and the
   * nested service operation in this same exclusive section prevents sync from enabling reprompt
   * between the check and secret access.
   */
  runAuthorizedOperation<T>(
    validate: (ids: readonly string[], state: { generation: number }) => boolean,
    operation: (authorize: (ids: readonly string[]) => void) => Promise<T>
  ): Promise<T> {
    return this.core.exclusive(async () => {
      let didAuthorize = false
      const authorize = (ids: readonly string[]): void => {
        didAuthorize = true
        let requiresReprompt = false
        for (const id of ids) {
          assertUuid(id)
          const login = findLogin(this.core.requireData(), id)
          if (login.reprompt === 1) requiresReprompt = true
        }
        if (requiresReprompt && !validate(ids, { generation: this.core.generation })) {
          throw new VaultError('REPROMPT_REQUIRED')
        }
      }
      const result = await operation(authorize)
      if (!didAuthorize) throw new VaultError('INTERNAL_ERROR')
      return result
    })
  }

  authorizeLogin(request: LoginAuthorizeRequest): Promise<number> {
    return this.core.exclusive(async () => {
      assertUuid(request.id)
      findLogin(this.core.requireData(), request.id)
      if (typeof request.masterPassword !== 'string') throw new VaultError('INVALID_INPUT')
      const candidate = request.masterPassword.normalize('NFC')
      if (candidate.length > MAX_MASTER_PASSWORD_LENGTH) {
        throw new VaultError('INVALID_MASTER_PASSWORD')
      }
      const generation = this.core.generation
      const valid = await this.core.verifyMasterPassword(candidate)
      if (!valid) throw new VaultError('INVALID_MASTER_PASSWORD')
      return generation
    })
  }

  authorizeLogins(request: LoginAuthorizeManyRequest): Promise<number> {
    return this.core.exclusive(async () => {
      if (
        !Array.isArray(request.ids) ||
        request.ids.length === 0 ||
        request.ids.length > MAX_LOGIN_AUTHORIZE_MANY_IDS ||
        new Set(request.ids).size !== request.ids.length
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      for (const id of request.ids) {
        assertUuid(id)
        findLogin(this.core.requireData(), id)
      }
      if (typeof request.masterPassword !== 'string') throw new VaultError('INVALID_INPUT')
      const candidate = request.masterPassword.normalize('NFC')
      if (candidate.length > MAX_MASTER_PASSWORD_LENGTH) {
        throw new VaultError('INVALID_MASTER_PASSWORD')
      }
      const generation = this.core.generation
      const valid = await this.core.verifyMasterPassword(candidate)
      if (!valid) throw new VaultError('INVALID_MASTER_PASSWORD')
      return generation
    })
  }
}
