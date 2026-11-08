import type {
  BearWardenAPI,
  CustomFieldRequest,
  LoginSummary,
  TotpCodeView,
  VaultCopyField,
  VaultSecretField
} from '../../../shared/vault-contract'
import type { VaultAuthorization } from '../stores/vault-authorization-store'
import { isSharedLoginSummary } from './organizations-ui'
import { authorizationTokenField } from './vault-detail-cache'

type ItemAccessMethods =
  | 'revealSecret'
  | 'copyField'
  | 'revealCustomField'
  | 'copyCustomField'
  | 'getTotp'
  | 'copyTotp'
  | 'openUri'

export interface VaultItemAccessOptions {
  logins: Pick<BearWardenAPI['logins'], ItemAccessMethods>
  sharedLogins: Pick<BearWardenAPI['sharedLogins'], ItemAccessMethods>
  authorization: Pick<VaultAuthorization, 'token' | 'withReprompt'>
}

export type CustomFieldLocator = Omit<CustomFieldRequest, 'id'>

/**
 * Reads and uses one item's secrets through the IPC namespace that owns it. Shared items go
 * to `sharedLogins` without a reprompt, because organization policy governs them in the main
 * process; personal items go to `logins` behind the master-password reprompt.
 */
export interface VaultItemAccess {
  revealSecret: (item: LoginSummary, field: VaultSecretField) => Promise<string>
  revealCustomField: (item: LoginSummary, locator: CustomFieldLocator) => Promise<string>
  copyField: (item: LoginSummary, field: VaultCopyField, uriIndex?: number) => Promise<void>
  copyCustomField: (item: LoginSummary, locator: CustomFieldLocator) => Promise<void>
  copyTotp: (item: LoginSummary) => Promise<void>
  openUri: (item: LoginSummary, uriIndex: number) => Promise<void>
  /** Reads the current code with the cached token only; it never opens a reprompt. */
  getTotp: (item: LoginSummary) => Promise<TotpCodeView>
}

/** Personal items count copies and opens; shared items do not, so only they need a refresh. */
export function tracksItemUsage(item: LoginSummary): boolean {
  return !isSharedLoginSummary(item)
}

export function createVaultItemAccess({
  logins,
  sharedLogins,
  authorization
}: VaultItemAccessOptions): VaultItemAccess {
  function personal<T>(
    item: LoginSummary,
    call: (token: { authorizationToken?: string }) => Promise<T>
  ): Promise<T> {
    return authorization.withReprompt([item.id], (tokenFor) =>
      call(authorizationTokenField(tokenFor(item.id)))
    )
  }

  return {
    revealSecret: (item, field) =>
      isSharedLoginSummary(item)
        ? sharedLogins.revealSecret({ id: item.id, field })
        : personal(item, (token) => logins.revealSecret({ id: item.id, field, ...token })),
    revealCustomField: (item, locator) =>
      isSharedLoginSummary(item)
        ? sharedLogins.revealCustomField({ id: item.id, ...locator })
        : personal(item, (token) =>
            logins.revealCustomField({ id: item.id, ...locator, ...token })
          ),
    copyField: (item, field, uriIndex) => {
      const request = { id: item.id, field, ...(uriIndex === undefined ? {} : { uriIndex }) }
      return isSharedLoginSummary(item)
        ? sharedLogins.copyField(request)
        : personal(item, (token) => logins.copyField({ ...request, ...token }))
    },
    copyCustomField: (item, locator) =>
      isSharedLoginSummary(item)
        ? sharedLogins.copyCustomField({ id: item.id, ...locator })
        : personal(item, (token) => logins.copyCustomField({ id: item.id, ...locator, ...token })),
    copyTotp: (item) =>
      isSharedLoginSummary(item)
        ? sharedLogins.copyTotp({ id: item.id })
        : personal(item, (token) => logins.copyTotp({ id: item.id, ...token })),
    openUri: (item, uriIndex) =>
      isSharedLoginSummary(item)
        ? sharedLogins.openUri({ id: item.id, uriIndex })
        : personal(item, (token) => logins.openUri({ id: item.id, uriIndex, ...token })),
    getTotp: (item) =>
      isSharedLoginSummary(item)
        ? sharedLogins.getTotp({ id: item.id })
        : logins.getTotp({ id: item.id, ...authorizationTokenField(authorization.token(item.id)) })
  }
}
