import type {
  SyncConnectRequest,
  SyncTwoFactorProvider,
  SyncTwoFactorMethod,
  SyncUnlockRequest
} from '../../../shared/vault-contract'

export const WEB_AUTHN_TWO_FACTOR_METHOD = 'webauthn' as const

export type SyncTwoFactorFormMethod = SyncTwoFactorMethod | typeof WEB_AUTHN_TWO_FACTOR_METHOD

export interface SyncTwoFactorFormValues {
  twoFactorMethod: SyncTwoFactorFormMethod
  twoFactorCode: string
  webAuthnRemember: boolean
}

const FORM_METHOD_BY_PROVIDER: Partial<Record<SyncTwoFactorProvider, SyncTwoFactorFormMethod>> = {
  '0': '0',
  '1': '1',
  '3': '3',
  '7': WEB_AUTHN_TWO_FACTOR_METHOD
}

/** Chooses only a server-advertised method that BearWarden can complete on this platform. */
export function resolveSyncTwoFactorMethod(
  current: SyncTwoFactorFormMethod,
  providers: readonly SyncTwoFactorProvider[]
): SyncTwoFactorFormMethod | null {
  const supported = new Set(
    providers.flatMap((provider) => {
      const method = FORM_METHOD_BY_PROVIDER[provider]
      return method === undefined ? [] : [method]
    })
  )
  if (supported.has(current)) return current
  for (const method of ['0', '1', '3', WEB_AUTHN_TWO_FACTOR_METHOD] as const) {
    if (supported.has(method)) return method
  }
  return null
}

export function syncTwoFactorProviderForMethod(
  method: SyncTwoFactorFormMethod
): SyncTwoFactorProvider {
  return method === WEB_AUTHN_TWO_FACTOR_METHOD ? '7' : method
}

/** Keeps WebAuthn ceremony material out of the main renderer boundary. */
export function buildSyncTwoFactorRequest({
  twoFactorMethod,
  twoFactorCode,
  webAuthnRemember
}: SyncTwoFactorFormValues): Pick<
  SyncConnectRequest | SyncUnlockRequest,
  'twoFactorMethod' | 'twoFactorCode' | 'webAuthnRemember'
> {
  if (twoFactorMethod === WEB_AUTHN_TWO_FACTOR_METHOD) {
    return { webAuthnRemember }
  }

  const code = twoFactorCode.trim()
  return code ? { twoFactorMethod, twoFactorCode: code } : {}
}
