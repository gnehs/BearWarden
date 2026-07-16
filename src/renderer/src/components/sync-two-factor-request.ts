import type {
  SyncConnectRequest,
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
