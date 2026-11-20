import type {
  SyncConnectRequest,
  SyncDuoTwoFactorProvider,
  SyncTwoFactorProvider,
  SyncTwoFactorMethod,
  SyncUnlockRequest
} from '../../../shared/vault-contract'

export const WEB_AUTHN_TWO_FACTOR_METHOD = 'webauthn' as const
export const DUO_TWO_FACTOR_METHOD = 'duo' as const
export const ORGANIZATION_DUO_TWO_FACTOR_METHOD = 'organization-duo' as const

type SyncTwoFactorMethodSpec =
  | { readonly kind: 'code'; readonly provider: SyncTwoFactorMethod }
  | { readonly kind: 'webauthn'; readonly provider: '7' }
  | { readonly kind: 'duo'; readonly provider: SyncDuoTwoFactorProvider }

/**
 * Every login second factor BearWarden can complete, in auto-selection order. Code methods come
 * first because they finish in place; ceremonies that leave the dialog come last.
 */
const SYNC_TWO_FACTOR_METHODS = {
  '0': { kind: 'code', provider: '0' },
  '1': { kind: 'code', provider: '1' },
  '3': { kind: 'code', provider: '3' },
  [WEB_AUTHN_TWO_FACTOR_METHOD]: { kind: 'webauthn', provider: '7' },
  [DUO_TWO_FACTOR_METHOD]: { kind: 'duo', provider: '2' },
  [ORGANIZATION_DUO_TWO_FACTOR_METHOD]: { kind: 'duo', provider: '6' }
} as const satisfies Record<string, SyncTwoFactorMethodSpec>

export type SyncTwoFactorFormMethod = keyof typeof SYNC_TWO_FACTOR_METHODS

const METHOD_ORDER = Object.keys(SYNC_TWO_FACTOR_METHODS) as SyncTwoFactorFormMethod[]

export function syncTwoFactorMethodKind(
  method: SyncTwoFactorFormMethod
): SyncTwoFactorMethodSpec['kind'] {
  return SYNC_TWO_FACTOR_METHODS[method].kind
}

/** Chooses only a server-advertised method that BearWarden can complete on this platform. */
export function resolveSyncTwoFactorMethod(
  current: SyncTwoFactorFormMethod,
  providers: readonly SyncTwoFactorProvider[]
): SyncTwoFactorFormMethod | null {
  const offered = (method: SyncTwoFactorFormMethod): boolean =>
    providers.includes(SYNC_TWO_FACTOR_METHODS[method].provider)
  if (offered(current)) return current
  return METHOD_ORDER.find(offered) ?? null
}

export function syncTwoFactorProviderForMethod(
  method: SyncTwoFactorFormMethod
): SyncTwoFactorProvider {
  return SYNC_TWO_FACTOR_METHODS[method].provider
}

interface SyncTwoFactorFormValues {
  twoFactorMethod: SyncTwoFactorFormMethod
  twoFactorCode: string
  rememberDevice: boolean
}

/** Keeps WebAuthn and Duo ceremony material out of the main renderer boundary. */
export function buildSyncTwoFactorRequest({
  twoFactorMethod,
  twoFactorCode,
  rememberDevice
}: SyncTwoFactorFormValues): Pick<
  SyncConnectRequest | SyncUnlockRequest,
  'twoFactorMethod' | 'twoFactorCode' | 'webAuthnRemember' | 'duo'
> {
  const spec: SyncTwoFactorMethodSpec = SYNC_TWO_FACTOR_METHODS[twoFactorMethod]
  switch (spec.kind) {
    case 'webauthn':
      return { webAuthnRemember: rememberDevice }
    case 'duo':
      return { duo: { provider: spec.provider, remember: rememberDevice } }
    case 'code': {
      const code = twoFactorCode.trim()
      return code ? { twoFactorMethod: spec.provider, twoFactorCode: code } : {}
    }
  }
}
