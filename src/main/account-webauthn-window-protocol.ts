export const ACCOUNT_WEBAUTHN_WRAPPER_INIT_CHANNEL =
  'bearwarden:private:account-webauthn-wrapper:init'
export const ACCOUNT_WEBAUTHN_WRAPPER_EVENT_CHANNEL =
  'bearwarden:private:account-webauthn-wrapper:event'

export const ACCOUNT_WEBAUTHN_EPOCH_ARGUMENT = '--bearwarden-webauthn-epoch='
export const ACCOUNT_WEBAUTHN_CAPABILITY_ARGUMENT = '--bearwarden-webauthn-capability='

export interface AccountWebAuthnWrapperIdentity {
  readonly epoch: number
  readonly capability: string
}

export interface AccountWebAuthnWrapperConfiguration extends AccountWebAuthnWrapperIdentity {
  readonly wrapperUrl: string
  readonly connectorUrl: string
  readonly connectorOrigin: string
}

export type AccountWebAuthnWrapperEvent =
  | (AccountWebAuthnWrapperIdentity & {
      readonly type: 'message'
      readonly data: string
    })
  | (AccountWebAuthnWrapperIdentity & {
      readonly type: 'cancel'
    })
