import type { AccountWebAuthnRegistrationChallenge } from './account-webauthn-registration-codec'

export const ACCOUNT_WEBAUTHN_REGISTRATION_INIT_CHANNEL =
  'bearwarden:private:account-webauthn-registration:init'
export const ACCOUNT_WEBAUTHN_REGISTRATION_EVENT_CHANNEL =
  'bearwarden:private:account-webauthn-registration:event'

export const ACCOUNT_WEBAUTHN_REGISTRATION_EPOCH_ARGUMENT =
  '--bearwarden-webauthn-registration-epoch='
export const ACCOUNT_WEBAUTHN_REGISTRATION_CAPABILITY_ARGUMENT =
  '--bearwarden-webauthn-registration-capability='

export interface AccountWebAuthnRegistrationWindowIdentity {
  readonly epoch: number
  readonly capability: string
}

export interface AccountWebAuthnRegistrationWindowConfiguration extends AccountWebAuthnRegistrationWindowIdentity {
  readonly connectorUrl: string
  readonly challenge: AccountWebAuthnRegistrationChallenge
}

export type AccountWebAuthnRegistrationFailureReason =
  'aborted' | 'invalid-state' | 'not-allowed' | 'not-supported' | 'security' | 'unknown'

export type AccountWebAuthnRegistrationWindowEvent =
  | (AccountWebAuthnRegistrationWindowIdentity & {
      readonly type: 'success'
      readonly attestation: unknown
    })
  | (AccountWebAuthnRegistrationWindowIdentity & {
      readonly type: 'failure'
      readonly reason: AccountWebAuthnRegistrationFailureReason
    })
