import { describe, expect, expectTypeOf, it } from 'vitest'
import {
  IPC_CHANNELS,
  type AccountWebAuthnKeyEnrollmentRequest,
  type AccountWebAuthnKeyRemovalRequest,
  type AccountWebAuthnKeyView,
  type AccountWebAuthnKeysRequest,
  type BearWardenAPI
} from './vault-contract'

describe('account WebAuthn renderer contract', () => {
  it('limits the public view to server key metadata', () => {
    const key: AccountWebAuthnKeyView = { id: 1, name: 'USB key', migrated: false }

    expect(key).toEqual({ id: 1, name: 'USB key', migrated: false })
    expect(Object.keys(key)).toEqual(['id', 'name', 'migrated'])
  })

  it('types only the narrow list, enrollment, and removal requests', () => {
    expectTypeOf<AccountWebAuthnKeysRequest>().toEqualTypeOf<{ masterPassword: string }>()
    expectTypeOf<AccountWebAuthnKeyEnrollmentRequest>().toEqualTypeOf<{
      masterPassword: string
      name: string
    }>()
    expectTypeOf<AccountWebAuthnKeyRemovalRequest>().toEqualTypeOf<{
      id: number
      masterPassword: string
      confirm: true
    }>()
    expectTypeOf<BearWardenAPI['accountSecurity']['listWebAuthnKeys']>().parameters.toEqualTypeOf<
      [AccountWebAuthnKeysRequest]
    >()
    expectTypeOf<BearWardenAPI['accountSecurity']['listWebAuthnKeys']>().returns.toEqualTypeOf<
      Promise<AccountWebAuthnKeyView[]>
    >()
    expectTypeOf<BearWardenAPI['accountSecurity']['enrollWebAuthnKey']>().returns.toEqualTypeOf<
      Promise<void>
    >()
    expectTypeOf<BearWardenAPI['accountSecurity']['removeWebAuthnKey']>().returns.toEqualTypeOf<
      Promise<void>
    >()
    expect(IPC_CHANNELS.accountSecurityWebAuthnKeys).toBe('account-security:webauthn-keys')
    expect(IPC_CHANNELS.accountSecurityEnrollWebAuthnKey).toBe(
      'account-security:enroll-webauthn-key'
    )
    expect(IPC_CHANNELS.accountSecurityRemoveWebAuthnKey).toBe(
      'account-security:remove-webauthn-key'
    )
  })
})
