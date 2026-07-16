import { describe, expect, it } from 'vitest'
import {
  AccountWebAuthnCodecError,
  parseAccountWebAuthnChallenge,
  parseAccountWebAuthnChallengeFromTokenError,
  serializeAccountWebAuthnAssertion
} from './account-webauthn-codec'

const CHALLENGE = Buffer.alloc(32, 0x31).toString('base64url')
const CREDENTIAL_ID = Buffer.alloc(32, 0x32).toString('base64url')

function vaultwardenChallenge(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    allowCredentials: [{ id: CREDENTIAL_ID, type: 'public-key' }],
    challenge: CHALLENGE,
    extensions: {
      appid: 'https://vault.example.com/app-id.json',
      getCredBlob: false,
      uvm: true
    },
    rpId: 'vault.example.com',
    timeout: 60_000,
    userVerification: 'discouraged',
    ...overrides
  }
}

function assertion(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: CREDENTIAL_ID,
    rawId: CREDENTIAL_ID,
    type: 'public-key',
    response: {
      clientDataJSON: Buffer.from('{"type":"webauthn.get"}').toString('base64url'),
      authenticatorData: Buffer.alloc(37, 1).toString('base64url'),
      signature: Buffer.alloc(70, 2).toString('base64url'),
      userHandle: null
    },
    clientExtensionResults: { appid: true, uvm: [[1, 2, 3]] },
    authenticatorAttachment: 'cross-platform',
    ...overrides
  }
}

function expectInvalid(run: () => unknown): void {
  expect(run).toThrow(AccountWebAuthnCodecError)
}

describe('account WebAuthn challenge codec', () => {
  it('normalizes the Vaultwarden camelCase provider fixture without arbitrary extensions', () => {
    expect(parseAccountWebAuthnChallenge(vaultwardenChallenge())).toEqual({
      challenge: CHALLENGE,
      rpId: 'vault.example.com',
      allowCredentials: [{ id: CREDENTIAL_ID, type: 'public-key' }],
      timeout: 60_000,
      userVerification: 'discouraged',
      extensions: {
        appid: 'https://vault.example.com/app-id.json',
        uvm: true
      }
    })
  })

  it('normalizes official PascalCase and extracts only provider type 7 from a token error', () => {
    const challenge = parseAccountWebAuthnChallengeFromTokenError({
      Error: 'invalid_grant',
      TwoFactorProviders2: {
        '0': null,
        '1': null,
        '3': { Nfc: true },
        '7': {
          AllowCredentials: [{ Id: CREDENTIAL_ID, Type: 'public-key', Transports: ['usb', 'nfc'] }],
          Challenge: CHALLENGE,
          Extensions: { AppId: 'https://vault.example.com/app-id.json', Uvm: true },
          RpId: 'vault.example.com',
          Timeout: 120_000,
          UserVerification: 'preferred'
        }
      }
    })

    expect(challenge).toMatchObject({
      rpId: 'vault.example.com',
      timeout: 120_000,
      userVerification: 'preferred',
      allowCredentials: [{ transports: ['usb', 'nfc'] }]
    })
    expect(
      parseAccountWebAuthnChallengeFromTokenError({ TwoFactorProviders2: { '0': null } })
    ).toBeUndefined()
  })

  it.each([
    `${CHALLENGE}=`,
    CHALLENGE.replace(/.$/u, '+'),
    'A',
    '',
    Buffer.alloc(1_025).toString('base64url')
  ])('rejects malformed or non-canonical challenge base64url %#', (challenge) => {
    expectInvalid(() => parseAccountWebAuthnChallenge(vaultwardenChallenge({ challenge })))
  })

  it.each([
    '127.0.0.1',
    '[::1]',
    'com',
    'co.uk',
    'github.io',
    'localhost',
    'bad..example.com',
    '-bad.example.com'
  ])('rejects unsafe RP ID %s', (rpId) => {
    expectInvalid(() => parseAccountWebAuthnChallenge(vaultwardenChallenge({ rpId })))
  })

  it('accepts a bounded self-hosted RP but rejects cross-origin or non-HTTPS AppID', () => {
    expect(
      parseAccountWebAuthnChallenge(
        vaultwardenChallenge({
          rpId: 'vw.local',
          extensions: { appid: 'https://vw.local/app-id.json' }
        })
      ).rpId
    ).toBe('vw.local')
    for (const appid of [
      'http://vault.example.com/app-id.json',
      'https://attacker.example/app-id.json',
      'https://user:secret@vault.example.com/app-id.json',
      'https://vault.example.com:8443/app-id.json'
    ]) {
      expectInvalid(() =>
        parseAccountWebAuthnChallenge(
          vaultwardenChallenge({ extensions: { appid, getCredBlob: false } })
        )
      )
    }
  })

  it('rejects credential, count, timeout, and extension overflows', () => {
    expectInvalid(() =>
      parseAccountWebAuthnChallenge(vaultwardenChallenge({ allowCredentials: [] }))
    )
    expectInvalid(() =>
      parseAccountWebAuthnChallenge(
        vaultwardenChallenge({
          allowCredentials: Array.from({ length: 65 }, () => ({
            id: CREDENTIAL_ID,
            type: 'public-key'
          }))
        })
      )
    )
    expectInvalid(() =>
      parseAccountWebAuthnChallenge(
        vaultwardenChallenge({
          allowCredentials: [{ id: Buffer.alloc(1_024).toString('base64url'), type: 'public-key' }]
        })
      )
    )
    expectInvalid(() => parseAccountWebAuthnChallenge(vaultwardenChallenge({ timeout: 0 })))
    expectInvalid(() => parseAccountWebAuthnChallenge(vaultwardenChallenge({ timeout: 600_001 })))
    expectInvalid(() =>
      parseAccountWebAuthnChallenge(vaultwardenChallenge({ userVerification: 'sometimes' }))
    )
    expectInvalid(() =>
      parseAccountWebAuthnChallenge(vaultwardenChallenge({ extensions: { arbitrary: true } }))
    )
  })

  it('rejects inherited objects, symbols, sparse arrays, and accessors without invocation', () => {
    expectInvalid(() =>
      parseAccountWebAuthnChallenge(
        Object.assign(Object.create({ injected: true }), vaultwardenChallenge())
      )
    )
    expectInvalid(() =>
      parseAccountWebAuthnChallenge({ ...vaultwardenChallenge(), [Symbol('hidden')]: true })
    )
    const sparse = Array(1)
    expectInvalid(() =>
      parseAccountWebAuthnChallenge(vaultwardenChallenge({ allowCredentials: sparse }))
    )
    let getterCalls = 0
    const accessor = vaultwardenChallenge()
    Object.defineProperty(accessor, 'challenge', {
      enumerable: true,
      get: () => {
        getterCalls += 1
        return CHALLENGE
      }
    })
    expectInvalid(() => parseAccountWebAuthnChallenge(accessor))
    expect(getterCalls).toBe(0)

    let providerGetterCalls = 0
    const providers = Object.create(null) as Record<string, unknown>
    Object.defineProperty(providers, '7', {
      enumerable: true,
      get: () => {
        providerGetterCalls += 1
        return vaultwardenChallenge()
      }
    })
    expectInvalid(() =>
      parseAccountWebAuthnChallengeFromTokenError({ TwoFactorProviders2: providers })
    )
    expect(providerGetterCalls).toBe(0)
    expectInvalid(() =>
      parseAccountWebAuthnChallengeFromTokenError({
        TwoFactorProviders2: { '7': vaultwardenChallenge() },
        twoFactorProviders2: { '7': vaultwardenChallenge() }
      })
    )
  })
})

describe('account WebAuthn assertion serializer', () => {
  it('serializes the exact official/Vaultwarden token wire shape and bounded UVM output', () => {
    const native = assertion()
    const response = native.response as Record<string, unknown>
    expect(JSON.parse(serializeAccountWebAuthnAssertion(native))).toEqual({
      id: CREDENTIAL_ID,
      rawId: CREDENTIAL_ID,
      type: 'public-key',
      response: {
        clientDataJson: response.clientDataJSON,
        authenticatorData: response.authenticatorData,
        signature: response.signature
      },
      extensions: { appid: true, uvm: [[1, 2, 3]] }
    })
    expect(
      JSON.parse(
        serializeAccountWebAuthnAssertion(
          assertion({
            response: { ...response, userHandle: Buffer.from('user').toString('base64url') },
            clientExtensionResults: {}
          })
        )
      )
    ).toEqual({
      id: CREDENTIAL_ID,
      rawId: CREDENTIAL_ID,
      type: 'public-key',
      response: {
        clientDataJson: response.clientDataJSON,
        authenticatorData: response.authenticatorData,
        signature: response.signature,
        userHandle: Buffer.from('user').toString('base64url')
      },
      extensions: {}
    })
  })

  it('rejects mismatched IDs, padding, extra fields, malformed UVM, and accessors', () => {
    expectInvalid(() =>
      serializeAccountWebAuthnAssertion(
        assertion({ rawId: Buffer.alloc(32, 9).toString('base64url') })
      )
    )
    expectInvalid(() => serializeAccountWebAuthnAssertion(assertion({ id: `${CREDENTIAL_ID}=` })))
    expectInvalid(() => serializeAccountWebAuthnAssertion({ ...assertion(), secret: 'extra' }))
    expectInvalid(() =>
      serializeAccountWebAuthnAssertion(
        assertion({ clientExtensionResults: { uvm: [[1, 2, 3, 4]] } })
      )
    )
    expectInvalid(() =>
      serializeAccountWebAuthnAssertion(
        assertion({ clientExtensionResults: { uvm: [[1, 2, 0x1_0000_0000]] } })
      )
    )
    let getterCalls = 0
    const accessor = assertion()
    Object.defineProperty(accessor, 'rawId', {
      enumerable: true,
      get: () => {
        getterCalls += 1
        return CREDENTIAL_ID
      }
    })
    expectInvalid(() => serializeAccountWebAuthnAssertion(accessor))
    expect(getterCalls).toBe(0)
  })
})
