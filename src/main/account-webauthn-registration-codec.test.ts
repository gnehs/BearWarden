import { describe, expect, it } from 'vitest'
import { AccountWebAuthnCodecError } from './account-webauthn-codec'
import {
  parseAccountWebAuthnRegistrationChallenge,
  parseAccountWebAuthnRegistrationChallengeFromResponse,
  serializeAccountWebAuthnAttestation
} from './account-webauthn-registration-codec'

const CHALLENGE = Buffer.alloc(32, 0x31).toString('base64url')
const USER_ID = Buffer.alloc(16, 0x32).toString('base64url')
const CREDENTIAL_ID = Buffer.alloc(32, 0x33).toString('base64url')
const CLIENT_DATA = Buffer.from(
  JSON.stringify({
    type: 'webauthn.create',
    challenge: CHALLENGE,
    origin: 'https://vault.example.com',
    crossOrigin: false
  })
).toString('base64url')
const ATTESTATION_OBJECT = Buffer.alloc(256, 0x34).toString('base64url')

function vaultwardenChallenge(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    rp: { id: 'vault.example.com', name: 'Vaultwarden' },
    user: { id: USER_ID, name: 'user@example.com', displayName: 'Example User' },
    challenge: CHALLENGE,
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -257 }
    ],
    timeout: 60_000,
    excludeCredentials: [{ type: 'public-key', id: CREDENTIAL_ID, transports: ['usb'] }],
    authenticatorSelection: {
      authenticatorAttachment: 'cross-platform',
      residentKey: 'discouraged',
      requireResidentKey: false,
      userVerification: 'discouraged'
    },
    attestation: 'none',
    extensions: {},
    status: 'ok',
    errorMessage: '',
    ...overrides
  }
}

function attestation(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: CREDENTIAL_ID,
    rawId: CREDENTIAL_ID,
    type: 'public-key',
    response: {
      clientDataJSON: CLIENT_DATA,
      attestationObject: ATTESTATION_OBJECT
    },
    clientExtensionResults: {},
    authenticatorAttachment: 'cross-platform',
    ...overrides
  }
}

function expectInvalid(run: () => unknown): void {
  expect(run).toThrow(AccountWebAuthnCodecError)
}

describe('account WebAuthn registration challenge codec', () => {
  it('normalizes a Vaultwarden direct challenge and removes transport-only status fields', () => {
    expect(parseAccountWebAuthnRegistrationChallenge(vaultwardenChallenge())).toEqual({
      rp: { id: 'vault.example.com', name: 'Vaultwarden' },
      user: { id: USER_ID, name: 'user@example.com', displayName: 'Example User' },
      challenge: CHALLENGE,
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 }
      ],
      timeout: 60_000,
      excludeCredentials: [{ type: 'public-key', id: CREDENTIAL_ID, transports: ['usb'] }],
      authenticatorSelection: {
        authenticatorAttachment: 'cross-platform',
        residentKey: 'discouraged',
        requireResidentKey: false,
        userVerification: 'discouraged'
      },
      attestation: 'none',
      extensions: {}
    })
  })

  it('accepts the official envelope and PascalCase option aliases', () => {
    const result = parseAccountWebAuthnRegistrationChallengeFromResponse({
      Options: {
        Rp: { Id: 'vault.example.com', Name: 'Bitwarden' },
        User: { Id: USER_ID, Name: 'user@example.com', DisplayName: 'Example User' },
        Challenge: CHALLENGE,
        PubKeyCredParams: [{ Type: 'public-key', Alg: -7 }],
        Timeout: 120_000,
        ExcludeCredentials: [
          { Type: 'public-key', Id: CREDENTIAL_ID, Transports: ['nfc', 'smart-card'] }
        ],
        AuthenticatorSelection: {
          AuthenticatorAttachment: 'platform',
          ResidentKey: 'required',
          RequireResidentKey: true,
          UserVerification: 'required'
        },
        Attestation: 'direct',
        Extensions: {
          AppIdExclude: 'https://vault.example.com/app-id.json',
          CredProps: true,
          LargeBlob: { Support: 'preferred' },
          Prf: { Eval: { first: USER_ID } }
        }
      },
      Object: 'twoFactorWebAuthnChallenge'
    })

    expect(result).toMatchObject({
      rp: { name: 'Bitwarden' },
      timeout: 120_000,
      attestation: 'direct',
      excludeCredentials: [{ transports: ['nfc', 'smart-card'] }],
      extensions: {
        appidExclude: 'https://vault.example.com/app-id.json',
        credProps: true,
        largeBlob: { support: 'preferred' },
        prf: { eval: { first: USER_ID } }
      }
    })
  })

  it('applies WebAuthn defaults for optional creation members', () => {
    const result = parseAccountWebAuthnRegistrationChallenge({
      rp: { id: 'vault.example.com', name: 'Vault' },
      user: { id: USER_ID, name: 'user@example.com', displayName: 'User' },
      challenge: CHALLENGE,
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }]
    })
    expect(result).toMatchObject({
      excludeCredentials: [],
      authenticatorSelection: {},
      attestation: 'none',
      extensions: {}
    })
    expect(result).not.toHaveProperty('timeout')
    expect(Object.isFrozen(result)).toBe(true)
    expect(Object.isFrozen(result.pubKeyCredParams)).toBe(true)
  })

  it.each([
    `${CHALLENGE}=`,
    CHALLENGE.replace(/.$/u, '+'),
    'A',
    '',
    Buffer.alloc(1_025).toString('base64url')
  ])('rejects malformed or non-canonical challenge base64url %#', (challenge) => {
    expectInvalid(() =>
      parseAccountWebAuthnRegistrationChallenge(vaultwardenChallenge({ challenge }))
    )
  })

  it('rejects bounded field and collection overflows', () => {
    expectInvalid(() =>
      parseAccountWebAuthnRegistrationChallenge(
        vaultwardenChallenge({
          user: { id: Buffer.alloc(65).toString('base64url'), name: 'user', displayName: 'User' }
        })
      )
    )
    expectInvalid(() =>
      parseAccountWebAuthnRegistrationChallenge(
        vaultwardenChallenge({
          pubKeyCredParams: Array.from({ length: 33 }, () => ({ type: 'public-key', alg: -7 }))
        })
      )
    )
    expectInvalid(() =>
      parseAccountWebAuthnRegistrationChallenge(
        vaultwardenChallenge({
          excludeCredentials: Array.from({ length: 65 }, () => ({
            type: 'public-key',
            id: CREDENTIAL_ID
          }))
        })
      )
    )
    expectInvalid(() =>
      parseAccountWebAuthnRegistrationChallenge(vaultwardenChallenge({ timeout: 600_001 }))
    )
    expectInvalid(() =>
      parseAccountWebAuthnRegistrationChallenge(
        vaultwardenChallenge({ rp: { id: 'com', name: 'x' } })
      )
    )
  })

  it('rejects duplicate aliases, identifiers, and inconsistent resident-key policy', () => {
    expectInvalid(() =>
      parseAccountWebAuthnRegistrationChallenge({
        ...vaultwardenChallenge(),
        Challenge: CHALLENGE
      })
    )
    expectInvalid(() =>
      parseAccountWebAuthnRegistrationChallenge(
        vaultwardenChallenge({
          excludeCredentials: [
            { type: 'public-key', id: CREDENTIAL_ID },
            { type: 'public-key', id: CREDENTIAL_ID }
          ]
        })
      )
    )
    expectInvalid(() =>
      parseAccountWebAuthnRegistrationChallenge(
        vaultwardenChallenge({
          authenticatorSelection: { residentKey: 'discouraged', requireResidentKey: true }
        })
      )
    )
  })

  it('rejects accessors, sparse arrays, inherited objects, and unknown shapes without invocation', () => {
    let getterCalls = 0
    const accessor = vaultwardenChallenge()
    Object.defineProperty(accessor, 'challenge', {
      enumerable: true,
      get: () => {
        getterCalls += 1
        return CHALLENGE
      }
    })
    expectInvalid(() => parseAccountWebAuthnRegistrationChallenge(accessor))
    expect(getterCalls).toBe(0)

    expectInvalid(() =>
      parseAccountWebAuthnRegistrationChallenge(
        Object.assign(Object.create({ injected: true }), vaultwardenChallenge())
      )
    )
    expectInvalid(() =>
      parseAccountWebAuthnRegistrationChallenge({
        ...vaultwardenChallenge(),
        [Symbol('hidden')]: true
      })
    )
    expectInvalid(() =>
      parseAccountWebAuthnRegistrationChallenge(
        vaultwardenChallenge({ pubKeyCredParams: new Array(1) })
      )
    )
    expectInvalid(() =>
      parseAccountWebAuthnRegistrationChallenge(
        vaultwardenChallenge({ extensions: { arbitrary: true } })
      )
    )
  })

  it('rejects assertion-shaped challenges and unsuccessful Vaultwarden metadata', () => {
    expectInvalid(() =>
      parseAccountWebAuthnRegistrationChallenge(
        vaultwardenChallenge({ rpId: 'vault.example.com', allowCredentials: [] })
      )
    )
    expectInvalid(() =>
      parseAccountWebAuthnRegistrationChallenge(vaultwardenChallenge({ status: 'error' }))
    )
    expectInvalid(() =>
      parseAccountWebAuthnRegistrationChallenge(vaultwardenChallenge({ errorMessage: 'failed' }))
    )
  })
})

describe('account WebAuthn attestation serializer', () => {
  it('serializes exact Bitwarden/Vaultwarden casing and bounded creation extensions', () => {
    expect(
      JSON.parse(
        serializeAccountWebAuthnAttestation(
          attestation({
            clientExtensionResults: {
              appidExclude: true,
              credProps: { rk: true },
              largeBlob: { supported: false },
              prf: { enabled: true },
              uvm: [[1, 2, 3]]
            }
          })
        )
      )
    ).toEqual({
      id: CREDENTIAL_ID,
      rawId: CREDENTIAL_ID,
      type: 'public-key',
      extensions: {
        appidExclude: true,
        credProps: { rk: true },
        largeBlob: { supported: false },
        prf: { enabled: true },
        uvm: [[1, 2, 3]]
      },
      response: {
        AttestationObject: ATTESTATION_OBJECT,
        clientDataJson: CLIENT_DATA
      }
    })
  })

  it('rejects mismatched IDs, padding, overflows, and unknown extension results', () => {
    expectInvalid(() =>
      serializeAccountWebAuthnAttestation(
        attestation({ rawId: Buffer.alloc(32, 0x35).toString('base64url') })
      )
    )
    expectInvalid(() =>
      serializeAccountWebAuthnAttestation(attestation({ id: `${CREDENTIAL_ID}=` }))
    )
    expectInvalid(() =>
      serializeAccountWebAuthnAttestation(
        attestation({
          response: {
            clientDataJSON: CLIENT_DATA,
            attestationObject: Buffer.alloc(1024 * 1_024 + 1).toString('base64url')
          }
        })
      )
    )
    expectInvalid(() =>
      serializeAccountWebAuthnAttestation(
        attestation({ clientExtensionResults: { arbitrary: true } })
      )
    )
  })

  it('rejects assertion-shaped responses, extra fields, sparse UVM, and accessors', () => {
    expectInvalid(() =>
      serializeAccountWebAuthnAttestation(
        attestation({
          response: {
            clientDataJSON: CLIENT_DATA,
            authenticatorData: Buffer.alloc(37).toString('base64url'),
            signature: Buffer.alloc(64).toString('base64url'),
            userHandle: null
          }
        })
      )
    )
    expectInvalid(() => serializeAccountWebAuthnAttestation({ ...attestation(), secret: true }))
    expectInvalid(() =>
      serializeAccountWebAuthnAttestation(
        attestation({ clientExtensionResults: { uvm: new Array(1) } })
      )
    )

    let getterCalls = 0
    const accessor = attestation()
    Object.defineProperty(accessor, 'rawId', {
      enumerable: true,
      get: () => {
        getterCalls += 1
        return CREDENTIAL_ID
      }
    })
    expectInvalid(() => serializeAccountWebAuthnAttestation(accessor))
    expect(getterCalls).toBe(0)
  })
})
