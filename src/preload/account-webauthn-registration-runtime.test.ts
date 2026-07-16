import { describe, expect, it, vi } from 'vitest'
import type {
  AccountWebAuthnAttestation,
  AccountWebAuthnRegistrationChallenge
} from '../main/account-webauthn-registration-codec'
import {
  ACCOUNT_WEBAUTHN_REGISTRATION_EVENT_CHANNEL,
  ACCOUNT_WEBAUTHN_REGISTRATION_INIT_CHANNEL
} from '../main/account-webauthn-registration-window-protocol'
import {
  credentialToAccountWebAuthnAttestation,
  registrationChallengeToPublicKeyOptions,
  startAccountWebAuthnRegistration
} from './account-webauthn-registration-runtime'

const CAPABILITY = 'A'.repeat(43)
const IDENTITY = { epoch: 7, capability: CAPABILITY }
const CONNECTOR_URL = 'https://vault.example.com/webauthn-connector.html'

function bytes(...values: number[]): ArrayBuffer {
  return Uint8Array.from(values).buffer
}

function base64Url(value: ArrayBuffer): string {
  return Buffer.from(value).toString('base64url')
}

function challenge(): AccountWebAuthnRegistrationChallenge {
  return {
    rp: { id: 'vault.example.com', name: 'Example Vault' },
    user: { id: base64Url(bytes(1, 2, 3)), name: 'person', displayName: 'Person' },
    challenge: base64Url(bytes(...Array.from({ length: 32 }, (_, index) => index))),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    timeout: 60_000,
    excludeCredentials: [
      { type: 'public-key', id: base64Url(bytes(4, 5, 6)), transports: ['internal'] }
    ],
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    attestation: 'none',
    extensions: {
      credProps: true,
      credBlob: base64Url(bytes(7, 8)),
      prf: { eval: { first: base64Url(bytes(9, 10)), second: base64Url(bytes(11, 12)) } }
    }
  }
}

function nativeCredential(): Credential {
  const rawId = bytes(21, 22, 23)
  return {
    id: base64Url(rawId),
    type: 'public-key',
    rawId,
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: bytes(31, 32),
      attestationObject: bytes(41, 42, 43)
    },
    getClientExtensionResults: () => ({
      credProps: { rk: true },
      prf: { enabled: true },
      ignoredFutureExtension: true
    })
  } as unknown as Credential
}

describe('account WebAuthn registration isolated runtime', () => {
  it('converts every binary creation input without exposing helpers to page JavaScript', () => {
    const source = challenge()
    const options = registrationChallengeToPublicKeyOptions(source)

    expect(base64Url(options.challenge as ArrayBuffer)).toBe(source.challenge)
    expect(base64Url(options.user.id as ArrayBuffer)).toBe(source.user.id)
    expect(base64Url(options.excludeCredentials![0]!.id as ArrayBuffer)).toBe(
      source.excludeCredentials[0]!.id
    )
    const extensions = options.extensions as Record<string, unknown>
    expect(base64Url(extensions.credBlob as ArrayBuffer)).toBe(source.extensions.credBlob)
    const evaluation = (extensions.prf as { eval: { first: ArrayBuffer; second: ArrayBuffer } })
      .eval
    expect(base64Url(evaluation.first)).toBe(source.extensions.prf!.eval!.first)
    expect(base64Url(evaluation.second)).toBe(source.extensions.prf!.eval!.second)
    expect(source.challenge).toEqual(challenge().challenge)
  })

  it('serializes only strict supported attestation fields', () => {
    const result = credentialToAccountWebAuthnAttestation(nativeCredential())

    expect(result).toEqual<AccountWebAuthnAttestation>({
      id: base64Url(bytes(21, 22, 23)),
      rawId: base64Url(bytes(21, 22, 23)),
      type: 'public-key',
      response: {
        clientDataJSON: base64Url(bytes(31, 32)),
        attestationObject: base64Url(bytes(41, 42, 43))
      },
      clientExtensionResults: { credProps: { rk: true }, prf: { enabled: true } },
      authenticatorAttachment: 'platform'
    })
  })

  it('autonomously invokes create and sends exactly one private terminal result', async () => {
    const create = vi.fn(async () => nativeCredential())
    const ipc = {
      invoke: vi.fn(async () => ({
        ...IDENTITY,
        connectorUrl: CONNECTOR_URL,
        challenge: challenge()
      })),
      send: vi.fn()
    }

    startAccountWebAuthnRegistration(
      ipc,
      { location: { href: CONNECTOR_URL }, navigator: { credentials: { create } as never } },
      IDENTITY
    )

    await vi.waitFor(() => expect(ipc.send).toHaveBeenCalledOnce())
    expect(ipc.invoke).toHaveBeenCalledWith(ACCOUNT_WEBAUTHN_REGISTRATION_INIT_CHANNEL, IDENTITY)
    expect(create).toHaveBeenCalledOnce()
    expect(ipc.send).toHaveBeenCalledWith(
      ACCOUNT_WEBAUTHN_REGISTRATION_EVENT_CHANNEL,
      expect.objectContaining({ ...IDENTITY, type: 'success' })
    )
  })

  it('fails closed before create when main does not bind the exact top-level URL', async () => {
    const create = vi.fn()
    const ipc = {
      invoke: vi.fn(async () => ({
        ...IDENTITY,
        connectorUrl: 'https://evil.example/webauthn-connector.html',
        challenge: challenge()
      })),
      send: vi.fn()
    }

    startAccountWebAuthnRegistration(
      ipc,
      { location: { href: CONNECTOR_URL }, navigator: { credentials: { create } as never } },
      IDENTITY
    )

    await vi.waitFor(() => expect(ipc.send).toHaveBeenCalledOnce())
    expect(create).not.toHaveBeenCalled()
    expect(ipc.send).toHaveBeenCalledWith(ACCOUNT_WEBAUTHN_REGISTRATION_EVENT_CHANNEL, {
      ...IDENTITY,
      type: 'failure',
      reason: 'unknown'
    })
  })
})
