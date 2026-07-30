import { afterEach, describe, expect, it, vi } from 'vitest'
import { BitwardenDirectClient } from './bitwarden-direct'
import { BitwardenHttpClient } from './bitwarden-http'

const EMAIL = 'webauthn-repro@example.test'
const PASSWORD = 'Repro-only-password-123!'
const CHALLENGE = Buffer.alloc(32, 1).toString('base64url')
const CREDENTIAL_ID = Buffer.alloc(32, 2).toString('base64url')

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' }
  })
}

function provider7(overrides: Record<string, unknown>): Record<string, unknown> {
  return {
    allowCredentials: [{ id: CREDENTIAL_ID, type: 'public-key' }],
    challenge: CHALLENGE,
    extensions: { appid: 'https://vault.example.test/app-id.json', getCredBlob: false },
    rpId: 'vault.example.test',
    timeout: 60_000,
    userVerification: 'discouraged',
    ...overrides
  }
}

describe('Bitwarden fresh-login compatibility', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('advertises explicit Email 2FA sending and recognizes a localized Email-only challenge', async () => {
    let tokenClientVersion: string | null = null
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        const url = input.toString()
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return response({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/identity/connect/token')) {
          tokenClientVersion = new Headers(init?.headers).get('bitwarden-client-version')
          return response(
            {
              error: 'invalid_grant',
              error_description: 'Se requiere autenticación en dos pasos.',
              TwoFactorProviders2: {
                '1': { Email: 'w***@example.test' }
              }
            },
            400
          )
        }
        return response({ message: 'not found' }, 404)
      })
    )
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.test',
      email: EMAIL
    })

    await expect(client.login({ email: EMAIL, password: PASSWORD })).rejects.toMatchObject({
      code: 'TWO_FACTOR_REQUIRED',
      twoFactorProviders: [1]
    })
    expect(tokenClientVersion).toBe('2025.5.0')
  })

  it.each([
    ['a legacy provider array', { TwoFactorProviders: ['1'], TwoFactorProviders2: null }, [1]],
    ['only a future provider', { TwoFactorProviders2: { '9': { future: true } } }, []]
  ])('preserves %s as a two-factor challenge', async (_label, providers, expected) => {
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.test',
      fetch: async (url) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return response({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/identity/connect/token')) {
          return response(
            {
              error: 'invalid_grant',
              error_description: 'Mehrstufige Anmeldung erforderlich.',
              ...providers
            },
            400
          )
        }
        return response({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.test',
      email: EMAIL,
      httpClient: http
    })

    await expect(client.login({ email: EMAIL, password: PASSWORD })).rejects.toMatchObject({
      code: 'TWO_FACTOR_REQUIRED',
      twoFactorProviders: expected
    })
  })

  it.each([
    ['localhost RP ID', { rpId: 'localhost', extensions: {} }],
    ['IP RP ID', { rpId: '127.0.0.1', extensions: {} }],
    ['single-label RP ID', { rpId: 'vault', extensions: {} }],
    ['unknown extension', { extensions: { credProps: true } }],
    ['padded challenge', { challenge: `${CHALLENGE}=` }],
    [
      'padded credential ID',
      {
        allowCredentials: [{ id: `${CREDENTIAL_ID}=`, type: 'public-key' }]
      }
    ]
  ])('keeps TOTP when provider 7 has %s', async (_label, overrides) => {
    const requested: string[] = []
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.test',
      fetch: async (url) => {
        requested.push(url)
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return response({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/identity/connect/token')) {
          return response(
            {
              error: 'invalid_grant',
              error_description: 'Two factor required.',
              TwoFactorProviders: ['0', '7', '9'],
              TwoFactorProviders2: {
                '0': null,
                '7': provider7(overrides),
                '9': { future: true }
              }
            },
            400
          )
        }
        if (url.endsWith('/api/sync')) {
          return response({ profile: {}, ciphers: [] })
        }
        return response({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.test',
      email: EMAIL,
      httpClient: http
    })

    await expect(client.login({ email: EMAIL, password: PASSWORD })).rejects.toMatchObject({
      code: 'TWO_FACTOR_REQUIRED',
      twoFactorProviders: [0],
      webAuthnChallenge: undefined
    })
    expect(requested.some((url) => url.endsWith('/api/sync'))).toBe(false)
  })

  it('rejects a malformed WebAuthn-only challenge before sync', async () => {
    const requested: string[] = []
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.test',
      fetch: async (url) => {
        requested.push(url)
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return response({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/identity/connect/token')) {
          return response(
            {
              error: 'invalid_grant',
              error_description: 'Two factor required.',
              TwoFactorProviders: ['7'],
              TwoFactorProviders2: {
                '7': provider7({ rpId: 'localhost', extensions: {} })
              }
            },
            400
          )
        }
        if (url.endsWith('/api/sync')) {
          return response({ profile: {}, ciphers: [] })
        }
        return response({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.test',
      email: EMAIL,
      httpClient: http
    })

    await expect(client.login({ email: EMAIL, password: PASSWORD })).rejects.toMatchObject({
      code: 'INVALID_RESPONSE',
      syncInvalidResponseStage: 'response',
      syncInvalidResponseReason: 'response-shape'
    })
    expect(requested.some((url) => url.endsWith('/api/sync'))).toBe(false)
  })
})
