import { describe, expect, it, vi } from 'vitest'
import { generateKeyPairSync } from 'node:crypto'
import {
  BitwardenHttpClient,
  BitwardenHttpError,
  resolveBitwardenUrls,
  type FetchLike,
  type JsonObject,
  type JsonValue
} from './bitwarden-http'

function json(body: unknown, status = 200, headers?: HeadersInit): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers }
  })
}

function deferred<T>(): {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (reason?: unknown) => void
} {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function cancelableResponse(
  status: number,
  headers?: HeadersInit,
  cancelResult?: Promise<void>
): { response: Response; cancel: ReturnType<typeof vi.fn> } {
  const cancel = vi.fn(() => cancelResult)
  const response = new Response(
    new ReadableStream<Uint8Array>({
      cancel
    }),
    { status, headers }
  )
  return { response, cancel }
}

function unsignedAccessToken(payload: Record<string, unknown>): string {
  return `${Buffer.from('{"alg":"none"}').toString('base64url')}.${Buffer.from(
    JSON.stringify(payload)
  ).toString('base64url')}.signature`
}

function accountProfile(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: '10000000-0000-4000-8000-000000000001',
    name: 'Test User',
    email: 'person@example.invalid',
    avatarColor: '#336699',
    emailVerified: false,
    twoFactorEnabled: true,
    object: 'profile',
    ...overrides
  }
}

function vaultwardenChallengeFixture(): Record<string, unknown> {
  return {
    allowCredentials: [{ id: Buffer.alloc(32, 2).toString('base64url'), type: 'public-key' }],
    challenge: Buffer.alloc(32, 1).toString('base64url'),
    extensions: { appid: 'https://vault.example.test/app-id.json', getCredBlob: false },
    rpId: 'vault.example.test',
    timeout: 60_000,
    userVerification: 'discouraged'
  }
}

const REGISTRATION_CREDENTIAL_ID = Buffer.alloc(32, 0x33).toString('base64url')
const REGISTRATION_CLIENT_DATA = Buffer.from('{"type":"webauthn.create"}').toString('base64url')
const REGISTRATION_ATTESTATION = Buffer.alloc(128, 0x34).toString('base64url')
const AUTH_REQUEST_ID = '90000000-0000-4000-8000-000000000001'

function authRequestPublicKey(modulusLength = 2_048): string {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength })
  return publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
}

function authRequest(
  publicKey: string,
  overrides: Record<string, unknown> = {}
): Record<string, unknown> {
  return {
    id: AUTH_REQUEST_ID,
    publicKey,
    requestDeviceType: 'Firefox',
    requestDeviceTypeValue: 3,
    requestDeviceIdentifier: 'must-not-cross-the-safe-model',
    requestIpAddress: '192.0.2.20',
    creationDate: '2026-07-20T03:50:00.000Z',
    requestApproved: false,
    responseDate: null,
    object: 'auth-request',
    ...overrides
  }
}

function registrationOptions(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    rp: { id: 'vault.example.test', name: 'Vault' },
    user: {
      id: Buffer.alloc(16, 0x32).toString('base64url'),
      name: 'person@example.test',
      displayName: 'Person'
    },
    challenge: Buffer.alloc(32, 0x31).toString('base64url'),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    timeout: 60_000,
    excludeCredentials: [],
    authenticatorSelection: { userVerification: 'discouraged' },
    attestation: 'none',
    extensions: {},
    ...overrides
  }
}

function registrationAttestation(): Parameters<
  BitwardenHttpClient['enableWebAuthn']
>[0]['attestation'] {
  return {
    id: REGISTRATION_CREDENTIAL_ID,
    rawId: REGISTRATION_CREDENTIAL_ID,
    type: 'public-key',
    response: {
      clientDataJSON: REGISTRATION_CLIENT_DATA,
      attestationObject: REGISTRATION_ATTESTATION
    },
    clientExtensionResults: {},
    authenticatorAttachment: 'cross-platform'
  }
}

describe('resolveBitwardenUrls', () => {
  it('maps the public Bitwarden cloud URLs to their split API and identity origins', () => {
    expect(resolveBitwardenUrls('https://bitwarden.com')).toEqual({
      apiUrl: 'https://api.bitwarden.com',
      identityUrl: 'https://identity.bitwarden.com',
      notificationsUrl: 'https://notifications.bitwarden.com',
      webVaultUrl: 'https://vault.bitwarden.com'
    })
  })

  it('uses Bitwarden cloud origins and preserves a self-hosted reverse-proxy prefix', () => {
    expect(resolveBitwardenUrls('us').apiUrl).toBe('https://api.bitwarden.com')
    expect(resolveBitwardenUrls('eu').identityUrl).toBe('https://identity.bitwarden.eu')
    expect(resolveBitwardenUrls('eu').notificationsUrl).toBe('https://notifications.bitwarden.eu')
    expect(resolveBitwardenUrls('https://vault.example.test/bw')).toEqual({
      apiUrl: 'https://vault.example.test/bw/api',
      identityUrl: 'https://vault.example.test/bw/identity',
      notificationsUrl: 'https://vault.example.test/bw/notifications',
      webVaultUrl: 'https://vault.example.test/bw'
    })
  })

  it('refuses insecure non-loopback origins', () => {
    expect(() => resolveBitwardenUrls('http://vault.example.test')).toThrow(BitwardenHttpError)
    expect(resolveBitwardenUrls('http://127.0.0.1:8080').apiUrl).toBe('http://127.0.0.1:8080/api')
  })
})

describe('BitwardenHttpClient', () => {
  it('selects flat password changes only from strict Vaultwarden config metadata', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json({ server: { name: 'Vaultwarden', url: 'https://example.test' } }))
      .mockResolvedValueOnce(
        json({ server: { name: 'Bitwarden', url: 'https://github.com/dani-garcia/vaultwarden/' } })
      )
      .mockResolvedValueOnce(
        json({
          server: { name: 'Bitwarden', url: 'https://github.com/dani-garcia/vaultwarden.evil' }
        })
      )
      .mockResolvedValueOnce(json({ server: { name: 42, url: ['malformed'] } }))
      .mockResolvedValueOnce(json({ message: 'unavailable' }, 503))
    const client = new BitwardenHttpClient({ server: 'us', fetch, maxRetries: 0 })

    await expect(client.passwordChangeContract()).resolves.toBe('vaultwarden')
    await expect(client.passwordChangeContract()).resolves.toBe('vaultwarden')
    await expect(client.passwordChangeContract()).resolves.toBe('official')
    await expect(client.passwordChangeContract()).resolves.toBe('official')
    await expect(client.passwordChangeContract()).resolves.toBe('official')
  })

  it('posts the exact official and Vaultwarden password-change contracts without retrying', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
      .mockResolvedValueOnce(json({ message: 'ambiguous failure' }, 503))
    const client = new BitwardenHttpClient({ server: 'us', fetch, maxRetries: 3 })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })
    await client.changeMasterPassword({
      contract: 'official',
      masterPasswordHash: 'current-proof',
      authenticationData: {
        salt: 'person@example.test',
        kdf: { kdfType: 0, iterations: 600000 },
        masterPasswordAuthenticationHash: 'new-proof'
      },
      unlockData: {
        salt: 'person@example.test',
        kdf: { kdfType: 0, iterations: 600000 },
        masterKeyWrappedUserKey: '2.wrapped'
      },
      masterPasswordHint: 'hint'
    })
    await expect(
      client.changeMasterPassword({
        contract: 'vaultwarden',
        masterPasswordHash: 'old',
        newMasterPasswordHash: 'new',
        key: '2.key',
        masterPasswordHint: null
      })
    ).rejects.toMatchObject({ code: 'NETWORK', status: 503 })
    expect(fetch).toHaveBeenCalledTimes(2)
    expect(JSON.parse(String(fetch.mock.calls[0]![1]?.body))).toEqual({
      masterPasswordHash: 'current-proof',
      authenticationData: {
        salt: 'person@example.test',
        kdf: { kdfType: 0, iterations: 600000 },
        masterPasswordAuthenticationHash: 'new-proof'
      },
      unlockData: {
        salt: 'person@example.test',
        kdf: { kdfType: 0, iterations: 600000 },
        masterKeyWrappedUserKey: '2.wrapped'
      },
      masterPasswordHint: 'hint'
    })
    expect(JSON.parse(String(fetch.mock.calls[1]![1]?.body))).toEqual({
      masterPasswordHash: 'old',
      newMasterPasswordHash: 'new',
      masterPasswordHint: null,
      key: '2.key'
    })
  })
  it('fetches the safe account profile and resends verification without a request body', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          id: '10000000-0000-4000-8000-000000000001',
          name: 'Test User',
          email: 'person@example.test',
          avatarColor: '#336699',
          emailVerified: false,
          twoFactorEnabled: true,
          privateKey: 'must-not-cross-the-safe-model'
        })
      )
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.getAccountSecurityProfile()).resolves.toEqual({
      id: '10000000-0000-4000-8000-000000000001',
      name: 'Test User',
      email: 'person@example.test',
      avatarColor: '#336699',
      emailVerified: false,
      twoFactorEnabled: true
    })
    await expect(client.resendVerificationEmail()).resolves.toBeUndefined()
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([
      'https://api.bitwarden.com/accounts/profile',
      'https://api.bitwarden.com/accounts/verify-email'
    ])
    expect(fetch.mock.calls[1]?.[1]).toMatchObject({ method: 'POST', body: undefined })
  })

  it('rejects malformed account security profiles and non-empty verification responses', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          id: 'not-an-id',
          name: 'Test User',
          email: 'person@example.test',
          avatarColor: null,
          emailVerified: false,
          twoFactorEnabled: false
        })
      )
      .mockResolvedValueOnce(json({ accepted: true }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.getAccountSecurityProfile()).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    await expect(client.resendVerificationEmail()).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
  })

  it('updates profile name and canonical avatar color with exact non-retried contracts', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json(accountProfile({ name: '', avatarColor: '#aabbcc' })))
      .mockResolvedValueOnce(json(accountProfile({ name: '', avatarColor: '#aabbcc' })))
    const client = new BitwardenHttpClient({ server: 'us', fetch, maxRetries: 3 })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.updateAccountProfileName('')).resolves.toMatchObject({
      name: '',
      avatarColor: '#AABBCC'
    })
    await expect(client.updateAccountAvatarColor('#aabbcc')).resolves.toMatchObject({
      avatarColor: '#AABBCC'
    })
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([
      'https://api.bitwarden.com/accounts/profile',
      'https://api.bitwarden.com/accounts/avatar'
    ])
    expect(JSON.parse(String(fetch.mock.calls[0]![1]?.body))).toEqual({ name: '' })
    expect(JSON.parse(String(fetch.mock.calls[1]![1]?.body))).toEqual({
      avatarColor: '#AABBCC'
    })
  })

  it('rejects missing avatar metadata, invalid profile inputs and ambiguous failures', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json(accountProfile({ avatarColor: undefined })))
      .mockResolvedValueOnce(json({ message: 'ambiguous' }, 503))
    const client = new BitwardenHttpClient({ server: 'us', fetch, maxRetries: 3 })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.getAccountSecurityProfile()).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    await expect(client.updateAccountAvatarColor('#123456')).rejects.toMatchObject({
      code: 'NETWORK'
    })
    await expect(client.updateAccountProfileName('你'.repeat(17))).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    await expect(client.updateAccountAvatarColor('#xyzxyz')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it('lists bounded account devices without exposing identifiers, keys, tokens, or IP data', async () => {
    const currentIdentifier = 'current-installation-id'
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      json({
        data: [
          {
            id: '10000000-0000-4000-8000-000000000010',
            name: 'BearWarden desktop',
            type: 7,
            identifier: currentIdentifier,
            creationDate: '2026-05-01T01:02:03Z',
            lastActivityDate: '2026-07-17T04:05:06.123Z',
            isTrusted: true,
            encryptedUserKey: 'must-not-cross-safe-model',
            encryptedPublicKey: 'must-not-cross-safe-model',
            ipAddress: '192.0.2.1',
            accessToken: 'must-not-cross-safe-model',
            object: 'device'
          },
          {
            id: '10000000-0000-4000-8000-000000000011',
            name: 'Firefox',
            type: 3,
            identifier: 'other-installation-id',
            creationDate: '2026-04-01T00:00:00.000Z',
            lastActivityDate: null,
            isTrusted: false,
            devicePendingAuthRequest: {
              id: '20000000-0000-4000-8000-000000000010',
              creationDate: '2026-07-17T04:00:00Z'
            },
            object: 'device'
          }
        ],
        object: 'list',
        continuationToken: null
      })
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    const devices = await client.getDevices(currentIdentifier)
    expect(devices).toEqual([
      {
        id: '10000000-0000-4000-8000-000000000010',
        name: 'BearWarden desktop',
        type: 7,
        createdAt: '2026-05-01T01:02:03.000Z',
        lastActivityAt: '2026-07-17T04:05:06.123Z',
        current: true,
        trusted: true,
        pendingAuthRequest: false
      },
      {
        id: '10000000-0000-4000-8000-000000000011',
        name: 'Firefox',
        type: 3,
        createdAt: '2026-04-01T00:00:00.000Z',
        lastActivityAt: null,
        current: false,
        trusted: false,
        pendingAuthRequest: true
      }
    ])
    expect(JSON.stringify(devices)).not.toContain(currentIdentifier)
    expect(JSON.stringify(devices)).not.toContain('192.0.2.1')
    expect(fetch).toHaveBeenCalledWith(
      'https://api.bitwarden.com/devices',
      expect.objectContaining({ method: 'GET' })
    )
  })

  it('strictly fetches one and lists pending actionable auth requests', async () => {
    const publicKey = authRequestPublicKey()
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json(authRequest(publicKey)))
      .mockResolvedValueOnce(
        json({ data: [authRequest(publicKey)], object: 'list', continuationToken: null })
      )
    const client = new BitwardenHttpClient({
      server: 'us',
      fetch,
      now: () => Date.parse('2026-07-20T04:00:00.000Z')
    })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    const expected = {
      id: AUTH_REQUEST_ID,
      publicKey,
      requestDeviceType: 'Firefox',
      creationDate: '2026-07-20T03:50:00.000Z'
    }
    await expect(client.getAuthRequest(AUTH_REQUEST_ID)).resolves.toEqual(expected)
    await expect(client.getPendingAuthRequests()).resolves.toEqual([expected])
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([
      `https://api.bitwarden.com/auth-requests/${AUTH_REQUEST_ID}`,
      'https://api.bitwarden.com/auth-requests/pending'
    ])
  })

  it.each([
    ['non-canonical Base64', (key: string) => authRequest(`${key}=`, {})],
    ['unsupported RSA size', () => authRequest(authRequestPublicKey(1_024))],
    [
      'expired request',
      (key: string) => authRequest(key, { creationDate: '2026-07-20T03:45:00.000Z' })
    ],
    [
      'answered request',
      (key: string) =>
        authRequest(key, {
          requestApproved: true,
          responseDate: '2026-07-20T03:55:00.000Z'
        })
    ]
  ])('rejects a %s', async (_label, fixture) => {
    const publicKey = authRequestPublicKey()
    const client = new BitwardenHttpClient({
      server: 'us',
      fetch: vi.fn<FetchLike>().mockResolvedValue(json(fixture(publicKey))),
      now: () => Date.parse('2026-07-20T04:00:00.000Z')
    })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })
    await expect(client.getAuthRequest(AUTH_REQUEST_ID)).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
  })

  it('puts the exact auth-request response body without retrying', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          id: AUTH_REQUEST_ID,
          requestApproved: null,
          responseDate: '2026-07-20T04:00:01.000Z'
        })
      )
      .mockResolvedValueOnce(json({ message: 'ambiguous' }, 503))
    const client = new BitwardenHttpClient({ server: 'us', fetch, maxRetries: 3 })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })
    const response = {
      key: `4.${Buffer.alloc(256, 0x33).toString('base64')}`,
      masterPasswordHash: null,
      deviceIdentifier: 'installation-id',
      requestApproved: false
    } as const

    await expect(client.respondAuthRequest(AUTH_REQUEST_ID, response)).resolves.toBeUndefined()
    await expect(client.respondAuthRequest(AUTH_REQUEST_ID, response)).rejects.toMatchObject({
      code: 'NETWORK',
      status: 503
    })
    expect(fetch).toHaveBeenCalledTimes(2)
    expect(JSON.parse(String(fetch.mock.calls[0]![1]?.body))).toEqual(response)
  })

  it('rejects malformed, duplicate, paginated, and excessive account-device responses', async () => {
    const valid = {
      id: '10000000-0000-4000-8000-000000000010',
      name: 'Desktop',
      type: 7,
      identifier: 'installation-id',
      creationDate: '2026-05-01T00:00:00Z',
      lastActivityDate: null,
      isTrusted: false,
      object: 'device'
    }
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json({ data: [valid, valid], object: 'list' }))
      .mockResolvedValueOnce(
        json({
          data: [valid, { ...valid, id: '10000000-0000-4000-8000-000000000011' }],
          object: 'list'
        })
      )
      .mockResolvedValueOnce(json({ data: [{ ...valid, type: 27 }], object: 'list' }))
      .mockResolvedValueOnce(
        json({ data: [{ ...valid, creationDate: 'not-a-date' }], object: 'list' })
      )
      .mockResolvedValueOnce(json({ data: [valid], object: 'list', continuationToken: 'next' }))
      .mockResolvedValueOnce(json({ data: Array(10_001).fill(valid), object: 'list' }))
      .mockResolvedValueOnce(json({ data: [{ ...valid, name: 'x'.repeat(257) }], object: 'list' }))
      .mockResolvedValueOnce(
        json({ data: [{ ...valid, identifier: 'unsafe\nidentifier' }], object: 'list' })
      )
      .mockResolvedValueOnce(json({ data: [{ ...valid, isTrusted: 'true' }], object: 'list' }))
      .mockResolvedValueOnce(
        json({ data: [{ ...valid, devicePendingAuthRequest: { id: 'invalid' } }], object: 'list' })
      )
      .mockResolvedValueOnce(json({ data: [{ ...valid, object: 'unexpected' }], object: 'list' }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    for (let index = 0; index < 11; index += 1) {
      await expect(client.getDevices('installation-id')).rejects.toMatchObject({
        code: 'INVALID_RESPONSE'
      })
    }
    await expect(client.getDevices('x'.repeat(257))).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    expect(fetch).toHaveBeenCalledTimes(11)
  })

  it('retrieves and rotates a personal API key with only the derived password proof', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          apiKey: 'existing-client-secret',
          revisionDate: '2026-07-16T00:00:00Z',
          object: 'apiKey'
        })
      )
      .mockResolvedValueOnce(
        json({
          apiKey: 'rotated-client-secret',
          revisionDate: '2026-07-16T00:01:00Z',
          object: 'apiKey'
        })
      )
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.getPersonalApiKey('derived-password-proof', false)).resolves.toMatchObject({
      apiKey: 'existing-client-secret'
    })
    await expect(client.getPersonalApiKey('derived-password-proof', true)).resolves.toMatchObject({
      apiKey: 'rotated-client-secret'
    })
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([
      'https://api.bitwarden.com/accounts/api-key',
      'https://api.bitwarden.com/accounts/rotate-api-key'
    ])
    for (const call of fetch.mock.calls) {
      expect(JSON.parse(String(call[1]?.body))).toEqual({
        masterPasswordHash: 'derived-password-proof'
      })
    }
  })

  it('rejects malformed personal API key responses', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      json({
        apiKey: 'secret\nheader-injection',
        revisionDate: 'not-a-date',
        object: 'apiKey'
      })
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })
    await expect(client.getPersonalApiKey('derived-password-proof', false)).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
  })

  it('keeps user verification failures distinct from new-device verification', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json({ message: 'User verification failed.' }, 400))
      .mockResolvedValueOnce(json({ message: 'Invalid password' }, 400))
      .mockResolvedValueOnce(json({ message: 'New device verification required.' }, 400))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.getPersonalApiKey('wrong-derived-proof', false)).rejects.toMatchObject({
      code: 'USER_VERIFICATION_FAILED'
    })
    await expect(client.getPersonalApiKey('wrong-derived-proof', false)).rejects.toMatchObject({
      code: 'USER_VERIFICATION_FAILED'
    })
    await expect(client.getPersonalApiKey('derived-proof', false)).rejects.toMatchObject({
      code: 'NEW_DEVICE'
    })
  })

  it('lists bounded 2FA providers and retrieves a recovery code with proof', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          data: [
            { type: 0, enabled: true, object: 'twoFactorProvider' },
            { type: 1, enabled: true, object: 'twoFactorProvider' }
          ],
          object: 'list',
          continuationToken: null
        })
      )
      .mockResolvedValueOnce(json({ code: 'RECOVERY-CODE', object: 'twoFactorRecover' }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.getTwoFactorProviders()).resolves.toEqual([
      { type: 0, enabled: true },
      { type: 1, enabled: true }
    ])
    await expect(client.getTwoFactorRecoveryCode('derived-proof')).resolves.toBe('RECOVERY-CODE')
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([
      'https://api.bitwarden.com/two-factor',
      'https://api.bitwarden.com/two-factor/get-recover'
    ])
    expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toEqual({
      masterPasswordHash: 'derived-proof'
    })
  })

  it('rejects duplicate providers and malformed recovery secrets', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          data: [
            { type: 0, enabled: true },
            { type: 0, enabled: true }
          ],
          object: 'list'
        })
      )
      .mockResolvedValueOnce(json({ code: 'secret\nleak', object: 'twoFactorRecover' }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })
    await expect(client.getTwoFactorProviders()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
    await expect(client.getTwoFactorRecoveryCode('derived-proof')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
  })

  it('disables official Authenticator and Email providers with provider-bound capabilities', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await client.disableTwoFactorProvider({
      type: 0,
      verificationMode: 'server-token',
      key: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
      userVerificationToken: 'authenticator-capability'
    })
    await client.disableTwoFactorProvider({
      type: 1,
      verificationMode: 'server-token',
      userVerificationToken: 'email-capability'
    })

    expect(fetch.mock.calls.map(([url, init]) => [url, init?.method])).toEqual([
      ['https://api.bitwarden.com/two-factor/authenticator', 'DELETE'],
      ['https://api.bitwarden.com/two-factor/email', 'DELETE']
    ])
    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toEqual({
      key: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
      userVerificationToken: 'authenticator-capability'
    })
    expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toEqual({
      userVerificationToken: 'email-capability'
    })
  })

  it('uses provider-bound official capabilities for Duo, YubiKey, and whole WebAuthn disable', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          duo: { enabled: true },
          userVerificationToken: 'duo-capability',
          object: 'twoFactorDuo'
        })
      )
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(
        json({
          yubiKey: { enabled: true },
          userVerificationToken: 'yubikey-capability',
          object: 'twoFactorYubiKey'
        })
      )
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.getTwoFactorDisableSetup(2, 'proof')).resolves.toMatchObject({
      enabled: true,
      verificationMode: 'server-token',
      userVerificationToken: 'duo-capability'
    })
    await client.disableTwoFactorProvider({
      type: 2,
      verificationMode: 'server-token',
      userVerificationToken: 'duo-capability'
    })
    await expect(client.getTwoFactorDisableSetup(3, 'proof')).resolves.toMatchObject({
      enabled: true,
      verificationMode: 'server-token',
      userVerificationToken: 'yubikey-capability'
    })
    await client.disableTwoFactorProvider({
      type: 3,
      verificationMode: 'server-token',
      userVerificationToken: 'yubikey-capability'
    })
    await client.disableTwoFactorProvider({
      type: 7,
      verificationMode: 'server-token',
      userVerificationToken: 'webauthn-capability'
    })

    expect(fetch.mock.calls.map(([url, init]) => [url, init?.method])).toEqual([
      ['https://api.bitwarden.com/two-factor/get-duo', 'POST'],
      ['https://api.bitwarden.com/two-factor/duo', 'DELETE'],
      ['https://api.bitwarden.com/two-factor/get-yubikey', 'POST'],
      ['https://api.bitwarden.com/two-factor/yubikey', 'DELETE'],
      ['https://api.bitwarden.com/two-factor/webauthn/all', 'DELETE']
    ])
  })

  it('disables Vaultwarden providers with a fresh master-password proof', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json({ enabled: false, type: 0, object: 'twoFactorProvider' }))
      .mockResolvedValueOnce(json({ enabled: false, type: 1, object: 'twoFactorProvider' }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await client.disableTwoFactorProvider({
      type: 0,
      verificationMode: 'master-password',
      masterPasswordHash: 'fresh-derived-proof'
    })
    await client.disableTwoFactorProvider({
      type: 1,
      verificationMode: 'master-password',
      masterPasswordHash: 'fresh-derived-proof'
    })
    expect(fetch).toHaveBeenCalledTimes(2)
    for (const [index, call] of fetch.mock.calls.entries()) {
      expect(call[0]).toBe('https://api.bitwarden.com/two-factor/disable')
      expect(call[1]?.method).toBe('POST')
      expect(JSON.parse(String(call[1]?.body))).toEqual({
        type: index,
        masterPasswordHash: 'fresh-derived-proof'
      })
    }
  })

  it('never replays disable mutations and rejects unsupported types or malformed responses', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json({ message: 'expired session' }, 401))
      .mockResolvedValueOnce(json({ enabled: true, type: 1, object: 'twoFactorProvider' }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(
      client.disableTwoFactorProvider({
        type: 1,
        verificationMode: 'server-token',
        userVerificationToken: 'email-capability'
      })
    ).rejects.toMatchObject({ code: 'AUTH' })
    expect(fetch).toHaveBeenCalledTimes(1)

    await expect(
      client.disableTwoFactorProvider({
        type: 1,
        verificationMode: 'master-password',
        masterPasswordHash: 'fresh-derived-proof'
      })
    ).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })

    const unsupported = {
      type: 6,
      verificationMode: 'master-password',
      masterPasswordHash: 'fresh-derived-proof'
    } as unknown as Parameters<BitwardenHttpClient['disableTwoFactorProvider']>[0]
    await expect(client.disableTwoFactorProvider(unsupported)).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it('branches official and Vaultwarden authenticator setup capabilities', async () => {
    const key = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          authenticator: { enabled: false, key },
          userVerificationToken: 'official-bound-capability',
          object: 'twoFactorAuthenticator'
        })
      )
      .mockResolvedValueOnce(
        json({
          authenticator: { enabled: true, key },
          object: 'twoFactorAuthenticatorUpdate'
        })
      )
      .mockResolvedValueOnce(json({ enabled: false, key, object: 'twoFactorAuthenticator' }))
      .mockResolvedValueOnce(json({ enabled: true, key, object: 'twoFactorAuthenticator' }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.getAuthenticatorSetup('derived-proof')).resolves.toEqual({
      enabled: false,
      key,
      verificationMode: 'server-token',
      userVerificationToken: 'official-bound-capability'
    })
    await client.enableAuthenticator({
      key,
      token: '123456',
      verificationMode: 'server-token',
      userVerificationToken: 'official-bound-capability'
    })
    await expect(client.getAuthenticatorSetup('derived-proof')).resolves.toEqual({
      enabled: false,
      key,
      verificationMode: 'master-password',
      userVerificationToken: null
    })
    await client.enableAuthenticator({
      key,
      token: '654321',
      verificationMode: 'master-password',
      masterPasswordHash: 'derived-proof'
    })

    expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toEqual({
      key,
      token: '123456',
      userVerificationToken: 'official-bound-capability'
    })
    expect(JSON.parse(String(fetch.mock.calls[3]?.[1]?.body))).toEqual({
      key,
      token: '654321',
      masterPasswordHash: 'derived-proof'
    })
  })

  it('never retries a one-time authenticator mutation', async () => {
    const key = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
    const fetch = vi.fn<FetchLike>().mockResolvedValue(json({ message: 'temporary failure' }, 503))
    const client = new BitwardenHttpClient({ server: 'us', fetch, maxRetries: 5 })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(
      client.enableAuthenticator({
        key,
        token: '123456',
        verificationMode: 'server-token',
        userVerificationToken: 'one-time-capability'
      })
    ).rejects.toMatchObject({ code: 'NETWORK', status: 503 })
    expect(fetch).toHaveBeenCalledOnce()
  })

  it('branches official and Vaultwarden Email 2FA setup capabilities', async () => {
    const email = 'factor@example.test'
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          email: { enabled: false, email: null },
          userVerificationToken: 'official-email-capability',
          object: 'twoFactorEmail'
        })
      )
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(
        json({
          email: { enabled: true, email },
          object: 'twoFactorEmailUpdate'
        })
      )
      .mockResolvedValueOnce(json({ enabled: false, email: null, object: 'twoFactorEmail' }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(json({ enabled: 'true', email, object: 'twoFactorEmail' }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.getEmailTwoFactorSetup('derived-proof')).resolves.toEqual({
      enabled: false,
      email: null,
      verificationMode: 'server-token',
      userVerificationToken: 'official-email-capability'
    })
    await client.sendEmailTwoFactorSetup({
      email,
      verificationMode: 'server-token',
      userVerificationToken: 'official-email-capability'
    })
    await client.enableEmailTwoFactor({
      email,
      token: '123456',
      verificationMode: 'server-token',
      userVerificationToken: 'official-email-capability'
    })
    await expect(client.getEmailTwoFactorSetup('fresh-proof')).resolves.toEqual({
      enabled: false,
      email: null,
      verificationMode: 'master-password',
      userVerificationToken: null
    })
    await client.sendEmailTwoFactorSetup({
      email,
      verificationMode: 'master-password',
      masterPasswordHash: 'fresh-send-proof'
    })
    await client.enableEmailTwoFactor({
      email,
      token: '654321',
      verificationMode: 'master-password',
      masterPasswordHash: 'fresh-enable-proof'
    })

    expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toEqual({
      email,
      userVerificationToken: 'official-email-capability'
    })
    expect(JSON.parse(String(fetch.mock.calls[2]?.[1]?.body))).toEqual({
      email,
      token: '123456',
      userVerificationToken: 'official-email-capability'
    })
    expect(JSON.parse(String(fetch.mock.calls[4]?.[1]?.body))).toEqual({
      email,
      masterPasswordHash: 'fresh-send-proof'
    })
    expect(JSON.parse(String(fetch.mock.calls[5]?.[1]?.body))).toEqual({
      email,
      token: '654321',
      masterPasswordHash: 'fresh-enable-proof'
    })
  })

  it('never retries Email 2FA setup mutations', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json({ message: 'temporary failure' }, 503))
      .mockResolvedValueOnce(json({ message: 'temporary failure' }, 503))
      .mockResolvedValueOnce(json({ message: 'expired capability' }, 401))
    const client = new BitwardenHttpClient({ server: 'us', fetch, maxRetries: 5 })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(
      client.sendEmailTwoFactorSetup({
        email: 'factor@example.test',
        verificationMode: 'server-token',
        userVerificationToken: 'one-time-capability'
      })
    ).rejects.toMatchObject({ code: 'NETWORK', status: 503 })
    await expect(
      client.enableEmailTwoFactor({
        email: 'factor@example.test',
        token: '123456',
        verificationMode: 'server-token',
        userVerificationToken: 'one-time-capability'
      })
    ).rejects.toMatchObject({ code: 'NETWORK', status: 503 })
    await expect(
      client.sendEmailTwoFactorSetup({
        email: 'factor@example.test',
        verificationMode: 'server-token',
        userVerificationToken: 'expired-capability'
      })
    ).rejects.toMatchObject({ code: 'AUTH', status: 401 })
    expect(fetch).toHaveBeenCalledTimes(3)
  })

  it('uses official WebAuthn capabilities and exact canonical mutation bodies', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          WebAuthn: {
            Enabled: false,
            Keys: [{ Id: 2, Name: 'Existing key', Migrated: false }]
          },
          UserVerificationToken: 'official-webauthn-capability'
        })
      )
      .mockResolvedValueOnce(
        json({ Options: registrationOptions(), Object: 'twoFactorWebAuthnChallenge' })
      )
      .mockResolvedValueOnce(
        json({
          webAuthn: {
            enabled: true,
            keys: [
              { id: 2, name: 'Existing key', migrated: false },
              { id: 1, name: 'New security key', migrated: false }
            ]
          }
        })
      )
      .mockResolvedValueOnce(
        json({
          webAuthn: { enabled: true, keys: [{ id: 2, name: 'Existing key', migrated: false }] }
        })
      )
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.getWebAuthnSetup('fresh-proof')).resolves.toEqual({
      enabled: false,
      keys: [{ id: 2, name: 'Existing key', migrated: false }],
      verificationMode: 'server-token',
      userVerificationToken: 'official-webauthn-capability'
    })
    await client.getWebAuthnRegistrationChallenge({
      verificationMode: 'server-token',
      userVerificationToken: 'official-webauthn-capability'
    })
    await client.enableWebAuthn({
      id: 1,
      name: 'New security key',
      attestation: registrationAttestation(),
      verificationMode: 'server-token',
      userVerificationToken: 'official-webauthn-capability'
    })
    await client.deleteWebAuthnKey({
      id: 1,
      verificationMode: 'server-token',
      userVerificationToken: 'official-webauthn-capability'
    })

    expect(fetch.mock.calls.map(([url, init]) => [url, init?.method])).toEqual([
      ['https://api.bitwarden.com/two-factor/get-webauthn', 'POST'],
      ['https://api.bitwarden.com/two-factor/get-webauthn-challenge', 'POST'],
      ['https://api.bitwarden.com/two-factor/webauthn', 'PUT'],
      ['https://api.bitwarden.com/two-factor/webauthn', 'DELETE']
    ])
    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toEqual({
      masterPasswordHash: 'fresh-proof'
    })
    expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toEqual({
      userVerificationToken: 'official-webauthn-capability'
    })
    expect(JSON.parse(String(fetch.mock.calls[2]?.[1]?.body))).toEqual({
      id: 1,
      name: 'New security key',
      userVerificationToken: 'official-webauthn-capability',
      deviceResponse: {
        id: REGISTRATION_CREDENTIAL_ID,
        rawId: REGISTRATION_CREDENTIAL_ID,
        type: 'public-key',
        extensions: {},
        response: {
          AttestationObject: REGISTRATION_ATTESTATION,
          clientDataJson: REGISTRATION_CLIENT_DATA
        }
      }
    })
    expect(JSON.parse(String(fetch.mock.calls[3]?.[1]?.body))).toEqual({
      id: 1,
      userVerificationToken: 'official-webauthn-capability'
    })
  })

  it('uses the flat Vaultwarden WebAuthn dialect with master-password proof', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json({ enabled: false, keys: [], object: 'twoFactorWebAuthn' }))
      .mockResolvedValueOnce(json({ ...registrationOptions(), status: 'ok', errorMessage: '' }))
      .mockResolvedValueOnce(
        json({
          enabled: true,
          keys: [{ id: 1, name: 'Vaultwarden key', migrated: false }],
          object: 'twoFactorU2f'
        })
      )
      .mockResolvedValueOnce(json({ enabled: true, keys: [], object: 'twoFactorU2f' }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.getWebAuthnSetup('fresh-vw-proof')).resolves.toMatchObject({
      verificationMode: 'master-password',
      userVerificationToken: null
    })
    await client.getWebAuthnRegistrationChallenge({
      verificationMode: 'master-password',
      masterPasswordHash: 'fresh-vw-proof'
    })
    await client.enableWebAuthn({
      id: 1,
      name: 'Vaultwarden key',
      attestation: registrationAttestation(),
      verificationMode: 'master-password',
      masterPasswordHash: 'fresh-vw-proof'
    })
    await client.deleteWebAuthnKey({
      id: 1,
      verificationMode: 'master-password',
      masterPasswordHash: 'fresh-vw-proof'
    })

    expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toEqual({
      masterPasswordHash: 'fresh-vw-proof'
    })
    expect(JSON.parse(String(fetch.mock.calls[2]?.[1]?.body))).toMatchObject({
      id: 1,
      name: 'Vaultwarden key',
      masterPasswordHash: 'fresh-vw-proof'
    })
    expect(JSON.parse(String(fetch.mock.calls[3]?.[1]?.body))).toEqual({
      id: 1,
      masterPasswordHash: 'fresh-vw-proof'
    })
  })

  it('rejects malformed WebAuthn metadata/challenges and never replays mutations', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          enabled: true,
          keys: [{ id: REGISTRATION_CREDENTIAL_ID, name: 'wrong', migrated: false }]
        })
      )
      .mockResolvedValueOnce(json({ ...registrationOptions(), status: 'failed', errorMessage: '' }))
      .mockResolvedValueOnce(json({ message: 'ambiguous failure' }, 503))
      .mockResolvedValueOnce(json({ message: 'ambiguous failure' }, 503))
    const client = new BitwardenHttpClient({ server: 'us', fetch, maxRetries: 5 })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.getWebAuthnSetup('proof')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    await expect(
      client.getWebAuthnRegistrationChallenge({
        verificationMode: 'master-password',
        masterPasswordHash: 'proof'
      })
    ).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
    await expect(
      client.enableWebAuthn({
        id: 1,
        name: 'Key',
        attestation: registrationAttestation(),
        verificationMode: 'master-password',
        masterPasswordHash: 'proof'
      })
    ).rejects.toMatchObject({ code: 'NETWORK', status: 503 })
    await expect(
      client.deleteWebAuthnKey({
        id: 1,
        verificationMode: 'master-password',
        masterPasswordHash: 'proof'
      })
    ).rejects.toMatchObject({ code: 'NETWORK', status: 503 })
    expect(fetch).toHaveBeenCalledTimes(4)
  })

  it('parses both current nested and legacy prelogin KDF payloads', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({ kdf: { type: 1, iterations: 600000, memory: 64, parallelism: 4 } })
      )
      .mockResolvedValueOnce(json({ Kdf: 0, KdfIterations: 100000 }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    await expect(client.prelogin('person@example.test')).resolves.toMatchObject({
      kdfType: 1,
      iterations: 600000
    })
    await expect(client.prelogin('person@example.test')).resolves.toMatchObject({
      kdfType: 0,
      iterations: 100000
    })
    expect(fetch.mock.calls[0]?.[0]).toBe(
      'https://identity.bitwarden.com/accounts/prelogin/password'
    )
  })

  it('parses the official PascalCase nested prelogin aliases', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      json({
        KdfSettings: {
          KdfType: 1,
          Iterations: 3,
          Memory: 64,
          Parallelism: 4
        },
        Salt: 'account-salt'
      })
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch })

    await expect(client.prelogin('person@example.test')).resolves.toMatchObject({
      kdfType: 1,
      iterations: 3,
      memory: 64,
      parallelism: 4,
      salt: 'account-salt'
    })
  })

  it('parses the current Vaultwarden dual flat and nested prelogin payload', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      json({
        kdf: 1,
        kdfIterations: 3,
        kdfMemory: 64,
        kdfParallelism: 4,
        kdfSettings: { kdfType: 1, iterations: 3, memory: 64, parallelism: 4 },
        salt: null
      })
    )
    const client = new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch })

    await expect(client.prelogin('person@example.test')).resolves.toMatchObject({
      kdfType: 1,
      iterations: 3,
      memory: 64,
      parallelism: 4,
      salt: null
    })
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it.each([
    {
      kdf: 0,
      kdfIterations: 600_000,
      kdfSettings: { kdfType: 1, iterations: 3, memory: 64, parallelism: 4 }
    },
    {
      kdfSettings: { kdfType: 0, iterations: 600_000 },
      kdf: { type: 1, iterations: 3, memory: 64, parallelism: 4 }
    },
    { kdf: 0, kdfIterations: 600_000, kdfMemory: 'unexpected' }
  ])('rejects conflicting or malformed prelogin KDF fields', async (response) => {
    const client = new BitwardenHttpClient({
      server: 'us',
      fetch: vi.fn<FetchLike>().mockResolvedValue(json(response))
    })

    await expect(client.prelogin('person@example.test')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE',
      invalidResponseReason: 'kdf-settings'
    })
  })

  it('falls back to legacy prelogin after a self-hosted proxy returns a 200 error envelope', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json({ message: 'route not found' }))
      .mockResolvedValueOnce(json({ kdf: 0, kdfIterations: 100000 }))
    const client = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch
    })

    await expect(client.prelogin('person@example.test')).resolves.toMatchObject({
      kdfType: 0,
      iterations: 100000
    })
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([
      'https://vault.example.invalid/identity/accounts/prelogin/password',
      'https://vault.example.invalid/identity/accounts/prelogin'
    ])
  })

  it('falls back to legacy prelogin after a self-hosted proxy returns HTML for the modern route', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(new Response('<html>route not found</html>', { status: 200 }))
      .mockResolvedValueOnce(json({ kdf: 0, kdfIterations: 100000 }))
    const client = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch
    })

    await expect(client.prelogin('person@example.test')).resolves.toMatchObject({
      kdfType: 0,
      iterations: 100000
    })
  })

  it.each([
    ['empty response', new Response(null, { status: 200 }), 'empty-response'],
    ['non-object response', json([]), 'non-object-response']
  ] as const)(
    'preserves the modern %s diagnosis when the self-hosted legacy route is absent',
    async (_, modernResponse, reason) => {
      const fetch = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(modernResponse)
        .mockResolvedValueOnce(json({ message: 'not found' }, 404))
      const client = new BitwardenHttpClient({
        server: 'https://vault.example.invalid',
        fetch
      })

      await expect(client.prelogin('person@example.test')).rejects.toMatchObject({
        code: 'INVALID_RESPONSE',
        invalidResponseReason: reason
      })
    }
  )

  it('does not fall back when the modern route contains conflicting KDF settings', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      json({
        kdf: 0,
        kdfIterations: 600_000,
        kdfSettings: { kdfType: 0, iterations: 5_000 }
      })
    )
    const client = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch
    })

    await expect(client.prelogin('person@example.test')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE',
      invalidResponseReason: 'kdf-settings'
    })
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it.each([404, 405])(
    'falls back to the legacy Vaultwarden prelogin route after %s',
    async (status) => {
      const fetch = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(json({ message: 'unsupported route' }, status))
        .mockResolvedValueOnce(json({ Kdf: 0, KdfIterations: 100000 }))
      const client = new BitwardenHttpClient({
        server: 'https://vault.example.invalid',
        fetch
      })

      await expect(client.prelogin('person@example.test')).resolves.toMatchObject({
        kdfType: 0,
        iterations: 100000
      })
      expect(fetch.mock.calls.map(([url]) => url)).toEqual([
        'https://vault.example.invalid/identity/accounts/prelogin/password',
        'https://vault.example.invalid/identity/accounts/prelogin'
      ])
    }
  )

  it('sends OAuth form tokens with 2FA and parses the rotated session', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValue(
        json({ access_token: 'access', refresh_token: 'refresh', expires_in: 3600 })
      )
    const client = new BitwardenHttpClient({ server: 'eu', fetch, now: () => 1000 })
    await expect(
      client.passwordToken({
        email: 'person@example.test',
        password: 'derived-secret',
        twoFactorProvider: 0,
        twoFactorToken: '123456',
        twoFactorRemember: true,
        newDeviceOtp: '654321'
      })
    ).resolves.toEqual({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 3_601_000 })
    const init = fetch.mock.calls[0]?.[1]
    expect(init?.body).toContain('twoFactorProvider=0')
    expect(init?.body).toContain('twoFactorToken=123456')
    expect(init?.body).toContain('twoFactorRemember=1')
    expect(init?.body).toContain('newDeviceOtp=654321')
    const requestHeaders = new Headers(init?.headers)
    expect(requestHeaders.get('bitwarden-client-name')).toBe('desktop')
    expect(requestHeaders.get('bitwarden-client-version')).toBe('1.0.0')
  })

  it.each([
    ['zero duration', { expires_in: 0 }],
    ['fractional duration', { expires_in: 1.5 }],
    ['overflowing duration', { expires_in: Number.MAX_SAFE_INTEGER }],
    ['fractional epoch', { expiresAt: 1.5 }],
    ['unsafe epoch', { expiresAt: Number.MAX_SAFE_INTEGER + 1 }],
    ['non-positive date epoch', { expiresAt: '1969-12-31T23:59:59.999Z' }]
  ])('rejects a session with %s', async (_label, expiry) => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValue(json({ access_token: 'access', refresh_token: 'refresh', ...expiry }))
    const client = new BitwardenHttpClient({ server: 'us', fetch, now: () => 1 })

    await expect(
      client.passwordToken({ email: 'person@example.test', password: 'derived-secret' })
    ).rejects.toMatchObject({
      code: 'INVALID_RESPONSE',
      invalidResponseReason: 'session-response'
    })
  })

  it.each([
    ['a non-bearer access token', { access_token: 'access token' }],
    ['an invalid refresh token', { refresh_token: 'refresh\nsecret' }],
    ['an invalid remembered 2FA token', { TwoFactorToken: 'remembered\u0000secret' }],
    ['an invalid OAuth client id', { client_id: 'not an oauth client id' }]
  ])('classifies a session with %s as a session response', async (_label, override) => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      json({
        access_token: 'access',
        refresh_token: 'refresh',
        expires_in: 3_600,
        ...override
      })
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch, now: () => 1 })

    await expect(
      client.passwordToken({ email: 'person@example.test', password: 'derived-secret' })
    ).rejects.toMatchObject({
      code: 'INVALID_RESPONSE',
      invalidResponseReason: 'session-response'
    })
  })

  it('accepts only positive safe integer epochs when restoring a session', () => {
    const client = new BitwardenHttpClient({
      server: 'us',
      fetch: vi.fn<FetchLike>()
    })
    const original = { accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 }
    client.setSession(original)

    for (const expiresAt of [0, -1, 1.5, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => client.setSession({ ...original, expiresAt })).toThrowError(
        expect.objectContaining({ code: 'INVALID_RESPONSE' })
      )
      expect(client.exportSession()).toEqual(original)
    }

    for (const accessToken of [' access', 'access ', 'access\u2028token', 'access\u0085token']) {
      expect(() => client.setSession({ ...original, accessToken })).toThrowError(
        expect.objectContaining({ code: 'INVALID_RESPONSE' })
      )
      expect(client.exportSession()).toEqual(original)
    }
  })

  it('keeps a bounded remembered 2FA token in the main-process session contract', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      json({
        access_token: 'access',
        refresh_token: 'refresh',
        expires_in: 3600,
        TwoFactorToken: 'remembered-device-token'
      })
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch, now: () => 0 })

    const session = await client.passwordToken({
      email: 'person@example.test',
      password: 'derived-secret',
      twoFactorProvider: 5,
      twoFactorToken: 'previous-remembered-token',
      twoFactorRemember: false
    })

    expect(session).toEqual({
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 3_600_000,
      twoFactorToken: 'remembered-device-token'
    })
    expect(fetch.mock.calls[0]?.[1]?.body).toContain('twoFactorProvider=5')
    expect(fetch.mock.calls[0]?.[1]?.body).toContain('twoFactorToken=previous-remembered-token')
    expect(fetch.mock.calls[0]?.[1]?.body).toContain('twoFactorRemember=0')
  })

  it('rejects malformed remembered 2FA tokens instead of persisting them', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      json({
        access_token: 'access',
        refresh_token: 'refresh',
        expires_in: 3600,
        TwoFactorToken: 'unsafe\ntoken'
      })
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    await expect(
      client.passwordToken({ email: 'person@example.test', password: 'derived-secret' })
    ).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
  })

  it('resends new-device OTP without authentication or retained credential metadata', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(json({ object: 'newDeviceOtpSent' }))
    const client = new BitwardenHttpClient({ server: 'https://vault.example.test', fetch })
    client.setSession({ accessToken: 'must-not-be-sent', refreshToken: 'refresh', expiresAt: 1 })

    await client.resendNewDeviceOtp({
      email: 'person@example.test',
      masterPasswordHash: 'derived-password-proof'
    })

    expect(fetch.mock.calls[0]?.[0]).toBe(
      'https://vault.example.test/api/accounts/resend-new-device-otp'
    )
    const init = fetch.mock.calls[0]?.[1]
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({
      email: 'person@example.test',
      masterPasswordHash: 'derived-password-proof'
    })
    const requestHeaders = new Headers(init?.headers)
    expect(requestHeaders.get('authorization')).toBeNull()
    expect(requestHeaders.get('auth-email')).toBe(
      Buffer.from('person@example.test').toString('base64url')
    )
  })

  it('does not retry or retain reflected new-device OTP proof errors', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValue(
        json({ message: 'failure', masterPasswordHash: 'derived-password-proof' }, 503)
      )
    const client = new BitwardenHttpClient({ server: 'us', fetch, maxRetries: 5 })
    const error = await client
      .resendNewDeviceOtp({
        email: 'person@example.test',
        masterPasswordHash: 'derived-password-proof'
      })
      .catch((caught: unknown) => caught)
    expect(error).toMatchObject({ code: 'NETWORK', status: 503, details: undefined })
    expect(JSON.stringify(error)).not.toContain('derived-password-proof')
    expect(fetch).toHaveBeenCalledOnce()
  })

  it('sends the exact unauthenticated Email 2FA login request with device headers', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(new Response(null, { status: 204 }))
    const client = new BitwardenHttpClient({ server: 'https://vault.example.test', fetch })
    client.setSession({
      accessToken: 'must-not-be-sent',
      refreshToken: 'refresh',
      expiresAt: 60_000
    })

    await client.sendEmailTwoFactorLoginCode({
      email: 'person@example.test',
      masterPasswordHash: 'derived-password-proof',
      deviceIdentifier: 'installation-id',
      deviceType: 99
    })

    expect(fetch).toHaveBeenCalledOnce()
    expect(fetch.mock.calls[0]?.[0]).toBe(
      'https://vault.example.test/api/two-factor/send-email-login'
    )
    const init = fetch.mock.calls[0]?.[1]
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({
      email: 'person@example.test',
      masterPasswordHash: 'derived-password-proof',
      deviceIdentifier: 'installation-id'
    })
    const requestHeaders = new Headers(init?.headers)
    expect(requestHeaders.get('authorization')).toBeNull()
    expect(requestHeaders.get('auth-email')).toBe(
      Buffer.from('person@example.test').toString('base64url')
    )
    expect(requestHeaders.get('device-type')).toBe('99')
    expect(requestHeaders.get('bitwarden-client-name')).toBe('desktop')
  })

  it('does not retry or retain reflected Email 2FA login secrets', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      json(
        {
          message: 'temporary failure',
          masterPasswordHash: 'derived-password-proof',
          deviceIdentifier: 'installation-id'
        },
        503
      )
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch, maxRetries: 5 })

    const error = await client
      .sendEmailTwoFactorLoginCode({
        email: 'person@example.test',
        masterPasswordHash: 'derived-password-proof',
        deviceIdentifier: 'installation-id'
      })
      .catch((caught: unknown) => caught)
    expect(error).toMatchObject({ code: 'NETWORK', status: 503, details: undefined })
    expect(JSON.stringify(error)).not.toContain('derived-password-proof')
    expect(JSON.stringify(error)).not.toContain('installation-id')
    expect(fetch).toHaveBeenCalledOnce()
  })

  it('clears the mutable Email 2FA login body after transport completion', async () => {
    const client = new BitwardenHttpClient({ server: 'us', fetch: vi.fn<FetchLike>() })
    let capturedBody: JsonObject | undefined
    const transport = client as unknown as {
      requestJson: (
        method: string,
        url: string,
        request: { body?: JsonObject }
      ) => Promise<JsonValue>
    }
    transport.requestJson = async (_method, _url, request) => {
      capturedBody = request.body
      return null
    }

    await client.sendEmailTwoFactorLoginCode({
      email: 'person@example.test',
      masterPasswordHash: 'derived-password-proof',
      deviceIdentifier: 'installation-id'
    })

    expect(capturedBody).toEqual({
      email: '',
      masterPasswordHash: '',
      deviceIdentifier: ''
    })
  })

  it.each([
    {
      label: 'Vaultwarden camelCase',
      providersKey: 'TwoFactorProviders2',
      provider: {
        allowCredentials: [{ id: Buffer.alloc(32, 2).toString('base64url'), type: 'public-key' }],
        challenge: Buffer.alloc(32, 1).toString('base64url'),
        extensions: {
          appid: 'https://vault.example.test/app-id.json',
          getCredBlob: false
        },
        rpId: 'vault.example.test',
        timeout: 60_000,
        userVerification: 'discouraged'
      }
    },
    {
      label: 'official PascalCase',
      providersKey: 'twoFactorProviders2',
      provider: {
        AllowCredentials: [{ Id: Buffer.alloc(32, 2).toString('base64url'), Type: 'public-key' }],
        Challenge: Buffer.alloc(32, 1).toString('base64url'),
        Extensions: { AppId: 'https://vault.example.test/app-id.json', Uvm: true },
        RpId: 'vault.example.test',
        Timeout: 60_000,
        UserVerification: 'preferred'
      }
    }
  ])(
    'preserves a strict provider-7 challenge from $label without raw error metadata',
    async ({ providersKey, provider }) => {
      const fetch = vi.fn<FetchLike>().mockResolvedValue(
        json(
          {
            error: 'invalid_grant',
            error_description: 'Two factor required.',
            [providersKey]: { '0': null, '1': null, '3': { Nfc: true }, '7': provider },
            serverSecret: 'must-not-escape'
          },
          400
        )
      )
      const client = new BitwardenHttpClient({ server: 'https://vault.example.test', fetch })

      const error = await client
        .passwordToken({ email: 'person@example.test', password: 'derived-secret' })
        .catch((caught: unknown) => caught)
      expect(error).toBeInstanceOf(BitwardenHttpError)
      expect(error).toMatchObject({
        code: 'TWO_FACTOR',
        status: 400,
        details: undefined,
        twoFactorProviders: [0, 1, 3, 7],
        webAuthnChallenge: {
          challenge: Buffer.alloc(32, 1).toString('base64url'),
          rpId: 'vault.example.test',
          allowCredentials: [{ id: Buffer.alloc(32, 2).toString('base64url') }]
        }
      })
      expect(JSON.stringify(error)).not.toContain('must-not-escape')
      expect(fetch).toHaveBeenCalledOnce()
    }
  )

  it('normalizes legacy provider arrays and provider-map keys without retaining raw metadata', async () => {
    const legacyPayload = {
      error: 'invalid_grant',
      error_description: 'Two factor required.',
      TwoFactorProviders: ['3', 1, '0', 8, 8],
      TwoFactorProviders2: { '0': null, '1': null, '3': { Nfc: true } },
      rawServerSecret: 'must-not-escape'
    }
    const legacyFetch = vi.fn<FetchLike>().mockResolvedValue(json(legacyPayload, 400))
    const legacy = new BitwardenHttpClient({ server: 'us', fetch: legacyFetch })
    await expect(
      legacy.passwordToken({ email: 'person@example.test', password: 'derived-secret' })
    ).rejects.toMatchObject({
      code: 'TWO_FACTOR',
      details: undefined,
      twoFactorProviders: [0, 1, 3, 8],
      webAuthnChallenge: undefined
    })
  })

  it.each([
    {
      label: 'legacy array without a provider map',
      providers: { TwoFactorProviders: ['0', '1'] },
      expected: [0, 1]
    },
    {
      label: 'legacy array with a null provider map',
      providers: { TwoFactorProviders: ['7'], TwoFactorProviders2: null },
      expected: []
    },
    {
      label: 'provider map with a null legacy array',
      providers: { TwoFactorProviders: null, TwoFactorProviders2: { '1': null } },
      expected: [1]
    }
  ])('recognizes $label and treats null metadata as absent', async ({ providers, expected }) => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      json(
        {
          error: 'invalid_grant',
          error_description: 'Mehrstufige Anmeldung erforderlich.',
          ...providers
        },
        400
      )
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch })

    await expect(
      client.passwordToken({ email: 'person@example.test', password: 'derived-secret' })
    ).rejects.toMatchObject({
      code: 'TWO_FACTOR',
      details: undefined,
      twoFactorProviders: expected,
      webAuthnChallenge: undefined
    })
  })

  it('ignores future providers when a known login alternative remains available', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      json(
        {
          error: 'invalid_grant',
          error_description: 'Mehrstufige Anmeldung erforderlich.',
          TwoFactorProviders: ['0', '9', 42],
          TwoFactorProviders2: { '0': null, '9': null, '42': { future: true } }
        },
        400
      )
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch })

    await expect(
      client.passwordToken({ email: 'person@example.test', password: 'derived-secret' })
    ).rejects.toMatchObject({
      code: 'TWO_FACTOR',
      details: undefined,
      twoFactorProviders: [0],
      webAuthnChallenge: undefined
    })
  })

  it('returns an unsupported challenge when only unknown future providers remain', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      json(
        {
          error: 'invalid_grant',
          error_description: 'Mehrstufige Anmeldung erforderlich.',
          TwoFactorProviders2: { '9': null, '42': { future: true } }
        },
        400
      )
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch })

    await expect(
      client.passwordToken({ email: 'person@example.test', password: 'derived-secret' })
    ).rejects.toMatchObject({
      code: 'TWO_FACTOR',
      details: undefined,
      twoFactorProviders: [],
      webAuthnChallenge: undefined
    })
  })

  it('does not infer a two-factor challenge from English error text alone', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValue(
        json({ error: 'invalid_grant', error_description: 'Two factor required.' }, 400)
      )
    const client = new BitwardenHttpClient({ server: 'us', fetch })

    await expect(
      client.passwordToken({ email: 'person@example.test', password: 'derived-secret' })
    ).rejects.toMatchObject({ code: 'AUTH' })
  })

  it('rejects malformed or unbounded login provider metadata without retry', async () => {
    const malformedProviders = [
      { TwoFactorProviders: ['01'], TwoFactorProviders2: { '0': null } },
      { TwoFactorProviders: [-1], TwoFactorProviders2: { '0': null } },
      {
        TwoFactorProviders: Array.from({ length: 33 }, () => 0),
        TwoFactorProviders2: { '0': null }
      },
      { TwoFactorProviders2: { '99999999999999999999999999999999': null } },
      { TwoFactorProviders2: [] }
    ]

    for (const providers of malformedProviders) {
      const fetch = vi.fn<FetchLike>().mockResolvedValue(
        json(
          {
            error: 'invalid_grant',
            error_description: 'Two factor required.',
            ...providers
          },
          400
        )
      )
      const client = new BitwardenHttpClient({ server: 'us', fetch, maxRetries: 5 })
      await expect(
        client.passwordToken({ email: 'person@example.test', password: 'derived-secret' })
      ).rejects.toMatchObject({ code: 'INVALID_RESPONSE', details: undefined })
      expect(fetch).toHaveBeenCalledOnce()
    }
  })

  it('rejects malformed provider 7 without retry', async () => {
    const malformedFetch = vi.fn<FetchLike>().mockResolvedValue(
      json(
        {
          error: 'invalid_grant',
          error_description: 'Two factor required.',
          TwoFactorProviders2: { '7': { ...vaultwardenChallengeFixture(), challenge: 'bad=' } }
        },
        400
      )
    )
    const malformed = new BitwardenHttpClient({ server: 'us', fetch: malformedFetch })
    await expect(
      malformed.passwordToken({ email: 'person@example.test', password: 'derived-secret' })
    ).rejects.toMatchObject({ code: 'INVALID_RESPONSE', details: undefined })
    expect(malformedFetch).toHaveBeenCalledOnce()
  })

  it('serializes refreshes and retries each rejected authenticated GET only once', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json({ error: 'invalid_token' }, 401))
      .mockResolvedValueOnce(json({ error: 'invalid_token' }, 401))
      .mockResolvedValueOnce(
        json({ access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 60 })
      )
      .mockResolvedValueOnce(json({ revisionDate: '2026-01-01T00:00:00.000Z' }))
      .mockResolvedValueOnce(json({ revisionDate: '2026-01-01T00:00:00.000Z' }))
    const changed = vi.fn()
    const client = new BitwardenHttpClient({
      server: 'us',
      fetch,
      onSessionChanged: changed,
      now: () => 0
    })
    client.setSession({ accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1 })
    await Promise.all([client.revisionDate(), client.revisionDate()])
    expect(fetch.mock.calls.filter(([url]) => url.endsWith('/connect/token'))).toHaveLength(1)
    expect(changed).toHaveBeenCalledWith({
      accessToken: 'new-access',
      refreshToken: 'new-refresh',
      expiresAt: 60_000
    })
    expect(client.exportSession()?.accessToken).toBe('new-access')
  })

  it('keeps a shared refresh running when its first waiter aborts', async () => {
    const refreshResponse = deferred<Response>()
    let refreshSignal: AbortSignal | null | undefined
    const fetch = vi.fn<FetchLike>().mockImplementation(async (_url, init) => {
      refreshSignal = init?.signal
      return refreshResponse.promise
    })
    const changed = vi.fn()
    const client = new BitwardenHttpClient({
      server: 'us',
      fetch,
      onSessionChanged: changed,
      now: () => 0
    })
    client.setSession({ accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1 })
    const firstController = new AbortController()

    const first = client.refresh(firstController.signal)
    const second = client.refresh()
    const firstResult = expect(first).rejects.toMatchObject({ code: 'ABORTED' })
    firstController.abort()

    await firstResult
    expect(refreshSignal?.aborted).toBe(false)
    expect(fetch).toHaveBeenCalledOnce()

    refreshResponse.resolve(
      json({ access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 60 })
    )
    await expect(second).resolves.toEqual({
      accessToken: 'new-access',
      refreshToken: 'new-refresh',
      expiresAt: 60_000
    })
    expect(changed).toHaveBeenCalledOnce()
  })

  it('finishes a dispatched refresh after its only waiter abandons it', async () => {
    const refreshResponse = deferred<Response>()
    let refreshSignal: AbortSignal | null | undefined
    const fetch = vi.fn<FetchLike>().mockImplementation(async (_url, init) => {
      refreshSignal = init?.signal
      return refreshResponse.promise
    })
    const changed = vi.fn()
    const client = new BitwardenHttpClient({
      server: 'us',
      fetch,
      onSessionChanged: changed,
      now: () => 0
    })
    client.setSession({ accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1 })
    const controller = new AbortController()

    const refresh = client.refresh(controller.signal)
    const refreshResult = expect(refresh).rejects.toMatchObject({ code: 'ABORTED' })
    controller.abort()

    await refreshResult
    expect(refreshSignal?.aborted).toBe(false)
    expect(fetch).toHaveBeenCalledOnce()
    refreshResponse.resolve(
      json({ access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 60 })
    )
    await vi.waitFor(() =>
      expect(client.exportSession()).toEqual({
        accessToken: 'new-access',
        refreshToken: 'new-refresh',
        expiresAt: 60_000
      })
    )
    expect(changed).toHaveBeenCalledOnce()
  })

  it('invalidates the session when a successful refresh response cannot be parsed', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValue(
        json({ access_token: 'bad token', refresh_token: 'rotated-refresh', expires_in: 60 })
      )
    const changed = vi.fn()
    const client = new BitwardenHttpClient({
      server: 'us',
      fetch,
      onSessionChanged: changed,
      now: () => 0
    })
    client.setSession({ accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1 })

    await expect(client.refresh()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
    expect(client.exportSession()).toBeNull()
    expect(changed).toHaveBeenCalledOnce()
    expect(changed).toHaveBeenCalledWith(null)
  })

  it('does not revive a cleared session when an ignored-abort refresh response arrives late', async () => {
    const refreshResponse = deferred<Response>()
    let refreshSignal: AbortSignal | null | undefined
    const fetch = vi.fn<FetchLike>().mockImplementation(async (_url, init) => {
      refreshSignal = init?.signal
      return refreshResponse.promise
    })
    const changed = vi.fn()
    const client = new BitwardenHttpClient({
      server: 'us',
      fetch,
      onSessionChanged: changed,
      now: () => 0
    })
    client.setSession({ accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1 })

    const refresh = client.refresh()
    const refreshResult = expect(refresh).rejects.toMatchObject({ code: 'AUTH' })
    client.clearSession()
    expect(refreshSignal?.aborted).toBe(true)
    refreshResponse.resolve(
      json({ access_token: 'stale-access', refresh_token: 'stale-refresh', expires_in: 60 })
    )

    await refreshResult
    expect(client.exportSession()).toBeNull()
    expect(changed).not.toHaveBeenCalled()
  })

  it('invalidates a rotated session when its persistence callback fails', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValue(
        json({ access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 60 })
      )
    const changed = vi.fn().mockRejectedValue(new Error('state persistence failed'))
    const client = new BitwardenHttpClient({
      server: 'us',
      fetch,
      onSessionChanged: changed,
      now: () => 0
    })
    client.setSession({ accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1 })

    await expect(client.refresh()).rejects.toMatchObject({ code: 'AUTH' })
    expect(changed).toHaveBeenCalledWith({
      accessToken: 'new-access',
      refreshToken: 'new-refresh',
      expiresAt: 60_000
    })
    expect(client.exportSession()).toBeNull()
  })

  it('does not expose or commit a rotated session before persistence completes', async () => {
    const persistence = deferred<void>()
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValue(
        json({ access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 60 })
      )
    const changed = vi.fn(async () => persistence.promise)
    const client = new BitwardenHttpClient({
      server: 'us',
      fetch,
      onSessionChanged: changed,
      now: () => 0
    })
    client.setSession({ accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1 })

    const refresh = client.refresh()
    const refreshResult = expect(refresh).rejects.toMatchObject({ code: 'AUTH' })
    await vi.waitFor(() => expect(changed).toHaveBeenCalledOnce())
    expect(client.exportSession()).toEqual({
      accessToken: 'old-access',
      refreshToken: 'old-refresh',
      expiresAt: 1
    })

    client.clearSession()
    persistence.resolve()
    await refreshResult
    expect(client.exportSession()).toBeNull()
  })

  it('isolates a new session refresh from an older generation still in flight', async () => {
    const oldRefreshResponse = deferred<Response>()
    const newRefreshResponse = deferred<Response>()
    const fetch = vi
      .fn<FetchLike>()
      .mockImplementationOnce(async () => oldRefreshResponse.promise)
      .mockImplementationOnce(async () => newRefreshResponse.promise)
    const changed = vi.fn()
    const client = new BitwardenHttpClient({
      server: 'us',
      fetch,
      onSessionChanged: changed,
      now: () => 0
    })
    client.setSession({ accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1 })
    const oldRefresh = client.refresh()
    const oldRefreshResult = expect(oldRefresh).rejects.toMatchObject({ code: 'AUTH' })

    client.setSession({
      accessToken: 'new-session-original-access',
      refreshToken: 'new-session-refresh',
      expiresAt: 1
    })
    const newRefresh = client.refresh()
    oldRefreshResponse.resolve(
      json({ access_token: 'stale-access', refresh_token: 'stale-refresh', expires_in: 60 })
    )

    await oldRefreshResult
    expect(fetch).toHaveBeenCalledTimes(2)
    const secondNewRefreshWaiter = client.refresh()
    expect(fetch).toHaveBeenCalledTimes(2)
    newRefreshResponse.resolve(
      json({
        access_token: 'new-session-access',
        refresh_token: 'new-session-refresh-rotated',
        expires_in: 60
      })
    )
    await expect(Promise.all([newRefresh, secondNewRefreshWaiter])).resolves.toEqual([
      {
        accessToken: 'new-session-access',
        refreshToken: 'new-session-refresh-rotated',
        expiresAt: 60_000
      },
      {
        accessToken: 'new-session-access',
        refreshToken: 'new-session-refresh-rotated',
        expiresAt: 60_000
      }
    ])
    expect(client.exportSession()).toEqual({
      accessToken: 'new-session-access',
      refreshToken: 'new-session-refresh-rotated',
      expiresAt: 60_000
    })
    expect(changed).toHaveBeenCalledTimes(1)
  })

  it('keeps the previous refresh token when a refresh response omits rotation', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValue(json({ access_token: 'new-access', expires_in: 60 }))
    const changed = vi.fn()
    const client = new BitwardenHttpClient({
      server: 'us',
      fetch,
      onSessionChanged: changed,
      now: () => 0
    })
    client.setSession({
      accessToken: 'old-access',
      refreshToken: 'old-refresh',
      expiresAt: 1
    })

    await expect(client.refresh()).resolves.toEqual({
      accessToken: 'new-access',
      refreshToken: 'old-refresh',
      expiresAt: 60_000
    })
    expect(changed).toHaveBeenCalledWith({
      accessToken: 'new-access',
      refreshToken: 'old-refresh',
      expiresAt: 60_000
    })
  })

  it('uses the access-token expiry when a refresh response omits expires_in', async () => {
    const accessToken = unsignedAccessToken({ exp: 4_000 })
    const fetch = vi.fn<FetchLike>().mockResolvedValue(json({ access_token: accessToken }))
    const client = new BitwardenHttpClient({ server: 'us', fetch, now: () => 0 })
    client.setSession({
      accessToken: 'old-access',
      refreshToken: 'old-refresh',
      expiresAt: 1
    })

    await expect(client.refresh()).resolves.toEqual({
      accessToken,
      refreshToken: 'old-refresh',
      expiresAt: 4_000_000
    })
  })

  it('still requires a refresh token for the initial password grant', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValue(json({ access_token: 'access', expires_in: 60 }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })

    await expect(
      client.passwordToken({ email: 'person@example.test', password: 'derived-secret' })
    ).rejects.toMatchObject({
      code: 'INVALID_RESPONSE',
      invalidResponseReason: 'session-response'
    })
  })

  it('uses the session or access-token OAuth client id when refreshing', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockImplementation(async () =>
        json({ access_token: 'fresh-access', refresh_token: 'fresh-refresh', expires_in: 60 })
      )
    const client = new BitwardenHttpClient({ server: 'us', fetch, now: () => 0 })
    client.setSession({
      accessToken: unsignedAccessToken({ client_id: 'browser' }),
      refreshToken: 'refresh',
      expiresAt: 1
    })
    await client.refresh()
    expect(fetch.mock.calls[0]?.[1]?.body).toContain('client_id=browser')

    client.setSession({
      accessToken: unsignedAccessToken({ client_id: 'browser' }),
      refreshToken: 'refresh',
      expiresAt: 1,
      clientId: 'desktop'
    })
    await client.refresh()
    expect(fetch.mock.calls[1]?.[1]?.body).toContain('client_id=desktop')
  })

  it('falls back to desktop for opaque or unsafe access-token client ids', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValue(
        json({ access_token: 'fresh-access', refresh_token: 'fresh-refresh', expires_in: 60 })
      )
    const client = new BitwardenHttpClient({ server: 'us', fetch, now: () => 0 })
    client.setSession({
      accessToken: unsignedAccessToken({ client_id: 'desktop\r\nx-unsafe' }),
      refreshToken: 'refresh',
      expiresAt: 1
    })
    await client.refresh()
    expect(fetch.mock.calls[0]?.[1]?.body).toContain('client_id=desktop')
  })

  it('classifies refresh invalid_grant as an expired session without raw identity details', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      json(
        {
          error: 'invalid_grant',
          error_description: 'refresh token expired for a deployment-specific account'
        },
        400
      )
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'opaque', refreshToken: 'expired', expiresAt: 1 })
    const error = await client.refresh().catch((caught: unknown) => caught)
    expect(error).toMatchObject({ code: 'SESSION_EXPIRED', status: 400, details: undefined })
    expect(JSON.stringify(error)).not.toContain('deployment-specific')
  })

  it('classifies forced SSO without exposing the organization identifier', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      json(
        {
          error: 'invalid_grant',
          error_description: 'SSO authentication required.',
          SsoOrganizationIdentifier: 'private-organization-slug'
        },
        400
      )
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    const error = await client
      .passwordToken({ email: 'person@example.test', password: 'derived-secret' })
      .catch((caught: unknown) => caught)
    expect(error).toMatchObject({ code: 'SSO_REQUIRED', status: 400, details: undefined })
    expect(JSON.stringify(error)).not.toContain('private-organization-slug')
  })

  it('reuses a live notification token and serializes proactive refresh near expiry', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValue(
        json({ access_token: 'fresh-access', refresh_token: 'fresh-refresh', expires_in: 3_600 })
      )
    const changed = vi.fn()
    const client = new BitwardenHttpClient({
      server: 'us',
      fetch,
      onSessionChanged: changed,
      now: () => 1_000
    })
    client.setSession({ accessToken: 'live-access', refreshToken: 'refresh', expiresAt: 61_001 })
    await expect(client.activeAccessToken()).resolves.toBe('live-access')
    expect(fetch).not.toHaveBeenCalled()

    client.setSession({
      accessToken: 'expiring-access',
      refreshToken: 'refresh',
      expiresAt: 61_000
    })
    await expect(
      Promise.all([client.activeAccessToken(), client.activeAccessToken()])
    ).resolves.toEqual(['fresh-access', 'fresh-access'])
    expect(fetch).toHaveBeenCalledOnce()
    expect(changed).toHaveBeenCalledWith({
      accessToken: 'fresh-access',
      refreshToken: 'fresh-refresh',
      expiresAt: 3_601_000
    })
  })

  it('uses Retry-After only for idempotent operations, and keeps encrypted payloads untouched', async () => {
    const sleep = vi.fn().mockResolvedValue(undefined)
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json({ message: 'slow down' }, 429, { 'retry-after': '2' }))
      .mockResolvedValueOnce(json({ revisionDate: '2026-01-01T00:00:00.000Z' }))
      .mockResolvedValueOnce(json({ message: 'slow down' }, 429, { 'retry-after': '2' }))
    const client = new BitwardenHttpClient({ server: 'us', fetch, sleep })
    client.setSession({ accessToken: 'a', refreshToken: 'r', expiresAt: 1 })
    await client.revisionDate()
    await expect(client.createCipher({ name: '2.encrypted', type: 1 })).rejects.toMatchObject({
      code: 'NETWORK'
    })
    expect(sleep).toHaveBeenCalledWith(2000, undefined)
    expect(fetch.mock.calls[2]?.[1]?.body).toBe(JSON.stringify({ name: '2.encrypted', type: 1 }))
  })

  it('cancels a rejected authenticated response body before refreshing and retrying', async () => {
    const rejected = cancelableResponse(401, undefined, new Promise<void>(() => undefined))
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(rejected.response)
      .mockResolvedValueOnce(
        json({ access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 60 })
      )
      .mockResolvedValueOnce(json({ revisionDate: '2026-01-01T00:00:00.000Z' }))
    const client = new BitwardenHttpClient({ server: 'us', fetch, now: () => 0 })
    client.setSession({ accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1 })

    await expect(client.revisionDate()).resolves.toBe('2026-01-01T00:00:00.000Z')
    expect(rejected.cancel).toHaveBeenCalledOnce()
  })

  it.each([429, 503])(
    'cancels a retryable %i response body before dispatching the next attempt',
    async (status) => {
      const rejected = cancelableResponse(status, undefined, new Promise<void>(() => undefined))
      const fetch = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(rejected.response)
        .mockResolvedValueOnce(json({ revisionDate: '2026-01-01T00:00:00.000Z' }))
      const client = new BitwardenHttpClient({ server: 'us', fetch })
      client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })

      await expect(client.revisionDate()).resolves.toBe('2026-01-01T00:00:00.000Z')
      expect(rejected.cancel).toHaveBeenCalledOnce()
    }
  )

  it('parses trusted and granted Emergency Access metadata without exposing encrypted keys', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          data: [
            {
              id: '60000000-0000-4000-8000-000000000001',
              granteeId: '60000000-0000-4000-8000-000000000002',
              name: 'Trusted contact',
              email: 'trusted@example.invalid',
              type: 0,
              status: 1,
              waitTimeDays: 7,
              creationDate: '2026-07-16T00:00:00Z',
              avatarColor: '#123456',
              keyEncrypted: 'must-not-escape'
            }
          ]
        })
      )
      .mockResolvedValueOnce(
        json({
          Data: [
            {
              Id: '60000000-0000-4000-8000-000000000003',
              GrantorId: '60000000-0000-4000-8000-000000000004',
              Name: 'Grantor contact',
              Email: 'grantor@example.invalid',
              Type: 1,
              Status: 2,
              WaitTimeDays: 14,
              CreationDate: '2026-07-15T00:00:00Z',
              AvatarColor: '#654321',
              KeyEncrypted: 'must-not-escape'
            }
          ]
        })
      )
    const client = new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })
    await expect(client.listEmergencyAccess()).resolves.toEqual([
      expect.objectContaining({
        role: 'trusted',
        subjectId: '60000000-0000-4000-8000-000000000002',
        email: 'trusted@example.invalid'
      }),
      expect.objectContaining({
        role: 'granted',
        subjectId: '60000000-0000-4000-8000-000000000004',
        type: 1
      })
    ])
    expect(JSON.stringify(fetch.mock.calls)).not.toContain('must-not-escape')
  })

  it('accepts a pending Emergency Access invitation with no grantee ID', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          data: [
            {
              id: '61000000-0000-4000-8000-000000000001',
              granteeId: null,
              name: '',
              email: 'trusted@example.invalid',
              type: 0,
              status: 0,
              waitTimeDays: 7,
              avatarColor: null
            }
          ]
        })
      )
      .mockResolvedValueOnce(
        json({
          data: [
            {
              id: '61000000-0000-4000-8000-000000000003',
              grantorId: '61000000-0000-4000-8000-000000000004',
              name: null,
              email: 'grantor@example.invalid',
              type: 1,
              status: 4,
              waitTimeDays: 14
            }
          ]
        })
      )
    const client = new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })

    await expect(client.listEmergencyAccess()).resolves.toEqual([
      expect.objectContaining({
        role: 'trusted',
        subjectId: null,
        name: '',
        creationDate: null,
        avatarColor: null
      }),
      expect.objectContaining({
        role: 'granted',
        name: null,
        creationDate: null,
        avatarColor: null
      })
    ])
  })

  it('rejects Emergency Access statuses outside the official enum', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          data: [
            {
              id: '62000000-0000-4000-8000-000000000001',
              granteeId: '62000000-0000-4000-8000-000000000002',
              name: 'Trusted contact',
              email: 'trusted@example.invalid',
              type: 0,
              status: 5,
              waitTimeDays: 7
            }
          ]
        })
      )
      .mockResolvedValueOnce(json({ data: [] }))
    const client = new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })

    await expect(client.listEmergencyAccess()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
  })

  it('queries Vaultwarden account breaches with auth and excludes remote HTML from the safe model', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      json([
        {
          Name: 'ExampleBreach',
          Title: 'Example Breach',
          Domain: 'example.test',
          BreachDate: '2025-01-02',
          AddedDate: '2025-02-03T04:05:06Z',
          ModifiedDate: '2025-03-04T05:06:07Z',
          PwnCount: 12,
          DataClasses: ['Email addresses', 'Passwords'],
          IsVerified: true,
          Description: '<img src=x onerror=alert(1)>'
        }
      ])
    )
    const client = new BitwardenHttpClient({
      server: 'https://vault.example.test/bw',
      fetch
    })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })

    await expect(client.getAccountBreachReport('person+tag@example.test')).resolves.toEqual({
      status: 'complete',
      breaches: [
        {
          name: 'ExampleBreach',
          title: 'Example Breach',
          domain: 'example.test',
          breachDate: '2025-01-02',
          addedDate: '2025-02-03T04:05:06Z',
          pwnCount: 12,
          dataClasses: ['Email addresses', 'Passwords'],
          isVerified: true
        }
      ]
    })
    expect(fetch.mock.calls[0]?.[0]).toBe(
      'https://vault.example.test/bw/api/hibp/breach?username=person%2Btag%40example.test'
    )
    expect(new Headers(fetch.mock.calls[0]?.[1]?.headers).get('authorization')).toBe(
      'Bearer access'
    )
  })

  it('normalizes the Vaultwarden no-breach 404 but not other failures', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(json({ reason: 'Not Found' }, 404))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })

    await expect(client.getAccountBreachReport('person@example.test')).resolves.toEqual({
      status: 'complete',
      breaches: []
    })

    const unavailable = vi
      .fn<FetchLike>()
      .mockResolvedValue(json({ reason: 'Service Unavailable' }, 503))
    const unavailableClient = new BitwardenHttpClient({ server: 'us', fetch: unavailable })
    unavailableClient.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })
    await expect(
      unavailableClient.getAccountBreachReport('person@example.test')
    ).rejects.toMatchObject({ code: 'NETWORK', status: 503 })
  })

  it('marks Vaultwarden HIBP key placeholders unavailable instead of reporting a breach', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      json([
        {
          name: 'HaveIBeenPwned',
          title: 'Manual HIBP Check',
          pwnCount: 0,
          dataClasses: ['Error - No API key set!'],
          description: '<a>untrusted remote html</a>'
        }
      ])
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })

    await expect(client.getAccountBreachReport('person@example.test')).resolves.toEqual({
      status: 'unavailable',
      reason: 'server-hibp-unconfigured'
    })
  })

  it('rejects malformed or oversized account-breach responses', async () => {
    const malformed = vi.fn<FetchLike>().mockResolvedValue(json([{ Name: 'only-a-name' }]))
    const malformedClient = new BitwardenHttpClient({ server: 'us', fetch: malformed })
    malformedClient.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })
    await expect(
      malformedClient.getAccountBreachReport('person@example.test')
    ).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })

    const oversized = vi
      .fn<FetchLike>()
      .mockResolvedValue(
        new Response('[]', { headers: { 'content-length': String(4 * 1024 * 1024 + 1) } })
      )
    const oversizedClient = new BitwardenHttpClient({ server: 'us', fetch: oversized })
    oversizedClient.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })
    await expect(
      oversizedClient.getAccountBreachReport('person@example.test')
    ).rejects.toMatchObject({
      code: 'TOO_LARGE'
    })
  })

  it('reads and updates authenticated equivalent-domain settings under a reverse-proxy prefix', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          Object: 'domains',
          EquivalentDomains: [[], ['one.example'], ['bücher.example', 'xn--bcher-kva.example']],
          GlobalEquivalentDomains: [
            { Type: 7, Domains: ['alpha.example', 'beta.example'], Excluded: true }
          ]
        })
      )
      .mockResolvedValueOnce(json({}))
    const client = new BitwardenHttpClient({
      server: 'https://vault.example.test/bw',
      fetch
    })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })

    await expect(client.getEquivalentDomainSettings()).resolves.toEqual({
      equivalentDomains: [[], ['one.example'], ['bücher.example', 'xn--bcher-kva.example']],
      globalEquivalentDomains: [
        { type: 7, domains: ['alpha.example', 'beta.example'], excluded: true }
      ]
    })
    await expect(
      client.updateEquivalentDomainSettings({
        equivalentDomains: [['one.example'], ['first.example', 'second.example']],
        excludedGlobalEquivalentDomains: [7]
      })
    ).resolves.toBeUndefined()

    expect(fetch.mock.calls.map(([url, init]) => `${init?.method} ${url}`)).toEqual([
      'GET https://vault.example.test/bw/api/settings/domains',
      'PUT https://vault.example.test/bw/api/settings/domains'
    ])
    expect(new Headers(fetch.mock.calls[1]?.[1]?.headers).get('authorization')).toBe(
      'Bearer access'
    )
    expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toEqual({
      equivalentDomains: [['one.example'], ['first.example', 'second.example']],
      excludedGlobalEquivalentDomains: [7]
    })
  })

  it('normalizes nullable official equivalent-domain lists to empty settings', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          object: 'domains',
          equivalentDomains: null,
          globalEquivalentDomains: [
            { type: 1, domains: ['google.com', 'gmail.com'], excluded: false }
          ]
        })
      )
      .mockResolvedValueOnce(
        json({
          object: 'domains',
          equivalentDomains: [],
          globalEquivalentDomains: null
        })
      )
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })

    await expect(client.getEquivalentDomainSettings()).resolves.toEqual({
      equivalentDomains: [],
      globalEquivalentDomains: [{ type: 1, domains: ['google.com', 'gmail.com'], excluded: false }]
    })
    await expect(client.getEquivalentDomainSettings()).resolves.toEqual({
      equivalentDomains: [],
      globalEquivalentDomains: []
    })
  })

  it('rejects malformed, ambiguous, or oversized equivalent-domain settings', async () => {
    const malformedFetch = vi.fn<FetchLike>().mockResolvedValue(
      json({
        equivalentDomains: [['valid.example']],
        globalEquivalentDomains: [
          { type: 1, domains: ['a.example'], excluded: false },
          { type: 1, domains: ['b.example'], excluded: true }
        ]
      })
    )
    const malformedClient = new BitwardenHttpClient({ server: 'us', fetch: malformedFetch })
    malformedClient.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })
    await expect(malformedClient.getEquivalentDomainSettings()).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })

    const oversizedFetch = vi.fn<FetchLike>().mockResolvedValue(
      new Response('{}', {
        headers: { 'content-length': String(2 * 1024 * 1024 + 1) }
      })
    )
    const oversizedClient = new BitwardenHttpClient({ server: 'us', fetch: oversizedFetch })
    oversizedClient.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })
    await expect(oversizedClient.getEquivalentDomainSettings()).rejects.toMatchObject({
      code: 'TOO_LARGE'
    })

    await expect(
      malformedClient.updateEquivalentDomainSettings({
        equivalentDomains: [['contains,comma.example']],
        excludedGlobalEquivalentDomains: []
      })
    ).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
  })

  it('uses the personal folder and cipher CRUD routes', async () => {
    const fetch = vi.fn<FetchLike>().mockImplementation(async (url, init) => {
      if (
        init?.method === 'DELETE' ||
        (init?.method === 'PUT' && url.endsWith('/ciphers/cipher%20id/delete'))
      ) {
        return new Response(null, { status: 204 })
      }
      return json({ id: 'entity-id' })
    })
    const client = new BitwardenHttpClient({ server: 'https://vault.example.test', fetch })
    client.setSession({ accessToken: 'a', refreshToken: 'r', expiresAt: 1 })
    await client.createFolder({ name: '2.folder' })
    await client.updateFolder('folder id', { name: '2.changed' })
    await client.deleteFolder('folder id')
    await client.createCipher({ name: '2.cipher' })
    await client.updateCipher('cipher id', { name: '2.changed' })
    await client.softDeleteCipher('cipher id')
    await expect(client.restoreCipher('cipher id')).resolves.toEqual({ id: 'entity-id' })
    await expect(client.archiveCipher('cipher id')).resolves.toEqual({ id: 'entity-id' })
    await expect(client.unarchiveCipher('cipher id')).resolves.toEqual({ id: 'entity-id' })
    await client.hardDeleteCipher('cipher id')
    expect(fetch.mock.calls.map(([url, init]) => `${init?.method} ${url}`)).toEqual([
      'POST https://vault.example.test/api/folders',
      'PUT https://vault.example.test/api/folders/folder%20id',
      'DELETE https://vault.example.test/api/folders/folder%20id',
      'POST https://vault.example.test/api/ciphers',
      'PUT https://vault.example.test/api/ciphers/cipher%20id',
      'PUT https://vault.example.test/api/ciphers/cipher%20id/delete',
      'PUT https://vault.example.test/api/ciphers/cipher%20id/restore',
      'PUT https://vault.example.test/api/ciphers/cipher%20id/archive',
      'PUT https://vault.example.test/api/ciphers/cipher%20id/unarchive',
      'DELETE https://vault.example.test/api/ciphers/cipher%20id'
    ])
  })

  it('uses authenticated owner Send CRUD routes and preserves the web-vault share base', async () => {
    const send = { id: 'send-id', accessId: 'access-id' }
    const fetch = vi.fn<FetchLike>().mockImplementation(async (_url, init) => {
      if (init?.method === 'GET') return json({ data: [send] })
      if (init?.method === 'DELETE') return new Response(null, { status: 204 })
      return json(send)
    })
    const client = new BitwardenHttpClient({ server: 'https://vault.example.test/bw', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })
    await expect(client.listSends()).resolves.toEqual([send])
    await client.createSend({
      type: 0,
      authType: 2,
      name: '2.name',
      notes: null,
      key: '2.key',
      maxAccessCount: null,
      expirationDate: null,
      deletionDate: '2026-07-30T00:00:00.000Z',
      text: { text: '2.text', hidden: false },
      password: null,
      emails: null,
      disabled: false,
      hideEmail: true
    })
    await client.updateSend('send-id', {
      type: 0,
      authType: 2,
      name: '2.name',
      notes: null,
      key: '2.key',
      maxAccessCount: null,
      expirationDate: null,
      deletionDate: '2026-07-30T00:00:00.000Z',
      text: { text: '2.text', hidden: false },
      password: null,
      emails: null,
      disabled: false,
      hideEmail: true
    })
    await client.removeSendPassword('send-id')
    await client.deleteSend('send-id')
    expect(fetch.mock.calls.map(([url, init]) => `${init?.method} ${url}`)).toEqual([
      'GET https://vault.example.test/bw/api/sends',
      'POST https://vault.example.test/bw/api/sends',
      'PUT https://vault.example.test/bw/api/sends/send-id',
      'PUT https://vault.example.test/bw/api/sends/send-id/remove-password',
      'DELETE https://vault.example.test/bw/api/sends/send-id'
    ])
    expect(client.sendUrl()).toBe('https://vault.example.test/bw/#/send/')
  })

  it('requires restore to return a cipher object while accepting empty delete responses', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'a', refreshToken: 'r', expiresAt: 1 })

    await expect(client.softDeleteCipher('cipher-id')).resolves.toBeUndefined()
    await expect(client.hardDeleteCipher('cipher-id')).resolves.toBeUndefined()
    await expect(client.restoreCipher('cipher-id')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
  })

  it('posts a bounded personal cipher import contract and accepts only empty 200 or 204', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    const client = new BitwardenHttpClient({
      server: 'https://vault.example.test/bw',
      fetch,
      maxRetries: 3
    })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })
    const request = {
      folders: [{ name: '2.encrypted-folder' }],
      ciphers: [
        { type: 1, name: '2.encrypted-login', organizationId: null },
        { type: 2, name: '2.encrypted-note', organizationId: null }
      ],
      folderRelationships: [{ key: 1, value: 0 }]
    }

    await expect(client.importPersonalCiphers(request)).resolves.toBeUndefined()
    await expect(client.importPersonalCiphers(request)).resolves.toBeUndefined()

    expect(fetch).toHaveBeenCalledTimes(2)
    expect(fetch.mock.calls.map(([url, init]) => `${init?.method} ${url}`)).toEqual([
      'POST https://vault.example.test/bw/api/ciphers/import',
      'POST https://vault.example.test/bw/api/ciphers/import'
    ])
    expect(new Headers(fetch.mock.calls[0]?.[1]?.headers).get('authorization')).toBe(
      'Bearer access'
    )
    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toEqual(request)
  })

  it('rejects non-personal or structurally invalid cipher imports before transport', async () => {
    const fetch = vi.fn<FetchLike>()
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })
    const valid = {
      folders: [{ name: '2.folder' }],
      ciphers: [{ type: 1, name: '2.login', organizationId: null }],
      folderRelationships: [{ key: 0, value: 0 }]
    }
    const invalidRequests: unknown[] = [
      { ...valid, attachments: [] },
      { ...valid, ciphers: [] },
      { ...valid, folders: [{ name: '' }] },
      { ...valid, folders: [{ id: 'not-a-uuid', name: '2.folder' }] },
      { ...valid, folders: [{ name: '2.folder', organizationId: null }] },
      { ...valid, ciphers: [{ type: 0, name: '2.login' }] },
      { ...valid, ciphers: [{ type: 1, name: '' }] },
      { ...valid, ciphers: [{ ...valid.ciphers[0], organizationId: 'org-id' }] },
      { ...valid, ciphers: [{ ...valid.ciphers[0], attachments: [] }] },
      { ...valid, ciphers: [{ ...valid.ciphers[0], collectionIds: [] }] },
      { ...valid, ciphers: [{ ...valid.ciphers[0], organization_id: 'org-id' }] },
      { ...valid, folderRelationships: [{ key: 0.5, value: 0 }] },
      { ...valid, folderRelationships: [{ key: 1, value: 0 }] },
      { ...valid, folderRelationships: [{ key: 0, value: 1 }] },
      {
        ...valid,
        folderRelationships: [
          { key: 0, value: 0 },
          { key: 0, value: 0 }
        ]
      },
      { ...valid, folders: Array.from({ length: 2_001 }, () => ({ name: '2.folder' })) },
      { ...valid, ciphers: Array.from({ length: 7_001 }, () => ({ type: 2, name: '2.note' })) },
      {
        ...valid,
        folderRelationships: Array.from({ length: 7_001 }, (_, key) => ({ key, value: 0 }))
      },
      { ...valid, ciphers: [{ type: 2, name: `2.${'x'.repeat(18 * 1024 * 1024)}` }] }
    ]

    for (const request of invalidRequests) {
      await expect(client.importPersonalCiphers(request as never)).rejects.toMatchObject({
        code: expect.stringMatching(/^(INVALID_RESPONSE|TOO_LARGE)$/u)
      })
    }
    expect(fetch).not.toHaveBeenCalled()
  })

  it('rejects nonempty or unexpected successful import responses and never retries', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json({ object: 'importResult' }))
      .mockResolvedValueOnce(new Response(null, { status: 201 }))
      .mockResolvedValueOnce(json({ message: 'ambiguous failure' }, 503))
    const client = new BitwardenHttpClient({ server: 'us', fetch, maxRetries: 3 })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })
    const request = {
      folders: [],
      ciphers: [{ type: 2, name: '2.encrypted-note' }],
      folderRelationships: []
    }

    await expect(client.importPersonalCiphers(request)).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    await expect(client.importPersonalCiphers(request)).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    await expect(client.importPersonalCiphers(request)).rejects.toMatchObject({
      code: 'NETWORK',
      status: 503
    })
    expect(fetch).toHaveBeenCalledTimes(3)
  })

  it('purges the personal vault with the exact non-retryable empty-200 contract', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(new Response(null, { status: 200 }))
    const client = new BitwardenHttpClient({
      server: 'https://vault.example.test/bw',
      fetch,
      maxRetries: 3
    })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.purgePersonalVault('fresh-master-password-proof')).resolves.toBeUndefined()

    expect(fetch).toHaveBeenCalledTimes(1)
    expect(fetch.mock.calls[0]?.[0]).toBe('https://vault.example.test/bw/api/ciphers/purge')
    expect(fetch.mock.calls[0]?.[1]).toMatchObject({ method: 'POST' })
    expect(new Headers(fetch.mock.calls[0]?.[1]?.headers).get('authorization')).toBe(
      'Bearer access'
    )
    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toEqual({
      masterPasswordHash: 'fresh-master-password-proof'
    })
  })

  it('rejects unsafe purge proofs and ambiguous successful responses', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
      .mockResolvedValueOnce(json({ purged: true }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    for (const proof of [
      '',
      'proof\0suffix',
      'proof\r',
      'proof\n',
      'x'.repeat(301),
      'é'.repeat(151)
    ]) {
      await expect(client.purgePersonalVault(proof)).rejects.toMatchObject({
        code: 'INVALID_RESPONSE'
      })
    }
    await expect(client.purgePersonalVault(new String('proof') as never)).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    expect(fetch).not.toHaveBeenCalled()

    await expect(client.purgePersonalVault('x'.repeat(300))).resolves.toBeUndefined()
    await expect(client.purgePersonalVault('é'.repeat(150))).resolves.toBeUndefined()
    await expect(client.purgePersonalVault('valid-proof')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    await expect(client.purgePersonalVault('valid-proof')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    expect(fetch).toHaveBeenCalledTimes(4)
  })

  it('normalizes only invalid purge verification and never retries unknown outcomes', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json({ message: 'Invalid password' }, 400))
      .mockResolvedValueOnce(json({ message: 'User verification failed' }, 400))
      .mockResolvedValueOnce(json({ message: 'Forbidden' }, 403))
      .mockResolvedValueOnce(json({ message: 'Session expired' }, 401))
      .mockResolvedValueOnce(json({ message: 'ambiguous failure' }, 503))
    const client = new BitwardenHttpClient({ server: 'us', fetch, maxRetries: 3 })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.purgePersonalVault('proof-one')).rejects.toMatchObject({
      code: 'USER_VERIFICATION_FAILED',
      status: 400
    })
    await expect(client.purgePersonalVault('proof-two')).rejects.toMatchObject({
      code: 'USER_VERIFICATION_FAILED',
      status: 400
    })
    await expect(client.purgePersonalVault('proof-three')).rejects.toMatchObject({
      code: 'FORBIDDEN',
      status: 403
    })
    await expect(client.purgePersonalVault('proof-four')).rejects.toMatchObject({
      code: 'AUTH',
      status: 401
    })
    await expect(client.purgePersonalVault('proof-five')).rejects.toMatchObject({
      code: 'NETWORK',
      status: 503
    })
    expect(fetch).toHaveBeenCalledTimes(5)
  })

  it('preserves abort and network failures while clearing a prototype-safe purge body', async () => {
    const abortedFetch = vi.fn<FetchLike>()
    const abortedClient = new BitwardenHttpClient({ server: 'us', fetch: abortedFetch })
    abortedClient.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })
    const controller = new AbortController()
    controller.abort()
    await expect(
      abortedClient.purgePersonalVault('proof', controller.signal)
    ).rejects.toMatchObject({
      code: 'ABORTED'
    })
    expect(abortedFetch).not.toHaveBeenCalled()

    const networkFetch = vi.fn<FetchLike>().mockRejectedValue(new TypeError('offline'))
    const networkClient = new BitwardenHttpClient({
      server: 'us',
      fetch: networkFetch,
      maxRetries: 3
    })
    networkClient.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })
    await expect(networkClient.purgePersonalVault('proof')).rejects.toMatchObject({
      code: 'NETWORK'
    })
    expect(networkFetch).toHaveBeenCalledTimes(1)

    type RequestJsonProbe = {
      requestJson(method: string, url: string, request: { body?: JsonObject }): Promise<JsonValue>
    }
    const probeClient = new BitwardenHttpClient({ server: 'us', fetch: vi.fn<FetchLike>() })
    let capturedBody: JsonObject | undefined
    vi.spyOn(probeClient as unknown as RequestJsonProbe, 'requestJson').mockImplementation(
      async (_method, _url, request) => {
        capturedBody = request.body
        throw new BitwardenHttpError('NETWORK')
      }
    )
    await expect(probeClient.purgePersonalVault('sensitive-proof')).rejects.toMatchObject({
      code: 'NETWORK'
    })
    expect(capturedBody).toBeDefined()
    expect(Object.getPrototypeOf(capturedBody)).toBeNull()
    expect(capturedBody?.masterPasswordHash).toBe('')
  })

  it('deauthorizes all sessions with the exact non-retryable empty response contract', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(json({ message: 'response lost' }, 503))
    const client = new BitwardenHttpClient({
      server: 'https://vault.example.test/bw',
      fetch,
      maxRetries: 3
    })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.deauthorizeAllSessions('fresh-proof')).resolves.toBeUndefined()
    await expect(client.deauthorizeAllSessions('fresh-proof')).resolves.toBeUndefined()
    await expect(client.deauthorizeAllSessions('fresh-proof')).rejects.toMatchObject({
      code: 'NETWORK',
      status: 503
    })

    expect(fetch).toHaveBeenCalledTimes(3)
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([
      'https://vault.example.test/bw/api/accounts/security-stamp',
      'https://vault.example.test/bw/api/accounts/security-stamp',
      'https://vault.example.test/bw/api/accounts/security-stamp'
    ])
    expect(fetch.mock.calls[0]?.[1]).toMatchObject({ method: 'POST' })
    expect(new Headers(fetch.mock.calls[0]?.[1]?.headers).get('authorization')).toBe(
      'Bearer access'
    )
    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toEqual({
      masterPasswordHash: 'fresh-proof'
    })
  })

  it('rejects unsafe session-deauthorization proofs and nonempty successful responses', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(json({ deauthorized: true }))
      .mockResolvedValueOnce(new Response(null, { status: 201 }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    for (const proof of [
      '',
      'proof\0suffix',
      'proof\r',
      'proof\n',
      'x'.repeat(301),
      'é'.repeat(151)
    ]) {
      await expect(client.deauthorizeAllSessions(proof)).rejects.toMatchObject({
        code: 'INVALID_RESPONSE'
      })
    }
    await expect(client.deauthorizeAllSessions(new String('proof') as never)).rejects.toMatchObject(
      {
        code: 'INVALID_RESPONSE'
      }
    )
    expect(fetch).not.toHaveBeenCalled()

    await expect(client.deauthorizeAllSessions('x'.repeat(300))).resolves.toBeUndefined()
    await expect(client.deauthorizeAllSessions('é'.repeat(150))).resolves.toBeUndefined()
    await expect(client.deauthorizeAllSessions('valid-proof')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    await expect(client.deauthorizeAllSessions('valid-proof')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    expect(fetch).toHaveBeenCalledTimes(4)
  })

  it('normalizes definitive deauthorization proof failures and clears its request body', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json({ message: 'Invalid password' }, 400))
      .mockResolvedValueOnce(json({ message: 'Forbidden' }, 403))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.deauthorizeAllSessions('wrong-proof')).rejects.toMatchObject({
      code: 'USER_VERIFICATION_FAILED',
      status: 400
    })
    await expect(client.deauthorizeAllSessions('valid-proof')).rejects.toMatchObject({
      code: 'FORBIDDEN',
      status: 403
    })

    type RequestJsonProbe = {
      requestJson(method: string, url: string, request: { body?: JsonObject }): Promise<JsonValue>
    }
    const probeClient = new BitwardenHttpClient({ server: 'us', fetch: vi.fn<FetchLike>() })
    let capturedBody: JsonObject | undefined
    vi.spyOn(probeClient as unknown as RequestJsonProbe, 'requestJson').mockImplementation(
      async (_method, _url, request) => {
        capturedBody = request.body
        throw new BitwardenHttpError('ABORTED')
      }
    )
    await expect(probeClient.deauthorizeAllSessions('sensitive-proof')).rejects.toMatchObject({
      code: 'ABORTED'
    })
    expect(capturedBody).toBeDefined()
    expect(Object.getPrototypeOf(capturedBody)).toBeNull()
    expect(capturedBody?.masterPasswordHash).toBe('')
  })

  it('does not mark a pre-aborted deauthorization request as dispatched', async () => {
    const fetch = vi.fn<FetchLike>()
    const onDispatch = vi.fn()
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })
    const controller = new AbortController()
    controller.abort()

    await expect(
      client.deauthorizeAllSessions('valid-proof', controller.signal, onDispatch)
    ).rejects.toMatchObject({ code: 'ABORTED' })
    expect(fetch).not.toHaveBeenCalled()
    expect(onDispatch).not.toHaveBeenCalled()
  })

  it('uses bounded personal cipher bulk lifecycle routes and validates list state', async () => {
    const ids = ['30000000-0000-4000-8000-000000000001', '30000000-0000-4000-8000-000000000002']
    const rows = ids.map((id) => ({
      id,
      organizationId: null,
      deletedDate: null,
      archivedDate: '2026-07-17T00:00:00.000Z'
    }))
    const fetch = vi.fn<FetchLike>().mockImplementation(async (url) => {
      if (url.endsWith('/restore')) {
        return json({
          data: rows.map((row) => ({ ...row, archivedDate: null })),
          object: 'list',
          continuationToken: null
        })
      }
      if (url.endsWith('/archive')) {
        return json({ data: rows, object: 'list', continuationToken: null })
      }
      if (url.endsWith('/unarchive')) {
        return json({
          data: rows.map((row) => ({ ...row, archivedDate: null })),
          object: 'list',
          continuationToken: null
        })
      }
      return new Response(null, { status: 204 })
    })
    const client = new BitwardenHttpClient({ server: 'https://vault.example.test', fetch })
    client.setSession({ accessToken: 'a', refreshToken: 'r', expiresAt: 1 })

    await client.bulkSoftDeleteCiphers(ids)
    await expect(client.bulkRestoreCiphers(ids)).resolves.toHaveLength(2)
    await client.bulkMoveCiphers(ids, '20000000-0000-4000-8000-000000000001')
    await expect(client.bulkArchiveCiphers(ids)).resolves.toHaveLength(2)
    await expect(client.bulkUnarchiveCiphers(ids)).resolves.toHaveLength(2)
    await client.bulkHardDeleteCiphers(ids)

    expect(fetch.mock.calls.map(([url, init]) => `${init?.method} ${url}`)).toEqual([
      'PUT https://vault.example.test/api/ciphers/delete',
      'PUT https://vault.example.test/api/ciphers/restore',
      'POST https://vault.example.test/api/ciphers/move',
      'PUT https://vault.example.test/api/ciphers/archive',
      'PUT https://vault.example.test/api/ciphers/unarchive',
      'POST https://vault.example.test/api/ciphers/delete'
    ])
    expect(JSON.parse(String(fetch.mock.calls[2]?.[1]?.body))).toEqual({
      ids,
      folderId: '20000000-0000-4000-8000-000000000001'
    })
  })

  it('rejects unsafe bulk cipher inputs and ambiguous bulk responses without retrying', async () => {
    const id = '30000000-0000-4000-8000-000000000001'
    const otherId = '30000000-0000-4000-8000-000000000002'
    const client = new BitwardenHttpClient({ server: 'us', fetch: vi.fn<FetchLike>() })
    client.setSession({ accessToken: 'a', refreshToken: 'r', expiresAt: 1 })
    await expect(client.bulkSoftDeleteCiphers([])).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    await expect(client.bulkSoftDeleteCiphers([id, id])).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    await expect(client.bulkSoftDeleteCiphers(['not-a-uuid'])).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    await expect(
      client.bulkSoftDeleteCiphers(
        Array.from(
          { length: 501 },
          (_, index) => `30000000-0000-4000-8000-${index.toString().padStart(12, '0')}`
        )
      )
    ).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })

    const nonEmptyFetch = vi.fn<FetchLike>().mockResolvedValue(json({ ok: true }))
    const nonEmptyClient = new BitwardenHttpClient({ server: 'us', fetch: nonEmptyFetch })
    nonEmptyClient.setSession({ accessToken: 'a', refreshToken: 'r', expiresAt: 1 })
    await expect(nonEmptyClient.bulkMoveCiphers([id], null)).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })

    const mismatchedFetch = vi.fn<FetchLike>().mockResolvedValue(
      json({
        data: [{ id: otherId, organizationId: null, deletedDate: null, archivedDate: null }],
        object: 'list',
        continuationToken: null
      })
    )
    const mismatchedClient = new BitwardenHttpClient({ server: 'us', fetch: mismatchedFetch })
    mismatchedClient.setSession({ accessToken: 'a', refreshToken: 'r', expiresAt: 1 })
    await expect(mismatchedClient.bulkRestoreCiphers([id])).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })

    const partialFailureFetch = vi
      .fn<FetchLike>()
      .mockResolvedValue(json({ message: 'partial' }, 503))
    const partialFailureClient = new BitwardenHttpClient({
      server: 'us',
      fetch: partialFailureFetch
    })
    partialFailureClient.setSession({ accessToken: 'a', refreshToken: 'r', expiresAt: 1 })
    await expect(partialFailureClient.bulkHardDeleteCiphers([id])).rejects.toMatchObject({
      code: 'NETWORK',
      status: 503
    })
    expect(partialFailureFetch).toHaveBeenCalledTimes(1)
  })

  it('rejects an oversized JSON response before buffering its body', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      new Response('{}', {
        headers: { 'content-length': String(128 * 1024 * 1024 + 1) }
      })
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    await expect(client.prelogin('person@example.test')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
  })

  it('matches the official query-free sync request and asks proxies for JSON', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(json({}))
    const client = new BitwardenHttpClient({ server: 'https://vault.example.test', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.sync()).resolves.toEqual({})
    expect(fetch.mock.calls[0]?.[0]).toBe('https://vault.example.test/api/sync')
    expect(new Headers(fetch.mock.calls[0]?.[1]?.headers).get('accept')).toBe('application/json')
  })

  it.each([
    ['empty', () => new Response(null, { status: 200 }), 'empty-response'],
    ['non-JSON', () => new Response('<html>not json</html>', { status: 200 }), 'invalid-json'],
    ['non-object JSON', () => json([]), 'non-object-response']
  ] as const)(
    'classifies a %s sync envelope without retaining its body',
    async (_, response, reason) => {
      const fetch = vi.fn<FetchLike>().mockResolvedValue(response())
      const client = new BitwardenHttpClient({ server: 'us', fetch })
      client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

      const error = await client.sync().catch((caught: unknown) => caught)
      expect(error).toMatchObject({ code: 'INVALID_RESPONSE', invalidResponseReason: reason })
      expect(JSON.stringify(error)).not.toContain('not json')
    }
  )

  it.each([
    new Error('truncated response containing deployment details'),
    new DOMException('remote stream aborted with deployment details', 'AbortError')
  ])('maps a truncated sync response stream to a network failure', async (streamError) => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('{"profile":'))
            controller.error(streamError)
          }
        }),
        { headers: { 'content-type': 'application/json' } }
      )
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    const error = await client.sync().catch((caught: unknown) => caught)
    expect(error).toMatchObject({ code: 'NETWORK' })
    expect(JSON.stringify(error)).not.toContain('deployment details')
  })

  it('retries one interrupted successful sync response and then returns the snapshot', async () => {
    const interrupted = new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('{"profile":'))
          controller.error(new Error('transient proxy stream failure'))
        }
      }),
      { headers: { 'content-type': 'application/json' } }
    )
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(interrupted)
      .mockResolvedValueOnce(json({}))
    const client = new BitwardenHttpClient({ server: 'us', fetch, maxRetries: 0 })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.sync()).resolves.toEqual({})
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it('uses the bounded two-minute transport window only for sync snapshots', async () => {
    const timeoutValues: number[] = []
    const timeout = vi.spyOn(AbortSignal, 'timeout').mockImplementation((milliseconds) => {
      timeoutValues.push(milliseconds)
      return new AbortController().signal
    })
    const fetch = vi.fn<FetchLike>(async (url) =>
      url.endsWith('/accounts/revision-date')
        ? json({ revisionDate: '2026-07-30T00:00:00.000Z' })
        : json({})
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    try {
      await client.sync()
      await client.revisionDate()
    } finally {
      timeout.mockRestore()
    }

    expect(timeoutValues).toEqual([120_000, 30_000])
  })

  it('reports a sync snapshot above the compatibility boundary as too large', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(
      new Response('{}', {
        headers: { 'content-length': String(512 * 1024 * 1024 + 1) }
      })
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 60_000 })

    await expect(client.sync()).rejects.toMatchObject({ code: 'TOO_LARGE' })
  })

  it('fetches fresh attachment metadata, then downloads relative encrypted bytes without auth', async () => {
    const encryptedBytes = Uint8Array.from([2, 10, 20, 30])
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          id: 'attachment id',
          url: 'attachments/cipher-id/attachment-id?token=signed',
          fileName: '2.encrypted-name',
          key: '2.wrapped-key',
          size: String(encryptedBytes.byteLength),
          sizeName: '4 B'
        })
      )
      .mockResolvedValueOnce(
        new Response(encryptedBytes, {
          status: 200,
          headers: { 'content-length': String(encryptedBytes.byteLength) }
        })
      )
    const client = new BitwardenHttpClient({
      server: 'https://vault.example.test/bw',
      fetch
    })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })

    const result = await client.prepareAttachmentDownload('cipher id', 'attachment id')
    const data = await result.download()

    expect(result).toMatchObject({
      id: 'attachment id',
      fileName: '2.encrypted-name',
      key: '2.wrapped-key',
      size: 4,
      sizeName: '4 B'
    })
    expect(data).toEqual(Buffer.from(encryptedBytes))
    expect(fetch.mock.calls[0]?.[0]).toBe(
      'https://vault.example.test/bw/api/ciphers/cipher%20id/attachment/attachment%20id'
    )
    expect(fetch.mock.calls[1]?.[0]).toBe(
      'https://vault.example.test/bw/attachments/cipher-id/attachment-id?token=signed'
    )
    const metadataHeaders = new Headers(fetch.mock.calls[0]?.[1]?.headers)
    const downloadHeaders = new Headers(fetch.mock.calls[1]?.[1]?.headers)
    expect(metadataHeaders.get('authorization')).toBe('Bearer access')
    expect(downloadHeaders.get('authorization')).toBeNull()
    expect(fetch.mock.calls[1]?.[1]).toMatchObject({
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer'
    })
  })

  it('allows Azure-like HTTPS signed origins without forwarding authentication', async () => {
    const metadata = {
      id: 'attachment-id',
      url: 'https://bearwarden.blob.core.windows.net/attachments/file?signature=secret',
      fileName: '2.encrypted-name',
      key: null,
      size: '1'
    }
    const allowedFetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json(metadata))
      .mockResolvedValueOnce(
        new Response(Uint8Array.from([2]), { headers: { 'content-length': '1' } })
      )
    const allowed = new BitwardenHttpClient({
      server: 'us',
      fetch: allowedFetch
    })
    allowed.setSession({ accessToken: 'a', refreshToken: 'r', expiresAt: 1 })
    const prepared = await allowed.prepareAttachmentDownload('cipher-id', 'attachment-id')
    await expect(prepared.download()).resolves.toEqual(Buffer.from([2]))
    expect(new Headers(allowedFetch.mock.calls[1]?.[1]?.headers).get('authorization')).toBeNull()
  })

  it.each([
    'https://localhost/attachment',
    'https://127.0.0.1/attachment',
    'https://10.0.0.7/attachment',
    'https://169.254.169.254/latest/meta-data',
    'https://192.168.1.5/attachment',
    'https://[::1]/attachment',
    'https://[fd00::1]/attachment',
    'https://[::ffff:7f00:1]/attachment',
    'https://[ff02::1]/attachment'
  ])('rejects unconfigured local or private attachment URL %s', async (url) => {
    const fetch = vi.fn<FetchLike>().mockResolvedValueOnce(
      json({
        id: 'attachment-id',
        url,
        fileName: '2.encrypted-name',
        key: null,
        size: '1'
      })
    )
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'a', refreshToken: 'r', expiresAt: 1 })
    await expect(
      client.prepareAttachmentDownload('cipher-id', 'attachment-id')
    ).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('rejects oversized, truncated, redirected, or aborted attachment downloads', async () => {
    const metadata = (size: string): Record<string, string | null> => ({
      id: 'attachment-id',
      url: '/attachments/cipher-id/attachment-id',
      fileName: '2.encrypted-name',
      key: null,
      size
    })
    const oversized = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json(metadata(String(500 * 1024 * 1024 + 66))))
    const oversizedClient = new BitwardenHttpClient({ server: 'us', fetch: oversized })
    oversizedClient.setSession({ accessToken: 'a', refreshToken: 'r', expiresAt: 1 })
    await expect(
      oversizedClient.prepareAttachmentDownload('cipher-id', 'attachment-id')
    ).rejects.toMatchObject({ code: 'TOO_LARGE' })

    const truncated = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json(metadata('4')))
      .mockResolvedValueOnce(new Response(Uint8Array.from([1, 2, 3])))
    const truncatedClient = new BitwardenHttpClient({ server: 'us', fetch: truncated })
    truncatedClient.setSession({ accessToken: 'a', refreshToken: 'r', expiresAt: 1 })
    const truncatedDownload = await truncatedClient.prepareAttachmentDownload(
      'cipher-id',
      'attachment-id'
    )
    await expect(truncatedDownload.download()).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })

    const controller = new AbortController()
    const aborted = vi.fn<FetchLike>().mockImplementation(async (_url, init) => {
      if (aborted.mock.calls.length === 1) return json(metadata('4'))
      controller.abort()
      throw init?.signal?.reason ?? new DOMException('aborted', 'AbortError')
    })
    const abortedClient = new BitwardenHttpClient({ server: 'us', fetch: aborted })
    abortedClient.setSession({ accessToken: 'a', refreshToken: 'r', expiresAt: 1 })
    const abortedDownload = await abortedClient.prepareAttachmentDownload(
      'cipher-id',
      'attachment-id',
      controller.signal
    )
    await expect(abortedDownload.download()).rejects.toMatchObject({ code: 'ABORTED' })
  })

  it('streams attachment response chunks without joining them into one Buffer', async () => {
    const size = 2 * 1024 * 1024 + 3
    const payload = Buffer.alloc(size, 0x6b)
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          id: 'attachment-id',
          url: '/attachments/cipher-id/attachment-id',
          fileName: '2.encrypted-name',
          key: null,
          size: String(size)
        })
      )
      .mockResolvedValueOnce(
        new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(payload.subarray(0, 1024 * 1024))
              controller.enqueue(payload.subarray(1024 * 1024))
              controller.close()
            }
          }),
          { headers: { 'content-length': String(size) } }
        )
      )
    const client = new BitwardenHttpClient({ server: 'https://vault.example.test', fetch })
    client.setSession({ accessToken: 'a', refreshToken: 'r', expiresAt: 1 })

    const prepared = await client.prepareAttachmentDownload('cipher-id', 'attachment-id')
    const source = await prepared.downloadStream()
    const chunks: Buffer[] = []
    for await (const chunk of source.chunks()) chunks.push(Buffer.from(chunk))

    expect(chunks).toHaveLength(2)
    expect(Buffer.concat(chunks)).toEqual(payload)
  })

  it('cancels the attachment response when a downstream stream consumer stops early', async () => {
    const cancel = vi.fn()
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          id: 'attachment-id',
          url: '/attachments/cipher-id/attachment-id',
          fileName: '2.encrypted-name',
          key: null,
          size: '4'
        })
      )
      .mockResolvedValueOnce(
        new Response(
          new ReadableStream({
            pull(controller) {
              controller.enqueue(Uint8Array.from([1, 2]))
            },
            cancel
          })
        )
      )
    const client = new BitwardenHttpClient({ server: 'https://vault.example.test', fetch })
    client.setSession({ accessToken: 'a', refreshToken: 'r', expiresAt: 1 })
    const prepared = await client.prepareAttachmentDownload('cipher-id', 'attachment-id')
    const source = await prepared.downloadStream()
    const iterator = source.chunks()[Symbol.asyncIterator]()

    await expect(iterator.next()).resolves.toMatchObject({ done: false })
    await iterator.return?.()
    expect(cancel).toHaveBeenCalledOnce()
  })

  it('creates V2 attachment metadata and uploads Direct multipart bytes to the fixed API route', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({
          attachmentId: 'attachment-id',
          url: '/ciphers/cipher-id/attachment/attachment-id',
          fileUploadType: 'Direct'
        })
      )
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    const client = new BitwardenHttpClient({ server: 'https://vault.example.test', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })

    await expect(
      client.createAttachment('cipher id', {
        key: '2.encrypted-key',
        fileName: '2.encrypted-name',
        fileSize: 65,
        lastKnownRevisionDate: '2026-07-16T01:02:03.000Z'
      })
    ).resolves.toEqual({
      attachmentId: 'attachment-id',
      url: '/ciphers/cipher-id/attachment/attachment-id',
      fileUploadType: 'direct'
    })
    const metadataInit = fetch.mock.calls[0]?.[1]
    expect(fetch.mock.calls[0]?.[0]).toBe(
      'https://vault.example.test/api/ciphers/cipher%20id/attachment/v2'
    )
    expect(JSON.parse(String(metadataInit?.body))).toEqual({
      key: '2.encrypted-key',
      fileName: '2.encrypted-name',
      fileSize: 65,
      adminRequest: false,
      lastKnownRevisionDate: '2026-07-16T01:02:03.000Z'
    })

    const encryptedBytes = Buffer.from([2, 10, 20, 30])
    await client.uploadAttachmentDirect(
      'cipher id',
      'attachment id',
      '2.encrypted-name',
      encryptedBytes
    )
    expect(fetch.mock.calls[1]?.[0]).toBe(
      'https://vault.example.test/api/ciphers/cipher%20id/attachment/attachment%20id'
    )
    const directInit = fetch.mock.calls[1]?.[1]
    const directHeaders = new Headers(directInit?.headers)
    expect(directHeaders.get('authorization')).toBe('Bearer access')
    expect(directHeaders.get('content-type')).toBeNull()
    expect(directInit).toMatchObject({
      method: 'POST',
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error'
    })
    const form = directInit?.body as FormData
    const file = form.get('data') as Blob & { name: string }
    expect(file.name).toBe('2.encrypted-name')
    expect(file.type).toBe('application/octet-stream')
    expect(Buffer.from(await file.arrayBuffer())).toEqual(encryptedBytes)
  })

  it('refreshes a rejected Direct upload once without using a server-issued external URL', async () => {
    const rejected = cancelableResponse(401, undefined, new Promise<void>(() => undefined))
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(rejected.response)
      .mockResolvedValueOnce(
        json({ access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 60 })
      )
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    const client = new BitwardenHttpClient({ server: 'us', fetch, now: () => 0 })
    client.setSession({ accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1 })

    await client.uploadAttachmentDirect(
      'cipher-id',
      'attachment-id',
      '2.encrypted-name',
      Buffer.from([2])
    )

    expect(fetch.mock.calls.map(([url]) => url)).toEqual([
      'https://api.bitwarden.com/ciphers/cipher-id/attachment/attachment-id',
      'https://identity.bitwarden.com/connect/token',
      'https://api.bitwarden.com/ciphers/cipher-id/attachment/attachment-id'
    ])
    expect(new Headers(fetch.mock.calls[0]?.[1]?.headers).get('authorization')).toBe(
      'Bearer old-access'
    )
    expect(new Headers(fetch.mock.calls[2]?.[1]?.headers).get('authorization')).toBe(
      'Bearer new-access'
    )
    expect(rejected.cancel).toHaveBeenCalledOnce()
  })

  it('uploads Azure blobs only to public HTTPS signed URLs without authentication leakage', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(new Response(null, { status: 201 }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({
      accessToken: 'secret-access',
      refreshToken: 'secret-refresh',
      expiresAt: 1
    })
    const encryptedBytes = Buffer.from([2, 10, 20, 30])

    await client.uploadAttachmentAzure(
      'https://bearwarden.blob.core.windows.net/container/file?sv=2023-11-03&sig=signed',
      encryptedBytes
    )

    const [url, init] = fetch.mock.calls[0]!
    expect(url).toBe(
      'https://bearwarden.blob.core.windows.net/container/file?sv=2023-11-03&sig=signed'
    )
    const uploadHeaders = new Headers(init?.headers)
    expect(uploadHeaders.get('authorization')).toBeNull()
    expect(uploadHeaders.get('cookie')).toBeNull()
    expect(uploadHeaders.get('bitwarden-client-name')).toBeNull()
    expect(uploadHeaders.get('x-ms-blob-type')).toBe('BlockBlob')
    expect(uploadHeaders.get('x-ms-version')).toBe('2023-11-03')
    expect(init).toMatchObject({
      method: 'PUT',
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer'
    })
    expect(Buffer.from(await (init?.body as Blob).arrayBuffer())).toEqual(encryptedBytes)
  })

  it('rejects unsafe, unsuccessful, oversized, or aborted Azure uploads', async () => {
    const fetch = vi.fn<FetchLike>().mockResolvedValue(new Response(null, { status: 200 }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    const bytes = Buffer.from([2])

    for (const url of [
      '/relative-upload',
      'http://blob.example.test/file?sig=signed',
      'https://127.0.0.1/file?sig=signed',
      'https://169.254.169.254/file?sig=signed',
      'https://[::ffff:7f00:1]/file?sig=signed',
      'https://[ff02::1]/file?sig=signed'
    ]) {
      await expect(client.uploadAttachmentAzure(url, bytes)).rejects.toMatchObject({
        code: 'INVALID_RESPONSE'
      })
    }
    await expect(
      client.uploadAttachmentAzure('https://blob.example.test/file?sig=signed', bytes)
    ).rejects.toMatchObject({ code: 'NETWORK', status: 200 })
    const oversizedBlob = new Blob()
    Object.defineProperty(oversizedBlob, 'size', { value: 500 * 1024 * 1024 + 66 })
    await expect(
      client.uploadAttachmentAzure('https://blob.example.test/file?sig=signed', oversizedBlob)
    ).rejects.toMatchObject({ code: 'TOO_LARGE' })

    const controller = new AbortController()
    controller.abort()
    await expect(
      client.uploadAttachmentAzure(
        'https://blob.example.test/file?sig=signed',
        bytes,
        controller.signal
      )
    ).rejects.toMatchObject({ code: 'ABORTED' })
  })

  it('deletes an attachment for rollback and strictly extracts the returned cipher', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json({ cipher: { id: 'cipher-id', name: '2.encrypted' } }))
      .mockResolvedValueOnce(json({ object: 'cipher' }))
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })

    await expect(client.deleteAttachment('cipher id', 'attachment id')).resolves.toEqual({
      id: 'cipher-id',
      name: '2.encrypted'
    })
    expect(fetch.mock.calls[0]?.[0]).toBe(
      'https://api.bitwarden.com/ciphers/cipher%20id/attachment/attachment%20id'
    )
    expect(fetch.mock.calls[0]?.[1]?.method).toBe('DELETE')
    await expect(client.deleteAttachment('cipher-id', 'attachment-id')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
  })

  it('maps attachment quota and disabled failures without retaining server messages', async () => {
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(
        json({ message: 'Attachment storage limit reached! account-specific detail' }, 400)
      )
      .mockResolvedValueOnce(
        json({ message: 'Attachments are disabled for account-specific detail' }, 400)
      )
    const client = new BitwardenHttpClient({ server: 'us', fetch })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })
    const request = {
      key: '2.encrypted-key',
      fileName: '2.encrypted-name',
      fileSize: 65,
      lastKnownRevisionDate: '2026-07-16T01:02:03.000Z'
    }

    for (const expectedCode of ['STORAGE_LIMIT', 'ATTACHMENT_REJECTED']) {
      try {
        await client.createAttachment('cipher-id', request)
        throw new Error('expected attachment creation to fail')
      } catch (error) {
        expect(error).toMatchObject({ code: expectedCode, status: 400, details: undefined })
        expect((error as Error).message).not.toContain('account-specific')
      }
    }
  })

  it('rejects incomplete or unknown attachment upload descriptors', async () => {
    for (const response of [
      { url: '/upload', fileUploadType: 0 },
      { attachmentId: 'attachment-id', fileUploadType: 0 },
      { attachmentId: 'attachment-id', url: '/upload', fileUploadType: 2 },
      { attachmentId: 'attachment-id', url: ' /upload', fileUploadType: 'Direct' }
    ]) {
      const fetch = vi.fn<FetchLike>().mockResolvedValue(json(response))
      const client = new BitwardenHttpClient({ server: 'us', fetch })
      client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })
      await expect(
        client.createAttachment('cipher-id', {
          key: '2.encrypted-key',
          fileName: '2.encrypted-name',
          fileSize: 65,
          lastKnownRevisionDate: '2026-07-16T01:02:03.000Z'
        })
      ).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
    }
  })

  it('preserves attachment permission, absence, conflict, abort, and size failures', async () => {
    for (const [status, code] of [
      [403, 'FORBIDDEN'],
      [404, 'NOT_FOUND'],
      [409, 'CONFLICT']
    ] as const) {
      const fetch = vi.fn<FetchLike>().mockResolvedValue(json({ message: 'hidden' }, status))
      const client = new BitwardenHttpClient({ server: 'us', fetch })
      client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })
      await expect(client.deleteAttachment('cipher-id', 'attachment-id')).rejects.toMatchObject({
        code,
        status
      })
    }

    const client = new BitwardenHttpClient({ server: 'us', fetch: vi.fn<FetchLike>() })
    client.setSession({ accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 })
    const controller = new AbortController()
    controller.abort()
    await expect(
      client.uploadAttachmentDirect(
        'cipher-id',
        'attachment-id',
        '2.encrypted-name',
        Buffer.from([2]),
        controller.signal
      )
    ).rejects.toMatchObject({ code: 'ABORTED' })
    await expect(
      client.createAttachment('cipher-id', {
        key: '2.encrypted-key',
        fileName: '2.encrypted-name',
        fileSize: 500 * 1024 * 1024 + 66,
        lastKnownRevisionDate: '2026-07-16T01:02:03.000Z'
      })
    ).rejects.toMatchObject({ code: 'TOO_LARGE' })
    const oversizedBlob = new Blob()
    Object.defineProperty(oversizedBlob, 'size', { value: 500 * 1024 * 1024 + 66 })
    await expect(
      client.uploadAttachmentDirect('cipher-id', 'attachment-id', '2.encrypted-name', oversizedBlob)
    ).rejects.toMatchObject({ code: 'TOO_LARGE' })
  })
})
