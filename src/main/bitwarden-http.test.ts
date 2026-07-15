import { describe, expect, it, vi } from 'vitest'
import {
  BitwardenHttpClient,
  BitwardenHttpError,
  resolveBitwardenUrls,
  type FetchLike
} from './bitwarden-http'

function json(body: unknown, status = 200, headers?: HeadersInit): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers }
  })
}

describe('resolveBitwardenUrls', () => {
  it('maps the public Bitwarden cloud URLs to their split API and identity origins', () => {
    expect(resolveBitwardenUrls('https://bitwarden.com')).toEqual({
      apiUrl: 'https://api.bitwarden.com',
      identityUrl: 'https://identity.bitwarden.com',
      webVaultUrl: 'https://vault.bitwarden.com'
    })
  })

  it('uses Bitwarden cloud origins and preserves a self-hosted reverse-proxy prefix', () => {
    expect(resolveBitwardenUrls('us').apiUrl).toBe('https://api.bitwarden.com')
    expect(resolveBitwardenUrls('eu').identityUrl).toBe('https://identity.bitwarden.eu')
    expect(resolveBitwardenUrls('https://vault.example.test/bw')).toEqual({
      apiUrl: 'https://vault.example.test/bw/api',
      identityUrl: 'https://vault.example.test/bw/identity',
      webVaultUrl: 'https://vault.example.test/bw'
    })
  })

  it('refuses insecure non-loopback origins', () => {
    expect(() => resolveBitwardenUrls('http://vault.example.test')).toThrow(BitwardenHttpError)
    expect(resolveBitwardenUrls('http://127.0.0.1:8080').apiUrl).toBe('http://127.0.0.1:8080/api')
  })
})

describe('BitwardenHttpClient', () => {
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

  it('uses the personal folder and cipher CRUD routes', async () => {
    const fetch = vi.fn<FetchLike>().mockImplementation(async () => json({ id: 'entity-id' }))
    const client = new BitwardenHttpClient({ server: 'https://vault.example.test', fetch })
    client.setSession({ accessToken: 'a', refreshToken: 'r', expiresAt: 1 })
    await client.createFolder({ name: '2.folder' })
    await client.updateFolder('folder id', { name: '2.changed' })
    await client.deleteFolder('folder id')
    await client.createCipher({ name: '2.cipher' })
    await client.updateCipher('cipher id', { name: '2.changed' })
    await client.deleteCipher('cipher id')
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([
      'https://vault.example.test/api/folders',
      'https://vault.example.test/api/folders/folder%20id',
      'https://vault.example.test/api/folders/folder%20id',
      'https://vault.example.test/api/ciphers',
      'https://vault.example.test/api/ciphers/cipher%20id',
      'https://vault.example.test/api/ciphers/cipher%20id'
    ])
  })
})
