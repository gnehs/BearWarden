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
      .mockResolvedValueOnce(json(metadata(String(128 * 1024 * 1024 + 1))))
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
    const fetch = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json({ error: 'invalid_token' }, 401))
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
    expect(Buffer.from(init?.body as Uint8Array)).toEqual(encryptedBytes)
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
    await expect(
      client.uploadAttachmentAzure(
        'https://blob.example.test/file?sig=signed',
        Buffer.allocUnsafe(128 * 1024 * 1024 + 1)
      )
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
        fileSize: 128 * 1024 * 1024 + 1,
        lastKnownRevisionDate: '2026-07-16T01:02:03.000Z'
      })
    ).rejects.toMatchObject({ code: 'TOO_LARGE' })
    await expect(
      client.uploadAttachmentDirect(
        'cipher-id',
        'attachment-id',
        '2.encrypted-name',
        Buffer.allocUnsafe(128 * 1024 * 1024 + 1)
      )
    ).rejects.toMatchObject({ code: 'TOO_LARGE' })
  })
})
