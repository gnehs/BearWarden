import { mkdtemp, mkdir, readFile, rm, stat, utimes, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { TwoFactorDirectoryCache, TwoFactorDirectoryCacheError } from './two-factor-directory-cache'
import { TWO_FACTOR_DIRECTORY_TOTP_URL } from './inactive-two-factor'

const directories: string[] = []
const VALID_DATASET = JSON.stringify({
  'example.com': {
    methods: ['totp'],
    documentation: 'https://help.example.com/2fa'
  }
})

async function cachePath(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'bearwarden-2fa-cache-'))
  directories.push(directory)
  return join(directory, 'cache', 'totp-v4.json')
}

function response(body: BodyInit, init: ResponseInit = {}): Response {
  return new Response(body, {
    status: 200,
    headers: { 'content-type': 'application/json', ...init.headers },
    ...init
  })
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

describe('TwoFactorDirectoryCache', () => {
  it('fetches only the pinned official endpoint and atomically stores a mode-0600 cache', async () => {
    const path = await cachePath()
    const fetchMock = vi.fn(async () => response(VALID_DATASET))
    const cache = new TwoFactorDirectoryCache(path, { fetch: fetchMock })

    await expect(cache.getDataset()).resolves.toMatchObject({
      apiVersion: 4,
      entries: [{ domain: 'example.com' }]
    })
    expect(fetchMock).toHaveBeenCalledWith(
      TWO_FACTOR_DIRECTORY_TOTP_URL,
      expect.objectContaining({ method: 'GET', redirect: 'manual' })
    )
    expect(await readFile(path, 'utf8')).toBe(VALID_DATASET)
    expect((await stat(path)).mode & 0o777).toBe(0o600)
  })

  it('rejects an untrusted redirect response without following it', async () => {
    const path = await cachePath()
    const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      void input
      void init
      return response('', { status: 302, headers: { location: 'https://127.0.0.1/private' } })
    })
    const cache = new TwoFactorDirectoryCache(path, { fetch: fetchMock })

    await expect(cache.getDataset()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
    expect(fetchMock).toHaveBeenCalledOnce()
    expect(fetchMock.mock.calls[0]?.[0]).toBe(TWO_FACTOR_DIRECTORY_TOTP_URL)

    const followed = response(VALID_DATASET)
    Object.defineProperty(followed, 'url', { value: 'https://attacker.invalid/totp.json' })
    const finalUrl = new TwoFactorDirectoryCache(await cachePath(), {
      fetch: async () => followed
    })
    await expect(finalUrl.getDataset()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
  })

  it('rejects declared and chunked bodies above the parser byte limit', async () => {
    const declared = new TwoFactorDirectoryCache(await cachePath(), {
      fetch: async () =>
        response('{}', { headers: { 'content-length': String(4 * 1024 * 1024 + 1) } })
    })
    await expect(declared.getDataset()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })

    const chunk = new Uint8Array(1024 * 1024).fill(0x20)
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let index = 0; index < 5; index += 1) controller.enqueue(chunk)
        controller.close()
      }
    })
    const chunked = new TwoFactorDirectoryCache(await cachePath(), {
      fetch: async () => response(body)
    })
    await expect(chunked.getDataset()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
  })

  it('ignores corrupt cache and fails closed when the network is unavailable', async () => {
    const path = await cachePath()
    await mkdir(join(path, '..'), { recursive: true })
    await writeFile(path, '{"malformed":', { mode: 0o600 })
    const cache = new TwoFactorDirectoryCache(path, {
      fetch: async () => {
        throw new TypeError('offline')
      }
    })

    await expect(cache.getDataset()).rejects.toMatchObject({ code: 'UNAVAILABLE' })
  })

  it('uses a validated stale cache when refresh fails but never returns corrupt data', async () => {
    const path = await cachePath()
    await mkdir(join(path, '..'), { recursive: true })
    await writeFile(path, VALID_DATASET, { mode: 0o600 })
    const stale = new Date('2026-01-01T00:00:00.000Z')
    await utimes(path, stale, stale)
    const cache = new TwoFactorDirectoryCache(path, {
      now: () => Date.parse('2026-01-10T00:00:00.000Z'),
      fetch: async () => {
        throw new TypeError('offline')
      }
    })

    await expect(cache.getDataset()).resolves.toMatchObject({
      entries: [{ domain: 'example.com' }]
    })
  })

  it('uses a fresh validated cache without network access', async () => {
    const path = await cachePath()
    await mkdir(join(path, '..'), { recursive: true })
    await writeFile(path, VALID_DATASET, { mode: 0o600 })
    const fetchMock = vi.fn(async () => response(VALID_DATASET))
    const cache = new TwoFactorDirectoryCache(path, { fetch: fetchMock, now: () => Date.now() })

    await expect(cache.getDataset()).resolves.toMatchObject({
      entries: [{ domain: 'example.com' }]
    })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('keeps a valid live dataset usable when private cache persistence fails', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-2fa-cache-blocked-'))
    directories.push(directory)
    const blocker = join(directory, 'not-a-directory')
    await writeFile(blocker, 'blocked', { mode: 0o600 })
    const cache = new TwoFactorDirectoryCache(join(blocker, 'totp-v4.json'), {
      fetch: async () => response(VALID_DATASET)
    })

    await expect(cache.getDataset()).resolves.toMatchObject({
      entries: [{ domain: 'example.com' }]
    })
    await expect(cache.getDataset()).resolves.toMatchObject({
      entries: [{ domain: 'example.com' }]
    })
  })

  it('shares one in-flight fetch and disposal aborts every waiter', async () => {
    const path = await cachePath()
    let observedSignal: AbortSignal | undefined
    const fetchMock = vi.fn(
      async (_url: string | URL | Request, init?: RequestInit): Promise<Response> => {
        observedSignal = init?.signal ?? undefined
        return await new Promise<Response>((_resolve, reject) => {
          observedSignal?.addEventListener('abort', () =>
            reject(new DOMException('aborted', 'AbortError'))
          )
        })
      }
    )
    const cache = new TwoFactorDirectoryCache(path, { fetch: fetchMock })
    const first = cache.getDataset()
    const second = cache.getDataset()
    expect(first).toBe(second)
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledOnce())
    cache.dispose()

    await expect(first).rejects.toBeInstanceOf(TwoFactorDirectoryCacheError)
    await expect(second).rejects.toMatchObject({ code: 'DISPOSED' })
    expect(observedSignal?.aborted).toBe(true)
    await expect(cache.getDataset()).rejects.toMatchObject({ code: 'DISPOSED' })
  })

  it('opens only documentation revalidated from the current dataset', async () => {
    const opened = vi.fn()
    const cache = new TwoFactorDirectoryCache(await cachePath(), {
      fetch: async () => response(VALID_DATASET),
      openExternal: opened
    })
    await cache.openDocumentation('example.com')
    expect(opened).toHaveBeenCalledWith('https://help.example.com/2fa')

    await expect(cache.openDocumentation('attacker.invalid')).rejects.toMatchObject({
      code: 'DOCUMENTATION_NOT_FOUND'
    })
    expect(opened).toHaveBeenCalledOnce()
  })
})
