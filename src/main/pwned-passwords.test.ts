import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  hashPasswordForPwnedLookup,
  hashPasswordsForPwnedLookup,
  PwnedPasswordsClient,
  type PwnedPasswordsFetch
} from './pwned-passwords'

const PASSWORD_HASH = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8'

function rangeResponse(lines: readonly string[], separator = '\r\n'): Response {
  return new Response(`${lines.join(separator)}${separator}`, {
    status: 200,
    headers: { 'content-type': 'text/plain' }
  })
}

function abortingFetch(): ReturnType<typeof vi.fn<PwnedPasswordsFetch>> {
  return vi.fn<PwnedPasswordsFetch>().mockImplementation(
    async (_url, init) =>
      new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal
        if (signal?.aborted) {
          reject(signal.reason)
          return
        }
        signal?.addEventListener('abort', () => reject(signal.reason), { once: true })
      })
  )
}

afterEach(() => {
  vi.useRealTimers()
})

describe('Pwned Passwords client', () => {
  it('matches the official SHA-1 password vector', () => {
    expect(hashPasswordForPwnedLookup('password')).toBe(PASSWORD_HASH)
    expect(hashPasswordsForPwnedLookup(['password', 'password'])).toEqual([
      PASSWORD_HASH,
      PASSWORD_HASH
    ])
  })

  it('uses only the five-character prefix with anonymous padded fixed-origin requests', async () => {
    const fetcher = vi
      .fn<PwnedPasswordsFetch>()
      .mockResolvedValue(rangeResponse([`${PASSWORD_HASH.slice(5)}:42`, `${'0'.repeat(35)}:0`]))
    const client = new PwnedPasswordsClient({ fetch: fetcher })

    await expect(client.lookupSha1Hashes([PASSWORD_HASH])).resolves.toEqual([42])

    expect(fetcher).toHaveBeenCalledOnce()
    expect(fetcher.mock.calls[0]?.[0]).toBe('https://api.pwnedpasswords.com/range/5BAA6')
    const init = fetcher.mock.calls[0]?.[1]
    const headers = new Headers(init?.headers)
    expect(init).toMatchObject({
      method: 'GET',
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer'
    })
    expect(headers.get('add-padding')).toBe('true')
    expect(headers.get('accept')).toBe('text/plain')
    expect(headers.get('user-agent')).toBe('BearWarden')
    expect(headers.has('authorization')).toBe(false)
    expect(headers.has('cookie')).toBe(false)
    expect(JSON.stringify(fetcher.mock.calls)).not.toContain(PASSWORD_HASH)
  })

  it('accepts LF and CRLF bodies, returns zero for padding or missing suffixes, and preserves order', async () => {
    const first = `AAAAA${'1'.repeat(35)}`
    const second = `BBBBB${'2'.repeat(35)}`
    const padding = `CCCCC${'3'.repeat(35)}`
    const missing = `AAAAA${'4'.repeat(35)}`
    const fetcher = vi.fn<PwnedPasswordsFetch>().mockImplementation(async (url) => {
      if (url.endsWith('AAAAA')) return rangeResponse([`${'1'.repeat(35)}:7`], '\n')
      if (url.endsWith('BBBBB')) return rangeResponse([`${'2'.repeat(35)}:11`])
      return rangeResponse([`${'3'.repeat(35)}:0`])
    })

    await expect(
      new PwnedPasswordsClient({ fetch: fetcher }).lookupSha1Hashes([
        second,
        padding,
        missing,
        first
      ])
    ).resolves.toEqual([11, 0, 0, 7])
  })

  it('fetches each shared prefix once and aligns duplicate hashes to their input indices', async () => {
    const first = `ABCDE${'1'.repeat(35)}`
    const second = `ABCDE${'2'.repeat(35)}`
    const fetcher = vi
      .fn<PwnedPasswordsFetch>()
      .mockResolvedValue(rangeResponse([`${'1'.repeat(35)}:3`, `${'2'.repeat(35)}:5`]))

    await expect(
      new PwnedPasswordsClient({ fetch: fetcher }).lookupSha1Hashes([second, first, second, first])
    ).resolves.toEqual([5, 3, 5, 3])
    expect(fetcher).toHaveBeenCalledOnce()
  })

  it('never exceeds eight concurrent prefix requests', async () => {
    let inFlight = 0
    let maximumInFlight = 0
    const releases: (() => void)[] = []
    const fetcher = vi.fn<PwnedPasswordsFetch>().mockImplementation(
      async () =>
        new Promise<Response>((resolve) => {
          inFlight += 1
          maximumInFlight = Math.max(maximumInFlight, inFlight)
          releases.push(() => {
            inFlight -= 1
            resolve(rangeResponse([`${'F'.repeat(35)}:0`]))
          })
        })
    )
    const hashes = Array.from(
      { length: 12 },
      (_, index) => `${index.toString(16).toUpperCase().padStart(5, '0')}${'A'.repeat(35)}`
    )
    const operation = new PwnedPasswordsClient({
      fetch: fetcher,
      concurrency: 99
    }).lookupSha1Hashes(hashes)

    await vi.waitFor(() => expect(releases).toHaveLength(8))
    while (releases.length > 0) {
      releases.shift()!()
      await Promise.resolve()
    }
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(12))
    while (releases.length > 0) releases.shift()!()

    await expect(operation).resolves.toEqual(Array(12).fill(0))
    expect(maximumInFlight).toBe(8)
  })

  it('maps external cancellation separately from timeout', async () => {
    const canceledFetch = abortingFetch()
    const canceledClient = new PwnedPasswordsClient({ fetch: canceledFetch })
    const controller = new AbortController()
    const canceled = canceledClient.lookupSha1Hashes([PASSWORD_HASH], controller.signal)
    controller.abort()
    await expect(canceled).rejects.toMatchObject({ code: 'ABORTED' })

    vi.useFakeTimers()
    const timedFetch = abortingFetch()
    const timed = new PwnedPasswordsClient({ fetch: timedFetch, timeoutMs: 25 }).lookupSha1Hashes([
      PASSWORD_HASH
    ])
    const timedExpectation = expect(timed).rejects.toMatchObject({ code: 'TIMEOUT' })
    await vi.advanceTimersByTimeAsync(25)
    await timedExpectation
  })

  it('rejects redirects and every non-200 status without treating them as zero exposure', async () => {
    for (const status of [302, 400, 404, 429, 503]) {
      const fetcher = vi.fn<PwnedPasswordsFetch>().mockResolvedValue(
        new Response('hidden server detail', {
          status,
          headers: status === 302 ? { location: 'http://127.0.0.1/private' } : undefined
        })
      )
      await expect(
        new PwnedPasswordsClient({ fetch: fetcher }).lookupSha1Hashes([PASSWORD_HASH])
      ).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
    }
  })

  it('rejects a successful response with a non-text media type', async () => {
    const fetcher = vi.fn<PwnedPasswordsFetch>().mockResolvedValue(
      new Response(`${PASSWORD_HASH.slice(5)}:42`, {
        status: 200,
        headers: { 'content-type': 'text/html' }
      })
    )

    await expect(
      new PwnedPasswordsClient({ fetch: fetcher }).lookupSha1Hashes([PASSWORD_HASH])
    ).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
  })

  it('strictly rejects malformed, duplicate, and unsafe counts', async () => {
    for (const body of [
      `${'A'.repeat(34)}:1`,
      `${'a'.repeat(35)}:1`,
      `${'A'.repeat(35)}: 1`,
      `${'A'.repeat(35)}:-1`,
      `${'A'.repeat(35)}:1.5`,
      `${'A'.repeat(35)}:9007199254740992`,
      `${'A'.repeat(35)}:1\n${'A'.repeat(35)}:1`,
      '',
      `${'A'.repeat(35)}:1\n\n${'B'.repeat(35)}:2`
    ]) {
      const fetcher = vi.fn<PwnedPasswordsFetch>().mockResolvedValue(new Response(body))
      await expect(
        new PwnedPasswordsClient({ fetch: fetcher }).lookupSha1Hashes([PASSWORD_HASH])
      ).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
    }
  })

  it('rejects declared and streamed bodies over 256 KiB', async () => {
    const declared = vi.fn<PwnedPasswordsFetch>().mockResolvedValue(
      new Response(`${'A'.repeat(35)}:1`, {
        headers: { 'content-length': String(256 * 1024 + 1) }
      })
    )
    await expect(
      new PwnedPasswordsClient({ fetch: declared }).lookupSha1Hashes([PASSWORD_HASH])
    ).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })

    const streamed = vi
      .fn<PwnedPasswordsFetch>()
      .mockResolvedValue(new Response(new Uint8Array(256 * 1024 + 1)))
    await expect(
      new PwnedPasswordsClient({ fetch: streamed }).lookupSha1Hashes([PASSWORD_HASH])
    ).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
  })

  it('fails the complete batch and aborts remaining requests after any prefix fails', async () => {
    let peerAborted = false
    const fetcher = vi.fn<PwnedPasswordsFetch>().mockImplementation(async (url, init) => {
      if (url.endsWith('AAAAA')) return new Response('malformed')
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener(
          'abort',
          () => {
            peerAborted = true
            reject(init.signal?.reason)
          },
          { once: true }
        )
      })
    })
    const operation = new PwnedPasswordsClient({ fetch: fetcher }).lookupSha1Hashes([
      `AAAAA${'1'.repeat(35)}`,
      `BBBBB${'2'.repeat(35)}`
    ])

    await expect(operation).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
    expect(peerAborted).toBe(true)
  })

  it('rejects malformed, accessor-backed, and oversized hash inputs without fetching', async () => {
    const fetcher = vi.fn<PwnedPasswordsFetch>()
    const client = new PwnedPasswordsClient({ fetch: fetcher })
    const accessor: string[] = []
    Object.defineProperty(accessor, '0', {
      get: () => PASSWORD_HASH,
      enumerable: true
    })
    accessor.length = 1

    for (const hashes of [
      ['not-a-hash'],
      [PASSWORD_HASH.slice(0, 39)],
      accessor,
      Array.from({ length: 50_001 }, () => PASSWORD_HASH)
    ]) {
      await expect(client.lookupSha1Hashes(hashes)).rejects.toMatchObject({
        code: 'INVALID_INPUT'
      })
    }
    expect(() => hashPasswordForPwnedLookup('')).toThrowError(
      expect.objectContaining({ code: 'INVALID_INPUT' })
    )
    expect(() => hashPasswordsForPwnedLookup(['x'.repeat(16_385)])).toThrowError(
      expect.objectContaining({ code: 'INVALID_INPUT' })
    )
    expect(() => hashPasswordsForPwnedLookup(Array(50_001).fill('password'))).toThrowError(
      expect.objectContaining({ code: 'INVALID_INPUT' })
    )
    const passwordAccessor: string[] = []
    Object.defineProperty(passwordAccessor, '0', {
      get: () => 'password',
      enumerable: true
    })
    passwordAccessor.length = 1
    expect(() => hashPasswordsForPwnedLookup(passwordAccessor)).toThrowError(
      expect.objectContaining({ code: 'INVALID_INPUT' })
    )
    const tooMuchTotal = Array(2_049).fill('x'.repeat(16_384))
    expect(() => hashPasswordsForPwnedLookup(tooMuchTotal)).toThrowError(
      expect.objectContaining({ code: 'INVALID_INPUT' })
    )
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('does not mutate inputs or expose hashes through results and errors', async () => {
    const hashes = [PASSWORD_HASH.toLowerCase()]
    const before = [...hashes]
    const fetcher = vi
      .fn<PwnedPasswordsFetch>()
      .mockResolvedValue(rangeResponse([`${PASSWORD_HASH.slice(5)}:9`]))
    const result = await new PwnedPasswordsClient({ fetch: fetcher }).lookupSha1Hashes(hashes)

    expect(hashes).toEqual(before)
    expect(result).toEqual([9])
    expect(JSON.stringify(result)).not.toContain(PASSWORD_HASH)

    const failing = new PwnedPasswordsClient({
      fetch: vi.fn<PwnedPasswordsFetch>().mockRejectedValue(new Error(PASSWORD_HASH))
    })
    await expect(failing.lookupSha1Hashes([PASSWORD_HASH])).rejects.not.toThrow(PASSWORD_HASH)
  })
})
