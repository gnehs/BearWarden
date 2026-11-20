import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  DuoLoginCallbacks,
  DuoLoginError,
  parseDuoLoginCallback,
  parseDuoLoginPrompt,
  type DuoLoginPrompt
} from './duo-login'

const STATE = 'S'.repeat(32) + 'abc123'
const REDIRECT = 'https://vault.example.com/duo-redirect-connector.html?client=desktop'

function encodeSegment(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url')
}

function duoAuthUrl({
  host = 'api-1234abcd.duosecurity.com',
  state = STATE,
  redirectUri = REDIRECT,
  path = '/oauth/v1/authorize'
}: { host?: string; state?: unknown; redirectUri?: unknown; path?: string } = {}): string {
  const jwt = [
    encodeSegment({ alg: 'HS512', typ: 'JWT' }),
    encodeSegment({ state, redirect_uri: redirectUri, nonce: 'n'.repeat(64) }),
    'signature'
  ].join('.')
  const url = new URL(`https://${host}${path}`)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('client_id', 'DIXXXXXXXXXXXXXXXXXX')
  url.searchParams.set('request', jwt)
  return url.toString()
}

function prompt(provider: 2 | 6 = 2): DuoLoginPrompt {
  return parseDuoLoginPrompt(provider, { AuthUrl: duoAuthUrl() })
}

function codeOf(run: () => unknown): string | undefined {
  try {
    run()
  } catch (error) {
    return error instanceof DuoLoginError ? error.code : 'unexpected'
  }
  return undefined
}

describe('parseDuoLoginPrompt', () => {
  it('extracts the signed state and redirect base from a Duo Universal Prompt URL', () => {
    expect(prompt(6)).toEqual({
      provider: 6,
      authUrl: duoAuthUrl(),
      state: STATE,
      redirectBase: 'https://vault.example.com/duo-redirect-connector.html'
    })
    expect(
      parseDuoLoginPrompt(2, { authUrl: duoAuthUrl({ host: 'api-9f.duofederal.com' }) }).authUrl
    ).toContain('api-9f.duofederal.com')
  })

  it.each([
    ['non-Duo host', duoAuthUrl({ host: 'api-1234.duosecurity.com.evil.example' })],
    ['Duo host without api prefix', duoAuthUrl({ host: 'admin-1234.duosecurity.com' })],
    ['other path', duoAuthUrl({ path: '/frame/prompt' })],
    ['plain HTTP', duoAuthUrl().replace('https://', 'http://')],
    ['explicit port', duoAuthUrl().replace('.com/', '.com:8443/')],
    ['embedded credentials', duoAuthUrl().replace('https://', 'https://user:pass@')],
    ['missing state', duoAuthUrl({ state: null })],
    ['short state', duoAuthUrl({ state: 'short' })],
    ['state with separator', duoAuthUrl({ state: `${STATE}|x` })],
    ['non-HTTPS redirect', duoAuthUrl({ redirectUri: 'http://vault.example.com/x' })],
    ['missing redirect', duoAuthUrl({ redirectUri: null })]
  ])('rejects %s', (_label, authUrl) => {
    expect(codeOf(() => parseDuoLoginPrompt(2, { AuthUrl: authUrl }))).toBe('INVALID_PROMPT')
  })

  it('rejects missing or malformed provider data', () => {
    expect(codeOf(() => parseDuoLoginPrompt(2, null))).toBe('INVALID_PROMPT')
    expect(codeOf(() => parseDuoLoginPrompt(2, { AuthUrl: 42 }))).toBe('INVALID_PROMPT')
    expect(codeOf(() => parseDuoLoginPrompt(2, { AuthUrl: 'not a url' }))).toBe('INVALID_PROMPT')
    const withoutRequest = new URL(duoAuthUrl())
    withoutRequest.searchParams.delete('request')
    expect(codeOf(() => parseDuoLoginPrompt(2, { AuthUrl: withoutRequest.toString() }))).toBe(
      'INVALID_PROMPT'
    )
  })
})

describe('parseDuoLoginCallback', () => {
  it('accepts the redirected connector URL, the desktop deep link, and a bare pair', () => {
    const expected = `duo-code-1|${STATE}`
    expect(parseDuoLoginCallback(`${REDIRECT}&code=duo-code-1&state=${STATE}`, prompt())).toBe(
      expected
    )
    expect(
      parseDuoLoginCallback(`  bitwarden://duo-callback?code=duo-code-1&state=${STATE}\n`, prompt())
    ).toBe(expected)
    expect(parseDuoLoginCallback(`duo-code-1|${STATE}`, prompt())).toBe(expected)
  })

  it('fails closed when the state does not belong to this prompt', () => {
    const foreign = 'F'.repeat(38)
    expect(
      codeOf(() => parseDuoLoginCallback(`${REDIRECT}&code=c&state=${foreign}`, prompt()))
    ).toBe('STATE_MISMATCH')
    expect(codeOf(() => parseDuoLoginCallback(`c|${STATE}x`, prompt()))).toBe('STATE_MISMATCH')
  })

  it.each([
    ['another origin', `https://evil.example/duo-redirect-connector.html?code=c&state=${STATE}`],
    ['another path', `https://vault.example.com/other.html?code=c&state=${STATE}`],
    ['missing code', `${REDIRECT}&state=${STATE}`],
    ['empty input', '   '],
    ['three parts', `c|${STATE}|x`],
    ['whitespace in code', `c c|${STATE}`]
  ])('rejects %s as malformed', (_label, input) => {
    expect(codeOf(() => parseDuoLoginCallback(input, prompt()))).toBe('INVALID_CALLBACK')
  })
})

describe('DuoLoginCallbacks', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('resolves the waiting login with the token built from the pasted callback', async () => {
    const callbacks = new DuoLoginCallbacks()
    const waiting = callbacks.wait(prompt(), new AbortController().signal)
    expect(codeOf(() => callbacks.submit('garbage'))).toBe('INVALID_CALLBACK')
    expect(callbacks.waiting).toBe(true)
    callbacks.submit(`code-9|${STATE}`)
    await expect(waiting).resolves.toBe(`code-9|${STATE}`)
    expect(callbacks.waiting).toBe(false)
    expect(codeOf(() => callbacks.submit(`code-9|${STATE}`))).toBe('NOT_WAITING')
  })

  it('ends the login on a foreign state instead of letting the user retry', async () => {
    const callbacks = new DuoLoginCallbacks()
    const waiting = callbacks.wait(prompt(), new AbortController().signal)
    callbacks.submit(`code|${'F'.repeat(38)}`)
    await expect(waiting).rejects.toMatchObject({ code: 'STATE_MISMATCH' })
    expect(callbacks.waiting).toBe(false)
  })

  it('settles on cancel, abort, and timeout', async () => {
    const callbacks = new DuoLoginCallbacks(1000)
    const canceled = callbacks.wait(prompt(), new AbortController().signal)
    callbacks.cancel()
    await expect(canceled).rejects.toMatchObject({ code: 'CANCELED' })

    const abort = new AbortController()
    const aborted = callbacks.wait(prompt(), abort.signal)
    abort.abort()
    await expect(aborted).rejects.toMatchObject({ code: 'ABORTED' })

    const preAborted = new AbortController()
    preAborted.abort()
    await expect(callbacks.wait(prompt(), preAborted.signal)).rejects.toMatchObject({
      code: 'ABORTED'
    })

    vi.useFakeTimers()
    const timedOut = callbacks.wait(prompt(), new AbortController().signal)
    vi.advanceTimersByTime(1000)
    await expect(timedOut).rejects.toMatchObject({ code: 'TIMEOUT' })
    expect(callbacks.waiting).toBe(false)
  })

  it('cancels a superseded waiter so only the newest login can complete', async () => {
    const callbacks = new DuoLoginCallbacks()
    const first = callbacks.wait(prompt(), new AbortController().signal)
    const second = callbacks.wait(prompt(6), new AbortController().signal)
    await expect(first).rejects.toMatchObject({ code: 'CANCELED' })
    callbacks.submit(`c|${STATE}`)
    await expect(second).resolves.toBe(`c|${STATE}`)
  })
})
