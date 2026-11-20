import { timingSafeEqual } from 'node:crypto'

/** Personal Duo (2) and organization Duo (6) share the Duo Universal Prompt login flow. */
export type DuoLoginProvider = 2 | 6

export const DUO_LOGIN_PROVIDERS: readonly DuoLoginProvider[] = Object.freeze([2, 6])

/** Main-process-only Duo Universal Prompt challenge from one identity token response. */
export interface DuoLoginPrompt {
  readonly provider: DuoLoginProvider
  readonly authUrl: string
  /** OAuth state signed into the authorization request; Duo echoes it to the redirect. */
  readonly state: string
  /** Origin and path of the server-configured redirect URI, without its query. */
  readonly redirectBase: string
}

export type DuoLoginErrorCode =
  | 'INVALID_PROMPT'
  | 'INVALID_CALLBACK'
  | 'STATE_MISMATCH'
  | 'NOT_WAITING'
  | 'TIMEOUT'
  | 'CANCELED'
  | 'ABORTED'

export class DuoLoginError extends Error {
  constructor(readonly code: DuoLoginErrorCode) {
    super(`Duo login failed (${code})`)
    this.name = 'DuoLoginError'
  }
}

// Vaultwarden keeps the Duo context for 300 seconds (CTX_VALIDITY_SECS in duo_oidc.rs).
export const DUO_LOGIN_TIMEOUT_MS = 5 * 60 * 1000

const MAX_DUO_URL_LENGTH = 8192
const MAX_DUO_JWT_PAYLOAD_BYTES = 8192
// Duo requires 16..1024 characters for state; codes get the same printable, bounded shape.
const DUO_TOKEN_PART = /^[\x21-\x7b\x7d\x7e]{1,1024}$/u
const DUO_STATE = /^[\x21-\x7b\x7d\x7e]{16,1024}$/u
// The host rule the official web-vault connector enforces before it redirects to Duo
// (bitwarden/clients apps/web/src/connectors/duo-redirect.ts, redirectToDuoFrameless).
const DUO_API_HOST = /^api-[a-z0-9]+\.(?:duosecurity|duofederal)\.com$/u
const DUO_AUTHORIZE_PATH = '/oauth/v1/authorize'

function invalidPrompt(): never {
  throw new DuoLoginError('INVALID_PROMPT')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function decodeJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split('.')
  const payload = parts[1]
  if (parts.length !== 3 || payload === undefined || !/^[A-Za-z0-9_-]+$/u.test(payload)) {
    invalidPrompt()
  }
  const bytes = Buffer.from(payload, 'base64url')
  if (bytes.length === 0 || bytes.length > MAX_DUO_JWT_PAYLOAD_BYTES) invalidPrompt()
  let decoded: unknown
  try {
    decoded = JSON.parse(bytes.toString('utf8'))
  } catch {
    invalidPrompt()
  }
  if (!isRecord(decoded)) invalidPrompt()
  return decoded
}

/**
 * Parses one `TwoFactorProviders2` entry. Only an HTTPS Duo authorization URL is accepted, and
 * its signed request must carry the state and redirect URI that the callback is checked against.
 */
export function parseDuoLoginPrompt(provider: DuoLoginProvider, value: unknown): DuoLoginPrompt {
  if (!isRecord(value)) invalidPrompt()
  const authUrl = value.AuthUrl ?? value.authUrl
  if (typeof authUrl !== 'string' || authUrl.length > MAX_DUO_URL_LENGTH) invalidPrompt()
  let url: URL
  try {
    url = new URL(authUrl)
  } catch {
    invalidPrompt()
  }
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    url.port !== '' ||
    url.hash !== '' ||
    url.pathname !== DUO_AUTHORIZE_PATH ||
    !DUO_API_HOST.test(url.hostname)
  ) {
    invalidPrompt()
  }
  const request = url.searchParams.get('request')
  if (request === null) invalidPrompt()
  const claims = decodeJwtPayload(request)
  const { state, redirect_uri: redirectUri } = claims
  if (typeof state !== 'string' || !DUO_STATE.test(state)) invalidPrompt()
  if (typeof redirectUri !== 'string' || redirectUri.length > MAX_DUO_URL_LENGTH) invalidPrompt()
  let redirect: URL
  try {
    redirect = new URL(redirectUri)
  } catch {
    invalidPrompt()
  }
  if (redirect.protocol !== 'https:' || redirect.username !== '' || redirect.password !== '') {
    invalidPrompt()
  }
  return Object.freeze({
    provider,
    authUrl: url.toString(),
    state,
    redirectBase: `${redirect.origin}${redirect.pathname}`
  })
}

function sameState(left: string, right: string): boolean {
  const a = Buffer.from(left, 'utf8')
  const b = Buffer.from(right, 'utf8')
  return a.length === b.length && timingSafeEqual(a, b)
}

function callbackParts(input: string, prompt: DuoLoginPrompt): [string | null, string | null] {
  if (!input.includes('://')) {
    const parts = input.split('|')
    return parts.length === 2 ? [parts[0]!, parts[1]!] : [null, null]
  }
  let url: URL
  try {
    url = new URL(input)
  } catch {
    return [null, null]
  }
  // The web-vault connector page (`client=desktop`) forwards to this official desktop deep link.
  const isDesktopDeepLink = url.protocol === 'bitwarden:' && url.host === 'duo-callback'
  if (!isDesktopDeepLink && `${url.origin}${url.pathname}` !== prompt.redirectBase) {
    return [null, null]
  }
  return [
    url.searchParams.get('code') ?? url.searchParams.get('duo_code'),
    url.searchParams.get('state')
  ]
}

/**
 * Turns pasted callback material into the `<code>|<state>` token both Vaultwarden
 * (`validate_duo_login`) and Bitwarden expect. Accepts the redirected connector URL, the
 * `bitwarden://duo-callback` deep link, or a bare `code|state` pair.
 */
export function parseDuoLoginCallback(input: unknown, prompt: DuoLoginPrompt): string {
  if (typeof input !== 'string') throw new DuoLoginError('INVALID_CALLBACK')
  const trimmed = input.trim()
  if (trimmed.length === 0 || trimmed.length > MAX_DUO_URL_LENGTH) {
    throw new DuoLoginError('INVALID_CALLBACK')
  }
  const [code, state] = callbackParts(trimmed, prompt)
  if (
    code === null ||
    state === null ||
    !DUO_TOKEN_PART.test(code) ||
    !DUO_TOKEN_PART.test(state)
  ) {
    throw new DuoLoginError('INVALID_CALLBACK')
  }
  if (!sameState(state, prompt.state)) throw new DuoLoginError('STATE_MISMATCH')
  return `${code}|${state}`
}

interface PendingDuoLogin {
  readonly prompt: DuoLoginPrompt
  readonly settle: (result: { token: string } | { error: DuoLoginError }) => void
}

/**
 * Single-slot rendezvous between an in-flight Duo login and the callback the user pastes.
 * Every exit path (state mismatch, timeout, cancel, abort) settles the waiter exactly once.
 */
export class DuoLoginCallbacks {
  private pending: PendingDuoLogin | null = null

  constructor(private readonly timeoutMs = DUO_LOGIN_TIMEOUT_MS) {}

  get waiting(): boolean {
    return this.pending !== null
  }

  wait(prompt: DuoLoginPrompt, signal: AbortSignal): Promise<string> {
    this.pending?.settle({ error: new DuoLoginError('CANCELED') })
    return new Promise<string>((resolve, reject) => {
      if (signal.aborted) {
        reject(new DuoLoginError('ABORTED'))
        return
      }
      const onAbort = (): void => entry.settle({ error: new DuoLoginError('ABORTED') })
      const timer = setTimeout(
        () => entry.settle({ error: new DuoLoginError('TIMEOUT') }),
        this.timeoutMs
      )
      const entry: PendingDuoLogin = {
        prompt,
        settle: (result) => {
          if (this.pending !== entry) return
          this.pending = null
          clearTimeout(timer)
          signal.removeEventListener('abort', onAbort)
          if ('token' in result) resolve(result.token)
          else reject(result.error)
        }
      }
      this.pending = entry
      signal.addEventListener('abort', onAbort, { once: true })
    })
  }

  /** Malformed input leaves the login waiting; a parsed but foreign state ends it. */
  submit(input: unknown): void {
    const pending = this.pending
    if (!pending) throw new DuoLoginError('NOT_WAITING')
    let token: string
    try {
      token = parseDuoLoginCallback(input, pending.prompt)
    } catch (error) {
      if (error instanceof DuoLoginError && error.code === 'STATE_MISMATCH') {
        pending.settle({ error })
        return
      }
      throw error
    }
    pending.settle({ token })
  }

  cancel(): void {
    this.pending?.settle({ error: new DuoLoginError('CANCELED') })
  }
}
