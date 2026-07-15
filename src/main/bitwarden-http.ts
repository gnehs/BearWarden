/**
 * A deliberately small transport for Bitwarden's client HTTP protocol.
 * These endpoints are compatibility surfaces, not a versioned public API.
 * It does not derive keys, encrypt values, or persist credentials: callers own
 * all cryptography and durable storage.
 */

export type BitwardenEnvironment = 'us' | 'eu' | string
export type JsonPrimitive = string | number | boolean | null
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[]
export interface JsonObject {
  [key: string]: JsonValue
}

export interface BitwardenUrls {
  apiUrl: string
  identityUrl: string
  webVaultUrl: string
}

export interface BitwardenSession {
  accessToken: string
  refreshToken: string
  /** Unix epoch milliseconds. */
  expiresAt: number
}

export interface BitwardenPrelogin {
  kdfType: number
  iterations: number
  memory: number | null
  parallelism: number | null
  salt: string | null
  raw: JsonObject
}

export interface PasswordTokenForm {
  email: string
  /** Already transformed by the caller's crypto layer; never a raw master password. */
  password: string
  clientId?: string
  deviceType?: number
  deviceIdentifier?: string
  deviceName?: string
  twoFactorProvider?: number
  twoFactorToken?: string
  twoFactorRemember?: boolean
  /** Server-specific new-device OTP fields are passed through without interpretation. */
  newDeviceOtp?: string
  [key: string]: string | number | boolean | undefined
}

export interface BitwardenHttpOptions {
  server: BitwardenEnvironment
  fetch?: FetchLike
  clientName?: string
  clientVersion?: string
  /** HTTP is allowed only for localhost/loopback, which keeps local test servers usable. */
  allowHttpLoopback?: boolean
  onSessionChanged?: (session: BitwardenSession) => void | Promise<void>
  now?: () => number
  sleep?: (milliseconds: number, signal?: AbortSignal) => Promise<void>
  maxRetryAfterMs?: number
  maxRetries?: number
  timeoutMs?: number
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>

export type BitwardenHttpErrorCode =
  'AUTH' | 'TWO_FACTOR' | 'NEW_DEVICE' | 'NETWORK' | 'INVALID_RESPONSE' | 'CONFLICT' | 'ABORTED'

export class BitwardenHttpError extends Error {
  constructor(
    readonly code: BitwardenHttpErrorCode,
    readonly status?: number,
    /** Non-secret, schema-checked error metadata supplied by the service. */
    readonly details?: JsonObject
  ) {
    super(`Bitwarden HTTP request failed (${code})`)
    this.name = 'BitwardenHttpError'
  }
}

const US_URLS: BitwardenUrls = {
  apiUrl: 'https://api.bitwarden.com',
  identityUrl: 'https://identity.bitwarden.com',
  webVaultUrl: 'https://vault.bitwarden.com'
}
const EU_URLS: BitwardenUrls = {
  apiUrl: 'https://api.bitwarden.eu',
  identityUrl: 'https://identity.bitwarden.eu',
  webVaultUrl: 'https://vault.bitwarden.eu'
}
const RETRYABLE_METHODS = new Set(['GET', 'PUT', 'DELETE'])
const DEFAULT_MAX_RETRIES = 5
const MAX_RESPONSE_BYTES = 128 * 1024 * 1024

function isRecord(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function string(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

function finiteInteger(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined
}

function normalizeBaseUrl(value: string, allowHttpLoopback: boolean): URL {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  const loopback =
    url.hostname === 'localhost' ||
    url.hostname === '::1' ||
    /^127(?:\.\d{1,3}){3}$/.test(url.hostname)
  if (url.protocol !== 'https:' && !(allowHttpLoopback && loopback && url.protocol === 'http:')) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  if (url.username || url.password || url.search || url.hash)
    throw new BitwardenHttpError('INVALID_RESPONSE')
  url.pathname = url.pathname.replace(/\/+$/, '') || ''
  return url
}

function appendPath(base: URL, path: string): string {
  const result = new URL(base.toString())
  result.pathname = `${base.pathname}/${path.replace(/^\/+/, '')}`.replace(/\/{2,}/g, '/')
  return result.toString().replace(/\/$/, '')
}

/** Resolves cloud regions or a self-hosted root URL without accepting insecure origins. */
export function resolveBitwardenUrls(
  server: BitwardenEnvironment,
  options: Pick<BitwardenHttpOptions, 'allowHttpLoopback'> = {}
): BitwardenUrls {
  if (server === 'us') return US_URLS
  if (server === 'eu') return EU_URLS
  const base = normalizeBaseUrl(server, options.allowHttpLoopback ?? true)
  const cloudRoot = base.toString().replace(/\/$/, '')
  if (cloudRoot === 'https://bitwarden.com' || cloudRoot === 'https://vault.bitwarden.com') {
    return US_URLS
  }
  if (cloudRoot === 'https://bitwarden.eu' || cloudRoot === 'https://vault.bitwarden.eu') {
    return EU_URLS
  }
  return {
    apiUrl: appendPath(base, 'api'),
    identityUrl: appendPath(base, 'identity'),
    webVaultUrl: base.toString().replace(/\/$/, '')
  }
}

function parseJson(text: string): JsonValue {
  try {
    return JSON.parse(text) as JsonValue
  } catch {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
}

function parseErrorJson(text: string): JsonValue | null {
  try {
    return JSON.parse(text) as JsonValue
  } catch {
    return null
  }
}

async function boundedResponseText(response: Response): Promise<string> {
  const contentLength = response.headers.get('content-length')
  if (contentLength !== null) {
    const parsed = Number(contentLength)
    if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > MAX_RESPONSE_BYTES) {
      throw new BitwardenHttpError('INVALID_RESPONSE')
    }
  }
  if (!response.body) return ''
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  const chunks: string[] = []
  let bytes = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      bytes += value.byteLength
      if (bytes > MAX_RESPONSE_BYTES) throw new BitwardenHttpError('INVALID_RESPONSE')
      chunks.push(decoder.decode(value, { stream: true }))
    }
    chunks.push(decoder.decode())
    return chunks.join('')
  } finally {
    reader.releaseLock()
  }
}

function normalizeExpiresAt(value: unknown, now: number): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
    // OAuth returns expires_in seconds. setSession may receive a Unix timestamp.
    return value < 10_000_000 ? now + value * 1000 : value
  }
  if (typeof value === 'string' && Number.isFinite(Date.parse(value))) return Date.parse(value)
  return undefined
}

function headers(init?: HeadersInit): Headers {
  return new Headers(init)
}

function retryAfter(response: Response, now: number, maximum: number): number {
  const value = response.headers.get('retry-after')
  if (!value) return 0
  const seconds = Number(value)
  const delay = Number.isFinite(seconds) && seconds >= 0 ? seconds * 1000 : Date.parse(value) - now
  return Number.isFinite(delay) && delay > 0 ? Math.min(delay, maximum) : 0
}

function defaultSleep(milliseconds: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new BitwardenHttpError('ABORTED'))
    const timer = setTimeout(resolve, milliseconds)
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(timer)
        reject(new BitwardenHttpError('ABORTED'))
      },
      { once: true }
    )
  })
}

function base64Url(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64url')
}

export class BitwardenHttpClient {
  readonly urls: BitwardenUrls
  private session: BitwardenSession | null = null
  private refreshInFlight: Promise<BitwardenSession> | null = null
  private readonly fetchFn: FetchLike
  private readonly now: () => number
  private readonly sleep: (milliseconds: number, signal?: AbortSignal) => Promise<void>
  private readonly maxRetryAfterMs: number
  private readonly maxRetries: number
  private readonly timeoutMs: number

  constructor(private readonly options: BitwardenHttpOptions) {
    this.urls = resolveBitwardenUrls(options.server, options)
    this.fetchFn = options.fetch ?? fetch
    this.now = options.now ?? Date.now
    this.sleep = options.sleep ?? defaultSleep
    this.maxRetryAfterMs = options.maxRetryAfterMs ?? 60_000
    this.maxRetries = Math.max(
      0,
      Math.min(options.maxRetries ?? DEFAULT_MAX_RETRIES, DEFAULT_MAX_RETRIES)
    )
    this.timeoutMs = Math.max(1_000, Math.min(options.timeoutMs ?? 30_000, 120_000))
  }

  setSession(session: BitwardenSession): void {
    if (
      !string(session.accessToken) ||
      !string(session.refreshToken) ||
      !Number.isFinite(session.expiresAt)
    ) {
      throw new BitwardenHttpError('INVALID_RESPONSE')
    }
    this.session = { ...session }
  }

  exportSession(): BitwardenSession | null {
    return this.session ? { ...this.session } : null
  }

  clearSession(): void {
    this.session = null
  }

  async prelogin(email: string, signal?: AbortSignal): Promise<BitwardenPrelogin> {
    if (!string(email)) throw new BitwardenHttpError('INVALID_RESPONSE')
    const request = {
      body: { email },
      signal,
      authenticate: false as const,
      headers: { 'auth-email': base64Url(email), 'cache-control': 'no-store' }
    }
    let response: JsonValue
    try {
      response = await this.requestJson(
        'POST',
        `${this.urls.identityUrl}/accounts/prelogin/password`,
        request
      )
    } catch (error) {
      if (!(error instanceof BitwardenHttpError) || (error.status !== 404 && error.status !== 405))
        throw error
      response = await this.requestJson(
        'POST',
        `${this.urls.identityUrl}/accounts/prelogin`,
        request
      )
    }
    return parsePrelogin(response)
  }

  async passwordToken(form: PasswordTokenForm, signal?: AbortSignal): Promise<BitwardenSession> {
    if (!string(form.email) || !string(form.password))
      throw new BitwardenHttpError('INVALID_RESPONSE')
    const body = new URLSearchParams()
    body.set('grant_type', 'password')
    body.set('username', form.email)
    body.set('password', form.password)
    body.set('scope', 'api offline_access')
    body.set('client_id', form.clientId ?? 'desktop')
    for (const [key, value] of Object.entries(form)) {
      if (['email', 'password', 'clientId', 'newDeviceOtp'].includes(key) || value === undefined)
        continue
      body.set(
        key,
        key === 'twoFactorRemember' && typeof value === 'boolean'
          ? value
            ? '1'
            : '0'
          : String(value)
      )
    }
    if (form.newDeviceOtp) body.set('newDeviceOtp', form.newDeviceOtp)
    const response = await this.requestJson('POST', `${this.urls.identityUrl}/connect/token`, {
      form: body,
      signal,
      authenticate: false,
      headers: {
        'auth-email': base64Url(form.email),
        'device-type': String(form.deviceType ?? 14),
        'cache-control': 'no-store'
      }
    })
    return parseSession(response, this.now())
  }

  async refresh(signal?: AbortSignal): Promise<BitwardenSession> {
    if (!this.session) throw new BitwardenHttpError('AUTH')
    if (!this.refreshInFlight) {
      const refreshToken = this.session.refreshToken
      this.refreshInFlight = this.refreshToken(refreshToken, signal).finally(() => {
        this.refreshInFlight = null
      })
    }
    return this.refreshInFlight
  }

  async revisionDate(signal?: AbortSignal): Promise<string> {
    const response = await this.requestJson('GET', `${this.urls.apiUrl}/accounts/revision-date`, {
      signal
    })
    const date =
      typeof response === 'string'
        ? response
        : isRecord(response)
          ? string(response.date ?? response.revisionDate ?? response.data)
          : undefined
    if (!date || !Number.isFinite(Date.parse(date)))
      throw new BitwardenHttpError('INVALID_RESPONSE')
    return date
  }

  async sync(signal?: AbortSignal): Promise<JsonObject> {
    const response = await this.requestJson(
      'GET',
      `${this.urls.apiUrl}/sync?excludeDomains=false`,
      { signal }
    )
    if (!isRecord(response)) throw new BitwardenHttpError('INVALID_RESPONSE')
    return response
  }

  async createFolder(ciphertext: JsonObject, signal?: AbortSignal): Promise<JsonObject> {
    return this.entity('POST', '/folders', ciphertext, signal)
  }
  async updateFolder(
    id: string,
    ciphertext: JsonObject,
    signal?: AbortSignal
  ): Promise<JsonObject> {
    return this.entity('PUT', `/folders/${encodeURIComponent(assertId(id))}`, ciphertext, signal)
  }
  async deleteFolder(id: string, signal?: AbortSignal): Promise<void> {
    await this.deleteEntity(`/folders/${encodeURIComponent(assertId(id))}`, signal)
  }
  async createCipher(ciphertext: JsonObject, signal?: AbortSignal): Promise<JsonObject> {
    return this.entity('POST', '/ciphers', ciphertext, signal)
  }
  async updateCipher(
    id: string,
    ciphertext: JsonObject,
    signal?: AbortSignal
  ): Promise<JsonObject> {
    return this.entity('PUT', `/ciphers/${encodeURIComponent(assertId(id))}`, ciphertext, signal)
  }
  async softDeleteCipher(id: string, signal?: AbortSignal): Promise<void> {
    await this.emptyEntity('PUT', `/ciphers/${encodeURIComponent(assertId(id))}/delete`, signal)
  }
  async restoreCipher(id: string, signal?: AbortSignal): Promise<JsonObject> {
    return this.entity(
      'PUT',
      `/ciphers/${encodeURIComponent(assertId(id))}/restore`,
      undefined,
      signal
    )
  }
  async archiveCipher(id: string, signal?: AbortSignal): Promise<JsonObject> {
    return this.entity(
      'PUT',
      `/ciphers/${encodeURIComponent(assertId(id))}/archive`,
      undefined,
      signal
    )
  }
  async unarchiveCipher(id: string, signal?: AbortSignal): Promise<JsonObject> {
    return this.entity(
      'PUT',
      `/ciphers/${encodeURIComponent(assertId(id))}/unarchive`,
      undefined,
      signal
    )
  }
  async hardDeleteCipher(id: string, signal?: AbortSignal): Promise<void> {
    await this.deleteEntity(`/ciphers/${encodeURIComponent(assertId(id))}`, signal)
  }
  async deleteCipher(id: string, signal?: AbortSignal): Promise<void> {
    await this.hardDeleteCipher(id, signal)
  }

  private async entity(
    method: 'POST' | 'PUT',
    path: string,
    body: JsonObject | undefined,
    signal?: AbortSignal
  ): Promise<JsonObject> {
    const response = await this.requestJson(method, `${this.urls.apiUrl}${path}`, { body, signal })
    if (!isRecord(response)) throw new BitwardenHttpError('INVALID_RESPONSE')
    return response
  }

  private async deleteEntity(path: string, signal?: AbortSignal): Promise<void> {
    await this.emptyEntity('DELETE', path, signal)
  }

  private async emptyEntity(
    method: 'PUT' | 'DELETE',
    path: string,
    signal?: AbortSignal
  ): Promise<void> {
    await this.requestJson(method, `${this.urls.apiUrl}${path}`, { signal })
  }

  private async refreshToken(
    refreshToken: string,
    signal?: AbortSignal
  ): Promise<BitwardenSession> {
    const form = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: 'desktop'
    })
    const payload = await this.requestJson('POST', `${this.urls.identityUrl}/connect/token`, {
      form,
      signal,
      authenticate: false,
      headers: { 'cache-control': 'no-store' }
    })
    const updated = parseSession(payload, this.now())
    this.session = updated
    await this.options.onSessionChanged?.({ ...updated })
    return updated
  }

  private async requestJson(
    method: string,
    url: string,
    request: {
      body?: JsonObject
      form?: URLSearchParams
      signal?: AbortSignal
      authenticate?: boolean
      headers?: HeadersInit
    } = {}
  ): Promise<JsonValue> {
    const authenticate = request.authenticate ?? true
    let refreshed = false
    let retries = 0
    for (;;) {
      if (request.signal?.aborted) throw new BitwardenHttpError('ABORTED')
      const initHeaders = headers(request.headers)
      initHeaders.set('cache-control', 'no-store')
      initHeaders.set('bitwarden-client-name', this.options.clientName ?? 'desktop')
      initHeaders.set('bitwarden-client-version', this.options.clientVersion ?? '1.0.0')
      if (request.form)
        initHeaders.set('content-type', 'application/x-www-form-urlencoded; charset=utf-8')
      if (request.body) initHeaders.set('content-type', 'application/json; charset=utf-8')
      let attemptedAccessToken: string | null = null
      if (authenticate) {
        if (!this.session) throw new BitwardenHttpError('AUTH')
        attemptedAccessToken = this.session.accessToken
        initHeaders.set('authorization', `Bearer ${attemptedAccessToken}`)
      }
      let response: Response
      const timeoutSignal = AbortSignal.timeout(this.timeoutMs)
      const fetchSignal = request.signal
        ? AbortSignal.any([request.signal, timeoutSignal])
        : timeoutSignal
      try {
        response = await this.fetchFn(url, {
          method,
          headers: initHeaders,
          redirect: 'error',
          body:
            request.form?.toString() ?? (request.body ? JSON.stringify(request.body) : undefined),
          signal: fetchSignal
        })
      } catch (error) {
        if (request.signal?.aborted) throw new BitwardenHttpError('ABORTED')
        if (timeoutSignal.aborted) throw new BitwardenHttpError('NETWORK')
        if (error instanceof DOMException && error.name === 'AbortError') {
          throw new BitwardenHttpError('ABORTED')
        }
        throw new BitwardenHttpError('NETWORK')
      }

      if (response.status === 401 && authenticate && !refreshed) {
        refreshed = true
        // A different request may already have rotated this account's token.
        // In that case retry with the current token instead of spending the
        // refresh token a second time.
        if (this.session?.accessToken === attemptedAccessToken) await this.refresh(request.signal)
        continue
      }
      if (
        (response.status === 429 || response.status >= 500) &&
        RETRYABLE_METHODS.has(method) &&
        retries < this.maxRetries
      ) {
        retries += 1
        const delay = retryAfter(response, this.now(), this.maxRetryAfterMs)
        if (delay > 0) await this.sleep(delay, request.signal)
        continue
      }
      const text = await boundedResponseText(response)
      const payload =
        text.length === 0 ? null : response.ok ? parseJson(text) : parseErrorJson(text)
      if (!response.ok) throw toHttpError(response.status, payload)
      return payload
    }
  }
}

function assertId(value: string): string {
  if (!string(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  return value
}

function parsePrelogin(value: JsonValue): BitwardenPrelogin {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const nested = isRecord(value.kdfSettings)
    ? value.kdfSettings
    : isRecord(value.kdf)
      ? value.kdf
      : value
  const kdfType = finiteInteger(nested.kdfType ?? nested.type ?? value.kdf ?? value.Kdf)
  const iterations = finiteInteger(
    nested.iterations ?? nested.kdfIterations ?? value.kdfIterations ?? value.KdfIterations
  )
  const memory = finiteInteger(
    nested.memory ?? nested.kdfMemory ?? value.kdfMemory ?? value.KdfMemory
  )
  const parallelism = finiteInteger(
    nested.parallelism ?? nested.kdfParallelism ?? value.kdfParallelism ?? value.KdfParallelism
  )
  const salt = string(nested.salt ?? value.salt ?? value.Salt)
  if (kdfType === undefined || iterations === undefined || iterations === 0) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return {
    kdfType,
    iterations,
    memory: memory ?? null,
    parallelism: parallelism ?? null,
    salt: salt ?? null,
    raw: value
  }
}

function parseSession(value: JsonValue, now: number): BitwardenSession {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const accessToken = string(value.access_token ?? value.accessToken)
  const refreshToken = string(value.refresh_token ?? value.refreshToken)
  const expiresAt = normalizeExpiresAt(value.expires_in ?? value.expiresAt, now)
  if (!accessToken || !refreshToken || !expiresAt) throw new BitwardenHttpError('INVALID_RESPONSE')
  return { accessToken, refreshToken, expiresAt }
}

function toHttpError(status: number, payload: JsonValue): BitwardenHttpError {
  const details = isRecord(payload) ? payload : undefined
  const message = [details?.error, details?.errorMessage, details?.message, details?.ErrorMessage]
    .filter((value): value is string => typeof value === 'string')
    .join(' ')
    .toLowerCase()
  if (status === 401) return new BitwardenHttpError('AUTH', status, details)
  if (status === 409) return new BitwardenHttpError('CONFLICT', status, details)
  if (message.includes('two factor')) return new BitwardenHttpError('TWO_FACTOR', status, details)
  if (message.includes('new device') || message.includes('verification')) {
    return new BitwardenHttpError('NEW_DEVICE', status, details)
  }
  if (
    status === 400 &&
    (message.includes('invalid_grant') ||
      message.includes('invalid credentials') ||
      message.includes('username or password') ||
      message.includes('invalid password'))
  ) {
    return new BitwardenHttpError('AUTH', status, details)
  }
  return new BitwardenHttpError('NETWORK', status, details)
}

export function createBitwardenHttpClient(options: BitwardenHttpOptions): BitwardenHttpClient {
  return new BitwardenHttpClient(options)
}
