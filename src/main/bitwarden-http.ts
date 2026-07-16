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
  notificationsUrl: string
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

export interface BitwardenAttachmentDownload {
  id: string
  /** Encrypted filename from the attachment metadata response. */
  fileName: string
  /** Wrapped per-attachment key, or null for historical attachments. */
  key: string | null
  size: number
  sizeName: string | null
  /** Fetches encrypted EncArrayBuffer bytes only after the caller validates this metadata. */
  download: (signal?: AbortSignal) => Promise<Buffer>
  /** Streams encrypted bytes with an exact, authenticated metadata size bound. */
  downloadStream: (
    signal?: AbortSignal
  ) => Promise<import('./bitwarden-attachment-stream').BitwardenAttachmentByteSource>
}

export interface BitwardenAttachmentUploadRequest {
  /** Wrapped per-attachment key. */
  key: string
  /** Encrypted attachment filename. */
  fileName: string
  /** Encrypted type-2 envelope size in bytes. */
  fileSize: number
  lastKnownRevisionDate: string
}

export interface BitwardenAttachmentUpload {
  attachmentId: string
  url: string
  fileUploadType: 'direct' | 'azure'
}

/**
 * Safe, structured HIBP breach metadata returned by Vaultwarden's authenticated
 * proxy. Descriptions and logo paths are deliberately excluded: the former is
 * remote HTML and neither is needed to identify or remediate a breach.
 */
export interface BitwardenAccountBreach {
  name: string
  title: string
  domain: string
  breachDate: string
  addedDate: string
  pwnCount: number
  dataClasses: string[]
  isVerified: boolean
}

/** Renderer-safe subset of the authenticated account profile. */
export interface BitwardenAccountSecurityProfile {
  id: string
  name: string
  email: string
  emailVerified: boolean
  twoFactorEnabled: boolean
}

/** Safe subset of GET /devices. Identifiers, keys, tokens, and network data are excluded. */
export interface BitwardenAccountDevice {
  id: string
  name: string
  type: number
  createdAt: string
  lastActivityAt: string | null
  current: boolean
  trusted: boolean
  pendingAuthRequest: boolean
}

export interface BitwardenPersonalApiKey {
  apiKey: string
  revisionDate: string
}

export interface BitwardenTwoFactorProvider {
  type: number
  enabled: boolean
}

export interface BitwardenAuthenticatorSetup {
  enabled: boolean
  key: string
  verificationMode: 'server-token' | 'master-password'
  userVerificationToken: string | null
}

export interface BitwardenEmailTwoFactorSetup {
  enabled: boolean
  email: string | null
  verificationMode: 'server-token' | 'master-password'
  userVerificationToken: string | null
}

/**
 * Vaultwarden returns a synthetic, otherwise-successful row when its HIBP API
 * key is absent. Keep that distinct from both a clean account and a breach.
 */
export type BitwardenAccountBreachReport =
  | { status: 'complete'; breaches: BitwardenAccountBreach[] }
  | { status: 'unavailable'; reason: 'server-hibp-unconfigured' }

export interface BitwardenGlobalEquivalentDomain {
  type: number
  domains: string[]
  excluded: boolean
}

export interface BitwardenEquivalentDomainSettings {
  equivalentDomains: string[][]
  globalEquivalentDomains: BitwardenGlobalEquivalentDomain[]
}

export interface BitwardenEquivalentDomainUpdate {
  equivalentDomains: string[][]
  excludedGlobalEquivalentDomains: number[]
}

export interface BitwardenEmergencyAccess {
  id: string
  role: 'trusted' | 'granted'
  subjectId: string
  name: string
  email: string
  type: number
  status: number
  waitTimeDays: number
  creationDate: string
  avatarColor: string
}

export interface BitwardenSendRequest {
  type: 0
  authType: 1 | 2
  name: string
  notes: string | null
  key: string
  maxAccessCount: number | null
  expirationDate: string | null
  deletionDate: string
  text: { text: string; hidden: boolean }
  password: string | null
  emails: null
  disabled: boolean
  hideEmail: boolean
}

/** Authenticated owner request for a file Send. File bytes are uploaded separately. */
export interface BitwardenSendFileRequest {
  type: 1
  fileLength: number
  authType: 1 | 2
  name: string
  notes: string | null
  key: string
  maxAccessCount: number | null
  expirationDate: string | null
  deletionDate: string
  file: { fileName: string }
  password: string | null
  emails: null
  disabled: boolean
  hideEmail: boolean
}

export interface BitwardenSendFileUpload {
  fileUploadType: 'direct' | 'azure'
  url: string
  sendResponse: JsonObject
}

export interface BitwardenSendFileDownload {
  id: string
  url: string
  download: (signal?: AbortSignal) => Promise<Buffer>
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
  /** Exact additional origins allowed for server-issued attachment download URLs. */
  attachmentDownloadOrigins?: readonly string[]
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>

export type BitwardenHttpErrorCode =
  | 'AUTH'
  | 'TWO_FACTOR'
  | 'NEW_DEVICE'
  | 'NETWORK'
  | 'INVALID_RESPONSE'
  | 'CONFLICT'
  | 'ABORTED'
  | 'NOT_FOUND'
  | 'FORBIDDEN'
  | 'TOO_LARGE'
  | 'STORAGE_LIMIT'
  | 'ATTACHMENT_REJECTED'
  | 'USER_VERIFICATION_FAILED'

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
  notificationsUrl: 'https://notifications.bitwarden.com',
  webVaultUrl: 'https://vault.bitwarden.com'
}
const EU_URLS: BitwardenUrls = {
  apiUrl: 'https://api.bitwarden.eu',
  identityUrl: 'https://identity.bitwarden.eu',
  notificationsUrl: 'https://notifications.bitwarden.eu',
  webVaultUrl: 'https://vault.bitwarden.eu'
}
const RETRYABLE_METHODS = new Set(['GET', 'PUT', 'DELETE'])
const DEFAULT_MAX_RETRIES = 5
const ACCESS_TOKEN_REFRESH_LEEWAY_MS = 60_000
const MAX_RESPONSE_BYTES = 128 * 1024 * 1024
const MAX_HIBP_BREACH_RESPONSE_BYTES = 4 * 1024 * 1024
const MAX_ACCOUNT_PROFILE_RESPONSE_BYTES = 256 * 1024
const MAX_ACCOUNT_DEVICES_RESPONSE_BYTES = 4 * 1024 * 1024
const MAX_ACCOUNT_DEVICES = 10_000
const MAX_DEVICE_STRING_BYTES = 256
const MAX_EMERGENCY_ACCESS_RESPONSE_BYTES = 2 * 1024 * 1024
const MAX_EMERGENCY_ACCESS_ENTRIES = 10_000
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu
const MAX_HIBP_BREACHES = 10_000
const MAX_HIBP_DATA_CLASSES = 100
const MAX_HIBP_STRING_BYTES = 4_096
const MAX_DOMAIN_SETTINGS_RESPONSE_BYTES = 2 * 1024 * 1024
const MAX_EQUIVALENT_DOMAIN_GROUPS = 10_000
const MAX_EQUIVALENT_DOMAINS_PER_GROUP = 1_000
const MAX_EQUIVALENT_DOMAIN_TOTAL = 100_000
const MAX_EQUIVALENT_DOMAIN_BYTES = 1_024
const MAX_SENDS = 10_000
const MAX_SEND_STRING_BYTES = 1_024 * 1_024
const MAX_SEND_FILE_BYTES = 128 * 1024 * 1024
const MAX_SEND_FILE_URL_BYTES = 64 * 1024
const MAX_ATTACHMENT_BYTES = 500 * 1024 * 1024 + 65
const MAX_ATTACHMENT_URL_BYTES = 64 * 1024

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

function isLoopbackHostname(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '::1' || /^127(?:\.\d{1,3}){3}$/.test(hostname)
}

function isPrivateIpv4Literal(hostname: string): boolean {
  const parts = hostname.split('.')
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/u.test(part) || Number(part) > 255)) {
    return false
  }
  const [first, second] = parts.map(Number)
  return (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    (first === 100 && second! >= 64 && second! <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second! >= 16 && second! <= 31) ||
    (first === 192 && second === 168) ||
    first! >= 224
  )
}

function isPrivateAttachmentHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/gu, '')
  if (
    normalized === 'localhost' ||
    normalized.endsWith('.localhost') ||
    normalized.endsWith('.local') ||
    isPrivateIpv4Literal(normalized)
  ) {
    return true
  }
  if (!normalized.includes(':')) return false
  if (normalized === '::' || normalized === '::1') return true
  if (/^f[cd]/u.test(normalized) || /^fe[89ab]/u.test(normalized)) return true
  // Reject multicast and the deprecated site-local range in addition to
  // link-local/ULA addresses. They must never be treated as public attachment
  // capabilities.
  if (/^ff/u.test(normalized) || /^fe[c-f]/u.test(normalized)) return true
  const mappedDottedIpv4 = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/u.exec(normalized)?.[1]
  if (mappedDottedIpv4 !== undefined) return isPrivateIpv4Literal(mappedDottedIpv4)

  // WHATWG URL canonicalization rewrites dotted IPv4-mapped IPv6 literals to
  // hexadecimal (for example ::ffff:127.0.0.1 becomes ::ffff:7f00:1). Decode
  // those final 32 bits before applying the IPv4 private-range policy.
  const mappedHexIpv4 = /^::ffff:([\da-f]{1,4}):([\da-f]{1,4})$/u.exec(normalized)
  if (mappedHexIpv4) {
    const high = Number.parseInt(mappedHexIpv4[1]!, 16)
    const low = Number.parseInt(mappedHexIpv4[2]!, 16)
    const ipv4 = `${high >>> 8}.${high & 0xff}.${low >>> 8}.${low & 0xff}`
    return isPrivateIpv4Literal(ipv4)
  }
  return false
}

function normalizeAttachmentOrigin(value: string, allowHttpLoopback: boolean): string {
  const url = normalizeBaseUrl(value, allowHttpLoopback)
  if (url.pathname !== '' && url.pathname !== '/') {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return url.origin
}

function resolveAttachmentDownloadUrl(
  value: string,
  webVaultUrl: string,
  allowedOrigins: ReadonlySet<string>,
  allowHttpLoopback: boolean
): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.trim() !== value ||
    value.includes('\\') ||
    Buffer.byteLength(value, 'utf8') > MAX_ATTACHMENT_URL_BYTES ||
    value.startsWith('//')
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }

  let url: URL
  try {
    const absolute = /^[A-Za-z][A-Za-z\d+.-]*:/u.test(value)
    url = absolute ? new URL(value) : new URL(value, `${webVaultUrl.replace(/\/+$/, '')}/`)
  } catch {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  const allowedProtocol =
    url.protocol === 'https:' ||
    (allowHttpLoopback && url.protocol === 'http:' && isLoopbackHostname(url.hostname))
  const explicitlyAllowed = allowedOrigins.has(url.origin)
  if (
    !allowedProtocol ||
    url.username ||
    url.password ||
    url.hash ||
    (!explicitlyAllowed && (url.protocol !== 'https:' || isPrivateAttachmentHostname(url.hostname)))
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return url.toString()
}

function resolveAttachmentUploadUrl(
  value: string,
  webVaultUrl: string,
  allowedOrigins: ReadonlySet<string>,
  allowHttpLoopback: boolean
): URL {
  // Azure uploads must never reinterpret an attacker-controlled relative URL
  // as an authenticated Bitwarden origin.
  if (!/^[A-Za-z][A-Za-z\d+.-]*:/u.test(value)) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  const resolved = new URL(
    resolveAttachmentDownloadUrl(value, webVaultUrl, allowedOrigins, allowHttpLoopback)
  )
  if (resolved.protocol !== 'https:' || isPrivateAttachmentHostname(resolved.hostname)) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return resolved
}

function assertAttachmentBuffer(value: Buffer): Buffer {
  if (!Buffer.isBuffer(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  if (value.length < 1 || value.length > MAX_ATTACHMENT_BYTES) {
    throw new BitwardenHttpError(
      value.length > MAX_ATTACHMENT_BYTES ? 'TOO_LARGE' : 'INVALID_RESPONSE'
    )
  }
  return value
}

function attachmentBody(value: Buffer): Uint8Array<ArrayBuffer> {
  if (!(value.buffer instanceof ArrayBuffer)) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
}

function assertEncryptedAttachmentValue(value: string): string {
  if (
    !string(value) ||
    Buffer.byteLength(value, 'utf8') > MAX_ATTACHMENT_URL_BYTES ||
    /[\0\r\n]/u.test(value)
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return value
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
    notificationsUrl: appendPath(base, 'notifications'),
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

async function boundedResponseText(
  response: Response,
  maxResponseBytes = MAX_RESPONSE_BYTES,
  tooLargeCode: BitwardenHttpErrorCode = 'INVALID_RESPONSE'
): Promise<string> {
  const contentLength = response.headers.get('content-length')
  if (contentLength !== null) {
    const parsed = Number(contentLength)
    if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maxResponseBytes) {
      throw new BitwardenHttpError(tooLargeCode)
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
      if (bytes > maxResponseBytes) throw new BitwardenHttpError(tooLargeCode)
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
  private readonly allowHttpLoopback: boolean
  private readonly attachmentDownloadOrigins: ReadonlySet<string>

  constructor(private readonly options: BitwardenHttpOptions) {
    this.urls = resolveBitwardenUrls(options.server, options)
    this.allowHttpLoopback = options.allowHttpLoopback ?? true
    this.fetchFn = options.fetch ?? fetch
    this.now = options.now ?? Date.now
    this.sleep = options.sleep ?? defaultSleep
    this.maxRetryAfterMs = options.maxRetryAfterMs ?? 60_000
    this.maxRetries = Math.max(
      0,
      Math.min(options.maxRetries ?? DEFAULT_MAX_RETRIES, DEFAULT_MAX_RETRIES)
    )
    this.timeoutMs = Math.max(1_000, Math.min(options.timeoutMs ?? 30_000, 120_000))
    const attachmentDownloadOrigins = new Set<string>([
      new URL(this.urls.apiUrl).origin,
      new URL(this.urls.webVaultUrl).origin
    ])
    for (const value of options.attachmentDownloadOrigins ?? []) {
      attachmentDownloadOrigins.add(normalizeAttachmentOrigin(value, this.allowHttpLoopback))
    }
    this.attachmentDownloadOrigins = attachmentDownloadOrigins
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

  /** Returns a token suitable for a new long-lived connection, refreshing it near expiry. */
  async activeAccessToken(signal?: AbortSignal): Promise<string> {
    if (signal?.aborted) throw new BitwardenHttpError('ABORTED')
    if (!this.session) throw new BitwardenHttpError('AUTH')
    if (this.session.expiresAt - this.now() <= ACCESS_TOKEN_REFRESH_LEEWAY_MS) {
      await this.refresh(signal)
    }
    if (signal?.aborted) throw new BitwardenHttpError('ABORTED')
    if (!this.session) throw new BitwardenHttpError('AUTH')
    return this.session.accessToken
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

  async getAccountSecurityProfile(signal?: AbortSignal): Promise<BitwardenAccountSecurityProfile> {
    const response = await this.requestJson('GET', `${this.urls.apiUrl}/accounts/profile`, {
      signal,
      maxResponseBytes: MAX_ACCOUNT_PROFILE_RESPONSE_BYTES,
      tooLargeCode: 'TOO_LARGE'
    })
    return parseAccountSecurityProfile(response)
  }

  async getDevices(
    currentDeviceIdentifier: string,
    signal?: AbortSignal
  ): Promise<BitwardenAccountDevice[]> {
    if (
      typeof currentDeviceIdentifier !== 'string' ||
      currentDeviceIdentifier.length === 0 ||
      Buffer.byteLength(currentDeviceIdentifier, 'utf8') > MAX_DEVICE_STRING_BYTES ||
      /[\0\r\n]/u.test(currentDeviceIdentifier)
    ) {
      throw new BitwardenHttpError('INVALID_RESPONSE')
    }
    const response = await this.requestJson('GET', `${this.urls.apiUrl}/devices`, {
      signal,
      maxResponseBytes: MAX_ACCOUNT_DEVICES_RESPONSE_BYTES,
      tooLargeCode: 'TOO_LARGE'
    })
    return parseAccountDevices(response, currentDeviceIdentifier)
  }

  async resendVerificationEmail(signal?: AbortSignal): Promise<void> {
    const response = await this.requestJson('POST', `${this.urls.apiUrl}/accounts/verify-email`, {
      signal,
      maxResponseBytes: MAX_ACCOUNT_PROFILE_RESPONSE_BYTES,
      tooLargeCode: 'TOO_LARGE'
    })
    if (response !== null) throw new BitwardenHttpError('INVALID_RESPONSE')
  }

  async getPersonalApiKey(
    masterPasswordHash: string,
    rotate: boolean,
    signal?: AbortSignal
  ): Promise<BitwardenPersonalApiKey> {
    if (
      typeof masterPasswordHash !== 'string' ||
      masterPasswordHash.length === 0 ||
      masterPasswordHash.length > 1_024 ||
      /[\0\r\n]/u.test(masterPasswordHash)
    ) {
      throw new BitwardenHttpError('INVALID_RESPONSE')
    }
    const body = { masterPasswordHash }
    try {
      const response = await this.requestJson(
        'POST',
        `${this.urls.apiUrl}/accounts/${rotate ? 'rotate-api-key' : 'api-key'}`,
        {
          body,
          signal,
          maxResponseBytes: MAX_ACCOUNT_PROFILE_RESPONSE_BYTES,
          tooLargeCode: 'TOO_LARGE'
        }
      )
      return parsePersonalApiKey(response)
    } catch (error) {
      // Vaultwarden uses "Invalid password" while Bitwarden Server uses
      // "User verification failed" for this endpoint. Neither means the
      // authenticated session itself expired.
      if (
        error instanceof BitwardenHttpError &&
        error.status === 400 &&
        (error.code === 'AUTH' || error.code === 'USER_VERIFICATION_FAILED')
      ) {
        throw new BitwardenHttpError('USER_VERIFICATION_FAILED', 400)
      }
      throw error
    } finally {
      body.masterPasswordHash = ''
    }
  }

  async getTwoFactorProviders(signal?: AbortSignal): Promise<BitwardenTwoFactorProvider[]> {
    const response = await this.requestJson('GET', `${this.urls.apiUrl}/two-factor`, {
      signal,
      maxResponseBytes: MAX_ACCOUNT_PROFILE_RESPONSE_BYTES,
      tooLargeCode: 'TOO_LARGE'
    })
    return parseTwoFactorProviders(response)
  }

  async getTwoFactorRecoveryCode(
    masterPasswordHash: string,
    signal?: AbortSignal
  ): Promise<string> {
    if (
      typeof masterPasswordHash !== 'string' ||
      masterPasswordHash.length === 0 ||
      masterPasswordHash.length > 1_024 ||
      /[\0\r\n]/u.test(masterPasswordHash)
    ) {
      throw new BitwardenHttpError('INVALID_RESPONSE')
    }
    const body = { masterPasswordHash }
    try {
      const response = await this.requestJson(
        'POST',
        `${this.urls.apiUrl}/two-factor/get-recover`,
        {
          body,
          signal,
          maxResponseBytes: MAX_ACCOUNT_PROFILE_RESPONSE_BYTES,
          tooLargeCode: 'TOO_LARGE'
        }
      )
      return parseTwoFactorRecoveryCode(response)
    } catch (error) {
      if (
        error instanceof BitwardenHttpError &&
        error.status === 400 &&
        (error.code === 'AUTH' || error.code === 'USER_VERIFICATION_FAILED')
      ) {
        throw new BitwardenHttpError('USER_VERIFICATION_FAILED', 400)
      }
      throw error
    } finally {
      body.masterPasswordHash = ''
    }
  }

  async getAuthenticatorSetup(
    masterPasswordHash: string,
    signal?: AbortSignal
  ): Promise<BitwardenAuthenticatorSetup> {
    const proof = assertMasterPasswordHash(masterPasswordHash)
    const body = { masterPasswordHash: proof }
    try {
      const response = await this.requestJson(
        'POST',
        `${this.urls.apiUrl}/two-factor/get-authenticator`,
        {
          body,
          signal,
          maxResponseBytes: MAX_ACCOUNT_PROFILE_RESPONSE_BYTES,
          tooLargeCode: 'TOO_LARGE'
        }
      )
      return parseAuthenticatorSetup(response)
    } catch (error) {
      throw normalizeUserVerificationError(error)
    } finally {
      body.masterPasswordHash = ''
    }
  }

  async enableAuthenticator(
    request: {
      key: string
      token: string
      verificationMode: BitwardenAuthenticatorSetup['verificationMode']
      userVerificationToken?: string
      masterPasswordHash?: string
    },
    signal?: AbortSignal
  ): Promise<void> {
    const key = assertTotpSetupKey(request.key)
    const token = assertTotpToken(request.token)
    const body: JsonObject = { key, token }
    if (request.verificationMode === 'server-token') {
      body.userVerificationToken = assertVerificationToken(request.userVerificationToken)
    } else if (request.verificationMode === 'master-password') {
      body.masterPasswordHash = assertMasterPasswordHash(request.masterPasswordHash)
    } else {
      throw new BitwardenHttpError('INVALID_RESPONSE')
    }
    try {
      const response = await this.requestJson(
        'PUT',
        `${this.urls.apiUrl}/two-factor/authenticator`,
        {
          body,
          signal,
          retry: false,
          maxResponseBytes: MAX_ACCOUNT_PROFILE_RESPONSE_BYTES,
          tooLargeCode: 'TOO_LARGE'
        }
      )
      parseEnabledAuthenticator(response, key)
    } catch (error) {
      throw normalizeUserVerificationError(error)
    } finally {
      if (typeof body.userVerificationToken === 'string') body.userVerificationToken = ''
      if (typeof body.masterPasswordHash === 'string') body.masterPasswordHash = ''
      body.key = ''
      body.token = ''
    }
  }

  async getEmailTwoFactorSetup(
    masterPasswordHash: string,
    signal?: AbortSignal
  ): Promise<BitwardenEmailTwoFactorSetup> {
    const body = { masterPasswordHash: assertMasterPasswordHash(masterPasswordHash) }
    try {
      const response = await this.requestJson('POST', `${this.urls.apiUrl}/two-factor/get-email`, {
        body,
        signal,
        maxResponseBytes: MAX_ACCOUNT_PROFILE_RESPONSE_BYTES,
        tooLargeCode: 'TOO_LARGE'
      })
      return parseEmailTwoFactorSetup(response)
    } catch (error) {
      throw normalizeUserVerificationError(error)
    } finally {
      body.masterPasswordHash = ''
    }
  }

  async sendEmailTwoFactorSetup(
    request: {
      email: string
      verificationMode: BitwardenEmailTwoFactorSetup['verificationMode']
      userVerificationToken?: string
      masterPasswordHash?: string
    },
    signal?: AbortSignal
  ): Promise<void> {
    const body: JsonObject = { email: assertTwoFactorEmail(request.email) }
    try {
      appendEmailVerification(body, request)
      await this.requestJson('POST', `${this.urls.apiUrl}/two-factor/send-email`, {
        body,
        signal,
        retry: false,
        maxResponseBytes: MAX_ACCOUNT_PROFILE_RESPONSE_BYTES,
        tooLargeCode: 'TOO_LARGE'
      })
    } catch (error) {
      throw normalizeUserVerificationError(error)
    } finally {
      clearEmailTwoFactorBody(body)
    }
  }

  async enableEmailTwoFactor(
    request: {
      email: string
      token: string
      verificationMode: BitwardenEmailTwoFactorSetup['verificationMode']
      userVerificationToken?: string
      masterPasswordHash?: string
    },
    signal?: AbortSignal
  ): Promise<void> {
    const email = assertTwoFactorEmail(request.email)
    const body: JsonObject = { email, token: assertEmailVerificationCode(request.token) }
    try {
      appendEmailVerification(body, request)
      const response = await this.requestJson('PUT', `${this.urls.apiUrl}/two-factor/email`, {
        body,
        signal,
        retry: false,
        maxResponseBytes: MAX_ACCOUNT_PROFILE_RESPONSE_BYTES,
        tooLargeCode: 'TOO_LARGE'
      })
      parseEnabledEmailTwoFactor(response, email)
    } catch (error) {
      throw normalizeUserVerificationError(error)
    } finally {
      clearEmailTwoFactorBody(body)
    }
  }

  /**
   * Queries the authenticated Vaultwarden HIBP proxy. The server, rather than
   * this client, forwards the complete email address to HIBP when configured.
   * Do not log the email or include it in any error metadata.
   */
  async getAccountBreachReport(
    email: string,
    signal?: AbortSignal
  ): Promise<BitwardenAccountBreachReport> {
    if (!isValidBreachEmail(email)) throw new BitwardenHttpError('INVALID_RESPONSE')
    let response: JsonValue
    try {
      response = await this.requestJson(
        'GET',
        `${this.urls.apiUrl}/hibp/breach?username=${encodeURIComponent(email)}`,
        {
          signal,
          maxResponseBytes: MAX_HIBP_BREACH_RESPONSE_BYTES,
          tooLargeCode: 'TOO_LARGE'
        }
      )
    } catch (error) {
      // HIBP and Vaultwarden both define a 404 as a successful no-breach
      // result. Do not normalize any other error to an empty result.
      if (
        error instanceof BitwardenHttpError &&
        error.code === 'NOT_FOUND' &&
        error.status === 404
      ) {
        return { status: 'complete', breaches: [] }
      }
      throw error
    }
    return parseAccountBreachReport(response)
  }

  async getEquivalentDomainSettings(
    signal?: AbortSignal
  ): Promise<BitwardenEquivalentDomainSettings> {
    const response = await this.requestJson('GET', `${this.urls.apiUrl}/settings/domains`, {
      signal,
      maxResponseBytes: MAX_DOMAIN_SETTINGS_RESPONSE_BYTES,
      tooLargeCode: 'TOO_LARGE'
    })
    return parseEquivalentDomainSettings(response)
  }

  async updateEquivalentDomainSettings(
    update: BitwardenEquivalentDomainUpdate,
    signal?: AbortSignal
  ): Promise<void> {
    const canonical = parseEquivalentDomainUpdate(update)
    const response = await this.requestJson('PUT', `${this.urls.apiUrl}/settings/domains`, {
      body: {
        equivalentDomains: canonical.equivalentDomains,
        excludedGlobalEquivalentDomains: canonical.excludedGlobalEquivalentDomains
      },
      signal,
      maxResponseBytes: MAX_DOMAIN_SETTINGS_RESPONSE_BYTES,
      tooLargeCode: 'TOO_LARGE'
    })
    if (!isRecord(response)) throw new BitwardenHttpError('INVALID_RESPONSE')
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

  async listSends(signal?: AbortSignal): Promise<JsonObject[]> {
    const response = await this.requestJson('GET', `${this.urls.apiUrl}/sends`, { signal })
    return parseSendList(response)
  }

  async listEmergencyAccess(signal?: AbortSignal): Promise<BitwardenEmergencyAccess[]> {
    const [trusted, granted] = await Promise.all([
      this.requestJson('GET', `${this.urls.apiUrl}/emergency-access/trusted`, {
        signal,
        maxResponseBytes: MAX_EMERGENCY_ACCESS_RESPONSE_BYTES,
        tooLargeCode: 'TOO_LARGE'
      }),
      this.requestJson('GET', `${this.urls.apiUrl}/emergency-access/granted`, {
        signal,
        maxResponseBytes: MAX_EMERGENCY_ACCESS_RESPONSE_BYTES,
        tooLargeCode: 'TOO_LARGE'
      })
    ])
    return [
      ...parseEmergencyAccessList(trusted, 'trusted'),
      ...parseEmergencyAccessList(granted, 'granted')
    ]
  }

  async createSend(request: BitwardenSendRequest, signal?: AbortSignal): Promise<JsonObject> {
    return parseSendEntity(
      await this.requestJson('POST', `${this.urls.apiUrl}/sends`, {
        body: request as unknown as JsonObject,
        signal
      })
    )
  }

  async createFileSend(
    request: BitwardenSendFileRequest,
    signal?: AbortSignal
  ): Promise<BitwardenSendFileUpload> {
    if (
      !Number.isSafeInteger(request.fileLength) ||
      request.fileLength < 1 ||
      request.fileLength > MAX_SEND_FILE_BYTES
    ) {
      throw new BitwardenHttpError(
        request.fileLength > MAX_SEND_FILE_BYTES ? 'TOO_LARGE' : 'INVALID_RESPONSE'
      )
    }
    const response = await this.requestJson('POST', `${this.urls.apiUrl}/sends/file/v2`, {
      body: request as unknown as JsonObject,
      signal
    })
    return parseSendFileUpload(response)
  }

  async uploadSendFileDirect(
    sendId: string,
    fileId: string,
    encryptedFileName: string,
    data: Buffer,
    signal?: AbortSignal
  ): Promise<void> {
    if (!Buffer.isBuffer(data) || data.length < 1 || data.length > MAX_SEND_FILE_BYTES) {
      throw new BitwardenHttpError(
        data.length > MAX_SEND_FILE_BYTES ? 'TOO_LARGE' : 'INVALID_RESPONSE'
      )
    }
    const form = new FormData()
    form.append(
      'data',
      new Blob([attachmentBody(data)], { type: 'application/octet-stream' }),
      assertEncryptedAttachmentValue(encryptedFileName)
    )
    await this.requestMultipart(
      'POST',
      `${this.urls.apiUrl}/sends/${encodeURIComponent(assertId(sendId))}/file/${encodeURIComponent(assertId(fileId))}`,
      form,
      signal
    )
  }

  async getSendAccess(
    accessId: string,
    password: string | null,
    signal?: AbortSignal
  ): Promise<JsonObject> {
    const response = await this.requestJson(
      'POST',
      `${this.urls.apiUrl}/sends/access/${encodeURIComponent(assertId(accessId))}`,
      {
        body: { password },
        headers: { 'Send-Id': assertId(accessId) },
        signal,
        authenticate: false
      }
    )
    return parseSendAccessEntity(response)
  }

  async getSendFileDownload(
    sendId: string,
    fileId: string,
    password: string | null,
    expectedSize: number,
    signal?: AbortSignal
  ): Promise<BitwardenSendFileDownload> {
    if (
      !Number.isSafeInteger(expectedSize) ||
      expectedSize < 1 ||
      expectedSize > MAX_SEND_FILE_BYTES
    ) {
      throw new BitwardenHttpError('INVALID_RESPONSE')
    }
    const response = await this.requestJson(
      'POST',
      `${this.urls.apiUrl}/sends/${encodeURIComponent(assertId(sendId))}/access/file/${encodeURIComponent(assertId(fileId))}`,
      {
        body: { password },
        headers: { 'Send-Id': assertId(sendId) },
        signal,
        authenticate: false
      }
    )
    const parsed = parseSendFileDownload(response, fileId)
    const url = resolveAttachmentDownloadUrl(
      parsed.url,
      this.urls.webVaultUrl,
      this.attachmentDownloadOrigins,
      this.allowHttpLoopback
    )
    return {
      id: parsed.id,
      url,
      download: (downloadSignal) =>
        this.requestAttachmentBytes(url, expectedSize, downloadSignal ?? signal)
    }
  }

  async updateSend(
    id: string,
    request: BitwardenSendRequest,
    signal?: AbortSignal
  ): Promise<JsonObject> {
    return parseSendEntity(
      await this.requestJson(
        'PUT',
        `${this.urls.apiUrl}/sends/${encodeURIComponent(assertId(id))}`,
        { body: request as unknown as JsonObject, signal }
      )
    )
  }

  async removeSendPassword(id: string, signal?: AbortSignal): Promise<JsonObject> {
    return parseSendEntity(
      await this.requestJson(
        'PUT',
        `${this.urls.apiUrl}/sends/${encodeURIComponent(assertId(id))}/remove-password`,
        { signal }
      )
    )
  }

  async deleteSend(id: string, signal?: AbortSignal): Promise<void> {
    await this.requestJson(
      'DELETE',
      `${this.urls.apiUrl}/sends/${encodeURIComponent(assertId(id))}`,
      { signal }
    )
  }

  /** Main-process-only base for owner-generated Send links. */
  sendUrl(): string {
    return `${this.urls.webVaultUrl.replace(/\/+$/u, '')}/#/send/`
  }

  async prepareAttachmentDownload(
    cipherId: string,
    attachmentId: string,
    signal?: AbortSignal
  ): Promise<BitwardenAttachmentDownload> {
    const requestedAttachmentId = assertId(attachmentId)
    const response = await this.requestJson(
      'GET',
      `${this.urls.apiUrl}/ciphers/${encodeURIComponent(assertId(cipherId))}/attachment/${encodeURIComponent(requestedAttachmentId)}`,
      { signal }
    )
    const metadata = parseAttachmentDownload(response, requestedAttachmentId)
    const url = resolveAttachmentDownloadUrl(
      metadata.url,
      this.urls.webVaultUrl,
      this.attachmentDownloadOrigins,
      this.allowHttpLoopback
    )
    return {
      id: metadata.id,
      fileName: metadata.fileName,
      key: metadata.key,
      size: metadata.size,
      sizeName: metadata.sizeName,
      download: (downloadSignal) =>
        this.requestAttachmentBytes(url, metadata.size, downloadSignal ?? signal),
      downloadStream: (downloadSignal) =>
        this.requestAttachmentStream(url, metadata.size, downloadSignal ?? signal)
    }
  }

  async createAttachment(
    cipherId: string,
    request: BitwardenAttachmentUploadRequest,
    signal?: AbortSignal
  ): Promise<BitwardenAttachmentUpload> {
    if (!request || typeof request !== 'object') {
      throw new BitwardenHttpError('INVALID_RESPONSE')
    }
    const key = assertEncryptedAttachmentValue(request.key)
    const fileName = assertEncryptedAttachmentValue(request.fileName)
    if (
      !Number.isSafeInteger(request.fileSize) ||
      request.fileSize < 1 ||
      request.fileSize > MAX_ATTACHMENT_BYTES
    ) {
      throw new BitwardenHttpError(
        request.fileSize > MAX_ATTACHMENT_BYTES ? 'TOO_LARGE' : 'INVALID_RESPONSE'
      )
    }
    if (
      !string(request.lastKnownRevisionDate) ||
      !Number.isFinite(Date.parse(request.lastKnownRevisionDate))
    ) {
      throw new BitwardenHttpError('INVALID_RESPONSE')
    }
    const response = await this.requestJson(
      'POST',
      `${this.urls.apiUrl}/ciphers/${encodeURIComponent(assertId(cipherId))}/attachment/v2`,
      {
        body: {
          key,
          fileName,
          fileSize: request.fileSize,
          adminRequest: false,
          lastKnownRevisionDate: request.lastKnownRevisionDate
        },
        signal
      }
    )
    return parseAttachmentUpload(response)
  }

  async uploadAttachmentDirect(
    cipherId: string,
    attachmentId: string,
    encryptedFileName: string,
    data: Buffer | Blob,
    signal?: AbortSignal
  ): Promise<void> {
    const body =
      data instanceof Blob
        ? data
        : new Blob([attachmentBody(assertAttachmentBuffer(data))], {
            type: 'application/octet-stream'
          })
    if (body.size < 1 || body.size > MAX_ATTACHMENT_BYTES) {
      throw new BitwardenHttpError(
        body.size > MAX_ATTACHMENT_BYTES ? 'TOO_LARGE' : 'INVALID_RESPONSE'
      )
    }
    const form = new FormData()
    form.append('data', body, assertEncryptedAttachmentValue(encryptedFileName))
    await this.requestMultipart(
      'POST',
      `${this.urls.apiUrl}/ciphers/${encodeURIComponent(assertId(cipherId))}/attachment/${encodeURIComponent(assertId(attachmentId))}`,
      form,
      signal
    )
  }

  async uploadAttachmentAzure(
    url: string,
    data: Buffer | Blob,
    signal?: AbortSignal
  ): Promise<void> {
    const body =
      data instanceof Blob
        ? data
        : new Blob([attachmentBody(assertAttachmentBuffer(data))], {
            type: 'application/octet-stream'
          })
    if (body.size < 1 || body.size > MAX_ATTACHMENT_BYTES) {
      throw new BitwardenHttpError(
        body.size > MAX_ATTACHMENT_BYTES ? 'TOO_LARGE' : 'INVALID_RESPONSE'
      )
    }
    const uploadUrl = resolveAttachmentUploadUrl(
      url,
      this.urls.webVaultUrl,
      this.attachmentDownloadOrigins,
      this.allowHttpLoopback
    )
    const uploadHeaders = new Headers({
      'cache-control': 'no-store',
      'content-type': 'application/octet-stream',
      'x-ms-blob-type': 'BlockBlob'
    })
    const serviceVersion = uploadUrl.searchParams.get('sv')
    if (serviceVersion !== null) {
      if (!/^\d{4}-\d{2}-\d{2}$/u.test(serviceVersion)) {
        throw new BitwardenHttpError('INVALID_RESPONSE')
      }
      uploadHeaders.set('x-ms-version', serviceVersion)
    }

    if (signal?.aborted) throw new BitwardenHttpError('ABORTED')
    const timeoutSignal = AbortSignal.timeout(this.timeoutMs)
    const fetchSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal
    let response: Response
    try {
      response = await this.fetchFn(uploadUrl.toString(), {
        method: 'PUT',
        headers: uploadHeaders,
        body,
        cache: 'no-store',
        credentials: 'omit',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: fetchSignal
      })
    } catch (error) {
      throw this.mapFetchFailure(error, signal, timeoutSignal)
    }
    if (response.status !== 201) {
      await response.body?.cancel().catch(() => undefined)
      throw toHttpError(response.status, null)
    }
    await response.body?.cancel().catch(() => undefined)
  }

  async deleteAttachment(
    cipherId: string,
    attachmentId: string,
    signal?: AbortSignal
  ): Promise<JsonObject> {
    const response = await this.requestJson(
      'DELETE',
      `${this.urls.apiUrl}/ciphers/${encodeURIComponent(assertId(cipherId))}/attachment/${encodeURIComponent(assertId(attachmentId))}`,
      { signal }
    )
    return parseDeletedAttachment(response)
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

  private mapFetchFailure(
    error: unknown,
    signal: AbortSignal | undefined,
    timeoutSignal: AbortSignal
  ): BitwardenHttpError {
    if (signal?.aborted) return new BitwardenHttpError('ABORTED')
    if (timeoutSignal.aborted) return new BitwardenHttpError('NETWORK')
    if (error instanceof DOMException && error.name === 'AbortError') {
      return new BitwardenHttpError('ABORTED')
    }
    return new BitwardenHttpError('NETWORK')
  }

  private async requestMultipart(
    method: 'POST',
    url: string,
    form: FormData,
    signal?: AbortSignal
  ): Promise<void> {
    let refreshed = false
    for (;;) {
      if (signal?.aborted) throw new BitwardenHttpError('ABORTED')
      if (!this.session) throw new BitwardenHttpError('AUTH')
      const attemptedAccessToken = this.session.accessToken
      const requestHeaders = new Headers({
        authorization: `Bearer ${attemptedAccessToken}`,
        'bitwarden-client-name': this.options.clientName ?? 'desktop',
        'bitwarden-client-version': this.options.clientVersion ?? '1.0.0',
        'cache-control': 'no-store'
      })
      const timeoutSignal = AbortSignal.timeout(this.timeoutMs)
      const fetchSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal
      let response: Response
      try {
        response = await this.fetchFn(url, {
          method,
          headers: requestHeaders,
          body: form,
          cache: 'no-store',
          credentials: 'omit',
          redirect: 'error',
          signal: fetchSignal
        })
      } catch (error) {
        throw this.mapFetchFailure(error, signal, timeoutSignal)
      }

      if (response.status === 401 && !refreshed) {
        refreshed = true
        await response.body?.cancel().catch(() => undefined)
        if (this.session?.accessToken === attemptedAccessToken) await this.refresh(signal)
        continue
      }
      const text = await boundedResponseText(response)
      if (!response.ok) throw toHttpError(response.status, parseErrorJson(text))
      return
    }
  }

  private async requestAttachmentBytes(
    url: string,
    expectedSize: number,
    signal?: AbortSignal
  ): Promise<Buffer> {
    if (signal?.aborted) throw new BitwardenHttpError('ABORTED')
    const timeoutSignal = AbortSignal.timeout(this.timeoutMs)
    const fetchSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal
    let response: Response
    try {
      response = await this.fetchFn(url, {
        method: 'GET',
        headers: {
          accept: 'application/octet-stream',
          'cache-control': 'no-store'
        },
        cache: 'no-store',
        credentials: 'omit',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: fetchSignal
      })
    } catch (error) {
      if (signal?.aborted) throw new BitwardenHttpError('ABORTED')
      if (timeoutSignal.aborted) throw new BitwardenHttpError('NETWORK')
      if (error instanceof DOMException && error.name === 'AbortError') {
        throw new BitwardenHttpError('ABORTED')
      }
      throw new BitwardenHttpError('NETWORK')
    }

    if (response.status !== 200) {
      await response.body?.cancel().catch(() => undefined)
      throw toHttpError(response.status, null)
    }
    const contentEncoding = response.headers.get('content-encoding')
    if (contentEncoding !== null && contentEncoding.toLowerCase() !== 'identity') {
      await response.body?.cancel().catch(() => undefined)
      throw new BitwardenHttpError('INVALID_RESPONSE')
    }
    const contentLength = response.headers.get('content-length')
    if (contentLength !== null) {
      const parsed = Number(contentLength)
      if (!Number.isSafeInteger(parsed) || parsed !== expectedSize) {
        await response.body?.cancel().catch(() => undefined)
        throw new BitwardenHttpError(
          parsed > MAX_ATTACHMENT_BYTES ? 'TOO_LARGE' : 'INVALID_RESPONSE'
        )
      }
    }
    if (!response.body) throw new BitwardenHttpError('INVALID_RESPONSE')

    const output = Buffer.allocUnsafe(expectedSize)
    const reader = response.body.getReader()
    let offset = 0
    try {
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        if (offset + value.byteLength > expectedSize) {
          await reader.cancel().catch(() => undefined)
          throw new BitwardenHttpError('INVALID_RESPONSE')
        }
        Buffer.from(value.buffer, value.byteOffset, value.byteLength).copy(output, offset)
        offset += value.byteLength
      }
      if (offset !== expectedSize) throw new BitwardenHttpError('INVALID_RESPONSE')
      return output
    } catch (error) {
      output.fill(0)
      if (error instanceof BitwardenHttpError) throw error
      if (signal?.aborted) throw new BitwardenHttpError('ABORTED')
      if (timeoutSignal.aborted) throw new BitwardenHttpError('NETWORK')
      if (error instanceof DOMException && error.name === 'AbortError') {
        throw new BitwardenHttpError('ABORTED')
      }
      throw new BitwardenHttpError('NETWORK')
    } finally {
      reader.releaseLock()
    }
  }

  private async requestAttachmentStream(
    url: string,
    expectedSize: number,
    signal?: AbortSignal
  ): Promise<import('./bitwarden-attachment-stream').BitwardenAttachmentByteSource> {
    if (
      !Number.isSafeInteger(expectedSize) ||
      expectedSize < 1 ||
      expectedSize > MAX_ATTACHMENT_BYTES
    ) {
      throw new BitwardenHttpError(
        expectedSize > MAX_ATTACHMENT_BYTES ? 'TOO_LARGE' : 'INVALID_RESPONSE'
      )
    }
    if (signal?.aborted) throw new BitwardenHttpError('ABORTED')
    const timeoutSignal = AbortSignal.timeout(this.timeoutMs)
    const fetchSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal
    let response: Response
    try {
      response = await this.fetchFn(url, {
        method: 'GET',
        headers: { accept: 'application/octet-stream', 'cache-control': 'no-store' },
        cache: 'no-store',
        credentials: 'omit',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: fetchSignal
      })
    } catch (error) {
      throw this.mapFetchFailure(error, signal, timeoutSignal)
    }
    if (response.status !== 200 || !response.body) {
      await response.body?.cancel().catch(() => undefined)
      throw response.status === 200
        ? new BitwardenHttpError('INVALID_RESPONSE')
        : toHttpError(response.status, null)
    }
    const contentEncoding = response.headers.get('content-encoding')
    const contentLength = response.headers.get('content-length')
    if (
      (contentEncoding !== null && contentEncoding.toLowerCase() !== 'identity') ||
      (contentLength !== null && Number(contentLength) !== expectedSize)
    ) {
      await response.body.cancel().catch(() => undefined)
      throw new BitwardenHttpError('INVALID_RESPONSE')
    }
    let consumed = false
    return {
      size: expectedSize,
      async *chunks(): AsyncGenerator<Buffer> {
        if (consumed) throw new BitwardenHttpError('INVALID_RESPONSE')
        consumed = true
        const reader = response.body!.getReader()
        let received = 0
        let complete = false
        try {
          for (;;) {
            const { done, value } = await reader.read()
            if (done) break
            received += value.byteLength
            if (received > expectedSize) {
              await reader.cancel().catch(() => undefined)
              throw new BitwardenHttpError('INVALID_RESPONSE')
            }
            yield Buffer.from(value.buffer, value.byteOffset, value.byteLength)
          }
          if (received !== expectedSize) throw new BitwardenHttpError('INVALID_RESPONSE')
          complete = true
        } catch (error) {
          if (error instanceof BitwardenHttpError) throw error
          if (signal?.aborted) throw new BitwardenHttpError('ABORTED')
          if (timeoutSignal.aborted) throw new BitwardenHttpError('NETWORK')
          throw new BitwardenHttpError('NETWORK')
        } finally {
          if (!complete) await reader.cancel().catch(() => undefined)
          reader.releaseLock()
        }
      }
    }
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
      maxResponseBytes?: number
      tooLargeCode?: BitwardenHttpErrorCode
      /** Overrides method-based retry safety. Mutating one-time 2FA capabilities set this false. */
      retry?: boolean
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

      if (response.status === 401 && authenticate && !refreshed && request.retry !== false) {
        refreshed = true
        // A different request may already have rotated this account's token.
        // In that case retry with the current token instead of spending the
        // refresh token a second time.
        if (this.session?.accessToken === attemptedAccessToken) await this.refresh(request.signal)
        continue
      }
      if (
        (response.status === 429 || response.status >= 500) &&
        (request.retry ?? RETRYABLE_METHODS.has(method)) &&
        retries < this.maxRetries
      ) {
        retries += 1
        const delay = retryAfter(response, this.now(), this.maxRetryAfterMs)
        if (delay > 0) await this.sleep(delay, request.signal)
        continue
      }
      const text = await boundedResponseText(
        response,
        request.maxResponseBytes,
        request.tooLargeCode
      )
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

function parseAccountSecurityProfile(value: JsonValue): BitwardenAccountSecurityProfile {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const id = value.id ?? value.Id
  const name = value.name ?? value.Name
  const email = value.email ?? value.Email
  const emailVerified = value.emailVerified ?? value.EmailVerified
  const twoFactorEnabled = value.twoFactorEnabled ?? value.TwoFactorEnabled
  if (
    typeof id !== 'string' ||
    !UUID_PATTERN.test(id) ||
    typeof name !== 'string' ||
    name.length > 50 ||
    /[\0\r\n]/u.test(name) ||
    typeof email !== 'string' ||
    email.length === 0 ||
    email.length > 254 ||
    /[\0\r\n]/u.test(email) ||
    typeof emailVerified !== 'boolean' ||
    typeof twoFactorEnabled !== 'boolean'
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return { id, name, email, emailVerified, twoFactorEnabled }
}

function deviceDate(value: unknown, nullable: false): string
function deviceDate(value: unknown, nullable: true): string | null
function deviceDate(value: unknown, nullable: boolean): string | null {
  if (nullable && (value === null || value === undefined)) return null
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 64 ||
    /[\0\r\n]/u.test(value) ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$/u.test(value) ||
    !Number.isFinite(Date.parse(value))
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return new Date(value).toISOString()
}

function parseAccountDevices(
  value: JsonValue,
  currentDeviceIdentifier: string
): BitwardenAccountDevice[] {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const data = value.data ?? value.Data
  const object = value.object ?? value.Object
  const continuationToken = value.continuationToken ?? value.ContinuationToken
  if (
    !Array.isArray(data) ||
    data.length > MAX_ACCOUNT_DEVICES ||
    (object !== undefined && object !== 'list') ||
    (continuationToken !== undefined && continuationToken !== null)
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  const ids = new Set<string>()
  const identifiers = new Set<string>()
  return data.map((entry) => {
    if (!isRecord(entry)) throw new BitwardenHttpError('INVALID_RESPONSE')
    const id = entry.id ?? entry.Id
    const name = entry.name ?? entry.Name
    const type = finiteInteger(entry.type ?? entry.Type)
    const identifier = entry.identifier ?? entry.Identifier
    const creationDate = entry.creationDate ?? entry.CreationDate
    const lastActivityDate = entry.lastActivityDate ?? entry.LastActivityDate
    const isTrusted = entry.isTrusted ?? entry.IsTrusted
    const deviceObject = entry.object ?? entry.Object
    const pending = entry.devicePendingAuthRequest ?? entry.DevicePendingAuthRequest
    if (
      typeof id !== 'string' ||
      !UUID_PATTERN.test(id) ||
      ids.has(id) ||
      typeof name !== 'string' ||
      name.length === 0 ||
      Buffer.byteLength(name, 'utf8') > MAX_DEVICE_STRING_BYTES ||
      /[\0\r\n]/u.test(name) ||
      type === undefined ||
      type > 26 ||
      typeof identifier !== 'string' ||
      identifier.length === 0 ||
      identifiers.has(identifier) ||
      Buffer.byteLength(identifier, 'utf8') > MAX_DEVICE_STRING_BYTES ||
      /[\0\r\n]/u.test(identifier) ||
      typeof isTrusted !== 'boolean' ||
      (deviceObject !== undefined && deviceObject !== 'device')
    ) {
      throw new BitwardenHttpError('INVALID_RESPONSE')
    }
    let pendingAuthRequest = false
    if (pending !== undefined && pending !== null) {
      if (!isRecord(pending)) throw new BitwardenHttpError('INVALID_RESPONSE')
      const pendingId = pending.id ?? pending.Id
      const pendingCreationDate = pending.creationDate ?? pending.CreationDate
      if (typeof pendingId !== 'string' || !UUID_PATTERN.test(pendingId)) {
        throw new BitwardenHttpError('INVALID_RESPONSE')
      }
      deviceDate(pendingCreationDate, false)
      pendingAuthRequest = true
    }
    ids.add(id)
    identifiers.add(identifier)
    return {
      id,
      name,
      type,
      createdAt: deviceDate(creationDate, false),
      lastActivityAt: deviceDate(lastActivityDate, true),
      current: identifier === currentDeviceIdentifier,
      trusted: isTrusted,
      pendingAuthRequest
    }
  })
}

function parsePersonalApiKey(value: JsonValue): BitwardenPersonalApiKey {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const apiKey = value.apiKey ?? value.ApiKey
  const revisionDate = value.revisionDate ?? value.RevisionDate
  const object = value.object ?? value.Object
  if (
    typeof apiKey !== 'string' ||
    apiKey.length === 0 ||
    apiKey.length > 512 ||
    /[\0\r\n]/u.test(apiKey) ||
    typeof revisionDate !== 'string' ||
    !Number.isFinite(Date.parse(revisionDate)) ||
    (object !== undefined && object !== 'apiKey')
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return { apiKey, revisionDate }
}

function parseTwoFactorProviders(value: JsonValue): BitwardenTwoFactorProvider[] {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const data = value.data ?? value.Data
  const object = value.object ?? value.Object
  if (!Array.isArray(data) || data.length > 32 || (object !== undefined && object !== 'list')) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  const seen = new Set<number>()
  return data.map((entry) => {
    if (!isRecord(entry)) throw new BitwardenHttpError('INVALID_RESPONSE')
    const type = finiteInteger(entry.type ?? entry.Type)
    const enabled = entry.enabled ?? entry.Enabled
    const providerObject = entry.object ?? entry.Object
    if (
      type === undefined ||
      type < 0 ||
      type > 8 ||
      seen.has(type) ||
      typeof enabled !== 'boolean' ||
      (providerObject !== undefined && providerObject !== 'twoFactorProvider')
    ) {
      throw new BitwardenHttpError('INVALID_RESPONSE')
    }
    seen.add(type)
    return { type, enabled }
  })
}

function parseTwoFactorRecoveryCode(value: JsonValue): string {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const code = value.code ?? value.Code
  const object = value.object ?? value.Object
  if (
    typeof code !== 'string' ||
    code.length === 0 ||
    code.length > 128 ||
    /[\0\r\n]/u.test(code) ||
    (object !== undefined && object !== 'twoFactorRecover')
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return code
}

function assertMasterPasswordHash(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 1_024 ||
    /[\0\r\n]/u.test(value)
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return value
}

function assertVerificationToken(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 16_384 ||
    /[\0\r\n]/u.test(value)
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return value
}

function assertTotpSetupKey(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Z2-7]{32}$/u.test(value)) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return value
}

function assertTotpToken(value: unknown): string {
  if (typeof value !== 'string' || !/^\d{6}$/u.test(value)) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return value
}

function normalizeUserVerificationError(error: unknown): unknown {
  if (
    error instanceof BitwardenHttpError &&
    error.status === 400 &&
    (error.code === 'AUTH' || error.code === 'USER_VERIFICATION_FAILED')
  ) {
    return new BitwardenHttpError('USER_VERIFICATION_FAILED', 400)
  }
  return error
}

function parseAuthenticatorDetails(value: JsonValue): { enabled: boolean; key: string } {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const enabled = value.enabled ?? value.Enabled
  const key = value.key ?? value.Key
  if (typeof enabled !== 'boolean') throw new BitwardenHttpError('INVALID_RESPONSE')
  return { enabled, key: assertTotpSetupKey(key) }
}

function parseAuthenticatorSetup(value: JsonValue): BitwardenAuthenticatorSetup {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const nested = value.authenticator ?? value.Authenticator
  if (nested !== undefined) {
    const details = parseAuthenticatorDetails(nested)
    return {
      ...details,
      verificationMode: 'server-token',
      userVerificationToken: assertVerificationToken(
        value.userVerificationToken ?? value.UserVerificationToken
      )
    }
  }
  const details = parseAuthenticatorDetails(value)
  return {
    ...details,
    verificationMode: 'master-password',
    userVerificationToken: null
  }
}

function parseEnabledAuthenticator(value: JsonValue, expectedKey: string): void {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const nested = value.authenticator ?? value.Authenticator
  const details = parseAuthenticatorDetails(nested === undefined ? value : nested)
  if (!details.enabled || details.key !== expectedKey) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
}

function assertTwoFactorEmail(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 256 ||
    value.trim() !== value ||
    /[\0\r\n]/u.test(value) ||
    !/^[^\s@]+@[^\s@]+$/u.test(value)
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return value
}

function assertEmailVerificationCode(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 50 ||
    value.trim() !== value ||
    /[\0\r\n]/u.test(value)
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return value
}

function appendEmailVerification(
  body: JsonObject,
  request: {
    verificationMode: BitwardenEmailTwoFactorSetup['verificationMode']
    userVerificationToken?: string
    masterPasswordHash?: string
  }
): void {
  if (request.verificationMode === 'server-token') {
    body.userVerificationToken = assertVerificationToken(request.userVerificationToken)
  } else if (request.verificationMode === 'master-password') {
    body.masterPasswordHash = assertMasterPasswordHash(request.masterPasswordHash)
  } else {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
}

function clearEmailTwoFactorBody(body: JsonObject): void {
  body.email = ''
  if (typeof body.token === 'string') body.token = ''
  if (typeof body.userVerificationToken === 'string') body.userVerificationToken = ''
  if (typeof body.masterPasswordHash === 'string') body.masterPasswordHash = ''
}

function parseEmailTwoFactorDetails(value: JsonValue): { enabled: boolean; email: string | null } {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const enabled = value.enabled ?? value.Enabled
  const rawEmail = value.email ?? value.Email
  if (typeof enabled !== 'boolean') throw new BitwardenHttpError('INVALID_RESPONSE')
  const email = rawEmail === null || rawEmail === undefined ? null : assertTwoFactorEmail(rawEmail)
  if (enabled && email === null) throw new BitwardenHttpError('INVALID_RESPONSE')
  return { enabled, email }
}

function parseEmailTwoFactorSetup(value: JsonValue): BitwardenEmailTwoFactorSetup {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const object = value.object ?? value.Object
  if (object !== undefined && object !== 'twoFactorEmail') {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  const nested = value.email ?? value.Email
  if (isRecord(nested)) {
    return {
      ...parseEmailTwoFactorDetails(nested),
      verificationMode: 'server-token',
      userVerificationToken: assertVerificationToken(
        value.userVerificationToken ?? value.UserVerificationToken
      )
    }
  }
  return {
    ...parseEmailTwoFactorDetails(value),
    verificationMode: 'master-password',
    userVerificationToken: null
  }
}

function parseEnabledEmailTwoFactor(value: JsonValue, expectedEmail: string): void {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const object = value.object ?? value.Object
  if (object !== undefined && object !== 'twoFactorEmail' && object !== 'twoFactorEmailUpdate') {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  const nested = value.email ?? value.Email
  const detailsSource = isRecord(nested) ? nested : value
  const rawEnabled = detailsSource.enabled ?? detailsSource.Enabled
  const enabled = rawEnabled === true || rawEnabled === 'true'
  const rawEmail = detailsSource.email ?? detailsSource.Email
  if (!enabled || assertTwoFactorEmail(rawEmail).toLowerCase() !== expectedEmail.toLowerCase()) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
}

function isValidBreachEmail(value: string): boolean {
  // This is intentionally only a transport guard, not a deliverability check.
  // HIBP trims and treats email casing as insensitive; callers retain the exact
  // submitted address so no unexpected transformation is sent to the server.
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 512 &&
    value.trim() === value &&
    !/[\0\r\n]/u.test(value) &&
    /^[^\s@]+@[^\s@]+$/u.test(value)
  )
}

function hibpProperty(record: JsonObject, lower: string, upper: string): JsonValue | undefined {
  return record[lower] ?? record[upper]
}

function boundedHibpString(value: JsonValue | undefined): string | undefined {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.trim() !== value ||
    /[\0\r\n]/u.test(value) ||
    Buffer.byteLength(value, 'utf8') > MAX_HIBP_STRING_BYTES
  ) {
    return undefined
  }
  return value
}

function isVaultwardenHibpUnconfigured(row: JsonObject): boolean {
  const name = hibpProperty(row, 'name', 'Name')
  const title = hibpProperty(row, 'title', 'Title')
  const pwnCount = hibpProperty(row, 'pwnCount', 'PwnCount')
  const dataClasses = hibpProperty(row, 'dataClasses', 'DataClasses')
  return (
    name === 'HaveIBeenPwned' &&
    title === 'Manual HIBP Check' &&
    pwnCount === 0 &&
    Array.isArray(dataClasses) &&
    dataClasses.length === 1 &&
    dataClasses[0] === 'Error - No API key set!'
  )
}

function parseHibpBreach(row: JsonObject): BitwardenAccountBreach {
  const name = boundedHibpString(hibpProperty(row, 'name', 'Name'))
  const title = boundedHibpString(hibpProperty(row, 'title', 'Title'))
  const breachDate = boundedHibpString(hibpProperty(row, 'breachDate', 'BreachDate'))
  const addedDate = boundedHibpString(hibpProperty(row, 'addedDate', 'AddedDate'))
  const domain = boundedHibpString(hibpProperty(row, 'domain', 'Domain'))
  const pwnCount = hibpProperty(row, 'pwnCount', 'PwnCount')
  const dataClasses = hibpProperty(row, 'dataClasses', 'DataClasses')
  const isVerified = hibpProperty(row, 'isVerified', 'IsVerified')
  if (!Array.isArray(dataClasses) || dataClasses.length > MAX_HIBP_DATA_CLASSES) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  const normalizedDataClasses = dataClasses.map((value) => {
    const dataClass = boundedHibpString(value)
    if (!dataClass) throw new BitwardenHttpError('INVALID_RESPONSE')
    return dataClass
  })
  if (
    !name ||
    !title ||
    !breachDate ||
    !addedDate ||
    !domain ||
    !Number.isSafeInteger(pwnCount) ||
    typeof pwnCount !== 'number' ||
    pwnCount < 0 ||
    typeof isVerified !== 'boolean' ||
    !Number.isFinite(Date.parse(breachDate)) ||
    !Number.isFinite(Date.parse(addedDate))
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return {
    name,
    title,
    domain,
    breachDate,
    addedDate,
    pwnCount,
    dataClasses: normalizedDataClasses,
    isVerified
  }
}

function parseAccountBreachReport(value: JsonValue): BitwardenAccountBreachReport {
  if (!Array.isArray(value) || value.length > MAX_HIBP_BREACHES) {
    throw new BitwardenHttpError(
      value instanceof Array && value.length > MAX_HIBP_BREACHES ? 'TOO_LARGE' : 'INVALID_RESPONSE'
    )
  }
  if (value.length === 1 && isRecord(value[0]) && isVaultwardenHibpUnconfigured(value[0])) {
    return { status: 'unavailable', reason: 'server-hibp-unconfigured' }
  }
  return {
    status: 'complete',
    breaches: value.map((row) => {
      if (!isRecord(row)) throw new BitwardenHttpError('INVALID_RESPONSE')
      return parseHibpBreach(row)
    })
  }
}

function domainSettingsProperty(
  record: JsonObject,
  lower: string,
  upper: string
): JsonValue | undefined {
  return record[lower] ?? record[upper]
}

function parseEquivalentDomain(value: JsonValue): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.trim() !== value ||
    /[\0\r\n,]/u.test(value) ||
    Buffer.byteLength(value, 'utf8') > MAX_EQUIVALENT_DOMAIN_BYTES
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return value
}

function parseEquivalentDomainGroups(value: JsonValue | undefined): string[][] {
  if (!Array.isArray(value) || value.length > MAX_EQUIVALENT_DOMAIN_GROUPS) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  let total = 0
  return value.map((group) => {
    if (!Array.isArray(group) || group.length > MAX_EQUIVALENT_DOMAINS_PER_GROUP) {
      throw new BitwardenHttpError('INVALID_RESPONSE')
    }
    total += group.length
    if (total > MAX_EQUIVALENT_DOMAIN_TOTAL) throw new BitwardenHttpError('TOO_LARGE')
    return group.map(parseEquivalentDomain)
  })
}

function parseEquivalentDomainTypes(value: JsonValue | undefined): number[] {
  if (!Array.isArray(value) || value.length > MAX_EQUIVALENT_DOMAIN_GROUPS) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  const seen = new Set<number>()
  return value.map((candidate) => {
    const type = finiteInteger(candidate)
    if (type === undefined || type > 2_147_483_647 || seen.has(type)) {
      throw new BitwardenHttpError('INVALID_RESPONSE')
    }
    seen.add(type)
    return type
  })
}

function parseEquivalentDomainUpdate(value: unknown): BitwardenEquivalentDomainUpdate {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const keys = Object.keys(value)
  if (
    keys.length !== 2 ||
    !keys.includes('equivalentDomains') ||
    !keys.includes('excludedGlobalEquivalentDomains')
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return {
    equivalentDomains: parseEquivalentDomainGroups(value.equivalentDomains),
    excludedGlobalEquivalentDomains: parseEquivalentDomainTypes(
      value.excludedGlobalEquivalentDomains
    )
  }
}

function parseEquivalentDomainSettings(value: JsonValue): BitwardenEquivalentDomainSettings {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const object = domainSettingsProperty(value, 'object', 'Object')
  if (object !== undefined && object !== 'domains') {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  const equivalentDomains = parseEquivalentDomainGroups(
    domainSettingsProperty(value, 'equivalentDomains', 'EquivalentDomains')
  )
  const rawGlobals = domainSettingsProperty(
    value,
    'globalEquivalentDomains',
    'GlobalEquivalentDomains'
  )
  if (!Array.isArray(rawGlobals) || rawGlobals.length > MAX_EQUIVALENT_DOMAIN_GROUPS) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  let total = equivalentDomains.reduce((count, group) => count + group.length, 0)
  const seenTypes = new Set<number>()
  const globalEquivalentDomains = rawGlobals.map((candidate) => {
    if (!isRecord(candidate)) throw new BitwardenHttpError('INVALID_RESPONSE')
    const type = finiteInteger(domainSettingsProperty(candidate, 'type', 'Type'))
    const domains = domainSettingsProperty(candidate, 'domains', 'Domains')
    const excluded = domainSettingsProperty(candidate, 'excluded', 'Excluded')
    if (
      type === undefined ||
      type > 2_147_483_647 ||
      seenTypes.has(type) ||
      !Array.isArray(domains) ||
      domains.length > MAX_EQUIVALENT_DOMAINS_PER_GROUP ||
      typeof excluded !== 'boolean'
    ) {
      throw new BitwardenHttpError('INVALID_RESPONSE')
    }
    seenTypes.add(type)
    total += domains.length
    if (total > MAX_EQUIVALENT_DOMAIN_TOTAL) throw new BitwardenHttpError('TOO_LARGE')
    return { type, domains: domains.map(parseEquivalentDomain), excluded }
  })
  return { equivalentDomains, globalEquivalentDomains }
}

function parseSendEntity(value: JsonValue): JsonObject {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const nested = value.send ?? value.Send
  if (nested !== undefined) {
    if (!isRecord(nested)) throw new BitwardenHttpError('INVALID_RESPONSE')
    return nested
  }
  return value
}

function sendProperty(record: JsonObject, lower: string, upper: string): JsonValue | undefined {
  return record[lower] ?? record[upper]
}

function parseSendFileUpload(value: JsonValue): BitwardenSendFileUpload {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const fileUploadType = sendProperty(value, 'fileUploadType', 'FileUploadType')
  const url = sendProperty(value, 'url', 'Url')
  const sendResponse = sendProperty(value, 'sendResponse', 'SendResponse')
  const normalizedType =
    fileUploadType === 0 || fileUploadType === '0'
      ? 'direct'
      : fileUploadType === 1 || fileUploadType === '1'
        ? 'azure'
        : null
  if (
    normalizedType === null ||
    typeof url !== 'string' ||
    url.length === 0 ||
    Buffer.byteLength(url, 'utf8') > MAX_SEND_FILE_URL_BYTES ||
    !isRecord(sendResponse)
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return {
    fileUploadType: normalizedType,
    url,
    sendResponse: parseSendEntity(sendResponse)
  }
}

function parseSendAccessEntity(value: JsonValue): JsonObject {
  const entity = parseSendEntity(value)
  const type = sendProperty(entity, 'type', 'Type')
  const id = sendProperty(entity, 'id', 'Id')
  if ((type !== 0 && type !== 1) || typeof id !== 'string' || !UUID_PATTERN.test(id)) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return entity
}

function parseSendFileDownload(value: JsonValue, expectedId: string): { id: string; url: string } {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const id = sendProperty(value, 'id', 'Id')
  const url = sendProperty(value, 'url', 'Url')
  if (
    typeof id !== 'string' ||
    id !== expectedId ||
    id.length === 0 ||
    id.length > 256 ||
    typeof url !== 'string' ||
    url.length === 0 ||
    Buffer.byteLength(url, 'utf8') > MAX_SEND_FILE_URL_BYTES
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return { id, url }
}

function parseSendList(value: JsonValue): JsonObject[] {
  const rows = Array.isArray(value)
    ? value
    : isRecord(value) && Array.isArray(value.data)
      ? value.data
      : null
  if (!rows || rows.length > MAX_SENDS) throw new BitwardenHttpError('INVALID_RESPONSE')
  return rows.map((row) => {
    const parsed = parseSendEntity(row)
    const serialized = JSON.stringify(parsed)
    if (serialized === undefined || Buffer.byteLength(serialized, 'utf8') > MAX_SEND_STRING_BYTES) {
      throw new BitwardenHttpError('TOO_LARGE')
    }
    return parsed
  })
}

function parseEmergencyAccessList(
  value: JsonValue,
  role: BitwardenEmergencyAccess['role']
): BitwardenEmergencyAccess[] {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const rows = value.data ?? value.Data
  if (!Array.isArray(rows) || rows.length > MAX_EMERGENCY_ACCESS_ENTRIES) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return rows.map((candidate) => {
    if (!isRecord(candidate)) throw new BitwardenHttpError('INVALID_RESPONSE')
    const id = emergencyStringProperty(candidate, 'id', 'Id')
    const subjectId = emergencyStringProperty(
      candidate,
      role === 'trusted' ? 'granteeId' : 'grantorId',
      role === 'trusted' ? 'GranteeId' : 'GrantorId'
    )
    const name = emergencyStringProperty(candidate, 'name', 'Name')
    const email = emergencyStringProperty(candidate, 'email', 'Email')
    const type = finiteInteger(emergencyProperty(candidate, 'type', 'Type'))
    const status = finiteInteger(emergencyProperty(candidate, 'status', 'Status'))
    const waitTimeDays = finiteInteger(emergencyProperty(candidate, 'waitTimeDays', 'WaitTimeDays'))
    const creationDate = emergencyStringProperty(candidate, 'creationDate', 'CreationDate')
    const avatarColor = emergencyStringProperty(candidate, 'avatarColor', 'AvatarColor')
    if (
      !id ||
      !UUID_PATTERN.test(id) ||
      !subjectId ||
      !UUID_PATTERN.test(subjectId) ||
      !name ||
      Buffer.byteLength(name, 'utf8') > 256 ||
      !email ||
      Buffer.byteLength(email, 'utf8') > 512 ||
      type === undefined ||
      type < 0 ||
      status === undefined ||
      status < 0 ||
      waitTimeDays === undefined ||
      waitTimeDays < 1 ||
      waitTimeDays > 32_767 ||
      !creationDate ||
      !Number.isFinite(Date.parse(creationDate)) ||
      !avatarColor ||
      avatarColor.length > 64
    ) {
      throw new BitwardenHttpError('INVALID_RESPONSE')
    }
    return {
      id,
      role,
      subjectId,
      name,
      email,
      type,
      status,
      waitTimeDays,
      creationDate: new Date(creationDate).toISOString(),
      avatarColor
    }
  })
}

function emergencyProperty(
  record: JsonObject,
  lower: string,
  upper: string
): JsonValue | undefined {
  return record[lower] ?? record[upper]
}

function emergencyStringProperty(record: JsonObject, lower: string, upper: string): string | null {
  const value = emergencyProperty(record, lower, upper)
  return typeof value === 'string' ? value : null
}

interface ParsedAttachmentDownload {
  id: string
  url: string
  fileName: string
  key: string | null
  size: number
  sizeName: string | null
}

function parseAttachmentUpload(value: JsonValue): BitwardenAttachmentUpload {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const attachmentId = string(value.attachmentId ?? value.AttachmentId)
  const url = string(value.url ?? value.Url)
  const rawFileUploadType = value.fileUploadType ?? value.FileUploadType
  const normalizedFileUploadType =
    typeof rawFileUploadType === 'string' ? rawFileUploadType.toLowerCase() : rawFileUploadType
  const fileUploadType =
    normalizedFileUploadType === 0 || normalizedFileUploadType === 'direct'
      ? 'direct'
      : normalizedFileUploadType === 1 || normalizedFileUploadType === 'azure'
        ? 'azure'
        : null
  if (
    !attachmentId ||
    !url ||
    attachmentId.trim() !== attachmentId ||
    url.trim() !== url ||
    /[\0\r\n]/u.test(attachmentId) ||
    /[\0\r\n\\]/u.test(url) ||
    Buffer.byteLength(attachmentId, 'utf8') > MAX_ATTACHMENT_URL_BYTES ||
    Buffer.byteLength(url, 'utf8') > MAX_ATTACHMENT_URL_BYTES ||
    fileUploadType === null
  ) {
    throw new BitwardenHttpError('INVALID_RESPONSE')
  }
  return { attachmentId, url, fileUploadType }
}

function parseDeletedAttachment(value: JsonValue): JsonObject {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const cipher = value.cipher ?? value.Cipher
  if (!isRecord(cipher)) throw new BitwardenHttpError('INVALID_RESPONSE')
  return cipher
}

function parseAttachmentDownload(
  value: JsonValue,
  expectedAttachmentId: string
): ParsedAttachmentDownload {
  if (!isRecord(value)) throw new BitwardenHttpError('INVALID_RESPONSE')
  const id = string(value.id ?? value.Id)
  const url = string(value.url ?? value.Url)
  const fileName = string(value.fileName ?? value.FileName)
  const keyValue = value.key ?? value.Key ?? null
  const sizeValue = value.size ?? value.Size
  const sizeNameValue = value.sizeName ?? value.SizeName ?? null
  const size =
    typeof sizeValue === 'number'
      ? sizeValue
      : typeof sizeValue === 'string' && /^(0|[1-9]\d*)$/u.test(sizeValue)
        ? Number(sizeValue)
        : Number.NaN
  if (
    !id ||
    id !== expectedAttachmentId ||
    !url ||
    !fileName ||
    (keyValue !== null && (typeof keyValue !== 'string' || keyValue.length === 0)) ||
    !Number.isSafeInteger(size) ||
    size < 1 ||
    size > MAX_ATTACHMENT_BYTES ||
    (sizeNameValue !== null && typeof sizeNameValue !== 'string')
  ) {
    throw new BitwardenHttpError(
      Number.isFinite(size) && size > MAX_ATTACHMENT_BYTES ? 'TOO_LARGE' : 'INVALID_RESPONSE'
    )
  }
  return {
    id,
    url,
    fileName,
    key: keyValue,
    size,
    sizeName: sizeNameValue
  }
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
  const message = [
    details?.error,
    details?.errorMessage,
    details?.message,
    details?.ErrorMessage,
    details?.reason
  ]
    .filter((value): value is string => typeof value === 'string')
    .join(' ')
    .toLowerCase()
  if (status === 401) return new BitwardenHttpError('AUTH', status, details)
  if (status === 403) return new BitwardenHttpError('FORBIDDEN', status, details)
  if (status === 404) return new BitwardenHttpError('NOT_FOUND', status, details)
  if (status === 413) return new BitwardenHttpError('TOO_LARGE', status, details)
  if (status === 409) return new BitwardenHttpError('CONFLICT', status, details)
  if (status === 400 && message.includes('user verification failed')) {
    return new BitwardenHttpError('USER_VERIFICATION_FAILED', status)
  }
  if (message.includes('two factor')) return new BitwardenHttpError('TWO_FACTOR', status, details)
  if (message.includes('new device') || message.includes('verification')) {
    return new BitwardenHttpError('NEW_DEVICE', status, details)
  }
  if (
    status === 400 &&
    (message.includes('storage limit') ||
      message.includes('storage quota') ||
      message.includes('maximum storage') ||
      message.includes('storage space') ||
      message.includes('quota'))
  ) {
    // Server wording is intentionally not retained in error metadata: quota
    // responses can contain deployment-specific account details.
    return new BitwardenHttpError('STORAGE_LIMIT', status)
  }
  if (
    status === 400 &&
    message.includes('attachment') &&
    (message.includes('disabled') ||
      message.includes('not enabled') ||
      message.includes('not allowed'))
  ) {
    return new BitwardenHttpError('ATTACHMENT_REJECTED', status)
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
