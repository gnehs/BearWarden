import { createHash } from 'node:crypto'

const PWNED_PASSWORDS_RANGE_URL = 'https://api.pwnedpasswords.com/range/'
const MAX_RESPONSE_BYTES = 256 * 1024
export const PWNED_PASSWORDS_MAX_CANDIDATES = 50_000
export const PWNED_PASSWORDS_MAX_PASSWORD_CHARACTERS = 16_384
export const PWNED_PASSWORDS_MAX_TOTAL_PASSWORD_CHARACTERS = 32 * 1_024 * 1_024
const MAX_CONCURRENCY = 8
const DEFAULT_TIMEOUT_MS = 10_000
const MAX_TIMEOUT_MS = 120_000
const SHA1_PATTERN = /^[A-F0-9]{40}$/u
const RANGE_LINE_PATTERN = /^([A-F0-9]{35}):([0-9]+)$/u

export type PwnedPasswordsErrorCode =
  'ABORTED' | 'TIMEOUT' | 'NETWORK' | 'INVALID_INPUT' | 'INVALID_RESPONSE'

export class PwnedPasswordsError extends Error {
  constructor(readonly code: PwnedPasswordsErrorCode) {
    super(`Pwned Passwords request failed (${code})`)
    this.name = 'PwnedPasswordsError'
  }
}

export type PwnedPasswordsFetch = (input: string, init?: RequestInit) => Promise<Response>

export interface PwnedPasswordsClientOptions {
  fetch?: PwnedPasswordsFetch
  timeoutMs?: number
  concurrency?: number
}

interface HashTarget {
  readonly index: number
  readonly suffix: string
}

function boundedInteger(value: unknown, fallback: number, maximum: number): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1
    ? Math.min(value, maximum)
    : fallback
}

function safeArrayValue(values: readonly unknown[], index: number): unknown {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(values, String(index))
    return descriptor && 'value' in descriptor ? descriptor.value : undefined
  } catch {
    throw new PwnedPasswordsError('INVALID_INPUT')
  }
}

function groupHashTargets(hashes: readonly string[]): Map<string, HashTarget[]> {
  if (!Array.isArray(hashes) || hashes.length > PWNED_PASSWORDS_MAX_CANDIDATES) {
    throw new PwnedPasswordsError('INVALID_INPUT')
  }

  const groups = new Map<string, HashTarget[]>()
  for (let index = 0; index < hashes.length; index += 1) {
    const value = safeArrayValue(hashes, index)
    if (typeof value !== 'string') throw new PwnedPasswordsError('INVALID_INPUT')
    const hash = value.toUpperCase()
    if (!SHA1_PATTERN.test(hash)) throw new PwnedPasswordsError('INVALID_INPUT')

    const prefix = hash.slice(0, 5)
    const targets = groups.get(prefix) ?? []
    targets.push({ index, suffix: hash.slice(5) })
    if (!groups.has(prefix)) groups.set(prefix, targets)
  }
  return groups
}

async function readBoundedText(response: Response, abort: AbortController): Promise<string> {
  const contentLength = response.headers.get('content-length')
  if (contentLength !== null) {
    const parsed = Number(contentLength)
    if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > MAX_RESPONSE_BYTES) {
      abort.abort()
      await response.body?.cancel().catch(() => undefined)
      throw new PwnedPasswordsError('INVALID_RESPONSE')
    }
  }
  if (!response.body) throw new PwnedPasswordsError('INVALID_RESPONSE')

  const reader = response.body.getReader()
  const decoder = new TextDecoder('utf-8', { fatal: true })
  const chunks: string[] = []
  let bytes = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      bytes += value.byteLength
      if (bytes > MAX_RESPONSE_BYTES) {
        abort.abort()
        throw new PwnedPasswordsError('INVALID_RESPONSE')
      }
      chunks.push(decoder.decode(value, { stream: true }))
    }
    chunks.push(decoder.decode())
    return chunks.join('')
  } catch (error) {
    if (error instanceof PwnedPasswordsError) throw error
    if (error instanceof TypeError) throw new PwnedPasswordsError('INVALID_RESPONSE')
    throw error
  } finally {
    await reader.cancel().catch(() => undefined)
    reader.releaseLock()
  }
}

function parseRangeResponse(text: string): Map<string, number> {
  const lines = text.split('\n')
  if (lines.at(-1) === '') lines.pop()
  if (lines.length === 0) throw new PwnedPasswordsError('INVALID_RESPONSE')

  const result = new Map<string, number>()
  for (const rawLine of lines) {
    const line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine
    const match = RANGE_LINE_PATTERN.exec(line)
    if (!match) throw new PwnedPasswordsError('INVALID_RESPONSE')
    const suffix = match[1]!
    const count = Number(match[2])
    if (!Number.isSafeInteger(count) || count < 0 || result.has(suffix)) {
      throw new PwnedPasswordsError('INVALID_RESPONSE')
    }
    // HIBP padding entries have a zero count. Keeping zero preserves an exact
    // target match while ensuring padding can never be reported as exposure.
    result.set(suffix, count)
  }
  return result
}

function normalizeFailure(error: unknown): PwnedPasswordsError {
  return error instanceof PwnedPasswordsError ? error : new PwnedPasswordsError('NETWORK')
}

/** Produces the uppercase SHA-1 required by the HIBP k-anonymity range API. */
export function hashPasswordForPwnedLookup(password: string): string {
  if (
    typeof password !== 'string' ||
    password.length === 0 ||
    password.length > PWNED_PASSWORDS_MAX_PASSWORD_CHARACTERS
  ) {
    throw new PwnedPasswordsError('INVALID_INPUT')
  }
  return createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase()
}

/**
 * Fail-closed snapshot helper for hashing all eligible passwords while the
 * caller still holds its secret-data boundary.
 */
export function hashPasswordsForPwnedLookup(passwords: readonly string[]): string[] {
  if (!Array.isArray(passwords) || passwords.length > PWNED_PASSWORDS_MAX_CANDIDATES) {
    throw new PwnedPasswordsError('INVALID_INPUT')
  }

  const validated: string[] = []
  let totalCharacters = 0
  for (let index = 0; index < passwords.length; index += 1) {
    const password = safeArrayValue(passwords, index)
    if (
      typeof password !== 'string' ||
      password.length === 0 ||
      password.length > PWNED_PASSWORDS_MAX_PASSWORD_CHARACTERS
    ) {
      throw new PwnedPasswordsError('INVALID_INPUT')
    }
    totalCharacters += password.length
    if (totalCharacters > PWNED_PASSWORDS_MAX_TOTAL_PASSWORD_CHARACTERS) {
      throw new PwnedPasswordsError('INVALID_INPUT')
    }
    validated.push(password)
  }
  return validated.map((password) => hashPasswordForPwnedLookup(password))
}

/**
 * Main-process-only client for HIBP's anonymous Pwned Passwords range API.
 *
 * Full hashes are accepted so a caller can hash while holding its secret-data
 * boundary, then perform network work after releasing it. Only exposure counts,
 * aligned to the original input indices, are returned.
 */
export class PwnedPasswordsClient {
  private readonly fetchFn: PwnedPasswordsFetch
  private readonly timeoutMs: number
  private readonly concurrency: number

  constructor(options: PwnedPasswordsClientOptions = {}) {
    this.fetchFn = options.fetch ?? fetch
    this.timeoutMs = boundedInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS)
    this.concurrency = boundedInteger(options.concurrency, MAX_CONCURRENCY, MAX_CONCURRENCY)
  }

  async lookupSha1Hashes(hashes: readonly string[], signal?: AbortSignal): Promise<number[]> {
    if (signal?.aborted) throw new PwnedPasswordsError('ABORTED')
    const groups = groupHashTargets(hashes)
    if (groups.size === 0) return []

    const counts = Array.from<number>({ length: hashes.length }).fill(0)
    const entries = [...groups.entries()]
    const batchAbort = new AbortController()
    let cursor = 0
    let firstFailure: PwnedPasswordsError | null = null

    const worker = async (): Promise<void> => {
      while (!firstFailure) {
        const index = cursor
        cursor += 1
        const entry = entries[index]
        if (!entry) return
        const [prefix, targets] = entry
        try {
          const matches = await this.lookupPrefix(prefix, signal, batchAbort.signal)
          for (const target of targets) counts[target.index] = matches.get(target.suffix) ?? 0
        } catch (error) {
          if (!firstFailure) firstFailure = normalizeFailure(error)
          batchAbort.abort()
          return
        }
      }
    }

    try {
      await Promise.all(
        Array.from({ length: Math.min(this.concurrency, entries.length) }, () => worker())
      )
      if (signal?.aborted) throw new PwnedPasswordsError('ABORTED')
      if (firstFailure) throw firstFailure
      return counts
    } finally {
      batchAbort.abort()
      groups.clear()
      entries.length = 0
    }
  }

  private async lookupPrefix(
    prefix: string,
    externalSignal: AbortSignal | undefined,
    batchSignal: AbortSignal
  ): Promise<Map<string, number>> {
    const timeoutAbort = new AbortController()
    const bodyAbort = new AbortController()
    const timer = setTimeout(() => timeoutAbort.abort(), this.timeoutMs)
    timer.unref?.()
    const requestSignal = AbortSignal.any(
      [externalSignal, batchSignal, timeoutAbort.signal, bodyAbort.signal].filter(
        (value): value is AbortSignal => value !== undefined
      )
    )

    try {
      const response = await this.fetchFn(`${PWNED_PASSWORDS_RANGE_URL}${prefix}`, {
        method: 'GET',
        headers: {
          accept: 'text/plain',
          'add-padding': 'true',
          'cache-control': 'no-store',
          'user-agent': 'BearWarden'
        },
        cache: 'no-store',
        credentials: 'omit',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: requestSignal
      })
      if (response.status !== 200) {
        await response.body?.cancel().catch(() => undefined)
        throw new PwnedPasswordsError('INVALID_RESPONSE')
      }
      const contentType = response.headers
        .get('content-type')
        ?.split(';', 1)[0]
        ?.trim()
        .toLowerCase()
      if (contentType !== 'text/plain') {
        await response.body?.cancel().catch(() => undefined)
        throw new PwnedPasswordsError('INVALID_RESPONSE')
      }
      const text = await readBoundedText(response, bodyAbort)
      if (externalSignal?.aborted) throw new PwnedPasswordsError('ABORTED')
      if (timeoutAbort.signal.aborted) throw new PwnedPasswordsError('TIMEOUT')
      return parseRangeResponse(text)
    } catch (error) {
      if (externalSignal?.aborted) throw new PwnedPasswordsError('ABORTED')
      if (timeoutAbort.signal.aborted) throw new PwnedPasswordsError('TIMEOUT')
      if (error instanceof PwnedPasswordsError) throw error
      if (batchSignal.aborted) throw new PwnedPasswordsError('ABORTED')
      throw new PwnedPasswordsError('NETWORK')
    } finally {
      clearTimeout(timer)
    }
  }
}
