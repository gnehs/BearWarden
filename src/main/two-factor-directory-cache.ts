import { chmod, mkdir, open, rename, unlink } from 'node:fs/promises'
import { randomBytes } from 'node:crypto'
import { dirname } from 'node:path'
import {
  InactiveTwoFactorError,
  loadTwoFactorDirectoryTotpJson,
  TWO_FACTOR_DIRECTORY_TOTP_URL,
  type TwoFactorDirectoryDataset
} from './inactive-two-factor'

const MAX_DATASET_BYTES = 4 * 1024 * 1024
const DEFAULT_FRESH_MS = 7 * 24 * 60 * 60 * 1_000
const DEFAULT_TIMEOUT_MS = 10_000
const JSON_CONTENT_TYPE = /^application\/(?:[a-z0-9.+-]+\+)?json(?:\s*;|$)/iu

export type TwoFactorDirectoryCacheErrorCode =
  'UNAVAILABLE' | 'INVALID_RESPONSE' | 'DISPOSED' | 'DOCUMENTATION_NOT_FOUND'

export class TwoFactorDirectoryCacheError extends Error {
  constructor(readonly code: TwoFactorDirectoryCacheErrorCode) {
    super(code)
    this.name = 'TwoFactorDirectoryCacheError'
  }
}

export interface TwoFactorDirectoryCacheOptions {
  fetch?: typeof fetch
  now?: () => number
  freshMs?: number
  timeoutMs?: number
  openExternal?: (url: string) => void | Promise<void>
}

interface ValidatedCache {
  dataset: TwoFactorDirectoryDataset
  modifiedAt: number
}

function cacheError(code: TwoFactorDirectoryCacheErrorCode): never {
  throw new TwoFactorDirectoryCacheError(code)
}

async function syncDirectory(path: string): Promise<void> {
  let handle: Awaited<ReturnType<typeof open>> | undefined
  try {
    handle = await open(path, 'r')
    await handle.sync()
  } catch {
    // Directory fsync is not supported by every Electron target.
  } finally {
    await handle?.close()
  }
}

async function atomicWritePrivate(path: string, contents: string): Promise<void> {
  const directory = dirname(path)
  await mkdir(directory, { recursive: true, mode: 0o700 })
  const temporaryPath = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`
  let handle: Awaited<ReturnType<typeof open>> | undefined
  try {
    handle = await open(temporaryPath, 'wx', 0o600)
    await handle.writeFile(contents, { encoding: 'utf8' })
    await handle.sync()
    await handle.close()
    handle = undefined
    await rename(temporaryPath, path)
    await chmod(path, 0o600)
    await syncDirectory(directory)
  } catch (error) {
    await handle?.close()
    await unlink(temporaryPath).catch(() => undefined)
    throw error
  }
}

async function readBoundedDataset(path: string): Promise<ValidatedCache | null> {
  let handle: Awaited<ReturnType<typeof open>> | undefined
  let contents: Buffer | undefined
  try {
    handle = await open(path, 'r')
    const stats = await handle.stat()
    if (!stats.isFile() || stats.size <= 0 || stats.size > MAX_DATASET_BYTES) return null
    contents = await handle.readFile()
    if (contents.length === 0 || contents.length > MAX_DATASET_BYTES) return null
    const serialized = new TextDecoder('utf-8', { fatal: true }).decode(contents)
    return { dataset: loadTwoFactorDirectoryTotpJson(serialized), modifiedAt: stats.mtimeMs }
  } catch {
    return null
  } finally {
    contents?.fill(0)
    await handle?.close()
  }
}

async function readBoundedResponse(response: Response, abort: AbortController): Promise<string> {
  const contentLength = response.headers.get('content-length')
  if (contentLength !== null) {
    const parsed = Number(contentLength)
    if (!Number.isSafeInteger(parsed) || parsed <= 0 || parsed > MAX_DATASET_BYTES) {
      abort.abort()
      await response.body?.cancel().catch(() => undefined)
      cacheError('INVALID_RESPONSE')
    }
  }
  const reader = response.body?.getReader()
  if (!reader) cacheError('INVALID_RESPONSE')
  const decoder = new TextDecoder('utf-8', { fatal: true })
  const chunks: string[] = []
  let bytes = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      bytes += value.byteLength
      if (bytes > MAX_DATASET_BYTES) {
        abort.abort()
        cacheError('INVALID_RESPONSE')
      }
      chunks.push(decoder.decode(value, { stream: true }))
    }
    chunks.push(decoder.decode())
    if (bytes === 0) cacheError('INVALID_RESPONSE')
    return chunks.join('')
  } catch (error) {
    if (error instanceof TwoFactorDirectoryCacheError) throw error
    cacheError('INVALID_RESPONSE')
  } finally {
    await reader.cancel().catch(() => undefined)
    reader.releaseLock()
  }
}

export class TwoFactorDirectoryCache {
  private readonly fetchImpl: typeof fetch
  private readonly now: () => number
  private readonly freshMs: number
  private readonly timeoutMs: number
  private readonly openExternal?: (url: string) => void | Promise<void>
  private active: { abort: AbortController; promise: Promise<TwoFactorDirectoryDataset> } | null =
    null
  private memory: ValidatedCache | null = null
  private disposed = false

  constructor(
    private readonly cachePath: string,
    options: TwoFactorDirectoryCacheOptions = {}
  ) {
    this.fetchImpl = options.fetch ?? fetch
    this.now = options.now ?? Date.now
    this.freshMs = options.freshMs ?? DEFAULT_FRESH_MS
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
    this.openExternal = options.openExternal
  }

  getDataset(): Promise<TwoFactorDirectoryDataset> {
    if (this.disposed) return Promise.reject(new TwoFactorDirectoryCacheError('DISPOSED'))
    if (this.active) return this.active.promise
    const abort = new AbortController()
    const promise = this.load(abort).finally(() => {
      if (this.active?.promise === promise) this.active = null
    })
    this.active = { abort, promise }
    return promise
  }

  async openDocumentation(matchedDomain: string): Promise<void> {
    if (
      typeof matchedDomain !== 'string' ||
      matchedDomain.length === 0 ||
      matchedDomain.length > 253 ||
      matchedDomain !== matchedDomain.toLowerCase()
    ) {
      cacheError('DOCUMENTATION_NOT_FOUND')
    }
    const dataset = await this.getDataset()
    const entry = dataset.entries.find((candidate) => candidate.domain === matchedDomain)
    if (!entry?.documentationUrl || !this.openExternal) cacheError('DOCUMENTATION_NOT_FOUND')
    await this.openExternal(entry.documentationUrl)
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.active?.abort.abort()
    this.active = null
    this.memory = null
  }

  private async load(abort: AbortController): Promise<TwoFactorDirectoryDataset> {
    const cached = this.memory ?? (await readBoundedDataset(this.cachePath))
    if (this.disposed) cacheError('DISPOSED')
    if (cached) this.memory = cached
    if (cached && this.now() - cached.modifiedAt <= this.freshMs) return cached.dataset

    try {
      const { dataset, serialized } = await this.fetchDataset(abort)
      if (this.disposed) cacheError('DISPOSED')
      if (abort.signal.aborted) cacheError('UNAVAILABLE')
      await atomicWritePrivate(this.cachePath, serialized).catch(() => undefined)
      if (this.disposed) cacheError('DISPOSED')
      this.memory = { dataset, modifiedAt: this.now() }
      return dataset
    } catch (error) {
      if (this.disposed) cacheError('DISPOSED')
      if (cached) return cached.dataset
      if (error instanceof TwoFactorDirectoryCacheError) throw error
      if (error instanceof InactiveTwoFactorError) cacheError('INVALID_RESPONSE')
      cacheError('UNAVAILABLE')
    }
  }

  private async fetchDataset(
    abort: AbortController
  ): Promise<{ dataset: TwoFactorDirectoryDataset; serialized: string }> {
    const timeout = setTimeout(() => abort.abort(), this.timeoutMs)
    timeout.unref()
    try {
      const response = await this.fetchImpl(TWO_FACTOR_DIRECTORY_TOTP_URL, {
        method: 'GET',
        redirect: 'manual',
        signal: abort.signal,
        headers: { accept: 'application/json' }
      })
      if (
        response.status !== 200 ||
        (response.url !== '' && response.url !== TWO_FACTOR_DIRECTORY_TOTP_URL) ||
        !JSON_CONTENT_TYPE.test(response.headers.get('content-type') ?? '')
      ) {
        await response.body?.cancel().catch(() => undefined)
        cacheError('INVALID_RESPONSE')
      }
      const serialized = await readBoundedResponse(response, abort)
      const dataset = loadTwoFactorDirectoryTotpJson(serialized)
      return { dataset, serialized }
    } finally {
      clearTimeout(timeout)
    }
  }
}
