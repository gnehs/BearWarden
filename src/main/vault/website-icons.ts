import type { VaultCore } from './core'
import {
  type EncryptedImageCache,
  type ImageCacheKeys,
  clearImageCacheKeys
} from '../encrypted-image-cache'
import { ConcurrencyLimiter, ImageMemoryCache } from '../image-memory-cache'
import { VaultError } from '../vault-errors'
import { findLogin, assertActiveLogin } from './data-lookup'
import type { LoginIdRequest } from '../../shared/vault-contract'
import {
  fetchWebsiteIcon,
  parseWebsiteHostname,
  resolveWebsiteIconUrl,
  websiteIconDataUrl
} from '../website-icon'
import { assertUuid } from './parse-primitives'
import type { ItemReadAuthorizationValidator } from './types'

const WEBSITE_ICON_TTL_MS = 7 * 24 * 60 * 60 * 1000

const WEBSITE_ICON_MISSING_TTL_MS = 24 * 60 * 60 * 1000

const WEBSITE_ICON_RETRY_MS = 10 * 60 * 1000

/**
 * Website icons for item lists: an in-memory cache in front of the encrypted on-disk image cache,
 * with deduplicated, concurrency-limited fetches that never hold the vault mutex.
 */
export class VaultWebsiteIcons {
  private readonly websiteIconCache = new ImageMemoryCache<string | null>({
    maxEntries: 512,
    maxSize: 32 * 1024 * 1024
  })
  private readonly websiteIconRequests = new Map<string, Promise<string | null>>()
  private readonly websiteIconFetches = new ConcurrencyLimiter(6)
  /** Aborted on lock so detached image downloads stop as soon as the vault key is gone. */
  private readonly imageRequestAborts = new Set<AbortController>()

  constructor(
    private readonly core: VaultCore,
    private readonly fetch: typeof globalThis.fetch,
    private readonly imageCache: EncryptedImageCache | null
  ) {
    core.registerResource({
      abort: () => {
        for (const abort of this.imageRequestAborts) abort.abort()
        this.imageRequestAborts.clear()
      },
      clear: () => {
        this.websiteIconCache.clear()
        this.websiteIconRequests.clear()
      }
    })
  }

  async getWebsiteIcon(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<string | null> {
    const iconUrl = (() => {
      assertUuid(request.id)
      const data = this.core.requireFastReadData()
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      if (
        login.reprompt === 1 &&
        !validateAuthorization?.([login.id], { generation: this.core.generation })
      ) {
        throw new VaultError('REPROMPT_REQUIRED')
      }
      if (login.type !== 'login' || !login.uri || !data.sync) return null
      const hostname = parseWebsiteHostname(login.uri)
      return hostname ? resolveWebsiteIconUrl(data.sync.serverUrl, hostname) : null
    })()
    if (!iconUrl) return null

    const cacheKey = iconUrl.toString()
    const cached = this.websiteIconCache.get(cacheKey)
    if (cached) return cached.value
    const existingRequest = this.websiteIconRequests.get(cacheKey)
    if (existingRequest) return existingRequest

    const pendingRequest = this.loadWebsiteIcon(cacheKey, iconUrl).finally(() => {
      if (this.websiteIconRequests.get(cacheKey) === pendingRequest) {
        this.websiteIconRequests.delete(cacheKey)
      }
    })
    this.websiteIconRequests.set(cacheKey, pendingRequest)
    return pendingRequest
  }

  /** Memory LRU miss: try the encrypted disk cache, then a concurrency-limited fetch. */
  private async loadWebsiteIcon(cacheKey: string, iconUrl: URL): Promise<string | null> {
    const generation = this.core.generation
    const keys = this.imageCacheKeys()
    const abort = new AbortController()
    this.imageRequestAborts.add(abort)
    try {
      const stored = keys ? await this.imageCache?.read(keys, 'website-icon', cacheKey) : null
      if (generation !== this.core.generation) return null
      const storedValue =
        stored?.mediaType && stored.data ? websiteIconDataUrl(stored.mediaType, stored.data) : null
      stored?.data?.fill(0)
      const storedTtl = stored?.mediaType ? WEBSITE_ICON_TTL_MS : WEBSITE_ICON_MISSING_TTL_MS
      if (stored && stored.storedAt + storedTtl > this.core.now().getTime()) {
        this.rememberWebsiteIcon(cacheKey, storedValue, storedTtl)
        return storedValue
      }

      let result: Awaited<ReturnType<typeof fetchWebsiteIcon>>
      try {
        result = await this.websiteIconFetches.run(
          () => fetchWebsiteIcon(iconUrl, this.fetch, abort.signal),
          abort.signal
        )
      } catch {
        return null
      }
      if (generation !== this.core.generation) return null

      if (result.kind === 'failed') {
        // Keep showing a stale icon instead of a letter, and retry the network later.
        if (stored) this.rememberWebsiteIcon(cacheKey, storedValue, WEBSITE_ICON_RETRY_MS)
        return storedValue
      }
      const storedAt = this.core.now().getTime()
      const value =
        result.kind === 'icon' ? websiteIconDataUrl(result.mediaType, result.data) : null
      if (keys) {
        void this.imageCache?.write(keys, 'website-icon', cacheKey, {
          mediaType: result.kind === 'icon' ? result.mediaType : null,
          data: result.kind === 'icon' ? result.data : null,
          storedAt
        })
      }
      this.rememberWebsiteIcon(
        cacheKey,
        value,
        result.kind === 'icon' ? WEBSITE_ICON_TTL_MS : WEBSITE_ICON_MISSING_TTL_MS
      )
      return value
    } finally {
      this.imageRequestAborts.delete(abort)
      if (keys) clearImageCacheKeys(keys)
    }
  }

  private rememberWebsiteIcon(cacheKey: string, value: string | null, ttlMs: number): void {
    this.websiteIconCache.set(cacheKey, value, { size: value?.length ?? 0, ttlMs })
  }

  /**
   * Derives per-operation image cache subkeys from the unlocked vault key. Callers must zero the
   * result with `clearImageCacheKeys`, and must re-check `generation` before every cache write.
   */
  private imageCacheKeys(): ImageCacheKeys | null {
    if (!this.imageCache) return null
    return this.core.imageCacheKeys()
  }
}
