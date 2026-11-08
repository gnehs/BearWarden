import {
  MAX_LOGIN_PREFETCH_IDS,
  type BearWardenAPI,
  type LoginSummary,
  type LoginView
} from '../../../shared/vault-contract'
import type { VaultAuthorization } from '../stores/vault-authorization-store'
import { isSharedLoginSummary } from './organizations-ui'
import {
  canUseCachedLoginDetail,
  isCurrentPrefetchedDetailResponse,
  isCurrentSelectedDetailResponse
} from './VaultShell-security'

const detailCacheLimit = 48

export function mergeCachedSummary(cache: Map<string, LoginView>, summary: LoginSummary): void {
  const cached = cache.get(summary.id)
  if (cached) cache.set(summary.id, mergeLoginSummary(cached, summary))
}

export function mergeLoginSummary(login: LoginView, summary: LoginSummary): LoginView {
  if (summary.reprompt === 0 || summary.deletedAt) return { ...login, ...summary }
  return {
    ...login,
    id: summary.id,
    type: summary.type,
    name: summary.name,
    folderId: summary.folderId,
    favorite: summary.favorite,
    usageCount: summary.usageCount,
    lastUsedAt: summary.lastUsedAt,
    createdAt: summary.createdAt,
    updatedAt: summary.updatedAt,
    deletedAt: summary.deletedAt,
    archivedAt: summary.archivedAt,
    reprompt: summary.reprompt,
    passwordHistoryCount: summary.passwordHistoryCount,
    attachmentCount: summary.attachmentCount
  }
}

export function cacheLoginDetail(cache: Map<string, LoginView>, login: LoginView): void {
  cache.delete(login.id)
  while (cache.size >= detailCacheLimit) {
    const oldestId = cache.keys().next().value
    if (!oldestId) break
    cache.delete(oldestId)
  }
  cache.set(login.id, login)
}

export function firstAuthorizationToken(
  ids: readonly string[],
  tokenFor: (id: string) => string | undefined
): string | undefined {
  for (const id of ids) {
    const token = tokenFor(id)
    if (token) return token
  }
  return undefined
}

export function authorizationTokenField(token: string | undefined): {
  authorizationToken?: string
} {
  return token ? { authorizationToken: token } : {}
}

export interface LoginDetailCacheOptions {
  logins: Pick<BearWardenAPI['logins'], 'get' | 'prefetch'>
  sharedLogins: Pick<BearWardenAPI['sharedLogins'], 'get'>
  authorization: Pick<VaultAuthorization, 'token' | 'withReprompt'>
  findItem: (id: string) => LoginSummary | undefined
  selectedId: () => string | null
  /** Runs for every detail that prefetch finds or fetches, for example to warm card covers. */
  onPrefetched: (login: LoginView) => void
}

export interface LoginDetailCache {
  /** The raw cached entry, without checking whether it may still be shown. */
  get: (id: string) => LoginView | undefined
  /** The cached entry when its summary and authorization still allow showing it. */
  usable: (id: string) => LoginView | undefined
  /** Detail for the selected item; rejects when the item stops being selected or authorized. */
  load: (id: string) => Promise<LoginView>
  /** Queues an unprotected active item for one batched background fetch. */
  prefetch: (id: string) => void
  remember: (login: LoginView) => void
  forget: (id: string) => void
  mergeSummary: (summary: LoginSummary) => void
  /** Drops entries missing from a fresh full list and merges the rest with their summaries. */
  retainSummaries: (summaries: readonly LoginSummary[]) => void
  moveFolderContentsToUnfiled: (folderId: string) => void
  /** Drops entries and makes every in-flight detail response stale. */
  invalidate: (ids: Iterable<string>) => void
  clear: () => void
}

/**
 * Decrypted-detail cache for the vault session. Each invalidation bumps a generation so a
 * response that started before it, whether a selected-item load or a background prefetch,
 * is never cached or shown afterwards.
 */
export function createLoginDetailCache(options: LoginDetailCacheOptions): LoginDetailCache {
  const cache = new Map<string, LoginView>()
  const requests = new Map<string, Promise<LoginView>>()
  const prefetchRequests = new Map<string, Promise<LoginView | undefined>>()
  const prefetchQueue = new Set<string>()
  let prefetchScheduled = false
  let generation = 0

  const hasAuthorization = (id: string): boolean => Boolean(options.authorization.token(id))

  function usable(id: string): LoginView | undefined {
    const cached = cache.get(id)
    if (
      cached &&
      canUseCachedLoginDetail(options.findItem(id), cached.reprompt, hasAuthorization(id))
    ) {
      return cached
    }
    return undefined
  }

  function invalidate(ids: Iterable<string>): void {
    generation += 1
    requests.clear()
    for (const id of ids) cache.delete(id)
  }

  function startSelectedRequest(id: string): Promise<LoginView> {
    let requestGeneration = generation
    return options.authorization
      .withReprompt([id], (tokenFor) => {
        requestGeneration = generation
        return options.logins.get({ id, ...authorizationTokenField(tokenFor(id)) })
      })
      .then((login) => {
        if (
          !isCurrentSelectedDetailResponse({
            id,
            selectedId: options.selectedId(),
            requestGeneration,
            currentGeneration: generation,
            reprompt: login.reprompt,
            authorizationToken: options.authorization.token(id)
          })
        ) {
          throw new Error('DETAIL_REQUEST_INVALIDATED')
        }
        cacheLoginDetail(cache, login)
        return login
      })
  }

  function load(id: string): Promise<LoginView> {
    const summary = options.findItem(id)
    if (summary?.deletedAt) return Promise.reject(new Error('INVALID_INPUT'))
    if (summary && isSharedLoginSummary(summary)) return options.sharedLogins.get({ id })
    const cached = usable(id)
    if (cached) {
      cacheLoginDetail(cache, cached)
      return Promise.resolve(cached)
    }

    const pending = requests.get(id)
    if (pending) return pending

    const pendingPrefetch = prefetchRequests.get(id)
    const promise = pendingPrefetch
      ? pendingPrefetch.then((prefetched) => {
          const currentCached = cache.get(id) ?? prefetched
          if (
            currentCached &&
            canUseCachedLoginDetail(
              options.findItem(id),
              currentCached.reprompt,
              hasAuthorization(id)
            )
          ) {
            cacheLoginDetail(cache, currentCached)
            return currentCached
          }
          if (options.selectedId() !== id) throw new Error('DETAIL_REQUEST_INVALIDATED')
          return startSelectedRequest(id)
        })
      : startSelectedRequest(id)
    requests.set(id, promise)
    void promise
      .catch(() => undefined)
      .finally(() => {
        if (requests.get(id) === promise) requests.delete(id)
      })
    return promise
  }

  function isPrefetchEligible(id: string): boolean {
    const summary = options.findItem(id)
    // Never speculatively cross the authorization boundary or hydrate inactive items.
    return Boolean(
      summary &&
      !isSharedLoginSummary(summary) &&
      summary.reprompt === 0 &&
      summary.deletedAt === null &&
      summary.archivedAt === null &&
      !cache.has(id) &&
      !requests.has(id) &&
      !prefetchRequests.has(id)
    )
  }

  function flushPrefetchQueue(): void {
    prefetchScheduled = false
    const eligibleIds = [...prefetchQueue].filter(isPrefetchEligible)
    prefetchQueue.clear()

    for (let offset = 0; offset < eligibleIds.length; offset += MAX_LOGIN_PREFETCH_IDS) {
      const ids = eligibleIds.slice(offset, offset + MAX_LOGIN_PREFETCH_IDS)
      const requestGeneration = generation
      const batchPromise = options.logins.prefetch({ ids })
      for (const queuedId of ids) {
        const itemPromise = batchPromise
          .then((logins) => {
            const login = logins.find((candidate) => candidate.id === queuedId)
            if (
              !login ||
              !isCurrentPrefetchedDetailResponse({
                requestGeneration,
                currentGeneration: generation,
                response: login,
                summary: options.findItem(queuedId)
              })
            ) {
              return undefined
            }
            cacheLoginDetail(cache, login)
            options.onPrefetched(login)
            return login
          })
          .catch(() => undefined)
          .finally(() => {
            if (prefetchRequests.get(queuedId) === itemPromise) prefetchRequests.delete(queuedId)
          })
        prefetchRequests.set(queuedId, itemPromise)
      }
    }
  }

  function prefetch(id: string): void {
    const cached = cache.get(id)
    if (cached) {
      options.onPrefetched(cached)
      return
    }
    if (!isPrefetchEligible(id)) return
    prefetchQueue.add(id)
    if (prefetchScheduled) return
    prefetchScheduled = true
    queueMicrotask(flushPrefetchQueue)
  }

  return {
    get: (id) => cache.get(id),
    usable,
    load,
    prefetch,
    remember: (login) => cacheLoginDetail(cache, login),
    forget: (id) => {
      cache.delete(id)
    },
    mergeSummary: (summary) => mergeCachedSummary(cache, summary),
    retainSummaries: (summaries) => {
      const currentIds = new Set(summaries.map((summary) => summary.id))
      for (const cachedId of cache.keys()) {
        if (!currentIds.has(cachedId)) cache.delete(cachedId)
      }
      for (const summary of summaries) mergeCachedSummary(cache, summary)
    },
    moveFolderContentsToUnfiled: (folderId) => {
      for (const [id, cached] of cache) {
        if (cached.folderId === folderId) cache.set(id, { ...cached, folderId: null })
      }
    },
    invalidate,
    clear: () => {
      generation += 1
      requests.clear()
      prefetchRequests.clear()
      prefetchQueue.clear()
      cache.clear()
    }
  }
}
