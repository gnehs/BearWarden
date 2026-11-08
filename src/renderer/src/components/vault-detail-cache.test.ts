import { describe, expect, it, vi } from 'vitest'
import { toLoginSummary, toSharedLoginSummary } from '../../../shared/login-summary'
import {
  MAX_LOGIN_PREFETCH_IDS,
  type LoginSummary,
  type LoginView,
  type SharedLoginSummary,
  type SharedLoginView
} from '../../../shared/vault-contract'
import {
  authorizationTokenField,
  cacheLoginDetail,
  createLoginDetailCache,
  firstAuthorizationToken,
  mergeCachedSummary,
  mergeLoginSummary,
  type LoginDetailCache
} from './vault-detail-cache'
import { makeLoginView } from './vault-detail-test-fixtures'

describe('mergeLoginSummary', () => {
  it('does not replace protected detail fields with redacted summary values', () => {
    const login = makeLoginView()
    const summary: LoginSummary = {
      ...toLoginSummary(login),
      name: 'Renamed item',
      username: '',
      uri: null,
      uris: [],
      favorite: true,
      reprompt: 1
    }

    const merged = mergeLoginSummary(login, summary)

    expect(merged.name).toBe('Renamed item')
    expect(merged.favorite).toBe(true)
    expect(merged.reprompt).toBe(1)
    expect(merged.username).toBe('sample-user')
    expect(merged.uri).toBe('https://example.invalid')
    expect(merged.uris).toEqual([{ uri: 'https://example.invalid', match: null }])
  })

  it('accepts complete public and deleted summaries', () => {
    const login = makeLoginView()
    const publicSummary = { ...toLoginSummary(login), username: 'updated-user' }
    const deletedSummary = {
      ...toLoginSummary(login),
      username: '',
      uris: [],
      deletedAt: '2026-07-17T00:00:00.000Z',
      reprompt: 1 as const
    }

    expect(mergeLoginSummary(login, publicSummary).username).toBe('updated-user')
    expect(mergeLoginSummary(login, deletedSummary).username).toBe('')
    expect(mergeLoginSummary(login, deletedSummary).uris).toEqual([])
  })
})

describe('detail cache helpers', () => {
  it('updates cached summaries without adding missing detail entries', () => {
    const cache = new Map([['item-id', makeLoginView()]])

    mergeCachedSummary(cache, { ...toLoginSummary(makeLoginView()), name: 'Updated name' })
    mergeCachedSummary(cache, toLoginSummary(makeLoginView({ id: 'missing' })))

    expect(cache.get('item-id')?.name).toBe('Updated name')
    expect(cache.has('missing')).toBe(false)
  })

  it('refreshes recency and evicts the oldest detail at the cache limit', () => {
    const cache = new Map<string, ReturnType<typeof makeLoginView>>()
    for (let index = 0; index < 48; index += 1) {
      cacheLoginDetail(cache, makeLoginView({ id: `item-${index}` }))
    }

    cacheLoginDetail(cache, makeLoginView({ id: 'item-0', name: 'Recently used' }))
    cacheLoginDetail(cache, makeLoginView({ id: 'item-48' }))

    expect(cache.size).toBe(48)
    expect(cache.get('item-0')?.name).toBe('Recently used')
    expect(cache.has('item-1')).toBe(false)
    expect(cache.has('item-48')).toBe(true)
  })
})

describe('summary and authorization projections', () => {
  it('creates an independent URI summary and preserves optional fields', () => {
    const login = makeLoginView({ passkeyCount: 2 })
    const summary = toLoginSummary(login)
    const card = makeLoginView({ type: 'card', cardBrand: 'visa' })

    expect(toLoginSummary(card).cardBrand).toBe('visa')
    expect(summary.passkeyCount).toBe(2)
    expect(summary.uris).toEqual(login.uris)
    expect(summary.uris).not.toBe(login.uris)
    expect(summary.uris[0]).not.toBe(login.uris[0])
  })

  it('hides protected identifiers in the list summary written after saving a re-prompt item', () => {
    const saved = makeLoginView({ reprompt: 1, subtitle: '', hasTotp: true, favorite: true })

    const summary = toLoginSummary(saved)

    expect(summary).toMatchObject({
      name: 'Sample item',
      favorite: true,
      reprompt: 1,
      subtitle: '',
      username: '',
      uri: null,
      uris: [],
      hasTotp: false,
      passkeyCount: 0
    })
  })

  it('hides identifiers and personal state in the list summary of a trashed item', () => {
    const trashed = makeLoginView({
      deletedAt: '2026-07-17T00:00:00.000Z',
      favorite: true,
      usageCount: 3,
      lastUsedAt: '2026-07-16T12:00:00.000Z'
    })

    expect(toLoginSummary(trashed)).toMatchObject({
      subtitle: '',
      username: '',
      uri: null,
      uris: [],
      favorite: false,
      usageCount: 0,
      lastUsedAt: null
    })
  })

  it('hides the username in a shared list summary when the member cannot view secrets', () => {
    const saved: SharedLoginView = {
      ...makeLoginView({ subtitle: 'sample-user', hasTotp: true }),
      organizationId: 'org-id',
      collectionIds: ['collection-id'],
      shared: true,
      edit: true,
      viewPassword: false,
      delete: false,
      restore: false
    }

    expect(toSharedLoginSummary(saved)).toMatchObject({
      subtitle: '',
      username: '',
      hasTotp: false,
      viewPassword: false
    })
  })

  it('returns the first available authorization token in item order', () => {
    const tokens = new Map([
      ['second', 'second-token'],
      ['third', 'third-token']
    ])

    expect(firstAuthorizationToken(['first', 'second', 'third'], (id) => tokens.get(id))).toBe(
      'second-token'
    )
    expect(firstAuthorizationToken(['first'], (id) => tokens.get(id))).toBeUndefined()
  })

  it('omits the authorization field entirely when no token is available', () => {
    expect(authorizationTokenField('token')).toEqual({ authorizationToken: 'token' })
    expect(Object.keys(authorizationTokenField(undefined))).toEqual([])
    expect(Object.keys(authorizationTokenField(''))).toEqual([])
  })
})

interface Deferred<T> {
  promise: Promise<T>
  resolve: (value: T) => void
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise
  })
  return { promise, resolve }
}

async function settle(): Promise<void> {
  for (let index = 0; index < 5; index++) await Promise.resolve()
}

interface Harness {
  cache: LoginDetailCache
  summaries: Map<string, LoginSummary>
  tokens: Map<string, string>
  selection: { id: string | null }
  get: ReturnType<typeof vi.fn>
  prefetch: ReturnType<typeof vi.fn>
  getShared: ReturnType<typeof vi.fn>
  prefetched: string[]
}

function setup(
  options: {
    get?: (request: { id: string }) => Promise<LoginView>
    prefetch?: (request: { ids: string[] }) => Promise<LoginView[]>
  } = {}
): Harness {
  const summaries = new Map<string, LoginSummary>()
  const tokens = new Map<string, string>()
  const selection = { id: null as string | null }
  const prefetched: string[] = []
  const get = vi.fn(options.get ?? (async ({ id }) => makeLoginView({ id })))
  const prefetch = vi.fn(
    options.prefetch ?? (async ({ ids }) => ids.map((id) => makeLoginView({ id })))
  )
  const getShared = vi.fn(
    async ({ id }: { id: string }) =>
      ({ ...makeLoginView({ id }), shared: true }) as SharedLoginView
  )
  const cache = createLoginDetailCache({
    logins: { get, prefetch },
    sharedLogins: { get: getShared },
    authorization: {
      token: (id) => tokens.get(id),
      withReprompt: (_ids, operation) => operation((id) => tokens.get(id))
    },
    findItem: (id) => summaries.get(id),
    selectedId: () => selection.id,
    onPrefetched: (login) => prefetched.push(login.id)
  })
  return { cache, summaries, tokens, selection, get, prefetch, getShared, prefetched }
}

function addSummary(harness: Harness, login: LoginView): void {
  harness.summaries.set(login.id, toLoginSummary(login))
}

describe('createLoginDetailCache', () => {
  it('fetches the selected detail once, shares concurrent loads and serves it from cache', async () => {
    const harness = setup()
    addSummary(harness, makeLoginView({ id: 'item' }))
    harness.selection.id = 'item'

    const [first, second] = await Promise.all([
      harness.cache.load('item'),
      harness.cache.load('item')
    ])
    const third = await harness.cache.load('item')

    expect(first.id).toBe('item')
    expect(second).toBe(first)
    expect(third).toBe(first)
    expect(harness.cache.usable('item')).toBe(first)
    expect(harness.get).toHaveBeenCalledTimes(1)
  })

  it('reads shared items through the shared-login API', async () => {
    const harness = setup()
    const shared = { ...makeLoginView({ id: 'shared' }), shared: true } as SharedLoginView
    const sharedSummary: SharedLoginSummary = {
      ...toLoginSummary(shared),
      organizationId: 'org',
      collectionIds: [],
      shared: true,
      edit: false,
      viewPassword: true,
      delete: false,
      restore: false
    }
    harness.summaries.set('shared', sharedSummary)

    await expect(harness.cache.load('shared')).resolves.toMatchObject({ id: 'shared' })

    expect(harness.getShared).toHaveBeenCalledWith({ id: 'shared' })
    expect(harness.get).not.toHaveBeenCalled()
  })

  it('discards a detail response once its item is no longer selected', async () => {
    const response = deferred<LoginView>()
    const harness = setup({ get: () => response.promise })
    addSummary(harness, makeLoginView({ id: 'item' }))
    harness.selection.id = 'item'

    const load = harness.cache.load('item')
    harness.selection.id = 'other'
    response.resolve(makeLoginView({ id: 'item' }))

    await expect(load).rejects.toThrow('DETAIL_REQUEST_INVALIDATED')
    expect(harness.cache.get('item')).toBeUndefined()
  })

  it('discards a detail response that started before an invalidation', async () => {
    const response = deferred<LoginView>()
    const harness = setup({ get: () => response.promise })
    addSummary(harness, makeLoginView({ id: 'item' }))
    harness.selection.id = 'item'

    const load = harness.cache.load('item')
    harness.cache.invalidate(['item'])
    response.resolve(makeLoginView({ id: 'item' }))

    await expect(load).rejects.toThrow('DETAIL_REQUEST_INVALIDATED')
    expect(harness.cache.get('item')).toBeUndefined()
  })

  it('keeps protected detail usable only while its authorization lasts', async () => {
    const protectedLogin = makeLoginView({ id: 'protected', reprompt: 1 })
    const harness = setup({ get: async () => protectedLogin })
    addSummary(harness, protectedLogin)
    harness.selection.id = 'protected'
    harness.tokens.set('protected', 'token')

    await harness.cache.load('protected')
    expect(harness.cache.usable('protected')).toBe(protectedLogin)

    harness.tokens.delete('protected')
    expect(harness.cache.usable('protected')).toBeUndefined()
  })

  it('prefetches unprotected active items in batches and skips everything else', async () => {
    const harness = setup()
    const ids = Array.from({ length: MAX_LOGIN_PREFETCH_IDS + 1 }, (_, index) => `item-${index}`)
    for (const id of ids) addSummary(harness, makeLoginView({ id }))
    addSummary(harness, makeLoginView({ id: 'protected', reprompt: 1 }))
    addSummary(harness, makeLoginView({ id: 'archived', archivedAt: '2026-07-17T00:00:00.000Z' }))

    for (const id of [...ids, 'protected', 'archived', 'missing']) harness.cache.prefetch(id)
    await settle()

    expect(harness.prefetch.mock.calls.map(([request]) => request.ids)).toEqual([
      ids.slice(0, MAX_LOGIN_PREFETCH_IDS),
      ids.slice(MAX_LOGIN_PREFETCH_IDS)
    ])
    expect(harness.prefetched).toEqual(ids)
    expect(harness.cache.get(ids.at(-1)!)?.id).toBe(ids.at(-1))
    expect(harness.cache.get('protected')).toBeUndefined()
  })

  it('drops a prefetch that resolves after the cache is cleared', async () => {
    const response = deferred<LoginView[]>()
    const harness = setup({ prefetch: () => response.promise })
    addSummary(harness, makeLoginView({ id: 'item' }))

    harness.cache.prefetch('item')
    await settle()
    harness.cache.clear()
    response.resolve([makeLoginView({ id: 'item' })])
    await settle()

    expect(harness.cache.get('item')).toBeUndefined()
    expect(harness.prefetched).toEqual([])
  })

  it('answers a selected load from an in-flight prefetch without a second request', async () => {
    const response = deferred<LoginView[]>()
    const harness = setup({ prefetch: () => response.promise })
    addSummary(harness, makeLoginView({ id: 'item' }))
    harness.selection.id = 'item'

    harness.cache.prefetch('item')
    await settle()
    const load = harness.cache.load('item')
    response.resolve([makeLoginView({ id: 'item' })])

    await expect(load).resolves.toMatchObject({ id: 'item' })
    expect(harness.get).not.toHaveBeenCalled()
  })

  it('retains only entries that are still listed and merges their new summaries', async () => {
    const harness = setup()
    for (const id of ['kept', 'removed']) {
      addSummary(harness, makeLoginView({ id }))
      harness.selection.id = id
      await harness.cache.load(id)
    }

    harness.cache.retainSummaries([
      { ...toLoginSummary(makeLoginView({ id: 'kept' })), name: 'Renamed' }
    ])

    expect(harness.cache.get('kept')?.name).toBe('Renamed')
    expect(harness.cache.get('removed')).toBeUndefined()
  })
})
