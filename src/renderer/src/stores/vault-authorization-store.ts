import { createStore, type StoreApi } from 'zustand/vanilla'
import type {
  BearWardenAPI,
  LoginAuthorization,
  LoginSummary
} from '../../../shared/vault-contract'
import { isRepromptRequired } from '../components/vault-error-ui'

/** What the master-password reprompt dialog shows while an operation waits on it. */
export interface RepromptPrompt {
  count: number
  /** Name of the single protected item, when the request covers exactly one known item. */
  itemName: string | null
}

export interface VaultAuthorizationState {
  prompt: RepromptPrompt | null
  busy: boolean
  /** Unexpired single-item tokens, for components that forward them to IPC themselves. */
  tokens: Readonly<Record<string, string>>
}

export type TokenFor = (id: string) => string | undefined

export interface VaultAuthorizationOptions {
  authorizeMany: BearWardenAPI['logins']['authorizeMany']
  findItem: (id: string) => LoginSummary | undefined
}

/**
 * Notified after a cached capability for `id` expires or the main process rejects it.
 * Listeners drop whatever they derived from the capability, such as decrypted detail.
 */
export type RevokedListener = (
  id: string,
  options: { preservePasswordHistoryDialog: boolean }
) => void

export interface VaultAuthorization {
  store: StoreApi<VaultAuthorizationState>
  token: TokenFor
  request: (ids: readonly string[]) => Promise<LoginAuthorization>
  withReprompt: <T>(
    ids: readonly string[],
    operation: (tokenFor: TokenFor) => Promise<T>,
    preservePasswordHistoryDialog?: boolean
  ) => Promise<T>
  revoke: (id: string, preservePasswordHistoryDialog?: boolean) => void
  subscribeRevoked: (listener: RevokedListener) => () => void
  submit: (masterPassword: string) => Promise<void>
  cancel: () => void
  activate: () => void
  dispose: () => void
}

interface PendingReprompt {
  key: string
  ids: string[]
  promise: Promise<LoginAuthorization>
  resolve: (authorization: LoginAuthorization) => void
  reject: (error: Error) => void
}

const initialState: VaultAuthorizationState = { prompt: null, busy: false, tokens: {} }

function repromptRequired(): Error {
  return new Error('REPROMPT_REQUIRED')
}

/**
 * Master-password reprompt for protected items: one pending prompt at a time, short-lived
 * single-item tokens with expiry timers, and a retry when the main process rejects a token.
 * `dispose` rejects the pending prompt and drops every token, and a submit that resolves
 * after disposal is discarded instead of re-caching a token for a closed session.
 */
export function createVaultAuthorization(options: VaultAuthorizationOptions): VaultAuthorization {
  const store = createStore<VaultAuthorizationState>()(() => initialState)
  const cache = new Map<string, LoginAuthorization>()
  const expiryTimers = new Map<string, ReturnType<typeof setTimeout>>()
  const revokedListeners = new Set<RevokedListener>()
  let pending: PendingReprompt | null = null
  let generation = 0

  function discard(id: string): void {
    cache.delete(id)
    const tokens = store.getState().tokens
    if (id in tokens) {
      const next = { ...tokens }
      delete next[id]
      store.setState({ tokens: next })
    }
    const timer = expiryTimers.get(id)
    if (timer !== undefined) clearTimeout(timer)
    expiryTimers.delete(id)
  }

  function revoke(id: string, preservePasswordHistoryDialog = false): void {
    discard(id)
    for (const listener of revokedListeners) listener(id, { preservePasswordHistoryDialog })
  }

  function token(id: string): string | undefined {
    const authorization = cache.get(id)
    if (!authorization) return undefined
    if (authorization.expiresAt <= Date.now()) {
      revoke(id)
      return undefined
    }
    return authorization.token
  }

  function remember(id: string, authorization: LoginAuthorization): void {
    // Replacing a token must not report a revocation to the operation that requested it.
    discard(id)
    cache.set(id, authorization)
    store.setState((state) => ({ tokens: { ...state.tokens, [id]: authorization.token } }))
    const delay = Math.max(0, authorization.expiresAt - Date.now())
    expiryTimers.set(
      id,
      setTimeout(() => {
        if (cache.get(id)?.token === authorization.token) revoke(id)
      }, delay)
    )
  }

  function request(ids: readonly string[]): Promise<LoginAuthorization> {
    const normalizedIds = ids.toSorted()
    if (normalizedIds.length === 1) {
      const cached = cache.get(normalizedIds[0])
      if (cached && token(normalizedIds[0])) return Promise.resolve(cached)
    }
    const key = normalizedIds.join('\n')
    if (pending) {
      if (pending.key === key) return pending.promise
      return Promise.reject(repromptRequired())
    }
    let resolve!: (authorization: LoginAuthorization) => void
    let reject!: (error: Error) => void
    const promise = new Promise<LoginAuthorization>((resolvePromise, rejectPromise) => {
      resolve = resolvePromise
      reject = rejectPromise
    })
    pending = { key, ids: normalizedIds, promise, resolve, reject }
    store.setState({
      prompt: {
        count: normalizedIds.length,
        itemName:
          normalizedIds.length === 1 ? (options.findItem(normalizedIds[0])?.name ?? null) : null
      }
    })
    return promise
  }

  async function withReprompt<T>(
    ids: readonly string[],
    operation: (tokenFor: TokenFor) => Promise<T>,
    preservePasswordHistoryDialog = false
  ): Promise<T> {
    const requiresPrompt = ids.some((id) => options.findItem(id)?.reprompt === 1)
    const authorization = requiresPrompt ? await request(ids) : undefined
    try {
      return await operation((id) => (authorization ? authorization.token : token(id)))
    } catch (error) {
      if (!isRepromptRequired(error) || ids.length === 0) throw error
      for (const id of ids) revoke(id, preservePasswordHistoryDialog)
      const retryAuthorization = await request(ids)
      return operation((id) => (ids.includes(id) ? retryAuthorization.token : token(id)))
    }
  }

  async function submit(masterPassword: string): Promise<void> {
    const current = pending
    if (!current) throw repromptRequired()
    const requestGeneration = generation
    store.setState({ busy: true })
    try {
      const authorization = await options.authorizeMany({ ids: current.ids, masterPassword })
      if (requestGeneration !== generation) return
      if (current.ids.length === 1) remember(current.ids[0], authorization)
      current.resolve(authorization)
      pending = null
      store.setState({ prompt: null })
    } finally {
      if (requestGeneration === generation) store.setState({ busy: false })
    }
  }

  function cancel(): void {
    if (store.getState().busy) return
    const current = pending
    pending = null
    store.setState({ prompt: null })
    current?.reject(repromptRequired())
  }

  return {
    store,
    token,
    request,
    withReprompt,
    revoke,
    subscribeRevoked: (listener) => {
      revokedListeners.add(listener)
      return () => revokedListeners.delete(listener)
    },
    submit,
    cancel,
    activate: () => {
      generation += 1
    },
    dispose: () => {
      generation += 1
      for (const timer of expiryTimers.values()) clearTimeout(timer)
      expiryTimers.clear()
      cache.clear()
      pending?.reject(repromptRequired())
      pending = null
      store.setState(initialState)
    }
  }
}
