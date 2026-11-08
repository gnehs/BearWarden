import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { LoginAuthorization, LoginSummary } from '../../../shared/vault-contract'
import { createVaultAuthorization, type VaultAuthorization } from './vault-authorization-store'

const now = new Date('2026-11-09T00:00:00.000Z').getTime()

function item(id: string, reprompt: 0 | 1): LoginSummary {
  return { id, name: `Item ${id}`, reprompt } as LoginSummary
}

function setup(items: LoginSummary[] = [item('protected', 1), item('public', 0)]): {
  authorization: VaultAuthorization
  authorizeMany: ReturnType<typeof vi.fn>
  revoked: string[]
} {
  const authorizeMany = vi.fn(
    async (request: { ids: string[]; masterPassword: string }): Promise<LoginAuthorization> => {
      if (request.masterPassword !== 'correct') throw new Error('INVALID_MASTER_PASSWORD')
      return { token: `token:${request.ids.join(',')}`, expiresAt: Date.now() + 60_000 }
    }
  )
  const authorization = createVaultAuthorization({
    authorizeMany,
    findItem: (id) => items.find((candidate) => candidate.id === id)
  })
  const revoked: string[] = []
  authorization.subscribeRevoked((id) => revoked.push(id))
  return { authorization, authorizeMany, revoked }
}

async function flush(): Promise<void> {
  await Promise.resolve()
  await Promise.resolve()
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(now)
})

afterEach(() => {
  vi.useRealTimers()
})

describe('createVaultAuthorization', () => {
  it('runs operations on unprotected items without prompting', async () => {
    const { authorization } = setup()

    const result = await authorization.withReprompt(['public'], async (tokenFor) =>
      tokenFor('public')
    )

    expect(result).toBeUndefined()
    expect(authorization.store.getState().prompt).toBeNull()
  })

  it('prompts once for a protected item and reuses the cached token until it expires', async () => {
    const { authorization, authorizeMany } = setup()
    const operation = vi.fn(async (tokenFor: (id: string) => string | undefined) =>
      tokenFor('protected')
    )

    const first = authorization.withReprompt(['protected'], operation)
    await flush()
    expect(authorization.store.getState().prompt).toEqual({ count: 1, itemName: 'Item protected' })
    await authorization.submit('correct')

    await expect(first).resolves.toBe('token:protected')
    expect(authorization.store.getState()).toMatchObject({
      prompt: null,
      busy: false,
      tokens: { protected: 'token:protected' }
    })
    await expect(authorization.withReprompt(['protected'], operation)).resolves.toBe(
      'token:protected'
    )
    expect(authorizeMany).toHaveBeenCalledTimes(1)
  })

  it('revokes a cached token when its expiry timer fires', async () => {
    const { authorization, revoked } = setup()
    const pending = authorization.request(['protected'])
    await authorization.submit('correct')
    await pending

    vi.advanceTimersByTime(59_999)
    expect(authorization.token('protected')).toBe('token:protected')
    expect(revoked).toEqual([])

    vi.advanceTimersByTime(1)
    expect(revoked).toEqual(['protected'])
    expect(authorization.token('protected')).toBeUndefined()
    expect(authorization.store.getState().tokens).toEqual({})
  })

  it('treats a token read after its expiry time as revoked even before the timer runs', async () => {
    const { authorization, revoked } = setup()
    const pending = authorization.request(['protected'])
    await authorization.submit('correct')
    await pending

    vi.setSystemTime(now + 60_000)

    expect(authorization.token('protected')).toBeUndefined()
    expect(revoked).toEqual(['protected'])
  })

  it('reprompts and retries once when the main process rejects the token', async () => {
    const { authorization, revoked } = setup()
    const operation = vi
      .fn<(tokenFor: (id: string) => string | undefined) => Promise<string | undefined>>()
      .mockRejectedValueOnce(new Error('REPROMPT_REQUIRED'))
      .mockImplementation(async (tokenFor) => tokenFor('public'))

    const result = authorization.withReprompt(['public'], operation)
    await flush()
    expect(revoked).toEqual(['public'])
    expect(authorization.store.getState().prompt).toEqual({ count: 1, itemName: 'Item public' })
    await authorization.submit('correct')

    await expect(result).resolves.toBe('token:public')
  })

  it('keeps the prompt open after a wrong master password', async () => {
    const { authorization } = setup()
    const pending = authorization.request(['protected'])

    await expect(authorization.submit('wrong')).rejects.toThrow('INVALID_MASTER_PASSWORD')
    expect(authorization.store.getState()).toMatchObject({ busy: false, prompt: { count: 1 } })

    await authorization.submit('correct')
    await expect(pending).resolves.toMatchObject({ token: 'token:protected' })
  })

  it('shares one prompt per id set and rejects a different concurrent request', async () => {
    const { authorization } = setup()

    const first = authorization.request(['b', 'a'])
    const same = authorization.request(['a', 'b'])
    const other = authorization.request(['c'])

    expect(same).toBe(first)
    await expect(other).rejects.toThrow('REPROMPT_REQUIRED')
    expect(authorization.store.getState().prompt).toEqual({ count: 2, itemName: null })
  })

  it('rejects the pending request when the prompt is canceled', async () => {
    const { authorization } = setup()
    const pending = authorization.request(['protected'])

    authorization.cancel()

    await expect(pending).rejects.toThrow('REPROMPT_REQUIRED')
    expect(authorization.store.getState().prompt).toBeNull()
  })

  it('clears tokens, timers and the pending prompt on dispose', async () => {
    const { authorization, revoked } = setup()
    const cached = authorization.request(['protected'])
    await authorization.submit('correct')
    await cached
    const pending = authorization.request(['public'])

    authorization.dispose()

    await expect(pending).rejects.toThrow('REPROMPT_REQUIRED')
    expect(authorization.token('protected')).toBeUndefined()
    expect(authorization.store.getState()).toEqual({ prompt: null, busy: false, tokens: {} })
    vi.advanceTimersByTime(120_000)
    expect(revoked).toEqual([])
  })

  it('does not cache a token from a submit that resolves after dispose', async () => {
    let resolveAuthorization!: (authorization: LoginAuthorization) => void
    const authorization = createVaultAuthorization({
      authorizeMany: () =>
        new Promise((resolve) => {
          resolveAuthorization = resolve
        }),
      findItem: (id) => item(id, 1)
    })
    const pending = authorization.request(['protected'])
    void pending.catch(() => undefined)
    const submit = authorization.submit('correct')

    authorization.dispose()
    authorization.activate()
    resolveAuthorization({ token: 'late', expiresAt: Date.now() + 60_000 })
    await submit

    expect(authorization.token('protected')).toBeUndefined()
    expect(authorization.store.getState()).toEqual({ prompt: null, busy: false, tokens: {} })
  })
})
