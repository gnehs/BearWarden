import { describe, expect, it, vi } from 'vitest'
import type { AccountRegistry } from './account-registry'
import {
  AccountRuntimeManager,
  type AccountRendererReloadRequest,
  type AccountRuntime,
  type AccountRuntimeBuildContext,
  type AccountRuntimeRegistryStore
} from './account-runtime-manager'

const ACCOUNT_A = '11111111-1111-4111-8111-111111111111'
const ACCOUNT_B = '22222222-2222-4222-8222-222222222222'
const ACCOUNT_C = '33333333-3333-4333-8333-333333333333'
const ACCOUNT_D = '44444444-4444-4444-8444-444444444444'
const ACCOUNT_E = '55555555-5555-4555-8555-555555555555'

interface TestRuntime extends AccountRuntime {
  readonly accountId: string
}

interface RuntimeHooks {
  readonly initialize?: () => void | Promise<void>
  readonly lock?: () => void | Promise<void>
  readonly dispose?: () => void | Promise<void>
}

function registry(revision = 1): AccountRegistry {
  return {
    format: 'bearwarden-account-registry',
    version: 1,
    revision,
    activeAccountId: ACCOUNT_A,
    accounts: [
      { id: ACCOUNT_A, identityHash: 'a'.repeat(64) },
      { id: ACCOUNT_B, identityHash: 'b'.repeat(64) },
      { id: ACCOUNT_C },
      { id: ACCOUNT_D, identityHash: 'd'.repeat(64) },
      { id: ACCOUNT_E, identityHash: 'e'.repeat(64) }
    ]
  }
}

function testRuntime(accountId: string, events: string[], hooks: RuntimeHooks = {}): TestRuntime {
  return {
    accountId,
    initialize: vi.fn(async () => {
      events.push(`${accountId}:initialize`)
      await hooks.initialize?.()
    }),
    lock: vi.fn(async () => {
      events.push(`${accountId}:lock`)
      await hooks.lock?.()
    }),
    dispose: vi.fn(async () => {
      events.push(`${accountId}:dispose`)
      await hooks.dispose?.()
    })
  }
}

function deferred<T>(): {
  readonly promise: Promise<T>
  resolve(value: T): void
  reject(reason?: unknown): void
} {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function createHarness(
  options: {
    readonly build?: (
      accountId: string,
      context: AccountRuntimeBuildContext,
      events: string[]
    ) => TestRuntime | Promise<TestRuntime>
    readonly save?: (
      next: AccountRegistry,
      expectedRevision: number | null
    ) => Promise<AccountRegistry>
    readonly reload?: (request: AccountRendererReloadRequest) => void | Promise<void>
  } = {}
): {
  readonly manager: AccountRuntimeManager<TestRuntime>
  readonly events: string[]
  readonly runtimes: TestRuntime[]
  readonly reloadRequests: AccountRendererReloadRequest[]
  readonly clipboard: ReturnType<typeof vi.fn>
  readonly registryStore: AccountRuntimeRegistryStore
  currentRegistry(): AccountRegistry
} {
  const events: string[] = []
  const runtimes: TestRuntime[] = []
  const reloadRequests: AccountRendererReloadRequest[] = []
  const clipboard = vi.fn(() => events.push('clipboard'))
  let current = registry()
  const load = vi.fn(async () => {
    events.push('registry:load')
    return current
  })
  const save = vi.fn(async (next: AccountRegistry, expectedRevision: number | null) => {
    events.push(`registry:save:${next.revision}:${next.activeAccountId}`)
    if (options.save) {
      current = await options.save(next, expectedRevision)
      return current
    }
    if (expectedRevision !== current.revision) throw new Error('ACCOUNT_REGISTRY_CONFLICT')
    current = next
    return current
  })
  const registryStore: AccountRuntimeRegistryStore = { load, save }
  const buildRuntime = vi.fn(
    async (accountId: string, context: AccountRuntimeBuildContext): Promise<TestRuntime> => {
      events.push(`build:${accountId}`)
      const runtime = options.build
        ? await options.build(accountId, context, events)
        : testRuntime(accountId, events)
      runtimes.push(runtime)
      return runtime
    }
  )
  const reloadRenderer = vi.fn(async (request: AccountRendererReloadRequest): Promise<void> => {
    events.push(`reload:${request.accountId}:${request.epoch}`)
    reloadRequests.push(request)
    await options.reload?.(request)
  })
  const manager = new AccountRuntimeManager<TestRuntime>({
    registryStore,
    buildRuntime,
    clearSensitiveClipboard: clipboard,
    reloadRenderer
  })
  return {
    manager,
    events,
    runtimes,
    reloadRequests,
    clipboard,
    registryStore,
    currentRegistry: () => current
  }
}

async function activate(
  manager: AccountRuntimeManager<TestRuntime>,
  accountId: string
): Promise<number> {
  const result = await manager.switchAccount(accountId)
  expect(result.kind).toBe('reloading')
  expect(manager.didFinishLoad(result.epoch)).toBe(true)
  return result.epoch
}

describe('AccountRuntimeManager', () => {
  it('tears A down before B is built, commits only B as active, and clears the clipboard twice', async () => {
    const { manager, events, clipboard, currentRegistry } = createHarness()
    await activate(manager, ACCOUNT_A)
    events.length = 0
    clipboard.mockClear()

    const result = await manager.switchAccount(ACCOUNT_B)

    expect(result).toEqual({ kind: 'reloading', accountId: ACCOUNT_B, epoch: 2 })
    expect(events).toEqual([
      'clipboard',
      `${ACCOUNT_A}:lock`,
      `${ACCOUNT_A}:dispose`,
      'registry:load',
      `build:${ACCOUNT_B}`,
      `${ACCOUNT_B}:initialize`,
      `registry:save:3:${ACCOUNT_B}`,
      `reload:${ACCOUNT_B}:2`,
      'clipboard'
    ])
    expect(clipboard).toHaveBeenCalledTimes(2)
    expect(currentRegistry()).toEqual({
      ...registry(3),
      activeAccountId: ACCOUNT_B
    })
    expect(manager.getRuntimeForRenderer(result.epoch)).toBeNull()
    expect(manager.didFinishLoad(result.epoch)).toBe(true)
    expect(manager.getRuntimeForRenderer(result.epoch)?.accountId).toBe(ACCOUNT_B)
  })

  it('does a full same-account replacement instead of reusing an old runtime', async () => {
    const { manager, runtimes, currentRegistry } = createHarness()
    const firstEpoch = await activate(manager, ACCOUNT_A)
    const first = manager.getRuntimeForRenderer(firstEpoch)
    expect(first).not.toBeNull()

    const replacement = await manager.switchAccount(ACCOUNT_A)

    expect(replacement).toEqual({ kind: 'reloading', accountId: ACCOUNT_A, epoch: 2 })
    expect(first?.lock).toHaveBeenCalledTimes(1)
    expect(first?.dispose).toHaveBeenCalledTimes(1)
    expect(runtimes).toHaveLength(2)
    expect(currentRegistry().revision).toBe(3)
  })

  it('rejects stale renderer callbacks and never lends B during reload', async () => {
    const { manager, reloadRequests } = createHarness()
    const aEpoch = await activate(manager, ACCOUNT_A)
    const oldRuntime = manager.getRuntimeForRenderer(aEpoch)
    const oldReload = reloadRequests.at(-1)!

    const b = await manager.switchAccount(ACCOUNT_B)
    const bReload = reloadRequests.at(-1)!

    expect(manager.isReadyRuntime(oldRuntime!, aEpoch)).toBe(false)
    expect(oldReload.didFinishLoad()).toBe(false)
    expect(manager.didFinishLoad(aEpoch)).toBe(false)
    expect(manager.state).toEqual({ phase: 'reloading', epoch: b.epoch, accountId: ACCOUNT_B })
    expect(manager.getRuntimeForRenderer(b.epoch)).toBeNull()
    expect(bReload.didFinishLoad()).toBe(true)
    expect(manager.getRuntimeForRenderer(b.epoch)?.accountId).toBe(ACCOUNT_B)
  })

  it('uses last-request-wins semantics for concurrent switches without lifecycle interleaving', async () => {
    const { manager, events } = createHarness()
    await activate(manager, ACCOUNT_A)
    events.length = 0

    const b = manager.switchAccount(ACCOUNT_B)
    const c = manager.switchAccount(ACCOUNT_C)

    await expect(b).resolves.toEqual({ kind: 'superseded', accountId: ACCOUNT_B, epoch: 2 })
    await expect(c).resolves.toEqual({ kind: 'reloading', accountId: ACCOUNT_C, epoch: 3 })
    expect(events).toEqual([
      'clipboard',
      'clipboard',
      'clipboard',
      `${ACCOUNT_A}:lock`,
      `${ACCOUNT_A}:dispose`,
      'registry:load',
      `build:${ACCOUNT_C}`,
      `${ACCOUNT_C}:initialize`,
      `registry:save:3:${ACCOUNT_C}`,
      `reload:${ACCOUNT_C}:3`,
      'clipboard'
    ])
  })

  it('disposes an in-flight candidate before the later switch can build', async () => {
    const initialized = deferred<void>()
    const { manager, events, runtimes } = createHarness({
      build: (accountId, _context, runtimeEvents) =>
        testRuntime(accountId, runtimeEvents, {
          initialize: accountId === ACCOUNT_B ? () => initialized.promise : undefined
        })
    })
    await activate(manager, ACCOUNT_A)
    events.length = 0

    const b = manager.switchAccount(ACCOUNT_B)
    await vi.waitFor(() => expect(events).toContain(`${ACCOUNT_B}:initialize`))
    const c = manager.switchAccount(ACCOUNT_C)
    initialized.resolve()

    await expect(b).resolves.toEqual({ kind: 'superseded', accountId: ACCOUNT_B, epoch: 2 })
    await expect(c).resolves.toEqual({ kind: 'reloading', accountId: ACCOUNT_C, epoch: 3 })
    const bRuntime = runtimes.find((runtime) => runtime.accountId === ACCOUNT_B)!
    expect(bRuntime.lock).toHaveBeenCalledTimes(1)
    expect(bRuntime.dispose).toHaveBeenCalledTimes(1)
    expect(events.indexOf(`${ACCOUNT_B}:dispose`)).toBeLessThan(
      events.indexOf(`build:${ACCOUNT_C}`)
    )
  })

  it('fails closed after a runtime build failure', async () => {
    const { manager, currentRegistry } = createHarness({
      build: (accountId, _context, events) => {
        if (accountId === ACCOUNT_B) throw new Error('BUILD_FAILED')
        return testRuntime(accountId, events)
      }
    })
    await activate(manager, ACCOUNT_A)

    await expect(manager.switchAccount(ACCOUNT_B)).rejects.toThrow('BUILD_FAILED')

    expect(manager.state).toEqual({ phase: 'idle', epoch: 2, accountId: null })
    expect(manager.getRuntimeForRenderer(2)).toBeNull()
    expect(currentRegistry()).toEqual(registry(2))
  })

  it('rejects an unregistered account before constructing its runtime', async () => {
    const { manager, events, runtimes } = createHarness()
    await activate(manager, ACCOUNT_A)
    events.length = 0

    await expect(manager.switchAccount('66666666-6666-4666-8666-666666666666')).rejects.toThrow(
      'ACCOUNT_RUNTIME_ACCOUNT_NOT_REGISTERED'
    )

    expect(runtimes).toHaveLength(1)
    expect(events).not.toContain('build:66666666-6666-4666-8666-666666666666')
    expect(manager.state.phase).toBe('idle')
  })

  it('fails closed and disposes the candidate after initialization or CAS failure', async () => {
    const initializedFailure = createHarness({
      build: (accountId, _context, events) =>
        testRuntime(accountId, events, {
          initialize:
            accountId === ACCOUNT_B
              ? () => Promise.reject(new Error('INITIALIZE_FAILED'))
              : undefined
        })
    })
    await activate(initializedFailure.manager, ACCOUNT_A)
    await expect(initializedFailure.manager.switchAccount(ACCOUNT_B)).rejects.toThrow(
      'INITIALIZE_FAILED'
    )
    const initializationCandidate = initializedFailure.runtimes.at(-1)!
    expect(initializationCandidate.lock).toHaveBeenCalledTimes(1)
    expect(initializationCandidate.dispose).toHaveBeenCalledTimes(1)
    expect(initializedFailure.manager.state.phase).toBe('idle')

    const casFailure = createHarness({
      save: async (next) => {
        if (next.activeAccountId === ACCOUNT_B) throw new Error('CAS_FAILED')
        return next
      }
    })
    await activate(casFailure.manager, ACCOUNT_A)
    await expect(casFailure.manager.switchAccount(ACCOUNT_B)).rejects.toThrow('CAS_FAILED')
    const casCandidate = casFailure.runtimes.at(-1)!
    expect(casCandidate.lock).toHaveBeenCalledTimes(1)
    expect(casCandidate.dispose).toHaveBeenCalledTimes(1)
    expect(casFailure.manager.state.phase).toBe('idle')
  })

  it('fails closed and disposes the committed candidate if renderer reload setup fails', async () => {
    const { manager, runtimes, currentRegistry } = createHarness({
      reload: (request) => {
        if (request.accountId === ACCOUNT_B) throw new Error('RELOAD_FAILED')
      }
    })
    await activate(manager, ACCOUNT_A)

    await expect(manager.switchAccount(ACCOUNT_B)).rejects.toThrow('RELOAD_FAILED')

    const candidate = runtimes.at(-1)!
    expect(candidate.accountId).toBe(ACCOUNT_B)
    expect(candidate.lock).toHaveBeenCalledTimes(1)
    expect(candidate.dispose).toHaveBeenCalledTimes(1)
    expect(manager.state).toEqual({ phase: 'idle', epoch: 2, accountId: null })
    expect(manager.getRuntimeForRenderer(2)).toBeNull()
    expect(currentRegistry()).toEqual({ ...registry(3), activeAccountId: ACCOUNT_B })
  })

  it('invalidates pending work and disposes exactly once', async () => {
    const { manager, clipboard, runtimes } = createHarness()
    const epoch = await activate(manager, ACCOUNT_A)
    const runtime = manager.getRuntimeForRenderer(epoch)!
    clipboard.mockClear()

    const first = manager.dispose()
    const second = manager.dispose()

    expect(second).toBe(first)
    await first
    expect(clipboard).toHaveBeenCalledTimes(2)
    expect(runtime.lock).toHaveBeenCalledTimes(1)
    expect(runtime.dispose).toHaveBeenCalledTimes(1)
    expect(runtimes).toHaveLength(1)
    expect(manager.state).toEqual({ phase: 'disposed', epoch: 2, accountId: null })
    expect(manager.didFinishLoad(epoch)).toBe(false)
    await expect(manager.switchAccount(ACCOUNT_B)).rejects.toThrow(
      'ACCOUNT_RUNTIME_MANAGER_DISPOSED'
    )
  })
})
