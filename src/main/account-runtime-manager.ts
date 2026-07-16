import { assertAccountId } from './account-paths'
import { parseAccountRegistry, type AccountRegistry } from './account-registry'

export type AccountRuntimePhase = 'idle' | 'switching' | 'reloading' | 'ready' | 'disposed'

/**
 * The account-bound services that must never outlive the account that created
 * them. A runtime owns any finer-grained teardown it needs, while the manager
 * guarantees that lock completes before disposal begins.
 */
export interface AccountRuntime {
  initialize(): void | Promise<void>
  lock(): void | Promise<void>
  dispose(): void | Promise<void>
}

export interface AccountRuntimeRegistryStore {
  load(): Promise<AccountRegistry | null>
  save(registry: AccountRegistry, expectedRevision: number | null): Promise<AccountRegistry>
}

export interface AccountRuntimeBuildContext {
  readonly accountId: string
  readonly epoch: number
  /**
   * Guards asynchronous work owned by the runtime while it is being built.
   * It is deliberately broader than `isReadyRuntime`: initialization is valid
   * before the renderer has loaded, but only for this exact switch request.
   */
  isCurrent(): boolean
}

export interface AccountRendererReloadRequest {
  readonly accountId: string
  readonly epoch: number
  /**
   * Bind this directly to Electron's `webContents.once('did-finish-load', …)`
   * before requesting the reload. It returns false for an old renderer event.
   */
  didFinishLoad(): boolean
}

export interface AccountRuntimeManagerOptions<TRuntime extends AccountRuntime> {
  readonly registryStore: AccountRuntimeRegistryStore
  readonly buildRuntime: (
    accountId: string,
    context: AccountRuntimeBuildContext
  ) => TRuntime | Promise<TRuntime>
  readonly clearSensitiveClipboard: () => void
  readonly reloadRenderer: (request: AccountRendererReloadRequest) => void | Promise<void>
}

export interface AccountRuntimeState {
  readonly phase: AccountRuntimePhase
  readonly epoch: number
  /** The requested account while switching, or the active account otherwise. */
  readonly accountId: string | null
}

export type AccountRuntimeSwitchResult =
  | {
      readonly kind: 'reloading'
      readonly accountId: string
      readonly epoch: number
    }
  | {
      readonly kind: 'superseded'
      readonly accountId: string
      readonly epoch: number
    }

interface SwitchRequest {
  readonly accountId: string
  readonly epoch: number
}

/**
 * Serializes account runtimes without ever lending one to a switching or stale
 * renderer. Calls made concurrently use deterministic last-request-wins
 * semantics: a request superseded before it begins does no lifecycle work.
 *
 * A Stage 2 Electron integration should install the `did-finish-load` listener
 * from `reloadRenderer` before calling `webContents.reload()`. The manager does
 * not import Electron so it remains independently testable.
 */
export class AccountRuntimeManager<TRuntime extends AccountRuntime> {
  private readonly registryStore: AccountRuntimeRegistryStore
  private readonly buildRuntime: AccountRuntimeManagerOptions<TRuntime>['buildRuntime']
  private readonly clearSensitiveClipboard: () => void
  private readonly reloadRenderer: AccountRuntimeManagerOptions<TRuntime>['reloadRenderer']
  private phase: AccountRuntimePhase = 'idle'
  private epoch = 0
  private accountId: string | null = null
  private runtime: TRuntime | null = null
  private switchTail: Promise<void> = Promise.resolve()
  private disposePromise: Promise<void> | null = null

  constructor(options: AccountRuntimeManagerOptions<TRuntime>) {
    this.registryStore = options.registryStore
    this.buildRuntime = options.buildRuntime
    this.clearSensitiveClipboard = options.clearSensitiveClipboard
    this.reloadRenderer = options.reloadRenderer
  }

  get state(): AccountRuntimeState {
    return { phase: this.phase, epoch: this.epoch, accountId: this.accountId }
  }

  /**
   * The only runtime accessor intended for renderer-originating work. Callers
   * must provide the epoch captured by their renderer lifecycle event.
   */
  getRuntimeForRenderer(epoch: number): TRuntime | null {
    return this.phase === 'ready' && this.epoch === epoch ? this.runtime : null
  }

  /** Returns whether an asynchronous callback still belongs to the ready runtime. */
  isReadyRuntime(runtime: TRuntime, epoch: number): boolean {
    return this.phase === 'ready' && this.epoch === epoch && this.runtime === runtime
  }

  /**
   * Starts a full teardown/rebuild even if `accountId` is already active. That
   * avoids treating an old renderer or partially disposed service graph as safe
   * merely because the opaque account ID happens to match.
   */
  switchAccount(accountId: string): Promise<AccountRuntimeSwitchResult> {
    try {
      assertAccountId(accountId)
    } catch (error) {
      return Promise.reject(error)
    }
    if (this.phase === 'disposed') {
      return Promise.reject(new Error('ACCOUNT_RUNTIME_MANAGER_DISPOSED'))
    }

    const request: SwitchRequest = { accountId, epoch: ++this.epoch }
    this.phase = 'switching'
    this.accountId = accountId
    this.clearClipboardSafely()

    const operation = this.switchTail.then(() => this.runSwitch(request))
    this.switchTail = operation.then(
      () => undefined,
      () => undefined
    )
    return operation
  }

  /**
   * Marks the current renderer ready only when its captured epoch still owns
   * the active runtime. A late `did-finish-load` from a prior reload is ignored.
   */
  didFinishLoad(epoch: number): boolean {
    if (this.phase !== 'reloading' || this.epoch !== epoch || this.runtime === null) return false
    this.phase = 'ready'
    return true
  }

  /**
   * Invalidates all pending continuations synchronously, then serially locks
   * and disposes the current runtime. Repeated calls return the same promise.
   */
  dispose(): Promise<void> {
    if (this.disposePromise) return this.disposePromise

    const runtime = this.runtime
    this.runtime = null
    this.accountId = null
    this.phase = 'disposed'
    this.epoch += 1
    this.clearClipboardSafely()

    const teardown = this.switchTail.then(async () => {
      try {
        if (runtime) await this.teardownRuntime(runtime)
      } finally {
        this.clearClipboardSafely()
      }
    })
    this.disposePromise = teardown
    this.switchTail = teardown.then(
      () => undefined,
      () => undefined
    )
    return teardown
  }

  private async runSwitch(request: SwitchRequest): Promise<AccountRuntimeSwitchResult> {
    let candidate: TRuntime | null = null
    let committedRuntime: TRuntime | null = null
    try {
      if (!this.isCurrentRequest(request)) return this.superseded(request)

      const oldRuntime = this.runtime
      this.runtime = null
      if (oldRuntime) {
        await this.teardownRuntime(oldRuntime)
        if (!this.isCurrentRequest(request)) return this.superseded(request)
      }

      const registry = await this.registryStore.load()
      if (!this.isCurrentRequest(request)) return this.superseded(request)
      if (!registry) throw new Error('ACCOUNT_RUNTIME_REGISTRY_UNAVAILABLE')
      // Validate membership before constructing anything at an attacker-selected opaque path.
      // The later compare-and-swap still detects a registry change during initialization.
      const nextRegistry = this.nextRegistry(registry, request.accountId)

      candidate = await this.buildRuntime(request.accountId, this.buildContext(request))
      if (!this.isCurrentRequest(request)) {
        const staleCandidate = candidate
        candidate = null
        await this.teardownRuntime(staleCandidate)
        return this.superseded(request)
      }

      await candidate.initialize()
      if (!this.isCurrentRequest(request)) {
        const staleCandidate = candidate
        candidate = null
        await this.teardownRuntime(staleCandidate)
        return this.superseded(request)
      }

      await this.registryStore.save(nextRegistry, registry.revision)
      if (!this.isCurrentRequest(request)) {
        const staleCandidate = candidate
        candidate = null
        await this.teardownRuntime(staleCandidate)
        return this.superseded(request)
      }

      this.runtime = candidate
      committedRuntime = candidate
      candidate = null
      this.phase = 'reloading'
      await this.reloadRenderer({
        accountId: request.accountId,
        epoch: request.epoch,
        didFinishLoad: () => this.didFinishLoad(request.epoch)
      })
      if (!this.isCurrentRuntime(request, committedRuntime)) return this.superseded(request)

      return { kind: 'reloading', accountId: request.accountId, epoch: request.epoch }
    } catch (error) {
      const runtimeToDispose = candidate ?? committedRuntime
      if (runtimeToDispose && this.runtime === runtimeToDispose) this.runtime = null

      let teardownError: unknown
      if (runtimeToDispose) {
        try {
          await this.teardownRuntime(runtimeToDispose)
        } catch (cleanupError) {
          teardownError = cleanupError
        }
      }
      if (this.isCurrentRequest(request)) this.enterIdle()
      if (teardownError !== undefined) {
        throw new AggregateError([error, teardownError], this.errorMessage(error))
      }
      throw error
    } finally {
      this.clearClipboardSafely()
    }
  }

  private buildContext(request: SwitchRequest): AccountRuntimeBuildContext {
    return {
      accountId: request.accountId,
      epoch: request.epoch,
      isCurrent: () => this.isCurrentRequest(request)
    }
  }

  private nextRegistry(registry: AccountRegistry | null, accountId: string): AccountRegistry {
    if (!registry) throw new Error('ACCOUNT_RUNTIME_REGISTRY_UNAVAILABLE')
    const current = parseAccountRegistry(registry)
    if (!current.accounts.some((account) => account.id === accountId)) {
      throw new Error('ACCOUNT_RUNTIME_ACCOUNT_NOT_REGISTERED')
    }
    return parseAccountRegistry({
      ...current,
      revision: current.revision + 1,
      activeAccountId: accountId,
      accounts: current.accounts.map((account) => ({ ...account }))
    })
  }

  private isCurrentRequest(request: SwitchRequest): boolean {
    return (
      this.phase !== 'disposed' &&
      this.epoch === request.epoch &&
      this.accountId === request.accountId
    )
  }

  private isCurrentRuntime(request: SwitchRequest, runtime: TRuntime): boolean {
    return (
      this.isCurrentRequest(request) &&
      this.runtime === runtime &&
      (this.phase === 'reloading' || this.phase === 'ready')
    )
  }

  private superseded(request: SwitchRequest): AccountRuntimeSwitchResult {
    return { kind: 'superseded', accountId: request.accountId, epoch: request.epoch }
  }

  private enterIdle(): void {
    this.runtime = null
    this.accountId = null
    this.phase = 'idle'
  }

  private async teardownRuntime(runtime: TRuntime): Promise<void> {
    let lockError: unknown
    try {
      await runtime.lock()
    } catch (error) {
      lockError = error
    }

    try {
      await runtime.dispose()
    } catch (disposeError) {
      if (lockError !== undefined) {
        throw new AggregateError([lockError, disposeError], 'ACCOUNT_RUNTIME_TEARDOWN_FAILED')
      }
      throw disposeError
    }
    if (lockError !== undefined) throw lockError
  }

  private clearClipboardSafely(): void {
    try {
      this.clearSensitiveClipboard()
    } catch {
      // A clipboard implementation must not prevent lock/dispose fail-closed teardown.
    }
  }

  private errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : 'ACCOUNT_RUNTIME_SWITCH_FAILED'
  }
}
