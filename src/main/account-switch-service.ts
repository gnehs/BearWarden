import { lstat } from 'node:fs/promises'
import {
  assertAccountId,
  createAccountId,
  createAccountPathLayout,
  ensurePrivateDirectory
} from './account-paths'
import {
  ACCOUNT_REGISTRY_MAX_ACCOUNTS,
  AccountRegistryStore,
  parseAccountRegistry,
  type AccountRegistry,
  type AccountRegistryEntry
} from './account-registry'
import {
  createPendingInitializationMarker,
  hasPendingInitializationMarker
} from './account-storage-initialization-marker'
import {
  AccountRemovalJournal,
  type AccountRemovalRecoveryCallbacks
} from './account-removal-journal'

export type AccountActivationReason = 'add-account' | 'switch-account'

export interface RendererSafeAccountStatusEntry {
  /** Opaque identifier. Display metadata must remain in account-scoped encrypted storage. */
  readonly id: string
  readonly active: boolean
  /** One-based position in the user-controlled local account order. */
  readonly slot: number
}

export interface RendererSafeAccountStatus {
  /** Non-sensitive CAS token used to reject stale reorder requests. */
  readonly revision: number
  readonly activeAccountId: string
  readonly accounts: readonly RendererSafeAccountStatusEntry[]
  readonly cleanupPending?: true
}

export type AccountSwitchMutationResult =
  | {
      readonly kind: 'unchanged'
      readonly status: RendererSafeAccountStatus
    }
  | {
      readonly kind: 'relaunch-required'
      readonly status: RendererSafeAccountStatus
    }
  | {
      readonly kind: 'updated'
      readonly status: RendererSafeAccountStatus
      readonly cleanupPending?: boolean
    }

export type AccountSwitchServiceErrorCode =
  | 'INVALID_ACCOUNT_SWITCH_REQUEST'
  | 'ACCOUNT_REGISTRY_UNAVAILABLE'
  | 'ACCOUNT_LIMIT_REACHED'
  | 'ACCOUNT_NOT_REGISTERED'
  | 'ACCOUNT_ACTIVE_REMOVAL_FORBIDDEN'
  | 'ACCOUNT_STALE_REORDER_REQUEST'
  | 'ACCOUNT_REMOVAL_UNAVAILABLE'
  | 'ACCOUNT_REMOVAL_PREPARATION_FAILED'
  | 'ACCOUNT_ID_GENERATION_FAILED'
  | 'ACCOUNT_STORAGE_PREPARATION_FAILED'
  | 'ACCOUNT_STORAGE_UNAVAILABLE'
  | 'ACCOUNT_ACTIVATION_FAILED'
  | 'ACCOUNT_REGISTRY_UPDATE_FAILED'
  | 'ACCOUNT_REGISTRY_UPDATE_RESULT_UNKNOWN'
  | 'ACCOUNT_SWITCH_IN_PROGRESS'

/** Safe to map at a future IPC boundary: the message is always the non-sensitive code. */
export class AccountSwitchServiceError extends Error {
  constructor(readonly code: AccountSwitchServiceErrorCode) {
    super(code)
    this.name = 'AccountSwitchServiceError'
  }
}

/**
 * The registry commit is durable, but the caller cannot know whether Electron accepted the
 * relaunch request. The committed renderer-safe status is the only attached context.
 */
export class AccountRelaunchResultUnknownError extends Error {
  readonly code = 'RELAUNCH_RESULT_UNKNOWN' as const

  constructor(readonly committedStatus: RendererSafeAccountStatus) {
    super('RELAUNCH_RESULT_UNKNOWN')
    this.name = 'AccountRelaunchResultUnknownError'
  }
}

export interface AccountSwitchRegistryStore {
  load(): Promise<AccountRegistry | null>
  loadPrimary?(): Promise<AccountRegistry | null>
  save(registry: AccountRegistry, expectedRevision: number | null): Promise<AccountRegistry>
  checkpoint?(registry: AccountRegistry, expectedRevision: number): Promise<AccountRegistry>
}

export interface AccountSwitchServiceOptions {
  readonly registryStore?: AccountSwitchRegistryStore
  readonly removalJournal?: AccountRemovalJournal
  readonly initialCleanupPending?: boolean
  readonly createUuid?: () => string
  /** Must finish deactivating account-bound state before the registry commit may begin. */
  readonly beforeActivation: (
    accountId: string,
    reason: AccountActivationReason
  ) => void | Promise<void>
  /** Integration should call Electron app.relaunch() and then app.quit() exactly once. */
  readonly afterCommitRelaunch: (
    accountId: string,
    reason: AccountActivationReason
  ) => void | Promise<void>
}

function copyEntry(entry: AccountRegistryEntry): AccountRegistryEntry {
  return entry.identityHash === undefined
    ? { id: entry.id }
    : { id: entry.id, identityHash: entry.identityHash }
}

function rendererSafeStatus(
  registry: AccountRegistry,
  cleanupPending = false
): RendererSafeAccountStatus {
  const accounts = registry.accounts.map((account, index) =>
    Object.freeze({
      id: account.id,
      active: account.id === registry.activeAccountId,
      slot: index + 1
    })
  )
  return Object.freeze({
    revision: registry.revision,
    activeAccountId: registry.activeAccountId,
    accounts: Object.freeze(accounts),
    ...(cleanupPending ? { cleanupPending: true as const } : {})
  })
}

function safeAccountIdArray(value: unknown): readonly string[] | null {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return null
  const descriptors = Object.getOwnPropertyDescriptors(value)
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== 'string')) return null
  const accountIds: string[] = []
  const allowedKeys = new Set(['length'])
  for (let index = 0; index < value.length; index += 1) {
    const key = String(index)
    const descriptor = descriptors[key]
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !('value' in descriptor) ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      return null
    }
    try {
      assertAccountId(descriptor.value)
    } catch {
      return null
    }
    accountIds.push(descriptor.value)
    allowedKeys.add(key)
  }
  if (Object.keys(descriptors).some((key) => !allowedKeys.has(key))) return null
  return Object.freeze(accountIds)
}

function registryEqual(left: AccountRegistry, right: AccountRegistry): boolean {
  return (
    left.format === right.format &&
    left.version === right.version &&
    left.revision === right.revision &&
    left.activeAccountId === right.activeAccountId &&
    left.accounts.length === right.accounts.length &&
    left.accounts.every(
      (account, index) =>
        account.id === right.accounts[index]?.id &&
        account.identityHash === right.accounts[index]?.identityHash
    )
  )
}

async function requireMissing(path: string): Promise<void> {
  try {
    await lstat(path)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    throw error
  }
  throw new Error('ACCOUNT_STORAGE_INITIALIZATION_COLLISION')
}

/**
 * Registry mutations and their activation barriers are serialized. Once a commit requests a
 * relaunch, the service permanently rejects further mutations: Electron starts one new instance
 * for every app.relaunch() call, so serialization alone would not prevent duplicate instances.
 */
export class AccountSwitchService {
  private readonly registryStore: AccountSwitchRegistryStore
  private readonly createUuid?: () => string
  private readonly paths: ReturnType<typeof createAccountPathLayout>
  private readonly removalJournal: AccountRemovalJournal
  private readonly beforeActivation: AccountSwitchServiceOptions['beforeActivation']
  private readonly afterCommitRelaunch: AccountSwitchServiceOptions['afterCommitRelaunch']
  private mutationTail: Promise<void> = Promise.resolve()
  private relaunchPending = false
  private accountRemovalCleanupPending: boolean

  constructor(userDataDirectory: string, options: AccountSwitchServiceOptions) {
    this.createUuid = options.createUuid
    this.paths = createAccountPathLayout(userDataDirectory)
    this.registryStore =
      options.registryStore ??
      new AccountRegistryStore(userDataDirectory, { createUuid: options.createUuid })
    this.removalJournal =
      options.removalJournal ??
      new AccountRemovalJournal(userDataDirectory, { createUuid: options.createUuid })
    this.accountRemovalCleanupPending = options.initialCleanupPending === true
    this.beforeActivation = options.beforeActivation
    this.afterCommitRelaunch = options.afterCommitRelaunch
  }

  async getStatus(request?: unknown): Promise<RendererSafeAccountStatus> {
    this.assertEmptyRequest(request)
    return rendererSafeStatus(await this.loadRegistry(), this.accountRemovalCleanupPending)
  }

  async listAccounts(request?: unknown): Promise<readonly RendererSafeAccountStatusEntry[]> {
    return (await this.getStatus(request)).accounts
  }

  addAccount(request?: unknown): Promise<AccountSwitchMutationResult> {
    try {
      this.assertEmptyRequest(request)
    } catch (error) {
      return Promise.reject(error)
    }
    return this.serializeMutation(() => this.performAddAccount())
  }

  switchAccount(accountId: unknown): Promise<AccountSwitchMutationResult> {
    try {
      assertAccountId(accountId)
    } catch {
      return Promise.reject(new AccountSwitchServiceError('INVALID_ACCOUNT_SWITCH_REQUEST'))
    }
    return this.serializeMutation(() => this.performSwitchAccount(accountId))
  }

  removeAccount(accountId: unknown, confirm: unknown): Promise<AccountSwitchMutationResult> {
    try {
      assertAccountId(accountId)
    } catch {
      return Promise.reject(new AccountSwitchServiceError('INVALID_ACCOUNT_SWITCH_REQUEST'))
    }
    if (confirm !== true) {
      return Promise.reject(new AccountSwitchServiceError('INVALID_ACCOUNT_SWITCH_REQUEST'))
    }
    return this.serializeMutation(() => this.performRemoveAccount(accountId))
  }

  reorderAccounts(
    orderedAccountIds: unknown,
    expectedRevision: unknown
  ): Promise<AccountSwitchMutationResult> {
    const accountIds = safeAccountIdArray(orderedAccountIds)
    if (
      !accountIds ||
      accountIds.length < 1 ||
      accountIds.length > ACCOUNT_REGISTRY_MAX_ACCOUNTS ||
      new Set(accountIds).size !== accountIds.length ||
      !Number.isSafeInteger(expectedRevision) ||
      (expectedRevision as number) < 1
    ) {
      return Promise.reject(new AccountSwitchServiceError('INVALID_ACCOUNT_SWITCH_REQUEST'))
    }
    return this.serializeMutation(() =>
      this.performReorderAccounts(accountIds, expectedRevision as number)
    )
  }

  private serializeMutation(
    mutate: () => Promise<AccountSwitchMutationResult>
  ): Promise<AccountSwitchMutationResult> {
    const operation = this.mutationTail.then(async () => {
      if (this.relaunchPending) {
        throw new AccountSwitchServiceError('ACCOUNT_SWITCH_IN_PROGRESS')
      }
      if (this.accountRemovalCleanupPending) {
        throw new AccountSwitchServiceError('ACCOUNT_REMOVAL_UNAVAILABLE')
      }
      return mutate()
    })
    this.mutationTail = operation.then(
      () => undefined,
      () => undefined
    )
    return operation
  }

  private async performAddAccount(): Promise<AccountSwitchMutationResult> {
    const current = await this.loadRegistry()
    if (current.accounts.length >= ACCOUNT_REGISTRY_MAX_ACCOUNTS) {
      throw new AccountSwitchServiceError('ACCOUNT_LIMIT_REACHED')
    }

    let accountId: string
    try {
      accountId = createAccountId(this.createUuid)
    } catch {
      throw new AccountSwitchServiceError('ACCOUNT_ID_GENERATION_FAILED')
    }
    if (current.accounts.some((account) => account.id === accountId)) {
      throw new AccountSwitchServiceError('ACCOUNT_ID_GENERATION_FAILED')
    }

    await this.prepareAccountStorage(accountId)
    const next = parseAccountRegistry({
      ...current,
      revision: current.revision + 1,
      activeAccountId: accountId,
      accounts: [...current.accounts.map(copyEntry), { id: accountId }]
    })
    return this.commitActivation(current, next, accountId, 'add-account')
  }

  private async performSwitchAccount(accountId: string): Promise<AccountSwitchMutationResult> {
    const current = await this.loadRegistry()
    if (!current.accounts.some((account) => account.id === accountId)) {
      throw new AccountSwitchServiceError('ACCOUNT_NOT_REGISTERED')
    }
    if (current.activeAccountId === accountId) {
      return {
        kind: 'unchanged',
        status: rendererSafeStatus(current, this.accountRemovalCleanupPending)
      }
    }

    await this.preflightAccountStorage(accountId)
    const next = parseAccountRegistry({
      ...current,
      revision: current.revision + 1,
      activeAccountId: accountId,
      accounts: current.accounts.map(copyEntry)
    })
    return this.commitActivation(current, next, accountId, 'switch-account')
  }

  private async performRemoveAccount(accountId: string): Promise<AccountSwitchMutationResult> {
    const current = await this.loadRegistry()
    if (!current.accounts.some((account) => account.id === accountId)) {
      throw new AccountSwitchServiceError('ACCOUNT_NOT_REGISTERED')
    }
    if (current.activeAccountId === accountId) {
      throw new AccountSwitchServiceError('ACCOUNT_ACTIVE_REMOVAL_FORBIDDEN')
    }
    const recoveryCallbacks = this.accountRemovalRecoveryCallbacks()
    try {
      await this.removalJournal.prepare(accountId, current.revision)
    } catch {
      throw new AccountSwitchServiceError('ACCOUNT_REMOVAL_PREPARATION_FAILED')
    }
    const next = parseAccountRegistry({
      ...current,
      revision: current.revision + 1,
      accounts: current.accounts.filter((account) => account.id !== accountId).map(copyEntry)
    })
    let result: Extract<AccountSwitchMutationResult, { kind: 'updated' }>
    try {
      result = await this.commitRegistryUpdate(current, next)
    } catch (error) {
      if (
        !(error instanceof AccountSwitchServiceError) ||
        error.code !== 'ACCOUNT_REGISTRY_UPDATE_RESULT_UNKNOWN'
      ) {
        await this.removalJournal.clear().catch(() => undefined)
      }
      throw error
    }
    try {
      const cleanup = await this.removalJournal.finish(recoveryCallbacks)
      if (cleanup !== 'deleted') {
        this.relaunchPending = true
        throw new AccountSwitchServiceError('ACCOUNT_REGISTRY_UPDATE_RESULT_UNKNOWN')
      }
      this.accountRemovalCleanupPending = false
      return result
    } catch (error) {
      if (error instanceof AccountSwitchServiceError) throw error
      this.accountRemovalCleanupPending = true
      return {
        ...result,
        status: rendererSafeStatus(next, true),
        cleanupPending: true
      }
    }
  }

  private accountRemovalRecoveryCallbacks(): AccountRemovalRecoveryCallbacks {
    const loadPrimary = this.registryStore.loadPrimary?.bind(this.registryStore)
    const checkpoint = this.registryStore.checkpoint?.bind(this.registryStore)
    if (!loadPrimary || !checkpoint) {
      throw new AccountSwitchServiceError('ACCOUNT_REMOVAL_UNAVAILABLE')
    }
    return {
      loadAuthoritativeRegistry: loadPrimary,
      checkpointRegistry: async (registry) => {
        await checkpoint(registry, registry.revision)
      }
    }
  }

  private async performReorderAccounts(
    orderedAccountIds: readonly string[],
    expectedRevision: number
  ): Promise<AccountSwitchMutationResult> {
    const current = await this.loadRegistry()
    if (current.revision !== expectedRevision) {
      throw new AccountSwitchServiceError('ACCOUNT_STALE_REORDER_REQUEST')
    }
    if (
      orderedAccountIds.length !== current.accounts.length ||
      orderedAccountIds.some((id) => !current.accounts.some((account) => account.id === id))
    ) {
      throw new AccountSwitchServiceError('INVALID_ACCOUNT_SWITCH_REQUEST')
    }
    if (orderedAccountIds.every((id, index) => current.accounts[index]?.id === id)) {
      return {
        kind: 'unchanged',
        status: rendererSafeStatus(current, this.accountRemovalCleanupPending)
      }
    }
    const entries = new Map(current.accounts.map((account) => [account.id, account] as const))
    const next = parseAccountRegistry({
      ...current,
      revision: current.revision + 1,
      accounts: orderedAccountIds.map((id) => copyEntry(entries.get(id)!))
    })
    return this.commitRegistryUpdate(current, next)
  }

  private async commitRegistryUpdate(
    current: AccountRegistry,
    next: AccountRegistry
  ): Promise<Extract<AccountSwitchMutationResult, { kind: 'updated' }>> {
    try {
      await this.registryStore.save(next, current.revision)
    } catch {
      let observed: AccountRegistry
      try {
        const loaded = await this.registryStore.load()
        if (!loaded) throw new Error('ACCOUNT_REGISTRY_MISSING')
        observed = parseAccountRegistry(loaded)
      } catch {
        this.relaunchPending = true
        throw new AccountSwitchServiceError('ACCOUNT_REGISTRY_UPDATE_RESULT_UNKNOWN')
      }
      if (registryEqual(observed, current)) {
        throw new AccountSwitchServiceError('ACCOUNT_REGISTRY_UPDATE_FAILED')
      }
      if (!registryEqual(observed, next)) {
        this.relaunchPending = true
        throw new AccountSwitchServiceError('ACCOUNT_REGISTRY_UPDATE_RESULT_UNKNOWN')
      }
    }
    return {
      kind: 'updated',
      status: rendererSafeStatus(next, this.accountRemovalCleanupPending)
    }
  }

  private async prepareAccountStorage(accountId: string): Promise<void> {
    const accountPaths = this.paths.account(accountId)
    try {
      await ensurePrivateDirectory(this.paths.accountsDirectory)
      await requireMissing(accountPaths.accountDirectory)
      await ensurePrivateDirectory(accountPaths.accountDirectory)
      await ensurePrivateDirectory(accountPaths.vaultDirectory)
      await requireMissing(accountPaths.vaultPath)
      await createPendingInitializationMarker(
        accountPaths.initializationMarkerPath,
        this.createUuid
      )
    } catch {
      // Never remove an abandoned directory: it may contain data created by another process or a
      // prior crashed attempt. A fresh opaque ID is safer than destructive cleanup.
      throw new AccountSwitchServiceError('ACCOUNT_STORAGE_PREPARATION_FAILED')
    }
  }

  private async preflightAccountStorage(accountId: string): Promise<void> {
    const accountPaths = this.paths.account(accountId)
    try {
      for (const directory of [
        this.paths.accountsDirectory,
        accountPaths.accountDirectory,
        accountPaths.vaultDirectory
      ]) {
        const info = await lstat(directory)
        if (info.isSymbolicLink() || !info.isDirectory()) {
          throw new Error('UNSAFE_ACCOUNT_STORAGE_DIRECTORY')
        }
      }

      try {
        const vault = await lstat(accountPaths.vaultPath)
        if (vault.isSymbolicLink() || !vault.isFile()) {
          throw new Error('UNSAFE_ACCOUNT_VAULT')
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
        if (!(await hasPendingInitializationMarker(accountPaths.initializationMarkerPath))) {
          throw new Error('ACCOUNT_VAULT_AND_INITIALIZATION_MARKER_MISSING')
        }
      }
    } catch {
      throw new AccountSwitchServiceError('ACCOUNT_STORAGE_UNAVAILABLE')
    }
  }

  private async commitActivation(
    current: AccountRegistry,
    next: AccountRegistry,
    accountId: string,
    reason: AccountActivationReason
  ): Promise<AccountSwitchMutationResult> {
    try {
      await this.beforeActivation(accountId, reason)
    } catch {
      throw new AccountSwitchServiceError('ACCOUNT_ACTIVATION_FAILED')
    }

    // The barrier may await arbitrary teardown work. Revalidate immediately before the CAS so a
    // target replaced while teardown was in progress is never made active.
    await this.preflightAccountStorage(accountId)

    try {
      await this.registryStore.save(next, current.revision)
    } catch {
      let observed: AccountRegistry
      try {
        const loaded = await this.registryStore.load()
        if (!loaded) throw new Error('ACCOUNT_REGISTRY_MISSING')
        observed = parseAccountRegistry(loaded)
      } catch {
        this.relaunchPending = true
        throw new AccountSwitchServiceError('ACCOUNT_REGISTRY_UPDATE_RESULT_UNKNOWN')
      }
      if (registryEqual(observed, current)) {
        throw new AccountSwitchServiceError('ACCOUNT_REGISTRY_UPDATE_FAILED')
      }
      if (!registryEqual(observed, next)) {
        this.relaunchPending = true
        throw new AccountSwitchServiceError('ACCOUNT_REGISTRY_UPDATE_RESULT_UNKNOWN')
      }
    }

    const status = rendererSafeStatus(next, this.accountRemovalCleanupPending)
    this.relaunchPending = true
    try {
      await this.afterCommitRelaunch(accountId, reason)
    } catch {
      throw new AccountRelaunchResultUnknownError(status)
    }
    return { kind: 'relaunch-required', status }
  }

  private async loadRegistry(): Promise<AccountRegistry> {
    try {
      const registry = await this.registryStore.load()
      if (!registry) throw new Error('ACCOUNT_REGISTRY_MISSING')
      return parseAccountRegistry(registry)
    } catch {
      throw new AccountSwitchServiceError('ACCOUNT_REGISTRY_UNAVAILABLE')
    }
  }

  private assertEmptyRequest(request: unknown): void {
    if (request !== undefined) {
      throw new AccountSwitchServiceError('INVALID_ACCOUNT_SWITCH_REQUEST')
    }
  }
}
