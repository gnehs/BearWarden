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

export type AccountActivationReason = 'add-account' | 'switch-account'

export interface RendererSafeAccountStatusEntry {
  /** Opaque identifier. Display metadata must remain in account-scoped encrypted storage. */
  readonly id: string
  readonly active: boolean
  /** One-based, stable position inherited from the registry's append-only account order. */
  readonly slot: number
}

export interface RendererSafeAccountStatus {
  readonly activeAccountId: string
  readonly accounts: readonly RendererSafeAccountStatusEntry[]
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

export type AccountSwitchServiceErrorCode =
  | 'INVALID_ACCOUNT_SWITCH_REQUEST'
  | 'ACCOUNT_REGISTRY_UNAVAILABLE'
  | 'ACCOUNT_LIMIT_REACHED'
  | 'ACCOUNT_NOT_REGISTERED'
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
  save(registry: AccountRegistry, expectedRevision: number | null): Promise<AccountRegistry>
}

export interface AccountSwitchServiceOptions {
  readonly registryStore?: AccountSwitchRegistryStore
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

function rendererSafeStatus(registry: AccountRegistry): RendererSafeAccountStatus {
  const accounts = registry.accounts.map((account, index) =>
    Object.freeze({
      id: account.id,
      active: account.id === registry.activeAccountId,
      slot: index + 1
    })
  )
  return Object.freeze({
    activeAccountId: registry.activeAccountId,
    accounts: Object.freeze(accounts)
  })
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
  private readonly beforeActivation: AccountSwitchServiceOptions['beforeActivation']
  private readonly afterCommitRelaunch: AccountSwitchServiceOptions['afterCommitRelaunch']
  private mutationTail: Promise<void> = Promise.resolve()
  private relaunchPending = false

  constructor(userDataDirectory: string, options: AccountSwitchServiceOptions) {
    this.createUuid = options.createUuid
    this.paths = createAccountPathLayout(userDataDirectory)
    this.registryStore =
      options.registryStore ??
      new AccountRegistryStore(userDataDirectory, { createUuid: options.createUuid })
    this.beforeActivation = options.beforeActivation
    this.afterCommitRelaunch = options.afterCommitRelaunch
  }

  async getStatus(request?: unknown): Promise<RendererSafeAccountStatus> {
    this.assertEmptyRequest(request)
    return rendererSafeStatus(await this.loadRegistry())
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

  private serializeMutation(
    mutate: () => Promise<AccountSwitchMutationResult>
  ): Promise<AccountSwitchMutationResult> {
    const operation = this.mutationTail.then(async () => {
      if (this.relaunchPending) {
        throw new AccountSwitchServiceError('ACCOUNT_SWITCH_IN_PROGRESS')
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
      return { kind: 'unchanged', status: rendererSafeStatus(current) }
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

    const status = rendererSafeStatus(next)
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
