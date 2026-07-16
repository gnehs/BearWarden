import {
  access,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  stat,
  symlink,
  unlink,
  writeFile
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import { createAccountPathLayout } from './account-paths'
import { parseAccountRegistry, type AccountRegistry } from './account-registry'
import {
  AccountRelaunchResultUnknownError,
  AccountSwitchService,
  type AccountActivationReason,
  type AccountSwitchRegistryStore
} from './account-switch-service'
import {
  createPendingInitializationMarker,
  hasPendingInitializationMarker
} from './account-storage-initialization-marker'

const ACCOUNT_A = '11111111-1111-4111-8111-111111111111'
const ACCOUNT_B = '22222222-2222-4222-8222-222222222222'
const ACCOUNT_C = '33333333-3333-4333-8333-333333333333'
const ACCOUNT_D = '44444444-4444-4444-8444-444444444444'
const ACCOUNT_E = '55555555-5555-4555-8555-555555555555'
const NEW_ACCOUNT = '66666666-6666-4666-8666-666666666666'
const MARKER_TEMP = 'aaaaaaaa-aaaa-4aaa-8aaa-000000000001'

function registry(
  revision = 1,
  activeAccountId = ACCOUNT_A,
  accountIds: readonly string[] = [ACCOUNT_A, ACCOUNT_B, ACCOUNT_C]
): AccountRegistry {
  return parseAccountRegistry({
    format: 'bearwarden-account-registry',
    version: 1,
    revision,
    activeAccountId,
    accounts: accountIds.map((id, index) =>
      index === 2 ? { id } : { id, identityHash: String(index + 1).repeat(64) }
    )
  })
}

interface MemoryStoreHarness {
  readonly store: AccountSwitchRegistryStore
  readonly load: ReturnType<typeof vi.fn>
  readonly save: ReturnType<typeof vi.fn>
  current(): AccountRegistry
}

function memoryStore(
  initial: AccountRegistry,
  beforeSave?: (next: AccountRegistry, expectedRevision: number | null) => void | Promise<void>
): MemoryStoreHarness {
  let current = initial
  const load = vi.fn(async () => current)
  const save = vi.fn(async (next: AccountRegistry, expectedRevision: number | null) => {
    await beforeSave?.(next, expectedRevision)
    if (expectedRevision !== current.revision) throw new Error('ACCOUNT_REGISTRY_CONFLICT')
    current = parseAccountRegistry(next)
    return current
  })
  return { store: { load, save }, load, save, current: () => current }
}

function uuidSequence(...values: readonly string[]): () => string {
  let index = 0
  return () => {
    const value = values[index]
    if (!value) throw new Error('UUID_SEQUENCE_EXHAUSTED')
    index += 1
    return value
  }
}

function deferred(): { readonly promise: Promise<void>; resolve(): void } {
  let resolve!: () => void
  const promise = new Promise<void>((resolvePromise) => {
    resolve = resolvePromise
  })
  return { promise, resolve }
}

async function prepareRegisteredVault(root: string, accountId: string): Promise<void> {
  const paths = createAccountPathLayout(root).account(accountId)
  await mkdir(paths.vaultDirectory, { recursive: true, mode: 0o700 })
  await writeFile(paths.vaultPath, 'opaque-encrypted-vault', { mode: 0o600 })
}

function callbacks(
  overrides: {
    readonly beforeActivation?: (accountId: string, reason: AccountActivationReason) => unknown
    readonly afterCommitRelaunch?: (accountId: string, reason: AccountActivationReason) => unknown
  } = {}
): {
  readonly beforeActivation: ReturnType<
    typeof vi.fn<(accountId: string, reason: AccountActivationReason) => Promise<void>>
  >
  readonly afterCommitRelaunch: ReturnType<
    typeof vi.fn<(accountId: string, reason: AccountActivationReason) => Promise<void>>
  >
} {
  return {
    beforeActivation: vi.fn(async (accountId, reason): Promise<void> => {
      await overrides.beforeActivation?.(accountId, reason)
    }),
    afterCommitRelaunch: vi.fn(async (accountId, reason): Promise<void> => {
      await overrides.afterCommitRelaunch?.(accountId, reason)
    })
  }
}

describe('AccountSwitchService renderer-safe status', () => {
  it('lists only opaque IDs, active flags and stable one-based slots', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-switch-status-'))
    const registryStore = memoryStore(registry())
    const service = new AccountSwitchService(root, {
      registryStore: registryStore.store,
      ...callbacks()
    })

    const status = await service.getStatus()
    expect(status).toEqual({
      activeAccountId: ACCOUNT_A,
      accounts: [
        { id: ACCOUNT_A, active: true, slot: 1 },
        { id: ACCOUNT_B, active: false, slot: 2 },
        { id: ACCOUNT_C, active: false, slot: 3 }
      ]
    })
    expect(await service.listAccounts()).toEqual(status.accounts)

    const serialized = JSON.stringify(status)
    expect(serialized).not.toContain('1'.repeat(64))
    expect(serialized).not.toContain('2'.repeat(64))
    expect(serialized).not.toContain('@')
    expect(serialized).not.toContain(root)
    expect(Object.keys(status)).toEqual(['activeAccountId', 'accounts'])
    expect(Object.keys(status.accounts[0]!)).toEqual(['id', 'active', 'slot'])
  })

  it('strictly rejects request payloads and malformed account IDs', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-switch-input-'))
    const service = new AccountSwitchService(root, {
      registryStore: memoryStore(registry()).store,
      ...callbacks()
    })

    await expect(service.getStatus({})).rejects.toMatchObject({
      code: 'INVALID_ACCOUNT_SWITCH_REQUEST'
    })
    await expect(service.addAccount({})).rejects.toMatchObject({
      code: 'INVALID_ACCOUNT_SWITCH_REQUEST'
    })
    await expect(service.switchAccount('../vault')).rejects.toMatchObject({
      code: 'INVALID_ACCOUNT_SWITCH_REQUEST'
    })
    await expect(service.switchAccount({ toString: () => ACCOUNT_B })).rejects.toMatchObject({
      code: 'INVALID_ACCOUNT_SWITCH_REQUEST'
    })
  })
})

describe('AccountSwitchService switching', () => {
  it('rejects unknown accounts before activation and treats the active account as a no-op', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-switch-noop-'))
    const registryStore = memoryStore(registry())
    const activation = callbacks()
    const service = new AccountSwitchService(root, {
      registryStore: registryStore.store,
      ...activation
    })

    await expect(service.switchAccount(NEW_ACCOUNT)).rejects.toMatchObject({
      code: 'ACCOUNT_NOT_REGISTERED'
    })
    await expect(service.switchAccount(ACCOUNT_A)).resolves.toMatchObject({
      kind: 'unchanged',
      status: { activeAccountId: ACCOUNT_A }
    })
    expect(registryStore.save).not.toHaveBeenCalled()
    expect(activation.beforeActivation).not.toHaveBeenCalled()
    expect(activation.afterCommitRelaunch).not.toHaveBeenCalled()
  })

  it('increments one revision and preserves account order and identity hashes', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-switch-success-'))
    await prepareRegisteredVault(root, ACCOUNT_B)
    const initial = registry()
    const registryStore = memoryStore(initial)
    const events: string[] = []
    const activation = callbacks({
      beforeActivation: (accountId, reason) => events.push(`before:${accountId}:${reason}`),
      afterCommitRelaunch: (accountId, reason) => events.push(`after:${accountId}:${reason}`)
    })
    const service = new AccountSwitchService(root, {
      registryStore: registryStore.store,
      ...activation
    })

    await expect(service.switchAccount(ACCOUNT_B)).resolves.toEqual({
      kind: 'relaunch-required',
      status: {
        activeAccountId: ACCOUNT_B,
        accounts: [
          { id: ACCOUNT_A, active: false, slot: 1 },
          { id: ACCOUNT_B, active: true, slot: 2 },
          { id: ACCOUNT_C, active: false, slot: 3 }
        ]
      }
    })
    expect(events).toEqual([
      `before:${ACCOUNT_B}:switch-account`,
      `after:${ACCOUNT_B}:switch-account`
    ])
    expect(registryStore.save).toHaveBeenCalledWith(expect.any(Object), 1)
    expect(registryStore.current()).toEqual({
      ...initial,
      revision: 2,
      activeAccountId: ACCOUNT_B,
      accounts: initial.accounts.map((account) => ({ ...account }))
    })
  })

  it('allows a registered first-run account only when its valid pending marker exists', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-switch-pending-target-'))
    const paths = createAccountPathLayout(root).account(ACCOUNT_B)
    await mkdir(paths.vaultDirectory, { recursive: true, mode: 0o700 })
    await createPendingInitializationMarker(paths.initializationMarkerPath, () => MARKER_TEMP)
    const registryStore = memoryStore(registry())
    const activation = callbacks()
    const service = new AccountSwitchService(root, {
      registryStore: registryStore.store,
      ...activation
    })

    await expect(service.switchAccount(ACCOUNT_B)).resolves.toMatchObject({
      kind: 'relaunch-required',
      status: { activeAccountId: ACCOUNT_B }
    })
    expect(registryStore.current()).toMatchObject({ revision: 2, activeAccountId: ACCOUNT_B })
  })

  it.each([
    {
      name: 'a missing vault without a marker',
      prepare: async (root: string) => {
        await mkdir(createAccountPathLayout(root).account(ACCOUNT_B).vaultDirectory, {
          recursive: true
        })
      }
    },
    {
      name: 'a corrupt pending marker',
      prepare: async (root: string) => {
        const paths = createAccountPathLayout(root).account(ACCOUNT_B)
        await mkdir(paths.vaultDirectory, { recursive: true })
        await writeFile(paths.initializationMarkerPath, 'not-a-valid-marker')
      }
    },
    {
      name: 'a symlinked pending marker',
      prepare: async (root: string) => {
        const paths = createAccountPathLayout(root).account(ACCOUNT_B)
        const outsideMarker = join(root, 'outside-pending-marker')
        await mkdir(paths.vaultDirectory, { recursive: true })
        await createPendingInitializationMarker(outsideMarker, () => MARKER_TEMP)
        await symlink(outsideMarker, paths.initializationMarkerPath)
      }
    },
    {
      name: 'a symlinked vault',
      prepare: async (root: string) => {
        const paths = createAccountPathLayout(root).account(ACCOUNT_B)
        const outsideVault = join(root, 'outside-vault.json')
        await mkdir(paths.vaultDirectory, { recursive: true })
        await writeFile(outsideVault, 'opaque-encrypted-vault')
        await symlink(outsideVault, paths.vaultPath)
      }
    }
  ])('fails closed before activation for $name', async ({ prepare }) => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-switch-unsafe-target-'))
    await prepare(root)
    const initial = registry()
    const registryStore = memoryStore(initial)
    const activation = callbacks()
    const service = new AccountSwitchService(root, {
      registryStore: registryStore.store,
      ...activation
    })

    await expect(service.switchAccount(ACCOUNT_B)).rejects.toMatchObject({
      code: 'ACCOUNT_STORAGE_UNAVAILABLE'
    })
    expect(registryStore.current()).toEqual(initial)
    expect(registryStore.save).not.toHaveBeenCalled()
    expect(activation.beforeActivation).not.toHaveBeenCalled()
    expect(activation.afterCommitRelaunch).not.toHaveBeenCalled()
  })

  it('awaits the activation barrier and keeps the registry unchanged when it fails', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-switch-before-fail-'))
    await prepareRegisteredVault(root, ACCOUNT_B)
    const initial = registry()
    const registryStore = memoryStore(initial)
    const activation = callbacks({
      beforeActivation: () => {
        throw new Error('private@example.invalid /Users/private/vault.json')
      }
    })
    const service = new AccountSwitchService(root, {
      registryStore: registryStore.store,
      ...activation
    })

    let failure: unknown
    try {
      await service.switchAccount(ACCOUNT_B)
    } catch (error) {
      failure = error
    }
    expect(failure).toMatchObject({ code: 'ACCOUNT_ACTIVATION_FAILED' })
    expect(String(failure)).not.toContain('private@example.invalid')
    expect(String(failure)).not.toContain('/Users/private')
    expect(registryStore.current()).toEqual(initial)
    expect(registryStore.save).not.toHaveBeenCalled()
    expect(activation.afterCommitRelaunch).not.toHaveBeenCalled()
  })

  it('revalidates target storage after the awaited barrier and before the registry commit', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-switch-revalidate-'))
    await prepareRegisteredVault(root, ACCOUNT_B)
    const initial = registry()
    const registryStore = memoryStore(initial)
    const target = createAccountPathLayout(root).account(ACCOUNT_B)
    const outsideVault = join(root, 'outside-after-barrier.json')
    await writeFile(outsideVault, 'opaque-encrypted-vault')
    const activation = callbacks({
      beforeActivation: async () => {
        await unlink(target.vaultPath)
        await symlink(outsideVault, target.vaultPath)
      }
    })
    const service = new AccountSwitchService(root, {
      registryStore: registryStore.store,
      ...activation
    })

    await expect(service.switchAccount(ACCOUNT_B)).rejects.toMatchObject({
      code: 'ACCOUNT_STORAGE_UNAVAILABLE'
    })
    expect(registryStore.current()).toEqual(initial)
    expect(registryStore.save).not.toHaveBeenCalled()
    expect(activation.afterCommitRelaunch).not.toHaveBeenCalled()
  })

  it('reconciles a store error after the primary commit and still requests one relaunch', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-switch-post-commit-store-error-'))
    await prepareRegisteredVault(root, ACCOUNT_B)
    let current = registry()
    const registryStore: AccountSwitchRegistryStore = {
      load: vi.fn(async () => current),
      save: vi.fn(async (next) => {
        current = parseAccountRegistry(next)
        throw new Error('INJECTED_AFTER_PRIMARY_COMMIT')
      })
    }
    const activation = callbacks()
    const service = new AccountSwitchService(root, { registryStore, ...activation })

    await expect(service.switchAccount(ACCOUNT_B)).resolves.toMatchObject({
      kind: 'relaunch-required',
      status: { activeAccountId: ACCOUNT_B }
    })
    expect(current).toMatchObject({ revision: 2, activeAccountId: ACCOUNT_B })
    expect(activation.afterCommitRelaunch).toHaveBeenCalledTimes(1)
  })

  it('serializes concurrent requests, lets a failed CAS unblock the last request, and never interleaves barriers', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-switch-concurrent-'))
    await Promise.all([
      prepareRegisteredVault(root, ACCOUNT_B),
      prepareRegisteredVault(root, ACCOUNT_C)
    ])
    const firstBarrier = deferred()
    const events: string[] = []
    let saveAttempts = 0
    const registryStore = memoryStore(registry(), async (next) => {
      saveAttempts += 1
      events.push(`save:${next.activeAccountId}`)
      if (saveAttempts === 1) throw new Error('CAS_FAILED')
    })
    const activation = callbacks({
      beforeActivation: async (accountId) => {
        events.push(`before:${accountId}`)
        if (accountId === ACCOUNT_B) await firstBarrier.promise
      },
      afterCommitRelaunch: (accountId) => events.push(`after:${accountId}`)
    })
    const service = new AccountSwitchService(root, {
      registryStore: registryStore.store,
      ...activation
    })

    const first = service.switchAccount(ACCOUNT_B)
    const last = service.switchAccount(ACCOUNT_C)
    await vi.waitFor(() => expect(events).toEqual([`before:${ACCOUNT_B}`]))
    firstBarrier.resolve()

    await expect(first).rejects.toMatchObject({ code: 'ACCOUNT_REGISTRY_UPDATE_FAILED' })
    await expect(last).resolves.toMatchObject({
      kind: 'relaunch-required',
      status: { activeAccountId: ACCOUNT_C }
    })
    expect(events).toEqual([
      `before:${ACCOUNT_B}`,
      `save:${ACCOUNT_B}`,
      `before:${ACCOUNT_C}`,
      `save:${ACCOUNT_C}`,
      `after:${ACCOUNT_C}`
    ])
    expect(registryStore.current()).toMatchObject({ revision: 2, activeAccountId: ACCOUNT_C })
  })

  it('allows only one relaunch-producing commit, including for already queued mutations', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-switch-relaunch-guard-'))
    await prepareRegisteredVault(root, ACCOUNT_B)
    const registryStore = memoryStore(registry())
    const activation = callbacks()
    const service = new AccountSwitchService(root, {
      registryStore: registryStore.store,
      ...activation
    })

    const first = service.switchAccount(ACCOUNT_B)
    const queued = service.switchAccount(ACCOUNT_C)

    await expect(first).resolves.toMatchObject({ kind: 'relaunch-required' })
    await expect(queued).rejects.toMatchObject({ code: 'ACCOUNT_SWITCH_IN_PROGRESS' })
    await expect(service.addAccount()).rejects.toMatchObject({
      code: 'ACCOUNT_SWITCH_IN_PROGRESS'
    })
    expect(registryStore.current()).toMatchObject({ revision: 2, activeAccountId: ACCOUNT_B })
    expect(activation.afterCommitRelaunch).toHaveBeenCalledTimes(1)
  })

  it('reports an unknown result after a committed relaunch failure and never rolls back', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-switch-after-fail-'))
    await prepareRegisteredVault(root, ACCOUNT_B)
    const registryStore = memoryStore(registry())
    const activation = callbacks({
      afterCommitRelaunch: () => {
        throw new Error('SHELL_PATH_OR_PII')
      }
    })
    const service = new AccountSwitchService(root, {
      registryStore: registryStore.store,
      ...activation
    })

    let failure: unknown
    try {
      await service.switchAccount(ACCOUNT_B)
    } catch (error) {
      failure = error
    }
    expect(failure).toBeInstanceOf(AccountRelaunchResultUnknownError)
    expect(failure).toMatchObject({
      code: 'RELAUNCH_RESULT_UNKNOWN',
      committedStatus: { activeAccountId: ACCOUNT_B }
    })
    expect(JSON.stringify(failure)).not.toContain('SHELL_PATH_OR_PII')
    expect(registryStore.current()).toMatchObject({ revision: 2, activeAccountId: ACCOUNT_B })
    await expect(service.switchAccount(ACCOUNT_C)).rejects.toMatchObject({
      code: 'ACCOUNT_SWITCH_IN_PROGRESS'
    })
  })
})

describe('AccountSwitchService account creation', () => {
  it('enforces the five-account limit before creating storage or activating', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-switch-max-'))
    const registryStore = memoryStore(
      registry(1, ACCOUNT_A, [ACCOUNT_A, ACCOUNT_B, ACCOUNT_C, ACCOUNT_D, ACCOUNT_E])
    )
    const activation = callbacks()
    const createUuid = vi.fn(() => NEW_ACCOUNT)
    const service = new AccountSwitchService(root, {
      registryStore: registryStore.store,
      createUuid,
      ...activation
    })

    await expect(service.addAccount()).rejects.toMatchObject({ code: 'ACCOUNT_LIMIT_REACHED' })
    expect(createUuid).not.toHaveBeenCalled()
    expect(registryStore.save).not.toHaveBeenCalled()
    expect(activation.beforeActivation).not.toHaveBeenCalled()
    await expect(access(createAccountPathLayout(root).accountsDirectory)).rejects.toMatchObject({
      code: 'ENOENT'
    })
  })

  it('prepares private account storage and a pending marker before the registry commit', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-switch-add-'))
    const initial = registry()
    let storageWasReadyAtCommit = false
    const paths = createAccountPathLayout(root).account(NEW_ACCOUNT)
    const registryStore = memoryStore(initial, async () => {
      storageWasReadyAtCommit =
        (await stat(paths.accountDirectory)).isDirectory() &&
        (await stat(paths.vaultDirectory)).isDirectory() &&
        (await hasPendingInitializationMarker(paths.initializationMarkerPath))
    })
    const activation = callbacks()
    const service = new AccountSwitchService(root, {
      registryStore: registryStore.store,
      createUuid: uuidSequence(NEW_ACCOUNT, MARKER_TEMP),
      ...activation
    })

    await expect(service.addAccount()).resolves.toMatchObject({
      kind: 'relaunch-required',
      status: {
        activeAccountId: NEW_ACCOUNT,
        accounts: [
          { id: ACCOUNT_A, slot: 1 },
          { id: ACCOUNT_B, slot: 2 },
          { id: ACCOUNT_C, slot: 3 },
          { id: NEW_ACCOUNT, active: true, slot: 4 }
        ]
      }
    })
    expect(storageWasReadyAtCommit).toBe(true)
    await expect(hasPendingInitializationMarker(paths.initializationMarkerPath)).resolves.toBe(true)
    await expect(access(paths.vaultPath)).rejects.toMatchObject({ code: 'ENOENT' })
    if (process.platform !== 'win32') {
      expect((await lstat(paths.accountDirectory)).mode & 0o777).toBe(0o700)
      expect((await lstat(paths.vaultDirectory)).mode & 0o777).toBe(0o700)
      expect((await lstat(paths.initializationMarkerPath)).mode & 0o777).toBe(0o600)
    }
    expect(registryStore.current()).toEqual({
      ...initial,
      revision: 2,
      activeAccountId: NEW_ACCOUNT,
      accounts: [...initial.accounts.map((account) => ({ ...account })), { id: NEW_ACCOUNT }]
    })
    expect(activation.beforeActivation).toHaveBeenCalledWith(NEW_ACCOUNT, 'add-account')
    expect(activation.afterCommitRelaunch).toHaveBeenCalledWith(NEW_ACCOUNT, 'add-account')
  })

  it('leaves a safe crash orphan with its marker when activation fails before commit', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-switch-orphan-'))
    const initial = registry()
    const registryStore = memoryStore(initial)
    const paths = createAccountPathLayout(root).account(NEW_ACCOUNT)
    const activation = callbacks({
      beforeActivation: () => {
        throw new Error('SIMULATED_CRASH')
      }
    })
    const service = new AccountSwitchService(root, {
      registryStore: registryStore.store,
      createUuid: uuidSequence(NEW_ACCOUNT, MARKER_TEMP),
      ...activation
    })

    await expect(service.addAccount()).rejects.toMatchObject({ code: 'ACCOUNT_ACTIVATION_FAILED' })
    expect(registryStore.current()).toEqual(initial)
    expect(registryStore.save).not.toHaveBeenCalled()
    await expect(hasPendingInitializationMarker(paths.initializationMarkerPath)).resolves.toBe(true)
    await expect(access(paths.vaultPath)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('keeps the prepared orphan and marker when the registry CAS fails', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-switch-cas-orphan-'))
    const initial = registry()
    const registryStore = memoryStore(initial, () => {
      throw new Error('ACCOUNT_REGISTRY_CONFLICT')
    })
    const paths = createAccountPathLayout(root).account(NEW_ACCOUNT)
    const activation = callbacks()
    const service = new AccountSwitchService(root, {
      registryStore: registryStore.store,
      createUuid: uuidSequence(NEW_ACCOUNT, MARKER_TEMP),
      ...activation
    })

    await expect(service.addAccount()).rejects.toMatchObject({
      code: 'ACCOUNT_REGISTRY_UPDATE_FAILED'
    })
    expect(registryStore.current()).toEqual(initial)
    await expect(hasPendingInitializationMarker(paths.initializationMarkerPath)).resolves.toBe(true)
    expect(activation.beforeActivation).toHaveBeenCalledTimes(1)
    expect(activation.afterCommitRelaunch).not.toHaveBeenCalled()
  })

  it('does not delete or overwrite unknown data when preparation encounters an orphan', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-switch-collision-'))
    const layout = createAccountPathLayout(root)
    const paths = layout.account(NEW_ACCOUNT)
    await mkdir(paths.accountDirectory, { recursive: true })
    const sentinel = join(paths.accountDirectory, 'unknown-vault-data.bin')
    await writeFile(sentinel, Buffer.from([0, 1, 2, 255]))
    const registryStore = memoryStore(registry())
    const activation = callbacks()
    const service = new AccountSwitchService(root, {
      registryStore: registryStore.store,
      createUuid: uuidSequence(NEW_ACCOUNT),
      ...activation
    })

    await expect(service.addAccount()).rejects.toMatchObject({
      code: 'ACCOUNT_STORAGE_PREPARATION_FAILED'
    })
    expect(await readFile(sentinel)).toEqual(Buffer.from([0, 1, 2, 255]))
    expect(registryStore.save).not.toHaveBeenCalled()
    expect(activation.beforeActivation).not.toHaveBeenCalled()
  })
})
