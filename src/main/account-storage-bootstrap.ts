import { lstat } from 'node:fs/promises'
import { match } from 'ts-pattern'
import {
  createAccountId,
  createAccountPathLayout,
  ensurePrivateDirectory,
  type AccountStoragePaths
} from './account-paths'
import { AccountRegistryStore, createInitialAccountRegistry } from './account-registry'
import {
  clearPendingInitializationMarker,
  createPendingInitializationMarker
} from './account-storage-initialization-marker'
import {
  migrateLegacyAccountStorage,
  type AccountStorageMigrationOptions
} from './account-storage-migration'

export type ActiveAccountStorage =
  | {
      readonly mode: 'account'
      readonly activeAccountId: string
      readonly paths: AccountStoragePaths
    }
  | {
      readonly mode: 'legacy-fallback'
      readonly activeAccountId: null
      readonly paths: Pick<AccountStoragePaths, 'vaultPath' | 'settingsPath' | 'touchIdPath'>
      readonly fallbackReason: 'registry-unavailable' | 'target-missing' | 'target-corrupt'
    }

export interface AccountStorageBootstrapOptions {
  readonly createUuid?: () => string
  readonly registryStore?: AccountRegistryStore
  readonly migrationOptions?: Omit<AccountStorageMigrationOptions, 'createUuid' | 'registryStore'>
}

function accountStorage(
  activeAccountId: string,
  paths: AccountStoragePaths
): Extract<ActiveAccountStorage, { mode: 'account' }> {
  return { mode: 'account', activeAccountId, paths }
}

async function vaultFileExists(path: string): Promise<boolean> {
  try {
    const info = await lstat(path)
    if (info.isSymbolicLink() || !info.isFile()) throw new Error('UNSAFE_ACCOUNT_VAULT')
    return true
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false
    throw error
  }
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

async function initializeAccountStorage(
  userDataDirectory: string,
  registryStore: AccountRegistryStore,
  createUuid: AccountStorageBootstrapOptions['createUuid']
): Promise<Extract<ActiveAccountStorage, { mode: 'account' }>> {
  const layout = createAccountPathLayout(userDataDirectory)
  const accountId = createAccountId(createUuid)
  const paths = layout.account(accountId)

  // EncryptedVaultStore creates vault.json only during initialize(masterPassword, data). Create
  // the private directory tree before committing the initial registry, but never manufacture an
  // empty vault file or overwrite an abandoned path.
  await ensurePrivateDirectory(layout.accountsDirectory)
  await requireMissing(paths.accountDirectory)
  await ensurePrivateDirectory(paths.accountDirectory)
  await ensurePrivateDirectory(paths.vaultDirectory)
  await requireMissing(paths.vaultPath)
  await createPendingInitializationMarker(paths.initializationMarkerPath, createUuid)

  const registry = createInitialAccountRegistry(accountId)
  await registryStore.save(registry, null)
  return accountStorage(registry.activeAccountId, paths)
}

/**
 * Establishes the sole storage location used by the currently active account. This is intentionally
 * separate from account switching: startup needs one safe path before it can construct services.
 */
export async function bootstrapAccountStorage(
  userDataDirectory: string,
  options: AccountStorageBootstrapOptions = {}
): Promise<ActiveAccountStorage> {
  const createUuid = options.createUuid
  const registryStore =
    options.registryStore ?? new AccountRegistryStore(userDataDirectory, { createUuid })
  const migration = await migrateLegacyAccountStorage(userDataDirectory, {
    ...options.migrationOptions,
    createUuid,
    registryStore
  })

  return match(migration)
    .with({ kind: 'account' }, async ({ accountId, accountPaths }) => {
      // A crash after the vault rename can leave the marker behind. The vault is already committed,
      // so repair is deliberately best effort and must not make startup fail.
      if (await vaultFileExists(accountPaths.vaultPath)) {
        await clearPendingInitializationMarker(accountPaths.initializationMarkerPath).catch(
          () => undefined
        )
      }
      return accountStorage(accountId, accountPaths)
    })
    .with(
      { kind: 'legacy-fallback' },
      ({ legacyVaultPath, legacySettingsPath, legacyTouchIdPath, reason }) => ({
        mode: 'legacy-fallback' as const,
        activeAccountId: null,
        paths: {
          vaultPath: legacyVaultPath,
          settingsPath: legacySettingsPath,
          touchIdPath: legacyTouchIdPath
        },
        fallbackReason: reason
      })
    )
    .with({ kind: 'storage-unavailable' }, ({ reason }) => {
      throw new Error(`ACCOUNT_STORAGE_${reason.toUpperCase().replaceAll('-', '_')}`)
    })
    .with({ kind: 'no-legacy-vault' }, () =>
      initializeAccountStorage(userDataDirectory, registryStore, createUuid)
    )
    .exhaustive()
}
