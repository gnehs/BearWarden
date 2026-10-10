import { lstat } from 'node:fs/promises'
import {
  createAccountId,
  createAccountPathLayout,
  ensurePrivateDirectory,
  requireMissing,
  type AccountStoragePaths
} from './account-paths'
import { AccountRegistryStore, createInitialAccountRegistry } from './account-registry'
import {
  clearPendingInitializationMarker,
  createPendingInitializationMarker
} from './account-storage-initialization-marker'
import { migrateLegacyAccountStorage } from './account-storage-migration'

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
    createUuid,
    registryStore
  })

  switch (migration.kind) {
    case 'account': {
      const { accountId, accountPaths } = migration
      // A crash after the vault rename can leave the marker behind. The vault is already committed,
      // so repair is deliberately best effort and must not make startup fail.
      if (await vaultFileExists(accountPaths.vaultPath)) {
        await clearPendingInitializationMarker(accountPaths.initializationMarkerPath).catch(
          () => undefined
        )
      }
      return accountStorage(accountId, accountPaths)
    }
    case 'legacy-fallback':
      return {
        mode: 'legacy-fallback',
        activeAccountId: null,
        paths: {
          vaultPath: migration.legacyVaultPath,
          settingsPath: migration.legacySettingsPath,
          touchIdPath: migration.legacyTouchIdPath
        },
        fallbackReason: migration.reason
      }
    case 'storage-unavailable':
      throw new Error(`ACCOUNT_STORAGE_${migration.reason.toUpperCase().replaceAll('-', '_')}`)
    case 'no-legacy-vault':
      return initializeAccountStorage(userDataDirectory, registryStore, createUuid)
  }
}
