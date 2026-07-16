import { randomUUID } from 'node:crypto'
import { constants } from 'node:fs'
import { lstat, mkdir, open, rename, unlink, type FileHandle } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'

export const ACCOUNT_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u

const PRIVATE_DIRECTORY_MODE = 0o700

export interface AccountStoragePaths {
  readonly accountDirectory: string
  readonly vaultDirectory: string
  readonly vaultPath: string
  readonly settingsPath: string
  readonly touchIdPath: string
  readonly displayMetadataPath: string
}

export interface AccountPathLayout {
  readonly userDataDirectory: string
  readonly accountsDirectory: string
  readonly registryPath: string
  readonly registryBackupPath: string
  readonly migrationJournalPath: string
  readonly legacyVaultPath: string
  readonly legacySettingsPath: string
  readonly legacyTouchIdPath: string
  account(accountId: string): AccountStoragePaths
  migrationTemporaryDirectory(migrationId: string): string
}

export function assertAccountId(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !ACCOUNT_ID_PATTERN.test(value)) {
    throw new Error('INVALID_ACCOUNT_ID')
  }
}

export function createAccountId(createUuid: () => string = randomUUID): string {
  const value = createUuid()
  assertAccountId(value)
  return value
}

function assertDerivedChild(parent: string, child: string): void {
  const resolvedParent = resolve(parent)
  const resolvedChild = resolve(child)
  if (dirname(resolvedChild) !== resolvedParent) throw new Error('UNSAFE_ACCOUNT_PATH')
}

export function createAccountPathLayout(userDataDirectory: string): AccountPathLayout {
  if (typeof userDataDirectory !== 'string' || userDataDirectory.length === 0) {
    throw new Error('INVALID_USER_DATA_PATH')
  }
  const root = resolve(userDataDirectory)
  const accountsDirectory = join(root, 'accounts')

  return {
    userDataDirectory: root,
    accountsDirectory,
    registryPath: join(accountsDirectory, 'registry.json'),
    registryBackupPath: join(accountsDirectory, 'registry.json.bak'),
    migrationJournalPath: join(root, 'account-migration.json'),
    legacyVaultPath: join(root, 'vault', 'vault.json'),
    legacySettingsPath: join(root, 'settings.json'),
    legacyTouchIdPath: join(root, 'vault', 'touch-id.bin'),
    account(accountId: string): AccountStoragePaths {
      assertAccountId(accountId)
      const accountDirectory = join(accountsDirectory, accountId)
      assertDerivedChild(accountsDirectory, accountDirectory)
      const vaultDirectory = join(accountDirectory, 'vault')
      return {
        accountDirectory,
        vaultDirectory,
        vaultPath: join(vaultDirectory, 'vault.json'),
        settingsPath: join(accountDirectory, 'account-settings.json'),
        touchIdPath: join(accountDirectory, 'touch-id.bin'),
        displayMetadataPath: join(accountDirectory, 'display-metadata.bin')
      }
    },
    migrationTemporaryDirectory(migrationId: string): string {
      assertAccountId(migrationId)
      const directory = join(accountsDirectory, `.migration-${migrationId}.tmp`)
      assertDerivedChild(accountsDirectory, directory)
      return directory
    }
  }
}

export async function ensurePrivateDirectory(path: string): Promise<void> {
  try {
    const info = await lstat(path)
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('UNSAFE_DIRECTORY')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    try {
      await mkdir(path, { mode: PRIVATE_DIRECTORY_MODE })
    } catch (mkdirError) {
      if ((mkdirError as NodeJS.ErrnoException).code !== 'EEXIST') throw mkdirError
    }
    const info = await lstat(path)
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('UNSAFE_DIRECTORY')
  }
  const handle = await open(
    path,
    constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | (constants.O_NOFOLLOW ?? 0)
  )
  try {
    const info = await handle.stat()
    if (!info.isDirectory()) throw new Error('UNSAFE_DIRECTORY')
    await handle.chmod(PRIVATE_DIRECTORY_MODE)
  } finally {
    await handle.close().catch(() => undefined)
  }
}

export async function openNoFollow(
  path: string,
  flags: number,
  mode?: number
): Promise<FileHandle> {
  const noFollow = constants.O_NOFOLLOW ?? 0
  const handle = await open(path, flags | noFollow, mode)
  try {
    const info = await handle.stat()
    if (!info.isFile()) throw new Error('UNSAFE_FILE')
    return handle
  } catch (error) {
    await handle.close().catch(() => undefined)
    throw error
  }
}

export async function syncDirectory(path: string): Promise<void> {
  let handle: FileHandle | undefined
  try {
    handle = await open(
      path,
      constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | (constants.O_NOFOLLOW ?? 0)
    )
    await handle.sync()
  } catch {
    // Directory fsync is unavailable on some Electron targets, especially Windows.
  } finally {
    await handle?.close().catch(() => undefined)
  }
}

export async function atomicWritePrivateFile(
  path: string,
  contents: string | Buffer,
  createUuid: () => string = randomUUID
): Promise<void> {
  const directory = dirname(path)
  const temporaryPath = join(directory, `.${createAccountId(createUuid)}.tmp`)
  let handle: FileHandle | undefined
  try {
    handle = await openNoFollow(
      temporaryPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
      0o600
    )
    await handle.writeFile(contents)
    await handle.chmod(0o600)
    await handle.sync()
    await handle.close()
    handle = undefined
    await rename(temporaryPath, path)
    await syncDirectory(directory)
  } catch (error) {
    await handle?.close().catch(() => undefined)
    await unlink(temporaryPath).catch(() => undefined)
    throw error
  }
}
