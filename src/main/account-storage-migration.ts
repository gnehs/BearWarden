import { createHash, randomUUID } from 'node:crypto'
import { constants } from 'node:fs'
import { lstat, rename, unlink, type FileHandle } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import {
  ACCOUNT_ID_PATTERN,
  atomicWritePrivateFile,
  createAccountId,
  createAccountPathLayout,
  ensurePrivateDirectory,
  openNoFollow,
  syncDirectory,
  type AccountPathLayout,
  type AccountStoragePaths
} from './account-paths'
import {
  AccountRegistryStore,
  createInitialAccountRegistry,
  type AccountRegistry
} from './account-registry'
import { hasPendingInitializationMarker } from './account-storage-initialization-marker'

const JOURNAL_FORMAT = 'bearwarden-account-storage-migration'
const JOURNAL_VERSION = 1
const MAX_JOURNAL_BYTES = 16 * 1024
const DIGEST_PATTERN = /^[0-9a-f]{64}$/u
const COPY_BUFFER_SIZE = 64 * 1024

type MigrationPhase = 'planned' | 'copied' | 'renamed' | 'committed'
type MigrationFailureStage =
  | 'journal-planned'
  | 'file-bytes-copied'
  | 'files-copied'
  | 'account-directory-renamed'
  | 'account-renamed'
  | 'registry-committed'
  | 'journal-committed'

interface OpaqueFileFingerprint {
  readonly size: number
  readonly sha256: string
}

interface MigrationFiles {
  readonly vault: OpaqueFileFingerprint
  readonly settings: OpaqueFileFingerprint | null
  readonly touchId: OpaqueFileFingerprint | null
}

interface MigrationJournal {
  readonly format: typeof JOURNAL_FORMAT
  readonly version: typeof JOURNAL_VERSION
  readonly migrationId: string
  readonly accountId: string
  readonly phase: MigrationPhase
  readonly files?: MigrationFiles
}

export type AccountStorageMigrationResult =
  | {
      readonly kind: 'account'
      readonly accountId: string
      readonly accountPaths: AccountStoragePaths
      readonly registry: AccountRegistry
    }
  | {
      readonly kind: 'legacy-fallback'
      readonly reason: 'registry-unavailable' | 'target-missing' | 'target-corrupt'
      readonly legacyVaultPath: string
      readonly legacySettingsPath: string
      readonly legacyTouchIdPath: string
    }
  | { readonly kind: 'no-legacy-vault' }
  | {
      /**
       * Existing account-storage metadata cannot be trusted and there is no legacy vault to
       * preserve. Callers must not mistake this for a clean install and create a new registry.
       */
      readonly kind: 'storage-unavailable'
      readonly reason:
        'journal-unavailable' | 'registry-unavailable' | 'target-missing' | 'target-corrupt'
    }

export interface AccountStorageMigrationOptions {
  readonly createUuid?: () => string
  readonly failAfter?: (stage: MigrationFailureStage) => void | Promise<void>
  readonly afterCopyChunk?: () => void | Promise<void>
  readonly registryStore?: AccountRegistryStore
}

type PlainRecord = Record<string, unknown>

function plainRecord(value: unknown): value is PlainRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) return false
  const descriptors = Object.getOwnPropertyDescriptors(value)
  return Reflect.ownKeys(descriptors).every((key) => {
    if (typeof key !== 'string') return false
    const descriptor = descriptors[key]!
    return (
      descriptor.enumerable === true &&
      'value' in descriptor &&
      descriptor.get === undefined &&
      descriptor.set === undefined
    )
  })
}

function exactKeys(
  value: PlainRecord,
  required: readonly string[],
  optional: readonly string[] = []
): boolean {
  const allowed = new Set([...required, ...optional])
  return (
    required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key))
  )
}

function parseFingerprint(value: unknown): OpaqueFileFingerprint {
  if (
    !plainRecord(value) ||
    !exactKeys(value, ['size', 'sha256']) ||
    !Number.isSafeInteger(value.size) ||
    (value.size as number) < 0 ||
    typeof value.sha256 !== 'string' ||
    !DIGEST_PATTERN.test(value.sha256)
  ) {
    throw new Error('INVALID_MIGRATION_JOURNAL')
  }
  return { size: value.size as number, sha256: value.sha256 }
}

function parseFiles(value: unknown): MigrationFiles {
  if (!plainRecord(value) || !exactKeys(value, ['vault', 'settings', 'touchId'])) {
    throw new Error('INVALID_MIGRATION_JOURNAL')
  }
  return {
    vault: parseFingerprint(value.vault),
    settings: value.settings === null ? null : parseFingerprint(value.settings),
    touchId: value.touchId === null ? null : parseFingerprint(value.touchId)
  }
}

function parseJournal(value: unknown): MigrationJournal {
  if (
    !plainRecord(value) ||
    !exactKeys(value, ['format', 'version', 'migrationId', 'accountId', 'phase'], ['files']) ||
    value.format !== JOURNAL_FORMAT ||
    value.version !== JOURNAL_VERSION ||
    typeof value.migrationId !== 'string' ||
    !ACCOUNT_ID_PATTERN.test(value.migrationId) ||
    typeof value.accountId !== 'string' ||
    !ACCOUNT_ID_PATTERN.test(value.accountId) ||
    (value.phase !== 'planned' &&
      value.phase !== 'copied' &&
      value.phase !== 'renamed' &&
      value.phase !== 'committed')
  ) {
    throw new Error('INVALID_MIGRATION_JOURNAL')
  }
  if (value.phase === 'planned') {
    if (value.files !== undefined) throw new Error('INVALID_MIGRATION_JOURNAL')
    return {
      format: JOURNAL_FORMAT,
      version: JOURNAL_VERSION,
      migrationId: value.migrationId,
      accountId: value.accountId,
      phase: value.phase
    }
  }
  if (value.files === undefined) throw new Error('INVALID_MIGRATION_JOURNAL')
  return {
    format: JOURNAL_FORMAT,
    version: JOURNAL_VERSION,
    migrationId: value.migrationId,
    accountId: value.accountId,
    phase: value.phase,
    files: parseFiles(value.files)
  }
}

async function fileExistsNoSymlink(path: string): Promise<boolean> {
  try {
    const parent = await lstat(dirname(path))
    if (parent.isSymbolicLink() || !parent.isDirectory()) {
      throw new Error('UNSAFE_MIGRATION_DIRECTORY')
    }
    const info = await lstat(path)
    if (info.isSymbolicLink() || !info.isFile()) throw new Error('UNSAFE_MIGRATION_FILE')
    return true
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false
    throw error
  }
}

async function directoryExistsNoSymlink(path: string): Promise<boolean> {
  try {
    const info = await lstat(path)
    if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('UNSAFE_MIGRATION_DIRECTORY')
    return true
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false
    throw error
  }
}

async function readJournal(path: string): Promise<MigrationJournal | null> {
  let handle: FileHandle | undefined
  try {
    handle = await openNoFollow(path, constants.O_RDONLY)
    const info = await handle.stat()
    if (info.size < 1 || info.size > MAX_JOURNAL_BYTES) {
      throw new Error('INVALID_MIGRATION_JOURNAL')
    }
    return parseJournal(JSON.parse((await handle.readFile()).toString('utf8')) as unknown)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw error
  } finally {
    await handle?.close().catch(() => undefined)
  }
}

async function writeJournal(
  path: string,
  journal: MigrationJournal,
  createUuid: () => string
): Promise<void> {
  const normalized = parseJournal(journal)
  await atomicWritePrivateFile(path, `${JSON.stringify(normalized)}\n`, createUuid)
}

async function fingerprintFile(path: string): Promise<OpaqueFileFingerprint> {
  let handle: FileHandle | undefined
  let buffer: Buffer | undefined
  try {
    handle = await openNoFollow(path, constants.O_RDONLY)
    const before = await handle.stat()
    const hash = createHash('sha256')
    buffer = Buffer.allocUnsafe(COPY_BUFFER_SIZE)
    let position = 0
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, position)
      if (bytesRead === 0) break
      hash.update(buffer.subarray(0, bytesRead))
      position += bytesRead
    }
    const after = await handle.stat()
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      position !== after.size
    ) {
      throw new Error('MIGRATION_SOURCE_CHANGED')
    }
    return { size: position, sha256: hash.digest('hex') }
  } finally {
    buffer?.fill(0)
    await handle?.close().catch(() => undefined)
  }
}

function fingerprintEqual(left: OpaqueFileFingerprint, right: OpaqueFileFingerprint): boolean {
  return left.size === right.size && left.sha256 === right.sha256
}

async function writeAll(handle: FileHandle, buffer: Buffer, position: number): Promise<void> {
  let offset = 0
  while (offset < buffer.length) {
    const result = await handle.write(buffer, offset, buffer.length - offset, position + offset)
    if (result.bytesWritten < 1) throw new Error('MIGRATION_COPY_FAILED')
    offset += result.bytesWritten
  }
}

async function copyOpaqueFile(
  sourcePath: string,
  destinationPath: string,
  createUuid: () => string,
  afterCopyChunk?: () => void | Promise<void>
): Promise<OpaqueFileFingerprint> {
  if (await fileExistsNoSymlink(destinationPath)) {
    // Existing partial recovery files are replaced only after proving they are regular files.
  }
  const temporaryPath = join(dirname(destinationPath), `.copy-${createAccountId(createUuid)}.tmp`)
  let source: FileHandle | undefined
  let destination: FileHandle | undefined
  let buffer: Buffer | undefined
  try {
    source = await openNoFollow(sourcePath, constants.O_RDONLY)
    const sourceBefore = await source.stat()
    destination = await openNoFollow(
      temporaryPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
      0o600
    )
    buffer = Buffer.allocUnsafe(COPY_BUFFER_SIZE)
    let position = 0
    while (true) {
      const { bytesRead } = await source.read(buffer, 0, buffer.length, position)
      if (bytesRead === 0) break
      await writeAll(destination, buffer.subarray(0, bytesRead), position)
      position += bytesRead
      await afterCopyChunk?.()
    }
    const sourceAfter = await source.stat()
    if (
      sourceBefore.dev !== sourceAfter.dev ||
      sourceBefore.ino !== sourceAfter.ino ||
      sourceBefore.size !== sourceAfter.size ||
      sourceBefore.mtimeMs !== sourceAfter.mtimeMs ||
      position !== sourceAfter.size
    ) {
      throw new Error('MIGRATION_SOURCE_CHANGED')
    }
    await destination.chmod(0o600)
    await destination.sync()
    await destination.close()
    destination = undefined
    await source.close()
    source = undefined
    await rename(temporaryPath, destinationPath)
    await syncDirectory(dirname(destinationPath))

    const [sourceFingerprint, destinationFingerprint] = await Promise.all([
      fingerprintFile(sourcePath),
      fingerprintFile(destinationPath)
    ])
    if (!fingerprintEqual(sourceFingerprint, destinationFingerprint)) {
      throw new Error('MIGRATION_COPY_VERIFICATION_FAILED')
    }
    return destinationFingerprint
  } catch (error) {
    await source?.close().catch(() => undefined)
    await destination?.close().catch(() => undefined)
    await unlink(temporaryPath).catch(() => undefined)
    throw error
  } finally {
    buffer?.fill(0)
  }
}

function temporaryStoragePaths(temporaryDirectory: string): AccountStoragePaths {
  const vaultDirectory = join(temporaryDirectory, 'vault')
  return {
    accountDirectory: temporaryDirectory,
    vaultDirectory,
    vaultPath: join(vaultDirectory, 'vault.json'),
    settingsPath: join(temporaryDirectory, 'account-settings.json'),
    touchIdPath: join(temporaryDirectory, 'touch-id.bin'),
    initializationMarkerPath: join(temporaryDirectory, '.pending-initialization'),
    displayMetadataPath: join(temporaryDirectory, 'display-metadata.bin')
  }
}

async function copyLegacyFiles(
  layout: AccountPathLayout,
  target: AccountStoragePaths,
  createUuid: () => string,
  afterCopyChunk?: () => void | Promise<void>
): Promise<MigrationFiles> {
  await ensurePrivateDirectory(target.accountDirectory)
  await ensurePrivateDirectory(target.vaultDirectory)
  const vault = await copyOpaqueFile(
    layout.legacyVaultPath,
    target.vaultPath,
    createUuid,
    afterCopyChunk
  )
  const settings = (await fileExistsNoSymlink(layout.legacySettingsPath))
    ? await copyOpaqueFile(
        layout.legacySettingsPath,
        target.settingsPath,
        createUuid,
        afterCopyChunk
      )
    : null
  const touchId = (await fileExistsNoSymlink(layout.legacyTouchIdPath))
    ? await copyOpaqueFile(layout.legacyTouchIdPath, target.touchIdPath, createUuid, afterCopyChunk)
    : null
  return { vault, settings, touchId }
}

async function verifyFiles(
  target: AccountStoragePaths,
  expected: MigrationFiles
): Promise<boolean> {
  try {
    if (!(await fileExistsNoSymlink(target.vaultPath))) return false
    const vault = await fingerprintFile(target.vaultPath)
    if (!fingerprintEqual(vault, expected.vault)) return false

    for (const [path, fingerprint] of [
      [target.settingsPath, expected.settings],
      [target.touchIdPath, expected.touchId]
    ] as const) {
      const exists = await fileExistsNoSymlink(path)
      if (fingerprint === null) {
        if (exists) return false
      } else {
        if (!exists || !fingerprintEqual(await fingerprintFile(path), fingerprint)) return false
      }
    }
    return true
  } catch {
    return false
  }
}

function legacyFallback(
  layout: AccountPathLayout,
  reason: Extract<AccountStorageMigrationResult, { kind: 'legacy-fallback' }>['reason']
): AccountStorageMigrationResult {
  return {
    kind: 'legacy-fallback',
    reason,
    legacyVaultPath: layout.legacyVaultPath,
    legacySettingsPath: layout.legacySettingsPath,
    legacyTouchIdPath: layout.legacyTouchIdPath
  }
}

export async function migrateLegacyAccountStorage(
  userDataDirectory: string,
  options: AccountStorageMigrationOptions = {}
): Promise<AccountStorageMigrationResult> {
  const layout = createAccountPathLayout(userDataDirectory)
  const createUuid = options.createUuid ?? randomUUID
  const registryStore = options.registryStore ?? new AccountRegistryStore(userDataDirectory)
  await ensurePrivateDirectory(layout.userDataDirectory)
  const legacyVaultExists = await fileExistsNoSymlink(layout.legacyVaultPath)

  let journal: MigrationJournal | null
  try {
    journal = await readJournal(layout.migrationJournalPath)
  } catch {
    return legacyVaultExists
      ? legacyFallback(layout, 'registry-unavailable')
      : { kind: 'storage-unavailable', reason: 'journal-unavailable' }
  }

  let registry: AccountRegistry | null
  try {
    registry = await registryStore.load()
  } catch {
    return legacyVaultExists
      ? legacyFallback(layout, 'registry-unavailable')
      : { kind: 'storage-unavailable', reason: 'registry-unavailable' }
  }

  if (registry) {
    const accountPaths = layout.account(registry.activeAccountId)
    const migrationAlreadyCommitted = journal?.phase === 'committed'
    const accountDirectoryExists = await directoryExistsNoSymlink(accountPaths.accountDirectory)
    const vaultDirectoryExists = await directoryExistsNoSymlink(accountPaths.vaultDirectory)
    if (!accountDirectoryExists || !vaultDirectoryExists) {
      return legacyVaultExists
        ? legacyFallback(layout, 'target-missing')
        : { kind: 'storage-unavailable', reason: 'target-missing' }
    }
    // Once both the registry and migration journal are committed, the account-scoped vault is
    // live mutable state. Its migration fingerprint only proves that the original copy was
    // correct; comparing it on later launches would mistake every legitimate vault write for
    // corruption and roll the app back to the stale legacy vault.
    if (
      !journal ||
      migrationAlreadyCommitted ||
      journal.accountId !== registry.activeAccountId ||
      !journal.files
    ) {
      if (await fileExistsNoSymlink(accountPaths.vaultPath)) {
        return { kind: 'account', accountId: registry.activeAccountId, accountPaths, registry }
      }

      // A fresh or newly added account deliberately has no vault.json until
      // EncryptedVaultStore.initialize() receives the user's master password. Its private
      // directories and marker are committed before it becomes active, so the marker must take
      // precedence over retained legacy recovery data from an older account.
      if (await hasPendingInitializationMarker(accountPaths.initializationMarkerPath)) {
        return { kind: 'account', accountId: registry.activeAccountId, accountPaths, registry }
      }
      if (legacyVaultExists) return legacyFallback(layout, 'target-missing')
      return { kind: 'storage-unavailable', reason: 'target-missing' }
    }
    if (!(await verifyFiles(accountPaths, journal.files))) {
      return legacyVaultExists
        ? legacyFallback(
            layout,
            (await fileExistsNoSymlink(accountPaths.vaultPath))
              ? 'target-corrupt'
              : 'target-missing'
          )
        : {
            kind: 'storage-unavailable',
            reason: (await fileExistsNoSymlink(accountPaths.vaultPath))
              ? 'target-corrupt'
              : 'target-missing'
          }
    }
    if (journal.phase !== 'committed') {
      journal = { ...journal, phase: 'committed' }
      await writeJournal(layout.migrationJournalPath, journal, createUuid)
      await options.failAfter?.('journal-committed')
    }
    return { kind: 'account', accountId: registry.activeAccountId, accountPaths, registry }
  }

  if (!legacyVaultExists) {
    // A clean install has neither a registry nor a journal. Retaining a journal without a
    // registry means a previous migration was interrupted after its intent was persisted; do
    // not overwrite that evidence by treating it as a fresh install.
    return journal
      ? { kind: 'storage-unavailable', reason: 'registry-unavailable' }
      : { kind: 'no-legacy-vault' }
  }
  await ensurePrivateDirectory(layout.accountsDirectory)

  if (!journal) {
    journal = {
      format: JOURNAL_FORMAT,
      version: JOURNAL_VERSION,
      migrationId: createAccountId(createUuid),
      accountId: createAccountId(createUuid),
      phase: 'planned'
    }
    await writeJournal(layout.migrationJournalPath, journal, createUuid)
    await options.failAfter?.('journal-planned')
  }

  const finalPaths = layout.account(journal.accountId)
  const temporaryDirectory = layout.migrationTemporaryDirectory(journal.migrationId)
  const temporaryPaths = temporaryStoragePaths(temporaryDirectory)

  if (journal.phase === 'planned') {
    if (await directoryExistsNoSymlink(finalPaths.accountDirectory)) {
      const sourceFiles = await copyLegacyFiles(
        layout,
        temporaryPaths,
        createUuid,
        options.afterCopyChunk
      )
      if (!(await verifyFiles(finalPaths, sourceFiles))) {
        return legacyFallback(layout, 'target-corrupt')
      }
      journal = { ...journal, phase: 'renamed', files: sourceFiles }
      await writeJournal(layout.migrationJournalPath, journal, createUuid)
    } else {
      const files = await copyLegacyFiles(
        layout,
        temporaryPaths,
        createUuid,
        options.afterCopyChunk
      )
      await options.failAfter?.('file-bytes-copied')
      journal = { ...journal, phase: 'copied', files }
      await writeJournal(layout.migrationJournalPath, journal, createUuid)
      await options.failAfter?.('files-copied')
    }
  }

  if (journal.phase === 'copied') {
    if (!journal.files) throw new Error('INVALID_MIGRATION_JOURNAL')
    if (await directoryExistsNoSymlink(finalPaths.accountDirectory)) {
      if (!(await verifyFiles(finalPaths, journal.files))) {
        return legacyFallback(layout, 'target-corrupt')
      }
    } else {
      if (!(await verifyFiles(temporaryPaths, journal.files))) {
        return legacyFallback(layout, 'target-corrupt')
      }
      await rename(temporaryDirectory, finalPaths.accountDirectory)
      await syncDirectory(layout.accountsDirectory)
      await options.failAfter?.('account-directory-renamed')
    }
    journal = { ...journal, phase: 'renamed' }
    await writeJournal(layout.migrationJournalPath, journal, createUuid)
    await options.failAfter?.('account-renamed')
  }

  if (journal.phase === 'renamed') {
    if (!journal.files) throw new Error('INVALID_MIGRATION_JOURNAL')
    if (!(await verifyFiles(finalPaths, journal.files))) {
      return legacyFallback(
        layout,
        (await directoryExistsNoSymlink(finalPaths.accountDirectory))
          ? 'target-corrupt'
          : 'target-missing'
      )
    }
    registry = createInitialAccountRegistry(journal.accountId)
    await registryStore.save(registry, null)
    await options.failAfter?.('registry-committed')
    journal = { ...journal, phase: 'committed' }
    await writeJournal(layout.migrationJournalPath, journal, createUuid)
    await options.failAfter?.('journal-committed')
  }

  if (journal.phase !== 'committed' || !journal.files) {
    throw new Error('INVALID_MIGRATION_JOURNAL')
  }
  registry = await registryStore.load()
  if (!registry || registry.activeAccountId !== journal.accountId) {
    return legacyFallback(layout, 'registry-unavailable')
  }
  if (!(await verifyFiles(finalPaths, journal.files))) {
    return legacyFallback(layout, 'target-corrupt')
  }
  return { kind: 'account', accountId: journal.accountId, accountPaths: finalPaths, registry }
}
