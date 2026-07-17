import { randomUUID } from 'node:crypto'
import { constants, type Stats } from 'node:fs'
import { link, lstat, open, rename, rm, unlink } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import {
  assertAccountId,
  createAccountId,
  createAccountPathLayout,
  ensurePrivateDirectory,
  openNoFollow,
  syncDirectory,
  type AccountPathLayout
} from './account-paths'
import { parseAccountRegistry, type AccountRegistry } from './account-registry'

const MAX_JOURNAL_BYTES = 512

type PlainRecord = Record<string, unknown>

export interface AccountRemovalJournalEntry {
  readonly accountId: string
  readonly deletionId: string
  readonly expectedRevision: number
}

export interface AccountRemovalRecoveryCallbacks {
  /** Must read the authoritative primary registry without falling back to an older backup. */
  readonly loadAuthoritativeRegistry: () => Promise<AccountRegistry | null>
  /** Must durably checkpoint this authoritative registry to its recovery backup. */
  readonly checkpointRegistry: (registry: AccountRegistry) => Promise<void>
}

export interface AccountRemovalJournalOptions {
  readonly createUuid?: () => string
  readonly syncDirectory?: (path: string) => Promise<void>
}

export type AccountRemovalRecoveryResult = 'none' | 'preserved' | 'deleted'

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

export function parseAccountRemovalJournal(value: unknown): AccountRemovalJournalEntry {
  if (!plainRecord(value)) throw new Error('INVALID_ACCOUNT_REMOVAL_JOURNAL')
  const keys = Object.keys(value)
  if (
    keys.length !== 3 ||
    !Object.hasOwn(value, 'accountId') ||
    !Object.hasOwn(value, 'deletionId') ||
    !Object.hasOwn(value, 'expectedRevision') ||
    !Number.isSafeInteger(value.expectedRevision) ||
    (value.expectedRevision as number) < 1
  ) {
    throw new Error('INVALID_ACCOUNT_REMOVAL_JOURNAL')
  }
  try {
    assertAccountId(value.accountId)
    assertAccountId(value.deletionId)
  } catch {
    throw new Error('INVALID_ACCOUNT_REMOVAL_JOURNAL')
  }
  return {
    accountId: value.accountId,
    deletionId: value.deletionId,
    expectedRevision: value.expectedRevision as number
  }
}

function serializeJournal(entry: AccountRemovalJournalEntry): string {
  return `${JSON.stringify(parseAccountRemovalJournal(entry))}\n`
}

async function createPrivateJournal(
  path: string,
  contents: string,
  createUuid: () => string,
  syncDirectoryEntry: (path: string) => Promise<void>
): Promise<void> {
  const directory = dirname(path)
  const temporaryPath = join(directory, `.account-removal-${createAccountId(createUuid)}.tmp`)
  let handle: Awaited<ReturnType<typeof open>> | undefined
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
    // Publishing with link is atomic and, unlike rename, cannot replace another prepared journal.
    await link(temporaryPath, path)
    await syncDirectoryEntry(directory)
  } finally {
    await handle?.close().catch(() => undefined)
    await unlink(temporaryPath).then(
      () => syncDirectoryEntry(directory),
      () => undefined
    )
  }
}

async function pathInfo(path: string): Promise<Stats | null> {
  try {
    return await lstat(path)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw error
  }
}

function removableNode(info: Stats): boolean {
  return info.isDirectory() || info.isFile() || info.isSymbolicLink()
}

function sameNode(left: Stats | null, right: Stats | null): boolean {
  if (!left || !right) return left === right
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode
}

function sameEntry(left: AccountRemovalJournalEntry, right: AccountRemovalJournalEntry): boolean {
  return (
    left.accountId === right.accountId &&
    left.deletionId === right.deletionId &&
    left.expectedRevision === right.expectedRevision
  )
}

export class AccountRemovalJournal {
  readonly paths: AccountPathLayout
  private readonly createUuid: () => string
  private readonly syncDirectoryEntry: (path: string) => Promise<void>

  constructor(userDataDirectory: string, options: AccountRemovalJournalOptions = {}) {
    this.paths = createAccountPathLayout(userDataDirectory)
    this.createUuid = options.createUuid ?? randomUUID
    this.syncDirectoryEntry = options.syncDirectory ?? syncDirectory
  }

  async prepare(accountId: string, expectedRevision: number): Promise<AccountRemovalJournalEntry> {
    assertAccountId(accountId)
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1) {
      throw new Error('INVALID_ACCOUNT_REMOVAL_REVISION')
    }
    await ensurePrivateDirectory(this.paths.accountsDirectory)
    const existing = await this.read()
    if (existing) throw new Error('ACCOUNT_REMOVAL_ALREADY_PREPARED')
    const entry = parseAccountRemovalJournal({
      accountId,
      deletionId: createAccountId(this.createUuid),
      expectedRevision
    })
    await createPrivateJournal(
      this.paths.removalJournalPath,
      serializeJournal(entry),
      this.createUuid,
      this.syncDirectoryEntry
    )
    return entry
  }

  async clear(): Promise<void> {
    await this.assertAccountsDirectory(true)
    const entry = await this.read()
    if (entry) await this.clearEntry(entry)
  }

  async finish(callbacks: AccountRemovalRecoveryCallbacks): Promise<AccountRemovalRecoveryResult> {
    return this.recover(callbacks)
  }

  async recover(callbacks: AccountRemovalRecoveryCallbacks): Promise<AccountRemovalRecoveryResult> {
    const accountsDirectoryInfo = await this.assertAccountsDirectory(true)
    const entry = await this.read()
    if (!entry) return 'none'
    if (!accountsDirectoryInfo) throw new Error('UNSAFE_ACCOUNT_REMOVAL_DIRECTORY')

    let registry: AccountRegistry
    try {
      const loaded = await callbacks.loadAuthoritativeRegistry()
      if (!loaded) throw new Error('ACCOUNT_REGISTRY_UNAVAILABLE')
      registry = parseAccountRegistry(loaded)
    } catch (error) {
      throw new AggregateError([error], 'ACCOUNT_REMOVAL_REGISTRY_UNAVAILABLE')
    }

    const source = this.paths.account(entry.accountId).accountDirectory
    const tombstone = this.paths.accountRemovalTombstone(entry.accountId, entry.deletionId)
    const [sourceInfo, tombstoneInfo] = await Promise.all([pathInfo(source), pathInfo(tombstone)])
    if (sourceInfo && tombstoneInfo) throw new Error('ACCOUNT_REMOVAL_PATH_COLLISION')

    const accountStillRegistered = registry.accounts.some(({ id }) => id === entry.accountId)
    if (accountStillRegistered) {
      if (!sourceInfo?.isDirectory() || sourceInfo.isSymbolicLink() || tombstoneInfo) {
        throw new Error('ACCOUNT_REMOVAL_SOURCE_NOT_INTACT')
      }
      await this.assertAccountsDirectoryUnchanged(accountsDirectoryInfo)
      await this.clearEntry(entry)
      return 'preserved'
    }

    if (registry.revision <= entry.expectedRevision) {
      throw new Error('ACCOUNT_REMOVAL_REGISTRY_REVISION_NOT_COMMITTED')
    }
    if (
      (sourceInfo && !removableNode(sourceInfo)) ||
      (tombstoneInfo && !removableNode(tombstoneInfo))
    ) {
      throw new Error('UNSAFE_ACCOUNT_REMOVAL_SOURCE')
    }

    // The primary registry is the deletion commit point. Its current value must be recoverable
    // before the account bytes are renamed or removed.
    await callbacks.checkpointRegistry(registry)
    await this.assertAccountsDirectoryUnchanged(accountsDirectoryInfo)

    const [checkedSourceInfo, checkedTombstoneInfo] = await Promise.all([
      pathInfo(source),
      pathInfo(tombstone)
    ])
    if (checkedSourceInfo && checkedTombstoneInfo) {
      throw new Error('ACCOUNT_REMOVAL_PATH_COLLISION')
    }
    if (
      !sameNode(sourceInfo, checkedSourceInfo) ||
      !sameNode(tombstoneInfo, checkedTombstoneInfo)
    ) {
      throw new Error('ACCOUNT_REMOVAL_PATH_CHANGED')
    }

    if (sourceInfo) {
      await this.assertAccountsDirectoryUnchanged(accountsDirectoryInfo)
      await rename(source, tombstone)
      await this.syncDirectoryEntry(this.paths.accountsDirectory)
      await this.assertAccountsDirectoryUnchanged(accountsDirectoryInfo)
      const publishedTombstoneInfo = await pathInfo(tombstone)
      if (!sameNode(checkedSourceInfo, publishedTombstoneInfo)) {
        throw new Error('ACCOUNT_REMOVAL_PATH_CHANGED')
      }
    }

    const renamedInfo = sourceInfo ?? tombstoneInfo
    await this.assertAccountsDirectoryUnchanged(accountsDirectoryInfo)
    if (renamedInfo?.isDirectory() && !renamedInfo.isSymbolicLink()) {
      await rm(tombstone, { recursive: true })
    } else if (renamedInfo) {
      await unlink(tombstone)
    }
    if (renamedInfo) await this.syncDirectoryEntry(this.paths.accountsDirectory)
    await this.assertAccountsDirectoryUnchanged(accountsDirectoryInfo)
    await this.clearEntry(entry)
    return 'deleted'
  }

  private async assertAccountsDirectory(allowMissing: boolean): Promise<Stats | null> {
    const info = await pathInfo(this.paths.accountsDirectory)
    if (!info) {
      if (allowMissing) return null
      throw new Error('UNSAFE_ACCOUNT_REMOVAL_DIRECTORY')
    }
    if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o077) !== 0) {
      throw new Error('UNSAFE_ACCOUNT_REMOVAL_DIRECTORY')
    }
    let handle: Awaited<ReturnType<typeof openNoFollow>> | undefined
    try {
      // openNoFollow accepts regular files only, so directories require their own checked handle.
      handle = await open(
        this.paths.accountsDirectory,
        constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | (constants.O_NOFOLLOW ?? 0)
      )
      const openedInfo = await handle.stat()
      if (!openedInfo.isDirectory() || !sameNode(info, openedInfo)) {
        throw new Error('UNSAFE_ACCOUNT_REMOVAL_DIRECTORY')
      }
      return openedInfo
    } finally {
      await handle?.close().catch(() => undefined)
    }
  }

  private async assertAccountsDirectoryUnchanged(expected: Stats): Promise<void> {
    const current = await this.assertAccountsDirectory(false)
    if (!current || !sameNode(expected, current)) {
      throw new Error('ACCOUNT_REMOVAL_PATH_CHANGED')
    }
  }

  private async read(): Promise<AccountRemovalJournalEntry | null> {
    let handle: Awaited<ReturnType<typeof openNoFollow>> | undefined
    try {
      handle = await openNoFollow(this.paths.removalJournalPath, constants.O_RDONLY)
      const info = await handle.stat()
      if (info.size < 1 || info.size > MAX_JOURNAL_BYTES || (info.mode & 0o077) !== 0) {
        throw new Error('INVALID_ACCOUNT_REMOVAL_JOURNAL')
      }
      const contents = await handle.readFile()
      return parseAccountRemovalJournal(JSON.parse(contents.toString('utf8')) as unknown)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
      throw error
    } finally {
      await handle?.close().catch(() => undefined)
    }
  }

  private async clearEntry(expected: AccountRemovalJournalEntry): Promise<void> {
    const current = await this.read()
    if (!current || !sameEntry(current, expected))
      throw new Error('ACCOUNT_REMOVAL_JOURNAL_CHANGED')
    await unlink(this.paths.removalJournalPath)
    await this.syncDirectoryEntry(dirname(this.paths.removalJournalPath))
  }
}

export async function completeCommittedAccountRemoval(
  journal: AccountRemovalJournal,
  callbacks: AccountRemovalRecoveryCallbacks
): Promise<AccountRemovalRecoveryResult> {
  return journal.finish(callbacks)
}
