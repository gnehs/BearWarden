import { randomUUID } from 'node:crypto'
import { constants } from 'node:fs'
import { lstat } from 'node:fs/promises'
import {
  assertAccountId,
  atomicWritePrivateFile,
  createAccountPathLayout,
  ensurePrivateDirectory,
  openNoFollow,
  type AccountPathLayout
} from './account-paths'
import { MAX_LOCAL_ACCOUNT_NAME_BYTES } from '../shared/vault-contract'

const REGISTRY_FORMAT = 'bearwarden-account-registry'
const REGISTRY_VERSION = 1
const MAX_ACCOUNTS = 5
const MAX_REGISTRY_BYTES = 64 * 1024
const IDENTITY_HASH_PATTERN = /^[0-9a-f]{64}$/u

export interface AccountRegistryEntry {
  readonly id: string
  readonly identityHash?: string
  /** Non-sensitive, user-controlled label for this device only. */
  readonly displayName?: string
}

export interface AccountRegistry {
  readonly format: typeof REGISTRY_FORMAT
  readonly version: typeof REGISTRY_VERSION
  readonly revision: number
  readonly activeAccountId: string
  readonly accounts: readonly AccountRegistryEntry[]
}

export interface AccountRegistryStoreOptions {
  readonly createUuid?: () => string
  readonly afterWriteStage?: (
    stage: 'backup' | 'before-primary' | 'primary'
  ) => void | Promise<void>
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
  const keys = Object.keys(value)
  const allowed = new Set([...required, ...optional])
  return required.every((key) => Object.hasOwn(value, key)) && keys.every((key) => allowed.has(key))
}

function safeArray(value: unknown): readonly unknown[] | null {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return null
  const descriptors = Object.getOwnPropertyDescriptors(value)
  if (
    Reflect.ownKeys(descriptors).some((key) => typeof key !== 'string') ||
    Object.keys(descriptors).some((key) => {
      if (key === 'length') return false
      const descriptor = descriptors[key]!
      return (
        !/^\d+$/u.test(key) ||
        descriptor.enumerable !== true ||
        !('value' in descriptor) ||
        descriptor.get !== undefined ||
        descriptor.set !== undefined
      )
    })
  ) {
    return null
  }
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(descriptors, String(index))) return null
  }
  return value
}

function parseDisplayName(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.trim().length === 0 ||
    Buffer.byteLength(value, 'utf8') > MAX_LOCAL_ACCOUNT_NAME_BYTES ||
    /[\0\r\n]/u.test(value)
  ) {
    throw new Error('INVALID_ACCOUNT_REGISTRY')
  }
  return value.trim()
}

export function parseAccountRegistry(value: unknown): AccountRegistry {
  if (
    !plainRecord(value) ||
    !exactKeys(value, ['format', 'version', 'revision', 'activeAccountId', 'accounts']) ||
    value.format !== REGISTRY_FORMAT ||
    value.version !== REGISTRY_VERSION ||
    !Number.isSafeInteger(value.revision) ||
    (value.revision as number) < 1
  ) {
    throw new Error('INVALID_ACCOUNT_REGISTRY')
  }

  try {
    assertAccountId(value.activeAccountId)
  } catch {
    throw new Error('INVALID_ACCOUNT_REGISTRY')
  }

  const rawAccounts = safeArray(value.accounts)
  if (!rawAccounts || rawAccounts.length < 1 || rawAccounts.length > MAX_ACCOUNTS) {
    throw new Error('INVALID_ACCOUNT_REGISTRY')
  }

  const accountIds = new Set<string>()
  const identityHashes = new Set<string>()
  const accounts = rawAccounts.map((candidate): AccountRegistryEntry => {
    if (!plainRecord(candidate) || !exactKeys(candidate, ['id'], ['identityHash', 'displayName'])) {
      throw new Error('INVALID_ACCOUNT_REGISTRY')
    }
    try {
      assertAccountId(candidate.id)
    } catch {
      throw new Error('INVALID_ACCOUNT_REGISTRY')
    }
    if (accountIds.has(candidate.id)) throw new Error('INVALID_ACCOUNT_REGISTRY')
    accountIds.add(candidate.id)

    if (candidate.identityHash !== undefined) {
      if (
        typeof candidate.identityHash !== 'string' ||
        !IDENTITY_HASH_PATTERN.test(candidate.identityHash) ||
        identityHashes.has(candidate.identityHash)
      ) {
        throw new Error('INVALID_ACCOUNT_REGISTRY')
      }
      identityHashes.add(candidate.identityHash)
      return {
        id: candidate.id,
        identityHash: candidate.identityHash,
        ...(candidate.displayName === undefined
          ? {}
          : { displayName: parseDisplayName(candidate.displayName) })
      }
    }
    return {
      id: candidate.id,
      ...(candidate.displayName === undefined
        ? {}
        : { displayName: parseDisplayName(candidate.displayName) })
    }
  })

  if (!accountIds.has(value.activeAccountId)) throw new Error('INVALID_ACCOUNT_REGISTRY')

  return {
    format: REGISTRY_FORMAT,
    version: REGISTRY_VERSION,
    revision: value.revision as number,
    activeAccountId: value.activeAccountId,
    accounts
  }
}

function serializeRegistry(registry: AccountRegistry): string {
  return `${JSON.stringify(parseAccountRegistry(registry))}\n`
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
        account.identityHash === right.accounts[index]?.identityHash &&
        account.displayName === right.accounts[index]?.displayName
    )
  )
}

async function readRegistryFile(path: string): Promise<AccountRegistry | null> {
  let handle: Awaited<ReturnType<typeof openNoFollow>> | undefined
  try {
    handle = await openNoFollow(path, constants.O_RDONLY)
    const info = await handle.stat()
    if (info.size < 1 || info.size > MAX_REGISTRY_BYTES) {
      throw new Error('INVALID_ACCOUNT_REGISTRY')
    }
    const contents = await handle.readFile()
    return parseAccountRegistry(JSON.parse(contents.toString('utf8')) as unknown)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw error
  } finally {
    await handle?.close().catch(() => undefined)
  }
}

export class AccountRegistryStore {
  readonly paths: AccountPathLayout
  private readonly createUuid: () => string
  private readonly afterWriteStage?: AccountRegistryStoreOptions['afterWriteStage']
  private operationTail: Promise<void> = Promise.resolve()

  constructor(userDataDirectory: string, options: AccountRegistryStoreOptions = {}) {
    this.paths = createAccountPathLayout(userDataDirectory)
    this.createUuid = options.createUuid ?? randomUUID
    this.afterWriteStage = options.afterWriteStage
  }

  private async requireAccountsDirectory(): Promise<boolean> {
    try {
      const accountsDirectory = await lstat(this.paths.accountsDirectory)
      if (!accountsDirectory.isDirectory() || accountsDirectory.isSymbolicLink()) {
        throw new Error('UNSAFE_ACCOUNT_REGISTRY_DIRECTORY')
      }
      return true
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false
      throw error
    }
  }

  async load(): Promise<AccountRegistry | null> {
    if (!(await this.requireAccountsDirectory())) return null
    let primaryError: unknown
    try {
      const primary = await readRegistryFile(this.paths.registryPath)
      if (primary) {
        // A valid primary is the commit point. Backup repair must not make an otherwise usable
        // account unavailable (for example when the disk becomes read-only or full).
        await this.repairInitialBackup(primary).catch(() => undefined)
        return primary
      }
    } catch (error) {
      primaryError = error
    }

    try {
      const backup = await readRegistryFile(this.paths.registryBackupPath)
      if (backup) {
        return backup
      }
    } catch (backupError) {
      throw new AggregateError(
        primaryError === undefined ? [backupError] : [primaryError, backupError],
        'ACCOUNT_REGISTRY_UNRECOVERABLE'
      )
    }

    if (primaryError !== undefined) throw primaryError
    return null
  }

  /**
   * Reads only the primary commit point. Destructive recovery must never make decisions from the
   * previous revision retained in the backup file.
   */
  async loadPrimary(): Promise<AccountRegistry | null> {
    if (!(await this.requireAccountsDirectory())) return null
    return readRegistryFile(this.paths.registryPath)
  }

  private async repairInitialBackup(primary: AccountRegistry): Promise<void> {
    let backup: AccountRegistry | null = null
    try {
      backup = await readRegistryFile(this.paths.registryBackupPath)
    } catch {
      // A valid primary is authoritative. Replace only a missing/corrupt backup, never a valid
      // older revision retained for rollback after an update.
    }
    if (backup) return
    await atomicWritePrivateFile(
      this.paths.registryBackupPath,
      serializeRegistry(primary),
      this.createUuid
    )
  }

  save(registry: AccountRegistry, expectedRevision: number | null): Promise<AccountRegistry> {
    const operation = this.operationTail.then(() => this.performSave(registry, expectedRevision))
    this.operationTail = operation.then(
      () => undefined,
      () => undefined
    )
    return operation
  }

  checkpoint(registry: AccountRegistry, expectedRevision: number): Promise<AccountRegistry> {
    const operation = this.operationTail.then(() =>
      this.performCheckpoint(registry, expectedRevision)
    )
    this.operationTail = operation.then(
      () => undefined,
      () => undefined
    )
    return operation
  }

  private async performCheckpoint(
    registry: AccountRegistry,
    expectedRevision: number
  ): Promise<AccountRegistry> {
    const expected = parseAccountRegistry(registry)
    if (expected.revision !== expectedRevision) {
      throw new Error('ACCOUNT_REGISTRY_CHECKPOINT_CONFLICT')
    }
    if (!(await this.requireAccountsDirectory())) {
      throw new Error('ACCOUNT_REGISTRY_CHECKPOINT_UNAVAILABLE')
    }
    const primary = await readRegistryFile(this.paths.registryPath)
    if (!primary || !registryEqual(primary, expected)) {
      throw new Error('ACCOUNT_REGISTRY_CHECKPOINT_CONFLICT')
    }
    await atomicWritePrivateFile(
      this.paths.registryBackupPath,
      serializeRegistry(primary),
      this.createUuid
    )
    await this.afterWriteStage?.('backup')
    return primary
  }

  private async performSave(
    registry: AccountRegistry,
    expectedRevision: number | null
  ): Promise<AccountRegistry> {
    const next = parseAccountRegistry(registry)
    await ensurePrivateDirectory(this.paths.accountsDirectory)
    const current = await this.load()
    const currentRevision = current?.revision ?? null
    if (currentRevision !== expectedRevision) throw new Error('ACCOUNT_REGISTRY_CONFLICT')
    if (next.revision !== (currentRevision ?? 0) + 1) {
      throw new Error('ACCOUNT_REGISTRY_REVISION_NOT_MONOTONIC')
    }

    if (current) {
      // For updates, the backup remains the last committed revision. A crash before the primary
      // rename therefore still loads the old primary (or its identical backup).
      await atomicWritePrivateFile(
        this.paths.registryBackupPath,
        serializeRegistry(current),
        this.createUuid
      )
      await this.afterWriteStage?.('backup')
    }
    await this.afterWriteStage?.('before-primary')
    await atomicWritePrivateFile(this.paths.registryPath, serializeRegistry(next), this.createUuid)
    await this.afterWriteStage?.('primary')
    if (!current) {
      // Initial creation has no committed state to back up. The primary rename is the sole commit
      // point; only afterwards may the same committed revision be copied to the recovery file.
      await atomicWritePrivateFile(
        this.paths.registryBackupPath,
        serializeRegistry(next),
        this.createUuid
      )
      await this.afterWriteStage?.('backup')
    }
    return next
  }
}

export function createInitialAccountRegistry(accountId: string): AccountRegistry {
  assertAccountId(accountId)
  return {
    format: REGISTRY_FORMAT,
    version: REGISTRY_VERSION,
    revision: 1,
    activeAccountId: accountId,
    accounts: [{ id: accountId }]
  }
}

export const ACCOUNT_REGISTRY_MAX_ACCOUNTS = MAX_ACCOUNTS
