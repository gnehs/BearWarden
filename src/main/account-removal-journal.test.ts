import { lstat, mkdir, readFile, rename, stat, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import {
  AccountRemovalJournal,
  parseAccountRemovalJournal,
  type AccountRemovalRecoveryCallbacks
} from './account-removal-journal'
import { createAccountPathLayout, ensurePrivateDirectory } from './account-paths'
import { type AccountRegistry } from './account-registry'

const ACCOUNT_ID = '11111111-1111-4111-8111-111111111111'
const OTHER_ACCOUNT_ID = '22222222-2222-4222-8222-222222222222'
const DELETION_ID = '33333333-3333-4333-8333-333333333333'
const TEMP_ID = '44444444-4444-4444-8444-444444444444'

function registry(revision: number, accountIds: readonly string[]): AccountRegistry {
  return {
    format: 'bearwarden-account-registry',
    version: 1,
    revision,
    activeAccountId: accountIds[0]!,
    accounts: accountIds.map((id) => ({ id }))
  }
}

function callbacks(current: AccountRegistry): AccountRemovalRecoveryCallbacks {
  return {
    loadAuthoritativeRegistry: vi.fn(async () => current),
    checkpointRegistry: vi.fn(async () => undefined)
  }
}

async function fixture(): Promise<{
  root: string
  journal: AccountRemovalJournal
  paths: ReturnType<typeof createAccountPathLayout>
}> {
  const { mkdtemp } = await import('node:fs/promises')
  const root = await mkdtemp(join(tmpdir(), 'bearwarden-account-removal-'))
  const paths = createAccountPathLayout(root)
  const values = [DELETION_ID, TEMP_ID]
  const journal = new AccountRemovalJournal(root, {
    createUuid: () => values.shift() ?? TEMP_ID
  })
  await ensurePrivateDirectory(paths.accountsDirectory)
  return { root, journal, paths }
}

async function createSource(paths: ReturnType<typeof createAccountPathLayout>): Promise<string> {
  const source = paths.account(ACCOUNT_ID).accountDirectory
  await mkdir(source, { mode: 0o700 })
  await writeFile(join(source, 'secret.bin'), 'encrypted')
  return source
}

describe('account removal journal parser', () => {
  it('accepts only opaque UUIDs and the expected registry revision', () => {
    expect(
      parseAccountRemovalJournal({
        accountId: ACCOUNT_ID,
        deletionId: DELETION_ID,
        expectedRevision: 1
      })
    ).toEqual({ accountId: ACCOUNT_ID, deletionId: DELETION_ID, expectedRevision: 1 })
  })

  it.each([
    null,
    [],
    {},
    { accountId: '../escape', deletionId: DELETION_ID, expectedRevision: 1 },
    { accountId: ACCOUNT_ID, deletionId: 'not-a-uuid', expectedRevision: 1 },
    { accountId: ACCOUNT_ID, deletionId: DELETION_ID, expectedRevision: 0 },
    { accountId: ACCOUNT_ID, deletionId: DELETION_ID, expectedRevision: 1.5 },
    { accountId: ACCOUNT_ID, deletionId: DELETION_ID, expectedRevision: 1, path: '/private' },
    { accountId: ACCOUNT_ID, deletionId: DELETION_ID, expectedRevision: 1, timestamp: 1 }
  ])('rejects malformed or expanded input %#', (value) => {
    expect(() => parseAccountRemovalJournal(value)).toThrow('INVALID_ACCOUNT_REMOVAL_JOURNAL')
  })
})

describe('AccountRemovalJournal', () => {
  it('atomically persists a private, minimal journal', async () => {
    const { journal, paths } = await fixture()
    await journal.prepare(ACCOUNT_ID, 1)

    const info = await stat(paths.removalJournalPath)
    if (process.platform !== 'win32') expect(info.mode & 0o777).toBe(0o600)
    const stored = JSON.parse(await readFile(paths.removalJournalPath, 'utf8')) as unknown
    expect(stored).toEqual({
      accountId: ACCOUNT_ID,
      deletionId: DELETION_ID,
      expectedRevision: 1
    })
    expect(Object.keys(stored as object).sort()).toEqual([
      'accountId',
      'deletionId',
      'expectedRevision'
    ])
  })

  it('atomically refuses to replace a concurrently prepared journal', async () => {
    const { root, paths } = await fixture()
    const firstValues = [DELETION_ID, TEMP_ID]
    const secondDeletionId = '55555555-5555-4555-8555-555555555555'
    const secondTempId = '66666666-6666-4666-8666-666666666666'
    const secondValues = [secondDeletionId, secondTempId]
    const first = new AccountRemovalJournal(root, {
      createUuid: () => firstValues.shift() ?? TEMP_ID
    })
    const second = new AccountRemovalJournal(root, {
      createUuid: () => secondValues.shift() ?? secondTempId
    })

    const results = await Promise.allSettled([
      first.prepare(ACCOUNT_ID, 1),
      second.prepare(ACCOUNT_ID, 1)
    ])
    expect(results.filter(({ status }) => status === 'fulfilled')).toHaveLength(1)
    expect(results.filter(({ status }) => status === 'rejected')).toHaveLength(1)
    const stored = JSON.parse(await readFile(paths.removalJournalPath, 'utf8')) as {
      deletionId: string
    }
    expect([DELETION_ID, secondDeletionId]).toContain(stored.deletionId)
  })

  it('preserves an intact source and clears a precommit journal', async () => {
    const { journal, paths } = await fixture()
    const source = await createSource(paths)
    await journal.prepare(ACCOUNT_ID, 1)
    const recovery = callbacks(registry(1, [ACCOUNT_ID]))

    await expect(journal.recover(recovery)).resolves.toBe('preserved')
    await expect(stat(source)).resolves.toBeDefined()
    await expect(stat(paths.removalJournalPath)).rejects.toMatchObject({ code: 'ENOENT' })
    expect(recovery.checkpointRegistry).not.toHaveBeenCalled()
  })

  it('checkpoints the committed registry before renaming and deleting the source', async () => {
    const { journal, paths } = await fixture()
    const source = await createSource(paths)
    await journal.prepare(ACCOUNT_ID, 1)
    const committed = registry(2, [OTHER_ACCOUNT_ID])
    const checkpointRegistry = vi.fn(async () => {
      await expect(lstat(source)).resolves.toBeDefined()
    })

    await expect(
      journal.finish({
        loadAuthoritativeRegistry: async () => committed,
        checkpointRegistry
      })
    ).resolves.toBe('deleted')
    expect(checkpointRegistry).toHaveBeenCalledWith(committed)
    await expect(lstat(source)).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(
      lstat(paths.accountRemovalTombstone(ACCOUNT_ID, DELETION_ID))
    ).rejects.toMatchObject({
      code: 'ENOENT'
    })
  })

  it('resumes deletion from an already-renamed tombstone', async () => {
    const { journal, paths } = await fixture()
    const source = await createSource(paths)
    await journal.prepare(ACCOUNT_ID, 1)
    const tombstone = paths.accountRemovalTombstone(ACCOUNT_ID, DELETION_ID)
    await rename(source, tombstone)

    await expect(journal.recover(callbacks(registry(2, [OTHER_ACCOUNT_ID])))).resolves.toBe(
      'deleted'
    )
    await expect(lstat(tombstone)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('unlinks a symlink source without touching its target', async () => {
    const { root, journal, paths } = await fixture()
    const outside = join(root, 'outside')
    await mkdir(outside)
    await writeFile(join(outside, 'keep.txt'), 'keep')
    const source = paths.account(ACCOUNT_ID).accountDirectory
    await symlink(outside, source)
    await journal.prepare(ACCOUNT_ID, 1)

    await expect(journal.recover(callbacks(registry(2, [OTHER_ACCOUNT_ID])))).resolves.toBe(
      'deleted'
    )
    await expect(lstat(source)).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(readFile(join(outside, 'keep.txt'), 'utf8')).resolves.toBe('keep')
  })

  it('unlinks a regular-file source', async () => {
    const { journal, paths } = await fixture()
    const source = paths.account(ACCOUNT_ID).accountDirectory
    await writeFile(source, 'opaque account bytes', { mode: 0o600 })
    await journal.prepare(ACCOUNT_ID, 1)

    await expect(journal.recover(callbacks(registry(2, [OTHER_ACCOUNT_ID])))).resolves.toBe(
      'deleted'
    )
    await expect(lstat(source)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('retains source and journal when registry checkpointing fails', async () => {
    const { journal, paths } = await fixture()
    const source = await createSource(paths)
    await journal.prepare(ACCOUNT_ID, 1)

    await expect(
      journal.recover({
        loadAuthoritativeRegistry: async () => registry(2, [OTHER_ACCOUNT_ID]),
        checkpointRegistry: async () => {
          throw new Error('disk full')
        }
      })
    ).rejects.toThrow('disk full')
    await expect(lstat(source)).resolves.toBeDefined()
    await expect(lstat(paths.removalJournalPath)).resolves.toBeDefined()
  })

  it('fails closed on a source/tombstone collision', async () => {
    const { journal, paths } = await fixture()
    const source = await createSource(paths)
    await journal.prepare(ACCOUNT_ID, 1)
    const tombstone = paths.accountRemovalTombstone(ACCOUNT_ID, DELETION_ID)
    await mkdir(tombstone)

    await expect(journal.recover(callbacks(registry(2, [OTHER_ACCOUNT_ID])))).rejects.toThrow(
      'ACCOUNT_REMOVAL_PATH_COLLISION'
    )
    await expect(lstat(source)).resolves.toBeDefined()
    await expect(lstat(tombstone)).resolves.toBeDefined()
    await expect(lstat(paths.removalJournalPath)).resolves.toBeDefined()
  })

  it('fails closed on malformed and oversized journals without loading the registry', async () => {
    const { journal, paths } = await fixture()
    await writeFile(paths.removalJournalPath, '{bad json', { mode: 0o600 })
    const loadAuthoritativeRegistry = vi.fn(async () => registry(2, [OTHER_ACCOUNT_ID]))

    await expect(
      journal.recover({ loadAuthoritativeRegistry, checkpointRegistry: async () => undefined })
    ).rejects.toBeDefined()
    expect(loadAuthoritativeRegistry).not.toHaveBeenCalled()

    await writeFile(paths.removalJournalPath, 'x'.repeat(513), { mode: 0o600 })
    await expect(
      journal.recover({ loadAuthoritativeRegistry, checkpointRegistry: async () => undefined })
    ).rejects.toThrow('INVALID_ACCOUNT_REMOVAL_JOURNAL')
  })

  it('fails closed when the authoritative registry is unavailable', async () => {
    const { journal, paths } = await fixture()
    const source = await createSource(paths)
    await journal.prepare(ACCOUNT_ID, 1)

    await expect(
      journal.recover({
        loadAuthoritativeRegistry: async () => null,
        checkpointRegistry: async () => undefined
      })
    ).rejects.toThrow('ACCOUNT_REMOVAL_REGISTRY_UNAVAILABLE')
    await expect(lstat(source)).resolves.toBeDefined()
    await expect(lstat(paths.removalJournalPath)).resolves.toBeDefined()
  })

  it('uses no-follow journal reads and rejects an unsafe accounts directory', async () => {
    const { root, journal, paths } = await fixture()
    const target = join(root, 'outside-journal.json')
    await writeFile(
      target,
      JSON.stringify({ accountId: ACCOUNT_ID, deletionId: DELETION_ID, expectedRevision: 1 })
    )
    await symlink(target, paths.removalJournalPath)
    await expect(journal.recover(callbacks(registry(1, [ACCOUNT_ID])))).rejects.toBeDefined()
    await expect(readFile(target, 'utf8')).resolves.toContain(ACCOUNT_ID)

    const unsafeRoot = join(root, 'unsafe-root')
    const outside = join(root, 'outside-accounts')
    await mkdir(unsafeRoot)
    await mkdir(outside)
    await symlink(outside, join(unsafeRoot, 'accounts'))
    const unsafe = new AccountRemovalJournal(unsafeRoot)
    await expect(unsafe.recover(callbacks(registry(1, [ACCOUNT_ID])))).rejects.toThrow(
      'UNSAFE_ACCOUNT_REMOVAL_DIRECTORY'
    )
  })
})
