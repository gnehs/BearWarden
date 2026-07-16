import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  stat,
  symlink,
  writeFile
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { createAccountPathLayout } from './account-paths'
import { AccountRegistryStore } from './account-registry'
import {
  migrateLegacyAccountStorage,
  type AccountStorageMigrationOptions
} from './account-storage-migration'

function uuidGenerator(): () => string {
  let counter = 0
  return () => {
    counter += 1
    return `aaaaaaaa-aaaa-4aaa-8aaa-${String(counter).padStart(12, '0')}`
  }
}

async function legacyFixture(
  options: {
    settings?: Buffer
    touchId?: Buffer
  } = {}
): Promise<{ root: string; vault: Buffer; settings?: Buffer; touchId?: Buffer }> {
  const root = await mkdtemp(join(tmpdir(), 'bearwarden-migration-'))
  const vaultDirectory = join(root, 'vault')
  await mkdir(vaultDirectory)
  const vault = Buffer.from([0, 255, 1, 2, 3, 128, 64])
  await writeFile(join(vaultDirectory, 'vault.json'), vault)
  if (options.settings) await writeFile(join(root, 'settings.json'), options.settings)
  if (options.touchId) await writeFile(join(vaultDirectory, 'touch-id.bin'), options.touchId)
  return { root, vault, ...options }
}

describe('legacy account storage migration', () => {
  it('copies opaque vault, settings and Touch ID bytes and never deletes legacy data', async () => {
    const fixture = await legacyFixture({
      settings: Buffer.from('{"opaque":"settings"}\n'),
      touchId: Buffer.from([9, 8, 7, 0, 255])
    })
    const result = await migrateLegacyAccountStorage(fixture.root, {
      createUuid: uuidGenerator()
    })
    expect(result.kind).toBe('account')
    if (result.kind !== 'account') return

    expect(await readFile(result.accountPaths.vaultPath)).toEqual(fixture.vault)
    expect(await readFile(result.accountPaths.settingsPath)).toEqual(fixture.settings)
    expect(await readFile(result.accountPaths.touchIdPath)).toEqual(fixture.touchId)
    expect(await readFile(join(fixture.root, 'vault', 'vault.json'))).toEqual(fixture.vault)
    expect(await readFile(join(fixture.root, 'settings.json'))).toEqual(fixture.settings)
    expect(await readFile(join(fixture.root, 'vault', 'touch-id.bin'))).toEqual(fixture.touchId)
    expect((await stat(join(fixture.root, 'account-migration.json'))).isFile()).toBe(true)
  })

  it.each([
    'journal-planned',
    'file-bytes-copied',
    'files-copied',
    'account-directory-renamed',
    'account-renamed',
    'registry-committed',
    'journal-committed'
  ] as const)('recovers after an injected crash at %s', async (failureStage) => {
    const fixture = await legacyFixture({ settings: Buffer.from('opaque') })
    const createUuid = uuidGenerator()
    const failAfter: NonNullable<AccountStorageMigrationOptions['failAfter']> = (stage) => {
      if (stage === failureStage) throw new Error(`CRASH_${stage}`)
    }

    await expect(
      migrateLegacyAccountStorage(fixture.root, { createUuid, failAfter })
    ).rejects.toThrow(`CRASH_${failureStage}`)
    const recovered = await migrateLegacyAccountStorage(fixture.root, { createUuid })
    expect(recovered.kind).toBe('account')
    if (recovered.kind === 'account') {
      expect(await readFile(recovered.accountPaths.vaultPath)).toEqual(fixture.vault)
      expect(recovered.registry.revision).toBe(1)
    }
  })

  it('does not treat a pre-primary registry crash as a migration commit', async () => {
    const fixture = await legacyFixture()
    const createUuid = uuidGenerator()
    const crashingRegistry = new AccountRegistryStore(fixture.root, {
      createUuid,
      afterWriteStage: (stage) => {
        if (stage === 'before-primary') throw new Error('CRASH_BEFORE_PRIMARY')
      }
    })
    await expect(
      migrateLegacyAccountStorage(fixture.root, {
        createUuid,
        registryStore: crashingRegistry
      })
    ).rejects.toThrow('CRASH_BEFORE_PRIMARY')
    expect(await crashingRegistry.load()).toBeNull()

    const recovered = await migrateLegacyAccountStorage(fixture.root, { createUuid })
    expect(recovered.kind).toBe('account')
  })

  it('falls back to legacy when a committed target is missing or corrupt', async () => {
    const corruptFixture = await legacyFixture()
    const corrupt = await migrateLegacyAccountStorage(corruptFixture.root, {
      createUuid: uuidGenerator()
    })
    expect(corrupt.kind).toBe('account')
    if (corrupt.kind !== 'account') return
    await writeFile(corrupt.accountPaths.vaultPath, Buffer.from('tampered'))
    const corruptRecovery = await migrateLegacyAccountStorage(corruptFixture.root)
    expect(corruptRecovery).toMatchObject({ kind: 'legacy-fallback', reason: 'target-corrupt' })

    const missingFixture = await legacyFixture()
    const missing = await migrateLegacyAccountStorage(missingFixture.root, {
      createUuid: uuidGenerator()
    })
    expect(missing.kind).toBe('account')
    if (missing.kind !== 'account') return
    await rename(
      missing.accountPaths.accountDirectory,
      `${missing.accountPaths.accountDirectory}.gone`
    )
    const missingRecovery = await migrateLegacyAccountStorage(missingFixture.root)
    expect(missingRecovery).toMatchObject({ kind: 'legacy-fallback', reason: 'target-missing' })
  })

  it('ignores unrelated orphan temporary directories', async () => {
    const fixture = await legacyFixture()
    const layout = createAccountPathLayout(fixture.root)
    await mkdir(layout.accountsDirectory)
    const orphan = layout.migrationTemporaryDirectory('99999999-9999-4999-8999-999999999999')
    await mkdir(orphan)
    await writeFile(join(orphan, 'attacker-controlled'), 'leave untouched')

    const result = await migrateLegacyAccountStorage(fixture.root, {
      createUuid: uuidGenerator()
    })
    expect(result.kind).toBe('account')
    expect(await readFile(join(orphan, 'attacker-controlled'), 'utf8')).toBe('leave untouched')
  })

  it('removes an operation-owned copy temp after an injected mid-copy failure', async () => {
    const fixture = await legacyFixture()
    const createUuid = uuidGenerator()
    let failed = false
    await expect(
      migrateLegacyAccountStorage(fixture.root, {
        createUuid,
        afterCopyChunk: () => {
          if (failed) return
          failed = true
          throw new Error('COPY_CRASH')
        }
      })
    ).rejects.toThrow('COPY_CRASH')

    const layout = createAccountPathLayout(fixture.root)
    const entries = await readdir(layout.accountsDirectory, { recursive: true })
    expect(entries.filter((entry) => entry.includes('.copy-'))).toEqual([])
    expect((await migrateLegacyAccountStorage(fixture.root, { createUuid })).kind).toBe('account')
  })

  it('fails closed for symlink legacy files, parent directories and migration targets', async () => {
    const fileLinkRoot = await mkdtemp(join(tmpdir(), 'bearwarden-migration-link-'))
    const outside = join(fileLinkRoot, 'outside-vault')
    await writeFile(outside, 'secret')
    await mkdir(join(fileLinkRoot, 'vault'))
    await symlink(outside, join(fileLinkRoot, 'vault', 'vault.json'))
    await expect(migrateLegacyAccountStorage(fileLinkRoot)).rejects.toThrow('UNSAFE_MIGRATION_FILE')

    const parentLinkRoot = await mkdtemp(join(tmpdir(), 'bearwarden-migration-parent-link-'))
    const outsideDirectory = join(parentLinkRoot, 'outside')
    await mkdir(outsideDirectory)
    await writeFile(join(outsideDirectory, 'vault.json'), 'secret')
    await symlink(outsideDirectory, join(parentLinkRoot, 'vault'))
    await expect(migrateLegacyAccountStorage(parentLinkRoot)).rejects.toThrow(
      'UNSAFE_MIGRATION_DIRECTORY'
    )

    const targetFixture = await legacyFixture()
    const createUuid = uuidGenerator()
    await expect(
      migrateLegacyAccountStorage(targetFixture.root, {
        createUuid,
        failAfter: (stage) => {
          if (stage === 'journal-planned') throw new Error('STOP')
        }
      })
    ).rejects.toThrow('STOP')
    const journal = JSON.parse(
      await readFile(join(targetFixture.root, 'account-migration.json'), 'utf8')
    ) as { migrationId: string }
    const targetLayout = createAccountPathLayout(targetFixture.root)
    const target = targetLayout.migrationTemporaryDirectory(journal.migrationId)
    const targetOutside = join(targetFixture.root, 'target-outside')
    await mkdir(targetOutside)
    await symlink(targetOutside, target)
    await expect(migrateLegacyAccountStorage(targetFixture.root, { createUuid })).rejects.toThrow(
      'UNSAFE_DIRECTORY'
    )
  })

  it('returns no-legacy instead of creating an empty vault', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-no-legacy-'))
    const result = await migrateLegacyAccountStorage(root, { createUuid: uuidGenerator() })
    expect(result).toEqual({ kind: 'no-legacy-vault' })
    const registry = new AccountRegistryStore(root)
    expect(await registry.load()).toBeNull()
  })
})
