import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  ACCOUNT_REGISTRY_MAX_ACCOUNTS,
  AccountRegistryStore,
  createInitialAccountRegistry,
  parseAccountRegistry,
  type AccountRegistry
} from './account-registry'

const IDS = [
  '11111111-1111-4111-8111-111111111111',
  '22222222-2222-4222-8222-222222222222',
  '33333333-3333-4333-8333-333333333333',
  '44444444-4444-4444-8444-444444444444',
  '55555555-5555-4555-8555-555555555555',
  '66666666-6666-4666-8666-666666666666'
]

let uuidCounter = 0
function testUuid(): string {
  uuidCounter += 1
  return `aaaaaaaa-aaaa-4aaa-8aaa-${String(uuidCounter).padStart(12, '0')}`
}

function registry(revision = 1, count = 1): AccountRegistry {
  return {
    format: 'bearwarden-account-registry',
    version: 1,
    revision,
    activeAccountId: IDS[0]!,
    accounts: IDS.slice(0, count).map((id, index) => ({
      id,
      identityHash: String(index + 1).repeat(64)
    }))
  }
}

describe('account registry parser', () => {
  it('accepts no more than five opaque accounts and no display PII', () => {
    expect(ACCOUNT_REGISTRY_MAX_ACCOUNTS).toBe(5)
    expect(parseAccountRegistry(registry(1, 5)).accounts).toHaveLength(5)
    expect(() => parseAccountRegistry(registry(1, 6))).toThrow('INVALID_ACCOUNT_REGISTRY')
    expect(() =>
      parseAccountRegistry({
        ...registry(),
        email: 'private@example.invalid'
      })
    ).toThrow('INVALID_ACCOUNT_REGISTRY')
    expect(() =>
      parseAccountRegistry({
        ...registry(),
        accounts: [{ id: IDS[0], serverUrl: 'https://private.invalid' }]
      })
    ).toThrow('INVALID_ACCOUNT_REGISTRY')
  })

  it('rejects duplicate account IDs and duplicate identity hashes', () => {
    expect(() =>
      parseAccountRegistry({ ...registry(), accounts: [{ id: IDS[0] }, { id: IDS[0] }] })
    ).toThrow('INVALID_ACCOUNT_REGISTRY')
    expect(() =>
      parseAccountRegistry({
        ...registry(),
        accounts: [
          { id: IDS[0], identityHash: 'a'.repeat(64) },
          { id: IDS[1], identityHash: 'a'.repeat(64) }
        ]
      })
    ).toThrow('INVALID_ACCOUNT_REGISTRY')
  })

  it('rejects malformed identity hashes, inactive IDs, prototypes and sparse arrays', () => {
    expect(() =>
      parseAccountRegistry({
        ...registry(),
        accounts: [{ id: IDS[0], identityHash: 'A'.repeat(64) }]
      })
    ).toThrow('INVALID_ACCOUNT_REGISTRY')
    expect(() => parseAccountRegistry({ ...registry(), activeAccountId: IDS[1] })).toThrow(
      'INVALID_ACCOUNT_REGISTRY'
    )
    expect(() => parseAccountRegistry(Object.create({ ...registry() }))).toThrow(
      'INVALID_ACCOUNT_REGISTRY'
    )
    const sparse = new Array(1)
    expect(() => parseAccountRegistry({ ...registry(), accounts: sparse })).toThrow(
      'INVALID_ACCOUNT_REGISTRY'
    )
  })

  it('rejects symbols and accessor properties without invoking the accessor', () => {
    let invoked = false
    const accessor = { ...registry() } as Record<string | symbol, unknown>
    Object.defineProperty(accessor, 'revision', {
      enumerable: true,
      get() {
        invoked = true
        return 1
      }
    })
    expect(() => parseAccountRegistry(accessor)).toThrow('INVALID_ACCOUNT_REGISTRY')
    expect(invoked).toBe(false)

    const symbol = { ...registry(), [Symbol('hidden')]: 'value' }
    expect(() => parseAccountRegistry(symbol)).toThrow('INVALID_ACCOUNT_REGISTRY')
  })
})

describe('AccountRegistryStore', () => {
  it('atomically writes owner-only primary and backup files', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-registry-'))
    const store = new AccountRegistryStore(root, { createUuid: testUuid })
    const initial = createInitialAccountRegistry(IDS[0]!)
    await store.save(initial, null)

    expect(await store.load()).toEqual(initial)
    expect(JSON.parse(await readFile(store.paths.registryPath, 'utf8'))).toEqual(initial)
    expect(JSON.parse(await readFile(store.paths.registryBackupPath, 'utf8'))).toEqual(initial)
    if (process.platform !== 'win32') {
      expect((await lstat(store.paths.registryPath)).mode & 0o777).toBe(0o600)
      expect((await lstat(store.paths.registryBackupPath)).mode & 0o777).toBe(0o600)
    }
  })

  it('requires compare-and-swap and a strictly monotonic revision', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-registry-'))
    const store = new AccountRegistryStore(root, { createUuid: testUuid })
    await store.save(registry(), null)
    await expect(store.save(registry(2), null)).rejects.toThrow('ACCOUNT_REGISTRY_CONFLICT')
    await expect(store.save(registry(3), 1)).rejects.toThrow(
      'ACCOUNT_REGISTRY_REVISION_NOT_MONOTONIC'
    )
    await store.save(registry(2), 1)
    expect((await store.load())?.revision).toBe(2)
  })

  it('does not commit initial creation before the primary rename', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-registry-'))
    const store = new AccountRegistryStore(root, {
      createUuid: testUuid,
      afterWriteStage: (stage) => {
        if (stage === 'before-primary') throw new Error('INJECTED_CRASH')
      }
    })
    await expect(store.save(registry(), null)).rejects.toThrow('INJECTED_CRASH')
    expect(await store.load()).toBeNull()
  })

  it.each(['primary', 'backup'] as const)(
    'treats initial creation as committed after the primary rename at %s',
    async (failureStage) => {
      const root = await mkdtemp(join(tmpdir(), 'bearwarden-registry-'))
      const store = new AccountRegistryStore(root, {
        createUuid: testUuid,
        afterWriteStage: (stage) => {
          if (stage === failureStage) throw new Error('INJECTED_CRASH')
        }
      })
      await expect(store.save(registry(), null)).rejects.toThrow('INJECTED_CRASH')
      expect(
        (await new AccountRegistryStore(root, { createUuid: testUuid }).load())?.revision
      ).toBe(1)
      expect(JSON.parse(await readFile(store.paths.registryBackupPath, 'utf8'))).toEqual(registry())
    }
  )

  it('keeps the old revision when an update crashes before primary commit', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-registry-'))
    const initialStore = new AccountRegistryStore(root, { createUuid: testUuid })
    await initialStore.save(registry(), null)
    const crashingStore = new AccountRegistryStore(root, {
      createUuid: testUuid,
      afterWriteStage: (stage) => {
        if (stage === 'before-primary') throw new Error('INJECTED_CRASH')
      }
    })
    await expect(crashingStore.save(registry(2), 1)).rejects.toThrow('INJECTED_CRASH')
    expect((await initialStore.load())?.revision).toBe(1)
  })

  it('loads the new revision when an update crashes after primary commit', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-registry-'))
    const initialStore = new AccountRegistryStore(root, { createUuid: testUuid })
    await initialStore.save(registry(), null)
    const crashingStore = new AccountRegistryStore(root, {
      createUuid: testUuid,
      afterWriteStage: (stage) => {
        if (stage === 'primary') throw new Error('INJECTED_CRASH')
      }
    })
    await expect(crashingStore.save(registry(2), 1)).rejects.toThrow('INJECTED_CRASH')
    expect((await initialStore.load())?.revision).toBe(2)
    expect(JSON.parse(await readFile(initialStore.paths.registryBackupPath, 'utf8')).revision).toBe(
      1
    )
  })

  it('checkpoints an exact primary revision to backup before destructive cleanup', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-registry-checkpoint-'))
    const store = new AccountRegistryStore(root, { createUuid: testUuid })
    await store.save(registry(), null)
    const updated = registry(2)
    await store.save(updated, 1)

    expect(JSON.parse(await readFile(store.paths.registryBackupPath, 'utf8')).revision).toBe(1)
    await expect(store.loadPrimary()).resolves.toEqual(updated)
    await expect(store.checkpoint(updated, 2)).resolves.toEqual(updated)
    expect(JSON.parse(await readFile(store.paths.registryBackupPath, 'utf8'))).toEqual(updated)
  })

  it('refuses to checkpoint a missing, corrupt, stale or mismatched primary', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-registry-checkpoint-reject-'))
    const store = new AccountRegistryStore(root, { createUuid: testUuid })
    await expect(store.loadPrimary()).resolves.toBeNull()
    await store.save(registry(), null)
    await expect(store.checkpoint(registry(2), 2)).rejects.toThrow(
      'ACCOUNT_REGISTRY_CHECKPOINT_CONFLICT'
    )
    await expect(store.checkpoint(registry(), 2)).rejects.toThrow(
      'ACCOUNT_REGISTRY_CHECKPOINT_CONFLICT'
    )
    await writeFile(store.paths.registryPath, '{broken')
    await expect(store.loadPrimary()).rejects.toThrow()
    await expect(store.checkpoint(registry(), 1)).rejects.toThrow()
    expect((await store.load())?.revision).toBe(1)
  })

  it('recovers a corrupt primary from a valid backup and ignores a corrupt backup', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-registry-'))
    const store = new AccountRegistryStore(root, { createUuid: testUuid })
    await store.save(registry(), null)
    await writeFile(store.paths.registryPath, '{broken')
    expect((await store.load())?.revision).toBe(1)

    await writeFile(store.paths.registryPath, `${JSON.stringify(registry())}\n`)
    await chmod(store.paths.registryPath, 0o600)
    await writeFile(store.paths.registryBackupPath, '{broken')
    expect((await store.load())?.revision).toBe(1)
  })

  it('keeps a valid committed primary available when backup repair fails', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-registry-'))
    const store = new AccountRegistryStore(root, { createUuid: testUuid })
    await store.save(registry(), null)
    await rm(store.paths.registryBackupPath)
    await mkdir(store.paths.registryBackupPath)

    expect((await store.load())?.revision).toBe(1)
  })

  it('fails closed when both registry copies are corrupt or a registry is a symlink', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-registry-'))
    const store = new AccountRegistryStore(root, { createUuid: testUuid })
    await store.save(registry(), null)
    await writeFile(store.paths.registryPath, '{broken')
    await writeFile(store.paths.registryBackupPath, '{broken')
    await expect(store.load()).rejects.toThrow('ACCOUNT_REGISTRY_UNRECOVERABLE')

    const linkedRoot = await mkdtemp(join(tmpdir(), 'bearwarden-registry-link-'))
    const linkedStore = new AccountRegistryStore(linkedRoot, { createUuid: testUuid })
    await symlink(store.paths.registryPath, linkedStore.paths.registryPath).catch(async () => {
      // The accounts parent does not exist yet.
      const { mkdir } = await import('node:fs/promises')
      await mkdir(linkedStore.paths.accountsDirectory)
      await symlink(store.paths.registryPath, linkedStore.paths.registryPath)
    })
    await expect(linkedStore.load()).rejects.toThrow()
  })
})
