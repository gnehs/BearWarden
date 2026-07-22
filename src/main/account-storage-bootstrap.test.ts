import { access, mkdir, mkdtemp, readFile, stat, unlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { createAccountPathLayout } from './account-paths'
import { AccountRegistryStore } from './account-registry'
import { bootstrapAccountStorage } from './account-storage-bootstrap'
import { AccountSwitchService } from './account-switch-service'
import {
  clearPendingInitializationMarker,
  hasPendingInitializationMarker
} from './account-storage-initialization-marker'
import { EncryptedVaultStore } from './encrypted-vault-store'

function uuidGenerator(): () => string {
  let counter = 0
  return () => {
    counter += 1
    return `aaaaaaaa-aaaa-4aaa-8aaa-${String(counter).padStart(12, '0')}`
  }
}

async function legacyFixture(): Promise<{ root: string; vault: Buffer }> {
  const root = await mkdtemp(join(tmpdir(), 'bearwarden-storage-bootstrap-'))
  const vaultDirectory = join(root, 'vault')
  const vault = Buffer.from([0, 255, 1, 2, 3, 128, 64])
  await mkdir(vaultDirectory)
  await writeFile(join(vaultDirectory, 'vault.json'), vault)
  await writeFile(join(root, 'settings.json'), '{"opaque":"settings"}\n')
  await writeFile(join(vaultDirectory, 'touch-id.bin'), Buffer.from([9, 8, 7]))
  return { root, vault }
}

describe('account storage bootstrap', () => {
  it('migrates legacy storage before exposing account-scoped service paths', async () => {
    const fixture = await legacyFixture()
    const storage = await bootstrapAccountStorage(fixture.root, { createUuid: uuidGenerator() })

    expect(storage.mode).toBe('account')
    if (storage.mode !== 'account') return
    expect(storage.activeAccountId).toBe('aaaaaaaa-aaaa-4aaa-8aaa-000000000002')
    expect(await readFile(storage.paths.vaultPath)).toEqual(fixture.vault)
    await expect(access(join(fixture.root, 'vault', 'vault.json'))).resolves.toBeUndefined()
  })

  it('keeps a migrated account active after restart', async () => {
    const fixture = await legacyFixture()
    const first = await bootstrapAccountStorage(fixture.root, { createUuid: uuidGenerator() })
    const restarted = await bootstrapAccountStorage(fixture.root)

    expect(restarted).toMatchObject({
      mode: 'account',
      activeAccountId: first.activeAccountId,
      paths: { vaultPath: first.paths.vaultPath }
    })
  })

  it('starts a newly added pending account instead of falling back to migrated legacy storage', async () => {
    const fixture = await legacyFixture()
    const createUuid = uuidGenerator()
    await bootstrapAccountStorage(fixture.root, { createUuid })
    const accountSwitchService = new AccountSwitchService(fixture.root, {
      createUuid,
      beforeActivation: () => undefined,
      afterCommitRelaunch: () => undefined
    })

    const added = await accountSwitchService.addAccount()
    expect(added.kind).toBe('relaunch-required')
    const restarted = await bootstrapAccountStorage(fixture.root)

    expect(restarted).toMatchObject({
      mode: 'account',
      activeAccountId: added.status.activeAccountId
    })
    if (restarted.mode !== 'account') return
    await expect(access(restarted.paths.vaultPath)).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(
      hasPendingInitializationMarker(restarted.paths.initializationMarkerPath)
    ).resolves.toBe(true)
  })

  it('does not roll a committed account back after its vault changes', async () => {
    const fixture = await legacyFixture()
    const storage = await bootstrapAccountStorage(fixture.root, { createUuid: uuidGenerator() })
    expect(storage.mode).toBe('account')
    if (storage.mode !== 'account') return
    await writeFile(storage.paths.vaultPath, 'legitimate post-migration write')

    await expect(bootstrapAccountStorage(fixture.root)).resolves.toMatchObject({
      mode: 'account',
      activeAccountId: storage.activeAccountId,
      paths: { vaultPath: storage.paths.vaultPath }
    })
    expect(await readFile(join(fixture.root, 'vault', 'vault.json'))).toEqual(fixture.vault)
  })

  it('creates private account storage before its registry commit without creating an empty vault', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-storage-bootstrap-fresh-'))
    const storage = await bootstrapAccountStorage(root, { createUuid: uuidGenerator() })
    expect(storage.mode).toBe('account')
    if (storage.mode !== 'account') return

    const layout = createAccountPathLayout(root)
    const registry = await new AccountRegistryStore(root).load()
    expect(registry?.activeAccountId).toBe(storage.activeAccountId)
    expect((await stat(storage.paths.accountDirectory)).isDirectory()).toBe(true)
    expect((await stat(storage.paths.vaultDirectory)).isDirectory()).toBe(true)
    await expect(access(storage.paths.vaultPath)).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(
      hasPendingInitializationMarker(storage.paths.initializationMarkerPath)
    ).resolves.toBe(true)
    expect(layout.account(registry!.activeAccountId).vaultPath).toBe(storage.paths.vaultPath)

    const restarted = await bootstrapAccountStorage(root)
    expect(restarted).toMatchObject({
      mode: 'account',
      activeAccountId: storage.activeAccountId,
      paths: { vaultPath: storage.paths.vaultPath }
    })
  })

  it('clears the pending marker after the first committed vault write', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-storage-bootstrap-first-write-'))
    const storage = await bootstrapAccountStorage(root, { createUuid: uuidGenerator() })
    expect(storage.mode).toBe('account')
    if (storage.mode !== 'account') return
    const store = new EncryptedVaultStore<{ initialized: true }>(storage.paths.vaultPath, {
      afterAtomicCommit: () =>
        clearPendingInitializationMarker(storage.paths.initializationMarkerPath)
    })

    await store.initialize('correct horse battery staple', { initialized: true })
    await expect(
      hasPendingInitializationMarker(storage.paths.initializationMarkerPath)
    ).resolves.toBe(false)
  })

  it('fails closed when an initialized vault is later deleted', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-storage-bootstrap-deleted-vault-'))
    const storage = await bootstrapAccountStorage(root, { createUuid: uuidGenerator() })
    expect(storage.mode).toBe('account')
    if (storage.mode !== 'account') return
    const store = new EncryptedVaultStore<{ initialized: true }>(storage.paths.vaultPath, {
      afterAtomicCommit: () =>
        clearPendingInitializationMarker(storage.paths.initializationMarkerPath)
    })
    await store.initialize('correct horse battery staple', { initialized: true })
    await unlink(storage.paths.vaultPath)

    await expect(bootstrapAccountStorage(root)).rejects.toThrow('ACCOUNT_STORAGE_TARGET_MISSING')
  })

  it('repairs a marker left behind by a crash after the vault commit', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-storage-bootstrap-marker-repair-'))
    const storage = await bootstrapAccountStorage(root, { createUuid: uuidGenerator() })
    expect(storage.mode).toBe('account')
    if (storage.mode !== 'account') return
    const store = new EncryptedVaultStore<{ initialized: true }>(storage.paths.vaultPath)
    await store.initialize('correct horse battery staple', { initialized: true })
    await expect(
      hasPendingInitializationMarker(storage.paths.initializationMarkerPath)
    ).resolves.toBe(true)

    await expect(bootstrapAccountStorage(root)).resolves.toMatchObject({
      mode: 'account',
      activeAccountId: storage.activeAccountId
    })
    await expect(
      hasPendingInitializationMarker(storage.paths.initializationMarkerPath)
    ).resolves.toBe(false)
  })

  it('does not commit a registry that points at storage not prepared by bootstrap', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-storage-bootstrap-order-'))
    const createUuid = uuidGenerator()
    const accountId = 'aaaaaaaa-aaaa-4aaa-8aaa-000000000001'
    const paths = createAccountPathLayout(root).account(accountId)
    let vaultDirectoryWasReady = false
    const registryStore = new AccountRegistryStore(root, {
      createUuid,
      afterWriteStage: async (stage) => {
        if (stage !== 'before-primary') return
        vaultDirectoryWasReady = (await stat(paths.vaultDirectory)).isDirectory()
        throw new Error('STOP_BEFORE_PRIMARY')
      }
    })

    await expect(bootstrapAccountStorage(root, { createUuid, registryStore })).rejects.toThrow(
      'STOP_BEFORE_PRIMARY'
    )
    expect(vaultDirectoryWasReady).toBe(true)
    expect(await registryStore.load()).toBeNull()
    await expect(access(paths.vaultPath)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('fails closed for a corrupt migration journal without a legacy vault', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-storage-bootstrap-corrupt-'))
    await writeFile(join(root, 'account-migration.json'), 'not a journal')

    await expect(bootstrapAccountStorage(root)).rejects.toThrow(
      'ACCOUNT_STORAGE_JOURNAL_UNAVAILABLE'
    )
    expect(await new AccountRegistryStore(root).load()).toBeNull()
  })
})
