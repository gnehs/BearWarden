import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { EncryptedVaultStore } from './encrypted-vault-store'

const directories: string[] = []

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true })))
})

describe('EncryptedVaultStore master-password proof', () => {
  it('does not report a committed initialize as failed when post-commit cleanup fails', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-post-commit-cleanup-'))
    directories.push(directory)
    const filePath = join(directory, 'vault.json')
    const store = new EncryptedVaultStore<{ marker: string }>(filePath, {
      afterAtomicCommit: () => {
        throw new Error('CLEANUP_FAILED')
      }
    })

    const material = await store.initialize('correct horse battery staple', { marker: 'committed' })
    expect((await stat(filePath)).isFile()).toBe(true)
    material.key.fill(0)
    material.salt.fill(0)
  })

  it('verifies the current master password without reading or rewriting the vault', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-proof-'))
    directories.push(directory)
    const filePath = join(directory, 'vault.json')
    const store = new EncryptedVaultStore<{ marker: string }>(filePath)
    const material = await store.initialize('correct horse battery staple', { marker: 'test' })
    const before = await readFile(filePath)
    const keyBefore = Buffer.from(material.key)
    const saltBefore = Buffer.from(material.salt)

    await expect(
      store.verifyMasterPassword('correct horse battery staple', material.key, material.salt)
    ).resolves.toBe(true)
    await expect(
      store.verifyMasterPassword('definitely not the password', material.key, material.salt)
    ).resolves.toBe(false)
    await expect(
      store.verifyMasterPassword(
        'correct horse battery staple',
        Buffer.alloc(material.key.length),
        material.salt
      )
    ).resolves.toBe(false)

    expect(await readFile(filePath)).toEqual(before)
    expect(material.key).toEqual(keyBefore)
    expect(material.salt).toEqual(saltBefore)
    before.fill(0)
    keyBefore.fill(0)
    saltBefore.fill(0)
    material.key.fill(0)
    material.salt.fill(0)
  })
})

describe('EncryptedVaultStore operation-scoped key unlock', () => {
  it('decrypts with the bound key and salt without modifying caller-owned buffers', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-key-unlock-'))
    directories.push(directory)
    const store = new EncryptedVaultStore<{ marker: string }>(join(directory, 'vault.json'))
    const material = await store.initialize('correct horse battery staple', { marker: 'safe' })
    const keyBefore = Buffer.from(material.key)
    const saltBefore = Buffer.from(material.salt)

    const unlocked = await store.unlockWithKey(material.key, material.salt)

    expect(unlocked.data).toEqual({ marker: 'safe' })
    expect(unlocked.key).toEqual(keyBefore)
    expect(unlocked.salt).toEqual(saltBefore)
    expect(unlocked.key).not.toBe(material.key)
    expect(unlocked.salt).not.toBe(material.salt)
    expect(material.key).toEqual(keyBefore)
    expect(material.salt).toEqual(saltBefore)

    unlocked.key.fill(0)
    unlocked.salt.fill(0)
    material.key.fill(0)
    material.salt.fill(0)
    keyBefore.fill(0)
    saltBefore.fill(0)
  })

  it('rejects key material bound to a different vault envelope salt', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-key-swap-'))
    directories.push(directory)
    const first = new EncryptedVaultStore<{ marker: string }>(join(directory, 'first.json'))
    const second = new EncryptedVaultStore<{ marker: string }>(join(directory, 'second.json'))
    const firstMaterial = await first.initialize('first master password', { marker: 'first' })
    const secondMaterial = await second.initialize('second master password', { marker: 'second' })

    await expect(second.unlockWithKey(firstMaterial.key, firstMaterial.salt)).rejects.toMatchObject(
      {
        code: 'CORRUPT_VAULT'
      }
    )

    firstMaterial.key.fill(0)
    firstMaterial.salt.fill(0)
    secondMaterial.key.fill(0)
    secondMaterial.salt.fill(0)
  })

  it('fails closed when authenticated ciphertext is corrupted', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-key-corrupt-'))
    directories.push(directory)
    const filePath = join(directory, 'vault.json')
    const store = new EncryptedVaultStore<{ marker: string }>(filePath)
    const material = await store.initialize('correct horse battery staple', { marker: 'safe' })
    const envelope = JSON.parse(await readFile(filePath, 'utf8')) as {
      ciphertext: string
    }
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64')
    ciphertext[0] = ciphertext[0]! ^ 0x80
    envelope.ciphertext = ciphertext.toString('base64')
    await writeFile(filePath, `${JSON.stringify(envelope)}\n`)
    ciphertext.fill(0)

    await expect(store.unlockWithKey(material.key, material.salt)).rejects.toMatchObject({
      code: 'CORRUPT_VAULT'
    })

    material.key.fill(0)
    material.salt.fill(0)
  })

  it('rejects malformed key material before reading the vault', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-key-bounds-'))
    directories.push(directory)
    const store = new EncryptedVaultStore(join(directory, 'missing.json'))

    await expect(store.unlockWithKey(Buffer.alloc(31), Buffer.alloc(16))).rejects.toMatchObject({
      code: 'INTERNAL_ERROR'
    })
    await expect(store.unlockWithKey(Buffer.alloc(32), Buffer.alloc(15))).rejects.toMatchObject({
      code: 'INTERNAL_ERROR'
    })
  })
})

describe('EncryptedVaultStore atomic master-password rekey', () => {
  it('preserves plaintext while replacing the salt and password-derived vault key', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-rekey-'))
    directories.push(directory)
    const filePath = join(directory, 'vault.json')
    const temporaryModes: number[] = []
    const store = new EncryptedVaultStore<{ marker: string; nested: { count: number } }>(filePath, {
      atomicWriteHook: async (stage, paths) => {
        if (stage === 'before-rename') {
          temporaryModes.push((await stat(paths.temporaryPath)).mode & 0o777)
        }
      }
    })
    const original = await store.initialize('correct horse battery staple', {
      marker: 'preserved',
      nested: { count: 42 }
    })
    const originalKey = Buffer.from(original.key)
    const originalSalt = Buffer.from(original.salt)

    const replacement = await store.rekey(
      'correct horse battery staple',
      'even better horse battery staple'
    )

    expect(replacement.key).not.toEqual(originalKey)
    expect(replacement.salt).not.toEqual(originalSalt)
    await expect(store.unlock('correct horse battery staple')).rejects.toMatchObject({
      code: 'INVALID_MASTER_PASSWORD'
    })
    const unlocked = await store.unlock('even better horse battery staple')
    expect(unlocked.data).toEqual({ marker: 'preserved', nested: { count: 42 } })
    expect(unlocked.key).toEqual(replacement.key)
    expect(unlocked.salt).toEqual(replacement.salt)
    expect(temporaryModes).toEqual([0o600, 0o600])
    expect((await stat(filePath)).mode & 0o777).toBe(0o600)

    original.key.fill(0)
    original.salt.fill(0)
    originalKey.fill(0)
    originalSalt.fill(0)
    replacement.key.fill(0)
    replacement.salt.fill(0)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)
  })

  it('rejects a wrong current password and a corrupt envelope without rewriting either file', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-rekey-proof-'))
    directories.push(directory)
    const filePath = join(directory, 'vault.json')
    const store = new EncryptedVaultStore<{ marker: string }>(filePath)
    const material = await store.initialize('correct horse battery staple', { marker: 'safe' })
    const originalContents = await readFile(filePath)

    await expect(
      store.rekey('wrong horse battery staple', 'replacement horse battery staple')
    ).rejects.toMatchObject({ code: 'INVALID_MASTER_PASSWORD' })
    expect(await readFile(filePath)).toEqual(originalContents)

    await writeFile(filePath, '{"format":"bearwarden-vault","version":1}\n')
    const corruptContents = await readFile(filePath)
    await expect(
      store.rekey('correct horse battery staple', 'replacement horse battery staple')
    ).rejects.toMatchObject({ code: 'CORRUPT_VAULT' })
    expect(await readFile(filePath)).toEqual(corruptContents)

    material.key.fill(0)
    material.salt.fill(0)
    originalContents.fill(0)
    corruptContents.fill(0)
  })

  it.each([
    ['short', 'too short'],
    ['unchanged', 'correct horse battery staple'],
    ['normalization-equivalent', 'correct horse battery staple'.normalize('NFD')],
    ['too long', 'x'.repeat(1_025)]
  ])('rejects %s new passwords before touching the envelope', async (_policy, newPassword) => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-rekey-bounds-'))
    directories.push(directory)
    const filePath = join(directory, 'vault.json')
    const store = new EncryptedVaultStore<{ marker: string }>(filePath)
    const material = await store.initialize('correct horse battery staple', { marker: 'safe' })
    const before = await readFile(filePath)

    await expect(store.rekey('correct horse battery staple', newPassword)).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    expect(await readFile(filePath)).toEqual(before)

    material.key.fill(0)
    material.salt.fill(0)
    before.fill(0)
  })

  it.each([
    ['non-string current password', 123, 'replacement horse battery staple'],
    ['non-string new password', 'correct horse battery staple', null],
    ['empty current password', '', 'replacement horse battery staple'],
    ['oversized UTF-8 current password', '猫'.repeat(342), 'replacement horse battery staple'],
    ['oversized UTF-8 new password', 'correct horse battery staple', '猫'.repeat(342)]
  ])('runtime-rejects %s before touching the envelope', async (_policy, current, replacement) => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-rekey-runtime-bounds-'))
    directories.push(directory)
    const filePath = join(directory, 'vault.json')
    const store = new EncryptedVaultStore<{ marker: string }>(filePath)
    const material = await store.initialize('correct horse battery staple', { marker: 'safe' })
    const before = await readFile(filePath)

    await expect(
      store.rekey(current as unknown as string, replacement as unknown as string)
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    expect(await readFile(filePath)).toEqual(before)

    material.key.fill(0)
    material.salt.fill(0)
    before.fill(0)
  })

  it.each(['before-temporary-write', 'before-rename'] as const)(
    'keeps the old envelope usable when %s fails',
    async (failureStage) => {
      const directory = await mkdtemp(join(tmpdir(), 'bearwarden-rekey-failure-'))
      directories.push(directory)
      const filePath = join(directory, 'vault.json')
      let injectFailure = false
      const store = new EncryptedVaultStore<{ marker: string }>(filePath, {
        atomicWriteHook: (stage) => {
          if (injectFailure && stage === failureStage) throw new Error(`injected ${stage} failure`)
        }
      })
      const material = await store.initialize('correct horse battery staple', { marker: 'safe' })
      const before = await readFile(filePath)
      injectFailure = true

      await expect(
        store.rekey('correct horse battery staple', 'replacement horse battery staple')
      ).rejects.toThrow(`injected ${failureStage} failure`)
      expect(await readFile(filePath)).toEqual(before)
      const oldUnlocked = await store.unlock('correct horse battery staple')
      expect(oldUnlocked.data).toEqual({ marker: 'safe' })
      await expect(store.unlock('replacement horse battery staple')).rejects.toMatchObject({
        code: 'INVALID_MASTER_PASSWORD'
      })

      material.key.fill(0)
      material.salt.fill(0)
      oldUnlocked.key.fill(0)
      oldUnlocked.salt.fill(0)
      before.fill(0)
    }
  )

  it('fails closed if the destination envelope changes before rename', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-rekey-toctou-'))
    directories.push(directory)
    const filePath = join(directory, 'vault.json')
    const alternatePath = join(directory, 'alternate.json')
    const alternateStore = new EncryptedVaultStore<{ marker: string }>(alternatePath)
    const alternateMaterial = await alternateStore.initialize('correct horse battery staple', {
      marker: 'newer external state'
    })
    const alternateContents = await readFile(alternatePath)
    let replaceAtBoundary = false
    const store = new EncryptedVaultStore<{ marker: string }>(filePath, {
      atomicWriteHook: async (stage, paths) => {
        if (replaceAtBoundary && stage === 'before-rename') {
          await writeFile(paths.destinationPath, alternateContents)
        }
      }
    })
    const material = await store.initialize('correct horse battery staple', {
      marker: 'original state'
    })
    replaceAtBoundary = true

    await expect(
      store.rekey('correct horse battery staple', 'replacement horse battery staple')
    ).rejects.toMatchObject({ code: 'CORRUPT_VAULT' })
    expect(await readFile(filePath)).toEqual(alternateContents)
    const externallyUpdated = await store.unlock('correct horse battery staple')
    expect(externallyUpdated.data).toEqual({ marker: 'newer external state' })
    await expect(store.unlock('replacement horse battery staple')).rejects.toMatchObject({
      code: 'INVALID_MASTER_PASSWORD'
    })

    material.key.fill(0)
    material.salt.fill(0)
    alternateMaterial.key.fill(0)
    alternateMaterial.salt.fill(0)
    alternateContents.fill(0)
    externallyUpdated.key.fill(0)
    externallyUpdated.salt.fill(0)
  })

  it('serializes a concurrent stale-key write behind rekey and rejects it', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-rekey-concurrency-'))
    directories.push(directory)
    const filePath = join(directory, 'vault.json')
    let releaseRename!: () => void
    let reachedRename!: () => void
    const atRename = new Promise<void>((resolve) => {
      reachedRename = resolve
    })
    const canRename = new Promise<void>((resolve) => {
      releaseRename = resolve
    })
    let blockRekey = false
    const store = new EncryptedVaultStore<{ marker: string }>(filePath, {
      atomicWriteHook: async (stage) => {
        if (blockRekey && stage === 'before-rename') {
          reachedRename()
          await canRename
        }
      }
    })
    const material = await store.initialize('correct horse battery staple', { marker: 'safe' })
    blockRekey = true
    const rekey = store.rekey('correct horse battery staple', 'replacement horse battery staple')
    await atRename
    const staleWrite = store.write({ marker: 'stale write' }, material.key, material.salt)
    releaseRename()

    const replacement = await rekey
    await expect(staleWrite).rejects.toMatchObject({ code: 'CORRUPT_VAULT' })
    const unlocked = await store.unlock('replacement horse battery staple')
    expect(unlocked.data).toEqual({ marker: 'safe' })

    material.key.fill(0)
    material.salt.fill(0)
    replacement.key.fill(0)
    replacement.salt.fill(0)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)
  })

  it('rejects an explicitly stale write after rekey has completed', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-rekey-stale-write-'))
    directories.push(directory)
    const filePath = join(directory, 'vault.json')
    const store = new EncryptedVaultStore<{ marker: string }>(filePath)
    const original = await store.initialize('correct horse battery staple', { marker: 'safe' })
    const replacement = await store.rekey(
      'correct horse battery staple',
      'replacement horse battery staple'
    )

    await expect(
      store.write({ marker: 'stale write' }, original.key, original.salt)
    ).rejects.toMatchObject({ code: 'CORRUPT_VAULT' })
    const unlocked = await store.unlock('replacement horse battery staple')
    expect(unlocked.data).toEqual({ marker: 'safe' })

    original.key.fill(0)
    original.salt.fill(0)
    replacement.key.fill(0)
    replacement.salt.fill(0)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)
  })
})
