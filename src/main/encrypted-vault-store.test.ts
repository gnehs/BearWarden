import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { EncryptedVaultStore } from './encrypted-vault-store'

const directories: string[] = []

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true })))
})

describe('EncryptedVaultStore master-password proof', () => {
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
