import { mkdtemp, readFile, rm } from 'node:fs/promises'
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
