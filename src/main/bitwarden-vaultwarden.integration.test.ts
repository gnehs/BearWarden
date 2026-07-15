import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  deriveMasterKey,
  derivePasswordKey,
  encryptBitwardenBytes,
  stretchMasterKey
} from './bitwarden-crypto'
import { BitwardenDirectClient } from './bitwarden-direct'

const serverUrl = process.env.BEARWARDEN_VAULTWARDEN_URL
const EMAIL = 'bearwarden-integration@example.invalid'
const PASSWORD = 'fake integration master password'
const KDF_ITERATIONS = 100_000

async function registerTemporaryAccount(server: string): Promise<void> {
  const masterKey = await deriveMasterKey(PASSWORD, EMAIL, {
    type: 'pbkdf2',
    iterations: KDF_ITERATIONS
  })
  const passwordKey = await derivePasswordKey(masterKey, PASSWORD)
  const stretched = stretchMasterKey(masterKey)
  const userKey = randomBytes(64)
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const privateKey = rsa.privateKey.export({ format: 'der', type: 'pkcs8' })
  const publicKey = rsa.publicKey.export({ format: 'der', type: 'spki' })
  try {
    const response = await fetch(`${server}/identity/accounts/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        email: EMAIL,
        name: 'BearWarden integration',
        masterPasswordHint: null,
        kdf: 0,
        kdfIterations: KDF_ITERATIONS,
        kdfMemory: null,
        kdfParallelism: null,
        key: encryptBitwardenBytes(userKey, stretched.combinedKey),
        masterPasswordHash: passwordKey.toString('base64'),
        keys: {
          encryptedPrivateKey: encryptBitwardenBytes(privateKey, userKey),
          publicKey: publicKey.toString('base64')
        }
      })
    })
    if (!response.ok) {
      throw new Error(
        `Vaultwarden registration failed (${response.status}): ${await response.text()}`
      )
    }
  } finally {
    masterKey.fill(0)
    passwordKey.fill(0)
    stretched.encKey.fill(0)
    stretched.macKey.fill(0)
    stretched.combinedKey.fill(0)
    userKey.fill(0)
    privateKey.fill(0)
    publicKey.fill(0)
  }
}

describe.runIf(Boolean(serverUrl))('Vaultwarden direct integration', () => {
  it('registers, logs in, syncs, and performs encrypted folder, login, and card CRUD', async () => {
    const server = serverUrl!
    await registerTemporaryAccount(server)
    const client = new BitwardenDirectClient({
      serverUrl: server,
      email: EMAIL,
      deviceName: 'BearWarden integration test'
    })

    await client.login({ email: EMAIL, password: PASSWORD })
    await client.sync()
    expect(await client.listFolders()).toEqual([])
    expect(await client.listPersonalLogins()).toEqual([])

    const folder = await client.createFolder('Integration folder')
    const login = await client.createLogin({
      name: 'Integration login',
      username: 'integration-user@example.invalid',
      password: 'fake remote secret',
      uri: 'https://integration.example.invalid',
      notes: 'Temporary integration data',
      folderId: folder.id,
      favorite: true
    })
    expect(login).toMatchObject({
      name: 'Integration login',
      username: 'integration-user@example.invalid',
      password: 'fake remote secret',
      folderId: folder.id
    })

    const edited = await client.editLogin(login.id, {
      name: 'Edited integration login',
      username: 'edited-user@example.invalid',
      password: 'edited fake secret',
      uri: 'https://edited.integration.example.invalid',
      folderId: folder.id
    })
    expect(edited).toMatchObject({
      name: 'Edited integration login',
      username: 'edited-user@example.invalid',
      password: 'edited fake secret'
    })

    const card = await client.createLogin({
      type: 'card',
      name: 'Integration card',
      cardholderName: 'Test Holder',
      brand: 'Visa',
      number: '4111111111111111',
      expMonth: '12',
      expYear: '2030',
      code: '123',
      folderId: folder.id
    })
    expect(card).toMatchObject({
      type: 'card',
      name: 'Integration card',
      cardholderName: 'Test Holder'
    })
    await expect(
      client.editLogin(card.id, {
        type: 'card',
        name: 'Edited integration card',
        cardholderName: 'Updated Holder',
        number: '5555555555554444'
      })
    ).resolves.toMatchObject({
      type: 'card',
      name: 'Edited integration card',
      cardholderName: 'Updated Holder',
      brand: 'Visa'
    })

    await client.sync()
    expect(await client.listPersonalLogins()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: login.id, name: 'Edited integration login' }),
        expect.objectContaining({ id: card.id, type: 'card', name: 'Edited integration card' })
      ])
    )
    await client.deleteLogin(login.id)
    await client.deleteLogin(card.id)
    await client.deleteFolder(folder.id)
    await client.sync()
    expect(await client.listPersonalLogins()).toEqual([])
    expect(await client.listFolders()).toEqual([])
  }, 30_000)
})
