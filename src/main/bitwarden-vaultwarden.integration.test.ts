import {
  constants,
  createPublicKey,
  generateKeyPairSync,
  publicEncrypt,
  randomBytes
} from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  deriveMasterKey,
  derivePasswordKey,
  encryptBitwardenBytes,
  encryptBitwardenString,
  stretchMasterKey
} from './bitwarden-crypto'
import { BitwardenDirectClient } from './bitwarden-direct'

const serverUrl = process.env.BEARWARDEN_VAULTWARDEN_URL
const EMAIL = 'bearwarden-integration@example.invalid'
const PASSWORD = 'fake integration master password'
const GRANTEE_EMAIL = 'bearwarden-emergency-contact@example.invalid'
const GRANTEE_PASSWORD = 'fake emergency contact master password'
const KDF_ITERATIONS = 100_000
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu

interface TemporaryAccountKeys {
  userKey: Buffer
  publicKey: Buffer
}

async function registerTemporaryAccount(
  server: string,
  email: string,
  password: string,
  name: string
): Promise<TemporaryAccountKeys> {
  const masterKey = await deriveMasterKey(password, email, {
    type: 'pbkdf2',
    iterations: KDF_ITERATIONS
  })
  const passwordKey = await derivePasswordKey(masterKey, password)
  const stretched = stretchMasterKey(masterKey)
  const userKey = randomBytes(64)
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const privateKey = rsa.privateKey.export({ format: 'der', type: 'pkcs8' })
  const publicKey = rsa.publicKey.export({ format: 'der', type: 'spki' })
  let registeredKeys: TemporaryAccountKeys | null = null
  try {
    const response = await fetch(`${server}/identity/accounts/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        email,
        name,
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
    registeredKeys = { userKey: Buffer.from(userKey), publicKey: Buffer.from(publicKey) }
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
  if (!registeredKeys) throw new Error('Vaultwarden registration did not return account keys')
  return registeredKeys
}

async function registerTemporaryAccounts(
  server: string
): Promise<{ owner: TemporaryAccountKeys; grantee: TemporaryAccountKeys }> {
  const owner = await registerTemporaryAccount(server, EMAIL, PASSWORD, 'BearWarden integration')
  try {
    const grantee = await registerTemporaryAccount(
      server,
      GRANTEE_EMAIL,
      GRANTEE_PASSWORD,
      'BearWarden emergency contact'
    )
    return { owner, grantee }
  } catch (error) {
    owner.userKey.fill(0)
    owner.publicKey.fill(0)
    throw error
  }
}

async function createTemporaryOrganization(
  server: string,
  accessToken: string,
  userKey: Buffer
): Promise<{ id: string; key: Buffer }> {
  const organizationKey = randomBytes(64)
  let retained = false
  try {
    const response = await fetch(`${server}/api/organizations`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${accessToken}`,
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        billingEmail: EMAIL,
        collectionName: encryptBitwardenString('Integration collection', organizationKey),
        key: encryptBitwardenBytes(organizationKey, userKey),
        name: 'BearWarden integration organization',
        planType: 0
      })
    })
    if (!response.ok) {
      throw new Error(
        `Vaultwarden organization creation failed (${response.status}): ${await response.text()}`
      )
    }
    const result = (await response.json()) as { id?: unknown }
    if (typeof result.id !== 'string' || !UUID_PATTERN.test(result.id)) {
      throw new Error('Vaultwarden organization creation returned an invalid id')
    }
    retained = true
    return { id: result.id, key: organizationKey }
  } finally {
    if (!retained) organizationKey.fill(0)
  }
}

async function createTemporaryOrganizationCipher(
  server: string,
  accessToken: string,
  organizationId: string,
  collectionId: string,
  organizationKey: Buffer
): Promise<string> {
  const itemKey = randomBytes(64)
  try {
    const response = await fetch(`${server}/api/ciphers/create`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${accessToken}`,
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        cipher: {
          type: 1,
          organizationId,
          folderId: null,
          key: encryptBitwardenBytes(itemKey, organizationKey, 'legacy-key'),
          name: encryptBitwardenString('Integration shared login', itemKey),
          notes: null,
          fields: [],
          login: {
            username: encryptBitwardenString('shared-user@example.invalid', itemKey),
            password: encryptBitwardenString('fake shared secret', itemKey),
            passwordRevisionDate: null,
            autofillOnPageLoad: null,
            totp: null,
            fido2Credentials: [],
            uris: [
              {
                uri: encryptBitwardenString('https://shared.example.invalid', itemKey),
                match: null
              }
            ]
          },
          secureNote: null,
          card: null,
          identity: null,
          sshKey: null,
          favorite: false,
          reprompt: 0,
          passwordHistory: null,
          attachments2: null,
          lastKnownRevisionDate: null,
          archivedDate: null
        },
        collectionIds: [collectionId]
      })
    })
    if (!response.ok) {
      throw new Error(
        `Vaultwarden organization cipher creation failed (${response.status}): ${await response.text()}`
      )
    }
    const result = (await response.json()) as { id?: unknown }
    if (typeof result.id !== 'string' || !UUID_PATTERN.test(result.id)) {
      throw new Error('Vaultwarden organization cipher creation returned an invalid id')
    }
    return result.id
  } finally {
    itemKey.fill(0)
  }
}

async function sendEmergencyAccessInvite(
  server: string,
  accessToken: string,
  granteeEmail: string
): Promise<void> {
  const response = await fetch(`${server}/api/emergency-access/invite`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${accessToken}`,
      'content-type': 'application/json'
    },
    body: JSON.stringify({ email: granteeEmail, type: 0, waitTimeDays: 1 })
  })
  if (!response.ok) {
    throw new Error(
      `Vaultwarden emergency access invite failed (${response.status}): ${await response.text()}`
    )
  }
}

async function confirmEmergencyAccess(
  server: string,
  accessToken: string,
  emergencyAccessId: string,
  grantorUserKey: Buffer,
  granteePublicKey: Buffer
): Promise<void> {
  const encryptedKey = publicEncrypt(
    {
      key: createPublicKey({ key: granteePublicKey, format: 'der', type: 'spki' }),
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha1'
    },
    grantorUserKey
  )
  try {
    const response = await fetch(`${server}/api/emergency-access/${emergencyAccessId}/confirm`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${accessToken}`,
        'content-type': 'application/json'
      },
      body: JSON.stringify({ key: `4.${encryptedKey.toString('base64')}` })
    })
    if (!response.ok) {
      throw new Error(
        `Vaultwarden emergency access confirmation failed (${response.status}): ${await response.text()}`
      )
    }
  } finally {
    encryptedKey.fill(0)
  }
}

async function runEmergencyAccessAction(
  server: string,
  accessToken: string,
  emergencyAccessId: string,
  action: 'initiate' | 'approve'
): Promise<void> {
  const response = await fetch(`${server}/api/emergency-access/${emergencyAccessId}/${action}`, {
    method: 'POST',
    headers: { authorization: `Bearer ${accessToken}` }
  })
  if (!response.ok) {
    throw new Error(
      `Vaultwarden emergency access ${action} failed (${response.status}): ${await response.text()}`
    )
  }
}

describe.runIf(Boolean(serverUrl))('Vaultwarden direct integration', () => {
  it('round-trips organizations, Sends, emergency access, and encrypted vault CRUD', async () => {
    const server = serverUrl!
    const { owner: ownerKeys, grantee: granteeKeys } = await registerTemporaryAccounts(server)
    const client = new BitwardenDirectClient({
      serverUrl: server,
      email: EMAIL,
      deviceName: 'BearWarden integration test'
    })
    const granteeClient = new BitwardenDirectClient({
      serverUrl: server,
      email: GRANTEE_EMAIL,
      deviceName: 'BearWarden emergency integration test'
    })

    let organizationKey: Buffer | null = null
    try {
      await client.login({ email: EMAIL, password: PASSWORD })
      await granteeClient.login({ email: GRANTEE_EMAIL, password: GRANTEE_PASSWORD })
      await granteeClient.sync()
      const accessToken = client.exportState().session?.accessToken
      if (!accessToken) throw new Error('Vaultwarden login did not return an access token')
      const granteeAccessToken = granteeClient.exportState().session?.accessToken
      if (!granteeAccessToken) {
        throw new Error('Vaultwarden emergency contact login did not return an access token')
      }
      const organization = await createTemporaryOrganization(server, accessToken, ownerKeys.userKey)
      organizationKey = organization.key

      await client.sync()
      const collections = await client.listCollections()
      expect(await client.listOrganizations()).toEqual([
        expect.objectContaining({
          id: organization.id,
          name: 'BearWarden integration organization'
        })
      ])
      expect(collections).toEqual([
        expect.objectContaining({
          organizationId: organization.id,
          name: 'Integration collection'
        })
      ])
      const collection = collections[0]
      if (!collection) throw new Error('Vaultwarden organization did not return a collection')
      const organizationCipherId = await createTemporaryOrganizationCipher(
        server,
        accessToken,
        organization.id,
        collection.id,
        organization.key
      )
      await client.sync()
      expect(await client.listOrganizationCiphers()).toEqual([
        expect.objectContaining({
          id: organizationCipherId,
          organizationId: organization.id,
          collectionIds: [collection.id],
          name: 'Integration shared login',
          username: 'shared-user@example.invalid',
          password: 'fake shared secret'
        })
      ])
      expect(
        (await client.listPersonalLogins()).some(({ id }) => id === organizationCipherId)
      ).toBe(false)

      await sendEmergencyAccessInvite(server, accessToken, GRANTEE_EMAIL)
      const acceptedTrusted = await client.listEmergencyAccess()
      const acceptedGranted = await granteeClient.listEmergencyAccess()
      expect(acceptedTrusted).toEqual([
        expect.objectContaining({
          role: 'trusted',
          email: GRANTEE_EMAIL,
          status: 1,
          waitTimeDays: 1
        })
      ])
      expect(acceptedGranted).toEqual([
        expect.objectContaining({ role: 'granted', email: EMAIL, status: 1, waitTimeDays: 1 })
      ])
      const emergencyAccess = acceptedTrusted[0]
      if (!emergencyAccess) throw new Error('Vaultwarden emergency access invite was not listed')
      await confirmEmergencyAccess(
        server,
        accessToken,
        emergencyAccess.id,
        ownerKeys.userKey,
        granteeKeys.publicKey
      )
      expect(await client.listEmergencyAccess()).toEqual([
        expect.objectContaining({ id: emergencyAccess.id, role: 'trusted', status: 2 })
      ])
      expect(await granteeClient.listEmergencyAccess()).toEqual([
        expect.objectContaining({ id: emergencyAccess.id, role: 'granted', status: 2 })
      ])
      await runEmergencyAccessAction(server, granteeAccessToken, emergencyAccess.id, 'initiate')
      expect(await client.listEmergencyAccess()).toEqual([
        expect.objectContaining({ id: emergencyAccess.id, role: 'trusted', status: 3 })
      ])
      expect(await granteeClient.listEmergencyAccess()).toEqual([
        expect.objectContaining({ id: emergencyAccess.id, role: 'granted', status: 3 })
      ])
      await runEmergencyAccessAction(server, accessToken, emergencyAccess.id, 'approve')
      expect(await client.listEmergencyAccess()).toEqual([
        expect.objectContaining({ id: emergencyAccess.id, role: 'trusted', status: 4 })
      ])
      expect(await granteeClient.listEmergencyAccess()).toEqual([
        expect.objectContaining({ id: emergencyAccess.id, role: 'granted', status: 4 })
      ])
    } finally {
      organizationKey?.fill(0)
      ownerKeys.userKey.fill(0)
      ownerKeys.publicKey.fill(0)
      granteeKeys.userKey.fill(0)
      granteeKeys.publicKey.fill(0)
    }

    expect(await client.listFolders()).toEqual([])
    expect(await client.listPersonalLogins()).toEqual([])

    const deletionDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1_000).toISOString()
    const textSend = await client.createSend({
      name: 'Integration text Send',
      notes: 'Temporary Send metadata',
      text: 'Temporary encrypted Send text',
      hidden: false,
      maxAccessCount: null,
      expirationDate: null,
      deletionDate,
      password: 'fake send password',
      disabled: false,
      hideEmail: false
    })
    expect(textSend).toMatchObject({
      type: 'text',
      name: 'Integration text Send',
      text: 'Temporary encrypted Send text',
      passwordProtected: true
    })
    await client.sync()
    expect(await client.listSends()).toEqual([
      expect.objectContaining({ id: textSend.id, passwordProtected: true })
    ])
    await expect(
      client.updateSend(textSend.id, {
        name: 'Updated integration text Send',
        notes: 'Updated temporary Send metadata',
        text: 'Updated encrypted Send text',
        hidden: true,
        maxAccessCount: 2,
        expirationDate: null,
        deletionDate,
        disabled: false,
        hideEmail: false
      })
    ).resolves.toMatchObject({
      name: 'Updated integration text Send',
      text: 'Updated encrypted Send text',
      hidden: true,
      maxAccessCount: 2,
      passwordProtected: true
    })
    await expect(client.removeSendPassword(textSend.id)).resolves.toMatchObject({
      id: textSend.id,
      passwordProtected: false
    })

    const filePayload = Buffer.from('Temporary encrypted file Send payload', 'utf8')
    let downloadedPayload: Buffer | null = null
    let fileSendId: string | null = null
    try {
      const fileSend = await client.createFileSend({
        name: 'Integration file Send',
        notes: null,
        fileName: 'integration-send.txt',
        data: filePayload,
        maxAccessCount: null,
        expirationDate: null,
        deletionDate,
        password: null,
        disabled: false,
        hideEmail: false
      })
      fileSendId = fileSend.id
      expect(fileSend).toMatchObject({
        type: 'file',
        name: 'Integration file Send',
        file: { fileName: 'integration-send.txt' }
      })
      const downloaded = await client.downloadFileSend(fileSend.id, null)
      downloadedPayload = downloaded.data
      expect(downloaded.fileName).toBe('integration-send.txt')
      expect(downloaded.data).toEqual(filePayload)
    } finally {
      downloadedPayload?.fill(0)
      filePayload.fill(0)
    }
    if (!fileSendId) throw new Error('Vaultwarden file Send did not return an id')
    await client.deleteSend(textSend.id)
    await client.deleteSend(fileSendId)
    await client.sync()
    expect(await client.listSends()).toEqual([])

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
    await client.softDeleteLogin(login.id)
    await client.sync()
    const trashed = (await client.listPersonalLogins()).find(({ id }) => id === login.id)
    expect(trashed?.deletedAt).toEqual(expect.any(String))

    await client.restoreLogin(login.id)
    await client.sync()
    const restored = (await client.listPersonalLogins()).find(({ id }) => id === login.id)
    expect(restored?.deletedAt).toBeNull()

    await client.hardDeleteLogin(login.id)
    await client.hardDeleteLogin(card.id)
    await client.deleteFolder(folder.id)
    await client.sync()
    expect(await client.listPersonalLogins()).toEqual([])
    expect(await client.listFolders()).toEqual([])
  }, 60_000)
})
