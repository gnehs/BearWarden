import { generateKeyPairSync, webcrypto } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { Encoder } from 'cbor-x'
import {
  deriveMasterKey,
  decryptBitwardenCipherBlob,
  decryptBitwardenString,
  encryptBitwardenBytes,
  encryptBitwardenCipherBlob,
  encryptBitwardenString,
  stretchMasterKey,
  type BitwardenXChaCha20Poly1305Key
} from './bitwarden-crypto'
import { BitwardenDirectClient } from './bitwarden-direct'
import { BitwardenHttpClient, type JsonObject } from './bitwarden-http'

const EMAIL = 'bear@example.invalid'
const PASSWORD = 'test master password'
const PROFILE_ID = '10000000-0000-4000-8000-000000000001'
const FOLDER_ID = '20000000-0000-4000-8000-000000000001'
const LOGIN_ID = '30000000-0000-4000-8000-000000000001'
const CREATED_ID = '40000000-0000-4000-8000-000000000001'
const CARD_ID = '30000000-0000-4000-8000-000000000002'
const IDENTITY_ID = '30000000-0000-4000-8000-000000000003'
const NOTE_ID = '30000000-0000-4000-8000-000000000004'
const SSH_ID = '30000000-0000-4000-8000-000000000005'

async function encryptedSync(
  options: { v2?: boolean; allTypes?: boolean } = {}
): Promise<JsonObject> {
  const masterKey = await deriveMasterKey(PASSWORD, EMAIL, { type: 'pbkdf2', iterations: 5_000 })
  const stretched = stretchMasterKey(masterKey)
  const userKey = Buffer.alloc(64, 7)
  const itemKey = Buffer.alloc(64, 9)
  try {
    return {
      profile: {
        id: PROFILE_ID,
        securityStamp: 'test-security-stamp',
        key: encryptBitwardenBytes(userKey, stretched.combinedKey),
        ...(options.v2
          ? {
              accountKeys: {
                publicKeyEncryptionKeyPair: { wrappedPrivateKey: '7.dGVzdA==' }
              }
            }
          : {})
      },
      folders: [
        {
          id: FOLDER_ID,
          name: encryptBitwardenString('Personal', userKey),
          revisionDate: '2026-07-14T00:00:00.000Z'
        }
      ],
      ciphers: [
        {
          id: LOGIN_ID,
          type: 1,
          organizationId: null,
          folderId: FOLDER_ID,
          name: encryptBitwardenString('Example', itemKey),
          notes: encryptBitwardenString('A note', itemKey),
          favorite: true,
          key: encryptBitwardenBytes(itemKey, userKey),
          login: {
            username: encryptBitwardenString('bear@example.invalid', itemKey),
            password: encryptBitwardenString('remote-secret', itemKey),
            totp: encryptBitwardenString(
              'otpauth://totp/example.invalid?secret=JBSWY3DPEHPK3PXP',
              itemKey
            ),
            fido2Credentials: [
              {
                credentialId: encryptBitwardenString('credential-id', itemKey),
                keyType: encryptBitwardenString('public-key', itemKey),
                keyAlgorithm: encryptBitwardenString('ECDSA', itemKey),
                keyCurve: encryptBitwardenString('P-256', itemKey),
                keyValue: encryptBitwardenString('fake-passkey-private-material', itemKey),
                rpId: encryptBitwardenString('example.invalid', itemKey),
                userHandle: encryptBitwardenString('user-handle', itemKey),
                userName: encryptBitwardenString('bear@example.invalid', itemKey),
                counter: encryptBitwardenString('4', itemKey),
                rpName: encryptBitwardenString('Example', itemKey),
                userDisplayName: encryptBitwardenString('Test User', itemKey),
                discoverable: encryptBitwardenString('true', itemKey),
                creationDate: '2026-07-13T00:00:00.000Z'
              }
            ],
            uris: [
              {
                uri: encryptBitwardenString('https://example.invalid', itemKey),
                match: 2,
                uriChecksum: 'opaque-future-checksum'
              },
              { uri: encryptBitwardenString('https://backup.example.invalid', itemKey), match: 1 }
            ]
          },
          fields: [
            {
              name: encryptBitwardenString('member-id', itemKey),
              value: encryptBitwardenString('legacy-member-42', itemKey),
              type: 0,
              linkedId: null
            },
            {
              name: encryptBitwardenString('recovery-code', itemKey),
              value: encryptBitwardenString('legacy-hidden-code', itemKey),
              type: 1,
              linkedId: null
            },
            {
              name: encryptBitwardenString('remember-device', itemKey),
              value: encryptBitwardenString('true', itemKey),
              type: 2,
              linkedId: null
            },
            {
              name: encryptBitwardenString('alternate-username', itemKey),
              value: null,
              type: 3,
              linkedId: 100
            }
          ],
          attachments: [
            {
              id: 'attachment-id',
              fileName: encryptBitwardenString('document.txt', itemKey),
              key: encryptBitwardenBytes(Buffer.alloc(64, 11), itemKey)
            }
          ],
          creationDate: '2026-07-13T00:00:00.000Z',
          revisionDate: '2026-07-14T00:00:00.000Z',
          deletedDate: null
        },
        ...(options.allTypes
          ? [
              {
                id: CARD_ID,
                type: 3,
                organizationId: null,
                folderId: null,
                name: encryptBitwardenString('Payment card', itemKey),
                notes: null,
                favorite: false,
                key: encryptBitwardenBytes(itemKey, userKey),
                card: {
                  cardholderName: encryptBitwardenString('Test Holder', itemKey),
                  brand: encryptBitwardenString('Visa', itemKey),
                  number: encryptBitwardenString('4111111111111111', itemKey),
                  expMonth: encryptBitwardenString('12', itemKey),
                  expYear: encryptBitwardenString('2030', itemKey),
                  code: encryptBitwardenString('123', itemKey),
                  futureCardField: encryptBitwardenString('preserve-me', itemKey)
                },
                fields: [{ type: 0, name: null, value: null, linkedId: null }],
                passwordHistory: [
                  {
                    password: encryptBitwardenString('old-value', itemKey),
                    lastUsedDate: '2026-01-01T00:00:00.000Z'
                  }
                ],
                revisionDate: '2026-07-14T00:00:00.000Z',
                deletedDate: null
              },
              {
                id: IDENTITY_ID,
                type: 4,
                organizationId: null,
                folderId: null,
                name: encryptBitwardenString('Identity', itemKey),
                notes: null,
                favorite: false,
                key: encryptBitwardenBytes(itemKey, userKey),
                identity: {
                  firstName: encryptBitwardenString('Test', itemKey),
                  lastName: encryptBitwardenString('Person', itemKey),
                  username: encryptBitwardenString('identity-user', itemKey)
                },
                revisionDate: null,
                deletedDate: null
              },
              {
                id: NOTE_ID,
                type: 2,
                organizationId: null,
                folderId: null,
                name: encryptBitwardenString('Secure note', itemKey),
                notes: encryptBitwardenString('Encrypted note body', itemKey),
                favorite: false,
                key: encryptBitwardenBytes(itemKey, userKey),
                secureNote: { type: 0 },
                revisionDate: null,
                deletedDate: null
              },
              {
                id: SSH_ID,
                type: 5,
                organizationId: null,
                folderId: null,
                name: encryptBitwardenString('SSH key', itemKey),
                notes: null,
                favorite: false,
                key: encryptBitwardenBytes(itemKey, userKey),
                sshKey: {
                  privateKey: encryptBitwardenString('fake-private-key', itemKey),
                  publicKey: encryptBitwardenString('ssh-ed25519 AAAA test', itemKey),
                  keyFingerprint: encryptBitwardenString('SHA256:fake-fingerprint', itemKey)
                },
                revisionDate: null,
                deletedDate: null
              }
            ]
          : [])
      ]
    }
  } finally {
    masterKey.fill(0)
    stretched.encKey.fill(0)
    stretched.macKey.fill(0)
    stretched.combinedKey.fill(0)
    userKey.fill(0)
    itemKey.fill(0)
  }
}

async function encryptedV2Sync(): Promise<JsonObject> {
  const encoder = new Encoder({ mapsAsObjects: false, tagUint8Array: false, useRecords: false })
  const masterKey = await deriveMasterKey(PASSWORD, EMAIL, { type: 'pbkdf2', iterations: 5_000 })
  const stretched = stretchMasterKey(masterKey)
  const userKey: BitwardenXChaCha20Poly1305Key = {
    algorithm: 'xchacha20-poly1305',
    keyId: Buffer.from([...Array(16).keys()]),
    encryptionKey: Buffer.from([...Array(32).keys()].map((value) => value + 1))
  }
  const encodedUserKey = encoder.encode(
    new Map<unknown, unknown>([
      [1, 4],
      [2, userKey.keyId],
      [3, -70_000],
      [4, [3, 4, 5, 6]],
      [-1, userKey.encryptionKey]
    ])
  )
  const userKeyPadding = Math.max(1, 65 - encodedUserKey.length)
  const paddedUserKey = Buffer.concat([
    encodedUserKey,
    Buffer.alloc(userKeyPadding, userKeyPadding)
  ])
  const itemKey = Buffer.alloc(64, 9)
  try {
    const signingKeys = (await webcrypto.subtle.generateKey('ML-DSA-44', true, [
      'sign',
      'verify'
    ])) as CryptoKeyPair
    const signingPublicKey = Buffer.from(
      await webcrypto.subtle.exportKey('raw-public', signingKeys.publicKey)
    )
    const signingSeed = Buffer.from(
      await webcrypto.subtle.exportKey('raw-seed', signingKeys.privateKey)
    )
    const signingKeyId = Buffer.alloc(16, 7)
    const signingCoseKey = encoder.encode(
      new Map<unknown, unknown>([
        [1, 7],
        [2, signingKeyId],
        [3, -48],
        [4, [1]],
        [-1, signingPublicKey],
        [-2, signingSeed]
      ])
    )
    const protectedHeader = encoder.encode(
      new Map<unknown, unknown>([
        [1, -48],
        [3, 60],
        [4, signingKeyId],
        [-80_000, 2]
      ])
    )
    const securityPayload = encoder.encode(new Map([['version', 2]]))
    const signatureStructure = encoder.encode([
      'Signature1',
      protectedHeader,
      Buffer.alloc(0),
      securityPayload
    ])
    const signature = Buffer.from(
      await webcrypto.subtle.sign('ML-DSA-44', signingKeys.privateKey, signatureStructure)
    )
    const securityState = encoder
      .encode([protectedHeader, new Map(), securityPayload, signature])
      .toString('base64')
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const privateKey = rsa.privateKey.export({ format: 'der', type: 'pkcs8' })
    const publicKey = rsa.publicKey.export({ format: 'der', type: 'spki' })
    const wrappedUserKey = encryptBitwardenBytes(paddedUserKey, stretched.combinedKey)
    const blobCipher = (
      id: string,
      type: number,
      content: Parameters<typeof encryptBitwardenCipherBlob>[0]
    ): JsonObject => ({
      id,
      type,
      organizationId: null,
      folderId: type === 1 ? FOLDER_ID : null,
      name: encryptBitwardenString('', itemKey),
      notes: null,
      favorite: false,
      key: encryptBitwardenBytes(itemKey, userKey, 'legacy-key'),
      login: null,
      secureNote: null,
      card: null,
      identity: null,
      sshKey: null,
      fields: null,
      data: encryptBitwardenCipherBlob(content, itemKey),
      creationDate: null,
      revisionDate: null,
      deletedDate: null
    })

    return {
      profile: {
        id: PROFILE_ID,
        securityStamp: 'test-v2-security-stamp',
        accountKeys: {
          publicKeyEncryptionKeyPair: {
            wrappedPrivateKey: encryptBitwardenBytes(privateKey, userKey, 'pkcs8'),
            publicKey: publicKey.toString('base64'),
            signedPublicKey: null
          },
          signatureKeyPair: {
            wrappedSigningKey: encryptBitwardenBytes(
              Buffer.from(signingCoseKey),
              userKey,
              'cose-key'
            )
          },
          securityState: { securityState, securityVersion: 2 }
        }
      },
      userDecryption: {
        masterPasswordUnlock: { masterKeyEncryptedUserKey: wrappedUserKey }
      },
      folders: [{ id: FOLDER_ID, name: encryptBitwardenString('V2 Personal', userKey) }],
      ciphers: [
        blobCipher(LOGIN_ID, 1, {
          name: 'V2 Example',
          notes: null,
          typeData: {
            type: 'login',
            username: 'v2-user@example.invalid',
            password: 'v2-remote-secret',
            passwordRevisionDate: null,
            uris: [
              { uri: 'https://primary.v2.example.invalid', match: 2 },
              { uri: 'https://backup.v2.example.invalid', match: 1 }
            ],
            totp: 'otpauth://totp/example.invalid?secret=JBSWY3DPEHPK3PXP',
            autofillOnPageLoad: null,
            fido2Credentials: [
              {
                credentialId: 'v2-credential-id',
                keyType: 'public-key',
                keyAlgorithm: 'ECDSA',
                keyCurve: 'P-256',
                keyValue: 'fake-v2-passkey-private-material',
                rpId: 'example.invalid',
                userHandle: null,
                userName: 'v2-user@example.invalid',
                counter: 7,
                rpName: 'V2 Example',
                userDisplayName: 'V2 Test User',
                discoverable: true,
                creationDate: '2026-07-13T00:00:00.000Z'
              }
            ],
            futureLoginField: { preserve: true }
          },
          fields: [
            {
              name: 'member-id',
              value: 'v2-member-42',
              type: 0,
              linkedId: null,
              futureFieldKey: 'preserve-field'
            },
            { name: 'recovery-code', value: 'v2-hidden-code', type: 1, linkedId: null },
            { name: 'remember-device', value: 'true', type: 2, linkedId: null },
            { name: 'alternate-username', value: null, type: 3, linkedId: 100 }
          ],
          passwordHistory: [
            { password: 'old-v2-secret', lastUsedDate: '2026-01-01T00:00:00.000Z' }
          ],
          futureRootField: 'preserve-root'
        }),
        blobCipher(CARD_ID, 3, {
          name: 'V2 card',
          notes: null,
          typeData: {
            type: 'card',
            cardholderName: 'V2 Holder',
            brand: 'Visa',
            number: '4111111111111111',
            expMonth: '12',
            expYear: '2030',
            code: '123'
          }
        }),
        blobCipher(IDENTITY_ID, 4, {
          name: 'V2 identity',
          notes: null,
          typeData: {
            type: 'identity',
            firstName: 'V2',
            lastName: 'Person',
            username: 'v2-identity-user'
          }
        }),
        blobCipher(NOTE_ID, 2, {
          name: 'V2 secure note',
          notes: 'V2 note body',
          typeData: { type: 'secureNote', secureNoteType: 0 }
        }),
        blobCipher(SSH_ID, 5, {
          name: 'V2 SSH key',
          notes: null,
          typeData: {
            type: 'sshKey',
            privateKey: 'fake-v2-synced-private-key',
            publicKey: 'ssh-ed25519 AAAA v2-synced',
            fingerprint: 'SHA256:v2-synced-fingerprint'
          }
        })
      ]
    }
  } finally {
    masterKey.fill(0)
    stretched.encKey.fill(0)
    stretched.macKey.fill(0)
    stretched.combinedKey.fill(0)
    userKey.keyId.fill(0)
    userKey.encryptionKey.fill(0)
    paddedUserKey.fill(0)
    itemKey.fill(0)
  }
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' }
  })
}

describe('BitwardenDirectClient', () => {
  it('authenticates, decrypts a V1 personal vault, and never uploads plaintext', async () => {
    const sync = await encryptedSync()
    const writes: string[] = []
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url, init) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/identity/connect/token')) {
          return jsonResponse({
            access_token: 'access-token',
            refresh_token: 'refresh-token',
            expires_in: 3600
          })
        }
        if (url.includes('/api/sync?')) return jsonResponse(sync)
        if (url.endsWith('/api/folders') && init?.method === 'POST') {
          const body = String(init.body)
          writes.push(body)
          const request = JSON.parse(body) as JsonObject
          return jsonResponse({
            id: CREATED_ID,
            name: request.name,
            revisionDate: '2026-07-14T00:00:01.000Z'
          })
        }
        if (url.endsWith(`/api/ciphers/${LOGIN_ID}`) && init?.method === 'PUT') {
          const body = String(init.body)
          writes.push(body)
          const request = JSON.parse(body) as JsonObject
          return jsonResponse({
            ...(sync.ciphers as JsonObject[])[0],
            ...request,
            id: LOGIN_ID,
            revisionDate: '2026-07-14T00:00:02.000Z'
          })
        }
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http
    })

    await client.login({ email: EMAIL, password: PASSWORD })
    await client.sync()

    expect(await client.listFolders()).toEqual([{ id: FOLDER_ID, name: 'Personal' }])
    expect(await client.listPersonalLogins()).toEqual([
      expect.objectContaining({
        id: LOGIN_ID,
        name: 'Example',
        username: EMAIL,
        password: 'remote-secret',
        totp: 'otpauth://totp/example.invalid?secret=JBSWY3DPEHPK3PXP',
        passkeys: [expect.objectContaining({ rpId: 'example.invalid', discoverable: true })],
        customFields: [
          { name: 'member-id', value: 'legacy-member-42', type: 'text', linkedId: null },
          { name: 'recovery-code', value: 'legacy-hidden-code', type: 'hidden', linkedId: null },
          { name: 'remember-device', value: 'true', type: 'boolean', linkedId: null },
          { name: 'alternate-username', value: '', type: 'linked', linkedId: 100 }
        ],
        notes: 'A note',
        folderId: FOLDER_ID,
        favorite: true
      })
    ])

    await expect(client.createFolder('Private folder')).resolves.toEqual({
      id: CREATED_ID,
      name: 'Private folder'
    })
    expect(writes).toHaveLength(1)
    expect(writes[0]).not.toContain('Private folder')
    expect(writes[0]).toContain('2.')

    await client.editLogin(LOGIN_ID, {
      name: 'Renamed',
      username: EMAIL,
      password: 'changed-secret',
      uri: 'https://changed.example.invalid',
      notes: 'Changed note',
      folderId: FOLDER_ID,
      favorite: false,
      customFields: [
        { name: 'member-id', value: 'legacy-member-99', type: 'text', linkedId: null },
        { name: 'recovery-code', value: 'legacy-updated-code', type: 'hidden', linkedId: null },
        { name: 'remember-device', value: 'false', type: 'boolean', linkedId: null },
        { name: 'alternate-username', value: '', type: 'linked', linkedId: 100 }
      ]
    })
    const update = JSON.parse(writes[1]!) as JsonObject
    const originalLogin = (sync.ciphers as JsonObject[])[0]!.login as JsonObject
    expect((update.login as JsonObject).totp).toBe(originalLogin.totp)
    expect((update.login as JsonObject).fido2Credentials).toEqual(originalLogin.fido2Credentials)
    expect(
      (update.fields as JsonObject[]).map((field) => ({
        name: decryptBitwardenString(field.name as string, Buffer.alloc(64, 9)),
        value:
          field.value === null
            ? null
            : decryptBitwardenString(field.value as string, Buffer.alloc(64, 9)),
        type: field.type,
        linkedId: field.linkedId
      }))
    ).toEqual([
      { name: 'member-id', value: 'legacy-member-99', type: 0, linkedId: null },
      { name: 'recovery-code', value: 'legacy-updated-code', type: 1, linkedId: null },
      { name: 'remember-device', value: 'false', type: 2, linkedId: null },
      { name: 'alternate-username', value: null, type: 3, linkedId: 100 }
    ])
    expect((update.login as JsonObject).uris).toHaveLength(2)
    expect(((update.login as JsonObject).uris as JsonObject[])[0]).toMatchObject({
      match: 2,
      uriChecksum: 'opaque-future-checksum'
    })
    expect(update.attachments).toMatchObject({ 'attachment-id': expect.stringContaining('2.') })
    expect(update.attachments2).toMatchObject({
      'attachment-id': {
        fileName: expect.stringContaining('2.'),
        key: expect.stringContaining('2.')
      }
    })
    expect(writes[1]).not.toContain('changed-secret')
    expect(writes[1]).not.toContain('Renamed')
  })

  it('lists and performs lossless V1 CRUD across card, identity, note, and SSH types', async () => {
    const sync = await encryptedSync({ allTypes: true })
    const writes: JsonObject[] = []
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url, init) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/identity/connect/token')) {
          return jsonResponse({
            access_token: 'access-token',
            refresh_token: 'refresh-token',
            expires_in: 3600
          })
        }
        if (url.includes('/api/sync?')) return jsonResponse(sync)
        if (url.endsWith(`/api/ciphers/${CARD_ID}`) && init?.method === 'PUT') {
          const request = JSON.parse(String(init.body)) as JsonObject
          writes.push(request)
          return jsonResponse({
            ...(sync.ciphers as JsonObject[])[1],
            ...request,
            id: CARD_ID,
            revisionDate: '2026-07-14T00:00:03.000Z'
          })
        }
        if (url.endsWith('/api/ciphers') && init?.method === 'POST') {
          const request = JSON.parse(String(init.body)) as JsonObject
          writes.push(request)
          return jsonResponse({
            ...request,
            id: CREATED_ID,
            creationDate: null,
            revisionDate: null,
            deletedDate: null
          })
        }
        if (url.endsWith(`/api/ciphers/${CREATED_ID}`) && init?.method === 'DELETE') {
          return new Response(null, { status: 204 })
        }
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http
    })

    await client.login({ email: EMAIL, password: PASSWORD })
    await client.sync()
    await expect(client.listPersonalLogins()).resolves.toEqual([
      expect.objectContaining({ id: LOGIN_ID, type: 'login', username: EMAIL }),
      expect.objectContaining({
        id: CARD_ID,
        type: 'card',
        cardholderName: 'Test Holder',
        number: '4111111111111111'
      }),
      expect.objectContaining({
        id: IDENTITY_ID,
        type: 'identity',
        firstName: 'Test',
        identityUsername: 'identity-user'
      }),
      expect.objectContaining({
        id: NOTE_ID,
        type: 'secureNote',
        notes: 'Encrypted note body'
      }),
      expect.objectContaining({
        id: SSH_ID,
        type: 'sshKey',
        privateKey: 'fake-private-key',
        fingerprint: 'SHA256:fake-fingerprint'
      })
    ])

    await expect(
      client.editLogin(CARD_ID, {
        type: 'card',
        name: 'Updated payment card',
        number: '5555555555554444'
      })
    ).resolves.toEqual(
      expect.objectContaining({
        type: 'card',
        name: 'Updated payment card',
        cardholderName: 'Test Holder',
        number: '5555555555554444'
      })
    )
    const cardRequest = writes[0]!
    expect(cardRequest).toMatchObject({
      type: 3,
      lastKnownRevisionDate: '2026-07-14T00:00:00.000Z',
      fields: (sync.ciphers as JsonObject[])[1]!.fields,
      passwordHistory: (sync.ciphers as JsonObject[])[1]!.passwordHistory
    })
    expect((cardRequest.card as JsonObject).futureCardField).toBe(
      ((sync.ciphers as JsonObject[])[1]!.card as JsonObject).futureCardField
    )

    await expect(
      client.createLogin({
        type: 'sshKey',
        name: 'Created SSH key',
        privateKey: 'fake-created-private-key',
        publicKey: 'ssh-ed25519 AAAA created',
        fingerprint: 'SHA256:created-fingerprint'
      })
    ).resolves.toEqual(
      expect.objectContaining({
        id: CREATED_ID,
        type: 'sshKey',
        fingerprint: 'SHA256:created-fingerprint'
      })
    )
    expect(writes[1]).toMatchObject({ type: 5, sshKey: { keyFingerprint: expect.any(String) } })
    expect(JSON.stringify(writes)).not.toMatch(
      /Updated payment card|5555555555554444|fake-created-private-key|created-fingerprint/
    )
    await expect(client.deleteLogin(CREATED_ID)).resolves.toBeUndefined()
    await expect(client.listPersonalLogins()).resolves.not.toEqual(
      expect.arrayContaining([expect.objectContaining({ id: CREATED_ID })])
    )
  })

  it('rejects inconsistent V1 user keys mixed with V2 account keys', async () => {
    const sync = await encryptedSync({ v2: true })
    let writeCount = 0
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url, init) => {
        if (init?.method === 'POST' && url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/identity/connect/token')) {
          return jsonResponse({
            access_token: 'access-token',
            refresh_token: 'refresh-token',
            expires_in: 3600
          })
        }
        if (url.includes('/api/sync?')) return jsonResponse(sync)
        if (init?.method === 'POST' || init?.method === 'PUT' || init?.method === 'DELETE') {
          writeCount += 1
        }
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http
    })

    await client.login({ email: EMAIL, password: PASSWORD })
    await expect(client.sync()).rejects.toMatchObject({
      code: 'UNSUPPORTED_ACCOUNT_ENCRYPTION'
    })
    await expect(client.listFolders()).rejects.toMatchObject({ code: 'AUTH_REQUIRED' })
    expect(writeCount).toBe(0)
  })

  it('authenticates, verifies, decrypts, and writes an Account Encryption V2 vault', async () => {
    const sync = await encryptedV2Sync()
    const folderWrites: string[] = []
    const cipherWrites: string[] = []
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url, init) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/identity/connect/token')) {
          return jsonResponse({
            access_token: 'v2-access-token',
            refresh_token: 'v2-refresh-token',
            expires_in: 3600
          })
        }
        if (url.includes('/api/sync?')) return jsonResponse(sync)
        if (url.endsWith('/api/folders') && init?.method === 'POST') {
          const body = String(init.body)
          folderWrites.push(body)
          const request = JSON.parse(body) as JsonObject
          return jsonResponse({ id: CREATED_ID, name: request.name })
        }
        if (url.endsWith('/api/ciphers') && init?.method === 'POST') {
          const body = String(init.body)
          cipherWrites.push(body)
          const cipher = JSON.parse(body) as JsonObject
          return jsonResponse({
            ...cipher,
            id: CREATED_ID,
            creationDate: null,
            revisionDate: null,
            deletedDate: null
          })
        }
        if (url.includes('/api/ciphers/') && init?.method === 'PUT') {
          const body = String(init.body)
          cipherWrites.push(body)
          const request = JSON.parse(body) as JsonObject
          const id = url.split('/').at(-1)
          return jsonResponse({
            ...request,
            id: id ?? CREATED_ID,
            creationDate: null,
            revisionDate: null,
            deletedDate: null
          })
        }
        if (url.includes('/api/ciphers/') && init?.method === 'DELETE') {
          return new Response(null, { status: 204 })
        }
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http
    })

    await client.login({ email: EMAIL, password: PASSWORD })
    await client.sync()
    await expect(client.listFolders()).resolves.toEqual([{ id: FOLDER_ID, name: 'V2 Personal' }])
    await expect(client.listPersonalLogins()).resolves.toEqual([
      expect.objectContaining({
        id: LOGIN_ID,
        type: 'login',
        name: 'V2 Example',
        username: 'v2-user@example.invalid',
        password: 'v2-remote-secret',
        totp: 'otpauth://totp/example.invalid?secret=JBSWY3DPEHPK3PXP',
        passkeys: [expect.objectContaining({ rpId: 'example.invalid', discoverable: true })],
        customFields: [
          { name: 'member-id', value: 'v2-member-42', type: 'text', linkedId: null },
          { name: 'recovery-code', value: 'v2-hidden-code', type: 'hidden', linkedId: null },
          { name: 'remember-device', value: 'true', type: 'boolean', linkedId: null },
          { name: 'alternate-username', value: '', type: 'linked', linkedId: 100 }
        ]
      }),
      expect.objectContaining({ id: CARD_ID, type: 'card', cardholderName: 'V2 Holder' }),
      expect.objectContaining({
        id: IDENTITY_ID,
        type: 'identity',
        identityUsername: 'v2-identity-user'
      }),
      expect.objectContaining({ id: NOTE_ID, type: 'secureNote', notes: 'V2 note body' }),
      expect.objectContaining({
        id: SSH_ID,
        type: 'sshKey',
        fingerprint: 'SHA256:v2-synced-fingerprint'
      })
    ])

    await expect(client.createFolder('V2 private folder')).resolves.toEqual({
      id: CREATED_ID,
      name: 'V2 private folder'
    })
    expect(folderWrites).toHaveLength(1)
    expect(folderWrites[0]).not.toContain('V2 private folder')
    expect(folderWrites[0]).toContain('7.')

    await expect(
      client.editLogin(LOGIN_ID, {
        name: 'V2 existing edited',
        username: 'existing-edited@example.invalid',
        password: 'existing-edited-fake-secret',
        uri: 'https://edited-primary.v2.example.invalid',
        customFields: [
          { name: 'member-id', value: 'v2-member-42', type: 'text', linkedId: null },
          { name: 'recovery-code', value: 'v2-hidden-code', type: 'hidden', linkedId: null },
          { name: 'remember-device', value: 'true', type: 'boolean', linkedId: null },
          { name: 'alternate-username', value: '', type: 'linked', linkedId: 100 }
        ]
      })
    ).resolves.toEqual(
      expect.objectContaining({
        id: LOGIN_ID,
        uris: [
          { uri: 'https://edited-primary.v2.example.invalid', match: 2 },
          { uri: 'https://backup.v2.example.invalid', match: 1 }
        ]
      })
    )
    const editedBlob = decryptBitwardenCipherBlob(
      (JSON.parse(cipherWrites[0]!) as JsonObject).data as string,
      Buffer.alloc(64, 9)
    ) as Record<string, unknown>
    expect(editedBlob).toMatchObject({
      fields: [
        { name: 'member-id', value: 'v2-member-42', type: 0, linkedId: null },
        { name: 'recovery-code', value: 'v2-hidden-code', type: 1, linkedId: null },
        { name: 'remember-device', value: 'true', type: 2, linkedId: null },
        { name: 'alternate-username', value: null, type: 3, linkedId: 100 }
      ],
      passwordHistory: [{ password: 'old-v2-secret', lastUsedDate: '2026-01-01T00:00:00.000Z' }],
      futureRootField: 'preserve-root',
      typeData: { futureLoginField: { preserve: true } }
    })
    expect((editedBlob.fields as JsonObject[])[0]).toMatchObject({
      futureFieldKey: 'preserve-field'
    })
    expect((editedBlob.typeData as JsonObject).totp).toBe(
      'otpauth://totp/example.invalid?secret=JBSWY3DPEHPK3PXP'
    )
    expect((editedBlob.typeData as JsonObject).fido2Credentials).toEqual([
      expect.objectContaining({
        credentialId: 'v2-credential-id',
        keyValue: 'fake-v2-passkey-private-material'
      })
    ])

    await expect(
      client.createLogin({
        name: 'V2 created login',
        username: 'created@example.invalid',
        password: 'created-fake-secret',
        uri: 'https://created.example.invalid',
        customFields: [
          { name: 'created-text', value: 'created-value', type: 'text', linkedId: null },
          { name: 'created-hidden', value: 'created-secret', type: 'hidden', linkedId: null },
          { name: 'created-boolean', value: 'true', type: 'boolean', linkedId: null },
          { name: 'created-linked', value: '', type: 'linked', linkedId: 101 }
        ]
      })
    ).resolves.toEqual(
      expect.objectContaining({
        id: CREATED_ID,
        name: 'V2 created login',
        username: 'created@example.invalid',
        password: 'created-fake-secret',
        customFields: [
          { name: 'created-text', value: 'created-value', type: 'text', linkedId: null },
          { name: 'created-hidden', value: 'created-secret', type: 'hidden', linkedId: null },
          { name: 'created-boolean', value: 'true', type: 'boolean', linkedId: null },
          { name: 'created-linked', value: '', type: 'linked', linkedId: 101 }
        ]
      })
    )
    await expect(
      client.editLogin(CREATED_ID, {
        name: 'V2 edited login',
        username: 'edited@example.invalid',
        password: 'edited-fake-secret',
        uri: 'https://edited.example.invalid'
      })
    ).resolves.toEqual(
      expect.objectContaining({
        id: CREATED_ID,
        name: 'V2 edited login',
        username: 'edited@example.invalid',
        password: 'edited-fake-secret'
      })
    )
    await expect(
      client.createLogin({
        type: 'card',
        name: 'V2 created card',
        cardholderName: 'V2 Test Holder',
        brand: 'Visa',
        number: '4111111111111111',
        expMonth: '12',
        expYear: '2030',
        code: '123'
      })
    ).resolves.toEqual(expect.objectContaining({ type: 'card', cardholderName: 'V2 Test Holder' }))
    await expect(
      client.createLogin({
        type: 'identity',
        name: 'V2 created identity',
        firstName: 'Test',
        lastName: 'Person',
        identityUsername: 'v2-identity-user'
      })
    ).resolves.toEqual(
      expect.objectContaining({
        type: 'identity',
        firstName: 'Test',
        identityUsername: 'v2-identity-user'
      })
    )
    await expect(
      client.createLogin({
        type: 'secureNote',
        name: 'V2 created note',
        notes: 'V2 encrypted note body'
      })
    ).resolves.toEqual(
      expect.objectContaining({ type: 'secureNote', notes: 'V2 encrypted note body' })
    )
    await expect(
      client.createLogin({
        type: 'sshKey',
        name: 'V2 created SSH key',
        privateKey: 'fake-v2-private-key',
        publicKey: 'ssh-ed25519 AAAA v2-created',
        fingerprint: 'SHA256:v2-created-fingerprint'
      })
    ).resolves.toEqual(
      expect.objectContaining({ type: 'sshKey', fingerprint: 'SHA256:v2-created-fingerprint' })
    )
    await expect(client.deleteLogin(CREATED_ID)).resolves.toBeUndefined()
    expect(cipherWrites).toHaveLength(7)
    for (const body of cipherWrites) {
      expect(JSON.parse((JSON.parse(body) as JsonObject).data as string)).toEqual({
        format_version: 1,
        wrapped_cek: expect.any(String),
        envelope: expect.any(String)
      })
    }
    expect(cipherWrites.join(' ')).not.toMatch(
      /V2 existing edited|existing-edited-fake-secret|V2 created login|created-fake-secret|V2 edited login|edited-fake-secret|V2 Test Holder|4111111111111111|v2-identity-user|V2 encrypted note body|fake-v2-private-key|v2-created-fingerprint/
    )
  })

  it('classifies a wrong master key as authentication failure and keeps data locked', async () => {
    const sync = await encryptedSync()
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/identity/connect/token')) {
          return jsonResponse({
            access_token: 'access-token',
            refresh_token: 'refresh-token',
            expires_in: 3600
          })
        }
        if (url.includes('/api/sync?')) return jsonResponse(sync)
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http
    })

    await client.login({ email: EMAIL, password: 'incorrect master password' })
    await expect(client.sync()).rejects.toMatchObject({ code: 'AUTH_REQUIRED' })
    await expect(client.listPersonalLogins()).rejects.toMatchObject({ code: 'AUTH_REQUIRED' })
  })
})
