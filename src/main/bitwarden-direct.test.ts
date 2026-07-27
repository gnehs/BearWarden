import {
  constants,
  createHash,
  createCipheriv,
  createHmac,
  generateKeyPairSync,
  privateDecrypt,
  publicEncrypt,
  webcrypto
} from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import { Encoder } from 'cbor-x'
import {
  deriveMasterKey,
  derivePasswordKey,
  decryptBitwardenBytes,
  decryptBitwardenAttachmentBuffer,
  encryptBitwardenAttachmentBuffer,
  decryptBitwardenCipherBlob,
  decryptBitwardenString,
  decryptBitwardenWrappedKey,
  deriveBitwardenSendKey,
  encryptBitwardenBytes,
  encryptBitwardenCipherBlob,
  encryptBitwardenString,
  stretchMasterKey,
  type BitwardenXChaCha20Poly1305Key
} from './bitwarden-crypto'
import {
  addAggregateRemoteRows,
  BitwardenDirectClient,
  type BitwardenDirectErrorCode,
  type BitwardenSyncInvalidResponseReason,
  type BitwardenSyncInvalidResponseStage,
  type BitwardenTwoFactor
} from './bitwarden-direct'
import type { AccountWebAuthnAssertion } from './account-webauthn-codec'
import type { AccountWebAuthnAttestation } from './account-webauthn-registration-codec'
import {
  BitwardenHttpClient,
  BitwardenHttpError,
  type BitwardenAttachmentUploadRequest,
  type FetchLike,
  type JsonObject
} from './bitwarden-http'
import { loadEffLongWordlist } from './eff-wordlist'

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
const DELETED_AT = '2026-07-15T00:00:00.000Z'
const ARCHIVED_AT = '2026-07-15T01:00:00.000Z'
const SEND_ID = '50000000-0000-4000-8000-000000000001'
const ORGANIZATION_ID = '60000000-0000-4000-8000-000000000001'
const COLLECTION_ID = '70000000-0000-4000-8000-000000000001'
const ORGANIZATION_CIPHER_ID = '80000000-0000-4000-8000-000000000001'
const POLICY_ID = 'a0000000-0000-4000-8000-000000000001'
const ACCOUNT_WEBAUTHN_CHALLENGE = Buffer.alloc(32, 0x31).toString('base64url')
const ACCOUNT_WEBAUTHN_CREDENTIAL_ID = Buffer.alloc(32, 0x32).toString('base64url')
const ACCOUNT_WEBAUTHN_REGISTRATION_USER_ID = Buffer.alloc(16, 0x33).toString('base64url')
const ACCOUNT_WEBAUTHN_ATTESTATION_OBJECT = Buffer.alloc(128, 0x34).toString('base64url')
const AUTH_REQUEST_ID = '90000000-0000-4000-8000-000000000001'
const LOGIN_REQUEST_FINGERPRINT_VECTOR_PUBLIC_KEY =
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7r0ep8ZLpe6cXqYz7IJutnhTdd8YqxAM1y7sh/dth1qR5LvBYg3H9GusCI4EXl+L9dfUoYGHFC+92bS3jTWsqLHEbIWcT41POqnZkgy1FPC2AxxB72diFqnyRP4yq33uP7YmvwBNZDi8A/QbUn9eTQKfrhJd5GcO1cWY9sQOj6G0D0ZnMBcgHMYwNy2e8dXKzC+S9AUcYprzR7W5uEdiqGE0gn6wILcGSZaIgisrwoG8Y6cy3W6Su8lW5dZOwMMl+8utkXx7vP4wZ+ChDPPJOFloauA1Rjju5FgFnH/eiiWN7it0C0XRSdDmVtQYKnjqst94uQGyG50CQjTaJTtE8QIDAQAB'

function accountWebAuthnAssertion(): AccountWebAuthnAssertion {
  return {
    id: ACCOUNT_WEBAUTHN_CREDENTIAL_ID,
    rawId: ACCOUNT_WEBAUTHN_CREDENTIAL_ID,
    type: 'public-key',
    response: {
      clientDataJSON: Buffer.from('{"type":"webauthn.get"}').toString('base64url'),
      authenticatorData: Buffer.alloc(37, 1).toString('base64url'),
      signature: Buffer.alloc(70, 2).toString('base64url'),
      userHandle: null
    },
    clientExtensionResults: { appid: true, uvm: [[1, 2, 3]] },
    authenticatorAttachment: 'cross-platform'
  }
}

function accountWebAuthnProvider(pascalCase: boolean): JsonObject {
  return pascalCase
    ? {
        AllowCredentials: [{ Id: ACCOUNT_WEBAUTHN_CREDENTIAL_ID, Type: 'public-key' }],
        Challenge: ACCOUNT_WEBAUTHN_CHALLENGE,
        Extensions: { AppId: 'https://vault.example.invalid/app-id.json', Uvm: true },
        RpId: 'vault.example.invalid',
        Timeout: 60_000,
        UserVerification: 'preferred'
      }
    : {
        allowCredentials: [{ id: ACCOUNT_WEBAUTHN_CREDENTIAL_ID, type: 'public-key' }],
        challenge: ACCOUNT_WEBAUTHN_CHALLENGE,
        extensions: {
          appid: 'https://vault.example.invalid/app-id.json',
          getCredBlob: false
        },
        rpId: 'vault.example.invalid',
        timeout: 60_000,
        userVerification: 'discouraged'
      }
}

function accountWebAuthnRegistrationOptions(): JsonObject {
  return {
    rp: { id: 'vault.example.invalid', name: 'Vault' },
    user: {
      id: ACCOUNT_WEBAUTHN_REGISTRATION_USER_ID,
      name: EMAIL,
      displayName: 'Bear'
    },
    challenge: ACCOUNT_WEBAUTHN_CHALLENGE,
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    timeout: 60_000,
    excludeCredentials: [],
    authenticatorSelection: { userVerification: 'discouraged' },
    attestation: 'none',
    extensions: {}
  }
}

function accountWebAuthnAttestation(): AccountWebAuthnAttestation {
  return {
    id: ACCOUNT_WEBAUTHN_CREDENTIAL_ID,
    rawId: ACCOUNT_WEBAUTHN_CREDENTIAL_ID,
    type: 'public-key',
    response: {
      clientDataJSON: Buffer.from('{"type":"webauthn.create"}').toString('base64url'),
      attestationObject: ACCOUNT_WEBAUTHN_ATTESTATION_OBJECT
    },
    clientExtensionResults: {},
    authenticatorAttachment: 'cross-platform'
  }
}

async function encryptedSync(
  options: {
    v2?: boolean
    allTypes?: boolean
    passkeyCredentialId?: string
    totp?: string
  } = {}
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
          reprompt: 1,
          key: encryptBitwardenBytes(itemKey, userKey),
          login: {
            username: encryptBitwardenString('bear@example.invalid', itemKey),
            password: encryptBitwardenString('remote-secret', itemKey),
            passwordRevisionDate: '2026-07-13T00:00:00Z',
            autofillOnPageLoad: false,
            totp: encryptBitwardenString(
              options.totp ?? 'otpauth://totp/example.invalid?secret=JBSWY3DPEHPK3PXP',
              itemKey
            ),
            fido2Credentials: [
              {
                credentialId: encryptBitwardenString(
                  options.passkeyCredentialId ?? 'credential-id',
                  itemKey
                ),
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
                creationDate: '2026-07-13T00:00:00.654321Z'
              }
            ],
            uris: [
              {
                uri: encryptBitwardenString('https://example.invalid', itemKey),
                match: 2,
                uriChecksum: 'opaque-future-checksum'
              },
              {
                uri: encryptBitwardenString('https://backup.example.invalid', itemKey),
                match: 1,
                uriChecksum: 'backup-checksum'
              }
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
          passwordHistory: [
            {
              password: encryptBitwardenString('old-login-secret', itemKey),
              // Vaultwarden f21a3ada serializes this field with microsecond precision.
              lastUsedDate: '2026-01-02T00:00:00.123456Z'
            }
          ],
          attachments: [
            {
              id: 'attachment-id',
              fileName: encryptBitwardenString('document.txt', itemKey),
              size: '12',
              sizeName: '12 B',
              key: encryptBitwardenBytes(Buffer.alloc(64, 11), itemKey)
            },
            {
              id: 'legacy-attachment-id',
              fileName: encryptBitwardenString('legacy-document.txt', itemKey),
              size: '7'
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

async function encryptedV2Sync(
  options: {
    passkeyCount?: number
    passkeyCredentialId?: string
    passkeyCreationDate?: string
  } = {}
): Promise<JsonObject> {
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
      deletedDate: null,
      reprompt: type === 1 ? 1 : 0,
      ...(type === 1
        ? {
            attachments: [
              {
                id: 'v2-attachment-id',
                fileName: encryptBitwardenString('v2-document.txt', itemKey),
                size: '1',
                sizeName: '1 B',
                key: encryptBitwardenBytes(Buffer.alloc(64, 12), itemKey, 'legacy-key')
              }
            ]
          }
        : {})
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
            passwordRevisionDate: '2026-07-13T00:00:00Z',
            uris: [
              { uri: 'https://primary.v2.example.invalid', match: 2 },
              {
                uri: 'https://backup.v2.example.invalid',
                match: 1,
                uriChecksum: 'blob-backup-checksum'
              }
            ],
            totp: 'otpauth://totp/example.invalid?secret=JBSWY3DPEHPK3PXP',
            autofillOnPageLoad: false,
            fido2Credentials: Array.from({ length: options.passkeyCount ?? 1 }, () => ({
              credentialId: options.passkeyCredentialId ?? 'v2-credential-id',
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
              creationDate: options.passkeyCreationDate ?? '2026-07-13T00:00:00.000Z'
            })),
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

function expectedLoginRequestFingerprint(publicKey: Buffer): string {
  const prk = createHash('sha256').update(publicKey).digest()
  const expanded = createHmac('sha256', prk)
    .update(Buffer.from(EMAIL.toLowerCase(), 'utf8'))
    .update(Buffer.from([1]))
    .digest()
  const words = loadEffLongWordlist()
  let value = BigInt(`0x${expanded.toString('hex')}`)
  const phrase: string[] = []
  for (let index = 0; index < 6; index += 1) {
    phrase.push(words[Number(value % BigInt(words.length))]!)
    value /= BigInt(words.length)
  }
  return phrase.join('-')
}

async function loginRequestHarness(
  v2 = false,
  publicKeyOverride?: Buffer
): Promise<{
  client: BitwardenDirectClient
  privateKey: ReturnType<typeof generateKeyPairSync>['privateKey']
  publicKey: Buffer
  responses: JsonObject[]
}> {
  const sync = v2 ? await encryptedV2Sync() : await encryptedSync()
  const pair = generateKeyPairSync('rsa', { modulusLength: 2_048 })
  const publicKey = publicKeyOverride ?? pair.publicKey.export({ format: 'der', type: 'spki' })
  const request = {
    id: AUTH_REQUEST_ID,
    publicKey: publicKey.toString('base64'),
    requestDeviceType: 'Firefox',
    creationDate: '2026-07-20T03:50:00.000Z',
    requestApproved: false,
    responseDate: null,
    object: 'auth-request'
  }
  const responses: JsonObject[] = []
  const http = new BitwardenHttpClient({
    server: 'https://vault.example.invalid',
    now: () => Date.parse('2026-07-20T04:00:00.000Z'),
    fetch: async (url, init) => {
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      if (url.endsWith('/identity/connect/token')) {
        return jsonResponse({
          access_token: 'access-token',
          refresh_token: 'refresh-token',
          expires_in: 3_600
        })
      }
      if (url.includes('/api/sync?')) return jsonResponse(sync)
      if (url.endsWith('/api/auth-requests/pending')) {
        return jsonResponse({ data: [request], object: 'list', continuationToken: null })
      }
      if (url.endsWith(`/api/auth-requests/${AUTH_REQUEST_ID}`) && init?.method === 'GET') {
        return jsonResponse(request)
      }
      if (url.endsWith(`/api/auth-requests/${AUTH_REQUEST_ID}`) && init?.method === 'PUT') {
        const response = JSON.parse(String(init.body)) as JsonObject
        responses.push(response)
        return jsonResponse({
          ...request,
          requestApproved: response.requestApproved,
          responseDate: '2026-07-20T04:00:01.000Z'
        })
      }
      return jsonResponse({ message: 'not found' }, 404)
    }
  })
  const client = new BitwardenDirectClient({
    serverUrl: 'https://vault.example.invalid',
    email: EMAIL,
    state: {
      session: null,
      deviceIdentifier: 'approving-installation-id',
      profileId: null,
      securityStamp: null
    },
    httpClient: http
  })
  await client.login({ email: EMAIL, password: PASSWORD })
  await client.sync()
  return { client, privateKey: pair.privateKey, publicKey, responses }
}

/** Produces Bitwarden's type-2 attachment envelope (type | IV | MAC | ciphertext). */
function encryptAttachmentFixture(plaintext: Buffer, key: Buffer): Buffer {
  const iv = Buffer.alloc(16, 21)
  const cipher = createCipheriv('aes-256-cbc', key.subarray(0, 32), iv)
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const mac = createHmac('sha256', key.subarray(32)).update(iv).update(ciphertext).digest()
  return Buffer.concat([Buffer.from([2]), iv, mac, ciphertext])
}

async function syncedAttachmentClient(
  sync: JsonObject,
  attachmentId: string,
  encrypted: Buffer,
  mutateFresh?: (metadata: JsonObject) => void,
  onBinaryRequest?: () => void
): Promise<BitwardenDirectClient> {
  const cipher = (sync.ciphers as JsonObject[])[0]!
  const attachment = (cipher.attachments as JsonObject[]).find(
    (entry) => entry.id === attachmentId
  )!
  attachment.size = String(encrypted.length)
  const fresh: JsonObject = {
    ...attachment,
    key: attachment.key ?? null,
    url: 'https://attachments.example.invalid/fresh-capability'
  }
  mutateFresh?.(fresh)
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
          expires_in: 3_600
        })
      }
      if (url.includes('/api/sync?')) return jsonResponse(sync)
      if (url.endsWith(`/api/ciphers/${LOGIN_ID}/attachment/${attachmentId}`)) {
        return jsonResponse(fresh)
      }
      if (url === fresh.url) {
        onBinaryRequest?.()
        const body = encrypted.buffer.slice(
          encrypted.byteOffset,
          encrypted.byteOffset + encrypted.byteLength
        ) as ArrayBuffer
        return new Response(body, {
          status: 200,
          headers: { 'content-length': String(encrypted.length) }
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
  return client
}

interface AttachmentMutationHarness {
  client: BitwardenDirectClient
  http: BitwardenHttpClient
  sync: JsonObject
  events: string[]
  createdRequests: BitwardenAttachmentUploadRequest[]
  uploadedBytes: Buffer[]
  uploadedReferences: Buffer[]
  syncSignals: Array<AbortSignal | undefined>
  setPublishUpload(value: boolean): void
  failNextUpload(error: Error): void
  failDelete(attachmentId: string): void
}

async function attachmentMutationHarness(
  sync: JsonObject,
  uploadType: 'direct' | 'azure' = 'direct',
  downloads: Readonly<Record<string, Buffer>> = {}
): Promise<AttachmentMutationHarness> {
  const events: string[] = []
  const createdRequests: BitwardenAttachmentUploadRequest[] = []
  const uploadedBytes: Buffer[] = []
  const uploadedReferences: Buffer[] = []
  let publishUpload = true
  let nextUploadError: Error | null = null
  const failedDeletes = new Set<string>()
  let nextAttachmentIndex = 1
  let pending: {
    attachmentId: string
    request: BitwardenAttachmentUploadRequest
    encryptedFileName: string
  } | null = null

  const cipher = (sync.ciphers as JsonObject[])[0]!
  if (cipher.revisionDate === null || cipher.revisionDate === undefined) {
    cipher.revisionDate = '2026-07-14T00:00:00.000Z'
  }
  const fetch = async (url: string): Promise<Response> => {
    if (url.endsWith('/identity/accounts/prelogin/password')) {
      return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
    }
    if (url.endsWith('/identity/connect/token')) {
      return jsonResponse({
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_in: 3_600
      })
    }
    if (url.includes('/api/sync?')) {
      events.push('sync')
      return jsonResponse(sync)
    }
    for (const [attachmentId, encrypted] of Object.entries(downloads)) {
      if (url.endsWith(`/api/ciphers/${LOGIN_ID}/attachment/${attachmentId}`)) {
        events.push(`download-metadata:${attachmentId}`)
        const attachment = (cipher.attachments as JsonObject[]).find(
          (candidate) => candidate.id === attachmentId
        )
        if (!attachment) return jsonResponse({ message: 'not found' }, 404)
        return jsonResponse({
          ...attachment,
          key: attachment.key ?? null,
          url: `https://attachments.example.invalid/${attachmentId}`
        })
      }
      if (url === `https://attachments.example.invalid/${attachmentId}`) {
        events.push(`download-bytes:${attachmentId}`)
        return new Response(Buffer.from(encrypted), {
          status: 200,
          headers: { 'content-length': String(encrypted.length) }
        })
      }
    }
    return jsonResponse({ message: 'not found' }, 404)
  }
  const http = new BitwardenHttpClient({
    server: 'https://vault.example.invalid',
    fetch
  })
  const syncSignals: Array<AbortSignal | undefined> = []
  const syncHttp = http.sync.bind(http)
  vi.spyOn(http, 'sync').mockImplementation(async (signal) => {
    syncSignals.push(signal)
    return await syncHttp(signal)
  })

  vi.spyOn(http, 'createAttachment').mockImplementation(async (_id, request, signal) => {
    if (signal?.aborted) throw new BitwardenHttpError('ABORTED')
    events.push('create')
    createdRequests.push({ ...request })
    const attachmentId = `uploaded-attachment-${nextAttachmentIndex++}`
    pending = { attachmentId, request: { ...request }, encryptedFileName: request.fileName }
    return {
      attachmentId,
      url: 'https://bearwarden.blob.core.windows.net/attachments/upload?sv=2026-01-01&sig=fake',
      fileUploadType: uploadType
    }
  })

  const publishPending = (data: Buffer): void => {
    if (!pending || !publishUpload) return
    const attachments = cipher.attachments as JsonObject[]
    attachments.push({
      id: pending.attachmentId,
      fileName: pending.request.fileName,
      size: String(data.length),
      sizeName: `${data.length} B`,
      key: pending.request.key
    })
    cipher.revisionDate = '2026-07-16T00:00:00.000Z'
  }

  vi.spyOn(http, 'uploadAttachmentDirect').mockImplementation(
    async (_id, _attachmentId, encryptedFileName, data, signal) => {
      events.push('upload-direct')
      if (signal?.aborted) throw new BitwardenHttpError('ABORTED')
      if (!pending || encryptedFileName !== pending.encryptedFileName) {
        throw new BitwardenHttpError('INVALID_RESPONSE')
      }
      if (nextUploadError) {
        const error = nextUploadError
        nextUploadError = null
        throw error
      }
      const bytes = Buffer.isBuffer(data)
        ? Buffer.from(data)
        : Buffer.from(await data.arrayBuffer())
      uploadedBytes.push(bytes)
      if (Buffer.isBuffer(data)) uploadedReferences.push(data)
      publishPending(bytes)
    }
  )
  vi.spyOn(http, 'uploadAttachmentAzure').mockImplementation(async (_url, data, signal) => {
    events.push('upload-azure')
    if (signal?.aborted) throw new BitwardenHttpError('ABORTED')
    if (nextUploadError) {
      const error = nextUploadError
      nextUploadError = null
      throw error
    }
    const bytes = Buffer.isBuffer(data) ? Buffer.from(data) : Buffer.from(await data.arrayBuffer())
    uploadedBytes.push(bytes)
    if (Buffer.isBuffer(data)) uploadedReferences.push(data)
    publishPending(bytes)
  })
  vi.spyOn(http, 'deleteAttachment').mockImplementation(async (_id, attachmentId) => {
    events.push(`delete:${attachmentId}`)
    if (failedDeletes.has(attachmentId)) throw new BitwardenHttpError('NETWORK')
    cipher.attachments = (cipher.attachments as JsonObject[]).filter(
      (attachment) => attachment.id !== attachmentId
    )
    cipher.revisionDate = '2026-07-16T00:00:01.000Z'
    return { cipher }
  })

  const client = new BitwardenDirectClient({
    serverUrl: 'https://vault.example.invalid',
    email: EMAIL,
    httpClient: http
  })
  await client.login({ email: EMAIL, password: PASSWORD })
  await client.sync()
  events.length = 0
  syncSignals.length = 0

  return {
    client,
    http,
    sync,
    events,
    createdRequests,
    uploadedBytes,
    uploadedReferences,
    syncSignals,
    setPublishUpload(value) {
      publishUpload = value
    },
    failNextUpload(error) {
      nextUploadError = error
    },
    failDelete(attachmentId) {
      failedDeletes.add(attachmentId)
    }
  }
}

async function expectInvalidSync(
  sync: unknown,
  code: BitwardenDirectErrorCode = 'INVALID_RESPONSE',
  stage?: BitwardenSyncInvalidResponseStage,
  reason?: BitwardenSyncInvalidResponseReason
): Promise<void> {
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
          expires_in: 3_600
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
  await client.login({ email: EMAIL, password: PASSWORD })
  await expect(client.sync()).rejects.toMatchObject({
    code,
    ...(stage ? { syncInvalidResponseStage: stage } : {}),
    ...(reason ? { syncInvalidResponseReason: reason } : {})
  })
  await expect(client.listPersonalLogins()).rejects.toMatchObject({ code: 'AUTH_REQUIRED' })
}

async function clientForSync(sync: JsonObject): Promise<BitwardenDirectClient> {
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
          expires_in: 3_600
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
  await client.login({ email: EMAIL, password: PASSWORD })
  await client.sync()
  return client
}

describe('BitwardenDirectClient', () => {
  it('annotates incompatible sign-in responses with a safe response stage', async () => {
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: new BitwardenHttpClient({
        server: 'https://vault.example.invalid',
        fetch: async (url) =>
          url.endsWith('/identity/accounts/prelogin/password')
            ? jsonResponse({ kdf: 'unexpected' })
            : jsonResponse({ message: 'not found' }, 404)
      })
    })

    await expect(client.login({ email: EMAIL, password: PASSWORD })).rejects.toMatchObject({
      code: 'INVALID_RESPONSE',
      syncInvalidResponseStage: 'response',
      syncInvalidResponseReason: 'response-shape'
    })
  })

  it('persists remembered two-factor tokens separately and retries with provider 5', async () => {
    const tokenBodies: URLSearchParams[] = []
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url, init) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/identity/connect/token')) {
          tokenBodies.push(new URLSearchParams(String(init?.body)))
          return jsonResponse({
            access_token: `access-${tokenBodies.length}`,
            refresh_token: `refresh-${tokenBodies.length}`,
            expires_in: 3_600,
            ...(tokenBodies.length === 1 ? { TwoFactorToken: 'remembered-token' } : {})
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

    await client.login({
      email: EMAIL,
      password: PASSWORD,
      twoFactor: { method: 0, code: '123456', remember: true }
    })
    expect(client.exportState()).toMatchObject({ rememberedTwoFactorToken: 'remembered-token' })
    expect(client.exportState().session).not.toHaveProperty('twoFactorToken')

    await client.logout()
    expect(client.exportState()).toMatchObject({
      session: null,
      rememberedTwoFactorToken: 'remembered-token'
    })
    await client.login({ email: EMAIL, password: PASSWORD })
    expect(tokenBodies[1]?.get('twoFactorProvider')).toBe('5')
    expect(tokenBodies[1]?.get('twoFactorToken')).toBe('remembered-token')
    expect(client.exportState().session).not.toHaveProperty('twoFactorToken')
  })

  it('clears a rejected remembered two-factor token before returning the fresh challenge', async () => {
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      state: {
        session: null,
        rememberedTwoFactorToken: 'expired-remembered-token',
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: null,
        securityStamp: null
      },
      httpClient: new BitwardenHttpClient({
        server: 'https://vault.example.invalid',
        fetch: async (url) => {
          if (url.endsWith('/identity/accounts/prelogin/password')) {
            return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
          }
          if (url.endsWith('/identity/connect/token')) {
            return jsonResponse(
              {
                error: 'invalid_grant',
                error_description: 'Two factor required.',
                TwoFactorProviders2: { '0': null }
              },
              400
            )
          }
          return jsonResponse({ message: 'not found' }, 404)
        }
      })
    })

    await expect(client.login({ email: EMAIL, password: PASSWORD })).rejects.toMatchObject({
      code: 'TWO_FACTOR_REQUIRED',
      twoFactorProviders: [0]
    })
    expect(client.exportState()).not.toHaveProperty('rememberedTwoFactorToken')
  })

  it('matches a fixed Login with device fingerprint vector', async () => {
    const publicKey = Buffer.from(LOGIN_REQUEST_FINGERPRINT_VECTOR_PUBLIC_KEY, 'base64')
    const { client } = await loginRequestHarness(false, publicKey)
    await expect(client.getLoginRequest(AUTH_REQUEST_ID)).resolves.toMatchObject({
      fingerprint: 'skeptic-macaroni-shamrock-snowdrop-audio-collage'
    })
  })

  it('derives the official six-word login-request fingerprint and exposes only safe metadata', async () => {
    const { client, publicKey } = await loginRequestHarness()
    const expected = {
      id: AUTH_REQUEST_ID,
      fingerprint: expectedLoginRequestFingerprint(publicKey),
      requestDeviceType: 'Firefox',
      createdAt: '2026-07-20T03:50:00.000Z'
    }
    await expect(client.getLoginRequest(AUTH_REQUEST_ID)).resolves.toEqual(expected)
    await expect(client.listPendingLoginRequests()).resolves.toEqual([expected])
    expect(Object.keys(expected).sort()).toEqual([
      'createdAt',
      'fingerprint',
      'id',
      'requestDeviceType'
    ])
  })

  it.each([
    ['legacy', false],
    ['V2', true]
  ])(
    'wraps the current %s user key with RSA-OAEP-SHA1 for approval and denial',
    async (_label, v2) => {
      for (const approved of [true, false]) {
        const { client, privateKey, publicKey, responses } = await loginRequestHarness(v2)
        const fingerprint = expectedLoginRequestFingerprint(publicKey)
        await client.respondLoginRequest(AUTH_REQUEST_ID, fingerprint, approved)
        expect(responses).toHaveLength(1)
        expect(responses[0]).toMatchObject({
          masterPasswordHash: null,
          deviceIdentifier: 'approving-installation-id',
          requestApproved: approved
        })
        const envelope = String(responses[0]!.key)
        expect(envelope.startsWith('4.')).toBe(true)
        const decoded = privateDecrypt(
          {
            key: privateKey,
            padding: constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha1'
          },
          Buffer.from(envelope.slice(2), 'base64')
        )
        if (v2) {
          const encoder = new Encoder({
            mapsAsObjects: false,
            tagUint8Array: false,
            useRecords: false
          })
          const encoded = Buffer.from(
            encoder.encode(
              new Map<unknown, unknown>([
                [1, 4],
                [2, Buffer.from([...Array(16).keys()])],
                [3, -70_000],
                [4, [3, 4, 5, 6]],
                [-1, Buffer.from([...Array(32).keys()].map((value) => value + 1))]
              ])
            )
          )
          const padding = Math.max(1, 65 - encoded.length)
          expect(decoded).toEqual(Buffer.concat([encoded, Buffer.alloc(padding, padding)]))
        } else {
          expect(decoded).toEqual(Buffer.alloc(64, 7))
        }
      }
    }
  )

  it('re-fetches before responding and refuses a mismatched fingerprint without sending a PUT', async () => {
    const { client, responses } = await loginRequestHarness()
    await expect(
      client.respondLoginRequest(AUTH_REQUEST_ID, 'wrong-wrong-wrong-wrong-wrong-wrong', true)
    ).rejects.toMatchObject({ code: 'CONFLICT' })
    expect(responses).toEqual([])
  })

  it.each([
    { label: 'Vaultwarden camelCase', pascalCase: false, providersKey: 'TwoFactorProviders2' },
    { label: 'official PascalCase', pascalCase: true, providersKey: 'twoFactorProviders2' }
  ])('propagates a strict $label challenge without raw token error details', async (fixture) => {
    let tokenRequests = 0
    const fetch = vi.fn<FetchLike>(async (url) => {
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      if (url.endsWith('/identity/connect/token')) {
        tokenRequests += 1
        return jsonResponse(
          {
            error: 'invalid_grant',
            error_description: 'Two factor required.',
            [fixture.providersKey]: {
              '0': null,
              '1': null,
              '3': null,
              '7': accountWebAuthnProvider(fixture.pascalCase)
            },
            rawServerSecret: 'must-not-escape'
          },
          400
        )
      }
      return jsonResponse({ message: 'not found' }, 404)
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch })
    })

    const error = await client
      .login({ email: EMAIL, password: PASSWORD })
      .catch((caught: unknown) => caught)
    expect(error).toMatchObject({
      code: 'TWO_FACTOR_REQUIRED',
      twoFactorProviders: [0, 1, 3, 7],
      webAuthnChallenge: {
        challenge: ACCOUNT_WEBAUTHN_CHALLENGE,
        rpId: 'vault.example.invalid',
        allowCredentials: [{ id: ACCOUNT_WEBAUTHN_CREDENTIAL_ID, type: 'public-key' }],
        timeout: 60_000
      }
    })
    expect(JSON.stringify(error)).not.toContain('must-not-escape')
    expect(client.exportState()).not.toHaveProperty('webAuthnChallenge')
    expect(tokenRequests).toBe(1)
  })

  it('uses an explicitly supplied two-factor code even when a persisted session exists', async () => {
    const tokenBodies: URLSearchParams[] = []
    const fetch = vi.fn<FetchLike>(async (url, init) => {
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      if (url.endsWith('/identity/connect/token')) {
        tokenBodies.push(new URLSearchParams(String(init?.body)))
        return jsonResponse({
          access_token: 'fresh-access',
          refresh_token: 'fresh-refresh',
          expires_in: 3600
        })
      }
      return jsonResponse({ message: 'not found' }, 404)
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch }),
      state: {
        session: {
          accessToken: 'stale-access',
          refreshToken: 'stale-refresh',
          expiresAt: Date.now() + 3_600_000
        },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'old-security-stamp'
      }
    })

    await client.unlock({
      password: PASSWORD,
      twoFactor: { method: 0, code: '123456' }
    })

    expect(tokenBodies).toHaveLength(1)
    expect(tokenBodies[0]!.get('twoFactorProvider')).toBe('0')
    expect(tokenBodies[0]!.get('twoFactorToken')).toBe('123456')
    expect(client.exportState().session).toMatchObject({ accessToken: 'fresh-access' })
  })

  it('clears a rejected persisted session so the next unlock performs a fresh login', async () => {
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async () => jsonResponse({ message: 'not found' }, 404)
    })
    vi.spyOn(http, 'sync').mockRejectedValueOnce(new BitwardenHttpError('AUTH', 401))
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: {
          accessToken: 'rejected-access',
          refreshToken: 'rejected-refresh',
          expiresAt: Date.now() + 3_600_000
        },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'old-security-stamp'
      }
    })

    await expect(client.sync()).rejects.toMatchObject({ code: 'AUTH_REQUIRED' })
    expect(client.exportState().session).toBeNull()
    await expect(client.status()).resolves.toEqual({ status: 'unauthenticated' })
  })

  it('derives and sends the Email 2FA login proof without authentication', async () => {
    const requests: Array<{ body: JsonObject; headers: Headers }> = []
    const fetch = vi.fn<FetchLike>(async (url, init) => {
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      if (url.endsWith('/api/two-factor/send-email-login')) {
        requests.push({
          body: JSON.parse(String(init?.body)) as JsonObject,
          headers: new Headers(init?.headers)
        })
        return new Response(null, { status: 201 })
      }
      return jsonResponse({ message: 'not found' }, 404)
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      deviceType: 99,
      state: {
        session: null,
        deviceIdentifier: 'installation-id',
        profileId: null,
        securityStamp: null
      },
      httpClient: new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch })
    })
    const expectedMasterKey = await deriveMasterKey(PASSWORD, EMAIL, {
      type: 'pbkdf2',
      iterations: 5_000
    })
    const expectedPasswordKey = await derivePasswordKey(expectedMasterKey, PASSWORD)
    const expectedHash = expectedPasswordKey.toString('base64')

    try {
      await client.sendEmailTwoFactorLoginCode(PASSWORD)
      expect(requests).toHaveLength(1)
      expect(requests[0]?.body).toEqual({
        email: EMAIL,
        masterPasswordHash: expectedHash,
        deviceIdentifier: 'installation-id'
      })
      expect(requests[0]?.headers.get('authorization')).toBeNull()
      expect(requests[0]?.headers.get('device-type')).toBe('99')
      expect(fetch.mock.calls.some(([url]) => url.endsWith('/identity/connect/token'))).toBe(false)
      expect(client.exportState().session).toBeNull()
    } finally {
      expectedMasterKey.fill(0)
      expectedPasswordKey.fill(0)
    }
  })

  it('rejects an invalid Email 2FA login password before deriving or dispatching', async () => {
    const fetch = vi.fn<FetchLike>()
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch })
    })

    await expect(client.sendEmailTwoFactorLoginCode('')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    expect(fetch).not.toHaveBeenCalled()
  })

  it.each([true, false])(
    'submits the exact provider-7 assertion form with remember=%s only on the user retry',
    async (remember) => {
      const tokenForms: URLSearchParams[] = []
      const fetch = vi.fn<FetchLike>(async (url, init) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/identity/connect/token')) {
          tokenForms.push(new URLSearchParams(String(init?.body)))
          if (tokenForms.length === 1) {
            return jsonResponse(
              {
                error: 'invalid_grant',
                error_description: 'Two factor required.',
                TwoFactorProviders2: { '7': accountWebAuthnProvider(false) }
              },
              400
            )
          }
          return jsonResponse({
            access_token: 'access',
            refresh_token: 'refresh',
            expires_in: 3600
          })
        }
        return jsonResponse({ message: 'not found' }, 404)
      })
      const client = new BitwardenDirectClient({
        serverUrl: 'https://vault.example.invalid',
        email: EMAIL,
        deviceName: 'Test desktop',
        deviceType: 99,
        httpClient: new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch })
      })

      await expect(client.login({ email: EMAIL, password: PASSWORD })).rejects.toMatchObject({
        code: 'TWO_FACTOR_REQUIRED'
      })
      await client.login({
        email: EMAIL,
        password: PASSWORD,
        twoFactor: { method: 7, assertion: accountWebAuthnAssertion(), remember }
      })

      expect(tokenForms).toHaveLength(2)
      expect(Object.fromEntries(tokenForms[0]!)).not.toHaveProperty('twoFactorProvider')
      expect(Object.fromEntries(tokenForms[1]!)).toEqual({
        grant_type: 'password',
        username: EMAIL,
        password: expect.any(String),
        scope: 'api offline_access',
        client_id: 'desktop',
        deviceIdentifier: expect.any(String),
        deviceType: '99',
        deviceName: 'Test desktop',
        twoFactorProvider: '7',
        twoFactorToken: JSON.stringify({
          id: ACCOUNT_WEBAUTHN_CREDENTIAL_ID,
          rawId: ACCOUNT_WEBAUTHN_CREDENTIAL_ID,
          type: 'public-key',
          response: {
            clientDataJson: accountWebAuthnAssertion().response.clientDataJSON,
            authenticatorData: accountWebAuthnAssertion().response.authenticatorData,
            signature: accountWebAuthnAssertion().response.signature
          },
          extensions: { appid: true, uvm: [[1, 2, 3]] }
        }),
        twoFactorRemember: remember ? '1' : '0'
      })
    }
  )

  it.each([
    { method: 0, code: '123456' },
    { method: 1, code: '654321' },
    { method: 3, code: 'recovery-code' }
  ] satisfies readonly BitwardenTwoFactor[])(
    'keeps provider $method token and remember defaults unchanged',
    async (twoFactor) => {
      let tokenForm: URLSearchParams | null = null
      const fetch = vi.fn<FetchLike>(async (url, init) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/identity/connect/token')) {
          tokenForm = new URLSearchParams(String(init?.body))
          return jsonResponse({
            access_token: 'access',
            refresh_token: 'refresh',
            expires_in: 3600
          })
        }
        return jsonResponse({ message: 'not found' }, 404)
      })
      const client = new BitwardenDirectClient({
        serverUrl: 'https://vault.example.invalid',
        email: EMAIL,
        httpClient: new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch })
      })

      await client.login({ email: EMAIL, password: PASSWORD, twoFactor })
      expect(tokenForm).not.toBeNull()
      expect(tokenForm!.get('twoFactorProvider')).toBe(String(twoFactor.method))
      expect(tokenForm!.get('twoFactorToken')).toBe(twoFactor.code)
      expect(tokenForm!.get('twoFactorRemember')).toBe('1')
    }
  )

  it.each([
    { httpCode: 'ABORTED' as const, directCode: 'ABORTED' },
    { httpCode: 'NETWORK' as const, directCode: 'NETWORK' }
  ])('does not retry a provider-7 request after $httpCode', async ({ httpCode, directCode }) => {
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url) =>
        url.endsWith('/identity/accounts/prelogin/password')
          ? jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
          : jsonResponse({ message: 'not found' }, 404)
    })
    const passwordToken = vi
      .spyOn(http, 'passwordToken')
      .mockRejectedValue(new BitwardenHttpError(httpCode))
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http
    })

    await expect(
      client.login({
        email: EMAIL,
        password: PASSWORD,
        twoFactor: { method: 7, assertion: accountWebAuthnAssertion(), remember: false }
      })
    ).rejects.toMatchObject({ code: directCode })
    expect(passwordToken).toHaveBeenCalledOnce()
  })

  it('rejects an invalid assertion before the token request', async () => {
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url) =>
        url.endsWith('/identity/accounts/prelogin/password')
          ? jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
          : jsonResponse({ message: 'not found' }, 404)
    })
    const passwordToken = vi.spyOn(http, 'passwordToken')
    const invalidAssertion = {
      ...accountWebAuthnAssertion(),
      rawId: `${ACCOUNT_WEBAUTHN_CREDENTIAL_ID}=`
    }
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http
    })

    await expect(
      client.login({
        email: EMAIL,
        password: PASSWORD,
        twoFactor: { method: 7, assertion: invalidAssertion, remember: false }
      })
    ).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
    expect(passwordToken).not.toHaveBeenCalled()
  })

  it('does not retain a previous WebAuthn challenge for a new login attempt', async () => {
    let tokenRequests = 0
    const fetch = vi.fn<FetchLike>(async (url) => {
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      if (url.endsWith('/identity/connect/token')) {
        tokenRequests += 1
        return jsonResponse(
          {
            error: 'invalid_grant',
            error_description: 'Two factor required.',
            TwoFactorProviders2:
              tokenRequests === 1
                ? { '7': accountWebAuthnProvider(false) }
                : { '0': null, '1': null, '3': null }
          },
          400
        )
      }
      return jsonResponse({ message: 'not found' }, 404)
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch })
    })

    await expect(client.login({ email: EMAIL, password: PASSWORD })).rejects.toMatchObject({
      code: 'TWO_FACTOR_REQUIRED',
      twoFactorProviders: [7],
      webAuthnChallenge: expect.any(Object)
    })
    await expect(client.login({ email: EMAIL, password: PASSWORD })).rejects.toMatchObject({
      code: 'TWO_FACTOR_REQUIRED',
      twoFactorProviders: [0, 1, 3],
      webAuthnChallenge: undefined
    })
    expect(tokenRequests).toBe(2)
  })

  it('rewraps the same user key for an official PBKDF2 password change and clears state', async () => {
    const sync = await encryptedSync()
    const bodies: JsonObject[] = []
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url, init) => {
        if (url.endsWith('/identity/accounts/prelogin/password'))
          return jsonResponse({ kdf: { type: 0, iterations: 5_000 }, salt: EMAIL })
        if (url.endsWith('/identity/connect/token'))
          return jsonResponse({
            access_token: 'access',
            refresh_token: 'refresh',
            expires_in: 3600
          })
        if (url.includes('/api/sync?')) return jsonResponse(sync)
        if (url.endsWith('/api/accounts/password')) {
          bodies.push(JSON.parse(String(init?.body)) as JsonObject)
          return new Response(null, { status: 200 })
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
    await client.changeMasterPassword({
      currentPassword: PASSWORD,
      newPassword: 'replacement master password',
      hint: 'safe hint'
    })
    expect(bodies).toHaveLength(1)
    expect(bodies[0]).toMatchObject({
      masterPasswordHint: 'safe hint',
      authenticationData: { salt: EMAIL, kdf: { kdfType: 0, iterations: 5_000 } },
      unlockData: { salt: EMAIL, kdf: { kdfType: 0, iterations: 5_000 } }
    })
    expect(bodies[0]).not.toHaveProperty('newMasterPasswordHash')
    await expect(client.status()).resolves.toEqual({ status: 'unauthenticated' })
    expect(client.exportState().session).toBeNull()
  })

  it('uses the flat contract when identity prelogin succeeds but config identifies Vaultwarden', async () => {
    const sync = await encryptedSync()
    let body: JsonObject | null = null
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url, init) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/api/config')) {
          return jsonResponse({
            server: { name: 'Vaultwarden', url: 'https://github.com/dani-garcia/vaultwarden' }
          })
        }
        if (url.endsWith('/identity/connect/token'))
          return jsonResponse({
            access_token: 'access',
            refresh_token: 'refresh',
            expires_in: 3600
          })
        if (url.includes('/api/sync?')) return jsonResponse(sync)
        if (url.endsWith('/api/accounts/password')) {
          body = JSON.parse(String(init?.body)) as JsonObject
          return new Response(null, { status: 200 })
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
    await client.changeMasterPassword({
      currentPassword: PASSWORD,
      newPassword: 'replacement master password',
      hint: null
    })
    expect(body).toMatchObject({ masterPasswordHint: null })
    expect(body).toHaveProperty('masterPasswordHash')
    expect(body).toHaveProperty('newMasterPasswordHash')
    expect(body).toHaveProperty('key')
    expect(body).not.toHaveProperty('authenticationData')
    expect(body).not.toHaveProperty('unlockData')
  })

  it('uses fresh Argon2 parameters and fails closed on an unknown mutation outcome', async () => {
    const sync = await encryptedSync()
    let preloginCalls = 0
    let mutationCalls = 0
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          preloginCalls += 1
          return preloginCalls === 1
            ? jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
            : jsonResponse({
                kdf: { type: 1, iterations: 2, memory: 16, parallelism: 1 },
                salt: EMAIL
              })
        }
        if (url.endsWith('/identity/connect/token'))
          return jsonResponse({
            access_token: 'access',
            refresh_token: 'refresh',
            expires_in: 3600
          })
        if (url.includes('/api/sync?')) return jsonResponse(sync)
        if (url.endsWith('/api/accounts/password')) {
          mutationCalls += 1
          throw new TypeError('connection dropped after upload')
        }
        return jsonResponse({ message: 'not found' }, 404)
      },
      maxRetries: 3
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http
    })
    await client.login({ email: EMAIL, password: PASSWORD })
    await client.sync()
    await expect(
      client.changeMasterPassword({
        currentPassword: PASSWORD,
        newPassword: 'replacement master password'
      })
    ).rejects.toMatchObject({ code: 'MASTER_PASSWORD_CHANGE_UNKNOWN' })
    expect(mutationCalls).toBe(1)
    await expect(client.status()).resolves.toEqual({ status: 'unauthenticated' })
    await expect(client.listPersonalLogins()).rejects.toMatchObject({ code: 'AUTH_REQUIRED' })
  })

  it('preserves unlocked state after a definitive password-change rejection', async () => {
    const sync = await encryptedSync()
    let mutationCalls = 0
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url) => {
        if (url.endsWith('/identity/accounts/prelogin/password'))
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        if (url.endsWith('/identity/connect/token'))
          return jsonResponse({
            access_token: 'access',
            refresh_token: 'refresh',
            expires_in: 3600
          })
        if (url.includes('/api/sync?')) return jsonResponse(sync)
        if (url.endsWith('/api/accounts/password')) {
          mutationCalls += 1
          return jsonResponse({ message: 'Invalid password' }, 400)
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
    await expect(
      client.changeMasterPassword({
        currentPassword: 'wrong password',
        newPassword: 'replacement master password'
      })
    ).rejects.toMatchObject({ code: 'AUTH_REQUIRED' })
    await expect(client.status()).resolves.toEqual({ status: 'unlocked' })
    await expect(client.listPersonalLogins()).resolves.not.toHaveLength(0)
    expect(mutationCalls).toBe(1)

    const abort = new AbortController()
    abort.abort()
    await expect(
      client.changeMasterPassword({
        currentPassword: PASSWORD,
        newPassword: 'another replacement password',
        signal: abort.signal
      })
    ).rejects.toMatchObject({ code: 'ABORTED' })
    await expect(client.status()).resolves.toEqual({ status: 'unlocked' })
  })

  it.each([
    ['V1', () => encryptedSync()],
    ['V2', () => encryptedV2Sync()]
  ])(
    'restores PIN-wrapped %s account material for sync without persisting the key',
    async (_version, createSync) => {
      const sync = await createSync()
      const createHttp = (): BitwardenHttpClient =>
        new BitwardenHttpClient({
          server: 'https://vault.example.invalid',
          fetch: async (url) => {
            if (url.endsWith('/identity/accounts/prelogin/password')) {
              return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
            }
            if (url.endsWith('/identity/connect/token')) {
              return jsonResponse({
                access_token: 'access',
                refresh_token: 'refresh',
                expires_in: 3600
              })
            }
            if (url.includes('/api/sync?')) return jsonResponse(sync)
            return jsonResponse({ message: 'not found' }, 404)
          }
        })
      const connected = new BitwardenDirectClient({
        serverUrl: 'https://vault.example.invalid',
        email: EMAIL,
        httpClient: createHttp()
      })
      await connected.login({ email: EMAIL, password: PASSWORD })
      await connected.sync()
      const persisted = connected.exportState()
      const pinMaterial = connected.pinUnlockMaterial()
      expect(pinMaterial).not.toBeNull()
      expect(persisted).not.toHaveProperty('accountKey')

      const resumed = new BitwardenDirectClient({
        serverUrl: 'https://vault.example.invalid',
        email: EMAIL,
        state: persisted,
        httpClient: createHttp()
      })
      resumed.restorePinUnlockMaterial(pinMaterial!)
      pinMaterial!.accountKey.fill(0)
      pinMaterial!.wrappedKeyFingerprint.fill(0)
      await expect(resumed.status()).resolves.toEqual({ status: 'unlocked' })
      await resumed.sync()
      await expect(resumed.listPersonalLogins()).resolves.toEqual(
        expect.arrayContaining([expect.objectContaining({ id: LOGIN_ID })])
      )
    }
  )

  it('rejects stale PIN account material when the remote wrapped key changes', async () => {
    const sync = await encryptedSync()
    const connectedHttp = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/identity/connect/token')) {
          return jsonResponse({
            access_token: 'access',
            refresh_token: 'refresh',
            expires_in: 3600
          })
        }
        if (url.includes('/api/sync?')) return jsonResponse(sync)
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const connected = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: connectedHttp
    })
    await connected.login({ email: EMAIL, password: PASSWORD })
    await connected.sync()
    const pinMaterial = connected.pinUnlockMaterial()!
    const rotated = structuredClone(sync)
    ;(rotated.profile as JsonObject).key = `${(rotated.profile as JsonObject).key}changed`
    const resumed = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      state: connected.exportState(),
      httpClient: new BitwardenHttpClient({
        server: 'https://vault.example.invalid',
        fetch: async () => jsonResponse(rotated)
      })
    })
    resumed.restorePinUnlockMaterial(pinMaterial)
    pinMaterial.accountKey.fill(0)
    pinMaterial.wrappedKeyFingerprint.fill(0)

    await expect(resumed.sync()).rejects.toMatchObject({ code: 'AUTH_REQUIRED' })
    await expect(resumed.status()).resolves.toEqual({ status: 'locked' })
  })

  it('decrypts current and legacy organization keys and keeps shared ciphers separate', async () => {
    const sync = await encryptedSync()
    const userKey = Buffer.alloc(64, 7)
    const organizationKey = Buffer.alloc(64, 11)
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const privateKey = rsa.privateKey.export({ format: 'der', type: 'pkcs8' })
    const encryptedOrganizationKey = publicEncrypt(
      {
        key: rsa.publicKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha1'
      },
      organizationKey
    )
    const legacyOrganizationKeyPayload = Buffer.from(organizationKey.toString('base64'))
    let encryptedLegacyOrganizationKey: Buffer
    try {
      encryptedLegacyOrganizationKey = publicEncrypt(
        {
          key: rsa.publicKey,
          padding: constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256'
        },
        legacyOrganizationKeyPayload
      )
    } finally {
      legacyOrganizationKeyPayload.fill(0)
    }
    const legacyOrganizationId = '66666666-6666-4666-8666-666666666666'
    const personalCipher = (sync.ciphers as JsonObject[])[0]!
    const sharedCipher: JsonObject = {
      ...personalCipher,
      id: ORGANIZATION_CIPHER_ID,
      organizationId: ORGANIZATION_ID,
      collectionIds: [COLLECTION_ID],
      folderId: null,
      name: encryptBitwardenString('Shared Example', Buffer.alloc(64, 9)),
      key: encryptBitwardenBytes(Buffer.alloc(64, 9), organizationKey),
      edit: true,
      viewPassword: false,
      permissions: { delete: true, restore: false }
    }
    sync.profile = {
      ...(sync.profile as JsonObject),
      privateKey: encryptBitwardenBytes(privateKey, userKey),
      organizations: [
        {
          id: ORGANIZATION_ID,
          name: 'Shared Team',
          key: `4.${encryptedOrganizationKey.toString('base64')}`,
          status: 0,
          type: 0,
          enabled: true,
          identifier: 'shared-team',
          hasPublicAndPrivateKeys: false
        },
        {
          id: legacyOrganizationId,
          name: 'Legacy Team',
          key: `3.${encryptedLegacyOrganizationKey.toString('base64')}`,
          status: 0,
          type: 0,
          enabled: true,
          identifier: 'legacy-team',
          hasPublicAndPrivateKeys: false
        }
      ]
    }
    sync.collections = [
      {
        id: COLLECTION_ID,
        organizationId: ORGANIZATION_ID,
        name: encryptBitwardenString('Shared Collection', organizationKey),
        externalId: null,
        readOnly: false,
        hidePasswords: false,
        manage: true,
        type: 0,
        assigned: true
      }
    ]
    sync.ciphers = [personalCipher, sharedCipher]
    privateKey.fill(0)
    encryptedOrganizationKey.fill(0)
    encryptedLegacyOrganizationKey.fill(0)
    userKey.fill(0)
    organizationKey.fill(0)

    let organizationUpdateRequest: JsonObject | null = null
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
            expires_in: 3_600
          })
        }
        if (url.includes('/api/sync?')) return jsonResponse(sync)
        if (init?.method === 'PUT' && url.endsWith(`/api/ciphers/${ORGANIZATION_CIPHER_ID}`)) {
          organizationUpdateRequest = JSON.parse(String(init.body)) as JsonObject
          return jsonResponse({
            ...sharedCipher,
            ...organizationUpdateRequest,
            id: ORGANIZATION_CIPHER_ID,
            organizationId: ORGANIZATION_ID,
            collectionIds: [COLLECTION_ID],
            revisionDate: '2026-07-14T00:00:00.000Z'
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
    await expect(client.listPersonalLogins()).resolves.toEqual([
      expect.objectContaining({ id: LOGIN_ID, name: 'Example' })
    ])
    await expect(client.listOrganizations()).resolves.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: ORGANIZATION_ID, name: 'Shared Team' }),
        expect.objectContaining({ id: legacyOrganizationId, name: 'Legacy Team' })
      ])
    )
    await expect(client.listCollections()).resolves.toEqual([
      expect.objectContaining({
        id: COLLECTION_ID,
        organizationId: ORGANIZATION_ID,
        name: 'Shared Collection'
      })
    ])
    await expect(client.listOrganizationCiphers()).resolves.toEqual([
      expect.objectContaining({
        id: ORGANIZATION_CIPHER_ID,
        organizationId: ORGANIZATION_ID,
        collectionIds: [COLLECTION_ID],
        name: 'Shared Example',
        username: 'bear@example.invalid',
        viewPassword: false,
        delete: true,
        restore: false
      })
    ])
    await expect(
      client.editOrganizationCipher(ORGANIZATION_CIPHER_ID, {
        name: 'Edited shared item',
        username: 'edited@example.invalid'
      })
    ).resolves.toMatchObject({
      id: ORGANIZATION_CIPHER_ID,
      organizationId: ORGANIZATION_ID,
      collectionIds: [COLLECTION_ID],
      name: 'Edited shared item',
      username: 'edited@example.invalid',
      edit: true
    })
    expect(organizationUpdateRequest).toMatchObject({
      organizationId: ORGANIZATION_ID,
      collectionIds: [COLLECTION_ID],
      folderId: null
    })
    await client.lock()
    await expect(
      client.editOrganizationCipher(ORGANIZATION_CIPHER_ID, { name: 'Locked edit' })
    ).rejects.toMatchObject({ code: 'AUTH_REQUIRED' })
  })

  it('decrypts provider-managed organization keys through the provider key', async () => {
    const sync = await encryptedSync()
    const userKey = Buffer.alloc(64, 7)
    const providerKey = Buffer.alloc(64, 12)
    const organizationKey = Buffer.alloc(64, 13)
    const itemKey = Buffer.alloc(64, 9)
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const privateKey = rsa.privateKey.export({ format: 'der', type: 'pkcs8' })
    const providerId = '77777777-7777-4777-8777-777777777777'
    const providerOrganizationId = '88888888-8888-4888-8888-888888888888'
    const encryptedProviderKey = publicEncrypt(
      {
        key: rsa.publicKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha1'
      },
      providerKey
    )
    const personalCipher = (sync.ciphers as JsonObject[])[0]!
    const providerCipher: JsonObject = {
      ...personalCipher,
      id: ORGANIZATION_CIPHER_ID,
      organizationId: providerOrganizationId,
      collectionIds: [],
      folderId: null,
      name: encryptBitwardenString('Provider item', itemKey),
      key: encryptBitwardenBytes(itemKey, organizationKey),
      edit: true,
      viewPassword: true,
      permissions: { delete: false, restore: false }
    }
    sync.profile = {
      ...(sync.profile as JsonObject),
      privateKey: encryptBitwardenBytes(privateKey, userKey),
      organizationsNew: [],
      organizations: [],
      providers: [
        {
          id: providerId,
          name: 'Managed provider',
          key: `4.${encryptedProviderKey.toString('base64')}`
        }
      ],
      providerOrganizations: [
        {
          id: providerOrganizationId,
          providerId,
          name: 'Provider team',
          key: encryptBitwardenBytes(organizationKey, providerKey),
          status: 0,
          type: 0,
          enabled: true,
          identifier: 'provider-team',
          hasPublicAndPrivateKeys: false
        }
      ]
    }
    sync.ciphers = [personalCipher, providerCipher]

    const client = await clientForSync(sync)
    await expect(client.listOrganizations()).resolves.toEqual([
      expect.objectContaining({ id: providerOrganizationId, name: 'Provider team' })
    ])
    await expect(client.listOrganizationCiphers()).resolves.toEqual([
      expect.objectContaining({
        id: ORGANIZATION_CIPHER_ID,
        organizationId: providerOrganizationId,
        name: 'Provider item'
      })
    ])

    privateKey.fill(0)
    encryptedProviderKey.fill(0)
    userKey.fill(0)
    providerKey.fill(0)
    organizationKey.fill(0)
    itemKey.fill(0)
  })

  it('falls back from an empty OrganizationsNew list to legacy organizations', async () => {
    const sync = await encryptedSync()
    const profile = sync.profile as JsonObject
    profile.organizationsNew = []
    profile.organizations = [
      {
        id: ORGANIZATION_ID,
        name: 'Legacy fallback team',
        status: 0,
        type: 0,
        enabled: true,
        identifier: null,
        hasPublicAndPrivateKeys: false
      }
    ]

    const client = await clientForSync(sync)
    await expect(client.listOrganizations()).resolves.toEqual([
      expect.objectContaining({ id: ORGANIZATION_ID, name: 'Legacy fallback team' })
    ])
  })

  it('syncs and decrypts personal text Sends while keeping the URL seed main-process-only', async () => {
    const sync = await encryptedSync()
    const userKey = Buffer.alloc(64, 7)
    const seed = Buffer.alloc(16, 3)
    const sendKey = deriveBitwardenSendKey(seed)
    const send: JsonObject = {
      id: SEND_ID,
      accessId: 'UAAAAAAAQABAAAAAAAAAAQ',
      type: 0,
      key: encryptBitwardenBytes(seed, userKey),
      name: encryptBitwardenString('One-time note', sendKey),
      notes: encryptBitwardenString('Owner note', sendKey),
      text: { text: encryptBitwardenString('shared text', sendKey), hidden: false },
      maxAccessCount: null,
      accessCount: 0,
      revisionDate: '2026-07-16T00:00:00.000Z',
      expirationDate: null,
      deletionDate: '2026-07-30T00:00:00.000Z',
      authType: 1,
      password: 'existing-password-proof',
      disabled: false,
      hideEmail: true
    }
    sync.sends = [send]
    let updateBody: JsonObject | null = null
    const fetch = vi.fn<FetchLike>().mockImplementation(async (url, init) => {
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      if (url.endsWith('/identity/connect/token')) {
        return jsonResponse({
          access_token: 'access-token',
          refresh_token: 'refresh-token',
          expires_in: 3_600
        })
      }
      if (url.includes('/api/sync?')) return jsonResponse(sync)
      if (url.endsWith('/api/sends')) return jsonResponse(send)
      if (url.endsWith('/api/sends/' + SEND_ID) && init?.method === 'PUT') {
        updateBody = JSON.parse(String(init.body)) as JsonObject
        return jsonResponse(send)
      }
      if (url.endsWith('/api/sends/' + SEND_ID) && init?.method === 'DELETE') {
        return new Response(null, { status: 204 })
      }
      return jsonResponse({ message: 'not found' }, 404)
    })
    const http = new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http
    })
    await client.login({ email: EMAIL, password: PASSWORD })
    await client.sync()
    await expect(client.listSends()).resolves.toEqual([
      expect.objectContaining({
        id: SEND_ID,
        name: 'One-time note',
        text: 'shared text',
        notes: 'Owner note',
        passwordProtected: true
      })
    ])
    const copy = vi.fn()
    await client.copySendLink(SEND_ID, copy)
    expect(copy).toHaveBeenCalledWith(
      `https://vault.example.invalid/#/send/UAAAAAAAQABAAAAAAAAAAQ/${Buffer.alloc(16, 3).toString('base64url')}`
    )
    expect(JSON.stringify(await client.listSends())).not.toContain(seed.toString('base64url'))
    await client.updateSend(SEND_ID, {
      name: 'Updated note',
      notes: 'Owner note',
      text: 'shared text',
      hidden: false,
      maxAccessCount: null,
      expirationDate: null,
      deletionDate: '2026-07-30T00:00:00.000Z',
      disabled: false,
      hideEmail: true
    })
    expect(updateBody).toMatchObject({ authType: 1, password: 'existing-password-proof' })
    seed.fill(0)
    sendKey.fill(0)
    userKey.fill(0)
  })

  it('preserves Email OTP authentication when updating Send metadata', async () => {
    const sync = await encryptedSync()
    const userKey = Buffer.alloc(64, 7)
    const seed = Buffer.alloc(16, 6)
    const sendKey = deriveBitwardenSendKey(seed)
    const send: JsonObject = {
      id: SEND_ID,
      accessId: 'UAAAAAAAQABAAAAAAAAAAQ',
      type: 0,
      key: encryptBitwardenBytes(seed, userKey),
      name: encryptBitwardenString('Verified note', sendKey),
      notes: null,
      text: { text: encryptBitwardenString('shared text', sendKey), hidden: true },
      maxAccessCount: 2,
      accessCount: 0,
      revisionDate: '2026-07-16T00:00:00.000Z',
      expirationDate: null,
      deletionDate: '2026-07-30T00:00:00.000Z',
      authType: 0,
      password: null,
      emails: 'recipient@example.invalid',
      disabled: false,
      hideEmail: true
    }
    sync.sends = [send]
    let updateBody: JsonObject | null = null
    const fetch = vi.fn<FetchLike>().mockImplementation(async (url, init) => {
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      if (url.endsWith('/identity/connect/token')) {
        return jsonResponse({
          access_token: 'access-token',
          refresh_token: 'refresh-token',
          expires_in: 3_600
        })
      }
      if (url.includes('/api/sync?')) return jsonResponse(sync)
      if (url.endsWith(`/api/sends/${SEND_ID}`) && init?.method === 'PUT') {
        updateBody = JSON.parse(String(init.body)) as JsonObject
        return jsonResponse(send)
      }
      return jsonResponse({ message: 'not found' }, 404)
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch })
    })

    await client.login({ email: EMAIL, password: PASSWORD })
    await client.sync()
    await expect(client.listSends()).resolves.toEqual([
      expect.objectContaining({ authType: 0, passwordProtected: false })
    ])
    await client.updateSend(SEND_ID, {
      name: 'Updated verified note',
      notes: null,
      text: 'shared text',
      hidden: true,
      maxAccessCount: 2,
      expirationDate: null,
      deletionDate: '2026-07-30T00:00:00.000Z',
      disabled: false,
      hideEmail: true
    })
    expect(updateBody).toMatchObject({
      authType: 0,
      password: null,
      emails: 'recipient@example.invalid'
    })
    expect(JSON.stringify(await client.listSends())).not.toContain('recipient@example.invalid')
    seed.fill(0)
    sendKey.fill(0)
    userKey.fill(0)
  })

  it('syncs file Send metadata without exposing encrypted bytes or URL capabilities', async () => {
    const sync = await encryptedSync()
    const userKey = Buffer.alloc(64, 7)
    const seed = Buffer.alloc(16, 4)
    const sendKey = deriveBitwardenSendKey(seed)
    const send: JsonObject = {
      id: SEND_ID,
      accessId: 'UAAAAAAAQABAAAAAAAAAAQ',
      type: 1,
      key: encryptBitwardenBytes(seed, userKey),
      name: encryptBitwardenString('Encrypted archive', sendKey),
      notes: null,
      file: {
        id: '0123456789abcdef0123456789abcdef',
        fileName: encryptBitwardenString('archive.txt', sendKey),
        size: '1234',
        sizeName: '1.2 KB'
      },
      maxAccessCount: null,
      accessCount: 0,
      revisionDate: '2026-07-16T00:00:00.000Z',
      expirationDate: null,
      deletionDate: '2026-07-30T00:00:00.000Z',
      authType: 2,
      password: null,
      disabled: false,
      hideEmail: true
    }
    sync.sends = [send]
    const fetch = vi.fn<FetchLike>().mockImplementation(async (url) => {
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      if (url.endsWith('/identity/connect/token')) {
        return jsonResponse({
          access_token: 'access-token',
          refresh_token: 'refresh-token',
          expires_in: 3_600
        })
      }
      if (url.includes('/api/sync?')) return jsonResponse(sync)
      if (url.endsWith('/api/sends')) return jsonResponse(send)
      return jsonResponse({ message: 'not found' }, 404)
    })
    const http = new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http
    })

    await client.login({ email: EMAIL, password: PASSWORD })
    await client.sync()
    await expect(client.listSends()).resolves.toEqual([
      expect.objectContaining({
        id: SEND_ID,
        type: 'file',
        name: 'Encrypted archive',
        text: '',
        file: {
          id: '0123456789abcdef0123456789abcdef',
          fileName: 'archive.txt',
          size: 1234,
          sizeName: '1.2 KB'
        }
      })
    ])
    expect(JSON.stringify(await client.listSends())).not.toContain(seed.toString('base64url'))
    expect(JSON.stringify(await client.listSends())).not.toContain('fileUpload')
    seed.fill(0)
    sendKey.fill(0)
    userKey.fill(0)
  })

  it('creates a file Send through Direct multipart upload and validates the authoritative reload', async () => {
    const sync = await encryptedSync()
    sync.sends = []
    const userKey = Buffer.alloc(64, 7)
    const fileId = '0123456789abcdef0123456789abcdef'
    let created: JsonObject | null = null
    const fetch = vi.fn<FetchLike>().mockImplementation(async (url, init) => {
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      if (url.endsWith('/identity/connect/token')) {
        return jsonResponse({
          access_token: 'access-token',
          refresh_token: 'refresh-token',
          expires_in: 3_600
        })
      }
      if (url.includes('/api/sync?'))
        return jsonResponse({ ...sync, sends: created ? [created] : [] })
      if (url.endsWith('/api/sends/file/v2')) {
        const request = JSON.parse(String(init?.body)) as JsonObject
        created = {
          ...request,
          id: SEND_ID,
          accessId: 'UAAAAAAAQABAAAAAAAAAAQ',
          file: {
            ...(request.file as JsonObject),
            id: fileId,
            size: request.fileLength,
            sizeName: 'encrypted bytes'
          },
          accessCount: 0,
          revisionDate: '2026-07-16T00:00:00.000Z',
          expirationDate: null,
          deletionDate: '2026-07-30T00:00:00.000Z'
        }
        return jsonResponse({
          object: 'send-fileUpload',
          fileUploadType: 0,
          url: `/api/sends/${SEND_ID}/file/${fileId}`,
          sendResponse: created
        })
      }
      if (url.endsWith(`/api/sends/${SEND_ID}/file/${fileId}`)) {
        expect(init?.method).toBe('POST')
        expect(init?.body).toBeInstanceOf(FormData)
        return new Response(null, { status: 204 })
      }
      if (url.endsWith('/api/sends')) return jsonResponse(created ? [created] : [])
      if (url.endsWith(`/api/sends/${SEND_ID}`) && init?.method === 'DELETE') {
        return new Response(null, { status: 204 })
      }
      return jsonResponse({ message: 'not found' }, 404)
    })
    const http = new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http
    })
    await client.login({ email: EMAIL, password: PASSWORD })
    await client.sync()

    const plaintext = Buffer.from('file send payload')
    const saved = await client.createFileSend({
      name: 'File Send',
      notes: null,
      fileName: 'payload.txt',
      data: plaintext,
      maxAccessCount: null,
      expirationDate: null,
      deletionDate: '2026-07-30T00:00:00.000Z',
      password: null,
      disabled: false,
      hideEmail: true
    })
    expect(saved).toMatchObject({
      id: SEND_ID,
      type: 'file',
      file: { id: fileId, fileName: 'payload.txt' }
    })
    const createCall = fetch.mock.calls.find(([url]) => url.endsWith('/api/sends/file/v2'))
    const createRequest = JSON.parse(String(createCall?.[1]?.body)) as JsonObject
    const seed = decryptBitwardenBytes(String(createRequest.key), userKey)
    const sendKey = deriveBitwardenSendKey(seed)
    const uploadCall = fetch.mock.calls.find(([url]) =>
      url.endsWith(`/api/sends/${SEND_ID}/file/${fileId}`)
    )
    const form = uploadCall?.[1]?.body as FormData
    const uploadedBlob = form.get('data')
    expect(uploadedBlob).toBeInstanceOf(Blob)
    expect((uploadedBlob as File).name).toBe(String((createRequest.file as JsonObject).fileName))
    const encryptedBytes = Buffer.from(await (uploadedBlob as Blob).arrayBuffer())
    expect(decryptBitwardenAttachmentBuffer(encryptedBytes, sendKey)).toEqual(plaintext)
    expect(JSON.stringify(saved)).not.toContain(seed.toString('base64url'))
    encryptedBytes.fill(0)
    sendKey.fill(0)
    seed.fill(0)
    plaintext.fill(0)
    userKey.fill(0)
  })

  it('downloads a file Send through legacy access and decrypts bytes only in main', async () => {
    const sync = await encryptedSync()
    const userKey = Buffer.alloc(64, 7)
    const seed = Buffer.alloc(16, 5)
    const sendKey = deriveBitwardenSendKey(seed)
    const plaintext = Buffer.from('downloaded Send file')
    const encryptedFile = encryptBitwardenAttachmentBuffer(plaintext, sendKey)
    const fileId = 'fedcba9876543210fedcba9876543210'
    const send: JsonObject = {
      id: SEND_ID,
      accessId: 'UAAAAAAAQABAAAAAAAAAAQ',
      type: 1,
      key: encryptBitwardenBytes(seed, userKey),
      name: encryptBitwardenString('Download archive', sendKey),
      notes: null,
      file: {
        id: fileId,
        fileName: encryptBitwardenString('download.txt', sendKey),
        size: String(encryptedFile.length),
        sizeName: `${encryptedFile.length} B`
      },
      maxAccessCount: null,
      accessCount: 0,
      revisionDate: '2026-07-16T00:00:00.000Z',
      expirationDate: null,
      deletionDate: '2026-07-30T00:00:00.000Z',
      authType: 1,
      password: 'password-proof',
      disabled: false,
      hideEmail: true
    }
    sync.sends = [send]
    const fetch = vi.fn<FetchLike>().mockImplementation(async (url, init) => {
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      if (url.endsWith('/identity/connect/token')) {
        return jsonResponse({
          access_token: 'access-token',
          refresh_token: 'refresh-token',
          expires_in: 3_600
        })
      }
      if (url.includes('/api/sync?')) return jsonResponse(sync)
      if (url.endsWith('/api/sends')) return jsonResponse(send)
      if (url.endsWith(`/api/sends/access/${send.accessId}`)) {
        expect(init?.method).toBe('POST')
        expect(JSON.parse(String(init?.body))).toEqual({ password: 'send-password' })
        return jsonResponse({
          id: SEND_ID,
          type: 1,
          name: send.name,
          file: send.file,
          expirationDate: null,
          creatorIdentifier: 'creator'
        })
      }
      if (url.endsWith(`/api/sends/${SEND_ID}/access/file/${fileId}`)) {
        expect(init?.method).toBe('POST')
        expect(JSON.parse(String(init?.body))).toEqual({ password: 'send-password' })
        return jsonResponse({ id: fileId, url: `/api/sends/${SEND_ID}/${fileId}?t=capability` })
      }
      if (url.includes(`/api/sends/${SEND_ID}/${fileId}`)) {
        expect(init?.method).toBe('GET')
        return new Response(new Blob([new Uint8Array(encryptedFile)]), { status: 200 })
      }
      return jsonResponse({ message: 'not found' }, 404)
    })
    const http = new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http
    })
    await client.login({ email: EMAIL, password: PASSWORD })
    await client.sync()
    const downloaded = await client.downloadFileSend(SEND_ID, 'send-password')
    expect(downloaded.fileName).toBe('download.txt')
    expect(downloaded.data).toEqual(plaintext)
    downloaded.data.fill(0)
    encryptedFile.fill(0)
    plaintext.fill(0)
    sendKey.fill(0)
    seed.fill(0)
    userKey.fill(0)
  })

  it('passes authenticated account-breach reports through without requiring decrypted vault keys', async () => {
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url) => {
        if (url.endsWith('/api/hibp/breach?username=person%40example.test')) {
          return jsonResponse([])
        }
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: null,
        securityStamp: null
      }
    })

    await expect(client.getAccountBreachReport('person@example.test')).resolves.toEqual({
      status: 'complete',
      breaches: []
    })
    await expect(client.status()).resolves.toEqual({ status: 'locked' })
  })

  it('updates personal profile fields with stale checks and response-loss reconciliation', async () => {
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async () => jsonResponse({ message: 'not found' }, 404)
    })
    const baseProfile = {
      id: PROFILE_ID,
      name: 'Before',
      email: EMAIL,
      avatarColor: '#112233',
      emailVerified: true,
      twoFactorEnabled: false
    }
    const profile = vi
      .spyOn(http, 'getAccountSecurityProfile')
      .mockResolvedValueOnce(baseProfile)
      .mockResolvedValueOnce({ ...baseProfile, name: 'After' })
      .mockResolvedValueOnce({ ...baseProfile, name: 'Concurrent edit' })
      .mockResolvedValueOnce({ ...baseProfile, avatarColor: '#AABBCC' })
    const updateName = vi
      .spyOn(http, 'updateAccountProfileName')
      .mockRejectedValueOnce(new BitwardenHttpError('NETWORK'))
    const updateAvatar = vi.spyOn(http, 'updateAccountAvatarColor').mockResolvedValue({
      ...baseProfile,
      avatarColor: '#AABBCC'
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.updateAccountProfileName('After', 'Before')).resolves.toMatchObject({
      name: 'After'
    })
    await expect(client.updateAccountProfileName('Ignored', 'Before')).rejects.toMatchObject({
      code: 'ACCOUNT_PROFILE_STALE'
    })
    await expect(client.updateAccountAvatarColor('#aabbcc', '#aabbcc')).resolves.toMatchObject({
      avatarColor: '#AABBCC'
    })
    expect(updateName).toHaveBeenCalledOnce()
    expect(updateAvatar).toHaveBeenCalledWith('#AABBCC', undefined)
    expect(profile).toHaveBeenCalledTimes(4)
  })

  it('does not replay an ambiguous profile mutation when reconciliation differs', async () => {
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async () => jsonResponse({ message: 'not found' }, 404)
    })
    const current = {
      id: PROFILE_ID,
      name: 'Before',
      email: EMAIL,
      avatarColor: null,
      emailVerified: true,
      twoFactorEnabled: false
    }
    vi.spyOn(http, 'getAccountSecurityProfile')
      .mockResolvedValueOnce(current)
      .mockResolvedValueOnce(current)
    const update = vi
      .spyOn(http, 'updateAccountProfileName')
      .mockRejectedValue(new BitwardenHttpError('NETWORK'))
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.updateAccountProfileName('After', 'Before')).rejects.toMatchObject({
      code: 'ACCOUNT_PROFILE_MUTATION_UNKNOWN'
    })
    expect(update).toHaveBeenCalledOnce()
  })

  it('purges the personal vault with a fresh KDF-derived proof while preserving lock state', async () => {
    const proofs: string[] = []
    const onStateChanged = vi.fn()
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async () => jsonResponse({ message: 'not found' }, 404)
    })
    vi.spyOn(http, 'prelogin').mockResolvedValue({
      kdfType: 0,
      iterations: 6_000,
      memory: null,
      parallelism: null,
      salt: 'account-specific-salt',
      raw: {}
    })
    vi.spyOn(http, 'purgePersonalVault').mockImplementation(async (proof) => {
      proofs.push(proof)
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      onStateChanged,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.purgePersonalVault(PASSWORD)).resolves.toBeUndefined()
    expect(http.prelogin).toHaveBeenCalledTimes(1)
    expect(http.purgePersonalVault).toHaveBeenCalledTimes(1)
    const masterKey = await deriveMasterKey(PASSWORD, 'account-specific-salt', {
      type: 'pbkdf2',
      iterations: 6_000
    })
    const passwordKey = await derivePasswordKey(masterKey, PASSWORD)
    try {
      expect(proofs).toEqual([passwordKey.toString('base64')])
      expect(proofs[0]).not.toBe(PASSWORD)
    } finally {
      masterKey.fill(0)
      passwordKey.fill(0)
      proofs.fill('')
    }
    expect(onStateChanged).toHaveBeenCalledTimes(1)
    await expect(client.status()).resolves.toEqual({ status: 'locked' })
  })

  it('does not clear an unlocked local cache after the purge POST succeeds', async () => {
    const sync = await encryptedSync()
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/identity/connect/token')) {
          return jsonResponse({
            access_token: 'access',
            refresh_token: 'refresh',
            expires_in: 3_600
          })
        }
        if (url.includes('/api/sync?')) return jsonResponse(sync)
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const purge = vi.spyOn(http, 'purgePersonalVault').mockResolvedValue()
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http
    })
    await client.login({ email: EMAIL, password: PASSWORD })
    await client.sync()
    const before = await client.listPersonalLogins()

    await client.purgePersonalVault(PASSWORD)

    expect(purge).toHaveBeenCalledTimes(1)
    await expect(client.status()).resolves.toEqual({ status: 'unlocked' })
    await expect(client.listPersonalLogins()).resolves.toEqual(before)
  })

  it('requires authenticated profile ownership before deriving a purge proof', async () => {
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async () => jsonResponse({ message: 'not found' }, 404)
    })
    const prelogin = vi.spyOn(http, 'prelogin')
    const purge = vi.spyOn(http, 'purgePersonalVault')
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: null,
        securityStamp: null
      }
    })

    await expect(client.purgePersonalVault(PASSWORD)).rejects.toMatchObject({
      code: 'AUTH_REQUIRED'
    })
    expect(prelogin).not.toHaveBeenCalled()
    expect(purge).not.toHaveBeenCalled()
  })

  it('distinguishes purge preflight and verification failures from unknown POST outcomes', async () => {
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async () => jsonResponse({ message: 'not found' }, 404)
    })
    vi.spyOn(http, 'prelogin').mockResolvedValue({
      kdfType: 0,
      iterations: 5_000,
      memory: null,
      parallelism: null,
      salt: EMAIL,
      raw: {}
    })
    const purge = vi.spyOn(http, 'purgePersonalVault')
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    vi.mocked(http.prelogin).mockRejectedValueOnce(new BitwardenHttpError('NETWORK'))
    await expect(client.purgePersonalVault(PASSWORD)).rejects.toMatchObject({ code: 'NETWORK' })
    expect(purge).not.toHaveBeenCalled()

    purge.mockRejectedValueOnce(new BitwardenHttpError('USER_VERIFICATION_FAILED'))
    await expect(client.purgePersonalVault(PASSWORD)).rejects.toMatchObject({
      code: 'USER_VERIFICATION_FAILED'
    })

    purge.mockRejectedValueOnce(new BitwardenHttpError('NETWORK'))
    await expect(client.purgePersonalVault(PASSWORD)).rejects.toMatchObject({
      code: 'VAULT_PURGE_UNKNOWN'
    })

    purge.mockRejectedValueOnce(new BitwardenHttpError('ABORTED'))
    await expect(client.purgePersonalVault(PASSWORD)).rejects.toMatchObject({
      code: 'VAULT_PURGE_UNKNOWN'
    })
    expect(purge).toHaveBeenCalledTimes(3)
    await expect(client.status()).resolves.toEqual({ status: 'locked' })
  })

  it('rejects invalid purge secrets and a pre-aborted request before starting the POST', async () => {
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async () => jsonResponse({ message: 'not found' }, 404)
    })
    vi.spyOn(http, 'prelogin').mockResolvedValue({
      kdfType: 0,
      iterations: 5_000,
      memory: null,
      parallelism: null,
      salt: EMAIL,
      raw: {}
    })
    const purge = vi.spyOn(http, 'purgePersonalVault')
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.purgePersonalVault('')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    await expect(client.purgePersonalVault('x'.repeat(16_385))).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    expect(http.prelogin).not.toHaveBeenCalled()

    const controller = new AbortController()
    controller.abort()
    await expect(client.purgePersonalVault(PASSWORD, controller.signal)).rejects.toMatchObject({
      code: 'ABORTED'
    })
    expect(purge).not.toHaveBeenCalled()
  })

  it('deauthorizes every session with a fresh proof and clears local authenticated state', async () => {
    const sync = await encryptedSync()
    const requestBodies: JsonObject[] = []
    const stateChanges: Array<ReturnType<BitwardenDirectClient['exportState']>> = []
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url, init) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/identity/connect/token')) {
          return jsonResponse({
            access_token: 'access',
            refresh_token: 'refresh',
            expires_in: 3600
          })
        }
        if (url.includes('/api/sync?')) return jsonResponse(sync)
        if (url.endsWith('/api/accounts/security-stamp')) {
          requestBodies.push(JSON.parse(String(init?.body)) as JsonObject)
          return new Response(null, { status: 204 })
        }
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      onStateChanged: (state) => {
        stateChanges.push(structuredClone(state))
      }
    })
    await client.login({ email: EMAIL, password: PASSWORD })
    await client.sync()
    await expect(client.listPersonalLogins()).resolves.toHaveLength(1)
    const before = client.exportState()
    stateChanges.splice(0)

    await expect(client.deauthorizeAllSessions(PASSWORD)).resolves.toBeUndefined()

    const expectedMasterKey = await deriveMasterKey(PASSWORD, EMAIL, {
      type: 'pbkdf2',
      iterations: 5_000
    })
    const expectedPasswordKey = await derivePasswordKey(expectedMasterKey, PASSWORD)
    try {
      expect(requestBodies).toEqual([
        { masterPasswordHash: expectedPasswordKey.toString('base64') }
      ])
    } finally {
      expectedMasterKey.fill(0)
      expectedPasswordKey.fill(0)
    }
    await expect(client.status()).resolves.toEqual({ status: 'unauthenticated' })
    await expect(client.listPersonalLogins()).rejects.toMatchObject({ code: 'AUTH_REQUIRED' })
    expect(client.exportState()).toEqual({
      session: null,
      deviceIdentifier: before.deviceIdentifier,
      profileId: PROFILE_ID,
      securityStamp: null,
      policySet: { source: 'none', policies: [] }
    })
    expect(http.exportSession()).toBeNull()
    expect(stateChanges).toEqual([client.exportState()])
  })

  it('preserves the session after deauthorization preflight and definitive proof failures', async () => {
    const session = {
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: Date.now() + 60_000
    }
    const onStateChanged = vi.fn()
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async () => jsonResponse({ message: 'not found' }, 404)
    })
    const prelogin = vi.spyOn(http, 'prelogin').mockResolvedValue({
      kdfType: 0,
      iterations: 5_000,
      memory: null,
      parallelism: null,
      salt: EMAIL,
      raw: {}
    })
    const deauthorize = vi
      .spyOn(http, 'deauthorizeAllSessions')
      .mockRejectedValue(new BitwardenHttpError('USER_VERIFICATION_FAILED', 400))
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      onStateChanged,
      state: {
        session,
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.deauthorizeAllSessions('wrong password')).rejects.toMatchObject({
      code: 'USER_VERIFICATION_FAILED'
    })
    expect(client.exportState()).toEqual({
      session,
      deviceIdentifier: '00000000-0000-4000-8000-000000000000',
      profileId: PROFILE_ID,
      securityStamp: 'security-stamp',
      policySet: { source: 'none', policies: [] }
    })
    expect(http.exportSession()).toEqual(session)
    expect(onStateChanged).not.toHaveBeenCalled()

    prelogin.mockRejectedValueOnce(new BitwardenHttpError('NETWORK'))
    await expect(client.deauthorizeAllSessions(PASSWORD)).rejects.toMatchObject({ code: 'NETWORK' })
    expect(deauthorize).toHaveBeenCalledTimes(1)

    const controller = new AbortController()
    controller.abort()
    await expect(client.deauthorizeAllSessions(PASSWORD, controller.signal)).rejects.toMatchObject({
      code: 'ABORTED'
    })
    expect(deauthorize).toHaveBeenCalledTimes(1)
    expect(client.exportState().session).toEqual(session)
    expect(onStateChanged).not.toHaveBeenCalled()

    deauthorize.mockRejectedValueOnce(new BitwardenHttpError('ABORTED'))
    await expect(client.deauthorizeAllSessions(PASSWORD)).rejects.toMatchObject({
      code: 'ABORTED'
    })
    expect(deauthorize).toHaveBeenCalledTimes(2)
    expect(client.exportState().session).toEqual(session)
    expect(onStateChanged).not.toHaveBeenCalled()
  })

  it.each([
    ['response loss', new BitwardenHttpError('NETWORK')],
    ['invalid response', new BitwardenHttpError('INVALID_RESPONSE')],
    ['abort after dispatch', new BitwardenHttpError('ABORTED')]
  ])('fails closed after an ambiguous deauthorization %s', async (_label, failure) => {
    const session = {
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: Date.now() + 60_000
    }
    const stateChanges: Array<ReturnType<BitwardenDirectClient['exportState']>> = []
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async () => jsonResponse({ message: 'not found' }, 404)
    })
    vi.spyOn(http, 'prelogin').mockResolvedValue({
      kdfType: 0,
      iterations: 5_000,
      memory: null,
      parallelism: null,
      salt: EMAIL,
      raw: {}
    })
    const deauthorize = vi
      .spyOn(http, 'deauthorizeAllSessions')
      .mockImplementation(async (_proof, _signal, onDispatch) => {
        onDispatch?.()
        throw failure
      })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      onStateChanged: (state) => {
        stateChanges.push(structuredClone(state))
      },
      state: {
        session,
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.deauthorizeAllSessions(PASSWORD)).rejects.toMatchObject({
      code: 'SESSION_DEAUTHORIZATION_UNKNOWN'
    })
    expect(deauthorize).toHaveBeenCalledTimes(1)
    await expect(client.status()).resolves.toEqual({ status: 'unauthenticated' })
    expect(client.exportState()).toEqual({
      session: null,
      deviceIdentifier: '00000000-0000-4000-8000-000000000000',
      profileId: PROFILE_ID,
      securityStamp: null,
      policySet: { source: 'none', policies: [] }
    })
    expect(http.exportSession()).toBeNull()
    expect(stateChanges).toEqual([client.exportState()])
  })

  it('rejects invalid deauthorization inputs before deriving or dispatching', async () => {
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async () => jsonResponse({ message: 'not found' }, 404)
    })
    const prelogin = vi.spyOn(http, 'prelogin')
    const deauthorize = vi.spyOn(http, 'deauthorizeAllSessions')
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: null,
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.deauthorizeAllSessions(PASSWORD)).rejects.toMatchObject({
      code: 'AUTH_REQUIRED'
    })
    await expect(client.deauthorizeAllSessions('')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    await expect(client.deauthorizeAllSessions('x'.repeat(16_385))).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    expect(prelogin).not.toHaveBeenCalled()
    expect(deauthorize).not.toHaveBeenCalled()
  })

  it('derives a fresh master-password proof for personal API key access without unlocking', async () => {
    const requestBodies: JsonObject[] = []
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url, init) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/api/accounts/api-key')) {
          requestBodies.push(JSON.parse(String(init?.body)))
          return jsonResponse({
            apiKey: 'personal-client-secret',
            revisionDate: '2026-07-16T00:00:00Z',
            object: 'apiKey'
          })
        }
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: '90000000-0000-4000-8000-000000000099',
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.getPersonalApiKey(PASSWORD, false)).resolves.toEqual({
      clientId: 'user.90000000-0000-4000-8000-000000000099',
      clientSecret: 'personal-client-secret',
      revisionDate: '2026-07-16T00:00:00Z'
    })
    expect(requestBodies).toHaveLength(1)
    const expectedMasterKey = await deriveMasterKey(PASSWORD, EMAIL, {
      type: 'pbkdf2',
      iterations: 5_000
    })
    const expectedPasswordKey = await derivePasswordKey(expectedMasterKey, PASSWORD)
    try {
      expect(requestBodies[0]?.masterPasswordHash).toBe(expectedPasswordKey.toString('base64'))
      expect(requestBodies[0]?.masterPasswordHash).not.toBe(PASSWORD)
    } finally {
      expectedMasterKey.fill(0)
      expectedPasswordKey.fill(0)
    }
    await expect(client.status()).resolves.toEqual({ status: 'locked' })
  })

  it('reports an unknown rotation outcome without retrying the POST', async () => {
    let rotationRequests = 0
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/api/accounts/rotate-api-key')) {
          rotationRequests += 1
          throw new TypeError('connection closed after request write')
        }
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: '90000000-0000-4000-8000-000000000099',
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.getPersonalApiKey(PASSWORD, true)).rejects.toMatchObject({
      code: 'API_KEY_ROTATION_UNKNOWN'
    })
    expect(rotationRequests).toBe(1)
  })

  it('derives a fresh proof to retrieve the 2FA recovery code without unlocking', async () => {
    const requestBodies: JsonObject[] = []
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url, init) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/api/two-factor/get-recover')) {
          requestBodies.push(JSON.parse(String(init?.body)))
          return jsonResponse({ code: 'RECOVERY-CODE', object: 'twoFactorRecover' })
        }
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: '90000000-0000-4000-8000-000000000099',
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.getTwoFactorRecoveryCode(PASSWORD)).resolves.toBe('RECOVERY-CODE')
    const masterKey = await deriveMasterKey(PASSWORD, EMAIL, {
      type: 'pbkdf2',
      iterations: 5_000
    })
    const passwordKey = await derivePasswordKey(masterKey, PASSWORD)
    try {
      expect(requestBodies[0]?.masterPasswordHash).toBe(passwordKey.toString('base64'))
    } finally {
      masterKey.fill(0)
      passwordKey.fill(0)
    }
    await expect(client.status()).resolves.toEqual({ status: 'locked' })
  })

  it('disables official Authenticator and Vaultwarden Email with fresh provider-bound proof', async () => {
    const requests: Array<{ url: string; method: string; body: JsonObject }> = []
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url, init) => {
        const method = init?.method ?? 'GET'
        const body = init?.body ? (JSON.parse(String(init.body)) as JsonObject) : {}
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        requests.push({ url, method, body })
        if (url.endsWith('/api/two-factor/get-authenticator')) {
          return jsonResponse({
            authenticator: {
              enabled: true,
              key: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
            },
            userVerificationToken: 'authenticator-capability'
          })
        }
        if (url.endsWith('/api/two-factor/authenticator') && method === 'DELETE') {
          return new Response(null, { status: 204 })
        }
        if (url.endsWith('/api/two-factor/get-email')) {
          return jsonResponse({
            enabled: true,
            email: EMAIL,
            object: 'twoFactorEmail'
          })
        }
        if (url.endsWith('/api/two-factor/disable')) {
          return jsonResponse({ enabled: false, type: 1, object: 'twoFactorProvider' })
        }
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    await client.disableTwoFactorProvider(0, PASSWORD)
    await client.disableTwoFactorProvider(1, PASSWORD)
    const masterKey = await deriveMasterKey(PASSWORD, EMAIL, {
      type: 'pbkdf2',
      iterations: 5_000
    })
    const passwordKey = await derivePasswordKey(masterKey, PASSWORD)
    try {
      const proof = passwordKey.toString('base64')
      expect(requests).toEqual([
        {
          url: 'https://vault.example.invalid/api/two-factor/get-authenticator',
          method: 'POST',
          body: { masterPasswordHash: proof }
        },
        {
          url: 'https://vault.example.invalid/api/two-factor/authenticator',
          method: 'DELETE',
          body: {
            userVerificationToken: 'authenticator-capability',
            key: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
          }
        },
        {
          url: 'https://vault.example.invalid/api/two-factor/get-email',
          method: 'POST',
          body: { masterPasswordHash: proof }
        },
        {
          url: 'https://vault.example.invalid/api/two-factor/disable',
          method: 'POST',
          body: { type: 1, masterPasswordHash: proof }
        }
      ])
    } finally {
      masterKey.fill(0)
      passwordKey.fill(0)
    }
  })

  it('rejects unsupported disable providers and distinguishes preflight failure from unknown mutation', async () => {
    let mutationRequests = 0
    let failPreflight = false
    const fetch = vi.fn<FetchLike>().mockImplementation(async (url) => {
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        if (failPreflight) throw new TypeError('offline before proof')
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      if (url.endsWith('/api/two-factor/get-authenticator')) {
        return jsonResponse({
          enabled: true,
          key: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
          object: 'twoFactorAuthenticator'
        })
      }
      if (url.endsWith('/api/two-factor/disable')) {
        mutationRequests += 1
        throw new TypeError('connection closed after request write')
      }
      return jsonResponse({ message: 'not found' }, 404)
    })
    const http = new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.disableTwoFactorProvider(0, PASSWORD)).rejects.toMatchObject({
      code: 'TWO_FACTOR_MUTATION_UNKNOWN'
    })
    expect(mutationRequests).toBe(1)

    failPreflight = true
    await expect(client.disableTwoFactorProvider(1, PASSWORD)).rejects.toMatchObject({
      code: 'NETWORK'
    })
    expect(mutationRequests).toBe(1)

    for (const type of [4, 5, 6, 8]) {
      await expect(client.disableTwoFactorProvider(type as 0, PASSWORD)).rejects.toMatchObject({
        code: 'INVALID_RESPONSE'
      })
    }
    expect(fetch).toHaveBeenCalledTimes(5)
  })

  it('uses the fresh generic proof as the YubiKey escape hatch when Vaultwarden config is unusable', async () => {
    let mutationBody: JsonObject | null = null
    const fetch = vi.fn<FetchLike>(async (url, init) => {
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      if (url.endsWith('/api/two-factor/get-yubikey')) {
        return jsonResponse({ message: 'Yubico support is disabled' }, 400)
      }
      if (url.endsWith('/api/two-factor/disable')) {
        mutationBody = JSON.parse(String(init?.body)) as JsonObject
        return jsonResponse({ enabled: false, type: 3, object: 'twoFactorProvider' })
      }
      return jsonResponse({ message: 'not found' }, 404)
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch }),
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.disableTwoFactorProvider(3, PASSWORD)).resolves.toBeUndefined()
    expect(mutationBody).toMatchObject({ type: 3, masterPasswordHash: expect.any(String) })
    expect(
      fetch.mock.calls.filter(([url]) => url.endsWith('/api/two-factor/disable'))
    ).toHaveLength(1)
  })

  it('keeps a lost YubiKey escape-hatch result unknown without replaying it', async () => {
    let mutationRequests = 0
    const fetch = vi.fn<FetchLike>(async (url) => {
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      if (url.endsWith('/api/two-factor/get-yubikey')) {
        return jsonResponse({ message: 'Yubico support is disabled' }, 400)
      }
      if (url.endsWith('/api/two-factor/disable')) {
        mutationRequests += 1
        throw new TypeError('response lost before outcome was known')
      }
      return jsonResponse({ message: 'not found' }, 404)
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch }),
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.disableTwoFactorProvider(3, PASSWORD)).rejects.toMatchObject({
      code: 'TWO_FACTOR_MUTATION_UNKNOWN'
    })
    expect(mutationRequests).toBe(1)
    expect(
      fetch.mock.calls.filter(([url]) => url.endsWith('/api/two-factor/get-yubikey'))
    ).toHaveLength(1)
  })

  it('uses the fresh generic proof when Vaultwarden hides a stale Duo provider row', async () => {
    let mutationBody: JsonObject | null = null
    const fetch = vi.fn<FetchLike>(async (url, init) => {
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      if (url.endsWith('/api/two-factor/get-duo')) {
        return jsonResponse({ enabled: false, object: 'twoFactorDuo' })
      }
      if (url.endsWith('/api/two-factor/disable')) {
        mutationBody = JSON.parse(String(init?.body)) as JsonObject
        return jsonResponse({ enabled: false, type: 2, object: 'twoFactorProvider' })
      }
      return jsonResponse({ message: 'not found' }, 404)
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch }),
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.disableTwoFactorProvider(2, PASSWORD)).resolves.toBeUndefined()
    expect(mutationBody).toMatchObject({ type: 2, masterPasswordHash: expect.any(String) })
    expect(
      fetch.mock.calls.filter(([url]) => url.endsWith('/api/two-factor/disable'))
    ).toHaveLength(1)
  })

  it('does not mistake a hidden stale Duo row for a confirmed lost-response disable', async () => {
    let mutationRequests = 0
    const fetch = vi.fn<FetchLike>(async (url) => {
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      if (url.endsWith('/api/two-factor/get-duo')) {
        return jsonResponse({ enabled: false, object: 'twoFactorDuo' })
      }
      if (url.endsWith('/api/two-factor/disable')) {
        mutationRequests += 1
        throw new TypeError('response lost before outcome was known')
      }
      return jsonResponse({ message: 'not found' }, 404)
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch }),
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.disableTwoFactorProvider(2, PASSWORD)).rejects.toMatchObject({
      code: 'TWO_FACTOR_MUTATION_UNKNOWN'
    })
    expect(mutationRequests).toBe(1)
    expect(
      fetch.mock.calls.filter(([url]) => url.endsWith('/api/two-factor/get-duo'))
    ).toHaveLength(1)
  })

  it('disables personal Duo, YubiKey, and the whole WebAuthn provider with fresh proofs', async () => {
    const requests: Array<{ url: string; method: string; body: JsonObject }> = []
    const fetch = vi.fn<FetchLike>(async (url, init) => {
      const method = init?.method ?? 'GET'
      const body = init?.body ? (JSON.parse(String(init.body)) as JsonObject) : {}
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      requests.push({ url, method, body })
      if (url.endsWith('/api/two-factor/get-duo')) {
        return jsonResponse({ enabled: true, object: 'twoFactorDuo' })
      }
      if (url.endsWith('/api/two-factor/get-yubikey')) {
        return jsonResponse({
          yubiKey: { enabled: true },
          userVerificationToken: 'yubikey-capability',
          object: 'twoFactorYubiKey'
        })
      }
      if (url.endsWith('/api/two-factor/get-webauthn')) {
        return jsonResponse({ enabled: true, keys: [], object: 'twoFactorWebAuthn' })
      }
      if (url.endsWith('/api/two-factor/yubikey')) return new Response(null, { status: 204 })
      if (url.endsWith('/api/two-factor/disable')) {
        return jsonResponse({ enabled: false, type: body.type, object: 'twoFactorProvider' })
      }
      return jsonResponse({ message: 'not found' }, 404)
    })
    const http = new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    await client.disableTwoFactorProvider(2, PASSWORD)
    await client.disableTwoFactorProvider(3, PASSWORD)
    await client.disableTwoFactorProvider(7, PASSWORD)

    expect(requests.map(({ url, method }) => [url, method])).toEqual([
      ['https://vault.example.invalid/api/two-factor/get-duo', 'POST'],
      ['https://vault.example.invalid/api/two-factor/disable', 'POST'],
      ['https://vault.example.invalid/api/two-factor/get-yubikey', 'POST'],
      ['https://vault.example.invalid/api/two-factor/yubikey', 'DELETE'],
      ['https://vault.example.invalid/api/two-factor/get-webauthn', 'POST'],
      ['https://vault.example.invalid/api/two-factor/disable', 'POST']
    ])
    expect(requests[1]?.body.type).toBe(2)
    expect(requests[3]?.body).toEqual({ userVerificationToken: 'yubikey-capability' })
    expect(requests[5]?.body.type).toBe(7)
  })

  it('reconciles a lost whole-WebAuthn disable response without replaying the mutation', async () => {
    let enabled = true
    let mutationRequests = 0
    const fetch = vi.fn<FetchLike>(async (url) => {
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      if (url.endsWith('/api/two-factor/get-webauthn')) {
        return jsonResponse({ enabled, keys: [], object: 'twoFactorWebAuthn' })
      }
      if (url.endsWith('/api/two-factor/disable')) {
        mutationRequests += 1
        enabled = false
        throw new TypeError('response lost after commit')
      }
      return jsonResponse({ message: 'not found' }, 404)
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch }),
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.disableTwoFactorProvider(7, PASSWORD)).resolves.toBeUndefined()
    expect(mutationRequests).toBe(1)
  })

  it('keeps an ambiguous WebAuthn disable unknown when the provider remains enabled', async () => {
    let mutationRequests = 0
    const fetch = vi.fn<FetchLike>(async (url) => {
      if (url.endsWith('/identity/accounts/prelogin/password')) {
        return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
      }
      if (url.endsWith('/api/two-factor/get-webauthn')) {
        return jsonResponse({ enabled: true, keys: [], object: 'twoFactorWebAuthn' })
      }
      if (url.endsWith('/api/two-factor/disable')) {
        mutationRequests += 1
        throw new TypeError('response lost before outcome was known')
      }
      return jsonResponse({ message: 'not found' }, 404)
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: new BitwardenHttpClient({ server: 'https://vault.example.invalid', fetch }),
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.disableTwoFactorProvider(7, PASSWORD)).rejects.toMatchObject({
      code: 'TWO_FACTOR_MUTATION_UNKNOWN'
    })
    expect(mutationRequests).toBe(1)
  })

  it('lists safe account devices while locked, captures refreshed sessions, and maps errors', async () => {
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async () => jsonResponse({ message: 'not found' }, 404)
    })
    const refreshedSession = {
      accessToken: 'refreshed-access',
      refreshToken: 'refreshed-refresh',
      expiresAt: Date.now() + 120_000
    }
    const getDevices = vi.spyOn(http, 'getDevices').mockImplementation(async (identifier) => {
      expect(identifier).toBe('00000000-0000-4000-8000-000000000123')
      http.setSession(refreshedSession)
      return [
        {
          id: '10000000-0000-4000-8000-000000000010',
          name: 'BearWarden desktop',
          type: 7,
          createdAt: '2026-05-01T00:00:00.000Z',
          lastActivityAt: '2026-07-17T00:00:00.000Z',
          current: true,
          trusted: true,
          pendingAuthRequest: false
        }
      ]
    })
    const onStateChanged = vi.fn()
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      onStateChanged,
      state: {
        session: {
          accessToken: 'access',
          refreshToken: 'refresh',
          expiresAt: Date.now() + 60_000
        },
        deviceIdentifier: '00000000-0000-4000-8000-000000000123',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.getAccountDevices()).resolves.toEqual([
      expect.objectContaining({ name: 'BearWarden desktop', current: true })
    ])
    expect(onStateChanged).toHaveBeenLastCalledWith(
      expect.objectContaining({ session: refreshedSession })
    )
    await expect(client.status()).resolves.toEqual({ status: 'locked' })

    getDevices.mockRejectedValueOnce(new BitwardenHttpError('AUTH'))
    await expect(client.getAccountDevices()).rejects.toMatchObject({ code: 'AUTH_REQUIRED' })
    getDevices.mockRejectedValueOnce(new BitwardenHttpError('NETWORK'))
    await expect(client.getAccountDevices()).rejects.toMatchObject({ code: 'NETWORK' })
    const abort = new AbortController()
    abort.abort()
    getDevices.mockRejectedValueOnce(new BitwardenHttpError('ABORTED'))
    await expect(client.getAccountDevices(abort.signal)).rejects.toMatchObject({ code: 'ABORTED' })
    expect(getDevices).toHaveBeenLastCalledWith(
      '00000000-0000-4000-8000-000000000123',
      abort.signal
    )
  })

  it('uses the official authenticator capability and reports unknown mutation outcomes', async () => {
    const key = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
    let mutationRequests = 0
    let failMutation = false
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/api/two-factor/get-authenticator')) {
          return jsonResponse({
            authenticator: { enabled: false, key },
            userVerificationToken: 'bound-capability',
            object: 'twoFactorAuthenticator'
          })
        }
        if (url.endsWith('/api/two-factor/authenticator')) {
          mutationRequests += 1
          if (failMutation) throw new TypeError('connection closed after request write')
          return jsonResponse({
            authenticator: { enabled: true, key },
            object: 'twoFactorAuthenticatorUpdate'
          })
        }
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: '90000000-0000-4000-8000-000000000099',
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.beginAuthenticatorSetup(PASSWORD)).resolves.toMatchObject({
      key,
      verificationMode: 'server-token',
      userVerificationToken: 'bound-capability'
    })
    await expect(
      client.completeAuthenticatorSetup({
        key,
        token: '123456',
        verificationMode: 'server-token',
        userVerificationToken: 'bound-capability'
      })
    ).resolves.toBeUndefined()

    failMutation = true
    await expect(
      client.completeAuthenticatorSetup({
        key,
        token: '654321',
        verificationMode: 'server-token',
        userVerificationToken: 'bound-capability'
      })
    ).rejects.toMatchObject({ code: 'TWO_FACTOR_MUTATION_UNKNOWN' })
    expect(mutationRequests).toBe(2)
  })

  it('supports official and Vaultwarden Email 2FA setup with fresh proofs', async () => {
    const factorEmail = 'factor@example.test'
    const bodies: JsonObject[] = []
    let preloginRequests = 0
    let mode: 'official' | 'vaultwarden' = 'official'
    let failMutation = false
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url, init) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          preloginRequests += 1
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (url.endsWith('/api/two-factor/get-email')) {
          bodies.push(JSON.parse(String(init?.body)))
          return mode === 'official'
            ? jsonResponse({
                email: { enabled: false, email: null },
                userVerificationToken: 'bound-email-capability',
                object: 'twoFactorEmail'
              })
            : jsonResponse({ enabled: false, email: null, object: 'twoFactorEmail' })
        }
        if (url.endsWith('/api/two-factor/send-email')) {
          bodies.push(JSON.parse(String(init?.body)))
          if (failMutation) throw new TypeError('connection closed after request write')
          return new Response(null, { status: 204 })
        }
        if (url.endsWith('/api/two-factor/email')) {
          bodies.push(JSON.parse(String(init?.body)))
          if (failMutation) throw new TypeError('connection closed after request write')
          return mode === 'official'
            ? jsonResponse({
                email: { enabled: true, email: factorEmail },
                object: 'twoFactorEmailUpdate'
              })
            : jsonResponse({ enabled: 'true', email: factorEmail, object: 'twoFactorEmail' })
        }
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: '90000000-0000-4000-8000-000000000099',
        securityStamp: 'security-stamp'
      }
    })

    await expect(client.beginEmailTwoFactorSetup(PASSWORD)).resolves.toMatchObject({
      verificationMode: 'server-token',
      userVerificationToken: 'bound-email-capability'
    })
    const officialSend = {
      email: factorEmail,
      verificationMode: 'server-token' as const,
      userVerificationToken: 'bound-email-capability'
    }
    await expect(client.sendEmailTwoFactorSetup(officialSend)).resolves.toBeUndefined()
    expect(officialSend.userVerificationToken).toBe('')

    failMutation = true
    const officialComplete = {
      email: factorEmail,
      token: '123456',
      verificationMode: 'server-token' as const,
      userVerificationToken: 'bound-email-capability'
    }
    await expect(client.completeEmailTwoFactorSetup(officialComplete)).rejects.toMatchObject({
      code: 'TWO_FACTOR_MUTATION_UNKNOWN'
    })
    expect(officialComplete.token).toBe('')
    expect(officialComplete.userVerificationToken).toBe('')

    failMutation = false
    mode = 'vaultwarden'
    await expect(client.beginEmailTwoFactorSetup(PASSWORD)).resolves.toMatchObject({
      verificationMode: 'master-password',
      userVerificationToken: null
    })
    const vaultwardenSend = {
      email: factorEmail,
      verificationMode: 'master-password' as const,
      masterPassword: PASSWORD
    }
    await expect(client.sendEmailTwoFactorSetup(vaultwardenSend)).resolves.toBeUndefined()
    expect(vaultwardenSend.masterPassword).toBe('')
    const vaultwardenComplete = {
      email: factorEmail,
      token: '654321',
      verificationMode: 'master-password' as const,
      masterPassword: PASSWORD
    }
    await expect(client.completeEmailTwoFactorSetup(vaultwardenComplete)).resolves.toBeUndefined()
    expect(vaultwardenComplete.masterPassword).toBe('')
    expect(vaultwardenComplete.token).toBe('')

    expect(preloginRequests).toBe(4)
    expect(bodies[1]).toEqual({
      email: factorEmail,
      userVerificationToken: 'bound-email-capability'
    })
    expect(bodies[2]).toEqual({
      email: factorEmail,
      token: '123456',
      userVerificationToken: 'bound-email-capability'
    })
    expect(bodies[4]).toMatchObject({ email: factorEmail, masterPasswordHash: expect.any(String) })
    expect(bodies[5]).toMatchObject({
      email: factorEmail,
      token: '654321',
      masterPasswordHash: expect.any(String)
    })
  })

  it('runs the official WebAuthn setup with a server-selected slot and no exported ceremony state', async () => {
    const requests: Array<{ url: string; method: string; body: JsonObject }> = []
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url, init) => {
        const method = init?.method ?? 'GET'
        const body = init?.body ? (JSON.parse(String(init.body)) as JsonObject) : {}
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        requests.push({ url, method, body })
        if (url.endsWith('/api/two-factor/get-webauthn')) {
          const deleting =
            requests.filter(({ url: requestUrl }) =>
              requestUrl.endsWith('/api/two-factor/get-webauthn')
            ).length > 1
          return jsonResponse({
            webAuthn: {
              enabled: deleting,
              keys: deleting
                ? [
                    { id: 2, name: 'Existing key', migrated: false },
                    { id: 1, name: 'New key', migrated: false }
                  ]
                : [{ id: 2, name: 'Existing key', migrated: false }]
            },
            userVerificationToken: deleting ? 'delete-capability' : 'setup-capability'
          })
        }
        if (url.endsWith('/api/two-factor/get-webauthn-challenge')) {
          return jsonResponse({ options: accountWebAuthnRegistrationOptions() })
        }
        if (url.endsWith('/api/two-factor/webauthn') && method === 'PUT') {
          return jsonResponse({
            webAuthn: {
              enabled: true,
              keys: [
                { id: 2, name: 'Existing key', migrated: false },
                { id: 1, name: 'New key', migrated: false }
              ]
            }
          })
        }
        if (url.endsWith('/api/two-factor/webauthn') && method === 'DELETE') {
          return jsonResponse({
            webAuthn: {
              enabled: true,
              keys: [{ id: 2, name: 'Existing key', migrated: false }]
            }
          })
        }
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    const setup = await client.beginWebAuthnSetup(PASSWORD)
    expect(setup).toMatchObject({
      registrationId: 1,
      verificationMode: 'server-token',
      userVerificationToken: 'setup-capability',
      keys: [{ id: 2, name: 'Existing key', migrated: false }]
    })
    const attestation = accountWebAuthnAttestation()
    await client.completeWebAuthnSetup({
      id: setup.registrationId,
      name: 'New key',
      attestation,
      verificationMode: setup.verificationMode,
      userVerificationToken: setup.userVerificationToken!
    })
    expect(attestation.id).toBe('')
    expect(attestation.response.attestationObject).toBe('')
    await client.deleteWebAuthnKey(1, PASSWORD)

    expect(requests.map(({ url, method }) => [url, method])).toEqual([
      ['https://vault.example.invalid/api/two-factor/get-webauthn', 'POST'],
      ['https://vault.example.invalid/api/two-factor/get-webauthn-challenge', 'POST'],
      ['https://vault.example.invalid/api/two-factor/webauthn', 'PUT'],
      ['https://vault.example.invalid/api/two-factor/get-webauthn', 'POST'],
      ['https://vault.example.invalid/api/two-factor/webauthn', 'DELETE']
    ])
    expect(requests[1]?.body).toEqual({ userVerificationToken: 'setup-capability' })
    expect(requests[2]?.body).toMatchObject({
      id: 1,
      name: 'New key',
      userVerificationToken: 'setup-capability'
    })
    expect(requests[4]?.body).toEqual({ id: 1, userVerificationToken: 'delete-capability' })
    const exported = JSON.stringify(client.exportState())
    expect(exported).not.toContain(ACCOUNT_WEBAUTHN_CHALLENGE)
    expect(exported).not.toContain(ACCOUNT_WEBAUTHN_ATTESTATION_OBJECT)
    expect(exported).not.toContain('setup-capability')
  })

  it('uses a fresh Vaultwarden proof and reports an unknown WebAuthn mutation outcome', async () => {
    let preloginRequests = 0
    let mutationRequests = 0
    const bodies: JsonObject[] = []
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      maxRetries: 5,
      fetch: async (url, init) => {
        if (url.endsWith('/identity/accounts/prelogin/password')) {
          preloginRequests += 1
          return jsonResponse({ kdf: 0, kdfIterations: 5_000, salt: EMAIL })
        }
        if (init?.body) bodies.push(JSON.parse(String(init.body)) as JsonObject)
        if (url.endsWith('/api/two-factor/get-webauthn')) {
          return jsonResponse({ enabled: false, keys: [], object: 'twoFactorWebAuthn' })
        }
        if (url.endsWith('/api/two-factor/get-webauthn-challenge')) {
          return jsonResponse({
            ...accountWebAuthnRegistrationOptions(),
            status: 'ok',
            errorMessage: ''
          })
        }
        if (url.endsWith('/api/two-factor/webauthn') && init?.method === 'PUT') {
          mutationRequests += 1
          throw new TypeError('connection closed after request write')
        }
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: Date.now() + 60_000 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: PROFILE_ID,
        securityStamp: 'security-stamp'
      }
    })

    const setup = await client.beginWebAuthnSetup(PASSWORD)
    expect(setup).toMatchObject({ registrationId: 1, verificationMode: 'master-password' })
    const request = {
      id: setup.registrationId,
      name: 'Vaultwarden key',
      attestation: accountWebAuthnAttestation(),
      verificationMode: 'master-password' as const,
      masterPassword: PASSWORD
    }
    await expect(client.completeWebAuthnSetup(request)).rejects.toMatchObject({
      code: 'TWO_FACTOR_MUTATION_UNKNOWN'
    })
    expect(preloginRequests).toBe(2)
    expect(mutationRequests).toBe(1)
    expect(request.masterPassword).toBe('')
    expect(request.attestation.id).toBe('')
    expect(bodies[1]).toEqual({ masterPasswordHash: expect.any(String) })
    expect(bodies[2]).toMatchObject({
      id: 1,
      name: 'Vaultwarden key',
      masterPasswordHash: expect.any(String)
    })
  })

  it('passes authenticated equivalent-domain settings through without requiring decrypted vault keys', async () => {
    const http = new BitwardenHttpClient({
      server: 'https://vault.example.invalid',
      fetch: async (url, init) => {
        if (url.endsWith('/api/settings/domains') && init?.method === 'GET') {
          return jsonResponse({
            equivalentDomains: [['first.example', 'second.example']],
            globalEquivalentDomains: [
              { type: 4, domains: ['a.example', 'b.example'], excluded: false }
            ]
          })
        }
        if (url.endsWith('/api/settings/domains') && init?.method === 'PUT') {
          return jsonResponse({})
        }
        return jsonResponse({ message: 'not found' }, 404)
      }
    })
    const client = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      httpClient: http,
      state: {
        session: { accessToken: 'access', refreshToken: 'refresh', expiresAt: 1 },
        deviceIdentifier: '00000000-0000-4000-8000-000000000000',
        profileId: null,
        securityStamp: null
      }
    })

    await expect(client.getEquivalentDomainSettings()).resolves.toEqual({
      equivalentDomains: [['first.example', 'second.example']],
      globalEquivalentDomains: [{ type: 4, domains: ['a.example', 'b.example'], excluded: false }]
    })
    await expect(
      client.updateEquivalentDomainSettings({
        equivalentDomains: [['one.example']],
        excludedGlobalEquivalentDomains: [4]
      })
    ).resolves.toBeUndefined()
    await expect(client.status()).resolves.toEqual({ status: 'locked' })
  })

  it('rejects a response whose aggregate nested rows exceed the sync budget', () => {
    expect(addAggregateRemoteRows(2, 1, 3)).toBe(3)
    expect(() => addAggregateRemoteRows(3, 1, 3)).toThrow(
      expect.objectContaining({ code: 'INVALID_RESPONSE' })
    )
  })

  it('reports only the coarse section of an incompatible sync response', async () => {
    await expectInvalidSync([], 'INVALID_RESPONSE', 'response')

    const account = await encryptedSync()
    account.profile = null
    await expectInvalidSync(account, 'INVALID_RESPONSE', 'account')

    for (const [stage, mutate] of [
      ['folder', (sync: JsonObject) => (sync.folders = {})],
      [
        'organization',
        (sync: JsonObject) => {
          const profile = sync.profile as JsonObject
          profile.organizations = {}
        }
      ],
      ['collection', (sync: JsonObject) => (sync.collections = {})],
      ['send', (sync: JsonObject) => (sync.sends = {})]
    ] as const) {
      const sync = await encryptedSync()
      mutate(sync)
      await expectInvalidSync(sync, 'INVALID_RESPONSE', stage)
    }
  })

  it('accepts omitted optional sync entity arrays as empty snapshots', async () => {
    const sync = await encryptedSync()
    delete sync.folders
    delete sync.ciphers
    delete sync.domains
    sync.collections = null
    sync.sends = null

    const client = await clientForSync(sync)
    await expect(client.listFolders()).resolves.toEqual([])
    await expect(client.listPersonalLogins()).resolves.toEqual([])
    await expect(client.listCollections()).resolves.toEqual([])
    await expect(client.listSends()).resolves.toEqual([])
    await expect(client.getEquivalentDomainSettings()).resolves.toEqual({
      equivalentDomains: [],
      globalEquivalentDomains: []
    })
  })

  it('uses equivalent domains embedded in the atomic sync snapshot', async () => {
    const sync = await encryptedSync()
    sync.domains = {
      object: 'domains',
      equivalentDomains: [['first.example', 'second.example']],
      globalEquivalentDomains: [{ type: 4, domains: ['global.example'], excluded: false }]
    }

    const client = await clientForSync(sync)
    await expect(client.getEquivalentDomainSettings()).resolves.toEqual({
      equivalentDomains: [['first.example', 'second.example']],
      globalEquivalentDomains: [{ type: 4, domains: ['global.example'], excluded: false }]
    })
  })

  it('isolates unsupported future cipher types without rejecting supported vault data', async () => {
    const sync = await encryptedSync()
    const cipher = (sync.ciphers as JsonObject[])[0]!
    const unsupportedPersonal = {
      ...cipher,
      id: '90000000-0000-4000-8000-000000000006',
      type: 6,
      bankAccount: { accountNumber: 'opaque-encrypted-bank-account' }
    }
    const unsupportedOrganization = {
      ...cipher,
      id: '90000000-0000-4000-8000-000000000007',
      type: 7,
      organizationId: '90000000-0000-4000-8000-000000000099',
      driversLicense: { number: 'opaque-encrypted-license' }
    }
    sync.ciphers = [cipher, unsupportedPersonal, unsupportedOrganization]

    const client = await clientForSync(sync)
    await expect(client.listPersonalLogins()).resolves.toEqual([
      expect.objectContaining({ id: LOGIN_ID, name: 'Example' })
    ])
    await expect(client.listOrganizationCiphers?.()).resolves.toEqual([])
  })

  it('rejects malformed cipher type values instead of treating them as future types', async () => {
    const sync = await encryptedSync()
    const cipher = (sync.ciphers as JsonObject[])[0]!
    cipher.type = 0

    await expectInvalidSync(sync, 'INVALID_RESPONSE', 'cipher', 'unsupported-cipher-type')
  })

  it('exposes only capability flags for unsupported user-decryption data', async () => {
    const sync = await encryptedSync()
    sync.userDecryption = {
      webAuthnPrfOptions: [{ encryptedPrivateKey: 'opaque-secret' }],
      v2UpgradeToken: { token: 'opaque-upgrade-secret' }
    }
    const client = await clientForSync(sync)
    expect(client.userDecryptionCapabilities()).toEqual({
      hasWebAuthnPrfOptions: true,
      hasV2UpgradeToken: true,
      webAuthnPrfUnlockSupported: false,
      v2AccountUpgradeSupported: false
    })
    expect(client.userDecryptionCapabilities()).not.toHaveProperty('token')

    const malformed = await encryptedSync()
    malformed.userDecryption = { webAuthnPrfOptions: ['opaque-secret'] }
    await expectInvalidSync(malformed, 'INVALID_RESPONSE', 'account', 'user-decryption-data')
  })

  it('commits PoliciesNew with explicit policy membership and exports an isolated snapshot', async () => {
    const sync = await encryptedSync()
    const profile = sync.profile as JsonObject
    profile.organizationsNew = [
      {
        id: ORGANIZATION_ID,
        name: 'Policy organization',
        usePolicies: true
      }
    ]
    sync.policies = [
      {
        id: 'a0000000-0000-4000-8000-000000000002',
        organizationId: ORGANIZATION_ID,
        type: 10,
        enabled: true
      }
    ]
    sync.policiesNew = [
      {
        id: POLICY_ID,
        organizationId: ORGANIZATION_ID,
        type: 6,
        enabled: true,
        canToggleState: false,
        revisionDate: '2026-07-22T00:00:00.000Z'
      }
    ]

    const client = await clientForSync(sync)
    const policySet = client.policySet()
    expect(policySet).toEqual({
      source: 'policiesNew',
      applicableOrganizationIds: [ORGANIZATION_ID],
      policies: [
        expect.objectContaining({
          id: POLICY_ID,
          organizationId: ORGANIZATION_ID,
          type: 6,
          execution: 'actionable',
          data: { kind: 'disableSend' }
        })
      ]
    })
    policySet.policies.splice(0)
    expect(client.policySet().policies).toHaveLength(1)
    expect(client.exportState().policySet).toEqual(client.policySet())
  })

  it('falls back from an empty PoliciesNew array and withholds ambiguous membership', async () => {
    const sync = await encryptedSync()
    const profile = sync.profile as JsonObject
    profile.organizations = [{ id: ORGANIZATION_ID, name: 'Legacy organization' }]
    sync.policiesNew = []
    sync.policies = [
      {
        id: POLICY_ID,
        organizationId: ORGANIZATION_ID,
        type: 6,
        enabled: true
      }
    ]

    const client = await clientForSync(sync)
    expect(client.policySet()).toMatchObject({ source: 'policies', policies: [{ id: POLICY_ID }] })
    expect(client.policySet()).not.toHaveProperty('applicableOrganizationIds')
  })

  it('commits read-only vault data with a fail-closed marker for malformed policy data', async () => {
    const sync = await encryptedSync()
    sync.policiesNew = [{ id: POLICY_ID, organizationId: ORGANIZATION_ID, type: 'invalid' }]

    const client = await clientForSync(sync)
    await expect(client.listFolders()).resolves.toHaveLength(1)
    expect(client.policySet()).toEqual({
      source: 'none',
      policies: [],
      parseFailure: 'invalid-response'
    })
    expect(client.exportState().policySet).toEqual(client.policySet())
  })

  it('restores legacy state without policy metadata as an explicit empty policy snapshot', async () => {
    const sync = await encryptedSync()
    const connected = await clientForSync(sync)
    const legacyState = connected.exportState()
    delete legacyState.policySet
    const restored = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      state: legacyState,
      httpClient: new BitwardenHttpClient({
        server: 'https://vault.example.invalid',
        fetch: async () => jsonResponse({ message: 'not found' }, 404)
      })
    })

    expect(restored.policySet()).toEqual({ source: 'none', policies: [] })
    expect(restored.exportState().policySet).toEqual({ source: 'none', policies: [] })

    const unsafeState = connected.exportState()
    unsafeState.policySet = {
      source: 'none',
      policies: [],
      rawPayload: { message: 'must-not-persist' }
    } as unknown as NonNullable<typeof unsafeState.policySet>
    const sanitized = new BitwardenDirectClient({
      serverUrl: 'https://vault.example.invalid',
      email: EMAIL,
      state: unsafeState,
      httpClient: new BitwardenHttpClient({
        server: 'https://vault.example.invalid',
        fetch: async () => jsonResponse({ message: 'not found' }, 404)
      })
    })
    expect(sanitized.policySet()).toEqual({
      source: 'none',
      policies: [],
      parseFailure: 'invalid-response'
    })
    expect(JSON.stringify(sanitized.exportState())).not.toContain('must-not-persist')
  })

  it.each([
    {
      label: 'Key Connector profile',
      mutate: (sync: JsonObject) => {
        const profile = sync.profile as JsonObject
        delete profile.key
        profile.usesKeyConnector = true
      },
      code: 'KEY_CONNECTOR_UNSUPPORTED'
    },
    {
      label: 'trusted-device-only decryption options',
      mutate: (sync: JsonObject) => {
        const profile = sync.profile as JsonObject
        delete profile.key
        sync.userDecryptionOptions = {
          hasMasterPassword: false,
          trustedDeviceOption: { hasAdminApproval: true }
        }
      },
      code: 'TRUSTED_DEVICE_UNSUPPORTED'
    },
    {
      label: 'ambiguous missing account key',
      mutate: (sync: JsonObject) => {
        const profile = sync.profile as JsonObject
        delete profile.key
      },
      code: 'UNSUPPORTED_ACCOUNT_ENCRYPTION'
    }
  ] as const)(
    'reports the precise unsupported encryption mode for $label',
    async ({ mutate, code }) => {
      const sync = await encryptedSync()
      mutate(sync)
      await expectInvalidSync(sync, code)
    }
  )

  it('rejects more than 1,000 legacy passkeys on one item', async () => {
    const sync = await encryptedSync()
    const cipher = (sync.ciphers as JsonObject[])[0]!
    const login = cipher.login as JsonObject
    const passkey = (login.fido2Credentials as JsonObject[])[0]!
    login.fido2Credentials = Array.from({ length: 1_001 }, () => passkey)

    await expectInvalidSync(sync, 'INVALID_RESPONSE', 'cipher')
  })

  it('rejects more than 1,000 V2 blob passkeys on one item', async () => {
    await expectInvalidSync(await encryptedV2Sync({ passkeyCount: 1_001 }))
  })

  it('identifies Vaultwarden SSH rows whose required type payload is null', async () => {
    const sync = await encryptedSync({ allTypes: true })
    const sshKey = (sync.ciphers as JsonObject[]).find((cipher) => cipher.type === 5)!
    sshKey.sshKey = null

    await expectInvalidSync(sync, 'INVALID_SSH_KEY')
  })

  it('rejects more than 1,000 attachments on one cipher', async () => {
    const sync = await encryptedSync()
    const cipher = (sync.ciphers as JsonObject[])[0]!
    const attachment = (cipher.attachments as JsonObject[])[0]!
    cipher.attachments = Array.from({ length: 1_001 }, (_, index) => ({
      ...attachment,
      id: `attachment-${index}`
    }))

    await expectInvalidSync(sync)
  })

  it('rejects non-canonical attachment sizes', async () => {
    for (const malformedSize of [12, '01', '-1']) {
      const sync = await encryptedSync()
      const cipher = (sync.ciphers as JsonObject[])[0]!
      const attachment = (cipher.attachments as JsonObject[])[0]!
      attachment.size = malformedSize

      await expectInvalidSync(sync)
    }
  })

  it('downloads a V1 attachment only from fresh metadata and returns decrypted bytes', async () => {
    const plaintext = Buffer.from('v1 attachment payload', 'utf8')
    const encrypted = encryptAttachmentFixture(plaintext, Buffer.alloc(64, 11))
    const client = await syncedAttachmentClient(await encryptedSync(), 'attachment-id', encrypted)

    const downloaded = await client.downloadAttachment(LOGIN_ID, 'attachment-id')
    try {
      expect(downloaded.fileName).toBe('document.txt')
      expect(downloaded.data).toEqual(plaintext)
    } finally {
      downloaded.data.fill(0)
      plaintext.fill(0)
      encrypted.fill(0)
    }
  })

  it('streams an authenticated attachment without returning a plaintext Buffer', async () => {
    const plaintext = Buffer.alloc(3 * 1024 * 1024 + 7, 0x5a)
    const encrypted = encryptAttachmentFixture(plaintext, Buffer.alloc(64, 11))
    const client = await syncedAttachmentClient(await encryptedSync(), 'attachment-id', encrypted)

    const downloaded = await client.downloadAttachmentStream(LOGIN_ID, 'attachment-id')
    const chunks: Buffer[] = []
    const yieldedReferences: Buffer[] = []
    try {
      for await (const chunk of downloaded.data.chunks()) {
        yieldedReferences.push(chunk)
        chunks.push(Buffer.from(chunk))
      }
      expect(Buffer.concat(chunks)).toEqual(plaintext)
      expect(Math.max(...chunks.map((chunk) => chunk.length))).toBeLessThanOrEqual(1024 * 1024)
      expect(yieldedReferences.every((chunk) => chunk.equals(Buffer.alloc(chunk.length)))).toBe(
        true
      )
      await expect(async () => {
        for await (const _chunk of downloaded.data.chunks()) void _chunk
      }).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    } finally {
      await downloaded.dispose()
    }
  })

  it('uses the cipher key for a legacy attachment that has no attachment CEK', async () => {
    const plaintext = Buffer.from('legacy attachment payload', 'utf8')
    const encrypted = encryptAttachmentFixture(plaintext, Buffer.alloc(64, 9))
    const client = await syncedAttachmentClient(
      await encryptedSync(),
      'legacy-attachment-id',
      encrypted
    )

    const downloaded = await client.downloadAttachment(LOGIN_ID, 'legacy-attachment-id')
    try {
      expect(downloaded.fileName).toBe('legacy-document.txt')
      expect(downloaded.data).toEqual(plaintext)
    } finally {
      downloaded.data.fill(0)
      plaintext.fill(0)
      encrypted.fill(0)
    }
  })

  it('downloads a V2-account attachment with its freshly wrapped CEK', async () => {
    const plaintext = Buffer.from('v2 attachment payload', 'utf8')
    const encrypted = encryptAttachmentFixture(plaintext, Buffer.alloc(64, 12))
    const client = await syncedAttachmentClient(
      await encryptedV2Sync(),
      'v2-attachment-id',
      encrypted
    )

    const downloaded = await client.downloadAttachment(LOGIN_ID, 'v2-attachment-id')
    try {
      expect(downloaded.fileName).toBe('v2-document.txt')
      expect(downloaded.data).toEqual(plaintext)
    } finally {
      downloaded.data.fill(0)
      plaintext.fill(0)
      encrypted.fill(0)
    }
  })

  it('rejects an attachment whose ciphertext MAC or fresh metadata does not authenticate', async () => {
    const plaintext = Buffer.from('authenticated attachment', 'utf8')
    const encrypted = encryptAttachmentFixture(plaintext, Buffer.alloc(64, 11))
    encrypted[encrypted.length - 1]! ^= 1
    const client = await syncedAttachmentClient(await encryptedSync(), 'attachment-id', encrypted)
    await expect(client.downloadAttachment(LOGIN_ID, 'attachment-id')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })

    const valid = encryptAttachmentFixture(plaintext, Buffer.alloc(64, 11))
    let binaryRequests = 0
    const mismatched = await syncedAttachmentClient(
      await encryptedSync(),
      'attachment-id',
      valid,
      (metadata) => {
        metadata.fileName = encryptBitwardenString('changed.txt', Buffer.alloc(64, 9))
      },
      () => {
        binaryRequests += 1
      }
    )
    await expect(mismatched.downloadAttachment(LOGIN_ID, 'attachment-id')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    expect(binaryRequests).toBe(0)
    plaintext.fill(0)
    encrypted.fill(0)
    valid.fill(0)
  })

  it('rejects an unknown cached attachment before requesting a download capability', async () => {
    const plaintext = Buffer.from('unused', 'utf8')
    const encrypted = encryptAttachmentFixture(plaintext, Buffer.alloc(64, 11))
    const client = await syncedAttachmentClient(await encryptedSync(), 'attachment-id', encrypted)

    await expect(client.downloadAttachment(LOGIN_ID, 'unknown-attachment')).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    plaintext.fill(0)
    encrypted.fill(0)
  })

  it('uploads a V1 attachment with a new CEK, encrypted size, and authoritative sync', async () => {
    const harness = await attachmentMutationHarness(await encryptedSync())
    const clearText = Buffer.from('new attachment payload', 'utf8')
    const original = Buffer.from(clearText)

    const uploaded = await harness.client.uploadAttachment(
      LOGIN_ID,
      'new-document.txt',
      clearText,
      undefined,
      () => harness.events.push('commit')
    )

    expect(uploaded).toMatchObject({
      id: 'uploaded-attachment-1',
      fileName: 'new-document.txt',
      legacy: false
    })
    expect(harness.events).toEqual(['create', 'upload-direct', 'sync', 'commit'])
    expect(harness.createdRequests).toHaveLength(1)
    expect(harness.uploadedBytes).toHaveLength(1)
    expect(harness.uploadedReferences[0]).toEqual(Buffer.alloc(harness.uploadedBytes[0]!.length))
    const request = harness.createdRequests[0]!
    const encrypted = harness.uploadedBytes[0]!
    const itemKey = Buffer.alloc(64, 9)
    const attachmentKey = decryptBitwardenWrappedKey(request.key, itemKey)
    try {
      expect(decryptBitwardenString(request.fileName, itemKey)).toBe('new-document.txt')
      expect(request.fileSize).toBe(encrypted.length)
      expect(request.lastKnownRevisionDate).toBe('2026-07-14T00:00:00.000Z')
      expect(encrypted[0]).toBe(2)
      expect(decryptBitwardenAttachmentBuffer(encrypted, attachmentKey)).toEqual(original)
      expect(clearText).toEqual(original)
    } finally {
      itemKey.fill(0)
      attachmentKey.fill(0)
      encrypted.fill(0)
      clearText.fill(0)
      original.fill(0)
    }
  })

  it('streams plaintext encryption into the attachment upload body', async () => {
    const harness = await attachmentMutationHarness(await encryptedSync())
    const chunks = [Buffer.alloc(1024 * 1024, 1), Buffer.alloc(1024 * 1024, 2), Buffer.of(3)]
    const clearText = Buffer.concat(chunks)
    await harness.client.uploadAttachmentStream(LOGIN_ID, 'streamed.bin', {
      size: clearText.length,
      async *chunks() {
        for (const chunk of chunks) yield chunk
      }
    })

    const request = harness.createdRequests[0]!
    const itemKey = Buffer.alloc(64, 9)
    const attachmentKey = decryptBitwardenWrappedKey(request.key, itemKey)
    try {
      expect(decryptBitwardenAttachmentBuffer(harness.uploadedBytes[0]!, attachmentKey)).toEqual(
        clearText
      )
    } finally {
      attachmentKey.fill(0)
    }
  })

  it('uploads an Account Encryption V2 attachment through Azure with the legacy item key', async () => {
    const harness = await attachmentMutationHarness(await encryptedV2Sync(), 'azure')
    const clearText = Buffer.from('v2 upload payload', 'utf8')

    const uploaded = await harness.client.uploadAttachment(LOGIN_ID, 'v2-upload.txt', clearText)

    expect(uploaded).toMatchObject({ fileName: 'v2-upload.txt', legacy: false })
    expect(harness.events).toEqual(['create', 'upload-azure', 'sync'])
    expect(harness.uploadedReferences[0]).toEqual(Buffer.alloc(harness.uploadedBytes[0]!.length))
    const request = harness.createdRequests[0]!
    const encrypted = harness.uploadedBytes[0]!
    const itemKey = Buffer.alloc(64, 9)
    const attachmentKey = decryptBitwardenWrappedKey(request.key, itemKey)
    try {
      expect(decryptBitwardenString(request.fileName, itemKey)).toBe('v2-upload.txt')
      expect(decryptBitwardenAttachmentBuffer(encrypted, attachmentKey)).toEqual(clearText)
    } finally {
      itemKey.fill(0)
      attachmentKey.fill(0)
      encrypted.fill(0)
      clearText.fill(0)
    }
  })

  it('rejects duplicate attachment names before creating remote metadata', async () => {
    const harness = await attachmentMutationHarness(await encryptedSync())
    const clearText = Buffer.from('duplicate', 'utf8')
    await expect(
      harness.client.uploadAttachment(LOGIN_ID, 'document.txt', clearText)
    ).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
    expect(harness.events).toEqual([])
    expect(harness.createdRequests).toHaveLength(0)
    expect(clearText.toString('utf8')).toBe('duplicate')
    clearText.fill(0)
  })

  it('rolls metadata back after phase-two failure without masking the upload error', async () => {
    const harness = await attachmentMutationHarness(await encryptedSync())
    harness.failNextUpload(new BitwardenHttpError('ABORTED'))
    harness.failDelete('uploaded-attachment-1')
    const clearText = Buffer.from('will abort', 'utf8')

    const onCommitted = vi.fn()
    await expect(
      harness.client.uploadAttachment(LOGIN_ID, 'aborted.txt', clearText, undefined, onCommitted)
    ).rejects.toMatchObject({ code: 'ABORTED' })
    expect(harness.events).toEqual(['create', 'upload-direct', 'delete:uploaded-attachment-1'])
    expect(onCommitted).not.toHaveBeenCalled()
    expect(clearText.toString('utf8')).toBe('will abort')
    clearText.fill(0)
  })

  it('preserves actionable attachment HTTP error codes', async () => {
    for (const code of [
      'NOT_FOUND',
      'FORBIDDEN',
      'TOO_LARGE',
      'STORAGE_LIMIT',
      'ATTACHMENT_REJECTED'
    ] as const) {
      const harness = await attachmentMutationHarness(await encryptedSync())
      vi.mocked(harness.http.createAttachment).mockRejectedValueOnce(new BitwardenHttpError(code))
      const clearText = Buffer.from(`error-${code}`, 'utf8')
      await expect(
        harness.client.uploadAttachment(LOGIN_ID, `${code}.txt`, clearText)
      ).rejects.toMatchObject({ code })
      expect(harness.events).toEqual([])
      clearText.fill(0)
    }
  })

  it('does not trust the create response when authoritative sync omits the upload', async () => {
    const harness = await attachmentMutationHarness(await encryptedSync())
    harness.setPublishUpload(false)
    const clearText = Buffer.from('not published', 'utf8')

    const onCommitted = vi.fn()
    await expect(
      harness.client.uploadAttachment(
        LOGIN_ID,
        'missing-after-sync.txt',
        clearText,
        undefined,
        onCommitted
      )
    ).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
    expect(harness.events).toEqual([
      'create',
      'upload-direct',
      'sync',
      'delete:uploaded-attachment-1'
    ])
    expect(onCommitted).not.toHaveBeenCalled()
    expect(clearText.toString('utf8')).toBe('not published')
    clearText.fill(0)
    harness.uploadedBytes.forEach((bytes) => bytes.fill(0))
  })

  it('rolls an upload back when caller cancellation interrupts authoritative validation', async () => {
    const harness = await attachmentMutationHarness(await encryptedSync())
    const abort = new AbortController()
    const onCommitted = vi.fn()
    const clearText = Buffer.from('cancel during sync', 'utf8')
    vi.mocked(harness.http.sync).mockImplementationOnce(async (signal) => {
      harness.events.push('sync')
      abort.abort()
      if (signal?.aborted) throw new BitwardenHttpError('ABORTED')
      return harness.sync
    })

    await expect(
      harness.client.uploadAttachment(
        LOGIN_ID,
        'cancel-during-sync.txt',
        clearText,
        abort.signal,
        onCommitted
      )
    ).rejects.toMatchObject({ code: 'ABORTED' })
    expect(harness.events).toEqual([
      'create',
      'upload-direct',
      'sync',
      'delete:uploaded-attachment-1'
    ])
    expect(onCommitted).not.toHaveBeenCalled()
    clearText.fill(0)
    harness.uploadedBytes.forEach((bytes) => bytes.fill(0))
  })

  it('deletes only a cached member attachment and confirms removal with full sync', async () => {
    const harness = await attachmentMutationHarness(await encryptedSync())

    await harness.client.deleteAttachment(LOGIN_ID, 'attachment-id', undefined, () =>
      harness.events.push('commit')
    )

    expect(harness.events).toEqual(['delete:attachment-id', 'commit', 'sync'])
    expect(harness.syncSignals).toEqual([undefined])
    await expect(harness.client.listPersonalLogins()).resolves.toEqual([
      expect.objectContaining({
        attachments: [expect.objectContaining({ id: 'legacy-attachment-id' })]
      })
    ])
    harness.events.length = 0
    await expect(
      harness.client.deleteAttachment(LOGIN_ID, 'unknown-attachment')
    ).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
    expect(harness.events).toEqual([])
  })

  it('commits a confirmed delete and finishes authoritative sync after caller cancellation', async () => {
    const harness = await attachmentMutationHarness(await encryptedSync())
    const abort = new AbortController()
    const deleteImplementation = vi.mocked(harness.http.deleteAttachment).getMockImplementation()!
    vi.mocked(harness.http.deleteAttachment).mockImplementationOnce(
      async (id, attachmentId, signal) => {
        const response = await deleteImplementation(id, attachmentId, signal)
        abort.abort()
        return response
      }
    )

    await harness.client.deleteAttachment(LOGIN_ID, 'attachment-id', abort.signal, () =>
      harness.events.push('commit')
    )

    expect(harness.events).toEqual(['delete:attachment-id', 'commit', 'sync'])
    expect(harness.syncSignals).toEqual([undefined])
  })

  it('fixes legacy attachments in download-upload-delete order and clears downloaded plaintext', async () => {
    const sync = await encryptedSync()
    const clearText = Buffer.from('legacy fix payload', 'utf8')
    const legacyEncrypted = encryptAttachmentFixture(clearText, Buffer.alloc(64, 9))
    const cipher = (sync.ciphers as JsonObject[])[0]!
    const legacy = (cipher.attachments as JsonObject[]).find(
      (attachment) => attachment.id === 'legacy-attachment-id'
    )!
    legacy.size = String(legacyEncrypted.length)
    const harness = await attachmentMutationHarness(sync, 'direct', {
      'legacy-attachment-id': legacyEncrypted
    })
    const originalDownload = harness.client.downloadAttachment.bind(harness.client)
    let downloadedPlaintext: Buffer | null = null
    vi.spyOn(harness.client, 'downloadAttachment').mockImplementation(async (...args) => {
      const result = await originalDownload(...args)
      downloadedPlaintext = result.data
      return result
    })
    const abort = new AbortController()
    const deleteImplementation = vi.mocked(harness.http.deleteAttachment).getMockImplementation()!
    vi.mocked(harness.http.deleteAttachment).mockImplementationOnce(
      async (id, attachmentId, signal) => {
        const response = await deleteImplementation(id, attachmentId, signal)
        abort.abort()
        return response
      }
    )

    const upgraded = await harness.client.upgradeLegacyAttachment(
      LOGIN_ID,
      'legacy-attachment-id',
      abort.signal,
      () => harness.events.push('commit')
    )

    expect(upgraded).toMatchObject({
      id: 'uploaded-attachment-1',
      fileName: 'legacy-document.txt',
      legacy: false
    })
    expect(harness.events).toEqual([
      'download-metadata:legacy-attachment-id',
      'download-bytes:legacy-attachment-id',
      'create',
      'upload-direct',
      'sync',
      'delete:legacy-attachment-id',
      'commit',
      'sync'
    ])
    expect(harness.syncSignals).toEqual([abort.signal, undefined])
    await expect(harness.client.listPersonalLogins()).resolves.toEqual([
      expect.objectContaining({
        attachments: [
          expect.objectContaining({ id: 'attachment-id' }),
          expect.objectContaining({ id: 'uploaded-attachment-1', legacy: false })
        ]
      })
    ])
    expect(downloadedPlaintext).toEqual(Buffer.alloc(clearText.length))
    clearText.fill(0)
    legacyEncrypted.fill(0)
    harness.uploadedBytes.forEach((bytes) => bytes.fill(0))
  })

  it('keeps both copies when legacy-fix deletion fails and rejects non-legacy fixes', async () => {
    const sync = await encryptedSync()
    const legacyPlaintext = Buffer.from('legacy retained payload', 'utf8')
    const legacyKey = Buffer.alloc(64, 9)
    const legacyEncrypted = encryptAttachmentFixture(legacyPlaintext, legacyKey)
    const cipher = (sync.ciphers as JsonObject[])[0]!
    const legacy = (cipher.attachments as JsonObject[]).find(
      (attachment) => attachment.id === 'legacy-attachment-id'
    )!
    legacy.size = String(legacyEncrypted.length)
    const harness = await attachmentMutationHarness(sync, 'direct', {
      'legacy-attachment-id': legacyEncrypted
    })
    harness.failDelete('legacy-attachment-id')
    const onCommitted = vi.fn()

    await expect(
      harness.client.upgradeLegacyAttachment(
        LOGIN_ID,
        'legacy-attachment-id',
        undefined,
        onCommitted
      )
    ).rejects.toMatchObject({ code: 'NETWORK' })
    expect(onCommitted).not.toHaveBeenCalled()
    const afterFailure = await harness.client.listPersonalLogins()
    expect(afterFailure[0]!.attachments.map((attachment) => attachment.id)).toEqual([
      'attachment-id',
      'legacy-attachment-id',
      'uploaded-attachment-1'
    ])
    await expect(
      harness.client.upgradeLegacyAttachment(LOGIN_ID, 'attachment-id')
    ).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
    legacyPlaintext.fill(0)
    legacyKey.fill(0)
    legacyEncrypted.fill(0)
    harness.uploadedBytes.forEach((bytes) => bytes.fill(0))
  })

  it('rolls back a validated replacement when legacy-fix is cancelled before delete starts', async () => {
    const sync = await encryptedSync()
    const clearText = Buffer.from('legacy cancel payload', 'utf8')
    const legacyEncrypted = encryptAttachmentFixture(clearText, Buffer.alloc(64, 9))
    const cipher = (sync.ciphers as JsonObject[])[0]!
    const legacy = (cipher.attachments as JsonObject[]).find(
      (attachment) => attachment.id === 'legacy-attachment-id'
    )!
    legacy.size = String(legacyEncrypted.length)
    const harness = await attachmentMutationHarness(sync, 'direct', {
      'legacy-attachment-id': legacyEncrypted
    })
    const abort = new AbortController()
    const onCommitted = vi.fn()
    vi.mocked(harness.http.sync).mockImplementationOnce(async () => {
      harness.events.push('sync')
      abort.abort()
      return harness.sync
    })

    await expect(
      harness.client.upgradeLegacyAttachment(
        LOGIN_ID,
        'legacy-attachment-id',
        abort.signal,
        onCommitted
      )
    ).rejects.toMatchObject({ code: 'ABORTED' })
    expect(harness.events).toEqual([
      'download-metadata:legacy-attachment-id',
      'download-bytes:legacy-attachment-id',
      'create',
      'upload-direct',
      'sync',
      'delete:uploaded-attachment-1'
    ])
    expect(onCommitted).not.toHaveBeenCalled()
    expect((cipher.attachments as JsonObject[]).map((attachment) => attachment.id)).toEqual([
      'attachment-id',
      'legacy-attachment-id'
    ])
    clearText.fill(0)
    legacyEncrypted.fill(0)
    harness.uploadedBytes.forEach((bytes) => bytes.fill(0))
  })

  it('aborts before upload without creating metadata', async () => {
    const harness = await attachmentMutationHarness(await encryptedSync())
    const abort = new AbortController()
    abort.abort()
    const clearText = Buffer.from('never uploaded', 'utf8')
    await expect(
      harness.client.uploadAttachment(LOGIN_ID, 'aborted-before-start.txt', clearText, abort.signal)
    ).rejects.toMatchObject({ code: 'ABORTED' })
    expect(harness.events).toEqual([])
    expect(clearText.toString('utf8')).toBe('never uploaded')
    clearText.fill(0)
  })

  it('rejects a decrypted passkey field longer than the local schema allows', async () => {
    await expectInvalidSync(await encryptedSync({ passkeyCredentialId: 'x'.repeat(4_097) }))
  })

  it('rejects an invalid passkey calendar date', async () => {
    await expectInvalidSync(await encryptedV2Sync({ passkeyCreationDate: '2026-02-30T00:00:00Z' }))
  })

  it.each([
    ['Steam', 'steam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ'],
    ['custom otpauth', 'otpauth://totp/example.invalid?secret=WQIQ25BRKZYCJVYP&digits=8&period=60']
  ])('round-trips an untouched %s TOTP string exactly', async (_kind, totp) => {
    const sync = await encryptedSync({ totp })
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
    await expect(client.listPersonalLogins()).resolves.toEqual([
      expect.objectContaining({ id: LOGIN_ID, totp })
    ])

    await client.editLogin(LOGIN_ID, { name: 'Renamed without touching TOTP' })
    const update = JSON.parse(writes[0]!) as JsonObject
    const originalLogin = (sync.ciphers as JsonObject[])[0]!.login as JsonObject
    expect((update.login as JsonObject).totp).toBe(originalLogin.totp)
    expect(
      decryptBitwardenString((update.login as JsonObject).totp as string, Buffer.alloc(64, 9))
    ).toBe(totp)
  })

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
        passwordRevisionDate: '2026-07-13T00:00:00.000Z',
        autofillOnPageLoad: false,
        totp: 'otpauth://totp/example.invalid?secret=JBSWY3DPEHPK3PXP',
        passkeys: [
          expect.objectContaining({
            rpId: 'example.invalid',
            discoverable: true,
            creationDate: '2026-07-13T00:00:00.654Z'
          })
        ],
        customFields: [
          { name: 'member-id', value: 'legacy-member-42', type: 'text', linkedId: null },
          { name: 'recovery-code', value: 'legacy-hidden-code', type: 'hidden', linkedId: null },
          { name: 'remember-device', value: 'true', type: 'boolean', linkedId: null },
          { name: 'alternate-username', value: '', type: 'linked', linkedId: 100 }
        ],
        passwordHistory: [
          { password: 'old-login-secret', lastUsedDate: '2026-01-02T00:00:00.123Z' }
        ],
        attachments: [
          {
            id: 'attachment-id',
            fileName: 'document.txt',
            size: 12,
            sizeName: '12 B',
            legacy: false
          },
          {
            id: 'legacy-attachment-id',
            fileName: 'legacy-document.txt',
            size: 7,
            sizeName: '7 B',
            legacy: true
          }
        ],
        notes: 'A note',
        folderId: FOLDER_ID,
        favorite: true,
        reprompt: 1
      })
    ])
    const detached = await client.listPersonalLogins()
    detached[0]!.attachments[0]!.fileName = 'mutated-in-renderer'
    expect((await client.listPersonalLogins())[0]!.attachments[0]!.fileName).toBe('document.txt')

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
      uris: [
        { uri: 'https://backup.example.invalid', match: 1 },
        { uri: 'https://example.invalid', match: 2 }
      ],
      notes: 'Changed note',
      folderId: FOLDER_ID,
      favorite: false,
      reprompt: 0,
      customFields: [
        { name: 'member-id', value: 'legacy-member-99', type: 'text', linkedId: null },
        { name: 'recovery-code', value: 'legacy-updated-code', type: 'hidden', linkedId: null },
        { name: 'remember-device', value: 'false', type: 'boolean', linkedId: null },
        { name: 'alternate-username', value: '', type: 'linked', linkedId: 100 }
      ]
    })
    const update = JSON.parse(writes[1]!) as JsonObject
    expect(update.reprompt).toBe(0)
    const originalLogin = (sync.ciphers as JsonObject[])[0]!.login as JsonObject
    expect(update.passwordHistory).toEqual((sync.ciphers as JsonObject[])[0]!.passwordHistory)
    expect((update.login as JsonObject).totp).toBe(originalLogin.totp)
    expect((update.login as JsonObject).passwordRevisionDate).toBe('2026-07-13T00:00:00.000Z')
    expect((update.login as JsonObject).autofillOnPageLoad).toBe(false)
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
      match: 1,
      uriChecksum: 'backup-checksum'
    })
    expect(((update.login as JsonObject).uris as JsonObject[])[1]).toMatchObject({
      match: 2,
      uriChecksum: 'opaque-future-checksum'
    })
    expect(
      decryptBitwardenString(
        ((update.login as JsonObject).uris as JsonObject[])[0]!.uri as string,
        Buffer.alloc(64, 9)
      )
    ).toBe('https://backup.example.invalid')
    expect(update.attachments).toMatchObject({ 'attachment-id': expect.stringContaining('2.') })
    expect(update.attachments2).toMatchObject({
      'attachment-id': {
        fileName: expect.stringContaining('2.'),
        key: expect.stringContaining('2.')
      }
    })
    expect(writes[1]).not.toContain('changed-secret')
    expect(writes[1]).not.toContain('Renamed')

    await client.editLogin(LOGIN_ID, {
      name: 'Renamed',
      passwordHistory: [
        { password: 'new-history-secret', lastUsedDate: '2026-01-03T00:00:00.000Z' }
      ],
      uris: [
        { uri: 'https://new.example.invalid', match: null },
        { uri: 'https://backup.example.invalid', match: 1 },
        { uri: 'https://example.invalid', match: 2 }
      ]
    })
    const prependedUris = ((JSON.parse(writes[2]!) as JsonObject).login as JsonObject)
      .uris as JsonObject[]
    expect(prependedUris[0]).not.toHaveProperty('uriChecksum')
    expect(prependedUris[1]).toMatchObject({ uriChecksum: 'backup-checksum' })
    expect(prependedUris[2]).toMatchObject({ uriChecksum: 'opaque-future-checksum' })
    const writtenHistory = (JSON.parse(writes[2]!) as JsonObject).passwordHistory as JsonObject[]
    expect(writtenHistory).toHaveLength(1)
    expect(decryptBitwardenString(writtenHistory[0]!.password as string, Buffer.alloc(64, 9))).toBe(
      'new-history-secret'
    )
    expect(writtenHistory[0]!.lastUsedDate).toBe('2026-01-03T00:00:00.000Z')

    await client.editLogin(LOGIN_ID, {
      name: 'Renamed',
      uris: [
        { uri: 'https://new.example.invalid', match: null },
        { uri: 'https://changed-backup.example.invalid', match: 1 },
        { uri: 'https://example.invalid', match: 2 }
      ]
    })
    const changedUris = ((JSON.parse(writes[3]!) as JsonObject).login as JsonObject)
      .uris as JsonObject[]
    expect(changedUris[1]).not.toHaveProperty('uriChecksum')
    expect(changedUris[2]).toMatchObject({ uriChecksum: 'opaque-future-checksum' })
  })

  it('rejects invalid reprompt metadata instead of weakening it to disabled', async () => {
    const sync = await encryptedSync()
    ;(sync.ciphers as JsonObject[])[0]!.reprompt = 2
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

    await client.login({ email: EMAIL, password: PASSWORD })
    await expect(client.sync()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
  })

  it('syncs trashed ciphers and keeps deletedAt coherent across restore, soft delete, and purge', async () => {
    const sync = await encryptedSync()
    const syncedCipher = (sync.ciphers as JsonObject[])[0]!
    syncedCipher.deletedDate = DELETED_AT
    const requests: string[] = []
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
        requests.push(`${init?.method} ${url}`)
        if (url.endsWith(`/api/ciphers/${LOGIN_ID}/restore`) && init?.method === 'PUT') {
          return jsonResponse({
            ...syncedCipher,
            deletedDate: null,
            revisionDate: '2026-07-15T00:00:01.000Z'
          })
        }
        if (url.endsWith(`/api/ciphers/${LOGIN_ID}/archive`) && init?.method === 'PUT') {
          return jsonResponse({
            ...syncedCipher,
            deletedDate: null,
            archivedDate: ARCHIVED_AT,
            revisionDate: '2026-07-15T00:00:02.000Z'
          })
        }
        if (url.endsWith(`/api/ciphers/${LOGIN_ID}/unarchive`) && init?.method === 'PUT') {
          return jsonResponse({
            ...syncedCipher,
            deletedDate: null,
            archivedDate: null,
            revisionDate: '2026-07-15T00:00:03.000Z'
          })
        }
        if (url.endsWith(`/api/ciphers/${LOGIN_ID}/delete`) && init?.method === 'PUT') {
          return new Response(null, { status: 204 })
        }
        if (url.endsWith(`/api/ciphers/${LOGIN_ID}`) && init?.method === 'DELETE') {
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
      expect.objectContaining({ id: LOGIN_ID, deletedAt: DELETED_AT })
    ])

    await client.restoreLogin(LOGIN_ID)
    await expect(client.listPersonalLogins()).resolves.toEqual([
      expect.objectContaining({ id: LOGIN_ID, deletedAt: null })
    ])

    await client.archiveLogin(LOGIN_ID)
    await expect(client.listPersonalLogins()).resolves.toEqual([
      expect.objectContaining({ id: LOGIN_ID, archivedAt: ARCHIVED_AT })
    ])
    await client.unarchiveLogin(LOGIN_ID)
    await expect(client.listPersonalLogins()).resolves.toEqual([
      expect.objectContaining({ id: LOGIN_ID, archivedAt: null })
    ])

    await client.softDeleteLogin(LOGIN_ID)
    const softDeleted = (await client.listPersonalLogins())[0]!
    expect(softDeleted.id).toBe(LOGIN_ID)
    expect(softDeleted.deletedAt).not.toBeNull()
    expect(Number.isFinite(Date.parse(softDeleted.deletedAt!))).toBe(true)

    await client.hardDeleteLogin(LOGIN_ID)
    await expect(client.listPersonalLogins()).resolves.toEqual([])
    expect(requests).toEqual([
      `PUT https://vault.example.invalid/api/ciphers/${LOGIN_ID}/restore`,
      `PUT https://vault.example.invalid/api/ciphers/${LOGIN_ID}/archive`,
      `PUT https://vault.example.invalid/api/ciphers/${LOGIN_ID}/unarchive`,
      `PUT https://vault.example.invalid/api/ciphers/${LOGIN_ID}/delete`,
      `DELETE https://vault.example.invalid/api/ciphers/${LOGIN_ID}`
    ])
  })

  it('applies validated bulk lifecycle responses to the personal cipher cache', async () => {
    const sync = await encryptedSync({ allTypes: true })
    const sourceRows = sync.ciphers as JsonObject[]
    const ids = [LOGIN_ID, CARD_ID]
    let rejectMoveResponse = true
    const requests: string[] = []
    const rowsFor = (operation: 'restore' | 'archive' | 'unarchive'): JsonObject[] =>
      ids.map((id) => {
        const source = sourceRows.find((row) => row.id === id)!
        return {
          ...source,
          deletedDate: null,
          archivedDate: operation === 'archive' ? ARCHIVED_AT : null,
          revisionDate: '2026-07-17T00:00:00.000Z'
        }
      })
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
        requests.push(`${init?.method} ${url}`)
        if (url.endsWith('/api/ciphers/restore')) {
          return jsonResponse({ data: rowsFor('restore'), object: 'list', continuationToken: null })
        }
        if (url.endsWith('/api/ciphers/archive')) {
          return jsonResponse({ data: rowsFor('archive'), object: 'list', continuationToken: null })
        }
        if (url.endsWith('/api/ciphers/unarchive')) {
          return jsonResponse({
            data: rowsFor('unarchive'),
            object: 'list',
            continuationToken: null
          })
        }
        if (url.endsWith('/api/ciphers/move')) {
          if (rejectMoveResponse) return jsonResponse({ ambiguous: true })
          return new Response(null, { status: 204 })
        }
        if (url.endsWith('/api/ciphers/delete') || url.endsWith('/api/ciphers')) {
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
    await expect(client.moveLogins(ids, null)).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
    expect(
      (await client.listPersonalLogins())
        .filter((item) => ids.includes(item.id))
        .map((item) => item.folderId)
    ).toEqual([FOLDER_ID, null])

    rejectMoveResponse = false
    await client.moveLogins(ids, null)
    expect(
      (await client.listPersonalLogins())
        .filter((item) => ids.includes(item.id))
        .map((item) => item.folderId)
    ).toEqual([null, null])

    await client.softDeleteLogins(ids)
    expect(
      (await client.listPersonalLogins())
        .filter((item) => ids.includes(item.id))
        .every((item) => item.deletedAt !== null)
    ).toBe(true)
    await client.restoreLogins(ids)
    expect(
      (await client.listPersonalLogins())
        .filter((item) => ids.includes(item.id))
        .every((item) => item.deletedAt === null)
    ).toBe(true)
    await client.archiveLogins(ids)
    expect(
      (await client.listPersonalLogins())
        .filter((item) => ids.includes(item.id))
        .every((item) => item.archivedAt === ARCHIVED_AT)
    ).toBe(true)
    await client.unarchiveLogins(ids)
    expect(
      (await client.listPersonalLogins())
        .filter((item) => ids.includes(item.id))
        .every((item) => item.archivedAt === null)
    ).toBe(true)
    await client.hardDeleteLogins(ids)
    expect((await client.listPersonalLogins()).filter((item) => ids.includes(item.id))).toEqual([])
    expect(requests).toEqual([
      'POST https://vault.example.invalid/api/ciphers/move',
      'POST https://vault.example.invalid/api/ciphers/move',
      'PUT https://vault.example.invalid/api/ciphers/delete',
      'PUT https://vault.example.invalid/api/ciphers/restore',
      'PUT https://vault.example.invalid/api/ciphers/archive',
      'PUT https://vault.example.invalid/api/ciphers/unarchive',
      'POST https://vault.example.invalid/api/ciphers/delete'
    ])
  })

  it('prepares a personal import with per-item keys and reconciles only exact markers', async () => {
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
            expires_in: 3_600
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
    await client.login({ email: EMAIL, password: PASSWORD })
    await client.sync()

    let imported: {
      folders: readonly { id?: string | null; name: string }[]
      ciphers: readonly JsonObject[]
      folderRelationships: readonly { key: number; value: number }[]
    } | null = null
    vi.spyOn(http, 'importPersonalCiphers').mockImplementation(async (request) => {
      imported = structuredClone(request)
    })
    const localIds = [
      '90000000-0000-4000-8000-000000000001',
      '90000000-0000-4000-8000-000000000002'
    ]
    const prepared = await client.prepareLoginImport([
      {
        localId: localIds[0]!,
        draft: {
          name: 'Imported one',
          username: 'first-user',
          password: 'first-secret',
          folderId: FOLDER_ID
        }
      },
      {
        localId: localIds[1]!,
        draft: {
          name: 'Imported two',
          username: 'second-user',
          password: 'second-secret',
          folderId: null
        }
      }
    ])

    expect(prepared.token).toMatch(/^[A-Za-z0-9_-]{43}$/u)
    expect(prepared.entries).toEqual([
      expect.objectContaining({ localId: localIds[0], remoteFolderId: FOLDER_ID }),
      expect.objectContaining({ localId: localIds[1], remoteFolderId: null })
    ])
    expect(new Set(prepared.entries.map((entry) => entry.marker)).size).toBe(2)
    await client.executePreparedLoginImport(prepared.token)
    expect(imported).not.toBeNull()
    const request = imported!
    expect(request.folders).toEqual([
      {
        id: FOLDER_ID,
        name: (sync.folders as JsonObject[])[0]!.name
      }
    ])
    expect(request.folderRelationships).toEqual([{ key: 0, value: 0 }])
    expect(request.ciphers).toHaveLength(2)
    expect(request.ciphers.map((cipher) => cipher.key)).toEqual(
      prepared.entries.map((entry) => entry.marker)
    )
    expect(
      request.ciphers.every(
        (cipher) =>
          cipher.organizationId === null &&
          cipher.folderId === null &&
          !Object.hasOwn(cipher, 'attachments') &&
          !Object.hasOwn(cipher, 'collectionIds')
      )
    ).toBe(true)
    expect(JSON.stringify(request)).not.toContain('first-secret')
    expect(JSON.stringify(request)).not.toContain('second-secret')

    const importedIds = [
      'a0000000-0000-4000-8000-000000000001',
      'a0000000-0000-4000-8000-000000000002'
    ]
    ;(sync.ciphers as JsonObject[]).push(
      ...request.ciphers.map((cipher, index) => ({
        ...cipher,
        id: importedIds[index],
        folderId: index === 0 ? FOLDER_ID : null,
        creationDate: '2026-07-17T00:00:00.000Z',
        revisionDate: '2026-07-17T00:00:00.000Z',
        deletedDate: null,
        archivedDate: null
      }))
    )
    await client.sync()
    await expect(
      client.reconcileLoginImportMarkers([prepared.entries[1]!.marker, prepared.entries[0]!.marker])
    ).resolves.toEqual([
      { marker: prepared.entries[1]!.marker, remoteId: importedIds[1] },
      { marker: prepared.entries[0]!.marker, remoteId: importedIds[0] }
    ])
    await expect(
      client.reconcileLoginImportMarkers([prepared.entries[0]!.marker, '2.unknown-marker'])
    ).resolves.toEqual([{ marker: prepared.entries[0]!.marker, remoteId: importedIds[0] }])
  })

  it('consumes prepared imports before I/O and clears them when the vault locks', async () => {
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
            expires_in: 3_600
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
    await client.login({ email: EMAIL, password: PASSWORD })
    await client.sync()
    const entries = [
      {
        localId: '90000000-0000-4000-8000-000000000011',
        draft: { name: 'One', username: 'u1', password: 'p1' }
      },
      {
        localId: '90000000-0000-4000-8000-000000000012',
        draft: { name: 'Two', username: 'u2', password: 'p2' }
      }
    ]
    const importSpy = vi
      .spyOn(http, 'importPersonalCiphers')
      .mockRejectedValueOnce(new BitwardenHttpError('NETWORK'))
    const unknown = await client.prepareLoginImport(entries)
    await expect(client.prepareLoginImport(entries)).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    await expect(client.executePreparedLoginImport(unknown.token)).rejects.toMatchObject({
      code: 'NETWORK'
    })
    await expect(client.executePreparedLoginImport(unknown.token)).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
    expect(importSpy).toHaveBeenCalledTimes(1)

    const discarded = await client.prepareLoginImport(entries)
    await client.discardPreparedLoginImport(discarded.token)
    await expect(client.executePreparedLoginImport(discarded.token)).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })

    const locked = await client.prepareLoginImport(entries)
    await client.lock()
    await expect(client.executePreparedLoginImport(locked.token)).rejects.toMatchObject({
      code: 'INVALID_RESPONSE'
    })
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
        archivedAt: ARCHIVED_AT,
        privateKey: 'fake-created-private-key',
        publicKey: 'ssh-ed25519 AAAA created',
        fingerprint: 'SHA256:created-fingerprint'
      })
    ).resolves.toEqual(
      expect.objectContaining({
        id: CREATED_ID,
        type: 'sshKey',
        fingerprint: 'SHA256:created-fingerprint',
        archivedAt: ARCHIVED_AT
      })
    )
    expect(writes[1]).toMatchObject({
      type: 5,
      archivedDate: ARCHIVED_AT,
      sshKey: { keyFingerprint: expect.any(String) }
    })
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
        passwordRevisionDate: '2026-07-13T00:00:00.000Z',
        autofillOnPageLoad: false,
        totp: 'otpauth://totp/example.invalid?secret=JBSWY3DPEHPK3PXP',
        passkeys: [expect.objectContaining({ rpId: 'example.invalid', discoverable: true })],
        customFields: [
          { name: 'member-id', value: 'v2-member-42', type: 'text', linkedId: null },
          { name: 'recovery-code', value: 'v2-hidden-code', type: 'hidden', linkedId: null },
          { name: 'remember-device', value: 'true', type: 'boolean', linkedId: null },
          { name: 'alternate-username', value: '', type: 'linked', linkedId: 100 }
        ],
        attachments: [
          {
            id: 'v2-attachment-id',
            fileName: 'v2-document.txt',
            size: 1,
            sizeName: '1 B',
            legacy: false
          }
        ],
        reprompt: 1
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
        reprompt: 0,
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
    expect((JSON.parse(cipherWrites[0]!) as JsonObject).reprompt).toBe(0)
    expect(editedBlob).toMatchObject({
      fields: [
        { name: 'member-id', value: 'v2-member-42', type: 0, linkedId: null },
        { name: 'recovery-code', value: 'v2-hidden-code', type: 1, linkedId: null },
        { name: 'remember-device', value: 'true', type: 2, linkedId: null },
        { name: 'alternate-username', value: null, type: 3, linkedId: 100 }
      ],
      passwordHistory: [{ password: 'old-v2-secret', lastUsedDate: '2026-01-01T00:00:00.000Z' }],
      futureRootField: 'preserve-root',
      typeData: {
        futureLoginField: { preserve: true },
        passwordRevisionDate: '2026-07-13T00:00:00.000Z',
        autofillOnPageLoad: false,
        uris: [
          { uri: 'https://edited-primary.v2.example.invalid', match: 2 },
          {
            uri: 'https://backup.v2.example.invalid',
            match: 1,
            uriChecksum: 'blob-backup-checksum'
          }
        ]
      }
    })
    expect(((editedBlob.typeData as JsonObject).uris as JsonObject[])[0]).not.toHaveProperty(
      'uriChecksum'
    )
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

    await client.editLogin(LOGIN_ID, {
      name: 'V2 existing edited',
      passwordHistory: [{ password: 'new-v2-history', lastUsedDate: '2026-01-04T00:00:00.000Z' }],
      uris: [
        { uri: 'https://backup.v2.example.invalid', match: 1 },
        { uri: 'https://edited-primary.v2.example.invalid', match: 2 }
      ]
    })
    const reorderedBlob = decryptBitwardenCipherBlob(
      (JSON.parse(cipherWrites[1]!) as JsonObject).data as string,
      Buffer.alloc(64, 9)
    ) as JsonObject
    const reorderedUris = ((reorderedBlob.typeData as JsonObject).uris ?? []) as JsonObject[]
    expect(reorderedBlob.passwordHistory).toEqual([
      { password: 'new-v2-history', lastUsedDate: '2026-01-04T00:00:00.000Z' }
    ])
    expect(reorderedUris[0]).toMatchObject({ uriChecksum: 'blob-backup-checksum' })
    expect(reorderedUris[1]).not.toHaveProperty('uriChecksum')

    await client.editLogin(LOGIN_ID, {
      name: 'V2 existing edited',
      uris: [
        { uri: 'https://new.v2.example.invalid', match: null },
        { uri: 'https://backup.v2.example.invalid', match: 1 },
        { uri: 'https://edited-primary.v2.example.invalid', match: 2 }
      ]
    })
    const prependedBlob = decryptBitwardenCipherBlob(
      (JSON.parse(cipherWrites[2]!) as JsonObject).data as string,
      Buffer.alloc(64, 9)
    ) as JsonObject
    const prependedUris = ((prependedBlob.typeData as JsonObject).uris ?? []) as JsonObject[]
    expect(prependedUris[0]).not.toHaveProperty('uriChecksum')
    expect(prependedUris[1]).toMatchObject({ uriChecksum: 'blob-backup-checksum' })
    expect(prependedUris[2]).not.toHaveProperty('uriChecksum')

    await expect(
      client.createLogin({
        name: 'V2 created login',
        username: 'created@example.invalid',
        password: 'created-fake-secret',
        reprompt: 1,
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
        reprompt: 1,
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
    expect(cipherWrites).toHaveLength(9)
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
