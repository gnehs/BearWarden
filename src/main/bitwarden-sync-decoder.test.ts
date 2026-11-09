import { constants, generateKeyPairSync, publicEncrypt } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  deriveBitwardenSendKey,
  encryptBitwardenBytes,
  encryptBitwardenString
} from './bitwarden-crypto'
import { BitwardenDirectError } from './bitwarden-direct-error'
import type { JsonObject } from './bitwarden-http'
import { decodeSyncPayload, SyncPayloadError } from './bitwarden-sync-decoder'

const PROFILE_ID = '10000000-0000-4000-8000-000000000001'
const FOLDER_ID = '20000000-0000-4000-8000-000000000001'
const LOGIN_ID = '30000000-0000-4000-8000-000000000001'
const FUTURE_ID = '30000000-0000-4000-8000-000000000002'
const CORRUPT_ID = '30000000-0000-4000-8000-000000000003'
const SEND_ID = '50000000-0000-4000-8000-000000000001'
const ORGANIZATION_ID = '60000000-0000-4000-8000-000000000001'
const COLLECTION_ID = '70000000-0000-4000-8000-000000000001'
const SHARED_ID = '80000000-0000-4000-8000-000000000001'
const POLICY_ID = 'a0000000-0000-4000-8000-000000000001'

const userKey = Buffer.alloc(64, 7)
const itemKey = Buffer.alloc(64, 9)
const organizationKey = Buffer.alloc(64, 11)

function login(id: string, key: Buffer, wrappingKey: Buffer, extra: JsonObject = {}): JsonObject {
  return {
    id,
    type: 1,
    organizationId: null,
    folderId: null,
    name: encryptBitwardenString('Example', key),
    notes: null,
    favorite: false,
    key: encryptBitwardenBytes(key, wrappingKey),
    login: {
      username: encryptBitwardenString('bear@example.invalid', key),
      password: encryptBitwardenString('secret', key),
      uris: []
    },
    revisionDate: '2026-07-14T00:00:00.000Z',
    ...extra
  }
}

function personalPayload(): { payload: JsonObject; profile: JsonObject } {
  const seed = Buffer.alloc(16, 3)
  const sendKey = deriveBitwardenSendKey(seed)
  const profile: JsonObject = { id: PROFILE_ID, securityStamp: 'stamp' }
  const payload: JsonObject = {
    profile,
    folders: [{ id: FOLDER_ID, name: encryptBitwardenString('Personal', userKey) }],
    ciphers: [login(LOGIN_ID, itemKey, userKey, { futureServerField: { kept: true } })],
    sends: [
      {
        id: SEND_ID,
        accessId: 'UAAAAAAAQABAAAAAAAAAAQ',
        type: 0,
        key: encryptBitwardenBytes(seed, userKey),
        name: encryptBitwardenString('Note', sendKey),
        text: { text: encryptBitwardenString('shared', sendKey), hidden: false },
        accessCount: 0,
        revisionDate: '2026-07-16T00:00:00.000Z',
        deletionDate: '2026-07-30T00:00:00.000Z'
      }
    ]
  }
  return { payload, profile }
}

/** A legacy-key account holding one organization with a collection and a shared login. */
function organizationPayload(): { payload: JsonObject; profile: JsonObject } {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const privateKey = rsa.privateKey.export({ format: 'der', type: 'pkcs8' })
  const wrappedOrganizationKey = publicEncrypt(
    { key: rsa.publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' },
    organizationKey
  )
  const { payload, profile } = personalPayload()
  profile.privateKey = encryptBitwardenBytes(privateKey, userKey)
  profile.organizationsNew = [
    {
      id: ORGANIZATION_ID,
      name: 'Team',
      key: `4.${wrappedOrganizationKey.toString('base64')}`,
      usePolicies: true
    }
  ]
  payload.collections = [
    {
      id: COLLECTION_ID,
      organizationId: ORGANIZATION_ID,
      name: encryptBitwardenString('Shared', organizationKey)
    }
  ]
  ;(payload.ciphers as JsonObject[]).push(
    login(SHARED_ID, itemKey, organizationKey, {
      organizationId: ORGANIZATION_ID,
      collectionIds: [COLLECTION_ID]
    })
  )
  payload.policiesNew = [{ id: POLICY_ID, organizationId: ORGANIZATION_ID, type: 6, enabled: true }]
  return { payload, profile }
}

function rejection(run: () => unknown): SyncPayloadError {
  try {
    run()
  } catch (error) {
    expect(error).toBeInstanceOf(SyncPayloadError)
    return error as SyncPayloadError
  }
  throw new Error('expected decodeSyncPayload to throw')
}

describe('decodeSyncPayload', () => {
  it('decodes personal rows and keeps each raw row as an independent copy', () => {
    const { payload, profile } = personalPayload()
    const snapshot = decodeSyncPayload(payload, profile, userKey)

    expect([...snapshot.folders.values()].map(({ item }) => item)).toEqual([
      { id: FOLDER_ID, name: 'Personal' }
    ])
    const cached = snapshot.logins.get(LOGIN_ID)!
    expect(cached.item).toMatchObject({ name: 'Example', username: 'bear@example.invalid' })
    expect(cached.raw).toEqual((payload.ciphers as JsonObject[])[0])
    expect(cached.raw).not.toBe((payload.ciphers as JsonObject[])[0])
    expect(cached.raw.futureServerField).toEqual({ kept: true })
    expect(snapshot.sends.get(SEND_ID)?.item).toMatchObject({ name: 'Note', text: 'shared' })
    expect(snapshot.policySet).toEqual({ source: 'none', policies: [] })
    expect(snapshot.equivalentDomainSettings).toEqual({
      equivalentDomains: [],
      globalEquivalentDomains: []
    })
    expect(snapshot.isolatedPersonalCiphers.size).toBe(0)
  })

  it('isolates unsupported and undecryptable personal ciphers instead of failing', () => {
    const { payload, profile } = personalPayload()
    ;(payload.ciphers as JsonObject[]).push(
      { ...login(FUTURE_ID, itemKey, userKey), type: 99 },
      { ...login(CORRUPT_ID, itemKey, userKey), name: 'not-a-cipherstring' }
    )
    const snapshot = decodeSyncPayload(payload, profile, userKey)

    expect([...snapshot.isolatedPersonalCiphers].sort()).toEqual([FUTURE_ID, CORRUPT_ID].sort())
    expect([...snapshot.logins.keys()]).toEqual([LOGIN_ID])
  })

  it('decodes organization data and returns organization keys the caller owns', () => {
    const { payload, profile } = organizationPayload()
    const snapshot = decodeSyncPayload(payload, profile, userKey)

    expect(snapshot.organizationCiphers.get(SHARED_ID)).toMatchObject({
      organizationId: ORGANIZATION_ID,
      collectionIds: [COLLECTION_ID],
      name: 'Example'
    })
    expect(snapshot.organizationCipherRaws.get(SHARED_ID)?.id).toBe(SHARED_ID)
    expect(snapshot.collections.get(COLLECTION_ID)?.name).toBe('Shared')
    expect(snapshot.organizationKeys.get(ORGANIZATION_ID)).toEqual(organizationKey)
    expect(snapshot.policySet).toMatchObject({
      source: 'policiesNew',
      applicableOrganizationIds: [ORGANIZATION_ID]
    })

    snapshot.organizationKeys.get(ORGANIZATION_ID)!.fill(0)
    const again = decodeSyncPayload(payload, profile, userKey)
    expect(again.organizationKeys.get(ORGANIZATION_ID)).toEqual(organizationKey)
  })

  it('fails closed on an unsupported organization cipher type', () => {
    const { payload, profile } = organizationPayload()
    ;(payload.ciphers as JsonObject[])[1]!.type = 99
    const error = rejection(() => decodeSyncPayload(payload, profile, userKey))

    expect(error.stage).toBe('cipher')
    expect(error.cause).toMatchObject({
      code: 'INVALID_RESPONSE',
      syncInvalidResponseReason: 'unsupported-cipher-type'
    })
  })

  it.each([
    ['folder', (payload: JsonObject) => delete payload.folders],
    ['cipher', (payload: JsonObject) => (payload.ciphers = null)],
    ['collection', (payload: JsonObject) => (payload.collections = {})],
    ['send', (payload: JsonObject) => (payload.sends = [null])],
    [
      'organization',
      (_payload: JsonObject, profile: JsonObject) => (profile.organizations = 'not-a-list')
    ],
    [
      'collection',
      (payload: JsonObject) =>
        ((payload.ciphers as JsonObject[])[1]!.collectionIds = [
          '70000000-0000-4000-8000-000000000009'
        ])
    ]
  ] as const)('names the %s section when it is malformed', (stage, mutate) => {
    const { payload, profile } = organizationPayload()
    mutate(payload, profile)
    const error = rejection(() => decodeSyncPayload(payload, profile, userKey))

    expect(error.stage).toBe(stage)
    expect(error.cause).toBeInstanceOf(BitwardenDirectError)
  })
})
