import { describe, expect, it } from 'vitest'
import type { VaultItemType } from '../shared/vault-contract'
import { deriveMasterKey, encryptBitwardenString, stretchMasterKey } from './bitwarden-crypto'
import type { StoredPasskeyCredential } from './passkey'
import {
  buildBitwardenJson,
  decryptBitwardenPasswordProtectedJson,
  encryptBitwardenPasswordProtectedJson,
  parseBitwardenJson,
  parseBitwardenOrChromiumCsv,
  type PortableVaultItem,
  type PortableVaultSnapshot
} from './vault-portability-codec'
import { VaultError } from './vault-errors'

const CREATED_AT = '2026-07-01T00:00:00.000Z'
const UPDATED_AT = '2026-07-02T00:00:00.000Z'
const ARCHIVED_AT = '2026-07-03T00:00:00.000Z'

const passkey: StoredPasskeyCredential = {
  credentialId: 'credential-id',
  keyType: 'public-key',
  keyAlgorithm: 'ECDSA',
  keyCurve: 'P-256',
  keyValue: 'private-passkey-material',
  rpId: 'example.test',
  userHandle: 'user-handle',
  userName: 'tester',
  counter: '7',
  rpName: 'Example',
  userDisplayName: 'Test User',
  discoverable: true,
  creationDate: CREATED_AT
}

function item(type: VaultItemType, id = `${type}-id`): PortableVaultItem {
  return {
    id,
    type,
    name: `${type} item`,
    notes: 'portable notes',
    folderId: 'folder:untrusted-but-bounded',
    favorite: type === 'login',
    createdAt: CREATED_AT,
    updatedAt: UPDATED_AT,
    deletedAt: null,
    archivedAt: type === 'secureNote' ? ARCHIVED_AT : null,
    reprompt: type === 'login' ? 1 : 0,
    username: type === 'login' ? 'login-user' : '',
    password: type === 'login' ? 'current-secret' : '',
    totp: type === 'login' ? 'otpauth://totp/Example?secret=TOPSECRET' : '',
    uri: type === 'login' ? 'https://example.test/login' : null,
    uris:
      type === 'login'
        ? [
            { uri: 'https://example.test/login', match: 1 },
            { uri: 'https://m.example.test', match: 3 }
          ]
        : [],
    cardholderName: type === 'card' ? 'Test Cardholder' : '',
    brand: type === 'card' ? 'visa' : '',
    number: type === 'card' ? '4111111111111111' : '',
    expMonth: type === 'card' ? '12' : '',
    expYear: type === 'card' ? '2030' : '',
    code: type === 'card' ? '123' : '',
    title: type === 'identity' ? 'Mx' : '',
    firstName: type === 'identity' ? 'Test' : '',
    middleName: '',
    lastName: type === 'identity' ? 'Person' : '',
    address1: type === 'identity' ? 'Example address' : '',
    address2: '',
    address3: '',
    city: type === 'identity' ? 'Test City' : '',
    state: '',
    postalCode: '',
    country: type === 'identity' ? 'TW' : '',
    company: '',
    email: '',
    phone: '',
    ssn: '',
    identityUsername: type === 'identity' ? 'identity-user' : '',
    passportNumber: '',
    licenseNumber: '',
    privateKey:
      type === 'sshKey' ? '-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----' : '',
    publicKey: type === 'sshKey' ? 'ssh-ed25519 AAAATEST' : '',
    fingerprint: type === 'sshKey' ? 'SHA256:test' : '',
    passkeys: type === 'login' ? [passkey] : [],
    customFields:
      type === 'login'
        ? [
            { name: 'API secret', value: 'hidden-secret', type: 'hidden', linkedId: null },
            { name: 'Username link', value: '', type: 'linked', linkedId: 100 }
          ]
        : [],
    passwordHistory:
      type === 'login'
        ? [{ password: 'previous-secret', lastUsedDate: '2026-06-01T00:00:00.000Z' }]
        : [],
    passwordRevisionDate: null,
    autofillOnPageLoad: null
  }
}

function snapshot(): PortableVaultSnapshot {
  return {
    folders: [{ id: 'folder:untrusted-but-bounded', name: 'Portable folder' }],
    items: (['login', 'secureNote', 'card', 'identity', 'sshKey'] as const).map((type) =>
      item(type)
    )
  }
}

async function expectInvalidInput(action: () => unknown | Promise<unknown>): Promise<void> {
  await expect(Promise.resolve().then(action)).rejects.toMatchObject({
    name: 'VaultError',
    code: 'INVALID_INPUT'
  })
}

describe('Bitwarden plaintext JSON portability', () => {
  it('omits login wire metadata that is not part of the official export model', () => {
    const original = snapshot()
    original.items[0]!.passwordRevisionDate = '2026-06-02T00:00:00.000Z'
    original.items[0]!.autofillOnPageLoad = false

    const wire = JSON.parse(buildBitwardenJson(original))
    expect(wire.items[0].login).not.toHaveProperty('passwordRevisionDate')
    expect(wire.items[0].login).not.toHaveProperty('autofillOnPageLoad')
    expect(parseBitwardenJson(JSON.stringify(wire)).snapshot.items[0]).toMatchObject({
      passwordRevisionDate: null,
      autofillOnPageLoad: null
    })
  })

  it('round-trips login wire metadata for BearWarden full backups', () => {
    const original = snapshot()
    original.items[0]!.passwordRevisionDate = '2026-06-02T00:00:00.000Z'
    original.items[0]!.autofillOnPageLoad = false

    const json = buildBitwardenJson(original, { includeLoginWireMetadata: true })
    const wire = JSON.parse(json)
    expect(wire.items[0].login).toMatchObject({
      passwordRevisionDate: '2026-06-02T00:00:00.000Z',
      autofillOnPageLoad: false
    })
    expect(parseBitwardenJson(json).snapshot.items[0]).toMatchObject({
      passwordRevisionDate: '2026-06-02T00:00:00.000Z',
      autofillOnPageLoad: false
    })
  })

  it('round-trips all five supported item types and private metadata', () => {
    const original = snapshot()
    const json = buildBitwardenJson(original)
    const wire = JSON.parse(json) as { encrypted: boolean; items: Array<Record<string, unknown>> }

    expect(wire.encrypted).toBe(false)
    expect(wire.items.map((entry) => entry.type)).toEqual([1, 2, 3, 4, 5])
    expect(wire.items[0]).toMatchObject({
      reprompt: 1,
      login: {
        username: 'login-user',
        password: 'current-secret',
        totp: 'otpauth://totp/Example?secret=TOPSECRET',
        uris: [
          { uri: 'https://example.test/login', match: 1 },
          { uri: 'https://m.example.test', match: 3 }
        ],
        fido2Credentials: [{ keyValue: 'private-passkey-material', discoverable: 'true' }]
      },
      fields: [
        { name: 'API secret', value: 'hidden-secret', type: 1, linkedId: null },
        { name: 'Username link', value: null, type: 3, linkedId: 100 }
      ],
      passwordHistory: [{ password: 'previous-secret' }]
    })

    expect(parseBitwardenJson(json)).toEqual({ snapshot: original, skippedTrashItems: 0 })
  })

  it('skips trash on import and excludes it on export', () => {
    const active = item('login', 'active')
    const trashed = { ...item('login', 'trash'), deletedAt: ARCHIVED_AT }
    const exported = JSON.parse(
      buildBitwardenJson({ folders: snapshot().folders, items: [active, trashed] })
    ) as { items: Array<{ id: string }> }
    expect(exported.items.map(({ id }) => id)).toEqual(['active'])

    const trashWire = JSON.parse(
      buildBitwardenJson({ folders: snapshot().folders, items: [active] })
    )
    trashWire.items.push({ ...trashWire.items[0], id: 'trash', deletedDate: ARCHIVED_AT })
    expect(parseBitwardenJson(JSON.stringify(trashWire))).toMatchObject({
      snapshot: { items: [{ id: 'active' }] },
      skippedTrashItems: 1
    })
  })

  it('rejects duplicate folders and missing folder references', () => {
    const original = JSON.parse(buildBitwardenJson(snapshot()))
    original.folders.push({ ...original.folders[0] })
    expect(() => parseBitwardenJson(JSON.stringify(original))).toThrowError(VaultError)

    const badReference = JSON.parse(buildBitwardenJson(snapshot()))
    badReference.items[0].folderId = 'missing-folder'
    expect(() => parseBitwardenJson(JSON.stringify(badReference))).toThrowError(VaultError)
  })

  it('rejects unknown item types rather than downgrading them', () => {
    const wire = JSON.parse(buildBitwardenJson(snapshot()))
    wire.items[0].type = 999
    expect(() => parseBitwardenJson(JSON.stringify(wire))).toThrowError(VaultError)
  })

  it('rejects oversized entity arrays, nested arrays, and fields', () => {
    expect(() =>
      parseBitwardenJson(
        JSON.stringify({ encrypted: false, folders: [], items: Array(100_001).fill(null) })
      )
    ).toThrowError(VaultError)

    const uris = JSON.parse(buildBitwardenJson(snapshot()))
    uris.items[0].login.uris = Array(1_001).fill({ uri: 'https://example.test', match: null })
    expect(() => parseBitwardenJson(JSON.stringify(uris))).toThrowError(VaultError)

    const fields = JSON.parse(buildBitwardenJson(snapshot()))
    fields.items[0].fields = Array(1_001).fill({ name: 'field', value: 'value', type: 0 })
    expect(() => parseBitwardenJson(JSON.stringify(fields))).toThrowError(VaultError)

    const passkeys = JSON.parse(buildBitwardenJson(snapshot()))
    passkeys.items[0].login.fido2Credentials = Array(1_001).fill(passkey)
    expect(() => parseBitwardenJson(JSON.stringify(passkeys))).toThrowError(VaultError)

    const history = JSON.parse(buildBitwardenJson(snapshot()))
    history.items[0].passwordHistory = Array(6).fill({
      password: 'old-secret',
      lastUsedDate: CREATED_AT
    })
    expect(() => parseBitwardenJson(JSON.stringify(history))).toThrowError(VaultError)

    const longName = JSON.parse(buildBitwardenJson(snapshot()))
    longName.items[0].name = 'x'.repeat(257)
    expect(() => parseBitwardenJson(JSON.stringify(longName))).toThrowError(VaultError)

    const invalidDate = JSON.parse(buildBitwardenJson(snapshot()))
    invalidDate.items[0].archivedDate = '2026-07-03'
    expect(() => parseBitwardenJson(JSON.stringify(invalidDate))).toThrowError(VaultError)

    const maximumSshKey = snapshot()
    maximumSshKey.items[4]!.privateKey = 'x'.repeat(1024 * 1024)
    expect(() => buildBitwardenJson(maximumSshKey)).not.toThrow()
    maximumSshKey.items[4]!.privateKey += 'x'
    expect(() => buildBitwardenJson(maximumSshKey)).toThrowError(VaultError)
  })
})

describe('Bitwarden and Chromium CSV portability', () => {
  it('parses the official Bitwarden CSV fields with RFC 4180 quoting and folders', () => {
    const csv = [
      'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp',
      'Social,1,login,"Example, Inc.","line one\r\nline ""two""","PIN: 1234\r\nRegion: TW",1,https://example.test,user,secret,TOTPSEED',
      'Social,0,note,Recovery,"secure,note",,0,,,,',
      ''
    ].join('\r\n')

    expect(parseBitwardenOrChromiumCsv(csv)).toEqual({
      skippedTrashItems: 0,
      snapshot: {
        folders: [{ id: 'csv-folder-1', name: 'Social' }],
        items: [
          expect.objectContaining({
            id: 'csv-item-1',
            type: 'login',
            name: 'Example, Inc.',
            notes: 'line one\r\nline "two"',
            folderId: 'csv-folder-1',
            favorite: true,
            reprompt: 1,
            uri: 'https://example.test',
            username: 'user',
            password: 'secret',
            totp: 'TOTPSEED',
            customFields: [
              { name: 'PIN', value: '1234', type: 'text', linkedId: null },
              { name: 'Region', value: 'TW', type: 'text', linkedId: null }
            ]
          }),
          expect.objectContaining({
            id: 'csv-item-2',
            type: 'secureNote',
            name: 'Recovery',
            notes: 'secure,note',
            folderId: 'csv-folder-1'
          })
        ]
      }
    })
  })

  it('detects Chrome and Chromium CSV, including notes and Android application URIs', () => {
    const csv = [
      '\ufeffname,url,username,password,note',
      'Example,https://example.test,alice,secret,"browser note"',
      ',android://hash@com.example.app/path,bob,android-secret,'
    ].join('\n')

    const parsed = parseBitwardenOrChromiumCsv(csv)
    expect(parsed.snapshot.folders).toEqual([])
    expect(parsed.snapshot.items).toEqual([
      expect.objectContaining({
        name: 'Example',
        uri: 'https://example.test',
        username: 'alice',
        password: 'secret',
        notes: 'browser note'
      }),
      expect.objectContaining({
        name: 'com.example.app',
        uri: 'androidapp://com.example.app',
        username: 'bob',
        password: 'android-secret'
      })
    ])
  })

  it('fails closed on malformed CSV, unknown schemas, lossy note rows, and bounds', async () => {
    for (const csv of [
      'name,url,username,password\n"unterminated,https://example.test,user,secret',
      'name,url,username,password\nname,"quoted"tail,user,secret',
      'unknown,url,username,password\nname,https://example.test,user,secret',
      'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,card,Card,,,,,,,,',
      'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,note,Note,,,,https://example.test,,,',
      `name,url,username,password\n${'x'.repeat(257)},https://example.test,user,secret`,
      `name,url,username,password\nname,https://example.test,user,${'x'.repeat(16_385)}`
    ]) {
      await expectInvalidInput(() => parseBitwardenOrChromiumCsv(csv))
    }

    const tooManyRows = [
      'name,url,username,password',
      ...Array.from({ length: 40_001 }, () => 'name,https://example.test,user,secret')
    ].join('\n')
    await expectInvalidInput(() => parseBitwardenOrChromiumCsv(tooManyRows))
  })
})

describe('Bitwarden password-protected JSON portability', () => {
  it('emits the official outer shape and decrypts successfully', async () => {
    const clearText = buildBitwardenJson(snapshot())
    const encrypted = await encryptBitwardenPasswordProtectedJson(clearText, 'backup-password')
    const outer = JSON.parse(encrypted) as Record<string, unknown>

    expect(Object.keys(outer)).toEqual([
      'encrypted',
      'passwordProtected',
      'salt',
      'kdfType',
      'kdfIterations',
      'encKeyValidation_DO_NOT_EDIT',
      'data'
    ])
    expect(outer).toMatchObject({
      encrypted: true,
      passwordProtected: true,
      kdfType: 0,
      kdfIterations: 600_000
    })
    expect(Buffer.from(outer.salt as string, 'base64')).toHaveLength(16)
    expect(await decryptBitwardenPasswordProtectedJson(encrypted, 'backup-password')).toBe(
      clearText
    )
  })

  it('unifies wrong-password and authenticated-data failures without leaking secrets', async () => {
    const secret = 'never-include-this-secret-in-errors'
    const encrypted = await encryptBitwardenPasswordProtectedJson(secret, 'correct-password')
    const wrongPasswordError = await decryptBitwardenPasswordProtectedJson(
      encrypted,
      'wrong-password'
    ).catch((error: unknown) => error)
    expect(wrongPasswordError).toMatchObject({ name: 'VaultError', code: 'INVALID_INPUT' })
    expect(String((wrongPasswordError as Error).message)).not.toContain(secret)

    const tampered = JSON.parse(encrypted) as { data: string }
    const parts = tampered.data.split('|')
    parts[1] = `${parts[1]![0] === 'A' ? 'B' : 'A'}${parts[1]!.slice(1)}`
    tampered.data = parts.join('|')
    await expect(
      decryptBitwardenPasswordProtectedJson(JSON.stringify(tampered), 'correct-password')
    ).rejects.toMatchObject({ name: 'VaultError', code: 'INVALID_INPUT' })
  })

  it('decrypts official Argon2id password-protected exports', async () => {
    const password = 'argon2-backup-password'
    const clearText = buildBitwardenJson(snapshot())
    const salt = Buffer.from('0123456789abcdef', 'utf8').toString('base64')
    let masterKey: Buffer | undefined
    let encKey: Buffer | undefined
    let macKey: Buffer | undefined
    let combinedKey: Buffer | undefined
    try {
      masterKey = await deriveMasterKey(password, salt, {
        type: 'argon2id',
        iterations: 2,
        memoryMiB: 16,
        parallelism: 1
      })
      ;({ encKey, macKey, combinedKey } = stretchMasterKey(masterKey))
      const encrypted = JSON.stringify({
        encrypted: true,
        passwordProtected: true,
        salt,
        kdfType: 1,
        kdfIterations: 2,
        kdfMemory: 16,
        kdfParallelism: 1,
        encKeyValidation_DO_NOT_EDIT: encryptBitwardenString(
          '00000000-0000-4000-8000-000000000001',
          combinedKey
        ),
        data: encryptBitwardenString(clearText, combinedKey)
      })

      expect(await decryptBitwardenPasswordProtectedJson(encrypted, password)).toBe(clearText)
    } finally {
      masterKey?.fill(0)
      encKey?.fill(0)
      macKey?.fill(0)
      combinedKey?.fill(0)
    }
  })

  it('rejects low, excessive, unsupported, and malformed KDF parameters', async () => {
    const encrypted = await encryptBitwardenPasswordProtectedJson('{}', 'backup-password')
    const outer = JSON.parse(encrypted)
    await expectInvalidInput(() =>
      decryptBitwardenPasswordProtectedJson(
        JSON.stringify({ ...outer, kdfIterations: 4_999 }),
        'backup-password'
      )
    )
    await expectInvalidInput(() =>
      decryptBitwardenPasswordProtectedJson(
        JSON.stringify({ ...outer, kdfIterations: 10_000_001 }),
        'backup-password'
      )
    )
    for (const argonParams of [
      { kdfIterations: 1, kdfMemory: 16, kdfParallelism: 1 },
      { kdfIterations: 2, kdfMemory: 15, kdfParallelism: 1 },
      { kdfIterations: 2, kdfMemory: 16, kdfParallelism: 0 },
      { kdfIterations: 101, kdfMemory: 16, kdfParallelism: 1 },
      { kdfIterations: 2, kdfMemory: 1_025, kdfParallelism: 1 },
      { kdfIterations: 2, kdfMemory: 16, kdfParallelism: 65 }
    ]) {
      await expectInvalidInput(() =>
        decryptBitwardenPasswordProtectedJson(
          JSON.stringify({ ...outer, kdfType: 1, ...argonParams }),
          'backup-password'
        )
      )
    }
    await expectInvalidInput(() =>
      decryptBitwardenPasswordProtectedJson(
        JSON.stringify({ ...outer, salt: `${outer.salt}=x` }),
        'backup-password'
      )
    )
  })
})
