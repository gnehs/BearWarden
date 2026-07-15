import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type {
  BitwardenDirectState,
  BitwardenLoginDraft,
  BitwardenLoginItem,
  BitwardenSyncClient
} from './bitwarden-direct'
import type { VaultItemFields } from '../shared/vault-contract'
import { EncryptedVaultStore } from './encrypted-vault-store'
import { VaultService, type VaultServiceOptions } from './vault-service'

const MASTER_PASSWORD = 'correct horse battery staple'
const IDS = [
  '00000000-0000-4000-8000-000000000001',
  '00000000-0000-4000-8000-000000000002',
  '00000000-0000-4000-8000-000000000003',
  '00000000-0000-4000-8000-000000000004',
  '00000000-0000-4000-8000-000000000005',
  '00000000-0000-4000-8000-000000000006'
]

const temporaryDirectories: string[] = []

const emptyItemFields: VaultItemFields = {
  username: '',
  password: '',
  totp: '',
  uri: null,
  cardholderName: '',
  brand: '',
  number: '',
  expMonth: '',
  expYear: '',
  code: '',
  title: '',
  firstName: '',
  middleName: '',
  lastName: '',
  address1: '',
  address2: '',
  address3: '',
  city: '',
  state: '',
  postalCode: '',
  country: '',
  company: '',
  email: '',
  phone: '',
  ssn: '',
  identityUsername: '',
  passportNumber: '',
  licenseNumber: '',
  privateKey: '',
  publicKey: '',
  fingerprint: ''
}

async function createHarness(options: VaultServiceOptions = {}): Promise<{
  directory: string
  filePath: string
  service: VaultService
  copyText: ReturnType<typeof vi.fn>
  openExternal: ReturnType<typeof vi.fn>
}> {
  const directory = await mkdtemp(join(tmpdir(), 'bearwarden-test-'))
  temporaryDirectories.push(directory)
  const filePath = join(directory, 'vault', 'vault.json')
  const copyText = vi.fn()
  const openExternal = vi.fn()
  let idIndex = 0
  let clock = Date.parse('2026-07-14T00:00:00.000Z')
  const service = new VaultService(
    new EncryptedVaultStore(filePath),
    {
      copyText,
      openExternal
    },
    {
      createId: () => IDS[idIndex++]!,
      now: () => new Date((clock += 1_000)),
      ...options
    }
  )
  return { directory, filePath, service, copyText, openExternal }
}

function createSyncFake(initialState: BitwardenDirectState): BitwardenSyncClient & {
  remoteLogins: BitwardenLoginItem[]
  readonly loginPassword: string | null
} {
  let unlocked = false
  let loginPassword: string | null = null
  let state: BitwardenDirectState = structuredClone(initialState)
  const remoteFolders = [{ id: '90000000-0000-4000-8000-000000000001', name: 'Remote folder' }]
  const remoteLogins: BitwardenLoginItem[] = [
    {
      ...emptyItemFields,
      id: '90000000-0000-4000-8000-000000000002',
      type: 'login',
      organizationId: null,
      folderId: remoteFolders[0]!.id,
      name: 'Remote login',
      notes: null,
      favorite: false,
      username: 'remote@example.invalid',
      password: 'remote-test-secret',
      totp: 'JBSWY3DPEHPK3PXP',
      uris: [{ uri: 'https://remote.example.invalid', match: null }],
      passkeys: [
        {
          credentialId: 'credential-id',
          keyType: 'public-key',
          keyAlgorithm: 'ECDSA',
          keyCurve: 'P-256',
          keyValue: 'fake-passkey-private-material',
          rpId: 'remote.example.invalid',
          userHandle: null,
          userName: 'remote@example.invalid',
          counter: '0',
          rpName: 'Remote example',
          userDisplayName: 'Test User',
          discoverable: true,
          creationDate: '2026-07-13T00:00:00.000Z'
        }
      ],
      creationDate: '2026-07-13T00:00:00.000Z',
      revisionDate: '2026-07-14T00:00:00.000Z'
    }
  ]
  const fromDraft = (id: string, draft: BitwardenLoginDraft): BitwardenLoginItem => ({
    ...emptyItemFields,
    id,
    type: draft.type ?? 'login',
    organizationId: null,
    folderId: draft.folderId ?? null,
    name: draft.name,
    notes: draft.notes ?? null,
    favorite: draft.favorite ?? false,
    username: draft.username ?? '',
    password: draft.password ?? '',
    totp: draft.totp ?? '',
    uri: draft.uri ?? null,
    uris: draft.uri ? [{ uri: draft.uri, match: null }] : [],
    passkeys: draft.passkeys ?? [],
    creationDate: '2026-07-14T00:00:00.000Z',
    revisionDate: '2026-07-14T00:00:01.000Z'
  })

  return {
    remoteLogins,
    get loginPassword() {
      return loginPassword
    },
    status: async () => ({
      status: state.session ? (unlocked ? 'unlocked' : 'locked') : 'unauthenticated'
    }),
    login: async (request) => {
      unlocked = true
      loginPassword = request.password
      state = {
        ...state,
        session: {
          accessToken: 'test-access-token',
          refreshToken: 'test-refresh-token',
          expiresAt: 1
        }
      }
    },
    unlock: async () => {
      unlocked = true
    },
    sync: async () => undefined,
    listFolders: async () => remoteFolders.map((folder) => ({ ...folder })),
    listPersonalLogins: async () =>
      remoteLogins.map((login) => ({ ...login, uris: login.uris.map((uri) => ({ ...uri })) })),
    createFolder: async (name) => {
      const folder = { id: '90000000-0000-4000-8000-000000000003', name }
      remoteFolders.push(folder)
      return { ...folder }
    },
    editFolder: async (id, name) => {
      const folder = remoteFolders.find((candidate) => candidate.id === id)!
      folder.name = name
      return { ...folder }
    },
    deleteFolder: async (id) => {
      const index = remoteFolders.findIndex((folder) => folder.id === id)
      if (index >= 0) remoteFolders.splice(index, 1)
    },
    createLogin: async (draft) => {
      const login = fromDraft('90000000-0000-4000-8000-000000000004', draft)
      remoteLogins.push(login)
      return structuredClone(login)
    },
    editLogin: async (id, draft) => {
      const index = remoteLogins.findIndex((login) => login.id === id)
      const login = fromDraft(id, draft)
      remoteLogins[index] = login
      return structuredClone(login)
    },
    deleteLogin: async (id) => {
      const index = remoteLogins.findIndex((login) => login.id === id)
      if (index >= 0) remoteLogins.splice(index, 1)
    },
    lock: async () => {
      unlocked = false
    },
    logout: async () => {
      unlocked = false
      state = { ...state, session: null }
    },
    exportState: () => structuredClone(state)
  }
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true }))
  )
})

describe('VaultService encrypted local data', () => {
  it('loads a synced login icon only through its configured server endpoint', async () => {
    const iconBytes = Uint8Array.from([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44,
      0x52, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20
    ])
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(iconBytes, { headers: { 'content-type': 'image/png' } }))
    const { service } = await createHarness({
      createSyncClient: (sync) => createSyncFake(sync.state),
      fetch: fetcher
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid/base',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const login = (await service.listLogins())[0]!

    const [firstIcon, secondIcon] = await Promise.all([
      service.getWebsiteIcon({ id: login.id }),
      service.getWebsiteIcon({ id: login.id })
    ])
    expect(firstIcon).toMatch(/^data:image\/png;base64,/)
    expect(secondIcon).toBe(firstIcon)
    expect(fetcher).toHaveBeenCalledOnce()
    expect(String(fetcher.mock.calls[0]?.[0])).toBe(
      'https://vault.example.invalid/base/icons/remote.example.invalid/icon.png'
    )
    await service.getWebsiteIcon({ id: login.id })
    expect(fetcher).toHaveBeenCalledOnce()
  })

  it('pulls and pushes through the direct connector while encrypting its session at rest', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)

    const connected = await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: ' remote master password '
    })
    expect(connected).toMatchObject({ state: 'ready', pulled: 2, pushed: 0, deleted: 0 })
    expect(fake!.loginPassword).toBe(' remote master password ')
    expect((await service.listFolders())[0]?.name).toBe('Remote folder')
    const local = (await service.listLogins())[0]!
    expect(await service.revealPassword({ id: local.id })).toBe('remote-test-secret')
    const localView = await service.getLogin({ id: local.id })
    expect(localView).toMatchObject({
      hasTotp: true,
      createdAt: '2026-07-13T00:00:00.000Z',
      updatedAt: '2026-07-14T00:00:00.000Z',
      passkeys: [expect.objectContaining({ rpId: 'remote.example.invalid' })]
    })
    expect(localView).not.toHaveProperty('totp')
    expect(JSON.stringify(localView)).not.toContain('fake-passkey-private-material')

    await service.updateLogin({ id: local.id, password: 'locally-changed-secret' })
    const synced = await service.syncNow()
    expect(synced.pushed).toBe(1)
    expect(fake!.remoteLogins[0]?.password).toBe('locally-changed-secret')

    const encryptedFile = await readFile(filePath, 'utf8')
    expect(encryptedFile).not.toContain('test-access-token')
    expect(encryptedFile).not.toContain('test-refresh-token')
    expect(encryptedFile).not.toContain('sync@example.invalid')
    expect(encryptedFile).not.toContain('locally-changed-secret')

    await service.lock()
    await service.unlock(MASTER_PASSWORD)
    expect((await service.syncStatus()).state).toBe('locked')
    await expect(service.unlockSyncWithLocalPassword(MASTER_PASSWORD)).resolves.toMatchObject({
      configured: true,
      state: 'ready'
    })
  })

  it('persists only authenticated ciphertext with owner-only permissions', async () => {
    const { filePath, service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({
      name: 'Example',
      username: 'bear@example.invalid',
      password: 'canary-secret-value',
      uri: 'https://example.com'
    })

    const contents = await readFile(filePath, 'utf8')
    expect(contents).toContain('bearwarden-vault')
    expect(contents).not.toContain(MASTER_PASSWORD)
    expect(contents).not.toContain('canary-secret-value')
    expect(contents).not.toContain('bear@example.invalid')

    const envelope = JSON.parse(contents) as { kdf: { salt: string } }
    const authenticatedSalt = envelope.kdf.salt
    envelope.kdf.salt = Buffer.alloc(16, 1).toString('base64')
    await writeFile(filePath, JSON.stringify(envelope), { mode: 0o600 })
    await service.updateLogin({ id: login.id, notes: 'still available' })
    expect(
      (JSON.parse(await readFile(filePath, 'utf8')) as { kdf: { salt: string } }).kdf.salt
    ).toBe(authenticatedSalt)

    if (process.platform !== 'win32') {
      expect((await stat(filePath)).mode & 0o777).toBe(0o600)
    }
  })

  it('supports folder and login CRUD without returning passwords from list or get', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const personal = await service.createFolder({ name: 'Personal' })
    const work = await service.createFolder({ name: 'Work' })
    expect((await service.reorderFolders({ orderedIds: [work.id, personal.id] }))[0]?.id).toBe(
      work.id
    )

    const login = await service.createLogin({
      name: 'Example',
      username: 'bear',
      password: 'secret',
      folderId: personal.id
    })
    expect('password' in login).toBe(false)
    expect('password' in (await service.listLogins())[0]!).toBe(false)
    expect('password' in (await service.getLogin({ id: login.id }))).toBe(false)

    await service.updateLogin({ id: login.id, folderId: work.id, favorite: true })
    expect(await service.getLogin({ id: login.id })).toMatchObject({
      folderId: work.id,
      favorite: true
    })

    await service.deleteFolder({ id: work.id })
    expect((await service.getLogin({ id: login.id })).folderId).toBeNull()
    await service.deleteLogin({ id: login.id })
    expect(await service.listLogins()).toEqual([])
  })

  it('tracks actual copy/open use but not reveal, without changing content updatedAt', async () => {
    const { service, copyText, openExternal } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const alpha = await service.createLogin({
      name: 'Alpha',
      username: 'a',
      password: 'alpha-secret',
      uri: 'https://alpha.example'
    })
    const zeta = await service.createLogin({
      name: 'Zeta',
      username: 'z',
      password: 'zeta-secret',
      uri: 'https://zeta.example'
    })

    expect((await service.listLogins()).map((login) => login.name)).toEqual(['Alpha', 'Zeta'])
    expect(await service.revealPassword({ id: zeta.id })).toBe('zeta-secret')
    expect((await service.getLogin({ id: zeta.id })).lastUsedAt).toBeNull()

    const originalUpdatedAt = (await service.getLogin({ id: zeta.id })).updatedAt
    await service.copyPassword({ id: zeta.id })
    expect(copyText).toHaveBeenCalledWith('zeta-secret')
    expect((await service.listLogins())[0]?.id).toBe(zeta.id)
    expect((await service.getLogin({ id: zeta.id })).updatedAt).toBe(originalUpdatedAt)

    const alphaUpdatedAt = (await service.getLogin({ id: alpha.id })).updatedAt
    await service.copyUsername({ id: alpha.id })
    expect(copyText).toHaveBeenCalledWith('a')

    await service.openLoginUri({ id: alpha.id })
    expect(openExternal).toHaveBeenCalledWith('https://alpha.example/')
    expect((await service.listLogins())[0]?.id).toBe(alpha.id)
    expect((await service.getLogin({ id: alpha.id })).updatedAt).toBe(alphaUpdatedAt)
  })

  it('generates and copies TOTP in the main process without exposing its seed', async () => {
    const { service, copyText } = await createHarness({ now: () => new Date(59_000) })
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({
      name: 'TOTP example',
      username: 'test-user',
      password: 'test-password',
      totp: 'JBSWY3DPEHPK3PXP'
    })

    expect(login).toMatchObject({ hasTotp: true, passkeys: [] })
    expect(login).not.toHaveProperty('totp')
    await expect(service.getTotp({ id: login.id })).resolves.toEqual({
      code: '996554',
      period: 30,
      remainingSeconds: 1
    })
    await service.copyTotp({ id: login.id })
    expect(copyText).toHaveBeenCalledWith('996554')

    const cleared = await service.updateLogin({ id: login.id, totp: '' })
    expect(cleared.hasTotp).toBe(false)
    await expect(service.getTotp({ id: login.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
  })

  it('zeroes the active key on lock and accepts canonically equivalent passwords', async () => {
    const { filePath, service } = await createHarness()
    const decomposedPassword = `secure-password-${'e\u0301'}`
    const composedPassword = `secure-password-${'é'}`
    await service.setup(decomposedPassword)
    await service.createLogin({ name: 'Example', username: '', password: 'secret' })
    await service.lock()
    expect(await service.status()).toEqual({ state: 'locked' })
    await expect(service.listLogins()).rejects.toMatchObject({ code: 'LOCKED' })

    const secondService = new VaultService(new EncryptedVaultStore(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(secondService.unlock('definitely the wrong password')).rejects.toMatchObject({
      code: 'INVALID_MASTER_PASSWORD'
    })
    await expect(secondService.unlock(composedPassword)).resolves.toEqual({ state: 'unlocked' })
    expect((await secondService.listLogins())[0]?.name).toBe('Example')
  })

  it('rejects authenticated ciphertext tampering', async () => {
    const { filePath, service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    await service.createLogin({ name: 'Example', username: '', password: 'secret' })
    await service.lock()

    const envelope = JSON.parse(await readFile(filePath, 'utf8')) as { ciphertext: string }
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64')
    ciphertext[0] = ciphertext[0]! ^ 1
    envelope.ciphertext = ciphertext.toString('base64')
    ciphertext.fill(0)
    await writeFile(filePath, JSON.stringify(envelope), { mode: 0o600 })

    await expect(service.unlock(MASTER_PASSWORD)).rejects.toMatchObject({
      code: 'INVALID_MASTER_PASSWORD'
    })
    expect(await service.status()).toEqual({ state: 'locked' })
  })

  it('rejects non-http URLs without marking the login as used', async () => {
    const { service, openExternal } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({
      name: 'Unsafe',
      username: '',
      password: '',
      uri: 'file:///tmp/not-allowed'
    })
    await expect(service.openLoginUri({ id: login.id })).rejects.toMatchObject({
      code: 'INVALID_URL'
    })
    expect(openExternal).not.toHaveBeenCalled()
    expect((await service.getLogin({ id: login.id })).lastUsedAt).toBeNull()
  })

  it('stores all five item types without exposing sensitive fields in list or detail responses', async () => {
    const { service, copyText } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const folder = await service.createFolder({ name: 'Private' })
    const card = await service.createLogin({
      type: 'card',
      name: 'Test card',
      cardholderName: 'Test holder',
      brand: 'visa',
      number: '4242424242424242',
      expMonth: '12',
      expYear: '2030',
      code: '123',
      folderId: folder.id
    })
    const identity = await service.createLogin({
      type: 'identity',
      name: 'Test identity',
      firstName: 'Test',
      lastName: 'Person',
      email: 'person@example.invalid',
      ssn: '123-45-6789',
      identityUsername: 'identity-user'
    })
    const note = await service.createLogin({
      type: 'secureNote',
      name: 'Test note',
      notes: 'private note body'
    })
    const sshKey = await service.createLogin({
      type: 'sshKey',
      name: 'Test SSH key',
      privateKey: '-----BEGIN PRIVATE KEY-----\nprivate-test-key\n-----END PRIVATE KEY-----',
      publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest key@example.invalid',
      fingerprint: 'SHA256:test'
    })

    expect((await service.listLogins()).map((item) => item.type)).toEqual([
      'card',
      'identity',
      'secureNote',
      'sshKey'
    ])
    expect((await service.listLogins()).find((item) => item.id === card.id)).toMatchObject({
      subtitle: '•••• 4242',
      username: '',
      uri: null
    })
    expect((await service.listLogins()).find((item) => item.id === note.id)).toMatchObject({
      subtitle: 'private note body'
    })
    expect(await service.getLogin({ id: note.id })).toMatchObject({
      type: 'secureNote',
      notes: 'private note body'
    })
    const multilineNote = `\n${'A'.repeat(100)}\nsecond line`
    await service.updateLogin({ id: note.id, notes: multilineNote })
    expect((await service.listLogins()).find((item) => item.id === note.id)?.subtitle).toBe(
      `${'A'.repeat(80)}…`
    )
    expect((await service.getLogin({ id: note.id })).notes).toBe(multilineNote)
    const emojiNote = `${'A'.repeat(79)}👨‍👩‍👧‍👦B`
    await service.updateLogin({ id: note.id, notes: emojiNote })
    expect((await service.listLogins()).find((item) => item.id === note.id)?.subtitle).toBe(
      `${'A'.repeat(79)}👨‍👩‍👧‍👦…`
    )
    await service.updateLogin({ id: note.id, notes: ' \r\n \n' })
    expect((await service.listLogins()).find((item) => item.id === note.id)?.subtitle).toBe('')
    expect('number' in card).toBe(false)
    expect('code' in card).toBe(false)
    expect('ssn' in identity).toBe(false)
    expect('privateKey' in sshKey).toBe(false)
    expect(await service.getLogin({ id: sshKey.id })).not.toHaveProperty('privateKey')
    expect(await service.revealSecret({ id: card.id, field: 'number' })).toBe('4242424242424242')
    await service.copyField({ id: identity.id, field: 'identityUsername' })
    expect(copyText).toHaveBeenCalledWith('identity-user')
    expect(await service.revealSecret({ id: sshKey.id, field: 'privateKey' })).toContain(
      'private-test-key'
    )
    await service.updateLogin({ id: card.id, number: '5555555555554444', code: '999' })
    expect(await service.revealSecret({ id: card.id, field: 'number' })).toBe('5555555555554444')
    await service.moveLogin({ id: card.id, folderId: null })
    expect((await service.getLogin({ id: card.id })).folderId).toBeNull()
    await service.deleteLogin({ id: note.id })
    expect((await service.listLogins()).map((item) => item.id)).not.toContain(note.id)
  })

  it('migrates V1 through V3 login records to V5 items', async () => {
    for (const version of [1, 2, 3] as const) {
      const directory = await mkdtemp(join(tmpdir(), 'bearwarden-migration-test-'))
      temporaryDirectories.push(directory)
      const filePath = join(directory, 'vault', 'vault.json')
      const createdAt = '2026-07-14T00:00:00.000Z'
      const legacyData = {
        version,
        createdAt,
        updatedAt: createdAt,
        folders: [],
        logins: [
          {
            id: IDS[0],
            name: `Legacy V${version}`,
            username: 'legacy-user',
            password: 'legacy-secret',
            uri: 'https://legacy.example.invalid',
            notes: null,
            folderId: null,
            favorite: false,
            lastUsedAt: null,
            createdAt,
            updatedAt: createdAt
          }
        ],
        ...(version === 1
          ? {}
          : {
              sync: {
                provider: 'bitwarden',
                serverUrl: 'https://vault.example.invalid',
                email: 'legacy@example.invalid',
                state:
                  version === 2
                    ? null
                    : {
                        session: null,
                        deviceIdentifier: IDS[1],
                        profileId: null,
                        securityStamp: null
                      },
                lastSyncAt: null,
                folderMappings: [],
                loginMappings: [],
                folderTombstones: [],
                loginTombstones: []
              }
            })
      }
      const store = new EncryptedVaultStore<unknown>(filePath)
      const material = await store.initialize(MASTER_PASSWORD, legacyData)
      material.key.fill(0)
      material.salt.fill(0)
      const service = new VaultService(store, { copyText: vi.fn(), openExternal: vi.fn() })

      await expect(service.unlock(MASTER_PASSWORD)).resolves.toEqual({ state: 'unlocked' })
      const migrated = (await service.listLogins())[0]!
      expect(migrated).toMatchObject({ type: 'login', username: 'legacy-user' })
      expect(await service.revealPassword({ id: migrated.id })).toBe('legacy-secret')
      await service.lock()
      const unlocked = await store.unlock(MASTER_PASSWORD)
      expect((unlocked.data as { version: number }).version).toBe(5)
      unlocked.key.fill(0)
      unlocked.salt.fill(0)
    }
  })
})
