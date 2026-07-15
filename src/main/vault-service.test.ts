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
import type { CustomFieldRequest, LoginView, VaultItemFields } from '../shared/vault-contract'
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

function customFieldRequest(login: LoginView, index: number): CustomFieldRequest {
  const field = login.customFields[index]
  if (!field) throw new Error(`Missing custom field ${index}`)
  return {
    id: login.id,
    expectedUpdatedAt: login.updatedAt,
    source: { index, name: field.name, type: field.type, linkedId: field.linkedId }
  }
}

async function createHarness(options: VaultServiceOptions = {}): Promise<{
  directory: string
  filePath: string
  store: EncryptedVaultStore<unknown>
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
  const store = new EncryptedVaultStore<unknown>(filePath)
  const service = new VaultService(
    store,
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
  return { directory, filePath, store, service, copyText, openExternal }
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
      customFields: [
        { name: 'member-id', value: 'remote-member-42', type: 'text', linkedId: null },
        { name: 'recovery-code', value: 'remote-hidden-code', type: 'hidden', linkedId: null },
        { name: 'remember-device', value: 'true', type: 'boolean', linkedId: null },
        { name: 'linked-username', value: '', type: 'linked', linkedId: 100 }
      ],
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
    customFields: draft.customFields ?? [],
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
      remoteLogins.map((login) => ({
        ...login,
        uris: login.uris.map((uri) => ({ ...uri })),
        customFields: login.customFields.map((field) => ({ ...field })),
        passkeys: login.passkeys.map((passkey) => ({ ...passkey }))
      })),
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
    const { copyText, filePath, service } = await createHarness({
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
      passkeys: [expect.objectContaining({ rpId: 'remote.example.invalid' })],
      customFields: [
        { name: 'member-id', type: 'text', value: 'remote-member-42', linkedId: null },
        { name: 'recovery-code', type: 'hidden', value: null, linkedId: null },
        { name: 'remember-device', type: 'boolean', value: 'true', linkedId: null },
        { name: 'linked-username', type: 'linked', value: null, linkedId: 100 }
      ]
    })
    expect(localView).not.toHaveProperty('totp')
    expect(JSON.stringify(localView)).not.toContain('fake-passkey-private-material')

    await expect(service.revealCustomField(customFieldRequest(localView, 1))).resolves.toBe(
      'remote-hidden-code'
    )
    await service.copyCustomField(customFieldRequest(localView, 0))
    expect(copyText).toHaveBeenCalledWith('remote-member-42')
    await service.copyCustomField(customFieldRequest(localView, 3))
    expect(copyText).toHaveBeenCalledWith('remote@example.invalid')
    await expect(
      service.revealCustomField({
        id: local.id,
        expectedUpdatedAt: localView.updatedAt,
        source: { index: 4, name: 'missing', type: 'hidden', linkedId: null }
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.copyCustomField({
        id: local.id,
        expectedUpdatedAt: localView.updatedAt,
        source: { index: -1, name: 'missing', type: 'text', linkedId: null }
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })

    await service.updateLogin({ id: local.id, password: 'locally-changed-secret' })
    const synced = await service.syncNow()
    expect(synced.pushed).toBe(1)
    expect(fake!.remoteLogins[0]?.password).toBe('locally-changed-secret')
    expect(fake!.remoteLogins[0]?.customFields).toEqual([
      { name: 'member-id', value: 'remote-member-42', type: 'text', linkedId: null },
      { name: 'recovery-code', value: 'remote-hidden-code', type: 'hidden', linkedId: null },
      { name: 'remember-device', value: 'true', type: 'boolean', linkedId: null },
      { name: 'linked-username', value: '', type: 'linked', linkedId: 100 }
    ])

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

  it('ignores empty fields from other item types while preserving active field clears', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const editorFields = { ...emptyItemFields }
    const itemTypes = ['login', 'card', 'identity', 'secureNote', 'sshKey'] as const
    const created: LoginView[] = []

    for (const type of itemTypes) {
      created.push(
        await service.createLogin({
          type,
          name: `${type} editor payload`,
          ...editorFields,
          ...(type === 'login' ? { username: 'before-clear', password: 'secret' } : {})
        })
      )
    }

    expect(created.map((item) => item.type)).toEqual(itemTypes)
    const login = created[0]!

    await expect(
      service.updateLogin({
        id: login.id,
        ...editorFields,
        username: ''
      })
    ).resolves.toMatchObject({ username: '' })
    await expect(service.revealPassword({ id: login.id })).resolves.toBe('')

    await expect(
      service.updateLogin({ id: login.id, cardholderName: 'cross-type value' })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('creates all four custom field types without exposing hidden or linked values', async () => {
    const { service, copyText } = await createHarness()
    await service.setup(MASTER_PASSWORD)

    const login = await service.createLogin({
      name: 'Custom fields',
      username: 'linked-user',
      customFields: [
        { source: null, name: 'member-id', type: 'text', value: 'member-42', linkedId: null },
        { source: null, name: 'recovery', type: 'hidden', value: 'secret-42', linkedId: null },
        { source: null, name: 'enabled', type: 'boolean', value: 'true', linkedId: null },
        { source: null, name: 'account', type: 'linked', value: null, linkedId: 100 }
      ]
    })

    expect(login.customFields).toEqual([
      { name: 'member-id', type: 'text', value: 'member-42', linkedId: null },
      { name: 'recovery', type: 'hidden', value: null, linkedId: null },
      { name: 'enabled', type: 'boolean', value: 'true', linkedId: null },
      { name: 'account', type: 'linked', value: null, linkedId: 100 }
    ])
    await expect(service.revealCustomField(customFieldRequest(login, 1))).resolves.toBe('secret-42')
    await service.copyCustomField(customFieldRequest(login, 3))
    expect(copyText).toHaveBeenCalledWith('linked-user')
  })

  it('updates, deletes, and reorders custom fields as one complete array', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({
      name: 'Custom fields',
      customFields: [
        { source: null, name: 'first', type: 'text', value: '1', linkedId: null },
        { source: null, name: 'delete-me', type: 'text', value: '2', linkedId: null },
        { source: null, name: 'last', type: 'boolean', value: 'false', linkedId: null }
      ]
    })

    const updated = await service.updateLogin({
      id: login.id,
      customFields: [
        {
          source: { index: 2, name: 'last', type: 'boolean', linkedId: null },
          name: 'last-first',
          type: 'boolean',
          value: 'true',
          linkedId: null
        },
        {
          source: { index: 0, name: 'first', type: 'text', linkedId: null },
          name: 'first-second',
          type: 'text',
          value: 'updated',
          linkedId: null
        },
        { source: null, name: 'new-third', type: 'text', value: '3', linkedId: null }
      ]
    })

    expect(updated.customFields).toEqual([
      { name: 'last-first', type: 'boolean', value: 'true', linkedId: null },
      { name: 'first-second', type: 'text', value: 'updated', linkedId: null },
      { name: 'new-third', type: 'text', value: '3', linkedId: null }
    ])
  })

  it('rejects reveal and copy requests from a stale custom field snapshot', async () => {
    const { service, copyText } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const original = await service.createLogin({
      name: 'Stale reads',
      customFields: [
        { source: null, name: 'duplicate', type: 'hidden', value: 'first-secret', linkedId: null },
        { source: null, name: 'duplicate', type: 'hidden', value: 'second-secret', linkedId: null }
      ]
    })
    const staleFirst = customFieldRequest(original, 0)

    await service.updateLogin({
      id: original.id,
      customFields: [
        {
          source: { index: 1, name: 'duplicate', type: 'hidden', linkedId: null },
          name: 'duplicate',
          type: 'hidden',
          value: null,
          linkedId: null
        },
        {
          source: { index: 0, name: 'duplicate', type: 'hidden', linkedId: null },
          name: 'duplicate',
          type: 'hidden',
          value: null,
          linkedId: null
        }
      ]
    })

    await expect(service.revealCustomField(staleFirst)).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.copyCustomField(staleFirst)).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    expect(copyText).not.toHaveBeenCalled()
  })

  it('rejects an editor save when the item revision changed after its snapshot', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const snapshot = await service.createLogin({
      name: 'Concurrent edit',
      customFields: [
        { source: null, name: 'environment', type: 'text', value: 'old', linkedId: null }
      ]
    })
    await service.updateLogin({
      id: snapshot.id,
      customFields: [
        {
          source: { index: 0, name: 'environment', type: 'text', linkedId: null },
          name: 'environment',
          type: 'text',
          value: 'newer',
          linkedId: null
        }
      ]
    })

    await expect(
      service.updateLogin({
        id: snapshot.id,
        expectedUpdatedAt: snapshot.updatedAt,
        name: 'Stale overwrite',
        customFields: [
          {
            source: { index: 0, name: 'environment', type: 'text', linkedId: null },
            name: 'environment',
            type: 'text',
            value: 'old',
            linkedId: null
          }
        ]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(service.getLogin({ id: snapshot.id })).resolves.toMatchObject({
      name: 'Concurrent edit',
      customFields: [{ name: 'environment', value: 'newer' }]
    })
  })

  it('preserves an existing hidden value only for a hidden-to-hidden null update and can clear it', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({
      name: 'Hidden field',
      customFields: [
        { source: null, name: 'secret', type: 'hidden', value: 'keep-me', linkedId: null }
      ]
    })

    await service.updateLogin({
      id: login.id,
      customFields: [
        {
          source: { index: 0, name: 'secret', type: 'hidden', linkedId: null },
          name: 'renamed-secret',
          type: 'hidden',
          value: null,
          linkedId: null
        }
      ]
    })
    await expect(
      service.revealCustomField(customFieldRequest(await service.getLogin({ id: login.id }), 0))
    ).resolves.toBe('keep-me')

    await expect(
      service.updateLogin({
        id: login.id,
        customFields: [
          {
            source: { index: 0, name: 'renamed-secret', type: 'hidden', linkedId: null },
            name: 'not-hidden',
            type: 'text',
            value: null,
            linkedId: null
          }
        ]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.revealCustomField(customFieldRequest(await service.getLogin({ id: login.id }), 0))
    ).resolves.toBe('keep-me')

    await service.updateLogin({
      id: login.id,
      customFields: [
        {
          source: { index: 0, name: 'renamed-secret', type: 'hidden', linkedId: null },
          name: 'renamed-secret',
          type: 'hidden',
          value: '',
          linkedId: null
        }
      ]
    })
    await expect(
      service.revealCustomField(customFieldRequest(await service.getLogin({ id: login.id }), 0))
    ).resolves.toBe('')
  })

  it('rejects stale or duplicated custom field sources without applying any part of the update', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({
      name: 'Atomic fields',
      customFields: [
        { source: null, name: 'first', type: 'text', value: '1', linkedId: null },
        { source: null, name: 'second', type: 'text', value: '2', linkedId: null }
      ]
    })
    const before = await service.getLogin({ id: login.id })
    const write = vi.spyOn(store, 'write')

    await expect(
      service.updateLogin({
        id: login.id,
        customFields: [
          {
            source: { index: 0, name: 'first', type: 'text', linkedId: null },
            name: 'changed',
            type: 'text',
            value: 'changed',
            linkedId: null
          },
          {
            source: { index: 1, name: 'stale-name', type: 'text', linkedId: null },
            name: 'second',
            type: 'text',
            value: 'changed',
            linkedId: null
          }
        ]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })

    expect(write).not.toHaveBeenCalled()
    expect(await service.getLogin({ id: login.id })).toEqual(before)

    await expect(
      service.updateLogin({
        id: login.id,
        customFields: [
          {
            source: { index: 0, name: 'first', type: 'text', linkedId: null },
            name: 'first',
            type: 'text',
            value: '1',
            linkedId: null
          },
          {
            source: { index: 0, name: 'first', type: 'text', linkedId: null },
            name: 'duplicate',
            type: 'text',
            value: '2',
            linkedId: null
          }
        ]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('rejects invalid linked targets, boolean values, null values, and custom field limits', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)

    await expect(
      service.createLogin({
        type: 'card',
        name: 'Invalid linked field',
        customFields: [
          { source: null, name: 'login-only', type: 'linked', value: null, linkedId: 100 }
        ]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.createLogin({
        name: 'Invalid linked value',
        customFields: [
          { source: null, name: 'username', type: 'linked', value: 'discard-me', linkedId: 100 }
        ]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.createLogin({
        name: 'Invalid boolean field',
        customFields: [
          { source: null, name: 'enabled', type: 'boolean', value: 'yes', linkedId: null }
        ]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.createLogin({
        name: 'Invalid null field',
        customFields: [{ source: null, name: 'text', type: 'text', value: null, linkedId: null }]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.createLogin({
        name: 'Too long',
        customFields: [
          { source: null, name: 'value', type: 'text', value: 'x'.repeat(5_001), linkedId: null }
        ]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.createLogin({
        name: 'Too many',
        customFields: Array.from({ length: 1_001 }, (_, index) => ({
          source: null,
          name: `field-${index}`,
          type: 'text' as const,
          value: '',
          linkedId: null
        }))
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('moves multiple logins atomically', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const source = await service.createFolder({ name: 'Source' })
    const destination = await service.createFolder({ name: 'Destination' })
    const first = await service.createLogin({ name: 'First', folderId: source.id })
    const second = await service.createLogin({ name: 'Second', folderId: source.id })
    const write = vi.spyOn(store, 'write')

    const moved = await service.moveLogins({
      ids: [first.id, second.id],
      folderId: destination.id
    })

    expect(moved.map((login) => login.id)).toEqual([first.id, second.id])
    expect(moved.every((login) => login.folderId === destination.id)).toBe(true)
    expect(new Set(moved.map((login) => login.updatedAt))).toHaveLength(1)
    expect(write).toHaveBeenCalledOnce()
    expect(
      (await service.listLogins({ folderId: destination.id })).map((login) => login.id)
    ).toEqual([first.id, second.id])
  })

  it('does not partially move logins when any id is invalid or missing', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const source = await service.createFolder({ name: 'Source' })
    const destination = await service.createFolder({ name: 'Destination' })
    const first = await service.createLogin({ name: 'First', folderId: source.id })
    const second = await service.createLogin({ name: 'Second', folderId: source.id })
    const original = await service.listLogins()

    await expect(
      service.moveLogins({ ids: [first.id, 'not-a-uuid'], folderId: destination.id })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    expect(await service.listLogins()).toEqual(original)

    await expect(
      service.moveLogins({ ids: [first.id, IDS[5]!], folderId: destination.id })
    ).rejects.toMatchObject({ code: 'NOT_FOUND' })
    expect(await service.listLogins()).toEqual(original)
    expect((await service.getLogin({ id: second.id })).folderId).toBe(source.id)
  })

  it('migrates V1 through V5 login records to V6 items', async () => {
    for (const version of [1, 2, 3, 4, 5] as const) {
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
            ...emptyItemFields,
            id: IDS[0],
            type: 'login',
            name: `Legacy V${version}`,
            username: 'legacy-user',
            password: 'legacy-secret',
            uri: 'https://legacy.example.invalid',
            notes: null,
            folderId: null,
            favorite: false,
            lastUsedAt: null,
            createdAt,
            updatedAt: createdAt,
            passkeys: []
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
      await expect(service.getLogin({ id: migrated.id })).resolves.toMatchObject({
        customFields: []
      })
      expect(await service.revealPassword({ id: migrated.id })).toBe('legacy-secret')
      await service.lock()
      const unlocked = await store.unlock(MASTER_PASSWORD)
      expect((unlocked.data as { version: number }).version).toBe(6)
      unlocked.key.fill(0)
      unlocked.salt.fill(0)
    }
  })
})
