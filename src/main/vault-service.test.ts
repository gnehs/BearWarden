import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  BitwardenDirectError,
  type BitwardenDirectState,
  type BitwardenLoginDraft,
  type BitwardenLoginItem,
  type BitwardenSyncClient
} from './bitwarden-direct'
import type { CustomFieldRequest, LoginView, VaultItemFields } from '../shared/vault-contract'
import { EncryptedVaultStore } from './encrypted-vault-store'
import { VaultService, type VaultServiceOptions } from './vault-service'
import { VaultAttachmentFileService } from './vault-attachment-files'

const MASTER_PASSWORD = 'correct horse battery staple'
const ATTACHMENT_OPERATION_ID = '70000000-0000-4000-8000-000000000001'
const IDS = [
  '00000000-0000-4000-8000-000000000001',
  '00000000-0000-4000-8000-000000000002',
  '00000000-0000-4000-8000-000000000003',
  '00000000-0000-4000-8000-000000000004',
  '00000000-0000-4000-8000-000000000005',
  '00000000-0000-4000-8000-000000000006',
  '00000000-0000-4000-8000-000000000007',
  '00000000-0000-4000-8000-000000000008',
  '00000000-0000-4000-8000-000000000009',
  '00000000-0000-4000-8000-000000000010',
  '00000000-0000-4000-8000-000000000011',
  '00000000-0000-4000-8000-000000000012'
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
  softDeletedIds: string[]
  restoredIds: string[]
  hardDeletedIds: string[]
  editedLoginIds: string[]
  downloadedAttachmentIds: string[]
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
      uri: 'https://remote.example.invalid',
      uris: [{ uri: 'https://remote.example.invalid', match: null }],
      customFields: [
        { name: 'member-id', value: 'remote-member-42', type: 'text', linkedId: null },
        { name: 'recovery-code', value: 'remote-hidden-code', type: 'hidden', linkedId: null },
        { name: 'remember-device', value: 'true', type: 'boolean', linkedId: null },
        { name: 'linked-username', value: '', type: 'linked', linkedId: 100 }
      ],
      passwordHistory: [],
      attachments: [],
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
      revisionDate: '2026-07-14T00:00:00.000Z',
      deletedAt: null,
      archivedAt: null,
      reprompt: 0
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
    uri: draft.uris?.[0]?.uri ?? draft.uri ?? null,
    uris:
      draft.uris?.map((entry) => ({ ...entry })) ??
      (draft.uri ? [{ uri: draft.uri, match: null }] : []),
    customFields: draft.customFields ?? [],
    passkeys: draft.passkeys ?? [],
    passwordHistory: draft.passwordHistory ?? [],
    attachments: [],
    creationDate: '2026-07-14T00:00:00.000Z',
    revisionDate: '2026-07-14T00:00:01.000Z',
    deletedAt: null,
    archivedAt: draft.archivedAt ?? null,
    reprompt: draft.reprompt ?? 0
  })

  const softDeletedIds: string[] = []
  const restoredIds: string[] = []
  const hardDeletedIds: string[] = []
  const editedLoginIds: string[] = []
  const downloadedAttachmentIds: string[] = []
  const hardDeleteLogin = async (id: string): Promise<void> => {
    hardDeletedIds.push(id)
    const index = remoteLogins.findIndex((login) => login.id === id)
    if (index >= 0) remoteLogins.splice(index, 1)
  }

  return {
    remoteLogins,
    softDeletedIds,
    restoredIds,
    hardDeletedIds,
    editedLoginIds,
    downloadedAttachmentIds,
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
        passkeys: login.passkeys.map((passkey) => ({ ...passkey })),
        attachments: login.attachments.map((attachment) => ({ ...attachment }))
      })),
    downloadAttachment: async (id, attachmentId) => {
      const attachment = remoteLogins
        .find((login) => login.id === id)
        ?.attachments.find((entry) => entry.id === attachmentId)
      if (!attachment) throw new Error('missing fake attachment')
      downloadedAttachmentIds.push(attachmentId)
      return {
        fileName: attachment.fileName,
        data: Buffer.from('fake attachment contents')
      }
    },
    uploadAttachment: async (id, fileName, data, _signal, onCommitted) => {
      const login = remoteLogins.find((entry) => entry.id === id)
      if (!login) throw new Error('missing fake login')
      const attachment = {
        id: `uploaded-attachment-${login.attachments.length + 1}`,
        fileName,
        size: data.length,
        sizeName: `${data.length} B`,
        legacy: false
      }
      login.attachments.push(attachment)
      login.revisionDate = '2026-07-16T00:00:00.000Z'
      onCommitted?.()
      return { ...attachment }
    },
    deleteAttachment: async (id, attachmentId, _signal, onCommitted) => {
      const login = remoteLogins.find((entry) => entry.id === id)
      if (!login) throw new Error('missing fake login')
      const index = login.attachments.findIndex((entry) => entry.id === attachmentId)
      if (index < 0) throw new Error('missing fake attachment')
      login.attachments.splice(index, 1)
      login.revisionDate = '2026-07-16T00:00:00.000Z'
      onCommitted?.()
    },
    upgradeLegacyAttachment: async (id, attachmentId, _signal, onCommitted) => {
      const login = remoteLogins.find((entry) => entry.id === id)
      const index = login?.attachments.findIndex((entry) => entry.id === attachmentId) ?? -1
      if (!login || index < 0 || !login.attachments[index]!.legacy) {
        throw new Error('missing fake legacy attachment')
      }
      const legacy = login.attachments[index]!
      const replacement = {
        ...legacy,
        id: `fixed-${legacy.id}`,
        legacy: false
      }
      login.attachments.splice(index, 1, replacement)
      login.revisionDate = '2026-07-16T00:00:00.000Z'
      onCommitted?.()
      return { ...replacement }
    },
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
      editedLoginIds.push(id)
      const index = remoteLogins.findIndex((login) => login.id === id)
      const login = fromDraft(id, draft)
      remoteLogins[index] = login
      return structuredClone(login)
    },
    softDeleteLogin: async (id) => {
      softDeletedIds.push(id)
      const login = remoteLogins.find((candidate) => candidate.id === id)
      if (login) login.deletedAt = '2026-07-14T00:00:02.000Z'
    },
    restoreLogin: async (id) => {
      restoredIds.push(id)
      const login = remoteLogins.find((candidate) => candidate.id === id)
      if (login) login.deletedAt = null
    },
    archiveLogin: async (id) => {
      const login = remoteLogins.find((candidate) => candidate.id === id)
      if (login) login.archivedAt = '2026-07-14T00:00:03.000Z'
    },
    unarchiveLogin: async (id) => {
      const login = remoteLogins.find((candidate) => candidate.id === id)
      if (login) login.archivedAt = null
    },
    hardDeleteLogin,
    deleteLogin: hardDeleteLogin,
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

  it('deletes one passkey atomically without returning private key material', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const login = (await service.listLogins())[0]!
    const before = await service.getLogin({ id: login.id })

    const updated = await service.deletePasskey({
      id: login.id,
      credentialId: 'credential-id',
      expectedUpdatedAt: before.updatedAt
    })

    expect(updated.passkeys).toEqual([])
    expect(updated.updatedAt).not.toBe(before.updatedAt)
    expect(JSON.stringify(updated)).not.toContain('fake-passkey-private-material')
    await service.syncNow()
    expect(fake!.remoteLogins[0]!.passkeys).toEqual([])
    await service.lock()
    const reopened = new VaultService(new EncryptedVaultStore(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await reopened.unlock(MASTER_PASSWORD)
    await expect(reopened.getLogin({ id: login.id })).resolves.toMatchObject({ passkeys: [] })
  })

  it('rejects stale, missing, and ambiguous passkey deletion without changing the item', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service, store } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.passkeys.push({ ...fake.remoteLogins[0]!.passkeys[0]! })
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const login = (await service.listLogins())[0]!
    const before = await service.getLogin({ id: login.id })
    const write = vi.spyOn(store, 'write')

    await expect(
      service.deletePasskey({
        id: login.id,
        credentialId: 'credential-id',
        expectedUpdatedAt: '2026-01-01T00:00:00.000Z'
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.deletePasskey({ id: login.id, credentialId: 'missing-credential' })
    ).rejects.toMatchObject({ code: 'NOT_FOUND' })
    await expect(
      service.deletePasskey({ id: login.id, credentialId: 'credential-id' })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    expect(write).not.toHaveBeenCalled()
    await expect(service.getLogin({ id: login.id })).resolves.toEqual(before)
  })

  it('keeps a passkey when persistence fails during deletion', async () => {
    const { service, store } = await createHarness({
      createSyncClient: (sync) => createSyncFake(sync.state)
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const login = (await service.listLogins())[0]!
    vi.spyOn(store, 'write').mockRejectedValueOnce(new Error('injected persistence failure'))

    await expect(
      service.deletePasskey({ id: login.id, credentialId: 'credential-id' })
    ).rejects.toThrow('injected persistence failure')
    await expect(service.getLogin({ id: login.id })).resolves.toMatchObject({
      passkeys: [expect.objectContaining({ credentialId: 'credential-id' })]
    })
  })

  it('reconciles attachment-only remote changes without creating item conflicts', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    fake!.remoteLogins[0]!.attachments = [
      {
        id: 'attachment-id',
        fileName: 'remote-document.txt',
        size: 12,
        sizeName: '12 B',
        legacy: false
      }
    ]
    fake!.remoteLogins[0]!.revisionDate = '2026-07-14T04:00:00.000Z'

    await expect(service.syncNow()).resolves.toMatchObject({
      pulled: 0,
      pushed: 0,
      deleted: 0,
      conflicts: 0
    })
    await expect(service.getLogin({ id: local.id })).resolves.toMatchObject({
      updatedAt: '2026-07-14T04:00:00.000Z',
      attachmentCount: 1,
      attachments: [
        {
          id: 'attachment-id',
          fileName: 'remote-document.txt',
          size: 12,
          sizeName: '12 B',
          legacy: false
        }
      ]
    })
    expect((await service.listLogins())[0]?.attachmentCount).toBe(1)
    expect(await readFile(filePath, 'utf8')).not.toContain('remote-document.txt')

    await service.lock()
    await service.unlock(MASTER_PASSWORD)
    await expect(service.getLogin({ id: local.id })).resolves.toMatchObject({
      attachmentCount: 1,
      attachments: [expect.objectContaining({ fileName: 'remote-document.txt' })]
    })
  })

  it('downloads an attachment through a main-only picker and clears plaintext memory', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-download-test-'))
    temporaryDirectories.push(directory)
    const destination = join(directory, 'saved-document.txt')
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => destination)
    })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.attachments = [
          {
            id: 'attachment-id',
            fileName: 'document.txt',
            size: 12,
            sizeName: '12 B',
            legacy: false
          }
        ]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    let clearText: Buffer | undefined
    fake!.downloadAttachment = async () => {
      clearText = Buffer.from('fake attachment contents')
      return { fileName: 'document.txt', data: clearText }
    }

    await expect(
      service.downloadAttachment({
        id: local.id,
        attachmentId: 'attachment-id',
        operationId: ATTACHMENT_OPERATION_ID
      })
    ).resolves.toEqual({ canceled: false, fileName: 'document.txt' })
    expect(await readFile(destination, 'utf8')).toBe('fake attachment contents')
    expect(clearText).toEqual(Buffer.alloc('fake attachment contents'.length))
    if (process.platform !== 'win32') expect((await stat(destination)).mode & 0o777).toBe(0o600)
  })

  it('cancels before downloading when the main-process save picker is dismissed', async () => {
    const chooseSavePath = vi.fn(async () => null)
    const attachmentFiles = new VaultAttachmentFileService({ chooseSavePath })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.attachments = [
          {
            id: 'attachment-id',
            fileName: 'document.txt',
            size: 12,
            sizeName: '12 B',
            legacy: false
          }
        ]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const downloadAttachment = vi.fn(fake!.downloadAttachment)
    fake!.downloadAttachment = downloadAttachment

    await expect(
      service.downloadAttachment({
        id: local.id,
        attachmentId: 'attachment-id',
        operationId: ATTACHMENT_OPERATION_ID
      })
    ).resolves.toEqual({ canceled: true, fileName: 'document.txt' })
    expect(chooseSavePath).toHaveBeenCalledWith('document.txt')
    expect(downloadAttachment).not.toHaveBeenCalled()
  })

  it('allows lock to clear the vault while the native save picker remains open', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-download-picker-lock-'))
    temporaryDirectories.push(directory)
    const destination = join(directory, 'must-not-be-written.txt')
    let resolvePicker!: (path: string | null) => void
    const picker = new Promise<string | null>((resolve) => {
      resolvePicker = resolve
    })
    const chooseSavePath = vi.fn(() => picker)
    const attachmentFiles = new VaultAttachmentFileService({ chooseSavePath })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.attachments = [
          {
            id: 'attachment-id',
            fileName: 'document.txt',
            size: 12,
            sizeName: '12 B',
            legacy: false
          }
        ]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const download = service.downloadAttachment({
      id: local.id,
      attachmentId: 'attachment-id',
      operationId: ATTACHMENT_OPERATION_ID
    })
    await vi.waitFor(() => expect(chooseSavePath).toHaveBeenCalledOnce())

    const lockOutcome = await Promise.race([
      service.lock(),
      new Promise<'timeout'>((resolve) => setTimeout(() => resolve('timeout'), 250))
    ])
    expect(lockOutcome).toEqual({ state: 'locked' })
    resolvePicker(destination)
    await expect(download).rejects.toMatchObject({ code: 'LOCKED' })
    expect(fake!.downloadedAttachmentIds).toEqual([])
    expect(await readdir(directory)).toEqual([])
  })

  it('aborts an attachment download before lock and leaves no partial plaintext file', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-download-abort-'))
    temporaryDirectories.push(directory)
    const destination = join(directory, 'should-not-exist.txt')
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => destination)
    })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.attachments = [
          {
            id: 'attachment-id',
            fileName: 'document.txt',
            size: 12,
            sizeName: '12 B',
            legacy: false
          }
        ]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    let started!: () => void
    const didStart = new Promise<void>((resolve) => {
      started = resolve
    })
    fake!.downloadAttachment = async (_id, _attachmentId, signal) => {
      started()
      return new Promise<never>((_resolve, reject) => {
        signal?.addEventListener('abort', () => reject(new BitwardenDirectError('ABORTED')), {
          once: true
        })
      })
    }

    const download = service.downloadAttachment({
      id: local.id,
      attachmentId: 'attachment-id',
      operationId: ATTACHMENT_OPERATION_ID
    })
    await didStart
    const lock = service.lock()
    await expect(download).rejects.toMatchObject({ code: 'LOCKED' })
    await expect(lock).resolves.toEqual({ state: 'locked' })
    expect(await readdir(directory)).toEqual([])
  })

  it('uploads a main-only selected file, reconciles metadata, reports progress, and clears plaintext', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-upload-test-'))
    temporaryDirectories.push(directory)
    const source = join(directory, 'upload.txt')
    await writeFile(source, 'fake upload contents')
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => null),
      chooseOpenFile: vi.fn(async () => source)
    })
    const readSelectedFile = attachmentFiles.readSelectedFile.bind(attachmentFiles)
    let clearText: Buffer | undefined
    vi.spyOn(attachmentFiles, 'readSelectedFile').mockImplementation(async (selection, signal) => {
      clearText = await readSelectedFile(selection, signal)
      return clearText
    })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const progress: string[] = []

    await expect(
      service.uploadAttachment({ id: local.id, operationId: ATTACHMENT_OPERATION_ID }, (event) =>
        progress.push(event.stage)
      )
    ).resolves.toMatchObject({
      canceled: false,
      attachment: { fileName: 'upload.txt', legacy: false }
    })
    await expect(service.getLogin({ id: local.id })).resolves.toMatchObject({
      attachments: [expect.objectContaining({ fileName: 'upload.txt', legacy: false })]
    })
    expect(progress).toEqual([
      'choosing-file',
      'reading-file',
      'reading-file',
      'encrypting',
      'uploading',
      'uploading',
      'syncing'
    ])
    expect(clearText).toEqual(Buffer.alloc('fake upload contents'.length))
    expect(fake!.remoteLogins[0]!.attachments).toHaveLength(1)
  })

  it('allows lock to clear the vault while the native upload picker remains open', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-upload-picker-lock-'))
    temporaryDirectories.push(directory)
    const source = join(directory, 'must-not-upload.txt')
    await writeFile(source, 'must not upload')
    let resolvePicker!: (path: string | null) => void
    const picker = new Promise<string | null>((resolve) => {
      resolvePicker = resolve
    })
    const chooseOpenFile = vi.fn(() => picker)
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => null),
      chooseOpenFile
    })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const uploadAttachment = vi.fn(fake!.uploadAttachment)
    fake!.uploadAttachment = uploadAttachment
    const upload = service.uploadAttachment({
      id: local.id,
      operationId: ATTACHMENT_OPERATION_ID
    })
    await vi.waitFor(() => expect(chooseOpenFile).toHaveBeenCalledOnce())

    await expect(service.lock()).resolves.toEqual({ state: 'locked' })
    resolvePicker(source)
    await expect(upload).rejects.toMatchObject({ code: 'LOCKED' })
    expect(uploadAttachment).not.toHaveBeenCalled()
  })

  it('revalidates attachment reprompt authorization after the native picker closes', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-upload-reprompt-'))
    temporaryDirectories.push(directory)
    const source = join(directory, 'protected.txt')
    await writeFile(source, 'protected upload')
    let resolvePicker!: (path: string | null) => void
    const picker = new Promise<string | null>((resolve) => {
      resolvePicker = resolve
    })
    const chooseOpenFile = vi.fn(() => picker)
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => null),
      chooseOpenFile
    })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.reprompt = 1
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const uploadAttachment = vi.fn(fake!.uploadAttachment)
    fake!.uploadAttachment = uploadAttachment
    let validations = 0
    const upload = service.uploadAttachment(
      { id: local.id, operationId: ATTACHMENT_OPERATION_ID },
      undefined,
      () => ++validations === 1
    )
    await vi.waitFor(() => expect(chooseOpenFile).toHaveBeenCalledOnce())

    resolvePicker(source)
    await expect(upload).rejects.toMatchObject({ code: 'REPROMPT_REQUIRED' })
    expect(validations).toBe(2)
    expect(uploadAttachment).not.toHaveBeenCalled()
  })

  it('deletes and fixes attachments only after server-authoritative reconciliation', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.attachments = [
          {
            id: 'modern-attachment',
            fileName: 'modern.txt',
            size: 12,
            sizeName: '12 B',
            legacy: false
          },
          {
            id: 'legacy-attachment',
            fileName: 'legacy.txt',
            size: 13,
            sizeName: '13 B',
            legacy: true
          }
        ]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!

    await expect(
      service.deleteAttachment({
        id: local.id,
        attachmentId: 'modern-attachment',
        operationId: ATTACHMENT_OPERATION_ID
      })
    ).resolves.toEqual({ attachmentId: 'modern-attachment' })
    await expect(
      service.fixLegacyAttachment({
        id: local.id,
        attachmentId: 'legacy-attachment',
        operationId: ATTACHMENT_OPERATION_ID
      })
    ).resolves.toMatchObject({
      attachment: { id: 'fixed-legacy-attachment', fileName: 'legacy.txt', legacy: false }
    })
    await expect(service.getLogin({ id: local.id })).resolves.toMatchObject({
      attachments: [{ id: 'fixed-legacy-attachment', fileName: 'legacy.txt', legacy: false }]
    })
    await expect(
      service.fixLegacyAttachment({
        id: local.id,
        attachmentId: 'fixed-legacy-attachment',
        operationId: ATTACHMENT_OPERATION_ID
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('cancels an active attachment upload without changing local metadata', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-upload-cancel-'))
    temporaryDirectories.push(directory)
    const source = join(directory, 'cancel.txt')
    await writeFile(source, 'cancel me')
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => null),
      chooseOpenFile: vi.fn(async () => source)
    })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    let started!: () => void
    const didStart = new Promise<void>((resolve) => {
      started = resolve
    })
    fake!.uploadAttachment = async (_id, _name, _data, signal) => {
      started()
      return new Promise<never>((_resolve, reject) => {
        signal?.addEventListener('abort', () => reject(new BitwardenDirectError('ABORTED')), {
          once: true
        })
      })
    }

    const upload = service.uploadAttachment({
      id: local.id,
      operationId: ATTACHMENT_OPERATION_ID
    })
    await didStart
    expect(
      service.cancelAttachmentOperation({
        operationId: '70000000-0000-4000-8000-000000000002'
      })
    ).toEqual({ canceled: false })
    expect(service.cancelAttachmentOperation({ operationId: ATTACHMENT_OPERATION_ID })).toEqual({
      canceled: true
    })
    await expect(upload).rejects.toMatchObject({ code: 'ATTACHMENT_CANCELED' })
    await expect(service.getLogin({ id: local.id })).resolves.toMatchObject({ attachments: [] })
    expect(fake!.remoteLogins[0]!.attachments).toEqual([])
  })

  it('refuses cancellation after the remote attachment commit point and persists success', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-upload-commit-'))
    temporaryDirectories.push(directory)
    const source = join(directory, 'committed.txt')
    await writeFile(source, 'committed upload')
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => null),
      chooseOpenFile: vi.fn(async () => source)
    })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const originalUpload = fake!.uploadAttachment.bind(fake!)
    let signalCommitted!: () => void
    const didCommit = new Promise<void>((resolve) => {
      signalCommitted = resolve
    })
    let release!: () => void
    const holdAfterCommit = new Promise<void>((resolve) => {
      release = resolve
    })
    fake!.uploadAttachment = async (id, fileName, data, signal, onCommitted) => {
      const result = await originalUpload(id, fileName, data, signal, onCommitted)
      signalCommitted()
      await holdAfterCommit
      return result
    }

    const upload = service.uploadAttachment({
      id: local.id,
      operationId: ATTACHMENT_OPERATION_ID
    })
    await didCommit
    expect(service.cancelAttachmentOperation({ operationId: ATTACHMENT_OPERATION_ID })).toEqual({
      canceled: false
    })
    release()
    await expect(upload).resolves.toMatchObject({
      canceled: false,
      attachment: { fileName: 'committed.txt' }
    })
    await expect(service.getLogin({ id: local.id })).resolves.toMatchObject({
      attachments: [expect.objectContaining({ fileName: 'committed.txt' })]
    })
  })

  it.each([
    ['STORAGE_LIMIT', 'ATTACHMENT_STORAGE_LIMIT'],
    ['TOO_LARGE', 'ATTACHMENT_TOO_LARGE'],
    ['ATTACHMENT_REJECTED', 'ATTACHMENT_REJECTED'],
    ['NOT_FOUND', 'NOT_FOUND']
  ] as const)('maps server attachment %s failures to safe %s errors', async (remoteCode, code) => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-upload-quota-'))
    temporaryDirectories.push(directory)
    const source = join(directory, 'quota.txt')
    await writeFile(source, 'quota')
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => null),
      chooseOpenFile: vi.fn(async () => source)
    })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    fake!.uploadAttachment = async () => {
      throw new BitwardenDirectError(remoteCode)
    }

    await expect(
      service.uploadAttachment({ id: local.id, operationId: ATTACHMENT_OPERATION_ID })
    ).rejects.toMatchObject({ code })
  })

  it.each(['content changes', 'mapped item disappears'] as const)(
    'rejects a final remote refetch when the %s and leaves the vault unchanged',
    async (race) => {
      let fake: ReturnType<typeof createSyncFake> | null = null
      const { service, store } = await createHarness({
        createSyncClient: (sync) => {
          fake = createSyncFake(sync.state)
          return fake
        }
      })
      await service.setup(MASTER_PASSWORD)
      await service.connectSync({
        serverUrl: 'https://vault.example.invalid',
        email: 'sync@example.invalid',
        masterPassword: 'remote master password'
      })
      const local = (await service.listLogins())[0]!
      const listPersonalLogins = fake!.listPersonalLogins.bind(fake!)
      let calls = 0
      fake!.listPersonalLogins = async () => {
        const logins = await listPersonalLogins()
        calls += 1
        if (calls !== 2) return logins
        if (race === 'mapped item disappears') return []
        logins[0]!.password = 'third-party-race-secret'
        return logins
      }
      const write = vi.spyOn(store, 'write')

      await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })
      expect(write).not.toHaveBeenCalled()
      await expect(service.revealPassword({ id: local.id })).resolves.toBe('remote-test-secret')
      expect((await service.getLogin({ id: local.id })).attachmentCount).toBe(0)
    }
  )

  it('syncs soft-delete, restore, content edits, and permanent deletion with distinct APIs', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const remoteId = fake!.remoteLogins[0]!.id

    await service.updateLogin({ id: local.id, password: 'changed-before-delete' })
    await service.deleteLogin({ id: local.id })
    await service.syncNow()
    expect(fake!.editedLoginIds).toContain(remoteId)
    expect(fake!.softDeletedIds).toEqual([remoteId])
    expect(fake!.remoteLogins[0]).toMatchObject({
      password: 'changed-before-delete',
      deletedAt: expect.any(String)
    })

    await service.restoreLogin({ id: local.id })
    await service.syncNow()
    expect(fake!.restoredIds).toEqual([remoteId])
    expect(fake!.remoteLogins[0]!.deletedAt).toBeNull()

    await service.deleteLogin({ id: local.id })
    await service.deleteLoginPermanently({ id: local.id })
    await service.syncNow()
    expect(fake!.hardDeletedIds).toEqual([remoteId])
    expect(fake!.remoteLogins).toEqual([])
  })

  it('resumes a partially completed trash update after restart without reviving or duplicating it', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake ??= createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const createSpy = vi.spyOn(fake!, 'createLogin')
    const softDelete = fake!.softDeleteLogin.bind(fake)
    let failOnce = true
    fake!.softDeleteLogin = async (id, signal) => {
      if (failOnce) {
        failOnce = false
        throw new Error('injected soft-delete failure')
      }
      await softDelete(id, signal)
    }

    await service.updateLogin({ id: local.id, password: 'changed-before-restart' })
    await service.archiveLogin({ id: local.id })
    await service.deleteLogin({ id: local.id })
    await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    expect(fake!.remoteLogins).toMatchObject([
      {
        id: fake!.remoteLogins[0]!.id,
        password: 'changed-before-restart',
        archivedAt: expect.any(String),
        deletedAt: null
      }
    ])

    service.dispose()
    const reopened = new VaultService(
      new EncryptedVaultStore(filePath),
      { copyText: vi.fn(), openExternal: vi.fn() },
      { createSyncClient: () => fake! }
    )
    await reopened.unlock(MASTER_PASSWORD)
    await expect(reopened.syncNow()).resolves.toMatchObject({ conflicts: 0 })

    expect(createSpy).not.toHaveBeenCalled()
    expect(fake!.remoteLogins).toHaveLength(1)
    expect(fake!.remoteLogins[0]).toMatchObject({
      password: 'changed-before-restart',
      archivedAt: expect.any(String),
      deletedAt: expect.any(String)
    })
    expect(await reopened.listLogins()).toEqual([])
    expect(await reopened.listLogins({ deleted: true })).toMatchObject([{ id: local.id }])
  })

  it('resumes the maximum restore-unarchive-edit-delete chain after restart', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake ??= createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    await service.archiveLogin({ id: local.id })
    await service.deleteLogin({ id: local.id })
    await service.syncNow()

    const createSpy = vi.spyOn(fake!, 'createLogin')
    const edit = fake!.editLogin.bind(fake)
    let failOnce = true
    fake!.editLogin = async (id, draft, signal) => {
      if (failOnce) {
        failOnce = false
        throw new Error('injected edit failure')
      }
      return edit(id, draft, signal)
    }
    await service.restoreLogin({ id: local.id })
    await service.unarchiveLogin({ id: local.id })
    await service.updateLogin({ id: local.id, password: 'changed-after-restore' })
    await service.deleteLogin({ id: local.id })
    await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    expect(fake!.remoteLogins[0]).toMatchObject({
      password: 'remote-test-secret',
      archivedAt: null,
      deletedAt: null
    })

    service.dispose()
    const reopened = new VaultService(
      new EncryptedVaultStore(filePath),
      { copyText: vi.fn(), openExternal: vi.fn() },
      { createSyncClient: () => fake! }
    )
    await reopened.unlock(MASTER_PASSWORD)
    await expect(reopened.syncNow()).resolves.toMatchObject({ conflicts: 0 })

    expect(createSpy).not.toHaveBeenCalled()
    expect(fake!.remoteLogins).toHaveLength(1)
    expect(fake!.remoteLogins[0]).toMatchObject({
      password: 'changed-after-restore',
      archivedAt: null,
      deletedAt: expect.any(String)
    })
    expect(await reopened.listLogins()).toEqual([])
    expect(await reopened.listLogins({ deleted: true })).toMatchObject([{ id: local.id }])
  })

  it('preserves a third-party remote edit made while a trash mutation is pending', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake ??= createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const softDelete = fake!.softDeleteLogin.bind(fake)
    let failOnce = true
    fake!.softDeleteLogin = async (id, signal) => {
      if (failOnce) {
        failOnce = false
        throw new Error('injected soft-delete failure')
      }
      await softDelete(id, signal)
    }
    await service.updateLogin({ id: local.id, password: 'local-pending-change' })
    await service.deleteLogin({ id: local.id })
    await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })

    fake!.remoteLogins[0]!.password = 'third-party-remote-change'
    service.dispose()
    const reopened = new VaultService(
      new EncryptedVaultStore(filePath),
      { copyText: vi.fn(), openExternal: vi.fn() },
      { createSyncClient: () => fake! }
    )
    await reopened.unlock(MASTER_PASSWORD)
    await expect(reopened.syncNow()).resolves.toMatchObject({ conflicts: 1 })

    expect(fake!.remoteLogins).toHaveLength(1)
    expect(fake!.remoteLogins[0]!.password).toBe('third-party-remote-change')
    const [remotePrimary] = await reopened.listLogins()
    expect(await reopened.revealPassword({ id: remotePrimary!.id })).toBe(
      'third-party-remote-change'
    )
    const [localConflict] = await reopened.listLogins({ deleted: true })
    expect(localConflict?.name).toContain('BearWarden conflict')
    await reopened.restoreLogin({ id: localConflict!.id })
    expect(await reopened.revealPassword({ id: localConflict!.id })).toBe('local-pending-change')
  })

  it('keeps permanent deletion final when a trash mutation was interrupted', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake ??= createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const softDelete = fake!.softDeleteLogin.bind(fake)
    let failOnce = true
    fake!.softDeleteLogin = async (id, signal) => {
      if (failOnce) {
        failOnce = false
        throw new Error('injected soft-delete failure')
      }
      await softDelete(id, signal)
    }
    await service.updateLogin({ id: local.id, password: 'must-not-revive' })
    await service.deleteLogin({ id: local.id })
    await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    await service.deleteLoginPermanently({ id: local.id })

    service.dispose()
    const reopened = new VaultService(
      new EncryptedVaultStore(filePath),
      { copyText: vi.fn(), openExternal: vi.fn() },
      { createSyncClient: () => fake! }
    )
    await reopened.unlock(MASTER_PASSWORD)
    await expect(reopened.syncNow()).resolves.toMatchObject({ conflicts: 0 })

    expect(fake!.hardDeletedIds).toContain('90000000-0000-4000-8000-000000000002')
    expect(fake!.remoteLogins).toEqual([])
    expect(await reopened.listLogins()).toEqual([])
    expect(await reopened.listLogins({ deleted: true })).toEqual([])
  })

  it('pulls a remote soft-delete into the local trash without hard-deleting content', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    fake!.remoteLogins[0]!.deletedAt = '2026-07-14T03:00:00.000Z'

    await expect(service.syncNow()).resolves.toMatchObject({ pulled: 1 })
    expect(await service.listLogins()).toEqual([])
    expect(await service.listLogins({ deleted: true })).toMatchObject([
      { id: local.id, deletedAt: '2026-07-14T03:00:00.000Z' }
    ])
    await expect(service.getLogin({ id: local.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.getWebsiteIcon({ id: local.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
  })

  it('rejects a malformed remote deletion date instead of treating a trashed item as active', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    fake!.remoteLogins[0]!.deletedAt = 'not-a-date'

    await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    expect(await service.listLogins({ deleted: true })).toEqual([])
  })

  it('rejects a malformed remote archive date instead of changing its visibility', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    fake!.remoteLogins[0]!.archivedAt = 'not-a-date'

    await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    expect(await service.listLogins()).toMatchObject([{ id: local.id, archivedAt: null }])
    expect(await service.listLogins({ archived: true })).toEqual([])
  })

  it.each([
    {
      label: 'more than 1,000 passkeys',
      mutate: (login: BitwardenLoginItem) => {
        const passkey = login.passkeys[0]!
        login.passkeys = Array.from({ length: 1_001 }, () => ({ ...passkey }))
      }
    },
    {
      label: 'a passkey field longer than 4,096 characters',
      mutate: (login: BitwardenLoginItem) => {
        login.passkeys[0]!.credentialId = 'x'.repeat(4_097)
      }
    },
    {
      label: 'a non-canonical passkey creation date',
      mutate: (login: BitwardenLoginItem) => {
        login.passkeys[0]!.creationDate = '2026-07-13T00:00:00Z'
      }
    }
  ])('rejects remote $label atomically and leaves a reopenable vault', async ({ mutate }) => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service, store } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    mutate(fake!.remoteLogins[0]!)
    const write = vi.spyOn(store, 'write')

    await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    expect(write).not.toHaveBeenCalled()

    await service.lock()
    const reopened = new VaultService(new EncryptedVaultStore(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(reopened.unlock(MASTER_PASSWORD)).resolves.toEqual({ state: 'unlocked' })
    const [intact] = await reopened.listLogins()
    expect(intact?.passkeyCount).toBe(1)
    await expect(reopened.getLogin({ id: intact!.id })).resolves.toMatchObject({
      passkeys: [expect.objectContaining({ credentialId: 'credential-id' })]
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

  it('exports full non-trash data and imports it as durable remapped copies', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const folder = await service.createFolder({ name: 'Shared' })
    const original = await service.createLogin({
      name: 'Portable account',
      username: 'sample-user',
      password: 'old-secret',
      totp: 'JBSWY3DPEHPK3PXP',
      folderId: folder.id,
      favorite: true,
      reprompt: 1,
      uris: [
        { uri: 'https://example.invalid', match: 0 },
        { uri: 'https://mobile.example.invalid', match: 3 }
      ],
      customFields: [
        { source: null, name: 'recovery', type: 'hidden', value: 'sample-code', linkedId: null }
      ]
    })
    await service.updateLogin({ id: original.id, password: 'new-secret' })
    await service.archiveLogin({ id: original.id })
    const deleted = await service.createLogin({ name: 'Deleted account', password: 'trash-secret' })
    await service.deleteLogin({ id: deleted.id })

    await expect(service.exportPortableSnapshot('incorrect master password')).rejects.toMatchObject(
      {
        code: 'INVALID_MASTER_PASSWORD'
      }
    )
    const exported = await service.exportPortableSnapshot(MASTER_PASSWORD)
    expect(exported.skippedTrashItems).toBe(1)
    expect(exported.snapshot.folders).toHaveLength(1)
    expect(exported.snapshot.items).toHaveLength(1)
    expect(exported.snapshot.items[0]).toMatchObject({
      id: original.id,
      name: 'Portable account',
      username: 'sample-user',
      password: 'new-secret',
      totp: 'JBSWY3DPEHPK3PXP',
      archivedAt: expect.any(String),
      reprompt: 1,
      uris: [
        { uri: 'https://example.invalid', match: 0 },
        { uri: 'https://mobile.example.invalid', match: 3 }
      ],
      customFields: [{ name: 'recovery', value: 'sample-code', type: 'hidden' }],
      passwordHistory: [{ password: 'old-secret' }]
    })

    await expect(
      service.importPortableSnapshot(exported.snapshot, exported.skippedTrashItems, MASTER_PASSWORD)
    ).resolves.toEqual({ importedFolders: 1, importedItems: 1, skippedTrashItems: 1 })

    const folders = await service.listFolders()
    expect(folders.map((entry) => entry.name)).toEqual(['Shared', 'Shared (Imported)'])
    const archived = await service.listLogins({ archived: true })
    expect(archived).toHaveLength(2)
    const imported = archived.find((entry) => entry.id !== original.id)!
    expect(imported.folderId).toBe(folders[1]!.id)
    expect(imported.id).not.toBe(original.id)

    const roundTrip = await service.exportPortableSnapshot(MASTER_PASSWORD)
    expect(roundTrip.snapshot.items.find((entry) => entry.id === imported.id)).toMatchObject({
      password: 'new-secret',
      customFields: [{ name: 'recovery', value: 'sample-code' }],
      passwordHistory: [{ password: 'old-secret' }]
    })

    await service.lock()
    await service.unlock(MASTER_PASSWORD)
    expect((await service.listFolders()).map((entry) => entry.name)).toEqual([
      'Shared',
      'Shared (Imported)'
    ])
    expect(await service.listLogins({ archived: true })).toHaveLength(2)
  })

  it('keeps imports atomic when validation or persistence fails', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const folder = await service.createFolder({ name: 'Existing' })
    await service.createLogin({ name: 'Existing account', folderId: folder.id })
    const exported = await service.exportPortableSnapshot(MASTER_PASSWORD)
    const foldersBefore = await service.listFolders()
    const itemsBefore = await service.listLogins()
    const write = vi.spyOn(store, 'write')

    await expect(
      service.importPortableSnapshot({ folders: [], items: [] }, 3, MASTER_PASSWORD)
    ).resolves.toEqual({ importedFolders: 0, importedItems: 0, skippedTrashItems: 3 })
    expect(write).not.toHaveBeenCalled()

    const invalid = structuredClone(exported.snapshot)
    invalid.items[0]!.folderId = IDS[11]!
    await expect(service.importPortableSnapshot(invalid, 0, MASTER_PASSWORD)).rejects.toMatchObject(
      { code: 'INVALID_INPUT' }
    )
    expect(write).not.toHaveBeenCalled()
    expect(await service.listFolders()).toEqual(foldersBefore)
    expect(await service.listLogins()).toEqual(itemsBefore)

    write.mockRejectedValueOnce(new Error('simulated write failure'))
    await expect(
      service.importPortableSnapshot(exported.snapshot, 0, MASTER_PASSWORD)
    ).rejects.toThrow('simulated write failure')
    expect(write).toHaveBeenCalledOnce()
    expect(await service.listFolders()).toEqual(foldersBefore)
    expect(await service.listLogins()).toEqual(itemsBefore)
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

  it('keeps deleted items in trash, blocks ordinary mutations, and restores or purges them', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const folder = await service.createFolder({ name: 'Trash test' })
    const first = await service.createLogin({
      type: 'secureNote',
      name: 'First',
      folderId: folder.id,
      notes: 'trash-summary-secret-canary'
    })
    const second = await service.createLogin({ name: 'Second' })

    await service.deleteLogin({ id: first.id })
    expect(await service.listLogins()).toMatchObject([{ id: second.id, deletedAt: null }])
    const [trashed] = await service.listLogins({ deleted: true })
    expect(trashed).toMatchObject({
      id: first.id,
      subtitle: '',
      username: '',
      uri: null,
      deletedAt: expect.any(String)
    })
    expect(JSON.stringify(trashed)).not.toContain('trash-summary-secret-canary')
    await expect(service.getLogin({ id: first.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.updateLogin({ id: first.id, name: 'Blocked' })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.setLoginFavorite({ id: first.id, favorite: true })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.moveLogin({ id: first.id, folderId: null })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.revealPassword({ id: first.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.copyPassword({ id: first.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })

    const restored = await service.restoreLogin({ id: first.id })
    expect(restored.deletedAt).toBeNull()
    expect((await service.listLogins()).map((login) => login.id)).toContain(first.id)

    await service.deleteLogin({ id: first.id })
    await service.deleteLoginPermanently({ id: first.id })
    await expect(service.getLogin({ id: first.id })).rejects.toMatchObject({ code: 'NOT_FOUND' })
    await service.deleteLogin({ id: second.id })
    await expect(service.emptyTrash()).resolves.toBe(1)
    expect(await service.listLogins({ deleted: true })).toEqual([])
  })

  it('clones an active item locally, preserves supported fields, and excludes passkeys', async () => {
    let fake: ReturnType<typeof createSyncFake> | undefined
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake ??= createSyncFake(sync.state)
        fake.remoteLogins[0]!.attachments = [
          {
            id: 'source-attachment',
            fileName: 'source-only.txt',
            size: 1,
            sizeName: '1 B',
            legacy: false
          }
        ]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const source = (await service.listLogins())[0]!
    const sourceBefore = await service.getLogin({ id: source.id })

    const cloned = await service.cloneLogin({ id: source.id })
    expect(cloned).toMatchObject({
      id: expect.not.stringMatching(new RegExp(`^${source.id}$`)),
      name: 'Remote login - Clone',
      type: sourceBefore.type,
      folderId: sourceBefore.folderId,
      favorite: sourceBefore.favorite,
      notes: sourceBefore.notes,
      passkeys: [],
      attachments: [],
      customFields: sourceBefore.customFields
    })
    expect(cloned.lastUsedAt).toBeNull()
    expect(await service.getLogin({ id: source.id })).toEqual(sourceBefore)
    await expect(service.revealPassword({ id: cloned.id })).resolves.toBe('remote-test-secret')
    await expect(
      service.revealEditorSecrets({ id: cloned.id, expectedUpdatedAt: cloned.updatedAt })
    ).resolves.toMatchObject({
      fields: { password: 'remote-test-secret', totp: 'JBSWY3DPEHPK3PXP' },
      customFields: [expect.objectContaining({ value: 'remote-hidden-code' })]
    })

    await expect(service.syncNow()).resolves.toMatchObject({ pushed: 1 })
    const remoteClone = fake!.remoteLogins.find((login) => login.name === 'Remote login - Clone')
    expect(remoteClone).toMatchObject({
      folderId: fake!.remoteLogins[0]!.folderId,
      favorite: false,
      notes: null,
      passkeys: [],
      attachments: []
    })
    expect(sourceBefore.attachments).toHaveLength(1)
    expect(fake!.remoteLogins[0]!.passkeys).toHaveLength(1)
  })

  it('rejects cloning from trash and keeps the clone suffix within the item name limit', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const source = await service.createLogin({ name: 'x'.repeat(256) })
    const cloned = await service.cloneLogin({ id: source.id })
    expect(cloned.name).toHaveLength(256)
    expect(cloned.name).toBe(`${'x'.repeat(248)} - Clone`)

    await service.deleteLogin({ id: source.id })
    await expect(service.cloneLogin({ id: source.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })

    const emojiSource = await service.createLogin({ name: '😀'.repeat(128) })
    const emojiClone = await service.cloneLogin({ id: emojiSource.id })
    expect(emojiClone.name).toHaveLength(256)
    expect(emojiClone.name).toBe(`${'😀'.repeat(124)} - Clone`)
  })

  it('archives active items, keeps them readable, and restores their prior vault behavior', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const folder = await service.createFolder({ name: 'Archive' })
    const source = await service.createLogin({
      name: 'Archived login',
      folderId: folder.id,
      favorite: true,
      password: 'archive-secret'
    })

    const archived = await service.archiveLogin({ id: source.id })
    expect(archived.archivedAt).toEqual(expect.any(String))
    expect(await service.listLogins()).toEqual([])
    expect(await service.listLogins({ archived: true })).toMatchObject([
      { id: source.id, archivedAt: archived.archivedAt, favorite: true }
    ])
    await expect(service.getLogin({ id: source.id })).resolves.toMatchObject({
      id: source.id,
      folderId: folder.id,
      archivedAt: archived.archivedAt
    })
    await expect(service.revealPassword({ id: source.id })).resolves.toBe('archive-secret')

    const cloned = await service.cloneLogin({ id: source.id })
    expect(cloned).toMatchObject({ archivedAt: archived.archivedAt, passkeys: [] })
    await expect(service.archiveLogin({ id: source.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    const unarchived = await service.unarchiveLogin({ id: source.id })
    expect(unarchived.archivedAt).toBeNull()
    expect(await service.listLogins()).toMatchObject([{ id: source.id }])
    await expect(service.unarchiveLogin({ id: source.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })

    await service.deleteLogin({ id: source.id })
    await expect(service.archiveLogin({ id: source.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.unarchiveLogin({ id: source.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
  })

  it('mutates login lifecycle batches atomically with one timestamp and one write', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const first = await service.createLogin({ name: 'First batch item' })
    const second = await service.createLogin({ name: 'Second batch item' })
    const write = vi.spyOn(store, 'write')

    const archived = await service.archiveLogins({ ids: [first.id, second.id] })
    expect(new Set(archived.map((login) => login.archivedAt))).toHaveLength(1)
    expect(new Set(archived.map((login) => login.updatedAt))).toHaveLength(1)
    expect(write).toHaveBeenCalledOnce()

    write.mockClear()
    const unarchived = await service.unarchiveLogins({ ids: [first.id, second.id] })
    expect(unarchived.every((login) => login.archivedAt === null)).toBe(true)
    expect(new Set(unarchived.map((login) => login.updatedAt))).toHaveLength(1)
    expect(write).toHaveBeenCalledOnce()

    await service.archiveLogin({ id: first.id })
    const firstArchivedAt = (await service.getLogin({ id: first.id })).archivedAt
    write.mockClear()
    await expect(service.deleteLogins({ ids: [first.id, second.id] })).resolves.toBe(2)
    const trashed = await service.listLogins({ deleted: true })
    expect(new Set(trashed.map((login) => login.deletedAt))).toHaveLength(1)
    expect(trashed.find((login) => login.id === first.id)?.archivedAt).toBe(firstArchivedAt)
    expect(write).toHaveBeenCalledOnce()

    write.mockClear()
    const restored = await service.restoreLogins({ ids: [first.id, second.id] })
    expect(new Set(restored.map((login) => login.updatedAt))).toHaveLength(1)
    expect(restored.find((login) => login.id === first.id)?.archivedAt).toBe(firstArchivedAt)
    expect(restored.find((login) => login.id === second.id)?.archivedAt).toBeNull()
    expect(write).toHaveBeenCalledOnce()

    await service.deleteLogins({ ids: [first.id, second.id] })
    write.mockClear()
    await expect(service.deleteLoginsPermanently({ ids: [first.id, second.id] })).resolves.toBe(2)
    expect(write).toHaveBeenCalledOnce()
    expect(await service.listLogins({ deleted: true })).toEqual([])
  })

  it('rejects invalid login batches without writes or partial lifecycle changes', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const first = await service.createLogin({ name: 'First validation item' })
    const second = await service.createLogin({ name: 'Second validation item' })
    const write = vi.spyOn(store, 'write')
    const oversizedIds = Array.from(
      { length: 501 },
      (_, index) => `00000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`
    )

    await expect(service.archiveLogins({ ids: [] })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.archiveLogins({ ids: oversizedIds.slice(0, 500) })).rejects.toMatchObject({
      code: 'NOT_FOUND'
    })
    await expect(service.archiveLogins({ ids: oversizedIds })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.archiveLogins({ ids: [first.id, 'not-a-uuid'] })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.archiveLogins({ ids: [first.id, first.id] })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.archiveLogins({ ids: [first.id, IDS[10]!] })).rejects.toMatchObject({
      code: 'NOT_FOUND'
    })
    expect(write).not.toHaveBeenCalled()
    expect((await service.listLogins()).map((login) => login.id)).toEqual([first.id, second.id])
  })

  it('validates every batch item state before changing any login', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const first = await service.createLogin({ name: 'Active batch item' })
    const second = await service.createLogin({ name: 'Archived batch item' })
    await service.archiveLogin({ id: second.id })
    const write = vi.spyOn(store, 'write')

    await expect(service.archiveLogins({ ids: [first.id, second.id] })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.unarchiveLogins({ ids: [second.id, first.id] })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    expect(write).not.toHaveBeenCalled()
    expect((await service.getLogin({ id: first.id })).archivedAt).toBeNull()
    expect((await service.getLogin({ id: second.id })).archivedAt).not.toBeNull()

    await service.deleteLogin({ id: first.id })
    write.mockClear()
    await expect(service.deleteLogins({ ids: [second.id, first.id] })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.restoreLogins({ ids: [first.id, second.id] })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(
      service.deleteLoginsPermanently({ ids: [first.id, second.id] })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    expect(write).not.toHaveBeenCalled()
    expect((await service.listLogins({ deleted: true })).map((login) => login.id)).toEqual([
      first.id
    ])
    expect((await service.listLogins({ archived: true })).map((login) => login.id)).toEqual([
      second.id
    ])
  })

  it('records a tombstone for every permanently deleted login in a batch', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake ??= createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const first = (await service.listLogins())[0]!
    const second = await service.createLogin({ name: 'Second mapped batch item' })
    await service.syncNow()
    const remoteIds = fake!.remoteLogins.map((login) => login.id)

    await service.deleteLogins({ ids: [first.id, second.id] })
    await expect(service.deleteLoginsPermanently({ ids: [first.id, second.id] })).resolves.toBe(2)
    await service.syncNow()

    expect(fake!.hardDeletedIds).toEqual(expect.arrayContaining(remoteIds))
    expect(fake!.hardDeletedIds).toHaveLength(2)
    expect(fake!.remoteLogins).toEqual([])
  })

  it('syncs archive atomically and resumes an interrupted content-plus-unarchive', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake ??= createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!

    await service.updateLogin({ id: local.id, password: 'archive-after-edit' })
    await service.archiveLogin({ id: local.id })
    await expect(service.syncNow()).resolves.toMatchObject({ conflicts: 0, pushed: 1 })
    expect(fake!.remoteLogins[0]).toMatchObject({
      password: 'archive-after-edit',
      archivedAt: expect.any(String)
    })
    await expect(service.listLogins({ archived: true })).resolves.toMatchObject([
      { id: local.id, archivedAt: expect.any(String) }
    ])

    const edit = fake!.editLogin.bind(fake)
    let failOnce = true
    fake!.editLogin = async (id, draft, signal) => {
      if (failOnce) {
        failOnce = false
        throw new Error('injected edit after unarchive failure')
      }
      return edit(id, draft, signal)
    }
    await service.unarchiveLogin({ id: local.id })
    await service.updateLogin({ id: local.id, password: 'unarchive-after-edit' })
    await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    expect(fake!.remoteLogins[0]).toMatchObject({
      password: 'archive-after-edit',
      archivedAt: null
    })

    service.dispose()
    const reopened = new VaultService(
      new EncryptedVaultStore(filePath),
      { copyText: vi.fn(), openExternal: vi.fn() },
      { createSyncClient: () => fake! }
    )
    await reopened.unlock(MASTER_PASSWORD)
    await expect(reopened.syncNow()).resolves.toMatchObject({ conflicts: 0 })
    expect(fake!.remoteLogins[0]).toMatchObject({
      password: 'unarchive-after-edit',
      archivedAt: null
    })
    expect(await reopened.listLogins()).toMatchObject([{ id: local.id, archivedAt: null }])
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

  it('generates official Steam and custom-period TOTP vectors at a fixed instant', async () => {
    const { service, copyText } = await createHarness({
      now: () => new Date('2023-01-01T00:00:00.000Z')
    })
    await service.setup(MASTER_PASSWORD)
    const steam = await service.createLogin({
      name: 'Steam test vector',
      totp: 'steam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ'
    })
    const custom = await service.createLogin({
      name: 'Custom TOTP test vector',
      totp: 'otpauth://totp/example.invalid?secret=WQIQ25BRKZYCJVYP&digits=8&period=60'
    })

    await expect(service.getTotp({ id: steam.id })).resolves.toEqual({
      code: '7W6CJ',
      period: 30,
      remainingSeconds: 30
    })
    await expect(service.getTotp({ id: custom.id })).resolves.toEqual({
      code: '97730364',
      period: 60,
      remainingSeconds: 60
    })

    await service.copyTotp({ id: steam.id })
    await service.copyTotp({ id: custom.id })
    expect(copyText).toHaveBeenNthCalledWith(1, '7W6CJ')
    expect(copyText).toHaveBeenNthCalledWith(2, '97730364')
  })

  it('preserves opaque TOTP values through create, update, and sync but refuses to use them', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const remoteOpaqueTotp = 'vaultwarden-opaque://totp?format=future'
    const createdOpaqueTotp = 'future-totp://created?format=opaque'
    const updatedOpaqueTotp = 'future-totp://updated?format=opaque'
    const { service, copyText } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.totp = remoteOpaqueTotp
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })

    const remote = (await service.listLogins())[0]!
    await expect(
      service.revealEditorSecrets({ id: remote.id, expectedUpdatedAt: remote.updatedAt })
    ).resolves.toMatchObject({ fields: { totp: remoteOpaqueTotp } })
    await expect(service.getTotp({ id: remote.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.copyTotp({ id: remote.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })

    const created = await service.createLogin({
      name: 'Opaque TOTP item',
      totp: createdOpaqueTotp
    })
    await expect(
      service.revealEditorSecrets({ id: created.id, expectedUpdatedAt: created.updatedAt })
    ).resolves.toMatchObject({ fields: { totp: createdOpaqueTotp } })
    const updated = await service.updateLogin({ id: created.id, totp: updatedOpaqueTotp })
    await expect(
      service.revealEditorSecrets({ id: updated.id, expectedUpdatedAt: updated.updatedAt })
    ).resolves.toMatchObject({ fields: { totp: updatedOpaqueTotp } })
    await expect(service.getTotp({ id: updated.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.copyTotp({ id: updated.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    expect(copyText).not.toHaveBeenCalled()

    await expect(service.syncNow()).resolves.toMatchObject({ pushed: 1 })
    expect(fake!.remoteLogins.find((login) => login.name === 'Opaque TOTP item')?.totp).toBe(
      updatedOpaqueTotp
    )
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

  it('reveals a complete editor secret snapshot for every item type', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({
      name: 'Login secrets',
      password: 'login-secret',
      totp: 'JBSWY3DPEHPK3PXP',
      customFields: [
        { source: null, name: 'recovery', type: 'hidden', value: 'custom-secret', linkedId: null }
      ]
    })
    const card = await service.createLogin({
      type: 'card',
      name: 'Card secrets',
      number: '4111111111111111',
      code: '123'
    })
    const identity = await service.createLogin({
      type: 'identity',
      name: 'Identity secrets',
      ssn: 'identity-secret',
      passportNumber: 'passport-secret',
      licenseNumber: 'license-secret'
    })
    const note = await service.createLogin({ type: 'secureNote', name: 'No secrets' })
    const sshKey = await service.createLogin({
      type: 'sshKey',
      name: 'SSH secret',
      privateKey: 'private-key-secret'
    })

    await expect(
      service.revealEditorSecrets({ id: login.id, expectedUpdatedAt: login.updatedAt })
    ).resolves.toEqual({
      fields: { password: 'login-secret', totp: 'JBSWY3DPEHPK3PXP' },
      customFields: [
        {
          source: { index: 0, name: 'recovery', type: 'hidden', linkedId: null },
          value: 'custom-secret'
        }
      ]
    })
    await expect(
      service.revealEditorSecrets({ id: card.id, expectedUpdatedAt: card.updatedAt })
    ).resolves.toEqual({
      fields: { number: '4111111111111111', code: '123' },
      customFields: []
    })
    await expect(
      service.revealEditorSecrets({ id: identity.id, expectedUpdatedAt: identity.updatedAt })
    ).resolves.toEqual({
      fields: {
        ssn: 'identity-secret',
        passportNumber: 'passport-secret',
        licenseNumber: 'license-secret'
      },
      customFields: []
    })
    await expect(
      service.revealEditorSecrets({ id: note.id, expectedUpdatedAt: note.updatedAt })
    ).resolves.toEqual({ fields: {}, customFields: [] })
    await expect(
      service.revealEditorSecrets({ id: sshKey.id, expectedUpdatedAt: sshKey.updatedAt })
    ).resolves.toEqual({ fields: { privateKey: 'private-key-secret' }, customFields: [] })

    await service.updateLogin({ id: login.id, name: 'Updated login secrets' })
    await expect(
      service.revealEditorSecrets({ id: login.id, expectedUpdatedAt: login.updatedAt })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
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

  it('records password and changed hidden fields in official order and caps history at five', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const created = await service.createLogin({
      name: 'History',
      password: 'password-zero',
      customFields: [
        { source: null, name: 'alpha', type: 'hidden', value: 'alpha-secret', linkedId: null },
        { source: null, name: 'beta', type: 'hidden', value: 'beta-secret', linkedId: null }
      ]
    })
    expect(created.passwordHistoryCount).toBe(0)
    expect(created).not.toHaveProperty('passwordHistory')

    const updated = await service.updateLogin({
      id: created.id,
      password: 'password-one',
      customFields: [
        {
          source: { index: 1, name: 'beta', type: 'hidden', linkedId: null },
          name: 'renamed-beta',
          type: 'hidden',
          value: null,
          linkedId: null
        }
      ]
    })
    expect(updated.passwordHistoryCount).toBe(3)
    expect(
      (await service.getPasswordHistory({ id: created.id })).map((entry) => entry.password)
    ).toEqual(['beta: beta-secret', 'alpha: alpha-secret', 'password-zero'])

    for (const password of ['password-two', 'password-three', 'password-four']) {
      await service.updateLogin({ id: created.id, password })
    }
    expect(
      (await service.getPasswordHistory({ id: created.id })).map((entry) => entry.password)
    ).toEqual([
      'password-three',
      'password-two',
      'password-one',
      'beta: beta-secret',
      'alpha: alpha-secret'
    ])
    await service.updateLogin({ id: created.id, password: 'password-three' })
    await service.updateLogin({ id: created.id, password: 'password-four' })
    expect(
      (await service.getPasswordHistory({ id: created.id })).map((entry) => entry.password)
    ).toEqual(['password-three', 'password-four', 'password-three', 'password-two', 'password-one'])
  })

  it('consumes duplicate hidden fields as a multiset when recording removed secrets', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const created = await service.createLogin({
      name: 'Duplicate hidden history',
      password: 'old-password',
      customFields: [
        { source: null, name: 'duplicate', type: 'hidden', value: 'same-secret', linkedId: null },
        { source: null, name: 'duplicate', type: 'hidden', value: 'same-secret', linkedId: null }
      ]
    })

    await service.updateLogin({
      id: created.id,
      password: 'new-password',
      customFields: [
        {
          source: { index: 0, name: 'duplicate', type: 'hidden', linkedId: null },
          name: 'duplicate',
          type: 'hidden',
          value: null,
          linkedId: null
        }
      ]
    })
    expect(await service.getPasswordHistory({ id: created.id })).toMatchObject([
      { password: 'duplicate: same-secret' },
      { password: 'old-password' }
    ])

    const renamed = await service.createLogin({
      name: 'Changed duplicates',
      customFields: [
        { source: null, name: 'duplicate', type: 'hidden', value: 'same-secret', linkedId: null },
        { source: null, name: 'duplicate', type: 'hidden', value: 'same-secret', linkedId: null }
      ]
    })
    await service.updateLogin({
      id: renamed.id,
      customFields: [
        {
          source: { index: 0, name: 'duplicate', type: 'hidden', linkedId: null },
          name: 'renamed',
          type: 'hidden',
          value: null,
          linkedId: null
        },
        {
          source: { index: 1, name: 'duplicate', type: 'hidden', linkedId: null },
          name: 'duplicate',
          type: 'text',
          value: 'visible-value',
          linkedId: null
        }
      ]
    })
    expect(await service.getPasswordHistory({ id: renamed.id })).toMatchObject([
      { password: 'duplicate: same-secret' },
      { password: 'duplicate: same-secret' }
    ])
  })

  it('starts clones with empty history, retains archive/trash history, and rejects trash reads', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const created = await service.createLogin({ name: 'Lifecycle history', password: 'old-secret' })
    await service.updateLogin({ id: created.id, password: 'new-secret' })
    const clone = await service.cloneLogin({ id: created.id })
    expect(clone.passwordHistoryCount).toBe(0)
    await expect(service.getPasswordHistory({ id: clone.id })).resolves.toEqual([])

    await service.archiveLogin({ id: created.id })
    await expect(service.getPasswordHistory({ id: created.id })).resolves.toMatchObject([
      { password: 'old-secret' }
    ])
    await service.deleteLogin({ id: created.id })
    await expect(service.getPasswordHistory({ id: created.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await service.restoreLogin({ id: created.id })
    await expect(service.getPasswordHistory({ id: created.id })).resolves.toMatchObject([
      { password: 'old-secret' }
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

  it('migrates V1 through V11 login records to V14 items', async () => {
    for (const version of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] as const) {
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
            ...(version >= 7 ? { deletedAt: null } : {}),
            ...(version >= 9 ? { archivedAt: null } : {}),
            ...(version >= 10 ? { reprompt: 0 } : {}),
            ...(version >= 11
              ? {
                  uris: [{ uri: 'https://legacy.example.invalid', match: null }],
                  passwordHistory: [
                    {
                      password: 'untrusted-pre-v12-history',
                      lastUsedDate: '2026-07-13T00:00:00.000Z'
                    }
                  ]
                }
              : {}),
            passkeys: [],
            ...(version >= 6 ? { customFields: [] } : {})
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
      expect(migrated).toMatchObject({
        type: 'login',
        username: 'legacy-user',
        deletedAt: null,
        archivedAt: null,
        reprompt: 0,
        uri: 'https://legacy.example.invalid',
        uris: [{ uri: 'https://legacy.example.invalid', match: null }]
      })
      await expect(service.getLogin({ id: migrated.id })).resolves.toMatchObject({
        customFields: [],
        passwordHistoryCount: 0
      })
      await expect(service.getPasswordHistory({ id: migrated.id })).resolves.toEqual([])
      await expect(service.generatorHistory()).resolves.toEqual([])
      expect(await service.revealPassword({ id: migrated.id })).toBe('legacy-secret')
      await service.lock()
      const unlocked = await store.unlock(MASTER_PASSWORD)
      expect((unlocked.data as { version: number }).version).toBe(14)
      unlocked.key.fill(0)
      unlocked.salt.fill(0)
    }
  }, 15_000)

  it('tracks encrypted local generator history, deduplicates, copies safely, and retains it across lock', async () => {
    const { copyText, filePath, service, store } = await createHarness({ randomInt: () => 0 })
    await service.setup(MASTER_PASSWORD)

    const password = await service.generateCredential({ algorithm: 'password', options: {} })
    await service.copyGeneratorHistory(password.historyLocator)
    expect(copyText).toHaveBeenLastCalledWith(password.credential)

    const write = vi.spyOn(store, 'write')
    const duplicate = await service.generateCredential({ algorithm: 'password', options: {} })
    expect(duplicate.credential).toBe(password.credential)
    expect(duplicate.historyLocator).toEqual(password.historyLocator)
    expect(write).not.toHaveBeenCalled()

    const passphrase = await service.generateCredential({ algorithm: 'passphrase', options: {} })
    const username = await service.generateCredential({
      algorithm: 'username',
      options: { capitalize: true, includeNumber: true }
    })
    const subaddress = await service.generateCredential({
      algorithm: 'subaddress',
      email: 'bear@example.invalid'
    })
    const catchall = await service.generateCredential({
      algorithm: 'catchall',
      domain: 'example.invalid'
    })
    expect(passphrase.credential).toBe('abacus-abacus-abacus-abacus-abacus-abacus')
    expect(username.credential).toBe('Abacus0000')
    expect(subaddress.credential).toBe('bear+aaaaaaaa@example.invalid')
    expect(catchall.credential).toBe('aaaaaaaa@example.invalid')

    const history = await service.generatorHistory()
    expect(history.map((entry) => entry.algorithm)).toEqual([
      'catchall',
      'subaddress',
      'username',
      'passphrase',
      'password'
    ])
    await expect(service.copyGeneratorHistory(password.historyLocator)).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(
      service.copyGeneratorHistory({
        index: 4,
        generationDate: password.generationDate,
        category: password.category,
        algorithm: password.algorithm
      })
    ).resolves.toBeUndefined()

    const encrypted = await readFile(filePath, 'utf8')
    for (const secret of history.map((entry) => entry.credential)) {
      expect(encrypted).not.toContain(secret)
    }
    await service.lock()
    await expect(service.generatorHistory()).rejects.toMatchObject({ code: 'LOCKED' })
    await service.unlock(MASTER_PASSWORD)
    expect(await service.generatorHistory()).toEqual(history)
    await service.clearGeneratorHistory()
    await expect(service.generatorHistory()).resolves.toEqual([])
  })

  it('generates transient SSH key material only while unlocked without recording history', async () => {
    const { service, store } = await createHarness()

    await expect(service.generateSshKey()).rejects.toMatchObject({ code: 'LOCKED' })
    await service.setup(MASTER_PASSWORD)
    const write = vi.spyOn(store, 'write')
    const historyBefore = await service.generatorHistory()

    const generated = await service.generateSshKey()

    expect(generated).toEqual({
      privateKey: expect.any(String),
      publicKey: expect.any(String),
      fingerprint: expect.any(String)
    })
    expect(generated.privateKey).not.toBe('')
    expect(generated.publicKey).not.toBe('')
    expect(generated.fingerprint).not.toBe('')
    await expect(service.generatorHistory()).resolves.toEqual(historyBefore)
    expect(write).not.toHaveBeenCalled()

    await service.lock()
    await expect(service.generateSshKey()).rejects.toMatchObject({ code: 'LOCKED' })
  })

  it('caps generator history at 200 newest exact entries', async () => {
    const { filePath, service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    await service.lock()
    const unlocked = await store.unlock(MASTER_PASSWORD)
    const data = unlocked.data as {
      generatorHistory: Array<{
        credential: string
        category: 'password'
        generationDate: number
        algorithm: 'password'
      }>
    }
    data.generatorHistory = Array.from({ length: 200 }, (_, index) => ({
      credential: `historical-${index}`,
      category: 'password',
      generationDate: index,
      algorithm: 'password'
    }))
    await store.write(data, unlocked.key, unlocked.salt)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)

    const reopened = new VaultService(
      new EncryptedVaultStore<unknown>(filePath),
      { copyText: vi.fn(), openExternal: vi.fn() },
      { randomInt: () => 0 }
    )
    await reopened.unlock(MASTER_PASSWORD)
    await reopened.generateCredential({ algorithm: 'catchall', domain: 'example.invalid' })
    const history = await reopened.generatorHistory()
    expect(history).toHaveLength(200)
    expect(history[0]).toMatchObject({
      credential: 'aaaaaaaa@example.invalid',
      category: 'email',
      algorithm: 'catchall'
    })
    expect(history.at(-1)?.credential).toBe('historical-198')
  })

  it('migrates V12 to an empty encrypted V14 generator history', async () => {
    const { filePath, service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    await service.lock()
    const unlocked = await store.unlock(MASTER_PASSWORD)
    const data = unlocked.data as Record<string, unknown>
    data.version = 12
    delete data.generatorHistory
    await store.write(data, unlocked.key, unlocked.salt)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)

    const reopenedStore = new EncryptedVaultStore<unknown>(filePath)
    const reopened = new VaultService(reopenedStore, {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(reopened.unlock(MASTER_PASSWORD)).resolves.toEqual({ state: 'unlocked' })
    await expect(reopened.generatorHistory()).resolves.toEqual([])
    await reopened.lock()
    const migrated = await reopenedStore.unlock(MASTER_PASSWORD)
    expect(migrated.data).toMatchObject({ version: 14, generatorHistory: [] })
    migrated.key.fill(0)
    migrated.salt.fill(0)
  })

  it('migrates V13 login records to V14 with empty attachment metadata', async () => {
    const { filePath, service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({ name: 'Pre-attachment item' })
    await service.lock()
    const unlocked = await store.unlock(MASTER_PASSWORD)
    const data = unlocked.data as {
      version: number
      logins: Array<Record<string, unknown>>
    }
    data.version = 13
    for (const storedLogin of data.logins) delete storedLogin.attachments
    await store.write(data, unlocked.key, unlocked.salt)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)

    const reopenedStore = new EncryptedVaultStore<unknown>(filePath)
    const reopened = new VaultService(reopenedStore, {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(reopened.unlock(MASTER_PASSWORD)).resolves.toEqual({ state: 'unlocked' })
    await expect(reopened.getLogin({ id: login.id })).resolves.toMatchObject({
      attachmentCount: 0,
      attachments: []
    })
    await reopened.lock()
    const migrated = await reopenedStore.unlock(MASTER_PASSWORD)
    expect(migrated.data).toMatchObject({
      version: 14,
      logins: [expect.objectContaining({ attachments: [] })]
    })
    migrated.key.fill(0)
    migrated.salt.fill(0)
  })

  it.each([
    {
      label: 'more than 200 entries',
      value: Array.from({ length: 201 }, (_, index) => ({
        credential: `generated-${index}`,
        category: 'password',
        generationDate: index,
        algorithm: 'password'
      }))
    },
    {
      label: 'a duplicate credential',
      value: [
        { credential: 'same', category: 'password', generationDate: 1, algorithm: 'password' },
        { credential: 'same', category: 'password', generationDate: 2, algorithm: 'password' }
      ]
    },
    {
      label: 'an oversized credential',
      value: [
        {
          credential: 'x'.repeat(513),
          category: 'password',
          generationDate: 1,
          algorithm: 'password'
        }
      ]
    },
    {
      label: 'an unknown key',
      value: [
        {
          credential: 'generated',
          category: 'password',
          generationDate: 1,
          algorithm: 'password',
          future: true
        }
      ]
    },
    {
      label: 'a category and algorithm mismatch',
      value: [
        {
          credential: 'generated',
          category: 'email',
          generationDate: 1,
          algorithm: 'password'
        }
      ]
    }
  ])('rejects generator history with $label in the V13 schema', async ({ value }) => {
    const { filePath, service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    await service.lock()
    const unlocked = await store.unlock(MASTER_PASSWORD)
    ;(unlocked.data as { generatorHistory: unknown }).generatorHistory = value
    await store.write(unlocked.data, unlocked.key, unlocked.salt)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)

    const reopened = new VaultService(new EncryptedVaultStore<unknown>(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(reopened.unlock(MASTER_PASSWORD)).rejects.toMatchObject({
      code: 'CORRUPT_VAULT'
    })
  })

  it('rejects an invalid deletedAt value in the current vault schema', async () => {
    const { filePath, service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    await service.createLogin({ name: 'Corrupt date test' })
    await service.lock()

    const unlocked = await store.unlock(MASTER_PASSWORD)
    const data = unlocked.data as { logins: Array<{ deletedAt: unknown }> }
    data.logins[0]!.deletedAt = 'not-an-iso-date'
    await store.write(data, unlocked.key, unlocked.salt)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)

    const reopened = new VaultService(new EncryptedVaultStore<unknown>(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(reopened.unlock(MASTER_PASSWORD)).rejects.toMatchObject({
      code: 'CORRUPT_VAULT'
    })
  })

  it.each([
    {
      label: 'more than five entries',
      value: Array.from({ length: 6 }, (_, index) => ({
        password: `old-${index}`,
        lastUsedDate: '2026-07-14T00:00:00.000Z'
      }))
    },
    {
      label: 'an unknown key',
      value: [
        {
          password: 'old',
          lastUsedDate: '2026-07-14T00:00:00.000Z',
          future: true
        }
      ]
    },
    {
      label: 'an empty password',
      value: [{ password: '', lastUsedDate: '2026-07-14T00:00:00.000Z' }]
    },
    {
      label: 'a non-canonical date',
      value: [{ password: 'old', lastUsedDate: '2026-07-14' }]
    }
  ])('rejects password history with $label in the V12 schema', async ({ value }) => {
    const { filePath, service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    await service.createLogin({ name: 'Corrupt history' })
    await service.lock()

    const unlocked = await store.unlock(MASTER_PASSWORD)
    const data = unlocked.data as { logins: Array<{ passwordHistory: unknown }> }
    data.logins[0]!.passwordHistory = value
    await store.write(data, unlocked.key, unlocked.salt)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)

    const reopened = new VaultService(new EncryptedVaultStore<unknown>(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(reopened.unlock(MASTER_PASSWORD)).rejects.toMatchObject({
      code: 'CORRUPT_VAULT'
    })
  })

  it('round-trips reprompt metadata and verifies the local master-password proof', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const protectedLogin = await service.createLogin({
      name: 'Protected item',
      username: 'private-user',
      uri: 'https://private.example.invalid',
      reprompt: 1
    })

    expect(await service.listLogins()).toEqual([
      expect.objectContaining({
        id: protectedLogin.id,
        reprompt: 1,
        username: '',
        uri: null,
        subtitle: ''
      })
    ])
    await expect(
      service.authorizeLogin({ id: protectedLogin.id, masterPassword: MASTER_PASSWORD })
    ).resolves.toBeTypeOf('number')
    await expect(
      service.authorizeLogin({ id: protectedLogin.id, masterPassword: 'wrong password' })
    ).rejects.toMatchObject({ code: 'INVALID_MASTER_PASSWORD' })

    const clone = await service.cloneLogin({ id: protectedLogin.id })
    expect(clone.reprompt).toBe(1)
    const updated = await service.updateLogin({ id: protectedLogin.id, reprompt: 0 })
    expect(updated.reprompt).toBe(0)
  })

  it('stores ordered URI match rows, keeps the primary alias, and addresses secondary rows', async () => {
    const { copyText, openExternal, service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const created = await service.createLogin({
      name: 'Multiple websites',
      username: 'multi-user',
      uri: 'https://primary.example.invalid',
      uris: [
        { uri: 'https://primary.example.invalid', match: 0 },
        { uri: '^https://accounts\\.example\\.invalid/', match: 4 },
        { uri: 'https://never.example.invalid', match: 5 }
      ]
    })

    expect(created.uri).toBe('https://primary.example.invalid')
    expect(created.uris).toEqual([
      { uri: 'https://primary.example.invalid', match: 0 },
      { uri: '^https://accounts\\.example\\.invalid/', match: 4 },
      { uri: 'https://never.example.invalid', match: 5 }
    ])
    await service.copyField({ id: created.id, field: 'uri', uriIndex: 1 })
    expect(copyText).toHaveBeenLastCalledWith('^https://accounts\\.example\\.invalid/')
    await service.openLoginUri({ id: created.id, uriIndex: 2 })
    expect(openExternal).toHaveBeenLastCalledWith('https://never.example.invalid/')
    await expect(service.openLoginUri({ id: created.id, uriIndex: 1 })).rejects.toMatchObject({
      code: 'INVALID_URL'
    })

    const clone = await service.cloneLogin({ id: created.id })
    await service.updateLogin({
      id: created.id,
      uris: [{ uri: 'https://changed.example.invalid', match: 3 }],
      uri: 'https://changed.example.invalid'
    })
    expect(clone.uris).toHaveLength(3)
    expect((await service.getLogin({ id: clone.id })).uris[0]?.uri).toBe(
      'https://primary.example.invalid'
    )
  })

  it('rejects blank, oversized, over-cap, and alias-inconsistent local URI rows', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    await expect(
      service.createLogin({ name: 'Blank URI', uris: [{ uri: '  ', match: null }] })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.createLogin({
        name: 'Alias mismatch',
        uri: 'https://one.example.invalid',
        uris: [{ uri: 'https://two.example.invalid', match: null }]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.createLogin({
        name: 'Too long',
        uris: [{ uri: 'x'.repeat(4_097), match: null }]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.createLogin({
        name: 'Too many',
        uris: Array.from({ length: 1_001 }, (_, index) => ({
          uri: `https://${index}.example.invalid`,
          match: null
        }))
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('keeps authorization and the protected operation atomic against a queued reprompt change', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({ name: 'Race target', password: 'race-secret' })
    let releaseOperation!: () => void
    const operationGate = new Promise<void>((resolve) => {
      releaseOperation = resolve
    })
    let authorized = false
    const protectedOperation = service.runAuthorizedOperation(
      () => false,
      async (authorize) => {
        authorize([login.id])
        authorized = true
        await operationGate
        return service.revealPassword({ id: login.id })
      }
    )
    await vi.waitFor(() => expect(authorized).toBe(true))
    const enableReprompt = service.updateLogin({ id: login.id, reprompt: 1 })
    releaseOperation()
    await expect(protectedOperation).resolves.toBe('race-secret')
    await expect(enableReprompt).resolves.toMatchObject({ reprompt: 1 })

    await expect(
      service.runAuthorizedOperation(
        () => false,
        async (authorize) => {
          authorize([login.id])
          return service.revealPassword({ id: login.id })
        }
      )
    ).rejects.toMatchObject({ code: 'REPROMPT_REQUIRED' })
  })

  it('expires inherited reentrant context after the outer exclusive operation completes', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({ name: 'Context target' })
    let releaseLate!: () => void
    const lateGate = new Promise<void>((resolve) => {
      releaseLate = resolve
    })
    let lateRead!: Promise<LoginView>
    await service.runAuthorizedOperation(
      () => true,
      async (authorize) => {
        authorize([])
        lateRead = lateGate.then(() => service.getLogin({ id: login.id }))
      }
    )

    let releaseBlocker!: () => void
    let blockerEntered = false
    const blocker = service.runAuthorizedOperation(
      () => true,
      async (authorize) => {
        authorize([])
        blockerEntered = true
        await new Promise<void>((resolve) => {
          releaseBlocker = resolve
        })
      }
    )
    await vi.waitFor(() => expect(blockerEntered).toBe(true))
    let lateResolved = false
    void lateRead.then(() => {
      lateResolved = true
    })
    releaseLate()
    await Promise.resolve()
    await Promise.resolve()
    expect(lateResolved).toBe(false)
    releaseBlocker()
    await blocker
    await expect(lateRead).resolves.toMatchObject({ id: login.id })
  })

  it('rejects an invalid reprompt value in the current V11 schema', async () => {
    const { filePath, service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    await service.createLogin({ name: 'Corrupt reprompt test' })
    await service.lock()

    const unlocked = await store.unlock(MASTER_PASSWORD)
    const data = unlocked.data as { logins: Array<{ reprompt: unknown }> }
    data.logins[0]!.reprompt = 2
    await store.write(data, unlocked.key, unlocked.salt)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)

    const reopened = new VaultService(new EncryptedVaultStore<unknown>(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(reopened.unlock(MASTER_PASSWORD)).rejects.toMatchObject({
      code: 'CORRUPT_VAULT'
    })
  })
})
