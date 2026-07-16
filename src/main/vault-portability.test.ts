import { mkdtemp, readFile, rm, stat, truncate, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { VaultItemFields } from '../shared/vault-contract'
import {
  buildBitwardenJson,
  decryptBitwardenPasswordProtectedJson,
  encryptBitwardenPasswordProtectedJson,
  parseBitwardenJson,
  type PortableVaultSnapshot
} from './vault-portability-codec'
import { VaultPortabilityService, type VaultPortabilityPicker } from './vault-portability'
import type { VaultService } from './vault-service'

const MASTER_PASSWORD = 'correct horse battery staple'
const BACKUP_PASSWORD = 'portable backup password'
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

function portableSnapshot(): PortableVaultSnapshot {
  return {
    folders: [
      {
        id: '00000000-0000-4000-8000-000000000001',
        name: 'Portable folder',
        updatedAt: '2026-07-16T00:00:00.000Z'
      }
    ],
    items: [
      {
        ...emptyItemFields,
        id: '00000000-0000-4000-8000-000000000002',
        type: 'login',
        name: 'Portable login',
        username: 'sample-user',
        password: 'sample-secret',
        uri: 'https://example.invalid',
        uris: [{ uri: 'https://example.invalid', match: null }],
        notes: null,
        folderId: '00000000-0000-4000-8000-000000000001',
        favorite: true,
        lastUsedAt: null,
        createdAt: '2026-07-16T00:00:00.000Z',
        updatedAt: '2026-07-16T00:00:00.000Z',
        deletedAt: null,
        archivedAt: null,
        reprompt: 0,
        passkeys: [],
        customFields: [],
        passwordHistory: []
      }
    ]
  }
}

async function harness(options?: {
  exportPath?: string | null
  importPath?: string | null
}): Promise<{
  directory: string
  outputPath: string
  inputPath: string
  vault: {
    verifyPortabilityOwner: ReturnType<typeof vi.fn>
    exportPortableSnapshot: ReturnType<typeof vi.fn>
    importPortableSnapshot: ReturnType<typeof vi.fn>
  }
  picker: VaultPortabilityPicker
  service: VaultPortabilityService
}> {
  const directory = await mkdtemp(join(tmpdir(), 'bearwarden-portability-test-'))
  temporaryDirectories.push(directory)
  const outputPath = join(directory, 'nested', 'backup.json')
  const inputPath = join(directory, 'input.json')
  const snapshot = portableSnapshot()
  const vault = {
    verifyPortabilityOwner: vi.fn(async () => undefined),
    exportPortableSnapshot: vi.fn(async () => ({ snapshot, skippedTrashItems: 2 })),
    importPortableSnapshot: vi.fn(async () => ({
      importedFolders: snapshot.folders.length,
      importedItems: snapshot.items.length,
      skippedTrashItems: 0
    }))
  }
  const picker: VaultPortabilityPicker = {
    chooseExportPath: vi.fn(async () =>
      options && 'exportPath' in options ? (options.exportPath ?? null) : outputPath
    ),
    chooseImportPath: vi.fn(async () =>
      options && 'importPath' in options ? (options.importPath ?? null) : inputPath
    )
  }
  return {
    directory,
    outputPath,
    inputPath,
    vault,
    picker,
    service: new VaultPortabilityService(
      vault as unknown as VaultService,
      picker,
      () => new Date('2026-07-16T03:04:05.000Z')
    )
  }
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true }))
  )
})

describe('VaultPortabilityService', () => {
  it('writes only a private password-protected Bitwarden JSON file', async () => {
    const { outputPath, picker, service, vault } = await harness()

    await expect(
      service.exportVault({ masterPassword: MASTER_PASSWORD, password: BACKUP_PASSWORD })
    ).resolves.toEqual({
      canceled: false,
      exportedFolders: 1,
      exportedItems: 1,
      skippedTrashItems: 2
    })

    expect(picker.chooseExportPath).toHaveBeenCalledWith(
      'bitwarden_encrypted_export_20260716_030405Z.json'
    )
    expect(vault.exportPortableSnapshot).toHaveBeenCalledWith(MASTER_PASSWORD)
    expect(vault.verifyPortabilityOwner).toHaveBeenCalledWith(MASTER_PASSWORD)
    const encrypted = await readFile(outputPath, 'utf8')
    expect(encrypted).not.toContain('sample-secret')
    expect(JSON.parse(encrypted)).toMatchObject({ encrypted: true, passwordProtected: true })
    const clearText = await decryptBitwardenPasswordProtectedJson(encrypted, BACKUP_PASSWORD)
    expect(parseBitwardenJson(clearText).snapshot.items[0]).toMatchObject({
      name: 'Portable login',
      password: 'sample-secret'
    })
    expect((await stat(outputPath)).mode & 0o777).toBe(0o600)
  })

  it('verifies the owner but does no data work when a native picker is canceled', async () => {
    const { service, vault } = await harness({ exportPath: null, importPath: null })

    await expect(
      service.exportVault({ masterPassword: MASTER_PASSWORD, password: BACKUP_PASSWORD })
    ).resolves.toMatchObject({ canceled: true })
    await expect(service.importVault({ masterPassword: MASTER_PASSWORD })).resolves.toMatchObject({
      canceled: true
    })
    expect(vault.verifyPortabilityOwner).toHaveBeenCalledTimes(2)
    expect(vault.exportPortableSnapshot).not.toHaveBeenCalled()
    expect(vault.importPortableSnapshot).not.toHaveBeenCalled()
  })

  it('rejects an invalid owner proof before opening a picker or decrypting a file', async () => {
    const { service, picker, vault } = await harness()
    vault.verifyPortabilityOwner.mockRejectedValueOnce(
      Object.assign(new Error('INVALID_MASTER_PASSWORD'), { code: 'INVALID_MASTER_PASSWORD' })
    )

    await expect(
      service.importVault({
        masterPassword: 'incorrect master password',
        password: BACKUP_PASSWORD
      })
    ).rejects.toMatchObject({ code: 'INVALID_MASTER_PASSWORD' })
    expect(picker.chooseImportPath).not.toHaveBeenCalled()
    expect(vault.importPortableSnapshot).not.toHaveBeenCalled()
  })

  it('imports plaintext and password-protected Bitwarden JSON without exposing file paths', async () => {
    const { inputPath, service, vault } = await harness()
    const snapshot = portableSnapshot()
    const clearText = buildBitwardenJson(snapshot)
    await writeFile(inputPath, clearText)

    await expect(service.importVault({ masterPassword: MASTER_PASSWORD })).resolves.toMatchObject({
      canceled: false,
      importedItems: 1
    })
    expect(vault.importPortableSnapshot).toHaveBeenLastCalledWith(
      expect.objectContaining({
        folders: [
          expect.objectContaining({ id: snapshot.folders[0]!.id, name: 'Portable folder' })
        ],
        items: [
          expect.objectContaining({
            id: snapshot.items[0]!.id,
            name: 'Portable login',
            password: 'sample-secret'
          })
        ]
      }),
      0,
      MASTER_PASSWORD
    )

    const encrypted = await encryptBitwardenPasswordProtectedJson(clearText, BACKUP_PASSWORD)
    await writeFile(inputPath, encrypted)
    await service.importVault({ masterPassword: MASTER_PASSWORD, password: BACKUP_PASSWORD })
    expect(vault.importPortableSnapshot).toHaveBeenCalledTimes(2)
  })

  it('auto-detects Bitwarden and Chromium CSV without changing the JSON flow', async () => {
    const { inputPath, service, vault } = await harness()
    await writeFile(
      inputPath,
      [
        'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp',
        'Imported,1,login,CSV Login,,,0,https://example.test,csv-user,csv-secret,'
      ].join('\n')
    )
    await expect(service.importVault({ masterPassword: MASTER_PASSWORD })).resolves.toMatchObject({
      canceled: false,
      importedItems: 1
    })
    expect(vault.importPortableSnapshot).toHaveBeenLastCalledWith(
      expect.objectContaining({
        folders: [{ id: 'csv-folder-1', name: 'Imported' }],
        items: [
          expect.objectContaining({
            type: 'login',
            name: 'CSV Login',
            username: 'csv-user',
            password: 'csv-secret'
          })
        ]
      }),
      0,
      MASTER_PASSWORD
    )

    await writeFile(
      inputPath,
      'name,url,username,password,note\nChrome,https://chrome.test,user,password,note'
    )
    await service.importVault({ masterPassword: MASTER_PASSWORD })
    expect(vault.importPortableSnapshot).toHaveBeenLastCalledWith(
      expect.objectContaining({
        folders: [],
        items: [expect.objectContaining({ name: 'Chrome', uri: 'https://chrome.test' })]
      }),
      0,
      MASTER_PASSWORD
    )
  })

  it('rejects missing or incorrect passwords, malformed files, and oversized files before mutation', async () => {
    const { inputPath, service, vault } = await harness()
    const encrypted = await encryptBitwardenPasswordProtectedJson(
      buildBitwardenJson(portableSnapshot()),
      BACKUP_PASSWORD
    )
    await writeFile(inputPath, encrypted)

    await expect(service.importVault({ masterPassword: MASTER_PASSWORD })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(
      service.importVault({ masterPassword: MASTER_PASSWORD, password: 'incorrect password' })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await writeFile(inputPath, '{not json')
    await expect(service.importVault({ masterPassword: MASTER_PASSWORD })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await writeFile(
      inputPath,
      'name,url,username,password\nChrome,https://example.test,user,password'
    )
    await expect(
      service.importVault({ masterPassword: MASTER_PASSWORD, password: BACKUP_PASSWORD })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await truncate(inputPath, 64 * 1024 * 1024 + 1)
    await expect(service.importVault({ masterPassword: MASTER_PASSWORD })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    expect(vault.importPortableSnapshot).not.toHaveBeenCalled()
  })
})
