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
import { inspectNativeAttachmentBackup } from './native-attachment-backup'

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
        passwordHistory: [],
        passwordRevisionDate: null,
        autofillOnPageLoad: null
      }
    ]
  }
}

async function harness(options?: {
  exportPath?: string | null
  importPath?: string | null
  now?: () => Date
}): Promise<{
  directory: string
  outputPath: string
  inputPath: string
  vault: {
    unlockedGeneration: ReturnType<typeof vi.fn>
    verifyPortabilityOwner: ReturnType<typeof vi.fn>
    exportPortableSnapshot: ReturnType<typeof vi.fn>
    createNativeAttachmentBackupSource: ReturnType<typeof vi.fn>
    importPortableSnapshot: ReturnType<typeof vi.fn>
    nativeAttachmentRestoreStatus: ReturnType<typeof vi.fn>
    beginNativeAttachmentRestore: ReturnType<typeof vi.fn>
    syncNativeAttachmentRestoreItems: ReturnType<typeof vi.fn>
    uploadNativeAttachmentRestoreEntry: ReturnType<typeof vi.fn>
    reconcileNativeAttachmentRestoreEntry: ReturnType<typeof vi.fn>
    clearCompletedNativeAttachmentRestore: ReturnType<typeof vi.fn>
  }
  picker: VaultPortabilityPicker
  service: VaultPortabilityService
}> {
  const directory = await mkdtemp(join(tmpdir(), 'bearwarden-portability-test-'))
  temporaryDirectories.push(directory)
  const outputPath = join(directory, 'nested', 'backup.json')
  const inputPath = join(directory, 'input.json')
  const snapshot = portableSnapshot()
  const disposeNativeSource = vi.fn()
  const vault = {
    unlockedGeneration: vi.fn(async () => 4),
    verifyPortabilityOwner: vi.fn(async () => undefined),
    exportPortableSnapshot: vi.fn(async () => ({ snapshot, skippedTrashItems: 2 })),
    createNativeAttachmentBackupSource: vi.fn(async () => ({
      vaultJson: buildBitwardenJson(snapshot),
      attachments: [],
      exportedFolders: snapshot.folders.length,
      exportedItems: snapshot.items.length,
      skippedTrashItems: 2,
      openAttachment: vi.fn(),
      dispose: disposeNativeSource
    })),
    importPortableSnapshot: vi.fn(async () => ({
      importedFolders: snapshot.folders.length,
      importedItems: snapshot.items.length,
      skippedTrashItems: 0
    })),
    nativeAttachmentRestoreStatus: vi.fn(async () => null),
    beginNativeAttachmentRestore: vi.fn(async () => ({
      phase: 'syncing-items',
      totalItems: 1,
      mappedItems: 0,
      totalAttachments: 0,
      uploadedAttachments: 0,
      needsReconciliationAttachments: 0,
      totalBytes: 0,
      completedBytes: 0
    })),
    syncNativeAttachmentRestoreItems: vi.fn(async () => ({
      phase: 'complete',
      totalItems: 1,
      mappedItems: 1,
      totalAttachments: 0,
      uploadedAttachments: 0,
      needsReconciliationAttachments: 0,
      totalBytes: 0,
      completedBytes: 0
    })),
    uploadNativeAttachmentRestoreEntry: vi.fn(),
    reconcileNativeAttachmentRestoreEntry: vi.fn(),
    clearCompletedNativeAttachmentRestore: vi.fn(async () => undefined)
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
      options?.now ?? (() => new Date('2026-07-16T03:04:05.000Z'))
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

  it('keeps native attachment backup behind an explicit main-process format', async () => {
    const { outputPath, picker, service, vault } = await harness()

    await expect(
      service.exportVault({
        masterPassword: MASTER_PASSWORD,
        password: BACKUP_PASSWORD,
        format: 'bearwarden-native'
      })
    ).resolves.toEqual({
      canceled: false,
      exportedFolders: 1,
      exportedItems: 1,
      skippedTrashItems: 2,
      attachmentCount: 0,
      attachmentBytes: 0,
      resumed: false
    })

    expect(picker.chooseExportPath).toHaveBeenCalledWith(
      'bearwarden_backup_20260716_030405Z.bwbackup'
    )
    expect(vault.createNativeAttachmentBackupSource).toHaveBeenCalledWith(MASTER_PASSWORD, {
      includeLoginWireMetadata: true
    })
    expect(vault.exportPortableSnapshot).not.toHaveBeenCalled()
    const nativeSource = await vault.createNativeAttachmentBackupSource.mock.results[0]!.value
    expect(nativeSource.dispose).toHaveBeenCalledOnce()
    const inspected = await inspectNativeAttachmentBackup(outputPath, BACKUP_PASSWORD)
    expect(parseBitwardenJson(inspected.vaultJson).snapshot.items).toHaveLength(1)
  })

  it('streams an explicitly plaintext Bitwarden ZIP through the attachment source', async () => {
    const { outputPath, picker, service, vault } = await harness()

    await expect(
      service.exportVault({ masterPassword: MASTER_PASSWORD, format: 'bitwarden-zip' })
    ).resolves.toEqual({
      canceled: false,
      exportedFolders: 1,
      exportedItems: 1,
      skippedTrashItems: 2,
      attachmentCount: 0,
      attachmentBytes: 0
    })

    expect(picker.chooseExportPath).toHaveBeenCalledWith('bitwarden_export_20260716_030405Z.zip')
    expect(vault.createNativeAttachmentBackupSource).toHaveBeenCalledWith(MASTER_PASSWORD, {
      includeLoginWireMetadata: false
    })
    expect(vault.exportPortableSnapshot).not.toHaveBeenCalled()
    const source = await vault.createNativeAttachmentBackupSource.mock.results[0]!.value
    expect(source.dispose).toHaveBeenCalledOnce()
    expect((await readFile(outputPath)).subarray(0, 2).toString('ascii')).toBe('PK')
    expect((await stat(outputPath)).mode & 0o777).toBe(0o600)
  })

  it('rejects passwords for plaintext ZIP and requires them for encrypted exports', async () => {
    const { picker, service, vault } = await harness()

    await expect(
      service.exportVault({
        masterPassword: MASTER_PASSWORD,
        format: 'bitwarden-zip',
        password: BACKUP_PASSWORD
      } as never)
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.exportVault({ masterPassword: MASTER_PASSWORD } as never)
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    expect(vault.verifyPortabilityOwner).not.toHaveBeenCalled()
    expect(picker.chooseExportPath).not.toHaveBeenCalled()
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

  it('keeps native restore archive secrets in one owner-bound main session', async () => {
    const { outputPath, picker, service, vault } = await harness()
    await service.exportVault({
      masterPassword: MASTER_PASSWORD,
      password: BACKUP_PASSWORD,
      format: 'bearwarden-native'
    })
    vi.mocked(picker.chooseImportPath).mockResolvedValue(outputPath)

    const preview = await service.previewNativeRestore(7, BACKUP_PASSWORD)
    expect(preview).toMatchObject({
      canceled: false,
      sessionId: expect.stringMatching(/^[0-9a-f-]{36}$/),
      folderCount: 1,
      itemCount: 1,
      attachmentCount: 0,
      attachmentBytes: 0,
      resumePhase: null
    })
    expect(JSON.stringify(preview)).not.toContain(outputPath)
    expect(JSON.stringify(preview)).not.toContain(BACKUP_PASSWORD)
    expect(JSON.stringify(preview)).not.toContain('sample-secret')
    if (preview.canceled) throw new Error('expected native restore session')
    await expect(
      service.runNativeRestore(8, preview.sessionId, MASTER_PASSWORD, vi.fn())
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    const progress = vi.fn()
    await expect(
      service.runNativeRestore(7, preview.sessionId, MASTER_PASSWORD, progress)
    ).resolves.toMatchObject({ state: 'complete', summary: { phase: 'complete' } })
    expect(vault.verifyPortabilityOwner).toHaveBeenLastCalledWith(MASTER_PASSWORD)
    expect(vault.beginNativeAttachmentRestore).toHaveBeenCalledWith(
      expect.objectContaining({ archiveFingerprint: expect.any(String) }),
      MASTER_PASSWORD
    )
    expect(progress).toHaveBeenCalledWith(
      expect.objectContaining({ phase: 'complete' }),
      'complete'
    )
    await service.clearCompletedNativeRestore(7, preview.sessionId)
    expect(vault.clearCompletedNativeAttachmentRestore).toHaveBeenCalledWith(expect.any(String))
  })

  it('replaces and cancels native restore sessions without mutating the durable journal', async () => {
    const { outputPath, picker, service, vault } = await harness()
    await service.exportVault({
      masterPassword: MASTER_PASSWORD,
      password: BACKUP_PASSWORD,
      format: 'bearwarden-native'
    })
    vi.mocked(picker.chooseImportPath).mockResolvedValue(outputPath)
    const first = await service.previewNativeRestore(7, BACKUP_PASSWORD)
    const second = await service.previewNativeRestore(7, BACKUP_PASSWORD)
    if (first.canceled || second.canceled) throw new Error('expected native restore sessions')
    await expect(
      service.runNativeRestore(7, first.sessionId, MASTER_PASSWORD, vi.fn())
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await service.cancelNativeRestore(7, second.sessionId)
    expect(vault.beginNativeAttachmentRestore).not.toHaveBeenCalled()
    expect(vault.clearCompletedNativeAttachmentRestore).not.toHaveBeenCalled()
    await expect(
      service.runNativeRestore(7, second.sessionId, MASTER_PASSWORD, vi.fn())
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('expires only an unused native restore capability and never aborts an active restore', async () => {
    let clock = Date.parse('2026-07-16T03:04:05.000Z')
    const { outputPath, picker, service, vault } = await harness({
      now: () => new Date(clock)
    })
    await service.exportVault({
      masterPassword: MASTER_PASSWORD,
      password: BACKUP_PASSWORD,
      format: 'bearwarden-native'
    })
    vi.mocked(picker.chooseImportPath).mockResolvedValue(outputPath)
    const expired = await service.previewNativeRestore(7, BACKUP_PASSWORD)
    if (expired.canceled) throw new Error('expected native restore session')
    clock += 5 * 60 * 1_000 + 1
    await expect(
      service.runNativeRestore(7, expired.sessionId, MASTER_PASSWORD, vi.fn())
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })

    const active = await service.previewNativeRestore(7, BACKUP_PASSWORD)
    if (active.canceled) throw new Error('expected native restore session')
    vault.verifyPortabilityOwner.mockImplementationOnce(async () => {
      clock += 30 * 60 * 1_000
    })
    await expect(
      service.runNativeRestore(7, active.sessionId, MASTER_PASSWORD, vi.fn())
    ).resolves.toMatchObject({ state: 'complete' })
  })

  it('streams a verified attachment and retries once only after authoritative missing reconciliation', async () => {
    const { outputPath, picker, service, vault } = await harness()
    const snapshot = portableSnapshot()
    const bytes = Buffer.from('verified native attachment')
    const entry = {
      id: 'archive-attachment-1',
      itemId: snapshot.items[0]!.id,
      fileName: 'verified.txt',
      size: bytes.length
    }
    vault.createNativeAttachmentBackupSource.mockResolvedValueOnce({
      vaultJson: buildBitwardenJson(snapshot),
      attachments: [entry],
      exportedFolders: 1,
      exportedItems: 1,
      skippedTrashItems: 0,
      openAttachment: async function* () {
        yield Buffer.from(bytes)
      },
      dispose: vi.fn()
    })
    const restoring = {
      phase: 'restoring-attachments' as const,
      totalItems: 1,
      mappedItems: 1,
      totalAttachments: 1,
      uploadedAttachments: 0,
      needsReconciliationAttachments: 0,
      totalBytes: bytes.length,
      completedBytes: 0
    }
    const needs = {
      ...restoring,
      phase: 'needs-reconciliation' as const,
      needsReconciliationAttachments: 1
    }
    const complete = {
      ...restoring,
      phase: 'complete' as const,
      uploadedAttachments: 1,
      completedBytes: bytes.length
    }
    vault.beginNativeAttachmentRestore.mockResolvedValueOnce({
      ...restoring,
      phase: 'syncing-items',
      mappedItems: 0
    })
    vault.syncNativeAttachmentRestoreItems.mockResolvedValueOnce(restoring)
    vault.nativeAttachmentRestoreStatus.mockResolvedValueOnce(null).mockResolvedValueOnce(needs)
    let uploadAttempt = 0
    vault.uploadNativeAttachmentRestoreEntry.mockImplementation(
      async (_fingerprint, _key, source) => {
        uploadAttempt += 1
        const chunks: Buffer[] = []
        for await (const chunk of source.chunks()) chunks.push(Buffer.from(chunk))
        expect(Buffer.concat(chunks)).toEqual(bytes)
        if (uploadAttempt === 1) throw new Error('response unknown')
        return complete
      }
    )
    vault.reconcileNativeAttachmentRestoreEntry.mockResolvedValueOnce({
      outcome: 'missing',
      summary: restoring
    })
    await service.exportVault({
      masterPassword: MASTER_PASSWORD,
      password: BACKUP_PASSWORD,
      format: 'bearwarden-native'
    })
    vi.mocked(picker.chooseImportPath).mockResolvedValue(outputPath)
    const preview = await service.previewNativeRestore(7, BACKUP_PASSWORD)
    if (preview.canceled) throw new Error('expected native restore session')
    await expect(
      service.runNativeRestore(7, preview.sessionId, MASTER_PASSWORD, vi.fn())
    ).resolves.toEqual({ state: 'complete', summary: complete })
    expect(vault.uploadNativeAttachmentRestoreEntry).toHaveBeenCalledTimes(2)
    expect(vault.reconcileNativeAttachmentRestoreEntry).toHaveBeenCalledOnce()
  })
})
