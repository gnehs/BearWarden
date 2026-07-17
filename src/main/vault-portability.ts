import { randomBytes, randomUUID } from 'node:crypto'
import { chmod, mkdir, open, rename, unlink } from 'node:fs/promises'
import { dirname } from 'node:path'
import type {
  VaultExportRequest,
  VaultExportResult,
  VaultImportRequest,
  VaultImportResult,
  NativeRestorePreviewResult,
  NativeRestoreRunResult,
  NativeRestoreSummary
} from '../shared/vault-contract'
import {
  buildBitwardenCsv,
  buildBitwardenJson,
  decryptBitwardenPasswordProtectedJson,
  encryptBitwardenPasswordProtectedJson,
  parseBitwardenJson,
  parseBitwardenOrChromiumCsv
} from './vault-portability-codec'
import { VaultError } from './vault-errors'
import {
  openNativeAttachmentBackup,
  writeNativeAttachmentBackup,
  type NativeAttachmentBackupReader
} from './native-attachment-backup'
import { writeBitwardenAttachmentZip } from './bitwarden-attachment-zip'
import type { VaultService } from './vault-service'

const MAX_PORTABLE_FILE_BYTES = 64 * 1024 * 1024
const MIN_EXPORT_PASSWORD_LENGTH = 12
const MAX_EXPORT_PASSWORD_LENGTH = 1_024
const NATIVE_RESTORE_SESSION_TTL_MS = 5 * 60 * 1_000

interface NativeRestoreSession {
  id: string
  ownerId: number
  generation: number
  expiresAt: number
  reader: NativeAttachmentBackupReader | null
  archiveFingerprint: string
  abort: AbortController
  timer: ReturnType<typeof setTimeout>
  running: boolean
}

export interface VaultPortabilityPicker {
  chooseExportPath: (defaultName: string) => Promise<string | null>
  chooseImportPath: () => Promise<string | null>
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exportFileName(now: Date): string {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new VaultError('INTERNAL_ERROR')
  }
  const stamp = now
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d{3}Z$/, 'Z')
    .replace('T', '_')
  return `bitwarden_encrypted_export_${stamp}.json`
}

function nativeExportFileName(now: Date): string {
  return exportFileName(now)
    .replace('bitwarden_encrypted_export_', 'bearwarden_backup_')
    .replace(/\.json$/, '.bwbackup')
}

function zipExportFileName(now: Date): string {
  return exportFileName(now)
    .replace('bitwarden_encrypted_export_', 'bitwarden_export_')
    .replace(/\.json$/, '.zip')
}

function csvExportFileName(now: Date): string {
  return exportFileName(now)
    .replace('bitwarden_encrypted_export_', 'bitwarden_export_')
    .replace(/\.json$/, '.csv')
}

export type DirectorySyncResult = 'confirmed' | 'unsupported' | 'unknown'

interface DirectoryHandle {
  sync: () => Promise<void>
  close: () => Promise<void>
}

function errorCode(error: unknown): string | null {
  return typeof error === 'object' && error !== null && 'code' in error
    ? String((error as { code?: unknown }).code)
    : null
}

function unsupportedDirectorySyncError(error: unknown, platform: NodeJS.Platform): boolean {
  const code = errorCode(error)
  if (code === 'EINVAL' || code === 'ENOTSUP' || code === 'EOPNOTSUPP' || code === 'ENOSYS') {
    return true
  }
  return platform === 'win32' && (code === 'EPERM' || code === 'EACCES')
}

export async function syncDirectory(
  path: string,
  options: {
    platform?: NodeJS.Platform
    openDirectory?: (path: string) => Promise<DirectoryHandle>
  } = {}
): Promise<DirectorySyncResult> {
  let handle: DirectoryHandle | undefined
  let result: DirectorySyncResult = 'confirmed'
  try {
    handle = await (options.openDirectory ?? (async (directory) => open(directory, 'r')))(path)
    await handle.sync()
  } catch (error) {
    result = unsupportedDirectorySyncError(error, options.platform ?? process.platform)
      ? 'unsupported'
      : 'unknown'
  } finally {
    try {
      await handle?.close()
    } catch {
      result = 'unknown'
    }
  }
  return result
}

export async function atomicWritePrivate(
  path: string,
  contents: string,
  directorySync: (path: string) => Promise<DirectorySyncResult> = syncDirectory
): Promise<{ durabilityWarning: boolean }> {
  const directory = dirname(path)
  await mkdir(directory, { recursive: true, mode: 0o700 })
  const temporaryPath = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`
  let handle: Awaited<ReturnType<typeof open>> | undefined
  try {
    handle = await open(temporaryPath, 'wx', 0o600)
    await handle.writeFile(contents, { encoding: 'utf8' })
    await handle.sync()
    await chmod(temporaryPath, 0o600)
    await handle.close()
    handle = undefined
    await rename(temporaryPath, path)
    let directorySyncResult: DirectorySyncResult = 'unknown'
    try {
      directorySyncResult = await directorySync(directory)
    } catch {
      // The file is already published; report uncertain durability instead of a false failure.
    }
    return { durabilityWarning: directorySyncResult === 'unknown' }
  } catch (error) {
    await handle?.close()
    await unlink(temporaryPath).catch(() => undefined)
    throw error
  }
}

async function readBoundedFile(path: string): Promise<string> {
  let handle: Awaited<ReturnType<typeof open>> | undefined
  let contents: Buffer | undefined
  try {
    handle = await open(path, 'r')
    const stats = await handle.stat()
    if (!stats.isFile() || stats.size <= 0 || stats.size > MAX_PORTABLE_FILE_BYTES) {
      throw new VaultError('INVALID_INPUT')
    }
    contents = await handle.readFile()
    if (contents.length === 0 || contents.length > MAX_PORTABLE_FILE_BYTES) {
      throw new VaultError('INVALID_INPUT')
    }
    return new TextDecoder('utf-8', { fatal: true }).decode(contents)
  } catch (error) {
    if (error instanceof VaultError) throw error
    throw new VaultError('INVALID_INPUT')
  } finally {
    contents?.fill(0)
    await handle?.close()
  }
}

function parseDocumentShape(text: string): Record<string, unknown> {
  try {
    const value = JSON.parse(text) as unknown
    if (!isRecord(value)) throw new Error('invalid document')
    return value
  } catch {
    throw new VaultError('INVALID_INPUT')
  }
}

function beginsWithJsonObject(text: string): boolean {
  let index = text.charCodeAt(0) === 0xfeff ? 1 : 0
  while (index < text.length && /\s/u.test(text[index]!)) index += 1
  return text[index] === '{'
}

export class VaultPortabilityService {
  private nativeRestoreSession: NativeRestoreSession | null = null

  constructor(
    private readonly vault: VaultService,
    private readonly picker: VaultPortabilityPicker,
    private readonly now: () => Date = () => new Date(),
    private readonly writePrivate: typeof atomicWritePrivate = atomicWritePrivate
  ) {}

  async previewNativeRestore(
    ownerId: number,
    password: string
  ): Promise<NativeRestorePreviewResult> {
    if (
      !Number.isSafeInteger(ownerId) ||
      ownerId < 0 ||
      typeof password !== 'string' ||
      password.length < MIN_EXPORT_PASSWORD_LENGTH ||
      password.length > MAX_EXPORT_PASSWORD_LENGTH
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    const generation = await this.vault.unlockedGeneration()
    const path = await this.picker.chooseImportPath()
    if (path === null) return { canceled: true }
    if (typeof path !== 'string' || path.length === 0) throw new VaultError('INTERNAL_ERROR')
    const abort = new AbortController()
    let reader: NativeAttachmentBackupReader | null = null
    try {
      reader = await openNativeAttachmentBackup(path, password, { signal: abort.signal })
      if ((await this.vault.unlockedGeneration()) !== generation) throw new VaultError('LOCKED')
      const parsed = parseBitwardenJson(reader.preview.vaultJson)
      if (parsed.skippedTrashItems !== 0) throw new VaultError('INVALID_INPUT')
      await this.disposeNativeRestoreSession()
      const id = randomUUID()
      const expiresAt = this.now().getTime() + NATIVE_RESTORE_SESSION_TTL_MS
      const session: NativeRestoreSession = {
        id,
        ownerId,
        generation,
        expiresAt,
        reader,
        archiveFingerprint: reader.preview.archiveFingerprint,
        abort,
        timer: setTimeout(() => undefined, NATIVE_RESTORE_SESSION_TTL_MS),
        running: false
      }
      this.scheduleNativeRestoreSessionExpiry(session)
      this.nativeRestoreSession = session
      reader = null
      return {
        canceled: false,
        sessionId: id,
        expiresAt,
        createdAt: session.reader!.preview.createdAt,
        folderCount: parsed.snapshot.folders.length,
        itemCount: parsed.snapshot.items.length,
        attachmentCount: session.reader!.preview.attachments.length,
        attachmentBytes: session.reader!.preview.attachmentBytes,
        resumePhase: null
      }
    } finally {
      password = ''
      if (reader) await reader.dispose().catch(() => undefined)
    }
  }

  async runNativeRestore(
    ownerId: number,
    sessionId: string,
    masterPassword: string,
    onProgress: (
      summary: NativeRestoreSummary,
      state: 'running' | 'partial' | 'conflict' | 'complete'
    ) => void
  ): Promise<NativeRestoreRunResult> {
    const session = await this.requireNativeRestoreSession(ownerId, sessionId)
    if (session.running || !session.reader) throw new VaultError('INVALID_INPUT')
    clearTimeout(session.timer)
    session.running = true
    try {
      await this.vault.verifyPortabilityOwner(masterPassword)
      let summary = await this.vault.nativeAttachmentRestoreStatus()
      if (summary === null) {
        summary = await this.vault.beginNativeAttachmentRestore(
          session.reader.preview,
          masterPassword
        )
      }
      if (summary.phase === 'syncing-items') {
        summary = await this.vault.syncNativeAttachmentRestoreItems(session.archiveFingerprint)
      } else {
        // Revalidates both the selected archive fingerprint and the active sync account.
        summary = await this.vault.syncNativeAttachmentRestoreItems(session.archiveFingerprint)
      }
      onProgress(summary, summary.phase === 'complete' ? 'complete' : 'running')
      const retried = new Set<number>()
      while (summary.uploadedAttachments < summary.totalAttachments) {
        this.assertNativeRestoreSessionCurrent(session)
        const index = summary.uploadedAttachments
        const entry = session.reader.preview.attachments[index]
        if (!entry) throw new VaultError('INVALID_INPUT')
        const key = { sourceItemId: entry.itemId, sourceAttachmentId: entry.id }
        if (summary.phase === 'needs-reconciliation') {
          const reconciled = await this.vault.reconcileNativeAttachmentRestoreEntry(
            session.archiveFingerprint,
            key
          )
          summary = reconciled.summary
          if (reconciled.outcome === 'conflict') {
            onProgress(summary, 'conflict')
            return { state: 'conflict', summary }
          }
          if (reconciled.outcome === 'uploaded') {
            onProgress(summary, summary.phase === 'complete' ? 'complete' : 'running')
            continue
          }
          if (retried.has(index)) {
            onProgress(summary, 'partial')
            return { state: 'partial', summary }
          }
          retried.add(index)
        }
        try {
          summary = await this.vault.uploadNativeAttachmentRestoreEntry(
            session.archiveFingerprint,
            key,
            {
              size: entry.size,
              chunks: (signal) =>
                session.reader!.openAttachment(
                  entry,
                  signal ? AbortSignal.any([session.abort.signal, signal]) : session.abort.signal
                )
            }
          )
          onProgress(summary, summary.phase === 'complete' ? 'complete' : 'running')
        } catch (error) {
          if (session.abort.signal.aborted) throw new VaultError('ATTACHMENT_CANCELED')
          summary = (await this.vault.nativeAttachmentRestoreStatus()) ?? summary
          if (summary.phase !== 'needs-reconciliation') throw error
        }
      }
      await session.reader.dispose()
      session.reader = null
      return { state: 'complete', summary }
    } finally {
      masterPassword = ''
      session.running = false
      if (this.nativeRestoreSession === session) {
        session.expiresAt = this.now().getTime() + NATIVE_RESTORE_SESSION_TTL_MS
        this.scheduleNativeRestoreSessionExpiry(session)
      }
    }
  }

  async cancelNativeRestore(ownerId: number, sessionId: string): Promise<void> {
    const session = await this.requireNativeRestoreSession(ownerId, sessionId)
    session.abort.abort()
    await this.disposeNativeRestoreSession()
  }

  async clearCompletedNativeRestore(ownerId: number, sessionId: string): Promise<void> {
    const session = await this.requireNativeRestoreSession(ownerId, sessionId)
    await this.vault.clearCompletedNativeAttachmentRestore(session.archiveFingerprint)
    await this.disposeNativeRestoreSession()
  }

  async disposeNativeRestoreSession(): Promise<void> {
    const session = this.nativeRestoreSession
    if (!session) return
    this.nativeRestoreSession = null
    clearTimeout(session.timer)
    session.abort.abort()
    await session.reader?.dispose().catch(() => undefined)
    session.reader = null
  }

  private async requireNativeRestoreSession(
    ownerId: number,
    sessionId: string
  ): Promise<NativeRestoreSession> {
    const session = this.nativeRestoreSession
    if (
      !session ||
      session.id !== sessionId ||
      session.ownerId !== ownerId ||
      session.expiresAt <= this.now().getTime()
    ) {
      if (session?.expiresAt && session.expiresAt <= this.now().getTime()) {
        await this.disposeNativeRestoreSession()
      }
      throw new VaultError('INVALID_INPUT')
    }
    if ((await this.vault.unlockedGeneration()) !== session.generation) {
      await this.disposeNativeRestoreSession()
      throw new VaultError('LOCKED')
    }
    this.assertNativeRestoreSessionCurrent(session)
    return session
  }

  private assertNativeRestoreSessionCurrent(session: NativeRestoreSession): void {
    if (session.abort.signal.aborted) throw new VaultError('ATTACHMENT_CANCELED')
    // Async generation checks are performed at every service boundary; this catches local expiry.
    if (!session.running && session.expiresAt <= this.now().getTime()) {
      throw new VaultError('INVALID_INPUT')
    }
  }

  private scheduleNativeRestoreSessionExpiry(session: NativeRestoreSession): void {
    clearTimeout(session.timer)
    session.timer = setTimeout(
      () => {
        if (this.nativeRestoreSession === session && !session.running) {
          void this.disposeNativeRestoreSession()
        }
      },
      Math.max(0, session.expiresAt - this.now().getTime())
    )
    session.timer.unref?.()
  }

  async exportVault(request: VaultExportRequest): Promise<VaultExportResult> {
    try {
      if (!request || typeof request.masterPassword !== 'string') {
        throw new VaultError('INVALID_INPUT')
      }
      const format = request.format ?? 'bitwarden-json'
      if (
        format !== 'bitwarden-json' &&
        format !== 'bitwarden-csv' &&
        format !== 'bitwarden-zip' &&
        format !== 'bearwarden-native'
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      if (
        ((format === 'bitwarden-csv' || format === 'bitwarden-zip') &&
          request.password !== undefined) ||
        (format !== 'bitwarden-csv' &&
          format !== 'bitwarden-zip' &&
          (typeof request.password !== 'string' ||
            request.password.length < MIN_EXPORT_PASSWORD_LENGTH ||
            request.password.length > MAX_EXPORT_PASSWORD_LENGTH))
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const exportPassword =
        format === 'bitwarden-csv' || format === 'bitwarden-zip' ? undefined : request.password
      await this.vault.verifyPortabilityOwner(request.masterPassword)
      const path = await this.picker.chooseExportPath(
        format === 'bearwarden-native'
          ? nativeExportFileName(this.now())
          : format === 'bitwarden-zip'
            ? zipExportFileName(this.now())
            : format === 'bitwarden-csv'
              ? csvExportFileName(this.now())
              : exportFileName(this.now())
      )
      if (path === null) {
        return { canceled: true, exportedFolders: 0, exportedItems: 0, skippedTrashItems: 0 }
      }
      if (typeof path !== 'string' || path.length === 0) throw new VaultError('INTERNAL_ERROR')

      if (format === 'bitwarden-zip') {
        const source = await this.vault.createNativeAttachmentBackupSource(request.masterPassword, {
          includeLoginWireMetadata: false
        })
        try {
          const result = await writeBitwardenAttachmentZip(path, source)
          return {
            canceled: false,
            exportedFolders: source.exportedFolders,
            exportedItems: source.exportedItems,
            skippedTrashItems: source.skippedTrashItems,
            attachmentCount: result.attachmentCount,
            attachmentBytes: result.attachmentBytes
          }
        } finally {
          source.dispose()
        }
      }

      if (format === 'bitwarden-csv') {
        const exported = await this.vault.exportPortableSnapshot(request.masterPassword)
        const csv = buildBitwardenCsv(exported.snapshot)
        const published = await this.writePrivate(path, csv.csv)
        return {
          canceled: false,
          exportedFolders: csv.exportedFolders,
          exportedItems: csv.exportedItems,
          skippedTrashItems: exported.skippedTrashItems,
          skippedUnsupportedItems: csv.skippedUnsupportedItems,
          skippedCards: csv.skippedCards,
          skippedIdentities: csv.skippedIdentities,
          skippedSshKeys: csv.skippedSshKeys,
          skippedPasskeys: csv.skippedPasskeys,
          skippedAttachments: csv.skippedAttachments,
          skippedPasswordHistoryEntries: csv.skippedPasswordHistoryEntries,
          simplifiedUriMatches: csv.simplifiedUriMatches,
          skippedPasswordRevisionDates: csv.skippedPasswordRevisionDates,
          skippedAutofillSettings: csv.skippedAutofillSettings,
          simplifiedCustomFieldTypes: csv.simplifiedCustomFieldTypes,
          riskyCustomFields: csv.riskyCustomFields,
          emptyCustomFieldNames: csv.emptyCustomFieldNames,
          multilineCustomFields: csv.multilineCustomFields,
          colonValueCustomFields: csv.colonValueCustomFields,
          ...(published.durabilityWarning ? { durabilityWarning: true as const } : {})
        }
      }

      if (exportPassword === undefined) throw new VaultError('INTERNAL_ERROR')
      if (format === 'bearwarden-native') {
        const source = await this.vault.createNativeAttachmentBackupSource(request.masterPassword, {
          includeLoginWireMetadata: true
        })
        try {
          const result = await writeNativeAttachmentBackup(path, exportPassword, source)
          return {
            canceled: false,
            exportedFolders: source.exportedFolders,
            exportedItems: source.exportedItems,
            skippedTrashItems: source.skippedTrashItems,
            attachmentCount: result.attachmentCount,
            attachmentBytes: result.attachmentBytes,
            resumed: result.resumed
          }
        } finally {
          source.dispose()
        }
      }

      const exported = await this.vault.exportPortableSnapshot(request.masterPassword)
      const clearText = buildBitwardenJson(exported.snapshot)
      const encrypted = await encryptBitwardenPasswordProtectedJson(clearText, exportPassword)
      const published = await this.writePrivate(path, `${encrypted}\n`)
      return {
        canceled: false,
        exportedFolders: exported.snapshot.folders.length,
        exportedItems: exported.snapshot.items.length,
        skippedTrashItems: exported.skippedTrashItems,
        ...(published.durabilityWarning ? { durabilityWarning: true as const } : {})
      }
    } finally {
      if (request && typeof request === 'object') {
        try {
          request.masterPassword = ''
          if ('password' in request && typeof request.password === 'string') request.password = ''
        } catch {
          // A frozen/exotic direct caller must not replace the intended export result or error.
        }
      }
    }
  }

  async importVault(request: VaultImportRequest): Promise<VaultImportResult> {
    if (
      !request ||
      typeof request.masterPassword !== 'string' ||
      (request.password !== undefined &&
        (typeof request.password !== 'string' ||
          request.password.length === 0 ||
          request.password.length > MAX_EXPORT_PASSWORD_LENGTH))
    ) {
      throw new VaultError('INVALID_INPUT')
    }

    await this.vault.verifyPortabilityOwner(request.masterPassword)
    const path = await this.picker.chooseImportPath()
    if (path === null) {
      return { canceled: true, importedFolders: 0, importedItems: 0, skippedTrashItems: 0 }
    }
    if (typeof path !== 'string' || path.length === 0) throw new VaultError('INTERNAL_ERROR')

    const document = await readBoundedFile(path)
    let parsed: ReturnType<typeof parseBitwardenJson>
    if (beginsWithJsonObject(document)) {
      const shape = parseDocumentShape(document)
      let clearText = document
      if (shape.encrypted === true) {
        if (shape.passwordProtected !== true || request.password === undefined) {
          throw new VaultError('INVALID_INPUT')
        }
        clearText = await decryptBitwardenPasswordProtectedJson(document, request.password)
      }
      parsed = parseBitwardenJson(clearText)
    } else {
      if (request.password !== undefined) throw new VaultError('INVALID_INPUT')
      parsed = parseBitwardenOrChromiumCsv(document)
    }
    const imported = await this.vault.importPortableSnapshot(
      parsed.snapshot,
      parsed.skippedTrashItems,
      request.masterPassword
    )
    return { canceled: false, ...imported }
  }
}
