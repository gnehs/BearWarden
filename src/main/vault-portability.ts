import { randomBytes } from 'node:crypto'
import { chmod, mkdir, open, rename, unlink } from 'node:fs/promises'
import { dirname } from 'node:path'
import type {
  VaultExportRequest,
  VaultExportResult,
  VaultImportRequest,
  VaultImportResult
} from '../shared/vault-contract'
import {
  buildBitwardenJson,
  decryptBitwardenPasswordProtectedJson,
  encryptBitwardenPasswordProtectedJson,
  parseBitwardenJson
} from './vault-portability-codec'
import { VaultError } from './vault-errors'
import type { VaultService } from './vault-service'

const MAX_PORTABLE_FILE_BYTES = 64 * 1024 * 1024
const MIN_EXPORT_PASSWORD_LENGTH = 12
const MAX_EXPORT_PASSWORD_LENGTH = 1_024

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

async function syncDirectory(path: string): Promise<void> {
  let handle: Awaited<ReturnType<typeof open>> | undefined
  try {
    handle = await open(path, 'r')
    await handle.sync()
  } catch {
    // Directory fsync is not supported on every Electron target, notably Windows.
  } finally {
    await handle?.close()
  }
}

async function atomicWritePrivate(path: string, contents: string): Promise<void> {
  const directory = dirname(path)
  await mkdir(directory, { recursive: true, mode: 0o700 })
  const temporaryPath = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`
  let handle: Awaited<ReturnType<typeof open>> | undefined
  try {
    handle = await open(temporaryPath, 'wx', 0o600)
    await handle.writeFile(contents, { encoding: 'utf8' })
    await handle.sync()
    await handle.close()
    handle = undefined
    await rename(temporaryPath, path)
    await chmod(path, 0o600)
    await syncDirectory(directory)
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

export class VaultPortabilityService {
  constructor(
    private readonly vault: VaultService,
    private readonly picker: VaultPortabilityPicker,
    private readonly now: () => Date = () => new Date()
  ) {}

  async exportVault(request: VaultExportRequest): Promise<VaultExportResult> {
    if (
      !request ||
      typeof request.masterPassword !== 'string' ||
      typeof request.password !== 'string' ||
      request.password.length < MIN_EXPORT_PASSWORD_LENGTH ||
      request.password.length > MAX_EXPORT_PASSWORD_LENGTH
    ) {
      throw new VaultError('INVALID_INPUT')
    }

    await this.vault.verifyPortabilityOwner(request.masterPassword)
    const path = await this.picker.chooseExportPath(exportFileName(this.now()))
    if (path === null) {
      return { canceled: true, exportedFolders: 0, exportedItems: 0, skippedTrashItems: 0 }
    }
    if (typeof path !== 'string' || path.length === 0) throw new VaultError('INTERNAL_ERROR')

    const exported = await this.vault.exportPortableSnapshot(request.masterPassword)
    const clearText = buildBitwardenJson(exported.snapshot)
    const encrypted = await encryptBitwardenPasswordProtectedJson(clearText, request.password)
    await atomicWritePrivate(path, `${encrypted}\n`)
    return {
      canceled: false,
      exportedFolders: exported.snapshot.folders.length,
      exportedItems: exported.snapshot.items.length,
      skippedTrashItems: exported.skippedTrashItems
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
    const shape = parseDocumentShape(document)
    let clearText = document
    if (shape.encrypted === true) {
      if (shape.passwordProtected !== true || request.password === undefined) {
        throw new VaultError('INVALID_INPUT')
      }
      clearText = await decryptBitwardenPasswordProtectedJson(document, request.password)
    }
    const parsed = parseBitwardenJson(clearText)
    const imported = await this.vault.importPortableSnapshot(
      parsed.snapshot,
      parsed.skippedTrashItems,
      request.masterPassword
    )
    return { canceled: false, ...imported }
  }
}
