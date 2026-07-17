import { randomBytes } from 'node:crypto'
import { constants } from 'node:fs'
import { chmod, mkdir, open, rename, unlink } from 'node:fs/promises'
import { dirname, isAbsolute } from 'node:path'
import { crc32 } from 'node:zlib'
import { MAX_STREAMED_ATTACHMENT_PLAINTEXT_BYTES } from './bitwarden-attachment-stream'
import type {
  NativeAttachmentBackupEntry,
  NativeAttachmentBackupSource
} from './native-attachment-backup'
import { VaultError } from './vault-errors'

const MAX_ATTACHMENTS = 100_000
const MAX_JSON_BYTES = 64 * 1024 * 1024
const MAX_NAME_LENGTH = 100_000
const MAX_ZIP_ENTRY_NAME_BYTES = 65_535
const UINT16_MAX = 0xffff
const UINT32_MAX = 0xffffffff
const ZIP_UTF8_DATA_DESCRIPTOR_FLAGS = 0x0808
const ZIP_VERSION_DEFAULT = 20
const ZIP_VERSION_ZIP64 = 45
const ZIP_DOS_DATE_1980_01_01 = 0x0021

export interface BitwardenAttachmentZipResult {
  /** Path to the completed plaintext ZIP. The caller must store it securely. */
  path: string
  attachmentCount: number
  attachmentBytes: number
}

function invalidInput(): never {
  throw new VaultError('INVALID_INPUT')
}

function attachmentFailed(): never {
  throw new VaultError('ATTACHMENT_FAILED')
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new VaultError('ATTACHMENT_CANCELED')
}

function validatePath(path: string): void {
  if (typeof path !== 'string' || path.length === 0 || !isAbsolute(path) || path.includes('\0')) {
    invalidInput()
  }
}

function validateSource(source: NativeAttachmentBackupSource): NativeAttachmentBackupEntry[] {
  if (
    !source ||
    typeof source.vaultJson !== 'string' ||
    Buffer.byteLength(source.vaultJson, 'utf8') > MAX_JSON_BYTES ||
    !Array.isArray(source.attachments) ||
    source.attachments.length > MAX_ATTACHMENTS ||
    typeof source.openAttachment !== 'function'
  ) {
    invalidInput()
  }
  const identities = new Set<string>()
  return source.attachments.map((entry) => {
    if (
      !entry ||
      typeof entry.id !== 'string' ||
      entry.id.length === 0 ||
      entry.id.length > MAX_NAME_LENGTH ||
      typeof entry.itemId !== 'string' ||
      entry.itemId.length === 0 ||
      entry.itemId.length > MAX_NAME_LENGTH ||
      typeof entry.fileName !== 'string' ||
      entry.fileName.length === 0 ||
      entry.fileName.length > MAX_NAME_LENGTH ||
      !Number.isSafeInteger(entry.size) ||
      entry.size < 0 ||
      entry.size > MAX_STREAMED_ATTACHMENT_PLAINTEXT_BYTES
    ) {
      invalidInput()
    }
    const identity = `${entry.itemId}\0${entry.id}`
    if (identities.has(identity)) invalidInput()
    identities.add(identity)
    return { ...entry }
  })
}

function itemNamesById(vaultJson: string): Map<string, string> {
  let parsed: unknown
  try {
    parsed = JSON.parse(vaultJson)
  } catch {
    invalidInput()
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) invalidInput()
  const items = (parsed as Record<string, unknown>).items
  if (!Array.isArray(items)) invalidInput()
  const names = new Map<string, string>()
  for (const item of items) {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) invalidInput()
    const { id, name } = item as Record<string, unknown>
    if (
      typeof id !== 'string' ||
      id.length === 0 ||
      id.length > MAX_NAME_LENGTH ||
      typeof name !== 'string' ||
      name.length === 0 ||
      name.length > MAX_NAME_LENGTH ||
      names.has(id)
    ) {
      invalidInput()
    }
    names.set(id, name)
  }
  return names
}

function replaceDisallowed(value: string, includeDot: boolean): string {
  const disallowed = includeDot ? '/\\><:"|?*.' : '/\\><:"|?*'
  return Array.from(value, (character) => {
    const codePoint = character.codePointAt(0)!
    return codePoint <= 0x1f || codePoint === 0x7f || disallowed.includes(character)
      ? '_'
      : character
  }).join('')
}

function sanitizeItemName(value: string): string {
  const sanitized = replaceDisallowed(value.normalize('NFC'), false).replace(/__+/gu, '_')
  return sanitized.length === 0 || sanitized === '.' || sanitized === '..' ? 'item' : sanitized
}

function attachmentNameParts(value: string): { stem: string; suffix: string } {
  const normalized = value.normalize('NFC')
  const parts = normalized.split('.')
  let stem = normalized
  let suffix = ''
  if (parts.length > 1) {
    stem = parts.slice(0, -1).join('')
    suffix = `.${parts.at(-1)!}`
  }
  stem = replaceDisallowed(stem, true).replace(/__+/gu, '_')
  suffix = replaceDisallowed(suffix, false)
  if (stem.length === 0) stem = 'attachment'
  return { stem, suffix }
}

function canonicalEntryName(value: string): string {
  // ZIP names are case-sensitive, but common Windows/macOS extraction targets are not. Windows
  // also discards trailing spaces and periods, so reserve their effective spelling as well.
  return value
    .normalize('NFC')
    .toLowerCase()
    .replace(/[ .]+$/gu, '')
}

function assertZipEntryName(value: string): void {
  if (Buffer.byteLength(value, 'utf8') > MAX_ZIP_ENTRY_NAME_BYTES) invalidInput()
}

function uniqueName(
  base: string,
  suffix: string,
  preferredIndex: number,
  used: Set<string>
): string {
  let index = preferredIndex
  while (true) {
    const candidate = `${base}${index === 0 ? '' : `_${index}`}${suffix}`
    const canonical = canonicalEntryName(candidate)
    if (!used.has(canonical)) {
      used.add(canonical)
      return candidate
    }
    index += 1
  }
}

function attachmentPaths(
  attachments: readonly NativeAttachmentBackupEntry[],
  names: ReadonlyMap<string, string>
): { foldersByItemId: ReadonlyMap<string, string>; paths: string[] } {
  const rawItemCounts = new Map<string, number>()
  const usedFolders = new Set<string>()
  const foldersByItemId = new Map<string, string>()
  const usedNamesByItemId = new Map<string, Set<string>>()
  const paths: string[] = []

  const itemIdsWithAttachments = new Set(attachments.map((attachment) => attachment.itemId))
  for (const [itemId, rawName] of names) {
    if (!itemIdsWithAttachments.has(itemId)) continue
    const normalizedRawName = rawName.normalize('NFC')
    const preferredIndex = rawItemCounts.get(normalizedRawName) ?? 0
    rawItemCounts.set(normalizedRawName, preferredIndex + 1)
    const folder = uniqueName(sanitizeItemName(rawName), '', preferredIndex, usedFolders)
    foldersByItemId.set(itemId, folder)
    usedNamesByItemId.set(itemId, new Set())
  }
  if (foldersByItemId.size !== itemIdsWithAttachments.size) invalidInput()

  for (const attachment of attachments) {
    const folder = foldersByItemId.get(attachment.itemId)
    if (folder === undefined) invalidInput()
    const { stem, suffix } = attachmentNameParts(attachment.fileName)
    const fileName = uniqueName(stem, suffix, 0, usedNamesByItemId.get(attachment.itemId)!)
    const path = `attachments/${folder}/${fileName}`
    assertZipEntryName(path)
    paths.push(path)
  }
  for (const folder of foldersByItemId.values()) assertZipEntryName(`attachments/${folder}/`)
  return { foldersByItemId, paths }
}

async function writeAll(
  handle: Awaited<ReturnType<typeof open>>,
  bytes: Uint8Array,
  position: number
): Promise<number> {
  let offset = 0
  while (offset < bytes.byteLength) {
    const { bytesWritten } = await handle.write(
      bytes,
      offset,
      bytes.byteLength - offset,
      position + offset
    )
    if (bytesWritten === 0) throw new Error('ZIP temporary file write stalled')
    offset += bytesWritten
  }
  return position + bytes.byteLength
}

function emptyChunks(): AsyncIterable<Buffer> {
  return {
    [Symbol.asyncIterator]() {
      return {
        async next() {
          return { done: true, value: undefined }
        }
      }
    }
  }
}

interface CentralDirectoryEntry {
  name: string
  size: number
  crc: number
  offset: number
  directory: boolean
}

interface ZipWriteState {
  handle: Awaited<ReturnType<typeof open>>
  position: number
  entries: CentralDirectoryEntry[]
}

function localHeader(nameBytes: Buffer, directory: boolean): Buffer {
  const header = Buffer.alloc(30 + nameBytes.length)
  header.writeUInt32LE(0x04034b50, 0)
  header.writeUInt16LE(ZIP_VERSION_DEFAULT, 4)
  header.writeUInt16LE(ZIP_UTF8_DATA_DESCRIPTOR_FLAGS, 6)
  header.writeUInt16LE(0, 8)
  header.writeUInt16LE(0, 10)
  header.writeUInt16LE(ZIP_DOS_DATE_1980_01_01, 12)
  header.writeUInt16LE(0, 14)
  header.writeUInt32LE(0, 18)
  header.writeUInt32LE(0, 22)
  header.writeUInt16LE(nameBytes.length, 26)
  header.writeUInt16LE(0, 28)
  nameBytes.copy(header, 30)
  if (directory) header.writeUInt32LE(0, 14)
  return header
}

function dataDescriptor(checksum: number, size: number): Buffer {
  const descriptor = Buffer.alloc(16)
  descriptor.writeUInt32LE(0x08074b50, 0)
  descriptor.writeUInt32LE(checksum, 4)
  descriptor.writeUInt32LE(size, 8)
  descriptor.writeUInt32LE(size, 12)
  return descriptor
}

async function appendBytes(state: ZipWriteState, bytes: Uint8Array): Promise<void> {
  state.position = await writeAll(state.handle, bytes, state.position)
}

async function appendStoredEntry(
  state: ZipWriteState,
  name: string,
  expectedSize: number,
  chunks: AsyncIterable<Buffer>,
  signal: AbortSignal | undefined,
  directory = false
): Promise<void> {
  const nameBytes = Buffer.from(name, 'utf8')
  const offset = state.position
  await appendBytes(state, localHeader(nameBytes, directory))
  const iterator = chunks[Symbol.asyncIterator]()
  let size = 0
  let checksum = 0
  try {
    while (true) {
      throwIfAborted(signal)
      const next = await iterator.next()
      if (next.done) break
      if (!Buffer.isBuffer(next.value)) attachmentFailed()
      const chunk = next.value
      try {
        size += chunk.length
        if (!Number.isSafeInteger(size) || size > expectedSize) attachmentFailed()
        checksum = crc32(chunk, checksum)
        await appendBytes(state, chunk)
      } finally {
        chunk.fill(0)
      }
    }
  } catch (error) {
    if (error instanceof VaultError) throw error
    attachmentFailed()
  } finally {
    await iterator.return?.().catch(() => undefined)
  }
  if (size !== expectedSize) attachmentFailed()
  await appendBytes(state, dataDescriptor(checksum, size))
  state.entries.push({ name, size, crc: checksum, offset, directory })
}

function zip64Extra(offset: number): Buffer {
  const extra = Buffer.alloc(12)
  extra.writeUInt16LE(0x0001, 0)
  extra.writeUInt16LE(8, 2)
  extra.writeBigUInt64LE(BigInt(offset), 4)
  return extra
}

function centralDirectoryRecord(entry: CentralDirectoryEntry): Buffer {
  const name = Buffer.from(entry.name, 'utf8')
  const needsZip64Offset = entry.offset >= UINT32_MAX
  const extra = needsZip64Offset ? zip64Extra(entry.offset) : Buffer.alloc(0)
  const header = Buffer.alloc(46 + name.length + extra.length)
  header.writeUInt32LE(0x02014b50, 0)
  header.writeUInt16LE(0x031e, 4)
  header.writeUInt16LE(needsZip64Offset ? ZIP_VERSION_ZIP64 : ZIP_VERSION_DEFAULT, 6)
  header.writeUInt16LE(ZIP_UTF8_DATA_DESCRIPTOR_FLAGS, 8)
  header.writeUInt16LE(0, 10)
  header.writeUInt16LE(0, 12)
  header.writeUInt16LE(ZIP_DOS_DATE_1980_01_01, 14)
  header.writeUInt32LE(entry.crc, 16)
  header.writeUInt32LE(entry.size, 20)
  header.writeUInt32LE(entry.size, 24)
  header.writeUInt16LE(name.length, 28)
  header.writeUInt16LE(extra.length, 30)
  header.writeUInt16LE(0, 32)
  header.writeUInt16LE(0, 34)
  header.writeUInt16LE(0, 36)
  header.writeUInt32LE(entry.directory ? 0x10 : 0, 38)
  header.writeUInt32LE(needsZip64Offset ? UINT32_MAX : entry.offset, 42)
  name.copy(header, 46)
  extra.copy(header, 46 + name.length)
  return header
}

function zip64EndRecord(entryCount: number, centralSize: number, centralOffset: number): Buffer {
  const record = Buffer.alloc(56)
  record.writeUInt32LE(0x06064b50, 0)
  record.writeBigUInt64LE(44n, 4)
  record.writeUInt16LE(0x031e, 12)
  record.writeUInt16LE(ZIP_VERSION_ZIP64, 14)
  record.writeBigUInt64LE(BigInt(entryCount), 24)
  record.writeBigUInt64LE(BigInt(entryCount), 32)
  record.writeBigUInt64LE(BigInt(centralSize), 40)
  record.writeBigUInt64LE(BigInt(centralOffset), 48)
  return record
}

function zip64Locator(zip64Offset: number): Buffer {
  const locator = Buffer.alloc(20)
  locator.writeUInt32LE(0x07064b50, 0)
  locator.writeBigUInt64LE(BigInt(zip64Offset), 8)
  locator.writeUInt32LE(1, 16)
  return locator
}

function endRecord(entryCount: number, centralSize: number, centralOffset: number): Buffer {
  const record = Buffer.alloc(22)
  record.writeUInt32LE(0x06054b50, 0)
  record.writeUInt16LE(Math.min(entryCount, UINT16_MAX), 8)
  record.writeUInt16LE(Math.min(entryCount, UINT16_MAX), 10)
  record.writeUInt32LE(Math.min(centralSize, UINT32_MAX), 12)
  record.writeUInt32LE(Math.min(centralOffset, UINT32_MAX), 16)
  return record
}

async function finishArchive(state: ZipWriteState): Promise<void> {
  const centralOffset = state.position
  for (const entry of state.entries) await appendBytes(state, centralDirectoryRecord(entry))
  const centralSize = state.position - centralOffset
  const needsZip64 =
    state.entries.length >= UINT16_MAX ||
    centralOffset >= UINT32_MAX ||
    centralSize >= UINT32_MAX ||
    state.entries.some((entry) => entry.offset >= UINT32_MAX)
  if (needsZip64) {
    const zip64Offset = state.position
    await appendBytes(state, zip64EndRecord(state.entries.length, centralSize, centralOffset))
    await appendBytes(state, zip64Locator(zip64Offset))
  }
  await appendBytes(state, endRecord(state.entries.length, centralSize, centralOffset))
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, 'r')
  try {
    await handle.sync()
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    if (
      process.platform !== 'win32' ||
      (code !== 'EINVAL' && code !== 'ENOTSUP' && code !== 'EISDIR' && code !== 'EPERM')
    ) {
      throw error
    }
  } finally {
    await handle.close()
  }
}

/**
 * Writes Bitwarden's plaintext ZIP-with-attachments format without buffering the ZIP or any
 * attachment in memory. The destination is private and atomically published only after fsync.
 */
export async function writeBitwardenAttachmentZip(
  path: string,
  source: NativeAttachmentBackupSource,
  options: {
    signal?: AbortSignal
    /** Error-injection seam for durability tests; production uses the strict implementation. */
    syncDirectory?: (path: string) => Promise<void>
  } = {}
): Promise<BitwardenAttachmentZipResult> {
  validatePath(path)
  const attachments = validateSource(source)
  const names = itemNamesById(source.vaultJson)
  const { foldersByItemId, paths } = attachmentPaths(attachments, names)
  if (!attachments.every((_attachment, index) => paths[index] !== undefined)) invalidInput()
  let declaredBytes = 0
  for (const attachment of attachments) {
    declaredBytes += attachment.size
    if (!Number.isSafeInteger(declaredBytes)) invalidInput()
  }
  const directory = dirname(path)
  await mkdir(directory, { recursive: true, mode: 0o700 })
  throwIfAborted(options.signal)

  const temporaryPath = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`
  let handle: Awaited<ReturnType<typeof open>> | undefined
  let published = false
  let totalBytes = 0
  try {
    const flags = constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY
    handle = await open(temporaryPath, flags, 0o600)
    const state: ZipWriteState = { handle, position: 0, entries: [] }
    const json = Buffer.from(source.vaultJson, 'utf8')
    await appendStoredEntry(
      state,
      'data.json',
      json.length,
      (async function* (): AsyncIterable<Buffer> {
        yield json
      })(),
      options.signal
    )
    await appendStoredEntry(state, 'attachments/', 0, emptyChunks(), options.signal, true)

    const writtenItemFolders = new Set<string>()
    for (let index = 0; index < attachments.length; index += 1) {
      throwIfAborted(options.signal)
      const attachment = attachments[index]!
      if (!writtenItemFolders.has(attachment.itemId)) {
        const folder = foldersByItemId.get(attachment.itemId)
        if (folder === undefined) invalidInput()
        await appendStoredEntry(
          state,
          `attachments/${folder}/`,
          0,
          emptyChunks(),
          options.signal,
          true
        )
        writtenItemFolders.add(attachment.itemId)
      }
      let chunks: AsyncIterable<Buffer>
      try {
        chunks = source.openAttachment(attachment, 0, options.signal)
      } catch {
        attachmentFailed()
      }
      await appendStoredEntry(state, paths[index]!, attachment.size, chunks, options.signal)
      totalBytes += attachment.size
    }
    await finishArchive(state)
    await handle.sync()
    await handle.close()
    handle = undefined
    await chmod(temporaryPath, 0o600)
    await rename(temporaryPath, path)
    published = true
    await (options.syncDirectory ?? syncDirectory)(directory)
    return { path, attachmentCount: attachments.length, attachmentBytes: totalBytes }
  } catch (error) {
    await handle?.close().catch(() => undefined)
    await unlink(temporaryPath).catch(() => undefined)
    if (published) throw new VaultError('EXPORT_RESULT_UNKNOWN')
    if (error instanceof VaultError) throw error
    throw new VaultError('ATTACHMENT_FAILED')
  }
}
