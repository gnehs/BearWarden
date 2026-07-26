import { randomBytes } from 'node:crypto'
import { constants, type BigIntStats } from 'node:fs'
import { lstat, open, rename, unlink } from 'node:fs/promises'
import { basename, dirname, isAbsolute } from 'node:path'
import { VaultError } from './vault-errors'
import type { BitwardenAttachmentByteSource } from './bitwarden-attachment-stream'

const MAX_DESTINATION_PATH_LENGTH = 32_768
const MAX_ATTACHMENT_FILE_NAME_LENGTH = 255
const MAX_ATTACHMENT_ENVELOPE_BYTES = 500 * 1024 * 1024 + 65
const ATTACHMENT_ENVELOPE_FIXED_BYTES = 1 + 16 + 32
const ATTACHMENT_BLOCK_BYTES = 16
const READ_CHUNK_BYTES = 1024 * 1024

/**
 * Largest plaintext accepted by current Bitwarden/Vaultwarden attachment APIs.
 * PKCS#7 always adds one full or partial
 * 16-byte block: `49 + 16 * (floor(n / 16) + 1)`.
 */
export const MAX_ATTACHMENT_PLAINTEXT_BYTES = 500 * 1024 * 1024

interface SelectedFileIdentity {
  dev: bigint
  ino: bigint
  size: bigint
  ctimeNs: bigint
  mtimeNs: bigint
}

/** Main-process-only capability. The selected absolute path never leaves this module. */
export interface VaultAttachmentFileSelection {
  readonly fileName: string
  readonly size: number
}

const selectedFilePaths = new WeakMap<
  VaultAttachmentFileSelection,
  { path: string; identity: SelectedFileIdentity }
>()

export interface VaultAttachmentFilePlatform {
  chooseSavePath: (defaultName: string) => Promise<string | null>
  chooseOpenFile?: () => Promise<string | null>
  chooseCardCoverFile?: () => Promise<string | null>
}

function attachmentEnvelopeLength(plaintextLength: number): number {
  return (
    ATTACHMENT_ENVELOPE_FIXED_BYTES +
    ATTACHMENT_BLOCK_BYTES * (Math.floor(plaintextLength / ATTACHMENT_BLOCK_BYTES) + 1)
  )
}

function selectedAttachmentFileName(path: string): string {
  const fileName = basename(path).normalize('NFC')
  const containsControlCharacter = Array.from(fileName).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0
    return codePoint < 32 || codePoint === 127
  })
  if (
    fileName.length === 0 ||
    fileName === '.' ||
    fileName === '..' ||
    fileName.length > MAX_ATTACHMENT_FILE_NAME_LENGTH ||
    containsControlCharacter
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return fileName
}

function identityOf(stats: BigIntStats): SelectedFileIdentity {
  return {
    dev: stats.dev,
    ino: stats.ino,
    size: stats.size,
    ctimeNs: stats.ctimeNs,
    mtimeNs: stats.mtimeNs
  }
}

function sameIdentity(left: SelectedFileIdentity, right: SelectedFileIdentity): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.ctimeNs === right.ctimeNs &&
    left.mtimeNs === right.mtimeNs
  )
}

function assertSupportedRegularFile(stats: BigIntStats): void {
  if (!stats.isFile() || stats.isSymbolicLink()) throw new VaultError('INVALID_INPUT')
  if (
    stats.size < 0n ||
    stats.size > BigInt(MAX_ATTACHMENT_PLAINTEXT_BYTES) ||
    attachmentEnvelopeLength(Number(stats.size)) > MAX_ATTACHMENT_ENVELOPE_BYTES
  ) {
    throw new VaultError('ATTACHMENT_TOO_LARGE')
  }
}

async function inspectSelectedFile(path: string): Promise<VaultAttachmentFileSelection> {
  if (
    typeof path !== 'string' ||
    path.length === 0 ||
    path.length > MAX_DESTINATION_PATH_LENGTH ||
    !isAbsolute(path)
  ) {
    throw new VaultError('INVALID_INPUT')
  }

  try {
    const stats = await lstat(path, { bigint: true })
    assertSupportedRegularFile(stats)
    const selection = Object.freeze({
      fileName: selectedAttachmentFileName(path),
      size: Number(stats.size)
    })
    selectedFilePaths.set(selection, { path, identity: identityOf(stats) })
    return selection
  } catch (error) {
    if (error instanceof VaultError) throw error
    throw new VaultError('ATTACHMENT_FAILED')
  }
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new VaultError('LOCKED')
}

async function writeAll(
  handle: Awaited<ReturnType<typeof open>>,
  bytes: Buffer,
  position: number
): Promise<void> {
  let offset = 0
  while (offset < bytes.length) {
    const { bytesWritten } = await handle.write(
      bytes,
      offset,
      bytes.length - offset,
      position + offset
    )
    if (bytesWritten === 0) throw new VaultError('ATTACHMENT_FAILED')
    offset += bytesWritten
  }
}

async function readSelectedAttachment(
  selection: VaultAttachmentFileSelection,
  signal?: AbortSignal
): Promise<Buffer> {
  const selected = selectedFilePaths.get(selection)
  if (!selected) throw new VaultError('INVALID_INPUT')
  throwIfAborted(signal)

  let handle: Awaited<ReturnType<typeof open>> | undefined
  let contents: Buffer | undefined
  let failure: unknown
  try {
    const beforeOpen = await lstat(selected.path, { bigint: true })
    assertSupportedRegularFile(beforeOpen)
    if (!sameIdentity(selected.identity, identityOf(beforeOpen))) {
      throw new VaultError('ATTACHMENT_FAILED')
    }

    // O_NOFOLLOW is unavailable on Windows. There, lstat plus the fstat identity
    // comparison below is the best available defense against a path swap.
    const flags = constants.O_RDONLY | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW)
    handle = await open(selected.path, flags)
    const opened = await handle.stat({ bigint: true })
    assertSupportedRegularFile(opened)
    const openedIdentity = identityOf(opened)
    if (
      !sameIdentity(selected.identity, openedIdentity) ||
      !sameIdentity(identityOf(beforeOpen), openedIdentity)
    ) {
      throw new VaultError('ATTACHMENT_FAILED')
    }

    throwIfAborted(signal)
    contents = Buffer.allocUnsafe(Number(opened.size))
    let offset = 0
    while (offset < contents.length) {
      throwIfAborted(signal)
      const length = Math.min(READ_CHUNK_BYTES, contents.length - offset)
      const { bytesRead } = await handle.read(contents, offset, length, offset)
      if (bytesRead === 0) throw new VaultError('ATTACHMENT_FAILED')
      offset += bytesRead
    }
    throwIfAborted(signal)

    const afterRead = await handle.stat({ bigint: true })
    if (!sameIdentity(openedIdentity, identityOf(afterRead))) {
      throw new VaultError('ATTACHMENT_FAILED')
    }
    throwIfAborted(signal)
  } catch (error) {
    failure = error
  }

  try {
    await handle?.close()
  } catch (error) {
    failure ??= error
  }

  if (failure !== undefined) {
    contents?.fill(0)
    if (failure instanceof VaultError) throw failure
    if (signal?.aborted || (failure instanceof Error && failure.name === 'AbortError')) {
      throw new VaultError('LOCKED')
    }
    throw new VaultError('ATTACHMENT_FAILED')
  }
  if (!contents) throw new VaultError('ATTACHMENT_FAILED')
  return contents
}

function selectedAttachmentSource(
  selection: VaultAttachmentFileSelection
): BitwardenAttachmentByteSource {
  const selected = selectedFilePaths.get(selection)
  if (!selected) throw new VaultError('INVALID_INPUT')
  return {
    size: selection.size,
    async *chunks(signal?: AbortSignal): AsyncGenerator<Buffer> {
      throwIfAborted(signal)
      const beforeOpen = await lstat(selected.path, { bigint: true })
      assertSupportedRegularFile(beforeOpen)
      if (!sameIdentity(selected.identity, identityOf(beforeOpen))) {
        throw new VaultError('ATTACHMENT_FAILED')
      }
      const flags = constants.O_RDONLY | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW)
      const handle = await open(selected.path, flags)
      try {
        const opened = await handle.stat({ bigint: true })
        const openedIdentity = identityOf(opened)
        assertSupportedRegularFile(opened)
        if (
          !sameIdentity(selected.identity, openedIdentity) ||
          !sameIdentity(identityOf(beforeOpen), openedIdentity)
        ) {
          throw new VaultError('ATTACHMENT_FAILED')
        }
        let position = 0
        while (position < selection.size) {
          throwIfAborted(signal)
          const chunk = Buffer.allocUnsafe(Math.min(READ_CHUNK_BYTES, selection.size - position))
          const { bytesRead } = await handle.read(chunk, 0, chunk.length, position)
          if (bytesRead === 0) {
            chunk.fill(0)
            throw new VaultError('ATTACHMENT_FAILED')
          }
          position += bytesRead
          const value = bytesRead === chunk.length ? chunk : chunk.subarray(0, bytesRead)
          try {
            yield value
          } finally {
            chunk.fill(0)
          }
        }
        const afterRead = await handle.stat({ bigint: true })
        if (!sameIdentity(openedIdentity, identityOf(afterRead))) {
          throw new VaultError('ATTACHMENT_FAILED')
        }
        throwIfAborted(signal)
      } finally {
        await handle.close()
      }
    }
  }
}

async function syncDirectory(path: string): Promise<void> {
  let handle: Awaited<ReturnType<typeof open>> | undefined
  try {
    handle = await open(path, 'r')
    await handle.sync()
  } catch {
    // Directory fsync is not supported on every Electron target, notably Windows.
  } finally {
    // The file rename is already the commit point. A directory-handle close
    // failure must not turn a successfully saved plaintext file into a false
    // failure report.
    await handle?.close().catch(() => undefined)
  }
}

export function safeAttachmentFileName(fileName: string): string {
  if (typeof fileName !== 'string' || fileName.length === 0) {
    throw new VaultError('INVALID_INPUT')
  }
  const sanitized = Array.from(fileName.normalize('NFC'), (character) => {
    const codePoint = character.codePointAt(0) ?? 0
    return codePoint < 32 || codePoint === 127 || '/\\<>:"|?*'.includes(character) ? '_' : character
  })
    .join('')
    .replace(/[. ]+$/u, '')
  return sanitized.length === 0 ? 'attachment' : Array.from(sanitized).slice(0, 255).join('')
}

export async function atomicWritePrivateAttachment(
  path: string,
  contents: Buffer,
  signal?: AbortSignal
): Promise<void> {
  if (
    typeof path !== 'string' ||
    path.length === 0 ||
    path.length > MAX_DESTINATION_PATH_LENGTH ||
    !isAbsolute(path) ||
    !Buffer.isBuffer(contents)
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  if (signal?.aborted) throw new VaultError('LOCKED')

  const directory = dirname(path)
  const temporaryPath = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`
  let handle: Awaited<ReturnType<typeof open>> | undefined
  try {
    handle = await open(temporaryPath, 'wx', 0o600)
    if (signal?.aborted) throw new VaultError('LOCKED')
    await handle.writeFile(contents)
    if (signal?.aborted) throw new VaultError('LOCKED')
    await handle.sync()
    await handle.close()
    handle = undefined
    if (signal?.aborted) throw new VaultError('LOCKED')
    // rename preserves the temporary file's 0600 mode. Avoid a post-commit chmod that
    // could fail after plaintext is already visible and incorrectly report no saved file.
    await rename(temporaryPath, path)
    await syncDirectory(directory)
  } catch (error) {
    await handle?.close()
    await unlink(temporaryPath).catch(() => undefined)
    throw error
  }
}

export async function atomicWritePrivateAttachmentStream(
  path: string,
  source: BitwardenAttachmentByteSource,
  signal?: AbortSignal
): Promise<void> {
  if (
    typeof path !== 'string' ||
    path.length === 0 ||
    path.length > MAX_DESTINATION_PATH_LENGTH ||
    !isAbsolute(path) ||
    !source ||
    !Number.isSafeInteger(source.size) ||
    source.size < 0 ||
    source.size > MAX_ATTACHMENT_PLAINTEXT_BYTES ||
    typeof source.chunks !== 'function'
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  throwIfAborted(signal)
  const directory = dirname(path)
  const temporaryPath = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`
  let handle: Awaited<ReturnType<typeof open>> | undefined
  try {
    handle = await open(temporaryPath, 'wx', 0o600)
    let position = 0
    for await (const chunk of source.chunks(signal)) {
      throwIfAborted(signal)
      if (!Buffer.isBuffer(chunk)) throw new VaultError('ATTACHMENT_FAILED')
      if (position + chunk.length > source.size) throw new VaultError('ATTACHMENT_FAILED')
      await writeAll(handle, chunk, position)
      position += chunk.length
    }
    throwIfAborted(signal)
    await handle.sync()
    await handle.close()
    handle = undefined
    throwIfAborted(signal)
    await rename(temporaryPath, path)
    await syncDirectory(directory)
  } catch (error) {
    await handle?.close().catch(() => undefined)
    await unlink(temporaryPath).catch(() => undefined)
    throw error
  }
}

export class VaultAttachmentFileService {
  constructor(private readonly platform: VaultAttachmentFilePlatform) {}

  async chooseOpenFile(): Promise<VaultAttachmentFileSelection | null> {
    if (!this.platform.chooseOpenFile) throw new VaultError('INTERNAL_ERROR')
    const path = await this.platform.chooseOpenFile()
    return path === null ? null : inspectSelectedFile(path)
  }

  async chooseCardCoverFile(): Promise<VaultAttachmentFileSelection | null> {
    if (!this.platform.chooseCardCoverFile) throw new VaultError('INTERNAL_ERROR')
    const path = await this.platform.chooseCardCoverFile()
    return path === null ? null : inspectSelectedFile(path)
  }

  readSelectedFile(selection: VaultAttachmentFileSelection, signal?: AbortSignal): Promise<Buffer> {
    return readSelectedAttachment(selection, signal)
  }

  selectedFileSource(selection: VaultAttachmentFileSelection): BitwardenAttachmentByteSource {
    return selectedAttachmentSource(selection)
  }

  chooseSavePath(fileName: string): Promise<string | null> {
    return this.platform.chooseSavePath(safeAttachmentFileName(fileName))
  }

  write(path: string, contents: Buffer, signal?: AbortSignal): Promise<void> {
    return atomicWritePrivateAttachment(path, contents, signal)
  }

  writeStream(
    path: string,
    source: BitwardenAttachmentByteSource,
    signal?: AbortSignal
  ): Promise<void> {
    return atomicWritePrivateAttachmentStream(path, source, signal)
  }
}
