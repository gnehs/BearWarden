import { randomBytes } from 'node:crypto'
import { open, rename, unlink } from 'node:fs/promises'
import { dirname, isAbsolute } from 'node:path'
import { VaultError } from './vault-errors'

const MAX_DESTINATION_PATH_LENGTH = 32_768

export interface VaultAttachmentFilePlatform {
  chooseSavePath: (defaultName: string) => Promise<string | null>
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

export class VaultAttachmentFileService {
  constructor(private readonly platform: VaultAttachmentFilePlatform) {}

  chooseSavePath(fileName: string): Promise<string | null> {
    return this.platform.chooseSavePath(safeAttachmentFileName(fileName))
  }

  write(path: string, contents: Buffer, signal?: AbortSignal): Promise<void> {
    return atomicWritePrivateAttachment(path, contents, signal)
  }
}
