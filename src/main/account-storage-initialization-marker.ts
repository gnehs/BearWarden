import { constants } from 'node:fs'
import { unlink, type FileHandle } from 'node:fs/promises'
import { dirname } from 'node:path'
import { atomicWritePrivateFile, openNoFollow, syncDirectory } from './account-paths'

const PENDING_INITIALIZATION_MARKER = 'bearwarden-pending-initialization-v1\n'

async function readPendingInitializationMarker(path: string): Promise<boolean> {
  let handle: FileHandle | undefined
  try {
    handle = await openNoFollow(path, constants.O_RDONLY)
    const info = await handle.stat()
    if (info.size !== Buffer.byteLength(PENDING_INITIALIZATION_MARKER, 'utf8')) {
      throw new Error('INVALID_PENDING_INITIALIZATION_MARKER')
    }
    return (await handle.readFile()).toString('utf8') === PENDING_INITIALIZATION_MARKER
  } finally {
    await handle?.close().catch(() => undefined)
  }
}

export async function hasPendingInitializationMarker(path: string): Promise<boolean> {
  try {
    const valid = await readPendingInitializationMarker(path)
    if (!valid) throw new Error('INVALID_PENDING_INITIALIZATION_MARKER')
    return true
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false
    throw error
  }
}

export function createPendingInitializationMarker(
  path: string,
  createUuid?: () => string
): Promise<void> {
  return atomicWritePrivateFile(path, PENDING_INITIALIZATION_MARKER, createUuid)
}

/** Removes only a validated marker; callers may safely ignore cleanup failures after a vault commit. */
export async function clearPendingInitializationMarker(path: string): Promise<void> {
  if (!(await hasPendingInitializationMarker(path))) return
  await unlink(path)
  await syncDirectory(dirname(path))
}
