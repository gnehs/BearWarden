import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  atomicWritePrivateAttachment,
  safeAttachmentFileName,
  VaultAttachmentFileService
} from './vault-attachment-files'

const temporaryDirectories: string[] = []

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true }))
  )
})

describe('vault attachment files', () => {
  it('sanitizes server-provided names before opening the main-process picker', async () => {
    const chooseSavePath = vi.fn(async () => null)
    const service = new VaultAttachmentFileService({ chooseSavePath })

    await expect(service.chooseSavePath('../unsafe\u0000:name.txt')).resolves.toBeNull()
    expect(chooseSavePath).toHaveBeenCalledWith('.._unsafe__name.txt')
    expect(safeAttachmentFileName('...')).toBe('attachment')
  })

  it('atomically replaces an existing file with owner-only bytes and no temporary file', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-attachment-'))
    temporaryDirectories.push(directory)
    const path = join(directory, 'document.bin')
    const clearText = Buffer.from('fake attachment contents')
    await writeFile(path, 'old contents', { mode: 0o644 })

    await atomicWritePrivateAttachment(path, clearText)

    expect(await readFile(path)).toEqual(clearText)
    expect(await readdir(directory)).toEqual(['document.bin'])
    if (process.platform !== 'win32') expect((await stat(path)).mode & 0o777).toBe(0o600)
  })

  it('rejects renderer-style relative paths and an already aborted write', async () => {
    await expect(
      atomicWritePrivateAttachment('renderer-controlled.txt', Buffer.from('fake'))
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })

    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-attachment-abort-'))
    temporaryDirectories.push(directory)
    const abort = new AbortController()
    abort.abort()
    await expect(
      atomicWritePrivateAttachment(
        join(directory, 'canceled.bin'),
        Buffer.from('fake'),
        abort.signal
      )
    ).rejects.toMatchObject({ code: 'LOCKED' })
    expect(await readdir(directory)).toEqual([])
  })
})
