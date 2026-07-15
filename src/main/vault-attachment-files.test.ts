import {
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  symlink,
  truncate,
  writeFile
} from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  atomicWritePrivateAttachment,
  MAX_ATTACHMENT_PLAINTEXT_BYTES,
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
  function uploadService(path: string | null): VaultAttachmentFileService {
    return new VaultAttachmentFileService({
      chooseOpenFile: async () => path,
      chooseSavePath: async () => null
    })
  }

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

  it('returns null when the main-process upload picker is canceled', async () => {
    await expect(uploadService(null).chooseOpenFile()).resolves.toBeNull()
  })

  it('selects and bounded-reads regular and empty files without exposing their paths', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-attachment-upload-'))
    temporaryDirectories.push(directory)
    const decomposedPath = join(directory, 'cafe\u0301.txt')
    const emptyPath = join(directory, 'empty.bin')
    await writeFile(decomposedPath, 'attachment contents')
    await writeFile(emptyPath, '')

    const regularFiles = uploadService(decomposedPath)
    const regular = await regularFiles.chooseOpenFile()
    expect(regular).toEqual({ fileName: 'caf\u00e9.txt', size: 19 })
    expect(regular).not.toHaveProperty('path')
    expect(await regularFiles.readSelectedFile(regular!)).toEqual(
      Buffer.from('attachment contents')
    )

    const emptyFiles = uploadService(emptyPath)
    const empty = await emptyFiles.chooseOpenFile()
    expect(empty).toEqual({ fileName: 'empty.bin', size: 0 })
    expect(await emptyFiles.readSelectedFile(empty!)).toEqual(Buffer.alloc(0))
  })

  it('rejects an attachment whose type-2 envelope would exceed 128 MiB', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-attachment-oversize-'))
    temporaryDirectories.push(directory)
    const path = join(directory, 'sparse.bin')
    await writeFile(path, '')
    await truncate(path, MAX_ATTACHMENT_PLAINTEXT_BYTES + 1)

    await expect(uploadService(path).chooseOpenFile()).rejects.toMatchObject({
      code: 'ATTACHMENT_TOO_LARGE'
    })
  })

  it('rejects symlinks and non-regular file selections', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-attachment-special-'))
    temporaryDirectories.push(directory)
    const target = join(directory, 'target.txt')
    const link = join(directory, 'link.txt')
    await writeFile(target, 'target')
    await symlink(target, link)

    await expect(uploadService(link).chooseOpenFile()).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(uploadService(directory).chooseOpenFile()).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    if (process.platform !== 'win32') {
      await expect(uploadService('/dev/null').chooseOpenFile()).rejects.toMatchObject({
        code: 'INVALID_INPUT'
      })
    }
  })

  it('aborts a selected-file read before returning caller-owned plaintext', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-attachment-read-abort-'))
    temporaryDirectories.push(directory)
    const path = join(directory, 'large.bin')
    await writeFile(path, Buffer.alloc(2 * 1024 * 1024, 7))
    const files = uploadService(path)
    const selection = await files.chooseOpenFile()
    const abort = new AbortController()

    const reading = files.readSelectedFile(selection!, abort.signal)
    abort.abort()
    await expect(reading).rejects.toMatchObject({ code: 'LOCKED' })
  })

  it('rejects a path replaced after selection instead of reading the replacement', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-attachment-replaced-'))
    temporaryDirectories.push(directory)
    const path = join(directory, 'selected.txt')
    const originalPath = join(directory, 'original.txt')
    await writeFile(path, 'original')
    const files = uploadService(path)
    const selection = await files.chooseOpenFile()

    await rename(path, originalPath)
    await writeFile(path, 'replacement')

    await expect(files.readSelectedFile(selection!)).rejects.toMatchObject({
      code: 'ATTACHMENT_FAILED'
    })
  })
})
