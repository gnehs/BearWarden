import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rename, rm, stat, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  inspectNativeAttachmentBackup,
  openNativeAttachmentBackup,
  writeNativeAttachmentBackup,
  type NativeAttachmentBackupEntry,
  type NativeAttachmentBackupSource
} from './native-attachment-backup'

const PASSWORD = 'correct horse attachment backup'
const directories: string[] = []

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'bearwarden-attachment-backup-'))
  directories.push(directory)
  return directory
}

afterEach(async () => {
  await Promise.all(
    directories.splice(0).map((directory) => rm(directory, { force: true, recursive: true }))
  )
})

function sourceFor(
  bytes: Buffer,
  opens: number[],
  entry: NativeAttachmentBackupEntry = {
    id: 'attachment-id',
    itemId: 'item-id',
    fileName: 'private-document.txt',
    size: bytes.length
  }
): NativeAttachmentBackupSource {
  return {
    vaultJson: JSON.stringify({ encrypted: false, items: [{ name: 'private vault item' }] }),
    attachments: [entry],
    openAttachment: async function* (_attachment, offset) {
      opens.push(offset)
      yield Buffer.from(bytes.subarray(offset))
    }
  }
}

describe('native encrypted attachment backup', () => {
  it('never writes plaintext vault or attachment data and verifies the completed archive', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'vault.bwbackup')
    const attachment = Buffer.from('highly sensitive attachment contents')
    const opens: number[] = []

    const result = await writeNativeAttachmentBackup(path, PASSWORD, sourceFor(attachment, opens), {
      now: () => new Date('2026-07-17T00:00:00.000Z')
    })

    expect(result).toEqual({
      path,
      attachmentCount: 1,
      attachmentBytes: attachment.length,
      resumed: false
    })
    expect(opens).toEqual([0])
    const archive = await readFile(path)
    expect(archive.includes(attachment)).toBe(false)
    expect(archive.includes(Buffer.from('private vault item'))).toBe(false)
    expect((await stat(path)).mode & 0o777).toBe(0o600)

    await expect(inspectNativeAttachmentBackup(path, PASSWORD)).resolves.toMatchObject({
      createdAt: '2026-07-17T00:00:00.000Z',
      attachments: [{ fileName: 'private-document.txt', size: attachment.length }],
      attachmentDigests: [createHash('sha256').update(attachment).digest('hex')]
    })
  })

  it('resumes only after the last authenticated and fsynced attachment chunk', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'vault.bwbackup')
    const bytes = Buffer.alloc(1024 * 1024 + 13, 0x5a)
    const firstOpens: number[] = []
    const abort = new AbortController()

    await expect(
      writeNativeAttachmentBackup(path, PASSWORD, sourceFor(bytes, firstOpens), {
        signal: abort.signal,
        onProgress: () => abort.abort()
      })
    ).rejects.toMatchObject({ code: 'ATTACHMENT_CANCELED' })
    expect(firstOpens).toEqual([0])
    await expect(stat(`${path}.partial`)).resolves.toMatchObject({ mode: expect.any(Number) })

    // Simulate a process dying midway through the next record. The unauthenticated
    // tail is discarded and is never treated as a committed resume point.
    const partial = await readFile(`${path}.partial`)
    await writeFile(`${path}.partial`, Buffer.concat([partial, Buffer.from([0, 0])]), {
      mode: 0o600
    })

    const resumeOpens: number[] = []
    const result = await writeNativeAttachmentBackup(path, PASSWORD, sourceFor(bytes, resumeOpens))
    expect(result.resumed).toBe(true)
    expect(resumeOpens).toEqual([1024 * 1024])
    await expect(inspectNativeAttachmentBackup(path, PASSWORD)).resolves.toMatchObject({
      attachmentDigests: [createHash('sha256').update(bytes).digest('hex')]
    })
  })

  it('rejects a wrong password, changed source, and authenticated-record tampering', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'vault.bwbackup')
    const bytes = Buffer.from('attachment')
    await writeNativeAttachmentBackup(path, PASSWORD, sourceFor(bytes, []))

    await expect(
      inspectNativeAttachmentBackup(path, 'wrong backup password')
    ).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })

    const archive = await readFile(path)
    archive[archive.length - 1] ^= 1
    await writeFile(path, archive, { mode: 0o600 })
    await expect(inspectNativeAttachmentBackup(path, PASSWORD)).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })

    const resumePath = join(directory, 'resume.bwbackup')
    const abort = new AbortController()
    await expect(
      writeNativeAttachmentBackup(
        resumePath,
        PASSWORD,
        sourceFor(Buffer.alloc(1024 * 1024 + 1), []),
        {
          signal: abort.signal,
          onProgress: () => abort.abort()
        }
      )
    ).rejects.toMatchObject({ code: 'ATTACHMENT_CANCELED' })
    await expect(
      writeNativeAttachmentBackup(
        resumePath,
        PASSWORD,
        sourceFor(Buffer.alloc(1024 * 1024 + 2), [])
      )
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('finishes an archive whose authenticated footer committed before the final rename', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'vault.bwbackup')
    const bytes = Buffer.from('finalized attachment')
    const source = sourceFor(bytes, [])
    await writeNativeAttachmentBackup(path, PASSWORD, source)
    await rename(path, `${path}.partial`)

    await expect(writeNativeAttachmentBackup(path, PASSWORD, source)).resolves.toMatchObject({
      path,
      attachmentBytes: bytes.length,
      resumed: true
    })
    await expect(stat(`${path}.partial`)).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(inspectNativeAttachmentBackup(path, PASSWORD)).resolves.toMatchObject({
      attachments: [{ size: bytes.length }]
    })
  })

  it('opens a verified same-fd reader and clears producer-owned chunks after advance', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'reader.bwbackup')
    const bytes = Buffer.alloc(1024 * 1024 + 17, 0x4f)
    await writeNativeAttachmentBackup(path, PASSWORD, sourceFor(bytes, []), {
      now: () => new Date('2026-07-17T01:02:03.000Z')
    })

    const reader = await openNativeAttachmentBackup(path, PASSWORD)
    const rawArchive = await readFile(path)
    expect(reader.preview).toMatchObject({
      createdAt: '2026-07-17T01:02:03.000Z',
      archiveFingerprint: expect.stringMatching(/^[0-9a-f]{64}$/),
      attachmentBytes: bytes.length,
      attachments: [{ size: bytes.length }],
      attachmentDigests: [createHash('sha256').update(bytes).digest('hex')]
    })
    expect('path' in reader.preview).toBe(false)
    expect('key' in reader.preview).toBe(false)
    expect(reader.preview.archiveFingerprint).toBe(
      createHash('sha256').update(rawArchive).digest('hex')
    )

    const iterator = reader.openAttachment(reader.preview.attachments[0]!)[Symbol.asyncIterator]()
    const first = await iterator.next()
    expect(first.done).toBe(false)
    const firstChunk = first.value!
    expect(firstChunk.length).toBe(1024 * 1024)
    const second = await iterator.next()
    expect(firstChunk).toEqual(Buffer.alloc(firstChunk.length))
    expect(second.done).toBe(false)
    const secondChunk = second.value!
    expect(secondChunk.length).toBe(17)
    await expect(iterator.next()).resolves.toMatchObject({ done: true })
    expect(secondChunk).toEqual(Buffer.alloc(secondChunk.length))
    await reader.dispose()
  })

  it('rejects concurrent iterators and aborts an active second-pass read', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'abort-reader.bwbackup')
    const bytes = Buffer.alloc(1024 * 1024 + 7, 0x33)
    await writeNativeAttachmentBackup(path, PASSWORD, sourceFor(bytes, []))
    const reader = await openNativeAttachmentBackup(path, PASSWORD)
    const entry = reader.preview.attachments[0]!
    const abort = new AbortController()
    const iterable = reader.openAttachment(entry, abort.signal)
    const iterator = iterable[Symbol.asyncIterator]()
    const first = await iterator.next()
    expect(first.done).toBe(false)
    const concurrent = reader.openAttachment(entry)[Symbol.asyncIterator]()
    await expect(concurrent.next()).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    const exposed = first.value!
    abort.abort()
    await expect(iterator.next()).rejects.toMatchObject({ code: 'ATTACHMENT_CANCELED' })
    expect(exposed).toEqual(Buffer.alloc(exposed.length))

    const replacement: Buffer[] = []
    for await (const chunk of reader.openAttachment(entry)) replacement.push(Buffer.from(chunk))
    expect(Buffer.concat(replacement)).toEqual(bytes)
    await reader.dispose()
  })

  it('fails closed when the verified inode changes size or contents', async () => {
    const directory = await temporaryDirectory()
    const sizePath = join(directory, 'changed-size.bwbackup')
    await writeNativeAttachmentBackup(sizePath, PASSWORD, sourceFor(Buffer.from('size'), []))
    const sizeReader = await openNativeAttachmentBackup(sizePath, PASSWORD)
    await writeFile(sizePath, Buffer.concat([await readFile(sizePath), Buffer.from([0])]))
    await expect(async () => {
      for await (const chunk of sizeReader.openAttachment(sizeReader.preview.attachments[0]!)) {
        chunk.fill(0)
      }
    }).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await sizeReader.dispose()

    const contentPath = join(directory, 'changed-content.bwbackup')
    await writeNativeAttachmentBackup(contentPath, PASSWORD, sourceFor(Buffer.from('contents'), []))
    const contentReader = await openNativeAttachmentBackup(contentPath, PASSWORD)
    const archive = await readFile(contentPath)
    archive[Math.floor(archive.length / 2)]! ^= 1
    await writeFile(contentPath, archive, { mode: 0o600 })
    await expect(async () => {
      for await (const chunk of contentReader.openAttachment(
        contentReader.preview.attachments[0]!
      )) {
        chunk.fill(0)
      }
    }).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await contentReader.dispose()
  })

  it('keeps reading the verified inode when the path is replaced and rejects symlinks', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'stable-inode.bwbackup')
    const moved = join(directory, 'verified-inode.bwbackup')
    const bytes = Buffer.from('verified inode contents')
    await writeNativeAttachmentBackup(path, PASSWORD, sourceFor(bytes, []))
    const reader = await openNativeAttachmentBackup(path, PASSWORD)
    await rename(path, moved)
    await writeNativeAttachmentBackup(path, PASSWORD, sourceFor(Buffer.from('replacement'), []))

    const restored: Buffer[] = []
    for await (const chunk of reader.openAttachment(reader.preview.attachments[0]!)) {
      restored.push(Buffer.from(chunk))
    }
    expect(Buffer.concat(restored)).toEqual(bytes)
    await reader.dispose()

    if (process.platform !== 'win32') {
      const link = join(directory, 'archive-link.bwbackup')
      await symlink(moved, link)
      await expect(openNativeAttachmentBackup(link, PASSWORD)).rejects.toMatchObject({
        code: 'INVALID_INPUT'
      })
    }
  })

  it('rejects wrong passwords, pre-aborted opens, and use after dispose', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'reader-errors.bwbackup')
    await writeNativeAttachmentBackup(path, PASSWORD, sourceFor(Buffer.from('reader'), []))
    await expect(openNativeAttachmentBackup(path, 'wrong backup password')).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    const abort = new AbortController()
    abort.abort()
    await expect(
      openNativeAttachmentBackup(path, PASSWORD, { signal: abort.signal })
    ).rejects.toMatchObject({ code: 'ATTACHMENT_CANCELED' })
    const reader = await openNativeAttachmentBackup(path, PASSWORD)
    await reader.dispose()
    expect(() => reader.openAttachment(reader.preview.attachments[0]!)).toThrowError(
      /INVALID_INPUT/
    )

    const activeReader = await openNativeAttachmentBackup(path, PASSWORD)
    const iterator = activeReader
      .openAttachment(activeReader.preview.attachments[0]!)
      [Symbol.asyncIterator]()
    const first = await iterator.next()
    expect(first.done).toBe(false)
    const exposed = first.value!
    await activeReader.dispose()
    await expect(iterator.next()).rejects.toMatchObject({ code: 'ATTACHMENT_CANCELED' })
    expect(exposed).toEqual(Buffer.alloc(exposed.length))
  })
})
