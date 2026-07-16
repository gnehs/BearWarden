import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rename, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  inspectNativeAttachmentBackup,
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
})
