import { mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Uint8ArrayReader, Uint8ArrayWriter, ZipReader } from '@zip.js/zip.js'
import { afterEach, describe, expect, it } from 'vitest'
import type {
  NativeAttachmentBackupEntry,
  NativeAttachmentBackupSource
} from './native-attachment-backup'
import { writeBitwardenAttachmentZip } from './bitwarden-attachment-zip'

const directories: string[] = []

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'bearwarden-bitwarden-zip-'))
  directories.push(directory)
  return directory
}

afterEach(async () => {
  await Promise.all(
    directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))
  )
})

function sourceFor(
  items: Array<{ id: string; name: string }>,
  attachments: NativeAttachmentBackupEntry[],
  contents: ReadonlyMap<string, readonly Buffer[]>
): NativeAttachmentBackupSource {
  return {
    vaultJson: JSON.stringify({ encrypted: false, folders: [], items }),
    attachments,
    openAttachment: async function* (attachment) {
      for (const chunk of contents.get(attachment.id) ?? []) yield chunk
    }
  }
}

async function readZip(path: string): Promise<Map<string, Buffer>> {
  const archive = await readFile(path)
  const reader = new ZipReader(new Uint8ArrayReader(archive))
  try {
    const result = new Map<string, Buffer>()
    for (const entry of await reader.getEntries()) {
      if (entry.directory) continue
      const bytes = await entry.getData!(new Uint8ArrayWriter())
      result.set(entry.filename, Buffer.from(bytes))
    }
    return result
  } finally {
    await reader.close()
    archive.fill(0)
  }
}

async function zipEntryNames(path: string): Promise<string[]> {
  const archive = await readFile(path)
  const reader = new ZipReader(new Uint8ArrayReader(archive))
  try {
    return (await reader.getEntries()).map((entry) => entry.filename)
  } finally {
    await reader.close()
    archive.fill(0)
  }
}

describe('Bitwarden attachment ZIP writer', () => {
  it('writes the official data.json and attachments/item/file shape with exact bytes', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'vault.zip')
    const first = Buffer.from([0, 1, 2, 3])
    const second = Buffer.from([0xff, 0x80, 0x00])
    const attachments = [
      { id: 'a1', itemId: 'i1', fileName: 'document.bin', size: 7 }
    ] satisfies NativeAttachmentBackupEntry[]
    const source = sourceFor(
      [{ id: 'i1', name: 'Private item' }],
      attachments,
      new Map([['a1', [first, second]]])
    )
    const expectedJson = source.vaultJson

    await expect(writeBitwardenAttachmentZip(path, source)).resolves.toEqual({
      path,
      attachmentCount: 1,
      attachmentBytes: 7
    })

    const entries = await readZip(path)
    expect([...entries.keys()]).toEqual(['data.json', 'attachments/Private item/document.bin'])
    expect(await zipEntryNames(path)).toEqual([
      'data.json',
      'attachments/',
      'attachments/Private item/',
      'attachments/Private item/document.bin'
    ])
    expect(entries.get('data.json')?.toString('utf8')).toBe(expectedJson)
    expect(entries.get('attachments/Private item/document.bin')).toEqual(
      Buffer.from([0, 1, 2, 3, 0xff, 0x80, 0x00])
    )
    const archive = await readFile(path)
    const reader = new ZipReader(new Uint8ArrayReader(archive))
    try {
      expect((await reader.getEntries()).every((entry) => entry.zip64 !== true)).toBe(true)
    } finally {
      await reader.close()
      archive.fill(0)
    }
    expect(first).toEqual(Buffer.alloc(first.length))
    expect(second).toEqual(Buffer.alloc(second.length))
  })

  it('sanitizes and deterministically deduplicates raw, sanitized, and NFC collisions', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'vault.zip')
    const items = [
      { id: 'i1', name: 'A/B' },
      { id: 'i2', name: 'A/B' },
      { id: 'i3', name: 'A\\B' },
      { id: 'i4', name: 'Cafe\u0301' },
      { id: 'i5', name: 'Café' },
      { id: 'i6', name: 'café' },
      { id: 'i7', name: '..' }
    ]
    const attachments = [
      { id: 'a1', itemId: 'i1', fileName: 'report?.txt', size: 1 },
      { id: 'a2', itemId: 'i1', fileName: 'report*.txt', size: 1 },
      { id: 'a3', itemId: 'i1', fileName: 'e\u0301.txt', size: 1 },
      { id: 'a4', itemId: 'i1', fileName: 'é.txt', size: 1 },
      { id: 'a5', itemId: 'i2', fileName: 'x.txt', size: 1 },
      { id: 'a6', itemId: 'i3', fileName: 'x.txt', size: 1 },
      { id: 'a7', itemId: 'i4', fileName: 'x.txt', size: 1 },
      { id: 'a8', itemId: 'i5', fileName: 'x.txt', size: 1 },
      { id: 'a9', itemId: 'i6', fileName: 'x.txt', size: 1 },
      { id: 'a10', itemId: 'i7', fileName: 'x.txt', size: 1 }
    ] satisfies NativeAttachmentBackupEntry[]
    const contents = new Map(
      attachments.map((attachment, index) => [attachment.id, [Buffer.from([index])]])
    )

    await writeBitwardenAttachmentZip(path, sourceFor(items, attachments, contents))

    expect([...(await readZip(path)).keys()]).toEqual([
      'data.json',
      'attachments/A_B/report_.txt',
      'attachments/A_B/report__1.txt',
      'attachments/A_B/é.txt',
      'attachments/A_B/é_1.txt',
      'attachments/A_B_1/x.txt',
      'attachments/A_B_2/x.txt',
      'attachments/Café/x.txt',
      'attachments/Café_1/x.txt',
      'attachments/café_2/x.txt',
      'attachments/item/x.txt'
    ])
  })

  it('supports zero-byte attachments', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'vault.zip')
    const attachment = { id: 'empty', itemId: 'item', fileName: 'empty', size: 0 }

    await writeBitwardenAttachmentZip(
      path,
      sourceFor([{ id: 'item', name: 'Item' }], [attachment], new Map([['empty', []]]))
    )

    expect((await readZip(path)).get('attachments/Item/empty')).toEqual(Buffer.alloc(0))
  })

  it('writes ZIP64 metadata when the archive reaches the classic entry-count sentinel', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'vault.zip')
    const count = 32_767
    const items = Array.from({ length: count }, (_, index) => ({
      id: `item-${index}`,
      name: `Item ${index}`
    }))
    const attachments = items.map(({ id }, index) => ({
      id: `attachment-${index}`,
      itemId: index === count - 1 ? items[count - 2]!.id : id,
      fileName: 'empty',
      size: 0
    }))

    await writeBitwardenAttachmentZip(path, sourceFor(items, attachments, new Map()))

    const archive = await readFile(path)
    const reader = new ZipReader(new Uint8ArrayReader(archive))
    try {
      const entries = await reader.getEntries()
      expect(entries).toHaveLength(65_535)
      expect(archive.indexOf(Buffer.from([0x50, 0x4b, 0x06, 0x06]))).toBeGreaterThan(-1)
      expect(archive.indexOf(Buffer.from([0x50, 0x4b, 0x06, 0x07]))).toBeGreaterThan(-1)
    } finally {
      await reader.close()
      archive.fill(0)
    }
  }, 20_000)

  it.each([
    ['shorter', 3, [Buffer.from([1, 2])]],
    ['longer', 1, [Buffer.from([1, 2])]]
  ])('rejects a source that is %s than its declared size', async (_label, size, chunks) => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'vault.zip')
    const attachment = { id: 'bad', itemId: 'item', fileName: 'bad.bin', size }

    await expect(
      writeBitwardenAttachmentZip(
        path,
        sourceFor([{ id: 'item', name: 'Item' }], [attachment], new Map([['bad', chunks]]))
      )
    ).rejects.toMatchObject({ code: 'ATTACHMENT_FAILED' })
    await expect(readdir(directory)).resolves.toEqual([])
    expect(chunks[0]).toEqual(Buffer.alloc(chunks[0]!.length))
  })

  it('removes the private temporary file when the source throws', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'vault.zip')
    let temporaryMode: number | undefined
    const source: NativeAttachmentBackupSource = {
      vaultJson: JSON.stringify({ encrypted: false, items: [{ id: 'item', name: 'Item' }] }),
      attachments: [{ id: 'bad', itemId: 'item', fileName: 'bad.bin', size: 1 }],
      openAttachment: async function* () {
        const temporary = (await readdir(directory)).find((name) => name.endsWith('.tmp'))
        if (temporary) temporaryMode = (await stat(join(directory, temporary))).mode & 0o777
        await Promise.reject(new Error('download failed'))
        yield Buffer.alloc(0)
      }
    }

    await expect(writeBitwardenAttachmentZip(path, source)).rejects.toMatchObject({
      code: 'ATTACHMENT_FAILED'
    })
    expect(temporaryMode).toBe(0o600)
    await expect(readdir(directory)).resolves.toEqual([])
  })

  it("rejects attachments larger than Bitwarden's 500 MiB limit before opening them", async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'vault.zip')
    let opened = false
    const source: NativeAttachmentBackupSource = {
      vaultJson: JSON.stringify({ encrypted: false, items: [{ id: 'item', name: 'Item' }] }),
      attachments: [
        { id: 'large', itemId: 'item', fileName: 'large.bin', size: 500 * 1024 * 1024 + 1 }
      ],
      openAttachment: async function* () {
        opened = true
        yield Buffer.alloc(0)
      }
    }

    await expect(writeBitwardenAttachmentZip(path, source)).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    expect(opened).toBe(false)
    await expect(readdir(directory)).resolves.toEqual([])
  })

  it('rejects generated UTF-8 entry names larger than the ZIP limit', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'vault.zip')
    const itemName = '界'.repeat(30_000)
    const attachment = { id: 'a', itemId: 'item', fileName: 'x', size: 0 }

    await expect(
      writeBitwardenAttachmentZip(
        path,
        sourceFor([{ id: 'item', name: itemName }], [attachment], new Map([['a', []]]))
      )
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(readdir(directory)).resolves.toEqual([])
  })

  it('publishes the plaintext archive with mode 0600', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'vault.zip')
    const source = sourceFor([{ id: 'item', name: 'Item' }], [], new Map())

    await writeBitwardenAttachmentZip(path, source)

    expect((await stat(path)).mode & 0o777).toBe(0o600)
  })

  it('reports an indeterminate result when the final directory durability barrier fails', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'vault.zip')
    const source = sourceFor([{ id: 'item', name: 'Item' }], [], new Map())

    await expect(
      writeBitwardenAttachmentZip(path, source, {
        syncDirectory: async () => {
          throw Object.assign(new Error('durability failure'), { code: 'EIO' })
        }
      })
    ).rejects.toMatchObject({ code: 'EXPORT_RESULT_UNKNOWN' })

    expect((await readFile(path)).subarray(0, 2).toString('ascii')).toBe('PK')
    await expect(readdir(directory)).resolves.toEqual(['vault.zip'])
    expect((await stat(path)).mode & 0o777).toBe(0o600)
  })
})
