import { createHmac } from 'node:crypto'
import { mkdtemp, readdir, readFile, rename, rm, utimes } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  EncryptedImageCache,
  clearImageCacheKeys,
  deriveImageCacheKeys
} from './encrypted-image-cache'

const directories: string[] = []

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

async function createCache(): Promise<{ cache: EncryptedImageCache; directory: string }> {
  const directory = await mkdtemp(join(tmpdir(), 'bearwarden-image-cache-'))
  directories.push(directory)
  return { cache: new EncryptedImageCache(join(directory, 'cache')), directory }
}

function keysFor(seed: number): ReturnType<typeof deriveImageCacheKeys> {
  return deriveImageCacheKeys(Buffer.alloc(32, seed), Buffer.alloc(16, seed))
}

async function entryFiles(directory: string, namespace: string): Promise<string[]> {
  const path = join(directory, 'cache', namespace)
  return (await readdir(path))
    .filter((name) => name.endsWith('.bin'))
    .map((name) => join(path, name))
}

describe('EncryptedImageCache', () => {
  it('round-trips entries without leaking the key or the image bytes to disk', async () => {
    const { cache, directory } = await createCache()
    const keys = keysFor(1)
    const data = Buffer.from('secret-card-face-bytes')
    await cache.write(keys, 'card-cover', 'https://vault.example.invalid\0remote\0cover', {
      mediaType: 'image/jpeg',
      data,
      storedAt: 1234
    })

    await expect(
      cache.read(keys, 'card-cover', 'https://vault.example.invalid\0remote\0cover')
    ).resolves.toEqual({ mediaType: 'image/jpeg', data, storedAt: 1234 })
    const [file] = await entryFiles(directory, 'card-cover')
    expect(file).not.toContain('example')
    const contents = await readFile(file!)
    expect(contents.includes(data)).toBe(false)
    expect(contents.includes(Buffer.from('vault.example.invalid'))).toBe(false)
  })

  it('stores definitive misses as negative entries', async () => {
    const { cache } = await createCache()
    const keys = keysFor(2)
    await cache.write(keys, 'website-icon', 'https://icons.invalid/a.png', {
      mediaType: null,
      data: null,
      storedAt: 5
    })
    await expect(cache.read(keys, 'website-icon', 'https://icons.invalid/a.png')).resolves.toEqual({
      mediaType: null,
      data: null,
      storedAt: 5
    })
  })

  it('treats entries written under another vault key as misses and removes them', async () => {
    const { cache, directory } = await createCache()
    const original = keysFor(3)
    await cache.write(original, 'website-icon', 'key', {
      mediaType: 'image/png',
      data: Buffer.from('png'),
      storedAt: 1
    })
    // After a master password change the naming key changes too, so the old file is unreachable.
    const rekeyed = keysFor(4)
    await expect(cache.read(rekeyed, 'website-icon', 'key')).resolves.toBeNull()

    // A file swapped under another logical key fails authentication and is deleted.
    const [file] = await entryFiles(directory, 'website-icon')
    const otherName = createHmac('sha256', original.naming)
      .update('website-icon\0other')
      .digest('hex')
    await rename(file!, join(directory, 'cache', 'website-icon', `${otherName}.bin`))
    await expect(cache.read(original, 'website-icon', 'other')).resolves.toBeNull()
    await expect(entryFiles(directory, 'website-icon')).resolves.toHaveLength(0)
    clearImageCacheKeys(original)
    expect(original.encryption.equals(Buffer.alloc(32))).toBe(true)
  })

  it('evicts the least recently used entries beyond the namespace limit', async () => {
    const { cache, directory } = await createCache()
    const keys = keysFor(5)
    for (let index = 0; index < 514; index += 1) {
      await cache.write(keys, 'card-cover', `cover-${index}`, {
        mediaType: 'image/jpeg',
        data: Buffer.from([index & 0xff]),
        storedAt: index
      })
    }
    const files = await entryFiles(directory, 'card-cover')
    const old = new Date(0)
    await Promise.all(files.map((file) => utimes(file, old, old)))
    // Reading refreshes recency, so this entry survives the prune.
    await cache.read(keys, 'card-cover', 'cover-0')
    await new Promise((resolve) => setTimeout(resolve, 20))
    await cache.prune('card-cover')

    await expect(entryFiles(directory, 'card-cover')).resolves.toHaveLength(512)
    await expect(cache.read(keys, 'card-cover', 'cover-0')).resolves.not.toBeNull()
  })
})
