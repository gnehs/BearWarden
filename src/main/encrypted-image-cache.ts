import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes } from 'node:crypto'
import { constants } from 'node:fs'
import { readdir, rename, rm, stat, unlink, utimes } from 'node:fs/promises'
import { join } from 'node:path'
import { createAccountId, ensurePrivateDirectory, openNoFollow } from './account-paths'

export type ImageCacheNamespace = 'website-icon' | 'card-cover'

export interface ImageCacheEntry {
  /** `null` records a definitive "no image" answer (negative cache entry). */
  mediaType: string | null
  data: Buffer | null
  storedAt: number
}

/**
 * Subkeys derived from the unlocked local vault key. Callers derive them per operation and must
 * zero them with `clearImageCacheKeys` once the operation finishes.
 */
export interface ImageCacheKeys {
  encryption: Buffer
  naming: Buffer
}

const MAGIC = Buffer.from('BWIC', 'ascii')
const FORMAT_VERSION = 1
const IV_LENGTH = 12
const AUTH_TAG_LENGTH = 16
const HEADER_LENGTH = MAGIC.length + 1 + IV_LENGTH + AUTH_TAG_LENGTH
const MAX_METADATA_BYTES = 1024
const PRUNE_EVERY_WRITES = 32

const NAMESPACE_LIMITS: Record<ImageCacheNamespace, { maxEntries: number; maxBytes: number }> = {
  'website-icon': { maxEntries: 2048, maxBytes: 512 * 1024 },
  'card-cover': { maxEntries: 512, maxBytes: 10 * 1024 * 1024 }
}

export function deriveImageCacheKeys(vaultKey: Buffer, vaultSalt: Buffer): ImageCacheKeys {
  return {
    encryption: Buffer.from(
      hkdfSync('sha256', vaultKey, vaultSalt, 'bearwarden-image-cache-v1:encryption', 32)
    ),
    naming: Buffer.from(
      hkdfSync('sha256', vaultKey, vaultSalt, 'bearwarden-image-cache-v1:naming', 32)
    )
  }
}

export function clearImageCacheKeys(keys: ImageCacheKeys): void {
  keys.encryption.fill(0)
  keys.naming.fill(0)
}

function associatedData(namespace: ImageCacheNamespace, key: string): Buffer {
  return Buffer.concat([
    MAGIC,
    Buffer.from([FORMAT_VERSION]),
    Buffer.from(`${namespace}\0${key}`, 'utf8')
  ])
}

function encodeEntry(
  keys: ImageCacheKeys,
  namespace: ImageCacheNamespace,
  key: string,
  entry: ImageCacheEntry
): Buffer {
  const metadata = Buffer.from(
    JSON.stringify({ mediaType: entry.mediaType, storedAt: entry.storedAt }),
    'utf8'
  )
  const metadataLength = Buffer.alloc(4)
  metadataLength.writeUInt32BE(metadata.length)
  const plaintext = Buffer.concat([metadataLength, metadata, entry.data ?? Buffer.alloc(0)])
  const iv = randomBytes(IV_LENGTH)
  try {
    const cipher = createCipheriv('aes-256-gcm', keys.encryption, iv)
    cipher.setAAD(associatedData(namespace, key))
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
    return Buffer.concat([
      MAGIC,
      Buffer.from([FORMAT_VERSION]),
      iv,
      cipher.getAuthTag(),
      ciphertext
    ])
  } finally {
    plaintext.fill(0)
  }
}

function decodeEntry(
  keys: ImageCacheKeys,
  namespace: ImageCacheNamespace,
  key: string,
  contents: Buffer
): ImageCacheEntry | null {
  if (
    contents.length < HEADER_LENGTH + 4 ||
    !contents.subarray(0, MAGIC.length).equals(MAGIC) ||
    contents[MAGIC.length] !== FORMAT_VERSION
  ) {
    return null
  }
  const ivOffset = MAGIC.length + 1
  const iv = contents.subarray(ivOffset, ivOffset + IV_LENGTH)
  const authTag = contents.subarray(ivOffset + IV_LENGTH, HEADER_LENGTH)
  let plaintext: Buffer
  try {
    const decipher = createDecipheriv('aes-256-gcm', keys.encryption, iv)
    decipher.setAAD(associatedData(namespace, key))
    decipher.setAuthTag(authTag)
    plaintext = Buffer.concat([decipher.update(contents.subarray(HEADER_LENGTH)), decipher.final()])
  } catch {
    // Written under another vault key (for example before a master password change) or corrupt.
    return null
  }
  try {
    const metadataLength = plaintext.readUInt32BE(0)
    if (metadataLength > MAX_METADATA_BYTES || 4 + metadataLength > plaintext.length) return null
    const metadata = JSON.parse(plaintext.subarray(4, 4 + metadataLength).toString('utf8')) as {
      mediaType?: unknown
      storedAt?: unknown
    }
    if (
      (metadata.mediaType !== null && typeof metadata.mediaType !== 'string') ||
      typeof metadata.storedAt !== 'number' ||
      !Number.isFinite(metadata.storedAt)
    ) {
      return null
    }
    const body = plaintext.subarray(4 + metadataLength)
    if (metadata.mediaType === null) {
      return body.length === 0 ? { mediaType: null, data: null, storedAt: metadata.storedAt } : null
    }
    if (body.length === 0) return null
    return { mediaType: metadata.mediaType, data: Buffer.from(body), storedAt: metadata.storedAt }
  } catch {
    return null
  } finally {
    plaintext.fill(0)
  }
}

/**
 * Persistent cache for remote images shown in the vault list. Every entry is encrypted with a
 * subkey of the local vault key, and file names are keyed HMACs so the cache directory reveals
 * neither hostnames nor item identifiers. Cache failures are never fatal: callers fall back to
 * the network.
 */
export class EncryptedImageCache {
  private readonly writesSincePrune = new Map<ImageCacheNamespace, number>()
  private readonly pruning = new Set<ImageCacheNamespace>()

  constructor(private readonly directory: string) {}

  private namespaceDirectory(namespace: ImageCacheNamespace): string {
    return join(this.directory, namespace)
  }

  private entryPath(keys: ImageCacheKeys, namespace: ImageCacheNamespace, key: string): string {
    const name = createHmac('sha256', keys.naming).update(`${namespace}\0${key}`).digest('hex')
    return join(this.namespaceDirectory(namespace), `${name}.bin`)
  }

  async read(
    keys: ImageCacheKeys,
    namespace: ImageCacheNamespace,
    key: string
  ): Promise<ImageCacheEntry | null> {
    const path = this.entryPath(keys, namespace, key)
    let contents: Buffer
    try {
      const handle = await openNoFollow(path, constants.O_RDONLY)
      try {
        const info = await handle.stat()
        if (
          info.size >
          NAMESPACE_LIMITS[namespace].maxBytes + HEADER_LENGTH + 4 + MAX_METADATA_BYTES
        ) {
          await unlink(path).catch(() => undefined)
          return null
        }
        contents = await handle.readFile()
      } finally {
        await handle.close().catch(() => undefined)
      }
    } catch {
      return null
    }
    const entry = decodeEntry(keys, namespace, key, contents)
    if (!entry) {
      await unlink(path).catch(() => undefined)
      return null
    }
    // Pruning evicts by modification time, so a read refreshes the entry's position.
    const now = new Date()
    void utimes(path, now, now).catch(() => undefined)
    return entry
  }

  async write(
    keys: ImageCacheKeys,
    namespace: ImageCacheNamespace,
    key: string,
    entry: ImageCacheEntry
  ): Promise<void> {
    if (entry.data && entry.data.length > NAMESPACE_LIMITS[namespace].maxBytes) return
    // Encrypt synchronously before any await so callers can check their generation and write
    // in the same tick, without the subkeys being zeroed underneath the cipher.
    const contents = encodeEntry(keys, namespace, key, entry)
    const path = this.entryPath(keys, namespace, key)
    const directory = this.namespaceDirectory(namespace)
    try {
      await ensurePrivateDirectory(this.directory)
      await ensurePrivateDirectory(directory)
      const temporaryPath = join(directory, `.${createAccountId()}.tmp`)
      const handle = await openNoFollow(
        temporaryPath,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
        0o600
      )
      try {
        await handle.writeFile(contents)
        await handle.close()
        await rename(temporaryPath, path)
      } catch (error) {
        await handle.close().catch(() => undefined)
        await unlink(temporaryPath).catch(() => undefined)
        throw error
      }
    } catch {
      return
    }
    const writes = (this.writesSincePrune.get(namespace) ?? 0) + 1
    this.writesSincePrune.set(namespace, writes)
    if (writes >= PRUNE_EVERY_WRITES) {
      this.writesSincePrune.set(namespace, 0)
      void this.prune(namespace)
    }
  }

  async remove(keys: ImageCacheKeys, namespace: ImageCacheNamespace, key: string): Promise<void> {
    await unlink(this.entryPath(keys, namespace, key)).catch(() => undefined)
  }

  async clear(): Promise<void> {
    await rm(this.directory, { recursive: true, force: true }).catch(() => undefined)
  }

  /** Keeps each namespace under its entry limit by evicting the least recently used files. */
  async prune(namespace: ImageCacheNamespace): Promise<void> {
    if (this.pruning.has(namespace)) return
    this.pruning.add(namespace)
    try {
      const directory = this.namespaceDirectory(namespace)
      const names = await readdir(directory).catch(() => [] as string[])
      const { maxEntries } = NAMESPACE_LIMITS[namespace]
      if (names.length <= maxEntries) return
      const entries = await Promise.all(
        names.map(async (name) => {
          const path = join(directory, name)
          const info = await stat(path).catch(() => null)
          return { path, modifiedAt: info?.mtimeMs ?? 0 }
        })
      )
      entries.sort((left, right) => left.modifiedAt - right.modifiedAt)
      await Promise.all(
        entries
          .slice(0, entries.length - maxEntries)
          .map(({ path }) => unlink(path).catch(() => undefined))
      )
    } finally {
      this.pruning.delete(namespace)
    }
  }
}
