import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual
} from 'node:crypto'
import { constants, openAsBlob } from 'node:fs'
import { mkdtemp, open, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { BitwardenCryptoError } from './bitwarden-crypto'

const IV_BYTES = 16
const MAC_BYTES = 32
const KEY_BYTES = 32
const COMBINED_KEY_BYTES = 64
const HEADER_BYTES = 1 + IV_BYTES + MAC_BYTES
const CHUNK_BYTES = 1024 * 1024

export const MAX_STREAMED_ATTACHMENT_PLAINTEXT_BYTES = 500 * 1024 * 1024
export const MAX_STREAMED_ATTACHMENT_ENVELOPE_BYTES =
  MAX_STREAMED_ATTACHMENT_PLAINTEXT_BYTES + HEADER_BYTES + IV_BYTES

export interface BitwardenAttachmentByteSource {
  readonly size: number
  /**
   * Yields producer-owned chunks. Consumers must not retain or mutate them.
   * Plaintext producers clear their chunks after the consumer advances.
   */
  chunks(signal?: AbortSignal): AsyncIterable<Buffer>
}

export interface BitwardenEncryptedAttachmentFile extends BitwardenAttachmentByteSource {
  blob(): Promise<Blob>
  dispose(): Promise<void>
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException('Attachment operation aborted', 'AbortError')
}

function assertCombinedKey(key: Buffer): void {
  if (!Buffer.isBuffer(key) || key.length !== COMBINED_KEY_BYTES) {
    throw new BitwardenCryptoError('INVALID_KEY', 'attachment key has an invalid length')
  }
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
    if (bytesWritten === 0) throw new Error('Attachment temporary file write stalled')
    offset += bytesWritten
  }
}

export function encryptedAttachmentLength(plaintextLength: number): number {
  if (
    !Number.isSafeInteger(plaintextLength) ||
    plaintextLength < 0 ||
    plaintextLength > MAX_STREAMED_ATTACHMENT_PLAINTEXT_BYTES
  ) {
    throw new BitwardenCryptoError('INVALID_INPUT', 'attachment plaintext has an invalid size')
  }
  return HEADER_BYTES + IV_BYTES * (Math.floor(plaintextLength / IV_BYTES) + 1)
}

async function* fileChunks(
  path: string,
  offset: number,
  length: number,
  signal?: AbortSignal
): AsyncGenerator<Buffer> {
  const handle = await open(path, constants.O_RDONLY)
  let position = offset
  let remaining = length
  try {
    while (remaining > 0) {
      throwIfAborted(signal)
      const chunk = Buffer.allocUnsafe(Math.min(CHUNK_BYTES, remaining))
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, position)
      if (bytesRead === 0) {
        chunk.fill(0)
        throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'attachment file is truncated')
      }
      position += bytesRead
      remaining -= bytesRead
      if (bytesRead === chunk.length) yield chunk
      else {
        const partial = chunk.subarray(0, bytesRead)
        yield partial
      }
    }
  } finally {
    await handle.close()
  }
}

async function temporaryEncryptedFile(
  write: (path: string) => Promise<number>
): Promise<BitwardenEncryptedAttachmentFile> {
  const directory = await mkdtemp(join(tmpdir(), 'bearwarden-attachment-'))
  const path = join(directory, 'encrypted.bin')
  try {
    const size = await write(path)
    return {
      size,
      chunks: (signal) => fileChunks(path, 0, size, signal),
      blob: () => openAsBlob(path, { type: 'application/octet-stream' }),
      dispose: () => rm(directory, { recursive: true, force: true })
    }
  } catch (error) {
    await rm(directory, { recursive: true, force: true }).catch(() => undefined)
    throw error
  }
}

export async function encryptAttachmentSource(
  source: BitwardenAttachmentByteSource,
  key: Buffer,
  signal?: AbortSignal
): Promise<BitwardenEncryptedAttachmentFile> {
  assertCombinedKey(key)
  const expectedSize = encryptedAttachmentLength(source.size)
  return temporaryEncryptedFile(async (path) => {
    const handle = await open(path, 'wx', 0o600)
    const iv = randomBytes(IV_BYTES)
    const emptyMac = Buffer.alloc(MAC_BYTES)
    const cipher = createCipheriv('aes-256-cbc', key.subarray(0, KEY_BYTES), iv)
    const hmac = createHmac('sha256', key.subarray(KEY_BYTES))
    let plaintextBytes = 0
    let position = HEADER_BYTES
    try {
      const header = Buffer.concat([Buffer.of(2), iv, emptyMac])
      await writeAll(handle, header, 0)
      header.fill(0)
      hmac.update(iv)
      for await (const chunk of source.chunks(signal)) {
        throwIfAborted(signal)
        plaintextBytes += chunk.length
        if (plaintextBytes > source.size) {
          throw new BitwardenCryptoError('INVALID_INPUT', 'attachment source exceeded its size')
        }
        const encrypted = cipher.update(chunk)
        try {
          hmac.update(encrypted)
          await writeAll(handle, encrypted, position)
          position += encrypted.length
        } finally {
          encrypted.fill(0)
        }
      }
      if (plaintextBytes !== source.size) {
        throw new BitwardenCryptoError('INVALID_INPUT', 'attachment source size changed')
      }
      const final = cipher.final()
      try {
        hmac.update(final)
        await writeAll(handle, final, position)
        position += final.length
      } finally {
        final.fill(0)
      }
      const mac = hmac.digest()
      try {
        await writeAll(handle, mac, 1 + IV_BYTES)
      } finally {
        mac.fill(0)
      }
      await handle.sync()
      if (position !== expectedSize) {
        throw new BitwardenCryptoError('INVALID_INPUT', 'attachment envelope size changed')
      }
      return position
    } finally {
      iv.fill(0)
      emptyMac.fill(0)
      await handle.close()
    }
  })
}

export async function spoolEncryptedAttachment(
  source: BitwardenAttachmentByteSource,
  expectedSize: number,
  signal?: AbortSignal
): Promise<BitwardenEncryptedAttachmentFile> {
  if (
    !Number.isSafeInteger(expectedSize) ||
    expectedSize < 1 ||
    expectedSize > MAX_STREAMED_ATTACHMENT_ENVELOPE_BYTES ||
    source.size !== expectedSize
  ) {
    throw new BitwardenCryptoError('INVALID_INPUT', 'attachment envelope has an invalid size')
  }
  return temporaryEncryptedFile(async (path) => {
    const handle = await open(path, 'wx', 0o600)
    let position = 0
    try {
      for await (const chunk of source.chunks(signal)) {
        throwIfAborted(signal)
        if (position + chunk.length > expectedSize) {
          throw new BitwardenCryptoError(
            'INVALID_CIPHERSTRING',
            'attachment file exceeded its size'
          )
        }
        await writeAll(handle, chunk, position)
        position += chunk.length
      }
      if (position !== expectedSize) {
        throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'attachment file is truncated')
      }
      await handle.sync()
      return position
    } finally {
      await handle.close()
    }
  })
}

export async function authenticatedAttachmentPlaintext(
  encrypted: BitwardenEncryptedAttachmentFile,
  key: Buffer,
  signal?: AbortSignal
): Promise<BitwardenAttachmentByteSource> {
  if (!Buffer.isBuffer(key) || (key.length !== KEY_BYTES && key.length !== COMBINED_KEY_BYTES)) {
    throw new BitwardenCryptoError('INVALID_KEY', 'attachment key has an invalid length')
  }
  const header = Buffer.alloc(Math.min(HEADER_BYTES, encrypted.size))
  const headerSource = encrypted.chunks(signal)[Symbol.asyncIterator]()
  let headerOffset = 0
  try {
    while (headerOffset < header.length) {
      const next = await headerSource.next()
      if (next.done) break
      const take = Math.min(next.value.length, header.length - headerOffset)
      next.value.copy(header, headerOffset, 0, take)
      headerOffset += take
    }
  } finally {
    await headerSource.return?.()
  }
  if (headerOffset < 1 + IV_BYTES) {
    header.fill(0)
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'attachment envelope is truncated')
  }
  const type = header[0]
  if (type !== 0 && type !== 2) {
    header.fill(0)
    throw new BitwardenCryptoError('UNSUPPORTED_CIPHER_TYPE', 'attachment type is unsupported')
  }
  if (type === 2 && headerOffset !== HEADER_BYTES) {
    header.fill(0)
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'attachment envelope is truncated')
  }
  const ciphertextOffset = type === 2 ? HEADER_BYTES : 1 + IV_BYTES
  const ciphertextLength = encrypted.size - ciphertextOffset
  if (ciphertextLength < IV_BYTES || ciphertextLength % IV_BYTES !== 0) {
    header.fill(0)
    throw new BitwardenCryptoError('INVALID_CIPHERSTRING', 'attachment ciphertext size is invalid')
  }
  const iv = Buffer.from(header.subarray(1, 1 + IV_BYTES))
  try {
    if (type === 2) {
      if (key.length !== COMBINED_KEY_BYTES) {
        throw new BitwardenCryptoError('INVALID_KEY', 'authenticated attachment requires a MAC key')
      }
      const mac = Buffer.from(header.subarray(1 + IV_BYTES, HEADER_BYTES))
      const expected = createHmac('sha256', key.subarray(KEY_BYTES)).update(iv)
      let skipped = 0
      for await (const chunk of encrypted.chunks(signal)) {
        if (skipped + chunk.length <= ciphertextOffset) {
          skipped += chunk.length
          continue
        }
        const start = Math.max(0, ciphertextOffset - skipped)
        expected.update(chunk.subarray(start))
        skipped += chunk.length
      }
      const digest = expected.digest()
      try {
        if (!timingSafeEqual(digest, mac)) {
          throw new BitwardenCryptoError(
            'AUTHENTICATION_FAILED',
            'attachment MAC verification failed'
          )
        }
      } finally {
        digest.fill(0)
        mac.fill(0)
      }
    }

    const plaintextSize = ciphertextLength - 1
    let consumed = false
    return {
      // CBC padding makes the exact plaintext length unknowable until final().
      // Consumers must treat this as an upper bound and accept fewer bytes.
      size: plaintextSize,
      async *chunks(chunkSignal?: AbortSignal): AsyncGenerator<Buffer> {
        if (consumed) {
          throw new BitwardenCryptoError('INVALID_INPUT', 'attachment plaintext is single-use')
        }
        consumed = true
        const combinedSignal =
          signal && chunkSignal ? AbortSignal.any([signal, chunkSignal]) : (signal ?? chunkSignal)
        const decipher = createDecipheriv('aes-256-cbc', key.subarray(0, KEY_BYTES), iv)
        let emitted: Buffer | null = null
        try {
          let skipped = 0
          for await (const chunk of encrypted.chunks(combinedSignal)) {
            if (skipped + chunk.length <= ciphertextOffset) {
              skipped += chunk.length
              continue
            }
            const start = Math.max(0, ciphertextOffset - skipped)
            skipped += chunk.length
            emitted = decipher.update(chunk.subarray(start))
            if (emitted.length > 0) {
              const plaintext = emitted
              try {
                yield plaintext
              } finally {
                plaintext.fill(0)
                emitted = null
              }
            }
          }
          emitted = decipher.final()
          if (emitted.length > 0) {
            const plaintext = emitted
            try {
              yield plaintext
            } finally {
              plaintext.fill(0)
              emitted = null
            }
          }
        } catch (error) {
          if (error instanceof BitwardenCryptoError) throw error
          throw new BitwardenCryptoError(
            'DECRYPTION_FAILED',
            'attachment AES-CBC decryption failed'
          )
        } finally {
          emitted?.fill(0)
          iv.fill(0)
        }
      }
    }
  } catch (error) {
    iv.fill(0)
    throw error
  } finally {
    header.fill(0)
  }
}
