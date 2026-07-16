import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scrypt as deriveWithScrypt,
  type Hash
} from 'node:crypto'
import { constants } from 'node:fs'
import { chmod, lstat, mkdir, open, rename, unlink } from 'node:fs/promises'
import { dirname, isAbsolute } from 'node:path'
import { VaultError } from './vault-errors'

const MAGIC = Buffer.from('BWAB0001', 'ascii')
const HEADER_LENGTH_BYTES = 4
const RECORD_LENGTH_BYTES = 4
const AUTH_TAG_BYTES = 16
const NONCE_BYTES = 12
const SALT_BYTES = 16
const KEY_BYTES = 32
const CHUNK_BYTES = 1024 * 1024
const MAX_HEADER_BYTES = 16 * 1024
const MAX_MANIFEST_BYTES = 64 * 1024 * 1024
const MAX_RECORD_BYTES = CHUNK_BYTES + MAX_MANIFEST_BYTES
const MAX_ATTACHMENTS = 100_000
const MAX_PATH_BYTES = 32_768
const MAX_PASSWORD_LENGTH = 1_024
const MIN_PASSWORD_LENGTH = 12
const SCRYPT_PARAMETERS = {
  N: 2 ** 17,
  r: 8,
  p: 1,
  maxmem: 256 * 1024 * 1024
} as const

interface BackupHeader {
  format: 'bearwarden-attachment-backup'
  version: 1
  kdf: {
    name: 'scrypt'
    salt: string
    N: number
    r: number
    p: number
    keyLength: number
  }
  cipher: {
    name: 'aes-256-gcm'
    nonceLength: number
    authTagLength: number
  }
}

export interface NativeAttachmentBackupEntry {
  id: string
  itemId: string
  fileName: string
  size: number
}

export interface NativeAttachmentBackupSource {
  /** Bitwarden-compatible plaintext JSON. It is encrypted before any file write. */
  vaultJson: string
  attachments: readonly NativeAttachmentBackupEntry[]
  /** Opens decrypted bytes at a committed offset. Returned buffers are cleared by the writer. */
  openAttachment: (
    attachment: NativeAttachmentBackupEntry,
    offset: number,
    signal?: AbortSignal
  ) => AsyncIterable<Buffer>
}

export interface NativeAttachmentBackupProgress {
  attachmentIndex: number
  attachmentCount: number
  attachmentBytes: number
  attachmentSize: number
  totalBytes: number
  resumed: boolean
}

export interface NativeAttachmentBackupResult {
  path: string
  attachmentCount: number
  attachmentBytes: number
  resumed: boolean
}

export interface NativeAttachmentBackupInspection {
  createdAt: string
  vaultJson: string
  attachments: NativeAttachmentBackupEntry[]
  attachmentDigests: string[]
}

interface BackupManifest {
  type: 'manifest'
  createdAt: string
  vaultJson: string
  attachments: NativeAttachmentBackupEntry[]
}

interface BackupFooter {
  type: 'footer'
  vaultDigest: string
  attachmentDigests: string[]
}

interface ScannedArchive {
  header: BackupHeader
  headerBytes: Buffer
  manifest: BackupManifest
  offsets: number[]
  hashes: Hash[]
  footer: BackupFooter | null
  nextRecordIndex: number
  validBytes: number
  tornTail: boolean
}

function invalidInput(): never {
  throw new VaultError('INVALID_INPUT')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function decodeBase64(value: unknown, bytes: number): Buffer {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) invalidInput()
  const decoded = Buffer.from(value, 'base64')
  if (decoded.length !== bytes || decoded.toString('base64') !== value) {
    decoded.fill(0)
    invalidInput()
  }
  return decoded
}

function validatePassword(password: string): void {
  if (
    typeof password !== 'string' ||
    password.length < MIN_PASSWORD_LENGTH ||
    password.length > MAX_PASSWORD_LENGTH
  ) {
    invalidInput()
  }
}

function validatePath(path: string): void {
  if (
    typeof path !== 'string' ||
    path.length === 0 ||
    path.length > MAX_PATH_BYTES ||
    !isAbsolute(path)
  ) {
    invalidInput()
  }
}

function validateEntry(value: unknown): NativeAttachmentBackupEntry {
  if (!isRecord(value)) invalidInput()
  const { id, itemId, fileName, size } = value
  if (
    typeof id !== 'string' ||
    id.length === 0 ||
    id.length > 256 ||
    typeof itemId !== 'string' ||
    itemId.length === 0 ||
    itemId.length > 256 ||
    typeof fileName !== 'string' ||
    fileName.length === 0 ||
    fileName.length > 255 ||
    !Number.isSafeInteger(size) ||
    (size as number) < 0
  ) {
    invalidInput()
  }
  return { id, itemId, fileName, size: size as number }
}

function validateEntries(
  values: readonly NativeAttachmentBackupEntry[]
): NativeAttachmentBackupEntry[] {
  if (!Array.isArray(values) || values.length > MAX_ATTACHMENTS) invalidInput()
  const entries = values.map(validateEntry)
  const identities = new Set<string>()
  for (const entry of entries) {
    const identity = `${entry.itemId}\0${entry.id}`
    if (identities.has(identity)) invalidInput()
    identities.add(identity)
  }
  return entries
}

function parseHeader(bytes: Buffer): BackupHeader {
  let value: unknown
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    invalidInput()
  }
  if (!isRecord(value) || !isRecord(value.kdf) || !isRecord(value.cipher)) invalidInput()
  if (
    value.format !== 'bearwarden-attachment-backup' ||
    value.version !== 1 ||
    value.kdf.name !== 'scrypt' ||
    value.kdf.N !== SCRYPT_PARAMETERS.N ||
    value.kdf.r !== SCRYPT_PARAMETERS.r ||
    value.kdf.p !== SCRYPT_PARAMETERS.p ||
    value.kdf.keyLength !== KEY_BYTES ||
    value.cipher.name !== 'aes-256-gcm' ||
    value.cipher.nonceLength !== NONCE_BYTES ||
    value.cipher.authTagLength !== AUTH_TAG_BYTES
  ) {
    invalidInput()
  }
  decodeBase64(value.kdf.salt, SALT_BYTES).fill(0)
  return value as unknown as BackupHeader
}

function parseManifest(bytes: Buffer): BackupManifest {
  if (bytes.length > MAX_MANIFEST_BYTES) invalidInput()
  let value: unknown
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    invalidInput()
  }
  if (
    !isRecord(value) ||
    value.type !== 'manifest' ||
    typeof value.createdAt !== 'string' ||
    new Date(value.createdAt).toISOString() !== value.createdAt ||
    typeof value.vaultJson !== 'string' ||
    Buffer.byteLength(value.vaultJson, 'utf8') > MAX_MANIFEST_BYTES ||
    !Array.isArray(value.attachments)
  ) {
    invalidInput()
  }
  return {
    type: 'manifest',
    createdAt: value.createdAt,
    vaultJson: value.vaultJson,
    attachments: validateEntries(value.attachments as NativeAttachmentBackupEntry[])
  }
}

function parseFooter(bytes: Buffer, attachmentCount: number): BackupFooter {
  let value: unknown
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    invalidInput()
  }
  if (
    !isRecord(value) ||
    value.type !== 'footer' ||
    typeof value.vaultDigest !== 'string' ||
    !/^[0-9a-f]{64}$/.test(value.vaultDigest) ||
    !Array.isArray(value.attachmentDigests) ||
    value.attachmentDigests.length !== attachmentCount ||
    !value.attachmentDigests.every(
      (digest) => typeof digest === 'string' && /^[0-9a-f]{64}$/.test(digest)
    )
  ) {
    invalidInput()
  }
  return value as unknown as BackupFooter
}

function deriveKey(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    deriveWithScrypt(password.normalize('NFC'), salt, KEY_BYTES, SCRYPT_PARAMETERS, (error, key) =>
      error ? reject(error) : resolve(key)
    )
  })
}

function aad(headerBytes: Buffer, recordIndex: number): Buffer {
  if (!Number.isSafeInteger(recordIndex) || recordIndex < 0 || recordIndex > 0xffffffff) {
    throw new VaultError('ATTACHMENT_TOO_LARGE')
  }
  const index = Buffer.allocUnsafe(4)
  index.writeUInt32BE(recordIndex)
  return Buffer.concat([MAGIC, headerBytes, index])
}

function encryptRecord(
  plaintext: Buffer,
  key: Buffer,
  headerBytes: Buffer,
  recordIndex: number
): Buffer {
  const iv = randomBytes(NONCE_BYTES)
  const authenticated = aad(headerBytes, recordIndex)
  let ciphertext: Buffer | undefined
  try {
    const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: AUTH_TAG_BYTES })
    cipher.setAAD(authenticated)
    ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
    const length = Buffer.allocUnsafe(RECORD_LENGTH_BYTES)
    length.writeUInt32BE(ciphertext.length)
    return Buffer.concat([length, iv, cipher.getAuthTag(), ciphertext])
  } finally {
    iv.fill(0)
    authenticated.fill(0)
    ciphertext?.fill(0)
  }
}

function decryptRecord(
  ciphertext: Buffer,
  authTag: Buffer,
  iv: Buffer,
  key: Buffer,
  headerBytes: Buffer,
  recordIndex: number
): Buffer {
  const authenticated = aad(headerBytes, recordIndex)
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: AUTH_TAG_BYTES })
    decipher.setAAD(authenticated)
    decipher.setAuthTag(authTag)
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
  } catch {
    invalidInput()
  } finally {
    authenticated.fill(0)
  }
}

async function readExactly(
  handle: Awaited<ReturnType<typeof open>>,
  length: number,
  position: number
): Promise<Buffer | null> {
  const buffer = Buffer.allocUnsafe(length)
  let offset = 0
  while (offset < length) {
    const { bytesRead } = await handle.read(buffer, offset, length - offset, position + offset)
    if (bytesRead === 0) {
      buffer.fill(0)
      return null
    }
    offset += bytesRead
  }
  return buffer
}

async function writeExactly(
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
    if (bytesWritten === 0) throw new VaultError('ATTACHMENT_FAILED')
    offset += bytesWritten
  }
}

async function scanArchive(
  handle: Awaited<ReturnType<typeof open>>,
  password: string
): Promise<ScannedArchive> {
  const stats = await handle.stat()
  const minimum = MAGIC.length + HEADER_LENGTH_BYTES
  if (!stats.isFile() || stats.size < minimum) invalidInput()
  const prefix = await readExactly(handle, minimum, 0)
  if (!prefix || !prefix.subarray(0, MAGIC.length).equals(MAGIC)) {
    prefix?.fill(0)
    invalidInput()
  }
  const headerLength = prefix.readUInt32BE(MAGIC.length)
  prefix.fill(0)
  if (headerLength <= 0 || headerLength > MAX_HEADER_BYTES) invalidInput()
  const headerBytes = await readExactly(handle, headerLength, minimum)
  if (!headerBytes) invalidInput()
  const header = parseHeader(headerBytes)
  const salt = decodeBase64(header.kdf.salt, SALT_BYTES)
  const key = await deriveKey(password, salt)
  salt.fill(0)

  let position = minimum + headerLength
  let recordIndex = 0
  let manifest: BackupManifest | null = null
  let footer: BackupFooter | null = null
  let offsets: number[] = []
  let hashes: Hash[] = []
  let tornTail = false
  try {
    while (position < stats.size) {
      const lengthBytes = await readExactly(handle, RECORD_LENGTH_BYTES, position)
      if (!lengthBytes) {
        tornTail = true
        break
      }
      const ciphertextLength = lengthBytes.readUInt32BE(0)
      lengthBytes.fill(0)
      if (ciphertextLength <= 0 || ciphertextLength > MAX_RECORD_BYTES) invalidInput()
      const recordBytes = RECORD_LENGTH_BYTES + NONCE_BYTES + AUTH_TAG_BYTES + ciphertextLength
      if (position + recordBytes > stats.size) {
        tornTail = true
        break
      }
      const encrypted = await readExactly(
        handle,
        NONCE_BYTES + AUTH_TAG_BYTES + ciphertextLength,
        position + 4
      )
      if (!encrypted) {
        tornTail = true
        break
      }
      let plaintext: Buffer | undefined
      try {
        plaintext = decryptRecord(
          encrypted.subarray(NONCE_BYTES + AUTH_TAG_BYTES),
          encrypted.subarray(NONCE_BYTES, NONCE_BYTES + AUTH_TAG_BYTES),
          encrypted.subarray(0, NONCE_BYTES),
          key,
          headerBytes,
          recordIndex
        )
        if (recordIndex === 0) {
          manifest = parseManifest(plaintext)
          offsets = manifest.attachments.map(() => 0)
          hashes = manifest.attachments.map(() => createHash('sha256'))
        } else {
          if (!manifest || footer) invalidInput()
          const type = plaintext[0]
          if (type === 2) {
            if (plaintext.length <= 13) invalidInput()
            const attachmentIndex = plaintext.readUInt32BE(1)
            const offset = Number(plaintext.readBigUInt64BE(5))
            const entry = manifest.attachments[attachmentIndex]
            if (!entry || offset !== offsets[attachmentIndex]) invalidInput()
            for (let index = 0; index < attachmentIndex; index += 1) {
              if (offsets[index] !== manifest.attachments[index]!.size) invalidInput()
            }
            const chunk = plaintext.subarray(13)
            if (chunk.length > CHUNK_BYTES || offset + chunk.length > entry.size) invalidInput()
            hashes[attachmentIndex]!.update(chunk)
            offsets[attachmentIndex] += chunk.length
          } else if (type === 3) {
            footer = parseFooter(plaintext.subarray(1), manifest.attachments.length)
          } else {
            invalidInput()
          }
        }
      } finally {
        encrypted.fill(0)
        plaintext?.fill(0)
      }
      position += recordBytes
      recordIndex += 1
    }
    if (!manifest) invalidInput()
    return {
      header,
      headerBytes,
      manifest,
      offsets,
      hashes,
      footer,
      nextRecordIndex: recordIndex,
      validBytes: position,
      tornTail
    }
  } catch (error) {
    headerBytes.fill(0)
    throw error
  } finally {
    key.fill(0)
  }
}

function equalSource(manifest: BackupManifest, source: NativeAttachmentBackupSource): boolean {
  return (
    manifest.vaultJson === source.vaultJson &&
    manifest.attachments.length === source.attachments.length &&
    manifest.attachments.every((entry, index) => {
      const expected = source.attachments[index]
      return (
        expected !== undefined &&
        entry.id === expected.id &&
        entry.itemId === expected.itemId &&
        entry.fileName === expected.fileName &&
        entry.size === expected.size
      )
    })
  )
}

function verifyCompletedArchive(scanned: ScannedArchive): string[] {
  if (!scanned.footer || scanned.tornTail) invalidInput()
  if (
    scanned.offsets.some((offset, index) => offset !== scanned.manifest.attachments[index]!.size)
  ) {
    invalidInput()
  }
  const attachmentDigests = scanned.hashes.map((hash) => hash.digest('hex'))
  if (
    scanned.footer.vaultDigest !==
      createHash('sha256').update(scanned.manifest.vaultJson, 'utf8').digest('hex') ||
    attachmentDigests.some((digest, index) => digest !== scanned.footer!.attachmentDigests[index])
  ) {
    invalidInput()
  }
  return attachmentDigests
}

function chunkRecord(attachmentIndex: number, offset: number, chunk: Buffer): Buffer {
  const result = Buffer.allocUnsafe(13 + chunk.length)
  result[0] = 2
  result.writeUInt32BE(attachmentIndex, 1)
  result.writeBigUInt64BE(BigInt(offset), 5)
  chunk.copy(result, 13)
  return result
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new VaultError('ATTACHMENT_CANCELED')
}

async function syncDirectory(path: string): Promise<void> {
  let handle: Awaited<ReturnType<typeof open>> | undefined
  try {
    handle = await open(path, 'r')
    await handle.sync()
  } catch {
    // Directory fsync is unavailable on some Electron targets.
  } finally {
    await handle?.close().catch(() => undefined)
  }
}

async function openExistingPartial(path: string): Promise<Awaited<ReturnType<typeof open>> | null> {
  try {
    const stats = await lstat(path)
    if (!stats.isFile() || stats.isSymbolicLink()) invalidInput()
    const flags = constants.O_RDWR | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW)
    return await open(path, flags)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw error
  }
}

export async function writeNativeAttachmentBackup(
  path: string,
  password: string,
  source: NativeAttachmentBackupSource,
  options: {
    signal?: AbortSignal
    now?: () => Date
    onProgress?: (progress: NativeAttachmentBackupProgress) => void
  } = {}
): Promise<NativeAttachmentBackupResult> {
  validatePath(path)
  validatePassword(password)
  if (
    !source ||
    typeof source.vaultJson !== 'string' ||
    typeof source.openAttachment !== 'function'
  ) {
    invalidInput()
  }
  if (Buffer.byteLength(source.vaultJson, 'utf8') > MAX_MANIFEST_BYTES) invalidInput()
  const attachments = validateEntries(source.attachments)
  const partialPath = `${path}.partial`
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  throwIfAborted(options.signal)

  let handle: Awaited<ReturnType<typeof open>> | undefined =
    (await openExistingPartial(partialPath)) ?? undefined
  const resumed = handle !== undefined
  let key: Buffer | undefined
  let salt: Buffer | undefined
  let headerBytes: Buffer | undefined
  let scanned: ScannedArchive | undefined
  let stagingPath: string | undefined
  let position = 0
  let recordIndex = 0
  try {
    if (!handle) {
      salt = randomBytes(SALT_BYTES)
      const header: BackupHeader = {
        format: 'bearwarden-attachment-backup',
        version: 1,
        kdf: {
          name: 'scrypt',
          salt: salt.toString('base64'),
          N: SCRYPT_PARAMETERS.N,
          r: SCRYPT_PARAMETERS.r,
          p: SCRYPT_PARAMETERS.p,
          keyLength: KEY_BYTES
        },
        cipher: {
          name: 'aes-256-gcm',
          nonceLength: NONCE_BYTES,
          authTagLength: AUTH_TAG_BYTES
        }
      }
      headerBytes = Buffer.from(JSON.stringify(header), 'utf8')
      const headerLength = Buffer.allocUnsafe(HEADER_LENGTH_BYTES)
      headerLength.writeUInt32BE(headerBytes.length)
      const fixedHeader = Buffer.concat([MAGIC, headerLength, headerBytes])
      position = MAGIC.length + HEADER_LENGTH_BYTES + headerBytes.length
      key = await deriveKey(password, salt)
      const manifest: BackupManifest = {
        type: 'manifest',
        createdAt: (options.now?.() ?? new Date()).toISOString(),
        vaultJson: source.vaultJson,
        attachments
      }
      const plaintext = Buffer.from(JSON.stringify(manifest), 'utf8')
      if (plaintext.length > MAX_MANIFEST_BYTES) {
        plaintext.fill(0)
        invalidInput()
      }
      const encrypted = encryptRecord(plaintext, key, headerBytes, recordIndex)
      plaintext.fill(0)
      stagingPath = `${partialPath}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`
      handle = await open(stagingPath, 'wx+', 0o600)
      await writeExactly(handle, fixedHeader, 0)
      fixedHeader.fill(0)
      await writeExactly(handle, encrypted, position)
      position += encrypted.length
      encrypted.fill(0)
      recordIndex += 1
      await handle.sync()
      await handle.close()
      handle = undefined
      await rename(stagingPath, partialPath)
      stagingPath = undefined
      await syncDirectory(dirname(path))
      handle = (await openExistingPartial(partialPath)) ?? undefined
      if (!handle) throw new VaultError('ATTACHMENT_FAILED')
      scanned = {
        header,
        headerBytes,
        manifest,
        offsets: attachments.map(() => 0),
        hashes: attachments.map(() => createHash('sha256')),
        footer: null,
        nextRecordIndex: recordIndex,
        validBytes: position,
        tornTail: false
      }
    } else {
      scanned = await scanArchive(handle, password)
      if (!equalSource(scanned.manifest, { ...source, attachments })) invalidInput()
      if (scanned.footer) {
        verifyCompletedArchive(scanned)
        const attachmentBytes = scanned.offsets.reduce((total, value) => total + value, 0)
        await handle.close()
        handle = undefined
        await rename(partialPath, path)
        await chmod(path, 0o600)
        await syncDirectory(dirname(path))
        return {
          path,
          attachmentCount: attachments.length,
          attachmentBytes,
          resumed: true
        }
      }
      if (scanned.tornTail) await handle.truncate(scanned.validBytes)
      position = scanned.validBytes
      recordIndex = scanned.nextRecordIndex
      headerBytes = scanned.headerBytes
      salt = decodeBase64(scanned.header.kdf.salt, SALT_BYTES)
      key = await deriveKey(password, salt)
    }

    let totalBytes = scanned.offsets.reduce((total, value) => total + value, 0)
    for (let index = 0; index < attachments.length; index += 1) {
      const attachment = attachments[index]!
      let offset = scanned.offsets[index]!
      if (offset === attachment.size) continue
      const chunks = source.openAttachment(attachment, offset, options.signal)
      for await (const sourceChunk of chunks) {
        throwIfAborted(options.signal)
        if (!Buffer.isBuffer(sourceChunk) || sourceChunk.length === 0) invalidInput()
        let consumed = 0
        try {
          while (consumed < sourceChunk.length) {
            const length = Math.min(CHUNK_BYTES, sourceChunk.length - consumed)
            if (offset + length > attachment.size) invalidInput()
            const chunk = sourceChunk.subarray(consumed, consumed + length)
            const plaintext = chunkRecord(index, offset, chunk)
            const encrypted = encryptRecord(plaintext, key, headerBytes, recordIndex)
            scanned.hashes[index]!.update(chunk)
            plaintext.fill(0)
            await writeExactly(handle, encrypted, position)
            position += encrypted.length
            encrypted.fill(0)
            recordIndex += 1
            offset += length
            totalBytes += length
            consumed += length
            await handle.sync()
            options.onProgress?.({
              attachmentIndex: index,
              attachmentCount: attachments.length,
              attachmentBytes: offset,
              attachmentSize: attachment.size,
              totalBytes,
              resumed
            })
            throwIfAborted(options.signal)
          }
        } finally {
          sourceChunk.fill(0)
        }
      }
      if (offset !== attachment.size) throw new VaultError('ATTACHMENT_FAILED')
    }

    const footer: BackupFooter = {
      type: 'footer',
      vaultDigest: createHash('sha256').update(source.vaultJson, 'utf8').digest('hex'),
      attachmentDigests: scanned.hashes.map((hash) => hash.digest('hex'))
    }
    const footerJson = Buffer.from(JSON.stringify(footer), 'utf8')
    const footerPlaintext = Buffer.concat([Buffer.from([3]), footerJson])
    footerJson.fill(0)
    const encryptedFooter = encryptRecord(footerPlaintext, key, headerBytes, recordIndex)
    footerPlaintext.fill(0)
    await writeExactly(handle, encryptedFooter, position)
    encryptedFooter.fill(0)
    await handle.sync()
    await handle.close()
    handle = undefined
    await rename(partialPath, path)
    await chmod(path, 0o600)
    await syncDirectory(dirname(path))
    return { path, attachmentCount: attachments.length, attachmentBytes: totalBytes, resumed }
  } catch (error) {
    if (error instanceof VaultError) throw error
    if (options.signal?.aborted || (error instanceof Error && error.name === 'AbortError')) {
      throw new VaultError('ATTACHMENT_CANCELED')
    }
    throw new VaultError('ATTACHMENT_FAILED')
  } finally {
    await handle?.close().catch(() => undefined)
    if (stagingPath) await unlink(stagingPath).catch(() => undefined)
    key?.fill(0)
    salt?.fill(0)
    headerBytes?.fill(0)
  }
}

export async function inspectNativeAttachmentBackup(
  path: string,
  password: string
): Promise<NativeAttachmentBackupInspection> {
  validatePath(path)
  validatePassword(password)
  let handle: Awaited<ReturnType<typeof open>> | undefined
  let scanned: ScannedArchive | undefined
  try {
    const stats = await lstat(path)
    if (!stats.isFile() || stats.isSymbolicLink()) invalidInput()
    const flags = constants.O_RDONLY | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW)
    handle = await open(path, flags)
    scanned = await scanArchive(handle, password)
    const attachmentDigests = verifyCompletedArchive(scanned)
    return {
      createdAt: scanned.manifest.createdAt,
      vaultJson: scanned.manifest.vaultJson,
      attachments: scanned.manifest.attachments,
      attachmentDigests
    }
  } catch (error) {
    if (error instanceof VaultError) throw error
    throw new VaultError('INVALID_INPUT')
  } finally {
    scanned?.headerBytes.fill(0)
    await handle?.close().catch(() => undefined)
  }
}
