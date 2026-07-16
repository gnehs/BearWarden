import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scrypt as deriveWithScrypt,
  timingSafeEqual
} from 'node:crypto'
import { mkdir, open, readFile, rename, stat, unlink } from 'node:fs/promises'
import { dirname } from 'node:path'
import { VaultError } from './vault-errors'

const FORMAT = 'bearwarden-vault'
const ENVELOPE_VERSION = 1
const KEY_LENGTH = 32
const SALT_LENGTH = 16
const IV_LENGTH = 12
const AUTH_TAG_LENGTH = 16
const MIN_MASTER_PASSWORD_LENGTH = 12
const MAX_MASTER_PASSWORD_BYTES = 1_024
const MAX_VAULT_BYTES = 64 * 1024 * 1024
const SCRYPT_PARAMETERS = {
  N: 2 ** 17,
  r: 8,
  p: 1,
  maxmem: 256 * 1024 * 1024
} as const

interface VaultEnvelopeV1 {
  format: typeof FORMAT
  version: typeof ENVELOPE_VERSION
  kdf: {
    name: 'scrypt'
    salt: string
    N: number
    r: number
    p: number
    keyLength: typeof KEY_LENGTH
  }
  cipher: {
    name: 'aes-256-gcm'
    iv: string
    authTag: string
  }
  ciphertext: string
}

export interface DecryptedVault<T> {
  data: T
  key: Buffer
  salt: Buffer
}

export interface VaultKeyMaterial {
  key: Buffer
  salt: Buffer
}

export type EncryptedVaultStoreAtomicWriteStage = 'before-temporary-write' | 'before-rename'

export interface EncryptedVaultStoreOptions {
  /** Observability/fault-injection boundary. Throwing aborts before the destination is replaced. */
  atomicWriteHook?: (
    stage: EncryptedVaultStoreAtomicWriteStage,
    paths: { temporaryPath: string; destinationPath: string }
  ) => void | Promise<void>
  /** Runs after the vault rename commit. Errors are intentionally ignored because the vault exists. */
  afterAtomicCommit?: () => void | Promise<void>
}

interface InternalDecryptedVault<T> extends DecryptedVault<T> {
  serializedEnvelope?: Buffer
}

function deriveKey(masterPassword: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    deriveWithScrypt(
      masterPassword.normalize('NFC'),
      salt,
      KEY_LENGTH,
      SCRYPT_PARAMETERS,
      (error, derivedKey) => {
        if (error) {
          reject(error)
          return
        }

        resolve(derivedKey)
      }
    )
  })
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function decodeBase64(value: unknown, expectedLength?: number): Buffer {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_VAULT_BYTES * 2 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }

  const decoded = Buffer.from(value, 'base64')
  if (
    decoded.toString('base64') !== value ||
    (expectedLength && decoded.length !== expectedLength)
  ) {
    decoded.fill(0)
    throw new VaultError('CORRUPT_VAULT')
  }

  return decoded
}

function parseEnvelope(value: unknown): VaultEnvelopeV1 {
  if (!isRecord(value) || !isRecord(value.kdf) || !isRecord(value.cipher)) {
    throw new VaultError('CORRUPT_VAULT')
  }

  if (
    value.format !== FORMAT ||
    value.version !== ENVELOPE_VERSION ||
    value.kdf.name !== 'scrypt' ||
    value.kdf.N !== SCRYPT_PARAMETERS.N ||
    value.kdf.r !== SCRYPT_PARAMETERS.r ||
    value.kdf.p !== SCRYPT_PARAMETERS.p ||
    value.kdf.keyLength !== KEY_LENGTH ||
    value.cipher.name !== 'aes-256-gcm' ||
    typeof value.kdf.salt !== 'string' ||
    typeof value.cipher.iv !== 'string' ||
    typeof value.cipher.authTag !== 'string' ||
    typeof value.ciphertext !== 'string'
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }

  return value as unknown as VaultEnvelopeV1
}

function authenticatedMetadata(envelope: VaultEnvelopeV1): Buffer {
  return Buffer.from(
    JSON.stringify({
      format: envelope.format,
      version: envelope.version,
      kdf: envelope.kdf,
      cipher: {
        name: envelope.cipher.name,
        iv: envelope.cipher.iv
      }
    }),
    'utf8'
  )
}

async function syncDirectory(path: string): Promise<void> {
  let directoryHandle: Awaited<ReturnType<typeof open>> | undefined
  try {
    directoryHandle = await open(path, 'r')
    await directoryHandle.sync()
  } catch {
    // Directory fsync is not supported on every Electron target, notably Windows.
  } finally {
    await directoryHandle?.close().catch(() => undefined)
  }
}

export class EncryptedVaultStore<T> {
  readonly filePath: string
  private operationTail: Promise<void> = Promise.resolve()
  private readonly options: EncryptedVaultStoreOptions

  constructor(filePath: string, options: EncryptedVaultStoreOptions = {}) {
    this.filePath = filePath
    this.options = options
  }

  async exists(): Promise<boolean> {
    return this.runSerialized(() => this.existsUnserialized())
  }

  private async existsUnserialized(): Promise<boolean> {
    try {
      await stat(this.filePath)
      return true
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false
      throw error
    }
  }

  async initialize(masterPassword: string, data: T): Promise<VaultKeyMaterial> {
    return this.runSerialized(() => this.initializeUnserialized(masterPassword, data))
  }

  private async initializeUnserialized(masterPassword: string, data: T): Promise<VaultKeyMaterial> {
    if (await this.existsUnserialized()) throw new VaultError('ALREADY_INITIALIZED')

    const salt = randomBytes(SALT_LENGTH)
    const key = await deriveKey(masterPassword, salt)

    try {
      await this.writeUnserialized(data, key, salt)
      return { key, salt }
    } catch (error) {
      key.fill(0)
      salt.fill(0)
      throw error
    }
  }

  async unlock(masterPassword: string): Promise<DecryptedVault<T>> {
    return this.runSerialized(() => this.unlockUnserialized(masterPassword))
  }

  private async unlockUnserialized(
    masterPassword: string,
    includeSerializedEnvelope = false
  ): Promise<InternalDecryptedVault<T>> {
    let fileContents: Buffer | undefined
    let salt: Buffer | undefined
    let iv: Buffer | undefined
    let authTag: Buffer | undefined
    let ciphertext: Buffer | undefined
    let aad: Buffer | undefined
    let key: Buffer | undefined

    try {
      const fileStats = await stat(this.filePath)
      if (!fileStats.isFile() || fileStats.size <= 0 || fileStats.size > MAX_VAULT_BYTES) {
        throw new VaultError('CORRUPT_VAULT')
      }

      fileContents = await readFile(this.filePath)
      let envelope: VaultEnvelopeV1
      try {
        envelope = parseEnvelope(JSON.parse(fileContents.toString('utf8')))
      } catch {
        throw new VaultError('CORRUPT_VAULT')
      }
      salt = decodeBase64(envelope.kdf.salt, SALT_LENGTH)
      iv = decodeBase64(envelope.cipher.iv, IV_LENGTH)
      authTag = decodeBase64(envelope.cipher.authTag, AUTH_TAG_LENGTH)
      ciphertext = decodeBase64(envelope.ciphertext)
      key = await deriveKey(masterPassword, salt)

      const decipher = createDecipheriv('aes-256-gcm', key, iv, {
        authTagLength: AUTH_TAG_LENGTH
      })
      aad = authenticatedMetadata(envelope)
      decipher.setAAD(aad)
      decipher.setAuthTag(authTag)
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()])

      try {
        let data: T
        try {
          data = JSON.parse(plaintext.toString('utf8')) as T
        } catch {
          throw new VaultError('CORRUPT_VAULT')
        }
        return {
          data,
          key,
          salt: Buffer.from(salt),
          serializedEnvelope: includeSerializedEnvelope ? Buffer.from(fileContents) : undefined
        }
      } finally {
        plaintext.fill(0)
      }
    } catch (error) {
      key?.fill(0)
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new VaultError('NOT_INITIALIZED')
      }
      if (error instanceof VaultError) throw error
      throw new VaultError('INVALID_MASTER_PASSWORD')
    } finally {
      fileContents?.fill(0)
      salt?.fill(0)
      iv?.fill(0)
      authTag?.fill(0)
      ciphertext?.fill(0)
      aad?.fill(0)
    }
  }

  /**
   * Opens the vault with operation-scoped key material recovered by another main-process unlock
   * mechanism. The envelope salt is bound to the supplied salt before any plaintext is returned.
   * Caller-owned buffers are never retained or modified.
   */
  async unlockWithKey(vaultKey: Buffer, expectedSalt: Buffer): Promise<DecryptedVault<T>> {
    return this.runSerialized(() => this.unlockWithKeyUnserialized(vaultKey, expectedSalt))
  }

  private async unlockWithKeyUnserialized(
    vaultKey: Buffer,
    expectedSalt: Buffer
  ): Promise<DecryptedVault<T>> {
    if (vaultKey.length !== KEY_LENGTH || expectedSalt.length !== SALT_LENGTH) {
      throw new VaultError('INTERNAL_ERROR')
    }

    let operationKey: Buffer | undefined
    let operationExpectedSalt: Buffer | undefined
    let fileContents: Buffer | undefined
    let envelopeSalt: Buffer | undefined
    let iv: Buffer | undefined
    let authTag: Buffer | undefined
    let ciphertext: Buffer | undefined
    let aad: Buffer | undefined

    try {
      operationKey = Buffer.from(vaultKey)
      operationExpectedSalt = Buffer.from(expectedSalt)
      const fileStats = await stat(this.filePath)
      if (!fileStats.isFile() || fileStats.size <= 0 || fileStats.size > MAX_VAULT_BYTES) {
        throw new VaultError('CORRUPT_VAULT')
      }

      fileContents = await readFile(this.filePath)
      let envelope: VaultEnvelopeV1
      try {
        envelope = parseEnvelope(JSON.parse(fileContents.toString('utf8')))
      } catch {
        throw new VaultError('CORRUPT_VAULT')
      }
      envelopeSalt = decodeBase64(envelope.kdf.salt, SALT_LENGTH)
      if (!timingSafeEqual(envelopeSalt, operationExpectedSalt)) {
        throw new VaultError('CORRUPT_VAULT')
      }
      iv = decodeBase64(envelope.cipher.iv, IV_LENGTH)
      authTag = decodeBase64(envelope.cipher.authTag, AUTH_TAG_LENGTH)
      ciphertext = decodeBase64(envelope.ciphertext)

      const decipher = createDecipheriv('aes-256-gcm', operationKey, iv, {
        authTagLength: AUTH_TAG_LENGTH
      })
      aad = authenticatedMetadata(envelope)
      decipher.setAAD(aad)
      decipher.setAuthTag(authTag)
      let plaintext: Buffer | undefined
      try {
        plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()])
        let data: T
        try {
          data = JSON.parse(plaintext.toString('utf8')) as T
        } catch {
          throw new VaultError('CORRUPT_VAULT')
        }
        return {
          data,
          key: Buffer.from(operationKey),
          salt: Buffer.from(envelopeSalt)
        }
      } finally {
        plaintext?.fill(0)
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new VaultError('NOT_INITIALIZED')
      }
      if (error instanceof VaultError) throw error
      throw new VaultError('CORRUPT_VAULT')
    } finally {
      operationKey?.fill(0)
      operationExpectedSalt?.fill(0)
      fileContents?.fill(0)
      envelopeSalt?.fill(0)
      iv?.fill(0)
      authTag?.fill(0)
      ciphertext?.fill(0)
      aad?.fill(0)
    }
  }

  async verifyMasterPassword(
    candidate: string,
    currentKey: Buffer,
    salt: Buffer
  ): Promise<boolean> {
    return this.runSerialized(() =>
      this.verifyMasterPasswordUnserialized(candidate, currentKey, salt)
    )
  }

  private async verifyMasterPasswordUnserialized(
    candidate: string,
    currentKey: Buffer,
    salt: Buffer
  ): Promise<boolean> {
    if (currentKey.length !== KEY_LENGTH || salt.length !== SALT_LENGTH) {
      throw new VaultError('INTERNAL_ERROR')
    }

    let derivedKey: Buffer | undefined
    try {
      derivedKey = await deriveKey(candidate, salt)
      return timingSafeEqual(derivedKey, currentKey)
    } finally {
      derivedKey?.fill(0)
    }
  }

  async write(data: T, key: Buffer, salt: Buffer): Promise<void> {
    return this.runSerialized(() => this.writeBoundUnserialized(data, key, salt))
  }

  private async writeBoundUnserialized(data: T, key: Buffer, salt: Buffer): Promise<void> {
    let currentContents: Buffer | undefined
    let envelopeSalt: Buffer | undefined
    try {
      const fileStats = await stat(this.filePath)
      if (!fileStats.isFile() || fileStats.size <= 0 || fileStats.size > MAX_VAULT_BYTES) {
        throw new VaultError('CORRUPT_VAULT')
      }
      currentContents = await readFile(this.filePath)
      let envelope: VaultEnvelopeV1
      try {
        envelope = parseEnvelope(JSON.parse(currentContents.toString('utf8')))
      } catch {
        throw new VaultError('CORRUPT_VAULT')
      }
      envelopeSalt = decodeBase64(envelope.kdf.salt, SALT_LENGTH)
      if (salt.length !== SALT_LENGTH || !timingSafeEqual(envelopeSalt, salt)) {
        throw new VaultError('CORRUPT_VAULT')
      }
      await this.writeUnserialized(data, key, salt, currentContents)
    } finally {
      currentContents?.fill(0)
      envelopeSalt?.fill(0)
    }
  }

  /**
   * Re-encrypts the local envelope with a fresh salt and password-derived key. This intentionally
   * does not rotate or mutate any Bitwarden account encryption key contained in the plaintext.
   */
  async rekey(currentPassword: string, newPassword: string): Promise<VaultKeyMaterial> {
    return this.runSerialized(() => this.rekeyUnserialized(currentPassword, newPassword))
  }

  private async rekeyUnserialized(
    currentPassword: string,
    newPassword: string
  ): Promise<VaultKeyMaterial> {
    if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
      throw new VaultError('INVALID_INPUT')
    }
    const normalizedCurrentPassword = currentPassword.normalize('NFC')
    const normalizedNewPassword = newPassword.normalize('NFC')
    if (
      normalizedCurrentPassword.length === 0 ||
      normalizedNewPassword.length < MIN_MASTER_PASSWORD_LENGTH ||
      Buffer.byteLength(normalizedCurrentPassword, 'utf8') > MAX_MASTER_PASSWORD_BYTES ||
      Buffer.byteLength(normalizedNewPassword, 'utf8') > MAX_MASTER_PASSWORD_BYTES ||
      normalizedNewPassword === normalizedCurrentPassword
    ) {
      throw new VaultError('INVALID_INPUT')
    }

    let unlocked: InternalDecryptedVault<T> | undefined
    let newSalt: Buffer | undefined
    let newKey: Buffer | undefined
    try {
      unlocked = await this.unlockUnserialized(normalizedCurrentPassword, true)
      if (!unlocked.serializedEnvelope) throw new VaultError('INTERNAL_ERROR')

      do {
        newSalt?.fill(0)
        newKey?.fill(0)
        newSalt = randomBytes(SALT_LENGTH)
        newKey = await deriveKey(normalizedNewPassword, newSalt)
      } while (timingSafeEqual(newSalt, unlocked.salt) || timingSafeEqual(newKey, unlocked.key))
      await this.writeUnserialized(unlocked.data, newKey, newSalt, unlocked.serializedEnvelope)

      const result = { key: newKey, salt: newSalt }
      newKey = undefined
      newSalt = undefined
      return result
    } finally {
      unlocked?.key.fill(0)
      unlocked?.salt.fill(0)
      unlocked?.serializedEnvelope?.fill(0)
      newKey?.fill(0)
      newSalt?.fill(0)
    }
  }

  private async writeUnserialized(
    data: T,
    key: Buffer,
    salt: Buffer,
    expectedCurrentContents?: Buffer
  ): Promise<void> {
    if (key.length !== KEY_LENGTH || salt.length !== SALT_LENGTH) {
      throw new VaultError('INTERNAL_ERROR')
    }

    // Keep an operation-local copy so synchronous disposal cannot turn an in-flight
    // atomic write into a valid file encrypted with an all-zero key.
    const operationKey = Buffer.from(key)
    const operationSalt = Buffer.from(salt)

    try {
      const directory = dirname(this.filePath)
      await mkdir(directory, { recursive: true, mode: 0o700 })

      const iv = randomBytes(IV_LENGTH)
      const envelope: VaultEnvelopeV1 = {
        format: FORMAT,
        version: ENVELOPE_VERSION,
        kdf: {
          name: 'scrypt',
          salt: operationSalt.toString('base64'),
          N: SCRYPT_PARAMETERS.N,
          r: SCRYPT_PARAMETERS.r,
          p: SCRYPT_PARAMETERS.p,
          keyLength: KEY_LENGTH
        },
        cipher: {
          name: 'aes-256-gcm',
          iv: iv.toString('base64'),
          authTag: ''
        },
        ciphertext: ''
      }
      const plaintext = Buffer.from(JSON.stringify(data), 'utf8')
      let encrypted: Buffer | undefined
      let aad: Buffer | undefined
      let authTag: Buffer | undefined

      try {
        const cipher = createCipheriv('aes-256-gcm', operationKey, iv, {
          authTagLength: AUTH_TAG_LENGTH
        })
        aad = authenticatedMetadata(envelope)
        cipher.setAAD(aad)
        encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()])
        authTag = cipher.getAuthTag()
        envelope.cipher.authTag = authTag.toString('base64')
        envelope.ciphertext = encrypted.toString('base64')
        await this.atomicWrite(`${JSON.stringify(envelope)}\n`, expectedCurrentContents)
      } finally {
        plaintext.fill(0)
        encrypted?.fill(0)
        aad?.fill(0)
        authTag?.fill(0)
        iv.fill(0)
      }
    } finally {
      operationKey.fill(0)
      operationSalt.fill(0)
    }
  }

  private async atomicWrite(contents: string, expectedCurrentContents?: Buffer): Promise<void> {
    const directory = dirname(this.filePath)
    const temporaryNameEntropy = randomBytes(8)
    const temporaryPath = `${this.filePath}.${process.pid}.${temporaryNameEntropy.toString('hex')}.tmp`
    temporaryNameEntropy.fill(0)
    let handle: Awaited<ReturnType<typeof open>> | undefined

    try {
      handle = await open(temporaryPath, 'wx', 0o600)
      await this.options.atomicWriteHook?.('before-temporary-write', {
        temporaryPath,
        destinationPath: this.filePath
      })
      await handle.writeFile(contents, { encoding: 'utf8' })
      await handle.sync()
      await handle.close()
      handle = undefined
      await this.options.atomicWriteHook?.('before-rename', {
        temporaryPath,
        destinationPath: this.filePath
      })
      if (expectedCurrentContents) {
        const currentContents = await readFile(this.filePath)
        try {
          if (
            currentContents.length !== expectedCurrentContents.length ||
            !timingSafeEqual(currentContents, expectedCurrentContents)
          ) {
            throw new VaultError('CORRUPT_VAULT')
          }
        } finally {
          currentContents.fill(0)
        }
      }
      // Rename is the commit point and the final operation whose failure is propagated. Directory
      // durability is attempted below, but an unsupported/failed directory fsync cannot be reported
      // as a failed rekey because the old destination can no longer be restored safely.
      await rename(temporaryPath, this.filePath)
      await syncDirectory(directory)
      try {
        await this.options.afterAtomicCommit?.()
      } catch {
        // The vault rename is committed. A post-commit cleanup failure must not be reported as a
        // failed initialize/rekey because the caller cannot safely retry it as if no write happened.
      }
    } catch (error) {
      await handle?.close().catch(() => undefined)
      await unlink(temporaryPath).catch(() => undefined)
      throw error
    }
  }

  private runSerialized<R>(operation: () => Promise<R>): Promise<R> {
    const result = this.operationTail.then(operation, operation)
    this.operationTail = result.then(
      () => undefined,
      () => undefined
    )
    return result
  }
}
