import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scrypt as deriveWithScrypt
} from 'node:crypto'
import { chmod, mkdir, open, readFile, rename, stat, unlink } from 'node:fs/promises'
import { dirname } from 'node:path'
import { VaultError } from './vault-errors'

const FORMAT = 'bearwarden-vault'
const ENVELOPE_VERSION = 1
const KEY_LENGTH = 32
const SALT_LENGTH = 16
const IV_LENGTH = 12
const AUTH_TAG_LENGTH = 16
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
    await directoryHandle?.close()
  }
}

export class EncryptedVaultStore<T> {
  readonly filePath: string

  constructor(filePath: string) {
    this.filePath = filePath
  }

  async exists(): Promise<boolean> {
    try {
      await stat(this.filePath)
      return true
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false
      throw error
    }
  }

  async initialize(masterPassword: string, data: T): Promise<VaultKeyMaterial> {
    if (await this.exists()) throw new VaultError('ALREADY_INITIALIZED')

    const salt = randomBytes(SALT_LENGTH)
    const key = await deriveKey(masterPassword, salt)

    try {
      await this.write(data, key, salt)
      return { key, salt }
    } catch (error) {
      key.fill(0)
      salt.fill(0)
      throw error
    }
  }

  async unlock(masterPassword: string): Promise<DecryptedVault<T>> {
    let fileContents: Buffer | undefined
    let salt: Buffer | undefined
    let iv: Buffer | undefined
    let authTag: Buffer | undefined
    let ciphertext: Buffer | undefined
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
      decipher.setAAD(authenticatedMetadata(envelope))
      decipher.setAuthTag(authTag)
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()])

      try {
        let data: T
        try {
          data = JSON.parse(plaintext.toString('utf8')) as T
        } catch {
          throw new VaultError('CORRUPT_VAULT')
        }
        return { data, key, salt: Buffer.from(salt) }
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
    }
  }

  async write(data: T, key: Buffer, salt: Buffer): Promise<void> {
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

      try {
        const cipher = createCipheriv('aes-256-gcm', operationKey, iv, {
          authTagLength: AUTH_TAG_LENGTH
        })
        cipher.setAAD(authenticatedMetadata(envelope))
        encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()])
        envelope.cipher.authTag = cipher.getAuthTag().toString('base64')
        envelope.ciphertext = encrypted.toString('base64')
        await this.atomicWrite(`${JSON.stringify(envelope)}\n`)
      } finally {
        plaintext.fill(0)
        encrypted?.fill(0)
        iv.fill(0)
      }
    } finally {
      operationKey.fill(0)
      operationSalt.fill(0)
    }
  }

  private async atomicWrite(contents: string): Promise<void> {
    const directory = dirname(this.filePath)
    const temporaryPath = `${this.filePath}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`
    let handle: Awaited<ReturnType<typeof open>> | undefined

    try {
      handle = await open(temporaryPath, 'wx', 0o600)
      await handle.writeFile(contents, { encoding: 'utf8' })
      await handle.sync()
      await handle.close()
      handle = undefined
      await rename(temporaryPath, this.filePath)
      await chmod(this.filePath, 0o600)
      await syncDirectory(directory)
    } catch (error) {
      await handle?.close()
      await unlink(temporaryPath).catch(() => undefined)
      throw error
    }
  }
}
