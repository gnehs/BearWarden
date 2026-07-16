import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scrypt as deriveWithScrypt
} from 'node:crypto'

const CAPSULE_FORMAT = 'bearwarden-pin-capsule'
const CAPSULE_VERSION = 1
const VAULT_KEY_LENGTH = 32
const VAULT_SALT_LENGTH = 16
const PAYLOAD_LENGTH = VAULT_KEY_LENGTH + VAULT_SALT_LENGTH
const KDF_SALT_LENGTH = 16
const IV_LENGTH = 12
const AUTH_TAG_LENGTH = 16
const DERIVED_KEY_LENGTH = 32
const MIN_PIN_CHARACTERS = 4
const MAX_PIN_CHARACTERS = 1_024
const MAX_PIN_BYTES = 4_096
const MAX_FAILED_ATTEMPTS = 5
const MAX_PENDING_ATTEMPTS = MAX_FAILED_ATTEMPTS

/** Fixed parameters prevent an attacker-controlled capsule from requesting unbounded resources. */
const PIN_SCRYPT_PARAMETERS = {
  N: 2 ** 17,
  r: 8,
  p: 1,
  maxmem: 256 * 1_024 * 1_024
} as const

export type PinUnlockErrorCode = 'INVALID_INPUT' | 'INVALID_PIN' | 'PIN_DISABLED' | 'RATE_LIMITED'

export class PinUnlockError extends Error {
  constructor(readonly code: PinUnlockErrorCode) {
    super(code)
    this.name = 'PinUnlockError'
  }
}

export interface PinUnlockStatus {
  available: boolean
  remainingAttempts: number
}

export interface PinVaultKeyMaterial {
  key: Buffer
  salt: Buffer
}

function pinBytes(pin: string): Buffer {
  if (typeof pin !== 'string') throw new PinUnlockError('INVALID_INPUT')
  const normalized = pin.normalize('NFC')
  if (normalized.length < MIN_PIN_CHARACTERS || normalized.length > MAX_PIN_CHARACTERS) {
    throw new PinUnlockError('INVALID_INPUT')
  }
  const bytes = Buffer.from(normalized, 'utf8')
  if (bytes.length === 0 || bytes.length > MAX_PIN_BYTES) {
    bytes.fill(0)
    throw new PinUnlockError('INVALID_INPUT')
  }
  return bytes
}

function derivePinKey(pin: Buffer, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    deriveWithScrypt(pin, salt, DERIVED_KEY_LENGTH, PIN_SCRYPT_PARAMETERS, (error, derivedKey) => {
      if (error) {
        reject(error)
        return
      }
      resolve(derivedKey)
    })
  })
}

function authenticatedMetadata(kdfSalt: Buffer, iv: Buffer): Buffer {
  return Buffer.from(
    JSON.stringify({
      format: CAPSULE_FORMAT,
      version: CAPSULE_VERSION,
      kdf: {
        name: 'scrypt',
        salt: kdfSalt.toString('base64'),
        N: PIN_SCRYPT_PARAMETERS.N,
        r: PIN_SCRYPT_PARAMETERS.r,
        p: PIN_SCRYPT_PARAMETERS.p,
        keyLength: DERIVED_KEY_LENGTH
      },
      cipher: {
        name: 'aes-256-gcm',
        iv: iv.toString('base64'),
        authTagLength: AUTH_TAG_LENGTH
      }
    }),
    'utf8'
  )
}

/**
 * Process-memory-only PIN capability. It retains only an authenticated, PIN-wrapped copy of the
 * local vault key material. No PIN, derived wrapping key, or plaintext vault key is retained.
 */
export class PinUnlockCapability {
  private failedAttempts = 0
  private pendingAttempts = 0
  private disposed = false
  private epoch = 0
  private operationTail: Promise<void> = Promise.resolve()

  private constructor(
    private readonly kdfSalt: Buffer,
    private readonly iv: Buffer,
    private readonly authTag: Buffer,
    private readonly ciphertext: Buffer
  ) {}

  static async create(
    pin: string,
    vaultKey: Buffer,
    vaultSalt: Buffer
  ): Promise<PinUnlockCapability> {
    if (vaultKey.length !== VAULT_KEY_LENGTH || vaultSalt.length !== VAULT_SALT_LENGTH) {
      throw new PinUnlockError('INVALID_INPUT')
    }

    const input = pinBytes(pin)
    let kdfSalt: Buffer | undefined
    let iv: Buffer | undefined
    let payload: Buffer | undefined
    let wrappingKey: Buffer | undefined
    let aad: Buffer | undefined
    let ciphertext: Buffer | undefined
    let authTag: Buffer | undefined

    try {
      kdfSalt = randomBytes(KDF_SALT_LENGTH)
      iv = randomBytes(IV_LENGTH)
      payload = Buffer.alloc(PAYLOAD_LENGTH)
      vaultKey.copy(payload, 0)
      vaultSalt.copy(payload, VAULT_KEY_LENGTH)
      wrappingKey = await derivePinKey(input, kdfSalt)
      aad = authenticatedMetadata(kdfSalt, iv)
      const cipher = createCipheriv('aes-256-gcm', wrappingKey, iv, {
        authTagLength: AUTH_TAG_LENGTH
      })
      cipher.setAAD(aad)
      ciphertext = Buffer.concat([cipher.update(payload), cipher.final()])
      authTag = cipher.getAuthTag()
      return new PinUnlockCapability(
        Buffer.from(kdfSalt),
        Buffer.from(iv),
        Buffer.from(authTag),
        Buffer.from(ciphertext)
      )
    } finally {
      input.fill(0)
      kdfSalt?.fill(0)
      iv?.fill(0)
      payload?.fill(0)
      wrappingKey?.fill(0)
      aad?.fill(0)
      ciphertext?.fill(0)
      authTag?.fill(0)
    }
  }

  status(): PinUnlockStatus {
    return {
      available: !this.disposed,
      remainingAttempts: this.disposed ? 0 : MAX_FAILED_ATTEMPTS - this.failedAttempts
    }
  }

  unlock(pin: string): Promise<PinVaultKeyMaterial> {
    if (this.disposed) return Promise.reject(new PinUnlockError('PIN_DISABLED'))
    if (this.pendingAttempts >= MAX_PENDING_ATTEMPTS) {
      return Promise.reject(new PinUnlockError('RATE_LIMITED'))
    }

    let input: Buffer
    try {
      input = pinBytes(pin)
    } catch (error) {
      return Promise.reject(error)
    }
    this.pendingAttempts += 1
    const operation = this.operationTail.then(() => this.performUnlock(input))
    this.operationTail = operation.then(
      () => undefined,
      () => undefined
    )
    return operation.finally(() => {
      input.fill(0)
      this.pendingAttempts -= 1
    })
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.epoch += 1
    this.failedAttempts = MAX_FAILED_ATTEMPTS
    this.kdfSalt.fill(0)
    this.iv.fill(0)
    this.authTag.fill(0)
    this.ciphertext.fill(0)
  }

  private async performUnlock(input: Buffer): Promise<PinVaultKeyMaterial> {
    if (this.disposed) throw new PinUnlockError('PIN_DISABLED')
    const operationEpoch = this.epoch
    let kdfSalt: Buffer | undefined
    let iv: Buffer | undefined
    let authTag: Buffer | undefined
    let ciphertext: Buffer | undefined
    let wrappingKey: Buffer | undefined
    let aad: Buffer | undefined
    let plaintext: Buffer | undefined

    try {
      kdfSalt = Buffer.from(this.kdfSalt)
      iv = Buffer.from(this.iv)
      authTag = Buffer.from(this.authTag)
      ciphertext = Buffer.from(this.ciphertext)
      if (
        kdfSalt.length !== KDF_SALT_LENGTH ||
        iv.length !== IV_LENGTH ||
        authTag.length !== AUTH_TAG_LENGTH ||
        ciphertext.length !== PAYLOAD_LENGTH
      ) {
        this.dispose()
        throw new PinUnlockError('PIN_DISABLED')
      }

      wrappingKey = await derivePinKey(input, kdfSalt)
      if (this.disposed || operationEpoch !== this.epoch) {
        throw new PinUnlockError('PIN_DISABLED')
      }
      aad = authenticatedMetadata(kdfSalt, iv)
      try {
        const decipher = createDecipheriv('aes-256-gcm', wrappingKey, iv, {
          authTagLength: AUTH_TAG_LENGTH
        })
        decipher.setAAD(aad)
        decipher.setAuthTag(authTag)
        plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()])
      } catch {
        this.recordFailure()
        throw new PinUnlockError(this.disposed ? 'PIN_DISABLED' : 'INVALID_PIN')
      }

      if (this.disposed || operationEpoch !== this.epoch || plaintext.length !== PAYLOAD_LENGTH) {
        this.dispose()
        throw new PinUnlockError('PIN_DISABLED')
      }

      const result = {
        key: Buffer.from(plaintext.subarray(0, VAULT_KEY_LENGTH)),
        salt: Buffer.from(plaintext.subarray(VAULT_KEY_LENGTH))
      }
      this.failedAttempts = 0
      return result
    } finally {
      kdfSalt?.fill(0)
      iv?.fill(0)
      authTag?.fill(0)
      ciphertext?.fill(0)
      wrappingKey?.fill(0)
      aad?.fill(0)
      plaintext?.fill(0)
    }
  }

  private recordFailure(): void {
    this.failedAttempts += 1
    if (this.failedAttempts >= MAX_FAILED_ATTEMPTS) this.dispose()
  }
}
