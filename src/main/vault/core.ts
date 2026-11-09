import { AsyncLocalStorage } from 'node:async_hooks'
import type { VaultStatus } from '../../shared/vault-contract'
import { deriveImageCacheKeys, type ImageCacheKeys } from '../encrypted-image-cache'
import type { EncryptedVaultStore } from '../encrypted-vault-store'
import { isRecord } from '../validation-primitives'
import { VaultError } from '../vault-errors'
import { DATA_VERSION, MAX_MASTER_PASSWORD_LENGTH } from './limits'
import { assertUuid } from './parse-primitives'
import { assertNoPendingPersonalVaultPurge } from './sync-data-parsing'
import type { VaultData } from './types'
import { cloneData, parseVaultData, parseVaultDataTagged } from './vault-data-parsing'

/**
 * Per-session runtime state a domain module owns. The core runs these hooks so every module is
 * torn down by the same lock, dispose and failed-unlock paths.
 */
export interface VaultSessionResource {
  /** Stops in-flight background work. Runs when lock starts and on every teardown. */
  readonly abort?: () => void
  /** Drops per-session runtime state. Runs on teardown, after every `abort`. */
  readonly clear?: () => void
  /** Drops state bound to the session key material. Runs whenever the session is discarded. */
  readonly discard?: () => void
}

export interface VaultCoreOptions {
  readonly now: () => Date
  readonly createId: () => string
}

/**
 * Owns the unlocked vault: key material, the committed snapshot, the generation that every lock
 * advances, and the re-entrant mutex. It is the only writer of that state; domain modules read
 * through `requireData` and replace the snapshot through `commit`.
 */
export class VaultCore {
  private key: Buffer | null = null
  private salt: Buffer | null = null
  private data: VaultData | null = null
  /** Blocks lock-free committed-snapshot reads before unlock and as soon as lock starts. */
  private fastReadsBlocked = true
  private currentGeneration = 0
  private operationQueue: Promise<void> = Promise.resolve()
  /** Marks the mutex holder and records the generation its operation started in. */
  private readonly exclusiveContext = new AsyncLocalStorage<{
    active: boolean
    generation: number
  }>()
  private readonly resources: VaultSessionResource[] = []
  readonly now: () => Date
  private readonly createId: () => string

  constructor(
    private readonly store: EncryptedVaultStore<unknown>,
    options: VaultCoreOptions
  ) {
    this.now = options.now
    this.createId = options.createId
  }

  get generation(): number {
    return this.currentGeneration
  }

  registerResource(resource: VaultSessionResource): void {
    this.resources.push(resource)
  }

  async exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const inherited = this.exclusiveContext.getStore()
    if (inherited?.active) return operation()
    const previous = this.operationQueue
    let release!: () => void
    this.operationQueue = new Promise<void>((resolve) => {
      release = resolve
    })
    await previous
    const context = { active: true, generation: this.currentGeneration }
    try {
      return await this.exclusiveContext.run(context, operation)
    } finally {
      context.active = false
      release()
    }
  }

  /**
   * The only path that replaces the committed snapshot: validates, encrypts and writes `next`,
   * then installs it. Throws `LOCKED` when the vault was locked after `generation` was captured
   * (by default, when the current exclusive operation started); the write is kept.
   */
  async commit(next: VaultData, generation = this.operationGeneration()): Promise<void> {
    if (!this.key || !this.salt) throw new VaultError('LOCKED')
    // Never persist data the read path would reject: a write-time bug must fail the current
    // operation loudly instead of locking the user out of the vault at the next unlock.
    parseVaultData(next)
    await this.store.write(next, this.key, this.salt)
    // Memory must match disk once the write landed. Operations queued ahead of lock()'s teardown
    // still read this snapshot, and rebuilding from an older one would overwrite this write.
    // dispose() has already torn the session down, so nothing may be reinstalled after it.
    if (this.key && this.salt) this.data = next
    if (generation !== this.currentGeneration) throw new VaultError('LOCKED')
  }

  mutate<T>(mutation: (data: VaultData, now: string) => T): Promise<T> {
    return this.exclusive(async () => {
      const next = cloneData(this.requireData())
      assertNoPendingPersonalVaultPurge(next.sync)
      const now = this.nowIso()
      const result = mutation(next, now)
      next.updatedAt = now
      await this.commit(next)
      return result
    })
  }

  private operationGeneration(): number {
    const context = this.exclusiveContext.getStore()
    if (!context?.active) throw new VaultError('INTERNAL_ERROR')
    return context.generation
  }

  isUnlocked(): boolean {
    return this.data !== null && this.key !== null && this.salt !== null
  }

  /** The committed snapshot, or `null` while locked. Prefer `requireData` inside operations. */
  currentData(): VaultData | null {
    return this.data
  }

  requireData(): VaultData {
    if (!this.data || !this.key || !this.salt) throw new VaultError('LOCKED')
    return this.data
  }

  requireFastReadData(): VaultData {
    if (this.fastReadsBlocked) throw new VaultError('LOCKED')
    return this.requireData()
  }

  async currentStatus(): Promise<VaultStatus> {
    if (this.isUnlocked()) return { state: 'unlocked' }
    return { state: (await this.store.exists()) ? 'locked' : 'uninitialized' }
  }

  /**
   * Borrows the session key material. Callers must neither retain nor zero the buffers; they are
   * replaced by `replaceKeyMaterial` and zeroed when the session is discarded.
   */
  keyMaterial(): { key: Buffer; salt: Buffer } {
    if (!this.key || !this.salt) throw new VaultError('LOCKED')
    return { key: this.key, salt: this.salt }
  }

  /**
   * Re-keys the vault file from `currentPassword` to `newPassword` and installs the new key
   * material. A vault that already opens with `newPassword` is left as is, so a master password
   * change interrupted after the local re-key resumes without re-keying twice.
   */
  async rekey(currentPassword: string, newPassword: string): Promise<void> {
    if (!this.key || !this.salt) throw new VaultError('LOCKED')
    const alreadyRekeyed = await this.store.verifyMasterPassword(newPassword, this.key, this.salt)
    if (alreadyRekeyed) return
    const stillUsesCurrent = await this.store.verifyMasterPassword(
      currentPassword,
      this.key,
      this.salt
    )
    if (!stillUsesCurrent) throw new VaultError('INVALID_MASTER_PASSWORD')
    const replacement = await this.store.rekey(currentPassword, newPassword)
    const oldKey = this.key
    const oldSalt = this.salt
    this.key = replacement.key
    this.salt = replacement.salt
    oldKey.fill(0)
    oldSalt.fill(0)
  }

  /** Checks a candidate against the open vault without throwing for a wrong password. */
  async verifyMasterPassword(candidate: string): Promise<boolean> {
    const generation = this.currentGeneration
    if (!this.key || !this.salt) throw new VaultError('LOCKED')
    const valid = await this.store.verifyMasterPassword(candidate, this.key, this.salt)
    if (generation !== this.currentGeneration) throw new VaultError('LOCKED')
    return valid
  }

  async assertMasterPassword(candidateValue: unknown): Promise<void> {
    if (typeof candidateValue !== 'string') throw new VaultError('INVALID_MASTER_PASSWORD')
    const candidate = candidateValue.normalize('NFC')
    if (candidate.length === 0 || candidate.length > MAX_MASTER_PASSWORD_LENGTH) {
      throw new VaultError('INVALID_MASTER_PASSWORD')
    }
    if (!(await this.verifyMasterPassword(candidate))) {
      throw new VaultError('INVALID_MASTER_PASSWORD')
    }
  }

  /**
   * Derives per-operation image cache subkeys from the unlocked vault key. Callers must zero the
   * result with `clearImageCacheKeys`, and must re-check `generation` before every cache write.
   */
  imageCacheKeys(): ImageCacheKeys | null {
    if (!this.key || !this.salt || this.fastReadsBlocked) return null
    return deriveImageCacheKeys(this.key, this.salt)
  }

  /**
   * The shared unlock transition. Takes ownership of `unlocked.key` and `unlocked.salt`: they
   * become the session key material, or are zeroed when the unlock fails. `validate` runs on the
   * parsed vault before anything is installed; `afterInstall` runs once it is installed and before
   * fast reads open, and a failure there discards the session.
   */
  async install(
    unlocked: { data: unknown; key: Buffer; salt: Buffer },
    generation: number,
    options: {
      validate?: (data: VaultData) => void
      afterInstall?: (requiresMigration: boolean) => Promise<void>
    } = {}
  ): Promise<VaultStatus> {
    let installed = false
    try {
      if (generation !== this.currentGeneration) throw new VaultError('LOCKED')
      const requiresMigration = isRecord(unlocked.data) && unlocked.data.version !== DATA_VERSION
      const data = parseVaultDataTagged(unlocked.data)
      options.validate?.(data)
      this.data = data
      this.key = unlocked.key
      this.salt = unlocked.salt
      installed = true
      await options.afterInstall?.(requiresMigration)
      this.fastReadsBlocked = false
      return { state: 'unlocked' }
    } catch (error) {
      if (installed) {
        this.discardSession()
      } else {
        unlocked.key.fill(0)
        unlocked.salt.fill(0)
      }
      throw error
    }
  }

  /** Advances the generation so every operation that captured the previous one fails `LOCKED`. */
  advanceGeneration(): number {
    this.currentGeneration += 1
    return this.currentGeneration
  }

  /** Starts a lock: closes fast reads and invalidates in-flight work before the mutex drains. */
  beginLock(): void {
    this.fastReadsBlocked = true
    this.advanceGeneration()
    this.abortBackgroundOperations()
  }

  /** Aborts every in-flight background operation registered by a session resource. */
  abortBackgroundOperations(): void {
    for (const resource of this.resources) resource.abort?.()
  }

  /** Tears the unlocked session down: aborts background work, clears runtime state, drops keys. */
  teardown(): void {
    this.fastReadsBlocked = true
    this.abortBackgroundOperations()
    for (const resource of this.resources) resource.clear?.()
    this.discardSession()
  }

  /** Zeroes and drops the session key material and snapshot. */
  discardSession(): void {
    this.key?.fill(0)
    this.salt?.fill(0)
    this.key = null
    this.salt = null
    this.data = null
    for (const resource of this.resources) resource.discard?.()
  }

  nowIso(): string {
    const value = this.now()
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw new VaultError('INTERNAL_ERROR')
    }
    return value.toISOString()
  }

  validatedNewId(): string {
    const id = this.createId()
    assertUuid(id)
    return id
  }
}

/** The clock and id source record builders need, without the rest of the core. */
export type VaultClock = Pick<VaultCore, 'nowIso' | 'validatedNewId'>
