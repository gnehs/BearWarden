import type { VaultCore } from './core'
import type { VaultPinUnlockState } from './pin-unlock-state'
import type { VaultSyncSession } from './sync-session'
import type { PinUnlockStatus, VaultStatus, VaultTimeoutPolicy } from '../../shared/vault-contract'
import { BITWARDEN_POLICY_TYPE } from '../bitwarden-policy'
import { EncryptedVaultStore } from '../encrypted-vault-store'
import {
  PinUnlockCapability,
  PinUnlockError,
  type PinSyncKeyMaterial,
  type PinVaultKeyMaterial
} from '../pin-unlock'
import type { TouchIdUnlockMaterial } from '../touch-id-unlock-capsule'
import { recoverInterruptedNativeAttachmentRestore } from '../native-attachment-restore'
import { VaultError } from '../vault-errors'
import { DATA_VERSION, MAX_MASTER_PASSWORD_LENGTH } from './limits'
import { normalizeMasterPassword } from './parse-primitives'
import { cloneData } from './vault-data-parsing'
import type { VaultData } from './types'
import {
  bitwardenPolicyDecision,
  assertBitwardenPolicyDoesNotBlock,
  maximumVaultTimeoutMinutes
} from './policy'
import { assertMasterPasswordChangeAccount } from './master-password-change'

/**
 * The vault session lifecycle: setup, unlock by master password, PIN or Touch ID material, PIN
 * enrollment, lock and dispose, plus the journal recovery that runs before an unlock completes.
 */
export class VaultUnlock {
  constructor(
    private readonly core: VaultCore,
    private readonly store: EncryptedVaultStore<unknown>,
    private readonly syncSession: VaultSyncSession,
    private readonly pinUnlock: VaultPinUnlockState
  ) {}

  status(): Promise<VaultStatus> {
    return this.core.exclusive(async () => this.core.currentStatus())
  }

  /**
   * Captures the unlocked-vault epoch for short-lived main-process capabilities. Callers must
   * re-enter normal service operations afterwards; this intentionally does not hold the mutex.
   */
  unlockedGeneration(): Promise<number> {
    return this.core.exclusive(async () => {
      this.core.requireData()
      return this.core.generation
    })
  }

  /** Runs a short, main-process-only capability commit against one unlocked-vault epoch. */
  runUnlockedOperation<T>(operation: (generation: number) => Promise<T>): Promise<T> {
    return this.core.exclusive(async () => {
      this.core.requireData()
      return operation(this.core.generation)
    })
  }

  setup(masterPassword: string): Promise<VaultStatus> {
    return this.core.exclusive(async () => {
      if (await this.store.exists()) throw new VaultError('ALREADY_INITIALIZED')
      const password = normalizeMasterPassword(masterPassword)
      const now = this.core.nowIso()
      const initialData: VaultData = {
        version: DATA_VERSION,
        createdAt: now,
        updatedAt: now,
        folders: [],
        logins: [],
        organizations: [],
        collections: [],
        sharedLogins: [],
        sends: [],
        generatorHistory: [],
        sync: null,
        nativeAttachmentRestore: null,
        masterPasswordChange: null
      }
      const generation = this.core.generation
      const material = await this.store.initialize(password, initialData)
      return this.installUnlockedVault({ data: initialData, ...material }, generation)
    })
  }

  unlock(masterPassword: string): Promise<VaultStatus> {
    return this.core.exclusive(async () => {
      if (this.core.isUnlocked()) return { state: 'unlocked' }
      if (!(await this.store.exists())) throw new VaultError('NOT_INITIALIZED')
      const password = normalizeMasterPassword(masterPassword)
      const generation = this.core.generation
      const unlocked = await this.store.unlock(password)
      return this.installUnlockedVault(unlocked, generation)
    })
  }

  /**
   * Installs an unlocked vault through the core, then recovers interrupted journals. Key-material
   * unlocks pass `startSync` so the connector starts, restoring the account key when the material
   * carries one.
   */
  private installUnlockedVault(
    unlocked: { data: unknown; key: Buffer; salt: Buffer },
    generation: number,
    options: {
      validate?: (data: VaultData) => void
      startSync?: { material: PinSyncKeyMaterial | null }
    } = {}
  ): Promise<VaultStatus> {
    return this.core.install(unlocked, generation, {
      validate: options.validate,
      afterInstall: async (requiresMigration) => {
        await this.recoverNativeAttachmentRestoreAfterUnlock(requiresMigration)
        const sync = this.core.requireData().sync
        if (options.startSync && sync) {
          const { material } = options.startSync
          if (material) {
            this.syncSession.restoreSyncClient(sync, material)
          } else {
            this.syncSession.getOrCreateSyncClient(sync)
          }
        }
      }
    })
  }

  pinUnlockStatus(): PinUnlockStatus {
    const data = this.core.currentData()
    if (
      data &&
      bitwardenPolicyDecision(BITWARDEN_POLICY_TYPE.RemoveUnlockWithPin, data).state !==
        'not-applicable'
    ) {
      return { available: false, remainingAttempts: 0 }
    }
    const status = this.pinUnlock.capability?.status()
    if (!status?.available) return { available: false, remainingAttempts: 0 }
    return status
  }

  enablePinUnlock(request: { pin: string; masterPassword: string }): Promise<PinUnlockStatus> {
    const lifecycleEpoch = this.pinUnlock.epoch
    const generation = this.core.generation
    return this.core.exclusive(async () => {
      let capability: PinUnlockCapability | null = null
      let syncMaterial: PinSyncKeyMaterial | null = null
      try {
        if (generation !== this.core.generation || lifecycleEpoch !== this.pinUnlock.epoch) {
          throw new VaultError('LOCKED')
        }
        const data = this.core.requireData()
        assertBitwardenPolicyDoesNotBlock(BITWARDEN_POLICY_TYPE.RemoveUnlockWithPin, data)
        if (
          typeof request.pin !== 'string' ||
          request.pin.normalize('NFC').length < 4 ||
          request.pin.length > 1_024 ||
          typeof request.masterPassword !== 'string' ||
          request.masterPassword.length === 0 ||
          request.masterPassword.length > MAX_MASTER_PASSWORD_LENGTH
        ) {
          throw new VaultError('INVALID_INPUT')
        }
        await this.core.assertMasterPassword(request.masterPassword)
        const { key, salt } = this.core.keyMaterial()
        const client = data.sync ? this.syncSession.getOrCreateSyncClient(data.sync) : null
        syncMaterial = client?.pinUnlockMaterial?.() ?? null
        capability = await PinUnlockCapability.create(request.pin, key, salt, syncMaterial)
        if (
          generation !== this.core.generation ||
          lifecycleEpoch !== this.pinUnlock.epoch ||
          !this.core.isUnlocked()
        ) {
          throw new VaultError('LOCKED')
        }
        this.pinUnlock.install(capability)
        capability = null
        return this.pinUnlockStatus()
      } catch (error) {
        if (error instanceof PinUnlockError) throw this.mapPinUnlockError(error)
        throw error
      } finally {
        request.pin = ''
        request.masterPassword = ''
        syncMaterial?.accountKey.fill(0)
        syncMaterial?.wrappedKeyFingerprint.fill(0)
        capability?.dispose()
      }
    })
  }

  disablePinUnlock(): PinUnlockStatus {
    this.pinUnlock.invalidate()
    return this.pinUnlockStatus()
  }

  /**
   * Verifies the master password against the open vault and returns copies of the local vault
   * key and, when the connector holds one, the Bitwarden account key bound to its current
   * server-wrapped-key fingerprint. The master password itself is never part of the result.
   * Callers own the returned buffers and must zero them.
   */
  exportTouchIdUnlockMaterial(masterPassword: string): Promise<TouchIdUnlockMaterial> {
    const generation = this.core.generation
    return this.core.exclusive(async () => {
      let sync: PinSyncKeyMaterial | null = null
      try {
        if (generation !== this.core.generation) throw new VaultError('LOCKED')
        const data = this.core.requireData()
        await this.core.assertMasterPassword(masterPassword)
        if (generation !== this.core.generation || !this.core.isUnlocked()) {
          throw new VaultError('LOCKED')
        }
        const client = data.sync ? this.syncSession.getOrCreateSyncClient(data.sync) : null
        sync = client?.pinUnlockMaterial?.() ?? null
        const { key, salt } = this.core.keyMaterial()
        const material = { key: Buffer.from(key), salt: Buffer.from(salt), sync }
        sync = null
        return material
      } finally {
        sync?.accountKey.fill(0)
        sync?.wrappedKeyFingerprint.fill(0)
      }
    })
  }

  /**
   * Opens the local vault with Touch ID capsule material and restores the sync account key so
   * the connector can sync without the master password. Material that no longer matches the
   * vault key or the persisted server-wrapped-key fingerprint fails closed with
   * `TOUCH_ID_UNAVAILABLE`, which tells the caller to discard the capsule.
   */
  unlockWithTouchIdMaterial(material: TouchIdUnlockMaterial): Promise<VaultStatus> {
    const generation = this.core.generation
    return this.core.exclusive(async () => {
      if (generation !== this.core.generation) throw new VaultError('LOCKED')
      if (this.core.isUnlocked()) return { state: 'unlocked' }
      let unlocked: Awaited<ReturnType<EncryptedVaultStore<unknown>['unlockWithKey']>>
      try {
        unlocked = await this.store.unlockWithKey(material.key, material.salt)
      } catch (error) {
        if (
          error instanceof VaultError &&
          error.code === 'CORRUPT_VAULT' &&
          (error.message === 'CORRUPT_VAULT:salt-mismatch' ||
            error.message === 'CORRUPT_VAULT:decrypt')
        ) {
          // A local re-key replaces both the salt and the key; the capsule is permanently stale.
          throw new VaultError('TOUCH_ID_UNAVAILABLE', 'TOUCH_ID_UNAVAILABLE:stale-vault-key')
        }
        throw error
      }
      return this.installUnlockedVault(unlocked, generation, {
        validate: (data) => {
          const persisted = data.sync?.unlockMaterial ?? null
          if (
            material.sync &&
            persisted &&
            !material.sync.wrappedKeyFingerprint.equals(
              Buffer.from(persisted.wrappedKeyFingerprint, 'base64')
            )
          ) {
            // The account key was re-wrapped (rotation or remote password change) after Touch ID
            // was enrolled. Never restore an older account-key generation; require the password.
            throw new VaultError('TOUCH_ID_UNAVAILABLE', 'TOUCH_ID_UNAVAILABLE:stale-account-key')
          }
        },
        startSync: { material: material.sync }
      })
    })
  }

  unlockWithPin(request: { pin: string }): Promise<VaultStatus> {
    const capability = this.pinUnlock.capability
    const lifecycleEpoch = this.pinUnlock.epoch
    const generation = this.core.generation
    return this.core.exclusive(async () => {
      let material: PinVaultKeyMaterial | null = null
      try {
        if (generation !== this.core.generation || lifecycleEpoch !== this.pinUnlock.epoch) {
          throw new VaultError('LOCKED')
        }
        if (this.core.isUnlocked()) return { state: 'unlocked' }
        if (!capability?.status().available) throw new VaultError('PIN_DISABLED')
        if (
          typeof request.pin !== 'string' ||
          request.pin.length < 4 ||
          request.pin.length > 1_024
        ) {
          throw new VaultError('INVALID_INPUT')
        }
        const materialPromise = capability.unlock(request.pin)
        request.pin = ''
        material = await materialPromise
        if (
          lifecycleEpoch !== this.pinUnlock.epoch ||
          generation !== this.core.generation ||
          capability !== this.pinUnlock.capability
        ) {
          throw new VaultError('LOCKED')
        }
        const unlocked = await this.store.unlockWithKey(material.key, material.salt)
        return await this.installUnlockedVault(unlocked, generation, {
          validate: (data) => {
            if (
              lifecycleEpoch !== this.pinUnlock.epoch ||
              capability !== this.pinUnlock.capability
            ) {
              throw new VaultError('LOCKED')
            }
            assertBitwardenPolicyDoesNotBlock(BITWARDEN_POLICY_TYPE.RemoveUnlockWithPin, data)
          },
          startSync: { material: material.sync }
        })
      } catch (error) {
        if (error instanceof PinUnlockError) {
          if (capability && !capability.status().available) this.pinUnlock.forget(capability)
          throw this.mapPinUnlockError(error)
        }
        this.core.discardSession()
        throw error
      } finally {
        request.pin = ''
        material?.key.fill(0)
        material?.salt.fill(0)
        material?.sync?.accountKey.fill(0)
        material?.sync?.wrappedKeyFingerprint.fill(0)
      }
    })
  }

  lock(): Promise<VaultStatus> {
    this.core.beginLock()
    return this.core.exclusive(async () => {
      try {
        await this.syncSession.syncClient?.lock()
      } catch {
        // Local vault locking must never depend on the remote connector.
      }
      this.core.teardown()
      return this.core.currentStatus()
    })
  }

  dispose(): void {
    this.core.advanceGeneration()
    this.pinUnlock.invalidate()
    this.core.teardown()
  }

  async constrainVaultTimeoutPolicy(requested: VaultTimeoutPolicy): Promise<VaultTimeoutPolicy> {
    return this.core.exclusive(async () => {
      const data = this.core.currentData()
      if (!data) return requested
      const decision = bitwardenPolicyDecision(BITWARDEN_POLICY_TYPE.MaximumVaultTimeout, data)
      if (decision.state === 'not-applicable') return requested
      if (decision.state === 'fail-closed') return { type: 'appInactivity', minutes: 1 }
      const maximum = maximumVaultTimeoutMinutes(decision.policies)
      return requested.type === 'appInactivity' && requested.minutes <= maximum
        ? requested
        : { type: 'appInactivity', minutes: maximum }
    })
  }

  private async recoverNativeAttachmentRestoreAfterUnlock(
    requiresMigration: boolean
  ): Promise<void> {
    const current = this.core.requireData()
    assertMasterPasswordChangeAccount(current)
    const interrupted = current.nativeAttachmentRestore?.attachments.some(
      (attachment) => attachment.status === 'attempting'
    )
    const completedPasswordChange = current.masterPasswordChange?.phase === 'local-rekeyed'
    const preparedPurge = current.sync?.pendingPersonalVaultPurge?.phase === 'prepared'
    if (!requiresMigration && !interrupted && !completedPasswordChange && !preparedPurge) return
    const next = cloneData(current)
    if (interrupted && next.nativeAttachmentRestore) {
      next.nativeAttachmentRestore = recoverInterruptedNativeAttachmentRestore(
        next.nativeAttachmentRestore,
        this.core.nowIso()
      )
      next.updatedAt = next.nativeAttachmentRestore.updatedAt
    }
    if (completedPasswordChange) {
      next.masterPasswordChange = null
      if (next.sync) next.sync.state.session = null
      next.updatedAt = this.core.nowIso()
    }
    if (preparedPurge && next.sync) {
      next.sync.pendingPersonalVaultPurge = null
      next.updatedAt = this.core.nowIso()
    }
    await this.core.commit(next)
  }

  private mapPinUnlockError(error: PinUnlockError): VaultError {
    if (error.code === 'INVALID_INPUT') return new VaultError('INVALID_INPUT')
    if (error.code === 'INVALID_PIN') return new VaultError('INVALID_PIN')
    if (error.code === 'RATE_LIMITED') return new VaultError('RATE_LIMITED')
    return new VaultError('PIN_DISABLED')
  }
}
