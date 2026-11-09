import { randomInt as nodeRandomInt, randomUUID } from 'node:crypto'
import type { VaultTimeoutPolicy, VaultStatus } from '../shared/vault-contract'
import { BitwardenDirectError, type BitwardenSyncClient } from './bitwarden-direct'
import { BITWARDEN_POLICY_TYPE } from './bitwarden-policy'
import { EncryptedVaultStore } from './encrypted-vault-store'
import { type EncryptedImageCache } from './encrypted-image-cache'
import {
  PinUnlockCapability,
  PinUnlockError,
  type PinSyncKeyMaterial,
  type PinVaultKeyMaterial
} from './pin-unlock'
import type { TouchIdUnlockMaterial } from './touch-id-unlock-capsule'
import { recoverInterruptedNativeAttachmentRestore } from './native-attachment-restore'
import { VaultError } from './vault-errors'
import type { VaultAttachmentFileService } from './vault-attachment-files'
import { DATA_VERSION, MAX_MASTER_PASSWORD_LENGTH, MAX_USERNAME_LENGTH } from './vault/limits'
import {
  normalizeRequiredString,
  normalizeMasterPassword,
  normalizeSyncPassword
} from './vault/parse-primitives'
import { cloneData } from './vault/vault-data-parsing'
import { assertNoPendingPersonalVaultPurge } from './vault/sync-data-parsing'
import { VaultGeneratorService } from './vault/generator-service'
import { VaultSendService } from './vault/send-service'
import { VaultCore } from './vault/core'
import { cloneGeneratorHistory } from './vault/generator-history'
import type {
  PersistedSyncData,
  VaultData,
  VaultMasterPasswordChangeStatus,
  VaultMasterPasswordChangeRequest,
  VaultMasterPasswordChangeResolutionRequest,
  VaultMasterPasswordChangeResolution,
  VaultPlatform,
  VaultAccountWebAuthnAssertionRequester,
  VaultAccountWebAuthnRegistrationRequester,
  VaultServiceOptions
} from './vault/types'
import {
  currentBitwardenPolicySet,
  bitwardenPolicyDecision,
  assertBitwardenPolicyDoesNotBlock,
  assertSendMutationAllowed,
  maximumVaultTimeoutMinutes
} from './vault/policy'
import { VaultSyncSession } from './vault/sync-session'
import { VaultFolders } from './vault/folders'
import { VaultHealth } from './vault/health'
import { VaultListings } from './vault/listings'
import { VaultPasswordHistory } from './vault/password-history-service'
import {
  masterPasswordChangeAccountFingerprint,
  assertMasterPasswordChangeAccount
} from './vault/master-password-change'
import { VaultAttachments } from './vault/attachments'
import { VaultPortability } from './vault/portability'
import { VaultSharedItems } from './vault/shared-items'
import { VaultItemAuthorization } from './vault/item-authorization'
import { VaultItems } from './vault/items'
import { VaultIntegrations } from './vault/integrations'
import { VaultWebsiteIcons } from './vault/website-icons'
import { VaultAccountSecurity } from './vault/account-security'
import { VaultPinUnlockState } from './vault/pin-unlock-state'
import { VaultSyncEngine } from './vault/sync-engine'

/**
 * Owns the vault's mutable runtime state, persistence transaction boundary, and sync engine.
 * Feature layers extend this class so every operation shares one mutex, generation, and cleanup
 * lifecycle; this module must never import a higher service layer.
 */
export class VaultServiceBase {
  protected readonly generatorService: VaultGeneratorService
  protected readonly sendService: VaultSendService
  protected readonly createSyncClient: (sync: PersistedSyncData) => BitwardenSyncClient
  protected readonly fetch: typeof fetch
  protected readonly attachmentFiles: VaultAttachmentFileService | null
  protected readonly requestAccountWebAuthnAssertion: VaultAccountWebAuthnAssertionRequester | null
  protected readonly requestAccountWebAuthnRegistration: VaultAccountWebAuthnRegistrationRequester | null
  protected readonly imageCache: EncryptedImageCache | null
  protected readonly core: VaultCore
  protected readonly syncSession: VaultSyncSession
  protected readonly folders: VaultFolders
  protected readonly health: VaultHealth
  protected readonly listings: VaultListings
  protected readonly passwordHistory: VaultPasswordHistory
  protected readonly attachments: VaultAttachments
  protected readonly portability: VaultPortability
  protected readonly sharedItems: VaultSharedItems
  protected readonly authorization: VaultItemAuthorization
  protected readonly items: VaultItems
  protected readonly integrations: VaultIntegrations
  protected readonly websiteIcons: VaultWebsiteIcons
  protected readonly accountSecurity: VaultAccountSecurity
  protected readonly pinUnlock: VaultPinUnlockState
  protected readonly syncEngine: VaultSyncEngine

  constructor(
    protected readonly store: EncryptedVaultStore<unknown>,
    protected readonly platform: VaultPlatform,
    options: VaultServiceOptions = {}
  ) {
    this.core = new VaultCore(store, {
      now: options.now ?? (() => new Date()),
      createId: options.createId ?? randomUUID
    })
    this.core.registerResource({
      clear: () => {
        this.generatorService.clearRuntimeState()
      }
    })
    this.fetch = options.fetch ?? fetch
    this.attachmentFiles = options.attachmentFiles ?? null
    this.imageCache = options.imageCache ?? null
    this.requestAccountWebAuthnAssertion = options.requestAccountWebAuthnAssertion ?? null
    this.requestAccountWebAuthnRegistration = options.requestAccountWebAuthnRegistration ?? null
    this.createSyncClient =
      options.createSyncClient ??
      (() => {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      })
    this.generatorService = new VaultGeneratorService({
      now: this.core.now,
      createId: options.createId ?? randomUUID,
      randomInt: options.randomInt ?? nodeRandomInt,
      copyText: (text) => this.platform.copyText(text),
      exclusive: (operation) => this.core.exclusive(operation),
      assertUnlocked: () => {
        this.core.requireData()
      },
      readPolicySet: () => currentBitwardenPolicySet(this.core.requireData()),
      readHistory: () => this.core.requireData().generatorHistory,
      commitHistory: async (history) => {
        const current = this.core.requireData()
        const next = cloneData(current)
        next.generatorHistory = cloneGeneratorHistory(history)
        next.updatedAt = this.core.nowIso()
        await this.core.commit(next)
      }
    })
    this.sendService = new VaultSendService({
      attachmentFiles: this.attachmentFiles,
      exclusive: (operation) => this.core.exclusive(operation),
      readData: () => this.core.requireData(),
      requireSyncData: () => this.syncSession.requireSyncData(),
      getSyncClient: (sync) => this.syncSession.getOrCreateSyncClient(sync),
      currentGeneration: () => this.core.generation,
      startSyncOperation: () => this.syncSession.startSyncOperation(),
      finishSyncOperation: (abort) => this.syncSession.finishSyncOperation(abort),
      commitData: (data, generation) => this.core.commit(data, generation),
      nowIso: () => this.core.nowIso(),
      clearSyncError: () => this.syncSession.clearSyncErrorState(),
      mapSyncError: (error) => this.syncSession.mapSyncError(error),
      copyText: (text) => this.platform.copyText(text),
      assertMutationAllowed: () => assertSendMutationAllowed(this.core.requireData())
    })
    this.syncSession = new VaultSyncSession(
      this.core,
      this.createSyncClient,
      this.requestAccountWebAuthnAssertion
    )
    this.folders = new VaultFolders(this.core)
    this.health = new VaultHealth(this.core, this.syncSession, this.platform, this.fetch)
    this.listings = new VaultListings(this.core, this.syncSession)
    this.passwordHistory = new VaultPasswordHistory(this.core, this.platform)
    this.attachments = new VaultAttachments(
      this.core,
      this.syncSession,
      this.attachmentFiles,
      this.imageCache
    )
    this.portability = new VaultPortability(this.core, this.syncSession, {
      performSync: (data, client, signal) => this.syncEngine.performSync(data, client, signal)
    })
    this.sharedItems = new VaultSharedItems(this.core, this.syncSession, this.platform)
    this.authorization = new VaultItemAuthorization(this.core)
    this.items = new VaultItems(this.core, this.platform)
    this.integrations = new VaultIntegrations(this.core, this.authorization)
    this.websiteIcons = new VaultWebsiteIcons(this.core, this.fetch, this.imageCache)
    this.accountSecurity = new VaultAccountSecurity(
      this.core,
      this.syncSession,
      this.health,
      this.platform,
      this.requestAccountWebAuthnRegistration
    )
    this.pinUnlock = new VaultPinUnlockState()
    this.syncEngine = new VaultSyncEngine(this.core, this.syncSession, this.pinUnlock)
  }

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
  protected installUnlockedVault(
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

  pinUnlockStatus(): import('../shared/vault-contract').PinUnlockStatus {
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

  enablePinUnlock(request: {
    pin: string
    masterPassword: string
  }): Promise<import('../shared/vault-contract').PinUnlockStatus> {
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

  disablePinUnlock(): import('../shared/vault-contract').PinUnlockStatus {
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

  masterPasswordChangeStatus(): Promise<VaultMasterPasswordChangeStatus> {
    return this.core.exclusive(async () => {
      const data = this.core.requireData()
      assertMasterPasswordChangeAccount(data)
      const journal = data.masterPasswordChange
      return {
        phase: journal?.phase ?? null,
        needsReconnect: false,
        needsRemoteVerification: journal?.phase === 'prepared'
      }
    })
  }

  changeMasterPassword(request: VaultMasterPasswordChangeRequest): Promise<void> {
    return this.core.exclusive(async () => {
      let currentPassword = ''
      let newPassword = ''
      let remoteRequest:
        | { currentPassword: string; newPassword: string; hint: string | null; signal: AbortSignal }
        | undefined
      let abort: AbortController | undefined
      try {
        currentPassword = normalizeMasterPassword(request.currentPassword)
        newPassword = normalizeMasterPassword(request.newPassword)
        if (currentPassword === newPassword) throw new VaultError('INVALID_INPUT')
        const hint = request.hint ?? null
        if (hint !== null && (typeof hint !== 'string' || hint.length > 50)) {
          throw new VaultError('INVALID_INPUT')
        }
        const current = this.core.requireData()
        assertNoPendingPersonalVaultPurge(current.sync)
        assertMasterPasswordChangeAccount(current)
        const existing = current.masterPasswordChange
        if (existing?.phase === 'prepared') {
          // A prepared mutation has an ambiguous remote outcome. Resolution must use the separate,
          // non-mutating password-proof API and must never replay the mutation.
          throw new VaultError('SYNC_FAILED')
        }
        if (existing?.phase === 'local-rekeyed') {
          await this.finishMasterPasswordChange(currentPassword, newPassword)
          return
        }

        if (!existing) {
          const sync = this.syncSession.requireSyncData()
          const client = this.syncSession.getOrCreateSyncClient(sync)
          if (!client.changeMasterPassword) throw new VaultError('SYNC_FAILED')
          const now = this.core.nowIso()
          const prepared = cloneData(current)
          prepared.masterPasswordChange = {
            phase: 'prepared',
            startedAt: now,
            updatedAt: now,
            accountFingerprint: masterPasswordChangeAccountFingerprint(sync)
          }
          prepared.updatedAt = now
          await this.core.commit(prepared)

          abort = this.syncSession.startSyncOperation()
          remoteRequest = { currentPassword, newPassword, hint, signal: abort.signal }
          try {
            await client.changeMasterPassword(remoteRequest)
          } catch (error) {
            if (
              error instanceof BitwardenDirectError &&
              error.code === 'MASTER_PASSWORD_CHANGE_UNKNOWN'
            ) {
              this.core.advanceGeneration()
              this.pinUnlock.invalidate()
              this.syncSession.dropSyncClient()
              this.core.teardown()
              throw new VaultError('SYNC_FAILED')
            }
            const cleared = cloneData(this.core.requireData())
            cleared.masterPasswordChange = null
            cleared.updatedAt = this.core.nowIso()
            await this.core.commit(cleared)
            throw this.syncSession.mapSyncError(error)
          }

          const confirmed = cloneData(this.core.requireData())
          if (!confirmed.masterPasswordChange) throw new VaultError('SYNC_FAILED')
          confirmed.masterPasswordChange.phase = 'remote-confirmed'
          confirmed.masterPasswordChange.updatedAt = this.core.nowIso()
          if (confirmed.sync) {
            confirmed.sync.state = { ...client.exportState(), session: null }
          }
          confirmed.updatedAt = confirmed.masterPasswordChange.updatedAt
          try {
            await this.core.commit(confirmed)
          } catch (error) {
            this.core.advanceGeneration()
            this.pinUnlock.invalidate()
            this.core.teardown()
            throw error
          }
        }

        await this.finishMasterPasswordChange(currentPassword, newPassword)
      } finally {
        if (abort) this.syncSession.finishSyncOperation(abort)
        request.currentPassword = ''
        request.newPassword = ''
        request.hint = null
        currentPassword = ''
        newPassword = ''
        if (remoteRequest) {
          remoteRequest.currentPassword = ''
          remoteRequest.newPassword = ''
          remoteRequest.hint = null
        }
      }
    })
  }

  resolveMasterPasswordChange(
    request: VaultMasterPasswordChangeResolutionRequest
  ): Promise<VaultMasterPasswordChangeResolution> {
    return this.core.exclusive(async () => {
      let currentPassword = ''
      let newPassword = ''
      let abort: AbortController | undefined
      try {
        currentPassword = normalizeMasterPassword(request.currentPassword)
        newPassword = normalizeMasterPassword(request.newPassword)
        if (currentPassword === newPassword) throw new VaultError('INVALID_INPUT')
        const current = this.core.requireData()
        assertMasterPasswordChangeAccount(current)
        if (current.masterPasswordChange?.phase !== 'prepared') {
          throw new VaultError('INVALID_INPUT')
        }
        const sync = this.syncSession.requireSyncData()
        abort = this.syncSession.startSyncOperation()
        const newPasswordProof = await this.proveRemotePassword(sync, newPassword, abort.signal)
        if (newPasswordProof === 'needs-reconnect') return { status: 'needs-reconnect' }
        if (newPasswordProof === 'rejected') {
          const currentPasswordProof = await this.proveRemotePassword(
            sync,
            currentPassword,
            abort.signal
          )
          if (currentPasswordProof === 'needs-reconnect') return { status: 'needs-reconnect' }
          if (currentPasswordProof === 'rejected') return { status: 'indeterminate' }

          const cleared = cloneData(this.core.requireData())
          assertMasterPasswordChangeAccount(cleared)
          if (cleared.masterPasswordChange?.phase !== 'prepared') {
            throw new VaultError('SYNC_FAILED')
          }
          cleared.masterPasswordChange = null
          if (cleared.sync) cleared.sync.state.session = null
          cleared.updatedAt = this.core.nowIso()
          await this.core.commit(cleared)
          this.syncSession.dropSyncClient()
          return { status: 'remote-not-changed' }
        }

        const confirmed = cloneData(this.core.requireData())
        assertMasterPasswordChangeAccount(confirmed)
        if (confirmed.masterPasswordChange?.phase !== 'prepared') {
          throw new VaultError('SYNC_FAILED')
        }
        confirmed.masterPasswordChange.phase = 'remote-confirmed'
        confirmed.masterPasswordChange.updatedAt = this.core.nowIso()
        if (confirmed.sync) confirmed.sync.state.session = null
        confirmed.updatedAt = confirmed.masterPasswordChange.updatedAt
        await this.core.commit(confirmed)
        this.syncSession.dropSyncClient()
        await this.finishMasterPasswordChange(currentPassword, newPassword)
        return { status: 'resolved' }
      } finally {
        if (abort) this.syncSession.finishSyncOperation(abort)
        request.currentPassword = ''
        request.newPassword = ''
        currentPassword = ''
        newPassword = ''
      }
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

  resendSyncNewDeviceOtp(request: {
    serverUrl: string
    email: string
    masterPassword: string
  }): Promise<void> {
    return this.core.exclusive(async () => {
      let abort: AbortController | null = null
      try {
        this.core.requireData()
        const serverUrl = this.syncSession.normalizeSyncServerUrl(request.serverUrl)
        const email = normalizeRequiredString(request.email, MAX_USERNAME_LENGTH)
        const password = normalizeSyncPassword(request.masterPassword)
        const sync: PersistedSyncData = {
          provider: 'bitwarden',
          serverUrl,
          email,
          state: {
            session: null,
            deviceIdentifier: randomUUID(),
            profileId: null,
            securityStamp: null
          },
          unlockMaterial: null,
          lastSyncAt: null,
          requiresFullSyncAfterCipherIsolation: false,
          folderMappings: [],
          loginMappings: [],
          folderTombstones: [],
          loginTombstones: [],
          pendingLoginMutation: null,
          pendingLoginImport: null,
          pendingPersonalVaultPurge: null,
          domainSettings: null
        }
        const client = this.syncSession.createDetachedClient(sync)
        if (!client.resendNewDeviceOtp) throw new VaultError('SYNC_FAILED')
        abort = this.syncSession.startSyncOperation()
        await client.resendNewDeviceOtp(password, abort.signal)
      } catch (error) {
        throw this.syncSession.mapSyncError(error)
      } finally {
        try {
          request.masterPassword = ''
        } catch {
          // Frozen or exotic input must not replace the intended service result.
        }
        if (abort) this.syncSession.finishSyncOperation(abort)
      }
    })
  }

  protected async proveRemotePassword(
    sync: PersistedSyncData,
    password: string,
    signal: AbortSignal
  ): Promise<'accepted' | 'rejected' | 'needs-reconnect'> {
    const verificationSync = structuredClone(sync)
    verificationSync.state.session = null
    const verifier = this.syncSession.createDetachedClient(verificationSync)
    try {
      await verifier.login({ email: sync.email, password, signal })
      return 'accepted'
    } catch (error) {
      if (error instanceof BitwardenDirectError && error.code === 'AUTH_REQUIRED') {
        return 'rejected'
      }
      if (
        error instanceof BitwardenDirectError &&
        (error.code === 'TWO_FACTOR_REQUIRED' || error.code === 'NEW_DEVICE_REQUIRED')
      ) {
        return 'needs-reconnect'
      }
      throw this.syncSession.mapSyncError(error)
    } finally {
      try {
        await verifier.logout()
      } catch {
        // Best-effort cleanup of the isolated proof session.
      }
    }
  }

  protected async recoverNativeAttachmentRestoreAfterUnlock(
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

  protected async finishMasterPasswordChange(
    currentPassword: string,
    newPassword: string
  ): Promise<void> {
    const current = this.core.requireData()
    assertMasterPasswordChangeAccount(current)
    if (
      current.masterPasswordChange?.phase !== 'remote-confirmed' &&
      current.masterPasswordChange?.phase !== 'local-rekeyed'
    ) {
      throw new VaultError('SYNC_FAILED')
    }
    await this.core.rekey(currentPassword, newPassword)

    const generation = this.core.advanceGeneration()
    this.pinUnlock.invalidate()
    this.syncSession.abortSyncOperation()
    this.syncSession.abortNotificationTokenLeases()
    this.syncSession.abortAccountSecurityRequests()
    this.syncSession.dropSyncClient()
    const localRekeyed = cloneData(this.core.requireData())
    if (!localRekeyed.masterPasswordChange) throw new VaultError('SYNC_FAILED')
    localRekeyed.masterPasswordChange.phase = 'local-rekeyed'
    localRekeyed.masterPasswordChange.updatedAt = this.core.nowIso()
    if (localRekeyed.sync) localRekeyed.sync.state.session = null
    localRekeyed.updatedAt = localRekeyed.masterPasswordChange.updatedAt
    await this.core.commit(localRekeyed, generation)

    const complete = cloneData(localRekeyed)
    complete.masterPasswordChange = null
    complete.updatedAt = this.core.nowIso()
    await this.core.commit(complete, generation)
  }

  protected mapPinUnlockError(error: PinUnlockError): VaultError {
    if (error.code === 'INVALID_INPUT') return new VaultError('INVALID_INPUT')
    if (error.code === 'INVALID_PIN') return new VaultError('INVALID_PIN')
    if (error.code === 'RATE_LIMITED') return new VaultError('RATE_LIMITED')
    return new VaultError('PIN_DISABLED')
  }
}
