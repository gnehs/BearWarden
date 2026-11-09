import { randomInt as nodeRandomInt, randomUUID } from 'node:crypto'
import type {
  LoginApprovalPrompt,
  OrganizationView,
  CollectionView,
  SyncPurgePersonalVaultResult,
  SyncResult,
  VaultTimeoutPolicy,
  VaultStatus
} from '../shared/vault-contract'
import {
  BitwardenDirectError,
  type BitwardenFolder,
  type BitwardenLoginItem,
  type BitwardenLoginApprovalRequest,
  type BitwardenSendItem,
  type BitwardenSyncClient,
  type BitwardenWebAuthnRegistrationSetup
} from './bitwarden-direct'
import { BITWARDEN_POLICY_TYPE } from './bitwarden-policy'
import { EncryptedVaultStore } from './encrypted-vault-store'
import { type EncryptedImageCache, type ImageCacheKeys } from './encrypted-image-cache'
import { ConcurrencyLimiter, ImageMemoryCache } from './image-memory-cache'
import {
  PinUnlockCapability,
  PinUnlockError,
  type PinSyncKeyMaterial,
  type PinVaultKeyMaterial
} from './pin-unlock'
import type { TouchIdUnlockMaterial } from './touch-id-unlock-capsule'
import { recoverInterruptedNativeAttachmentRestore } from './native-attachment-restore'
import {
  completeSyncMetadata,
  fingerprintLogin,
  legacyCustomFieldBaselineUpgrades,
  planSync,
  type SyncAction,
  type SyncActionResult,
  type SyncLink
} from './sync-merge'
import { VaultError } from './vault-errors'
import type { VaultAttachmentFileService } from './vault-attachment-files'
import type { AccountWebAuthnAttestation } from './account-webauthn-registration-codec'
import {
  DATA_VERSION,
  MAX_MASTER_PASSWORD_LENGTH,
  MAX_USERNAME_LENGTH,
  MAX_PASSWORD_LENGTH,
  MAX_PENDING_LOGIN_IMPORT_ENTRIES,
  MAX_PENDING_LOGIN_IMPORT_MARKER_LENGTH
} from './vault/limits'
import {
  normalizeRequiredString,
  normalizeMasterPassword,
  normalizeSyncPassword
} from './vault/parse-primitives'
import { cloneData } from './vault/vault-data-parsing'
import { isCompositeRemoteLoginUpdate } from './vault/views'
import { assertNoPendingPersonalVaultPurge } from './vault/sync-data-parsing'
import { sendViewFromRemote } from './vault/send-parsing'
import { cloneCustomFields } from './vault/custom-fields'
import { cloneLoginUris, uriAlias } from './vault/login-uris'
import {
  cloneEquivalentDomainSettings,
  validateRemoteEquivalentDomainSettings
} from './vault/equivalent-domains'
import { parseStoredOrganization, parseStoredCollection } from './vault/org-collection-parsing'
import { VaultGeneratorService } from './vault/generator-service'
import { VaultSendService } from './vault/send-service'
import { VaultCore } from './vault/core'
import { cloneGeneratorHistory } from './vault/generator-history'
import { clonePasswordHistory } from './vault/password-history'
import type {
  StoredSharedLogin,
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
import { UUID_PATTERN, isRecord } from './validation-primitives'
import { findFolder, findLogin } from './vault/data-lookup'
import {
  currentBitwardenPolicySet,
  bitwardenPolicyDecision,
  assertBitwardenPolicyDoesNotBlock,
  assertSendMutationAllowed,
  maximumVaultTimeoutMinutes
} from './vault/policy'
import {
  VaultSyncSession,
  type AuthenticatorSetupSession,
  type EmailTwoFactorSetupSession
} from './vault/sync-session'
import { VaultFolders } from './vault/folders'
import { VaultHealth } from './vault/health'
import { VaultListings } from './vault/listings'
import { VaultPasswordHistory } from './vault/password-history-service'
import {
  localSyncSnapshot,
  remoteSyncSnapshot,
  syncMetadataOf,
  withoutProtectedLoginSnapshot,
  reattachProtectedLoginLinks,
  getSyncEquivalentDomainSettings,
  isolatedPersonalCipherIdsOf,
  findNewlyIsolatedMappedRemoteIds,
  supportsLoginImport,
  supportsBulkRemoteLoginMutation,
  bulkRemoteLoginMutationApplied,
  resolveFolderReference,
  remoteDraft,
  hasPendingLocalSyncWork,
  reconcileServerAuthoritativeAttachments,
  loginImportCandidate,
  bulkRemoteLoginCandidate,
  updateRemoteLogin,
  throwSharedSnapshotError,
  MAX_REMOTE_LOGIN_BATCH_IDS,
  type BulkRemoteLoginCandidate,
  type LoginImportCandidate
} from './vault/sync-snapshots'
import {
  masterPasswordChangeAccountFingerprint,
  assertMasterPasswordChangeAccount
} from './vault/master-password-change'
import {
  createLocalLogin,
  sharedLoginFromRemote,
  updateLocalLogin,
  createLocalFolder,
  deleteLocalFolder
} from './vault/local-records'
import { VaultAttachments } from './vault/attachments'
import { VaultPortability } from './vault/portability'
import { VaultSharedItems } from './vault/shared-items'
import { VaultItemAuthorization } from './vault/item-authorization'
import { VaultItems } from './vault/items'
import { VaultIntegrations } from './vault/integrations'

interface AccountWebAuthnOperationLease {
  readonly generation: number
  readonly client: BitwardenSyncClient
  readonly abort: AbortController
}

const LOGIN_APPROVAL_TTL_MS = 15 * 60 * 1_000
const MAX_LOGIN_APPROVAL_SESSIONS = 64

function clearAccountWebAuthnRegistrationSetup(
  setup: BitwardenWebAuthnRegistrationSetup | null
): void {
  if (!setup) return
  setup.userVerificationToken = null
  setup.keys.splice(0)
}

function clearAccountWebAuthnAttestation(attestation: AccountWebAuthnAttestation | null): void {
  if (!attestation) return
  attestation.id = ''
  attestation.rawId = ''
  attestation.response.clientDataJSON = ''
  attestation.response.attestationObject = ''
  attestation.clientExtensionResults = {}
  attestation.authenticatorAttachment = null
}

function scrubAccountSessionDeauthorizationRequest(value: unknown): void {
  if (typeof value !== 'object' || value === null) return
  for (const key of ['masterPassword', 'confirmation'] as const) {
    try {
      const descriptor = Object.getOwnPropertyDescriptor(value, key)
      if (!descriptor || !('value' in descriptor)) continue
      Reflect.defineProperty(value, key, { ...descriptor, value: '' })
    } catch {
      // Cleanup is best-effort and must not invoke accessors or replace the intended result.
    }
  }
}

export {
  clearAccountWebAuthnRegistrationSetup,
  clearAccountWebAuthnAttestation,
  scrubAccountSessionDeauthorizationRequest
}
export type { AccountWebAuthnOperationLease }

function changesRemote(action: SyncAction): boolean {
  if (action.kind === 'conflict-copy') return action.reason !== 'both-modified'
  return (
    action.kind === 'push-create' ||
    action.kind === 'push-update' ||
    action.kind === 'delete-remote'
  )
}

/**
 * Owns the vault's mutable runtime state, persistence transaction boundary, and sync engine.
 * Feature layers extend this class so every operation shares one mutex, generation, and cleanup
 * lifecycle; this module must never import a higher service layer.
 */
export class VaultServiceBase {
  protected pinUnlockCapability: PinUnlockCapability | null = null
  protected pinLifecycleEpoch = 0
  protected readonly generatorService: VaultGeneratorService
  protected readonly sendService: VaultSendService
  protected readonly createSyncClient: (sync: PersistedSyncData) => BitwardenSyncClient
  protected readonly fetch: typeof fetch
  protected readonly attachmentFiles: VaultAttachmentFileService | null
  protected readonly requestAccountWebAuthnAssertion: VaultAccountWebAuthnAssertionRequester | null
  protected readonly requestAccountWebAuthnRegistration: VaultAccountWebAuthnRegistrationRequester | null
  protected readonly imageCache: EncryptedImageCache | null
  protected readonly websiteIconCache = new ImageMemoryCache<string | null>({
    maxEntries: 512,
    maxSize: 32 * 1024 * 1024
  })
  protected readonly websiteIconRequests = new Map<string, Promise<string | null>>()
  protected readonly websiteIconFetches = new ConcurrencyLimiter(6)
  /** Aborted on lock so detached image downloads stop as soon as the vault key is gone. */
  protected readonly imageRequestAborts = new Set<AbortController>()
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
      abort: () => {
        this.abortImageRequests()
      },
      clear: () => {
        this.generatorService.clearRuntimeState()
        this.websiteIconCache.clear()
        this.websiteIconRequests.clear()
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
      performSync: (data, client, signal) => this.performSync(data, client, signal)
    })
    this.sharedItems = new VaultSharedItems(this.core, this.syncSession, this.platform)
    this.authorization = new VaultItemAuthorization(this.core)
    this.items = new VaultItems(this.core, this.platform)
    this.integrations = new VaultIntegrations(this.core, this.authorization)
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
    const status = this.pinUnlockCapability?.status()
    if (!status?.available) return { available: false, remainingAttempts: 0 }
    return status
  }

  enablePinUnlock(request: {
    pin: string
    masterPassword: string
  }): Promise<import('../shared/vault-contract').PinUnlockStatus> {
    const lifecycleEpoch = this.pinLifecycleEpoch
    const generation = this.core.generation
    return this.core.exclusive(async () => {
      let capability: PinUnlockCapability | null = null
      let syncMaterial: PinSyncKeyMaterial | null = null
      try {
        if (generation !== this.core.generation || lifecycleEpoch !== this.pinLifecycleEpoch) {
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
          lifecycleEpoch !== this.pinLifecycleEpoch ||
          !this.core.isUnlocked()
        ) {
          throw new VaultError('LOCKED')
        }
        this.pinUnlockCapability?.dispose()
        this.pinUnlockCapability = capability
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
    this.invalidatePinUnlockCapability()
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
              this.invalidatePinUnlockCapability()
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
            this.invalidatePinUnlockCapability()
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
    const capability = this.pinUnlockCapability
    const lifecycleEpoch = this.pinLifecycleEpoch
    const generation = this.core.generation
    return this.core.exclusive(async () => {
      let material: PinVaultKeyMaterial | null = null
      try {
        if (generation !== this.core.generation || lifecycleEpoch !== this.pinLifecycleEpoch) {
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
          lifecycleEpoch !== this.pinLifecycleEpoch ||
          generation !== this.core.generation ||
          capability !== this.pinUnlockCapability
        ) {
          throw new VaultError('LOCKED')
        }
        const unlocked = await this.store.unlockWithKey(material.key, material.salt)
        return await this.installUnlockedVault(unlocked, generation, {
          validate: (data) => {
            if (
              lifecycleEpoch !== this.pinLifecycleEpoch ||
              capability !== this.pinUnlockCapability
            ) {
              throw new VaultError('LOCKED')
            }
            assertBitwardenPolicyDoesNotBlock(BITWARDEN_POLICY_TYPE.RemoveUnlockWithPin, data)
          },
          startSync: { material: material.sync }
        })
      } catch (error) {
        if (error instanceof PinUnlockError) {
          if (
            capability &&
            !capability.status().available &&
            this.pinUnlockCapability === capability
          ) {
            this.pinUnlockCapability = null
          }
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
    this.invalidatePinUnlockCapability()
    this.core.teardown()
  }

  protected abortImageRequests(): void {
    for (const abort of this.imageRequestAborts) abort.abort()
    this.imageRequestAborts.clear()
  }

  /**
   * Derives per-operation image cache subkeys from the unlocked vault key. Callers must zero the
   * result with `clearImageCacheKeys`, and must re-check `generation` before every cache write.
   */
  protected imageCacheKeys(): ImageCacheKeys | null {
    if (!this.imageCache) return null
    return this.core.imageCacheKeys()
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

  protected assertAccountWebAuthnOperationCurrent(
    lease: AccountWebAuthnOperationLease
  ): Promise<void> {
    return this.core.exclusive(async () => {
      this.core.requireData()
      if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
        throw new VaultError('LOCKED')
      }
      if (this.syncSession.syncClient !== lease.client || !lease.client.exportState().session) {
        throw new VaultError('SYNC_AUTH_REQUIRED')
      }
    })
  }

  protected finishAccountWebAuthnOperation(lease: AccountWebAuthnOperationLease): Promise<void> {
    return this.core.exclusive(async () => {
      this.core.requireData()
      if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
        throw new VaultError('LOCKED')
      }
      if (this.syncSession.syncClient !== lease.client || !lease.client.exportState().session) {
        throw new VaultError('SYNC_AUTH_REQUIRED')
      }
      await this.syncSession.persistCurrentClientState()
      if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
        throw new VaultError('LOCKED')
      }
      if (this.syncSession.syncClient !== lease.client || !lease.client.exportState().session) {
        throw new VaultError('SYNC_AUTH_REQUIRED')
      }
      this.syncSession.accountSecurityAborts.delete(lease.abort)
    })
  }

  protected releaseAccountWebAuthnOperation(lease: AccountWebAuthnOperationLease): Promise<void> {
    return this.core.exclusive(async () => {
      this.syncSession.accountSecurityAborts.delete(lease.abort)
    })
  }

  protected throwAccountWebAuthnOperationError(
    error: unknown,
    lease: AccountWebAuthnOperationLease
  ): never {
    if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
      throw new VaultError('LOCKED')
    }
    if (this.syncSession.syncClient !== lease.client || !lease.client.exportState().session) {
      throw new VaultError('SYNC_AUTH_REQUIRED')
    }
    if (error instanceof BitwardenDirectError) {
      if (error.code === 'USER_VERIFICATION_FAILED') {
        throw new VaultError('INVALID_MASTER_PASSWORD')
      }
      if (error.code === 'TWO_FACTOR_MUTATION_UNKNOWN') {
        throw new VaultError('TWO_FACTOR_MUTATION_UNKNOWN')
      }
      if (error.code === 'NOT_FOUND') throw new VaultError('NOT_FOUND')
    }
    if (error instanceof VaultError) throw error
    throw this.syncSession.mapSyncError(error)
  }

  protected assertLoginApprovalLease(lease: {
    generation: number
    client: BitwardenSyncClient
    abort: AbortController
  }): void {
    if (
      lease.abort.signal.aborted ||
      lease.generation !== this.core.generation ||
      lease.client !== this.syncSession.syncClient ||
      !lease.client.exportState().session
    ) {
      throw new VaultError('SYNC_AUTH_REQUIRED')
    }
  }

  protected issueLoginApproval(
    request: BitwardenLoginApprovalRequest,
    client: BitwardenSyncClient,
    generation: number
  ): LoginApprovalPrompt | null {
    const now = this.core.now().getTime()
    const expiresAt = Date.parse(request.createdAt) + LOGIN_APPROVAL_TTL_MS
    for (const [token, session] of this.syncSession.loginApprovalSessions) {
      if (
        session.expiresAt <= now ||
        session.generation !== this.core.generation ||
        session.client !== this.syncSession.syncClient
      ) {
        this.syncSession.loginApprovalSessions.delete(token)
        continue
      }
      if (
        session.requestId === request.id &&
        session.fingerprint === request.fingerprint &&
        session.client === client &&
        session.generation === generation
      ) {
        return {
          token,
          fingerprint: session.fingerprint,
          requestDeviceType: session.requestDeviceType,
          createdAt: session.createdAt,
          expiresAt: new Date(session.expiresAt).toISOString()
        }
      }
    }
    if (!Number.isFinite(expiresAt) || expiresAt <= now) return null
    while (this.syncSession.loginApprovalSessions.size >= MAX_LOGIN_APPROVAL_SESSIONS) {
      const oldest = this.syncSession.loginApprovalSessions.keys().next().value
      if (oldest === undefined) break
      this.syncSession.loginApprovalSessions.delete(oldest)
    }
    const token = randomUUID()
    this.syncSession.loginApprovalSessions.set(token, {
      generation,
      client,
      requestId: request.id,
      fingerprint: request.fingerprint,
      requestDeviceType: request.requestDeviceType,
      createdAt: request.createdAt,
      expiresAt
    })
    return {
      token,
      fingerprint: request.fingerprint,
      requestDeviceType: request.requestDeviceType,
      createdAt: request.createdAt,
      expiresAt: new Date(expiresAt).toISOString()
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
    this.invalidatePinUnlockCapability()
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

  protected evictExpiredAuthenticatorSetupSessions(): void {
    const now = this.core.now().getTime()
    for (const [sessionId, session] of this.syncSession.authenticatorSetupSessions) {
      if (session.expiresAt <= now) this.syncSession.deleteAuthenticatorSetupSession(sessionId)
    }
  }

  protected requireAuthenticatorSetupSession(sessionId: string): AuthenticatorSetupSession {
    this.evictExpiredAuthenticatorSetupSessions()
    const session = this.syncSession.authenticatorSetupSessions.get(sessionId)
    if (
      !session ||
      session.generation !== this.core.generation ||
      session.client !== this.syncSession.syncClient ||
      !session.client.exportState().session
    ) {
      if (session) this.syncSession.deleteAuthenticatorSetupSession(sessionId)
      throw new VaultError('INVALID_INPUT')
    }
    return session
  }

  protected evictExpiredEmailTwoFactorSetupSessions(): void {
    const now = this.core.now().getTime()
    for (const [sessionId, session] of this.syncSession.emailTwoFactorSetupSessions) {
      if (session.expiresAt <= now) this.syncSession.deleteEmailTwoFactorSetupSession(sessionId)
    }
  }

  protected requireEmailTwoFactorSetupSession(
    sessionId: string,
    phase: EmailTwoFactorSetupSession['phase']
  ): EmailTwoFactorSetupSession {
    this.evictExpiredEmailTwoFactorSetupSessions()
    const session = this.syncSession.emailTwoFactorSetupSessions.get(sessionId)
    if (!session) throw new VaultError('INVALID_INPUT')
    if (
      session.generation !== this.core.generation ||
      session.client !== this.syncSession.syncClient ||
      !session.client.exportState().session
    ) {
      this.syncSession.deleteEmailTwoFactorSetupSession(sessionId)
      throw new VaultError('INVALID_INPUT')
    }
    if (session.phase !== phase) throw new VaultError('INVALID_INPUT')
    return session
  }

  protected validateEmailTwoFactorSetupPassword(
    session: EmailTwoFactorSetupSession,
    masterPassword: string | undefined
  ): void {
    if (session.verificationMode === 'server-token') {
      if (masterPassword !== undefined) throw new VaultError('INVALID_INPUT')
      return
    }
    if (
      typeof masterPassword !== 'string' ||
      masterPassword.length === 0 ||
      masterPassword.length > MAX_PASSWORD_LENGTH
    ) {
      throw new VaultError('INVALID_INPUT')
    }
  }

  protected throwTwoFactorMutationError(
    error: unknown,
    lease: { abort: AbortController; generation: number }
  ): never {
    if (lease.abort.signal.aborted || lease.generation !== this.core.generation) {
      throw new VaultError('LOCKED')
    }
    if (error instanceof BitwardenDirectError) {
      if (error.code === 'USER_VERIFICATION_FAILED') {
        throw new VaultError('INVALID_MASTER_PASSWORD')
      }
      if (error.code === 'TWO_FACTOR_MUTATION_UNKNOWN') {
        throw new VaultError('TWO_FACTOR_MUTATION_UNKNOWN')
      }
    }
    if (error instanceof VaultError) throw error
    throw this.syncSession.mapSyncError(error)
  }

  protected applyBitwardenPolicyRuntimeState(data: VaultData): void {
    if (
      bitwardenPolicyDecision(BITWARDEN_POLICY_TYPE.RemoveUnlockWithPin, data).state !==
      'not-applicable'
    ) {
      this.invalidatePinUnlockCapability()
    }
  }

  protected async restorePreDispatchPurge(original: VaultData): Promise<void> {
    const restored = cloneData(original)
    restored.updatedAt = this.core.nowIso()
    await this.core.commit(restored)
  }

  protected async reconcilePersonalVaultPurge(
    client: BitwardenSyncClient
  ): Promise<SyncPurgePersonalVaultResult> {
    const current = this.core.requireData()
    const journal = current.sync?.pendingPersonalVaultPurge
    if (journal?.phase !== 'dispatched') throw new VaultError('SYNC_FAILED')
    try {
      // Do not reuse the mutation signal: cancellation after dispatch must not suppress the
      // authoritative read that distinguishes a completed purge from an unknown partial result.
      await client.sync()
      const isolatedPersonalCipherIds = isolatedPersonalCipherIdsOf(client)
      const [remoteFolders, remoteLogins] = await Promise.all([
        client.listFolders(),
        client.listPersonalLogins()
      ])
      if (
        remoteFolders.length === 0 &&
        remoteLogins.length === 0 &&
        isolatedPersonalCipherIds.size === 0
      ) {
        return await this.finalizePersonalVaultPurge(current, client)
      }
      const pending = cloneData(current)
      if (!pending.sync?.pendingPersonalVaultPurge) throw new VaultError('SYNC_FAILED')
      pending.sync.pendingPersonalVaultPurge.phase = 'dispatched'
      pending.sync.pendingPersonalVaultPurge.remainingItems =
        remoteLogins.length + isolatedPersonalCipherIds.size
      pending.sync.pendingPersonalVaultPurge.remainingFolders = remoteFolders.length
      pending.sync.state = client.exportState()
      pending.sync.lastSyncAt = this.core.nowIso()
      pending.updatedAt = pending.sync.lastSyncAt
      await this.core.commit(pending)
      this.syncSession.clearSyncErrorState()
      return {
        status: 'pending',
        remainingItems: remoteLogins.length + isolatedPersonalCipherIds.size,
        remainingFolders: remoteFolders.length,
        startedAt: journal.startedAt
      }
    } catch (error) {
      // The dispatched journal remains the sole source of truth when the authoritative read fails.
      if (error instanceof VaultError) throw error
      if (error instanceof BitwardenDirectError) throw error
      throw new VaultError('SYNC_FAILED')
    }
  }

  protected async finalizePersonalVaultPurge(
    current: VaultData,
    client: BitwardenSyncClient
  ): Promise<{ status: 'complete'; removedItems: number; removedFolders: number }> {
    if (current.sync?.pendingPersonalVaultPurge?.phase !== 'dispatched') {
      throw new VaultError('SYNC_FAILED')
    }
    const removedItems = current.logins.length
    const removedFolders = current.folders.length
    const complete = cloneData(current)
    complete.logins = []
    complete.folders = []
    complete.nativeAttachmentRestore = null
    if (!complete.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    complete.sync.folderMappings = []
    complete.sync.loginMappings = []
    complete.sync.folderTombstones = []
    complete.sync.loginTombstones = []
    complete.sync.pendingLoginMutation = null
    complete.sync.pendingLoginImport = null
    complete.sync.pendingPersonalVaultPurge = null
    complete.sync.requiresFullSyncAfterCipherIsolation = false
    complete.sync.state = client.exportState()
    complete.sync.lastSyncAt = this.core.nowIso()
    complete.updatedAt = complete.sync.lastSyncAt
    await this.core.commit(complete)
    this.syncSession.clearSyncErrorState()
    return { status: 'complete', removedItems, removedFolders }
  }

  protected async performSync(
    current: VaultData,
    client: BitwardenSyncClient,
    signal: AbortSignal
  ): Promise<SyncResult> {
    const syncStartedAt = this.core.nowIso()
    let source = current
    const pendingPurge = source.sync?.pendingPersonalVaultPurge
    if (pendingPurge?.phase === 'prepared') {
      const cleared = cloneData(source)
      if (!cleared.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
      cleared.sync.pendingPersonalVaultPurge = null
      cleared.updatedAt = this.core.nowIso()
      await this.core.commit(cleared)
      source = cleared
    } else if (pendingPurge?.phase === 'dispatched') {
      const reconciled = await this.reconcilePersonalVaultPurge(client)
      if (reconciled.status === 'pending') throw new VaultError('SYNC_FAILED')
      const completedSync = this.syncSession.requireSyncData()
      return {
        ...this.syncSession.baseSyncStatus(completedSync, 'ready'),
        pulled: 0,
        pushed: 0,
        deleted: reconciled.removedItems + reconciled.removedFolders,
        conflicts: 0
      }
    }
    let sync = source.sync
    if (!sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    const unchanged = await this.skipUnchangedRemoteSync(source, client, signal, syncStartedAt)
    if (unchanged) return unchanged
    await client.sync(signal)
    const initialIsolatedPersonalCipherIds = isolatedPersonalCipherIdsOf(client)
    if (initialIsolatedPersonalCipherIds.size > 0) {
      // Persist the full-sync requirement before any later parsing, shared-vault read, or mutation
      // can fail. Otherwise a revision fast path could hide the quarantined personal ciphers.
      await this.persistCipherIsolationRecovery([], initialIsolatedPersonalCipherIds)
      source = this.core.requireData()
      sync = source.sync
      if (!sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    }
    const protectedLoginMappings = sync.loginMappings.filter((entry) =>
      initialIsolatedPersonalCipherIds.has(entry.remoteId)
    )
    const protectedLoginTombstones = sync.loginTombstones.filter((entry) =>
      initialIsolatedPersonalCipherIds.has(entry.remoteId)
    )
    const protectedLocalLoginIds = new Set(
      [...protectedLoginMappings, ...protectedLoginTombstones].map((entry) => entry.localId)
    )
    const protectedRemoteLoginIds = new Set(
      [...protectedLoginMappings, ...protectedLoginTombstones].map((entry) => entry.remoteId)
    )
    const mappedLoginLinksBeforeActions = [...sync.loginMappings, ...sync.loginTombstones]
    const sharedSnapshot = await this.fetchSharedSnapshot(client)
    const initialRemote = await Promise.all([
      client.listFolders(signal),
      client.listPersonalLogins(signal),
      getSyncEquivalentDomainSettings(
        client,
        sync.domainSettings ?? { equivalentDomains: [], globalEquivalentDomains: [] },
        signal
      ),
      client.listSends?.(signal) ?? Promise.resolve([] as BitwardenSendItem[])
    ])
    let remoteFolders = initialRemote[0]
    let remoteLogins = initialRemote[1]
    validateRemoteEquivalentDomainSettings(initialRemote[2])
    let remoteSends = initialRemote[3]
    const next = cloneData(source)
    if (sharedSnapshot) {
      next.organizations = sharedSnapshot.organizations
      next.collections = sharedSnapshot.collections
      next.sharedLogins = sharedSnapshot.sharedLogins
    }
    if (
      next.sync?.pendingLoginMutation &&
      initialIsolatedPersonalCipherIds.has(next.sync.pendingLoginMutation.remoteId)
    ) {
      // A pending mutation is an unresolved remote operation, so quarantine leaves its outcome
      // ambiguous. Keep the durable journal intact and retry only after the cipher is readable.
      throw new VaultError('SYNC_FAILED')
    }
    if (next.sync?.pendingLoginMutation) {
      await this.resumePendingLoginMutation(next, client, remoteFolders, remoteLogins, signal)
      await client.sync(signal)
      const refreshedIsolatedPersonalCipherIds = isolatedPersonalCipherIdsOf(client)
      if (refreshedIsolatedPersonalCipherIds.size > 0) {
        await this.persistCipherIsolationRecovery([], refreshedIsolatedPersonalCipherIds)
        if (next.sync) next.sync.requiresFullSyncAfterCipherIsolation = true
      }
      const newlyIsolatedPendingRemoteIds = findNewlyIsolatedMappedRemoteIds(
        refreshedIsolatedPersonalCipherIds,
        [...(next.sync?.loginMappings ?? []), ...(next.sync?.loginTombstones ?? [])],
        protectedRemoteLoginIds
      )
      if (newlyIsolatedPendingRemoteIds.size > 0) {
        throw new VaultError('SYNC_FAILED')
      }
      const refreshed = await Promise.all([
        client.listFolders(signal),
        client.listPersonalLogins(signal),
        client.listSends?.(signal) ?? Promise.resolve([] as BitwardenSendItem[])
      ])
      remoteFolders = refreshed[0]
      remoteLogins = refreshed[1]
      remoteSends = refreshed[2]
    }
    const skipBulkImportLocalIds = new Set<string>()
    if (next.sync?.pendingLoginImport) {
      const pendingImportPhase = next.sync.pendingLoginImport.phase
      const unmatched = await this.reconcilePendingLoginImport(
        next,
        client,
        remoteFolders,
        remoteLogins,
        signal
      )
      if (unmatched.length > 0) {
        if (pendingImportPhase === 'dispatched') {
          throw new VaultError('SYNC_FAILED')
        }
        for (const localId of unmatched) skipBulkImportLocalIds.add(localId)
      }
    }
    const remoteSnapshot = remoteSyncSnapshot(remoteFolders, remoteLogins)
    const syncMetadata = syncMetadataOf(next.sync ?? sync)
    syncMetadata.loginLinks = syncMetadata.loginLinks.filter(
      (entry) => !initialIsolatedPersonalCipherIds.has(entry.remoteId)
    )
    for (const upgrade of legacyCustomFieldBaselineUpgrades(
      withoutProtectedLoginSnapshot(localSyncSnapshot(next), protectedLocalLoginIds),
      remoteSnapshot,
      syncMetadata
    )) {
      const upgradedLogin = findLogin(next, upgrade.localId)
      upgradedLogin.customFields = cloneCustomFields(upgrade.customFields)
      if (upgrade.uris) {
        upgradedLogin.uris = cloneLoginUris(upgrade.uris)
        upgradedLogin.uri = uriAlias(upgradedLogin.uris)
      }
      if (upgrade.reprompt !== undefined) upgradedLogin.reprompt = upgrade.reprompt
      if (upgrade.passwordHistory) {
        upgradedLogin.passwordHistory = clonePasswordHistory(upgrade.passwordHistory)
      }
      if (upgrade.passwordRevisionDate !== undefined) {
        upgradedLogin.passwordRevisionDate = upgrade.passwordRevisionDate
      }
      if (upgrade.autofillOnPageLoad !== undefined) {
        upgradedLogin.autofillOnPageLoad = upgrade.autofillOnPageLoad
      }
      const mapping = next.sync?.loginMappings.find(
        (entry) => entry.localId === upgrade.localId && entry.remoteId === upgrade.remoteId
      )
      if (mapping) mapping.baseFingerprint = upgrade.baseFingerprint
      const metadataLink = syncMetadata.loginLinks.find(
        (entry) => entry.localId === upgrade.localId && entry.remoteId === upgrade.remoteId
      )
      if (metadataLink) metadataLink.baseFingerprint = upgrade.baseFingerprint
    }
    const plan = planSync(
      withoutProtectedLoginSnapshot(localSyncSnapshot(next), protectedLocalLoginIds),
      remoteSnapshot,
      syncMetadata
    )
    const results: SyncActionResult[] = []
    const completed = new Map<string, SyncActionResult>()
    const counts = { pulled: 0, pushed: 0, deleted: 0, conflicts: 0 }

    for (let actionIndex = 0; actionIndex < plan.actions.length; actionIndex += 1) {
      const action = plan.actions[actionIndex]!
      if (signal.aborted) throw new BitwardenDirectError('ABORTED')
      const importCandidate = loginImportCandidate(action, completed, skipBulkImportLocalIds)
      if (importCandidate && supportsLoginImport(client)) {
        const batch: LoginImportCandidate[] = [importCandidate]
        for (let nextIndex = actionIndex + 1; nextIndex < plan.actions.length; nextIndex += 1) {
          if (batch.length === MAX_PENDING_LOGIN_IMPORT_ENTRIES) break
          const candidate = loginImportCandidate(
            plan.actions[nextIndex]!,
            completed,
            skipBulkImportLocalIds
          )
          if (candidate === null) break
          batch.push(candidate)
        }
        if (batch.length > 1) {
          const remoteIds = await this.executeLoginImportBatch(next, client, batch, signal)
          for (const candidate of batch) {
            const remoteId = remoteIds.get(candidate.action.actionId)
            if (!remoteId) throw new VaultError('SYNC_FAILED')
            const result: SyncActionResult = {
              actionId: candidate.action.actionId,
              remoteId
            }
            results.push(result)
            completed.set(candidate.action.actionId, result)
            counts.pushed += 1
          }
          actionIndex += batch.length - 1
          continue
        }
      }
      const batchCandidate = bulkRemoteLoginCandidate(action, completed)
      if (batchCandidate && supportsBulkRemoteLoginMutation(client, batchCandidate.mutation)) {
        const batch: BulkRemoteLoginCandidate[] = [batchCandidate]
        for (let nextIndex = actionIndex + 1; nextIndex < plan.actions.length; nextIndex += 1) {
          if (batch.length === MAX_REMOTE_LOGIN_BATCH_IDS) break
          const candidate = bulkRemoteLoginCandidate(plan.actions[nextIndex]!, completed)
          if (
            candidate === null ||
            candidate.mutation !== batchCandidate.mutation ||
            candidate.folderId !== batchCandidate.folderId
          ) {
            break
          }
          batch.push(candidate)
        }
        if (batch.length > 1) {
          await this.executeBulkRemoteLoginMutation(client, batch, signal)
          for (const candidate of batch) {
            const result: SyncActionResult = { actionId: candidate.action.actionId }
            results.push(result)
            completed.set(candidate.action.actionId, result)
            if (candidate.action.kind === 'delete-remote') counts.deleted += 1
            else counts.pushed += 1
          }
          actionIndex += batch.length - 1
          continue
        }
      }
      const result = await this.executeSyncAction(next, client, action, completed, signal)
      results.push(result)
      completed.set(action.actionId, result)
      if (action.kind === 'conflict-copy') counts.conflicts += 1
      else if (action.kind === 'delete-local' || action.kind === 'delete-remote')
        counts.deleted += 1
      else if (action.kind.startsWith('pull-')) counts.pulled += 1
      else counts.pushed += 1
    }

    const metadata = completeSyncMetadata(plan, results)
    const completedLoginLinks = reattachProtectedLoginLinks(
      metadata.loginLinks,
      protectedLoginMappings,
      protectedLoginTombstones
    )
    // A plan that only touched local data leaves the server as the last download saw it.
    if (plan.actions.some(changesRemote)) await client.sync(signal)
    const finalIsolatedPersonalCipherIds = isolatedPersonalCipherIdsOf(client)
    const newlyIsolatedMappedRemoteIds = findNewlyIsolatedMappedRemoteIds(
      finalIsolatedPersonalCipherIds,
      [
        ...mappedLoginLinksBeforeActions,
        ...completedLoginLinks.loginMappings,
        ...completedLoginLinks.loginTombstones
      ],
      protectedRemoteLoginIds
    )
    if (
      finalIsolatedPersonalCipherIds.size > 0 &&
      (initialIsolatedPersonalCipherIds.size === 0 || newlyIsolatedMappedRemoteIds.size > 0)
    ) {
      await this.persistCipherIsolationRecovery(metadata.loginLinks, newlyIsolatedMappedRemoteIds)
      if (next.sync) next.sync.requiresFullSyncAfterCipherIsolation = true
    }
    if (newlyIsolatedMappedRemoteIds.size > 0) {
      throw new VaultError('SYNC_FAILED')
    }
    const [finalRemoteFolders, finalRemoteLogins, finalDomainSettings] = await Promise.all([
      client.listFolders(signal),
      client.listPersonalLogins(signal),
      getSyncEquivalentDomainSettings(client, initialRemote[2], signal)
    ])
    const finalSharedSnapshot = await this.fetchSharedSnapshot(client)
    const finalRemoteSends = client.listSends ? await client.listSends(signal) : remoteSends
    reconcileServerAuthoritativeAttachments(
      next,
      metadata.loginLinks,
      finalRemoteFolders,
      finalRemoteLogins
    )
    next.sends = finalRemoteSends.map(sendViewFromRemote)
    if (finalSharedSnapshot) {
      next.organizations = finalSharedSnapshot.organizations
      next.collections = finalSharedSnapshot.collections
      next.sharedLogins = finalSharedSnapshot.sharedLogins
    }
    const syncedAt = syncStartedAt
    next.sync = {
      ...sync,
      state: client.exportState(),
      lastSyncAt: syncedAt,
      requiresFullSyncAfterCipherIsolation:
        initialIsolatedPersonalCipherIds.size > 0 || finalIsolatedPersonalCipherIds.size > 0,
      folderMappings: metadata.folderLinks.map((link) => ({ ...link })),
      loginMappings: completedLoginLinks.loginMappings,
      folderTombstones: [],
      loginTombstones: completedLoginLinks.loginTombstones,
      pendingLoginMutation: next.sync?.pendingLoginMutation ?? null,
      pendingLoginImport: null,
      pendingPersonalVaultPurge: null,
      domainSettings: cloneEquivalentDomainSettings(
        validateRemoteEquivalentDomainSettings(finalDomainSettings)
      )
    }
    next.updatedAt = syncedAt
    await this.core.commit(next)
    this.applyBitwardenPolicyRuntimeState(next)
    this.syncSession.clearSyncErrorState()
    return { ...this.syncSession.baseSyncStatus(next.sync, 'ready'), ...counts }
  }

  protected async skipUnchangedRemoteSync(
    source: VaultData,
    client: BitwardenSyncClient,
    signal: AbortSignal,
    syncStartedAt: string
  ): Promise<SyncResult | null> {
    const sync = source.sync
    if (!sync?.lastSyncAt || !Number.isFinite(Date.parse(sync.lastSyncAt))) return null
    if (hasPendingLocalSyncWork(source)) return null
    const revisionDate = client.revisionDate
    if (!revisionDate) return null

    let remoteRevision: string
    try {
      remoteRevision = await revisionDate.call(client, signal)
    } catch {
      // The revision endpoint is an optimization. A full sync remains the authoritative fallback.
      return null
    }
    if (
      !Number.isFinite(Date.parse(remoteRevision)) ||
      Date.parse(remoteRevision) > Date.parse(sync.lastSyncAt)
    ) {
      return null
    }

    const completed = cloneData(source)
    if (!completed.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    completed.sync.state = client.exportState()
    completed.sync.lastSyncAt = syncStartedAt
    completed.updatedAt = syncStartedAt
    await this.core.commit(completed)
    this.applyBitwardenPolicyRuntimeState(completed)
    this.syncSession.clearSyncErrorState()
    return {
      ...this.syncSession.baseSyncStatus(completed.sync, 'ready'),
      pulled: 0,
      pushed: 0,
      deleted: 0,
      conflicts: 0
    }
  }

  protected async fetchSharedSnapshot(client: BitwardenSyncClient): Promise<{
    organizations: OrganizationView[]
    collections: CollectionView[]
    sharedLogins: StoredSharedLogin[]
  } | null> {
    if (!client.listOrganizations || !client.listCollections || !client.listOrganizationCiphers) {
      return null
    }
    const [organizations, collections, sharedLogins] = await Promise.all([
      client.listOrganizations().catch((error) => throwSharedSnapshotError(error, 'organization')),
      client.listCollections().catch((error) => throwSharedSnapshotError(error, 'collection')),
      client.listOrganizationCiphers().catch((error) => throwSharedSnapshotError(error, 'cipher'))
    ])
    let parsedOrganizations: OrganizationView[]
    try {
      parsedOrganizations = organizations.map(parseStoredOrganization)
    } catch (error) {
      throwSharedSnapshotError(error, 'organization')
    }
    const organizationIds = new Set(parsedOrganizations.map((organization) => organization.id))
    if (organizationIds.size !== parsedOrganizations.length) {
      throw new BitwardenDirectError('INVALID_RESPONSE', undefined, 'organization')
    }
    let parsedCollections: CollectionView[]
    try {
      parsedCollections = collections.map(parseStoredCollection)
    } catch (error) {
      throwSharedSnapshotError(error, 'collection')
    }
    const collectionIds = new Set(parsedCollections.map((collection) => collection.id))
    if (
      collectionIds.size !== parsedCollections.length ||
      parsedCollections.some((collection) => !organizationIds.has(collection.organizationId))
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE', undefined, 'collection')
    }
    let parsedSharedLogins: StoredSharedLogin[]
    try {
      parsedSharedLogins = sharedLogins.map((login) => sharedLoginFromRemote(this.core, login))
    } catch (error) {
      throwSharedSnapshotError(error, 'cipher')
    }
    const sharedIds = new Set(parsedSharedLogins.map((login) => login.id))
    if (
      sharedIds.size !== parsedSharedLogins.length ||
      parsedSharedLogins.some(
        (login) =>
          !organizationIds.has(login.organizationId) ||
          login.collectionIds.some(
            (id) =>
              !collectionIds.has(id) ||
              parsedCollections.find((collection) => collection.id === id)?.organizationId !==
                login.organizationId
          )
      )
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE', undefined, 'cipher')
    }
    return {
      organizations: parsedOrganizations,
      collections: parsedCollections,
      sharedLogins: parsedSharedLogins
    }
  }

  protected async resumePendingLoginMutation(
    data: VaultData,
    client: BitwardenSyncClient,
    remoteFolders: BitwardenFolder[],
    remoteLogins: BitwardenLoginItem[],
    signal: AbortSignal
  ): Promise<void> {
    const pending = data.sync?.pendingLoginMutation
    if (!pending || !data.sync) return
    const desired = localSyncSnapshot(data).logins.find((login) => login.id === pending.localId)
    const current = remoteSyncSnapshot(remoteFolders, remoteLogins).logins.find(
      (login) => login.id === pending.remoteId
    )

    if (pending.intent === 'hard-delete') {
      if (current) await client.hardDeleteLogin(pending.remoteId, signal)
      data.sync.pendingLoginMutation = null
      await this.core.commit(cloneData(data))
      return
    }

    if (desired && current) {
      const desiredFolderName =
        desired.folderId === null
          ? null
          : (data.folders.find((folder) => folder.id === desired.folderId)?.name ?? null)
      const currentFolderName =
        current.folderId === null
          ? null
          : (remoteFolders.find((folder) => folder.id === current.folderId)?.name ?? null)
      const currentFingerprint = fingerprintLogin(current, currentFolderName)
      const liveRemoteFolderIds = new Set(remoteFolders.map((folder) => folder.id))
      const mappedRemoteFolderId =
        desired.folderId === null
          ? null
          : data.sync.folderMappings.find(
              (mapping) =>
                mapping.localId === desired.folderId && liveRemoteFolderIds.has(mapping.remoteId)
            )?.remoteId
      const remoteFolderId =
        desired.folderId === null
          ? null
          : mappedRemoteFolderId !== undefined
            ? mappedRemoteFolderId
            : pending.remoteFolderId && liveRemoteFolderIds.has(pending.remoteFolderId)
              ? pending.remoteFolderId
              : undefined
      if (
        remoteFolderId !== undefined &&
        pending.expectedRemoteFingerprints.includes(currentFingerprint)
      ) {
        const contentChanged =
          fingerprintLogin({ ...desired, deletedAt: null, archivedAt: null }, desiredFolderName) !==
          fingerprintLogin({ ...current, deletedAt: null, archivedAt: null }, currentFolderName)
        await updateRemoteLogin(
          client,
          pending.remoteId,
          desired,
          current,
          remoteFolderId,
          contentChanged,
          signal
        )
      }
    }

    data.sync.pendingLoginMutation = null
    await this.core.commit(cloneData(data))
  }

  protected async persistCipherIsolationRecovery(
    completedLinks: readonly SyncLink[],
    newlyIsolatedRemoteIds: ReadonlySet<string>
  ): Promise<void> {
    const recovery = cloneData(this.core.requireData())
    if (!recovery.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    recovery.sync.requiresFullSyncAfterCipherIsolation = true

    for (const link of completedLinks) {
      if (
        !newlyIsolatedRemoteIds.has(link.remoteId) ||
        !recovery.logins.some((login) => login.id === link.localId)
      ) {
        continue
      }
      const duplicate = [...recovery.sync.loginMappings, ...recovery.sync.loginTombstones].find(
        (entry) => entry.localId === link.localId || entry.remoteId === link.remoteId
      )
      if (duplicate) {
        if (duplicate.localId === link.localId && duplicate.remoteId === link.remoteId) continue
        throw new VaultError('SYNC_FAILED')
      }
      // A create reached the server before its final authoritative snapshot quarantined the new
      // cipher. Persisting the assigned remote ID prevents retry from creating a duplicate.
      recovery.sync.loginMappings.push({ ...link })
    }
    recovery.updatedAt = this.core.nowIso()
    await this.core.commit(recovery)
  }

  protected async executeLoginImportBatch(
    data: VaultData,
    client: BitwardenSyncClient,
    batch: readonly LoginImportCandidate[],
    signal: AbortSignal
  ): Promise<Map<string, string>> {
    if (!data.sync || !supportsLoginImport(client) || batch.length < 2) {
      throw new VaultError('SYNC_FAILED')
    }
    const preparedValue: unknown = await client.prepareLoginImport!(
      batch.map((candidate) => ({
        localId: candidate.action.local.id,
        draft: remoteDraft(candidate.action.local, candidate.remoteFolderId)
      }))
    )
    const expected = new Map(batch.map((candidate) => [candidate.action.local.id, candidate]))
    const discardToken =
      isRecord(preparedValue) &&
      typeof preparedValue.token === 'string' &&
      preparedValue.token.length > 0 &&
      preparedValue.token.length <= 256
        ? preparedValue.token
        : null
    if (
      !isRecord(preparedValue) ||
      Reflect.ownKeys(preparedValue).length !== 2 ||
      discardToken === null ||
      !Array.isArray(preparedValue.entries) ||
      preparedValue.entries.length !== batch.length ||
      preparedValue.entries.some(
        (entry) =>
          !isRecord(entry) ||
          Reflect.ownKeys(entry).length !== 3 ||
          !Object.hasOwn(entry, 'localId') ||
          !Object.hasOwn(entry, 'marker') ||
          !Object.hasOwn(entry, 'remoteFolderId')
      )
    ) {
      if (discardToken) {
        await client.discardPreparedLoginImport!(discardToken).catch(() => undefined)
      }
      throw new VaultError('SYNC_FAILED')
    }
    const preparedEntries = preparedValue.entries as Array<{
      localId: string
      marker: string
      remoteFolderId: string | null
    }>
    if (
      new Set(preparedEntries.map((entry) => entry.localId)).size !== batch.length ||
      new Set(preparedEntries.map((entry) => entry.marker)).size !== batch.length ||
      preparedEntries.some((entry) => {
        const candidate = expected.get(entry.localId)
        return (
          !candidate ||
          typeof entry.localId !== 'string' ||
          !UUID_PATTERN.test(entry.localId) ||
          entry.remoteFolderId !== candidate.remoteFolderId ||
          typeof entry.marker !== 'string' ||
          entry.marker.length === 0 ||
          entry.marker.length > MAX_PENDING_LOGIN_IMPORT_MARKER_LENGTH ||
          /[\0\r\n]/u.test(entry.marker)
        )
      })
    ) {
      await client.discardPreparedLoginImport!(discardToken).catch(() => undefined)
      throw new VaultError('SYNC_FAILED')
    }

    data.sync.pendingLoginImport = {
      phase: 'prepared',
      startedAt: this.core.nowIso(),
      entries: preparedEntries.map((entry) => {
        const candidate = expected.get(entry.localId)!
        return {
          localId: entry.localId,
          marker: entry.marker,
          remoteFolderId: entry.remoteFolderId,
          baseFingerprint: candidate.baseFingerprint
        }
      })
    }
    data.updatedAt = this.core.nowIso()
    try {
      await this.core.commit(cloneData(data))
    } catch (error) {
      await client.discardPreparedLoginImport!(discardToken).catch(() => undefined)
      throw error
    }

    if (signal.aborted) {
      await client.discardPreparedLoginImport!(discardToken).catch(() => undefined)
      throw new BitwardenDirectError('ABORTED')
    }
    data.sync.pendingLoginImport.phase = 'dispatched'
    data.updatedAt = this.core.nowIso()
    try {
      await this.core.commit(cloneData(data))
    } catch (error) {
      // A lock that raced this write leaves 'dispatched' on disk; the abort path reverts it.
      if (!signal.aborted) {
        await client.discardPreparedLoginImport!(discardToken).catch(() => undefined)
        throw error
      }
    }

    if (signal.aborted) {
      try {
        data.sync.pendingLoginImport.phase = 'prepared'
        data.updatedAt = this.core.nowIso()
        await this.core.commit(cloneData(data))
      } finally {
        await client.discardPreparedLoginImport!(discardToken).catch(() => undefined)
      }
      throw new BitwardenDirectError('ABORTED')
    }
    let mutationError: unknown = null
    try {
      await client.executePreparedLoginImport!(discardToken, signal)
    } catch (error) {
      mutationError = error
    }
    if (signal.aborted) throw new BitwardenDirectError('ABORTED')

    let remoteFolders: BitwardenFolder[]
    let remoteLogins: BitwardenLoginItem[]
    try {
      await client.sync(signal)
      ;[remoteFolders, remoteLogins] = await Promise.all([
        client.listFolders(signal),
        client.listPersonalLogins(signal)
      ])
    } catch (error) {
      if (signal.aborted) throw new BitwardenDirectError('ABORTED')
      throw mutationError ?? error
    }
    const unmatched = await this.reconcilePendingLoginImport(
      data,
      client,
      remoteFolders,
      remoteLogins,
      signal
    )
    const remoteIds = new Map<string, string>()
    for (const candidate of batch) {
      const mapping = data.sync.loginMappings.find(
        (entry) => entry.localId === candidate.action.local.id
      )
      if (mapping) remoteIds.set(candidate.action.actionId, mapping.remoteId)
    }

    if (unmatched.length > 0) throw mutationError ?? new VaultError('SYNC_FAILED')
    return remoteIds
  }

  protected async reconcilePendingLoginImport(
    data: VaultData,
    client: BitwardenSyncClient,
    remoteFolders: readonly BitwardenFolder[],
    remoteLogins: readonly BitwardenLoginItem[],
    signal: AbortSignal
  ): Promise<string[]> {
    const pending = data.sync?.pendingLoginImport
    if (!data.sync || !pending || !client.reconcileLoginImportMarkers) {
      if (pending) throw new VaultError('SYNC_FAILED')
      return []
    }
    if (signal.aborted) throw new BitwardenDirectError('ABORTED')
    const matches = await client.reconcileLoginImportMarkers(
      pending.entries.map((entry) => entry.marker)
    )
    if (signal.aborted) throw new BitwardenDirectError('ABORTED')
    const pendingByMarker = new Map(pending.entries.map((entry) => [entry.marker, entry]))
    const remoteById = new Map(remoteLogins.map((login) => [login.id, login]))
    const remoteFolderNames = new Map(remoteFolders.map((folder) => [folder.id, folder.name]))
    const remoteSnapshotById = new Map(
      remoteSyncSnapshot([...remoteFolders], [...remoteLogins]).logins.map((login) => [
        login.id,
        login
      ])
    )
    const matchedMarkers = new Set<string>()
    const matchedRemoteIds = new Set<string>()
    if (remoteById.size !== remoteLogins.length) throw new VaultError('SYNC_FAILED')
    for (const match of matches) {
      const entry = pendingByMarker.get(match.marker)
      if (
        !entry ||
        matchedMarkers.has(match.marker) ||
        matchedRemoteIds.has(match.remoteId) ||
        !remoteById.has(match.remoteId) ||
        !remoteSnapshotById.has(match.remoteId) ||
        data.sync.loginMappings.some(
          (mapping) => mapping.localId === entry.localId || mapping.remoteId === match.remoteId
        ) ||
        data.sync.loginTombstones.some(
          (tombstone) =>
            tombstone.localId === entry.localId || tombstone.remoteId === match.remoteId
        )
      ) {
        throw new VaultError('SYNC_FAILED')
      }
      const remote = remoteSnapshotById.get(match.remoteId)!
      const remoteFingerprint = fingerprintLogin(
        remote,
        remote.folderId === null
          ? null
          : (remoteFolderNames.get(remote.folderId) ?? `missing:${remote.folderId}`)
      )
      if (remote.folderId !== entry.remoteFolderId || remoteFingerprint !== entry.baseFingerprint) {
        throw new VaultError('SYNC_FAILED')
      }
      matchedMarkers.add(match.marker)
      matchedRemoteIds.add(match.remoteId)
      data.sync.loginMappings.push({
        localId: entry.localId,
        remoteId: match.remoteId,
        baseFingerprint: entry.baseFingerprint
      })
    }
    const unmatchedEntries = pending.entries.filter((entry) => !matchedMarkers.has(entry.marker))
    const unmatched = unmatchedEntries.map((entry) => entry.localId)
    data.sync.pendingLoginImport =
      pending.phase === 'prepared' || unmatchedEntries.length === 0
        ? null
        : { ...pending, entries: unmatchedEntries.map((entry) => ({ ...entry })) }
    data.updatedAt = this.core.nowIso()
    await this.core.commit(cloneData(data))
    return unmatched
  }

  protected async executeBulkRemoteLoginMutation(
    client: BitwardenSyncClient,
    batch: readonly BulkRemoteLoginCandidate[],
    signal: AbortSignal
  ): Promise<void> {
    const mutation = batch[0]?.mutation
    if (!mutation || batch.some((candidate) => candidate.mutation !== mutation)) {
      throw new VaultError('SYNC_FAILED')
    }
    const ids = batch.map((candidate) => candidate.remoteId)
    let isolatedDuringReconciliation = new Set<string>()
    try {
      if (mutation === 'soft-delete') await client.softDeleteLogins!(ids, signal)
      else if (mutation === 'restore') await client.restoreLogins!(ids, signal)
      else if (mutation === 'move') await client.moveLogins!(ids, batch[0]!.folderId, signal)
      else if (mutation === 'archive') await client.archiveLogins!(ids, signal)
      else if (mutation === 'unarchive') await client.unarchiveLogins!(ids, signal)
      else await client.hardDeleteLogins!(ids, signal)
    } catch (error) {
      if (signal.aborted) throw error
      try {
        await client.sync(signal)
        const isolated = isolatedPersonalCipherIdsOf(client)
        isolatedDuringReconciliation = new Set(
          batch.flatMap((candidate) =>
            isolated.has(candidate.remoteId) ? [candidate.remoteId] : []
          )
        )
        const remote = new Map(
          (await client.listPersonalLogins(signal)).map((login) => [login.id, login])
        )
        if (
          batch.every(
            (candidate) =>
              !isolated.has(candidate.remoteId) && bulkRemoteLoginMutationApplied(candidate, remote)
          )
        ) {
          return
        }
      } catch (reconciliationError) {
        if (
          reconciliationError instanceof BitwardenDirectError &&
          (reconciliationError.code === 'AUTH_REQUIRED' ||
            reconciliationError.code === 'ACCOUNT_CHANGED' ||
            reconciliationError.code === 'ABORTED')
        ) {
          throw reconciliationError
        }
        // The original mutation error is the most useful failure. A later sync retries safely
        // from the server's authoritative state instead of assuming this batch was atomic.
      }
      if (signal.aborted) throw new BitwardenDirectError('ABORTED')
      if (isolatedDuringReconciliation.size > 0) {
        await this.persistCipherIsolationRecovery([], isolatedDuringReconciliation)
      }
      throw error
    }
  }

  protected async executeSyncAction(
    data: VaultData,
    client: BitwardenSyncClient,
    action: SyncAction,
    completed: Map<string, SyncActionResult>,
    signal: AbortSignal
  ): Promise<SyncActionResult> {
    const result: SyncActionResult = { actionId: action.actionId }
    if (action.entity === 'folder') {
      if (action.kind === 'push-create') {
        result.remoteId = (await client.createFolder(action.local.name, signal)).id
      } else if (action.kind === 'push-update') {
        await client.editFolder(action.remoteId, action.local.name, signal)
      } else if (action.kind === 'pull-create') {
        result.localId = createLocalFolder(this.core, data, action.remote.name).id
      } else if (action.kind === 'pull-update') {
        const folder = findFolder(data, action.localId)
        folder.name = action.remote.name
        folder.updatedAt = this.core.nowIso()
      } else if (action.kind === 'delete-local') {
        deleteLocalFolder(this.core, data, action.localId)
      } else if (action.kind === 'delete-remote') {
        await client.deleteFolder(action.remoteId, signal)
      } else if (action.reason === 'both-modified') {
        if (!action.local || !action.remote) throw new VaultError('SYNC_FAILED')
        createLocalFolder(this.core, data, action.conflictName)
        const primary = findFolder(data, action.local.id)
        primary.name = action.remote.name
        primary.updatedAt = this.core.nowIso()
      } else if (action.reason === 'remote-deleted') {
        if (!action.local) throw new VaultError('SYNC_FAILED')
        const local = findFolder(data, action.local.id)
        local.name = action.conflictName
        local.updatedAt = this.core.nowIso()
        result.remoteId = (await client.createFolder(action.conflictName, signal)).id
      } else {
        if (!action.remote) throw new VaultError('SYNC_FAILED')
        await client.editFolder(action.remote.id, action.conflictName, signal)
        result.localId = createLocalFolder(this.core, data, action.conflictName).id
      }
      return result
    }

    if (action.kind === 'push-create') {
      const folderId = resolveFolderReference(action.remoteFolder, completed, 'remoteId')
      const created = await client.createLogin(remoteDraft(action.local, folderId), signal)
      result.remoteId = created.id
      if (action.local.deletedAt !== null) await client.softDeleteLogin(created.id, signal)
    } else if (action.kind === 'push-update') {
      const folderId = resolveFolderReference(action.remoteFolder, completed, 'remoteId')
      const composite = isCompositeRemoteLoginUpdate(
        action.local,
        action.remote,
        action.contentChanged
      )
      if (composite) {
        if (!data.sync) throw new VaultError('SYNC_FAILED')
        data.sync.pendingLoginMutation = {
          intent: 'converge',
          localId: action.local.id,
          remoteId: action.remoteId,
          remoteFolderId: folderId,
          expectedRemoteFingerprints: [...action.resumeFingerprints]
        }
        await this.core.commit(cloneData(data))
      }
      await updateRemoteLogin(
        client,
        action.remoteId,
        action.local,
        action.remote,
        folderId,
        action.contentChanged,
        signal
      )
      if (composite) {
        if (!data.sync) throw new VaultError('SYNC_FAILED')
        data.sync.pendingLoginMutation = null
        await this.core.commit(cloneData(data))
      }
    } else if (action.kind === 'pull-create') {
      const folderId = resolveFolderReference(action.localFolder, completed, 'localId')
      result.localId = createLocalLogin(this.core, data, action.remote, folderId).id
    } else if (action.kind === 'pull-update') {
      const folderId = resolveFolderReference(action.localFolder, completed, 'localId')
      updateLocalLogin(this.core, data, action.localId, action.remote, folderId)
    } else if (action.kind === 'delete-local') {
      data.logins = data.logins.filter((login) => login.id !== action.localId)
    } else if (action.kind === 'delete-remote') {
      await client.hardDeleteLogin(action.remoteId, signal)
    } else if (action.reason === 'both-modified') {
      if (!action.local || !action.remote) throw new VaultError('SYNC_FAILED')
      const copyFolderId =
        action.local.folderId && data.folders.some((folder) => folder.id === action.local!.folderId)
          ? action.local.folderId
          : null
      createLocalLogin(
        this.core,
        data,
        { ...action.local, name: action.conflictName },
        copyFolderId
      )
      const primaryFolderId = resolveFolderReference(action.localFolder, completed, 'localId')
      updateLocalLogin(this.core, data, action.local.id, action.remote, primaryFolderId)
    } else if (action.reason === 'remote-deleted') {
      if (!action.local) throw new VaultError('SYNC_FAILED')
      const local = findLogin(data, action.local.id)
      local.name = action.conflictName
      local.updatedAt = this.core.nowIso()
      const folderId = resolveFolderReference(action.remoteFolder, completed, 'remoteId')
      result.remoteId = (
        await client.createLogin(
          remoteDraft({ ...action.local, name: action.conflictName }, folderId),
          signal
        )
      ).id
      if (action.local.deletedAt !== null) await client.softDeleteLogin(result.remoteId, signal)
    } else {
      if (!action.remote) throw new VaultError('SYNC_FAILED')
      const remoteFolderId = action.remote.folderId
      await updateRemoteLogin(
        client,
        action.remote.id,
        { ...action.remote, name: action.conflictName },
        action.remote,
        remoteFolderId,
        true,
        signal
      )
      const localFolderId = resolveFolderReference(action.localFolder, completed, 'localId')
      result.localId = createLocalLogin(
        this.core,
        data,
        { ...action.remote, name: action.conflictName },
        localFolderId
      ).id
    }
    return result
  }

  protected invalidatePinUnlockCapability(): void {
    this.pinLifecycleEpoch += 1
    this.pinUnlockCapability?.dispose()
    this.pinUnlockCapability = null
  }

  protected mapPinUnlockError(error: PinUnlockError): VaultError {
    if (error.code === 'INVALID_INPUT') return new VaultError('INVALID_INPUT')
    if (error.code === 'INVALID_PIN') return new VaultError('INVALID_PIN')
    if (error.code === 'RATE_LIMITED') return new VaultError('RATE_LIMITED')
    return new VaultError('PIN_DISABLED')
  }
}
