import { createHash, randomInt as nodeRandomInt, randomUUID } from 'node:crypto'
import type {
  AttachmentOperationKind,
  AttachmentOperationStage,
  AttachmentProgressEvent,
  AttachmentTargetRequest,
  CardCoverPreviewResult,
  LoginApprovalPrompt,
  FolderView,
  LoginIdRequest,
  OrganizationView,
  CollectionView,
  VaultAttachmentView,
  SyncPurgePersonalVaultResult,
  SyncResult,
  VaultTimeoutPolicy,
  VaultStatus
} from '../shared/vault-contract'
import {
  BitwardenDirectError,
  type BitwardenFolder,
  type BitwardenLoginDraft,
  type BitwardenLoginItem,
  type BitwardenLoginApprovalRequest,
  type BitwardenOrganizationCipher,
  type BitwardenSendItem,
  type BitwardenSyncClient,
  type BitwardenWebAuthnRegistrationSetup
} from './bitwarden-direct'
import { resolveBitwardenUrls, type BitwardenEquivalentDomainSettings } from './bitwarden-http'
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
import { type PortableVaultSnapshot } from './vault-portability-codec'
import {
  assertNativeAttachmentRestoreBinding,
  failNativeAttachmentRestoreAttempt,
  recoverInterruptedNativeAttachmentRestore,
  type NativeAttachmentRestoreAttachmentKey,
  type NativeAttachmentRestoreJournal
} from './native-attachment-restore'
import {
  completeSyncMetadata,
  fingerprintFolder,
  fingerprintLogin,
  legacyCustomFieldBaselineUpgrades,
  planSync,
  type SyncAction,
  type SyncActionResult,
  type SyncFolderReference,
  type SyncLink,
  type SyncLogin,
  type SyncMetadata,
  type SyncSnapshot
} from './sync-merge'
import { VaultError } from './vault-errors'
import type { VaultAttachmentFileService } from './vault-attachment-files'
import type { AccountWebAuthnAttestation } from './account-webauthn-registration-codec'
import {
  DATA_VERSION,
  MAX_MASTER_PASSWORD_LENGTH,
  MAX_USERNAME_LENGTH,
  MAX_NAME_LENGTH,
  MAX_PASSWORD_LENGTH,
  MAX_NOTES_LENGTH,
  MAX_ATTACHMENT_ID_LENGTH,
  MAX_PENDING_LOGIN_IMPORT_ENTRIES,
  MAX_PENDING_LOGIN_IMPORT_MARKER_LENGTH
} from './vault/limits'
import {
  assertUuid,
  normalizeRequiredString,
  normalizeNullableString,
  normalizeMasterPassword,
  normalizeSyncPassword
} from './vault/parse-primitives'
import { cloneData } from './vault/vault-data-parsing'
import {
  validRemoteDate,
  validRemoteDeletedDate,
  validRemoteArchivedDate,
  isCompositeRemoteLoginUpdate,
  sameLoginContentExceptFolder
} from './vault/views'
import { assertNoPendingPersonalVaultPurge } from './vault/sync-data-parsing'
import { parseFolder, parseStoredLogin } from './vault/login-parsing'
import { sendViewFromRemote } from './vault/send-parsing'
import { validateRemotePasskeys } from './vault/passkey-parsing'
import { cloneCustomFields } from './vault/custom-fields'
import { cloneLoginUris, uriAlias, remoteLoginUris } from './vault/login-uris'
import { normalizeItemFieldsForStorage, normalizeItemType } from './vault/item-fields'
import {
  cloneEquivalentDomainSettings,
  validateRemoteEquivalentDomainSettings
} from './vault/equivalent-domains'
import { parseStoredOrganization, parseStoredCollection } from './vault/org-collection-parsing'
import { cloneAttachments, validateRemoteAttachments } from './vault/attachments-parsing'
import { VaultGeneratorService } from './vault/generator-service'
import { VaultSendService } from './vault/send-service'
import { VaultCore } from './vault/core'
import { cloneGeneratorHistory } from './vault/generator-history'
import { clonePasswordHistory } from './vault/password-history'
import type {
  StoredLogin,
  StoredSharedLogin,
  SyncEntityMapping,
  SyncTombstone,
  PersistedSyncData,
  VaultData,
  VaultMasterPasswordChangeStatus,
  VaultMasterPasswordChangeRequest,
  VaultMasterPasswordChangeResolutionRequest,
  VaultMasterPasswordChangeResolution,
  VaultPlatform,
  VaultAccountWebAuthnAssertionRequester,
  VaultAccountWebAuthnRegistrationRequester,
  VaultServiceOptions,
  VaultNativeAttachmentRestoreSummary
} from './vault/types'
import { UUID_PATTERN, isRecord } from './validation-primitives'
import {
  findFolder,
  findLogin,
  assertActiveLogin,
  uniqueImportedFolderName
} from './vault/data-lookup'
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

type BulkRemoteLoginMutation =
  'soft-delete' | 'restore' | 'move' | 'archive' | 'unarchive' | 'hard-delete'
const MAX_REMOTE_LOGIN_BATCH_IDS = 500

interface BulkRemoteLoginCandidate {
  action: Extract<SyncAction, { entity: 'login' }>
  mutation: BulkRemoteLoginMutation
  remoteId: string
  folderId: string | null
}

interface LoginImportCandidate {
  action: Extract<SyncAction, { entity: 'login'; kind: 'push-create' }>
  remoteFolderId: string | null
  baseFingerprint: string
}

type AttachmentAuthorizationValidator = (
  ids: readonly string[],
  state: { generation: number }
) => boolean

type ItemReadAuthorizationValidator = (
  ids: readonly string[],
  state: { generation: number }
) => boolean

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
export type {
  AttachmentAuthorizationValidator,
  ItemReadAuthorizationValidator,
  AccountWebAuthnOperationLease
}

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
  protected readonly cardCoverCache = new ImageMemoryCache<CardCoverPreviewResult>({
    maxEntries: 256,
    maxSize: 64 * 1024 * 1024
  })
  protected readonly cardCoverRequests = new Map<string, Promise<CardCoverPreviewResult | null>>()
  protected readonly cardCoverDownloads = new ConcurrencyLimiter(3)
  /** Aborted on lock so detached image downloads stop as soon as the vault key is gone. */
  protected readonly imageRequestAborts = new Set<AbortController>()
  protected readonly core: VaultCore
  protected readonly syncSession: VaultSyncSession
  protected readonly folders: VaultFolders
  protected readonly health: VaultHealth

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
        this.cardCoverCache.clear()
        this.cardCoverRequests.clear()
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
      this.assertMasterPasswordChangeAccount(data)
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
        this.assertMasterPasswordChangeAccount(current)
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
            accountFingerprint: this.masterPasswordChangeAccountFingerprint(sync)
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
        this.assertMasterPasswordChangeAccount(current)
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
          this.assertMasterPasswordChangeAccount(cleared)
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
        this.assertMasterPasswordChangeAccount(confirmed)
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

  protected masterPasswordChangeAccountFingerprint(sync: PersistedSyncData): string {
    const profileId = sync.state.profileId
    if (!profileId || !UUID_PATTERN.test(profileId)) {
      throw new VaultError('CORRUPT_VAULT', 'CORRUPT_VAULT:sync-profile-id')
    }
    const canonicalAccount = JSON.stringify({
      provider: sync.provider,
      serverUrl: resolveBitwardenUrls(sync.serverUrl).apiUrl,
      profileId
    })
    return createHash('sha256').update(canonicalAccount, 'utf8').digest('hex')
  }

  protected assertMasterPasswordChangeAccount(data: VaultData): void {
    const journal = data.masterPasswordChange
    if (!journal) return
    if (
      !data.sync ||
      journal.accountFingerprint !== this.masterPasswordChangeAccountFingerprint(data.sync)
    ) {
      throw new VaultError('CORRUPT_VAULT', 'CORRUPT_VAULT:password-change-account')
    }
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
    this.assertMasterPasswordChangeAccount(current)
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
    this.assertMasterPasswordChangeAccount(current)
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

  protected mapAttachmentError(
    error: unknown,
    operation?: { canceledByUser: boolean }
  ): VaultError {
    if (
      operation?.canceledByUser &&
      ((error instanceof VaultError && error.code === 'LOCKED') ||
        (error instanceof BitwardenDirectError && error.code === 'ABORTED'))
    ) {
      return new VaultError('ATTACHMENT_CANCELED')
    }
    if (error instanceof VaultError) return error
    if (error instanceof BitwardenDirectError) {
      if (error.code === 'ABORTED') return new VaultError('LOCKED')
      if (error.code === 'NOT_FOUND') return new VaultError('NOT_FOUND')
      if (error.code === 'STORAGE_LIMIT') return new VaultError('ATTACHMENT_STORAGE_LIMIT')
      if (error.code === 'TOO_LARGE') return new VaultError('ATTACHMENT_TOO_LARGE')
      if (error.code === 'ATTACHMENT_REJECTED') return new VaultError('ATTACHMENT_REJECTED')
      if (
        error.code === 'AUTH_REQUIRED' ||
        error.code === 'TWO_FACTOR_REQUIRED' ||
        error.code === 'NEW_DEVICE_REQUIRED'
      ) {
        return this.syncSession.mapSyncError(error)
      }
    }
    return new VaultError('ATTACHMENT_FAILED')
  }

  protected attachmentMutationContext(
    request: AttachmentTargetRequest,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): {
    data: VaultData
    attachment: VaultAttachmentView
    mapping: SyncEntityMapping
    client: BitwardenSyncClient
  } {
    assertUuid(request.id)
    assertUuid(request.operationId)
    if (
      typeof request.attachmentId !== 'string' ||
      request.attachmentId.length === 0 ||
      request.attachmentId.length > MAX_ATTACHMENT_ID_LENGTH
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    const data = this.core.requireData()
    assertNoPendingPersonalVaultPurge(data.sync)
    const login = findLogin(data, request.id)
    assertActiveLogin(login)
    this.assertAttachmentAuthorized(login, validateAuthorization)
    const attachment = login.attachments.find((entry) => entry.id === request.attachmentId)
    if (!attachment) throw new VaultError('NOT_FOUND')
    const sync = this.syncSession.requireSyncData()
    const mapping = sync.loginMappings.find((entry) => entry.localId === login.id)
    if (!mapping) throw new VaultError('INVALID_INPUT')
    return { data, attachment, mapping, client: this.syncSession.getOrCreateSyncClient(sync) }
  }

  protected assertAttachmentAuthorized(
    login: StoredLogin,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): void {
    if (
      login.reprompt === 1 &&
      !validateAuthorization?.([login.id], { generation: this.core.generation })
    ) {
      throw new VaultError('REPROMPT_REQUIRED')
    }
  }

  protected reportAttachmentProgress(
    report: ((progress: AttachmentProgressEvent) => void) | undefined,
    request: { id: string; operationId: string },
    kind: AttachmentOperationKind,
    stage: AttachmentOperationStage,
    completedBytes: number,
    totalBytes: number | null
  ): void {
    if (!report) return
    try {
      report({
        operationId: request.operationId,
        itemId: request.id,
        kind,
        stage,
        completedBytes,
        totalBytes
      })
    } catch {
      // Renderer progress is advisory and must never decide mutation success.
    }
  }

  protected async persistAttachmentMutation(
    current: VaultData,
    client: BitwardenSyncClient
  ): Promise<void> {
    const sync = current.sync
    if (!sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    assertNoPendingPersonalVaultPurge(sync)
    const [remoteFolders, remoteLogins] = await Promise.all([
      client.listFolders(),
      client.listPersonalLogins()
    ])
    const next = cloneData(current)
    this.reconcileServerAuthoritativeAttachments(
      next,
      sync.loginMappings,
      remoteFolders,
      remoteLogins
    )
    const syncedAt = this.core.nowIso()
    if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    next.sync.state = client.exportState()
    next.sync.lastSyncAt = syncedAt
    next.updatedAt = syncedAt
    await this.core.commit(next)
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
      const isolatedPersonalCipherIds = this.isolatedPersonalCipherIds(client)
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
    const initialIsolatedPersonalCipherIds = this.isolatedPersonalCipherIds(client)
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
      this.getSyncEquivalentDomainSettings(
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
      const refreshedIsolatedPersonalCipherIds = this.isolatedPersonalCipherIds(client)
      if (refreshedIsolatedPersonalCipherIds.size > 0) {
        await this.persistCipherIsolationRecovery([], refreshedIsolatedPersonalCipherIds)
        if (next.sync) next.sync.requiresFullSyncAfterCipherIsolation = true
      }
      const newlyIsolatedPendingRemoteIds = this.newlyIsolatedMappedRemoteIds(
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
    const remoteSnapshot = this.remoteSyncSnapshot(remoteFolders, remoteLogins)
    const syncMetadata = this.syncMetadata(next.sync ?? sync)
    syncMetadata.loginLinks = syncMetadata.loginLinks.filter(
      (entry) => !initialIsolatedPersonalCipherIds.has(entry.remoteId)
    )
    for (const upgrade of legacyCustomFieldBaselineUpgrades(
      this.withoutProtectedLoginSnapshot(this.localSyncSnapshot(next), protectedLocalLoginIds),
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
      this.withoutProtectedLoginSnapshot(this.localSyncSnapshot(next), protectedLocalLoginIds),
      remoteSnapshot,
      syncMetadata
    )
    const results: SyncActionResult[] = []
    const completed = new Map<string, SyncActionResult>()
    const counts = { pulled: 0, pushed: 0, deleted: 0, conflicts: 0 }

    for (let actionIndex = 0; actionIndex < plan.actions.length; actionIndex += 1) {
      const action = plan.actions[actionIndex]!
      if (signal.aborted) throw new BitwardenDirectError('ABORTED')
      const importCandidate = this.loginImportCandidate(action, completed, skipBulkImportLocalIds)
      if (importCandidate && this.supportsLoginImport(client)) {
        const batch: LoginImportCandidate[] = [importCandidate]
        for (let nextIndex = actionIndex + 1; nextIndex < plan.actions.length; nextIndex += 1) {
          if (batch.length === MAX_PENDING_LOGIN_IMPORT_ENTRIES) break
          const candidate = this.loginImportCandidate(
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
      const batchCandidate = this.bulkRemoteLoginCandidate(action, completed)
      if (batchCandidate && this.supportsBulkRemoteLoginMutation(client, batchCandidate.mutation)) {
        const batch: BulkRemoteLoginCandidate[] = [batchCandidate]
        for (let nextIndex = actionIndex + 1; nextIndex < plan.actions.length; nextIndex += 1) {
          if (batch.length === MAX_REMOTE_LOGIN_BATCH_IDS) break
          const candidate = this.bulkRemoteLoginCandidate(plan.actions[nextIndex]!, completed)
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
    const completedLoginLinks = this.reattachProtectedLoginLinks(
      metadata.loginLinks,
      protectedLoginMappings,
      protectedLoginTombstones
    )
    // A plan that only touched local data leaves the server as the last download saw it.
    if (plan.actions.some(changesRemote)) await client.sync(signal)
    const finalIsolatedPersonalCipherIds = this.isolatedPersonalCipherIds(client)
    const newlyIsolatedMappedRemoteIds = this.newlyIsolatedMappedRemoteIds(
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
      this.getSyncEquivalentDomainSettings(client, initialRemote[2], signal)
    ])
    const finalSharedSnapshot = await this.fetchSharedSnapshot(client)
    const finalRemoteSends = client.listSends ? await client.listSends(signal) : remoteSends
    this.reconcileServerAuthoritativeAttachments(
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
    if (this.hasPendingLocalSyncWork(source)) return null
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

  protected hasPendingLocalSyncWork(data: VaultData): boolean {
    const sync = data.sync
    if (!sync) return true
    if (
      sync.requiresFullSyncAfterCipherIsolation === true ||
      sync.pendingLoginMutation ||
      sync.pendingLoginImport ||
      sync.pendingPersonalVaultPurge ||
      sync.folderTombstones.length > 0 ||
      sync.loginTombstones.length > 0
    ) {
      return true
    }

    const folderMappings = new Map(sync.folderMappings.map((entry) => [entry.localId, entry]))
    const mappedRemoteFolderIds = new Set(sync.folderMappings.map((entry) => entry.remoteId))
    if (
      folderMappings.size !== sync.folderMappings.length ||
      mappedRemoteFolderIds.size !== sync.folderMappings.length ||
      folderMappings.size !== data.folders.length
    ) {
      return true
    }
    for (const folder of data.folders) {
      if (folderMappings.get(folder.id)?.baseFingerprint !== fingerprintFolder(folder)) return true
    }

    const loginMappings = new Map(sync.loginMappings.map((entry) => [entry.localId, entry]))
    const mappedRemoteLoginIds = new Set(sync.loginMappings.map((entry) => entry.remoteId))
    if (
      loginMappings.size !== sync.loginMappings.length ||
      mappedRemoteLoginIds.size !== sync.loginMappings.length ||
      loginMappings.size !== data.logins.length
    ) {
      return true
    }
    const folderNames = new Map(data.folders.map((folder) => [folder.id, folder.name]))
    for (const login of this.localSyncSnapshot(data).logins) {
      const canonicalFolder =
        login.folderId === null
          ? null
          : (folderNames.get(login.folderId) ?? `missing:${login.folderId}`)
      if (
        loginMappings.get(login.id)?.baseFingerprint !== fingerprintLogin(login, canonicalFolder)
      ) {
        return true
      }
    }
    return false
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
      client
        .listOrganizations()
        .catch((error) => this.throwSharedSnapshotError(error, 'organization')),
      client.listCollections().catch((error) => this.throwSharedSnapshotError(error, 'collection')),
      client
        .listOrganizationCiphers()
        .catch((error) => this.throwSharedSnapshotError(error, 'cipher'))
    ])
    let parsedOrganizations: OrganizationView[]
    try {
      parsedOrganizations = organizations.map(parseStoredOrganization)
    } catch (error) {
      this.throwSharedSnapshotError(error, 'organization')
    }
    const organizationIds = new Set(parsedOrganizations.map((organization) => organization.id))
    if (organizationIds.size !== parsedOrganizations.length) {
      throw new BitwardenDirectError('INVALID_RESPONSE', undefined, 'organization')
    }
    let parsedCollections: CollectionView[]
    try {
      parsedCollections = collections.map(parseStoredCollection)
    } catch (error) {
      this.throwSharedSnapshotError(error, 'collection')
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
      parsedSharedLogins = sharedLogins.map((login) => this.sharedLoginFromRemote(login))
    } catch (error) {
      this.throwSharedSnapshotError(error, 'cipher')
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

  protected throwSharedSnapshotError(
    error: unknown,
    stage: 'organization' | 'collection' | 'cipher'
  ): never {
    if (error instanceof BitwardenDirectError) {
      if (error.code !== 'INVALID_RESPONSE' || error.syncInvalidResponseStage) throw error
      throw new BitwardenDirectError('INVALID_RESPONSE', undefined, stage)
    }
    throw new BitwardenDirectError('INVALID_RESPONSE', undefined, stage)
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
    const desired = this.localSyncSnapshot(data).logins.find(
      (login) => login.id === pending.localId
    )
    const current = this.remoteSyncSnapshot(remoteFolders, remoteLogins).logins.find(
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
        await this.updateRemoteLogin(
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

  protected localSyncSnapshot(data: VaultData): SyncSnapshot {
    return {
      folders: data.folders.map((folder) => ({
        id: folder.id,
        name: folder.name,
        updatedAt: folder.updatedAt
      })),
      logins: data.logins.map((login) => ({
        ...login,
        uris: cloneLoginUris(login.uris),
        passkeys: login.passkeys.map((passkey) => ({ ...passkey })),
        customFields: cloneCustomFields(login.customFields),
        passwordHistory: clonePasswordHistory(login.passwordHistory),
        attachments: cloneAttachments(login.attachments)
      })),
      tombstones: {
        folders: (data.sync?.folderTombstones ?? []).map((entry) => ({
          id: entry.localId,
          deletedAt: data.updatedAt
        })),
        logins: (data.sync?.loginTombstones ?? []).map((entry) => ({
          id: entry.localId,
          deletedAt: data.updatedAt
        }))
      }
    }
  }

  protected remoteSyncSnapshot(
    folders: BitwardenFolder[],
    logins: BitwardenLoginItem[]
  ): SyncSnapshot {
    return {
      folders: folders.map((folder) => ({ id: folder.id, name: folder.name })),
      logins: logins.map((login) => ({
        ...login,
        uris: cloneLoginUris(login.uris),
        passkeys: validateRemotePasskeys(login.passkeys),
        passwordHistory: clonePasswordHistory(login.passwordHistory),
        uri: uriAlias(login.uris),
        // Wire metadata is login-only upstream (vaultwarden nests it under the login object).
        // Null it for other item types here, mirroring the upload path, so a quirky server
        // cannot persist a combination the vault schema rejects at the next unlock.
        passwordRevisionDate: login.type === 'login' ? login.passwordRevisionDate : null,
        autofillOnPageLoad: login.type === 'login' ? login.autofillOnPageLoad : null,
        createdAt: validRemoteDate(login.creationDate),
        updatedAt: validRemoteDate(login.revisionDate),
        deletedAt: validRemoteDeletedDate(login.deletedAt),
        archivedAt: validRemoteArchivedDate(login.archivedAt)
      })),
      tombstones: { folders: [], logins: [] }
    }
  }

  protected reconcileServerAuthoritativeAttachments(
    data: VaultData,
    links: readonly SyncLink[],
    remoteFolders: readonly BitwardenFolder[],
    remoteLogins: readonly BitwardenLoginItem[]
  ): void {
    const remoteById = new Map(remoteLogins.map((login) => [login.id, login]))
    if (remoteById.size !== remoteLogins.length) throw new VaultError('SYNC_FAILED')
    const remoteSnapshotById = new Map(
      this.remoteSyncSnapshot([], [...remoteLogins]).logins.map((login) => [login.id, login])
    )
    const remoteFolderNames = new Map(remoteFolders.map((folder) => [folder.id, folder.name]))
    if (remoteFolderNames.size !== remoteFolders.length) throw new VaultError('SYNC_FAILED')

    for (const link of links) {
      const local = data.logins.find((login) => login.id === link.localId)
      const remote = remoteById.get(link.remoteId)
      const remoteSnapshot = remoteSnapshotById.get(link.remoteId)
      if (
        !local ||
        !remote ||
        !remoteSnapshot ||
        fingerprintLogin(
          remoteSnapshot,
          remoteSnapshot.folderId === null
            ? null
            : (remoteFolderNames.get(remoteSnapshot.folderId) ??
                `missing:${remoteSnapshot.folderId}`)
        ) !== link.baseFingerprint
      ) {
        throw new VaultError('SYNC_FAILED')
      }
      local.attachments = validateRemoteAttachments(remote.attachments)
      const revisionDate = validRemoteDate(remote.revisionDate)
      if (revisionDate) local.updatedAt = revisionDate
    }
  }

  protected syncMetadata(sync: PersistedSyncData): SyncMetadata {
    return {
      version: 1,
      folderLinks: [...sync.folderMappings, ...sync.folderTombstones].map((entry) => ({
        localId: entry.localId,
        remoteId: entry.remoteId,
        baseFingerprint: entry.baseFingerprint
      })),
      loginLinks: [...sync.loginMappings, ...sync.loginTombstones].map((entry) => ({
        localId: entry.localId,
        remoteId: entry.remoteId,
        baseFingerprint: entry.baseFingerprint
      }))
    }
  }

  protected withoutProtectedLoginSnapshot(
    snapshot: SyncSnapshot,
    protectedLocalIds: ReadonlySet<string>
  ): SyncSnapshot {
    if (protectedLocalIds.size === 0) return snapshot
    return {
      ...snapshot,
      logins: snapshot.logins.filter((login) => !protectedLocalIds.has(login.id)),
      tombstones: {
        ...snapshot.tombstones,
        logins: snapshot.tombstones.logins.filter(
          (tombstone) => !protectedLocalIds.has(tombstone.id)
        )
      }
    }
  }

  protected reattachProtectedLoginLinks(
    completedLinks: readonly SyncLink[],
    protectedMappings: readonly SyncEntityMapping[],
    protectedTombstones: readonly SyncTombstone[]
  ): { loginMappings: SyncEntityMapping[]; loginTombstones: SyncTombstone[] } {
    const loginMappings: SyncEntityMapping[] = []
    const loginTombstones: SyncTombstone[] = []
    const attached: Array<{
      kind: 'mapping' | 'tombstone'
      link: SyncEntityMapping | SyncTombstone
    }> = []
    const attach = (
      kind: 'mapping' | 'tombstone',
      link: SyncEntityMapping | SyncTombstone
    ): void => {
      const duplicate = attached.find(
        (entry) => entry.link.localId === link.localId || entry.link.remoteId === link.remoteId
      )
      if (duplicate) {
        if (
          duplicate.kind === kind &&
          duplicate.link.localId === link.localId &&
          duplicate.link.remoteId === link.remoteId &&
          duplicate.link.baseFingerprint === link.baseFingerprint
        ) {
          return
        }
        throw new VaultError('SYNC_FAILED')
      }
      const cloned = { ...link }
      attached.push({ kind, link: cloned })
      if (kind === 'mapping') loginMappings.push(cloned)
      else loginTombstones.push(cloned)
    }

    for (const link of completedLinks) attach('mapping', link)
    for (const link of protectedMappings) attach('mapping', link)
    for (const link of protectedTombstones) attach('tombstone', link)
    return { loginMappings, loginTombstones }
  }

  protected getAuthoritativeEquivalentDomainSettings(
    client: BitwardenSyncClient,
    signal?: AbortSignal
  ): Promise<BitwardenEquivalentDomainSettings> {
    const getter =
      client.getAuthoritativeEquivalentDomainSettings ?? client.getEquivalentDomainSettings
    return getter.call(client, signal)
  }

  protected async getSyncEquivalentDomainSettings(
    client: BitwardenSyncClient,
    lastKnownGood: BitwardenEquivalentDomainSettings,
    signal?: AbortSignal
  ): Promise<BitwardenEquivalentDomainSettings> {
    try {
      return await this.getAuthoritativeEquivalentDomainSettings(client, signal)
    } catch (error) {
      if (
        error instanceof BitwardenDirectError &&
        (error.code === 'INVALID_RESPONSE' ||
          error.code === 'TOO_LARGE' ||
          error.code === 'NOT_FOUND')
      ) {
        // Equivalent-domain rules are ancillary matching hints. A malformed self-hosted setting
        // must not block vault data, but it also must not replace the last authoritative snapshot.
        return cloneEquivalentDomainSettings(lastKnownGood)
      }
      throw error
    }
  }

  protected isolatedPersonalCipherIds(client: BitwardenSyncClient): ReadonlySet<string> {
    return new Set(client.isolatedPersonalCipherIds?.() ?? [])
  }

  protected newlyIsolatedMappedRemoteIds(
    isolatedRemoteIds: ReadonlySet<string>,
    links: readonly { remoteId: string }[],
    protectedRemoteIds: ReadonlySet<string>
  ): ReadonlySet<string> {
    return new Set(
      links.flatMap((link) =>
        isolatedRemoteIds.has(link.remoteId) && !protectedRemoteIds.has(link.remoteId)
          ? [link.remoteId]
          : []
      )
    )
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

  protected loginImportCandidate(
    action: SyncAction,
    completed: Map<string, SyncActionResult>,
    skipLocalIds: ReadonlySet<string>
  ): LoginImportCandidate | null {
    if (
      action.entity !== 'login' ||
      action.kind !== 'push-create' ||
      action.local.deletedAt !== null ||
      skipLocalIds.has(action.local.id) ||
      typeof action.baseFingerprint !== 'string' ||
      !/^[0-9a-f]{64}$/u.test(action.baseFingerprint)
    ) {
      return null
    }
    return {
      action,
      remoteFolderId: this.resolveFolderReference(action.remoteFolder, completed, 'remoteId'),
      baseFingerprint: action.baseFingerprint
    }
  }

  protected supportsLoginImport(client: BitwardenSyncClient): boolean {
    return (
      client.prepareLoginImport !== undefined &&
      client.executePreparedLoginImport !== undefined &&
      client.reconcileLoginImportMarkers !== undefined &&
      client.discardPreparedLoginImport !== undefined
    )
  }

  protected async executeLoginImportBatch(
    data: VaultData,
    client: BitwardenSyncClient,
    batch: readonly LoginImportCandidate[],
    signal: AbortSignal
  ): Promise<Map<string, string>> {
    if (!data.sync || !this.supportsLoginImport(client) || batch.length < 2) {
      throw new VaultError('SYNC_FAILED')
    }
    const preparedValue: unknown = await client.prepareLoginImport!(
      batch.map((candidate) => ({
        localId: candidate.action.local.id,
        draft: this.remoteDraft(candidate.action.local, candidate.remoteFolderId)
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
      this.remoteSyncSnapshot([...remoteFolders], [...remoteLogins]).logins.map((login) => [
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

  protected bulkRemoteLoginCandidate(
    action: SyncAction,
    completed: Map<string, SyncActionResult>
  ): BulkRemoteLoginCandidate | null {
    if (action.entity !== 'login') return null
    if (action.kind === 'delete-remote') {
      return {
        action,
        mutation: 'hard-delete',
        remoteId: action.remoteId,
        folderId: null
      }
    }
    if (action.kind !== 'push-update') return null

    const desiredDeleted = action.local.deletedAt !== null
    const currentDeleted = action.remote.deletedAt !== null
    const desiredArchived = action.local.archivedAt !== null
    const currentArchived = action.remote.archivedAt !== null
    if (!action.contentChanged) {
      const mutations: BulkRemoteLoginMutation[] = []
      if (currentDeleted && !desiredDeleted) mutations.push('restore')
      if (currentArchived && !desiredArchived) mutations.push('unarchive')
      if (desiredArchived && !currentArchived) mutations.push('archive')
      if (desiredDeleted && !currentDeleted) mutations.push('soft-delete')
      return mutations.length === 1
        ? {
            action,
            mutation: mutations[0]!,
            remoteId: action.remoteId,
            folderId: null
          }
        : null
    }

    if (
      desiredDeleted !== currentDeleted ||
      desiredArchived !== currentArchived ||
      !sameLoginContentExceptFolder(action.local, action.remote)
    ) {
      return null
    }
    const folderId = this.resolveFolderReference(action.remoteFolder, completed, 'remoteId')
    if (folderId === action.remote.folderId) return null
    return { action, mutation: 'move', remoteId: action.remoteId, folderId }
  }

  protected supportsBulkRemoteLoginMutation(
    client: BitwardenSyncClient,
    mutation: BulkRemoteLoginMutation
  ): boolean {
    if (mutation === 'soft-delete') return client.softDeleteLogins !== undefined
    if (mutation === 'restore') return client.restoreLogins !== undefined
    if (mutation === 'move') return client.moveLogins !== undefined
    if (mutation === 'archive') return client.archiveLogins !== undefined
    if (mutation === 'unarchive') return client.unarchiveLogins !== undefined
    return client.hardDeleteLogins !== undefined
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
        const isolated = this.isolatedPersonalCipherIds(client)
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
              !isolated.has(candidate.remoteId) &&
              this.bulkRemoteLoginMutationApplied(candidate, remote)
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

  protected bulkRemoteLoginMutationApplied(
    candidate: BulkRemoteLoginCandidate,
    remote: ReadonlyMap<string, BitwardenLoginItem>
  ): boolean {
    const current = remote.get(candidate.remoteId)
    if (candidate.mutation === 'hard-delete') return current === undefined
    if (!current) return false
    if (candidate.mutation === 'soft-delete') return current.deletedAt !== null
    if (candidate.mutation === 'restore') return current.deletedAt === null
    if (candidate.mutation === 'archive') return current.archivedAt !== null
    if (candidate.mutation === 'unarchive') return current.archivedAt === null
    return current.folderId === candidate.folderId
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
        result.localId = this.createLocalFolder(data, action.remote.name).id
      } else if (action.kind === 'pull-update') {
        const folder = findFolder(data, action.localId)
        folder.name = action.remote.name
        folder.updatedAt = this.core.nowIso()
      } else if (action.kind === 'delete-local') {
        this.deleteLocalFolder(data, action.localId)
      } else if (action.kind === 'delete-remote') {
        await client.deleteFolder(action.remoteId, signal)
      } else if (action.reason === 'both-modified') {
        if (!action.local || !action.remote) throw new VaultError('SYNC_FAILED')
        this.createLocalFolder(data, action.conflictName)
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
        result.localId = this.createLocalFolder(data, action.conflictName).id
      }
      return result
    }

    if (action.kind === 'push-create') {
      const folderId = this.resolveFolderReference(action.remoteFolder, completed, 'remoteId')
      const created = await client.createLogin(this.remoteDraft(action.local, folderId), signal)
      result.remoteId = created.id
      if (action.local.deletedAt !== null) await client.softDeleteLogin(created.id, signal)
    } else if (action.kind === 'push-update') {
      const folderId = this.resolveFolderReference(action.remoteFolder, completed, 'remoteId')
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
      await this.updateRemoteLogin(
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
      const folderId = this.resolveFolderReference(action.localFolder, completed, 'localId')
      result.localId = this.createLocalLogin(data, action.remote, folderId).id
    } else if (action.kind === 'pull-update') {
      const folderId = this.resolveFolderReference(action.localFolder, completed, 'localId')
      this.updateLocalLogin(data, action.localId, action.remote, folderId)
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
      this.createLocalLogin(data, { ...action.local, name: action.conflictName }, copyFolderId)
      const primaryFolderId = this.resolveFolderReference(action.localFolder, completed, 'localId')
      this.updateLocalLogin(data, action.local.id, action.remote, primaryFolderId)
    } else if (action.reason === 'remote-deleted') {
      if (!action.local) throw new VaultError('SYNC_FAILED')
      const local = findLogin(data, action.local.id)
      local.name = action.conflictName
      local.updatedAt = this.core.nowIso()
      const folderId = this.resolveFolderReference(action.remoteFolder, completed, 'remoteId')
      result.remoteId = (
        await client.createLogin(
          this.remoteDraft({ ...action.local, name: action.conflictName }, folderId),
          signal
        )
      ).id
      if (action.local.deletedAt !== null) await client.softDeleteLogin(result.remoteId, signal)
    } else {
      if (!action.remote) throw new VaultError('SYNC_FAILED')
      const remoteFolderId = action.remote.folderId
      await this.updateRemoteLogin(
        client,
        action.remote.id,
        { ...action.remote, name: action.conflictName },
        action.remote,
        remoteFolderId,
        true,
        signal
      )
      const localFolderId = this.resolveFolderReference(action.localFolder, completed, 'localId')
      result.localId = this.createLocalLogin(
        data,
        { ...action.remote, name: action.conflictName },
        localFolderId
      ).id
    }
    return result
  }

  protected resolveFolderReference(
    reference: SyncFolderReference,
    completed: Map<string, SyncActionResult>,
    side: 'localId' | 'remoteId'
  ): string | null {
    if (reference.id !== null) return reference.id
    if (!reference.pendingKey) return null
    const id = completed.get(reference.pendingKey)?.[side]
    if (!id) throw new VaultError('SYNC_FAILED')
    return id
  }

  protected createLocalFolder(data: VaultData, name: string): FolderView {
    const now = this.core.nowIso()
    const folder: FolderView = {
      id: this.core.validatedNewId(),
      name: normalizeRequiredString(name, MAX_NAME_LENGTH),
      position: data.folders.length,
      createdAt: now,
      updatedAt: now
    }
    data.folders.push(folder)
    return folder
  }

  protected deleteLocalFolder(data: VaultData, id: string): void {
    data.folders = data.folders
      .filter((folder) => folder.id !== id)
      .sort((left, right) => left.position - right.position)
      .map((folder, position) => ({ ...folder, position }))
    const now = this.core.nowIso()
    for (const login of data.logins) {
      if (login.folderId === id) {
        login.folderId = null
        login.updatedAt = now
      }
    }
  }

  protected appendPortableSnapshot(
    data: VaultData,
    snapshot: PortableVaultSnapshot
  ): {
    itemMappings: { sourceItemId: string; localItemId: string }[]
  } {
    const now = this.core.nowIso()
    const sourceFolderIds = new Set<string>()
    const sourceItemIds = new Set<string>()
    const importedFolderIds = new Map<string, string>()
    const itemMappings: { sourceItemId: string; localItemId: string }[] = []
    for (const source of snapshot.folders) {
      if (
        !source ||
        typeof source.id !== 'string' ||
        sourceFolderIds.has(source.id) ||
        typeof source.name !== 'string'
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      sourceFolderIds.add(source.id)
      const folder: FolderView = {
        id: this.core.validatedNewId(),
        name: uniqueImportedFolderName(data, normalizeRequiredString(source.name, MAX_NAME_LENGTH)),
        position: data.folders.length,
        createdAt: now,
        updatedAt: now
      }
      parseFolder(folder)
      data.folders.push(folder)
      importedFolderIds.set(source.id, folder.id)
    }
    for (const source of snapshot.items) {
      if (
        !source ||
        typeof source.id !== 'string' ||
        sourceItemIds.has(source.id) ||
        source.deletedAt !== null
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      sourceItemIds.add(source.id)
      const folderId =
        source.folderId === null ? null : (importedFolderIds.get(source.folderId) ?? null)
      if (source.folderId !== null && folderId === null) throw new VaultError('INVALID_INPUT')
      const created = this.createLocalLogin(data, source, folderId)
      parseStoredLogin(created)
      itemMappings.push({ sourceItemId: source.id, localItemId: created.id })
    }
    return { itemMappings }
  }

  protected startNativeAttachmentRestoreOperation(client: BitwardenSyncClient): {
    abort: AbortController
    client: BitwardenSyncClient
    generation: number
  } {
    const operation = {
      abort: this.syncSession.startSyncOperation(),
      client,
      generation: this.core.generation
    }
    this.syncSession.nativeAttachmentRestoreAborts.add(operation.abort)
    return operation
  }

  protected finishNativeAttachmentRestoreOperation(operation: { abort: AbortController }): void {
    this.syncSession.nativeAttachmentRestoreAborts.delete(operation.abort)
    this.syncSession.finishSyncOperation(operation.abort)
  }

  protected assertNativeAttachmentRestoreLease(operation: {
    abort: AbortController
    client: BitwardenSyncClient
    generation: number
  }): void {
    if (
      operation.abort.signal.aborted ||
      operation.generation !== this.core.generation ||
      operation.client !== this.syncSession.syncClient ||
      !operation.client.exportState().session
    ) {
      throw new VaultError('LOCKED')
    }
  }

  protected nativeAttachmentRestoreAccountFingerprint(
    sync: PersistedSyncData,
    client: BitwardenSyncClient
  ): string {
    const state = client.exportState()
    if (!state.session || !state.profileId) throw new VaultError('SYNC_AUTH_REQUIRED')
    return createHash('sha256')
      .update(
        JSON.stringify({
          provider: 'bitwarden',
          serverUrl: sync.serverUrl,
          profileId: state.profileId
        })
      )
      .digest('hex')
  }

  protected requireBoundNativeAttachmentRestore(
    data: VaultData,
    archiveFingerprint: string,
    sync: PersistedSyncData,
    client: BitwardenSyncClient
  ): NativeAttachmentRestoreJournal {
    if (!data.nativeAttachmentRestore) throw new VaultError('INVALID_INPUT')
    return assertNativeAttachmentRestoreBinding(
      data.nativeAttachmentRestore,
      archiveFingerprint,
      this.nativeAttachmentRestoreAccountFingerprint(sync, client)
    )
  }

  protected nativeAttachmentRestoreSummary(
    journal: NativeAttachmentRestoreJournal
  ): VaultNativeAttachmentRestoreSummary {
    return {
      phase: journal.phase,
      totalItems: journal.items.length,
      mappedItems: journal.items.filter((item) => item.remoteItemId !== null).length,
      totalAttachments: journal.attachments.length,
      uploadedAttachments: journal.attachments.filter(
        (attachment) => attachment.status === 'uploaded'
      ).length,
      needsReconciliationAttachments: journal.attachments.filter(
        (attachment) => attachment.status === 'needs-reconciliation'
      ).length,
      totalBytes: journal.attachments.reduce((total, attachment) => total + attachment.size, 0),
      completedBytes: journal.attachments.reduce(
        (total, attachment) => total + (attachment.status === 'uploaded' ? attachment.size : 0),
        0
      )
    }
  }

  protected applyNativeAttachmentRestoreRemoteSnapshot(
    current: VaultData,
    client: BitwardenSyncClient,
    remoteFolders: BitwardenFolder[],
    remoteLogins: BitwardenLoginItem[]
  ): VaultData {
    if (!current.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    const next = cloneData(current)
    this.reconcileServerAuthoritativeAttachments(
      next,
      current.sync.loginMappings,
      remoteFolders,
      remoteLogins
    )
    if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    next.sync.state = client.exportState()
    next.sync.lastSyncAt = this.core.nowIso()
    return next
  }

  protected async persistFailedNativeAttachmentRestoreAttempt(
    key: NativeAttachmentRestoreAttachmentKey
  ): Promise<void> {
    const current = this.core.currentData()
    if (!current?.nativeAttachmentRestore) return
    const target = current.nativeAttachmentRestore.attachments.find(
      (attachment) =>
        attachment.sourceItemId === key.sourceItemId &&
        attachment.sourceAttachmentId === key.sourceAttachmentId
    )
    if (target?.status !== 'attempting') return
    const next = cloneData(current)
    next.nativeAttachmentRestore = failNativeAttachmentRestoreAttempt(
      next.nativeAttachmentRestore!,
      key,
      null,
      this.core.nowIso()
    )
    next.updatedAt = next.nativeAttachmentRestore.updatedAt
    await this.core.commit(next)
  }

  protected async nativeAttachmentRestoreCandidateMatches(
    client: BitwardenSyncClient,
    remoteItemId: string,
    remoteAttachmentId: string,
    expectedFileName: string,
    expectedSize: number,
    expectedDigest: string,
    signal: AbortSignal
  ): Promise<boolean> {
    let streamed:
      Awaited<ReturnType<NonNullable<BitwardenSyncClient['downloadAttachmentStream']>>> | undefined
    let clearText: Buffer | undefined
    try {
      const downloaded = client.downloadAttachmentStream
        ? await client.downloadAttachmentStream(remoteItemId, remoteAttachmentId, signal)
        : await client.downloadAttachment(remoteItemId, remoteAttachmentId, signal)
      if (downloaded.fileName !== expectedFileName) return false
      if ('dispose' in downloaded) streamed = downloaded
      else clearText = downloaded.data
      const chunks: AsyncIterable<Buffer> = streamed
        ? streamed.data.chunks(signal)
        : (async function* (): AsyncIterable<Buffer> {
            yield clearText!
          })()
      const hash = createHash('sha256')
      let size = 0
      for await (const chunk of chunks) {
        size += chunk.length
        if (size > expectedSize) return false
        hash.update(chunk)
      }
      return size === expectedSize && hash.digest('hex') === expectedDigest
    } catch {
      return false
    } finally {
      clearText?.fill(0)
      await streamed?.dispose().catch(() => undefined)
    }
  }

  protected createLocalLogin(
    data: VaultData,
    source: SyncLogin,
    folderId: string | null
  ): StoredLogin {
    const now = this.core.nowIso()
    const createdAt = source.createdAt ?? now
    const updatedAt = source.updatedAt ?? createdAt
    const login: StoredLogin = {
      id: this.core.validatedNewId(),
      type: normalizeItemType(source.type),
      name: normalizeRequiredString(source.name, MAX_NAME_LENGTH),
      notes: normalizeNullableString(source.notes, MAX_NOTES_LENGTH),
      folderId,
      favorite: source.favorite,
      usageCount: 0,
      lastUsedAt: source.lastUsedAt ?? null,
      createdAt,
      updatedAt,
      deletedAt: source.deletedAt,
      archivedAt: source.archivedAt,
      reprompt: source.reprompt,
      passkeys: validateRemotePasskeys(source.passkeys),
      customFields: cloneCustomFields(source.customFields),
      passwordHistory: clonePasswordHistory(source.passwordHistory),
      passwordRevisionDate: source.passwordRevisionDate,
      autofillOnPageLoad: source.autofillOnPageLoad,
      attachments: [],
      uris: remoteLoginUris(source),
      ...normalizeItemFieldsForStorage(source)
    }
    data.logins.push(login)
    return login
  }

  protected sharedLoginFromRemote(source: BitwardenOrganizationCipher): StoredSharedLogin {
    const normalized = this.remoteSyncSnapshot([], [{ ...source, organizationId: null }]).logins[0]
    if (!normalized) throw new VaultError('SYNC_FAILED')
    return {
      id: source.id,
      type: normalizeItemType(normalized.type),
      name: normalizeRequiredString(normalized.name, MAX_NAME_LENGTH),
      notes: normalizeNullableString(normalized.notes, MAX_NOTES_LENGTH),
      folderId: null,
      favorite: normalized.favorite,
      usageCount: 0,
      lastUsedAt: null,
      createdAt: normalized.createdAt ?? this.core.nowIso(),
      updatedAt: normalized.updatedAt ?? this.core.nowIso(),
      deletedAt: normalized.deletedAt,
      archivedAt: normalized.archivedAt,
      reprompt: normalized.reprompt,
      passkeys: validateRemotePasskeys(normalized.passkeys),
      customFields: cloneCustomFields(normalized.customFields),
      passwordHistory: clonePasswordHistory(normalized.passwordHistory),
      passwordRevisionDate: normalized.passwordRevisionDate,
      autofillOnPageLoad: normalized.autofillOnPageLoad,
      attachments: validateRemoteAttachments(source.attachments),
      uris: remoteLoginUris(normalized),
      ...normalizeItemFieldsForStorage(normalized),
      organizationId: source.organizationId,
      collectionIds: [...source.collectionIds],
      shared: true,
      edit: source.edit,
      viewPassword: source.viewPassword,
      delete: source.delete,
      restore: source.restore
    }
  }

  protected updateLocalLogin(
    data: VaultData,
    id: string,
    source: SyncLogin,
    folderId: string | null
  ): void {
    const login = findLogin(data, id)
    login.type = normalizeItemType(source.type)
    login.name = normalizeRequiredString(source.name, MAX_NAME_LENGTH)
    login.notes = normalizeNullableString(source.notes, MAX_NOTES_LENGTH)
    Object.assign(login, normalizeItemFieldsForStorage(source))
    login.uris = remoteLoginUris(source)
    login.uri = uriAlias(login.uris)
    login.passkeys = validateRemotePasskeys(source.passkeys)
    login.customFields = cloneCustomFields(source.customFields)
    login.passwordHistory = clonePasswordHistory(source.passwordHistory)
    login.passwordRevisionDate = source.passwordRevisionDate
    login.autofillOnPageLoad = source.autofillOnPageLoad
    login.folderId = folderId
    login.favorite = source.favorite
    login.deletedAt = source.deletedAt
    login.archivedAt = source.archivedAt
    login.reprompt = source.reprompt
    if (source.createdAt) login.createdAt = source.createdAt
    login.updatedAt = source.updatedAt ?? this.core.nowIso()
  }

  protected remoteDraft(login: SyncLogin, folderId: string | null): BitwardenLoginDraft {
    return {
      type: login.type,
      name: login.name,
      username: login.username,
      password: login.password,
      totp: login.totp,
      uri: login.uri,
      uris: cloneLoginUris(login.uris),
      cardholderName: login.cardholderName,
      brand: login.brand,
      number: login.number,
      expMonth: login.expMonth,
      expYear: login.expYear,
      code: login.code,
      title: login.title,
      firstName: login.firstName,
      middleName: login.middleName,
      lastName: login.lastName,
      address1: login.address1,
      address2: login.address2,
      address3: login.address3,
      city: login.city,
      state: login.state,
      postalCode: login.postalCode,
      country: login.country,
      company: login.company,
      email: login.email,
      phone: login.phone,
      ssn: login.ssn,
      identityUsername: login.identityUsername,
      passportNumber: login.passportNumber,
      licenseNumber: login.licenseNumber,
      privateKey: login.privateKey,
      publicKey: login.publicKey,
      fingerprint: login.fingerprint,
      notes: login.notes,
      folderId,
      favorite: login.favorite,
      archivedAt: login.archivedAt,
      reprompt: login.reprompt,
      passkeys: login.passkeys.map((passkey) => ({ ...passkey })),
      customFields: cloneCustomFields(login.customFields),
      passwordHistory: clonePasswordHistory(login.passwordHistory),
      passwordRevisionDate: login.passwordRevisionDate,
      autofillOnPageLoad: login.autofillOnPageLoad
    }
  }

  protected async updateRemoteLogin(
    client: BitwardenSyncClient,
    remoteId: string,
    desired: SyncLogin,
    current: SyncLogin,
    folderId: string | null,
    contentChanged: boolean,
    signal: AbortSignal
  ): Promise<void> {
    const desiredDeleted = desired.deletedAt !== null
    const currentDeleted = current.deletedAt !== null
    const desiredArchived = desired.archivedAt !== null
    const currentArchived = current.archivedAt !== null

    if (currentDeleted && (!desiredDeleted || contentChanged)) {
      await client.restoreLogin(remoteId, signal)
    }
    // Vaultwarden treats archivedDate: null in an ordinary cipher update as "leave unchanged",
    // so an explicit unarchive route is required even when a content edit follows.
    if (currentArchived && !desiredArchived) {
      await client.unarchiveLogin(remoteId, signal)
    }
    if (contentChanged) {
      await client.editLogin(remoteId, this.remoteDraft(desired, folderId), signal)
    }
    if (!contentChanged && desiredArchived && !currentArchived) {
      await client.archiveLogin(remoteId, signal)
    }
    if (desiredDeleted && (!currentDeleted || contentChanged)) {
      await client.softDeleteLogin(remoteId, signal)
    }
  }

  protected useLogin<T>(
    request: LoginIdRequest,
    operation: (login: StoredLogin) => Promise<T>
  ): Promise<T> {
    return this.core.exclusive(async () => {
      assertUuid(request.id)
      const current = this.core.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      const currentLogin = findLogin(current, request.id)
      assertActiveLogin(currentLogin)
      const result = await operation(currentLogin)
      const next = cloneData(current)
      const usedLogin = findLogin(next, request.id)
      const now = this.core.nowIso()
      usedLogin.usageCount = Math.min(Number.MAX_SAFE_INTEGER, usedLogin.usageCount + 1)
      usedLogin.lastUsedAt = now
      next.updatedAt = now
      await this.core.commit(next)
      return result
    })
  }

  protected assertExpectedPasskeyGeneration(value: unknown): asserts value is number {
    if (!Number.isSafeInteger(value) || (value as number) < 0) {
      throw new VaultError('INVALID_INPUT')
    }
    if (value !== this.core.generation) throw new VaultError('LOCKED')
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
