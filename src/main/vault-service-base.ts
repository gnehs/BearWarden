import { createHash, randomInt as nodeRandomInt, randomUUID } from 'node:crypto'
import { AsyncLocalStorage } from 'node:async_hooks'
import type {
  AttachmentOperationKind,
  AttachmentOperationStage,
  AttachmentProgressEvent,
  AttachmentTargetRequest,
  LoginApprovalPrompt,
  FolderView,
  LoginBatchRequest,
  LoginIdRequest,
  OrganizationView,
  CollectionView,
  VaultAttachmentView,
  VaultHealthExposedReport,
  VaultHealthAccountBreachReport,
  SyncConnectRequest,
  SyncPurgePersonalVaultResult,
  SyncResult,
  SyncStatus,
  SyncTwoFactorProvider,
  VaultStatus
} from '../shared/vault-contract'
import { MAX_LOGIN_BATCH_IDS } from '../shared/vault-contract'
import {
  BitwardenDirectError,
  type BitwardenFolder,
  type BitwardenLoginDraft,
  type BitwardenLoginItem,
  type BitwardenLoginApprovalRequest,
  type BitwardenOrganizationCipher,
  type BitwardenSendItem,
  type BitwardenLoginTwoFactor,
  type BitwardenSyncClient,
  type BitwardenTwoFactor,
  type BitwardenWebAuthnRegistrationSetup
} from './bitwarden-direct'
import { resolveBitwardenUrls } from './bitwarden-http'
import { EncryptedVaultStore } from './encrypted-vault-store'
import {
  PinUnlockCapability,
  PinUnlockError,
  type PinSyncKeyMaterial,
  type PinVaultKeyMaterial
} from './pin-unlock'
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
import { SyncTwoFactorRequiredError, VaultError } from './vault-errors'
import type { VaultAttachmentFileService } from './vault-attachment-files'
import type { AccountWebAuthnAssertion } from './account-webauthn-codec'
import type { AccountWebAuthnAttestation } from './account-webauthn-registration-codec'
import {
  DATA_VERSION,
  MAX_MASTER_PASSWORD_LENGTH,
  MAX_NAME_LENGTH,
  MAX_PASSWORD_LENGTH,
  MAX_URI_LENGTH,
  MAX_NOTES_LENGTH,
  MAX_ATTACHMENT_ID_LENGTH,
  MAX_TWO_FACTOR_CODE_LENGTH,
  MAX_PENDING_LOGIN_IMPORT_ENTRIES,
  MAX_PENDING_LOGIN_IMPORT_MARKER_LENGTH,
  UUID_PATTERN
} from './vault/limits'
import {
  isRecord,
  assertUuid,
  normalizeRequiredString,
  normalizeNullableString,
  normalizeMasterPassword
} from './vault/parse-primitives'
import { parseVaultData, parseVaultDataTagged, cloneData } from './vault/vault-data-parsing'
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
import { cloneGeneratorHistory } from './vault/generator-history'
import { clonePasswordHistory } from './vault/password-history'
import type {
  StoredLogin,
  StoredSharedLogin,
  SyncEntityMapping,
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

export type {
  PersistedSyncData,
  VaultMasterPasswordChangeStatus,
  VaultMasterPasswordChangeRequest,
  VaultMasterPasswordChangeResolutionRequest,
  VaultMasterPasswordChangeResolution,
  VaultPlatform,
  VaultAccountWebAuthnRequest,
  VaultAccountWebAuthnAssertionRequester,
  VaultAccountWebAuthnRegistrationRequest,
  VaultAccountWebAuthnRegistrationRequester,
  VaultServiceOptions,
  VaultExportSnapshot,
  VaultNativeAttachmentBackupSource,
  VaultNativeAttachmentRestoreSummary,
  SshAgentVaultIdentity,
  SshAgentVaultSignRequest,
  SshAgentVaultSignResult,
  SshAgentVaultAuthorizationValidator,
  PasskeyVaultAuthorizationValidator,
  PasskeyVaultCredentialCandidate,
  PasskeyVaultDiscoveryRequest,
  PasskeyVaultDiscoveryResult,
  PasskeyVaultCreationTarget,
  PasskeyVaultCreationTargetDiscoveryResult,
  PasskeyVaultCreationTargetDiscoveryRequest,
  PasskeyVaultCreateRequest,
  PasskeyVaultCreateResult,
  PasskeyVaultAssertionRequest,
  PasskeyVaultAssertionResult
} from './vault/types'

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

interface ExposedPasswordSnapshot {
  readonly generation: number
  readonly revision: string
  readonly candidates: readonly {
    id: string
    name: string
    subtitle: string
  }[]
  readonly hashes: string[]
  readonly protectedSkippedCount: number
}

interface ActiveExposedPasswordOperation {
  readonly generation: number
  readonly revision: string
  readonly abort: AbortController
  readonly promise: Promise<VaultHealthExposedReport>
}

interface ActiveAccountBreachOperation {
  readonly generation: number
  readonly email: string
  readonly client: BitwardenSyncClient
  readonly abort: AbortController
  readonly promise: Promise<VaultHealthAccountBreachReport>
}

interface AuthenticatorSetupSession {
  readonly generation: number
  readonly client: BitwardenSyncClient
  key: string
  readonly verificationMode: 'server-token' | 'master-password'
  userVerificationToken: string | null
  readonly expiresAt: number
}

interface EmailTwoFactorSetupSession {
  readonly generation: number
  readonly client: BitwardenSyncClient
  readonly verificationMode: 'server-token' | 'master-password'
  userVerificationToken: string | null
  phase: 'ready-to-send' | 'awaiting-code'
  email: string | null
  readonly expiresAt: number
}

interface AccountWebAuthnOperationLease {
  readonly generation: number
  readonly client: BitwardenSyncClient
  readonly abort: AbortController
}

interface LoginApprovalSession {
  readonly generation: number
  readonly client: BitwardenSyncClient
  readonly requestId: string
  readonly fingerprint: string
  readonly requestDeviceType: string
  readonly createdAt: string
  readonly expiresAt: number
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
  MAX_REMOTE_LOGIN_BATCH_IDS,
  LOGIN_APPROVAL_TTL_MS,
  MAX_LOGIN_APPROVAL_SESSIONS,
  clearAccountWebAuthnRegistrationSetup,
  clearAccountWebAuthnAttestation,
  scrubAccountSessionDeauthorizationRequest
}
export type {
  BulkRemoteLoginMutation,
  BulkRemoteLoginCandidate,
  LoginImportCandidate,
  AttachmentAuthorizationValidator,
  ItemReadAuthorizationValidator,
  ExposedPasswordSnapshot,
  ActiveExposedPasswordOperation,
  ActiveAccountBreachOperation,
  AuthenticatorSetupSession,
  EmailTwoFactorSetupSession,
  AccountWebAuthnOperationLease,
  LoginApprovalSession
}

/**
 * Owns the vault's mutable runtime state, persistence transaction boundary, and sync engine.
 * Feature layers extend this class so every operation shares one mutex, generation, and cleanup
 * lifecycle; this module must never import a higher service layer.
 */
export class VaultServiceBase {
  protected key: Buffer | null = null
  protected salt: Buffer | null = null
  protected data: VaultData | null = null
  /** Blocks lock-free committed-snapshot reads before unlock and as soon as lock starts. */
  protected fastReadsBlocked = true
  protected pinUnlockCapability: PinUnlockCapability | null = null
  protected pinLifecycleEpoch = 0
  protected generation = 0
  protected operationQueue: Promise<void> = Promise.resolve()
  protected readonly exclusiveContext = new AsyncLocalStorage<{ active: boolean }>()
  protected syncClient: BitwardenSyncClient | null = null
  protected syncAbort: AbortController | null = null
  protected readonly notificationTokenAborts = new Set<AbortController>()
  protected readonly accountSecurityAborts = new Set<AbortController>()
  protected readonly nativeAttachmentBackupAborts = new Set<AbortController>()
  protected readonly nativeAttachmentRestoreAborts = new Set<AbortController>()
  protected readonly authenticatorSetupSessions = new Map<string, AuthenticatorSetupSession>()
  protected readonly emailTwoFactorSetupSessions = new Map<string, EmailTwoFactorSetupSession>()
  protected readonly loginApprovalSessions = new Map<string, LoginApprovalSession>()
  protected readonly generatorService: VaultGeneratorService
  protected readonly sendService: VaultSendService
  protected syncInProgress = false
  protected sessionDeauthorizationInProgress = false
  protected syncLastError: import('../shared/vault-contract').SyncErrorCode | null = null
  protected syncLastErrorAt: string | null = null
  protected syncLastErrorDetail:
    import('../shared/vault-contract').SyncInvalidResponseStage | null = null
  protected activeAttachmentOperation: {
    operationId: string
    abort: AbortController
    canceledByUser: boolean
    committed: boolean
  } | null = null
  protected readonly now: () => Date
  protected readonly createId: () => string
  protected readonly createSyncClient: (sync: PersistedSyncData) => BitwardenSyncClient
  protected readonly fetch: typeof fetch
  protected readonly attachmentFiles: VaultAttachmentFileService | null
  protected readonly requestAccountWebAuthnAssertion: VaultAccountWebAuthnAssertionRequester | null
  protected readonly requestAccountWebAuthnRegistration: VaultAccountWebAuthnRegistrationRequester | null
  protected readonly websiteIconCache = new Map<string, string | null>()
  protected readonly websiteIconRequests = new Map<string, Promise<string | null>>()
  protected activeExposedPasswordOperation: ActiveExposedPasswordOperation | null = null
  protected activeAccountBreachOperation: ActiveAccountBreachOperation | null = null

  constructor(
    protected readonly store: EncryptedVaultStore<unknown>,
    protected readonly platform: VaultPlatform,
    options: VaultServiceOptions = {}
  ) {
    this.now = options.now ?? (() => new Date())
    this.createId = options.createId ?? randomUUID
    this.fetch = options.fetch ?? fetch
    this.attachmentFiles = options.attachmentFiles ?? null
    this.requestAccountWebAuthnAssertion = options.requestAccountWebAuthnAssertion ?? null
    this.requestAccountWebAuthnRegistration = options.requestAccountWebAuthnRegistration ?? null
    this.createSyncClient =
      options.createSyncClient ??
      (() => {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      })
    this.generatorService = new VaultGeneratorService({
      now: this.now,
      createId: this.createId,
      randomInt: options.randomInt ?? nodeRandomInt,
      copyText: (text) => this.platform.copyText(text),
      exclusive: (operation) => this.exclusive(operation),
      assertUnlocked: () => {
        this.requireData()
      },
      readHistory: () => this.requireData().generatorHistory,
      commitHistory: async (history) => {
        const current = this.requireData()
        const next = cloneData(current)
        next.generatorHistory = cloneGeneratorHistory(history)
        next.updatedAt = this.nowIso()
        const generation = this.generation
        await this.persist(next)
        if (generation !== this.generation) throw new VaultError('LOCKED')
        this.data = next
      }
    })
    this.sendService = new VaultSendService({
      attachmentFiles: this.attachmentFiles,
      exclusive: (operation) => this.exclusive(operation),
      readData: () => this.requireData(),
      requireSyncData: () => this.requireSyncData(),
      getSyncClient: (sync) => this.getOrCreateSyncClient(sync),
      currentGeneration: () => this.generation,
      startSyncOperation: () => this.startSyncOperation(),
      finishSyncOperation: (abort) => this.finishSyncOperation(abort),
      persistData: async (data) => {
        await this.persist(data)
        this.data = data
      },
      nowIso: () => this.nowIso(),
      clearSyncError: () => {
        this.syncLastError = null
      },
      mapSyncError: (error) => this.mapSyncError(error),
      copyText: (text) => this.platform.copyText(text)
    })
  }

  status(): Promise<VaultStatus> {
    return this.exclusive(async () => this.currentStatus())
  }

  /**
   * Captures the unlocked-vault epoch for short-lived main-process capabilities. Callers must
   * re-enter normal service operations afterwards; this intentionally does not hold the mutex.
   */
  unlockedGeneration(): Promise<number> {
    return this.exclusive(async () => {
      this.requireData()
      return this.generation
    })
  }

  /** Runs a short, main-process-only capability commit against one unlocked-vault epoch. */
  runUnlockedOperation<T>(operation: (generation: number) => Promise<T>): Promise<T> {
    return this.exclusive(async () => {
      this.requireData()
      return operation(this.generation)
    })
  }

  setup(masterPassword: string): Promise<VaultStatus> {
    return this.exclusive(async () => {
      if (await this.store.exists()) throw new VaultError('ALREADY_INITIALIZED')
      const password = normalizeMasterPassword(masterPassword)
      const now = this.nowIso()
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
      const generation = this.generation
      const material = await this.store.initialize(password, initialData)
      if (generation !== this.generation) {
        material.key.fill(0)
        material.salt.fill(0)
        throw new VaultError('LOCKED')
      }
      this.key = material.key
      this.salt = material.salt
      this.data = initialData
      this.fastReadsBlocked = false
      return { state: 'unlocked' }
    })
  }

  unlock(masterPassword: string): Promise<VaultStatus> {
    return this.exclusive(async () => {
      if (this.data && this.key && this.salt) return { state: 'unlocked' }
      if (!(await this.store.exists())) throw new VaultError('NOT_INITIALIZED')
      const password = normalizeMasterPassword(masterPassword)
      const generation = this.generation
      const unlocked = await this.store.unlock(password)

      try {
        if (generation !== this.generation) throw new VaultError('LOCKED')
        const requiresMigration = isRecord(unlocked.data) && unlocked.data.version !== DATA_VERSION
        this.data = parseVaultDataTagged(unlocked.data)
        this.key = unlocked.key
        this.salt = unlocked.salt
        await this.recoverNativeAttachmentRestoreAfterUnlock(requiresMigration)
        this.fastReadsBlocked = false
        return { state: 'unlocked' }
      } catch (error) {
        unlocked.key.fill(0)
        unlocked.salt.fill(0)
        this.key = null
        this.salt = null
        this.data = null
        throw error
      }
    })
  }

  pinUnlockStatus(): import('../shared/vault-contract').PinUnlockStatus {
    const status = this.pinUnlockCapability?.status()
    if (!status?.available) return { available: false, remainingAttempts: 0 }
    return status
  }

  enablePinUnlock(request: {
    pin: string
    masterPassword: string
  }): Promise<import('../shared/vault-contract').PinUnlockStatus> {
    const lifecycleEpoch = this.pinLifecycleEpoch
    const generation = this.generation
    return this.exclusive(async () => {
      let capability: PinUnlockCapability | null = null
      let syncMaterial: PinSyncKeyMaterial | null = null
      try {
        if (generation !== this.generation || lifecycleEpoch !== this.pinLifecycleEpoch) {
          throw new VaultError('LOCKED')
        }
        const data = this.requireData()
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
        await this.assertMasterPassword(request.masterPassword)
        if (!this.key || !this.salt) throw new VaultError('LOCKED')
        const client = data.sync ? this.getOrCreateSyncClient(data.sync) : null
        syncMaterial = client?.pinUnlockMaterial?.() ?? null
        capability = await PinUnlockCapability.create(
          request.pin,
          this.key,
          this.salt,
          syncMaterial
        )
        if (
          generation !== this.generation ||
          lifecycleEpoch !== this.pinLifecycleEpoch ||
          !this.data ||
          !this.key ||
          !this.salt
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

  masterPasswordChangeStatus(): Promise<VaultMasterPasswordChangeStatus> {
    return this.exclusive(async () => {
      const data = this.requireData()
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
    return this.exclusive(async () => {
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
        const current = this.requireData()
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
          const sync = this.requireSyncData()
          const client = this.getOrCreateSyncClient(sync)
          if (!client.changeMasterPassword) throw new VaultError('SYNC_FAILED')
          const now = this.nowIso()
          const prepared = cloneData(current)
          prepared.masterPasswordChange = {
            phase: 'prepared',
            startedAt: now,
            updatedAt: now,
            accountFingerprint: this.masterPasswordChangeAccountFingerprint(sync)
          }
          prepared.updatedAt = now
          await this.persist(prepared)
          this.data = prepared

          abort = this.startSyncOperation()
          remoteRequest = { currentPassword, newPassword, hint, signal: abort.signal }
          try {
            await client.changeMasterPassword(remoteRequest)
          } catch (error) {
            if (
              error instanceof BitwardenDirectError &&
              error.code === 'MASTER_PASSWORD_CHANGE_UNKNOWN'
            ) {
              this.generation += 1
              this.invalidatePinUnlockCapability()
              this.syncClient = null
              this.clearUnlockedRuntimeState()
              throw new VaultError('SYNC_FAILED')
            }
            const cleared = cloneData(this.requireData())
            cleared.masterPasswordChange = null
            cleared.updatedAt = this.nowIso()
            await this.persist(cleared)
            this.data = cleared
            throw this.mapSyncError(error)
          }

          const confirmed = cloneData(this.requireData())
          if (!confirmed.masterPasswordChange) throw new VaultError('SYNC_FAILED')
          confirmed.masterPasswordChange.phase = 'remote-confirmed'
          confirmed.masterPasswordChange.updatedAt = this.nowIso()
          if (confirmed.sync) {
            confirmed.sync.state = { ...client.exportState(), session: null }
          }
          confirmed.updatedAt = confirmed.masterPasswordChange.updatedAt
          try {
            await this.persist(confirmed)
            this.data = confirmed
          } catch (error) {
            this.generation += 1
            this.invalidatePinUnlockCapability()
            this.clearUnlockedRuntimeState()
            throw error
          }
        }

        await this.finishMasterPasswordChange(currentPassword, newPassword)
      } finally {
        if (abort) this.finishSyncOperation(abort)
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
    return this.exclusive(async () => {
      let currentPassword = ''
      let newPassword = ''
      let abort: AbortController | undefined
      try {
        currentPassword = normalizeMasterPassword(request.currentPassword)
        newPassword = normalizeMasterPassword(request.newPassword)
        if (currentPassword === newPassword) throw new VaultError('INVALID_INPUT')
        const current = this.requireData()
        this.assertMasterPasswordChangeAccount(current)
        if (current.masterPasswordChange?.phase !== 'prepared') {
          throw new VaultError('INVALID_INPUT')
        }
        const sync = this.requireSyncData()
        abort = this.startSyncOperation()
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

          const cleared = cloneData(this.requireData())
          this.assertMasterPasswordChangeAccount(cleared)
          if (cleared.masterPasswordChange?.phase !== 'prepared') {
            throw new VaultError('SYNC_FAILED')
          }
          cleared.masterPasswordChange = null
          if (cleared.sync) cleared.sync.state.session = null
          cleared.updatedAt = this.nowIso()
          await this.persist(cleared)
          this.data = cleared
          this.syncClient = null
          return { status: 'remote-not-changed' }
        }

        const confirmed = cloneData(this.requireData())
        this.assertMasterPasswordChangeAccount(confirmed)
        if (confirmed.masterPasswordChange?.phase !== 'prepared') {
          throw new VaultError('SYNC_FAILED')
        }
        confirmed.masterPasswordChange.phase = 'remote-confirmed'
        confirmed.masterPasswordChange.updatedAt = this.nowIso()
        if (confirmed.sync) confirmed.sync.state.session = null
        confirmed.updatedAt = confirmed.masterPasswordChange.updatedAt
        await this.persist(confirmed)
        this.data = confirmed
        this.syncClient = null
        await this.finishMasterPasswordChange(currentPassword, newPassword)
        return { status: 'resolved' }
      } finally {
        if (abort) this.finishSyncOperation(abort)
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
    const generation = this.generation
    return this.exclusive(async () => {
      let material: PinVaultKeyMaterial | null = null
      let unlocked: Awaited<ReturnType<EncryptedVaultStore<unknown>['unlockWithKey']>> | null = null
      try {
        if (generation !== this.generation || lifecycleEpoch !== this.pinLifecycleEpoch) {
          throw new VaultError('LOCKED')
        }
        if (this.data && this.key && this.salt) return { state: 'unlocked' }
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
          generation !== this.generation ||
          capability !== this.pinUnlockCapability
        ) {
          throw new VaultError('LOCKED')
        }
        unlocked = await this.store.unlockWithKey(material.key, material.salt)
        if (
          lifecycleEpoch !== this.pinLifecycleEpoch ||
          generation !== this.generation ||
          capability !== this.pinUnlockCapability
        ) {
          throw new VaultError('LOCKED')
        }
        const requiresMigration = isRecord(unlocked.data) && unlocked.data.version !== DATA_VERSION
        this.data = parseVaultDataTagged(unlocked.data)
        this.key = unlocked.key
        this.salt = unlocked.salt
        unlocked = null
        await this.recoverNativeAttachmentRestoreAfterUnlock(requiresMigration)
        if (material.sync && this.data.sync) {
          this.getOrCreateSyncClient(this.data.sync).restorePinUnlockMaterial?.(material.sync)
        }
        this.fastReadsBlocked = false
        return { state: 'unlocked' }
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
        this.key?.fill(0)
        this.salt?.fill(0)
        this.key = null
        this.salt = null
        this.data = null
        throw error
      } finally {
        request.pin = ''
        material?.key.fill(0)
        material?.salt.fill(0)
        material?.sync?.accountKey.fill(0)
        material?.sync?.wrappedKeyFingerprint.fill(0)
        unlocked?.key.fill(0)
        unlocked?.salt.fill(0)
      }
    })
  }

  lock(): Promise<VaultStatus> {
    this.fastReadsBlocked = true
    this.generation += 1
    this.syncAbort?.abort()
    this.abortNotificationTokenLeases()
    this.abortAccountSecurityRequests()
    this.abortNativeAttachmentBackups()
    this.abortNativeAttachmentRestores()
    this.activeExposedPasswordOperation?.abort.abort()
    this.activeAccountBreachOperation?.abort.abort()
    return this.exclusive(async () => {
      try {
        await this.syncClient?.lock()
      } catch {
        // Local vault locking must never depend on the remote connector.
      }
      this.clearUnlockedRuntimeState()
      return this.currentStatus()
    })
  }

  dispose(): void {
    this.generation += 1
    this.invalidatePinUnlockCapability()
    this.clearUnlockedRuntimeState()
  }

  protected clearUnlockedRuntimeState(): void {
    this.fastReadsBlocked = true
    this.syncAbort?.abort()
    this.abortNotificationTokenLeases()
    this.abortAccountSecurityRequests()
    this.abortNativeAttachmentBackups()
    this.abortNativeAttachmentRestores()
    this.activeExposedPasswordOperation?.abort.abort()
    this.activeExposedPasswordOperation = null
    this.activeAccountBreachOperation?.abort.abort()
    this.activeAccountBreachOperation = null
    this.syncAbort = null
    this.activeAttachmentOperation = null
    this.syncClient = null
    this.syncInProgress = false
    this.sessionDeauthorizationInProgress = false
    this.key?.fill(0)
    this.salt?.fill(0)
    this.key = null
    this.salt = null
    this.data = null
    this.generatorService.clearRuntimeState()
    this.websiteIconCache.clear()
    this.websiteIconRequests.clear()
  }

  protected async currentSyncStatus(checkConnection: boolean): Promise<SyncStatus> {
    const data = this.requireData()
    if (!data.sync) return { configured: false, state: 'unconfigured' }
    if (this.syncInProgress) return this.baseSyncStatus(data.sync, 'syncing')
    if (this.syncLastError) return this.baseSyncStatus(data.sync, 'error')
    if (!checkConnection) return this.baseSyncStatus(data.sync, 'locked')
    try {
      const client = this.getOrCreateSyncClient(data.sync)
      const status = await client.status()
      return this.baseSyncStatus(data.sync, status.status === 'unlocked' ? 'ready' : 'locked')
    } catch {
      this.recordSyncError('SYNC_FAILED')
      return this.baseSyncStatus(data.sync, 'error')
    }
  }

  protected baseSyncStatus(sync: PersistedSyncData, state: SyncStatus['state']): SyncStatus {
    return {
      configured: true,
      state,
      serverUrl: sync.serverUrl,
      email: sync.email,
      ...(sync.lastSyncAt ? { lastSyncAt: sync.lastSyncAt } : {}),
      ...(this.syncLastError ? { lastError: this.syncLastError } : {}),
      ...(this.syncLastError && this.syncLastErrorAt ? { lastErrorAt: this.syncLastErrorAt } : {}),
      ...(this.syncLastError === 'SYNC_INVALID_RESPONSE' && this.syncLastErrorDetail
        ? { lastErrorDetail: this.syncLastErrorDetail }
        : {}),
      ...(sync.pendingLoginImport?.phase === 'dispatched'
        ? {
            pendingImport: {
              count: sync.pendingLoginImport.entries.length,
              startedAt: sync.pendingLoginImport.startedAt
            }
          }
        : {}),
      ...(sync.pendingPersonalVaultPurge?.phase === 'dispatched'
        ? {
            pendingPurge: {
              remainingItems: sync.pendingPersonalVaultPurge.remainingItems,
              remainingFolders: sync.pendingPersonalVaultPurge.remainingFolders,
              startedAt: sync.pendingPersonalVaultPurge.startedAt
            }
          }
        : {})
    }
  }

  protected normalizeSyncServerUrl(value: unknown): string {
    if (typeof value !== 'string' || value.length === 0 || value.length > MAX_URI_LENGTH) {
      throw new VaultError('INVALID_URL')
    }
    try {
      const normalized = value.trim()
      resolveBitwardenUrls(normalized)
      return normalized.replace(/\/$/, '')
    } catch {
      throw new VaultError('INVALID_URL')
    }
  }

  protected normalizeTwoFactor(
    method: SyncConnectRequest['twoFactorMethod'],
    code: string | undefined
  ): BitwardenTwoFactor | undefined {
    if (method === undefined && code === undefined) return undefined
    if (
      method === undefined ||
      code === undefined ||
      code.length === 0 ||
      code.length > MAX_TWO_FACTOR_CODE_LENGTH
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    return { method: Number(method) as BitwardenTwoFactor['method'], code }
  }

  protected async authenticateSyncWithWebAuthnRetry(
    authenticate: (twoFactor: BitwardenLoginTwoFactor | undefined) => Promise<void>,
    initialTwoFactor: BitwardenTwoFactor | undefined,
    webAuthnRemember: unknown,
    serverUrl: string,
    signal: AbortSignal
  ): Promise<void> {
    try {
      await authenticate(initialTwoFactor)
    } catch (error) {
      if (signal.aborted) throw new BitwardenDirectError('ABORTED')
      if (
        !(error instanceof BitwardenDirectError) ||
        error.code !== 'TWO_FACTOR_REQUIRED' ||
        error.webAuthnChallenge === undefined ||
        initialTwoFactor !== undefined ||
        typeof webAuthnRemember !== 'boolean' ||
        this.requestAccountWebAuthnAssertion === null
      ) {
        throw error
      }

      let assertion: AccountWebAuthnAssertion
      try {
        assertion = await this.requestAccountWebAuthnAssertion(
          Object.freeze({
            webVaultUrl: resolveBitwardenUrls(serverUrl).webVaultUrl,
            challenge: error.webAuthnChallenge,
            remember: webAuthnRemember,
            signal
          })
        )
      } catch {
        // Connector cancellation, timeout, and remote details collapse to stable public errors.
        throw new BitwardenDirectError(signal.aborted ? 'ABORTED' : 'INVALID_RESPONSE')
      }
      if (signal.aborted) throw new BitwardenDirectError('ABORTED')

      // This is the only retry. A second provider-7 challenge propagates to the normal mapper.
      await authenticate({ method: 7, assertion, remember: webAuthnRemember })
    }
  }

  protected normalizeNewDeviceOtp(value: string | undefined): string | undefined {
    if (value === undefined) return undefined
    const normalized = value.trim()
    if (normalized.length === 0 || normalized.length > MAX_TWO_FACTOR_CODE_LENGTH) {
      throw new VaultError('INVALID_INPUT')
    }
    return normalized
  }

  protected getOrCreateSyncClient(sync: PersistedSyncData): BitwardenSyncClient {
    if (this.sessionDeauthorizationInProgress) throw new VaultError('SYNC_FAILED')
    this.syncClient ??= this.createSyncClient(sync)
    return this.syncClient
  }

  protected requireSyncData(): PersistedSyncData {
    const sync = this.requireData().sync
    if (!sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    return sync
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
    const verifier = this.createSyncClient(verificationSync)
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
      throw this.mapSyncError(error)
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
    return this.exclusive(async () => {
      this.requireData()
      if (lease.abort.signal.aborted || lease.generation !== this.generation) {
        throw new VaultError('LOCKED')
      }
      if (this.syncClient !== lease.client || !lease.client.exportState().session) {
        throw new VaultError('SYNC_AUTH_REQUIRED')
      }
    })
  }

  protected finishAccountWebAuthnOperation(
    lease: AccountWebAuthnOperationLease,
    persistClientState: boolean
  ): Promise<void> {
    return this.exclusive(async () => {
      this.requireData()
      if (lease.abort.signal.aborted || lease.generation !== this.generation) {
        throw new VaultError('LOCKED')
      }
      if (this.syncClient !== lease.client || !lease.client.exportState().session) {
        throw new VaultError('SYNC_AUTH_REQUIRED')
      }
      if (persistClientState) await this.persistCurrentClientState()
      if (lease.abort.signal.aborted || lease.generation !== this.generation) {
        throw new VaultError('LOCKED')
      }
      if (this.syncClient !== lease.client || !lease.client.exportState().session) {
        throw new VaultError('SYNC_AUTH_REQUIRED')
      }
      this.accountSecurityAborts.delete(lease.abort)
    })
  }

  protected releaseAccountWebAuthnOperation(lease: AccountWebAuthnOperationLease): Promise<void> {
    return this.exclusive(async () => {
      this.accountSecurityAborts.delete(lease.abort)
    })
  }

  protected throwAccountWebAuthnOperationError(
    error: unknown,
    lease: AccountWebAuthnOperationLease
  ): never {
    if (lease.abort.signal.aborted || lease.generation !== this.generation) {
      throw new VaultError('LOCKED')
    }
    if (this.syncClient !== lease.client || !lease.client.exportState().session) {
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
    throw this.mapSyncError(error)
  }

  protected startSyncOperation(): AbortController {
    if (this.syncInProgress || this.sessionDeauthorizationInProgress) {
      throw new VaultError('SYNC_FAILED')
    }
    this.abortAccountSecurityRequests()
    const abort = new AbortController()
    this.syncAbort = abort
    this.syncInProgress = true
    this.syncLastError = null
    return abort
  }

  protected startAttachmentOperation(operationId: string): {
    operationId: string
    abort: AbortController
    canceledByUser: boolean
    committed: boolean
  } {
    assertUuid(operationId)
    if (this.activeAttachmentOperation) throw new VaultError('SYNC_FAILED')
    const operation = {
      operationId,
      abort: this.startSyncOperation(),
      canceledByUser: false,
      committed: false
    }
    this.activeAttachmentOperation = operation
    return operation
  }

  protected finishAttachmentOperation(operation: {
    operationId: string
    abort: AbortController
  }): void {
    if (this.activeAttachmentOperation?.operationId === operation.operationId) {
      this.activeAttachmentOperation = null
    }
    this.finishSyncOperation(operation.abort)
  }

  protected commitAttachmentOperation(operation: {
    operationId: string
    committed: boolean
  }): void {
    if (this.activeAttachmentOperation?.operationId === operation.operationId) {
      operation.committed = true
    }
  }

  protected finishSyncOperation(abort: AbortController): void {
    if (this.syncAbort === abort) this.syncAbort = null
    this.syncInProgress = false
  }

  protected abortNotificationTokenLeases(): void {
    for (const abort of this.notificationTokenAborts) abort.abort()
    this.notificationTokenAborts.clear()
  }

  protected assertLoginApprovalLease(lease: {
    generation: number
    client: BitwardenSyncClient
    abort: AbortController
  }): void {
    if (
      lease.abort.signal.aborted ||
      lease.generation !== this.generation ||
      lease.client !== this.syncClient ||
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
    const now = this.now().getTime()
    const expiresAt = Date.parse(request.createdAt) + LOGIN_APPROVAL_TTL_MS
    for (const [token, session] of this.loginApprovalSessions) {
      if (
        session.expiresAt <= now ||
        session.generation !== this.generation ||
        session.client !== this.syncClient
      ) {
        this.loginApprovalSessions.delete(token)
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
    while (this.loginApprovalSessions.size >= MAX_LOGIN_APPROVAL_SESSIONS) {
      const oldest = this.loginApprovalSessions.keys().next().value
      if (oldest === undefined) break
      this.loginApprovalSessions.delete(oldest)
    }
    const token = randomUUID()
    this.loginApprovalSessions.set(token, {
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

  protected abortAccountSecurityRequests(): void {
    for (const abort of this.accountSecurityAborts) abort.abort()
    this.accountSecurityAborts.clear()
    this.loginApprovalSessions.clear()
    for (const sessionId of this.authenticatorSetupSessions.keys()) {
      this.deleteAuthenticatorSetupSession(sessionId)
    }
    for (const sessionId of this.emailTwoFactorSetupSessions.keys()) {
      this.deleteEmailTwoFactorSetupSession(sessionId)
    }
  }

  protected abortNativeAttachmentBackups(): void {
    for (const abort of this.nativeAttachmentBackupAborts) abort.abort()
    this.nativeAttachmentBackupAborts.clear()
  }

  protected abortNativeAttachmentRestores(): void {
    for (const abort of this.nativeAttachmentRestoreAborts) abort.abort()
    this.nativeAttachmentRestoreAborts.clear()
  }

  protected async recoverNativeAttachmentRestoreAfterUnlock(
    requiresMigration: boolean
  ): Promise<void> {
    const current = this.requireData()
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
        this.nowIso()
      )
      next.updatedAt = next.nativeAttachmentRestore.updatedAt
    }
    if (completedPasswordChange) {
      next.masterPasswordChange = null
      if (next.sync) next.sync.state.session = null
      next.updatedAt = this.nowIso()
    }
    if (preparedPurge && next.sync) {
      next.sync.pendingPersonalVaultPurge = null
      next.updatedAt = this.nowIso()
    }
    await this.persist(next)
    this.data = next
  }

  protected async finishMasterPasswordChange(
    currentPassword: string,
    newPassword: string
  ): Promise<void> {
    const current = this.requireData()
    this.assertMasterPasswordChangeAccount(current)
    if (
      current.masterPasswordChange?.phase !== 'remote-confirmed' &&
      current.masterPasswordChange?.phase !== 'local-rekeyed'
    ) {
      throw new VaultError('SYNC_FAILED')
    }
    if (!this.key || !this.salt) throw new VaultError('LOCKED')

    const alreadyRekeyed = await this.store.verifyMasterPassword(newPassword, this.key, this.salt)
    if (!alreadyRekeyed) {
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

    this.generation += 1
    this.invalidatePinUnlockCapability()
    this.syncAbort?.abort()
    this.abortNotificationTokenLeases()
    this.abortAccountSecurityRequests()
    this.syncClient = null
    const localRekeyed = cloneData(this.requireData())
    if (!localRekeyed.masterPasswordChange) throw new VaultError('SYNC_FAILED')
    localRekeyed.masterPasswordChange.phase = 'local-rekeyed'
    localRekeyed.masterPasswordChange.updatedAt = this.nowIso()
    if (localRekeyed.sync) localRekeyed.sync.state.session = null
    localRekeyed.updatedAt = localRekeyed.masterPasswordChange.updatedAt
    await this.persist(localRekeyed)
    this.data = localRekeyed

    const complete = cloneData(localRekeyed)
    complete.masterPasswordChange = null
    complete.updatedAt = this.nowIso()
    await this.persist(complete)
    this.data = complete
  }

  protected evictExpiredAuthenticatorSetupSessions(): void {
    const now = this.now().getTime()
    for (const [sessionId, session] of this.authenticatorSetupSessions) {
      if (session.expiresAt <= now) this.deleteAuthenticatorSetupSession(sessionId)
    }
  }

  protected requireAuthenticatorSetupSession(sessionId: string): AuthenticatorSetupSession {
    this.evictExpiredAuthenticatorSetupSessions()
    const session = this.authenticatorSetupSessions.get(sessionId)
    if (
      !session ||
      session.generation !== this.generation ||
      session.client !== this.syncClient ||
      !session.client.exportState().session
    ) {
      if (session) this.deleteAuthenticatorSetupSession(sessionId)
      throw new VaultError('INVALID_INPUT')
    }
    return session
  }

  protected deleteAuthenticatorSetupSession(sessionId: string): void {
    const session = this.authenticatorSetupSessions.get(sessionId)
    if (!session) return
    session.key = ''
    session.userVerificationToken = null
    this.authenticatorSetupSessions.delete(sessionId)
  }

  protected evictExpiredEmailTwoFactorSetupSessions(): void {
    const now = this.now().getTime()
    for (const [sessionId, session] of this.emailTwoFactorSetupSessions) {
      if (session.expiresAt <= now) this.deleteEmailTwoFactorSetupSession(sessionId)
    }
  }

  protected requireEmailTwoFactorSetupSession(
    sessionId: string,
    phase: EmailTwoFactorSetupSession['phase']
  ): EmailTwoFactorSetupSession {
    this.evictExpiredEmailTwoFactorSetupSessions()
    const session = this.emailTwoFactorSetupSessions.get(sessionId)
    if (!session) throw new VaultError('INVALID_INPUT')
    if (
      session.generation !== this.generation ||
      session.client !== this.syncClient ||
      !session.client.exportState().session
    ) {
      this.deleteEmailTwoFactorSetupSession(sessionId)
      throw new VaultError('INVALID_INPUT')
    }
    if (session.phase !== phase) throw new VaultError('INVALID_INPUT')
    return session
  }

  protected deleteEmailTwoFactorSetupSession(sessionId: string): void {
    const session = this.emailTwoFactorSetupSessions.get(sessionId)
    if (!session) return
    session.userVerificationToken = null
    session.email = null
    this.emailTwoFactorSetupSessions.delete(sessionId)
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

  protected throwEmailTwoFactorSetupError(
    error: unknown,
    lease: { abort: AbortController; generation: number }
  ): never {
    if (lease.abort.signal.aborted || lease.generation !== this.generation) {
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
    throw this.mapSyncError(error)
  }

  protected mapSyncError(error: unknown): VaultError {
    if (error instanceof VaultError) {
      if (
        error.code === 'SYNC_AUTH_REQUIRED' ||
        error.code === 'SYNC_NEW_DEVICE_REQUIRED' ||
        error.code === 'SYNC_UNSUPPORTED_ACCOUNT' ||
        error.code === 'SYNC_NETWORK' ||
        error.code === 'SYNC_INVALID_RESPONSE' ||
        error.code === 'SYNC_INVALID_SSH_KEY' ||
        error.code === 'SYNC_CONFLICT' ||
        error.code === 'SYNC_FAILED'
      ) {
        this.recordSyncError(error.code)
      }
      return error
    }
    if (error instanceof BitwardenDirectError) {
      if (error.code === 'AUTH_REQUIRED') {
        this.recordSyncError('SYNC_AUTH_REQUIRED')
        return new VaultError('SYNC_AUTH_REQUIRED')
      }
      if (error.code === 'TWO_FACTOR_REQUIRED') {
        this.recordSyncError('SYNC_AUTH_REQUIRED')
        const providers = (error.twoFactorProviders ?? []).flatMap((provider) =>
          Number.isInteger(provider) && provider >= 0 && provider <= 8
            ? [String(provider) as SyncTwoFactorProvider]
            : []
        )
        return new SyncTwoFactorRequiredError(providers)
      }
      if (error.code === 'NEW_DEVICE_REQUIRED') {
        this.recordSyncError('SYNC_NEW_DEVICE_REQUIRED')
        return new VaultError('SYNC_NEW_DEVICE_REQUIRED')
      }
      if (error.code === 'NETWORK') {
        this.recordSyncError('SYNC_NETWORK')
        return new VaultError('SYNC_NETWORK')
      }
      if (error.code === 'INVALID_RESPONSE') {
        this.recordSyncError('SYNC_INVALID_RESPONSE', error.syncInvalidResponseStage)
        return new VaultError('SYNC_INVALID_RESPONSE')
      }
      if (error.code === 'INVALID_SSH_KEY') {
        this.recordSyncError('SYNC_INVALID_SSH_KEY')
        return new VaultError('SYNC_INVALID_SSH_KEY')
      }
      if (error.code === 'CONFLICT') {
        this.recordSyncError('SYNC_CONFLICT')
        return new VaultError('SYNC_CONFLICT')
      }
      if (error.code === 'ABORTED') return new VaultError('LOCKED')
      if (error.code === 'UNSUPPORTED_ACCOUNT_ENCRYPTION') {
        this.recordSyncError('SYNC_UNSUPPORTED_ACCOUNT')
        return new VaultError('SYNC_UNSUPPORTED_ACCOUNT')
      }
    }
    this.recordSyncError('SYNC_FAILED')
    return new VaultError('SYNC_FAILED')
  }

  protected recordSyncError(
    code: import('../shared/vault-contract').SyncErrorCode,
    detail?: import('../shared/vault-contract').SyncInvalidResponseStage
  ): void {
    this.syncLastError = code
    this.syncLastErrorAt = this.nowIso()
    this.syncLastErrorDetail = code === 'SYNC_INVALID_RESPONSE' ? (detail ?? null) : null
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
        return this.mapSyncError(error)
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
    const data = this.requireData()
    assertNoPendingPersonalVaultPurge(data.sync)
    const login = this.findLogin(data, request.id)
    this.assertActiveLogin(login)
    this.assertAttachmentAuthorized(login, validateAuthorization)
    const attachment = login.attachments.find((entry) => entry.id === request.attachmentId)
    if (!attachment) throw new VaultError('NOT_FOUND')
    const sync = this.requireSyncData()
    const mapping = sync.loginMappings.find((entry) => entry.localId === login.id)
    if (!mapping) throw new VaultError('INVALID_INPUT')
    return { data, attachment, mapping, client: this.getOrCreateSyncClient(sync) }
  }

  protected assertAttachmentAuthorized(
    login: StoredLogin,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): void {
    if (
      login.reprompt === 1 &&
      !validateAuthorization?.([login.id], { generation: this.generation })
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

  protected async persistCurrentClientState(): Promise<void> {
    const client = this.syncClient
    const current = this.requireData()
    if (!client || !current.sync) return
    const state = client.exportState()
    if (JSON.stringify(state) === JSON.stringify(current.sync.state)) return
    const next = cloneData(current)
    if (!next.sync) return
    next.sync.state = state
    next.updatedAt = this.nowIso()
    await this.persist(next)
    this.data = next
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
    const syncedAt = this.nowIso()
    if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    next.sync.state = client.exportState()
    next.sync.lastSyncAt = syncedAt
    next.updatedAt = syncedAt
    await this.persist(next)
    this.data = next
  }

  protected async restorePreDispatchPurge(original: VaultData): Promise<void> {
    const restored = cloneData(original)
    restored.updatedAt = this.nowIso()
    await this.persist(restored)
    this.data = restored
  }

  protected async reconcilePersonalVaultPurge(
    client: BitwardenSyncClient
  ): Promise<SyncPurgePersonalVaultResult> {
    const current = this.requireData()
    const journal = current.sync?.pendingPersonalVaultPurge
    if (journal?.phase !== 'dispatched') throw new VaultError('SYNC_FAILED')
    try {
      // Do not reuse the mutation signal: cancellation after dispatch must not suppress the
      // authoritative read that distinguishes a completed purge from an unknown partial result.
      await client.sync()
      const [remoteFolders, remoteLogins] = await Promise.all([
        client.listFolders(),
        client.listPersonalLogins()
      ])
      if (remoteFolders.length === 0 && remoteLogins.length === 0) {
        return await this.finalizePersonalVaultPurge(current, client)
      }
      const pending = cloneData(current)
      if (!pending.sync?.pendingPersonalVaultPurge) throw new VaultError('SYNC_FAILED')
      pending.sync.pendingPersonalVaultPurge.phase = 'dispatched'
      pending.sync.pendingPersonalVaultPurge.remainingItems = remoteLogins.length
      pending.sync.pendingPersonalVaultPurge.remainingFolders = remoteFolders.length
      pending.sync.state = client.exportState()
      pending.sync.lastSyncAt = this.nowIso()
      pending.updatedAt = pending.sync.lastSyncAt
      await this.persist(pending)
      this.data = pending
      this.syncLastError = null
      return {
        status: 'pending',
        remainingItems: remoteLogins.length,
        remainingFolders: remoteFolders.length,
        startedAt: journal.startedAt
      }
    } catch (error) {
      // The dispatched journal remains the sole source of truth when the authoritative read fails.
      if (error instanceof VaultError) throw error
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
    complete.sync.state = client.exportState()
    complete.sync.lastSyncAt = this.nowIso()
    complete.updatedAt = complete.sync.lastSyncAt
    await this.persist(complete)
    this.data = complete
    this.syncLastError = null
    return { status: 'complete', removedItems, removedFolders }
  }

  protected async performSync(
    current: VaultData,
    client: BitwardenSyncClient,
    signal: AbortSignal
  ): Promise<SyncResult> {
    let source = current
    const pendingPurge = source.sync?.pendingPersonalVaultPurge
    if (pendingPurge?.phase === 'prepared') {
      const cleared = cloneData(source)
      if (!cleared.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
      cleared.sync.pendingPersonalVaultPurge = null
      cleared.updatedAt = this.nowIso()
      await this.persist(cleared)
      this.data = cleared
      source = cleared
    } else if (pendingPurge?.phase === 'dispatched') {
      const reconciled = await this.reconcilePersonalVaultPurge(client)
      if (reconciled.status === 'pending') throw new VaultError('SYNC_FAILED')
      const completedSync = this.requireSyncData()
      return {
        ...this.baseSyncStatus(completedSync, 'ready'),
        pulled: 0,
        pushed: 0,
        deleted: reconciled.removedItems + reconciled.removedFolders,
        conflicts: 0
      }
    }
    const sync = source.sync
    if (!sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    await client.sync(signal)
    const sharedSnapshot = await this.fetchSharedSnapshot(client)
    const initialRemote = await Promise.all([
      client.listFolders(signal),
      client.listPersonalLogins(signal),
      client.getEquivalentDomainSettings(signal),
      client.listSends?.(signal) ?? Promise.resolve([] as BitwardenSendItem[])
    ])
    let remoteFolders = initialRemote[0]
    let remoteLogins = initialRemote[1]
    const domainSettings = validateRemoteEquivalentDomainSettings(initialRemote[2])
    let remoteSends = initialRemote[3]
    const next = cloneData(source)
    if (sharedSnapshot) {
      next.organizations = sharedSnapshot.organizations
      next.collections = sharedSnapshot.collections
      next.sharedLogins = sharedSnapshot.sharedLogins
    }
    if (next.sync?.pendingLoginMutation) {
      await this.resumePendingLoginMutation(next, client, remoteFolders, remoteLogins, signal)
      await client.sync(signal)
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
    for (const upgrade of legacyCustomFieldBaselineUpgrades(
      this.localSyncSnapshot(next),
      remoteSnapshot,
      syncMetadata
    )) {
      const upgradedLogin = this.findLogin(next, upgrade.localId)
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
    const plan = planSync(this.localSyncSnapshot(next), remoteSnapshot, syncMetadata)
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
    await client.sync(signal)
    const [finalRemoteFolders, finalRemoteLogins] = await Promise.all([
      client.listFolders(signal),
      client.listPersonalLogins(signal)
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
    const syncedAt = this.nowIso()
    next.sync = {
      ...sync,
      state: client.exportState(),
      lastSyncAt: syncedAt,
      folderMappings: metadata.folderLinks.map((link) => ({ ...link })),
      loginMappings: metadata.loginLinks.map((link) => ({ ...link })),
      folderTombstones: [],
      loginTombstones: [],
      pendingLoginMutation: null,
      pendingLoginImport: null,
      pendingPersonalVaultPurge: null,
      domainSettings: cloneEquivalentDomainSettings(domainSettings)
    }
    next.updatedAt = syncedAt
    await this.persist(next)
    this.data = next
    this.syncLastError = null
    return { ...this.baseSyncStatus(next.sync, 'ready'), ...counts }
  }

  protected async fetchSharedSnapshot(client: BitwardenSyncClient): Promise<{
    organizations: OrganizationView[]
    collections: CollectionView[]
    sharedLogins: StoredSharedLogin[]
  } | null> {
    if (!client.listOrganizations || !client.listCollections || !client.listOrganizationCiphers) {
      return null
    }
    try {
      const [organizations, collections, sharedLogins] = await Promise.all([
        client.listOrganizations(),
        client.listCollections(),
        client.listOrganizationCiphers()
      ])
      const parsedOrganizations = organizations.map(parseStoredOrganization)
      const organizationIds = new Set(parsedOrganizations.map((organization) => organization.id))
      if (organizationIds.size !== parsedOrganizations.length)
        throw new Error('duplicate organization')
      const parsedCollections = collections.map(parseStoredCollection)
      const collectionIds = new Set(parsedCollections.map((collection) => collection.id))
      if (
        collectionIds.size !== parsedCollections.length ||
        parsedCollections.some((collection) => !organizationIds.has(collection.organizationId))
      ) {
        throw new Error('invalid collection membership')
      }
      const parsedSharedLogins = sharedLogins.map((login) => this.sharedLoginFromRemote(login))
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
        throw new Error('invalid shared cipher membership')
      }
      return {
        organizations: parsedOrganizations,
        collections: parsedCollections,
        sharedLogins: parsedSharedLogins
      }
    } catch {
      throw new VaultError('SYNC_FAILED')
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
    const desired = this.localSyncSnapshot(data).logins.find(
      (login) => login.id === pending.localId
    )
    const current = this.remoteSyncSnapshot(remoteFolders, remoteLogins).logins.find(
      (login) => login.id === pending.remoteId
    )

    if (pending.intent === 'hard-delete') {
      if (current) await client.hardDeleteLogin(pending.remoteId, signal)
      data.sync.pendingLoginMutation = null
      await this.persist(data)
      this.data = cloneData(data)
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
    await this.persist(data)
    this.data = cloneData(data)
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
      startedAt: this.nowIso(),
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
    data.updatedAt = this.nowIso()
    try {
      await this.persist(data)
      this.data = cloneData(data)
    } catch (error) {
      await client.discardPreparedLoginImport!(discardToken).catch(() => undefined)
      throw error
    }

    if (signal.aborted) {
      await client.discardPreparedLoginImport!(discardToken).catch(() => undefined)
      throw new BitwardenDirectError('ABORTED')
    }
    data.sync.pendingLoginImport.phase = 'dispatched'
    data.updatedAt = this.nowIso()
    try {
      await this.persist(data)
      this.data = cloneData(data)
    } catch (error) {
      await client.discardPreparedLoginImport!(discardToken).catch(() => undefined)
      throw error
    }

    if (signal.aborted) {
      try {
        data.sync.pendingLoginImport.phase = 'prepared'
        data.updatedAt = this.nowIso()
        await this.persist(data)
        this.data = cloneData(data)
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
    data.updatedAt = this.nowIso()
    await this.persist(data)
    this.data = cloneData(data)
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
        const remote = new Map(
          (await client.listPersonalLogins(signal)).map((login) => [login.id, login])
        )
        if (batch.every((candidate) => this.bulkRemoteLoginMutationApplied(candidate, remote))) {
          return
        }
      } catch {
        // The original mutation error is the most useful failure. A later sync retries safely
        // from the server's authoritative state instead of assuming this batch was atomic.
      }
      if (signal.aborted) throw new BitwardenDirectError('ABORTED')
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
        const folder = this.findFolder(data, action.localId)
        folder.name = action.remote.name
        folder.updatedAt = this.nowIso()
      } else if (action.kind === 'delete-local') {
        this.deleteLocalFolder(data, action.localId)
      } else if (action.kind === 'delete-remote') {
        await client.deleteFolder(action.remoteId, signal)
      } else if (action.reason === 'both-modified') {
        if (!action.local || !action.remote) throw new VaultError('SYNC_FAILED')
        this.createLocalFolder(data, action.conflictName)
        const primary = this.findFolder(data, action.local.id)
        primary.name = action.remote.name
        primary.updatedAt = this.nowIso()
      } else if (action.reason === 'remote-deleted') {
        if (!action.local) throw new VaultError('SYNC_FAILED')
        const local = this.findFolder(data, action.local.id)
        local.name = action.conflictName
        local.updatedAt = this.nowIso()
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
        await this.persist(data)
        this.data = cloneData(data)
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
        await this.persist(data)
        this.data = cloneData(data)
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
      const local = this.findLogin(data, action.local.id)
      local.name = action.conflictName
      local.updatedAt = this.nowIso()
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
    const now = this.nowIso()
    const folder: FolderView = {
      id: this.validatedNewId(),
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
    const now = this.nowIso()
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
    const now = this.nowIso()
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
        id: this.validatedNewId(),
        name: this.uniqueImportedFolderName(
          data,
          normalizeRequiredString(source.name, MAX_NAME_LENGTH)
        ),
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
      abort: this.startSyncOperation(),
      client,
      generation: this.generation
    }
    this.nativeAttachmentRestoreAborts.add(operation.abort)
    return operation
  }

  protected finishNativeAttachmentRestoreOperation(operation: { abort: AbortController }): void {
    this.nativeAttachmentRestoreAborts.delete(operation.abort)
    this.finishSyncOperation(operation.abort)
  }

  protected assertNativeAttachmentRestoreLease(operation: {
    abort: AbortController
    client: BitwardenSyncClient
    generation: number
  }): void {
    if (
      operation.abort.signal.aborted ||
      operation.generation !== this.generation ||
      operation.client !== this.syncClient ||
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
    next.sync.lastSyncAt = this.nowIso()
    return next
  }

  protected async persistFailedNativeAttachmentRestoreAttempt(
    key: NativeAttachmentRestoreAttachmentKey
  ): Promise<void> {
    const current = this.data
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
      this.nowIso()
    )
    next.updatedAt = next.nativeAttachmentRestore.updatedAt
    await this.persist(next)
    this.data = next
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
    const now = this.nowIso()
    const createdAt = source.createdAt ?? now
    const updatedAt = source.updatedAt ?? createdAt
    const login: StoredLogin = {
      id: this.validatedNewId(),
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
      createdAt: normalized.createdAt ?? this.nowIso(),
      updatedAt: normalized.updatedAt ?? this.nowIso(),
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
    const login = this.findLogin(data, id)
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
    login.updatedAt = source.updatedAt ?? this.nowIso()
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
    return this.exclusive(async () => {
      assertUuid(request.id)
      const current = this.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      const generation = this.generation
      const currentLogin = this.findLogin(current, request.id)
      this.assertActiveLogin(currentLogin)
      const result = await operation(currentLogin)
      const next = cloneData(current)
      const usedLogin = this.findLogin(next, request.id)
      const now = this.nowIso()
      usedLogin.usageCount = Math.min(Number.MAX_SAFE_INTEGER, usedLogin.usageCount + 1)
      usedLogin.lastUsedAt = now
      next.updatedAt = now
      await this.persist(next)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      this.data = next
      return result
    })
  }

  protected mutate<T>(mutation: (data: VaultData, now: string) => T): Promise<T> {
    return this.exclusive(async () => {
      const next = cloneData(this.requireData())
      assertNoPendingPersonalVaultPurge(next.sync)
      const generation = this.generation
      const now = this.nowIso()
      const result = mutation(next, now)
      next.updatedAt = now
      await this.persist(next)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      this.data = next
      return result
    })
  }

  protected async persist(data: VaultData): Promise<void> {
    if (!this.key || !this.salt) throw new VaultError('LOCKED')
    // Never persist data the read path would reject: a write-time bug must fail the current
    // operation loudly instead of locking the user out of the vault at the next unlock.
    parseVaultData(data)
    await this.store.write(data, this.key, this.salt)
  }

  protected requireData(): VaultData {
    if (!this.data || !this.key || !this.salt) throw new VaultError('LOCKED')
    return this.data
  }

  protected requireFastReadData(): VaultData {
    if (this.fastReadsBlocked) throw new VaultError('LOCKED')
    return this.requireData()
  }

  protected async currentStatus(): Promise<VaultStatus> {
    if (this.data && this.key && this.salt) return { state: 'unlocked' }
    return { state: (await this.store.exists()) ? 'locked' : 'uninitialized' }
  }

  protected findFolder(data: VaultData, id: string): FolderView {
    const folder = data.folders.find((candidate) => candidate.id === id)
    if (!folder) throw new VaultError('NOT_FOUND')
    return folder
  }

  protected findLogin(data: VaultData, id: string): StoredLogin {
    const login = data.logins.find((candidate) => candidate.id === id)
    if (!login) throw new VaultError('NOT_FOUND')
    return login
  }

  protected resolveLoginBatch(
    data: VaultData,
    request: LoginBatchRequest,
    assertState: (login: StoredLogin) => void
  ): StoredLogin[] {
    if (
      !Array.isArray(request.ids) ||
      request.ids.length === 0 ||
      request.ids.length > MAX_LOGIN_BATCH_IDS
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    request.ids.forEach(assertUuid)
    if (new Set(request.ids).size !== request.ids.length) {
      throw new VaultError('INVALID_INPUT')
    }
    const logins = request.ids.map((id) => this.findLogin(data, id))
    logins.forEach(assertState)
    return logins
  }

  protected assertActiveLogin(login: StoredLogin): void {
    if (login.deletedAt !== null) throw new VaultError('INVALID_INPUT')
  }

  protected assertExpectedPasskeyGeneration(value: unknown): asserts value is number {
    if (!Number.isSafeInteger(value) || (value as number) < 0) {
      throw new VaultError('INVALID_INPUT')
    }
    if (value !== this.generation) throw new VaultError('LOCKED')
  }

  protected assertExpectedPasskeyRevision(
    login: StoredLogin,
    value: unknown
  ): asserts value is string {
    if (typeof value !== 'string' || value !== login.updatedAt) {
      throw new VaultError('INVALID_INPUT')
    }
  }

  protected normalizeFolderId(data: VaultData, folderId: unknown): string | null {
    if (folderId === undefined || folderId === null) return null
    assertUuid(folderId)
    this.findFolder(data, folderId)
    return folderId
  }

  protected assertUniqueFolderName(data: VaultData, name: string, excludedId?: string): void {
    const normalized = name.toLocaleLowerCase('en-US')
    if (
      data.folders.some(
        (folder) =>
          folder.id !== excludedId && folder.name.toLocaleLowerCase('en-US') === normalized
      )
    ) {
      throw new VaultError('DUPLICATE_NAME')
    }
  }

  protected uniqueImportedFolderName(data: VaultData, requestedName: string): string {
    const existing = new Set(data.folders.map((folder) => folder.name.toLocaleLowerCase('en-US')))
    if (!existing.has(requestedName.toLocaleLowerCase('en-US'))) return requestedName

    for (let copy = 1; copy <= data.folders.length + 1; copy += 1) {
      const suffix = copy === 1 ? ' (Imported)' : ` (Imported ${copy})`
      const codePoints = Array.from(requestedName)
      while (codePoints.join('').length > MAX_NAME_LENGTH - suffix.length) codePoints.pop()
      const candidate = `${codePoints.join('')}${suffix}`
      if (!existing.has(candidate.toLocaleLowerCase('en-US'))) return candidate
    }
    throw new VaultError('INVALID_INPUT')
  }

  protected async assertMasterPassword(candidateValue: unknown): Promise<void> {
    if (typeof candidateValue !== 'string') throw new VaultError('INVALID_MASTER_PASSWORD')
    const candidate = candidateValue.normalize('NFC')
    if (candidate.length === 0 || candidate.length > MAX_MASTER_PASSWORD_LENGTH) {
      throw new VaultError('INVALID_MASTER_PASSWORD')
    }
    const generation = this.generation
    if (!this.key || !this.salt) throw new VaultError('LOCKED')
    const valid = await this.store.verifyMasterPassword(candidate, this.key, this.salt)
    if (generation !== this.generation) throw new VaultError('LOCKED')
    if (!valid) throw new VaultError('INVALID_MASTER_PASSWORD')
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

  protected validatedNewId(): string {
    const id = this.createId()
    assertUuid(id)
    return id
  }

  protected nowIso(): string {
    const value = this.now()
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw new VaultError('INTERNAL_ERROR')
    }
    return value.toISOString()
  }

  protected async exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const inherited = this.exclusiveContext.getStore()
    if (inherited?.active) return operation()
    const previous = this.operationQueue
    let release!: () => void
    this.operationQueue = new Promise<void>((resolve) => {
      release = resolve
    })
    await previous
    const context = { active: true }
    try {
      return await this.exclusiveContext.run(context, operation)
    } finally {
      context.active = false
      release()
    }
  }
}
