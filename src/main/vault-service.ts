import { createHash, randomInt as nodeRandomInt, randomUUID } from 'node:crypto'
import { AsyncLocalStorage } from 'node:async_hooks'
import type {
  EditorSecretsRequest,
  EquivalentDomainSettingsUpdate,
  EquivalentDomainSettingsView,
  AttachmentCancelRequest,
  AttachmentCancelResult,
  AttachmentDeleteRequest,
  AttachmentDeleteResult,
  AttachmentDownloadRequest,
  AttachmentDownloadResult,
  AttachmentFixLegacyRequest,
  AttachmentFixLegacyResult,
  AttachmentOperationKind,
  AttachmentOperationStage,
  AttachmentProgressEvent,
  AttachmentTargetRequest,
  AttachmentUploadRequest,
  AttachmentUploadResult,
  AccountSessionDeauthorizationRequest,
  EditorSecretsView,
  CredentialGeneratorRequest,
  CredentialGeneratorResult,
  FolderCreateRequest,
  FolderDeleteRequest,
  FolderReorderRequest,
  FolderUpdateRequest,
  CustomFieldRequest,
  ItemFieldRequest,
  FolderView,
  GeneratedCredentialCopyRequest,
  GeneratorHistoryEntry,
  GeneratorHistoryLocator,
  LoginCreateRequest,
  LoginAuthorizeRequest,
  LoginAuthorizeManyRequest,
  LoginBatchRequest,
  LoginFavoriteRequest,
  LoginIdRequest,
  LoginListRequest,
  LoginOpenUriRequest,
  LoginPrefetchRequest,
  PasskeyDeleteRequest,
  PasswordHistoryEntryRequest,
  PasswordHistoryRestoreRequest,
  LoginMoveRequest,
  LoginMoveManyRequest,
  LoginSummary,
  LoginUpdateRequest,
  LoginView,
  OrganizationView,
  CollectionView,
  SharedLoginListRequest,
  SharedLoginSummary,
  SharedLoginView,
  EmergencyAccessView,
  VaultAttachmentView,
  VaultPasswordHistoryEntry,
  VaultPasswordHistoryView,
  VaultHealthExposedReport,
  VaultHealthAccountBreachReport,
  VaultHealthAccountBreachRequest,
  VaultHealthReport,
  VaultReprompt,
  VaultSecretField,
  SyncConnectRequest,
  SyncPurgePersonalVaultRequest,
  SyncPurgePersonalVaultResult,
  SyncResult,
  SyncStatus,
  SyncUnlockRequest,
  TotpCodeView,
  SendCreateRequest,
  SendFileCreateRequest,
  SendFileCreateResult,
  SendFileDownloadRequest,
  SendFileDownloadResult,
  SendUpdateRequest,
  SendIdRequest,
  SendView,
  VaultImportResult,
  VaultStatus
} from '../shared/vault-contract'
import {
  MAX_LOGIN_BATCH_IDS,
  MAX_LOGIN_AUTHORIZE_MANY_IDS,
  MAX_LOGIN_MOVE_MANY_IDS,
  MAX_LOGIN_PREFETCH_IDS,
  MAX_LOGIN_SEARCH_QUERY_LENGTH,
  MAX_ACCOUNT_PROFILE_NAME_BYTES,
  ACCOUNT_SESSION_DEAUTHORIZATION_CONFIRMATION
} from '../shared/vault-contract'
import {
  BitwardenDirectError,
  type BitwardenFolder,
  type BitwardenLoginDraft,
  type BitwardenLoginItem,
  type BitwardenOrganizationCipher,
  type BitwardenSendItem,
  type BitwardenDirectState,
  type BitwardenLoginTwoFactor,
  type BitwardenSyncClient,
  type BitwardenTwoFactor,
  type BitwardenWebAuthnRegistrationRequest,
  type BitwardenWebAuthnRegistrationSetup
} from './bitwarden-direct'
import { resolveBitwardenUrls } from './bitwarden-http'
import { EncryptedVaultStore } from './encrypted-vault-store'
import { PinUnlockCapability, PinUnlockError } from './pin-unlock'
import type { BitwardenNotificationConnectionInfo } from './bitwarden-notifications'
import { searchVaultItems } from './vault-search'
import { analyzeVaultHealth, type VaultHealthItem } from './vault-health'
import { hashPasswordsForPwnedLookup, PwnedPasswordsClient } from './pwned-passwords'
import {
  analyzeInactiveTwoFactor,
  type InactiveTwoFactorInput,
  type InactiveTwoFactorReport,
  type TwoFactorDirectoryDataset
} from './inactive-two-factor'
import {
  buildBitwardenJson,
  parseBitwardenJson,
  type PortableVaultSnapshot
} from './vault-portability-codec'
import type {
  NativeAttachmentBackupEntry,
  NativeAttachmentBackupPreview
} from './native-attachment-backup'
import type { BitwardenAttachmentByteSource } from './bitwarden-attachment-stream'
import {
  assertNativeAttachmentRestoreBinding,
  beginNativeAttachmentRestoreAttempt,
  bindNativeAttachmentRestoreRemoteItem,
  completeNativeAttachmentRestoreAttempt,
  createNativeAttachmentRestoreJournal,
  failNativeAttachmentRestoreAttempt,
  reconcileNativeAttachmentRestoreMissing,
  reconcileNativeAttachmentRestoreUploaded,
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
import { VaultError } from './vault-errors'
import type { VaultAttachmentFileService } from './vault-attachment-files'
import {
  createPasskeyCredential as createSoftwarePasskeyCredential,
  getPasskeyAssertion as createSoftwarePasskeyAssertion
} from './passkey-authenticator'
import { generateTotp } from './totp'
import type { SshKeyMaterial } from './ssh-key'
import { signSshAgentData as createSshAgentSignature } from './ssh-agent-crypto'
import { SSH_AGENT_MAX_MESSAGE_LENGTH } from './ssh-agent-protocol'
import {
  fetchWebsiteIconDataUrl,
  parseWebsiteHostname,
  resolveWebsiteIconUrl
} from './website-icon'
import { createUriMatchBudget, loginUrisMatch } from './uri-matcher'
import { validatePasskeyOrigin } from './passkey-origin-validation'
import type { AccountWebAuthnAssertion } from './account-webauthn-codec'
import type { AccountWebAuthnAttestation } from './account-webauthn-registration-codec'
import {
  DATA_VERSION,
  MAX_MASTER_PASSWORD_LENGTH,
  MAX_NAME_LENGTH,
  MAX_USERNAME_LENGTH,
  MAX_PASSWORD_LENGTH,
  AUTHENTICATOR_SETUP_TTL_MS,
  MAX_AUTHENTICATOR_SETUP_SESSIONS,
  EMAIL_TWO_FACTOR_SETUP_TTL_MS,
  MAX_EMAIL_TWO_FACTOR_SETUP_SESSIONS,
  MAX_URI_LENGTH,
  MAX_NOTES_LENGTH,
  MAX_ITEM_FIELD_LENGTH,
  MAX_PASSWORD_HISTORY,
  MAX_ATTACHMENT_ID_LENGTH,
  MAX_SYNC_SECRET_LENGTH,
  MAX_TWO_FACTOR_CODE_LENGTH,
  MAX_PENDING_LOGIN_IMPORT_ENTRIES,
  MAX_PENDING_LOGIN_IMPORT_MARKER_LENGTH,
  UUID_PATTERN
} from './vault/limits'
import {
  isRecord,
  assertUuid,
  normalizeRequiredString,
  normalizeSyncPassword,
  normalizeNullableString,
  normalizeMasterPassword
} from './vault/parse-primitives'
import { parseVaultData, parseVaultDataTagged, cloneData } from './vault/vault-data-parsing'
import {
  toSummary,
  toSharedSummary,
  toVaultSearchItem,
  toView,
  toSharedView,
  compareText,
  validRemoteDate,
  validRemoteDeletedDate,
  validRemoteArchivedDate,
  isCompositeRemoteLoginUpdate,
  sameLoginContentExceptFolder
} from './vault/views'
import {
  recordSyncDeletion,
  assertNoPendingLoginImport,
  assertNoPendingPersonalVaultPurge
} from './vault/sync-data-parsing'
import { parseFolder, cloneItemName, parseStoredLogin } from './vault/login-parsing'
import { sendViewFromRemote } from './vault/send-parsing'
import {
  normalizePasskeyRpId,
  normalizePasskeyCredentialId,
  normalizePasskeyCredentialIds,
  assertPasskeyApproval,
  validateRemotePasskeys,
  findPasskeyVaultMatches,
  activeVaultContainsCredentialId
} from './vault/passkey-parsing'
import {
  cloneCustomFields,
  normalizeCustomFields,
  customFieldFromSource,
  customFieldValue
} from './vault/custom-fields'
import {
  cloneLoginUris,
  uriAlias,
  createRequestUris,
  updateRequestUris,
  remoteLoginUris,
  loginUriAt
} from './vault/login-uris'
import {
  EDITOR_SECRET_FIELDS_BY_TYPE,
  emptyItemFields,
  normalizeItemFieldsForStorage,
  normalizeItemType,
  normalizeReprompt,
  applyItemFields,
  assertSecretField,
  assertCopyField
} from './vault/item-fields'
import {
  cloneEquivalentDomainSettings,
  validateRemoteEquivalentDomainSettings,
  equivalentDomainRevision,
  equivalentDomainSettingsView,
  normalizeEquivalentDomainUpdate
} from './vault/equivalent-domains'
import {
  parseStoredOrganization,
  parseStoredCollection,
  emergencyAccessViewFromRemote
} from './vault/org-collection-parsing'
import { cloneAttachments, validateRemoteAttachments } from './vault/attachments-parsing'
import { parseSupportedSshAgentPublicKeyBlob, sshAgentFingerprint } from './vault/ssh-helpers'
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
  VaultExportSnapshot,
  VaultNativeAttachmentBackupSource,
  VaultNativeAttachmentRestoreSummary,
  SshAgentVaultIdentity,
  SshAgentVaultSignRequest,
  SshAgentVaultSignResult,
  SshAgentVaultAuthorizationValidator,
  PasskeyVaultAuthorizationValidator,
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

export class VaultService {
  private key: Buffer | null = null
  private salt: Buffer | null = null
  private data: VaultData | null = null
  /** Blocks lock-free committed-snapshot reads before unlock and as soon as lock starts. */
  private fastReadsBlocked = true
  private pinUnlockCapability: PinUnlockCapability | null = null
  private pinLifecycleEpoch = 0
  private generation = 0
  private operationQueue: Promise<void> = Promise.resolve()
  private readonly exclusiveContext = new AsyncLocalStorage<{ active: boolean }>()
  private syncClient: BitwardenSyncClient | null = null
  private syncAbort: AbortController | null = null
  private readonly notificationTokenAborts = new Set<AbortController>()
  private readonly accountSecurityAborts = new Set<AbortController>()
  private readonly nativeAttachmentBackupAborts = new Set<AbortController>()
  private readonly nativeAttachmentRestoreAborts = new Set<AbortController>()
  private readonly authenticatorSetupSessions = new Map<string, AuthenticatorSetupSession>()
  private readonly emailTwoFactorSetupSessions = new Map<string, EmailTwoFactorSetupSession>()
  private readonly generatorService: VaultGeneratorService
  private readonly sendService: VaultSendService
  private syncInProgress = false
  private sessionDeauthorizationInProgress = false
  private syncLastError: import('../shared/vault-contract').SyncErrorCode | null = null
  private syncLastErrorAt: string | null = null
  private syncLastErrorDetail: import('../shared/vault-contract').SyncInvalidResponseStage | null =
    null
  private activeAttachmentOperation: {
    operationId: string
    abort: AbortController
    canceledByUser: boolean
    committed: boolean
  } | null = null
  private readonly now: () => Date
  private readonly createId: () => string
  private readonly createSyncClient: (sync: PersistedSyncData) => BitwardenSyncClient
  private readonly fetch: typeof fetch
  private readonly attachmentFiles: VaultAttachmentFileService | null
  private readonly requestAccountWebAuthnAssertion: VaultAccountWebAuthnAssertionRequester | null
  private readonly requestAccountWebAuthnRegistration: VaultAccountWebAuthnRegistrationRequester | null
  private readonly websiteIconCache = new Map<string, string | null>()
  private readonly websiteIconRequests = new Map<string, Promise<string | null>>()
  private activeExposedPasswordOperation: ActiveExposedPasswordOperation | null = null
  private activeAccountBreachOperation: ActiveAccountBreachOperation | null = null

  constructor(
    private readonly store: EncryptedVaultStore<unknown>,
    private readonly platform: VaultPlatform,
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
      try {
        if (generation !== this.generation || lifecycleEpoch !== this.pinLifecycleEpoch) {
          throw new VaultError('LOCKED')
        }
        this.requireData()
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
        capability = await PinUnlockCapability.create(request.pin, this.key, this.salt)
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
      let material: { key: Buffer; salt: Buffer } | null = null
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

  private clearUnlockedRuntimeState(): void {
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

  syncStatus(): Promise<SyncStatus> {
    return this.exclusive(async () => this.currentSyncStatus(true))
  }

  async getAccountSecurityProfile(): Promise<
    import('../shared/vault-contract').AccountSecurityProfile
  > {
    const lease = await this.exclusive(async () => {
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.getAccountSecurityProfile) throw new VaultError('SYNC_FAILED')
      const abort = new AbortController()
      this.accountSecurityAborts.add(abort)
      return {
        generation: this.generation,
        client,
        email: sync.email,
        request: client.getAccountSecurityProfile.bind(client),
        abort
      }
    })
    try {
      const profile = await lease.request(lease.abort.signal)
      return await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        const state = lease.client.exportState()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !state.session ||
          state.profileId !== profile.id ||
          profile.email.toLowerCase() !== lease.email.toLowerCase()
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.persistCurrentClientState()
        return {
          name: profile.name,
          email: profile.email,
          avatarColor: profile.avatarColor,
          emailVerified: profile.emailVerified,
          twoFactorEnabled: profile.twoFactorEnabled
        }
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    }
  }

  async updateAccountProfileName(request: {
    name: string
    expectedName: string
  }): Promise<import('../shared/vault-contract').AccountSecurityProfile> {
    if (
      typeof request.name !== 'string' ||
      typeof request.expectedName !== 'string' ||
      Buffer.byteLength(request.name, 'utf8') > MAX_ACCOUNT_PROFILE_NAME_BYTES ||
      Buffer.byteLength(request.expectedName, 'utf8') > MAX_ACCOUNT_PROFILE_NAME_BYTES ||
      /[\0\r\n]/u.test(request.name) ||
      /[\0\r\n]/u.test(request.expectedName)
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    return this.updateAccountProfile((client, signal) => {
      if (!client.updateAccountProfileName) throw new VaultError('SYNC_FAILED')
      return client.updateAccountProfileName(request.name, request.expectedName, signal)
    })
  }

  async updateAccountAvatarColor(request: {
    avatarColor: string | null
    expectedAvatarColor: string | null
  }): Promise<import('../shared/vault-contract').AccountSecurityProfile> {
    const validColor = (value: unknown): value is string | null =>
      value === null || (typeof value === 'string' && /^#[0-9a-f]{6}$/iu.test(value))
    if (!validColor(request.avatarColor) || !validColor(request.expectedAvatarColor)) {
      throw new VaultError('INVALID_INPUT')
    }
    const avatarColor = request.avatarColor?.toLocaleUpperCase('en-US') ?? null
    const expectedAvatarColor = request.expectedAvatarColor?.toLocaleUpperCase('en-US') ?? null
    return this.updateAccountProfile((client, signal) => {
      if (!client.updateAccountAvatarColor) throw new VaultError('SYNC_FAILED')
      return client.updateAccountAvatarColor(avatarColor, expectedAvatarColor, signal)
    })
  }

  private async updateAccountProfile(
    request: (
      client: BitwardenSyncClient,
      signal: AbortSignal
    ) => Promise<import('./bitwarden-http').BitwardenAccountSecurityProfile>
  ): Promise<import('../shared/vault-contract').AccountSecurityProfile> {
    const lease = await this.exclusive(async () => {
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.exportState().session) throw new VaultError('SYNC_AUTH_REQUIRED')
      const abort = new AbortController()
      this.accountSecurityAborts.add(abort)
      return { generation: this.generation, client, email: sync.email, abort }
    })
    try {
      const profile = await request(lease.client, lease.abort.signal)
      return await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        const state = lease.client.exportState()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !state.session ||
          state.profileId !== profile.id ||
          profile.email.toLowerCase() !== lease.email.toLowerCase()
        ) {
          throw new VaultError('ACCOUNT_PROFILE_MUTATION_UNKNOWN')
        }
        await this.persistCurrentClientState()
        return {
          name: profile.name,
          email: profile.email,
          avatarColor: profile.avatarColor,
          emailVerified: profile.emailVerified,
          twoFactorEnabled: profile.twoFactorEnabled
        }
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof BitwardenDirectError) {
          if (error.code === 'ACCOUNT_PROFILE_STALE') {
            throw new VaultError('ACCOUNT_PROFILE_STALE')
          }
          if (error.code === 'ACCOUNT_PROFILE_MUTATION_UNKNOWN') {
            throw new VaultError('ACCOUNT_PROFILE_MUTATION_UNKNOWN')
          }
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    }
  }

  async getAccountDevices(): Promise<import('../shared/vault-contract').AccountDevicesResult> {
    const lease = await this.exclusive(async () => {
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.exportState().session) throw new VaultError('SYNC_AUTH_REQUIRED')
      const abort = new AbortController()
      this.accountSecurityAborts.add(abort)
      return {
        generation: this.generation,
        client,
        request: client.getAccountDevices?.bind(client) ?? null,
        abort
      }
    })
    try {
      const devices = lease.request ? await lease.request(lease.abort.signal) : null
      return await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        if (!devices) return { status: 'unavailable' }
        await this.persistCurrentClientState().catch(() => undefined)
        return {
          status: 'available',
          devices: devices.map((device) => ({
            name: device.name,
            type: device.type,
            createdAt: device.createdAt,
            lastActivityAt: device.lastActivityAt,
            current: device.current,
            trusted: device.trusted,
            pendingAuthRequest: device.pendingAuthRequest
          }))
        }
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (this.syncClient !== lease.client || !lease.client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        if (error instanceof BitwardenDirectError && error.code === 'NOT_FOUND') {
          return { status: 'unavailable' }
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    }
  }

  async deauthorizeAllSessions(request: AccountSessionDeauthorizationRequest): Promise<SyncStatus> {
    let lease: {
      generation: number
      client: BitwardenSyncClient
      request: NonNullable<BitwardenSyncClient['deauthorizeAllSessions']>
      abort: AbortController
      masterPassword: string
      originalState: BitwardenDirectState
    }
    try {
      lease = await this.exclusive(async () => {
        const descriptors =
          typeof request === 'object' && request !== null
            ? Object.getOwnPropertyDescriptors(request)
            : Object.create(null)
        const masterPassword = descriptors.masterPassword?.value
        const confirmation = descriptors.confirmation?.value
        const confirm = descriptors.confirm?.value
        if (
          !isRecord(request) ||
          (Object.getPrototypeOf(request) !== Object.prototype &&
            Object.getPrototypeOf(request) !== null) ||
          Reflect.ownKeys(request).length !== 3 ||
          !descriptors.masterPassword?.enumerable ||
          !('value' in descriptors.masterPassword) ||
          !descriptors.confirmation?.enumerable ||
          !('value' in descriptors.confirmation) ||
          !descriptors.confirm?.enumerable ||
          !('value' in descriptors.confirm) ||
          typeof masterPassword !== 'string' ||
          masterPassword.length === 0 ||
          masterPassword.length > MAX_SYNC_SECRET_LENGTH ||
          confirmation !== ACCOUNT_SESSION_DEAUTHORIZATION_CONFIRMATION ||
          confirm !== true
        ) {
          throw new VaultError('INVALID_INPUT')
        }

        const current = this.requireData()
        if (
          this.syncInProgress ||
          current.sync?.pendingLoginMutation ||
          current.sync?.pendingLoginImport ||
          current.sync?.pendingPersonalVaultPurge ||
          current.nativeAttachmentRestore ||
          current.masterPasswordChange ||
          this.activeAttachmentOperation ||
          this.activeAccountBreachOperation ||
          this.notificationTokenAborts.size > 0 ||
          this.accountSecurityAborts.size > 0 ||
          this.nativeAttachmentBackupAborts.size > 0 ||
          this.nativeAttachmentRestoreAborts.size > 0
        ) {
          throw new VaultError('SYNC_FAILED')
        }
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        if (!client.deauthorizeAllSessions || !client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        const abort = new AbortController()
        const originalState = client.exportState()
        const failClosed = cloneData(current)
        if (!failClosed.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
        failClosed.sync.state = {
          ...originalState,
          session: null,
          securityStamp: null
        }
        failClosed.updatedAt = this.nowIso()
        this.sessionDeauthorizationInProgress = true
        this.abortNotificationTokenLeases()
        try {
          await this.persist(failClosed)
        } catch {
          this.sessionDeauthorizationInProgress = false
          throw new VaultError('SYNC_FAILED')
        }
        this.data = failClosed
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          request: client.deauthorizeAllSessions.bind(client),
          abort,
          masterPassword,
          originalState
        }
      })
    } catch (error) {
      scrubAccountSessionDeauthorizationRequest(request)
      throw error
    }

    scrubAccountSessionDeauthorizationRequest(request)
    let operationError: unknown = null
    try {
      await lease.request(lease.masterPassword, lease.abort.signal)
    } catch (error) {
      operationError = error
    }

    try {
      return await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        try {
          const current = this.requireData()
          if (lease.abort.signal.aborted || lease.generation !== this.generation) {
            throw new VaultError('LOCKED')
          }
          if (this.syncClient !== lease.client) throw new VaultError('SYNC_AUTH_REQUIRED')

          if (operationError) {
            if (operationError instanceof BitwardenDirectError) {
              if (operationError.code === 'SESSION_DEAUTHORIZATION_UNKNOWN') {
                const state = lease.client.exportState()
                if (state.session || state.securityStamp !== null) {
                  throw new VaultError('SYNC_FAILED')
                }
                this.abortNotificationTokenLeases()
                this.syncLastError = null
                throw new VaultError('SESSION_DEAUTHORIZATION_UNKNOWN')
              }
            }
            if (operationError instanceof VaultError) throw operationError

            const restored = cloneData(current)
            if (!restored.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
            restored.sync.state = lease.originalState
            restored.updatedAt = this.nowIso()
            try {
              await this.persist(restored)
              this.data = restored
            } catch {
              this.syncClient = null
              await lease.client.logout().catch(() => undefined)
              throw new VaultError('SYNC_FAILED')
            }
            if (
              operationError instanceof BitwardenDirectError &&
              operationError.code === 'USER_VERIFICATION_FAILED'
            ) {
              throw new VaultError('INVALID_MASTER_PASSWORD')
            }
            throw this.mapSyncError(operationError)
          }

          const state = lease.client.exportState()
          if (state.session || state.securityStamp !== null) throw new VaultError('SYNC_FAILED')
          this.abortNotificationTokenLeases()
          this.syncLastError = null
          const sync = this.requireSyncData()
          return this.baseSyncStatus(sync, 'locked')
        } finally {
          this.sessionDeauthorizationInProgress = false
        }
      })
    } finally {
      scrubAccountSessionDeauthorizationRequest(request)
      lease.masterPassword = ''
    }
  }

  async resendAccountVerificationEmail(): Promise<void> {
    const lease = await this.exclusive(async () => {
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.resendVerificationEmail) throw new VaultError('SYNC_FAILED')
      const abort = new AbortController()
      this.accountSecurityAborts.add(abort)
      return {
        generation: this.generation,
        client,
        request: client.resendVerificationEmail.bind(client),
        abort
      }
    })
    try {
      await lease.request(lease.abort.signal)
      await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.persistCurrentClientState()
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    }
  }

  copyAccountApiClientId(): Promise<void> {
    return this.exclusive(async () => {
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const state = client.exportState()
      if (!state.session || !state.profileId) throw new VaultError('SYNC_AUTH_REQUIRED')
      await this.platform.copyText(`user.${state.profileId}`)
    })
  }

  async copyPersonalApiKey(request: {
    masterPassword: string
    rotate: boolean
    confirmRotation: boolean
  }): Promise<{ rotated: boolean; revisionDate: string }> {
    if (
      typeof request.masterPassword !== 'string' ||
      request.masterPassword.length === 0 ||
      request.masterPassword.length > MAX_PASSWORD_LENGTH ||
      typeof request.rotate !== 'boolean' ||
      typeof request.confirmRotation !== 'boolean' ||
      request.confirmRotation !== request.rotate
    ) {
      request.masterPassword = ''
      throw new VaultError('INVALID_INPUT')
    }
    const copySensitiveText = this.platform.copySensitiveText
    if (!copySensitiveText) {
      request.masterPassword = ''
      throw new VaultError('INTERNAL_ERROR')
    }
    let lease: {
      generation: number
      client: BitwardenSyncClient
      request: NonNullable<BitwardenSyncClient['getPersonalApiKey']>
      abort: AbortController
    }
    try {
      lease = await this.exclusive(async () => {
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        if (!client.getPersonalApiKey) throw new VaultError('SYNC_FAILED')
        const state = client.exportState()
        if (!state.session || !state.profileId) throw new VaultError('SYNC_AUTH_REQUIRED')
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          request: client.getPersonalApiKey.bind(client),
          abort
        }
      })
    } catch (error) {
      request.masterPassword = ''
      throw error
    }
    let result: Awaited<ReturnType<NonNullable<BitwardenSyncClient['getPersonalApiKey']>>> | null =
      null
    try {
      result = await lease.request(request.masterPassword, request.rotate, lease.abort.signal)
      return await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await copySensitiveText(result!.clientSecret, 30)
        await this.persistCurrentClientState().catch(() => undefined)
        return { rotated: request.rotate, revisionDate: result!.revisionDate }
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof BitwardenDirectError) {
          if (error.code === 'USER_VERIFICATION_FAILED') {
            throw new VaultError('INVALID_MASTER_PASSWORD')
          }
          if (error.code === 'API_KEY_ROTATION_UNKNOWN') {
            throw new VaultError('API_KEY_ROTATION_UNKNOWN')
          }
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    } finally {
      request.masterPassword = ''
      if (result) result.clientSecret = ''
    }
  }

  async getTwoFactorStatus(): Promise<{ type: number; enabled: boolean }[]> {
    const lease = await this.exclusive(async () => {
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.getTwoFactorProviders) throw new VaultError('SYNC_FAILED')
      const abort = new AbortController()
      this.accountSecurityAborts.add(abort)
      return {
        generation: this.generation,
        client,
        request: client.getTwoFactorProviders.bind(client),
        abort
      }
    })
    try {
      const providers = await lease.request(lease.abort.signal)
      return await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.persistCurrentClientState().catch(() => undefined)
        return providers.map((provider) => ({ ...provider }))
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    }
  }

  async disableTwoFactorProvider(request: {
    type: 0 | 1 | 2 | 3 | 7
    masterPassword: string
    confirm: true
  }): Promise<void> {
    if (
      !([0, 1, 2, 3, 7] as const).includes(request.type) ||
      request.confirm !== true ||
      typeof request.masterPassword !== 'string' ||
      request.masterPassword.length === 0 ||
      request.masterPassword.length > MAX_PASSWORD_LENGTH
    ) {
      request.masterPassword = ''
      throw new VaultError('INVALID_INPUT')
    }
    let lease: {
      generation: number
      client: BitwardenSyncClient
      request: NonNullable<BitwardenSyncClient['disableTwoFactorProvider']>
      abort: AbortController
    }
    try {
      lease = await this.exclusive(async () => {
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        if (!client.disableTwoFactorProvider || !client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          request: client.disableTwoFactorProvider.bind(client),
          abort
        }
      })
    } catch (error) {
      request.masterPassword = ''
      throw error
    }
    const mutation = { type: request.type, masterPassword: request.masterPassword }
    request.masterPassword = ''
    try {
      await lease.request(mutation.type, mutation.masterPassword, lease.abort.signal)
      await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.persistCurrentClientState().catch(() => undefined)
      })
    } catch (error) {
      await this.exclusive(async () => this.accountSecurityAborts.delete(lease.abort))
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
    } finally {
      request.masterPassword = ''
      mutation.type = -1 as 0 | 1 | 2 | 3 | 7
      mutation.masterPassword = ''
    }
  }

  async copyTwoFactorRecoveryCode(request: { masterPassword: string }): Promise<void> {
    if (
      typeof request.masterPassword !== 'string' ||
      request.masterPassword.length === 0 ||
      request.masterPassword.length > MAX_PASSWORD_LENGTH
    ) {
      request.masterPassword = ''
      throw new VaultError('INVALID_INPUT')
    }
    const copySensitiveText = this.platform.copySensitiveText
    if (!copySensitiveText) {
      request.masterPassword = ''
      throw new VaultError('INTERNAL_ERROR')
    }
    let lease: {
      generation: number
      client: BitwardenSyncClient
      request: NonNullable<BitwardenSyncClient['getTwoFactorRecoveryCode']>
      abort: AbortController
    }
    try {
      lease = await this.exclusive(async () => {
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        if (!client.getTwoFactorRecoveryCode) throw new VaultError('SYNC_FAILED')
        if (!client.exportState().session) throw new VaultError('SYNC_AUTH_REQUIRED')
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          request: client.getTwoFactorRecoveryCode.bind(client),
          abort
        }
      })
    } catch (error) {
      request.masterPassword = ''
      throw error
    }
    let code = ''
    try {
      code = await lease.request(request.masterPassword, lease.abort.signal)
      await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await copySensitiveText(code, 30)
        await this.persistCurrentClientState().catch(() => undefined)
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof BitwardenDirectError && error.code === 'USER_VERIFICATION_FAILED') {
          throw new VaultError('INVALID_MASTER_PASSWORD')
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    } finally {
      request.masterPassword = ''
      code = ''
    }
  }

  async beginAccountAuthenticatorSetup(request: { masterPassword: string }): Promise<{
    sessionId: string
    key: string
    requiresMasterPassword: boolean
    expiresAt: number
  }> {
    if (
      typeof request.masterPassword !== 'string' ||
      request.masterPassword.length === 0 ||
      request.masterPassword.length > MAX_PASSWORD_LENGTH
    ) {
      request.masterPassword = ''
      throw new VaultError('INVALID_INPUT')
    }
    let lease: {
      generation: number
      client: BitwardenSyncClient
      request: NonNullable<BitwardenSyncClient['beginAuthenticatorSetup']>
      abort: AbortController
    }
    try {
      lease = await this.exclusive(async () => {
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        if (!client.beginAuthenticatorSetup || !client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          request: client.beginAuthenticatorSetup.bind(client),
          abort
        }
      })
    } catch (error) {
      request.masterPassword = ''
      throw error
    }
    try {
      const setup = await lease.request(request.masterPassword, lease.abort.signal)
      return await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        if (setup.enabled || !/^[A-Z2-7]{32}$/.test(setup.key)) {
          throw new VaultError('INVALID_INPUT')
        }
        this.evictExpiredAuthenticatorSetupSessions()
        while (this.authenticatorSetupSessions.size >= MAX_AUTHENTICATOR_SETUP_SESSIONS) {
          const oldest = this.authenticatorSetupSessions.keys().next().value
          if (typeof oldest !== 'string') break
          this.deleteAuthenticatorSetupSession(oldest)
        }
        const sessionId = randomUUID()
        const expiresAt = this.now().getTime() + AUTHENTICATOR_SETUP_TTL_MS
        this.authenticatorSetupSessions.set(sessionId, {
          generation: lease.generation,
          client: lease.client,
          key: setup.key,
          verificationMode: setup.verificationMode,
          userVerificationToken: setup.userVerificationToken ?? null,
          expiresAt
        })
        await this.persistCurrentClientState().catch(() => undefined)
        return {
          sessionId,
          key: setup.key,
          requiresMasterPassword: setup.verificationMode === 'master-password',
          expiresAt
        }
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof BitwardenDirectError && error.code === 'USER_VERIFICATION_FAILED') {
          throw new VaultError('INVALID_MASTER_PASSWORD')
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    } finally {
      request.masterPassword = ''
    }
  }

  async copyAccountAuthenticatorKey(request: { sessionId: string }): Promise<void> {
    const copySensitiveText = this.platform.copySensitiveText
    if (!copySensitiveText) throw new VaultError('INTERNAL_ERROR')
    await this.exclusive(async () => {
      const session = this.requireAuthenticatorSetupSession(request.sessionId)
      await copySensitiveText(session.key, 30)
    })
  }

  async completeAccountAuthenticatorSetup(request: {
    sessionId: string
    token: string
    masterPassword?: string
  }): Promise<void> {
    if (!/^\d{6}$/.test(request.token)) {
      if (request.masterPassword !== undefined) request.masterPassword = ''
      throw new VaultError('INVALID_INPUT')
    }
    let lease: {
      generation: number
      client: BitwardenSyncClient
      request: NonNullable<BitwardenSyncClient['completeAuthenticatorSetup']>
      key: string
      verificationMode: 'server-token' | 'master-password'
      userVerificationToken: string | null
      abort: AbortController
    }
    try {
      lease = await this.exclusive(async () => {
        const session = this.requireAuthenticatorSetupSession(request.sessionId)
        if (!session.client.completeAuthenticatorSetup) throw new VaultError('SYNC_FAILED')
        if (session.verificationMode === 'server-token' && request.masterPassword !== undefined) {
          throw new VaultError('INVALID_INPUT')
        }
        if (
          session.verificationMode === 'master-password' &&
          (typeof request.masterPassword !== 'string' ||
            request.masterPassword.length === 0 ||
            request.masterPassword.length > MAX_PASSWORD_LENGTH)
        ) {
          throw new VaultError('INVALID_INPUT')
        }
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        const result = {
          generation: session.generation,
          client: session.client,
          request: session.client.completeAuthenticatorSetup.bind(session.client),
          key: session.key,
          verificationMode: session.verificationMode,
          userVerificationToken: session.userVerificationToken,
          abort
        }
        session.key = ''
        session.userVerificationToken = null
        this.authenticatorSetupSessions.delete(request.sessionId)
        return result
      })
    } catch (error) {
      request.token = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      throw error
    }
    const completion = {
      key: lease.key,
      token: request.token,
      verificationMode: lease.verificationMode,
      ...(lease.userVerificationToken
        ? { userVerificationToken: lease.userVerificationToken }
        : {}),
      ...(lease.verificationMode === 'master-password'
        ? { masterPassword: request.masterPassword }
        : {})
    }
    try {
      await lease.request(completion, lease.abort.signal)
      await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.persistCurrentClientState().catch(() => undefined)
      })
    } catch (error) {
      await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
      })
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
    } finally {
      request.token = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      completion.key = ''
      completion.token = ''
      if ('masterPassword' in completion) completion.masterPassword = ''
      if ('userVerificationToken' in completion) completion.userVerificationToken = ''
      lease.key = ''
      lease.userVerificationToken = null
    }
  }

  async beginAccountEmailTwoFactorSetup(request: { masterPassword: string }): Promise<{
    sessionId: string
    requiresMasterPassword: boolean
    expiresAt: number
  }> {
    if (
      typeof request.masterPassword !== 'string' ||
      request.masterPassword.length === 0 ||
      request.masterPassword.length > MAX_PASSWORD_LENGTH
    ) {
      request.masterPassword = ''
      throw new VaultError('INVALID_INPUT')
    }
    let lease: {
      generation: number
      client: BitwardenSyncClient
      request: NonNullable<BitwardenSyncClient['beginEmailTwoFactorSetup']>
      abort: AbortController
    }
    try {
      lease = await this.exclusive(async () => {
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        if (!client.beginEmailTwoFactorSetup || !client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          request: client.beginEmailTwoFactorSetup.bind(client),
          abort
        }
      })
    } catch (error) {
      request.masterPassword = ''
      throw error
    }
    try {
      const setup = await lease.request(request.masterPassword, lease.abort.signal)
      return await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        if (setup.enabled) throw new VaultError('INVALID_INPUT')
        this.evictExpiredEmailTwoFactorSetupSessions()
        while (this.emailTwoFactorSetupSessions.size >= MAX_EMAIL_TWO_FACTOR_SETUP_SESSIONS) {
          const oldest = this.emailTwoFactorSetupSessions.keys().next().value
          if (typeof oldest !== 'string') break
          this.deleteEmailTwoFactorSetupSession(oldest)
        }
        const sessionId = randomUUID()
        const expiresAt = this.now().getTime() + EMAIL_TWO_FACTOR_SETUP_TTL_MS
        this.emailTwoFactorSetupSessions.set(sessionId, {
          generation: lease.generation,
          client: lease.client,
          verificationMode: setup.verificationMode,
          userVerificationToken: setup.userVerificationToken ?? null,
          phase: 'ready-to-send',
          email: null,
          expiresAt
        })
        await this.persistCurrentClientState().catch(() => undefined)
        return {
          sessionId,
          requiresMasterPassword: setup.verificationMode === 'master-password',
          expiresAt
        }
      })
    } catch (error) {
      return this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        if (lease.abort.signal.aborted || lease.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof BitwardenDirectError && error.code === 'USER_VERIFICATION_FAILED') {
          throw new VaultError('INVALID_MASTER_PASSWORD')
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      })
    } finally {
      request.masterPassword = ''
    }
  }

  async sendAccountEmailTwoFactorSetup(request: {
    sessionId: string
    email: string
    masterPassword?: string
  }): Promise<void> {
    if (
      typeof request.email !== 'string' ||
      request.email.length === 0 ||
      request.email.length > 256 ||
      request.email.trim() !== request.email ||
      /[\0\r\n]/u.test(request.email) ||
      !/^[^\s@]+@[^\s@]+$/u.test(request.email)
    ) {
      request.email = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      throw new VaultError('INVALID_INPUT')
    }
    let lease: EmailTwoFactorSetupSession & {
      request: NonNullable<BitwardenSyncClient['sendEmailTwoFactorSetup']>
      abort: AbortController
      emailForSetup: string
    }
    try {
      lease = await this.exclusive(async () => {
        const session = this.requireEmailTwoFactorSetupSession(request.sessionId, 'ready-to-send')
        if (!session.client.sendEmailTwoFactorSetup) throw new VaultError('SYNC_FAILED')
        this.validateEmailTwoFactorSetupPassword(session, request.masterPassword)
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        const result = {
          ...session,
          request: session.client.sendEmailTwoFactorSetup.bind(session.client),
          abort,
          emailForSetup: request.email
        }
        this.deleteEmailTwoFactorSetupSession(request.sessionId)
        return result
      })
    } catch (error) {
      request.email = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      throw error
    }
    const mutation = {
      email: lease.emailForSetup,
      verificationMode: lease.verificationMode,
      ...(lease.userVerificationToken
        ? { userVerificationToken: lease.userVerificationToken }
        : {}),
      ...(lease.verificationMode === 'master-password'
        ? { masterPassword: request.masterPassword }
        : {})
    }
    try {
      await lease.request(mutation, lease.abort.signal)
      await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session ||
          lease.expiresAt <= this.now().getTime()
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        this.evictExpiredEmailTwoFactorSetupSessions()
        while (this.emailTwoFactorSetupSessions.size >= MAX_EMAIL_TWO_FACTOR_SETUP_SESSIONS) {
          const oldest = this.emailTwoFactorSetupSessions.keys().next().value
          if (typeof oldest !== 'string') break
          this.deleteEmailTwoFactorSetupSession(oldest)
        }
        this.emailTwoFactorSetupSessions.set(request.sessionId, {
          generation: lease.generation,
          client: lease.client,
          verificationMode: lease.verificationMode,
          userVerificationToken: lease.userVerificationToken,
          phase: 'awaiting-code',
          email: lease.emailForSetup,
          expiresAt: lease.expiresAt
        })
        await this.persistCurrentClientState().catch(() => undefined)
      })
    } catch (error) {
      await this.exclusive(async () => this.accountSecurityAborts.delete(lease.abort))
      this.throwEmailTwoFactorSetupError(error, lease)
    } finally {
      request.email = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      mutation.email = ''
      if ('masterPassword' in mutation) mutation.masterPassword = ''
      if ('userVerificationToken' in mutation) mutation.userVerificationToken = ''
      lease.emailForSetup = ''
      lease.userVerificationToken = null
    }
  }

  async completeAccountEmailTwoFactorSetup(request: {
    sessionId: string
    token: string
    masterPassword?: string
  }): Promise<void> {
    if (!/^\d{1,50}$/u.test(request.token)) {
      request.token = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      throw new VaultError('INVALID_INPUT')
    }
    let lease: EmailTwoFactorSetupSession & {
      request: NonNullable<BitwardenSyncClient['completeEmailTwoFactorSetup']>
      abort: AbortController
      emailForSetup: string
    }
    try {
      lease = await this.exclusive(async () => {
        const session = this.requireEmailTwoFactorSetupSession(request.sessionId, 'awaiting-code')
        if (!session.client.completeEmailTwoFactorSetup || !session.email) {
          throw new VaultError('SYNC_FAILED')
        }
        this.validateEmailTwoFactorSetupPassword(session, request.masterPassword)
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        const result = {
          ...session,
          request: session.client.completeEmailTwoFactorSetup.bind(session.client),
          abort,
          emailForSetup: session.email
        }
        this.deleteEmailTwoFactorSetupSession(request.sessionId)
        return result
      })
    } catch (error) {
      request.token = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      throw error
    }
    const mutation = {
      email: lease.emailForSetup,
      token: request.token,
      verificationMode: lease.verificationMode,
      ...(lease.userVerificationToken
        ? { userVerificationToken: lease.userVerificationToken }
        : {}),
      ...(lease.verificationMode === 'master-password'
        ? { masterPassword: request.masterPassword }
        : {})
    }
    try {
      await lease.request(mutation, lease.abort.signal)
      await this.exclusive(async () => {
        this.accountSecurityAborts.delete(lease.abort)
        this.requireData()
        if (
          lease.abort.signal.aborted ||
          lease.generation !== this.generation ||
          this.syncClient !== lease.client ||
          !lease.client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.persistCurrentClientState().catch(() => undefined)
      })
    } catch (error) {
      await this.exclusive(async () => this.accountSecurityAborts.delete(lease.abort))
      this.throwEmailTwoFactorSetupError(error, lease)
    } finally {
      request.token = ''
      if (request.masterPassword !== undefined) request.masterPassword = ''
      mutation.email = ''
      mutation.token = ''
      if ('masterPassword' in mutation) mutation.masterPassword = ''
      if ('userVerificationToken' in mutation) mutation.userVerificationToken = ''
      lease.emailForSetup = ''
      lease.userVerificationToken = null
    }
  }

  async listAccountWebAuthnKeys(request: {
    masterPassword: string
  }): Promise<{ id: number; name: string; migrated: boolean }[]> {
    let masterPassword = ''
    let setup: BitwardenWebAuthnRegistrationSetup | null = null
    let lease:
      | (AccountWebAuthnOperationLease & {
          begin: NonNullable<BitwardenSyncClient['beginWebAuthnSetup']>
        })
      | null = null
    try {
      masterPassword = normalizeSyncPassword(request.masterPassword)
      request.masterPassword = ''
      lease = await this.exclusive(async () => {
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        if (!client.beginWebAuthnSetup || !client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          abort,
          begin: client.beginWebAuthnSetup.bind(client)
        }
      })
      setup = await lease.begin(masterPassword, lease.abort.signal)
      masterPassword = ''
      const keys = setup.keys.map(({ id, name, migrated }) => ({ id, name, migrated }))
      await this.finishAccountWebAuthnOperation(lease, true)
      lease = null
      return keys
    } catch (error) {
      if (lease) {
        await this.releaseAccountWebAuthnOperation(lease)
        this.throwAccountWebAuthnOperationError(error, lease)
      }
      if (error instanceof VaultError) throw error
      throw this.mapSyncError(error)
    } finally {
      request.masterPassword = ''
      masterPassword = ''
      clearAccountWebAuthnRegistrationSetup(setup)
    }
  }

  async enrollAccountWebAuthnKey(request: { masterPassword: string; name: string }): Promise<void> {
    let masterPassword = ''
    let name = ''
    let setup: BitwardenWebAuthnRegistrationSetup | null = null
    let attestation: AccountWebAuthnAttestation | null = null
    let mutation: BitwardenWebAuthnRegistrationRequest | null = null
    let lease:
      | (AccountWebAuthnOperationLease & {
          webVaultUrl: string
          begin: NonNullable<BitwardenSyncClient['beginWebAuthnSetup']>
          complete: NonNullable<BitwardenSyncClient['completeWebAuthnSetup']>
          register: VaultAccountWebAuthnRegistrationRequester
        })
      | null = null
    try {
      masterPassword = normalizeSyncPassword(request.masterPassword)
      name = normalizeRequiredString(request.name, MAX_NAME_LENGTH)
      request.masterPassword = ''
      request.name = ''
      lease = await this.exclusive(async () => {
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        const register = this.requestAccountWebAuthnRegistration
        if (
          !client.beginWebAuthnSetup ||
          !client.completeWebAuthnSetup ||
          !client.exportState().session
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        if (!register) throw new VaultError('SYNC_FAILED')
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          abort,
          webVaultUrl: resolveBitwardenUrls(sync.serverUrl).webVaultUrl,
          begin: client.beginWebAuthnSetup.bind(client),
          complete: client.completeWebAuthnSetup.bind(client),
          register
        }
      })

      setup = await lease.begin(masterPassword, lease.abort.signal)
      await this.assertAccountWebAuthnOperationCurrent(lease)
      attestation = structuredClone(
        await lease.register({
          webVaultUrl: lease.webVaultUrl,
          challenge: setup.registrationChallenge,
          signal: lease.abort.signal
        })
      )
      await this.assertAccountWebAuthnOperationCurrent(lease)
      mutation = {
        id: setup.registrationId,
        name,
        attestation,
        verificationMode: setup.verificationMode,
        ...(setup.userVerificationToken
          ? { userVerificationToken: setup.userVerificationToken }
          : {}),
        ...(setup.verificationMode === 'master-password' ? { masterPassword } : {})
      }
      await lease.complete(mutation, lease.abort.signal)
      await this.finishAccountWebAuthnOperation(lease, true)
      lease = null
    } catch (error) {
      if (lease) {
        await this.releaseAccountWebAuthnOperation(lease)
        this.throwAccountWebAuthnOperationError(error, lease)
      }
      if (error instanceof VaultError) throw error
      throw this.mapSyncError(error)
    } finally {
      request.masterPassword = ''
      request.name = ''
      masterPassword = ''
      name = ''
      clearAccountWebAuthnRegistrationSetup(setup)
      clearAccountWebAuthnAttestation(attestation)
      if (mutation) {
        mutation.name = ''
        if (mutation.masterPassword !== undefined) mutation.masterPassword = ''
        if (mutation.userVerificationToken !== undefined) mutation.userVerificationToken = ''
      }
    }
  }

  async removeAccountWebAuthnKey(request: {
    id: number
    masterPassword: string
    confirm: true
  }): Promise<void> {
    let masterPassword = ''
    let id = 0
    let lease:
      | (AccountWebAuthnOperationLease & {
          remove: NonNullable<BitwardenSyncClient['deleteWebAuthnKey']>
        })
      | null = null
    try {
      if (!Number.isSafeInteger(request.id) || request.id < 1 || request.confirm !== true) {
        throw new VaultError('INVALID_INPUT')
      }
      id = request.id
      masterPassword = normalizeSyncPassword(request.masterPassword)
      request.masterPassword = ''
      lease = await this.exclusive(async () => {
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        if (!client.deleteWebAuthnKey || !client.exportState().session) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        const abort = new AbortController()
        this.accountSecurityAborts.add(abort)
        return {
          generation: this.generation,
          client,
          abort,
          remove: client.deleteWebAuthnKey.bind(client)
        }
      })
      await lease.remove(id, masterPassword, lease.abort.signal)
      await this.finishAccountWebAuthnOperation(lease, true)
      lease = null
    } catch (error) {
      if (lease) {
        await this.releaseAccountWebAuthnOperation(lease)
        this.throwAccountWebAuthnOperationError(error, lease)
      }
      if (error instanceof VaultError) throw error
      throw this.mapSyncError(error)
    } finally {
      request.masterPassword = ''
      id = 0
      masterPassword = ''
    }
  }

  /** Main-process-only notification credentials. Never expose this through IPC or renderer state. */
  async notificationConnectionInfo(): Promise<BitwardenNotificationConnectionInfo | null> {
    const lease = await this.exclusive(async () => {
      const sync = this.requireData().sync
      if (!sync) return null
      const client = this.getOrCreateSyncClient(sync)
      const status = await client.status()
      if (status.status !== 'unlocked') return null
      const state = client.exportState()
      const notificationAccessToken = client.notificationAccessToken?.bind(client)
      if (!state.session || !state.profileId || !notificationAccessToken) return null
      const abort = new AbortController()
      this.notificationTokenAborts.add(abort)
      return {
        client,
        notificationAccessToken,
        generation: this.generation,
        abort,
        notificationsUrl: resolveBitwardenUrls(sync.serverUrl).notificationsUrl,
        userId: state.profileId,
        deviceIdentifier: state.deviceIdentifier
      }
    })
    if (!lease) return null

    let accessToken: string
    try {
      accessToken = await lease.notificationAccessToken(lease.abort.signal)
    } catch {
      await this.exclusive(async () => {
        this.notificationTokenAborts.delete(lease.abort)
      })
      if (lease.abort.signal.aborted) return null
      throw new Error('NOTIFICATION_TOKEN_UNAVAILABLE')
    }

    return this.exclusive(async () => {
      this.notificationTokenAborts.delete(lease.abort)
      const current = this.requireData()
      if (
        lease.abort.signal.aborted ||
        lease.generation !== this.generation ||
        lease.client !== this.syncClient ||
        this.sessionDeauthorizationInProgress ||
        !current.sync
      ) {
        return null
      }
      const state = lease.client.exportState()
      if (
        !state.session ||
        state.session.accessToken !== accessToken ||
        state.profileId !== lease.userId
      ) {
        return null
      }
      if (JSON.stringify(state) !== JSON.stringify(current.sync.state)) {
        const next = cloneData(current)
        if (!next.sync) return null
        next.sync.state = state
        next.updatedAt = this.nowIso()
        await this.persist(next)
        this.data = next
      }
      return {
        notificationsUrl: lease.notificationsUrl,
        accessToken,
        userId: lease.userId,
        deviceIdentifier: lease.deviceIdentifier
      }
    })
  }

  /** Applies a trusted authenticated LogOut notification without deleting sync mappings. */
  remoteLogoutSync(): Promise<SyncStatus> {
    return this.exclusive(async () => {
      const current = this.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      this.invalidatePinUnlockCapability()
      this.syncAbort?.abort()
      this.abortNotificationTokenLeases()
      this.abortAccountSecurityRequests()
      this.abortNativeAttachmentBackups()
      this.abortNativeAttachmentRestores()
      this.activeAccountBreachOperation?.abort.abort()
      if (!current.sync) return { configured: false, state: 'unconfigured' }
      const client = this.syncClient
      this.syncClient = null
      this.syncLastError = null
      try {
        await client?.logout()
      } catch {
        // A server-directed logout is fail-closed locally even if connector cleanup fails.
      }
      const next = cloneData(current)
      if (!next.sync) return { configured: false, state: 'unconfigured' }
      next.sync.state = {
        ...(client?.exportState() ?? next.sync.state),
        session: null
      }
      next.updatedAt = this.nowIso()
      await this.persist(next)
      this.data = next
      return this.baseSyncStatus(next.sync, 'locked')
    })
  }

  connectSync(request: SyncConnectRequest): Promise<SyncResult> {
    this.invalidatePinUnlockCapability()
    return this.exclusive(async () => {
      const current = this.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      const serverUrl = this.normalizeSyncServerUrl(request.serverUrl)
      const email = normalizeRequiredString(request.email, MAX_USERNAME_LENGTH)
      const password = normalizeSyncPassword(request.masterPassword)
      const twoFactor = this.normalizeTwoFactor(request.twoFactorMethod, request.twoFactorCode)
      const newDeviceOtp = this.normalizeNewDeviceOtp(request.newDeviceOtp)
      const abort = this.startSyncOperation()

      try {
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
          lastSyncAt: null,
          folderMappings: [],
          loginMappings: [],
          folderTombstones: [],
          loginTombstones: [],
          pendingLoginMutation: null,
          pendingLoginImport: null,
          pendingPersonalVaultPurge: null,
          domainSettings: null
        }
        const client = this.createSyncClient(sync)
        await this.authenticateSyncWithWebAuthnRetry(
          (retryTwoFactor) =>
            client.login({
              email,
              password,
              twoFactor: retryTwoFactor,
              newDeviceOtp,
              signal: abort.signal
            }),
          twoFactor,
          request.webAuthnRemember,
          sync.serverUrl,
          abort.signal
        )
        const next = cloneData(current)
        sync.state = client.exportState()
        next.sync = sync
        next.updatedAt = this.nowIso()
        await this.persist(next)
        this.data = next
        this.syncClient = client
        return await this.performSync(next, client, abort.signal)
      } catch (error) {
        await this.persistCurrentClientState().catch(() => undefined)
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
    })
  }

  unlockSync(request: SyncUnlockRequest): Promise<SyncStatus> {
    return this.exclusive(async () => {
      const sync = this.requireSyncData()
      const password = normalizeSyncPassword(request.masterPassword)
      const twoFactor = this.normalizeTwoFactor(request.twoFactorMethod, request.twoFactorCode)
      const newDeviceOtp = this.normalizeNewDeviceOtp(request.newDeviceOtp)
      const client = this.getOrCreateSyncClient(sync)
      const abort = this.startSyncOperation()
      try {
        await this.authenticateSyncWithWebAuthnRetry(
          (retryTwoFactor) =>
            client.unlock({
              password,
              twoFactor: retryTwoFactor,
              newDeviceOtp,
              signal: abort.signal
            }),
          twoFactor,
          request.webAuthnRemember,
          sync.serverUrl,
          abort.signal
        )
        await this.persistCurrentClientState()
        this.syncLastError = null
        return this.baseSyncStatus(sync, 'ready')
      } catch (error) {
        await this.persistCurrentClientState().catch(() => undefined)
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
    })
  }

  async unlockSyncWithLocalPassword(masterPassword: string): Promise<SyncStatus> {
    const current = await this.syncStatus()
    if (!current.configured || current.state === 'ready') return current
    try {
      return await this.unlockSync({ masterPassword })
    } catch (error) {
      if (
        error instanceof VaultError &&
        (error.code === 'SYNC_AUTH_REQUIRED' || error.code === 'SYNC_NEW_DEVICE_REQUIRED')
      ) {
        return this.exclusive(async () => {
          this.syncLastError = null
          const sync = this.requireData().sync
          return sync
            ? this.baseSyncStatus(sync, 'locked')
            : { configured: false, state: 'unconfigured' }
        })
      }
      throw error
    }
  }

  syncNow(): Promise<SyncResult> {
    return this.exclusive(async () => {
      const data = this.requireData()
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const abort = this.startSyncOperation()
      try {
        return await this.performSync(data, client, abort.signal)
      } catch (error) {
        await this.persistCurrentClientState().catch(() => undefined)
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
    })
  }

  disconnectSync(): Promise<SyncStatus> {
    return this.exclusive(async () => {
      const current = this.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      this.invalidatePinUnlockCapability()
      this.syncAbort?.abort()
      this.abortNotificationTokenLeases()
      this.abortAccountSecurityRequests()
      this.abortNativeAttachmentBackups()
      this.abortNativeAttachmentRestores()
      this.activeAccountBreachOperation?.abort.abort()
      const next = cloneData(current)
      const client = this.syncClient
      this.syncClient = null
      this.syncLastError = null
      try {
        await client?.logout()
      } catch {
        // Clearing local sync configuration must work even when the server is offline.
      }
      next.sync = null
      next.updatedAt = this.nowIso()
      await this.persist(next)
      this.data = next
      return { configured: false, state: 'unconfigured' }
    })
  }

  resolvePendingLoginImport(request: {
    masterPassword: string
    confirmRetry: true
  }): Promise<SyncStatus> {
    return this.exclusive(async () => {
      if (request.confirmRetry !== true) throw new VaultError('INVALID_INPUT')
      await this.assertMasterPassword(request.masterPassword)
      const current = this.requireData()
      if (!current.sync?.pendingLoginImport) throw new VaultError('INVALID_INPUT')
      if (current.sync.pendingLoginImport.phase === 'prepared') {
        throw new VaultError('SYNC_FAILED')
      }
      const next = cloneData(current)
      if (!next.sync?.pendingLoginImport) throw new VaultError('SYNC_FAILED')
      next.sync.pendingLoginImport.phase = 'retry-approved'
      next.updatedAt = this.nowIso()
      await this.persist(next)
      this.data = next
      this.syncLastError = null
      return await this.currentSyncStatus(true)
    })
  }

  purgePersonalVault(
    request: SyncPurgePersonalVaultRequest
  ): Promise<SyncPurgePersonalVaultResult> {
    return this.exclusive(async () => {
      let abort: AbortController | undefined
      let didDispatch = false
      let original: VaultData | undefined
      let operationGeneration = -1
      try {
        if (
          !isRecord(request) ||
          (Object.getPrototypeOf(request) !== Object.prototype &&
            Object.getPrototypeOf(request) !== null) ||
          Reflect.ownKeys(request).length !== 3 ||
          !Object.hasOwn(request, 'masterPassword') ||
          !Object.hasOwn(request, 'confirmation') ||
          !Object.hasOwn(request, 'confirmPurge') ||
          typeof request.masterPassword !== 'string' ||
          request.masterPassword.length === 0 ||
          request.masterPassword.length > MAX_MASTER_PASSWORD_LENGTH ||
          request.confirmation !== 'PURGE' ||
          request.confirmPurge !== true
        ) {
          throw new VaultError('INVALID_INPUT')
        }

        const current = this.requireData()
        operationGeneration = this.generation
        original = cloneData(current)
        if (
          current.sync?.pendingLoginMutation ||
          current.sync?.pendingLoginImport ||
          current.nativeAttachmentRestore ||
          current.masterPasswordChange ||
          this.activeAttachmentOperation ||
          this.nativeAttachmentBackupAborts.size > 0 ||
          this.nativeAttachmentRestoreAborts.size > 0
        ) {
          throw new VaultError('SYNC_FAILED')
        }
        const sync = this.requireSyncData()
        const client = this.getOrCreateSyncClient(sync)
        if (!client.purgePersonalVault) throw new VaultError('SYNC_FAILED')
        const remoteStatus = await client.status()
        if (remoteStatus.status !== 'unlocked') throw new VaultError('SYNC_AUTH_REQUIRED')

        // A prepared record proves the request was never durably marked as dispatched. It is safe
        // to discard before this separately authorized attempt. A dispatched record is retried only
        // here, never by ordinary synchronization.
        if (current.sync?.pendingPersonalVaultPurge?.phase === 'prepared') {
          const cleared = cloneData(current)
          if (!cleared.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
          cleared.sync.pendingPersonalVaultPurge = null
          cleared.updatedAt = this.nowIso()
          await this.persist(cleared)
          this.data = cleared
          original = cloneData(cleared)
        }

        const active = this.requireData()
        const retryingDispatched = active.sync?.pendingPersonalVaultPurge?.phase === 'dispatched'
        if (retryingDispatched) {
          // Never downgrade an earlier unknown outcome to prepared: a crash at that point would
          // make unlock recovery erase the only durable evidence that a purge may have run.
          didDispatch = true
        } else {
          const startedAt = this.nowIso()
          const prepared = cloneData(active)
          if (!prepared.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
          prepared.sync.pendingPersonalVaultPurge = {
            phase: 'prepared',
            startedAt,
            remainingItems: active.logins.length,
            remainingFolders: active.folders.length
          }
          prepared.updatedAt = this.nowIso()
          await this.persist(prepared)
          this.data = prepared

          const dispatched = cloneData(prepared)
          if (!dispatched.sync?.pendingPersonalVaultPurge) throw new VaultError('SYNC_FAILED')
          dispatched.sync.pendingPersonalVaultPurge.phase = 'dispatched'
          dispatched.updatedAt = this.nowIso()
          try {
            await this.persist(dispatched)
            this.data = dispatched
          } catch (error) {
            await this.restorePreDispatchPurge(original).catch(() => undefined)
            throw error
          }
          didDispatch = true
        }
        abort = this.startSyncOperation()

        let remoteError: unknown
        try {
          await client.purgePersonalVault(request.masterPassword, abort.signal)
        } catch (error) {
          remoteError = error
        }
        if (abort.signal.aborted || operationGeneration !== this.generation) {
          // Locking wins over a potentially slow reconciliation. The dispatched journal remains
          // durable, so the next explicitly unlocked generic sync can reconcile without replaying.
          throw new VaultError('LOCKED')
        }
        if (
          remoteError instanceof BitwardenDirectError &&
          remoteError.code === 'USER_VERIFICATION_FAILED'
        ) {
          await this.restorePreDispatchPurge(original)
          throw new VaultError('INVALID_MASTER_PASSWORD')
        }

        const reconciled = await this.reconcilePersonalVaultPurge(client)
        if (reconciled.status === 'complete') return reconciled
        // A dispatched failure is intentionally surfaced as pending after an authoritative read.
        // The caller may start one fresh, explicitly confirmed attempt; generic sync never replays.
        return reconciled
      } catch (error) {
        if (!didDispatch && original) {
          await this.restorePreDispatchPurge(original).catch(() => undefined)
        }
        if (error instanceof VaultError) throw error
        throw this.mapSyncError(error)
      } finally {
        if (abort) this.finishSyncOperation(abort)
        try {
          request.masterPassword = ''
          request.confirmation = '' as 'PURGE'
        } catch {
          // Validation rejects frozen/exotic inputs; never replace the intended service error.
        }
      }
    })
  }

  getEquivalentDomainSettings(): Promise<EquivalentDomainSettingsView> {
    return this.exclusive(async () => {
      const current = this.requireData()
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const abort = this.startSyncOperation()
      try {
        const settings = validateRemoteEquivalentDomainSettings(
          await client.getEquivalentDomainSettings(abort.signal)
        )
        if (abort.signal.aborted) throw new BitwardenDirectError('ABORTED')
        const next = cloneData(current)
        if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
        next.sync.domainSettings = cloneEquivalentDomainSettings(settings)
        next.sync.state = client.exportState()
        next.updatedAt = this.nowIso()
        await this.persist(next)
        if (abort.signal.aborted) throw new BitwardenDirectError('ABORTED')
        this.data = next
        this.syncLastError = null
        return equivalentDomainSettingsView(settings)
      } catch (error) {
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
    })
  }

  updateEquivalentDomainSettings(
    request: EquivalentDomainSettingsUpdate
  ): Promise<EquivalentDomainSettingsView> {
    return this.exclusive(async () => {
      if (!/^[0-9a-f]{64}$/u.test(request.expectedRevision)) {
        throw new VaultError('INVALID_INPUT')
      }
      const update = normalizeEquivalentDomainUpdate(request)
      const current = this.requireData()
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const abort = this.startSyncOperation()
      try {
        const serverSettings = validateRemoteEquivalentDomainSettings(
          await client.getEquivalentDomainSettings(abort.signal)
        )
        if (equivalentDomainRevision(serverSettings) !== request.expectedRevision) {
          throw new VaultError('SYNC_CONFLICT')
        }
        const globalTypes = new Set(serverSettings.globalEquivalentDomains.map(({ type }) => type))
        if (update.excludedGlobalEquivalentDomains.some((type) => !globalTypes.has(type))) {
          throw new VaultError('INVALID_INPUT')
        }
        await client.updateEquivalentDomainSettings(update, abort.signal)
        const confirmed = validateRemoteEquivalentDomainSettings(
          await client.getEquivalentDomainSettings(abort.signal)
        )
        if (abort.signal.aborted) throw new BitwardenDirectError('ABORTED')
        const next = cloneData(current)
        if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
        next.sync.domainSettings = cloneEquivalentDomainSettings(confirmed)
        next.sync.state = client.exportState()
        next.updatedAt = this.nowIso()
        await this.persist(next)
        if (abort.signal.aborted) throw new BitwardenDirectError('ABORTED')
        this.data = next
        this.syncLastError = null
        return equivalentDomainSettingsView(confirmed)
      } catch (error) {
        if (error instanceof BitwardenDirectError && error.code === 'NOT_FOUND') {
          throw new VaultError('NOT_FOUND')
        }
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
    })
  }

  listSends(): Promise<SendView[]> {
    return this.sendService.list()
  }

  createSend(request: SendCreateRequest): Promise<SendView> {
    return this.sendService.create(request)
  }

  async createFileSend(request: SendFileCreateRequest): Promise<SendFileCreateResult> {
    return this.sendService.createFile(request)
  }

  async downloadFileSend(request: SendFileDownloadRequest): Promise<SendFileDownloadResult> {
    return this.sendService.downloadFile(request)
  }

  updateSend(request: SendUpdateRequest): Promise<SendView> {
    return this.sendService.update(request)
  }

  removeSendPassword(request: SendIdRequest): Promise<SendView> {
    return this.sendService.removePassword(request)
  }

  deleteSend(request: SendIdRequest): Promise<void> {
    return this.sendService.delete(request)
  }

  copySendLink(request: SendIdRequest): Promise<void> {
    return this.sendService.copyLink(request)
  }

  listFolders(): Promise<FolderView[]> {
    return this.exclusive(async () =>
      this.requireData()
        .folders.map((folder) => ({ ...folder }))
        .sort((left, right) => left.position - right.position || compareText(left.name, right.name))
    )
  }

  createFolder(request: FolderCreateRequest): Promise<FolderView> {
    return this.mutate((data, now) => {
      const name = normalizeRequiredString(request.name, MAX_NAME_LENGTH)
      this.assertUniqueFolderName(data, name)
      const folder: FolderView = {
        id: this.validatedNewId(),
        name,
        position: data.folders.length,
        createdAt: now,
        updatedAt: now
      }
      data.folders.push(folder)
      return { ...folder }
    })
  }

  updateFolder(request: FolderUpdateRequest): Promise<FolderView> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const folder = this.findFolder(data, request.id)
      const name = normalizeRequiredString(request.name, MAX_NAME_LENGTH)
      this.assertUniqueFolderName(data, name, folder.id)
      folder.name = name
      folder.updatedAt = now
      return { ...folder }
    })
  }

  deleteFolder(request: FolderDeleteRequest): Promise<void> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      this.findFolder(data, request.id)
      recordSyncDeletion(data.sync, 'folder', request.id)
      data.folders = data.folders
        .filter((folder) => folder.id !== request.id)
        .sort((left, right) => left.position - right.position)
        .map((folder, position) => ({ ...folder, position }))
      data.logins.forEach((login) => {
        if (login.folderId === request.id) {
          login.folderId = null
          login.updatedAt = now
        }
      })
    })
  }

  reorderFolders(request: FolderReorderRequest): Promise<FolderView[]> {
    return this.mutate((data, now) => {
      if (!Array.isArray(request.orderedIds) || request.orderedIds.length !== data.folders.length) {
        throw new VaultError('INVALID_INPUT')
      }
      request.orderedIds.forEach(assertUuid)
      const uniqueIds = new Set(request.orderedIds)
      if (
        uniqueIds.size !== data.folders.length ||
        data.folders.some((folder) => !uniqueIds.has(folder.id))
      ) {
        throw new VaultError('INVALID_INPUT')
      }

      const foldersById = new Map(data.folders.map((folder) => [folder.id, folder]))
      data.folders = request.orderedIds.map((id, position) => ({
        ...foldersById.get(id)!,
        position,
        updatedAt: now
      }))
      return data.folders.map((folder) => ({ ...folder }))
    })
  }

  /**
   * Runs password-health analysis under the vault mutex. Raw password material is adapted only
   * for unprotected active logins and never leaves this method.
   */
  getHealthReport(): Promise<VaultHealthReport> {
    return this.exclusive(async () => {
      const data = this.requireData()
      const summaryById = new Map<string, { id: string; name: string; subtitle: string }>()
      const candidates: VaultHealthItem[] = []

      for (const login of data.logins) {
        // Archive and trash are not current credentials. Filter before building any core input.
        if (login.type !== 'login' || login.deletedAt !== null || login.archivedAt !== null)
          continue

        if (login.reprompt === 1) {
          // Do not even read protected password or username fields at this boundary.
          candidates.push({
            id: login.id,
            type: login.type,
            name: login.name,
            reprompt: 1
          })
          continue
        }

        // Health findings never need a URI. Avoid `toSummary`, whose fallback subtitle may contain
        // a complete URI including a private path or query when the username is empty.
        summaryById.set(login.id, { id: login.id, name: login.name, subtitle: login.username })
        candidates.push({
          id: login.id,
          type: login.type,
          name: login.name,
          password: login.password,
          username: login.username,
          uris: login.uris.map(({ uri }) => ({ uri })),
          reprompt: 0
        })
      }

      const analysis = analyzeVaultHealth(candidates)
      const weakPasswords = analysis.weakPasswords.flatMap((finding) => {
        const summary = summaryById.get(finding.id)
        return summary
          ? [
              {
                id: summary.id,
                name: summary.name,
                subtitle: summary.subtitle,
                score: finding.score
              }
            ]
          : []
      })
      const reusedPasswords = analysis.reusedPasswords.flatMap((finding) => {
        const summary = summaryById.get(finding.id)
        return summary
          ? [
              {
                id: summary.id,
                name: summary.name,
                subtitle: summary.subtitle,
                reuseCount: finding.reuseCount
              }
            ]
          : []
      })
      const unsecuredWebsites = analysis.unsecuredWebsites.map(({ id, name }) => ({ id, name }))

      return {
        generatedAt: this.nowIso(),
        totals: {
          analyzedCount: analysis.analyzedCount,
          weakPasswordCount: weakPasswords.length,
          reusedPasswordCount: reusedPasswords.length,
          unsecuredWebsiteCount: unsecuredWebsites.length,
          protectedSkippedCount: analysis.protectedSkippedCount
        },
        weakPasswords,
        reusedPasswords,
        unsecuredWebsites
      }
    })
  }

  /**
   * Adapts personal login metadata to the main-only inactive-2FA core under one unlocked epoch.
   * Secret fields and organization-owned items never cross this boundary.
   */
  getInactiveTwoFactorReport(dataset: TwoFactorDirectoryDataset): Promise<InactiveTwoFactorReport> {
    return this.exclusive(async () => {
      const generation = this.generation
      const data = this.requireData()
      const inputs: InactiveTwoFactorInput[] = []

      for (const login of data.logins) {
        if (login.type !== 'login') continue
        const hasTotp = Boolean(login.totp)
        const isDeleted = login.deletedAt !== null
        const isArchived = login.archivedAt !== null
        inputs.push({
          id: login.id,
          name: login.name,
          hasTotp,
          isDeleted,
          isArchived,
          // Avoid reading even URI metadata for lifecycle/TOTP exclusions.
          uris: hasTotp || isDeleted || isArchived ? [] : login.uris.map(({ uri }) => uri)
        })
      }

      const report = analyzeInactiveTwoFactor(inputs, dataset)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      return report
    })
  }

  /**
   * Runs an explicit HIBP Pwned Passwords check without holding the vault mutex during network
   * I/O. Only SHA-1 range material leaves the initial snapshot, and only five-character prefixes
   * are sent to HIBP by the fixed-origin client.
   */
  async getExposedPasswordReport(): Promise<VaultHealthExposedReport> {
    const snapshot = await this.exclusive(async () => this.captureExposedPasswordSnapshot())
    const active = this.activeExposedPasswordOperation
    if (
      active &&
      !active.abort.signal.aborted &&
      active.generation === snapshot.generation &&
      active.revision === snapshot.revision
    ) {
      snapshot.hashes.fill('')
      return active.promise
    }

    active?.abort.abort()
    const abort = new AbortController()
    const client = new PwnedPasswordsClient({ fetch: this.fetch })
    const promise = this.resolveExposedPasswordSnapshot(snapshot, client, abort.signal).finally(
      () => {
        snapshot.hashes.fill('')
        if (this.activeExposedPasswordOperation?.promise === promise) {
          this.activeExposedPasswordOperation = null
        }
      }
    )
    this.activeExposedPasswordOperation = {
      generation: snapshot.generation,
      revision: snapshot.revision,
      abort,
      promise
    }
    return promise
  }

  cancelExposedPasswordReport(): boolean {
    const active = this.activeExposedPasswordOperation
    if (!active || active.abort.signal.aborted) return false
    active.abort.abort()
    return true
  }

  /**
   * Queries the configured Vaultwarden HIBP proxy without holding the vault mutex during network
   * I/O. Unlike the password range report, this explicitly discloses the complete address through
   * the configured server, so callers must only invoke it after a user action.
   */
  async getAccountBreachReport(
    request: VaultHealthAccountBreachRequest
  ): Promise<VaultHealthAccountBreachReport> {
    const snapshot = await this.exclusive(async () => {
      const email = this.normalizeAccountBreachEmail(request.email)
      const sync = this.requireSyncData()
      return {
        generation: this.generation,
        email,
        client: this.getOrCreateSyncClient(sync)
      }
    })
    const active = this.activeAccountBreachOperation
    if (
      active &&
      !active.abort.signal.aborted &&
      active.generation === snapshot.generation &&
      active.email === snapshot.email &&
      active.client === snapshot.client
    ) {
      return active.promise
    }

    active?.abort.abort()
    const abort = new AbortController()
    const promise = this.resolveAccountBreachReport(
      snapshot.generation,
      snapshot.client,
      snapshot.email,
      abort.signal
    ).finally(() => {
      if (this.activeAccountBreachOperation?.promise === promise) {
        this.activeAccountBreachOperation = null
      }
    })
    this.activeAccountBreachOperation = { ...snapshot, abort, promise }
    return promise
  }

  cancelAccountBreachReport(): boolean {
    const active = this.activeAccountBreachOperation
    if (!active || active.abort.signal.aborted) return false
    active.abort.abort()
    return true
  }

  async openHibpWebsite(): Promise<void> {
    await this.exclusive(async () => this.requireData())
    await this.platform.openExternal('https://haveibeenpwned.com/')
  }

  private normalizeAccountBreachEmail(value: unknown): string {
    const email = normalizeRequiredString(value, 254).toLowerCase()
    const firstAt = email.indexOf('@')
    if (
      /\s/u.test(email) ||
      firstAt <= 0 ||
      firstAt !== email.lastIndexOf('@') ||
      firstAt === email.length - 1
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    return email
  }

  private async resolveAccountBreachReport(
    generation: number,
    client: BitwardenSyncClient,
    email: string,
    signal: AbortSignal
  ): Promise<VaultHealthAccountBreachReport> {
    let report: Awaited<ReturnType<BitwardenSyncClient['getAccountBreachReport']>>
    try {
      report = await client.getAccountBreachReport(email, signal)
    } catch (error) {
      return this.exclusive(async () => {
        this.requireData()
        if (generation !== this.generation) throw new VaultError('LOCKED')
        if (this.syncClient !== client || !this.requireData().sync) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        if (error instanceof BitwardenDirectError && error.code === 'AUTH_REQUIRED') {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        throw new VaultError('HEALTH_CHECK_FAILED')
      })
    }

    return this.exclusive(async () => {
      this.requireData()
      if (generation !== this.generation) throw new VaultError('LOCKED')
      if (this.syncClient !== client || !this.requireData().sync) {
        throw new VaultError('SYNC_AUTH_REQUIRED')
      }
      if (report.status === 'unavailable') {
        return {
          generatedAt: this.nowIso(),
          status: 'unavailable',
          reason: report.reason,
          breaches: []
        }
      }
      return {
        generatedAt: this.nowIso(),
        status: 'complete',
        breaches: report.breaches.map((breach) => ({
          name: breach.name,
          title: breach.title,
          domain: breach.domain,
          breachDate: breach.breachDate,
          addedDate: breach.addedDate,
          pwnCount: breach.pwnCount,
          dataClasses: [...breach.dataClasses],
          isVerified: breach.isVerified
        }))
      }
    })
  }

  private captureExposedPasswordSnapshot(): ExposedPasswordSnapshot {
    const data = this.requireData()
    const passwords: string[] = []
    const candidates: ExposedPasswordSnapshot['candidates'][number][] = []
    let protectedSkippedCount = 0

    for (const login of data.logins) {
      if (login.type !== 'login' || login.deletedAt !== null || login.archivedAt !== null) continue
      if (login.reprompt === 1) {
        // A protected item's password and username are outside this report's read boundary.
        protectedSkippedCount += 1
        continue
      }
      if (!login.password) continue

      const summary = toSummary(login)
      candidates.push({ id: summary.id, name: summary.name, subtitle: summary.subtitle })
      passwords.push(login.password)
    }

    try {
      const hashes = hashPasswordsForPwnedLookup(passwords)
      const revisionHash = createHash('sha256')
      revisionHash.update(String(protectedSkippedCount), 'utf8')
      for (let index = 0; index < candidates.length; index += 1) {
        const candidate = candidates[index]!
        for (const value of [candidate.id, candidate.name, candidate.subtitle, hashes[index]!]) {
          revisionHash.update(String(Buffer.byteLength(value, 'utf8')), 'utf8')
          revisionHash.update(':', 'utf8')
          revisionHash.update(value, 'utf8')
          revisionHash.update(';', 'utf8')
        }
      }
      return {
        generation: this.generation,
        revision: revisionHash.digest('hex'),
        candidates,
        hashes,
        protectedSkippedCount
      }
    } catch {
      throw new VaultError('HEALTH_CHECK_FAILED')
    } finally {
      passwords.fill('')
    }
  }

  private async resolveExposedPasswordSnapshot(
    snapshot: ExposedPasswordSnapshot,
    client: PwnedPasswordsClient,
    signal: AbortSignal
  ): Promise<VaultHealthExposedReport> {
    let counts: number[]
    try {
      counts = await client.lookupSha1Hashes(snapshot.hashes, signal)
    } catch {
      return this.exclusive(async () => {
        this.requireData()
        if (snapshot.generation !== this.generation) throw new VaultError('LOCKED')
        throw new VaultError('HEALTH_CHECK_FAILED')
      })
    }

    return this.exclusive(async () => {
      this.requireData()
      if (snapshot.generation !== this.generation) throw new VaultError('LOCKED')
      const currentSnapshot = this.captureExposedPasswordSnapshot()
      try {
        if (currentSnapshot.revision !== snapshot.revision) {
          throw new VaultError('HEALTH_CHECK_FAILED')
        }
      } finally {
        currentSnapshot.hashes.fill('')
      }

      const exposedPasswords = snapshot.candidates
        .flatMap((candidate, index) => {
          const exposedCount = counts[index] ?? 0
          return exposedCount > 0 ? [{ ...candidate, exposedCount }] : []
        })
        .sort((first, second) => second.exposedCount - first.exposedCount)

      return {
        generatedAt: this.nowIso(),
        totals: {
          analyzedCount: snapshot.candidates.length,
          exposedPasswordCount: exposedPasswords.length,
          protectedSkippedCount: snapshot.protectedSkippedCount
        },
        exposedPasswords
      }
    })
  }

  listLogins(request: LoginListRequest = {}): Promise<LoginSummary[]> {
    return this.exclusive(async () => {
      const data = this.requireData()
      const sort = request.sort ?? 'recent'
      if (sort !== 'recent' && sort !== 'name' && sort !== 'frequency') {
        throw new VaultError('INVALID_INPUT')
      }
      if (
        request.query !== undefined &&
        (typeof request.query !== 'string' || request.query.length > MAX_LOGIN_SEARCH_QUERY_LENGTH)
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      if (request.deleted !== undefined && typeof request.deleted !== 'boolean') {
        throw new VaultError('INVALID_INPUT')
      }
      if (request.archived !== undefined && typeof request.archived !== 'boolean') {
        throw new VaultError('INVALID_INPUT')
      }
      if (request.deleted === true && request.archived === true)
        throw new VaultError('INVALID_INPUT')
      if (request.folderId !== undefined && request.folderId !== null) {
        assertUuid(request.folderId)
        this.findFolder(data, request.folderId)
      }

      const scoped = data.logins.filter(
        (login) =>
          (request.deleted === true
            ? login.deletedAt !== null
            : request.archived === true
              ? login.deletedAt === null && login.archivedAt !== null
              : login.deletedAt === null && login.archivedAt === null) &&
          (request.folderId === undefined || login.folderId === request.folderId)
      )
      const filtered =
        request.query === undefined
          ? scoped
          : (() => {
              const matchingIds = new Set(
                searchVaultItems(scoped.map(toVaultSearchItem), request.query).map(
                  (searchable) => searchable.id
                )
              )
              return scoped.filter((login) => matchingIds.has(login.id))
            })()
      return filtered.map(toSummary).sort((left, right) => {
        if (sort === 'frequency' && left.usageCount !== right.usageCount) {
          return right.usageCount - left.usageCount
        }
        if (sort === 'recent' || sort === 'frequency') {
          if (left.lastUsedAt && right.lastUsedAt && left.lastUsedAt !== right.lastUsedAt) {
            return right.lastUsedAt.localeCompare(left.lastUsedAt)
          }
          if (left.lastUsedAt && !right.lastUsedAt) return -1
          if (!left.lastUsedAt && right.lastUsedAt) return 1
        }
        return compareText(left.name, right.name) || left.id.localeCompare(right.id)
      })
    })
  }

  listOrganizations(): Promise<OrganizationView[]> {
    return this.exclusive(async () => {
      const data = this.requireData()
      return data.organizations.map((organization) => ({ ...organization }))
    })
  }

  listCollections(organizationId?: string): Promise<CollectionView[]> {
    return this.exclusive(async () => {
      const data = this.requireData()
      if (organizationId !== undefined) assertUuid(organizationId)
      return data.collections
        .filter(
          (collection) =>
            organizationId === undefined || collection.organizationId === organizationId
        )
        .map((collection) => ({ ...collection }))
    })
  }

  listSharedLogins(request: SharedLoginListRequest = {}): Promise<SharedLoginSummary[]> {
    return this.exclusive(async () => {
      const data = this.requireData()
      if (
        request.sort !== undefined &&
        request.sort !== 'recent' &&
        request.sort !== 'name' &&
        request.sort !== 'frequency'
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      if (
        request.query !== undefined &&
        (typeof request.query !== 'string' || request.query.length > MAX_LOGIN_SEARCH_QUERY_LENGTH)
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      if (request.organizationId !== undefined) assertUuid(request.organizationId)
      if (request.collectionId !== undefined) assertUuid(request.collectionId)
      const scoped = data.sharedLogins.filter(
        (login) =>
          login.deletedAt === null &&
          login.archivedAt === null &&
          (request.organizationId === undefined ||
            login.organizationId === request.organizationId) &&
          (request.collectionId === undefined || login.collectionIds.includes(request.collectionId))
      )
      const filtered =
        request.query === undefined
          ? scoped
          : (() => {
              const matchingIds = new Set(
                searchVaultItems(scoped.map(toVaultSearchItem), request.query).map(
                  (searchable) => searchable.id
                )
              )
              return scoped.filter((login) => matchingIds.has(login.id))
            })()
      return filtered.map(toSharedSummary).sort((left, right) => {
        if (request.sort === 'frequency' && left.usageCount !== right.usageCount) {
          return right.usageCount - left.usageCount
        }
        return request.sort === 'name' || request.sort === 'frequency'
          ? compareText(left.name, right.name) || left.id.localeCompare(right.id)
          : right.updatedAt.localeCompare(left.updatedAt) || left.id.localeCompare(right.id)
      })
    })
  }

  getSharedLogin(request: LoginIdRequest): Promise<SharedLoginView> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.requireData().sharedLogins.find((candidate) => candidate.id === request.id)
      if (!login || login.deletedAt !== null || login.archivedAt !== null) {
        throw new VaultError('NOT_FOUND')
      }
      return toSharedView(login)
    })
  }

  listEmergencyAccess(): Promise<EmergencyAccessView[]> {
    return this.exclusive(async () => {
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.listEmergencyAccess) return []
      try {
        const entries = await client.listEmergencyAccess()
        return entries.map(emergencyAccessViewFromRemote)
      } catch (error) {
        throw this.mapSyncError(error)
      }
    })
  }

  getLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      this.assertActiveLogin(login)
      return toView(login)
    })
  }

  /**
   * Hydrates one viewport from a synchronous committed snapshot. Protected and inactive items
   * are omitted so speculative reads never cross a reprompt boundary.
   */
  async prefetchLogins(request: LoginPrefetchRequest): Promise<LoginView[]> {
    if (
      !Array.isArray(request.ids) ||
      request.ids.length === 0 ||
      request.ids.length > MAX_LOGIN_PREFETCH_IDS ||
      new Set(request.ids).size !== request.ids.length
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    request.ids.forEach(assertUuid)
    // Writers clone, persist, then atomically replace this.data. This synchronous projection can
    // therefore read the last committed snapshot without waiting behind network-bound sync work.
    const loginsById = new Map(this.requireFastReadData().logins.map((login) => [login.id, login]))
    return request.ids.flatMap((id) => {
      const login = loginsById.get(id)
      return login && login.deletedAt === null && login.archivedAt === null && login.reprompt === 0
        ? [toView(login)]
        : []
    })
  }

  async getPasswordHistory(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<VaultPasswordHistoryEntry[]> {
    const login = this.passwordHistoryLogin(request, validateAuthorization)
    return clonePasswordHistory(login.passwordHistory)
  }

  async getPasswordHistoryView(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<VaultPasswordHistoryView> {
    const login = this.passwordHistoryLogin(request, validateAuthorization)
    return {
      expectedUpdatedAt: login.updatedAt,
      entries: login.passwordHistory.map(({ lastUsedDate }) => ({ lastUsedDate }))
    }
  }

  async revealPasswordHistory(
    request: PasswordHistoryEntryRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<string> {
    return this.passwordHistoryEntry(request, validateAuthorization).password
  }

  async copyPasswordHistory(
    request: PasswordHistoryEntryRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<void> {
    const entry = this.passwordHistoryEntry(request, validateAuthorization)
    await this.platform.copyText(entry.password)
  }

  private passwordHistoryLogin(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): StoredLogin {
    assertUuid(request.id)
    // History is cloned synchronously from the last committed snapshot so a background sync
    // cannot leave the explicit reveal action waiting behind network I/O. Lock starts by
    // blocking fast reads, and authorization is validated before this turn can yield.
    const login = this.findLogin(this.requireFastReadData(), request.id)
    if (
      (login.reprompt === 1 || login.deletedAt !== null) &&
      !validateAuthorization?.([login.id], { generation: this.generation })
    ) {
      throw new VaultError('REPROMPT_REQUIRED')
    }
    return login
  }

  private passwordHistoryEntry(
    request: PasswordHistoryEntryRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): VaultPasswordHistoryEntry {
    if (
      !Number.isSafeInteger(request.index) ||
      request.index < 0 ||
      request.index >= MAX_PASSWORD_HISTORY ||
      typeof request.lastUsedDate !== 'string' ||
      !Number.isFinite(Date.parse(request.lastUsedDate)) ||
      typeof request.expectedUpdatedAt !== 'string' ||
      !Number.isFinite(Date.parse(request.expectedUpdatedAt))
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    const login = this.passwordHistoryLogin(request, validateAuthorization)
    if (login.updatedAt !== request.expectedUpdatedAt) throw new VaultError('INVALID_INPUT')
    const entry = login.passwordHistory[request.index]
    if (!entry || entry.lastUsedDate !== request.lastUsedDate) {
      throw new VaultError('INVALID_INPUT')
    }
    return entry
  }

  restorePasswordHistory(request: PasswordHistoryRestoreRequest): Promise<LoginView> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      if (
        !Number.isSafeInteger(request.index) ||
        request.index < 0 ||
        request.index >= MAX_PASSWORD_HISTORY ||
        typeof request.lastUsedDate !== 'string' ||
        !Number.isFinite(Date.parse(request.lastUsedDate)) ||
        typeof request.expectedUpdatedAt !== 'string'
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      if (login.type !== 'login' || login.updatedAt !== request.expectedUpdatedAt) {
        throw new VaultError('INVALID_INPUT')
      }
      const entry = login.passwordHistory[request.index]
      if (
        !entry ||
        entry.lastUsedDate !== request.lastUsedDate ||
        entry.password === login.password
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const previousPassword = login.password
      const previousHistory = clonePasswordHistory(login.passwordHistory)
      login.password = entry.password
      login.passwordHistory = (
        previousPassword.length > 0
          ? [{ password: previousPassword, lastUsedDate: now }, ...previousHistory]
          : previousHistory
      ).slice(0, MAX_PASSWORD_HISTORY)
      login.passwordRevisionDate = now
      login.updatedAt = now
      return toView(login)
    })
  }

  async downloadAttachment(
    request: AttachmentDownloadRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentDownloadResult> {
    const preflight = await this.exclusive(async () => {
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
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      this.assertAttachmentAuthorized(login, validateAuthorization)
      const attachment = login.attachments.find((entry) => entry.id === request.attachmentId)
      if (!attachment) throw new VaultError('NOT_FOUND')
      const files = this.attachmentFiles
      if (!files) throw new VaultError('INTERNAL_ERROR')
      const sync = this.requireSyncData()
      const mapping = sync.loginMappings.find((entry) => entry.localId === login.id)
      if (!mapping) throw new VaultError('INVALID_INPUT')
      return { files, fileName: attachment.fileName, generation: this.generation }
    })

    this.reportAttachmentProgress(reportProgress, request, 'download', 'choosing-file', 0, null)
    // Electron's native save dialog is not abortable. Keep it outside the vault
    // mutex so auto-lock can clear keys even while the user leaves the dialog open.
    const destination = await preflight.files.chooseSavePath(preflight.fileName)
    if (destination === null) {
      return { canceled: true, fileName: preflight.fileName }
    }

    return this.exclusive(async () => {
      if (preflight.generation !== this.generation) throw new VaultError('LOCKED')
      assertUuid(request.id)
      const data = this.requireData()
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      this.assertAttachmentAuthorized(login, validateAuthorization)
      const attachment = login.attachments.find((entry) => entry.id === request.attachmentId)
      if (!attachment) throw new VaultError('NOT_FOUND')
      if (attachment.fileName !== preflight.fileName) {
        throw new VaultError('ATTACHMENT_FAILED')
      }
      const sync = this.requireSyncData()
      const mapping = sync.loginMappings.find((entry) => entry.localId === login.id)
      if (!mapping) throw new VaultError('INVALID_INPUT')
      const client = this.getOrCreateSyncClient(sync)
      const operation = this.startAttachmentOperation(request.operationId)
      const { abort } = operation
      let downloadedStream:
        Awaited<ReturnType<NonNullable<typeof client.downloadAttachmentStream>>> | undefined
      let clearText: Buffer | undefined
      try {
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'download',
          'downloading',
          0,
          attachment.size
        )
        if (abort.signal.aborted) throw new VaultError('LOCKED')
        const generation = this.generation
        const downloaded = client.downloadAttachmentStream
          ? await client.downloadAttachmentStream(mapping.remoteId, attachment.id, abort.signal)
          : await client.downloadAttachment(mapping.remoteId, attachment.id, abort.signal)
        if ('dispose' in downloaded) downloadedStream = downloaded
        else clearText = downloaded.data
        if (generation !== this.generation || abort.signal.aborted) {
          throw new VaultError('LOCKED')
        }
        if (downloaded.fileName !== attachment.fileName) {
          throw new VaultError('ATTACHMENT_FAILED')
        }
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'download',
          'downloading',
          attachment.size,
          attachment.size
        )
        if (downloadedStream) {
          await preflight.files.writeStream(destination, downloadedStream.data, abort.signal)
        } else {
          await preflight.files.write(destination, clearText!, abort.signal)
        }
        // The atomic rename is the commit point. Once the requested plaintext file exists,
        // report success even if a lock races with the final chmod/directory sync.
        return { canceled: false, fileName: attachment.fileName }
      } catch (error) {
        throw this.mapAttachmentError(error, operation)
      } finally {
        clearText?.fill(0)
        await downloadedStream?.dispose().catch(() => undefined)
        this.finishAttachmentOperation(operation)
      }
    })
  }

  async uploadAttachment(
    request: AttachmentUploadRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentUploadResult> {
    const preflight = await this.exclusive(async () => {
      assertUuid(request.id)
      assertUuid(request.operationId)
      const data = this.requireData()
      assertNoPendingPersonalVaultPurge(data.sync)
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      this.assertAttachmentAuthorized(login, validateAuthorization)
      const files = this.attachmentFiles
      if (!files) throw new VaultError('INTERNAL_ERROR')
      const sync = this.requireSyncData()
      if (!sync.loginMappings.some((entry) => entry.localId === login.id)) {
        throw new VaultError('INVALID_INPUT')
      }
      return { files, generation: this.generation }
    })

    this.reportAttachmentProgress(reportProgress, request, 'upload', 'choosing-file', 0, null)
    const selection = await preflight.files.chooseOpenFile()
    if (selection === null) return { canceled: true, attachment: null }

    return this.exclusive(async () => {
      if (preflight.generation !== this.generation) throw new VaultError('LOCKED')
      const data = this.requireData()
      assertNoPendingPersonalVaultPurge(data.sync)
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      this.assertAttachmentAuthorized(login, validateAuthorization)
      if (login.attachments.some((attachment) => attachment.fileName === selection.fileName)) {
        throw new VaultError('DUPLICATE_NAME')
      }
      const sync = this.requireSyncData()
      const mapping = sync.loginMappings.find((entry) => entry.localId === login.id)
      if (!mapping) throw new VaultError('INVALID_INPUT')
      const client = this.getOrCreateSyncClient(sync)
      const operation = this.startAttachmentOperation(request.operationId)
      let clearText: Buffer | undefined
      try {
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'upload',
          'reading-file',
          0,
          selection.size
        )
        const selectedSource = preflight.files.selectedFileSource(selection)
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'upload',
          'reading-file',
          selection.size,
          selection.size
        )
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'upload',
          'encrypting',
          0,
          selection.size
        )
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'upload',
          'uploading',
          0,
          selection.size
        )
        const uploaded = client.uploadAttachmentStream
          ? await client.uploadAttachmentStream(
              mapping.remoteId,
              selection.fileName,
              selectedSource,
              operation.abort.signal,
              () => this.commitAttachmentOperation(operation)
            )
          : await (async () => {
              clearText = await preflight.files.readSelectedFile(selection, operation.abort.signal)
              return client.uploadAttachment(
                mapping.remoteId,
                selection.fileName,
                clearText,
                operation.abort.signal,
                () => this.commitAttachmentOperation(operation)
              )
            })()
        this.commitAttachmentOperation(operation)
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'upload',
          'uploading',
          selection.size,
          selection.size
        )
        this.reportAttachmentProgress(reportProgress, request, 'upload', 'syncing', 0, null)
        await this.persistAttachmentMutation(data, client)
        const updated = this.findLogin(this.requireData(), request.id)
        const attachment = updated.attachments.find((entry) => entry.id === uploaded.id)
        if (!attachment || attachment.fileName !== selection.fileName || attachment.legacy) {
          throw new VaultError('ATTACHMENT_FAILED')
        }
        return { canceled: false, attachment: { ...attachment } }
      } catch (error) {
        throw this.mapAttachmentError(error, operation)
      } finally {
        clearText?.fill(0)
        this.finishAttachmentOperation(operation)
      }
    })
  }

  deleteAttachment(
    request: AttachmentDeleteRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentDeleteResult> {
    return this.exclusive(async () => {
      const { data, attachment, mapping, client } = this.attachmentMutationContext(
        request,
        validateAuthorization
      )
      const operation = this.startAttachmentOperation(request.operationId)
      try {
        this.reportAttachmentProgress(reportProgress, request, 'delete', 'deleting', 0, null)
        await client.deleteAttachment(mapping.remoteId, attachment.id, operation.abort.signal, () =>
          this.commitAttachmentOperation(operation)
        )
        this.commitAttachmentOperation(operation)
        this.reportAttachmentProgress(reportProgress, request, 'delete', 'syncing', 0, null)
        await this.persistAttachmentMutation(data, client)
        const updated = this.findLogin(this.requireData(), request.id)
        if (updated.attachments.some((entry) => entry.id === attachment.id)) {
          throw new VaultError('ATTACHMENT_FAILED')
        }
        return { attachmentId: attachment.id }
      } catch (error) {
        throw this.mapAttachmentError(error, operation)
      } finally {
        this.finishAttachmentOperation(operation)
      }
    })
  }

  fixLegacyAttachment(
    request: AttachmentFixLegacyRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentFixLegacyResult> {
    return this.exclusive(async () => {
      const { data, attachment, mapping, client } = this.attachmentMutationContext(
        request,
        validateAuthorization
      )
      if (!attachment.legacy) throw new VaultError('INVALID_INPUT')
      const operation = this.startAttachmentOperation(request.operationId)
      try {
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'fix-legacy',
          'downloading',
          0,
          attachment.size
        )
        const upgraded = await client.upgradeLegacyAttachment(
          mapping.remoteId,
          attachment.id,
          operation.abort.signal,
          () => this.commitAttachmentOperation(operation)
        )
        this.commitAttachmentOperation(operation)
        this.reportAttachmentProgress(reportProgress, request, 'fix-legacy', 'syncing', 0, null)
        await this.persistAttachmentMutation(data, client)
        const updated = this.findLogin(this.requireData(), request.id)
        if (updated.attachments.some((entry) => entry.id === attachment.id)) {
          throw new VaultError('ATTACHMENT_FAILED')
        }
        const replacement = updated.attachments.find((entry) => entry.id === upgraded.id)
        if (!replacement || replacement.fileName !== attachment.fileName || replacement.legacy) {
          throw new VaultError('ATTACHMENT_FAILED')
        }
        return { attachment: { ...replacement } }
      } catch (error) {
        throw this.mapAttachmentError(error, operation)
      } finally {
        this.finishAttachmentOperation(operation)
      }
    })
  }

  cancelAttachmentOperation(request: AttachmentCancelRequest): AttachmentCancelResult {
    assertUuid(request.operationId)
    const active = this.activeAttachmentOperation
    if (
      !active ||
      active.operationId !== request.operationId ||
      active.committed ||
      active.abort.signal.aborted
    ) {
      return { canceled: false }
    }
    active.canceledByUser = true
    active.abort.abort()
    return { canceled: true }
  }

  verifyPortabilityOwner(masterPassword: string): Promise<void> {
    return this.exclusive(() => this.assertMasterPassword(masterPassword))
  }

  exportPortableSnapshot(masterPassword: string): Promise<VaultExportSnapshot> {
    return this.exclusive(async () => {
      await this.assertMasterPassword(masterPassword)
      const snapshot = this.localSyncSnapshot(this.requireData())
      const items = snapshot.logins.filter((item) => item.deletedAt === null)
      return {
        snapshot: {
          folders: snapshot.folders.map((folder) => ({ ...folder })),
          items: items.map((item) => ({
            ...item,
            uris: cloneLoginUris(item.uris),
            passkeys: item.passkeys.map((passkey) => ({ ...passkey })),
            customFields: cloneCustomFields(item.customFields),
            passwordHistory: clonePasswordHistory(item.passwordHistory)
          }))
        },
        skippedTrashItems: snapshot.logins.length - items.length
      }
    })
  }

  async createNativeAttachmentBackupSource(
    masterPassword: string,
    options: { includeLoginWireMetadata?: boolean } = {}
  ): Promise<VaultNativeAttachmentBackupSource> {
    // Bitwarden's attachment metadata contains encrypted-envelope size, while the native archive
    // requires exact plaintext sizes in its authenticated manifest. Preflight therefore downloads,
    // authenticates and counts every plaintext once without retaining it. Each later open (including
    // a resume) deliberately re-downloads and re-authenticates the complete ciphertext before bytes
    // at the committed offset are yielded. A native export consequently transfers attachments twice.
    type Candidate = NativeAttachmentBackupEntry & { remoteItemId: string }
    const prepared = await this.exclusive(async () => {
      await this.assertMasterPassword(masterPassword)
      const data = this.requireData()
      assertNoPendingPersonalVaultPurge(data.sync)
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const snapshot = this.localSyncSnapshot(data)
      const activeItems = snapshot.logins.filter((item) => item.deletedAt === null)
      const candidates: Candidate[] = []
      for (const item of data.logins.filter((login) => login.deletedAt === null)) {
        const mapping = sync.loginMappings.find((entry) => entry.localId === item.id)
        if (!mapping) continue
        for (const attachment of item.attachments) {
          candidates.push({
            id: attachment.id,
            itemId: item.id,
            fileName: attachment.fileName,
            size: 0,
            remoteItemId: mapping.remoteId
          })
        }
      }
      const abort = new AbortController()
      this.nativeAttachmentBackupAborts.add(abort)
      const portable: PortableVaultSnapshot = {
        folders: snapshot.folders.map((folder) => ({ ...folder })),
        items: activeItems.map((item) => ({
          ...item,
          uris: cloneLoginUris(item.uris),
          passkeys: item.passkeys.map((passkey) => ({ ...passkey })),
          customFields: cloneCustomFields(item.customFields),
          passwordHistory: clonePasswordHistory(item.passwordHistory)
        }))
      }
      return {
        abort,
        candidates,
        client,
        generation: this.generation,
        portable,
        skippedTrashItems: snapshot.logins.length - activeItems.length
      }
    })

    let disposed = false
    const ensureCurrent = (): void => {
      if (
        disposed ||
        prepared.abort.signal.aborted ||
        prepared.generation !== this.generation ||
        this.syncClient !== prepared.client ||
        !this.data?.sync?.state.session
      ) {
        throw new VaultError('LOCKED')
      }
    }
    const download = async (
      candidate: Candidate,
      consume: (chunks: AsyncIterable<Buffer>) => Promise<number>
    ): Promise<number> => {
      ensureCurrent()
      let streamed:
        | Awaited<ReturnType<NonNullable<BitwardenSyncClient['downloadAttachmentStream']>>>
        | undefined
      let clearText: Buffer | undefined
      try {
        const result = prepared.client.downloadAttachmentStream
          ? await prepared.client.downloadAttachmentStream(
              candidate.remoteItemId,
              candidate.id,
              prepared.abort.signal
            )
          : await prepared.client.downloadAttachment(
              candidate.remoteItemId,
              candidate.id,
              prepared.abort.signal
            )
        ensureCurrent()
        if (result.fileName !== candidate.fileName) throw new VaultError('ATTACHMENT_FAILED')
        if ('dispose' in result) streamed = result
        else clearText = result.data
        const chunks: AsyncIterable<Buffer> = streamed
          ? streamed.data.chunks(prepared.abort.signal)
          : (async function* (): AsyncIterable<Buffer> {
              yield clearText!
            })()
        return await consume(chunks)
      } catch (error) {
        if (prepared.abort.signal.aborted || prepared.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof VaultError) throw error
        throw new VaultError('ATTACHMENT_FAILED')
      } finally {
        clearText?.fill(0)
        await streamed?.dispose().catch(() => undefined)
      }
    }

    try {
      const entries: NativeAttachmentBackupEntry[] = []
      for (const candidate of prepared.candidates) {
        const size = await download(candidate, async (chunks) => {
          let bytes = 0
          for await (const chunk of chunks) {
            try {
              bytes += chunk.length
            } finally {
              chunk.fill(0)
            }
          }
          return bytes
        })
        entries.push({
          id: candidate.id,
          itemId: candidate.itemId,
          fileName: candidate.fileName,
          size
        })
      }
      ensureCurrent()
      const source: VaultNativeAttachmentBackupSource = {
        vaultJson: buildBitwardenJson(prepared.portable, {
          includeLoginWireMetadata: options.includeLoginWireMetadata === true
        }),
        attachments: entries,
        exportedFolders: prepared.portable.folders.length,
        exportedItems: prepared.portable.items.length,
        skippedTrashItems: prepared.skippedTrashItems,
        openAttachment: (entry, offset, signal) => {
          const index = entries.findIndex(
            (candidate) =>
              candidate.id === entry.id &&
              candidate.itemId === entry.itemId &&
              candidate.fileName === entry.fileName &&
              candidate.size === entry.size
          )
          if (index < 0 || !Number.isSafeInteger(offset) || offset < 0 || offset > entry.size) {
            throw new VaultError('INVALID_INPUT')
          }
          const candidate = prepared.candidates[index]!
          return (async function* (): AsyncIterable<Buffer> {
            ensureCurrent()
            const operationSignal = signal
              ? AbortSignal.any([prepared.abort.signal, signal])
              : prepared.abort.signal
            let skipped = 0
            let total = 0
            let streamed:
              | Awaited<ReturnType<NonNullable<BitwardenSyncClient['downloadAttachmentStream']>>>
              | undefined
            let clearText: Buffer | undefined
            try {
              const result = prepared.client.downloadAttachmentStream
                ? await prepared.client.downloadAttachmentStream(
                    candidate.remoteItemId,
                    candidate.id,
                    operationSignal
                  )
                : await prepared.client.downloadAttachment(
                    candidate.remoteItemId,
                    candidate.id,
                    operationSignal
                  )
              ensureCurrent()
              if (result.fileName !== candidate.fileName) {
                throw new VaultError('ATTACHMENT_FAILED')
              }
              if ('dispose' in result) streamed = result
              else clearText = result.data
              const chunks: AsyncIterable<Buffer> = streamed
                ? streamed.data.chunks(operationSignal)
                : (async function* (): AsyncIterable<Buffer> {
                    yield clearText!
                  })()
              for await (const chunk of chunks) {
                if (operationSignal.aborted) throw new VaultError('LOCKED')
                total += chunk.length
                if (skipped + chunk.length <= offset) {
                  skipped += chunk.length
                  chunk.fill(0)
                  continue
                }
                const start = Math.max(0, offset - skipped)
                if (start > 0) chunk.subarray(0, start).fill(0)
                skipped += chunk.length
                yield chunk.subarray(start)
              }
              if (total !== entry.size) throw new VaultError('ATTACHMENT_FAILED')
            } catch (error) {
              if (prepared.abort.signal.aborted) {
                throw new VaultError('LOCKED')
              }
              if (error instanceof VaultError) throw error
              throw new VaultError('ATTACHMENT_FAILED')
            } finally {
              clearText?.fill(0)
              await streamed?.dispose().catch(() => undefined)
            }
          })()
        },
        dispose: () => {
          if (disposed) return
          disposed = true
          prepared.abort.abort()
          this.nativeAttachmentBackupAborts.delete(prepared.abort)
        }
      }
      return source
    } catch (error) {
      disposed = true
      prepared.abort.abort()
      this.nativeAttachmentBackupAborts.delete(prepared.abort)
      throw error
    }
  }

  nativeAttachmentRestoreStatus(): Promise<VaultNativeAttachmentRestoreSummary | null> {
    return this.exclusive(async () => {
      const journal = this.requireData().nativeAttachmentRestore
      return journal ? this.nativeAttachmentRestoreSummary(journal) : null
    })
  }

  clearCompletedNativeAttachmentRestore(archiveFingerprint: string): Promise<void> {
    return this.exclusive(async () => {
      const current = this.requireData()
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const journal = this.requireBoundNativeAttachmentRestore(
        current,
        archiveFingerprint,
        sync,
        client
      )
      if (journal.phase !== 'complete') throw new VaultError('INVALID_INPUT')
      const next = cloneData(current)
      next.nativeAttachmentRestore = null
      next.updatedAt = this.nowIso()
      await this.persist(next)
      this.data = next
    })
  }

  beginNativeAttachmentRestore(
    preview: NativeAttachmentBackupPreview,
    masterPassword: string
  ): Promise<VaultNativeAttachmentRestoreSummary> {
    return this.exclusive(async () => {
      await this.assertMasterPassword(masterPassword)
      const current = this.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      assertNoPendingLoginImport(current.sync)
      if (current.nativeAttachmentRestore !== null) throw new VaultError('INVALID_INPUT')
      if (
        !preview ||
        typeof preview.vaultJson !== 'string' ||
        !Array.isArray(preview.attachments) ||
        !Array.isArray(preview.attachmentDigests) ||
        preview.attachments.length !== preview.attachmentDigests.length
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const operation = this.startNativeAttachmentRestoreOperation(client)
      try {
        await client.sync(operation.abort.signal)
        this.assertNativeAttachmentRestoreLease(operation)
        const accountFingerprint = this.nativeAttachmentRestoreAccountFingerprint(sync, client)
        const parsed = parseBitwardenJson(preview.vaultJson)
        if (parsed.skippedTrashItems !== 0) throw new VaultError('INVALID_INPUT')
        const next = cloneData(this.requireData())
        const imported = this.appendPortableSnapshot(next, parsed.snapshot)
        const sourceItemIds = new Set(parsed.snapshot.items.map((item) => item.id))
        const attachments = preview.attachments.map((attachment, index) => {
          if (!sourceItemIds.has(attachment.itemId)) throw new VaultError('INVALID_INPUT')
          return {
            sourceItemId: attachment.itemId,
            sourceAttachmentId: attachment.id,
            fileName: attachment.fileName,
            size: attachment.size,
            digest: preview.attachmentDigests[index]!
          }
        })
        const now = this.nowIso()
        next.nativeAttachmentRestore = createNativeAttachmentRestoreJournal({
          archiveFingerprint: preview.archiveFingerprint,
          accountFingerprint,
          createdAt: now,
          items: imported.itemMappings,
          attachments
        })
        next.updatedAt = now
        await this.persist(next)
        this.assertNativeAttachmentRestoreLease(operation)
        this.data = next
        return this.nativeAttachmentRestoreSummary(next.nativeAttachmentRestore)
      } catch (error) {
        if (operation.abort.signal.aborted || operation.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof VaultError) throw error
        throw new VaultError('SYNC_FAILED')
      } finally {
        this.finishNativeAttachmentRestoreOperation(operation)
      }
    })
  }

  syncNativeAttachmentRestoreItems(
    archiveFingerprint: string
  ): Promise<VaultNativeAttachmentRestoreSummary> {
    return this.exclusive(async () => {
      const current = this.requireData()
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const journal = this.requireBoundNativeAttachmentRestore(
        current,
        archiveFingerprint,
        sync,
        client
      )
      if (journal.phase !== 'syncing-items') return this.nativeAttachmentRestoreSummary(journal)
      const operation = this.startNativeAttachmentRestoreOperation(client)
      try {
        await this.performSync(current, client, operation.abort.signal)
        this.assertNativeAttachmentRestoreLease(operation)
        const next = cloneData(this.requireData())
        let updated = next.nativeAttachmentRestore
        if (!updated || !next.sync) throw new VaultError('SYNC_FAILED')
        for (const item of updated.items.filter((candidate) => candidate.remoteItemId === null)) {
          const mapping = next.sync.loginMappings.find(
            (entry) => entry.localId === item.localItemId
          )
          if (!mapping) throw new VaultError('SYNC_FAILED')
          updated = bindNativeAttachmentRestoreRemoteItem(
            updated,
            item.sourceItemId,
            mapping.remoteId,
            this.nowIso()
          )
        }
        next.nativeAttachmentRestore = updated
        next.updatedAt = updated.updatedAt
        await this.persist(next)
        this.assertNativeAttachmentRestoreLease(operation)
        this.data = next
        return this.nativeAttachmentRestoreSummary(updated)
      } finally {
        this.finishNativeAttachmentRestoreOperation(operation)
      }
    })
  }

  uploadNativeAttachmentRestoreEntry(
    archiveFingerprint: string,
    key: NativeAttachmentRestoreAttachmentKey,
    source: BitwardenAttachmentByteSource
  ): Promise<VaultNativeAttachmentRestoreSummary> {
    return this.exclusive(async () => {
      const current = this.requireData()
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const journal = this.requireBoundNativeAttachmentRestore(
        current,
        archiveFingerprint,
        sync,
        client
      )
      const target = journal.attachments.find(
        (attachment) =>
          attachment.sourceItemId === key.sourceItemId &&
          attachment.sourceAttachmentId === key.sourceAttachmentId
      )
      const item = journal.items.find((candidate) => candidate.sourceItemId === key.sourceItemId)
      if (!target || !item?.remoteItemId || source?.size !== target.size) {
        throw new VaultError('INVALID_INPUT')
      }
      if (!client.uploadAttachmentStream) throw new VaultError('ATTACHMENT_FAILED')
      const operation = this.startNativeAttachmentRestoreOperation(client)
      try {
        const attempting = cloneData(current)
        if (!attempting.nativeAttachmentRestore) throw new VaultError('INVALID_INPUT')
        attempting.nativeAttachmentRestore = beginNativeAttachmentRestoreAttempt(
          attempting.nativeAttachmentRestore,
          key,
          this.nowIso()
        )
        attempting.updatedAt = attempting.nativeAttachmentRestore.updatedAt
        await this.persist(attempting)
        this.data = attempting
        this.assertNativeAttachmentRestoreLease(operation)
        const uploaded = await client.uploadAttachmentStream(
          item.remoteItemId,
          target.fileName,
          source,
          operation.abort.signal
        )
        this.assertNativeAttachmentRestoreLease(operation)
        await client.sync(operation.abort.signal)
        const [remoteFolders, remoteLogins] = await Promise.all([
          client.listFolders(operation.abort.signal),
          client.listPersonalLogins(operation.abort.signal)
        ])
        this.assertNativeAttachmentRestoreLease(operation)
        const authoritativeItem = remoteLogins.find(
          (candidate) => candidate.id === item.remoteItemId
        )
        if (
          authoritativeItem?.attachments.filter(
            (attachment) => attachment.id === uploaded.id && attachment.fileName === target.fileName
          ).length !== 1
        ) {
          throw new VaultError('ATTACHMENT_FAILED')
        }
        const next = this.applyNativeAttachmentRestoreRemoteSnapshot(
          this.requireData(),
          client,
          remoteFolders,
          remoteLogins
        )
        if (!next.nativeAttachmentRestore) throw new VaultError('ATTACHMENT_FAILED')
        next.nativeAttachmentRestore = completeNativeAttachmentRestoreAttempt(
          next.nativeAttachmentRestore,
          key,
          uploaded.id,
          this.nowIso()
        )
        next.updatedAt = next.nativeAttachmentRestore.updatedAt
        await this.persist(next)
        this.data = next
        return this.nativeAttachmentRestoreSummary(next.nativeAttachmentRestore)
      } catch (error) {
        let reconciliationPersistenceError: unknown = null
        try {
          await this.persistFailedNativeAttachmentRestoreAttempt(key)
        } catch (persistError) {
          reconciliationPersistenceError = persistError
        }
        if (operation.abort.signal.aborted || operation.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (reconciliationPersistenceError) throw reconciliationPersistenceError
        if (error instanceof VaultError) throw error
        throw new VaultError('ATTACHMENT_FAILED')
      } finally {
        this.finishNativeAttachmentRestoreOperation(operation)
      }
    })
  }

  reconcileNativeAttachmentRestoreEntry(
    archiveFingerprint: string,
    key: NativeAttachmentRestoreAttachmentKey
  ): Promise<{
    outcome: 'uploaded' | 'missing' | 'conflict'
    summary: VaultNativeAttachmentRestoreSummary
  }> {
    return this.exclusive(async () => {
      const current = this.requireData()
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const journal = this.requireBoundNativeAttachmentRestore(
        current,
        archiveFingerprint,
        sync,
        client
      )
      const target = journal.attachments.find(
        (attachment) =>
          attachment.sourceItemId === key.sourceItemId &&
          attachment.sourceAttachmentId === key.sourceAttachmentId
      )
      const item = journal.items.find((candidate) => candidate.sourceItemId === key.sourceItemId)
      if (!target || target.status !== 'needs-reconciliation' || !item?.remoteItemId) {
        throw new VaultError('INVALID_INPUT')
      }
      const operation = this.startNativeAttachmentRestoreOperation(client)
      try {
        await client.sync(operation.abort.signal)
        const [remoteFolders, remoteLogins] = await Promise.all([
          client.listFolders(operation.abort.signal),
          client.listPersonalLogins(operation.abort.signal)
        ])
        this.assertNativeAttachmentRestoreLease(operation)
        const remoteItem = remoteLogins.find((candidate) => candidate.id === item.remoteItemId)
        const candidates =
          remoteItem?.attachments.filter((attachment) => attachment.fileName === target.fileName) ??
          []
        let outcome: 'uploaded' | 'missing' | 'conflict' = 'conflict'
        let remoteAttachmentId: string | null = null
        if (remoteItem && candidates.length === 0) {
          outcome = 'missing'
        } else if (remoteItem && candidates.length === 1) {
          const candidate = candidates[0]!
          if (
            await this.nativeAttachmentRestoreCandidateMatches(
              client,
              item.remoteItemId,
              candidate.id,
              target.fileName,
              target.size,
              target.digest,
              operation.abort.signal
            )
          ) {
            outcome = 'uploaded'
            remoteAttachmentId = candidate.id
          }
        }
        this.assertNativeAttachmentRestoreLease(operation)
        const next = remoteItem
          ? this.applyNativeAttachmentRestoreRemoteSnapshot(
              this.requireData(),
              client,
              remoteFolders,
              remoteLogins
            )
          : (() => {
              const preserved = cloneData(this.requireData())
              if (!preserved.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
              preserved.sync.state = client.exportState()
              preserved.sync.lastSyncAt = this.nowIso()
              return preserved
            })()
        if (!next.nativeAttachmentRestore) throw new VaultError('ATTACHMENT_FAILED')
        if (outcome === 'missing') {
          next.nativeAttachmentRestore = reconcileNativeAttachmentRestoreMissing(
            next.nativeAttachmentRestore,
            key,
            this.nowIso()
          )
        } else if (outcome === 'uploaded' && remoteAttachmentId) {
          next.nativeAttachmentRestore = reconcileNativeAttachmentRestoreUploaded(
            next.nativeAttachmentRestore,
            key,
            remoteAttachmentId,
            this.nowIso()
          )
        }
        next.updatedAt = next.nativeAttachmentRestore.updatedAt
        await this.persist(next)
        this.data = next
        return {
          outcome,
          summary: this.nativeAttachmentRestoreSummary(next.nativeAttachmentRestore)
        }
      } catch (error) {
        if (operation.abort.signal.aborted || operation.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof VaultError) throw error
        throw new VaultError('ATTACHMENT_FAILED')
      } finally {
        this.finishNativeAttachmentRestoreOperation(operation)
      }
    })
  }

  importPortableSnapshot(
    snapshot: PortableVaultSnapshot,
    skippedTrashItems: number,
    masterPassword: string
  ): Promise<Omit<VaultImportResult, 'canceled'>> {
    return this.exclusive(async () => {
      await this.assertMasterPassword(masterPassword)
      const current = this.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      if (
        !snapshot ||
        !Array.isArray(snapshot.folders) ||
        !Array.isArray(snapshot.items) ||
        !Number.isSafeInteger(skippedTrashItems) ||
        skippedTrashItems < 0
      ) {
        throw new VaultError('INVALID_INPUT')
      }

      if (snapshot.folders.length === 0 && snapshot.items.length === 0) {
        return { importedFolders: 0, importedItems: 0, skippedTrashItems }
      }

      const next = cloneData(current)
      const generation = this.generation
      try {
        this.appendPortableSnapshot(next, snapshot)
      } catch (error) {
        if (error instanceof VaultError && error.code === 'INVALID_INPUT') throw error
        throw new VaultError('INVALID_INPUT')
      }

      next.updatedAt = this.nowIso()
      await this.persist(next)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      this.data = next
      return {
        importedFolders: snapshot.folders.length,
        importedItems: snapshot.items.length,
        skippedTrashItems
      }
    })
  }

  generateCredential(request: CredentialGeneratorRequest): Promise<CredentialGeneratorResult> {
    return this.generatorService.generateCredential(request)
  }

  copyGeneratedCredential(request: GeneratedCredentialCopyRequest): Promise<void> {
    return this.generatorService.copyGeneratedCredential(request)
  }

  generateSshKey(): Promise<SshKeyMaterial> {
    return this.generatorService.generateSshKey()
  }

  generatorHistory(): Promise<GeneratorHistoryEntry[]> {
    return this.generatorService.history()
  }

  clearGeneratorHistory(): Promise<void> {
    return this.generatorService.clearHistory()
  }

  copyGeneratorHistory(request: GeneratorHistoryLocator): Promise<void> {
    return this.generatorService.copyHistory(request)
  }

  loginAuthorizationState(request: LoginIdRequest): Promise<{
    reprompt: VaultReprompt
    generation: number
  }> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      return { reprompt: login.reprompt, generation: this.generation }
    })
  }

  /**
   * Returns a point-in-time public identity snapshot for the main-process SSH Agent. Invalid or
   * unsupported public keys are omitted rather than allowing unusable identities onto the wire.
   */
  listSshAgentIdentities(): Promise<SshAgentVaultIdentity[]> {
    return this.exclusive(async () => {
      const data = this.requireData()
      const generation = this.generation
      const identities: SshAgentVaultIdentity[] = []
      for (const login of data.logins) {
        if (login.type !== 'sshKey' || login.deletedAt !== null || login.archivedAt !== null) {
          continue
        }
        const publicKeyBlob = parseSupportedSshAgentPublicKeyBlob(login.publicKey)
        if (!publicKeyBlob) continue
        identities.push({
          itemId: login.id,
          name: login.name,
          publicKeyBlob,
          fingerprint: sshAgentFingerprint(publicKeyBlob),
          reprompt: login.reprompt,
          generation
        })
      }
      return identities
    })
  }

  /**
   * Signs inside the vault mutex after atomically re-checking the item and its reprompt policy.
   * The validator is intentionally synchronous so an approval capability cannot be raced by sync.
   */
  signSshAgentRequest(
    request: SshAgentVaultSignRequest,
    validateAuthorization: SshAgentVaultAuthorizationValidator
  ): Promise<SshAgentVaultSignResult> {
    return this.runAuthorizedOperation(validateAuthorization, async (authorize) => {
      if (
        !Buffer.isBuffer(request.publicKeyBlob) ||
        request.publicKeyBlob.length === 0 ||
        request.publicKeyBlob.length > SSH_AGENT_MAX_MESSAGE_LENGTH ||
        !Buffer.isBuffer(request.data) ||
        request.data.length > SSH_AGENT_MAX_MESSAGE_LENGTH ||
        (request.rsaHash !== undefined &&
          request.rsaHash !== 'sha256' &&
          request.rsaHash !== 'sha512') ||
        !Number.isSafeInteger(request.expectedGeneration) ||
        request.expectedGeneration < 0
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      if (request.expectedGeneration !== this.generation) throw new VaultError('LOCKED')

      const matches = this.requireData().logins.filter((login) => {
        if (login.type !== 'sshKey' || login.deletedAt !== null || login.archivedAt !== null) {
          return false
        }
        return parseSupportedSshAgentPublicKeyBlob(login.publicKey)?.equals(request.publicKeyBlob)
      })
      if (matches.length === 0) throw new VaultError('NOT_FOUND')
      // The public key is the protocol identifier. Refuse an ambiguous duplicate instead of
      // accidentally selecting the copy with the weaker reprompt policy.
      if (matches.length !== 1) throw new VaultError('INVALID_INPUT')
      const login = matches[0]!

      authorize([login.id])
      const signature = createSshAgentSignature(
        login.privateKey,
        request.publicKeyBlob,
        request.data,
        request.rsaHash
      )
      if (request.expectedGeneration !== this.generation) throw new VaultError('LOCKED')
      return {
        itemId: login.id,
        generation: this.generation,
        algorithm: signature.algorithm,
        signature: signature.signature
      }
    })
  }

  /**
   * Main-process authorization boundary. The validator must be synchronous: keeping it and the
   * nested service operation in this same exclusive section prevents sync from enabling reprompt
   * between the check and secret access.
   */
  runAuthorizedOperation<T>(
    validate: (ids: readonly string[], state: { generation: number }) => boolean,
    operation: (authorize: (ids: readonly string[]) => void) => Promise<T>
  ): Promise<T> {
    return this.exclusive(async () => {
      let didAuthorize = false
      const authorize = (ids: readonly string[]): void => {
        didAuthorize = true
        let requiresReprompt = false
        for (const id of ids) {
          assertUuid(id)
          const login = this.findLogin(this.requireData(), id)
          if (login.reprompt === 1) requiresReprompt = true
        }
        if (requiresReprompt && !validate(ids, { generation: this.generation })) {
          throw new VaultError('REPROMPT_REQUIRED')
        }
      }
      const result = await operation(authorize)
      if (!didAuthorize) throw new VaultError('INTERNAL_ERROR')
      return result
    })
  }

  authorizeLogin(request: LoginAuthorizeRequest): Promise<number> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      this.findLogin(this.requireData(), request.id)
      if (typeof request.masterPassword !== 'string') throw new VaultError('INVALID_INPUT')
      const candidate = request.masterPassword.normalize('NFC')
      if (candidate.length > MAX_MASTER_PASSWORD_LENGTH) {
        throw new VaultError('INVALID_MASTER_PASSWORD')
      }
      const generation = this.generation
      if (!this.key || !this.salt) throw new VaultError('LOCKED')
      const valid = await this.store.verifyMasterPassword(candidate, this.key, this.salt)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      if (!valid) throw new VaultError('INVALID_MASTER_PASSWORD')
      return generation
    })
  }

  authorizeLogins(request: LoginAuthorizeManyRequest): Promise<number> {
    return this.exclusive(async () => {
      if (
        !Array.isArray(request.ids) ||
        request.ids.length === 0 ||
        request.ids.length > MAX_LOGIN_AUTHORIZE_MANY_IDS ||
        new Set(request.ids).size !== request.ids.length
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      for (const id of request.ids) {
        assertUuid(id)
        this.findLogin(this.requireData(), id)
      }
      if (typeof request.masterPassword !== 'string') throw new VaultError('INVALID_INPUT')
      const candidate = request.masterPassword.normalize('NFC')
      if (candidate.length > MAX_MASTER_PASSWORD_LENGTH) {
        throw new VaultError('INVALID_MASTER_PASSWORD')
      }
      const generation = this.generation
      if (!this.key || !this.salt) throw new VaultError('LOCKED')
      const valid = await this.store.verifyMasterPassword(candidate, this.key, this.salt)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      if (!valid) throw new VaultError('INVALID_MASTER_PASSWORD')
      return generation
    })
  }

  createLogin(request: LoginCreateRequest): Promise<LoginView> {
    return this.mutate((data, now) => {
      const folderId = this.normalizeFolderId(data, request.folderId)
      const type = normalizeItemType(request.type ?? 'login')
      const fields = emptyItemFields()
      applyItemFields(fields, request, type)
      const uris = createRequestUris(request, type)
      fields.uri = uriAlias(uris)
      const customFields = normalizeCustomFields([], request.customFields ?? [], type)
      const login: StoredLogin = {
        id: this.validatedNewId(),
        type,
        name: normalizeRequiredString(request.name, MAX_NAME_LENGTH),
        notes: normalizeNullableString(request.notes, MAX_NOTES_LENGTH),
        folderId,
        favorite: request.favorite ?? false,
        usageCount: 0,
        lastUsedAt: null,
        createdAt: now,
        updatedAt: now,
        deletedAt: null,
        archivedAt: null,
        reprompt: normalizeReprompt(request.reprompt ?? 0),
        passkeys: [],
        customFields,
        passwordHistory: [],
        passwordRevisionDate: null,
        autofillOnPageLoad: null,
        attachments: [],
        uris,
        ...fields
      }
      if (typeof login.favorite !== 'boolean') throw new VaultError('INVALID_INPUT')
      data.logins.push(login)
      return toView(login)
    })
  }

  cloneLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const source = this.findLogin(data, request.id)
      this.assertActiveLogin(source)
      const clone: StoredLogin = {
        id: this.validatedNewId(),
        type: source.type,
        name: cloneItemName(source.name),
        notes: source.notes,
        folderId: source.folderId,
        favorite: source.favorite,
        usageCount: 0,
        lastUsedAt: null,
        createdAt: now,
        updatedAt: now,
        deletedAt: null,
        archivedAt: source.archivedAt,
        reprompt: source.reprompt,
        // Bitwarden does not clone passkeys, whose private material must remain bound to the source.
        passkeys: [],
        customFields: cloneCustomFields(source.customFields),
        passwordHistory: [],
        passwordRevisionDate: source.passwordRevisionDate,
        autofillOnPageLoad: source.autofillOnPageLoad,
        attachments: [],
        uris: cloneLoginUris(source.uris),
        // Deliberately build the stored shape instead of spreading the source so future
        // attachment fields cannot accidentally become part of the clone.
        ...normalizeItemFieldsForStorage(source)
      }
      data.logins.push(clone)
      return toView(clone)
    })
  }

  archiveLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      if (login.archivedAt !== null) throw new VaultError('INVALID_INPUT')
      login.archivedAt = now
      login.updatedAt = now
      return toView(login)
    })
  }

  archiveLogins(request: LoginBatchRequest): Promise<LoginSummary[]> {
    return this.mutate((data, now) => {
      const logins = this.resolveLoginBatch(data, request, (login) => {
        this.assertActiveLogin(login)
        if (login.archivedAt !== null) throw new VaultError('INVALID_INPUT')
      })
      return logins.map((login) => {
        login.archivedAt = now
        login.updatedAt = now
        return toSummary(login)
      })
    })
  }

  unarchiveLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      if (login.archivedAt === null) throw new VaultError('INVALID_INPUT')
      login.archivedAt = null
      login.updatedAt = now
      return toView(login)
    })
  }

  unarchiveLogins(request: LoginBatchRequest): Promise<LoginSummary[]> {
    return this.mutate((data, now) => {
      const logins = this.resolveLoginBatch(data, request, (login) => {
        this.assertActiveLogin(login)
        if (login.archivedAt === null) throw new VaultError('INVALID_INPUT')
      })
      return logins.map((login) => {
        login.archivedAt = null
        login.updatedAt = now
        return toSummary(login)
      })
    })
  }

  updateLogin(request: LoginUpdateRequest): Promise<LoginView> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      if (
        request.expectedUpdatedAt !== undefined &&
        (typeof request.expectedUpdatedAt !== 'string' ||
          request.expectedUpdatedAt !== login.updatedAt)
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const previousPassword = login.password
      const previousHistory = clonePasswordHistory(login.passwordHistory)
      const previousHiddenFields = login.customFields.filter(
        (field) => field.type === 'hidden' && field.name.length > 0 && field.value.length > 0
      )
      // Normalize the complete post-save set first. Partial editor updates can preserve hidden
      // values that never entered renderer state and therefore must not create false history.
      const nextCustomFields =
        request.customFields === undefined
          ? cloneCustomFields(login.customFields)
          : normalizeCustomFields(login.customFields, request.customFields, login.type)
      if (request.name !== undefined)
        login.name = normalizeRequiredString(request.name, MAX_NAME_LENGTH)
      applyItemFields(login, request, login.type)
      login.uris = updateRequestUris(request, login)
      login.uri = uriAlias(login.uris)
      if (request.notes !== undefined) {
        login.notes = normalizeNullableString(request.notes, MAX_NOTES_LENGTH)
      }
      if (request.folderId !== undefined) {
        login.folderId = this.normalizeFolderId(data, request.folderId)
      }
      if (request.favorite !== undefined) {
        if (typeof request.favorite !== 'boolean') throw new VaultError('INVALID_INPUT')
        login.favorite = request.favorite
      }
      if (request.reprompt !== undefined) login.reprompt = normalizeReprompt(request.reprompt)
      if (request.customFields !== undefined) login.customFields = nextCustomFields
      const newHistory: VaultPasswordHistoryEntry[] = []
      if (
        login.type === 'login' &&
        request.password !== undefined &&
        previousPassword.length > 0 &&
        login.password !== previousPassword
      ) {
        newHistory.unshift({ password: previousPassword, lastUsedDate: now })
      }
      const consumedNextHiddenFields = new Set<number>()
      for (const field of previousHiddenFields) {
        const unchangedIndex = nextCustomFields.findIndex(
          (candidate, index) =>
            !consumedNextHiddenFields.has(index) &&
            candidate.type === 'hidden' &&
            candidate.name === field.name &&
            candidate.value === field.value
        )
        if (unchangedIndex >= 0) {
          consumedNextHiddenFields.add(unchangedIndex)
        } else {
          newHistory.unshift({ password: `${field.name}: ${field.value}`, lastUsedDate: now })
        }
      }
      login.passwordHistory = [...newHistory, ...previousHistory].slice(0, MAX_PASSWORD_HISTORY)
      if (
        login.type === 'login' &&
        request.password !== undefined &&
        login.password !== previousPassword
      ) {
        login.passwordRevisionDate = now
      }
      login.updatedAt = now
      return toView(login)
    })
  }

  deletePasskey(request: PasskeyDeleteRequest): Promise<LoginView> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      if (
        typeof request.credentialId !== 'string' ||
        request.credentialId.length === 0 ||
        request.credentialId.length > MAX_ITEM_FIELD_LENGTH
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      if (login.type !== 'login') throw new VaultError('INVALID_INPUT')
      if (
        request.expectedUpdatedAt !== undefined &&
        (typeof request.expectedUpdatedAt !== 'string' ||
          request.expectedUpdatedAt !== login.updatedAt)
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const matchingIndexes = login.passkeys.flatMap((passkey, index) =>
        passkey.credentialId === request.credentialId ? [index] : []
      )
      if (matchingIndexes.length === 0) throw new VaultError('NOT_FOUND')
      if (matchingIndexes.length !== 1) throw new VaultError('INVALID_INPUT')
      login.passkeys.splice(matchingIndexes[0]!, 1)
      login.updatedAt = now
      return toView(login)
    })
  }

  /** Main-process-only discovery. It deliberately returns metadata rather than stored keys. */
  discoverPasskeyCredentials(
    request: PasskeyVaultDiscoveryRequest
  ): Promise<PasskeyVaultDiscoveryResult> {
    return this.exclusive(async () => {
      const data = this.requireData()
      const rpId = normalizePasskeyRpId(request.rpId)
      const allowCredentialIds = normalizePasskeyCredentialIds(request.allowCredentialIds)
      const matches = findPasskeyVaultMatches(data, rpId, allowCredentialIds)
      return {
        generation: this.generation,
        credentials: matches.map(({ login, passkey, credentialId }) => ({
          itemId: login.id,
          itemName: login.name,
          itemUpdatedAt: login.updatedAt,
          reprompt: login.reprompt,
          credentialId: Uint8Array.from(credentialId),
          rpId: passkey.rpId,
          userHandle: passkey.userHandle,
          userName: passkey.userName,
          userDisplayName: passkey.userDisplayName,
          discoverable: passkey.discoverable
        }))
      }
    })
  }

  /**
   * Returns one atomic unlocked-vault snapshot for a passkey-create picker. Read raw stored
   * logins rather than list summaries: protected summaries intentionally redact passkey counts.
   */
  discoverPasskeyCreationTargets(
    request: PasskeyVaultCreationTargetDiscoveryRequest
  ): Promise<PasskeyVaultCreationTargetDiscoveryResult> {
    return this.exclusive(async () => {
      const data = this.requireData()
      const rpId = normalizePasskeyRpId(request.rpId)
      let targetUri: string
      try {
        targetUri = validatePasskeyOrigin({ origin: request.origin, rpId }).origin
      } catch {
        throw new VaultError('INVALID_INPUT')
      }
      const targets: PasskeyVaultCreationTarget[] = []
      const matchBudget = createUriMatchBudget()
      for (const login of data.logins) {
        if (login.type !== 'login' || login.deletedAt !== null || login.archivedAt !== null) {
          continue
        }
        if (
          !loginUrisMatch(login.uris, targetUri, data.sync?.domainSettings ?? null, 0, matchBudget)
        ) {
          continue
        }
        // Bitwarden permits only one passkey per login item. Legacy/corrupt multi-passkey items
        // are excluded fail-closed instead of offering an ambiguous replacement target.
        if (login.passkeys.length > 1) continue
        const existingPasskeyCount: 0 | 1 = login.passkeys.length === 0 ? 0 : 1
        targets.push({
          itemId: login.id,
          itemName: login.name,
          itemUpdatedAt: login.updatedAt,
          reprompt: login.reprompt,
          existingPasskeyCount
        })
      }
      return { generation: this.generation, targets }
    })
  }

  /**
   * Creates and persists a software-authenticator credential without allowing its private key to
   * leave this service. The validator and userVerified value must come from a main-process
   * ceremony coordinator.
   */
  createPasskey(
    request: PasskeyVaultCreateRequest,
    validateAuthorization: PasskeyVaultAuthorizationValidator
  ): Promise<PasskeyVaultCreateResult> {
    return this.runAuthorizedOperation(validateAuthorization, async (authorize) => {
      const current = this.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      this.assertExpectedPasskeyGeneration(request.expectedGeneration)
      assertUuid(request.itemId)
      const next = cloneData(current)
      const login = this.findLogin(next, request.itemId)
      this.assertActiveLogin(login)
      if (login.type !== 'login' || login.archivedAt !== null) {
        throw new VaultError('INVALID_INPUT')
      }
      this.assertExpectedPasskeyRevision(login, request.expectedUpdatedAt)
      if (typeof request.replaceExisting !== 'boolean') throw new VaultError('INVALID_INPUT')
      if (login.passkeys.length > 1 || (login.passkeys.length === 1 && !request.replaceExisting)) {
        throw new VaultError('INVALID_INPUT')
      }
      assertPasskeyApproval(request.requireUserVerification, request.userVerified)
      const rpId = normalizePasskeyRpId(request.rpId)
      const excludeCredentialIds = normalizePasskeyCredentialIds(request.excludeCredentialIds)
      if (
        excludeCredentialIds.some((credentialId) =>
          activeVaultContainsCredentialId(current, rpId, credentialId)
        )
      ) {
        throw new VaultError('INVALID_INPUT')
      }

      authorize([login.id])
      const generation = this.generation
      const now = this.nowIso()
      const created = await createSoftwarePasskeyCredential(
        {
          rpId,
          rpName: request.rpName,
          userHandle: request.userHandle,
          userName: request.userName,
          userDisplayName: request.userDisplayName,
          discoverable: request.discoverable,
          userVerified: request.userVerified,
          userPresent: true
        },
        {
          uuid: () => this.validatedNewId(),
          now: () => new Date(now)
        }
      )
      if (generation !== this.generation) throw new VaultError('LOCKED')
      const credentialId = Buffer.from(created.credentialId)
      if (activeVaultContainsCredentialId(current, rpId, credentialId)) {
        throw new VaultError('INVALID_INPUT')
      }

      login.passkeys = [created.credential]
      if (login.username.length === 0) login.username = created.credential.userName ?? ''
      login.updatedAt = now
      next.updatedAt = now
      await this.persist(next)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      this.data = next
      return {
        item: toView(login),
        generation,
        credentialId: Uint8Array.from(created.credentialId),
        attestationObject: Uint8Array.from(created.attestationObject),
        authenticatorData: Uint8Array.from(created.authenticatorData),
        publicKey: Uint8Array.from(created.publicKey),
        publicKeyAlgorithm: created.publicKeyAlgorithm
      }
    })
  }

  /** Signs one assertion and atomically commits an enabled signature counter. */
  getPasskeyAssertion(
    request: PasskeyVaultAssertionRequest,
    validateAuthorization: PasskeyVaultAuthorizationValidator
  ): Promise<PasskeyVaultAssertionResult> {
    return this.runAuthorizedOperation(validateAuthorization, async (authorize) => {
      const current = this.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      this.assertExpectedPasskeyGeneration(request.expectedGeneration)
      assertUuid(request.itemId)
      const rpId = normalizePasskeyRpId(request.rpId)
      const requestedCredentialId = normalizePasskeyCredentialId(request.credentialId)
      const allowCredentialIds = normalizePasskeyCredentialIds(request.allowCredentialIds)
      const matches = findPasskeyVaultMatches(current, rpId, allowCredentialIds)
      const selected = matches.filter(
        (match) =>
          match.login.id === request.itemId && match.credentialId.equals(requestedCredentialId)
      )
      if (selected.length === 0) throw new VaultError('NOT_FOUND')
      if (selected.length !== 1) throw new VaultError('INVALID_INPUT')
      const match = selected[0]!
      this.assertExpectedPasskeyRevision(match.login, request.expectedUpdatedAt)
      assertPasskeyApproval(request.requireUserVerification, request.userVerified)

      authorize([match.login.id])
      const generation = this.generation
      const assertion = await createSoftwarePasskeyAssertion({
        credential: match.passkey,
        rpId,
        clientDataHash: request.clientDataHash,
        userVerified: request.userVerified,
        userPresent: true
      })
      if (generation !== this.generation) throw new VaultError('LOCKED')
      if (assertion.counter !== match.passkey.counter) {
        const next = cloneData(current)
        const nextLogin = this.findLogin(next, match.login.id)
        const nextPasskey = nextLogin.passkeys[match.passkeyIndex]
        if (
          nextPasskey === undefined ||
          nextPasskey.credentialId !== match.passkey.credentialId ||
          nextPasskey.counter !== match.passkey.counter
        ) {
          throw new VaultError('LOCKED')
        }
        const now = this.nowIso()
        nextPasskey.counter = assertion.counter
        nextLogin.updatedAt = now
        next.updatedAt = now
        await this.persist(next)
        if (generation !== this.generation) throw new VaultError('LOCKED')
        this.data = next
      }
      return {
        itemId: match.login.id,
        generation,
        credentialId: Uint8Array.from(assertion.credentialId),
        userHandle: assertion.userHandle === null ? null : Uint8Array.from(assertion.userHandle),
        authenticatorData: Uint8Array.from(assertion.authenticatorData),
        signature: Uint8Array.from(assertion.signature),
        counter: assertion.counter,
        didPersistCounter: assertion.counter !== match.passkey.counter
      }
    })
  }

  deleteLogin(request: LoginIdRequest): Promise<void> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      login.deletedAt = now
      login.updatedAt = now
    })
  }

  deleteLogins(request: LoginBatchRequest): Promise<number> {
    return this.mutate((data, now) => {
      const logins = this.resolveLoginBatch(data, request, (login) => this.assertActiveLogin(login))
      for (const login of logins) {
        login.deletedAt = now
        login.updatedAt = now
      }
      return logins.length
    })
  }

  restoreLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const login = this.findLogin(data, request.id)
      if (login.deletedAt === null) throw new VaultError('INVALID_INPUT')
      login.deletedAt = null
      login.updatedAt = now
      return toView(login)
    })
  }

  restoreLogins(request: LoginBatchRequest): Promise<LoginSummary[]> {
    return this.mutate((data, now) => {
      const logins = this.resolveLoginBatch(data, request, (login) => {
        if (login.deletedAt === null) throw new VaultError('INVALID_INPUT')
      })
      return logins.map((login) => {
        login.deletedAt = null
        login.updatedAt = now
        return toSummary(login)
      })
    })
  }

  deleteLoginPermanently(request: LoginIdRequest): Promise<void> {
    return this.mutate((data) => {
      assertNoPendingLoginImport(data.sync)
      assertUuid(request.id)
      const login = this.findLogin(data, request.id)
      if (login.deletedAt === null) throw new VaultError('INVALID_INPUT')
      recordSyncDeletion(data.sync, 'login', request.id)
      data.logins = data.logins.filter((candidate) => candidate.id !== request.id)
    })
  }

  deleteLoginsPermanently(request: LoginBatchRequest): Promise<number> {
    return this.mutate((data) => {
      assertNoPendingLoginImport(data.sync)
      const logins = this.resolveLoginBatch(data, request, (login) => {
        if (login.deletedAt === null) throw new VaultError('INVALID_INPUT')
      })
      for (const login of logins) recordSyncDeletion(data.sync, 'login', login.id)
      const deletedIds = new Set(logins.map((login) => login.id))
      data.logins = data.logins.filter((login) => !deletedIds.has(login.id))
      return logins.length
    })
  }

  emptyTrash(): Promise<number> {
    return this.mutate((data) => {
      assertNoPendingLoginImport(data.sync)
      const deleted = data.logins.filter((login) => login.deletedAt !== null)
      for (const login of deleted) recordSyncDeletion(data.sync, 'login', login.id)
      const deletedIds = new Set(deleted.map((login) => login.id))
      data.logins = data.logins.filter((login) => !deletedIds.has(login.id))
      return deleted.length
    })
  }

  setLoginFavorite(request: LoginFavoriteRequest): Promise<LoginSummary> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      if (typeof request.favorite !== 'boolean') throw new VaultError('INVALID_INPUT')
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      login.favorite = request.favorite
      login.updatedAt = now
      return toSummary(login)
    })
  }

  moveLogin(request: LoginMoveRequest): Promise<LoginSummary> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      login.folderId = this.normalizeFolderId(data, request.folderId)
      login.updatedAt = now
      return toSummary(login)
    })
  }

  moveLogins(request: LoginMoveManyRequest): Promise<LoginSummary[]> {
    return this.mutate((data, now) => {
      if (
        !Array.isArray(request.ids) ||
        request.ids.length === 0 ||
        request.ids.length > MAX_LOGIN_MOVE_MANY_IDS
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      request.ids.forEach(assertUuid)
      if (new Set(request.ids).size !== request.ids.length) {
        throw new VaultError('INVALID_INPUT')
      }

      const folderId = this.normalizeFolderId(data, request.folderId)
      const logins = request.ids.map((id) => this.findLogin(data, id))
      logins.forEach((login) => this.assertActiveLogin(login))
      return logins.map((login) => {
        login.folderId = folderId
        login.updatedAt = now
        return toSummary(login)
      })
    })
  }

  revealPassword(request: LoginIdRequest): Promise<string> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      this.assertActiveLogin(login)
      assertSecretField(login.type, 'password')
      return login.password
    })
  }

  revealEditorSecrets(request: EditorSecretsRequest): Promise<EditorSecretsView> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      this.assertActiveLogin(login)
      if (request.expectedUpdatedAt !== login.updatedAt) throw new VaultError('INVALID_INPUT')

      const fields: EditorSecretsView['fields'] = {}
      for (const field of EDITOR_SECRET_FIELDS_BY_TYPE[login.type]) {
        Object.assign(fields, { [field]: login[field] })
      }
      const customFields = login.customFields.flatMap((field, index) =>
        field.type === 'hidden'
          ? [
              {
                source: {
                  index,
                  name: field.name,
                  type: field.type,
                  linkedId: field.linkedId
                },
                value: field.value
              }
            ]
          : []
      )
      return { fields, customFields }
    })
  }

  revealSecret(request: ItemFieldRequest): Promise<string> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      this.assertActiveLogin(login)
      assertSecretField(login.type, request.field as VaultSecretField)
      return login[request.field] as string
    })
  }

  revealCustomField(request: CustomFieldRequest): Promise<string> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      this.assertActiveLogin(login)
      if (request.expectedUpdatedAt !== login.updatedAt) throw new VaultError('INVALID_INPUT')
      const field = customFieldFromSource(login, request.source)
      if (field.type !== 'hidden') throw new VaultError('INVALID_INPUT')
      return field.value
    })
  }

  copyPassword(request: LoginIdRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      assertSecretField(login.type, 'password')
      await this.platform.copyText(login.password)
    })
  }

  getTotp(request: LoginIdRequest): Promise<TotpCodeView> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      this.assertActiveLogin(login)
      if (login.type !== 'login' || !login.totp) throw new VaultError('INVALID_INPUT')
      return generateTotp(login.totp, this.now())
    })
  }

  copyTotp(request: LoginIdRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      if (login.type !== 'login' || !login.totp) throw new VaultError('INVALID_INPUT')
      await this.platform.copyText(generateTotp(login.totp, this.now()).code)
    })
  }

  copyField(request: ItemFieldRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      assertCopyField(login.type, request.field)
      const value =
        request.field === 'uri'
          ? loginUriAt(login, request.uriIndex)
          : request.field === 'cardExpiration'
            ? [login.expMonth, login.expYear].filter(Boolean).join(' / ')
            : login[request.field]
      if (typeof value !== 'string' || value.length === 0) throw new VaultError('INVALID_INPUT')
      await this.platform.copyText(value)
    })
  }

  copyCustomField(request: CustomFieldRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      if (request.expectedUpdatedAt !== login.updatedAt) throw new VaultError('INVALID_INPUT')
      const value = customFieldValue(login, customFieldFromSource(login, request.source))
      if (!value) throw new VaultError('INVALID_INPUT')
      await this.platform.copyText(value)
    })
  }

  copyUsername(request: LoginIdRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      assertCopyField(login.type, 'username')
      await this.platform.copyText(login.username)
    })
  }

  openLoginUri(request: LoginOpenUriRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      assertCopyField(login.type, 'uri')
      const selectedUri = loginUriAt(login, request.uriIndex)
      let url: URL
      try {
        url = new URL(selectedUri)
      } catch {
        throw new VaultError('INVALID_URL')
      }
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        throw new VaultError('INVALID_URL')
      }
      await this.platform.openExternal(url.toString())
    })
  }

  async getWebsiteIcon(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<string | null> {
    const iconUrl = (() => {
      assertUuid(request.id)
      const data = this.requireFastReadData()
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      if (
        login.reprompt === 1 &&
        !validateAuthorization?.([login.id], { generation: this.generation })
      ) {
        throw new VaultError('REPROMPT_REQUIRED')
      }
      if (login.type !== 'login' || !login.uri || !data.sync) return null
      const hostname = parseWebsiteHostname(login.uri)
      return hostname ? resolveWebsiteIconUrl(data.sync.serverUrl, hostname) : null
    })()
    if (!iconUrl) return null

    const cacheKey = iconUrl.toString()
    if (this.websiteIconCache.has(cacheKey)) return this.websiteIconCache.get(cacheKey) ?? null
    const existingRequest = this.websiteIconRequests.get(cacheKey)
    if (existingRequest) return existingRequest

    const generation = this.generation
    const pendingRequest = fetchWebsiteIconDataUrl(iconUrl, this.fetch)
      .then((dataUrl) => {
        if (generation !== this.generation) return null
        if (this.websiteIconCache.size >= 128) {
          const oldestKey = this.websiteIconCache.keys().next().value
          if (oldestKey) this.websiteIconCache.delete(oldestKey)
        }
        this.websiteIconCache.set(cacheKey, dataUrl)
        return dataUrl
      })
      .finally(() => {
        if (this.websiteIconRequests.get(cacheKey) === pendingRequest) {
          this.websiteIconRequests.delete(cacheKey)
        }
      })
    this.websiteIconRequests.set(cacheKey, pendingRequest)
    return pendingRequest
  }

  private async currentSyncStatus(checkConnection: boolean): Promise<SyncStatus> {
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

  private baseSyncStatus(sync: PersistedSyncData, state: SyncStatus['state']): SyncStatus {
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

  private normalizeSyncServerUrl(value: unknown): string {
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

  private normalizeTwoFactor(
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

  private async authenticateSyncWithWebAuthnRetry(
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

  private normalizeNewDeviceOtp(value: string | undefined): string | undefined {
    if (value === undefined) return undefined
    const normalized = value.trim()
    if (normalized.length === 0 || normalized.length > MAX_TWO_FACTOR_CODE_LENGTH) {
      throw new VaultError('INVALID_INPUT')
    }
    return normalized
  }

  private getOrCreateSyncClient(sync: PersistedSyncData): BitwardenSyncClient {
    if (this.sessionDeauthorizationInProgress) throw new VaultError('SYNC_FAILED')
    this.syncClient ??= this.createSyncClient(sync)
    return this.syncClient
  }

  private requireSyncData(): PersistedSyncData {
    const sync = this.requireData().sync
    if (!sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    return sync
  }

  private masterPasswordChangeAccountFingerprint(sync: PersistedSyncData): string {
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

  private assertMasterPasswordChangeAccount(data: VaultData): void {
    const journal = data.masterPasswordChange
    if (!journal) return
    if (
      !data.sync ||
      journal.accountFingerprint !== this.masterPasswordChangeAccountFingerprint(data.sync)
    ) {
      throw new VaultError('CORRUPT_VAULT', 'CORRUPT_VAULT:password-change-account')
    }
  }

  private async proveRemotePassword(
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

  private assertAccountWebAuthnOperationCurrent(
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

  private finishAccountWebAuthnOperation(
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

  private releaseAccountWebAuthnOperation(lease: AccountWebAuthnOperationLease): Promise<void> {
    return this.exclusive(async () => {
      this.accountSecurityAborts.delete(lease.abort)
    })
  }

  private throwAccountWebAuthnOperationError(
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

  private startSyncOperation(): AbortController {
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

  private startAttachmentOperation(operationId: string): {
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

  private finishAttachmentOperation(operation: {
    operationId: string
    abort: AbortController
  }): void {
    if (this.activeAttachmentOperation?.operationId === operation.operationId) {
      this.activeAttachmentOperation = null
    }
    this.finishSyncOperation(operation.abort)
  }

  private commitAttachmentOperation(operation: { operationId: string; committed: boolean }): void {
    if (this.activeAttachmentOperation?.operationId === operation.operationId) {
      operation.committed = true
    }
  }

  private finishSyncOperation(abort: AbortController): void {
    if (this.syncAbort === abort) this.syncAbort = null
    this.syncInProgress = false
  }

  private abortNotificationTokenLeases(): void {
    for (const abort of this.notificationTokenAborts) abort.abort()
    this.notificationTokenAborts.clear()
  }

  private abortAccountSecurityRequests(): void {
    for (const abort of this.accountSecurityAborts) abort.abort()
    this.accountSecurityAborts.clear()
    for (const sessionId of this.authenticatorSetupSessions.keys()) {
      this.deleteAuthenticatorSetupSession(sessionId)
    }
    for (const sessionId of this.emailTwoFactorSetupSessions.keys()) {
      this.deleteEmailTwoFactorSetupSession(sessionId)
    }
  }

  private abortNativeAttachmentBackups(): void {
    for (const abort of this.nativeAttachmentBackupAborts) abort.abort()
    this.nativeAttachmentBackupAborts.clear()
  }

  private abortNativeAttachmentRestores(): void {
    for (const abort of this.nativeAttachmentRestoreAborts) abort.abort()
    this.nativeAttachmentRestoreAborts.clear()
  }

  private async recoverNativeAttachmentRestoreAfterUnlock(
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

  private async finishMasterPasswordChange(
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

  private evictExpiredAuthenticatorSetupSessions(): void {
    const now = this.now().getTime()
    for (const [sessionId, session] of this.authenticatorSetupSessions) {
      if (session.expiresAt <= now) this.deleteAuthenticatorSetupSession(sessionId)
    }
  }

  private requireAuthenticatorSetupSession(sessionId: string): AuthenticatorSetupSession {
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

  private deleteAuthenticatorSetupSession(sessionId: string): void {
    const session = this.authenticatorSetupSessions.get(sessionId)
    if (!session) return
    session.key = ''
    session.userVerificationToken = null
    this.authenticatorSetupSessions.delete(sessionId)
  }

  private evictExpiredEmailTwoFactorSetupSessions(): void {
    const now = this.now().getTime()
    for (const [sessionId, session] of this.emailTwoFactorSetupSessions) {
      if (session.expiresAt <= now) this.deleteEmailTwoFactorSetupSession(sessionId)
    }
  }

  private requireEmailTwoFactorSetupSession(
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

  private deleteEmailTwoFactorSetupSession(sessionId: string): void {
    const session = this.emailTwoFactorSetupSessions.get(sessionId)
    if (!session) return
    session.userVerificationToken = null
    session.email = null
    this.emailTwoFactorSetupSessions.delete(sessionId)
  }

  private validateEmailTwoFactorSetupPassword(
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

  private throwEmailTwoFactorSetupError(
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

  private mapSyncError(error: unknown): VaultError {
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
      if (error.code === 'AUTH_REQUIRED' || error.code === 'TWO_FACTOR_REQUIRED') {
        this.recordSyncError('SYNC_AUTH_REQUIRED')
        return new VaultError('SYNC_AUTH_REQUIRED')
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

  private recordSyncError(
    code: import('../shared/vault-contract').SyncErrorCode,
    detail?: import('../shared/vault-contract').SyncInvalidResponseStage
  ): void {
    this.syncLastError = code
    this.syncLastErrorAt = this.nowIso()
    this.syncLastErrorDetail = code === 'SYNC_INVALID_RESPONSE' ? (detail ?? null) : null
  }

  private mapAttachmentError(error: unknown, operation?: { canceledByUser: boolean }): VaultError {
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

  private attachmentMutationContext(
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

  private assertAttachmentAuthorized(
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

  private reportAttachmentProgress(
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

  private async persistCurrentClientState(): Promise<void> {
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

  private async persistAttachmentMutation(
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

  private async restorePreDispatchPurge(original: VaultData): Promise<void> {
    const restored = cloneData(original)
    restored.updatedAt = this.nowIso()
    await this.persist(restored)
    this.data = restored
  }

  private async reconcilePersonalVaultPurge(
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

  private async finalizePersonalVaultPurge(
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

  private async performSync(
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

  private async fetchSharedSnapshot(client: BitwardenSyncClient): Promise<{
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

  private async resumePendingLoginMutation(
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

  private localSyncSnapshot(data: VaultData): SyncSnapshot {
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

  private remoteSyncSnapshot(
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

  private reconcileServerAuthoritativeAttachments(
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

  private syncMetadata(sync: PersistedSyncData): SyncMetadata {
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

  private loginImportCandidate(
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

  private supportsLoginImport(client: BitwardenSyncClient): boolean {
    return (
      client.prepareLoginImport !== undefined &&
      client.executePreparedLoginImport !== undefined &&
      client.reconcileLoginImportMarkers !== undefined &&
      client.discardPreparedLoginImport !== undefined
    )
  }

  private async executeLoginImportBatch(
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

  private async reconcilePendingLoginImport(
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

  private bulkRemoteLoginCandidate(
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

  private supportsBulkRemoteLoginMutation(
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

  private async executeBulkRemoteLoginMutation(
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

  private bulkRemoteLoginMutationApplied(
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

  private async executeSyncAction(
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

  private resolveFolderReference(
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

  private createLocalFolder(data: VaultData, name: string): FolderView {
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

  private deleteLocalFolder(data: VaultData, id: string): void {
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

  private appendPortableSnapshot(
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

  private startNativeAttachmentRestoreOperation(client: BitwardenSyncClient): {
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

  private finishNativeAttachmentRestoreOperation(operation: { abort: AbortController }): void {
    this.nativeAttachmentRestoreAborts.delete(operation.abort)
    this.finishSyncOperation(operation.abort)
  }

  private assertNativeAttachmentRestoreLease(operation: {
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

  private nativeAttachmentRestoreAccountFingerprint(
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

  private requireBoundNativeAttachmentRestore(
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

  private nativeAttachmentRestoreSummary(
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

  private applyNativeAttachmentRestoreRemoteSnapshot(
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

  private async persistFailedNativeAttachmentRestoreAttempt(
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

  private async nativeAttachmentRestoreCandidateMatches(
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

  private createLocalLogin(
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

  private sharedLoginFromRemote(source: BitwardenOrganizationCipher): StoredSharedLogin {
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

  private updateLocalLogin(
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

  private remoteDraft(login: SyncLogin, folderId: string | null): BitwardenLoginDraft {
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

  private async updateRemoteLogin(
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

  private useLogin<T>(
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

  private mutate<T>(mutation: (data: VaultData, now: string) => T): Promise<T> {
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

  private async persist(data: VaultData): Promise<void> {
    if (!this.key || !this.salt) throw new VaultError('LOCKED')
    // Never persist data the read path would reject: a write-time bug must fail the current
    // operation loudly instead of locking the user out of the vault at the next unlock.
    parseVaultData(data)
    await this.store.write(data, this.key, this.salt)
  }

  private requireData(): VaultData {
    if (!this.data || !this.key || !this.salt) throw new VaultError('LOCKED')
    return this.data
  }

  private requireFastReadData(): VaultData {
    if (this.fastReadsBlocked) throw new VaultError('LOCKED')
    return this.requireData()
  }

  private async currentStatus(): Promise<VaultStatus> {
    if (this.data && this.key && this.salt) return { state: 'unlocked' }
    return { state: (await this.store.exists()) ? 'locked' : 'uninitialized' }
  }

  private findFolder(data: VaultData, id: string): FolderView {
    const folder = data.folders.find((candidate) => candidate.id === id)
    if (!folder) throw new VaultError('NOT_FOUND')
    return folder
  }

  private findLogin(data: VaultData, id: string): StoredLogin {
    const login = data.logins.find((candidate) => candidate.id === id)
    if (!login) throw new VaultError('NOT_FOUND')
    return login
  }

  private resolveLoginBatch(
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

  private assertActiveLogin(login: StoredLogin): void {
    if (login.deletedAt !== null) throw new VaultError('INVALID_INPUT')
  }

  private assertExpectedPasskeyGeneration(value: unknown): asserts value is number {
    if (!Number.isSafeInteger(value) || (value as number) < 0) {
      throw new VaultError('INVALID_INPUT')
    }
    if (value !== this.generation) throw new VaultError('LOCKED')
  }

  private assertExpectedPasskeyRevision(
    login: StoredLogin,
    value: unknown
  ): asserts value is string {
    if (typeof value !== 'string' || value !== login.updatedAt) {
      throw new VaultError('INVALID_INPUT')
    }
  }

  private normalizeFolderId(data: VaultData, folderId: unknown): string | null {
    if (folderId === undefined || folderId === null) return null
    assertUuid(folderId)
    this.findFolder(data, folderId)
    return folderId
  }

  private assertUniqueFolderName(data: VaultData, name: string, excludedId?: string): void {
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

  private uniqueImportedFolderName(data: VaultData, requestedName: string): string {
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

  private async assertMasterPassword(candidateValue: unknown): Promise<void> {
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

  private invalidatePinUnlockCapability(): void {
    this.pinLifecycleEpoch += 1
    this.pinUnlockCapability?.dispose()
    this.pinUnlockCapability = null
  }

  private mapPinUnlockError(error: PinUnlockError): VaultError {
    if (error.code === 'INVALID_INPUT') return new VaultError('INVALID_INPUT')
    if (error.code === 'INVALID_PIN') return new VaultError('INVALID_PIN')
    if (error.code === 'RATE_LIMITED') return new VaultError('RATE_LIMITED')
    return new VaultError('PIN_DISABLED')
  }

  private validatedNewId(): string {
    const id = this.createId()
    assertUuid(id)
    return id
  }

  private nowIso(): string {
    const value = this.now()
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw new VaultError('INTERNAL_ERROR')
    }
    return value.toISOString()
  }

  private async exclusive<T>(operation: () => Promise<T>): Promise<T> {
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
