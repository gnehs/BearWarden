import type {
  EditorSecretsRequest,
  EditorSecretsView,
  CredentialGeneratorRequest,
  CredentialGeneratorResult,
  CustomFieldRequest,
  ItemFieldRequest,
  GeneratedCredentialCopyRequest,
  GeneratorHistoryEntry,
  GeneratorHistoryLocator,
  LoginCreateRequest,
  LoginAuthorizeRequest,
  LoginAuthorizeManyRequest,
  LoginBatchRequest,
  LoginFavoriteRequest,
  LoginIdRequest,
  LoginOpenUriRequest,
  PasskeyDeleteRequest,
  LoginMoveRequest,
  LoginMoveManyRequest,
  LoginSummary,
  LoginUpdateRequest,
  LoginView,
  SharedLoginCreateRequest,
  SharedLoginUpdateRequest,
  SharedLoginView,
  VaultPasswordHistoryEntry,
  TotpCodeView,
  SendCreateRequest,
  SendFileCreateRequest,
  SendFileCreateResult,
  SendFileDownloadRequest,
  SendFileDownloadResult,
  SendIdRequest,
  SendUpdateRequest,
  SendView,
  FolderCreateRequest,
  FolderDeleteRequest,
  FolderReorderRequest,
  FolderReparentRequest,
  FolderUpdateRequest,
  FolderView,
  VaultHealthExposedReport,
  VaultHealthAccountBreachReport,
  VaultHealthAccountBreachRequest,
  VaultHealthReport,
  LoginListRequest,
  LoginPrefetchRequest,
  OrganizationView,
  CollectionView,
  SharedLoginListRequest,
  SharedLoginSummary,
  EmergencyAccessView,
  PasswordHistoryEntryRequest,
  PasswordHistoryRestoreRequest,
  VaultPasswordHistoryView,
  AttachmentProgressEvent,
  CardCoverPreviewResult,
  AttachmentCancelRequest,
  AttachmentCancelResult,
  AttachmentDeleteRequest,
  AttachmentDeleteResult,
  AttachmentDownloadRequest,
  AttachmentDownloadResult,
  AttachmentFixLegacyRequest,
  AttachmentFixLegacyResult,
  AttachmentPreviewRequest,
  AttachmentPreviewResult,
  AttachmentUploadCardCoverRequest,
  AttachmentUploadRequest,
  AttachmentUploadResult,
  VaultImportResult,
  LoginApprovalPrompt,
  AccountSessionDeauthorizationRequest,
  LoginApprovalResponse,
  SyncStatus,
  EquivalentDomainSettingsUpdate,
  EquivalentDomainSettingsView,
  SyncConnectRequest,
  SyncEmailTwoFactorCodeRequest,
  SyncPurgePersonalVaultRequest,
  SyncPurgePersonalVaultResult,
  SyncResult,
  SyncUnlockRequest,
  VaultTimeoutPolicy,
  VaultStatus,
  PinUnlockStatus,
  AccountDevicesResult,
  AccountSecurityProfile
} from '../shared/vault-contract'
import type { SshKeyMaterial } from './ssh-key'
import type {
  AutofillAuthorizationValidator,
  AutofillCredentialConsumer,
  AutofillDiscoveryResult,
  AutofillExecutionRequest
} from './autofill'
import type {
  SshAgentVaultIdentity,
  SshAgentVaultSignRequest,
  SshAgentVaultSignResult,
  SshAgentVaultAuthorizationValidator,
  PasskeyVaultAuthorizationValidator,
  PasskeyVaultDiscoveryRequest,
  PasskeyVaultDiscoveryResult,
  PasskeyVaultCreationTargetDiscoveryResult,
  PasskeyVaultCreationTargetDiscoveryRequest,
  PasskeyVaultCreateRequest,
  PasskeyVaultCreateResult,
  PasskeyVaultAssertionRequest,
  PasskeyVaultAssertionResult,
  VaultData,
  ItemReadAuthorizationValidator,
  AttachmentAuthorizationValidator,
  VaultExportSnapshot,
  VaultNativeAttachmentBackupSource,
  VaultNativeAttachmentRestoreSummary,
  VaultMasterPasswordChangeStatus,
  VaultMasterPasswordChangeRequest,
  VaultMasterPasswordChangeResolutionRequest,
  VaultMasterPasswordChangeResolution,
  VaultPlatform,
  VaultServiceOptions
} from './vault/types'
import type { InactiveTwoFactorReport, TwoFactorDirectoryDataset } from './inactive-two-factor'
import type { PortableVaultSnapshot } from './vault-portability-codec'
import type { NativeAttachmentRestoreAttachmentKey } from './native-attachment-restore'
import type { NativeAttachmentBackupPreview } from './native-attachment-backup'
import type { BitwardenAttachmentByteSource } from './bitwarden-attachment-stream'
import type { BitwardenNotificationConnectionInfo } from './bitwarden-notifications'
import type { TouchIdUnlockMaterial } from './touch-id-unlock-capsule'
import { randomInt as nodeRandomInt, randomUUID } from 'node:crypto'
import { BitwardenDirectError } from './bitwarden-direct'
import type { EncryptedVaultStore } from './encrypted-vault-store'
import { cloneData } from './vault/vault-data-parsing'
import { VaultGeneratorService } from './vault/generator-service'
import { VaultSendService } from './vault/send-service'
import { VaultCore } from './vault/core'
import { cloneGeneratorHistory } from './vault/generator-history'
import { currentBitwardenPolicySet, assertSendMutationAllowed } from './vault/policy'
import { VaultSyncSession } from './vault/sync-session'
import { VaultFolders } from './vault/folders'
import { VaultHealth } from './vault/health'
import { VaultListings } from './vault/listings'
import { VaultPasswordHistory } from './vault/password-history-service'
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
import { VaultSyncService } from './vault/sync-service'
import { VaultMasterPasswordChange } from './vault/master-password-change-service'
import { VaultUnlock } from './vault/unlock'

export type {
  VaultAccountWebAuthnAssertionRequester,
  VaultAccountWebAuthnRegistrationRequester,
  VaultServiceOptions,
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

/**
 * The vault's stable public API. It builds one VaultCore, which owns the key material, committed
 * snapshot, generation and mutex, and composes the domain modules over it; every public method
 * delegates to the module that owns it.
 */
export class VaultService {
  private readonly core: VaultCore
  private readonly unlocking: VaultUnlock
  private readonly masterPasswordChange: VaultMasterPasswordChange
  private readonly sync: VaultSyncService
  private readonly accountSecurity: VaultAccountSecurity
  private readonly folders: VaultFolders
  private readonly listings: VaultListings
  private readonly items: VaultItems
  private readonly authorization: VaultItemAuthorization
  private readonly sharedItems: VaultSharedItems
  private readonly passwordHistory: VaultPasswordHistory
  private readonly attachments: VaultAttachments
  private readonly portability: VaultPortability
  private readonly health: VaultHealth
  private readonly integrations: VaultIntegrations
  private readonly websiteIcons: VaultWebsiteIcons
  private readonly sends: VaultSendService
  private readonly generator: VaultGeneratorService

  constructor(
    store: EncryptedVaultStore<unknown>,
    platform: VaultPlatform,
    options: VaultServiceOptions = {}
  ) {
    const fetchImpl = options.fetch ?? fetch
    const attachmentFiles = options.attachmentFiles ?? null
    const imageCache = options.imageCache ?? null
    const createId = options.createId ?? randomUUID
    const core = new VaultCore(store, { now: options.now ?? (() => new Date()), createId })
    const syncSession = new VaultSyncSession(
      core,
      options.createSyncClient ??
        (() => {
          throw new BitwardenDirectError('INVALID_RESPONSE')
        }),
      options.requestAccountWebAuthnAssertion ?? null
    )
    const pinUnlock = new VaultPinUnlockState()
    const syncEngine = new VaultSyncEngine(core, syncSession, pinUnlock)
    this.core = core
    this.health = new VaultHealth(core, syncSession, platform, fetchImpl)
    this.unlocking = new VaultUnlock(core, store, syncSession, pinUnlock)
    this.masterPasswordChange = new VaultMasterPasswordChange(core, syncSession, pinUnlock)
    this.sync = new VaultSyncService(core, syncSession, syncEngine, pinUnlock, this.health)
    this.accountSecurity = new VaultAccountSecurity(
      core,
      syncSession,
      this.health,
      platform,
      options.requestAccountWebAuthnRegistration ?? null
    )
    this.folders = new VaultFolders(core)
    this.listings = new VaultListings(core, syncSession)
    this.items = new VaultItems(core, platform)
    this.authorization = new VaultItemAuthorization(core)
    this.sharedItems = new VaultSharedItems(core, syncSession, platform)
    this.passwordHistory = new VaultPasswordHistory(core, platform)
    this.attachments = new VaultAttachments(core, syncSession, attachmentFiles, imageCache)
    this.portability = new VaultPortability(core, syncSession, syncEngine)
    this.integrations = new VaultIntegrations(core, this.authorization)
    this.websiteIcons = new VaultWebsiteIcons(core, fetchImpl, imageCache)
    this.sends = new VaultSendService({
      attachmentFiles,
      exclusive: (operation) => core.exclusive(operation),
      readData: () => core.requireData(),
      requireSyncData: () => syncSession.requireSyncData(),
      getSyncClient: (sync) => syncSession.getOrCreateSyncClient(sync),
      currentGeneration: () => core.generation,
      startSyncOperation: () => syncSession.startSyncOperation(),
      finishSyncOperation: (abort) => syncSession.finishSyncOperation(abort),
      commitData: (data, generation) => core.commit(data, generation),
      nowIso: () => core.nowIso(),
      clearSyncError: () => syncSession.clearSyncErrorState(),
      mapSyncError: (error) => syncSession.mapSyncError(error),
      copyText: (text) => platform.copyText(text),
      assertMutationAllowed: () => assertSendMutationAllowed(core.requireData())
    })
    this.generator = new VaultGeneratorService({
      now: core.now,
      createId,
      randomInt: options.randomInt ?? nodeRandomInt,
      copyText: (text) => platform.copyText(text),
      exclusive: (operation) => core.exclusive(operation),
      assertUnlocked: () => {
        core.requireData()
      },
      readPolicySet: () => currentBitwardenPolicySet(core.requireData()),
      readHistory: () => core.requireData().generatorHistory,
      commitHistory: async (history) => {
        const next = cloneData(core.requireData())
        next.generatorHistory = cloneGeneratorHistory(history)
        next.updatedAt = core.nowIso()
        await core.commit(next)
      }
    })
    core.registerResource({ clear: () => this.generator.clearRuntimeState() })
  }

  status(): Promise<VaultStatus> {
    return this.unlocking.status()
  }

  unlockedGeneration(): Promise<number> {
    return this.unlocking.unlockedGeneration()
  }

  runUnlockedOperation<T>(operation: (generation: number) => Promise<T>): Promise<T> {
    return this.unlocking.runUnlockedOperation(operation)
  }

  setup(masterPassword: string): Promise<VaultStatus> {
    return this.unlocking.setup(masterPassword)
  }

  unlock(masterPassword: string): Promise<VaultStatus> {
    return this.unlocking.unlock(masterPassword)
  }

  pinUnlockStatus(): PinUnlockStatus {
    return this.unlocking.pinUnlockStatus()
  }

  enablePinUnlock(request: { pin: string; masterPassword: string }): Promise<PinUnlockStatus> {
    return this.unlocking.enablePinUnlock(request)
  }

  disablePinUnlock(): PinUnlockStatus {
    return this.unlocking.disablePinUnlock()
  }

  exportTouchIdUnlockMaterial(masterPassword: string): Promise<TouchIdUnlockMaterial> {
    return this.unlocking.exportTouchIdUnlockMaterial(masterPassword)
  }

  unlockWithTouchIdMaterial(material: TouchIdUnlockMaterial): Promise<VaultStatus> {
    return this.unlocking.unlockWithTouchIdMaterial(material)
  }

  unlockWithPin(request: { pin: string }): Promise<VaultStatus> {
    return this.unlocking.unlockWithPin(request)
  }

  lock(): Promise<VaultStatus> {
    return this.unlocking.lock()
  }

  dispose(): void {
    return this.unlocking.dispose()
  }

  constrainVaultTimeoutPolicy(requested: VaultTimeoutPolicy): Promise<VaultTimeoutPolicy> {
    return this.unlocking.constrainVaultTimeoutPolicy(requested)
  }

  masterPasswordChangeStatus(): Promise<VaultMasterPasswordChangeStatus> {
    return this.masterPasswordChange.masterPasswordChangeStatus()
  }

  changeMasterPassword(request: VaultMasterPasswordChangeRequest): Promise<void> {
    return this.masterPasswordChange.changeMasterPassword(request)
  }

  resolveMasterPasswordChange(
    request: VaultMasterPasswordChangeResolutionRequest
  ): Promise<VaultMasterPasswordChangeResolution> {
    return this.masterPasswordChange.resolveMasterPasswordChange(request)
  }

  syncStatus(): Promise<SyncStatus> {
    return this.sync.syncStatus()
  }

  remoteLogoutSync(): Promise<SyncStatus> {
    return this.sync.remoteLogoutSync()
  }

  connectSync(request: SyncConnectRequest): Promise<SyncResult> {
    return this.sync.connectSync(request)
  }

  sendSyncEmailTwoFactorCode(request: SyncEmailTwoFactorCodeRequest): Promise<void> {
    return this.sync.sendSyncEmailTwoFactorCode(request)
  }

  resendSyncNewDeviceOtp(request: {
    serverUrl: string
    email: string
    masterPassword: string
  }): Promise<void> {
    return this.sync.resendSyncNewDeviceOtp(request)
  }

  unlockSync(request: SyncUnlockRequest): Promise<SyncStatus> {
    return this.sync.unlockSync(request)
  }

  unlockAndSync(request: SyncUnlockRequest): Promise<SyncResult> {
    return this.sync.unlockAndSync(request)
  }

  unlockSyncWithLocalPassword(masterPassword: string): Promise<SyncStatus> {
    return this.sync.unlockSyncWithLocalPassword(masterPassword)
  }

  syncNow(): Promise<SyncResult> {
    return this.sync.syncNow()
  }

  disconnectSync(): Promise<SyncStatus> {
    return this.sync.disconnectSync()
  }

  resolvePendingLoginImport(request: {
    masterPassword: string
    confirmRetry: true
  }): Promise<SyncStatus> {
    return this.sync.resolvePendingLoginImport(request)
  }

  purgePersonalVault(
    request: SyncPurgePersonalVaultRequest
  ): Promise<SyncPurgePersonalVaultResult> {
    return this.sync.purgePersonalVault(request)
  }

  getEquivalentDomainSettings(): Promise<EquivalentDomainSettingsView> {
    return this.sync.getEquivalentDomainSettings()
  }

  updateEquivalentDomainSettings(
    request: EquivalentDomainSettingsUpdate
  ): Promise<EquivalentDomainSettingsView> {
    return this.sync.updateEquivalentDomainSettings(request)
  }

  getAccountSecurityProfile(): Promise<AccountSecurityProfile> {
    return this.accountSecurity.getAccountSecurityProfile()
  }

  updateAccountProfileName(request: {
    name: string
    expectedName: string
  }): Promise<AccountSecurityProfile> {
    return this.accountSecurity.updateAccountProfileName(request)
  }

  updateAccountAvatarColor(request: {
    avatarColor: string | null
    expectedAvatarColor: string | null
  }): Promise<AccountSecurityProfile> {
    return this.accountSecurity.updateAccountAvatarColor(request)
  }

  getAccountDevices(): Promise<AccountDevicesResult> {
    return this.accountSecurity.getAccountDevices()
  }

  prepareLoginApproval(requestId: string): Promise<LoginApprovalPrompt | null> {
    return this.accountSecurity.prepareLoginApproval(requestId)
  }

  getPendingLoginApprovals(): Promise<LoginApprovalPrompt[]> {
    return this.accountSecurity.getPendingLoginApprovals()
  }

  respondLoginApproval(response: LoginApprovalResponse): Promise<void> {
    return this.accountSecurity.respondLoginApproval(response)
  }

  deauthorizeAllSessions(request: AccountSessionDeauthorizationRequest): Promise<SyncStatus> {
    return this.accountSecurity.deauthorizeAllSessions(request)
  }

  resendAccountVerificationEmail(): Promise<void> {
    return this.accountSecurity.resendAccountVerificationEmail()
  }

  copyAccountApiClientId(): Promise<void> {
    return this.accountSecurity.copyAccountApiClientId()
  }

  copyPersonalApiKey(request: {
    masterPassword: string
    rotate: boolean
    confirmRotation: boolean
  }): Promise<{ rotated: boolean; revisionDate: string }> {
    return this.accountSecurity.copyPersonalApiKey(request)
  }

  getTwoFactorStatus(): Promise<{ type: number; enabled: boolean }[]> {
    return this.accountSecurity.getTwoFactorStatus()
  }

  disableTwoFactorProvider(request: {
    type: 0 | 1 | 2 | 3 | 7
    masterPassword: string
    confirm: true
  }): Promise<void> {
    return this.accountSecurity.disableTwoFactorProvider(request)
  }

  copyTwoFactorRecoveryCode(request: { masterPassword: string }): Promise<void> {
    return this.accountSecurity.copyTwoFactorRecoveryCode(request)
  }

  beginAccountAuthenticatorSetup(request: { masterPassword: string }): Promise<{
    sessionId: string
    key: string
    requiresMasterPassword: boolean
    expiresAt: number
  }> {
    return this.accountSecurity.beginAccountAuthenticatorSetup(request)
  }

  copyAccountAuthenticatorKey(request: { sessionId: string }): Promise<void> {
    return this.accountSecurity.copyAccountAuthenticatorKey(request)
  }

  completeAccountAuthenticatorSetup(request: {
    sessionId: string
    token: string
    masterPassword?: string
  }): Promise<void> {
    return this.accountSecurity.completeAccountAuthenticatorSetup(request)
  }

  beginAccountEmailTwoFactorSetup(request: { masterPassword: string }): Promise<{
    sessionId: string
    requiresMasterPassword: boolean
    expiresAt: number
  }> {
    return this.accountSecurity.beginAccountEmailTwoFactorSetup(request)
  }

  sendAccountEmailTwoFactorSetup(request: {
    sessionId: string
    email: string
    masterPassword?: string
  }): Promise<void> {
    return this.accountSecurity.sendAccountEmailTwoFactorSetup(request)
  }

  completeAccountEmailTwoFactorSetup(request: {
    sessionId: string
    token: string
    masterPassword?: string
  }): Promise<void> {
    return this.accountSecurity.completeAccountEmailTwoFactorSetup(request)
  }

  listAccountWebAuthnKeys(request: {
    masterPassword: string
  }): Promise<{ id: number; name: string; migrated: boolean }[]> {
    return this.accountSecurity.listAccountWebAuthnKeys(request)
  }

  enrollAccountWebAuthnKey(request: { masterPassword: string; name: string }): Promise<void> {
    return this.accountSecurity.enrollAccountWebAuthnKey(request)
  }

  removeAccountWebAuthnKey(request: {
    id: number
    masterPassword: string
    confirm: true
  }): Promise<void> {
    return this.accountSecurity.removeAccountWebAuthnKey(request)
  }

  notificationConnectionInfo(): Promise<BitwardenNotificationConnectionInfo | null> {
    return this.accountSecurity.notificationConnectionInfo()
  }

  listFolders(): Promise<FolderView[]> {
    return this.folders.listFolders()
  }

  createFolder(request: FolderCreateRequest): Promise<FolderView> {
    return this.folders.createFolder(request)
  }

  updateFolder(request: FolderUpdateRequest): Promise<FolderView[]> {
    return this.folders.updateFolder(request)
  }

  reparentFolder(request: FolderReparentRequest): Promise<FolderView[]> {
    return this.folders.reparentFolder(request)
  }

  deleteFolder(request: FolderDeleteRequest): Promise<void> {
    return this.folders.deleteFolder(request)
  }

  reorderFolders(request: FolderReorderRequest): Promise<FolderView[]> {
    return this.folders.reorderFolders(request)
  }

  listLogins(request: LoginListRequest = {}): Promise<LoginSummary[]> {
    return this.listings.listLogins(request)
  }

  listOrganizations(): Promise<OrganizationView[]> {
    return this.listings.listOrganizations()
  }

  listCollections(organizationId?: string): Promise<CollectionView[]> {
    return this.listings.listCollections(organizationId)
  }

  listSharedLogins(request: SharedLoginListRequest = {}): Promise<SharedLoginSummary[]> {
    return this.listings.listSharedLogins(request)
  }

  getSharedLogin(request: LoginIdRequest): Promise<SharedLoginView> {
    return this.listings.getSharedLogin(request)
  }

  listEmergencyAccess(): Promise<EmergencyAccessView[]> {
    return this.listings.listEmergencyAccess()
  }

  getLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.listings.getLogin(request)
  }

  prefetchLogins(request: LoginPrefetchRequest): Promise<LoginView[]> {
    return this.listings.prefetchLogins(request)
  }

  createLogin(request: LoginCreateRequest): Promise<LoginView> {
    return this.items.createLogin(request)
  }

  cloneLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.items.cloneLogin(request)
  }

  archiveLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.items.archiveLogin(request)
  }

  archiveLogins(request: LoginBatchRequest): Promise<LoginSummary[]> {
    return this.items.archiveLogins(request)
  }

  unarchiveLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.items.unarchiveLogin(request)
  }

  unarchiveLogins(request: LoginBatchRequest): Promise<LoginSummary[]> {
    return this.items.unarchiveLogins(request)
  }

  updateLogin(request: LoginUpdateRequest): Promise<LoginView> {
    return this.items.updateLogin(request)
  }

  deletePasskey(request: PasskeyDeleteRequest): Promise<LoginView> {
    return this.items.deletePasskey(request)
  }

  deleteLogin(request: LoginIdRequest): Promise<void> {
    return this.items.deleteLogin(request)
  }

  deleteLogins(request: LoginBatchRequest): Promise<number> {
    return this.items.deleteLogins(request)
  }

  restoreLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.items.restoreLogin(request)
  }

  restoreLogins(request: LoginBatchRequest): Promise<LoginSummary[]> {
    return this.items.restoreLogins(request)
  }

  deleteLoginPermanently(request: LoginIdRequest): Promise<void> {
    return this.items.deleteLoginPermanently(request)
  }

  deleteLoginsPermanently(request: LoginBatchRequest): Promise<number> {
    return this.items.deleteLoginsPermanently(request)
  }

  emptyTrash(): Promise<number> {
    return this.items.emptyTrash()
  }

  setLoginFavorite(request: LoginFavoriteRequest): Promise<LoginSummary> {
    return this.items.setLoginFavorite(request)
  }

  moveLogin(request: LoginMoveRequest): Promise<LoginSummary> {
    return this.items.moveLogin(request)
  }

  moveLogins(request: LoginMoveManyRequest): Promise<LoginSummary[]> {
    return this.items.moveLogins(request)
  }

  revealPassword(request: LoginIdRequest): Promise<string> {
    return this.items.revealPassword(request)
  }

  revealEditorSecrets(request: EditorSecretsRequest): Promise<EditorSecretsView> {
    return this.items.revealEditorSecrets(request)
  }

  revealSecret(request: ItemFieldRequest): Promise<string> {
    return this.items.revealSecret(request)
  }

  revealCustomField(request: CustomFieldRequest): Promise<string> {
    return this.items.revealCustomField(request)
  }

  copyPassword(request: LoginIdRequest): Promise<void> {
    return this.items.copyPassword(request)
  }

  getTotp(request: LoginIdRequest): Promise<TotpCodeView> {
    return this.items.getTotp(request)
  }

  copyTotp(request: LoginIdRequest): Promise<void> {
    return this.items.copyTotp(request)
  }

  copyField(request: ItemFieldRequest): Promise<void> {
    return this.items.copyField(request)
  }

  copyCustomField(request: CustomFieldRequest): Promise<void> {
    return this.items.copyCustomField(request)
  }

  copyUsername(request: LoginIdRequest): Promise<void> {
    return this.items.copyUsername(request)
  }

  openLoginUri(request: LoginOpenUriRequest): Promise<void> {
    return this.items.openLoginUri(request)
  }

  runAuthorizedOperation<T>(
    validate: (ids: readonly string[], state: { generation: number }) => boolean,
    operation: (authorize: (ids: readonly string[]) => void) => Promise<T>
  ): Promise<T> {
    return this.authorization.runAuthorizedOperation(validate, operation)
  }

  authorizeLogin(request: LoginAuthorizeRequest): Promise<number> {
    return this.authorization.authorizeLogin(request)
  }

  authorizeLogins(request: LoginAuthorizeManyRequest): Promise<number> {
    return this.authorization.authorizeLogins(request)
  }

  createSharedLogin(request: SharedLoginCreateRequest): Promise<SharedLoginView> {
    return this.sharedItems.createSharedLogin(request)
  }

  revealSharedSecret(request: ItemFieldRequest): Promise<string> {
    return this.sharedItems.revealSharedSecret(request)
  }

  revealSharedEditorSecrets(request: EditorSecretsRequest): Promise<EditorSecretsView> {
    return this.sharedItems.revealSharedEditorSecrets(request)
  }

  updateSharedLogin(request: SharedLoginUpdateRequest): Promise<SharedLoginView> {
    return this.sharedItems.updateSharedLogin(request)
  }

  copySharedField(request: ItemFieldRequest): Promise<void> {
    return this.sharedItems.copySharedField(request)
  }

  revealSharedCustomField(request: CustomFieldRequest): Promise<string> {
    return this.sharedItems.revealSharedCustomField(request)
  }

  copySharedCustomField(request: CustomFieldRequest): Promise<void> {
    return this.sharedItems.copySharedCustomField(request)
  }

  getSharedTotp(request: LoginIdRequest): Promise<TotpCodeView> {
    return this.sharedItems.getSharedTotp(request)
  }

  copySharedTotp(request: LoginIdRequest): Promise<void> {
    return this.sharedItems.copySharedTotp(request)
  }

  openSharedLoginUri(request: LoginOpenUriRequest): Promise<void> {
    return this.sharedItems.openSharedLoginUri(request)
  }

  getPasswordHistory(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<VaultPasswordHistoryEntry[]> {
    return this.passwordHistory.getPasswordHistory(request, validateAuthorization)
  }

  getPasswordHistoryView(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<VaultPasswordHistoryView> {
    return this.passwordHistory.getPasswordHistoryView(request, validateAuthorization)
  }

  revealPasswordHistory(
    request: PasswordHistoryEntryRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<string> {
    return this.passwordHistory.revealPasswordHistory(request, validateAuthorization)
  }

  copyPasswordHistory(
    request: PasswordHistoryEntryRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<void> {
    return this.passwordHistory.copyPasswordHistory(request, validateAuthorization)
  }

  restorePasswordHistory(request: PasswordHistoryRestoreRequest): Promise<LoginView> {
    return this.passwordHistory.restorePasswordHistory(request)
  }

  downloadAttachment(
    request: AttachmentDownloadRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentDownloadResult> {
    return this.attachments.downloadAttachment(request, reportProgress, validateAuthorization)
  }

  getCardCoverPreview(
    request: LoginIdRequest,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<CardCoverPreviewResult | null> {
    return this.attachments.getCardCoverPreview(request, validateAuthorization)
  }

  previewAttachment(
    request: AttachmentPreviewRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentPreviewResult> {
    return this.attachments.previewAttachment(request, reportProgress, validateAuthorization)
  }

  uploadAttachment(
    request: AttachmentUploadRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentUploadResult> {
    return this.attachments.uploadAttachment(request, reportProgress, validateAuthorization)
  }

  uploadCardCoverAttachment(
    request: AttachmentUploadCardCoverRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentUploadResult> {
    return this.attachments.uploadCardCoverAttachment(
      request,
      reportProgress,
      validateAuthorization
    )
  }

  uploadCardCoverFileAttachment(
    request: AttachmentUploadRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentUploadResult> {
    return this.attachments.uploadCardCoverFileAttachment(
      request,
      reportProgress,
      validateAuthorization
    )
  }

  deleteAttachment(
    request: AttachmentDeleteRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentDeleteResult> {
    return this.attachments.deleteAttachment(request, reportProgress, validateAuthorization)
  }

  fixLegacyAttachment(
    request: AttachmentFixLegacyRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentFixLegacyResult> {
    return this.attachments.fixLegacyAttachment(request, reportProgress, validateAuthorization)
  }

  cancelAttachmentOperation(request: AttachmentCancelRequest): AttachmentCancelResult {
    return this.attachments.cancelAttachmentOperation(request)
  }

  verifyPortabilityOwner(masterPassword: string): Promise<void> {
    return this.portability.verifyPortabilityOwner(masterPassword)
  }

  exportPortableSnapshot(masterPassword: string): Promise<VaultExportSnapshot> {
    return this.portability.exportPortableSnapshot(masterPassword)
  }

  createNativeAttachmentBackupSource(
    masterPassword: string,
    options: { includeLoginWireMetadata?: boolean } = {}
  ): Promise<VaultNativeAttachmentBackupSource> {
    return this.portability.createNativeAttachmentBackupSource(masterPassword, options)
  }

  nativeAttachmentRestoreStatus(): Promise<VaultNativeAttachmentRestoreSummary | null> {
    return this.portability.nativeAttachmentRestoreStatus()
  }

  clearCompletedNativeAttachmentRestore(archiveFingerprint: string): Promise<void> {
    return this.portability.clearCompletedNativeAttachmentRestore(archiveFingerprint)
  }

  beginNativeAttachmentRestore(
    preview: NativeAttachmentBackupPreview,
    masterPassword: string
  ): Promise<VaultNativeAttachmentRestoreSummary> {
    return this.portability.beginNativeAttachmentRestore(preview, masterPassword)
  }

  syncNativeAttachmentRestoreItems(
    archiveFingerprint: string
  ): Promise<VaultNativeAttachmentRestoreSummary> {
    return this.portability.syncNativeAttachmentRestoreItems(archiveFingerprint)
  }

  uploadNativeAttachmentRestoreEntry(
    archiveFingerprint: string,
    key: NativeAttachmentRestoreAttachmentKey,
    source: BitwardenAttachmentByteSource
  ): Promise<VaultNativeAttachmentRestoreSummary> {
    return this.portability.uploadNativeAttachmentRestoreEntry(archiveFingerprint, key, source)
  }

  reconcileNativeAttachmentRestoreEntry(
    archiveFingerprint: string,
    key: NativeAttachmentRestoreAttachmentKey
  ): Promise<{
    outcome: 'uploaded' | 'missing' | 'conflict'
    summary: VaultNativeAttachmentRestoreSummary
  }> {
    return this.portability.reconcileNativeAttachmentRestoreEntry(archiveFingerprint, key)
  }

  importPortableSnapshot(
    snapshot: PortableVaultSnapshot,
    skippedTrashItems: number,
    masterPassword: string
  ): Promise<Omit<VaultImportResult, 'canceled'>> {
    return this.portability.importPortableSnapshot(snapshot, skippedTrashItems, masterPassword)
  }

  getHealthReport(): Promise<VaultHealthReport> {
    return this.health.getHealthReport()
  }

  getInactiveTwoFactorReport(dataset: TwoFactorDirectoryDataset): Promise<InactiveTwoFactorReport> {
    return this.health.getInactiveTwoFactorReport(dataset)
  }

  getExposedPasswordReport(): Promise<VaultHealthExposedReport> {
    return this.health.getExposedPasswordReport()
  }

  cancelExposedPasswordReport(): boolean {
    return this.health.cancelExposedPasswordReport()
  }

  getAccountBreachReport(
    request: VaultHealthAccountBreachRequest
  ): Promise<VaultHealthAccountBreachReport> {
    return this.health.getAccountBreachReport(request)
  }

  cancelAccountBreachReport(): boolean {
    return this.health.cancelAccountBreachReport()
  }

  openHibpWebsite(): Promise<void> {
    return this.health.openHibpWebsite()
  }

  listSshAgentIdentities(): Promise<SshAgentVaultIdentity[]> {
    return this.integrations.listSshAgentIdentities()
  }

  signSshAgentRequest(
    request: SshAgentVaultSignRequest,
    validateAuthorization: SshAgentVaultAuthorizationValidator
  ): Promise<SshAgentVaultSignResult> {
    return this.integrations.signSshAgentRequest(request, validateAuthorization)
  }

  discoverAutofillCandidates(targetUrl: string): Promise<AutofillDiscoveryResult> {
    return this.integrations.discoverAutofillCandidates(targetUrl)
  }

  performAutofill(
    request: AutofillExecutionRequest,
    validateAuthorization: AutofillAuthorizationValidator,
    consume: AutofillCredentialConsumer
  ): Promise<void> {
    return this.integrations.performAutofill(request, validateAuthorization, consume)
  }

  discoverPasskeyCredentials(
    request: PasskeyVaultDiscoveryRequest
  ): Promise<PasskeyVaultDiscoveryResult> {
    return this.integrations.discoverPasskeyCredentials(request)
  }

  discoverPasskeyCreationTargets(
    request: PasskeyVaultCreationTargetDiscoveryRequest
  ): Promise<PasskeyVaultCreationTargetDiscoveryResult> {
    return this.integrations.discoverPasskeyCreationTargets(request)
  }

  createPasskey(
    request: PasskeyVaultCreateRequest,
    validateAuthorization: PasskeyVaultAuthorizationValidator
  ): Promise<PasskeyVaultCreateResult> {
    return this.integrations.createPasskey(request, validateAuthorization)
  }

  getPasskeyAssertion(
    request: PasskeyVaultAssertionRequest,
    validateAuthorization: PasskeyVaultAuthorizationValidator
  ): Promise<PasskeyVaultAssertionResult> {
    return this.integrations.getPasskeyAssertion(request, validateAuthorization)
  }

  getWebsiteIcon(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<string | null> {
    return this.websiteIcons.getWebsiteIcon(request, validateAuthorization)
  }

  listSends(): Promise<SendView[]> {
    return this.sends.list()
  }

  createSend(request: SendCreateRequest): Promise<SendView> {
    return this.sends.create(request)
  }

  createFileSend(request: SendFileCreateRequest): Promise<SendFileCreateResult> {
    return this.sends.createFile(request)
  }

  downloadFileSend(request: SendFileDownloadRequest): Promise<SendFileDownloadResult> {
    return this.sends.downloadFile(request)
  }

  updateSend(request: SendUpdateRequest): Promise<SendView> {
    return this.sends.update(request)
  }

  removeSendPassword(request: SendIdRequest): Promise<SendView> {
    return this.sends.removePassword(request)
  }

  deleteSend(request: SendIdRequest): Promise<void> {
    return this.sends.delete(request)
  }

  copySendLink(request: SendIdRequest): Promise<void> {
    return this.sends.copyLink(request)
  }

  generateCredential(request: CredentialGeneratorRequest): Promise<CredentialGeneratorResult> {
    return this.generator.generateCredential(request)
  }

  copyGeneratedCredential(request: GeneratedCredentialCopyRequest): Promise<void> {
    return this.generator.copyGeneratedCredential(request)
  }

  generateSshKey(): Promise<SshKeyMaterial> {
    return this.generator.generateSshKey()
  }

  generatorHistory(): Promise<GeneratorHistoryEntry[]> {
    return this.generator.history()
  }

  clearGeneratorHistory(): Promise<void> {
    return this.generator.clearHistory()
  }

  copyGeneratorHistory(request: GeneratorHistoryLocator): Promise<void> {
    return this.generator.copyHistory(request)
  }

  /**
   * Test-only view of the committed in-memory snapshot, for planting records the public API cannot
   * create and trapping reads of protected fields. Production code must not call it.
   */
  committedSnapshotForTesting(): VaultData | null {
    return this.core.currentData()
  }
}
