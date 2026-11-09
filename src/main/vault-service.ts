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
  VaultImportResult
} from '../shared/vault-contract'
import { VaultError } from './vault-errors'
import type { SshKeyMaterial } from './ssh-key'
import {
  fetchWebsiteIcon,
  parseWebsiteHostname,
  resolveWebsiteIconUrl,
  websiteIconDataUrl
} from './website-icon'
import { clearImageCacheKeys } from './encrypted-image-cache'
import type {
  AutofillAuthorizationValidator,
  AutofillCredentialConsumer,
  AutofillDiscoveryResult,
  AutofillExecutionRequest
} from './autofill'
import { assertUuid } from './vault/parse-primitives'
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
  VaultNativeAttachmentRestoreSummary
} from './vault/types'
import { VaultAccountService } from './vault-account-service'
import { findLogin, assertActiveLogin } from './vault/data-lookup'
import type { InactiveTwoFactorReport, TwoFactorDirectoryDataset } from './inactive-two-factor'
import type { PortableVaultSnapshot } from './vault-portability-codec'
import type { NativeAttachmentRestoreAttachmentKey } from './native-attachment-restore'
import type { NativeAttachmentBackupPreview } from './native-attachment-backup'
import type { BitwardenAttachmentByteSource } from './bitwarden-attachment-stream'
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

const WEBSITE_ICON_TTL_MS = 7 * 24 * 60 * 60 * 1000
const WEBSITE_ICON_MISSING_TTL_MS = 24 * 60 * 60 * 1000
const WEBSITE_ICON_RETRY_MS = 10 * 60 * 1000

/** Stable public entry point for item, autofill, passkey, SSH, and generator operations. */
export class VaultService extends VaultAccountService {
  /**
   * Test-only view of the committed in-memory snapshot, for planting records the public API cannot
   * create and trapping reads of protected fields. Production code must not call it.
   */
  committedSnapshotForTesting(): VaultData | null {
    return this.core.currentData()
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

  listSshAgentIdentities(): Promise<SshAgentVaultIdentity[]> {
    return this.integrations.listSshAgentIdentities()
  }

  signSshAgentRequest(
    request: SshAgentVaultSignRequest,
    validateAuthorization: SshAgentVaultAuthorizationValidator
  ): Promise<SshAgentVaultSignResult> {
    return this.integrations.signSshAgentRequest(request, validateAuthorization)
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

  async getWebsiteIcon(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<string | null> {
    const iconUrl = (() => {
      assertUuid(request.id)
      const data = this.core.requireFastReadData()
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      if (
        login.reprompt === 1 &&
        !validateAuthorization?.([login.id], { generation: this.core.generation })
      ) {
        throw new VaultError('REPROMPT_REQUIRED')
      }
      if (login.type !== 'login' || !login.uri || !data.sync) return null
      const hostname = parseWebsiteHostname(login.uri)
      return hostname ? resolveWebsiteIconUrl(data.sync.serverUrl, hostname) : null
    })()
    if (!iconUrl) return null

    const cacheKey = iconUrl.toString()
    const cached = this.websiteIconCache.get(cacheKey)
    if (cached) return cached.value
    const existingRequest = this.websiteIconRequests.get(cacheKey)
    if (existingRequest) return existingRequest

    const pendingRequest = this.loadWebsiteIcon(cacheKey, iconUrl).finally(() => {
      if (this.websiteIconRequests.get(cacheKey) === pendingRequest) {
        this.websiteIconRequests.delete(cacheKey)
      }
    })
    this.websiteIconRequests.set(cacheKey, pendingRequest)
    return pendingRequest
  }

  /** Memory LRU miss: try the encrypted disk cache, then a concurrency-limited fetch. */
  private async loadWebsiteIcon(cacheKey: string, iconUrl: URL): Promise<string | null> {
    const generation = this.core.generation
    const keys = this.imageCacheKeys()
    const abort = new AbortController()
    this.imageRequestAborts.add(abort)
    try {
      const stored = keys ? await this.imageCache?.read(keys, 'website-icon', cacheKey) : null
      if (generation !== this.core.generation) return null
      const storedValue =
        stored?.mediaType && stored.data ? websiteIconDataUrl(stored.mediaType, stored.data) : null
      stored?.data?.fill(0)
      const storedTtl = stored?.mediaType ? WEBSITE_ICON_TTL_MS : WEBSITE_ICON_MISSING_TTL_MS
      if (stored && stored.storedAt + storedTtl > this.core.now().getTime()) {
        this.rememberWebsiteIcon(cacheKey, storedValue, storedTtl)
        return storedValue
      }

      let result: Awaited<ReturnType<typeof fetchWebsiteIcon>>
      try {
        result = await this.websiteIconFetches.run(
          () => fetchWebsiteIcon(iconUrl, this.fetch, abort.signal),
          abort.signal
        )
      } catch {
        return null
      }
      if (generation !== this.core.generation) return null

      if (result.kind === 'failed') {
        // Keep showing a stale icon instead of a letter, and retry the network later.
        if (stored) this.rememberWebsiteIcon(cacheKey, storedValue, WEBSITE_ICON_RETRY_MS)
        return storedValue
      }
      const storedAt = this.core.now().getTime()
      const value =
        result.kind === 'icon' ? websiteIconDataUrl(result.mediaType, result.data) : null
      if (keys) {
        void this.imageCache?.write(keys, 'website-icon', cacheKey, {
          mediaType: result.kind === 'icon' ? result.mediaType : null,
          data: result.kind === 'icon' ? result.data : null,
          storedAt
        })
      }
      this.rememberWebsiteIcon(
        cacheKey,
        value,
        result.kind === 'icon' ? WEBSITE_ICON_TTL_MS : WEBSITE_ICON_MISSING_TTL_MS
      )
      return value
    } finally {
      this.imageRequestAborts.delete(abort)
      if (keys) clearImageCacheKeys(keys)
    }
  }

  private rememberWebsiteIcon(cacheKey: string, value: string | null, ttlMs: number): void {
    this.websiteIconCache.set(cacheKey, value, { size: value?.length ?? 0, ttlMs })
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
}
