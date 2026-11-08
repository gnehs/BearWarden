import type { SelectedItemCopyCommand } from './selected-item-shortcuts'
import type {
  AccountApiKeyCopyRequest,
  AccountApiKeyCopyResult,
  AccountAuthenticatorCompleteRequest,
  AccountAuthenticatorSetup,
  AccountAuthenticatorSetupLocator,
  AccountAuthenticatorSetupRequest,
  AccountDevicesResult,
  AccountEmailTwoFactorCompleteRequest,
  AccountEmailTwoFactorSendRequest,
  AccountEmailTwoFactorSetup,
  AccountEmailTwoFactorSetupRequest,
  AccountMutationResult,
  AccountProfileAvatarUpdateRequest,
  AccountProfileNameUpdateRequest,
  AccountRecoveryCodeCopyRequest,
  AccountRemoveRequest,
  AccountRenameRequest,
  AccountReorderRequest,
  AccountSecurityProfile,
  AccountSessionDeauthorizationRequest,
  AccountStatus,
  AccountSwitchRequest,
  AccountTwoFactorDisableRequest,
  AccountTwoFactorProvider,
  AccountWebAuthnKeyEnrollmentRequest,
  AccountWebAuthnKeyRemovalRequest,
  AccountWebAuthnKeyView,
  AccountWebAuthnKeysRequest,
  AppSettings,
  AppSettingsUpdate,
  AppUpdateState,
  ApplicationMenuCommand,
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
  AttachmentProgressEvent,
  AttachmentUploadCardCoverFileRequest,
  AttachmentUploadCardCoverRequest,
  AttachmentUploadRequest,
  AttachmentUploadResult,
  AutofillFeatureStatus,
  AutofillPrompt,
  AutofillPromptRequest,
  AutofillSelectionRequest,
  CardCoverPreviewResult,
  CollectionView,
  CredentialGeneratorRequest,
  CredentialGeneratorResult,
  CustomFieldRequest,
  EditorSecretsRequest,
  EditorSecretsView,
  EmergencyAccessView,
  EquivalentDomainSettingsUpdate,
  EquivalentDomainSettingsView,
  FolderCreateRequest,
  FolderDeleteRequest,
  FolderReorderRequest,
  FolderReparentRequest,
  FolderUpdateRequest,
  FolderView,
  GeneratedCredentialCopyRequest,
  GeneratorHistoryEntry,
  GeneratorHistoryLocator,
  InactiveTwoFactorDocumentationRequest,
  InactiveTwoFactorReport,
  ItemFieldRequest,
  LoginApprovalPrompt,
  LoginApprovalResponse,
  LoginAuthorization,
  LoginAuthorizeManyRequest,
  LoginAuthorizeRequest,
  LoginBatchRequest,
  LoginContextMenuRequest,
  LoginCreateRequest,
  LoginEmptyTrashRequest,
  LoginFavoriteRequest,
  LoginIdRequest,
  LoginListRequest,
  LoginMoveManyRequest,
  LoginMoveRequest,
  LoginOpenUriRequest,
  LoginPrefetchRequest,
  LoginSummary,
  LoginUpdateRequest,
  LoginView,
  MasterPasswordChangeRequest,
  MasterPasswordChangeResolutionRequest,
  MasterPasswordChangeStatus,
  NativeRestorePreviewRequest,
  NativeRestorePreviewResult,
  NativeRestoreProgress,
  NativeRestoreRunResult,
  NativeRestoreSessionRequest,
  NativeRestoreStartRequest,
  OrganizationView,
  PasskeyApprovalPrompt,
  PasskeyApprovalResponse,
  PasskeyApprovalVerificationRequest,
  PasskeyDeleteRequest,
  PasswordHistoryEntryRequest,
  PasswordHistoryRestoreRequest,
  PinUnlockEnableRequest,
  PinUnlockRequest,
  PinUnlockStatus,
  RendererErrorLogRequest,
  SendCreateRequest,
  SendFileCreateRequest,
  SendFileCreateResult,
  SendFileDownloadRequest,
  SendFileDownloadResult,
  SendIdRequest,
  SendUpdateRequest,
  SendView,
  SharedLoginCreateRequest,
  SharedLoginListRequest,
  SharedLoginSummary,
  SharedLoginUpdateRequest,
  SharedLoginView,
  SshAgentApprovalPrompt,
  SshAgentApprovalResponse,
  SshAgentStatus,
  SshKeyCreateImportedRequest,
  SshKeyGenerationResult,
  SshKeyImportCancelRequest,
  SshKeyImportPassphraseRequest,
  SshKeyImportResult,
  SshKeyUpdateImportedRequest,
  SyncConnectRequest,
  SyncConnectResponse,
  SyncEmailTwoFactorCodeRequest,
  SyncPurgePersonalVaultRequest,
  SyncPurgePersonalVaultResult,
  SyncResendNewDeviceOtpRequest,
  SyncResolvePendingImportRequest,
  SyncResult,
  SyncStatus,
  SyncUnlockRequest,
  SyncUnlockResponse,
  TotpCodeView,
  TouchIdEnableRequest,
  VaultExportRequest,
  VaultExportResult,
  VaultHealthAccountBreachReport,
  VaultHealthAccountBreachRequest,
  VaultHealthExposedReport,
  VaultHealthReport,
  VaultImportRequest,
  VaultImportResult,
  VaultPasswordHistoryView,
  VaultSetupRequest,
  VaultStatus,
  VaultUnlockRequest
} from './vault-contract'

declare const contract: unique symbol

/** A renderer method backed by `ipcRenderer.invoke`; a null `toRequest` sends no payload. */
interface InvokeEndpoint<Channel extends string, Args extends unknown[], Request, Response> {
  readonly kind: 'invoke'
  readonly channel: Channel
  readonly toRequest: ((...args: Args) => Request) | null
  readonly [contract]?: { readonly request: Request; readonly response: Response }
}

/** A fire-and-forget renderer method backed by `ipcRenderer.send`. */
interface SendEndpoint<Channel extends string, Args extends unknown[], Payload> {
  readonly kind: 'send'
  readonly channel: Channel
  readonly toPayload: (...args: Args) => Payload
}

/** A main-to-renderer event whose single payload reaches the listener. */
interface EventEndpoint<Channel extends string, Payload> {
  readonly kind: 'event'
  readonly channel: Channel
  readonly [contract]?: { readonly payload: Payload }
}

/** A main-to-renderer event whose listener is called without arguments. */
interface SignalEndpoint<Channel extends string> {
  readonly kind: 'signal'
  readonly channel: Channel
}

export type IpcEndpoint =
  | InvokeEndpoint<string, never[], unknown, unknown>
  | SendEndpoint<string, never[], unknown>
  | EventEndpoint<string, unknown>
  | SignalEndpoint<string>

/** Identity request mapper: the renderer's single argument is the wire request. */
function forward<T>(request: T): T {
  return request
}

function invoke<const Channel extends string>(
  channel: Channel
): { returns<Response = void>(): InvokeEndpoint<Channel, [], void, Response> }
function invoke<const Channel extends string, Args extends unknown[], Request>(
  channel: Channel,
  toRequest: (...args: Args) => Request
): { returns<Response = void>(): InvokeEndpoint<Channel, Args, Request, Response> }
function invoke(
  channel: string,
  toRequest: ((...args: never[]) => unknown) | null = null
): { returns(): InvokeEndpoint<string, never[], unknown, unknown> } {
  return { returns: () => ({ kind: 'invoke', channel, toRequest }) }
}

function send<const Channel extends string, Args extends unknown[], Payload>(
  channel: Channel,
  toPayload: (...args: Args) => Payload
): SendEndpoint<Channel, Args, Payload> {
  return { kind: 'send', channel, toPayload }
}

function event<const Channel extends string>(
  channel: Channel
): { carries<Payload>(): EventEndpoint<Channel, Payload> } {
  return { carries: () => ({ kind: 'event', channel }) }
}

function signal<const Channel extends string>(channel: Channel): SignalEndpoint<Channel> {
  return { kind: 'signal', channel }
}

/**
 * The single definition of every renderer-to-main channel and main-to-renderer event. The preload
 * builds `window.bearwarden` from it, and main handlers are typed against it by channel name.
 */
export const IPC_API = {
  vault: {
    status: invoke('vault:status').returns<VaultStatus>(),
    setup: invoke('vault:setup', forward<VaultSetupRequest>).returns<VaultStatus>(),
    unlock: invoke('vault:unlock', forward<VaultUnlockRequest>).returns<VaultStatus>(),
    pinStatus: invoke('vault:pin-status').returns<PinUnlockStatus>(),
    enablePin: invoke(
      'vault:pin-enable',
      forward<PinUnlockEnableRequest>
    ).returns<PinUnlockStatus>(),
    disablePin: invoke('vault:pin-disable').returns<PinUnlockStatus>(),
    unlockPin: invoke('vault:pin-unlock', forward<PinUnlockRequest>).returns<VaultStatus>(),
    masterPasswordChangeStatus: invoke(
      'vault:master-password-change-status'
    ).returns<MasterPasswordChangeStatus>(),
    changeMasterPassword: invoke(
      'vault:master-password-change',
      forward<MasterPasswordChangeRequest>
    ).returns<MasterPasswordChangeStatus>(),
    resolveMasterPasswordChange: invoke(
      'vault:master-password-change-resolve',
      forward<MasterPasswordChangeResolutionRequest>
    ).returns<MasterPasswordChangeStatus>(),
    lock: invoke('vault:lock').returns<VaultStatus>(),
    setLockRequestReady: send('vault:lock-request-ready', forward<boolean>),
    onLocked: signal('vault:locked'),
    onLockRequested: signal('vault:lock-requested'),
    onUnlocked: signal('vault:unlocked'),
    onChanged: signal('vault:changed')
  },
  portability: {
    export: invoke('vault:export', forward<VaultExportRequest>).returns<VaultExportResult>(),
    import: invoke('vault:import', forward<VaultImportRequest>).returns<VaultImportResult>(),
    previewNativeRestore: invoke(
      'vault:native-restore-preview',
      forward<NativeRestorePreviewRequest>
    ).returns<NativeRestorePreviewResult>(),
    startNativeRestore: invoke(
      'vault:native-restore-start',
      forward<NativeRestoreStartRequest>
    ).returns<NativeRestoreRunResult>(),
    cancelNativeRestore: invoke(
      'vault:native-restore-cancel',
      forward<NativeRestoreSessionRequest>
    ).returns(),
    clearCompletedNativeRestore: invoke(
      'vault:native-restore-clear-completed',
      forward<NativeRestoreSessionRequest>
    ).returns(),
    onNativeRestoreProgress: event('vault:native-restore-progress').carries<NativeRestoreProgress>()
  },
  health: {
    /** Runs entirely in main; the renderer receives only safe finding metadata. */
    report: invoke('vault:health-report').returns<VaultHealthReport>(),
    /** Performs an explicit k-anonymous HIBP range check from the main process. */
    exposedPasswords: invoke('vault:health-exposed-passwords').returns<VaultHealthExposedReport>(),
    cancelExposedPasswords: invoke('vault:health-cancel-exposed-passwords').returns<boolean>(),
    /** Sends the complete address through the configured Vaultwarden server to HIBP. */
    accountBreaches: invoke(
      'vault:health-account-breaches',
      forward<VaultHealthAccountBreachRequest>
    ).returns<VaultHealthAccountBreachReport>(),
    cancelAccountBreaches: invoke('vault:health-cancel-account-breaches').returns<boolean>(),
    /** Opens the fixed HIBP attribution URL in the system browser. */
    openHibpWebsite: invoke('vault:health-open-hibp').returns(),
    inactiveTwoFactor: invoke(
      'vault:health-inactive-two-factor'
    ).returns<InactiveTwoFactorReport>(),
    openTwoFactorDocumentation: invoke(
      'vault:health-open-two-factor-documentation',
      forward<InactiveTwoFactorDocumentationRequest>
    ).returns()
  },
  folders: {
    list: invoke('folder:list').returns<FolderView[]>(),
    create: invoke('folder:create', forward<FolderCreateRequest>).returns<FolderView>(),
    update: invoke('folder:update', forward<FolderUpdateRequest>).returns<FolderView[]>(),
    reparent: invoke('folder:reparent', forward<FolderReparentRequest>).returns<FolderView[]>(),
    delete: invoke('folder:delete', forward<FolderDeleteRequest>).returns(),
    reorder: invoke('folder:reorder', forward<FolderReorderRequest>).returns<FolderView[]>()
  },
  organizations: {
    list: invoke('organization:list').returns<OrganizationView[]>()
  },
  collections: {
    list: invoke('collection:list', (organizationId?: string) => organizationId).returns<
      CollectionView[]
    >()
  },
  sharedLogins: {
    list: invoke('shared-login:list', (request: SharedLoginListRequest = {}) => request).returns<
      SharedLoginSummary[]
    >(),
    get: invoke('shared-login:get', forward<LoginIdRequest>).returns<SharedLoginView>(),
    create: invoke(
      'shared-login:create',
      forward<SharedLoginCreateRequest>
    ).returns<SharedLoginView>(),
    update: invoke(
      'shared-login:update',
      forward<SharedLoginUpdateRequest>
    ).returns<SharedLoginView>(),
    revealEditorSecrets: invoke(
      'shared-login:reveal-editor-secrets',
      forward<EditorSecretsRequest>
    ).returns<EditorSecretsView>(),
    revealSecret: invoke('shared-login:reveal-secret', forward<ItemFieldRequest>).returns<string>(),
    copyField: invoke('shared-login:copy-field', forward<ItemFieldRequest>).returns(),
    revealCustomField: invoke(
      'shared-login:reveal-custom-field',
      forward<CustomFieldRequest>
    ).returns<string>(),
    copyCustomField: invoke(
      'shared-login:copy-custom-field',
      forward<CustomFieldRequest>
    ).returns(),
    getTotp: invoke('shared-login:get-totp', forward<LoginIdRequest>).returns<TotpCodeView>(),
    copyTotp: invoke('shared-login:copy-totp', forward<LoginIdRequest>).returns(),
    openUri: invoke('shared-login:open-uri', forward<LoginOpenUriRequest>).returns()
  },
  emergencyAccess: {
    list: invoke('emergency-access:list').returns<EmergencyAccessView[]>()
  },
  logins: {
    list: invoke('login:list', (request: LoginListRequest = {}) => request).returns<
      LoginSummary[]
    >(),
    authorize: invoke(
      'login:authorize',
      forward<LoginAuthorizeRequest>
    ).returns<LoginAuthorization>(),
    authorizeMany: invoke(
      'login:authorize-many',
      forward<LoginAuthorizeManyRequest>
    ).returns<LoginAuthorization>(),
    get: invoke('login:get', forward<LoginIdRequest>).returns<LoginView>(),
    prefetch: invoke('login:prefetch', forward<LoginPrefetchRequest>).returns<LoginView[]>(),
    getPasswordHistory: invoke(
      'login:get-password-history',
      forward<LoginIdRequest>
    ).returns<VaultPasswordHistoryView>(),
    revealPasswordHistory: invoke(
      'login:reveal-password-history',
      forward<PasswordHistoryEntryRequest>
    ).returns<string>(),
    copyPasswordHistory: invoke(
      'login:copy-password-history',
      forward<PasswordHistoryEntryRequest>
    ).returns(),
    restorePasswordHistory: invoke(
      'login:restore-password-history',
      forward<PasswordHistoryRestoreRequest>
    ).returns<LoginView>(),
    downloadAttachment: invoke(
      'attachment:download',
      forward<AttachmentDownloadRequest>
    ).returns<AttachmentDownloadResult>(),
    previewAttachment: invoke(
      'attachment:preview',
      forward<AttachmentPreviewRequest>
    ).returns<AttachmentPreviewResult>(),
    getCardCoverPreview: invoke(
      'attachment:card-cover-preview',
      forward<LoginIdRequest>
    ).returns<CardCoverPreviewResult | null>(),
    uploadAttachment: invoke(
      'attachment:upload',
      forward<AttachmentUploadRequest>
    ).returns<AttachmentUploadResult>(),
    uploadCardCoverAttachment: invoke(
      'attachment:upload-card-cover',
      forward<AttachmentUploadCardCoverRequest>
    ).returns<AttachmentUploadResult>(),
    uploadCardCoverFileAttachment: invoke(
      'attachment:upload-card-cover-file',
      forward<AttachmentUploadCardCoverFileRequest>
    ).returns<AttachmentUploadResult>(),
    deleteAttachment: invoke(
      'attachment:delete',
      forward<AttachmentDeleteRequest>
    ).returns<AttachmentDeleteResult>(),
    fixLegacyAttachment: invoke(
      'attachment:fix-legacy',
      forward<AttachmentFixLegacyRequest>
    ).returns<AttachmentFixLegacyResult>(),
    cancelAttachment: invoke(
      'attachment:cancel',
      forward<AttachmentCancelRequest>
    ).returns<AttachmentCancelResult>(),
    onAttachmentProgress: event('attachment:progress').carries<AttachmentProgressEvent>(),
    create: invoke('login:create', forward<LoginCreateRequest>).returns<LoginView>(),
    /** Creates an active copy without any passkeys or attachments. */
    clone: invoke('login:clone', forward<LoginIdRequest>).returns<LoginView>(),
    archive: invoke('login:archive', forward<LoginIdRequest>).returns<LoginView>(),
    archiveMany: invoke('login:archive-many', forward<LoginBatchRequest>).returns<LoginSummary[]>(),
    unarchive: invoke('login:unarchive', forward<LoginIdRequest>).returns<LoginView>(),
    unarchiveMany: invoke('login:unarchive-many', forward<LoginBatchRequest>).returns<
      LoginSummary[]
    >(),
    update: invoke('login:update', forward<LoginUpdateRequest>).returns<LoginView>(),
    /** Move an active item to the trash. */
    delete: invoke('login:delete', forward<LoginIdRequest>).returns(),
    /** Move active items to the trash. */
    deleteMany: invoke('login:delete-many', forward<LoginBatchRequest>).returns<number>(),
    restore: invoke('login:restore', forward<LoginIdRequest>).returns<LoginView>(),
    restoreMany: invoke('login:restore-many', forward<LoginBatchRequest>).returns<LoginSummary[]>(),
    deletePermanently: invoke('login:delete-permanently', forward<LoginIdRequest>).returns(),
    deletePermanentlyMany: invoke(
      'login:delete-permanently-many',
      forward<LoginBatchRequest>
    ).returns<number>(),
    emptyTrash: invoke(
      'login:empty-trash',
      (request: LoginEmptyTrashRequest = {}) => request
    ).returns<number>(),
    setFavorite: invoke(
      'login:set-favorite',
      forward<LoginFavoriteRequest>
    ).returns<LoginSummary>(),
    move: invoke('login:move', forward<LoginMoveRequest>).returns<LoginSummary>(),
    moveMany: invoke('login:move-many', forward<LoginMoveManyRequest>).returns<LoginSummary[]>(),
    revealPassword: invoke('login:reveal-password', forward<LoginIdRequest>).returns<string>(),
    copyUsername: invoke('login:copy-username', forward<LoginIdRequest>).returns(),
    copyPassword: invoke('login:copy-password', forward<LoginIdRequest>).returns(),
    openUri: invoke('login:open-uri', forward<LoginOpenUriRequest>).returns(),
    getTotp: invoke('login:get-totp', forward<LoginIdRequest>).returns<TotpCodeView>(),
    copyTotp: invoke('login:copy-totp', forward<LoginIdRequest>).returns(),
    showContextMenu: invoke('login:context-menu', forward<LoginContextMenuRequest>).returns(),
    getWebsiteIcon: invoke('login:website-icon', forward<LoginIdRequest>).returns<string | null>(),
    revealEditorSecrets: invoke(
      'item:reveal-editor-secrets',
      forward<EditorSecretsRequest>
    ).returns<EditorSecretsView>(),
    revealSecret: invoke('item:reveal-secret', forward<ItemFieldRequest>).returns<string>(),
    copyField: invoke('item:copy-field', forward<ItemFieldRequest>).returns(),
    revealCustomField: invoke(
      'item:reveal-custom-field',
      forward<CustomFieldRequest>
    ).returns<string>(),
    copyCustomField: invoke('item:copy-custom-field', forward<CustomFieldRequest>).returns()
  },
  passkeys: {
    /** Deletes one passkey without exposing its private key material to the renderer. */
    delete: invoke('passkey:delete', forward<PasskeyDeleteRequest>).returns<LoginView>(),
    /** Verifies a master password for one pending ceremony without starting a ceremony. */
    verifyApproval: invoke(
      'passkey:verify-approval',
      forward<PasskeyApprovalVerificationRequest>
    ).returns(),
    respondApproval: invoke('passkey:respond-approval', forward<PasskeyApprovalResponse>).returns(),
    onApprovalRequested: event('passkey:approval-requested').carries<PasskeyApprovalPrompt>()
  },
  autofill: {
    status: invoke('autofill:status').returns<AutofillFeatureStatus>(),
    requestAccessibility: invoke('autofill:request-accessibility').returns<AutofillFeatureStatus>(),
    current: invoke('autofill:current').returns<AutofillPrompt | null>(),
    select: invoke('autofill:select', forward<AutofillSelectionRequest>).returns(),
    cancel: invoke('autofill:cancel', forward<AutofillPromptRequest>).returns(),
    openMain: invoke('autofill:open-main', forward<AutofillPromptRequest>).returns(),
    onPromptChanged: event('autofill:prompt-changed').carries<AutofillPrompt | null>()
  },
  generator: {
    generate: invoke(
      'generator:generate',
      forward<CredentialGeneratorRequest>
    ).returns<CredentialGeneratorResult>(),
    copyGenerated: invoke(
      'generator:generated-copy',
      forward<GeneratedCredentialCopyRequest>
    ).returns(),
    history: invoke('generator:history-list').returns<GeneratorHistoryEntry[]>(),
    clearHistory: invoke('generator:history-clear').returns(),
    copyHistory: invoke('generator:history-copy', forward<GeneratorHistoryLocator>).returns()
  },
  sshKeys: {
    generate: invoke('ssh-key:generate').returns<SshKeyGenerationResult>(),
    beginImport: invoke('ssh-key:begin-import').returns<SshKeyImportResult>(),
    submitImportPassphrase: invoke(
      'ssh-key:submit-import-passphrase',
      forward<SshKeyImportPassphraseRequest>
    ).returns<SshKeyImportResult>(),
    cancelImport: invoke('ssh-key:cancel-import', forward<SshKeyImportCancelRequest>).returns(),
    createImported: invoke(
      'ssh-key:create-imported',
      forward<SshKeyCreateImportedRequest>
    ).returns<LoginView>(),
    updateImported: invoke(
      'ssh-key:update-imported',
      forward<SshKeyUpdateImportedRequest>
    ).returns<LoginView>()
  },
  sshAgent: {
    status: invoke('ssh-agent:status').returns<SshAgentStatus>(),
    respondApproval: invoke(
      'ssh-agent:respond-approval',
      forward<SshAgentApprovalResponse>
    ).returns(),
    onApprovalRequested: event('ssh-agent:approval-requested').carries<SshAgentApprovalPrompt>(),
    onStatusChanged: event('ssh-agent:status-changed').carries<SshAgentStatus>()
  },
  sync: {
    status: invoke('sync:status').returns<SyncStatus>(),
    connect: invoke('sync:connect', forward<SyncConnectRequest>).returns<SyncConnectResponse>(),
    unlock: invoke('sync:unlock', forward<SyncUnlockRequest>).returns<SyncUnlockResponse>(),
    sendEmailTwoFactorCode: invoke(
      'sync:send-email-two-factor-code',
      forward<SyncEmailTwoFactorCodeRequest>
    ).returns(),
    resendNewDeviceOtp: invoke(
      'sync:resend-new-device-otp',
      forward<SyncResendNewDeviceOtpRequest>
    ).returns(),
    now: invoke('sync:now').returns<SyncResult>(),
    resolvePendingImport: invoke(
      'sync:resolve-pending-import',
      forward<SyncResolvePendingImportRequest>
    ).returns<SyncStatus>(),
    purgePersonalVault: invoke(
      'sync:purge-personal-vault',
      forward<SyncPurgePersonalVaultRequest>
    ).returns<SyncPurgePersonalVaultResult>(),
    disconnect: invoke('sync:disconnect').returns<SyncStatus>(),
    onChanged: event('sync:changed').carries<SyncStatus>()
  },
  accounts: {
    status: invoke('account:status').returns<AccountStatus>(),
    add: invoke('account:add').returns<AccountMutationResult>(),
    switch: invoke('account:switch', (accountId: string): AccountSwitchRequest => ({
      accountId
    })).returns<AccountMutationResult>(),
    rename: invoke(
      'account:rename',
      (accountId: string, displayName: string, expectedRevision: number): AccountRenameRequest => ({
        accountId,
        displayName,
        expectedRevision
      })
    ).returns<AccountMutationResult>(),
    reorder: invoke(
      'account:reorder',
      (accountIds: readonly string[], expectedRevision: number): AccountReorderRequest => ({
        accountIds,
        expectedRevision
      })
    ).returns<AccountMutationResult>(),
    remove: invoke('account:remove', (accountId: string, confirm: true): AccountRemoveRequest => ({
      accountId,
      confirm
    })).returns<AccountMutationResult>()
  },
  accountSecurity: {
    profile: invoke('account-security:profile').returns<AccountSecurityProfile>(),
    updateName: invoke(
      'account-security:update-name',
      forward<AccountProfileNameUpdateRequest>
    ).returns<AccountSecurityProfile>(),
    updateAvatar: invoke(
      'account-security:update-avatar',
      forward<AccountProfileAvatarUpdateRequest>
    ).returns<AccountSecurityProfile>(),
    devices: invoke('account-security:devices').returns<AccountDevicesResult>(),
    pendingLoginApprovals: invoke('account-security:pending-login-approvals').returns<
      LoginApprovalPrompt[]
    >(),
    respondLoginApproval: invoke(
      'account-security:respond-login-approval',
      forward<LoginApprovalResponse>
    ).returns(),
    onLoginApprovalRequested: event(
      'account-security:login-approval-requested'
    ).carries<LoginApprovalPrompt>(),
    deauthorizeSessions: invoke(
      'account-security:deauthorize-sessions',
      forward<AccountSessionDeauthorizationRequest>
    ).returns(),
    resendVerification: invoke('account-security:resend-verification').returns(),
    copyApiClientId: invoke('account-security:copy-api-client-id').returns(),
    copyApiKey: invoke(
      'account-security:copy-api-key',
      forward<AccountApiKeyCopyRequest>
    ).returns<AccountApiKeyCopyResult>(),
    twoFactorStatus: invoke('account-security:two-factor-status').returns<
      AccountTwoFactorProvider[]
    >(),
    disableTwoFactorProvider: invoke(
      'account-security:disable-two-factor-provider',
      forward<AccountTwoFactorDisableRequest>
    ).returns(),
    copyRecoveryCode: invoke(
      'account-security:copy-recovery-code',
      forward<AccountRecoveryCodeCopyRequest>
    ).returns(),
    beginAuthenticatorSetup: invoke(
      'account-security:begin-authenticator-setup',
      forward<AccountAuthenticatorSetupRequest>
    ).returns<AccountAuthenticatorSetup>(),
    copyAuthenticatorKey: invoke(
      'account-security:copy-authenticator-key',
      forward<AccountAuthenticatorSetupLocator>
    ).returns(),
    completeAuthenticatorSetup: invoke(
      'account-security:complete-authenticator-setup',
      forward<AccountAuthenticatorCompleteRequest>
    ).returns(),
    beginEmailTwoFactorSetup: invoke(
      'account-security:begin-email-two-factor-setup',
      forward<AccountEmailTwoFactorSetupRequest>
    ).returns<AccountEmailTwoFactorSetup>(),
    sendEmailTwoFactorSetup: invoke(
      'account-security:send-email-two-factor-setup',
      forward<AccountEmailTwoFactorSendRequest>
    ).returns(),
    completeEmailTwoFactorSetup: invoke(
      'account-security:complete-email-two-factor-setup',
      forward<AccountEmailTwoFactorCompleteRequest>
    ).returns(),
    listWebAuthnKeys: invoke(
      'account-security:webauthn-keys',
      forward<AccountWebAuthnKeysRequest>
    ).returns<AccountWebAuthnKeyView[]>(),
    enrollWebAuthnKey: invoke(
      'account-security:enroll-webauthn-key',
      forward<AccountWebAuthnKeyEnrollmentRequest>
    ).returns(),
    removeWebAuthnKey: invoke(
      'account-security:remove-webauthn-key',
      forward<AccountWebAuthnKeyRemovalRequest>
    ).returns()
  },
  domainRules: {
    get: invoke('domain-rules:get').returns<EquivalentDomainSettingsView>(),
    update: invoke(
      'domain-rules:update',
      forward<EquivalentDomainSettingsUpdate>
    ).returns<EquivalentDomainSettingsView>()
  },
  sends: {
    list: invoke('send:list').returns<SendView[]>(),
    create: invoke('send:create', forward<SendCreateRequest>).returns<SendView>(),
    createFile: invoke(
      'send:create-file',
      forward<SendFileCreateRequest>
    ).returns<SendFileCreateResult>(),
    downloadFile: invoke(
      'send:download-file',
      forward<SendFileDownloadRequest>
    ).returns<SendFileDownloadResult>(),
    update: invoke('send:update', forward<SendUpdateRequest>).returns<SendView>(),
    removePassword: invoke('send:remove-password', forward<SendIdRequest>).returns<SendView>(),
    delete: invoke('send:delete', forward<SendIdRequest>).returns(),
    /** Copies the share link directly from main; the URL fragment seed never crosses IPC. */
    copyLink: invoke('send:copy-link', forward<SendIdRequest>).returns()
  },
  settings: {
    get: invoke('settings:get').returns<AppSettings>(),
    update: invoke('settings:update', forward<AppSettingsUpdate>).returns<AppSettings>(),
    enableTouchId: invoke(
      'settings:enable-touch-id',
      forward<TouchIdEnableRequest>
    ).returns<AppSettings>(),
    disableTouchId: invoke('settings:disable-touch-id').returns<AppSettings>(),
    unlockTouchId: invoke('settings:unlock-touch-id').returns<VaultStatus>(),
    activity: invoke('settings:activity').returns(),
    showErrorLog: invoke('settings:show-error-log').returns()
  },
  applicationMenu: {
    execute: invoke('application-menu:execute', forward<ApplicationMenuCommand>).returns(),
    onCopySelectedItem: event(
      'application-menu:copy-selected-item'
    ).carries<SelectedItemCopyCommand>()
  },
  updater: {
    state: invoke('app-update:state').returns<AppUpdateState>(),
    check: invoke('app-update:check').returns<AppUpdateState>(),
    download: invoke('app-update:download').returns<AppUpdateState>(),
    install: invoke('app-update:install').returns(),
    openReleasePage: invoke('app-update:open-release-page').returns(),
    openRepositoryPage: invoke('app-update:open-repository-page').returns(),
    onStateChanged: event('app-update:state-changed').carries<AppUpdateState>()
  }
}

/** Preload-owned channels that are not exposed on `window.bearwarden`. */
export const PRELOAD_IPC = {
  recordRendererError: invoke(
    'error-log:record-renderer',
    forward<RendererErrorLogRequest>
  ).returns()
}

type RendererMethod<E> =
  E extends InvokeEndpoint<string, infer Args, unknown, infer Response>
    ? (...args: Args) => Promise<Response>
    : E extends SendEndpoint<string, infer Args, unknown>
      ? (...args: Args) => void
      : E extends EventEndpoint<string, infer Payload>
        ? (listener: (payload: Payload) => void) => () => void
        : E extends SignalEndpoint<string>
          ? (listener: () => void) => () => void
          : never

type IpcApiTable = typeof IPC_API

/** The `window.bearwarden` surface, derived from `IPC_API`. */
export type BearWardenAPI = {
  -readonly [Namespace in keyof IpcApiTable]: {
    -readonly [Method in keyof IpcApiTable[Namespace]]: RendererMethod<
      IpcApiTable[Namespace][Method]
    >
  }
}

type AnyEndpoint =
  | {
      [Namespace in keyof IpcApiTable]: IpcApiTable[Namespace][keyof IpcApiTable[Namespace]]
    }[keyof IpcApiTable]
  | (typeof PRELOAD_IPC)[keyof typeof PRELOAD_IPC]

type InvokeEndpointOf<Channel> = Extract<AnyEndpoint, { kind: 'invoke'; channel: Channel }>
type SendEndpointOf<Channel> = Extract<AnyEndpoint, { kind: 'send'; channel: Channel }>
type EventEndpointOf<Channel> = Extract<AnyEndpoint, { kind: 'event' | 'signal'; channel: Channel }>

export type IpcInvokeChannel = Extract<AnyEndpoint, { kind: 'invoke' }>['channel']
export type IpcSendChannel = Extract<AnyEndpoint, { kind: 'send' }>['channel']
export type IpcEventChannel = Extract<AnyEndpoint, { kind: 'event' | 'signal' }>['channel']

/** The wire request main receives on an invoke channel; `void` for channels without input. */
export type IpcRequest<Channel extends IpcInvokeChannel> =
  InvokeEndpointOf<Channel> extends InvokeEndpoint<Channel, never, infer Request, unknown>
    ? Request
    : never

/** The resolved value an invoke channel's main handler must produce. */
export type IpcResponse<Channel extends IpcInvokeChannel> =
  InvokeEndpointOf<Channel> extends InvokeEndpoint<Channel, never, unknown, infer Response>
    ? Response
    : never

export type IpcSendPayload<Channel extends IpcSendChannel> =
  SendEndpointOf<Channel> extends SendEndpoint<Channel, never, infer Payload> ? Payload : never

/** Arguments after the channel name for `webContents.send` on an event channel. */
export type IpcEventArgs<Channel extends IpcEventChannel> =
  EventEndpointOf<Channel> extends EventEndpoint<Channel, infer Payload> ? [payload: Payload] : []
