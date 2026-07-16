import { contextBridge, ipcRenderer, type IpcRendererEvent } from 'electron'
import { IPC_CHANNELS, IPC_EVENTS, type BearWardenAPI } from '../shared/vault-contract'

const api: BearWardenAPI = {
  vault: {
    status: () => ipcRenderer.invoke(IPC_CHANNELS.vaultStatus),
    setup: (request) => ipcRenderer.invoke(IPC_CHANNELS.vaultSetup, request),
    unlock: (request) => ipcRenderer.invoke(IPC_CHANNELS.vaultUnlock, request),
    pinStatus: () => ipcRenderer.invoke(IPC_CHANNELS.vaultPinStatus),
    enablePin: (request) => ipcRenderer.invoke(IPC_CHANNELS.vaultPinEnable, request),
    disablePin: () => ipcRenderer.invoke(IPC_CHANNELS.vaultPinDisable),
    unlockPin: (request) => ipcRenderer.invoke(IPC_CHANNELS.vaultPinUnlock, request),
    lock: () => ipcRenderer.invoke(IPC_CHANNELS.vaultLock),
    setLockRequestReady: (ready) => ipcRenderer.send(IPC_CHANNELS.vaultLockRequestReady, ready),
    onLocked: (listener) => {
      const wrappedListener = (): void => listener()
      ipcRenderer.on(IPC_EVENTS.vaultLocked, wrappedListener)

      return () => ipcRenderer.removeListener(IPC_EVENTS.vaultLocked, wrappedListener)
    },
    onLockRequested: (listener) => {
      const wrappedListener = (): void => listener()
      ipcRenderer.on(IPC_EVENTS.vaultLockRequested, wrappedListener)

      return () => ipcRenderer.removeListener(IPC_EVENTS.vaultLockRequested, wrappedListener)
    },
    onUnlocked: (listener) => {
      const wrappedListener = (): void => listener()
      ipcRenderer.on(IPC_EVENTS.vaultUnlocked, wrappedListener)

      return () => ipcRenderer.removeListener(IPC_EVENTS.vaultUnlocked, wrappedListener)
    },
    onChanged: (listener) => {
      const wrappedListener = (): void => listener()
      ipcRenderer.on(IPC_EVENTS.vaultChanged, wrappedListener)
      return () => ipcRenderer.removeListener(IPC_EVENTS.vaultChanged, wrappedListener)
    }
  },
  portability: {
    export: (request) => ipcRenderer.invoke(IPC_CHANNELS.vaultExport, request),
    import: (request) => ipcRenderer.invoke(IPC_CHANNELS.vaultImport, request)
  },
  health: {
    report: () => ipcRenderer.invoke(IPC_CHANNELS.vaultHealthReport, {}),
    exposedPasswords: () => ipcRenderer.invoke(IPC_CHANNELS.vaultHealthExposedPasswords, {}),
    cancelExposedPasswords: () =>
      ipcRenderer.invoke(IPC_CHANNELS.vaultHealthCancelExposedPasswords, {}),
    accountBreaches: (request) =>
      ipcRenderer.invoke(IPC_CHANNELS.vaultHealthAccountBreaches, request),
    cancelAccountBreaches: () =>
      ipcRenderer.invoke(IPC_CHANNELS.vaultHealthCancelAccountBreaches, {}),
    openHibpWebsite: () => ipcRenderer.invoke(IPC_CHANNELS.vaultHealthOpenHibp, {})
  },
  folders: {
    list: () => ipcRenderer.invoke(IPC_CHANNELS.folderList),
    create: (request) => ipcRenderer.invoke(IPC_CHANNELS.folderCreate, request),
    update: (request) => ipcRenderer.invoke(IPC_CHANNELS.folderUpdate, request),
    delete: (request) => ipcRenderer.invoke(IPC_CHANNELS.folderDelete, request),
    reorder: (request) => ipcRenderer.invoke(IPC_CHANNELS.folderReorder, request)
  },
  organizations: {
    list: () => ipcRenderer.invoke(IPC_CHANNELS.organizationList)
  },
  collections: {
    list: (organizationId) => ipcRenderer.invoke(IPC_CHANNELS.collectionList, organizationId)
  },
  sharedLogins: {
    list: (request = {}) => ipcRenderer.invoke(IPC_CHANNELS.sharedLoginList, request),
    get: (request) => ipcRenderer.invoke(IPC_CHANNELS.sharedLoginGet, request)
  },
  emergencyAccess: {
    list: () => ipcRenderer.invoke(IPC_CHANNELS.emergencyAccessList)
  },
  logins: {
    list: (request = {}) => ipcRenderer.invoke(IPC_CHANNELS.loginList, request),
    authorize: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginAuthorize, request),
    authorizeMany: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginAuthorizeMany, request),
    get: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginGet, request),
    getPasswordHistory: (request) =>
      ipcRenderer.invoke(IPC_CHANNELS.loginGetPasswordHistory, request),
    restorePasswordHistory: (request) =>
      ipcRenderer.invoke(IPC_CHANNELS.loginRestorePasswordHistory, request),
    downloadAttachment: (request) => ipcRenderer.invoke(IPC_CHANNELS.attachmentDownload, request),
    uploadAttachment: (request) => ipcRenderer.invoke(IPC_CHANNELS.attachmentUpload, request),
    deleteAttachment: (request) => ipcRenderer.invoke(IPC_CHANNELS.attachmentDelete, request),
    fixLegacyAttachment: (request) => ipcRenderer.invoke(IPC_CHANNELS.attachmentFixLegacy, request),
    cancelAttachment: (request) => ipcRenderer.invoke(IPC_CHANNELS.attachmentCancel, request),
    onAttachmentProgress: (listener) => {
      const wrappedListener = (
        _event: IpcRendererEvent,
        progress: Parameters<typeof listener>[0]
      ): void => listener(progress)
      ipcRenderer.on(IPC_EVENTS.attachmentProgress, wrappedListener)
      return () => ipcRenderer.removeListener(IPC_EVENTS.attachmentProgress, wrappedListener)
    },
    create: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginCreate, request),
    clone: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginClone, request),
    archive: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginArchive, request),
    archiveMany: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginArchiveMany, request),
    unarchive: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginUnarchive, request),
    unarchiveMany: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginUnarchiveMany, request),
    update: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginUpdate, request),
    delete: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginDelete, request),
    deleteMany: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginDeleteMany, request),
    restore: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginRestore, request),
    restoreMany: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginRestoreMany, request),
    deletePermanently: (request) =>
      ipcRenderer.invoke(IPC_CHANNELS.loginDeletePermanently, request),
    deletePermanentlyMany: (request) =>
      ipcRenderer.invoke(IPC_CHANNELS.loginDeletePermanentlyMany, request),
    emptyTrash: (request = {}) => ipcRenderer.invoke(IPC_CHANNELS.loginEmptyTrash, request),
    setFavorite: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginSetFavorite, request),
    move: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginMove, request),
    moveMany: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginMoveMany, request),
    revealPassword: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginRevealPassword, request),
    copyUsername: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginCopyUsername, request),
    copyPassword: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginCopyPassword, request),
    openUri: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginOpenUri, request),
    getTotp: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginGetTotp, request),
    copyTotp: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginCopyTotp, request),
    showContextMenu: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginContextMenu, request),
    getWebsiteIcon: (request) => ipcRenderer.invoke(IPC_CHANNELS.loginWebsiteIcon, request),
    revealEditorSecrets: (request) =>
      ipcRenderer.invoke(IPC_CHANNELS.itemRevealEditorSecrets, request),
    revealSecret: (request) => ipcRenderer.invoke(IPC_CHANNELS.itemRevealSecret, request),
    copyField: (request) => ipcRenderer.invoke(IPC_CHANNELS.itemCopyField, request),
    revealCustomField: (request) => ipcRenderer.invoke(IPC_CHANNELS.itemRevealCustomField, request),
    copyCustomField: (request) => ipcRenderer.invoke(IPC_CHANNELS.itemCopyCustomField, request)
  },
  passkeys: {
    delete: (request) => ipcRenderer.invoke(IPC_CHANNELS.passkeyDelete, request),
    verifyApproval: (request) => ipcRenderer.invoke(IPC_CHANNELS.passkeyVerifyApproval, request),
    respondApproval: (response) =>
      ipcRenderer.invoke(IPC_CHANNELS.passkeyRespondApproval, response),
    onApprovalRequested: (listener) => {
      const wrappedListener = (
        _event: IpcRendererEvent,
        request: Parameters<typeof listener>[0]
      ): void => listener(request)
      ipcRenderer.on(IPC_EVENTS.passkeyApprovalRequested, wrappedListener)
      return () => ipcRenderer.removeListener(IPC_EVENTS.passkeyApprovalRequested, wrappedListener)
    }
  },
  generator: {
    generate: (request) => ipcRenderer.invoke(IPC_CHANNELS.generatorGenerate, request),
    history: () => ipcRenderer.invoke(IPC_CHANNELS.generatorHistoryList),
    clearHistory: () => ipcRenderer.invoke(IPC_CHANNELS.generatorHistoryClear),
    copyHistory: (request) => ipcRenderer.invoke(IPC_CHANNELS.generatorHistoryCopy, request)
  },
  sshKeys: {
    generate: () => ipcRenderer.invoke(IPC_CHANNELS.sshKeyGenerate),
    beginImport: () => ipcRenderer.invoke(IPC_CHANNELS.sshKeyBeginImport),
    submitImportPassphrase: (request) =>
      ipcRenderer.invoke(IPC_CHANNELS.sshKeySubmitImportPassphrase, request),
    cancelImport: (request) => ipcRenderer.invoke(IPC_CHANNELS.sshKeyCancelImport, request),
    createImported: (request) => ipcRenderer.invoke(IPC_CHANNELS.sshKeyCreateImported, request),
    updateImported: (request) => ipcRenderer.invoke(IPC_CHANNELS.sshKeyUpdateImported, request)
  },
  sshAgent: {
    status: () => ipcRenderer.invoke(IPC_CHANNELS.sshAgentStatus),
    respondApproval: (response) =>
      ipcRenderer.invoke(IPC_CHANNELS.sshAgentRespondApproval, response),
    onApprovalRequested: (listener) => {
      const wrappedListener = (
        _event: IpcRendererEvent,
        request: Parameters<typeof listener>[0]
      ): void => listener(request)
      ipcRenderer.on(IPC_EVENTS.sshAgentApprovalRequested, wrappedListener)
      return () => ipcRenderer.removeListener(IPC_EVENTS.sshAgentApprovalRequested, wrappedListener)
    },
    onStatusChanged: (listener) => {
      const wrappedListener = (
        _event: IpcRendererEvent,
        status: Parameters<typeof listener>[0]
      ): void => listener(status)
      ipcRenderer.on(IPC_EVENTS.sshAgentStatusChanged, wrappedListener)
      return () => ipcRenderer.removeListener(IPC_EVENTS.sshAgentStatusChanged, wrappedListener)
    }
  },
  sync: {
    status: () => ipcRenderer.invoke(IPC_CHANNELS.syncStatus),
    connect: (request) => ipcRenderer.invoke(IPC_CHANNELS.syncConnect, request),
    unlock: (request) => ipcRenderer.invoke(IPC_CHANNELS.syncUnlock, request),
    now: () => ipcRenderer.invoke(IPC_CHANNELS.syncNow),
    disconnect: () => ipcRenderer.invoke(IPC_CHANNELS.syncDisconnect),
    onChanged: (listener) => {
      const wrappedListener = (
        _event: IpcRendererEvent,
        status: Parameters<typeof listener>[0]
      ): void => listener(status)
      ipcRenderer.on(IPC_EVENTS.syncChanged, wrappedListener)

      return () => ipcRenderer.removeListener(IPC_EVENTS.syncChanged, wrappedListener)
    }
  },
  accountSecurity: {
    profile: () => ipcRenderer.invoke(IPC_CHANNELS.accountSecurityProfile),
    devices: () => ipcRenderer.invoke(IPC_CHANNELS.accountDevices),
    resendVerification: () => ipcRenderer.invoke(IPC_CHANNELS.accountResendVerification),
    copyApiClientId: () => ipcRenderer.invoke(IPC_CHANNELS.accountCopyApiClientId),
    copyApiKey: (request) => ipcRenderer.invoke(IPC_CHANNELS.accountCopyApiKey, request),
    twoFactorStatus: () => ipcRenderer.invoke(IPC_CHANNELS.accountTwoFactorStatus),
    disableTwoFactorProvider: (request) =>
      ipcRenderer.invoke(IPC_CHANNELS.accountDisableTwoFactorProvider, request),
    copyRecoveryCode: (request) =>
      ipcRenderer.invoke(IPC_CHANNELS.accountCopyRecoveryCode, request),
    beginAuthenticatorSetup: (request) =>
      ipcRenderer.invoke(IPC_CHANNELS.accountBeginAuthenticatorSetup, request),
    copyAuthenticatorKey: (request) =>
      ipcRenderer.invoke(IPC_CHANNELS.accountCopyAuthenticatorKey, request),
    completeAuthenticatorSetup: (request) =>
      ipcRenderer.invoke(IPC_CHANNELS.accountCompleteAuthenticatorSetup, request),
    beginEmailTwoFactorSetup: (request) =>
      ipcRenderer.invoke(IPC_CHANNELS.accountBeginEmailTwoFactorSetup, request),
    sendEmailTwoFactorSetup: (request) =>
      ipcRenderer.invoke(IPC_CHANNELS.accountSendEmailTwoFactorSetup, request),
    completeEmailTwoFactorSetup: (request) =>
      ipcRenderer.invoke(IPC_CHANNELS.accountCompleteEmailTwoFactorSetup, request)
  },
  domainRules: {
    get: () => ipcRenderer.invoke(IPC_CHANNELS.domainRulesGet),
    update: (request) => ipcRenderer.invoke(IPC_CHANNELS.domainRulesUpdate, request)
  },
  sends: {
    list: () => ipcRenderer.invoke(IPC_CHANNELS.sendList),
    create: (request) => ipcRenderer.invoke(IPC_CHANNELS.sendCreate, request),
    createFile: (request) => ipcRenderer.invoke(IPC_CHANNELS.sendCreateFile, request),
    downloadFile: (request) => ipcRenderer.invoke(IPC_CHANNELS.sendDownloadFile, request),
    update: (request) => ipcRenderer.invoke(IPC_CHANNELS.sendUpdate, request),
    removePassword: (request) => ipcRenderer.invoke(IPC_CHANNELS.sendRemovePassword, request),
    delete: (request) => ipcRenderer.invoke(IPC_CHANNELS.sendDelete, request),
    copyLink: (request) => ipcRenderer.invoke(IPC_CHANNELS.sendCopyLink, request)
  },
  settings: {
    get: () => ipcRenderer.invoke(IPC_CHANNELS.settingsGet),
    update: (request) => ipcRenderer.invoke(IPC_CHANNELS.settingsUpdate, request),
    enableTouchId: (request) => ipcRenderer.invoke(IPC_CHANNELS.settingsEnableTouchId, request),
    disableTouchId: () => ipcRenderer.invoke(IPC_CHANNELS.settingsDisableTouchId),
    unlockTouchId: () => ipcRenderer.invoke(IPC_CHANNELS.settingsUnlockTouchId),
    activity: () => ipcRenderer.invoke(IPC_CHANNELS.settingsActivity)
  }
}

if (!process.contextIsolated) {
  throw new Error('BearWarden requires Electron context isolation')
}

contextBridge.exposeInMainWorld('bearwarden', api)
