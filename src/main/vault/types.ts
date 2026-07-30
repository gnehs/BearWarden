import type {
  CollectionView,
  FolderView,
  GeneratorHistoryEntry,
  LoginView,
  OrganizationView,
  SendView,
  VaultCustomField,
  VaultItemFields,
  VaultPasswordHistoryEntry,
  VaultReprompt
} from '../../shared/vault-contract'
import type { BitwardenDirectState, BitwardenSyncClient } from '../bitwarden-direct'
import type { BitwardenEquivalentDomainSettings } from '../bitwarden-http'
import type { RandomInt } from '../credential-generator'
import type { NativeAttachmentBackupSource } from '../native-attachment-backup'
import type { NativeAttachmentRestoreJournal } from '../native-attachment-restore'
import type { StoredPasskeyCredential } from '../passkey'
import type { SshAgentSignature } from '../ssh-agent-crypto'
import type { SshAgentRsaHash } from '../ssh-agent-protocol'
import type { VaultAttachmentFileService } from '../vault-attachment-files'
import type { PortableVaultSnapshot } from '../vault-portability-codec'
import type { AccountWebAuthnAssertion, AccountWebAuthnChallenge } from '../account-webauthn-codec'
import type {
  AccountWebAuthnAttestation,
  AccountWebAuthnRegistrationChallenge
} from '../account-webauthn-registration-codec'
import type { DATA_VERSION } from './limits'

export interface StoredLogin
  extends
    Omit<
      LoginView,
      | 'subtitle'
      | 'hasTotp'
      | 'passkeys'
      | 'customFields'
      | 'passwordHistoryCount'
      | 'passwordUpdatedAt'
      | 'attachmentCount'
    >,
    VaultItemFields {
  passkeys: StoredPasskeyCredential[]
  customFields: VaultCustomField[]
  passwordHistory: VaultPasswordHistoryEntry[]
  passwordRevisionDate: string | null
  autofillOnPageLoad: boolean | null
}

export interface StoredSend extends SendView {}

export interface StoredSharedLogin extends StoredLogin {
  organizationId: string
  collectionIds: string[]
  shared: true
  edit: boolean
  viewPassword: boolean
  delete: boolean
  restore: boolean
}

export interface SyncEntityMapping {
  localId: string
  remoteId: string
  baseFingerprint: string
}

export interface SyncTombstone {
  localId: string
  remoteId: string
  baseFingerprint: string
}

export interface PendingLoginMutation {
  intent: 'converge' | 'hard-delete'
  localId: string
  remoteId: string
  remoteFolderId: string | null
  expectedRemoteFingerprints: string[]
}

export interface PendingLoginImportEntry {
  localId: string
  marker: string
  remoteFolderId: string | null
  baseFingerprint: string
}

export interface PendingLoginImport {
  phase: 'prepared' | 'dispatched' | 'retry-approved'
  startedAt: string
  entries: PendingLoginImportEntry[]
}

export interface PendingPersonalVaultPurge {
  phase: 'prepared' | 'dispatched'
  startedAt: string
  remainingItems: number
  remainingFolders: number
}

export interface PersistedSyncData {
  provider: 'bitwarden'
  serverUrl: string
  email: string
  state: BitwardenDirectState
  /** Account key material protected at rest by the encrypted local vault. Never expose over IPC. */
  unlockMaterial: PersistedSyncUnlockMaterial | null
  lastSyncAt: string | null
  /**
   * Forces an authoritative sync after personal ciphers were quarantined, including one recovery
   * pass after the connector can decrypt them again. Optional for vaults written before this flag.
   */
  requiresFullSyncAfterCipherIsolation?: boolean
  folderMappings: SyncEntityMapping[]
  loginMappings: SyncEntityMapping[]
  folderTombstones: SyncTombstone[]
  loginTombstones: SyncTombstone[]
  pendingLoginMutation: PendingLoginMutation | null
  pendingLoginImport: PendingLoginImport | null
  pendingPersonalVaultPurge: PendingPersonalVaultPurge | null
  domainSettings: BitwardenEquivalentDomainSettings | null
}

export interface PersistedSyncUnlockMaterial {
  accountKey: string
  wrappedKeyFingerprint: string
}

export interface VaultData {
  version: typeof DATA_VERSION
  createdAt: string
  updatedAt: string
  folders: FolderView[]
  logins: StoredLogin[]
  organizations: OrganizationView[]
  collections: CollectionView[]
  sharedLogins: StoredSharedLogin[]
  sends: StoredSend[]
  generatorHistory: GeneratorHistoryEntry[]
  sync: PersistedSyncData | null
  nativeAttachmentRestore: NativeAttachmentRestoreJournal | null
  masterPasswordChange: MasterPasswordChangeJournal | null
}

export interface MasterPasswordChangeJournal {
  phase: 'prepared' | 'remote-confirmed' | 'local-rekeyed'
  startedAt: string
  updatedAt: string
  accountFingerprint: string
}

export interface VaultMasterPasswordChangeStatus {
  phase: MasterPasswordChangeJournal['phase'] | null
  needsReconnect: boolean
  needsRemoteVerification: boolean
}

export interface VaultMasterPasswordChangeRequest {
  currentPassword: string
  newPassword: string
  hint?: string | null
}

export interface VaultMasterPasswordChangeResolutionRequest {
  currentPassword: string
  newPassword: string
}

export type VaultMasterPasswordChangeResolution =
  | { status: 'resolved' }
  | { status: 'remote-not-changed' }
  | { status: 'needs-reconnect' }
  | { status: 'indeterminate' }

export interface VaultPlatform {
  copyText: (text: string) => void | Promise<void>
  /** Copies highly sensitive text with a hard lifetime cap independent of user settings. */
  copySensitiveText?: (text: string, maxLifetimeSeconds: number) => void | Promise<void>
  openExternal: (url: string) => void | Promise<void>
}

/** Main-process-only input for the native Web Vault provider-7 connector. */
export interface VaultAccountWebAuthnRequest {
  readonly webVaultUrl: string
  readonly challenge: AccountWebAuthnChallenge
  readonly remember: boolean
  readonly signal: AbortSignal
}

export type VaultAccountWebAuthnAssertionRequester = (
  request: VaultAccountWebAuthnRequest
) => Promise<AccountWebAuthnAssertion>

/** Main-process-only input for the isolated native WebAuthn registration ceremony. */
export interface VaultAccountWebAuthnRegistrationRequest {
  readonly webVaultUrl: string
  readonly challenge: AccountWebAuthnRegistrationChallenge
  readonly signal: AbortSignal
}

export type VaultAccountWebAuthnRegistrationRequester = (
  request: VaultAccountWebAuthnRegistrationRequest
) => Promise<AccountWebAuthnAttestation>

export interface VaultServiceOptions {
  now?: () => Date
  createId?: () => string
  createSyncClient?: (sync: PersistedSyncData) => BitwardenSyncClient
  fetch?: typeof fetch
  randomInt?: RandomInt
  attachmentFiles?: VaultAttachmentFileService
  /** Main-process-only bridge to the one-shot Web Vault provider-7 connector. */
  requestAccountWebAuthnAssertion?: VaultAccountWebAuthnAssertionRequester
  /** Main-process-only bridge to the isolated WebAuthn credential-creation window. */
  requestAccountWebAuthnRegistration?: VaultAccountWebAuthnRegistrationRequester
}

export interface VaultExportSnapshot {
  snapshot: PortableVaultSnapshot
  skippedTrashItems: number
}

export interface VaultNativeAttachmentBackupSource extends NativeAttachmentBackupSource {
  exportedFolders: number
  exportedItems: number
  skippedTrashItems: number
  dispose(): void
}

export interface VaultNativeAttachmentRestoreSummary {
  phase: NativeAttachmentRestoreJournal['phase']
  totalItems: number
  mappedItems: number
  totalAttachments: number
  uploadedAttachments: number
  needsReconciliationAttachments: number
  totalBytes: number
  completedBytes: number
}

/** Main-process-only SSH Agent identity metadata. Private key material is never exposed here. */
export interface SshAgentVaultIdentity {
  itemId: string
  name: string
  publicKeyBlob: Buffer
  fingerprint: string
  reprompt: VaultReprompt
  generation: number
}

export interface SshAgentVaultSignRequest {
  publicKeyBlob: Buffer
  data: Buffer
  rsaHash: SshAgentRsaHash | undefined
  /** The unlocked-vault epoch in which the approval context was created. */
  expectedGeneration: number
}

export interface SshAgentVaultSignResult extends SshAgentSignature {
  itemId: string
  generation: number
}

export type SshAgentVaultAuthorizationValidator = (
  ids: readonly string[],
  state: { generation: number }
) => boolean

export type PasskeyVaultAuthorizationValidator = SshAgentVaultAuthorizationValidator

/**
 * Main-process-only metadata used by native/browser WebAuthn coordinators. No private key
 * material is present, and this type must not be added to the preload contract.
 */
export interface PasskeyVaultCredentialCandidate {
  itemId: string
  itemName: string
  itemUpdatedAt: string
  reprompt: VaultReprompt
  credentialId: Uint8Array
  rpId: string
  userHandle: string | null
  userName: string | null
  userDisplayName: string | null
  discoverable: boolean
}

export interface PasskeyVaultDiscoveryRequest {
  rpId: string
  /** An absent or empty list requests discoverable credentials. */
  allowCredentialIds?: readonly Uint8Array[]
}

export interface PasskeyVaultDiscoveryResult {
  generation: number
  credentials: PasskeyVaultCredentialCandidate[]
}

/**
 * Main-process-only, renderer-safe metadata for choosing a login during passkey creation.
 * It intentionally excludes all credential and secret fields and must not be added to preload.
 */
export interface PasskeyVaultCreationTarget {
  itemId: string
  itemName: string
  itemUpdatedAt: string
  reprompt: VaultReprompt
  existingPasskeyCount: 0 | 1
}

export interface PasskeyVaultCreationTargetDiscoveryResult {
  generation: number
  targets: PasskeyVaultCreationTarget[]
}

export interface PasskeyVaultCreationTargetDiscoveryRequest {
  rpId: string
  origin: string
}

export interface PasskeyVaultCreateRequest {
  itemId: string
  expectedUpdatedAt: string
  /** Binds an interactive approval to one unlocked-vault epoch. */
  expectedGeneration: number
  rpId: string
  rpName: string
  userHandle: Uint8Array
  userName: string
  userDisplayName: string
  discoverable: boolean
  excludeCredentialIds?: readonly Uint8Array[]
  replaceExisting: boolean
  requireUserVerification: boolean
  /** Trusted only because this API is main-process-only. */
  userVerified: boolean
}

export interface PasskeyVaultCreateResult {
  item: LoginView
  generation: number
  credentialId: Uint8Array
  attestationObject: Uint8Array
  authenticatorData: Uint8Array
  publicKey: Uint8Array
  publicKeyAlgorithm: -7
}

export interface PasskeyVaultAssertionRequest {
  itemId: string
  credentialId: Uint8Array
  expectedUpdatedAt: string
  /** Binds credential selection and interactive approval to one unlocked-vault epoch. */
  expectedGeneration: number
  rpId: string
  clientDataHash: Uint8Array
  /** An absent or empty list requests a discoverable credential. */
  allowCredentialIds?: readonly Uint8Array[]
  requireUserVerification: boolean
  /** Trusted only because this API is main-process-only. */
  userVerified: boolean
}

export interface PasskeyVaultAssertionResult {
  itemId: string
  generation: number
  credentialId: Uint8Array
  userHandle: Uint8Array | null
  authenticatorData: Uint8Array
  signature: Uint8Array
  counter: string
  /** Main-only lifecycle hint; true only when the encrypted vault committed a counter update. */
  didPersistCounter: boolean
}

export interface PasskeyVaultMatch {
  login: StoredLogin
  passkey: StoredPasskeyCredential
  passkeyIndex: number
  credentialId: Buffer
}
