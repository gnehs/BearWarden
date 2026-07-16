import { createHash, randomInt as nodeRandomInt, randomUUID } from 'node:crypto'
import { AsyncLocalStorage } from 'node:async_hooks'
import { isIP } from 'node:net'
import { parse as parseDomain } from 'tldts'
import { utils } from 'ssh2'
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
  GeneratorCredentialAlgorithm,
  GeneratorCredentialCategory,
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
  PasskeyDeleteRequest,
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
  VaultCopyField,
  VaultAttachmentView,
  VaultCustomField,
  VaultCustomFieldSource,
  VaultCustomFieldUpdate,
  VaultCustomFieldView,
  VaultEditorSecretField,
  VaultItemFields,
  VaultLoginUri,
  VaultPasswordHistoryEntry,
  VaultItemType,
  VaultHealthExposedReport,
  VaultHealthAccountBreachReport,
  VaultHealthAccountBreachRequest,
  VaultHealthReport,
  VaultReprompt,
  VaultUriMatch,
  VaultSecretField,
  SyncConnectRequest,
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
  MAX_LOGIN_SEARCH_QUERY_LENGTH,
  VAULT_LINKED_FIELD_IDS_BY_TYPE
} from '../shared/vault-contract'
import {
  BitwardenDirectError,
  type BitwardenFolder,
  type BitwardenLoginDraft,
  type BitwardenLoginItem,
  type BitwardenOrganizationCipher,
  type BitwardenSendDraft,
  type BitwardenSendItem,
  type BitwardenDirectState,
  type BitwardenFileSendDraft,
  type BitwardenSyncClient,
  type BitwardenTwoFactor
} from './bitwarden-direct'
import {
  resolveBitwardenUrls,
  type BitwardenEquivalentDomainSettings,
  type BitwardenEquivalentDomainUpdate,
  type BitwardenEmergencyAccess
} from './bitwarden-http'
import { EncryptedVaultStore } from './encrypted-vault-store'
import { PinUnlockCapability, PinUnlockError } from './pin-unlock'
import type { BitwardenNotificationConnectionInfo } from './bitwarden-notifications'
import { searchVaultItems, type VaultSearchItem } from './vault-search'
import { analyzeVaultHealth, type VaultHealthItem } from './vault-health'
import { hashPasswordsForPwnedLookup, PwnedPasswordsClient } from './pwned-passwords'
import {
  generateCatchAllEmail,
  generatePassphrase,
  generatePassword,
  generatePlusAddressedEmail,
  generateRandomWordUsername,
  type RandomInt
} from './credential-generator'
import { loadEffLongWordlist } from './eff-wordlist'
import {
  buildBitwardenJson,
  parseBitwardenJson,
  type PortableVaultSnapshot
} from './vault-portability-codec'
import type {
  NativeAttachmentBackupEntry,
  NativeAttachmentBackupPreview,
  NativeAttachmentBackupSource
} from './native-attachment-backup'
import type { BitwardenAttachmentByteSource } from './bitwarden-attachment-stream'
import {
  assertNativeAttachmentRestoreBinding,
  beginNativeAttachmentRestoreAttempt,
  bindNativeAttachmentRestoreRemoteItem,
  completeNativeAttachmentRestoreAttempt,
  createNativeAttachmentRestoreJournal,
  failNativeAttachmentRestoreAttempt,
  parseNativeAttachmentRestoreJournal,
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
import { type StoredPasskeyCredential, toPasskeyView } from './passkey'
import {
  createPasskeyCredential as createSoftwarePasskeyCredential,
  getPasskeyAssertion as createSoftwarePasskeyAssertion
} from './passkey-authenticator'
import { generateTotp } from './totp'
import { generateSshKeyMaterial, type SshKeyMaterial } from './ssh-key'
import {
  signSshAgentData as createSshAgentSignature,
  type SshAgentSignature
} from './ssh-agent-crypto'
import { SSH_AGENT_MAX_MESSAGE_LENGTH, type SshAgentRsaHash } from './ssh-agent-protocol'
import {
  fetchWebsiteIconDataUrl,
  parseWebsiteHostname,
  resolveWebsiteIconUrl
} from './website-icon'
import { createUriMatchBudget, loginUrisMatch } from './uri-matcher'
import { validatePasskeyOrigin } from './passkey-origin-validation'

const LEGACY_DATA_VERSION = 1
const CLI_DATA_VERSION = 2
const ITEM_TYPES_DATA_VERSION = 4
const PASSKEYS_DATA_VERSION = 5
const CUSTOM_FIELDS_DATA_VERSION = 6
const TRASH_DATA_VERSION = 7
const PENDING_LOGIN_MUTATION_DATA_VERSION = 8
const ARCHIVE_DATA_VERSION = 9
const REPROMPT_DATA_VERSION = 10
const MULTIPLE_URIS_DATA_VERSION = 11
const PASSWORD_HISTORY_DATA_VERSION = 12
const GENERATOR_HISTORY_DATA_VERSION = 13
const ATTACHMENTS_DATA_VERSION = 14
const EQUIVALENT_DOMAINS_DATA_VERSION = 15
const SENDS_DATA_VERSION = 16
const ORGANIZATIONS_DATA_VERSION = 17
const NATIVE_ATTACHMENT_RESTORE_DATA_VERSION = 18
const DATA_VERSION = 18
const MIN_MASTER_PASSWORD_LENGTH = 12
const MAX_MASTER_PASSWORD_LENGTH = 1024
const MAX_NAME_LENGTH = 256
const MAX_USERNAME_LENGTH = 512
const MAX_PASSWORD_LENGTH = 16_384
const AUTHENTICATOR_SETUP_TTL_MS = 5 * 60 * 1_000
const MAX_AUTHENTICATOR_SETUP_SESSIONS = 8
const EMAIL_TWO_FACTOR_SETUP_TTL_MS = 5 * 60 * 1_000
const MAX_EMAIL_TWO_FACTOR_SETUP_SESSIONS = 8
const MAX_URI_LENGTH = 4096
const MAX_LOGIN_URIS = 1_000
const MAX_NOTES_LENGTH = 65_536
const MAX_ITEM_FIELD_LENGTH = 4_096
const MAX_CUSTOM_FIELDS = 1_000
const MAX_CUSTOM_FIELD_NAME_LENGTH = 5_000
const MAX_CUSTOM_FIELD_VALUE_LENGTH = 5_000
const MAX_PASSWORD_HISTORY = 5
const MAX_ATTACHMENTS = 1_000
const MAX_ATTACHMENT_ID_LENGTH = 256
const MAX_ATTACHMENT_FILE_NAME_LENGTH = 255
const MAX_ATTACHMENT_SIZE_NAME_LENGTH = 64
const MAX_GENERATOR_HISTORY = 200
const MAX_GENERATED_CREDENTIAL_LENGTH = 512
const MAX_SENDS = 10_000
const MAX_REMOTE_ENTITIES = 100_000
const MAX_SEND_TEXT_LENGTH = 1024 * 1024
const MAX_SEND_FILE_ID_LENGTH = 256
const MAX_SEND_FILE_NAME_LENGTH = 255
const MAX_SEND_FILE_SIZE = 550_502_400
const MAX_SEND_FILE_SIZE_NAME_LENGTH = 64
const MAX_SSH_PRIVATE_KEY_LENGTH = 1024 * 1024
const MAX_SYNC_SECRET_LENGTH = 16_384
const MAX_EQUIVALENT_DOMAIN_GROUPS = 10_000
const MAX_EQUIVALENT_DOMAINS_PER_GROUP = 1_000
const MAX_EQUIVALENT_DOMAIN_TOTAL = 100_000
const MAX_EQUIVALENT_DOMAIN_LENGTH = 1_024
const MAX_TWO_FACTOR_CODE_LENGTH = 256
const MAX_PASSKEY_CREDENTIAL_DESCRIPTORS = 1_000
const MAX_PASSKEY_CREDENTIAL_ID_BYTES = 1_023
const MAX_PASSKEY_RP_ID_LENGTH = 253
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const PASSKEY_UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u

interface StoredLogin
  extends
    Omit<
      LoginView,
      | 'subtitle'
      | 'hasTotp'
      | 'passkeys'
      | 'customFields'
      | 'passwordHistoryCount'
      | 'attachmentCount'
    >,
    VaultItemFields {
  passkeys: StoredPasskeyCredential[]
  customFields: VaultCustomField[]
  passwordHistory: VaultPasswordHistoryEntry[]
}

interface StoredSend extends SendView {}

interface StoredSharedLogin extends StoredLogin {
  organizationId: string
  collectionIds: string[]
  shared: true
  edit: boolean
  viewPassword: boolean
  delete: boolean
  restore: boolean
}

interface SyncEntityMapping {
  localId: string
  remoteId: string
  baseFingerprint: string
}

interface SyncTombstone {
  localId: string
  remoteId: string
  baseFingerprint: string
}

interface PendingLoginMutation {
  intent: 'converge' | 'hard-delete'
  localId: string
  remoteId: string
  remoteFolderId: string | null
  expectedRemoteFingerprints: string[]
}

export interface PersistedSyncData {
  provider: 'bitwarden'
  serverUrl: string
  email: string
  state: BitwardenDirectState
  lastSyncAt: string | null
  folderMappings: SyncEntityMapping[]
  loginMappings: SyncEntityMapping[]
  folderTombstones: SyncTombstone[]
  loginTombstones: SyncTombstone[]
  pendingLoginMutation: PendingLoginMutation | null
  domainSettings: BitwardenEquivalentDomainSettings | null
}

interface VaultData {
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
}

export interface VaultPlatform {
  copyText: (text: string) => void | Promise<void>
  /** Copies highly sensitive text with a hard lifetime cap independent of user settings. */
  copySensitiveText?: (text: string, maxLifetimeSeconds: number) => void | Promise<void>
  openExternal: (url: string) => void | Promise<void>
}

export interface VaultServiceOptions {
  now?: () => Date
  createId?: () => string
  createSyncClient?: (sync: PersistedSyncData) => BitwardenSyncClient
  fetch?: typeof fetch
  randomInt?: RandomInt
  attachmentFiles?: VaultAttachmentFileService
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

interface PasskeyVaultMatch {
  login: StoredLogin
  passkey: StoredPasskeyCredential
  passkeyIndex: number
  credentialId: Buffer
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function normalizePasskeyRpId(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_PASSKEY_RP_ID_LENGTH ||
    value !== value.toLowerCase() ||
    !/^[\x21-\x7e]+$/u.test(value) ||
    isIP(value) !== 0
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  if (value === 'localhost') return value
  if (value.endsWith('.') || !value.includes('.')) throw new VaultError('INVALID_INPUT')
  for (const label of value.split('.')) {
    if (
      label.length === 0 ||
      label.length > 63 ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label)
    ) {
      throw new VaultError('INVALID_INPUT')
    }
  }
  return value
}

function normalizePasskeyCredentialId(value: unknown): Buffer {
  if (
    !(value instanceof Uint8Array) ||
    value.byteLength === 0 ||
    value.byteLength > MAX_PASSKEY_CREDENTIAL_ID_BYTES
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return Buffer.from(value)
}

function normalizePasskeyCredentialIds(value: unknown): Buffer[] {
  if (value === undefined) return []
  if (!Array.isArray(value) || value.length > MAX_PASSKEY_CREDENTIAL_DESCRIPTORS) {
    throw new VaultError('INVALID_INPUT')
  }
  return value.map(normalizePasskeyCredentialId)
}

function decodeStoredPasskeyCredentialId(value: unknown): Buffer | null {
  if (typeof value !== 'string') return null
  if (value.startsWith('b64.')) {
    const encoded = value.slice(4)
    if (
      encoded.length === 0 ||
      encoded.length > Math.ceil((MAX_PASSKEY_CREDENTIAL_ID_BYTES * 4) / 3) ||
      !BASE64URL_PATTERN.test(encoded)
    ) {
      return null
    }
    const decoded = Buffer.from(encoded, 'base64url')
    return decoded.byteLength > 0 &&
      decoded.byteLength <= MAX_PASSKEY_CREDENTIAL_ID_BYTES &&
      decoded.toString('base64url') === encoded
      ? decoded
      : null
  }
  return PASSKEY_UUID_PATTERN.test(value) ? Buffer.from(value.replaceAll('-', ''), 'hex') : null
}

function credentialIdIsAllowed(
  credentialId: Buffer,
  allowCredentialIds: readonly Buffer[]
): boolean {
  return allowCredentialIds.some((allowed) => allowed.equals(credentialId))
}

function assertPasskeyApproval(
  requireUserVerification: unknown,
  userVerified: unknown
): asserts userVerified is boolean {
  if (typeof requireUserVerification !== 'boolean' || typeof userVerified !== 'boolean') {
    throw new VaultError('INVALID_INPUT')
  }
  if (!userVerified && requireUserVerification) {
    throw new VaultError('REPROMPT_REQUIRED')
  }
}

function assertIsoDate(value: unknown): asserts value is string {
  if (
    typeof value !== 'string' ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
}

function assertUuid(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) {
    throw new VaultError('INVALID_INPUT')
  }
}

function parseFolder(value: unknown): FolderView {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  if (
    typeof value.id !== 'string' ||
    !UUID_PATTERN.test(value.id) ||
    typeof value.name !== 'string' ||
    value.name.length === 0 ||
    value.name.length > MAX_NAME_LENGTH ||
    typeof value.position !== 'number' ||
    !Number.isSafeInteger(value.position) ||
    value.position < 0
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  assertIsoDate(value.createdAt)
  assertIsoDate(value.updatedAt)

  return {
    id: value.id,
    name: value.name,
    position: value.position,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt
  }
}

function parseNullableString(value: unknown, maxLength: number): string | null {
  if (value === null) return null
  if (typeof value !== 'string' || value.length > maxLength) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return value
}

function isVaultUriMatch(value: unknown): value is VaultUriMatch {
  return value === 0 || value === 1 || value === 2 || value === 3 || value === 4 || value === 5
}

function parseStoredLoginUris(value: unknown): VaultLoginUri[] {
  if (!Array.isArray(value) || value.length > MAX_LOGIN_URIS) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return value.map((entry) => {
    if (
      !isRecord(entry) ||
      typeof entry.uri !== 'string' ||
      entry.uri.length > MAX_URI_LENGTH ||
      (entry.match !== null && !isVaultUriMatch(entry.match))
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    return { uri: entry.uri, match: entry.match }
  })
}

function normalizeLoginUris(value: unknown): VaultLoginUri[] {
  if (!Array.isArray(value) || value.length > MAX_LOGIN_URIS) {
    throw new VaultError('INVALID_INPUT')
  }
  return value.map((entry) => {
    if (
      !isRecord(entry) ||
      typeof entry.uri !== 'string' ||
      entry.uri.length > MAX_URI_LENGTH ||
      entry.uri.trim().length === 0 ||
      (entry.match !== null && !isVaultUriMatch(entry.match))
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    return { uri: entry.uri, match: entry.match }
  })
}

function cloneLoginUris(uris: readonly VaultLoginUri[]): VaultLoginUri[] {
  return uris.map((entry) => ({ ...entry }))
}

function parsePasswordHistory(value: unknown): VaultPasswordHistoryEntry[] {
  if (!Array.isArray(value) || value.length > MAX_PASSWORD_HISTORY) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return value.map((entry) => {
    if (
      !isRecord(entry) ||
      Object.keys(entry).length !== 2 ||
      !Object.hasOwn(entry, 'password') ||
      !Object.hasOwn(entry, 'lastUsedDate') ||
      typeof entry.password !== 'string' ||
      entry.password.length === 0 ||
      entry.password.length > MAX_PASSWORD_LENGTH ||
      typeof entry.lastUsedDate !== 'string' ||
      !Number.isFinite(Date.parse(entry.lastUsedDate)) ||
      new Date(entry.lastUsedDate).toISOString() !== entry.lastUsedDate
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    return { password: entry.password, lastUsedDate: entry.lastUsedDate }
  })
}

function clonePasswordHistory(
  entries: readonly VaultPasswordHistoryEntry[]
): VaultPasswordHistoryEntry[] {
  return entries.map((entry) => ({ ...entry }))
}

function generatorCategoryForAlgorithm(
  algorithm: GeneratorCredentialAlgorithm
): GeneratorCredentialCategory {
  if (algorithm === 'password' || algorithm === 'passphrase') return 'password'
  if (algorithm === 'username') return 'username'
  return 'email'
}

function isGeneratorCategory(value: unknown): value is GeneratorCredentialCategory {
  return value === 'password' || value === 'username' || value === 'email'
}

function isGeneratorAlgorithm(value: unknown): value is GeneratorCredentialAlgorithm {
  return (
    value === 'password' ||
    value === 'passphrase' ||
    value === 'username' ||
    value === 'subaddress' ||
    value === 'catchall'
  )
}

function parseGeneratorHistory(value: unknown): GeneratorHistoryEntry[] {
  if (!Array.isArray(value) || value.length > MAX_GENERATOR_HISTORY) {
    throw new VaultError('CORRUPT_VAULT')
  }
  const credentials = new Set<string>()
  return value.map((entry) => {
    if (!isRecord(entry)) throw new VaultError('CORRUPT_VAULT')
    const keys = Object.keys(entry)
    if (
      keys.some(
        (key) =>
          key !== 'credential' &&
          key !== 'category' &&
          key !== 'generationDate' &&
          key !== 'algorithm'
      ) ||
      !Object.hasOwn(entry, 'credential') ||
      !Object.hasOwn(entry, 'category') ||
      !Object.hasOwn(entry, 'generationDate') ||
      typeof entry.credential !== 'string' ||
      entry.credential.length === 0 ||
      entry.credential.length > MAX_GENERATED_CREDENTIAL_LENGTH ||
      credentials.has(entry.credential) ||
      !isGeneratorCategory(entry.category) ||
      typeof entry.generationDate !== 'number' ||
      !Number.isSafeInteger(entry.generationDate) ||
      entry.generationDate < 0 ||
      entry.generationDate > 8_640_000_000_000_000 ||
      (entry.algorithm !== undefined &&
        (!isGeneratorAlgorithm(entry.algorithm) ||
          generatorCategoryForAlgorithm(entry.algorithm) !== entry.category))
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    credentials.add(entry.credential)
    return {
      credential: entry.credential,
      category: entry.category,
      generationDate: entry.generationDate,
      ...(entry.algorithm === undefined ? {} : { algorithm: entry.algorithm })
    }
  })
}

function cloneGeneratorHistory(entries: readonly GeneratorHistoryEntry[]): GeneratorHistoryEntry[] {
  return entries.map((entry) => ({ ...entry }))
}

function uriAlias(uris: readonly VaultLoginUri[]): string | null {
  return uris[0]?.uri ?? null
}

const ITEM_FIELD_NAMES = [
  'username',
  'password',
  'totp',
  'uri',
  'cardholderName',
  'brand',
  'number',
  'expMonth',
  'expYear',
  'code',
  'title',
  'firstName',
  'middleName',
  'lastName',
  'address1',
  'address2',
  'address3',
  'city',
  'state',
  'postalCode',
  'country',
  'company',
  'email',
  'phone',
  'ssn',
  'identityUsername',
  'passportNumber',
  'licenseNumber',
  'privateKey',
  'publicKey',
  'fingerprint'
] as const satisfies readonly (keyof VaultItemFields)[]

type ItemFieldName = (typeof ITEM_FIELD_NAMES)[number]

const ITEM_FIELDS_BY_TYPE: Record<VaultItemType, readonly ItemFieldName[]> = {
  login: ['username', 'password', 'totp', 'uri'],
  card: ['cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code'],
  identity: [
    'title',
    'firstName',
    'middleName',
    'lastName',
    'address1',
    'address2',
    'address3',
    'city',
    'state',
    'postalCode',
    'country',
    'company',
    'email',
    'phone',
    'ssn',
    'identityUsername',
    'passportNumber',
    'licenseNumber'
  ],
  secureNote: [],
  sshKey: ['privateKey', 'publicKey', 'fingerprint']
}

const SECRET_FIELDS_BY_TYPE: Record<VaultItemType, readonly VaultSecretField[]> = {
  login: ['password'],
  card: ['number', 'code'],
  identity: ['ssn', 'passportNumber', 'licenseNumber'],
  secureNote: [],
  sshKey: ['privateKey']
}

const EDITOR_SECRET_FIELDS_BY_TYPE: Record<VaultItemType, readonly VaultEditorSecretField[]> = {
  ...SECRET_FIELDS_BY_TYPE,
  login: ['password', 'totp']
}

const COPY_FIELDS_BY_TYPE: Record<VaultItemType, readonly VaultCopyField[]> = {
  login: ['username', 'password', 'uri'],
  card: ['number', 'code'],
  identity: ['email', 'phone', 'ssn', 'identityUsername', 'passportNumber', 'licenseNumber'],
  secureNote: [],
  sshKey: ['privateKey', 'publicKey', 'fingerprint']
}

function emptyItemFields(): VaultItemFields {
  return {
    username: '',
    password: '',
    totp: '',
    uri: null,
    cardholderName: '',
    brand: '',
    number: '',
    expMonth: '',
    expYear: '',
    code: '',
    title: '',
    firstName: '',
    middleName: '',
    lastName: '',
    address1: '',
    address2: '',
    address3: '',
    city: '',
    state: '',
    postalCode: '',
    country: '',
    company: '',
    email: '',
    phone: '',
    ssn: '',
    identityUsername: '',
    passportNumber: '',
    licenseNumber: '',
    privateKey: '',
    publicKey: '',
    fingerprint: ''
  }
}

function normalizeItemFieldsForStorage(input: VaultItemFields): VaultItemFields {
  const fields = emptyItemFields()
  for (const field of ITEM_FIELD_NAMES) {
    const value = input[field]
    if (field === 'uri') {
      fields.uri = normalizeNullableString(value, MAX_URI_LENGTH)
    } else {
      fields[field] = normalizeString(value, maxLengthForItemField(field))
    }
  }
  return fields
}

function maxLengthForItemField(field: ItemFieldName): number {
  if (field === 'password' || field === 'totp') return MAX_PASSWORD_LENGTH
  if (field === 'uri') return MAX_URI_LENGTH
  if (field === 'privateKey') return MAX_SSH_PRIVATE_KEY_LENGTH
  return MAX_ITEM_FIELD_LENGTH
}

function isVaultItemType(value: unknown): value is VaultItemType {
  return (
    value === 'login' ||
    value === 'card' ||
    value === 'identity' ||
    value === 'secureNote' ||
    value === 'sshKey'
  )
}

function parseSupportedSshAgentPublicKeyBlob(publicKey: string): Buffer | null {
  const parsed = utils.parseKey(publicKey)
  if (parsed instanceof Error || Array.isArray(parsed) || parsed.isPrivateKey()) return null
  if (
    parsed.type !== 'ssh-ed25519' &&
    parsed.type !== 'ssh-rsa' &&
    parsed.type !== 'ecdsa-sha2-nistp256' &&
    parsed.type !== 'ecdsa-sha2-nistp384' &&
    parsed.type !== 'ecdsa-sha2-nistp521'
  ) {
    return null
  }
  const blob = parsed.getPublicSSH()
  return blob.length === 0 || blob.length > SSH_AGENT_MAX_MESSAGE_LENGTH ? null : Buffer.from(blob)
}

function sshAgentFingerprint(publicKeyBlob: Buffer): string {
  return `SHA256:${createHash('sha256').update(publicKeyBlob).digest('base64').replace(/=+$/u, '')}`
}

function parseStoredPasskey(value: unknown): StoredPasskeyCredential {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  const required = [
    'credentialId',
    'keyType',
    'keyAlgorithm',
    'keyCurve',
    'keyValue',
    'rpId',
    'counter',
    'creationDate'
  ] as const
  for (const field of required) {
    if (typeof value[field] !== 'string' || value[field].length > MAX_ITEM_FIELD_LENGTH) {
      throw new VaultError('CORRUPT_VAULT')
    }
  }
  assertIsoDate(value.creationDate)
  if (typeof value.discoverable !== 'boolean') throw new VaultError('CORRUPT_VAULT')
  const optional = (field: string): string | null => {
    const candidate = value[field]
    if (candidate === undefined || candidate === null) return null
    if (typeof candidate !== 'string' || candidate.length > MAX_ITEM_FIELD_LENGTH) {
      throw new VaultError('CORRUPT_VAULT')
    }
    return candidate
  }
  const requiredValue = (field: (typeof required)[number]): string => value[field] as string
  return {
    credentialId: requiredValue('credentialId'),
    keyType: requiredValue('keyType'),
    keyAlgorithm: requiredValue('keyAlgorithm'),
    keyCurve: requiredValue('keyCurve'),
    keyValue: requiredValue('keyValue'),
    rpId: requiredValue('rpId'),
    userHandle: optional('userHandle'),
    userName: optional('userName'),
    counter: requiredValue('counter'),
    rpName: optional('rpName'),
    userDisplayName: optional('userDisplayName'),
    discoverable: value.discoverable,
    creationDate: requiredValue('creationDate')
  }
}

function validateRemotePasskeys(value: unknown): StoredPasskeyCredential[] {
  if (!Array.isArray(value) || value.length > 1_000) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  try {
    return value.map(parseStoredPasskey)
  } catch {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
}

function parseCustomField(value: unknown): VaultCustomField {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  if (
    typeof value.name !== 'string' ||
    value.name.length > MAX_CUSTOM_FIELD_NAME_LENGTH ||
    typeof value.value !== 'string' ||
    value.value.length > MAX_CUSTOM_FIELD_VALUE_LENGTH ||
    (value.type !== 'text' &&
      value.type !== 'hidden' &&
      value.type !== 'boolean' &&
      value.type !== 'linked') ||
    (value.linkedId !== null &&
      (!Number.isSafeInteger(value.linkedId) || (value.linkedId as number) < 0))
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return {
    name: value.name,
    value: value.value,
    type: value.type,
    linkedId: value.linkedId as number | null
  }
}

function cloneCustomFields(fields: readonly VaultCustomField[]): VaultCustomField[] {
  return fields.map((field) => ({ ...field }))
}

function parseStoredAttachment(value: unknown): VaultAttachmentView {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  if (
    typeof value.id !== 'string' ||
    value.id.length === 0 ||
    value.id.length > MAX_ATTACHMENT_ID_LENGTH ||
    typeof value.fileName !== 'string' ||
    value.fileName.length === 0 ||
    value.fileName.length > MAX_ATTACHMENT_FILE_NAME_LENGTH ||
    typeof value.size !== 'number' ||
    !Number.isSafeInteger(value.size) ||
    value.size < 0 ||
    typeof value.sizeName !== 'string' ||
    value.sizeName.length > MAX_ATTACHMENT_SIZE_NAME_LENGTH ||
    typeof value.legacy !== 'boolean'
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return {
    id: value.id,
    fileName: value.fileName,
    size: value.size,
    sizeName: value.sizeName,
    legacy: value.legacy
  }
}

function parseStoredAttachments(value: unknown): VaultAttachmentView[] {
  if (!Array.isArray(value) || value.length > MAX_ATTACHMENTS) {
    throw new VaultError('CORRUPT_VAULT')
  }
  const attachments = value.map(parseStoredAttachment)
  if (new Set(attachments.map((attachment) => attachment.id)).size !== attachments.length) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return attachments
}

function cloneAttachments(attachments: readonly VaultAttachmentView[]): VaultAttachmentView[] {
  return attachments.map((attachment) => ({ ...attachment }))
}

function validateRemoteAttachments(value: unknown): VaultAttachmentView[] {
  try {
    return parseStoredAttachments(value)
  } catch {
    throw new VaultError('SYNC_FAILED')
  }
}

function cloneItemName(name: string): string {
  const suffix = ' - Clone'
  const codePoints = Array.from(name)
  while (codePoints.join('').length > MAX_NAME_LENGTH - suffix.length) codePoints.pop()
  return `${codePoints.join('')}${suffix}`
}

function parseStoredLogin(
  value: unknown,
  legacyItemType = false,
  allowMissingExtendedFields = false,
  allowMissingCustomFields = false,
  allowMissingDeletedAt = false,
  allowMissingArchivedAt = false,
  allowMissingReprompt = false,
  allowMissingUris = false,
  allowMissingPasswordHistory = false,
  allowMissingAttachments = false
): StoredLogin {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  if (
    typeof value.id !== 'string' ||
    !UUID_PATTERN.test(value.id) ||
    typeof value.name !== 'string' ||
    value.name.length === 0 ||
    value.name.length > MAX_NAME_LENGTH ||
    typeof value.username !== 'string' ||
    value.username.length > MAX_USERNAME_LENGTH ||
    typeof value.password !== 'string' ||
    value.password.length > MAX_PASSWORD_LENGTH ||
    typeof value.favorite !== 'boolean'
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }

  const folderId = value.folderId
  const lastUsedAt = value.lastUsedAt
  let parsedFolderId: string | null
  if (folderId === null) {
    parsedFolderId = null
  } else if (typeof folderId === 'string' && UUID_PATTERN.test(folderId)) {
    parsedFolderId = folderId
  } else {
    throw new VaultError('CORRUPT_VAULT')
  }
  let parsedLastUsedAt: string | null
  if (lastUsedAt === null) {
    parsedLastUsedAt = null
  } else {
    assertIsoDate(lastUsedAt)
    parsedLastUsedAt = lastUsedAt
  }
  assertIsoDate(value.createdAt)
  assertIsoDate(value.updatedAt)
  let deletedAt: string | null
  if (allowMissingDeletedAt && value.deletedAt === undefined) {
    deletedAt = null
  } else if (value.deletedAt === null) {
    deletedAt = null
  } else {
    assertIsoDate(value.deletedAt)
    deletedAt = value.deletedAt
  }
  let archivedAt: string | null
  if (allowMissingArchivedAt && value.archivedAt === undefined) {
    archivedAt = null
  } else if (value.archivedAt === null) {
    archivedAt = null
  } else {
    assertIsoDate(value.archivedAt)
    archivedAt = value.archivedAt
  }
  const reprompt =
    allowMissingReprompt && value.reprompt === undefined
      ? 0
      : value.reprompt === 0 || value.reprompt === 1
        ? value.reprompt
        : null
  if (reprompt === null) throw new VaultError('CORRUPT_VAULT')

  const type = legacyItemType ? 'login' : value.type
  if (!isVaultItemType(type)) throw new VaultError('CORRUPT_VAULT')
  const fields = emptyItemFields()
  for (const field of ITEM_FIELD_NAMES) {
    if (allowMissingExtendedFields && !(field in value)) continue
    const raw = value[field]
    if (field === 'uri') {
      fields.uri = parseNullableString(raw, MAX_URI_LENGTH)
      continue
    }
    if (typeof raw !== 'string' || raw.length > maxLengthForItemField(field)) {
      throw new VaultError('CORRUPT_VAULT')
    }
    fields[field] = raw
  }
  const uris = allowMissingUris
    ? fields.uri === null
      ? []
      : [{ uri: fields.uri, match: null }]
    : parseStoredLoginUris(value.uris)
  if (fields.uri !== uriAlias(uris)) throw new VaultError('CORRUPT_VAULT')

  return {
    id: value.id,
    type,
    name: value.name,
    notes: parseNullableString(value.notes, MAX_NOTES_LENGTH),
    folderId: parsedFolderId,
    favorite: value.favorite,
    lastUsedAt: parsedLastUsedAt,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
    deletedAt,
    archivedAt,
    reprompt,
    passkeys:
      allowMissingExtendedFields || value.passkeys === undefined
        ? []
        : (() => {
            if (!Array.isArray(value.passkeys) || value.passkeys.length > 1000) {
              throw new VaultError('CORRUPT_VAULT')
            }
            return value.passkeys.map(parseStoredPasskey)
          })(),
    customFields:
      allowMissingCustomFields && value.customFields === undefined
        ? []
        : (() => {
            if (
              !Array.isArray(value.customFields) ||
              value.customFields.length > MAX_CUSTOM_FIELDS
            ) {
              throw new VaultError('CORRUPT_VAULT')
            }
            return value.customFields.map(parseCustomField)
          })(),
    passwordHistory: allowMissingPasswordHistory ? [] : parsePasswordHistory(value.passwordHistory),
    attachments: allowMissingAttachments ? [] : parseStoredAttachments(value.attachments),
    uris,
    ...fields
  }
}

function parseStoredSend(value: unknown): StoredSend {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  const {
    id,
    accessId,
    type,
    name,
    notes,
    text,
    file,
    hidden,
    maxAccessCount,
    accessCount,
    revisionDate,
    expirationDate,
    deletionDate,
    disabled,
    hideEmail,
    authType,
    passwordProtected
  } = value
  if (
    typeof id !== 'string' ||
    !UUID_PATTERN.test(id) ||
    typeof accessId !== 'string' ||
    !/^[A-Za-z0-9_-]{16,128}$/u.test(accessId) ||
    (type !== 'text' && type !== 'file') ||
    typeof name !== 'string' ||
    name.length === 0 ||
    name.length > MAX_NAME_LENGTH ||
    (notes !== null && typeof notes !== 'string') ||
    (typeof notes === 'string' && notes.length > MAX_NOTES_LENGTH) ||
    (type === 'text' && (typeof text !== 'string' || text.length > MAX_SEND_TEXT_LENGTH)) ||
    (type === 'file' && text !== null && text !== undefined) ||
    (type === 'file' && !isRecord(file)) ||
    typeof hidden !== 'boolean' ||
    (maxAccessCount !== null &&
      (typeof maxAccessCount !== 'number' ||
        !Number.isSafeInteger(maxAccessCount) ||
        (maxAccessCount as number) < 1)) ||
    typeof accessCount !== 'number' ||
    !Number.isSafeInteger(accessCount) ||
    (accessCount as number) < 0 ||
    typeof revisionDate !== 'string' ||
    typeof deletionDate !== 'string' ||
    !Number.isFinite(Date.parse(revisionDate)) ||
    !Number.isFinite(Date.parse(deletionDate)) ||
    (expirationDate !== null &&
      (typeof expirationDate !== 'string' || !Number.isFinite(Date.parse(expirationDate)))) ||
    typeof disabled !== 'boolean' ||
    typeof hideEmail !== 'boolean' ||
    (authType !== 'none' && authType !== 'password') ||
    typeof passwordProtected !== 'boolean'
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  let parsedFile: SendView['file']
  if (type === 'file') {
    const fileRecord = isRecord(file) ? file : null
    if (!fileRecord) throw new VaultError('CORRUPT_VAULT')
    const { id: fileId, fileName, size, sizeName } = fileRecord
    if (
      typeof fileId !== 'string' ||
      fileId.length === 0 ||
      fileId.length > MAX_SEND_FILE_ID_LENGTH ||
      typeof fileName !== 'string' ||
      fileName.length === 0 ||
      fileName.length > MAX_SEND_FILE_NAME_LENGTH ||
      typeof size !== 'number' ||
      !Number.isSafeInteger(size) ||
      size < 1 ||
      size > MAX_SEND_FILE_SIZE ||
      (sizeName !== null &&
        (typeof sizeName !== 'string' || sizeName.length > MAX_SEND_FILE_SIZE_NAME_LENGTH))
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    parsedFile = { id: fileId, fileName, size, sizeName }
  }
  const parsedMaxAccessCount = maxAccessCount === null ? null : (maxAccessCount as number)
  const parsedAccessCount = accessCount as number
  return {
    id,
    accessId,
    type,
    name,
    notes,
    text: type === 'text' ? (text as string) : '',
    ...(parsedFile ? { file: parsedFile } : {}),
    hidden,
    maxAccessCount: parsedMaxAccessCount,
    accessCount: parsedAccessCount,
    revisionDate,
    expirationDate,
    deletionDate,
    disabled,
    hideEmail,
    authType,
    passwordProtected
  }
}

function parseStoredOrganization(value: unknown): OrganizationView {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  const { id, name, status, type, enabled, identifier, hasPublicAndPrivateKeys } = value
  if (
    typeof id !== 'string' ||
    !UUID_PATTERN.test(id) ||
    typeof name !== 'string' ||
    name.length === 0 ||
    name.length > MAX_NAME_LENGTH ||
    (status !== null &&
      (typeof status !== 'number' || !Number.isSafeInteger(status) || status < 0)) ||
    (type !== null && (typeof type !== 'number' || !Number.isSafeInteger(type) || type < 0)) ||
    typeof enabled !== 'boolean' ||
    (identifier !== null &&
      (typeof identifier !== 'string' || identifier.length > MAX_NAME_LENGTH)) ||
    typeof hasPublicAndPrivateKeys !== 'boolean'
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return {
    id,
    name,
    status,
    type,
    enabled,
    identifier,
    hasPublicAndPrivateKeys
  }
}

function parseStoredCollection(value: unknown): CollectionView {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  const { id, organizationId, name, externalId, readOnly, hidePasswords, manage, type, assigned } =
    value
  if (
    typeof id !== 'string' ||
    !UUID_PATTERN.test(id) ||
    typeof organizationId !== 'string' ||
    !UUID_PATTERN.test(organizationId) ||
    typeof name !== 'string' ||
    name.length === 0 ||
    name.length > MAX_NAME_LENGTH ||
    (externalId !== null &&
      (typeof externalId !== 'string' || externalId.length > MAX_NAME_LENGTH)) ||
    typeof readOnly !== 'boolean' ||
    typeof hidePasswords !== 'boolean' ||
    typeof manage !== 'boolean' ||
    typeof type !== 'number' ||
    !Number.isSafeInteger(type) ||
    type < 0 ||
    typeof assigned !== 'boolean'
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return {
    id,
    organizationId,
    name,
    externalId,
    readOnly,
    hidePasswords,
    manage,
    type,
    assigned
  }
}

function parseStoredSharedLogin(value: unknown): StoredSharedLogin {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  const login = parseStoredLogin(value)
  const {
    organizationId,
    collectionIds,
    shared,
    edit,
    viewPassword,
    delete: canDelete,
    restore
  } = value
  if (
    typeof organizationId !== 'string' ||
    !UUID_PATTERN.test(organizationId) ||
    !Array.isArray(collectionIds) ||
    collectionIds.length > MAX_REMOTE_ENTITIES ||
    collectionIds.some((id) => typeof id !== 'string' || !UUID_PATTERN.test(id)) ||
    new Set(collectionIds).size !== collectionIds.length ||
    shared !== true ||
    typeof edit !== 'boolean' ||
    typeof viewPassword !== 'boolean' ||
    typeof canDelete !== 'boolean' ||
    typeof restore !== 'boolean'
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return {
    ...login,
    organizationId,
    collectionIds: [...collectionIds],
    shared,
    edit,
    viewPassword,
    delete: canDelete,
    restore
  }
}

function parseSyncMappings(
  value: unknown,
  localIds: Set<string>,
  label: 'mapping' | 'tombstone'
): SyncEntityMapping[] | SyncTombstone[] {
  if (!Array.isArray(value) || value.length > 100_000) throw new VaultError('CORRUPT_VAULT')
  const remoteIds = new Set<string>()
  const parsed = value.map((entry) => {
    if (!isRecord(entry)) throw new VaultError('CORRUPT_VAULT')
    const remoteId = entry.remoteId
    const baseFingerprint = entry.baseFingerprint
    if (
      typeof remoteId !== 'string' ||
      !UUID_PATTERN.test(remoteId) ||
      typeof baseFingerprint !== 'string' ||
      !/^[0-9a-f]{64}$/.test(baseFingerprint) ||
      remoteIds.has(remoteId)
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    remoteIds.add(remoteId)

    const localId = entry.localId
    if (
      typeof localId !== 'string' ||
      !UUID_PATTERN.test(localId) ||
      (label === 'mapping' && !localIds.has(localId))
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    return { localId, remoteId, baseFingerprint }
  })

  if (label === 'mapping') {
    const mappedLocalIds = new Set((parsed as SyncEntityMapping[]).map((entry) => entry.localId))
    if (mappedLocalIds.size !== parsed.length) throw new VaultError('CORRUPT_VAULT')
  }
  return parsed
}

function parseDirectState(value: unknown): BitwardenDirectState {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  const deviceIdentifier = value.deviceIdentifier
  const profileId = value.profileId
  const securityStamp = value.securityStamp
  if (
    typeof deviceIdentifier !== 'string' ||
    !UUID_PATTERN.test(deviceIdentifier) ||
    (profileId !== null && (typeof profileId !== 'string' || !UUID_PATTERN.test(profileId))) ||
    (securityStamp !== null &&
      (typeof securityStamp !== 'string' || securityStamp.length > MAX_SYNC_SECRET_LENGTH))
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }

  let session: BitwardenDirectState['session'] = null
  if (value.session !== null) {
    if (!isRecord(value.session)) throw new VaultError('CORRUPT_VAULT')
    const { accessToken, refreshToken, expiresAt } = value.session
    if (
      typeof accessToken !== 'string' ||
      accessToken.length === 0 ||
      accessToken.length > MAX_SYNC_SECRET_LENGTH ||
      typeof refreshToken !== 'string' ||
      refreshToken.length === 0 ||
      refreshToken.length > MAX_SYNC_SECRET_LENGTH ||
      typeof expiresAt !== 'number' ||
      !Number.isSafeInteger(expiresAt) ||
      expiresAt <= 0
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    session = { accessToken, refreshToken, expiresAt }
  }

  return { session, deviceIdentifier, profileId, securityStamp }
}

function parseStoredEquivalentDomain(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value !== value.trim() ||
    /[\0\r\n,]/u.test(value) ||
    Buffer.byteLength(value, 'utf8') > MAX_EQUIVALENT_DOMAIN_LENGTH
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return value
}

function parseStoredEquivalentDomainGroups(value: unknown): string[][] {
  if (!Array.isArray(value) || value.length > MAX_EQUIVALENT_DOMAIN_GROUPS) {
    throw new VaultError('CORRUPT_VAULT')
  }
  let total = 0
  return value.map((group) => {
    if (!Array.isArray(group) || group.length > MAX_EQUIVALENT_DOMAINS_PER_GROUP) {
      throw new VaultError('CORRUPT_VAULT')
    }
    total += group.length
    if (total > MAX_EQUIVALENT_DOMAIN_TOTAL) throw new VaultError('CORRUPT_VAULT')
    return group.map(parseStoredEquivalentDomain)
  })
}

function parseStoredEquivalentDomainSettings(value: unknown): BitwardenEquivalentDomainSettings {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  const equivalentDomains = parseStoredEquivalentDomainGroups(value.equivalentDomains)
  if (
    !Array.isArray(value.globalEquivalentDomains) ||
    value.globalEquivalentDomains.length > MAX_EQUIVALENT_DOMAIN_GROUPS
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  let total = equivalentDomains.reduce((count, group) => count + group.length, 0)
  const seenTypes = new Set<number>()
  const globalEquivalentDomains = value.globalEquivalentDomains.map((candidate) => {
    if (!isRecord(candidate)) throw new VaultError('CORRUPT_VAULT')
    const { type, domains, excluded } = candidate
    if (
      typeof type !== 'number' ||
      !Number.isInteger(type) ||
      type < 0 ||
      type > 2_147_483_647 ||
      seenTypes.has(type) ||
      !Array.isArray(domains) ||
      domains.length > MAX_EQUIVALENT_DOMAINS_PER_GROUP ||
      typeof excluded !== 'boolean'
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    seenTypes.add(type)
    total += domains.length
    if (total > MAX_EQUIVALENT_DOMAIN_TOTAL) throw new VaultError('CORRUPT_VAULT')
    return { type, domains: domains.map(parseStoredEquivalentDomain), excluded }
  })
  return { equivalentDomains, globalEquivalentDomains }
}

function cloneEquivalentDomainSettings(
  settings: BitwardenEquivalentDomainSettings
): BitwardenEquivalentDomainSettings {
  return {
    equivalentDomains: settings.equivalentDomains.map((group) => [...group]),
    globalEquivalentDomains: settings.globalEquivalentDomains.map((group) => ({
      ...group,
      domains: [...group.domains]
    }))
  }
}

function sendViewFromRemote(send: BitwardenSendItem): StoredSend {
  return {
    id: send.id,
    accessId: send.accessId,
    type: send.type,
    name: send.name,
    notes: send.notes,
    text: send.type === 'text' ? send.text : '',
    ...(send.type === 'file' && send.file ? { file: { ...send.file } } : {}),
    hidden: send.hidden,
    maxAccessCount: send.maxAccessCount,
    accessCount: send.accessCount,
    revisionDate: send.revisionDate,
    expirationDate: send.expirationDate,
    deletionDate: send.deletionDate,
    disabled: send.disabled,
    hideEmail: send.hideEmail,
    authType: send.authType === 1 ? 'password' : 'none',
    passwordProtected: send.passwordProtected
  }
}

function emergencyAccessViewFromRemote(value: BitwardenEmergencyAccess): EmergencyAccessView {
  return { ...value }
}

function validateRemoteEquivalentDomainSettings(value: unknown): BitwardenEquivalentDomainSettings {
  try {
    return parseStoredEquivalentDomainSettings(value)
  } catch {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
}

function equivalentDomainRevision(settings: BitwardenEquivalentDomainSettings): string {
  return createHash('sha256').update(JSON.stringify(settings)).digest('hex')
}

function equivalentDomainSettingsView(
  settings: BitwardenEquivalentDomainSettings
): EquivalentDomainSettingsView {
  return {
    ...cloneEquivalentDomainSettings(settings),
    revision: equivalentDomainRevision(settings)
  }
}

function normalizeEquivalentDomain(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_EQUIVALENT_DOMAIN_LENGTH ||
    /[\0\r\n,]/u.test(value)
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  const normalized = value.trim()
  if (
    normalized.length === 0 ||
    normalized.startsWith('data:') ||
    normalized.startsWith('about:')
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  let parsed: ReturnType<typeof parseDomain>
  try {
    parsed = parseDomain(normalized, { allowPrivateDomains: true, validHosts: ['localhost'] })
  } catch {
    throw new VaultError('INVALID_INPUT')
  }
  const domain = parsed.isIp || parsed.hostname === 'localhost' ? parsed.hostname : parsed.domain
  if (!domain || Buffer.byteLength(domain, 'utf8') > MAX_EQUIVALENT_DOMAIN_LENGTH) {
    throw new VaultError('INVALID_INPUT')
  }
  return domain.toLowerCase()
}

function normalizeEquivalentDomainUpdate(
  request: EquivalentDomainSettingsUpdate
): BitwardenEquivalentDomainUpdate {
  if (
    !Array.isArray(request.equivalentDomains) ||
    request.equivalentDomains.length > MAX_EQUIVALENT_DOMAIN_GROUPS ||
    !Array.isArray(request.excludedGlobalEquivalentDomains) ||
    request.excludedGlobalEquivalentDomains.length > MAX_EQUIVALENT_DOMAIN_GROUPS
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  let total = 0
  const seenGroups = new Set<string>()
  const equivalentDomains: string[][] = []
  for (const candidate of request.equivalentDomains) {
    if (!Array.isArray(candidate) || candidate.length > MAX_EQUIVALENT_DOMAINS_PER_GROUP) {
      throw new VaultError('INVALID_INPUT')
    }
    const group = [...new Set(candidate.map(normalizeEquivalentDomain))]
    if (group.length === 0) continue
    total += group.length
    if (total > MAX_EQUIVALENT_DOMAIN_TOTAL) throw new VaultError('INVALID_INPUT')
    const signature = [...group].sort().join('\0')
    if (seenGroups.has(signature)) continue
    seenGroups.add(signature)
    equivalentDomains.push(group)
  }
  const seenTypes = new Set<number>()
  const excludedGlobalEquivalentDomains = request.excludedGlobalEquivalentDomains.map((type) => {
    if (
      typeof type !== 'number' ||
      !Number.isInteger(type) ||
      type < 0 ||
      type > 2_147_483_647 ||
      seenTypes.has(type)
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    seenTypes.add(type)
    return type
  })
  return { equivalentDomains, excludedGlobalEquivalentDomains }
}

function parseSyncData(
  value: unknown,
  folderIds: Set<string>,
  loginIds: Set<string>,
  isCliData: boolean,
  allowMissingPendingMutation: boolean,
  allowMissingDomainSettings: boolean
): PersistedSyncData | null {
  if (value === null) return null
  if (!isRecord(value) || value.provider !== 'bitwarden') {
    throw new VaultError('CORRUPT_VAULT')
  }
  if (
    typeof value.serverUrl !== 'string' ||
    value.serverUrl.length > MAX_URI_LENGTH ||
    typeof value.email !== 'string' ||
    value.email.length === 0 ||
    value.email.length > MAX_USERNAME_LENGTH
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  try {
    resolveBitwardenUrls(value.serverUrl)
  } catch {
    throw new VaultError('CORRUPT_VAULT')
  }
  if (value.lastSyncAt !== null) assertIsoDate(value.lastSyncAt)

  const folderMappings = parseSyncMappings(
    value.folderMappings,
    folderIds,
    'mapping'
  ) as SyncEntityMapping[]
  const loginMappings = parseSyncMappings(
    value.loginMappings,
    loginIds,
    'mapping'
  ) as SyncEntityMapping[]
  const folderTombstones = parseSyncMappings(
    value.folderTombstones,
    folderIds,
    'tombstone'
  ) as SyncTombstone[]
  const loginTombstones = parseSyncMappings(
    value.loginTombstones,
    loginIds,
    'tombstone'
  ) as SyncTombstone[]
  const mappedFolderRemoteIds = new Set(folderMappings.map((entry) => entry.remoteId))
  const mappedLoginRemoteIds = new Set(loginMappings.map((entry) => entry.remoteId))
  if (
    folderTombstones.some((entry) => mappedFolderRemoteIds.has(entry.remoteId)) ||
    loginTombstones.some((entry) => mappedLoginRemoteIds.has(entry.remoteId))
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }

  let pendingLoginMutation: PendingLoginMutation | null = null
  if (value.pendingLoginMutation !== null && value.pendingLoginMutation !== undefined) {
    const pending = value.pendingLoginMutation
    if (
      !isRecord(pending) ||
      (pending.intent !== 'converge' && pending.intent !== 'hard-delete') ||
      typeof pending.localId !== 'string' ||
      !UUID_PATTERN.test(pending.localId) ||
      typeof pending.remoteId !== 'string' ||
      !UUID_PATTERN.test(pending.remoteId) ||
      (pending.remoteFolderId !== null &&
        (typeof pending.remoteFolderId !== 'string' ||
          !UUID_PATTERN.test(pending.remoteFolderId))) ||
      !Array.isArray(pending.expectedRemoteFingerprints) ||
      pending.expectedRemoteFingerprints.length === 0 ||
      pending.expectedRemoteFingerprints.length > 5 ||
      pending.expectedRemoteFingerprints.some(
        (fingerprint) => typeof fingerprint !== 'string' || !/^[0-9a-f]{64}$/.test(fingerprint)
      ) ||
      new Set(pending.expectedRemoteFingerprints).size !==
        pending.expectedRemoteFingerprints.length ||
      !(pending.intent === 'converge'
        ? loginMappings.some(
            (mapping) =>
              mapping.localId === pending.localId && mapping.remoteId === pending.remoteId
          )
        : loginTombstones.some(
            (tombstone) =>
              tombstone.localId === pending.localId && tombstone.remoteId === pending.remoteId
          ))
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    pendingLoginMutation = {
      intent: pending.intent,
      localId: pending.localId,
      remoteId: pending.remoteId,
      remoteFolderId: pending.remoteFolderId,
      expectedRemoteFingerprints: [...pending.expectedRemoteFingerprints]
    }
  } else if (!allowMissingPendingMutation && value.pendingLoginMutation === undefined) {
    throw new VaultError('CORRUPT_VAULT')
  }

  const domainSettings =
    value.domainSettings === undefined && allowMissingDomainSettings
      ? null
      : value.domainSettings === null
        ? null
        : parseStoredEquivalentDomainSettings(value.domainSettings)

  return {
    provider: 'bitwarden',
    serverUrl: value.serverUrl,
    email: value.email,
    state: isCliData
      ? {
          session: null,
          deviceIdentifier: randomUUID(),
          profileId: null,
          securityStamp: null
        }
      : parseDirectState(value.state),
    lastSyncAt: value.lastSyncAt,
    folderMappings,
    loginMappings,
    folderTombstones,
    loginTombstones,
    pendingLoginMutation,
    domainSettings
  }
}

function parseVaultData(value: unknown): VaultData {
  if (
    !isRecord(value) ||
    typeof value.version !== 'number' ||
    ![
      LEGACY_DATA_VERSION,
      CLI_DATA_VERSION,
      3,
      ITEM_TYPES_DATA_VERSION,
      PASSKEYS_DATA_VERSION,
      CUSTOM_FIELDS_DATA_VERSION,
      TRASH_DATA_VERSION,
      PENDING_LOGIN_MUTATION_DATA_VERSION,
      ARCHIVE_DATA_VERSION,
      REPROMPT_DATA_VERSION,
      MULTIPLE_URIS_DATA_VERSION,
      PASSWORD_HISTORY_DATA_VERSION,
      GENERATOR_HISTORY_DATA_VERSION,
      ATTACHMENTS_DATA_VERSION,
      SENDS_DATA_VERSION,
      ORGANIZATIONS_DATA_VERSION,
      NATIVE_ATTACHMENT_RESTORE_DATA_VERSION,
      DATA_VERSION
    ].includes(value.version) ||
    !Array.isArray(value.folders) ||
    !Array.isArray(value.logins)
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  const dataVersion = value.version
  assertIsoDate(value.createdAt)
  assertIsoDate(value.updatedAt)

  const folders = value.folders.map(parseFolder)
  const logins = value.logins.map((login) =>
    parseStoredLogin(
      login,
      dataVersion < ITEM_TYPES_DATA_VERSION,
      dataVersion < PASSKEYS_DATA_VERSION,
      dataVersion < CUSTOM_FIELDS_DATA_VERSION,
      dataVersion < TRASH_DATA_VERSION,
      dataVersion < ARCHIVE_DATA_VERSION,
      dataVersion < REPROMPT_DATA_VERSION,
      dataVersion < MULTIPLE_URIS_DATA_VERSION,
      dataVersion < PASSWORD_HISTORY_DATA_VERSION,
      dataVersion < ATTACHMENTS_DATA_VERSION
    )
  )
  const folderIds = new Set(folders.map((folder) => folder.id))
  const folderPositions = new Set(folders.map((folder) => folder.position))
  const loginIds = new Set(logins.map((login) => login.id))

  if (
    folderIds.size !== folders.length ||
    folderPositions.size !== folders.length ||
    folders.some((folder) => folder.position >= folders.length) ||
    loginIds.size !== logins.length
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  if (logins.some((login) => login.folderId !== null && !folderIds.has(login.folderId))) {
    throw new VaultError('CORRUPT_VAULT')
  }

  const organizations =
    dataVersion < ORGANIZATIONS_DATA_VERSION
      ? []
      : (() => {
          if (
            !Array.isArray(value.organizations) ||
            value.organizations.length > MAX_REMOTE_ENTITIES
          ) {
            throw new VaultError('CORRUPT_VAULT')
          }
          const parsed = value.organizations.map(parseStoredOrganization)
          if (new Set(parsed.map((organization) => organization.id)).size !== parsed.length) {
            throw new VaultError('CORRUPT_VAULT')
          }
          return parsed
        })()
  const organizationIds = new Set(organizations.map((organization) => organization.id))
  const collections =
    dataVersion < ORGANIZATIONS_DATA_VERSION
      ? []
      : (() => {
          if (!Array.isArray(value.collections) || value.collections.length > MAX_REMOTE_ENTITIES) {
            throw new VaultError('CORRUPT_VAULT')
          }
          const parsed = value.collections.map(parseStoredCollection)
          if (
            new Set(parsed.map((collection) => collection.id)).size !== parsed.length ||
            parsed.some((collection) => !organizationIds.has(collection.organizationId))
          ) {
            throw new VaultError('CORRUPT_VAULT')
          }
          return parsed
        })()
  const collectionIds = new Set(collections.map((collection) => collection.id))
  const sharedLogins =
    dataVersion < ORGANIZATIONS_DATA_VERSION
      ? []
      : (() => {
          if (
            !Array.isArray(value.sharedLogins) ||
            value.sharedLogins.length > MAX_REMOTE_ENTITIES
          ) {
            throw new VaultError('CORRUPT_VAULT')
          }
          const parsed = value.sharedLogins.map(parseStoredSharedLogin)
          if (
            new Set(parsed.map((login) => login.id)).size !== parsed.length ||
            parsed.some(
              (login) =>
                loginIds.has(login.id) ||
                !organizationIds.has(login.organizationId) ||
                login.collectionIds.some((id) => !collectionIds.has(id)) ||
                login.collectionIds.some(
                  (id) =>
                    collections.find((collection) => collection.id === id)?.organizationId !==
                    login.organizationId
                )
            )
          ) {
            throw new VaultError('CORRUPT_VAULT')
          }
          return parsed
        })()

  const sync =
    dataVersion === LEGACY_DATA_VERSION
      ? null
      : parseSyncData(
          value.sync,
          folderIds,
          loginIds,
          dataVersion === CLI_DATA_VERSION,
          dataVersion < DATA_VERSION,
          dataVersion < EQUIVALENT_DOMAINS_DATA_VERSION
        )

  let nativeAttachmentRestore: NativeAttachmentRestoreJournal | null = null
  if (dataVersion >= NATIVE_ATTACHMENT_RESTORE_DATA_VERSION) {
    try {
      nativeAttachmentRestore =
        value.nativeAttachmentRestore === null
          ? null
          : parseNativeAttachmentRestoreJournal(value.nativeAttachmentRestore)
    } catch {
      throw new VaultError('CORRUPT_VAULT')
    }
  }

  return {
    version: DATA_VERSION,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
    folders,
    logins,
    organizations,
    collections,
    sharedLogins,
    sends:
      dataVersion < SENDS_DATA_VERSION
        ? []
        : (() => {
            if (!Array.isArray(value.sends) || value.sends.length > MAX_SENDS) {
              throw new VaultError('CORRUPT_VAULT')
            }
            const sends = value.sends.map(parseStoredSend)
            if (new Set(sends.map((send) => send.id)).size !== sends.length) {
              throw new VaultError('CORRUPT_VAULT')
            }
            return sends
          })(),
    generatorHistory:
      dataVersion < GENERATOR_HISTORY_DATA_VERSION
        ? []
        : parseGeneratorHistory(value.generatorHistory),
    sync,
    nativeAttachmentRestore
  }
}

function normalizeRequiredString(value: unknown, maxLength: number): string {
  if (typeof value !== 'string') throw new VaultError('INVALID_INPUT')
  const normalized = value.trim()
  if (normalized.length === 0 || normalized.length > maxLength) {
    throw new VaultError('INVALID_INPUT')
  }
  return normalized
}

function normalizeString(value: unknown, maxLength: number): string {
  if (typeof value !== 'string' || value.length > maxLength) {
    throw new VaultError('INVALID_INPUT')
  }
  return value
}

function normalizeSyncPassword(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_SYNC_SECRET_LENGTH) {
    throw new VaultError('INVALID_INPUT')
  }
  return value
}

function normalizeNullableString(value: unknown, maxLength: number): string | null {
  if (value === null || value === undefined || value === '') return null
  if (typeof value !== 'string' || value.length > maxLength) {
    throw new VaultError('INVALID_INPUT')
  }
  return value
}

interface NormalizedSendOptions {
  name: string
  notes: string | null
  maxAccessCount: number | null
  expirationDate: string | null
  deletionDate: string
  password: string | null | undefined
  disabled: boolean
  hideEmail: boolean
}

function normalizeSendOptions(
  request: SendCreateRequest | SendUpdateRequest | SendFileCreateRequest
): NormalizedSendOptions {
  const name = normalizeRequiredString(request.name, MAX_NAME_LENGTH)
  const notes = normalizeNullableString(request.notes, MAX_NOTES_LENGTH)
  const maxAccessCount = request.maxAccessCount ?? null
  if (
    maxAccessCount !== null &&
    (!Number.isSafeInteger(maxAccessCount) || maxAccessCount < 1 || maxAccessCount > 2_147_483_647)
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  const expirationDate = request.expirationDate ?? null
  const deletionDate =
    request.deletionDate ?? new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
  for (const value of [expirationDate, deletionDate]) {
    if (value !== null && (typeof value !== 'string' || !Number.isFinite(Date.parse(value)))) {
      throw new VaultError('INVALID_INPUT')
    }
  }
  const password =
    request.password === undefined
      ? undefined
      : normalizeNullableString(request.password, MAX_SYNC_SECRET_LENGTH)
  const disabled = request.disabled ?? false
  const hideEmail = request.hideEmail ?? true
  if (typeof disabled !== 'boolean' || typeof hideEmail !== 'boolean') {
    throw new VaultError('INVALID_INPUT')
  }
  if (expirationDate && Date.parse(expirationDate) <= Date.now()) {
    throw new VaultError('INVALID_INPUT')
  }
  if (
    Date.parse(deletionDate) <= Date.now() ||
    Date.parse(deletionDate) > Date.now() + 31 * 24 * 60 * 60 * 1000
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  if (expirationDate && Date.parse(expirationDate) > Date.parse(deletionDate)) {
    throw new VaultError('INVALID_INPUT')
  }
  return {
    name,
    notes,
    maxAccessCount,
    expirationDate,
    deletionDate,
    password,
    disabled,
    hideEmail
  }
}

function normalizeSendDraft(request: SendCreateRequest | SendUpdateRequest): BitwardenSendDraft {
  const options = normalizeSendOptions(request)
  const hidden = request.hidden ?? false
  if (typeof hidden !== 'boolean') throw new VaultError('INVALID_INPUT')
  return {
    ...options,
    text: normalizeString(request.text, MAX_SEND_TEXT_LENGTH),
    hidden
  }
}

function normalizeFileSendDraft(
  request: SendFileCreateRequest
): Omit<BitwardenFileSendDraft, 'fileName' | 'data'> {
  return normalizeSendOptions(request)
}

function normalizeItemType(value: unknown): VaultItemType {
  if (!isVaultItemType(value)) throw new VaultError('INVALID_INPUT')
  return value
}

function normalizeReprompt(value: unknown): VaultReprompt {
  if (value !== 0 && value !== 1) throw new VaultError('INVALID_INPUT')
  return value
}

function applyItemFields(
  target: VaultItemFields,
  input: Partial<VaultItemFields>,
  type: VaultItemType
): void {
  const allowed = new Set(ITEM_FIELDS_BY_TYPE[type])
  for (const field of ITEM_FIELD_NAMES) {
    const value = input[field]
    if (value === undefined) continue
    if (!allowed.has(field)) {
      if (value === '' || value === null) continue
      throw new VaultError('INVALID_INPUT')
    }
    if (field === 'uri') {
      target.uri = normalizeNullableString(value, MAX_URI_LENGTH)
    } else {
      target[field] = normalizeString(value, maxLengthForItemField(field))
    }
  }
}

function createRequestUris(request: LoginCreateRequest, type: VaultItemType): VaultLoginUri[] {
  if (type !== 'login') {
    if (request.uris !== undefined && request.uris.length > 0) throw new VaultError('INVALID_INPUT')
    return []
  }
  if (request.uris === undefined) {
    const primary = normalizeNullableString(request.uri, MAX_URI_LENGTH)
    return primary === null ? [] : [{ uri: primary, match: null }]
  }
  const uris = normalizeLoginUris(request.uris)
  if (
    request.uri !== undefined &&
    normalizeNullableString(request.uri, MAX_URI_LENGTH) !== uriAlias(uris)
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return uris
}

function updateRequestUris(request: LoginUpdateRequest, existing: StoredLogin): VaultLoginUri[] {
  if (existing.type !== 'login') {
    if (request.uris !== undefined && request.uris.length > 0) throw new VaultError('INVALID_INPUT')
    return []
  }
  if (request.uris !== undefined) {
    const uris = normalizeLoginUris(request.uris)
    if (
      request.uri !== undefined &&
      normalizeNullableString(request.uri, MAX_URI_LENGTH) !== uriAlias(uris)
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    return uris
  }
  if (request.uri === undefined) return cloneLoginUris(existing.uris)
  const primary = normalizeNullableString(request.uri, MAX_URI_LENGTH)
  const remaining = cloneLoginUris(existing.uris.slice(1))
  return primary === null
    ? remaining
    : [{ uri: primary, match: existing.uris[0]?.match ?? null }, ...remaining]
}

function remoteLoginUris(source: SyncLogin): VaultLoginUri[] {
  if (!Array.isArray(source.uris) || source.uris.length > MAX_LOGIN_URIS) {
    throw new VaultError('SYNC_FAILED')
  }
  const uris = source.uris.map((entry) => {
    if (
      !entry ||
      typeof entry.uri !== 'string' ||
      entry.uri.length > MAX_URI_LENGTH ||
      (entry.match !== null && !isVaultUriMatch(entry.match))
    ) {
      throw new VaultError('SYNC_FAILED')
    }
    return { uri: entry.uri, match: entry.match }
  })
  if (source.uri !== uriAlias(uris)) throw new VaultError('SYNC_FAILED')
  return uris
}

function normalizeCustomFields(
  existing: readonly VaultCustomField[],
  updates: unknown,
  itemType: VaultItemType
): VaultCustomField[] {
  if (!Array.isArray(updates) || updates.length > MAX_CUSTOM_FIELDS) {
    throw new VaultError('INVALID_INPUT')
  }

  const linkedIds = VAULT_LINKED_FIELD_IDS_BY_TYPE[itemType] as readonly number[]
  const sourceIndexes = new Set<number>()

  return updates.map((candidate): VaultCustomField => {
    if (!isRecord(candidate)) throw new VaultError('INVALID_INPUT')
    const update = candidate as unknown as VaultCustomFieldUpdate
    if (
      typeof update.name !== 'string' ||
      update.name.length > MAX_CUSTOM_FIELD_NAME_LENGTH ||
      (update.type !== 'text' &&
        update.type !== 'hidden' &&
        update.type !== 'boolean' &&
        update.type !== 'linked') ||
      (update.value !== null &&
        (typeof update.value !== 'string' ||
          update.value.length > MAX_CUSTOM_FIELD_VALUE_LENGTH)) ||
      (update.linkedId !== null && (!Number.isSafeInteger(update.linkedId) || update.linkedId < 0))
    ) {
      throw new VaultError('INVALID_INPUT')
    }

    let sourceField: VaultCustomField | null = null
    if (update.source !== null) {
      if (!isRecord(update.source)) throw new VaultError('INVALID_INPUT')
      const { index, name, type, linkedId } = update.source
      if (
        !Number.isSafeInteger(index) ||
        index < 0 ||
        sourceIndexes.has(index) ||
        typeof name !== 'string' ||
        name.length > MAX_CUSTOM_FIELD_NAME_LENGTH ||
        (type !== 'text' && type !== 'hidden' && type !== 'boolean' && type !== 'linked') ||
        (linkedId !== null && (!Number.isSafeInteger(linkedId) || linkedId < 0))
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      sourceIndexes.add(index)
      sourceField = existing[index] ?? null
      if (
        !sourceField ||
        sourceField.name !== name ||
        sourceField.type !== type ||
        sourceField.linkedId !== linkedId
      ) {
        throw new VaultError('INVALID_INPUT')
      }
    }

    if (update.type === 'linked') {
      if (
        update.value !== null ||
        update.linkedId === null ||
        !linkedIds.includes(update.linkedId)
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      return { name: update.name, type: update.type, value: '', linkedId: update.linkedId }
    }
    if (update.linkedId !== null) throw new VaultError('INVALID_INPUT')

    if (update.value === null) {
      if (update.type !== 'hidden' || sourceField?.type !== 'hidden') {
        throw new VaultError('INVALID_INPUT')
      }
      return { name: update.name, type: update.type, value: sourceField.value, linkedId: null }
    }
    if (update.type === 'boolean' && update.value !== 'true' && update.value !== 'false') {
      throw new VaultError('INVALID_INPUT')
    }
    return { name: update.name, type: update.type, value: update.value, linkedId: null }
  })
}

function assertSecretField(type: VaultItemType, field: VaultSecretField): void {
  if (!SECRET_FIELDS_BY_TYPE[type].includes(field)) throw new VaultError('INVALID_INPUT')
}

function assertCopyField(type: VaultItemType, field: VaultCopyField): void {
  if (!COPY_FIELDS_BY_TYPE[type].includes(field)) throw new VaultError('INVALID_INPUT')
}

function customFieldFromSource(
  login: StoredLogin,
  source: VaultCustomFieldSource
): VaultCustomField {
  const { index } = source
  if (!Number.isSafeInteger(index) || index < 0 || index >= login.customFields.length) {
    throw new VaultError('INVALID_INPUT')
  }
  const field = login.customFields[index]!
  if (
    field.name !== source.name ||
    field.type !== source.type ||
    field.linkedId !== source.linkedId
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return field
}

function linkedCustomFieldValue(login: StoredLogin, linkedId: number | null): string {
  if (login.type === 'login') {
    if (linkedId === 100) return login.username
    if (linkedId === 101) return login.password
  } else if (login.type === 'card') {
    const fields: Partial<Record<number, keyof VaultItemFields>> = {
      300: 'cardholderName',
      301: 'expMonth',
      302: 'expYear',
      303: 'code',
      304: 'brand',
      305: 'number'
    }
    const field = linkedId === null ? undefined : fields[linkedId]
    if (field) return String(login[field] ?? '')
  } else if (login.type === 'identity') {
    if (linkedId === 418) {
      return [login.title, login.firstName, login.middleName, login.lastName]
        .filter(Boolean)
        .join(' ')
    }
    const fields: Partial<Record<number, keyof VaultItemFields>> = {
      400: 'title',
      401: 'middleName',
      402: 'address1',
      403: 'address2',
      404: 'address3',
      405: 'city',
      406: 'state',
      407: 'postalCode',
      408: 'country',
      409: 'company',
      410: 'email',
      411: 'phone',
      412: 'ssn',
      413: 'identityUsername',
      414: 'passportNumber',
      415: 'licenseNumber',
      416: 'firstName',
      417: 'lastName'
    }
    const field = linkedId === null ? undefined : fields[linkedId]
    if (field) return String(login[field] ?? '')
  }
  throw new VaultError('INVALID_INPUT')
}

function customFieldValue(login: StoredLogin, field: VaultCustomField): string {
  return field.type === 'linked' ? linkedCustomFieldValue(login, field.linkedId) : field.value
}

function loginUriAt(login: StoredLogin, uriIndex: number | undefined): string {
  if (login.type !== 'login') throw new VaultError('INVALID_INPUT')
  const index = uriIndex ?? 0
  if (!Number.isSafeInteger(index) || index < 0 || index >= login.uris.length) {
    throw new VaultError('INVALID_INPUT')
  }
  const uri = login.uris[index]?.uri
  if (!uri) throw new VaultError('INVALID_INPUT')
  return uri
}

function normalizeMasterPassword(value: unknown): string {
  if (typeof value !== 'string') {
    throw new VaultError('INVALID_INPUT')
  }
  const normalized = value.normalize('NFC')
  if (
    normalized.length < MIN_MASTER_PASSWORD_LENGTH ||
    normalized.length > MAX_MASTER_PASSWORD_LENGTH
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return normalized
}

function cloneData(data: VaultData): VaultData {
  return {
    ...data,
    folders: data.folders.map((folder) => ({ ...folder })),
    logins: data.logins.map((login) => ({
      ...login,
      uris: cloneLoginUris(login.uris),
      passkeys: login.passkeys.map((passkey) => ({ ...passkey })),
      customFields: cloneCustomFields(login.customFields),
      passwordHistory: clonePasswordHistory(login.passwordHistory),
      attachments: cloneAttachments(login.attachments)
    })),
    organizations: data.organizations.map((organization) => ({ ...organization })),
    collections: data.collections.map((collection) => ({ ...collection })),
    sharedLogins: data.sharedLogins.map((login) => ({
      ...login,
      collectionIds: [...login.collectionIds],
      uris: cloneLoginUris(login.uris),
      passkeys: login.passkeys.map((passkey) => ({ ...passkey })),
      customFields: cloneCustomFields(login.customFields),
      passwordHistory: clonePasswordHistory(login.passwordHistory),
      attachments: cloneAttachments(login.attachments)
    })),
    sends: data.sends.map((send) => ({
      ...send,
      ...(send.file ? { file: { ...send.file } } : {})
    })),
    generatorHistory: cloneGeneratorHistory(data.generatorHistory),
    nativeAttachmentRestore:
      data.nativeAttachmentRestore === null
        ? null
        : parseNativeAttachmentRestoreJournal(data.nativeAttachmentRestore),
    sync: data.sync
      ? {
          ...data.sync,
          state: {
            ...data.sync.state,
            session: data.sync.state.session ? { ...data.sync.state.session } : null
          },
          folderMappings: data.sync.folderMappings.map((entry) => ({ ...entry })),
          loginMappings: data.sync.loginMappings.map((entry) => ({ ...entry })),
          folderTombstones: data.sync.folderTombstones.map((entry) => ({ ...entry })),
          loginTombstones: data.sync.loginTombstones.map((entry) => ({ ...entry })),
          domainSettings: data.sync.domainSettings
            ? cloneEquivalentDomainSettings(data.sync.domainSettings)
            : null,
          pendingLoginMutation: data.sync.pendingLoginMutation
            ? {
                ...data.sync.pendingLoginMutation,
                expectedRemoteFingerprints: [
                  ...data.sync.pendingLoginMutation.expectedRemoteFingerprints
                ]
              }
            : null
        }
      : null
  }
}

function recordSyncDeletion(
  sync: PersistedSyncData | null,
  entity: 'folder' | 'login',
  localId: string
): void {
  if (!sync) return
  const mappings = entity === 'folder' ? sync.folderMappings : sync.loginMappings
  const mapping = mappings.find((entry) => entry.localId === localId)
  if (!mapping) return
  const tombstones = entity === 'folder' ? sync.folderTombstones : sync.loginTombstones
  tombstones.push({
    localId: mapping.localId,
    remoteId: mapping.remoteId,
    baseFingerprint: mapping.baseFingerprint
  })
  if (entity === 'folder') {
    sync.folderMappings = sync.folderMappings.filter((entry) => entry.localId !== localId)
  } else {
    sync.loginMappings = sync.loginMappings.filter((entry) => entry.localId !== localId)
    if (sync.pendingLoginMutation?.localId === localId) {
      sync.pendingLoginMutation.intent = 'hard-delete'
    }
  }
}

function toSummary(login: StoredLogin): LoginSummary {
  if (login.deletedAt !== null || login.reprompt === 1) {
    return {
      id: login.id,
      type: login.type,
      name: login.name,
      subtitle: '',
      username: '',
      uri: null,
      uris: [],
      ...(login.type === 'login' ? { hasTotp: false, passkeyCount: 0 } : {}),
      passwordHistoryCount: login.passwordHistory.length,
      attachmentCount: login.attachments.length,
      folderId: login.folderId,
      favorite: login.deletedAt === null ? login.favorite : false,
      lastUsedAt: login.deletedAt === null ? login.lastUsedAt : null,
      createdAt: login.createdAt,
      updatedAt: login.updatedAt,
      deletedAt: login.deletedAt,
      archivedAt: login.archivedAt,
      reprompt: login.reprompt
    }
  }
  const notePreview = login.type === 'secureNote' ? summarizeSecureNote(login.notes) : ''
  const subtitle =
    login.type === 'login'
      ? login.username || login.uri || ''
      : login.type === 'card'
        ? login.number.length >= 4
          ? `•••• ${login.number.slice(-4)}`
          : login.brand
        : login.type === 'identity'
          ? [login.firstName, login.lastName].filter(Boolean).join(' ')
          : login.type === 'secureNote'
            ? notePreview
            : login.type === 'sshKey'
              ? login.fingerprint || 'SSH key'
              : ''
  return {
    id: login.id,
    type: login.type,
    name: login.name,
    subtitle,
    username: login.type === 'login' ? login.username : '',
    uri: login.type === 'login' ? login.uri : null,
    uris: login.type === 'login' ? cloneLoginUris(login.uris) : [],
    ...(login.type === 'card' ? { cardBrand: login.brand } : {}),
    ...(login.type === 'login'
      ? { hasTotp: Boolean(login.totp), passkeyCount: login.passkeys.length }
      : {}),
    passwordHistoryCount: login.passwordHistory.length,
    attachmentCount: login.attachments.length,
    folderId: login.folderId,
    favorite: login.favorite,
    lastUsedAt: login.lastUsedAt,
    createdAt: login.createdAt,
    updatedAt: login.updatedAt,
    deletedAt: login.deletedAt,
    archivedAt: login.archivedAt,
    reprompt: login.reprompt
  }
}

function toSharedSummary(login: StoredSharedLogin): SharedLoginSummary {
  return {
    ...toSummary(login),
    organizationId: login.organizationId,
    collectionIds: [...login.collectionIds],
    shared: true,
    edit: login.edit,
    viewPassword: login.viewPassword,
    delete: login.delete,
    restore: login.restore
  }
}

function toVaultSearchItem(login: StoredLogin): VaultSearchItem {
  const protectedItem = login.reprompt === 1 || login.deletedAt !== null
  const searchable: VaultSearchItem = {
    id: login.id,
    type: login.type,
    name: login.name,
    reprompt: login.reprompt,
    protected: protectedItem
  }
  if (protectedItem) return searchable

  const summary = toSummary(login)
  return {
    ...searchable,
    subtitle: summary.subtitle,
    notes: login.notes ?? '',
    customFields: login.customFields.map(({ name, value, type }) => ({ name, value, type })),
    attachments: login.attachments.map(({ fileName }) => ({ fileName })),
    ...(login.type === 'login'
      ? {
          username: login.username,
          uri: login.uri,
          uris: login.uris.map(({ uri }) => ({ uri }))
        }
      : {})
  }
}

function summarizeSecureNote(notes: string | null): string {
  const firstLine =
    notes
      ?.split(/\r\n?|\n/u)
      .map((line) => line.trim())
      .find(Boolean) ?? ''
  const graphemes = Array.from(
    new Intl.Segmenter('zh-Hant', { granularity: 'grapheme' }).segment(firstLine),
    (segment) => segment.segment
  )
  if (graphemes.length <= 80) return firstLine
  return `${graphemes.slice(0, 80).join('')}…`
}

function toView(login: StoredLogin): LoginView {
  return {
    ...toSummary(login),
    // This method is only exposed through the main-process authorization gate. Restore fields
    // intentionally redacted from protected list summaries.
    username: login.type === 'login' ? login.username : '',
    uri: login.type === 'login' ? login.uri : null,
    uris: login.type === 'login' ? cloneLoginUris(login.uris) : [],
    notes: login.notes,
    hasTotp: Boolean(login.totp),
    passkeys: login.passkeys.map(toPasskeyView),
    customFields: login.customFields.map((field): VaultCustomFieldView => ({
      ...field,
      value: field.type === 'hidden' || field.type === 'linked' ? null : field.value
    })),
    attachments: cloneAttachments(login.attachments),
    cardholderName: login.cardholderName,
    brand: login.brand,
    expMonth: login.expMonth,
    expYear: login.expYear,
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
    identityUsername: login.identityUsername,
    publicKey: login.publicKey,
    fingerprint: login.fingerprint
  }
}

function toSharedView(login: StoredSharedLogin): SharedLoginView {
  const view = toView(login)
  const safeView = login.viewPassword
    ? view
    : {
        ...view,
        username: '',
        notes: null,
        hasTotp: false,
        customFields: view.customFields.map((field) => ({ ...field, value: null })),
        cardholderName: '',
        brand: '',
        expMonth: '',
        expYear: '',
        title: '',
        firstName: '',
        middleName: '',
        lastName: '',
        address1: '',
        address2: '',
        address3: '',
        city: '',
        state: '',
        postalCode: '',
        country: '',
        company: '',
        email: '',
        phone: '',
        identityUsername: '',
        publicKey: '',
        fingerprint: ''
      }
  return {
    ...safeView,
    organizationId: login.organizationId,
    collectionIds: [...login.collectionIds],
    shared: true,
    edit: login.edit,
    viewPassword: login.viewPassword,
    delete: login.delete,
    restore: login.restore
  }
}

function compareText(left: string, right: string): number {
  const normalizedLeft = left.toLocaleLowerCase('en-US')
  const normalizedRight = right.toLocaleLowerCase('en-US')
  if (normalizedLeft < normalizedRight) return -1
  if (normalizedLeft > normalizedRight) return 1
  return 0
}

function validRemoteDate(value: string | null): string | undefined {
  return value && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : undefined
}

function validRemoteDeletedDate(value: string | null): string | null {
  if (value === null) return null
  const parsed = validRemoteDate(value)
  if (!parsed) throw new VaultError('SYNC_FAILED')
  return parsed
}

function validRemoteArchivedDate(value: string | null): string | null {
  if (value === null) return null
  const parsed = validRemoteDate(value)
  if (!parsed) throw new VaultError('SYNC_FAILED')
  return parsed
}

function isCompositeRemoteLoginUpdate(
  desired: SyncLogin,
  current: SyncLogin,
  contentChanged: boolean
): boolean {
  const desiredDeleted = desired.deletedAt !== null
  const currentDeleted = current.deletedAt !== null
  const desiredArchived = desired.archivedAt !== null
  const currentArchived = current.archivedAt !== null
  let steps = contentChanged ? 1 : 0
  if (currentDeleted && (!desiredDeleted || contentChanged)) steps += 1
  if (currentArchived && !desiredArchived) steps += 1
  if (!contentChanged && desiredArchived && !currentArchived) steps += 1
  if (desiredDeleted && (!currentDeleted || contentChanged)) steps += 1
  return steps > 1
}

function findPasskeyVaultMatches(
  data: VaultData,
  rpId: string,
  allowCredentialIds: readonly Buffer[]
): PasskeyVaultMatch[] {
  const rpMatches: PasskeyVaultMatch[] = []
  for (const login of data.logins) {
    if (login.type !== 'login' || login.deletedAt !== null || login.archivedAt !== null) continue
    login.passkeys.forEach((passkey, passkeyIndex) => {
      if (passkey.rpId !== rpId) return
      const credentialId = decodeStoredPasskeyCredentialId(passkey.credentialId)
      if (credentialId === null) return
      rpMatches.push({ login, passkey, passkeyIndex, credentialId })
    })
  }
  // Refuse an ambiguous credential even when only one duplicate is discoverable. A hidden copy
  // could otherwise become selectable solely by changing allowCredentials.
  assertUnambiguousPasskeyMatches(rpMatches)
  return rpMatches.filter(({ passkey, credentialId }) =>
    allowCredentialIds.length > 0
      ? credentialIdIsAllowed(credentialId, allowCredentialIds)
      : passkey.discoverable
  )
}

function assertUnambiguousPasskeyMatches(matches: readonly PasskeyVaultMatch[]): void {
  const seen = new Set<string>()
  for (const match of matches) {
    const encoded = match.credentialId.toString('base64url')
    if (seen.has(encoded)) throw new VaultError('INVALID_INPUT')
    seen.add(encoded)
  }
}

function activeVaultContainsCredentialId(
  data: VaultData,
  rpId: string,
  credentialId: Buffer
): boolean {
  return data.logins.some(
    (login) =>
      login.type === 'login' &&
      login.deletedAt === null &&
      login.archivedAt === null &&
      login.passkeys.some(
        (passkey) =>
          passkey.rpId === rpId &&
          decodeStoredPasskeyCredentialId(passkey.credentialId)?.equals(credentialId)
      )
  )
}

type AttachmentAuthorizationValidator = (
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

export class VaultService {
  private key: Buffer | null = null
  private salt: Buffer | null = null
  private data: VaultData | null = null
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
  private syncInProgress = false
  private syncLastError: string | null = null
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
  private readonly randomInt: RandomInt
  private readonly attachmentFiles: VaultAttachmentFileService | null
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
    this.randomInt = options.randomInt ?? nodeRandomInt
    this.attachmentFiles = options.attachmentFiles ?? null
    this.createSyncClient =
      options.createSyncClient ??
      (() => {
        throw new BitwardenDirectError('INVALID_RESPONSE')
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
        nativeAttachmentRestore: null
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
        this.data = parseVaultData(unlocked.data)
        this.key = unlocked.key
        this.salt = unlocked.salt
        await this.recoverNativeAttachmentRestoreAfterUnlock(requiresMigration)
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
        this.data = parseVaultData(unlocked.data)
        this.key = unlocked.key
        this.salt = unlocked.salt
        unlocked = null
        await this.recoverNativeAttachmentRestoreAfterUnlock(requiresMigration)
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
    this.key?.fill(0)
    this.salt?.fill(0)
    this.key = null
    this.salt = null
    this.data = null
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
          (state.profileId !== null && state.profileId !== profile.id) ||
          profile.email.toLowerCase() !== lease.email.toLowerCase()
        ) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        await this.persistCurrentClientState()
        return {
          name: profile.name,
          email: profile.email,
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
    type: 0 | 1
    masterPassword: string
    confirm: true
  }): Promise<void> {
    if (
      (request.type !== 0 && request.type !== 1) ||
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
      mutation.type = -1 as 0 | 1
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
    this.invalidatePinUnlockCapability()
    this.syncAbort?.abort()
    this.abortNotificationTokenLeases()
    this.abortAccountSecurityRequests()
    this.abortNativeAttachmentBackups()
    this.abortNativeAttachmentRestores()
    this.activeAccountBreachOperation?.abort.abort()
    return this.exclusive(async () => {
      const current = this.requireData()
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
          domainSettings: null
        }
        const client = this.createSyncClient(sync)
        await client.login({ email, password, twoFactor, newDeviceOtp, signal: abort.signal })
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
        await client.unlock({ password, twoFactor, newDeviceOtp, signal: abort.signal })
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
    this.invalidatePinUnlockCapability()
    this.syncAbort?.abort()
    this.abortNotificationTokenLeases()
    this.abortAccountSecurityRequests()
    this.abortNativeAttachmentBackups()
    this.abortNativeAttachmentRestores()
    this.activeAccountBreachOperation?.abort.abort()
    return this.exclusive(async () => {
      const next = cloneData(this.requireData())
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
    return this.exclusive(async () =>
      this.requireData()
        .sends.map((send) => ({ ...send }))
        .sort(
          (left, right) => compareText(left.name, right.name) || left.id.localeCompare(right.id)
        )
    )
  }

  createSend(request: SendCreateRequest): Promise<SendView> {
    return this.exclusive(async () => {
      const draft = normalizeSendDraft(request)
      const current = this.requireData()
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.createSend) throw new VaultError('SYNC_FAILED')
      const abort = this.startSyncOperation()
      try {
        const remote = await client.createSend(draft, abort.signal)
        const next = cloneData(current)
        next.sends = [
          ...next.sends.filter((send) => send.id !== remote.id),
          sendViewFromRemote(remote)
        ]
        if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
        next.sync.state = client.exportState()
        next.updatedAt = this.nowIso()
        await this.persist(next)
        this.data = next
        this.syncLastError = null
        return { ...sendViewFromRemote(remote) }
      } catch (error) {
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
    })
  }

  async createFileSend(request: SendFileCreateRequest): Promise<SendFileCreateResult> {
    const preflight = await this.exclusive(async () => {
      assertUuid(request.operationId)
      const files = this.attachmentFiles
      if (!files) throw new VaultError('INTERNAL_ERROR')
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.createFileSend) throw new VaultError('SYNC_FAILED')
      return { files, generation: this.generation }
    })
    const selection = await preflight.files.chooseOpenFile()
    if (selection === null) return { canceled: true, send: null }

    return this.exclusive(async () => {
      if (preflight.generation !== this.generation) throw new VaultError('LOCKED')
      const current = this.requireData()
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.createFileSend) throw new VaultError('SYNC_FAILED')
      const normalized = normalizeFileSendDraft(request)
      const abort = this.startSyncOperation()
      let plaintext: Buffer | null = null
      try {
        plaintext = await preflight.files.readSelectedFile(selection, abort.signal)
        const remote = await client.createFileSend(
          {
            ...normalized,
            fileName: selection.fileName,
            data: plaintext
          },
          abort.signal
        )
        const authoritative = (await client.listSends?.(abort.signal))?.find(
          (send) => send.id === remote.id
        )
        if (!authoritative || authoritative.type !== 'file' || !authoritative.file) {
          throw new VaultError('SYNC_FAILED')
        }
        const next = cloneData(current)
        next.sends = [
          ...next.sends.filter((send) => send.id !== authoritative.id),
          sendViewFromRemote(authoritative)
        ]
        if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
        next.sync.state = client.exportState()
        next.sync.lastSyncAt = this.nowIso()
        next.updatedAt = this.nowIso()
        await this.persist(next)
        this.data = next
        this.syncLastError = null
        return { canceled: false, send: { ...sendViewFromRemote(authoritative) } }
      } catch (error) {
        throw this.mapSyncError(error)
      } finally {
        plaintext?.fill(0)
        this.finishSyncOperation(abort)
      }
    })
  }

  async downloadFileSend(request: SendFileDownloadRequest): Promise<SendFileDownloadResult> {
    const password =
      request.password === undefined
        ? null
        : normalizeNullableString(request.password, MAX_SYNC_SECRET_LENGTH)
    const preflight = await this.exclusive(async () => {
      assertUuid(request.id)
      const send = this.requireData().sends.find((candidate) => candidate.id === request.id)
      if (!send || send.type !== 'file' || !send.file) throw new VaultError('NOT_FOUND')
      const files = this.attachmentFiles
      if (!files) throw new VaultError('INTERNAL_ERROR')
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.downloadFileSend) throw new VaultError('SYNC_FAILED')
      return { files, fileName: send.file.fileName, generation: this.generation }
    })
    const destination = await preflight.files.chooseSavePath(preflight.fileName)
    if (destination === null) return { canceled: true, fileName: preflight.fileName }

    return this.exclusive(async () => {
      if (preflight.generation !== this.generation) throw new VaultError('LOCKED')
      const send = this.requireData().sends.find((candidate) => candidate.id === request.id)
      if (
        !send ||
        send.type !== 'file' ||
        !send.file ||
        send.file.fileName !== preflight.fileName
      ) {
        throw new VaultError('NOT_FOUND')
      }
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.downloadFileSend) throw new VaultError('SYNC_FAILED')
      const abort = this.startSyncOperation()
      let clearText: Buffer | null = null
      try {
        clearText = (await client.downloadFileSend(send.id, password, abort.signal)).data
        if (preflight.generation !== this.generation || abort.signal.aborted) {
          throw new VaultError('LOCKED')
        }
        await preflight.files.write(destination, clearText, abort.signal)
        return { canceled: false, fileName: preflight.fileName }
      } catch (error) {
        if (error instanceof BitwardenDirectError && error.code === 'NOT_FOUND') {
          throw new VaultError('NOT_FOUND')
        }
        throw this.mapSyncError(error)
      } finally {
        clearText?.fill(0)
        this.finishSyncOperation(abort)
      }
    })
  }

  updateSend(request: SendUpdateRequest): Promise<SendView> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const draft = normalizeSendDraft(request)
      const current = this.requireData()
      if (!current.sends.some((send) => send.id === request.id)) throw new VaultError('NOT_FOUND')
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.updateSend) throw new VaultError('SYNC_FAILED')
      const abort = this.startSyncOperation()
      try {
        const remote = await client.updateSend(request.id, draft, abort.signal)
        const next = cloneData(current)
        next.sends = [
          ...next.sends.filter((send) => send.id !== remote.id),
          sendViewFromRemote(remote)
        ]
        if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
        next.sync.state = client.exportState()
        next.updatedAt = this.nowIso()
        await this.persist(next)
        this.data = next
        this.syncLastError = null
        return { ...sendViewFromRemote(remote) }
      } catch (error) {
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
    })
  }

  removeSendPassword(request: SendIdRequest): Promise<SendView> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const current = this.requireData()
      if (!current.sends.some((send) => send.id === request.id)) throw new VaultError('NOT_FOUND')
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.removeSendPassword) throw new VaultError('SYNC_FAILED')
      const abort = this.startSyncOperation()
      try {
        const remote = await client.removeSendPassword(request.id, abort.signal)
        const next = cloneData(current)
        next.sends = [
          ...next.sends.filter((send) => send.id !== remote.id),
          sendViewFromRemote(remote)
        ]
        if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
        next.sync.state = client.exportState()
        next.updatedAt = this.nowIso()
        await this.persist(next)
        this.data = next
        this.syncLastError = null
        return { ...sendViewFromRemote(remote) }
      } catch (error) {
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
    })
  }

  deleteSend(request: SendIdRequest): Promise<void> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const current = this.requireData()
      if (!current.sends.some((send) => send.id === request.id)) throw new VaultError('NOT_FOUND')
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.deleteSend) throw new VaultError('SYNC_FAILED')
      const abort = this.startSyncOperation()
      try {
        await client.deleteSend(request.id, abort.signal)
        const next = cloneData(current)
        next.sends = next.sends.filter((send) => send.id !== request.id)
        if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
        next.sync.state = client.exportState()
        next.updatedAt = this.nowIso()
        await this.persist(next)
        this.data = next
        this.syncLastError = null
      } catch (error) {
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
    })
  }

  copySendLink(request: SendIdRequest): Promise<void> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.copySendLink) throw new VaultError('SYNC_FAILED')
      try {
        await client.copySendLink(request.id, (value) => this.platform.copyText(value))
      } catch (error) {
        throw this.mapSyncError(error)
      }
    })
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
      if (sort !== 'recent' && sort !== 'name') throw new VaultError('INVALID_INPUT')
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
        if (sort === 'recent') {
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
      if (request.sort !== undefined && request.sort !== 'recent' && request.sort !== 'name') {
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
      return filtered
        .map(toSharedSummary)
        .sort((left, right) =>
          request.sort === 'name'
            ? compareText(left.name, right.name) || left.id.localeCompare(right.id)
            : right.updatedAt.localeCompare(left.updatedAt) || left.id.localeCompare(right.id)
        )
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

  getPasswordHistory(request: LoginIdRequest): Promise<VaultPasswordHistoryEntry[]> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      this.assertActiveLogin(login)
      return clonePasswordHistory(login.passwordHistory)
    })
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
    masterPassword: string
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
        vaultJson: buildBitwardenJson(prepared.portable),
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

      const next = cloneData(this.requireData())
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
    return this.exclusive(async () => {
      const current = this.requireData()
      let credential: string
      const algorithm = request.algorithm
      if (algorithm === 'password') {
        credential = generatePassword(request.options, this.randomInt)
      } else if (algorithm === 'passphrase') {
        credential = generatePassphrase(request.options, loadEffLongWordlist(), this.randomInt)
      } else if (algorithm === 'username') {
        credential = generateRandomWordUsername(
          request.options,
          loadEffLongWordlist(),
          this.randomInt
        )
      } else if (algorithm === 'subaddress') {
        credential = generatePlusAddressedEmail(request.email, this.randomInt)
      } else if (algorithm === 'catchall') {
        credential = generateCatchAllEmail(request.domain, this.randomInt)
      } else {
        throw new VaultError('INVALID_INPUT')
      }
      if (credential.length === 0 || credential.length > MAX_GENERATED_CREDENTIAL_LENGTH) {
        throw new VaultError('INTERNAL_ERROR')
      }

      const category = generatorCategoryForAlgorithm(algorithm)
      const generationDate = Date.parse(this.nowIso())
      const generated: GeneratorHistoryEntry & { algorithm: GeneratorCredentialAlgorithm } = {
        credential,
        category,
        generationDate,
        algorithm
      }
      const existingIndex = current.generatorHistory.findIndex(
        (entry) => entry.credential === credential
      )
      if (existingIndex >= 0) {
        const existing = current.generatorHistory[existingIndex]!
        return {
          ...generated,
          historyLocator: {
            index: existingIndex,
            generationDate: existing.generationDate,
            category: existing.category,
            ...(existing.algorithm === undefined ? {} : { algorithm: existing.algorithm })
          }
        }
      }

      const next = cloneData(current)
      next.generatorHistory.unshift(generated)
      next.generatorHistory.splice(MAX_GENERATOR_HISTORY)
      next.updatedAt = new Date(generationDate).toISOString()
      const generation = this.generation
      await this.persist(next)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      this.data = next
      return {
        ...generated,
        historyLocator: { index: 0, generationDate, category, algorithm }
      }
    })
  }

  generateSshKey(): Promise<SshKeyMaterial> {
    return this.exclusive(async () => {
      this.requireData()
      return generateSshKeyMaterial()
    })
  }

  generatorHistory(): Promise<GeneratorHistoryEntry[]> {
    return this.exclusive(async () => cloneGeneratorHistory(this.requireData().generatorHistory))
  }

  clearGeneratorHistory(): Promise<void> {
    return this.exclusive(async () => {
      const current = this.requireData()
      if (current.generatorHistory.length === 0) return
      const next = cloneData(current)
      next.generatorHistory = []
      next.updatedAt = this.nowIso()
      const generation = this.generation
      await this.persist(next)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      this.data = next
    })
  }

  copyGeneratorHistory(request: GeneratorHistoryLocator): Promise<void> {
    return this.exclusive(async () => {
      if (
        !Number.isSafeInteger(request.index) ||
        request.index < 0 ||
        !Number.isSafeInteger(request.generationDate) ||
        !isGeneratorCategory(request.category) ||
        (request.algorithm !== undefined && !isGeneratorAlgorithm(request.algorithm))
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const entry = this.requireData().generatorHistory[request.index]
      if (
        !entry ||
        entry.generationDate !== request.generationDate ||
        entry.category !== request.category ||
        entry.algorithm !== request.algorithm
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      await this.platform.copyText(entry.credential)
    })
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
        lastUsedAt: null,
        createdAt: now,
        updatedAt: now,
        deletedAt: null,
        archivedAt: null,
        reprompt: normalizeReprompt(request.reprompt ?? 0),
        passkeys: [],
        customFields,
        passwordHistory: [],
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
      assertUuid(request.id)
      const login = this.findLogin(data, request.id)
      if (login.deletedAt === null) throw new VaultError('INVALID_INPUT')
      recordSyncDeletion(data.sync, 'login', request.id)
      data.logins = data.logins.filter((candidate) => candidate.id !== request.id)
    })
  }

  deleteLoginsPermanently(request: LoginBatchRequest): Promise<number> {
    return this.mutate((data) => {
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
        request.field === 'uri' ? loginUriAt(login, request.uriIndex) : login[request.field]
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

  async getWebsiteIcon(request: LoginIdRequest): Promise<string | null> {
    const iconUrl = await this.exclusive(async () => {
      assertUuid(request.id)
      const data = this.requireData()
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      if (login.type !== 'login' || !login.uri || !data.sync) return null
      const hostname = parseWebsiteHostname(login.uri)
      return hostname ? resolveWebsiteIconUrl(data.sync.serverUrl, hostname) : null
    })
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
      this.syncLastError = 'SYNC_FAILED'
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
      ...(this.syncLastError ? { lastError: this.syncLastError } : {})
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

  private normalizeNewDeviceOtp(value: string | undefined): string | undefined {
    if (value === undefined) return undefined
    const normalized = value.trim()
    if (normalized.length === 0 || normalized.length > MAX_TWO_FACTOR_CODE_LENGTH) {
      throw new VaultError('INVALID_INPUT')
    }
    return normalized
  }

  private getOrCreateSyncClient(sync: PersistedSyncData): BitwardenSyncClient {
    this.syncClient ??= this.createSyncClient(sync)
    return this.syncClient
  }

  private requireSyncData(): PersistedSyncData {
    const sync = this.requireData().sync
    if (!sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    return sync
  }

  private startSyncOperation(): AbortController {
    if (this.syncInProgress) throw new VaultError('SYNC_FAILED')
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
    const interrupted = current.nativeAttachmentRestore?.attachments.some(
      (attachment) => attachment.status === 'attempting'
    )
    if (!requiresMigration && !interrupted) return
    const next = cloneData(current)
    if (interrupted && next.nativeAttachmentRestore) {
      next.nativeAttachmentRestore = recoverInterruptedNativeAttachmentRestore(
        next.nativeAttachmentRestore,
        this.nowIso()
      )
      next.updatedAt = next.nativeAttachmentRestore.updatedAt
    }
    await this.persist(next)
    this.data = next
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
    if (error instanceof VaultError) return error
    this.syncLastError = 'SYNC_FAILED'
    if (error instanceof BitwardenDirectError) {
      if (error.code === 'AUTH_REQUIRED' || error.code === 'TWO_FACTOR_REQUIRED') {
        return new VaultError('SYNC_AUTH_REQUIRED')
      }
      if (error.code === 'NEW_DEVICE_REQUIRED') {
        return new VaultError('SYNC_NEW_DEVICE_REQUIRED')
      }
      if (error.code === 'ABORTED') return new VaultError('LOCKED')
      if (error.code === 'UNSUPPORTED_ACCOUNT_ENCRYPTION') {
        this.syncLastError = 'SYNC_UNSUPPORTED_ACCOUNT'
        return new VaultError('SYNC_UNSUPPORTED_ACCOUNT')
      }
    }
    return new VaultError('SYNC_FAILED')
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

  private async performSync(
    current: VaultData,
    client: BitwardenSyncClient,
    signal: AbortSignal
  ): Promise<SyncResult> {
    const sync = current.sync
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
    const next = cloneData(current)
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
    const remoteSnapshot = this.remoteSyncSnapshot(remoteFolders, remoteLogins)
    const syncMetadata = this.syncMetadata(sync)
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

    for (const action of plan.actions) {
      if (signal.aborted) throw new BitwardenDirectError('ABORTED')
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
      lastUsedAt: source.lastUsedAt ?? null,
      createdAt,
      updatedAt,
      deletedAt: source.deletedAt,
      archivedAt: source.archivedAt,
      reprompt: source.reprompt,
      passkeys: validateRemotePasskeys(source.passkeys),
      customFields: cloneCustomFields(source.customFields),
      passwordHistory: clonePasswordHistory(source.passwordHistory),
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
      lastUsedAt: null,
      createdAt: normalized.createdAt ?? this.nowIso(),
      updatedAt: normalized.updatedAt ?? this.nowIso(),
      deletedAt: normalized.deletedAt,
      archivedAt: normalized.archivedAt,
      reprompt: normalized.reprompt,
      passkeys: validateRemotePasskeys(normalized.passkeys),
      customFields: cloneCustomFields(normalized.customFields),
      passwordHistory: clonePasswordHistory(normalized.passwordHistory),
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
      passwordHistory: clonePasswordHistory(login.passwordHistory)
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
      const generation = this.generation
      const currentLogin = this.findLogin(current, request.id)
      this.assertActiveLogin(currentLogin)
      const result = await operation(currentLogin)
      const next = cloneData(current)
      const usedLogin = this.findLogin(next, request.id)
      const now = this.nowIso()
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
    await this.store.write(data, this.key, this.salt)
  }

  private requireData(): VaultData {
    if (!this.data || !this.key || !this.salt) throw new VaultError('LOCKED')
    return this.data
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
