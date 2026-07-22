import {
  BITWARDEN_POLICY_TYPE,
  type ActionablePolicyMetadata,
  type BitwardenPolicyMetadata,
  type BitwardenPolicySet
} from '../bitwarden-policy'
import {
  parseNativeAttachmentRestoreJournal,
  type NativeAttachmentRestoreJournal
} from '../native-attachment-restore'
import { VaultError } from '../vault-errors'
import {
  LEGACY_DATA_VERSION,
  CLI_DATA_VERSION,
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
  EQUIVALENT_DOMAINS_DATA_VERSION,
  SENDS_DATA_VERSION,
  ORGANIZATIONS_DATA_VERSION,
  NATIVE_ATTACHMENT_RESTORE_DATA_VERSION,
  MASTER_PASSWORD_CHANGE_DATA_VERSION,
  LOGIN_WIRE_METADATA_DATA_VERSION,
  PENDING_LOGIN_IMPORT_DATA_VERSION,
  PERSONAL_VAULT_PURGE_DATA_VERSION,
  USAGE_COUNT_DATA_VERSION,
  DATA_VERSION,
  MAX_REMOTE_ENTITIES,
  MAX_SENDS
} from './limits'
import { assertIsoDate, isRecord } from './parse-primitives'
import { parseFolder, parseStoredLogin, parseStoredSharedLogin } from './login-parsing'
import { parseStoredSend } from './send-parsing'
import { parseStoredCollection, parseStoredOrganization } from './org-collection-parsing'
import { cloneGeneratorHistory, parseGeneratorHistory } from './generator-history'
import { parseSyncData } from './sync-data-parsing'
import { cloneEquivalentDomainSettings } from './equivalent-domains'
import { cloneAttachments } from './attachments-parsing'
import { cloneLoginUris } from './login-uris'
import { clonePasswordHistory } from './password-history'
import { cloneCustomFields } from './custom-fields'
import type { MasterPasswordChangeJournal, VaultData } from './types'

const STORED_POLICY_NAMES = new Map<number, keyof typeof BITWARDEN_POLICY_TYPE>(
  Object.entries(BITWARDEN_POLICY_TYPE).map(([name, type]) => [
    type,
    name as keyof typeof BITWARDEN_POLICY_TYPE
  ])
)
const STORED_POLICY_UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
const STORED_POLICY_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u

function strictStoredRecord(
  value: unknown,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[] = []
): Record<string, unknown> {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) throw new VaultError('CORRUPT_VAULT')
  const allowed = new Set([...requiredKeys, ...optionalKeys])
  const keys = Reflect.ownKeys(value)
  if (
    keys.some((key) => typeof key !== 'string' || !allowed.has(key)) ||
    requiredKeys.some((key) => !Object.hasOwn(value, key))
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) {
      throw new VaultError('CORRUPT_VAULT')
    }
  }
  return value
}

function storedInteger(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return value as number
}

function parseStoredPolicyDate(value: unknown): string | null {
  if (value === null) return null
  if (
    typeof value !== 'string' ||
    value.length > 40 ||
    !STORED_POLICY_DATE_PATTERN.test(value) ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString().slice(0, 19) !== value.slice(0, 19)
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return value
}

function parseStoredActionablePolicyData(
  value: unknown,
  policyType: number
): ActionablePolicyMetadata {
  if (policyType === BITWARDEN_POLICY_TYPE.PasswordGenerator) {
    const data = strictStoredRecord(value, [
      'kind',
      'overridePasswordType',
      'minLength',
      'useUppercase',
      'useLowercase',
      'useNumbers',
      'numberCount',
      'useSpecial',
      'specialCount',
      'minNumberWords',
      'capitalize',
      'includeNumber'
    ])
    if (
      data.kind !== 'passwordGenerator' ||
      (data.overridePasswordType !== '' &&
        data.overridePasswordType !== 'password' &&
        data.overridePasswordType !== 'passphrase') ||
      typeof data.useUppercase !== 'boolean' ||
      typeof data.useLowercase !== 'boolean' ||
      typeof data.useNumbers !== 'boolean' ||
      typeof data.useSpecial !== 'boolean' ||
      typeof data.capitalize !== 'boolean' ||
      typeof data.includeNumber !== 'boolean'
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    return {
      kind: 'passwordGenerator',
      overridePasswordType: data.overridePasswordType,
      minLength: storedInteger(data.minLength, 0, 4_096),
      useUppercase: data.useUppercase,
      useLowercase: data.useLowercase,
      useNumbers: data.useNumbers,
      numberCount: storedInteger(data.numberCount, 0, 1_024),
      useSpecial: data.useSpecial,
      specialCount: storedInteger(data.specialCount, 0, 1_024),
      minNumberWords: storedInteger(data.minNumberWords, 0, 1_024),
      capitalize: data.capitalize,
      includeNumber: data.includeNumber
    }
  }
  if (policyType === BITWARDEN_POLICY_TYPE.MaximumVaultTimeout) {
    const data = strictStoredRecord(value, ['kind', 'minutes', 'timeoutType', 'action'])
    if (
      data.kind !== 'maximumVaultTimeout' ||
      (data.timeoutType !== null &&
        data.timeoutType !== 'never' &&
        data.timeoutType !== 'onAppRestart' &&
        data.timeoutType !== 'onSystemLock' &&
        data.timeoutType !== 'immediately' &&
        data.timeoutType !== 'custom') ||
      (data.action !== null && data.action !== 'lock' && data.action !== 'logOut')
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    return {
      kind: 'maximumVaultTimeout',
      minutes: storedInteger(data.minutes, 1, 366 * 24 * 60),
      timeoutType: data.timeoutType,
      action: data.action
    }
  }
  if (policyType === BITWARDEN_POLICY_TYPE.RestrictedItemTypes) {
    const data = strictStoredRecord(value, ['kind', 'cipherTypes'])
    if (
      data.kind !== 'restrictedItemTypes' ||
      !Array.isArray(data.cipherTypes) ||
      data.cipherTypes.length === 0 ||
      data.cipherTypes.length > 16
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    const cipherTypes = data.cipherTypes.map((type) => storedInteger(type, 1, 8))
    if (
      new Set(cipherTypes).size !== cipherTypes.length ||
      cipherTypes.some((type, index) => index > 0 && cipherTypes[index - 1]! >= type)
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    return { kind: 'restrictedItemTypes', cipherTypes }
  }
  const booleanKinds = new Map<
    number,
    | 'organizationDataOwnership'
    | 'disableSend'
    | 'disablePersonalVaultExport'
    | 'removeUnlockWithPin'
  >([
    [BITWARDEN_POLICY_TYPE.OrganizationDataOwnership, 'organizationDataOwnership'],
    [BITWARDEN_POLICY_TYPE.DisableSend, 'disableSend'],
    [BITWARDEN_POLICY_TYPE.DisablePersonalVaultExport, 'disablePersonalVaultExport'],
    [BITWARDEN_POLICY_TYPE.RemoveUnlockWithPin, 'removeUnlockWithPin']
  ])
  const expectedKind = booleanKinds.get(policyType)
  const data = strictStoredRecord(value, ['kind'])
  if (!expectedKind || data.kind !== expectedKind) throw new VaultError('CORRUPT_VAULT')
  return { kind: expectedKind }
}

function parseStoredPolicy(value: unknown): BitwardenPolicyMetadata {
  const policy = strictStoredRecord(value, [
    'id',
    'organizationId',
    'type',
    'typeName',
    'enabled',
    'canToggleState',
    'revisionDate',
    'execution',
    'data'
  ])
  if (
    typeof policy.id !== 'string' ||
    !STORED_POLICY_UUID_PATTERN.test(policy.id) ||
    typeof policy.organizationId !== 'string' ||
    !STORED_POLICY_UUID_PATTERN.test(policy.organizationId) ||
    typeof policy.enabled !== 'boolean' ||
    typeof policy.canToggleState !== 'boolean' ||
    (policy.execution !== 'actionable' &&
      policy.execution !== 'unsupported' &&
      policy.execution !== 'unknown' &&
      policy.execution !== 'malformed')
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  const type = storedInteger(policy.type, 0, 65_535)
  const expectedTypeName = STORED_POLICY_NAMES.get(type) ?? null
  if (policy.typeName !== expectedTypeName) throw new VaultError('CORRUPT_VAULT')

  const actionableTypes = new Set<number>([
    BITWARDEN_POLICY_TYPE.PasswordGenerator,
    BITWARDEN_POLICY_TYPE.OrganizationDataOwnership,
    BITWARDEN_POLICY_TYPE.DisableSend,
    BITWARDEN_POLICY_TYPE.MaximumVaultTimeout,
    BITWARDEN_POLICY_TYPE.DisablePersonalVaultExport,
    BITWARDEN_POLICY_TYPE.RemoveUnlockWithPin,
    BITWARDEN_POLICY_TYPE.RestrictedItemTypes
  ])
  const expectedExecution =
    expectedTypeName === null
      ? 'unknown'
      : actionableTypes.has(type)
        ? policy.execution === 'malformed'
          ? 'malformed'
          : 'actionable'
        : 'unsupported'
  if (policy.execution !== expectedExecution) throw new VaultError('CORRUPT_VAULT')
  const data =
    policy.execution === 'actionable'
      ? parseStoredActionablePolicyData(policy.data, type)
      : policy.data === null
        ? null
        : (() => {
            throw new VaultError('CORRUPT_VAULT')
          })()
  return {
    id: policy.id,
    organizationId: policy.organizationId,
    type,
    typeName: expectedTypeName,
    enabled: policy.enabled,
    canToggleState: policy.canToggleState,
    revisionDate: parseStoredPolicyDate(policy.revisionDate),
    execution: policy.execution,
    data
  }
}

/** Strictly reconstructs the secret-free policy metadata allowed in encrypted vault storage. */
export function parseStoredBitwardenPolicySet(value: unknown): BitwardenPolicySet {
  const set = strictStoredRecord(
    value,
    ['source', 'policies'],
    ['parseFailure', 'applicableOrganizationIds']
  )
  if (set.source !== 'policiesNew' && set.source !== 'policies' && set.source !== 'none') {
    throw new VaultError('CORRUPT_VAULT')
  }
  if (!Array.isArray(set.policies) || set.policies.length > 256) {
    throw new VaultError('CORRUPT_VAULT')
  }
  const policies = set.policies.map(parseStoredPolicy)
  if (new Set(policies.map((policy) => policy.id)).size !== policies.length) {
    throw new VaultError('CORRUPT_VAULT')
  }
  const hasParseFailure = Object.hasOwn(set, 'parseFailure')
  if (
    hasParseFailure &&
    set.parseFailure !== 'invalid-response' &&
    set.parseFailure !== 'limit-exceeded'
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  if (
    (set.source === 'none' && policies.length !== 0) ||
    (hasParseFailure && (set.source !== 'none' || policies.length !== 0))
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  const hasApplicableOrganizationIds = Object.hasOwn(set, 'applicableOrganizationIds')
  let applicableOrganizationIds: string[] | undefined
  if (hasApplicableOrganizationIds) {
    if (
      !Array.isArray(set.applicableOrganizationIds) ||
      set.applicableOrganizationIds.length > MAX_REMOTE_ENTITIES
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    applicableOrganizationIds = set.applicableOrganizationIds.map((id) => {
      if (typeof id !== 'string' || !STORED_POLICY_UUID_PATTERN.test(id)) {
        throw new VaultError('CORRUPT_VAULT')
      }
      return id
    })
    if (new Set(applicableOrganizationIds).size !== applicableOrganizationIds.length) {
      throw new VaultError('CORRUPT_VAULT')
    }
  }
  return {
    source: set.source,
    policies,
    ...(hasParseFailure ? { parseFailure: set.parseFailure } : {}),
    ...(hasApplicableOrganizationIds ? { applicableOrganizationIds } : {})
  } as BitwardenPolicySet
}

export function parseMasterPasswordChangeJournal(value: unknown): MasterPasswordChangeJournal {
  if (
    !isRecord(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) ||
    Reflect.ownKeys(value).length !== 4 ||
    !['accountFingerprint', 'phase', 'startedAt', 'updatedAt'].every((key) =>
      Object.hasOwn(value, key)
    )
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  const { phase, startedAt, updatedAt, accountFingerprint } = value
  if (
    (phase !== 'prepared' && phase !== 'remote-confirmed' && phase !== 'local-rekeyed') ||
    typeof startedAt !== 'string' ||
    typeof updatedAt !== 'string' ||
    typeof accountFingerprint !== 'string' ||
    !/^[0-9a-f]{64}$/u.test(accountFingerprint)
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  assertIsoDate(startedAt)
  assertIsoDate(updatedAt)
  if (Date.parse(updatedAt) < Date.parse(startedAt)) throw new VaultError('CORRUPT_VAULT')
  return { phase, startedAt, updatedAt, accountFingerprint }
}

/**
 * Tags one parseVaultData section so main-process diagnostics can identify the rejected portion
 * of the vault without exposing its contents.
 */
export function taggedVaultSection<T>(section: string, parse: () => T): T {
  try {
    return parse()
  } catch (error) {
    if (
      error instanceof VaultError &&
      error.code === 'CORRUPT_VAULT' &&
      error.message === error.code
    ) {
      throw new VaultError('CORRUPT_VAULT', `CORRUPT_VAULT:parse-data:${section}`)
    }
    throw error
  }
}

/** Tags one rejected stored item with its array index and opaque id for diagnosis. */
export function taggedVaultItem<T>(
  section: string,
  index: number,
  value: unknown,
  parse: () => T
): T {
  try {
    return parse()
  } catch (error) {
    if (
      error instanceof VaultError &&
      error.code === 'CORRUPT_VAULT' &&
      error.message === error.code
    ) {
      const id = isRecord(value) && typeof value.id === 'string' ? `:${value.id}` : ''
      throw new VaultError('CORRUPT_VAULT', `CORRUPT_VAULT:parse-data:${section}:${index}${id}`)
    }
    throw error
  }
}

export function parseVaultData(value: unknown): VaultData {
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
      MASTER_PASSWORD_CHANGE_DATA_VERSION,
      LOGIN_WIRE_METADATA_DATA_VERSION,
      PENDING_LOGIN_IMPORT_DATA_VERSION,
      PERSONAL_VAULT_PURGE_DATA_VERSION,
      USAGE_COUNT_DATA_VERSION,
      DATA_VERSION
    ].includes(value.version)
  ) {
    throw new VaultError('CORRUPT_VAULT', 'CORRUPT_VAULT:parse-data:version')
  }
  if (!Array.isArray(value.folders) || !Array.isArray(value.logins)) {
    throw new VaultError('CORRUPT_VAULT', 'CORRUPT_VAULT:parse-data:header')
  }
  const dataVersion = value.version
  assertIsoDate(value.createdAt)
  assertIsoDate(value.updatedAt)

  const folders = value.folders.map((folder, index) =>
    taggedVaultItem('folders', index, folder, () => parseFolder(folder))
  )
  const logins = value.logins.map((login, index) =>
    taggedVaultItem('logins', index, login, () =>
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
        dataVersion < ATTACHMENTS_DATA_VERSION,
        dataVersion < LOGIN_WIRE_METADATA_DATA_VERSION,
        dataVersion < USAGE_COUNT_DATA_VERSION
      )
    )
  )
  const folderIds = new Set(folders.map((folder) => folder.id))
  const folderPositions = new Set(folders.map((folder) => folder.position))
  const loginIds = new Set(logins.map((login) => login.id))

  if (
    folderIds.size !== folders.length ||
    folderPositions.size !== folders.length ||
    folders.some((folder) => folder.position >= folders.length)
  ) {
    throw new VaultError('CORRUPT_VAULT', 'CORRUPT_VAULT:parse-data:folders:duplicate-or-position')
  }
  if (loginIds.size !== logins.length) {
    throw new VaultError('CORRUPT_VAULT', 'CORRUPT_VAULT:parse-data:logins:duplicate-id')
  }
  if (logins.some((login) => login.folderId !== null && !folderIds.has(login.folderId))) {
    throw new VaultError('CORRUPT_VAULT', 'CORRUPT_VAULT:parse-data:logins:unknown-folder')
  }

  const organizations =
    dataVersion < ORGANIZATIONS_DATA_VERSION
      ? []
      : taggedVaultSection('organizations', () => {
          if (
            !Array.isArray(value.organizations) ||
            value.organizations.length > MAX_REMOTE_ENTITIES
          ) {
            throw new VaultError('CORRUPT_VAULT')
          }
          const parsed = value.organizations.map((organization, index) =>
            taggedVaultItem('organizations', index, organization, () =>
              parseStoredOrganization(organization)
            )
          )
          if (new Set(parsed.map((organization) => organization.id)).size !== parsed.length) {
            throw new VaultError(
              'CORRUPT_VAULT',
              'CORRUPT_VAULT:parse-data:organizations:duplicate-id'
            )
          }
          return parsed
        })
  const organizationIds = new Set(organizations.map((organization) => organization.id))
  const collections =
    dataVersion < ORGANIZATIONS_DATA_VERSION
      ? []
      : taggedVaultSection('collections', () => {
          if (!Array.isArray(value.collections) || value.collections.length > MAX_REMOTE_ENTITIES) {
            throw new VaultError('CORRUPT_VAULT')
          }
          const parsed = value.collections.map((collection, index) =>
            taggedVaultItem('collections', index, collection, () =>
              parseStoredCollection(collection)
            )
          )
          if (new Set(parsed.map((collection) => collection.id)).size !== parsed.length) {
            throw new VaultError(
              'CORRUPT_VAULT',
              'CORRUPT_VAULT:parse-data:collections:duplicate-id'
            )
          }
          if (parsed.some((collection) => !organizationIds.has(collection.organizationId))) {
            throw new VaultError(
              'CORRUPT_VAULT',
              'CORRUPT_VAULT:parse-data:collections:unknown-organization'
            )
          }
          return parsed
        })
  const collectionIds = new Set(collections.map((collection) => collection.id))
  const sharedLogins =
    dataVersion < ORGANIZATIONS_DATA_VERSION
      ? []
      : taggedVaultSection('shared-logins', () => {
          if (
            !Array.isArray(value.sharedLogins) ||
            value.sharedLogins.length > MAX_REMOTE_ENTITIES
          ) {
            throw new VaultError('CORRUPT_VAULT')
          }
          const parsed = value.sharedLogins.map((login, index) =>
            taggedVaultItem('shared-logins', index, login, () =>
              parseStoredSharedLogin(
                login,
                dataVersion < LOGIN_WIRE_METADATA_DATA_VERSION,
                dataVersion < USAGE_COUNT_DATA_VERSION
              )
            )
          )
          if (new Set(parsed.map((login) => login.id)).size !== parsed.length) {
            throw new VaultError(
              'CORRUPT_VAULT',
              'CORRUPT_VAULT:parse-data:shared-logins:duplicate-id'
            )
          }
          if (parsed.some((login) => loginIds.has(login.id))) {
            throw new VaultError(
              'CORRUPT_VAULT',
              'CORRUPT_VAULT:parse-data:shared-logins:id-collision'
            )
          }
          if (parsed.some((login) => !organizationIds.has(login.organizationId))) {
            throw new VaultError(
              'CORRUPT_VAULT',
              'CORRUPT_VAULT:parse-data:shared-logins:unknown-organization'
            )
          }
          if (parsed.some((login) => login.collectionIds.some((id) => !collectionIds.has(id)))) {
            throw new VaultError(
              'CORRUPT_VAULT',
              'CORRUPT_VAULT:parse-data:shared-logins:unknown-collection'
            )
          }
          if (
            parsed.some((login) =>
              login.collectionIds.some(
                (id) =>
                  collections.find((collection) => collection.id === id)?.organizationId !==
                  login.organizationId
              )
            )
          ) {
            throw new VaultError(
              'CORRUPT_VAULT',
              'CORRUPT_VAULT:parse-data:shared-logins:collection-organization-mismatch'
            )
          }
          return parsed
        })

  const sync =
    dataVersion === LEGACY_DATA_VERSION
      ? null
      : taggedVaultSection('sync', () =>
          parseSyncData(
            value.sync,
            folderIds,
            loginIds,
            dataVersion === CLI_DATA_VERSION,
            dataVersion < PENDING_LOGIN_MUTATION_DATA_VERSION,
            dataVersion < PENDING_LOGIN_IMPORT_DATA_VERSION,
            dataVersion < PERSONAL_VAULT_PURGE_DATA_VERSION,
            dataVersion < EQUIVALENT_DOMAINS_DATA_VERSION
          )
        )

  if (sync) {
    const storedSync = value.sync
    const storedState = isRecord(storedSync) && isRecord(storedSync.state) ? storedSync.state : null
    const policySet =
      storedState && Object.hasOwn(storedState, 'policySet')
        ? taggedVaultSection('sync-policy-set', () =>
            parseStoredBitwardenPolicySet(storedState.policySet)
          )
        : { source: 'none' as const, policies: [] }
    sync.state = { ...sync.state, policySet }
  }

  let nativeAttachmentRestore: NativeAttachmentRestoreJournal | null = null
  if (dataVersion >= NATIVE_ATTACHMENT_RESTORE_DATA_VERSION) {
    try {
      nativeAttachmentRestore =
        value.nativeAttachmentRestore === null
          ? null
          : parseNativeAttachmentRestoreJournal(value.nativeAttachmentRestore)
    } catch {
      throw new VaultError('CORRUPT_VAULT', 'CORRUPT_VAULT:parse-data:native-attachment-restore')
    }
  }

  const masterPasswordChange =
    dataVersion < MASTER_PASSWORD_CHANGE_DATA_VERSION
      ? null
      : taggedVaultSection('master-password-change', () =>
          value.masterPasswordChange === null
            ? null
            : parseMasterPasswordChangeJournal(value.masterPasswordChange)
        )

  if (
    sync?.pendingPersonalVaultPurge &&
    (nativeAttachmentRestore !== null || masterPasswordChange !== null)
  ) {
    throw new VaultError('CORRUPT_VAULT', 'CORRUPT_VAULT:parse-data:purge-journal-conflict')
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
        : taggedVaultSection('sends', () => {
            if (!Array.isArray(value.sends) || value.sends.length > MAX_SENDS) {
              throw new VaultError('CORRUPT_VAULT')
            }
            const sends = value.sends.map((send, index) =>
              taggedVaultItem('sends', index, send, () => parseStoredSend(send))
            )
            if (new Set(sends.map((send) => send.id)).size !== sends.length) {
              throw new VaultError('CORRUPT_VAULT', 'CORRUPT_VAULT:parse-data:sends:duplicate-id')
            }
            return sends
          }),
    generatorHistory:
      dataVersion < GENERATOR_HISTORY_DATA_VERSION
        ? []
        : taggedVaultSection('generator-history', () =>
            parseGeneratorHistory(value.generatorHistory)
          ),
    sync,
    nativeAttachmentRestore,
    masterPasswordChange
  }
}

/**
 * Tags schema-validation failures of decrypted content so IPC diagnostics can distinguish a
 * structurally damaged envelope from plaintext that fails validation. Finer stage tags applied
 * inside the store are preserved.
 */
export function parseVaultDataTagged(value: unknown): VaultData {
  try {
    return parseVaultData(value)
  } catch (error) {
    if (
      error instanceof VaultError &&
      error.code === 'CORRUPT_VAULT' &&
      error.message === error.code
    ) {
      throw new VaultError('CORRUPT_VAULT', 'CORRUPT_VAULT:parse-data')
    }
    throw error
  }
}

export function cloneData(data: VaultData): VaultData {
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
    masterPasswordChange: data.masterPasswordChange ? { ...data.masterPasswordChange } : null,
    sync: data.sync
      ? {
          ...data.sync,
          state: {
            ...data.sync.state,
            session: data.sync.state.session ? { ...data.sync.state.session } : null,
            policySet:
              data.sync.state.policySet === undefined
                ? { source: 'none', policies: [] }
                : parseStoredBitwardenPolicySet(data.sync.state.policySet)
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
            : null,
          pendingLoginImport: data.sync.pendingLoginImport
            ? {
                phase: data.sync.pendingLoginImport.phase,
                startedAt: data.sync.pendingLoginImport.startedAt,
                entries: data.sync.pendingLoginImport.entries.map((entry) => ({ ...entry }))
              }
            : null,
          pendingPersonalVaultPurge: data.sync.pendingPersonalVaultPurge
            ? { ...data.sync.pendingPersonalVaultPurge }
            : null
        }
      : null
  }
}
