/**
 * Decodes a `/sync` payload into the next vault snapshot once the account user key is known.
 * Pure apart from zeroing the key buffers it allocates; the caller commits the result.
 */
import type { KeyObject } from 'node:crypto'
import { BitwardenCryptoError, type BitwardenSymmetricKey } from './bitwarden-crypto'
import {
  BitwardenHttpError,
  isJsonObject,
  parseEquivalentDomainSettings,
  type BitwardenEquivalentDomainSettings,
  type JsonObject,
  type JsonValue
} from './bitwarden-http'
import {
  BitwardenPolicyParseError,
  parseBitwardenPolicySync,
  type BitwardenPolicySet
} from './bitwarden-policy'
import type { SyncInvalidResponseStage } from '../shared/vault-contract'
import { MAX_REMOTE_ENTITIES } from './vault/limits'
import { readField } from './bitwarden-fields'
import { UUID_PATTERN } from './validation-primitives'
import { BitwardenDirectError, invalidResponse } from './bitwarden-direct-error'
import {
  addAggregateRemoteRows,
  assertUuidValue,
  booleanProperty,
  decryptCollection,
  decryptFolder,
  decryptLogin,
  decryptSend,
  normalizedBitwardenTimestamp,
  nullableStringProperty,
  organizationCipher,
  parseOrganization,
  parsedCipherNestedRows,
  rawCipherNestedRows,
  remoteCipherType,
  repromptProperty,
  requiredStringProperty,
  isSupportedCipherType,
  stringProperty,
  type BitwardenCollection,
  type BitwardenLoginItem,
  type BitwardenOrganization,
  type BitwardenOrganizationCipher,
  type CachedFolder,
  type CachedLogin,
  type CachedSend
} from './bitwarden-cipher-codec'
import {
  decryptOrganizationKey,
  decryptSymmetricWrappedKey,
  resolveAccountPrivateKey
} from './bitwarden-account-keys'

export interface DecodedSyncSnapshot {
  folders: Map<string, CachedFolder>
  logins: Map<string, CachedLogin>
  organizations: Map<string, BitwardenOrganization>
  collections: Map<string, BitwardenCollection>
  organizationCiphers: Map<string, BitwardenOrganizationCipher>
  /** Server rows kept verbatim so edits round-trip fields this client does not model. */
  organizationCipherRaws: Map<string, JsonObject>
  /** Fresh copies the caller owns and must zero when it discards the snapshot. */
  organizationKeys: Map<string, Buffer>
  sends: Map<string, CachedSend>
  /** Personal ciphers withheld from the snapshot because they are unsupported or corrupt. */
  isolatedPersonalCiphers: Set<string>
  policySet: BitwardenPolicySet
  equivalentDomainSettings: BitwardenEquivalentDomainSettings
}

/** Carries the payload section that was being decoded when `cause` was thrown. */
export class SyncPayloadError extends Error {
  constructor(
    readonly stage: SyncInvalidResponseStage,
    override readonly cause: unknown
  ) {
    super(`Sync payload rejected in ${stage}`)
    this.name = 'SyncPayloadError'
  }
}

interface OrganizationIndex {
  organizations: Map<string, BitwardenOrganization>
  rowsById: Map<string, JsonObject>
  providerRowsById: Map<string, JsonObject>
  providerRows: JsonValue[]
}

function emptyEquivalentDomainSettings(): BitwardenEquivalentDomainSettings {
  return { equivalentDomains: [], globalEquivalentDomains: [] }
}

function parseSyncEquivalentDomainSettings(
  value: JsonValue | undefined
): BitwardenEquivalentDomainSettings {
  if (value === undefined || value === null) return emptyEquivalentDomainSettings()
  try {
    return parseEquivalentDomainSettings(value)
  } catch (error) {
    if (
      error instanceof BitwardenHttpError &&
      (error.code === 'INVALID_RESPONSE' || error.code === 'TOO_LARGE')
    ) {
      // Equivalent domains are ancillary matching hints. Invalid server-stored values must not
      // block vault data, and disabling every equivalence is the fail-closed matching fallback.
      return emptyEquivalentDomainSettings()
    }
    throw error
  }
}

function parseSyncPolicySet(payload: JsonObject): BitwardenPolicySet {
  try {
    return parseBitwardenPolicySync(payload)
  } catch (error) {
    if (!(error instanceof BitwardenPolicyParseError)) throw error
    return {
      source: 'none',
      policies: [],
      parseFailure: error.code === 'POLICY_LIMIT_EXCEEDED' ? 'limit-exceeded' : 'invalid-response'
    }
  }
}

function optionalRemoteArrayProperty(record: JsonObject, name: string): JsonValue[] {
  const value = readField(record, name)
  if (value === undefined || value === null) return []
  if (!Array.isArray(value) || value.length > MAX_REMOTE_ENTITIES) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value
}

function requiredRemoteArrayProperty(record: JsonObject, name: string): JsonValue[] {
  const value = readField(record, name)
  if (!Array.isArray(value) || value.length > MAX_REMOTE_ENTITIES) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return value
}

function validatePersonalCipherSecurityMetadata(record: JsonObject): void {
  nullableStringProperty(record, 'folderId')
  booleanProperty(record, 'favorite')
  nullableStringProperty(record, 'creationDate')
  nullableStringProperty(record, 'revisionDate')
  repromptProperty(record)
  for (const name of ['deletedDate', 'archivedDate'] as const) {
    const value = nullableStringProperty(record, name)
    if (value !== null) normalizedBitwardenTimestamp(value)
  }
}

function isQuarantinablePersonalCipherError(error: unknown): boolean {
  if (error instanceof BitwardenDirectError) {
    return (
      error.code === 'INVALID_RESPONSE' ||
      error.code === 'INVALID_SSH_KEY' ||
      error.code === 'UNSUPPORTED_ACCOUNT_ENCRYPTION'
    )
  }
  if (!(error instanceof BitwardenCryptoError)) return false
  return (
    error.code === 'INVALID_INPUT' ||
    error.code === 'INVALID_KEY' ||
    error.code === 'INVALID_CIPHERSTRING' ||
    error.code === 'AUTHENTICATION_FAILED' ||
    error.code === 'UNSUPPORTED_CIPHER_TYPE' ||
    error.code === 'DECRYPTION_FAILED'
  )
}

function organizationRows(payload: JsonObject, profile: JsonObject): JsonValue[] {
  const candidates = [
    readField(profile, 'organizationsNew'),
    readField(payload, 'organizationsNew'),
    readField(profile, 'organizations')
  ]
  if (candidates.some((value) => value !== undefined && value !== null && !Array.isArray(value))) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  const rows = candidates[0] ?? candidates[1] ?? candidates[2]
  if (rows === undefined || rows === null) return []
  if (!Array.isArray(rows) || rows.length > MAX_REMOTE_ENTITIES) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  return rows
}

function indexOrganizations(payload: JsonObject, profile: JsonObject): OrganizationIndex {
  const rows = organizationRows(payload, profile)
  const providerOrganizationRows = optionalRemoteArrayProperty(profile, 'providerOrganizations')
  const providerRows = optionalRemoteArrayProperty(profile, 'providers')
  const organizations = new Map<string, BitwardenOrganization>()
  const rowsById = new Map<string, JsonObject>()
  for (const value of rows) {
    if (!isJsonObject(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
    const organization = parseOrganization(value)
    if (rowsById.has(organization.id)) throw new BitwardenDirectError('INVALID_RESPONSE')
    rowsById.set(organization.id, value)
    organizations.set(organization.id, organization)
  }
  const providerRowsById = new Map<string, JsonObject>()
  for (const value of providerOrganizationRows) {
    if (!isJsonObject(value)) throw invalidResponse('organization-profile')
    const organization = parseOrganization(value)
    if (providerRowsById.has(organization.id)) throw invalidResponse('organization-profile')
    providerRowsById.set(organization.id, value)
    if (!organizations.has(organization.id)) organizations.set(organization.id, organization)
  }
  return { organizations, rowsById, providerRowsById, providerRows }
}

/**
 * Records which policy organizations enforce policies, but only when every one of them states
 * `usePolicies` explicitly; otherwise applicability stays unknown and enforcement stays broad.
 */
function withPolicyMembership(
  policySet: BitwardenPolicySet,
  rowsById: ReadonlyMap<string, JsonObject>
): BitwardenPolicySet {
  if (policySet.parseFailure || policySet.policies.length === 0) return policySet
  const applicableOrganizationIds = new Set<string>()
  for (const organizationId of new Set(policySet.policies.map((policy) => policy.organizationId))) {
    const rawOrganization = rowsById.get(organizationId)
    const usePolicies = rawOrganization ? readField(rawOrganization, 'usePolicies') : undefined
    if (typeof usePolicies !== 'boolean') return policySet
    if (usePolicies) applicableOrganizationIds.add(organizationId)
  }
  return { ...policySet, applicableOrganizationIds: [...applicableOrganizationIds].sort() }
}

/** Validates cipher ids and organization ids, and isolates unsupported personal cipher types. */
function preflightCipherRows(
  cipherRows: readonly JsonValue[],
  requiredOrganizationIds: Set<string>,
  isolatedPersonalCiphers: Set<string>
): void {
  const cipherIds = new Set<string>()
  for (const value of cipherRows) {
    if (!isJsonObject(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
    const id = assertUuidValue(requiredStringProperty(value, 'id'))
    if (cipherIds.has(id)) throw new BitwardenDirectError('INVALID_RESPONSE')
    cipherIds.add(id)
    const type = remoteCipherType(value)
    const organizationId = readField(value, 'organizationId')
    if (
      organizationId !== null &&
      organizationId !== undefined &&
      (typeof organizationId !== 'string' || !UUID_PATTERN.test(organizationId))
    ) {
      throw new BitwardenDirectError('INVALID_RESPONSE')
    }
    if (!isSupportedCipherType(type)) {
      if (organizationId === null || organizationId === undefined) {
        isolatedPersonalCiphers.add(id)
        continue
      }
      // Shared rows are server-authoritative and replace the prior shared snapshot. Until
      // shared-item quarantine can preserve that snapshot by ID, an unknown organization
      // cipher kind must remain fail-closed instead of silently disappearing.
      throw invalidResponse('unsupported-cipher-type')
    }
    if (organizationId === null || organizationId === undefined) continue
    requiredOrganizationIds.add(organizationId)
  }
}

/** Unwraps the keys of organizations that own synced data into `organizationKeys`. */
function unwrapOrganizationKeys(
  index: OrganizationIndex,
  requiredOrganizationIds: ReadonlySet<string>,
  profile: JsonObject,
  userKey: BitwardenSymmetricKey,
  organizationKeys: Map<string, Buffer>
): void {
  const hasOrganizationEncryptedData = requiredOrganizationIds.size > 0
  const accountPrivateKey = hasOrganizationEncryptedData
    ? resolveAccountPrivateKey(profile, userKey)
    : null
  for (const [organizationId, rawOrganization] of index.rowsById) {
    if (!requiredOrganizationIds.has(organizationId)) continue
    const encryptedKey = stringProperty(rawOrganization, 'key')
    if (!encryptedKey) continue
    if (!accountPrivateKey) throw new BitwardenDirectError('UNSUPPORTED_ACCOUNT_ENCRYPTION')
    organizationKeys.set(
      organizationId,
      decryptOrganizationKey(encryptedKey, userKey, accountPrivateKey, 'organization-key')
    )
  }
  if (index.providerRowsById.size > 0 && hasOrganizationEncryptedData) {
    unwrapProviderOrganizationKeys(
      index,
      requiredOrganizationIds,
      userKey,
      accountPrivateKey,
      organizationKeys
    )
  }
}

function unwrapProviderOrganizationKeys(
  index: OrganizationIndex,
  requiredOrganizationIds: ReadonlySet<string>,
  userKey: BitwardenSymmetricKey,
  accountPrivateKey: KeyObject | null,
  organizationKeys: Map<string, Buffer>
): void {
  const providerKeys = new Map<string, Buffer>()
  try {
    if (!accountPrivateKey) throw invalidResponse('provider-organization-key')
    const requiredProviderIds = new Set<string>()
    for (const [organizationId, rawOrganization] of index.providerRowsById) {
      if (!requiredOrganizationIds.has(organizationId)) continue
      requiredProviderIds.add(
        assertUuidValue(requiredStringProperty(rawOrganization, 'providerId'))
      )
    }
    for (const value of index.providerRows) {
      if (!isJsonObject(value)) throw invalidResponse('provider-organization-key')
      const providerId = assertUuidValue(requiredStringProperty(value, 'id'))
      if (!requiredProviderIds.has(providerId)) continue
      if (providerKeys.has(providerId)) throw invalidResponse('provider-organization-key')
      providerKeys.set(
        providerId,
        decryptOrganizationKey(
          requiredStringProperty(value, 'key'),
          userKey,
          accountPrivateKey,
          'provider-organization-key'
        )
      )
    }
    for (const [organizationId, rawOrganization] of index.providerRowsById) {
      if (!requiredOrganizationIds.has(organizationId)) continue
      const encryptedKey = stringProperty(rawOrganization, 'key')
      if (!encryptedKey) continue
      const providerId = assertUuidValue(requiredStringProperty(rawOrganization, 'providerId'))
      const providerKey = providerKeys.get(providerId)
      if (!providerKey) throw invalidResponse('provider-organization-key')
      const organizationKey = decryptSymmetricWrappedKey(encryptedKey, providerKey)
      organizationKeys.get(organizationId)?.fill(0)
      organizationKeys.set(organizationId, organizationKey)
    }
  } finally {
    for (const providerKey of providerKeys.values()) providerKey.fill(0)
  }
}

/**
 * Decodes every vault section of `payload` with the already validated account `profile` and
 * `userKey`. Throws a `SyncPayloadError` naming the section that failed; `userKey` stays owned
 * by the caller.
 */
export function decodeSyncPayload(
  payload: JsonObject,
  profile: JsonObject,
  userKey: BitwardenSymmetricKey
): DecodedSyncSnapshot {
  let stage: SyncInvalidResponseStage = 'folder'
  const organizationKeys = new Map<string, Buffer>()
  const snapshotKeys = new Map<string, Buffer>()
  try {
    const equivalentDomainSettings = parseSyncEquivalentDomainSettings(
      readField(payload, 'domains')
    )
    const folderRows = requiredRemoteArrayProperty(payload, 'folders')
    stage = 'cipher'
    const cipherRows = requiredRemoteArrayProperty(payload, 'ciphers')
    stage = 'collection'
    const collectionRows = optionalRemoteArrayProperty(payload, 'collections')
    stage = 'send'
    const sendRows = optionalRemoteArrayProperty(payload, 'sends')
    stage = 'organization'
    const index = indexOrganizations(payload, profile)
    const policySet = withPolicyMembership(parseSyncPolicySet(payload), index.rowsById)

    const requiredOrganizationIds = new Set<string>()
    const isolatedPersonalCiphers = new Set<string>()
    stage = 'cipher'
    preflightCipherRows(cipherRows, requiredOrganizationIds, isolatedPersonalCiphers)
    stage = 'collection'
    for (const value of collectionRows) {
      if (!isJsonObject(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
      requiredOrganizationIds.add(assertUuidValue(requiredStringProperty(value, 'organizationId')))
    }
    stage = 'organization'
    unwrapOrganizationKeys(index, requiredOrganizationIds, profile, userKey, organizationKeys)

    stage = 'snapshot'
    let aggregateRows = addAggregateRemoteRows(0, folderRows.length)
    aggregateRows = addAggregateRemoteRows(aggregateRows, cipherRows.length)
    aggregateRows = addAggregateRemoteRows(aggregateRows, collectionRows.length)
    aggregateRows = addAggregateRemoteRows(aggregateRows, sendRows.length)

    stage = 'folder'
    const folders = new Map<string, CachedFolder>()
    for (const value of folderRows) {
      if (!isJsonObject(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
      const item = decryptFolder(value, userKey)
      if (folders.has(item.id)) throw new BitwardenDirectError('INVALID_RESPONSE')
      folders.set(item.id, { raw: structuredClone(value), item })
    }

    stage = 'cipher'
    const logins = new Map<string, CachedLogin>()
    const organizationCiphers = new Map<string, BitwardenOrganizationCipher>()
    const organizationCipherRaws = new Map<string, JsonObject>()
    for (const value of cipherRows) {
      if (!isJsonObject(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
      const type = remoteCipherType(value)
      const organizationId = readField(value, 'organizationId')
      const rawNestedRows = rawCipherNestedRows(value)
      aggregateRows = addAggregateRemoteRows(aggregateRows, rawNestedRows)
      // The preflight validated organization ids, isolated unsupported personal rows, and
      // rejected unsupported shared rows.
      if (!isSupportedCipherType(type)) continue
      if (typeof organizationId === 'string') {
        const organizationKey = organizationKeys.get(organizationId)
        if (
          !organizationKey ||
          (!index.rowsById.has(organizationId) && !index.providerRowsById.has(organizationId))
        ) {
          throw new BitwardenDirectError('INVALID_RESPONSE')
        }
        const item = decryptLogin(value, organizationKey)
        const parsed = organizationCipher(value, item, organizationId)
        organizationCiphers.set(parsed.id, parsed)
        organizationCipherRaws.set(parsed.id, structuredClone(value))
        aggregateRows = addAggregateRemoteRows(
          aggregateRows,
          Math.max(0, parsedCipherNestedRows(item) - rawNestedRows)
        )
        continue
      }
      const id = assertUuidValue(requiredStringProperty(value, 'id'))
      validatePersonalCipherSecurityMetadata(value)
      let item: BitwardenLoginItem
      let blobNestedRows = 0
      try {
        item = decryptLogin(value, userKey, (rows) => {
          blobNestedRows = rows
        })
      } catch (error) {
        aggregateRows = addAggregateRemoteRows(aggregateRows, blobNestedRows)
        if (!isQuarantinablePersonalCipherError(error)) throw error
        isolatedPersonalCiphers.add(id)
        continue
      }
      aggregateRows = addAggregateRemoteRows(aggregateRows, blobNestedRows)
      aggregateRows = addAggregateRemoteRows(
        aggregateRows,
        Math.max(0, parsedCipherNestedRows(item) - rawNestedRows - blobNestedRows)
      )
      logins.set(item.id, { raw: structuredClone(value), item })
    }

    stage = 'collection'
    const collections = new Map<string, BitwardenCollection>()
    for (const value of collectionRows) {
      if (!isJsonObject(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
      const collection = decryptCollection(value, organizationKeys)
      if (collections.has(collection.id)) throw new BitwardenDirectError('INVALID_RESPONSE')
      collections.set(collection.id, collection)
    }
    for (const cipher of organizationCiphers.values()) {
      for (const collectionId of cipher.collectionIds) {
        const collection = collections.get(collectionId)
        if (!collection || collection.organizationId !== cipher.organizationId) {
          throw new BitwardenDirectError('INVALID_RESPONSE')
        }
      }
    }

    stage = 'send'
    const sends = new Map<string, CachedSend>()
    for (const value of sendRows) {
      if (!isJsonObject(value)) throw new BitwardenDirectError('INVALID_RESPONSE')
      const send = decryptSend(value, userKey)
      sends.set(send.item.id, send)
    }

    for (const [organizationId, organizationKey] of organizationKeys) {
      snapshotKeys.set(organizationId, Buffer.from(organizationKey))
    }
    return {
      folders,
      logins,
      organizations: index.organizations,
      collections,
      organizationCiphers,
      organizationCipherRaws,
      organizationKeys: snapshotKeys,
      sends,
      isolatedPersonalCiphers,
      policySet,
      equivalentDomainSettings
    }
  } catch (error) {
    for (const organizationKey of snapshotKeys.values()) organizationKey.fill(0)
    throw new SyncPayloadError(stage, error)
  } finally {
    for (const organizationKey of organizationKeys.values()) organizationKey.fill(0)
  }
}
