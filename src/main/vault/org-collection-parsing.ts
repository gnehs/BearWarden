import type {
  CollectionView,
  EmergencyAccessView,
  OrganizationView
} from '../../shared/vault-contract'
import type { BitwardenEmergencyAccess } from '../bitwarden-http'
import { VaultError } from '../vault-errors'
import { MAX_NAME_LENGTH, UUID_PATTERN } from './limits'
import { isRecord } from './parse-primitives'

export function parseStoredOrganization(value: unknown): OrganizationView {
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

export function parseStoredCollection(value: unknown): CollectionView {
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

export function emergencyAccessViewFromRemote(
  value: BitwardenEmergencyAccess
): EmergencyAccessView {
  return { ...value }
}
