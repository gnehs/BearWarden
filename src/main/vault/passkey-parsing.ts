import { isIP } from 'node:net'
import { BitwardenDirectError } from '../bitwarden-direct'
import type { StoredPasskeyCredential } from '../passkey'
import { VaultError } from '../vault-errors'
import {
  BASE64URL_PATTERN,
  MAX_ITEM_FIELD_LENGTH,
  MAX_PASSKEY_CREDENTIAL_DESCRIPTORS,
  MAX_PASSKEY_CREDENTIAL_ID_BYTES,
  MAX_PASSKEY_RP_ID_LENGTH,
  PASSKEY_UUID_PATTERN
} from './limits'
import { assertIsoDate, isRecord } from './parse-primitives'
import type { PasskeyVaultMatch, VaultData } from './types'

export function normalizePasskeyRpId(value: unknown): string {
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

export function normalizePasskeyCredentialId(value: unknown): Buffer {
  if (
    !(value instanceof Uint8Array) ||
    value.byteLength === 0 ||
    value.byteLength > MAX_PASSKEY_CREDENTIAL_ID_BYTES
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return Buffer.from(value)
}

export function normalizePasskeyCredentialIds(value: unknown): Buffer[] {
  if (value === undefined) return []
  if (!Array.isArray(value) || value.length > MAX_PASSKEY_CREDENTIAL_DESCRIPTORS) {
    throw new VaultError('INVALID_INPUT')
  }
  return value.map(normalizePasskeyCredentialId)
}

export function decodeStoredPasskeyCredentialId(value: unknown): Buffer | null {
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

export function credentialIdIsAllowed(
  credentialId: Buffer,
  allowCredentialIds: readonly Buffer[]
): boolean {
  return allowCredentialIds.some((allowed) => allowed.equals(credentialId))
}

export function assertPasskeyApproval(
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

export function parseStoredPasskey(value: unknown): StoredPasskeyCredential {
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

export function validateRemotePasskeys(value: unknown): StoredPasskeyCredential[] {
  if (!Array.isArray(value) || value.length > 1_000) {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
  try {
    return value.map(parseStoredPasskey)
  } catch {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
}

export function findPasskeyVaultMatches(
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

export function assertUnambiguousPasskeyMatches(matches: readonly PasskeyVaultMatch[]): void {
  const seen = new Set<string>()
  for (const match of matches) {
    const encoded = match.credentialId.toString('base64url')
    if (seen.has(encoded)) throw new VaultError('INVALID_INPUT')
    seen.add(encoded)
  }
}

export function activeVaultContainsCredentialId(
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
