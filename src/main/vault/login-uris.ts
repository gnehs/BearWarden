import type {
  LoginCreateRequest,
  LoginUpdateRequest,
  VaultItemType,
  VaultLoginUri,
  VaultUriMatch
} from '../../shared/vault-contract'
import type { SyncLogin } from '../sync-merge'
import { VaultError } from '../vault-errors'
import { MAX_LOGIN_URIS, MAX_URI_LENGTH } from './limits'
import { isRecord, normalizeNullableString } from './parse-primitives'
import type { StoredLogin } from './types'

export function isVaultUriMatch(value: unknown): value is VaultUriMatch {
  return value === 0 || value === 1 || value === 2 || value === 3 || value === 4 || value === 5
}

export function parseStoredLoginUris(value: unknown): VaultLoginUri[] {
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

export function normalizeLoginUris(value: unknown): VaultLoginUri[] {
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

export function cloneLoginUris(uris: readonly VaultLoginUri[]): VaultLoginUri[] {
  return uris.map((entry) => ({ ...entry }))
}

export function uriAlias(uris: readonly VaultLoginUri[]): string | null {
  return uris[0]?.uri ?? null
}

export function createRequestUris(
  request: LoginCreateRequest,
  type: VaultItemType
): VaultLoginUri[] {
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

export function updateRequestUris(
  request: LoginUpdateRequest,
  existing: StoredLogin
): VaultLoginUri[] {
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

export function remoteLoginUris(source: SyncLogin): VaultLoginUri[] {
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

export function loginUriAt(login: StoredLogin, uriIndex: number | undefined): string {
  if (login.type !== 'login') throw new VaultError('INVALID_INPUT')
  const index = uriIndex ?? 0
  if (!Number.isSafeInteger(index) || index < 0 || index >= login.uris.length) {
    throw new VaultError('INVALID_INPUT')
  }
  const uri = login.uris[index]?.uri
  if (!uri) throw new VaultError('INVALID_INPUT')
  return uri
}
