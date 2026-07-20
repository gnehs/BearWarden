import type { VaultPasswordHistoryEntry } from '../../shared/vault-contract'
import { VaultError } from '../vault-errors'
import { MAX_PASSWORD_HISTORY, MAX_PASSWORD_LENGTH } from './limits'
import { isRecord } from './parse-primitives'

export function parsePasswordHistory(value: unknown): VaultPasswordHistoryEntry[] {
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

export function clonePasswordHistory(
  entries: readonly VaultPasswordHistoryEntry[]
): VaultPasswordHistoryEntry[] {
  return entries.map((entry) => ({ ...entry }))
}
