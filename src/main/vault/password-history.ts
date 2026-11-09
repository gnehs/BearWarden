import type { VaultCustomField, VaultPasswordHistoryEntry } from '../../shared/vault-contract'
import { VaultError } from '../vault-errors'
import { MAX_PASSWORD_HISTORY, MAX_PASSWORD_LENGTH } from './limits'
import { isRecord } from '../validation-primitives'

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

/**
 * Returns the history after an edit, newest first: every non-empty hidden custom field whose name
 * and value did not survive the edit, then the retired login password, ahead of the previous
 * entries. This is the official clients' order. `lastUsedDate` is read once, and only when an
 * entry is added.
 */
export function passwordHistoryAfterEdit(edit: {
  readonly previousHistory: readonly VaultPasswordHistoryEntry[]
  readonly retiredPassword: string | null
  readonly previousCustomFields: readonly VaultCustomField[]
  readonly nextCustomFields: readonly VaultCustomField[]
  readonly lastUsedDate: () => string
}): VaultPasswordHistoryEntry[] {
  const retired: string[] = []
  if (edit.retiredPassword) retired.unshift(edit.retiredPassword)
  const consumedNextHiddenFields = new Set<number>()
  for (const field of edit.previousCustomFields) {
    if (field.type !== 'hidden' || field.name.length === 0 || field.value.length === 0) continue
    const unchangedIndex = edit.nextCustomFields.findIndex(
      (candidate, index) =>
        !consumedNextHiddenFields.has(index) &&
        candidate.type === 'hidden' &&
        candidate.name === field.name &&
        candidate.value === field.value
    )
    if (unchangedIndex >= 0) consumedNextHiddenFields.add(unchangedIndex)
    else retired.unshift(`${field.name}: ${field.value}`)
  }
  const previous = clonePasswordHistory(edit.previousHistory)
  if (retired.length === 0) return previous
  const lastUsedDate = edit.lastUsedDate()
  return [...retired.map((password) => ({ password, lastUsedDate })), ...previous].slice(
    0,
    MAX_PASSWORD_HISTORY
  )
}
