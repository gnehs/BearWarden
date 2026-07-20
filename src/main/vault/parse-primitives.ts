import { VaultError } from '../vault-errors'
import {
  MAX_MASTER_PASSWORD_LENGTH,
  MAX_SYNC_SECRET_LENGTH,
  MIN_MASTER_PASSWORD_LENGTH,
  UUID_PATTERN
} from './limits'

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function assertIsoDate(value: unknown): asserts value is string {
  if (
    typeof value !== 'string' ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
}

export function assertUuid(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) {
    throw new VaultError('INVALID_INPUT')
  }
}

export function parseNullableString(value: unknown, maxLength: number): string | null {
  if (value === null) return null
  if (typeof value !== 'string' || value.length > maxLength) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return value
}

export function normalizeRequiredString(value: unknown, maxLength: number): string {
  if (typeof value !== 'string') throw new VaultError('INVALID_INPUT')
  const normalized = value.trim()
  if (normalized.length === 0 || normalized.length > maxLength) {
    throw new VaultError('INVALID_INPUT')
  }
  return normalized
}

export function normalizeString(value: unknown, maxLength: number): string {
  if (typeof value !== 'string' || value.length > maxLength) {
    throw new VaultError('INVALID_INPUT')
  }
  return value
}

export function normalizeSyncPassword(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_SYNC_SECRET_LENGTH) {
    throw new VaultError('INVALID_INPUT')
  }
  return value
}

export function normalizeNullableString(value: unknown, maxLength: number): string | null {
  if (value === null || value === undefined || value === '') return null
  if (typeof value !== 'string' || value.length > maxLength) {
    throw new VaultError('INVALID_INPUT')
  }
  return value
}

export function normalizeMasterPassword(value: unknown): string {
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
