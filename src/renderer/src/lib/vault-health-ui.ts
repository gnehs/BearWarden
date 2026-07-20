import { msg } from '@lingui/core/macro'
import type {
  LoginSummary,
  VaultHealthAccountBreachReport,
  VaultHealthExposedReport,
  VaultHealthWeakFinding
} from '../../../shared/vault-contract'
import { i18n } from '../i18n'

const MAX_EXPOSED_FINDINGS = 50_000
const MAX_ACCOUNT_BREACH_FINDINGS = 10_000
const MAX_ACCOUNT_BREACH_TEXT_LENGTH = 5_000
const MAX_ACCOUNT_BREACH_DATA_CLASSES = 100

type PlainRecord = Record<string, unknown>

export type ExposedPasswordCheckState =
  | { status: 'idle'; revision: string }
  | { status: 'loading'; revision: string; requestId: number }
  | { status: 'success'; revision: string; requestId: number; report: VaultHealthExposedReport }
  | { status: 'failed'; revision: string; requestId: number }

export type AccountBreachCheckState =
  | { status: 'idle'; revision: string }
  | { status: 'loading'; revision: string; requestId: number; email: string }
  | {
      status: 'success'
      revision: string
      requestId: number
      email: string
      report: Extract<VaultHealthAccountBreachReport, { status: 'complete' }>
    }
  | {
      status: 'unavailable'
      revision: string
      requestId: number
      email: string
      report: Extract<VaultHealthAccountBreachReport, { status: 'unavailable' }>
    }
  | { status: 'failed'; revision: string; requestId: number; email: string }

export function weakPasswordLabel(score: VaultHealthWeakFinding['score']): string {
  return score <= 1 ? i18n._(msg`Very weak`) : i18n._(msg`Weak`)
}

export function vaultHealthRevision(items: readonly LoginSummary[]): string {
  return items
    .map((item) =>
      [
        item.id,
        item.type,
        item.updatedAt,
        item.deletedAt ?? '',
        item.archivedAt ?? '',
        String(item.reprompt)
      ].join('\0')
    )
    .sort()
    .join('\n')
}

function isPlainRecord(value: unknown): value is PlainRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  try {
    const prototype = Object.getPrototypeOf(value)
    return prototype === Object.prototype || prototype === null
  } catch {
    return false
  }
}

function hasExactKeys(record: PlainRecord, expected: readonly string[]): boolean {
  try {
    const keys = Object.keys(record)
    return keys.length === expected.length && keys.every((key) => expected.includes(key))
  } catch {
    return false
  }
}

function isSafeCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0
}

export function isVaultHealthExposedReport(value: unknown): value is VaultHealthExposedReport {
  if (
    !isPlainRecord(value) ||
    !hasExactKeys(value, ['generatedAt', 'totals', 'exposedPasswords']) ||
    typeof value.generatedAt !== 'string' ||
    !Number.isFinite(Date.parse(value.generatedAt)) ||
    !isPlainRecord(value.totals) ||
    !hasExactKeys(value.totals, [
      'analyzedCount',
      'exposedPasswordCount',
      'protectedSkippedCount'
    ]) ||
    !isSafeCount(value.totals.analyzedCount) ||
    !isSafeCount(value.totals.exposedPasswordCount) ||
    !isSafeCount(value.totals.protectedSkippedCount) ||
    !Array.isArray(value.exposedPasswords) ||
    value.exposedPasswords.length > MAX_EXPOSED_FINDINGS ||
    value.totals.exposedPasswordCount !== value.exposedPasswords.length ||
    value.totals.exposedPasswordCount > value.totals.analyzedCount
  ) {
    return false
  }

  return value.exposedPasswords.every(
    (finding) =>
      isPlainRecord(finding) &&
      hasExactKeys(finding, ['id', 'name', 'subtitle', 'exposedCount']) &&
      typeof finding.id === 'string' &&
      finding.id.length > 0 &&
      finding.id.length <= 256 &&
      typeof finding.name === 'string' &&
      finding.name.length <= 5_000 &&
      typeof finding.subtitle === 'string' &&
      finding.subtitle.length <= 5_000 &&
      isSafeCount(finding.exposedCount) &&
      finding.exposedCount > 0
  )
}

function isValidIsoDate(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 64 &&
    Number.isFinite(Date.parse(value))
  )
}

function isValidBreachDate(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false
  const date = new Date(`${value}T00:00:00.000Z`)
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value
}

function isVaultHealthAccountBreachFinding(value: unknown): boolean {
  if (
    !isPlainRecord(value) ||
    !hasExactKeys(value, [
      'name',
      'title',
      'domain',
      'breachDate',
      'addedDate',
      'pwnCount',
      'dataClasses',
      'isVerified'
    ]) ||
    typeof value.name !== 'string' ||
    value.name.length === 0 ||
    value.name.length > MAX_ACCOUNT_BREACH_TEXT_LENGTH ||
    typeof value.title !== 'string' ||
    value.title.length === 0 ||
    value.title.length > MAX_ACCOUNT_BREACH_TEXT_LENGTH ||
    typeof value.domain !== 'string' ||
    value.domain.length > MAX_ACCOUNT_BREACH_TEXT_LENGTH ||
    !isValidBreachDate(value.breachDate) ||
    !isValidIsoDate(value.addedDate) ||
    !isSafeCount(value.pwnCount) ||
    !Array.isArray(value.dataClasses) ||
    value.dataClasses.length > MAX_ACCOUNT_BREACH_DATA_CLASSES ||
    !value.dataClasses.every(
      (dataClass) =>
        typeof dataClass === 'string' &&
        dataClass.length > 0 &&
        dataClass.length <= MAX_ACCOUNT_BREACH_TEXT_LENGTH
    ) ||
    typeof value.isVerified !== 'boolean'
  ) {
    return false
  }

  return true
}

/**
 * Defends the renderer trust boundary. The HIBP description and logo are intentionally absent
 * from the shared contract, so a response that includes either is rejected rather than rendered.
 */
export function isVaultHealthAccountBreachReport(
  value: unknown
): value is VaultHealthAccountBreachReport {
  if (
    !isPlainRecord(value) ||
    !isValidIsoDate(value.generatedAt) ||
    typeof value.status !== 'string'
  ) {
    return false
  }

  if (value.status === 'complete') {
    return (
      hasExactKeys(value, ['generatedAt', 'status', 'breaches']) &&
      Array.isArray(value.breaches) &&
      value.breaches.length <= MAX_ACCOUNT_BREACH_FINDINGS &&
      value.breaches.every(isVaultHealthAccountBreachFinding)
    )
  }

  return (
    value.status === 'unavailable' &&
    hasExactKeys(value, ['generatedAt', 'status', 'reason', 'breaches']) &&
    value.reason === 'server-hibp-unconfigured' &&
    Array.isArray(value.breaches) &&
    value.breaches.length === 0
  )
}

export function createExposedPasswordIdleState(revision: string): ExposedPasswordCheckState {
  return { status: 'idle', revision }
}

export function beginExposedPasswordCheck(
  revision: string,
  requestId: number
): ExposedPasswordCheckState {
  return { status: 'loading', revision, requestId }
}

function isCurrentExposedPasswordRequest(
  state: ExposedPasswordCheckState,
  revision: string,
  requestId: number
): boolean {
  return state.status === 'loading' && state.revision === revision && state.requestId === requestId
}

export function resolveExposedPasswordCheck(
  state: ExposedPasswordCheckState,
  revision: string,
  requestId: number,
  report: unknown
): ExposedPasswordCheckState {
  if (!isCurrentExposedPasswordRequest(state, revision, requestId)) return state
  if (!isVaultHealthExposedReport(report)) return { status: 'failed', revision, requestId }
  return { status: 'success', revision, requestId, report }
}

export function failExposedPasswordCheck(
  state: ExposedPasswordCheckState,
  revision: string,
  requestId: number
): ExposedPasswordCheckState {
  return isCurrentExposedPasswordRequest(state, revision, requestId)
    ? { status: 'failed', revision, requestId }
    : state
}

export function cancelExposedPasswordCheck(revision: string): ExposedPasswordCheckState {
  return createExposedPasswordIdleState(revision)
}

export function invalidateExposedPasswordCheck(
  state: ExposedPasswordCheckState,
  revision: string
): ExposedPasswordCheckState {
  return state.revision === revision ? state : createExposedPasswordIdleState(revision)
}

export function createAccountBreachIdleState(revision: string): AccountBreachCheckState {
  return { status: 'idle', revision }
}

export function beginAccountBreachCheck(
  revision: string,
  requestId: number,
  email: string
): AccountBreachCheckState {
  return { status: 'loading', revision, requestId, email }
}

function isCurrentAccountBreachRequest(
  state: AccountBreachCheckState,
  revision: string,
  requestId: number
): state is Extract<AccountBreachCheckState, { status: 'loading' }> {
  return state.status === 'loading' && state.revision === revision && state.requestId === requestId
}

export function resolveAccountBreachCheck(
  state: AccountBreachCheckState,
  revision: string,
  requestId: number,
  report: unknown
): AccountBreachCheckState {
  if (!isCurrentAccountBreachRequest(state, revision, requestId)) return state
  if (!isVaultHealthAccountBreachReport(report)) {
    return { status: 'failed', revision, requestId, email: state.email }
  }
  return report.status === 'complete'
    ? { status: 'success', revision, requestId, email: state.email, report }
    : { status: 'unavailable', revision, requestId, email: state.email, report }
}

export function failAccountBreachCheck(
  state: AccountBreachCheckState,
  revision: string,
  requestId: number
): AccountBreachCheckState {
  return isCurrentAccountBreachRequest(state, revision, requestId)
    ? { status: 'failed', revision, requestId, email: state.email }
    : state
}

export function cancelAccountBreachCheck(revision: string): AccountBreachCheckState {
  return createAccountBreachIdleState(revision)
}

export function invalidateAccountBreachCheck(
  state: AccountBreachCheckState,
  revision: string
): AccountBreachCheckState {
  return state.revision === revision ? state : createAccountBreachIdleState(revision)
}
