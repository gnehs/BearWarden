import type {
  LoginSummary,
  VaultHealthExposedReport,
  VaultHealthWeakFinding
} from '../../../shared/vault-contract'

const MAX_EXPOSED_FINDINGS = 50_000

type PlainRecord = Record<string, unknown>

export type ExposedPasswordCheckState =
  | { status: 'idle'; revision: string }
  | { status: 'loading'; revision: string; requestId: number }
  | { status: 'success'; revision: string; requestId: number; report: VaultHealthExposedReport }
  | { status: 'failed'; revision: string; requestId: number }

export function weakPasswordLabel(score: VaultHealthWeakFinding['score']): string {
  return score <= 1 ? '非常弱' : '弱'
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
  const keys = Object.keys(record)
  return keys.length === expected.length && keys.every((key) => expected.includes(key))
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
