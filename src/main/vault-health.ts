import zxcvbn from 'zxcvbn'

const MAX_HEALTH_ITEMS = 50_000
const MAX_ID_LENGTH = 256
const MAX_NAME_LENGTH = 5_000
const MAX_PASSWORD_LENGTH = 16_384
const MAX_USERNAME_LENGTH = 512
const MAX_TOTAL_INPUT_CHARACTERS = 32 * 1_024 * 1_024
// The upstream zxcvbn guidance recommends ~100 characters to bound synchronous latency.
// Reuse detection below still compares each complete, bounded password exactly.
const MAX_ZXCVBN_PASSWORD_LENGTH = 100

const BRAND_USER_INPUTS = ['bearwarden', 'bear', 'warden'] as const

type HealthRecord = Record<string, unknown>

export interface VaultHealthItemBase {
  readonly id: string
  readonly type: string
  readonly name: string
  /** Optional because the service can prefilter active items before adapting them. */
  readonly deletedAt?: string | null
  /** Optional because the service can prefilter active items before adapting them. */
  readonly archivedAt?: string | null
}

/** Protected items deliberately omit secret-bearing fields from this analysis boundary. */
export interface VaultHealthProtectedItem extends VaultHealthItemBase {
  readonly reprompt: 1
}

export interface VaultHealthUnprotectedItem extends VaultHealthItemBase {
  readonly reprompt: 0
  readonly password: string
  readonly username?: string
}

export type VaultHealthItem = VaultHealthProtectedItem | VaultHealthUnprotectedItem

export interface WeakPasswordFinding {
  readonly id: string
  readonly name: string
  readonly score: 0 | 1 | 2
}

export interface ReusedPasswordFinding {
  readonly id: string
  readonly name: string
  readonly reuseCount: number
}

export interface VaultHealthAnalysis {
  readonly analyzedCount: number
  readonly protectedSkippedCount: number
  readonly weakPasswordCount: number
  readonly reusedPasswordCount: number
  readonly weakPasswords: readonly WeakPasswordFinding[]
  readonly reusedPasswords: readonly ReusedPasswordFinding[]
}

interface Candidate {
  readonly id: string
  readonly name: string
  readonly password: string
  readonly username: string
  readonly originalIndex: number
}

interface InputBudget {
  remaining: number
}

class HealthBoundsError extends Error {}

function emptyAnalysis(): VaultHealthAnalysis {
  return {
    analyzedCount: 0,
    protectedSkippedCount: 0,
    weakPasswordCount: 0,
    reusedPasswordCount: 0,
    weakPasswords: [],
    reusedPasswords: []
  }
}

function isPlainRecord(value: unknown): value is HealthRecord {
  if (value === null || typeof value !== 'object') return false

  try {
    const prototype = Object.getPrototypeOf(value)
    return prototype === Object.prototype || prototype === null
  } catch {
    return false
  }
}

function ownData(record: HealthRecord, key: string): unknown {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(record, key)
    return descriptor && 'value' in descriptor ? descriptor.value : undefined
  } catch {
    return undefined
  }
}

function isActiveOptionalDate(record: HealthRecord, key: string): boolean {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(record, key)
    if (!descriptor) return true
    if (!('value' in descriptor)) return false
    return descriptor.value === null
  } catch {
    return false
  }
}

function boundedString(
  record: HealthRecord,
  key: string,
  maximumLength: number,
  budget: InputBudget
): string | undefined {
  const value = ownData(record, key)
  if (typeof value !== 'string' || value.length > maximumLength) return undefined

  budget.remaining -= value.length
  if (budget.remaining < 0) throw new HealthBoundsError()
  return value
}

function inputAt(items: readonly unknown[], index: number): unknown {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(items, String(index))
    return descriptor && 'value' in descriptor ? descriptor.value : undefined
  } catch {
    throw new HealthBoundsError()
  }
}

function usernameInputs(username: string): string[] {
  const atPosition = username.indexOf('@')
  const value = atPosition >= 0 ? username.slice(0, atPosition) : username
  return value
    .trim()
    .toLowerCase()
    .split(/[^A-Za-z0-9]/u)
    .filter((token) => token.length >= 3)
}

function normalizedName(name: string): string {
  return name
    .normalize('NFD')
    .replace(/\p{M}+/gu, '')
    .toLocaleLowerCase('und')
}

function compareNames(
  first: { readonly name: string; readonly originalIndex: number },
  second: { readonly name: string; readonly originalIndex: number }
): number {
  const firstName = normalizedName(first.name)
  const secondName = normalizedName(second.name)
  if (firstName < secondName) return -1
  if (firstName > secondName) return 1
  return first.originalIndex - second.originalIndex
}

function parseCandidates(items: readonly unknown[]): {
  candidates: Candidate[]
  protectedSkippedCount: number
} {
  const candidates: Candidate[] = []
  const budget: InputBudget = { remaining: MAX_TOTAL_INPUT_CHARACTERS }
  let protectedSkippedCount = 0

  for (let index = 0; index < items.length; index += 1) {
    const value = inputAt(items, index)
    if (!isPlainRecord(value)) continue
    if (ownData(value, 'type') !== 'login') continue
    if (!isActiveOptionalDate(value, 'deletedAt') || !isActiveOptionalDate(value, 'archivedAt')) {
      continue
    }

    const reprompt = ownData(value, 'reprompt')
    if (reprompt !== 0 && reprompt !== 1) continue

    if (reprompt === 1) {
      protectedSkippedCount += 1
      continue
    }

    const password = boundedString(value, 'password', MAX_PASSWORD_LENGTH, budget)
    if (!password) continue

    const id = boundedString(value, 'id', MAX_ID_LENGTH, budget)
    const name = boundedString(value, 'name', MAX_NAME_LENGTH, budget)
    const usernameValue = ownData(value, 'username')
    const username =
      usernameValue === undefined
        ? ''
        : boundedString(value, 'username', MAX_USERNAME_LENGTH, budget)
    if (!id || name === undefined || username === undefined) continue

    candidates.push({ id, name, password, username, originalIndex: index })
  }

  return { candidates, protectedSkippedCount }
}

/**
 * Analyzes decrypted login secrets exclusively inside the main process.
 *
 * Passwords and usernames are used only as transient comparison inputs. The
 * returned object contains safe item metadata and aggregate counts, never a
 * password, hash, username, URI, or timestamp.
 */
export function analyzeVaultHealth(items: readonly VaultHealthItem[]): VaultHealthAnalysis {
  if (!Array.isArray(items) || items.length > MAX_HEALTH_ITEMS) return emptyAnalysis()

  let parsed: ReturnType<typeof parseCandidates>
  try {
    parsed = parseCandidates(items)
  } catch {
    return emptyAnalysis()
  }

  const passwordUseCounts = new Map<string, number>()
  for (const candidate of parsed.candidates) {
    passwordUseCounts.set(candidate.password, (passwordUseCounts.get(candidate.password) ?? 0) + 1)
  }

  const weakWithOrder: (WeakPasswordFinding & { readonly originalIndex: number })[] = []
  const reusedWithOrder: (ReusedPasswordFinding & { readonly originalIndex: number })[] = []

  for (const candidate of parsed.candidates) {
    const userInputs = Array.from(
      new Set([...BRAND_USER_INPUTS, ...usernameInputs(candidate.username)])
    )
    const score = zxcvbn(candidate.password.slice(0, MAX_ZXCVBN_PASSWORD_LENGTH), userInputs).score
    if (score === 0 || score === 1 || score === 2) {
      weakWithOrder.push({
        id: candidate.id,
        name: candidate.name,
        score,
        originalIndex: candidate.originalIndex
      })
    }

    const reuseCount = passwordUseCounts.get(candidate.password) ?? 0
    if (reuseCount >= 2) {
      reusedWithOrder.push({
        id: candidate.id,
        name: candidate.name,
        reuseCount,
        originalIndex: candidate.originalIndex
      })
    }
  }

  weakWithOrder.sort((first, second) => first.score - second.score || compareNames(first, second))
  reusedWithOrder.sort(compareNames)

  const weakPasswords: WeakPasswordFinding[] = weakWithOrder.map(({ id, name, score }) => ({
    id,
    name,
    score
  }))
  const reusedPasswords: ReusedPasswordFinding[] = reusedWithOrder.map(
    ({ id, name, reuseCount }) => ({ id, name, reuseCount })
  )

  return {
    analyzedCount: parsed.candidates.length,
    protectedSkippedCount: parsed.protectedSkippedCount,
    weakPasswordCount: weakPasswords.length,
    reusedPasswordCount: reusedPasswords.length,
    weakPasswords,
    reusedPasswords
  }
}
