import { msg } from '@lingui/core/macro'
import type {
  EquivalentDomainSettingsView,
  GlobalEquivalentDomainView
} from '../../../shared/vault-contract'
import { i18n } from '../i18n'

const MAX_GROUPS = 10_000
const MAX_DOMAINS_PER_GROUP = 1_000
const MAX_TOTAL_DOMAINS = 100_000
const MAX_DOMAIN_LENGTH = 1_024

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  try {
    const prototype = Object.getPrototypeOf(value)
    return prototype === Object.prototype || prototype === null
  } catch {
    return false
  }
}

function isDomain(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= MAX_DOMAIN_LENGTH &&
    value === value.trim() &&
    !/[\0\r\n,]/u.test(value)
  )
}

function isDomainGroup(value: unknown): value is string[] {
  return Array.isArray(value) && value.length <= MAX_DOMAINS_PER_GROUP && value.every(isDomain)
}

function isGlobalDomainGroup(value: unknown): value is GlobalEquivalentDomainView {
  if (!isPlainRecord(value)) return false
  return (
    typeof value.type === 'number' &&
    Number.isInteger(value.type) &&
    value.type >= 0 &&
    value.type <= 2_147_483_647 &&
    isDomainGroup(value.domains) &&
    typeof value.excluded === 'boolean'
  )
}

export function isEquivalentDomainSettingsView(
  value: unknown
): value is EquivalentDomainSettingsView {
  if (!isPlainRecord(value)) return false
  try {
    const keys = Object.keys(value)
    if (
      keys.length !== 3 ||
      !keys.includes('equivalentDomains') ||
      !keys.includes('globalEquivalentDomains') ||
      !keys.includes('revision') ||
      !Array.isArray(value.equivalentDomains) ||
      value.equivalentDomains.length > MAX_GROUPS ||
      !Array.isArray(value.globalEquivalentDomains) ||
      value.globalEquivalentDomains.length > MAX_GROUPS ||
      typeof value.revision !== 'string' ||
      !/^[0-9a-f]{64}$/u.test(value.revision) ||
      !value.equivalentDomains.every(isDomainGroup) ||
      !value.globalEquivalentDomains.every(isGlobalDomainGroup)
    ) {
      return false
    }
    const types = value.globalEquivalentDomains.map(({ type }) => type)
    const total =
      value.equivalentDomains.reduce((count, group) => count + group.length, 0) +
      value.globalEquivalentDomains.reduce((count, group) => count + group.domains.length, 0)
    return new Set(types).size === types.length && total <= MAX_TOTAL_DOMAINS
  } catch {
    return false
  }
}

export interface ParsedEquivalentDomainDraft {
  groups: string[][]
  singleDomainGroupCount: number
}

export function parseEquivalentDomainDraft(rows: readonly string[]): ParsedEquivalentDomainDraft {
  if (rows.length > MAX_GROUPS) throw new Error('INVALID_INPUT')
  const groups: string[][] = []
  let total = 0
  for (const row of rows) {
    if (typeof row !== 'string' || row.length > MAX_DOMAIN_LENGTH * MAX_DOMAINS_PER_GROUP) {
      throw new Error('INVALID_INPUT')
    }
    const domains = [
      ...new Set(
        row
          .split(/[\n,]/u)
          .map((domain) => domain.trim())
          .filter(Boolean)
      )
    ]
    if (domains.length === 0) continue
    if (
      domains.length > MAX_DOMAINS_PER_GROUP ||
      domains.some((domain) => domain.length > MAX_DOMAIN_LENGTH || /[\0\r]/u.test(domain))
    ) {
      throw new Error('INVALID_INPUT')
    }
    total += domains.length
    if (total > MAX_TOTAL_DOMAINS) throw new Error('INVALID_INPUT')
    groups.push(domains)
  }
  return {
    groups,
    singleDomainGroupCount: groups.filter((group) => group.length === 1).length
  }
}

export function equivalentDomainRows(settings: EquivalentDomainSettingsView): string[] {
  return settings.equivalentDomains.map((group) => group.join(', '))
}

export function equivalentDomainErrorMessage(error: unknown): string {
  if (!(error instanceof Error)) {
    return i18n._(msg`Unable to read equivalent domain settings. Please try again later.`)
  }
  if (error.message.includes('SYNC_CONFLICT')) {
    return i18n._(
      msg`Settings were changed on another device. The server version has been reloaded; review it before saving.`
    )
  }
  if (error.message.includes('SYNC_AUTH_REQUIRED')) {
    return i18n._(msg`Your Bitwarden account needs to be signed in or unlocked again.`)
  }
  if (error.message.includes('LOCKED')) {
    return i18n._(msg`The vault is locked. Unlock it and try again.`)
  }
  if (error.message.includes('INVALID_INPUT')) {
    return i18n._(msg`Check the domain format; separate domains with commas or new lines.`)
  }
  return i18n._(
    msg`Unable to save equivalent domain settings. Check your connection and try again.`
  )
}
