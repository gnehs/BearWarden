import { createHash } from 'node:crypto'
import { parse as parseDomain } from 'tldts'
import type {
  EquivalentDomainSettingsUpdate,
  EquivalentDomainSettingsView
} from '../../shared/vault-contract'
import { BitwardenDirectError } from '../bitwarden-direct'
import type {
  BitwardenEquivalentDomainSettings,
  BitwardenEquivalentDomainUpdate
} from '../bitwarden-http'
import { VaultError } from '../vault-errors'
import {
  MAX_EQUIVALENT_DOMAIN_GROUPS,
  MAX_EQUIVALENT_DOMAIN_LENGTH,
  MAX_EQUIVALENT_DOMAIN_TOTAL,
  MAX_EQUIVALENT_DOMAINS_PER_GROUP
} from './limits'
import { isRecord } from './parse-primitives'

export function parseStoredEquivalentDomain(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value !== value.trim() ||
    /[\0\r\n,]/u.test(value) ||
    Buffer.byteLength(value, 'utf8') > MAX_EQUIVALENT_DOMAIN_LENGTH
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return value
}

export function parseStoredEquivalentDomainGroups(value: unknown): string[][] {
  if (!Array.isArray(value) || value.length > MAX_EQUIVALENT_DOMAIN_GROUPS) {
    throw new VaultError('CORRUPT_VAULT')
  }
  let total = 0
  return value.map((group) => {
    if (!Array.isArray(group) || group.length > MAX_EQUIVALENT_DOMAINS_PER_GROUP) {
      throw new VaultError('CORRUPT_VAULT')
    }
    total += group.length
    if (total > MAX_EQUIVALENT_DOMAIN_TOTAL) throw new VaultError('CORRUPT_VAULT')
    return group.map(parseStoredEquivalentDomain)
  })
}

export function parseStoredEquivalentDomainSettings(
  value: unknown
): BitwardenEquivalentDomainSettings {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  const equivalentDomains = parseStoredEquivalentDomainGroups(value.equivalentDomains)
  if (
    !Array.isArray(value.globalEquivalentDomains) ||
    value.globalEquivalentDomains.length > MAX_EQUIVALENT_DOMAIN_GROUPS
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  let total = equivalentDomains.reduce((count, group) => count + group.length, 0)
  const seenTypes = new Set<number>()
  const globalEquivalentDomains = value.globalEquivalentDomains.map((candidate) => {
    if (!isRecord(candidate)) throw new VaultError('CORRUPT_VAULT')
    const { type, domains, excluded } = candidate
    if (
      typeof type !== 'number' ||
      !Number.isInteger(type) ||
      type < 0 ||
      type > 2_147_483_647 ||
      seenTypes.has(type) ||
      !Array.isArray(domains) ||
      domains.length > MAX_EQUIVALENT_DOMAINS_PER_GROUP ||
      typeof excluded !== 'boolean'
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    seenTypes.add(type)
    total += domains.length
    if (total > MAX_EQUIVALENT_DOMAIN_TOTAL) throw new VaultError('CORRUPT_VAULT')
    return { type, domains: domains.map(parseStoredEquivalentDomain), excluded }
  })
  return { equivalentDomains, globalEquivalentDomains }
}

export function cloneEquivalentDomainSettings(
  settings: BitwardenEquivalentDomainSettings
): BitwardenEquivalentDomainSettings {
  return {
    equivalentDomains: settings.equivalentDomains.map((group) => [...group]),
    globalEquivalentDomains: settings.globalEquivalentDomains.map((group) => ({
      ...group,
      domains: [...group.domains]
    }))
  }
}

export function validateRemoteEquivalentDomainSettings(
  value: unknown
): BitwardenEquivalentDomainSettings {
  try {
    return parseStoredEquivalentDomainSettings(value)
  } catch {
    throw new BitwardenDirectError('INVALID_RESPONSE')
  }
}

export function equivalentDomainRevision(settings: BitwardenEquivalentDomainSettings): string {
  return createHash('sha256').update(JSON.stringify(settings)).digest('hex')
}

export function equivalentDomainSettingsView(
  settings: BitwardenEquivalentDomainSettings
): EquivalentDomainSettingsView {
  return {
    ...cloneEquivalentDomainSettings(settings),
    revision: equivalentDomainRevision(settings)
  }
}

export function normalizeEquivalentDomain(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_EQUIVALENT_DOMAIN_LENGTH ||
    /[\0\r\n,]/u.test(value)
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  const normalized = value.trim()
  if (
    normalized.length === 0 ||
    normalized.startsWith('data:') ||
    normalized.startsWith('about:')
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  let parsed: ReturnType<typeof parseDomain>
  try {
    parsed = parseDomain(normalized, { allowPrivateDomains: true, validHosts: ['localhost'] })
  } catch {
    throw new VaultError('INVALID_INPUT')
  }
  const domain = parsed.isIp || parsed.hostname === 'localhost' ? parsed.hostname : parsed.domain
  if (!domain || Buffer.byteLength(domain, 'utf8') > MAX_EQUIVALENT_DOMAIN_LENGTH) {
    throw new VaultError('INVALID_INPUT')
  }
  return domain.toLowerCase()
}

export function normalizeEquivalentDomainUpdate(
  request: EquivalentDomainSettingsUpdate
): BitwardenEquivalentDomainUpdate {
  if (
    !Array.isArray(request.equivalentDomains) ||
    request.equivalentDomains.length > MAX_EQUIVALENT_DOMAIN_GROUPS ||
    !Array.isArray(request.excludedGlobalEquivalentDomains) ||
    request.excludedGlobalEquivalentDomains.length > MAX_EQUIVALENT_DOMAIN_GROUPS
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  let total = 0
  const seenGroups = new Set<string>()
  const equivalentDomains: string[][] = []
  for (const candidate of request.equivalentDomains) {
    if (!Array.isArray(candidate) || candidate.length > MAX_EQUIVALENT_DOMAINS_PER_GROUP) {
      throw new VaultError('INVALID_INPUT')
    }
    const group = [...new Set(candidate.map(normalizeEquivalentDomain))]
    if (group.length === 0) continue
    total += group.length
    if (total > MAX_EQUIVALENT_DOMAIN_TOTAL) throw new VaultError('INVALID_INPUT')
    const signature = [...group].sort().join('\0')
    if (seenGroups.has(signature)) continue
    seenGroups.add(signature)
    equivalentDomains.push(group)
  }
  const seenTypes = new Set<number>()
  const excludedGlobalEquivalentDomains = request.excludedGlobalEquivalentDomains.map((type) => {
    if (
      typeof type !== 'number' ||
      !Number.isInteger(type) ||
      type < 0 ||
      type > 2_147_483_647 ||
      seenTypes.has(type)
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    seenTypes.add(type)
    return type
  })
  return { equivalentDomains, excludedGlobalEquivalentDomains }
}
