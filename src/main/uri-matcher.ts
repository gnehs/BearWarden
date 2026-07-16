import { runInNewContext } from 'node:vm'
import { parse } from 'tldts'
import type { VaultLoginUri, VaultUriMatch } from '../shared/vault-contract'

export interface EquivalentDomainConfiguration {
  equivalentDomains: readonly (readonly string[])[]
  globalEquivalentDomains: readonly {
    domains: readonly string[]
    excluded: boolean
  }[]
}

const DOMAIN_MATCH_BLACKLIST = new Map<string, ReadonlySet<string>>([
  ['google.com', new Set(['script.google.com'])]
])
const REGEX_TIMEOUT_MS = 25
const DEFAULT_REGEX_BUDGET_MS = 100
const DEFAULT_REGEX_EVALUATIONS = 128

export interface UriMatchBudget {
  regexDeadline: number
  remainingRegexEvaluations: number
}

export function createUriMatchBudget(
  now: number = Date.now(),
  durationMs: number = DEFAULT_REGEX_BUDGET_MS,
  regexEvaluations: number = DEFAULT_REGEX_EVALUATIONS
): UriMatchBudget {
  return {
    regexDeadline: now + durationMs,
    remainingRegexEvaluations: regexEvaluations
  }
}

function domainFromUri(uri: string): string | null {
  if (!uri || uri.trim().length === 0 || uri.startsWith('data:') || uri.startsWith('about:')) {
    return null
  }
  try {
    const result = parse(uri.trim(), { allowPrivateDomains: true, validHosts: ['localhost'] })
    const domain = result.isIp || result.hostname === 'localhost' ? result.hostname : result.domain
    return domain?.toLocaleLowerCase('en-US') ?? null
  } catch {
    return null
  }
}

function hostFromUri(uri: string): string | null {
  const trimmed = uri.trim()
  if (!trimmed) return null
  const withProtocol = trimmed.includes('://')
    ? trimmed
    : trimmed.includes('.')
      ? `http://${trimmed}`
      : null
  if (!withProtocol) return null
  try {
    const host = new URL(withProtocol).host
    return host || null
  } catch {
    return null
  }
}

function canonicalConfiguredDomain(value: string): string | null {
  return domainFromUri(value)
}

export function equivalentDomainsForTarget(
  targetUri: string,
  settings: EquivalentDomainConfiguration | null
): ReadonlySet<string> {
  const targetDomain = domainFromUri(targetUri)
  if (!targetDomain) return new Set()
  const matches = new Set<string>([targetDomain])
  if (!settings) return matches
  const groups = [
    ...settings.equivalentDomains,
    ...settings.globalEquivalentDomains
      .filter(({ excluded }) => !excluded)
      .map(({ domains }) => domains)
  ]
  for (const group of groups) {
    const canonical = group.flatMap((domain) => {
      const parsed = canonicalConfiguredDomain(domain)
      return parsed ? [parsed] : []
    })
    if (canonical.includes(targetDomain)) canonical.forEach((domain) => matches.add(domain))
  }
  return matches
}

function boundedRegexMatches(pattern: string, targetUri: string, budget?: UriMatchBudget): boolean {
  try {
    if (budget) {
      if (budget.remainingRegexEvaluations <= 0) return false
      budget.remainingRegexEvaluations -= 1
    }
    const remainingMs = budget ? budget.regexDeadline - Date.now() : REGEX_TIMEOUT_MS
    if (remainingMs <= 0) return false
    const regex = new RegExp(pattern, 'i')
    return (
      runInNewContext(
        'regex.test(targetUri)',
        { regex, targetUri },
        { timeout: Math.max(1, Math.min(REGEX_TIMEOUT_MS, Math.ceil(remainingMs))) }
      ) === true
    )
  } catch {
    return false
  }
}

export function loginUriMatches(
  loginUri: VaultLoginUri,
  targetUri: string,
  settings: EquivalentDomainConfiguration | null,
  defaultMatch: VaultUriMatch = 0,
  budget?: UriMatchBudget
): boolean {
  if (!loginUri.uri || !targetUri) return false
  const strategy = loginUri.match ?? defaultMatch
  switch (strategy) {
    case 0: {
      const loginDomain = domainFromUri(loginUri.uri)
      if (!loginDomain || !equivalentDomainsForTarget(targetUri, settings).has(loginDomain)) {
        return false
      }
      const blockedHosts = DOMAIN_MATCH_BLACKLIST.get(loginDomain)
      return !blockedHosts?.has(hostFromUri(targetUri) ?? '')
    }
    case 1: {
      const targetHost = hostFromUri(targetUri)
      return targetHost !== null && targetHost === hostFromUri(loginUri.uri)
    }
    case 2:
      return targetUri.startsWith(loginUri.uri)
    case 3:
      return targetUri === loginUri.uri
    case 4:
      return boundedRegexMatches(loginUri.uri, targetUri, budget)
    case 5:
      return false
  }
}

export function loginUrisMatch(
  loginUris: readonly VaultLoginUri[],
  targetUri: string,
  settings: EquivalentDomainConfiguration | null,
  defaultMatch: VaultUriMatch = 0,
  budget?: UriMatchBudget
): boolean {
  return loginUris.some((loginUri) =>
    loginUriMatches(loginUri, targetUri, settings, defaultMatch, budget)
  )
}
