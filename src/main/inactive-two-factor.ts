import { domainToASCII } from 'node:url'
import { parse as parseDomain } from 'tldts'

export const TWO_FACTOR_DIRECTORY_API_VERSION = 4 as const
export const TWO_FACTOR_DIRECTORY_TOTP_URL = 'https://api.2fa.directory/v4/totp.json' as const

const MAX_DATASET_BYTES = 4 * 1024 * 1024
const MAX_DATASET_ENTRIES = 10_000
const MAX_DATASET_CHARACTERS = 16 * 1024 * 1024
const MAX_DOMAIN_LENGTH = 253
const MAX_METHODS = 16
const MAX_METHOD_LENGTH = 64
const MAX_URL_LENGTH = 4_096
const MAX_NOTES_LENGTH = 32_768
const MAX_CUSTOM_METHODS = 64
const MAX_CUSTOM_METHOD_LENGTH = 256
const MAX_ITEMS = 50_000
const MAX_ID_LENGTH = 256
const MAX_NAME_LENGTH = 5_000
const MAX_URIS_PER_ITEM = 1_000
const MAX_URI_LENGTH = 4_096
const MAX_ITEM_CHARACTERS = 32 * 1024 * 1024

const ENTRY_KEYS = new Set([
  'methods',
  'documentation',
  'recovery',
  'notes',
  'custom-hardware',
  'custom-software'
])

const METHODS = new Set([
  'sms',
  'call',
  'email',
  'totp',
  'u2f',
  'custom-hardware',
  'custom-software'
])

type PlainRecord = Record<string, unknown>

export type InactiveTwoFactorErrorCode =
  'UNSUPPORTED_DATASET_VERSION' | 'DATASET_TOO_LARGE' | 'INVALID_DATASET' | 'INVALID_INPUT'

export class InactiveTwoFactorError extends Error {
  constructor(readonly code: InactiveTwoFactorErrorCode) {
    super(code)
    this.name = 'InactiveTwoFactorError'
  }
}

export interface TwoFactorDirectoryEntry {
  readonly domain: string
  readonly documentationUrl: string | null
}

export interface TwoFactorDirectoryDataset {
  readonly apiVersion: typeof TWO_FACTOR_DIRECTORY_API_VERSION
  readonly entries: readonly TwoFactorDirectoryEntry[]
}

/** A deliberately narrow adapter boundary. The caller must provide lifecycle and TOTP flags. */
export interface InactiveTwoFactorInput {
  readonly id: string
  readonly name: string
  readonly hasTotp: boolean
  readonly isDeleted: boolean
  readonly isArchived: boolean
  readonly uris: readonly string[]
}

export interface InactiveTwoFactorFinding {
  readonly id: string
  readonly name: string
  /** A public 2fa.directory service domain, never the original vault URI or hostname. */
  readonly matchedDomain: string
  readonly documentationUrl: string | null
}

export interface InactiveTwoFactorReport {
  readonly analyzedCount: number
  readonly excludedTotpCount: number
  readonly excludedDeletedCount: number
  readonly excludedArchivedCount: number
  readonly findings: readonly InactiveTwoFactorFinding[]
}

interface CharacterBudget {
  remaining: number
}

function fail(code: InactiveTwoFactorErrorCode): never {
  throw new InactiveTwoFactorError(code)
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

function ownData(
  record: PlainRecord,
  key: string,
  code: InactiveTwoFactorErrorCode = 'INVALID_DATASET'
): unknown {
  let descriptor: PropertyDescriptor | undefined
  try {
    descriptor = Object.getOwnPropertyDescriptor(record, key)
  } catch {
    fail(code)
  }
  if (!descriptor || !('value' in descriptor) || descriptor.get || descriptor.set) {
    fail(code)
  }
  return descriptor.value
}

function optionalOwnData(record: PlainRecord, key: string): unknown {
  let descriptor: PropertyDescriptor | undefined
  try {
    descriptor = Object.getOwnPropertyDescriptor(record, key)
  } catch {
    fail('INVALID_DATASET')
  }
  if (!descriptor) return undefined
  if (!('value' in descriptor) || descriptor.get || descriptor.set) fail('INVALID_DATASET')
  return descriptor.value
}

function ownKeys(record: PlainRecord, code: InactiveTwoFactorErrorCode): string[] {
  try {
    const keys = Reflect.ownKeys(record)
    if (keys.some((key) => typeof key !== 'string')) fail(code)
    return keys as string[]
  } catch (error) {
    if (error instanceof InactiveTwoFactorError) throw error
    fail(code)
  }
}

function strictArray(value: unknown, maximum: number, code: InactiveTwoFactorErrorCode): unknown[] {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) fail(code)
    if (value.length > maximum) fail(code)
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const elementKeys = Reflect.ownKeys(descriptors).filter((key) => key !== 'length')
    if (elementKeys.length !== value.length) fail(code)
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)]
      if (!descriptor || !('value' in descriptor) || descriptor.get || descriptor.set) fail(code)
    }
    return value
  } catch (error) {
    if (error instanceof InactiveTwoFactorError) throw error
    fail(code)
  }
}

function consumeString(
  value: unknown,
  maximum: number,
  budget: CharacterBudget,
  code: InactiveTwoFactorErrorCode,
  allowEmpty = false
): string {
  if (typeof value !== 'string' || value.length > maximum || (!allowEmpty && value.length === 0)) {
    fail(code)
  }
  budget.remaining -= value.length
  if (budget.remaining < 0) fail(code === 'INVALID_DATASET' ? 'DATASET_TOO_LARGE' : code)
  return value
}

function canonicalHostname(value: string): string | null {
  if (value.length === 0 || value.length > MAX_DOMAIN_LENGTH || value.trim() !== value) return null
  const withoutDot = value.endsWith('.') ? value.slice(0, -1) : value
  const ascii = domainToASCII(withoutDot).toLowerCase()
  if (!ascii || ascii.length > MAX_DOMAIN_LENGTH || ascii.includes('..')) return null
  const labels = ascii.split('.')
  if (
    labels.length < 2 ||
    labels.some(
      (label) =>
        label.length === 0 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label)
    )
  ) {
    return null
  }
  const parsed = parseDomain(ascii, { allowPrivateDomains: true })
  // A few official entries (for example pythonanywhere.com) are themselves private suffixes.
  // They are safe as exact hosts, but matchDatasetDomain prevents them from covering tenants.
  if (parsed.isIp || (!parsed.domain && !parsed.isPrivate)) return null
  return ascii
}

function datasetUrl(value: unknown, budget: CharacterBudget, exposeHttps: boolean): string | null {
  if (value === undefined) return null
  const raw = consumeString(value, MAX_URL_LENGTH, budget, 'INVALID_DATASET')
  try {
    const url = new URL(raw)
    if (
      (url.protocol !== 'https:' && url.protocol !== 'http:') ||
      url.username !== '' ||
      url.password !== '' ||
      !canonicalHostname(url.hostname)
    ) {
      fail('INVALID_DATASET')
    }
    return exposeHttps && url.protocol === 'https:' ? url.toString() : null
  } catch {
    fail('INVALID_DATASET')
  }
}

function parseStringArray(
  value: unknown,
  maximumItems: number,
  maximumLength: number,
  budget: CharacterBudget
): string[] {
  const array = strictArray(value, maximumItems, 'INVALID_DATASET')
  const result: string[] = []
  const seen = new Set<string>()
  for (const entry of array) {
    const text = consumeString(entry, maximumLength, budget, 'INVALID_DATASET')
    if (seen.has(text)) fail('INVALID_DATASET')
    seen.add(text)
    result.push(text)
  }
  return result
}

function parseDatasetEntry(
  domainKey: string,
  value: unknown,
  budget: CharacterBudget
): TwoFactorDirectoryEntry {
  if (!isPlainRecord(value)) fail('INVALID_DATASET')
  const keys = ownKeys(value, 'INVALID_DATASET')
  if (!keys.includes('methods') || keys.some((key) => !ENTRY_KEYS.has(key))) fail('INVALID_DATASET')

  const domain = canonicalHostname(domainKey)
  if (!domain) fail('INVALID_DATASET')
  budget.remaining -= domainKey.length
  if (budget.remaining < 0) fail('DATASET_TOO_LARGE')

  const methods = parseStringArray(
    ownData(value, 'methods'),
    MAX_METHODS,
    MAX_METHOD_LENGTH,
    budget
  )
  if (!methods.includes('totp') || methods.some((method) => !METHODS.has(method))) {
    fail('INVALID_DATASET')
  }

  for (const key of ['custom-hardware', 'custom-software'] as const) {
    const custom = optionalOwnData(value, key)
    if (custom !== undefined) {
      if (!methods.includes(key)) fail('INVALID_DATASET')
      parseStringArray(custom, MAX_CUSTOM_METHODS, MAX_CUSTOM_METHOD_LENGTH, budget)
    }
  }

  const recovery = optionalOwnData(value, 'recovery')
  if (recovery !== undefined) datasetUrl(recovery, budget, false)
  const notes = optionalOwnData(value, 'notes')
  if (notes !== undefined) {
    consumeString(notes, MAX_NOTES_LENGTH, budget, 'INVALID_DATASET', true)
  }

  return Object.freeze({
    domain,
    documentationUrl: datasetUrl(optionalOwnData(value, 'documentation'), budget, true)
  })
}

export function parseTwoFactorDirectoryTotpData(
  value: unknown,
  apiVersion: number = TWO_FACTOR_DIRECTORY_API_VERSION
): TwoFactorDirectoryDataset {
  if (apiVersion !== TWO_FACTOR_DIRECTORY_API_VERSION) fail('UNSUPPORTED_DATASET_VERSION')
  if (!isPlainRecord(value)) fail('INVALID_DATASET')
  const keys = ownKeys(value, 'INVALID_DATASET')
  if (keys.length > MAX_DATASET_ENTRIES) fail('DATASET_TOO_LARGE')

  const budget: CharacterBudget = { remaining: MAX_DATASET_CHARACTERS }
  const entries: TwoFactorDirectoryEntry[] = []
  const canonicalDomains = new Set<string>()
  for (const key of keys) {
    const entry = parseDatasetEntry(key, ownData(value, key), budget)
    if (canonicalDomains.has(entry.domain)) fail('INVALID_DATASET')
    canonicalDomains.add(entry.domain)
    entries.push(entry)
  }
  entries.sort((first, second) => first.domain.localeCompare(second.domain, 'en'))
  return Object.freeze({
    apiVersion: TWO_FACTOR_DIRECTORY_API_VERSION,
    entries: Object.freeze(entries)
  })
}

/** Parses a cached v4 TOTP response. Fetching and signature verification belong to the updater. */
export function loadTwoFactorDirectoryTotpJson(
  serialized: string,
  apiVersion: number = TWO_FACTOR_DIRECTORY_API_VERSION
): TwoFactorDirectoryDataset {
  if (apiVersion !== TWO_FACTOR_DIRECTORY_API_VERSION) fail('UNSUPPORTED_DATASET_VERSION')
  if (typeof serialized !== 'string' || Buffer.byteLength(serialized, 'utf8') > MAX_DATASET_BYTES) {
    fail('DATASET_TOO_LARGE')
  }
  let value: unknown
  try {
    value = JSON.parse(serialized) as unknown
  } catch {
    fail('INVALID_DATASET')
  }
  return parseTwoFactorDirectoryTotpData(value, apiVersion)
}

function hostnameFromLoginUri(value: string): string | null {
  if (value.length === 0 || value.length > MAX_URI_LENGTH || value.trim() !== value) return null
  if (!value.includes('://')) {
    if (['/', '?', '#', '@', ':'].some((separator) => value.includes(separator))) return null
    return canonicalHostname(value)
  }
  try {
    const url = new URL(value)
    if (
      (url.protocol !== 'https:' && url.protocol !== 'http:') ||
      url.username !== '' ||
      url.password !== ''
    ) {
      return null
    }
    return canonicalHostname(url.hostname)
  } catch {
    return null
  }
}

function matchDatasetDomain(
  hostname: string,
  entries: ReadonlyMap<string, TwoFactorDirectoryEntry>
): TwoFactorDirectoryEntry | null {
  let suffix = hostname
  while (suffix.includes('.')) {
    const match = entries.get(suffix)
    if (match) {
      const parsed = parseDomain(match.domain, { allowPrivateDomains: true })
      // A dataset key that is itself a private suffix applies only to the exact service host.
      // Treating it as a normal suffix would incorrectly flag every independent tenant.
      if (suffix === hostname || parsed.domain !== null) return match
    }
    suffix = suffix.slice(suffix.indexOf('.') + 1)
  }
  return null
}

function normalizedName(value: string): string {
  return value
    .normalize('NFD')
    .replace(/\p{M}+/gu, '')
    .toLocaleLowerCase('und')
}

export function analyzeInactiveTwoFactor(
  inputs: readonly unknown[],
  dataset: TwoFactorDirectoryDataset
): InactiveTwoFactorReport {
  if (!Array.isArray(inputs) || inputs.length > MAX_ITEMS) fail('INVALID_INPUT')
  const inputValues = strictArray(inputs, MAX_ITEMS, 'INVALID_INPUT')
  if (!isPlainRecord(dataset)) fail('INVALID_DATASET')
  const datasetKeys = ownKeys(dataset, 'INVALID_DATASET')
  if (
    datasetKeys.length !== 2 ||
    !datasetKeys.includes('apiVersion') ||
    !datasetKeys.includes('entries') ||
    ownData(dataset, 'apiVersion') !== TWO_FACTOR_DIRECTORY_API_VERSION
  ) {
    fail('INVALID_DATASET')
  }
  const datasetEntries = strictArray(
    ownData(dataset, 'entries'),
    MAX_DATASET_ENTRIES,
    'INVALID_DATASET'
  )

  const directory = new Map<string, TwoFactorDirectoryEntry>()
  for (const rawEntry of datasetEntries) {
    if (!isPlainRecord(rawEntry)) fail('INVALID_DATASET')
    const keys = ownKeys(rawEntry, 'INVALID_DATASET')
    if (keys.length !== 2 || !keys.includes('domain') || !keys.includes('documentationUrl')) {
      fail('INVALID_DATASET')
    }
    const domain = ownData(rawEntry, 'domain')
    const documentationUrl = ownData(rawEntry, 'documentationUrl')
    if (
      typeof domain !== 'string' ||
      canonicalHostname(domain) !== domain ||
      (documentationUrl !== null &&
        (typeof documentationUrl !== 'string' ||
          datasetUrl(documentationUrl, { remaining: MAX_URL_LENGTH }, true) === null)) ||
      directory.has(domain)
    ) {
      fail('INVALID_DATASET')
    }
    directory.set(domain, rawEntry as unknown as TwoFactorDirectoryEntry)
  }

  const budget: CharacterBudget = { remaining: MAX_ITEM_CHARACTERS }
  const findings: Array<InactiveTwoFactorFinding & { originalIndex: number }> = []
  let analyzedCount = 0
  let excludedTotpCount = 0
  let excludedDeletedCount = 0
  let excludedArchivedCount = 0

  for (let index = 0; index < inputValues.length; index += 1) {
    const value = inputValues[index]
    if (!isPlainRecord(value)) fail('INVALID_INPUT')
    const keys = ownKeys(value, 'INVALID_INPUT')
    const expectedKeys = ['id', 'name', 'hasTotp', 'isDeleted', 'isArchived', 'uris']
    if (keys.length !== expectedKeys.length || expectedKeys.some((key) => !keys.includes(key))) {
      fail('INVALID_INPUT')
    }
    const id = consumeString(
      ownData(value, 'id', 'INVALID_INPUT'),
      MAX_ID_LENGTH,
      budget,
      'INVALID_INPUT'
    )
    const name = consumeString(
      ownData(value, 'name', 'INVALID_INPUT'),
      MAX_NAME_LENGTH,
      budget,
      'INVALID_INPUT',
      true
    )
    const hasTotp = ownData(value, 'hasTotp', 'INVALID_INPUT')
    const isDeleted = ownData(value, 'isDeleted', 'INVALID_INPUT')
    const isArchived = ownData(value, 'isArchived', 'INVALID_INPUT')
    if (
      typeof hasTotp !== 'boolean' ||
      typeof isDeleted !== 'boolean' ||
      typeof isArchived !== 'boolean'
    ) {
      fail('INVALID_INPUT')
    }
    const uris = strictArray(
      ownData(value, 'uris', 'INVALID_INPUT'),
      MAX_URIS_PER_ITEM,
      'INVALID_INPUT'
    ).map((uri) => consumeString(uri, MAX_URI_LENGTH, budget, 'INVALID_INPUT'))

    if (isDeleted) {
      excludedDeletedCount += 1
      continue
    }
    if (isArchived) {
      excludedArchivedCount += 1
      continue
    }
    if (hasTotp) {
      excludedTotpCount += 1
      continue
    }
    analyzedCount += 1

    let matched: TwoFactorDirectoryEntry | null = null
    for (const uri of uris) {
      const hostname = hostnameFromLoginUri(uri)
      if (!hostname) continue
      matched = matchDatasetDomain(hostname, directory)
      if (matched) break
    }
    if (matched) {
      findings.push({
        id,
        name,
        matchedDomain: matched.domain,
        documentationUrl: matched.documentationUrl,
        originalIndex: index
      })
    }
  }

  findings.sort((first, second) => {
    const firstName = normalizedName(first.name)
    const secondName = normalizedName(second.name)
    if (firstName < secondName) return -1
    if (firstName > secondName) return 1
    return first.originalIndex - second.originalIndex
  })

  return Object.freeze({
    analyzedCount,
    excludedTotpCount,
    excludedDeletedCount,
    excludedArchivedCount,
    findings: Object.freeze(
      findings.map((finding) =>
        Object.freeze({
          id: finding.id,
          name: finding.name,
          matchedDomain: finding.matchedDomain,
          documentationUrl: finding.documentationUrl
        })
      )
    )
  })
}
