import lunr from 'lunr'

const MAX_QUERY_LENGTH = 1_024
const MAX_SEARCH_ITEMS = 50_000
const MAX_COLLECTION_LENGTH = 1_000
const MAX_SHORT_FIELD_LENGTH = 5_000
const MAX_URI_LENGTH = 4_096
const MAX_NOTES_LENGTH = 65_536
const MAX_INDEXED_CHARACTERS = 32 * 1_024 * 1_024

const ADVANCED_FIELDS = [
  'shortid',
  'name',
  'subtitle',
  'notes',
  'login.username',
  'login.uris',
  'fields',
  'fields_joined',
  'attachments',
  'attachments_joined'
] as const

type SearchRecord = Record<string, unknown>

export interface VaultSearchUri {
  readonly uri: string
}

export interface VaultSearchCustomField {
  readonly name: string
  readonly value: string | null
  readonly type: 'text' | 'hidden' | 'boolean' | 'linked' | number
}

export interface VaultSearchAttachment {
  readonly fileName: string
}

export interface VaultSearchLoginFields {
  readonly username?: string
  readonly uris?: readonly (VaultSearchUri | string)[]
}

/**
 * Decrypted, main-process-only data accepted by the vault search engine.
 *
 * This interface must not be moved into the preload contract. Search returns the
 * original item references and never exposes its transient Lunr documents.
 */
export interface VaultSearchItem {
  readonly id: string
  readonly type: string
  readonly name: string
  readonly subtitle?: string
  readonly username?: string
  readonly uri?: string | null
  readonly uris?: readonly (VaultSearchUri | string)[]
  readonly notes?: string | null
  readonly customFields?: readonly VaultSearchCustomField[]
  /** Bitwarden-compatible alias for custom fields. */
  readonly fields?: readonly VaultSearchCustomField[]
  readonly attachments?: readonly (VaultSearchAttachment | string)[]
  readonly login?: VaultSearchLoginFields
  readonly reprompt?: 0 | 1
  readonly protected?: boolean
}

interface SearchDocument {
  readonly ref: string
  readonly originalIndex: number
  readonly shortid: string
  readonly name: string
  readonly subtitle: string
  readonly notes: string
  readonly 'login.username': string
  readonly 'login.uris': string
  readonly fields: string
  readonly fields_joined: string
  readonly attachments: string
  readonly attachments_joined: string
  readonly basicText: readonly string[]
}

class SearchBoundsError extends Error {}

interface SearchBudget {
  remaining: number
}

function isPlainRecord(value: unknown): value is SearchRecord {
  if (value === null || typeof value !== 'object') return false

  try {
    const prototype = Object.getPrototypeOf(value)
    return prototype === Object.prototype || prototype === null
  } catch {
    return false
  }
}

function ownData(record: SearchRecord, key: string): PropertyDescriptor | undefined {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(record, key)
    return descriptor && 'value' in descriptor ? descriptor : undefined
  } catch {
    return undefined
  }
}

function boundedString(
  record: SearchRecord,
  key: string,
  maximumLength: number,
  budget: SearchBudget
): string | undefined {
  const value = ownData(record, key)?.value
  if (typeof value !== 'string') return undefined

  const result = value.slice(0, maximumLength)
  budget.remaining -= result.length
  if (budget.remaining < 0) throw new SearchBoundsError()
  return result
}

function normalizeSearchText(value: string): string {
  return value
    .normalize('NFD')
    .replace(/\p{M}+/gu, '')
    .toLocaleLowerCase('und')
}

function isProtected(record: SearchRecord): boolean {
  const protectedDescriptor = (() => {
    try {
      return Object.getOwnPropertyDescriptor(record, 'protected')
    } catch {
      return undefined
    }
  })()
  if (protectedDescriptor) {
    if (!('value' in protectedDescriptor) || typeof protectedDescriptor.value !== 'boolean') {
      return true
    }
    if (protectedDescriptor.value) return true
  }

  const repromptDescriptor = (() => {
    try {
      return Object.getOwnPropertyDescriptor(record, 'reprompt')
    } catch {
      return undefined
    }
  })()
  if (!repromptDescriptor) return false
  if (!('value' in repromptDescriptor)) return true
  return repromptDescriptor.value !== 0
}

function ownArray(record: SearchRecord, key: string): readonly unknown[] {
  const value = ownData(record, key)?.value
  if (!Array.isArray(value)) return []
  if (value.length > MAX_COLLECTION_LENGTH) throw new SearchBoundsError()
  return value
}

function safeArrayEntries(values: readonly unknown[]): unknown[] {
  const result: unknown[] = []
  for (let index = 0; index < values.length; index += 1) {
    let descriptor: PropertyDescriptor | undefined
    try {
      descriptor = Object.getOwnPropertyDescriptor(values, String(index))
    } catch {
      throw new SearchBoundsError()
    }
    if (descriptor && 'value' in descriptor) result.push(descriptor.value)
  }
  return result
}

function collectUris(record: SearchRecord, budget: SearchBudget): string[] {
  const result: string[] = []
  const primary = boundedString(record, 'uri', MAX_URI_LENGTH, budget)
  if (primary) result.push(primary)

  const appendUris = (values: readonly unknown[]): void => {
    for (const value of safeArrayEntries(values)) {
      if (typeof value === 'string') {
        const uri = value.slice(0, MAX_URI_LENGTH)
        budget.remaining -= uri.length
        if (budget.remaining < 0) throw new SearchBoundsError()
        if (uri) result.push(uri)
        continue
      }
      if (!isPlainRecord(value)) continue
      const uri = boundedString(value, 'uri', MAX_URI_LENGTH, budget)
      if (uri) result.push(uri)
    }
  }

  appendUris(ownArray(record, 'uris'))

  const login = ownData(record, 'login')?.value
  if (isPlainRecord(login)) appendUris(ownArray(login, 'uris'))
  return [...new Set(result)]
}

function hostnameFromUri(value: string): string | null {
  try {
    const hasScheme = /^[a-z][a-z0-9+.-]*:/iu.test(value)
    const url = new URL(hasScheme ? value : `https://${value}`)
    return url.hostname ? normalizeSearchText(url.hostname) : null
  } catch {
    return null
  }
}

function collectUsername(record: SearchRecord, budget: SearchBudget): string {
  const username = boundedString(record, 'username', MAX_SHORT_FIELD_LENGTH, budget)
  if (username !== undefined) return username

  const login = ownData(record, 'login')?.value
  if (!isPlainRecord(login)) return ''
  return boundedString(login, 'username', MAX_SHORT_FIELD_LENGTH, budget) ?? ''
}

function collectCustomFields(
  record: SearchRecord,
  budget: SearchBudget
): { fields: string[]; joined: string[] } {
  const fields: string[] = []
  const joined: string[] = []
  const collections = [ownArray(record, 'customFields'), ownArray(record, 'fields')]

  for (const collection of collections) {
    for (const value of safeArrayEntries(collection)) {
      if (!isPlainRecord(value)) continue
      const type = ownData(value, 'type')?.value
      // Text is Cipher.Field type 0 upstream. Hidden, boolean, linked and malformed
      // fields are excluded in their entirety so even their names cannot become an oracle.
      if (type !== 'text' && type !== 0) continue
      const name = boundedString(value, 'name', MAX_SHORT_FIELD_LENGTH, budget) ?? ''
      const fieldValue = boundedString(value, 'value', MAX_SHORT_FIELD_LENGTH, budget) ?? ''
      if (name) fields.push(normalizeSearchText(name))
      if (fieldValue) fields.push(normalizeSearchText(fieldValue))
      if (name || fieldValue) joined.push(normalizeSearchText(`${name}:${fieldValue}`))
    }
  }

  return { fields, joined }
}

function collectAttachments(
  record: SearchRecord,
  budget: SearchBudget
): { attachments: string[]; joined: string[] } {
  const attachments: string[] = []
  for (const value of safeArrayEntries(ownArray(record, 'attachments'))) {
    let fileName: string | undefined
    if (typeof value === 'string') {
      fileName = value.slice(0, MAX_SHORT_FIELD_LENGTH)
      budget.remaining -= fileName.length
      if (budget.remaining < 0) throw new SearchBoundsError()
    } else if (isPlainRecord(value)) {
      fileName = boundedString(value, 'fileName', MAX_SHORT_FIELD_LENGTH, budget)
    }
    if (fileName) attachments.push(normalizeSearchText(fileName))
  }
  return { attachments, joined: attachments.slice() }
}

function toSearchDocument(
  value: unknown,
  originalIndex: number,
  budget: SearchBudget
): SearchDocument | null {
  if (!isPlainRecord(value)) return null

  const protectedItem = isProtected(value)
  const id = boundedString(value, 'id', MAX_SHORT_FIELD_LENGTH, budget)
  const type = boundedString(value, 'type', 64, budget)
  const name = boundedString(value, 'name', MAX_SHORT_FIELD_LENGTH, budget)
  if (!id || !type || name === undefined) return null

  const shortid = normalizeSearchText(id.slice(0, 8))
  const normalizedName = normalizeSearchText(name)
  if (protectedItem) {
    return {
      ref: String(originalIndex),
      originalIndex,
      shortid,
      name: normalizedName,
      subtitle: '',
      notes: '',
      'login.username': '',
      'login.uris': '',
      fields: '',
      fields_joined: '',
      attachments: '',
      attachments_joined: '',
      basicText: [normalizedName]
    }
  }

  const subtitle = boundedString(value, 'subtitle', MAX_SHORT_FIELD_LENGTH, budget) ?? ''
  const notes = boundedString(value, 'notes', MAX_NOTES_LENGTH, budget) ?? ''
  const username = collectUsername(value, budget)
  const uris = collectUris(value, budget)
  const normalizedUris = uris.map(normalizeSearchText)
  const hostnames = uris.map(hostnameFromUri).filter((entry): entry is string => entry !== null)
  const customFields = collectCustomFields(value, budget)
  const attachmentFields = collectAttachments(value, budget)
  const normalizedSubtitle = normalizeSearchText(subtitle)
  const normalizedNotes = normalizeSearchText(notes)
  const normalizedUsername = normalizeSearchText(username)
  // BearWarden summaries use the primary URI as a fallback subtitle. Do not let
  // that compatibility presentation field make a URI's secret path basic-searchable.
  const basicSubtitle = normalizedUris.includes(normalizedSubtitle) ? '' : normalizedSubtitle

  return {
    ref: String(originalIndex),
    originalIndex,
    shortid,
    name: normalizedName,
    subtitle: normalizedSubtitle,
    notes: normalizedNotes,
    'login.username': normalizedUsername,
    'login.uris': normalizedUris.join(' '),
    fields: customFields.fields.join(' '),
    fields_joined: customFields.joined.join(' '),
    attachments: attachmentFields.attachments.join(' '),
    attachments_joined: attachmentFields.joined.join(' '),
    basicText: [normalizedName, basicSubtitle, ...hostnames, normalizedNotes]
  }
}

function safeOriginalItems<T>(items: readonly T[]): T[] {
  const result: T[] = []
  for (let index = 0; index < items.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(items, String(index))
    if (descriptor && 'value' in descriptor) result.push(descriptor.value as T)
  }
  return result
}

function basicSearch<T>(
  items: readonly T[],
  documents: readonly SearchDocument[],
  query: string
): T[] {
  const terms = query.split(/\s+/u).filter(Boolean)
  return documents
    .filter((document) =>
      terms.every(
        (term) =>
          document.basicText.some((candidate) => candidate.includes(term)) ||
          (term.length >= 8 && document.shortid.includes(term))
      )
    )
    .map((document) => items[document.originalIndex]!)
}

function advancedSearch<T>(
  items: readonly T[],
  documents: readonly SearchDocument[],
  query: string
): T[] {
  if (!query) return []

  const index = lunr(function buildVaultSearchIndex() {
    this.ref('ref')
    for (const field of ADVANCED_FIELDS) this.field(field)
    // Search data and query text are normalized before they enter Lunr. Keeping
    // the pipeline empty preserves CJK tokens and makes wildcard behavior exact.
    this.pipeline.reset()
    this.searchPipeline.reset()
    for (const document of documents) this.add(document)
  })

  try {
    return index
      .search(query)
      .map((result) => Number.parseInt(result.ref, 10))
      .filter((originalIndex) => Number.isSafeInteger(originalIndex) && originalIndex >= 0)
      .map((originalIndex) => items[originalIndex])
      .filter((item): item is T => item !== undefined)
  } catch {
    // Invalid/unknown Lunr syntax is an empty result, never a renderer-visible error.
    return []
  }
}

/**
 * Searches decrypted vault data without moving a plaintext index or result body
 * across the main/renderer boundary.
 *
 * Basic queries use case/diacritic-insensitive substring matching and AND all
 * whitespace-separated terms. Queries prefixed with `>` use Lunr's advanced
 * field, wildcard, presence, boost and fuzzy syntax.
 */
export function searchVaultItems<T extends VaultSearchItem>(
  items: readonly T[],
  query: string
): T[] {
  try {
    if (!Array.isArray(items) || typeof query !== 'string') return []
    if (items.length > MAX_SEARCH_ITEMS || query.length > MAX_QUERY_LENGTH) return []

    const trimmedQuery = query.trim()
    if (!trimmedQuery) return safeOriginalItems(items)

    const normalizedQuery = normalizeSearchText(trimmedQuery)
    const advanced = normalizedQuery.startsWith('>')
    const searchableQuery = advanced ? normalizedQuery.slice(1).trim() : normalizedQuery
    const budget: SearchBudget = { remaining: MAX_INDEXED_CHARACTERS }
    const documents: SearchDocument[] = []
    for (let index = 0; index < items.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(items, String(index))
      if (!descriptor || !('value' in descriptor)) continue
      const document = toSearchDocument(descriptor.value, index, budget)
      if (document) documents.push(document)
    }

    return advanced
      ? advancedSearch(items, documents, searchableQuery)
      : basicSearch(items, documents, searchableQuery)
  } catch {
    return []
  }
}
