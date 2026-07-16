import { VaultError } from './vault-errors'

const JOURNAL_VERSION = 1
const MAX_ITEMS = 40_000
const MAX_ATTACHMENTS = 100_000
const MAX_SOURCE_ID_LENGTH = 256
const MAX_ATTACHMENT_ID_LENGTH = 256
const MAX_FILE_NAME_LENGTH = 255
const MAX_ATTACHMENT_BYTES = 500 * 1024 * 1024
const MAX_SERIALIZED_BYTES = 64 * 1024 * 1024
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const DIGEST_PATTERN = /^[0-9a-f]{64}$/

export type NativeAttachmentRestorePhase =
  'syncing-items' | 'restoring-attachments' | 'needs-reconciliation' | 'complete'

export type NativeAttachmentRestoreAttachmentStatus =
  'pending' | 'attempting' | 'uploaded' | 'needs-reconciliation'

export interface NativeAttachmentRestoreItemMapping {
  readonly sourceItemId: string
  readonly localItemId: string
  readonly remoteItemId: string | null
}

export interface NativeAttachmentRestoreAttachmentMapping {
  readonly sourceItemId: string
  readonly sourceAttachmentId: string
  readonly localItemId: string
  readonly fileName: string
  readonly size: number
  readonly digest: string
  readonly status: NativeAttachmentRestoreAttachmentStatus
  readonly remoteAttachmentId: string | null
}

export interface NativeAttachmentRestoreJournal {
  readonly version: 1
  readonly archiveFingerprint: string
  /** Stable hash of the sync account identity. The journal never stores an email or server URL. */
  readonly accountFingerprint: string
  readonly phase: NativeAttachmentRestorePhase
  readonly createdAt: string
  readonly updatedAt: string
  readonly items: readonly NativeAttachmentRestoreItemMapping[]
  readonly attachments: readonly NativeAttachmentRestoreAttachmentMapping[]
}

export interface NativeAttachmentRestorePlan {
  archiveFingerprint: string
  accountFingerprint: string
  createdAt: string
  items: readonly { sourceItemId: string; localItemId: string }[]
  attachments: readonly {
    sourceItemId: string
    sourceAttachmentId: string
    fileName: string
    size: number
    digest: string
  }[]
}

export interface NativeAttachmentRestoreAttachmentKey {
  sourceItemId: string
  sourceAttachmentId: string
}

function invalid(): never {
  throw new VaultError('INVALID_INPUT')
}

function plainRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) invalid()
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) invalid()
  return value as Record<string, unknown>
}

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const record = plainRecord(value)
  const ownKeys = Reflect.ownKeys(record)
  if (
    ownKeys.length !== keys.length ||
    ownKeys.some((key) => typeof key !== 'string' || !keys.includes(key)) ||
    keys.some((key) => !Object.prototype.hasOwnProperty.call(record, key))
  ) {
    invalid()
  }
  return record
}

function array(value: unknown, maximum: number): unknown[] {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length > maximum
  ) {
    invalid()
  }
  return value
}

function boundedString(value: unknown, maximum: number): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maximum ||
    Array.from(value).some((character) => {
      const code = character.charCodeAt(0)
      return (
        code <= 0x1f ||
        code === 0x7f ||
        (character.length === 1 && code >= 0xd800 && code <= 0xdfff)
      )
    })
  ) {
    invalid()
  }
  return value
}

function digest(value: unknown): string {
  if (typeof value !== 'string' || !DIGEST_PATTERN.test(value)) invalid()
  return value
}

function uuid(value: unknown): string {
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) invalid()
  return value.toLowerCase()
}

function nullableRemoteId(value: unknown): string | null {
  return value === null ? null : boundedString(value, MAX_ATTACHMENT_ID_LENGTH)
}

function isoDate(value: unknown): string {
  if (typeof value !== 'string') invalid()
  const parsed = new Date(value)
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) invalid()
  return value
}

function phase(value: unknown): NativeAttachmentRestorePhase {
  if (
    value !== 'syncing-items' &&
    value !== 'restoring-attachments' &&
    value !== 'needs-reconciliation' &&
    value !== 'complete'
  ) {
    invalid()
  }
  return value
}

function attachmentStatus(value: unknown): NativeAttachmentRestoreAttachmentStatus {
  if (
    value !== 'pending' &&
    value !== 'attempting' &&
    value !== 'uploaded' &&
    value !== 'needs-reconciliation'
  ) {
    invalid()
  }
  return value
}

function sourceIdentity(itemId: string, attachmentId?: string): string {
  return attachmentId === undefined ? itemId : `${itemId}\0${attachmentId}`
}

function parseItem(value: unknown): NativeAttachmentRestoreItemMapping {
  const record = exactRecord(value, ['sourceItemId', 'localItemId', 'remoteItemId'])
  return {
    sourceItemId: boundedString(record.sourceItemId, MAX_SOURCE_ID_LENGTH),
    localItemId: uuid(record.localItemId),
    remoteItemId: record.remoteItemId === null ? null : uuid(record.remoteItemId)
  }
}

function parseAttachment(value: unknown): NativeAttachmentRestoreAttachmentMapping {
  const record = exactRecord(value, [
    'sourceItemId',
    'sourceAttachmentId',
    'localItemId',
    'fileName',
    'size',
    'digest',
    'status',
    'remoteAttachmentId'
  ])
  if (
    !Number.isSafeInteger(record.size) ||
    (record.size as number) < 0 ||
    (record.size as number) > MAX_ATTACHMENT_BYTES
  ) {
    invalid()
  }
  return {
    sourceItemId: boundedString(record.sourceItemId, MAX_SOURCE_ID_LENGTH),
    sourceAttachmentId: boundedString(record.sourceAttachmentId, MAX_ATTACHMENT_ID_LENGTH),
    localItemId: uuid(record.localItemId),
    fileName: boundedString(record.fileName, MAX_FILE_NAME_LENGTH),
    size: record.size as number,
    digest: digest(record.digest),
    status: attachmentStatus(record.status),
    remoteAttachmentId: nullableRemoteId(record.remoteAttachmentId)
  }
}

function expectedPhase(
  items: readonly NativeAttachmentRestoreItemMapping[],
  attachments: readonly NativeAttachmentRestoreAttachmentMapping[]
): NativeAttachmentRestorePhase {
  if (items.some((item) => item.remoteItemId === null)) return 'syncing-items'
  if (attachments.every((attachment) => attachment.status === 'uploaded')) return 'complete'
  if (attachments.some((attachment) => attachment.status === 'needs-reconciliation')) {
    return 'needs-reconciliation'
  }
  return 'restoring-attachments'
}

function validateInvariants(journal: NativeAttachmentRestoreJournal): void {
  const sourceItems = new Set<string>()
  const itemBySource = new Map<string, NativeAttachmentRestoreItemMapping>()
  const localItems = new Set<string>()
  const remoteItems = new Set<string>()
  for (const item of journal.items) {
    if (sourceItems.has(item.sourceItemId) || localItems.has(item.localItemId)) invalid()
    sourceItems.add(item.sourceItemId)
    itemBySource.set(item.sourceItemId, item)
    localItems.add(item.localItemId)
    if (item.remoteItemId !== null) {
      if (remoteItems.has(item.remoteItemId)) invalid()
      remoteItems.add(item.remoteItemId)
    }
  }

  const identities = new Set<string>()
  const itemFileNames = new Set<string>()
  const remoteAttachments = new Set<string>()
  let totalBytes = 0
  let attempting = 0
  for (const attachment of journal.attachments) {
    const item = itemBySource.get(attachment.sourceItemId)
    if (!item || item.localItemId !== attachment.localItemId) invalid()
    const identity = sourceIdentity(attachment.sourceItemId, attachment.sourceAttachmentId)
    const fileIdentity = sourceIdentity(attachment.sourceItemId, attachment.fileName)
    if (identities.has(identity) || itemFileNames.has(fileIdentity)) invalid()
    identities.add(identity)
    itemFileNames.add(fileIdentity)
    totalBytes += attachment.size
    if (!Number.isSafeInteger(totalBytes)) invalid()
    if (attachment.status === 'attempting') attempting += 1
    if (attachment.status === 'uploaded' && attachment.remoteAttachmentId === null) invalid()
    if (
      (attachment.status === 'pending' || attachment.status === 'attempting') &&
      attachment.remoteAttachmentId !== null
    ) {
      invalid()
    }
    if (attachment.remoteAttachmentId !== null) {
      if (remoteAttachments.has(attachment.remoteAttachmentId)) invalid()
      remoteAttachments.add(attachment.remoteAttachmentId)
    }
  }
  if (attempting > 1) invalid()
  if (journal.phase !== expectedPhase(journal.items, journal.attachments)) invalid()
  if (journal.phase === 'needs-reconciliation' && attempting !== 0) invalid()
  if (
    journal.phase === 'syncing-items' &&
    journal.attachments.some((attachment) => attachment.status !== 'pending')
  ) {
    invalid()
  }
  if (Date.parse(journal.updatedAt) < Date.parse(journal.createdAt)) invalid()
}

function freezeJournal(journal: NativeAttachmentRestoreJournal): NativeAttachmentRestoreJournal {
  return Object.freeze({
    ...journal,
    items: Object.freeze(journal.items.map((item) => Object.freeze({ ...item }))),
    attachments: Object.freeze(
      journal.attachments.map((attachment) => Object.freeze({ ...attachment }))
    )
  })
}

function parseNativeAttachmentRestoreJournalInternal(
  value: unknown
): NativeAttachmentRestoreJournal {
  const record = exactRecord(value, [
    'version',
    'archiveFingerprint',
    'accountFingerprint',
    'phase',
    'createdAt',
    'updatedAt',
    'items',
    'attachments'
  ])
  if (record.version !== JOURNAL_VERSION) invalid()
  const journal: NativeAttachmentRestoreJournal = {
    version: JOURNAL_VERSION,
    archiveFingerprint: digest(record.archiveFingerprint),
    accountFingerprint: digest(record.accountFingerprint),
    phase: phase(record.phase),
    createdAt: isoDate(record.createdAt),
    updatedAt: isoDate(record.updatedAt),
    items: array(record.items, MAX_ITEMS).map(parseItem),
    attachments: array(record.attachments, MAX_ATTACHMENTS).map(parseAttachment)
  }
  validateInvariants(journal)
  if (Buffer.byteLength(JSON.stringify(journal), 'utf8') > MAX_SERIALIZED_BYTES) invalid()
  return freezeJournal(journal)
}

export function parseNativeAttachmentRestoreJournal(
  value: unknown
): NativeAttachmentRestoreJournal {
  try {
    return parseNativeAttachmentRestoreJournalInternal(value)
  } catch (error) {
    if (error instanceof VaultError) throw error
    invalid()
  }
}

export function parseNativeAttachmentRestoreJournalJson(
  serialized: string
): NativeAttachmentRestoreJournal {
  if (
    typeof serialized !== 'string' ||
    serialized.length === 0 ||
    Buffer.byteLength(serialized, 'utf8') > MAX_SERIALIZED_BYTES
  ) {
    invalid()
  }
  try {
    return parseNativeAttachmentRestoreJournal(JSON.parse(serialized) as unknown)
  } catch (error) {
    if (error instanceof VaultError) throw error
    invalid()
  }
}

export function serializeNativeAttachmentRestoreJournal(
  journal: NativeAttachmentRestoreJournal
): string {
  const validated = parseNativeAttachmentRestoreJournal(journal)
  const serialized = JSON.stringify(validated)
  if (Buffer.byteLength(serialized, 'utf8') > MAX_SERIALIZED_BYTES) invalid()
  return serialized
}

export function createNativeAttachmentRestoreJournal(
  plan: NativeAttachmentRestorePlan
): NativeAttachmentRestoreJournal {
  const record = exactRecord(plan, [
    'archiveFingerprint',
    'accountFingerprint',
    'createdAt',
    'items',
    'attachments'
  ])
  const createdAt = isoDate(record.createdAt)
  const rawItems = array(record.items, MAX_ITEMS)
  const items = rawItems.map((value) => {
    const item = exactRecord(value, ['sourceItemId', 'localItemId'])
    return {
      sourceItemId: boundedString(item.sourceItemId, MAX_SOURCE_ID_LENGTH),
      localItemId: uuid(item.localItemId),
      remoteItemId: null
    }
  })
  const itemBySource = new Map(items.map((item) => [item.sourceItemId, item]))
  const rawAttachments = array(record.attachments, MAX_ATTACHMENTS)
  const attachments = rawAttachments.map((value) => {
    const attachment = exactRecord(value, [
      'sourceItemId',
      'sourceAttachmentId',
      'fileName',
      'size',
      'digest'
    ])
    const sourceItemId = boundedString(attachment.sourceItemId, MAX_SOURCE_ID_LENGTH)
    const item = itemBySource.get(sourceItemId)
    if (!item) invalid()
    return {
      sourceItemId,
      sourceAttachmentId: boundedString(attachment.sourceAttachmentId, MAX_ATTACHMENT_ID_LENGTH),
      localItemId: item.localItemId,
      fileName: boundedString(attachment.fileName, MAX_FILE_NAME_LENGTH),
      size: attachment.size,
      digest: digest(attachment.digest),
      status: 'pending',
      remoteAttachmentId: null
    }
  })
  return parseNativeAttachmentRestoreJournal({
    version: JOURNAL_VERSION,
    archiveFingerprint: digest(record.archiveFingerprint),
    accountFingerprint: digest(record.accountFingerprint),
    phase: items.length === 0 ? 'complete' : 'syncing-items',
    createdAt,
    updatedAt: createdAt,
    items,
    attachments
  })
}

function transitionTime(journal: NativeAttachmentRestoreJournal, now: string): string {
  const timestamp = isoDate(now)
  if (Date.parse(timestamp) < Date.parse(journal.updatedAt)) invalid()
  return timestamp
}

function attachmentIndex(
  journal: NativeAttachmentRestoreJournal,
  key: NativeAttachmentRestoreAttachmentKey
): number {
  const sourceItemId = boundedString(key.sourceItemId, MAX_SOURCE_ID_LENGTH)
  const sourceAttachmentId = boundedString(key.sourceAttachmentId, MAX_ATTACHMENT_ID_LENGTH)
  const index = journal.attachments.findIndex(
    (attachment) =>
      attachment.sourceItemId === sourceItemId &&
      attachment.sourceAttachmentId === sourceAttachmentId
  )
  if (index < 0) invalid()
  return index
}

function withAttachments(
  journal: NativeAttachmentRestoreJournal,
  attachments: NativeAttachmentRestoreAttachmentMapping[],
  now: string
): NativeAttachmentRestoreJournal {
  return parseNativeAttachmentRestoreJournal({
    ...journal,
    phase: expectedPhase(journal.items, attachments),
    updatedAt: transitionTime(journal, now),
    attachments
  })
}

export function bindNativeAttachmentRestoreRemoteItem(
  journalValue: NativeAttachmentRestoreJournal,
  sourceItemIdValue: string,
  remoteItemIdValue: string,
  now: string
): NativeAttachmentRestoreJournal {
  const journal = parseNativeAttachmentRestoreJournal(journalValue)
  if (journal.phase !== 'syncing-items') invalid()
  const sourceItemId = boundedString(sourceItemIdValue, MAX_SOURCE_ID_LENGTH)
  const remoteItemId = uuid(remoteItemIdValue)
  if (journal.items.some((item) => item.remoteItemId === remoteItemId)) invalid()
  let found = false
  const items = journal.items.map((item) => {
    if (item.sourceItemId !== sourceItemId) return { ...item }
    found = true
    if (item.remoteItemId !== null) invalid()
    return { ...item, remoteItemId }
  })
  if (!found) invalid()
  return parseNativeAttachmentRestoreJournal({
    ...journal,
    phase: expectedPhase(items, journal.attachments),
    updatedAt: transitionTime(journal, now),
    items,
    attachments: journal.attachments.map((attachment) => ({ ...attachment }))
  })
}

export function beginNativeAttachmentRestoreAttempt(
  journalValue: NativeAttachmentRestoreJournal,
  key: NativeAttachmentRestoreAttachmentKey,
  now: string
): NativeAttachmentRestoreJournal {
  const journal = parseNativeAttachmentRestoreJournal(journalValue)
  if (journal.phase !== 'restoring-attachments') invalid()
  const index = attachmentIndex(journal, key)
  if (journal.attachments[index]!.status !== 'pending') invalid()
  const firstPending = journal.attachments.findIndex(
    (attachment) => attachment.status === 'pending'
  )
  if (index !== firstPending) invalid()
  const attachments = journal.attachments.map((attachment, candidate) =>
    candidate === index ? { ...attachment, status: 'attempting' as const } : { ...attachment }
  )
  return withAttachments(journal, attachments, now)
}

export function completeNativeAttachmentRestoreAttempt(
  journalValue: NativeAttachmentRestoreJournal,
  key: NativeAttachmentRestoreAttachmentKey,
  remoteAttachmentIdValue: string,
  now: string
): NativeAttachmentRestoreJournal {
  const journal = parseNativeAttachmentRestoreJournal(journalValue)
  const index = attachmentIndex(journal, key)
  if (journal.attachments[index]!.status !== 'attempting') invalid()
  const remoteAttachmentId = boundedString(remoteAttachmentIdValue, MAX_ATTACHMENT_ID_LENGTH)
  if (
    journal.attachments.some((attachment) => attachment.remoteAttachmentId === remoteAttachmentId)
  ) {
    invalid()
  }
  const attachments = journal.attachments.map((attachment, candidate) =>
    candidate === index
      ? { ...attachment, status: 'uploaded' as const, remoteAttachmentId }
      : { ...attachment }
  )
  return withAttachments(journal, attachments, now)
}

export function failNativeAttachmentRestoreAttempt(
  journalValue: NativeAttachmentRestoreJournal,
  key: NativeAttachmentRestoreAttachmentKey,
  candidateRemoteAttachmentId: string | null,
  now: string
): NativeAttachmentRestoreJournal {
  const journal = parseNativeAttachmentRestoreJournal(journalValue)
  const index = attachmentIndex(journal, key)
  if (journal.attachments[index]!.status !== 'attempting') invalid()
  const remoteAttachmentId = nullableRemoteId(candidateRemoteAttachmentId)
  if (
    remoteAttachmentId !== null &&
    journal.attachments.some((attachment) => attachment.remoteAttachmentId === remoteAttachmentId)
  ) {
    invalid()
  }
  const attachments = journal.attachments.map((attachment, candidate) =>
    candidate === index
      ? { ...attachment, status: 'needs-reconciliation' as const, remoteAttachmentId }
      : { ...attachment }
  )
  return withAttachments(journal, attachments, now)
}

export function recoverInterruptedNativeAttachmentRestore(
  journalValue: NativeAttachmentRestoreJournal,
  now: string
): NativeAttachmentRestoreJournal {
  const journal = parseNativeAttachmentRestoreJournal(journalValue)
  if (!journal.attachments.some((attachment) => attachment.status === 'attempting')) return journal
  const attachments = journal.attachments.map((attachment) =>
    attachment.status === 'attempting'
      ? { ...attachment, status: 'needs-reconciliation' as const }
      : { ...attachment }
  )
  return withAttachments(journal, attachments, now)
}

export function reconcileNativeAttachmentRestoreUploaded(
  journalValue: NativeAttachmentRestoreJournal,
  key: NativeAttachmentRestoreAttachmentKey,
  remoteAttachmentIdValue: string,
  now: string
): NativeAttachmentRestoreJournal {
  const journal = parseNativeAttachmentRestoreJournal(journalValue)
  if (journal.phase !== 'needs-reconciliation') invalid()
  const index = attachmentIndex(journal, key)
  const current = journal.attachments[index]!
  if (current.status !== 'needs-reconciliation') invalid()
  const remoteAttachmentId = boundedString(remoteAttachmentIdValue, MAX_ATTACHMENT_ID_LENGTH)
  if (current.remoteAttachmentId !== null && current.remoteAttachmentId !== remoteAttachmentId) {
    invalid()
  }
  if (
    journal.attachments.some(
      (attachment, candidate) =>
        candidate !== index && attachment.remoteAttachmentId === remoteAttachmentId
    )
  ) {
    invalid()
  }
  const attachments = journal.attachments.map((attachment, candidate) =>
    candidate === index
      ? { ...attachment, status: 'uploaded' as const, remoteAttachmentId }
      : { ...attachment }
  )
  return withAttachments(journal, attachments, now)
}

export function reconcileNativeAttachmentRestoreMissing(
  journalValue: NativeAttachmentRestoreJournal,
  key: NativeAttachmentRestoreAttachmentKey,
  now: string
): NativeAttachmentRestoreJournal {
  const journal = parseNativeAttachmentRestoreJournal(journalValue)
  if (journal.phase !== 'needs-reconciliation') invalid()
  const index = attachmentIndex(journal, key)
  if (journal.attachments[index]!.status !== 'needs-reconciliation') invalid()
  const attachments = journal.attachments.map((attachment, candidate) =>
    candidate === index
      ? { ...attachment, status: 'pending' as const, remoteAttachmentId: null }
      : { ...attachment }
  )
  return withAttachments(journal, attachments, now)
}

export function assertNativeAttachmentRestoreBinding(
  journalValue: NativeAttachmentRestoreJournal,
  archiveFingerprintValue: string,
  accountFingerprintValue: string
): NativeAttachmentRestoreJournal {
  const journal = parseNativeAttachmentRestoreJournal(journalValue)
  if (
    journal.archiveFingerprint !== digest(archiveFingerprintValue) ||
    journal.accountFingerprint !== digest(accountFingerprintValue)
  ) {
    invalid()
  }
  return journal
}

export function nextNativeAttachmentRestoreAttachment(
  journalValue: NativeAttachmentRestoreJournal
): NativeAttachmentRestoreAttachmentMapping | null {
  const journal = parseNativeAttachmentRestoreJournal(journalValue)
  if (journal.phase !== 'restoring-attachments') return null
  return journal.attachments.find((attachment) => attachment.status === 'pending') ?? null
}
