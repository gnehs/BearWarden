import type {
  SendCreateRequest,
  SendFileCreateRequest,
  SendUpdateRequest,
  SendView
} from '../../shared/vault-contract'
import type {
  BitwardenFileSendDraft,
  BitwardenSendDraft,
  BitwardenSendItem
} from '../bitwarden-direct'
import { VaultError } from '../vault-errors'
import {
  MAX_NAME_LENGTH,
  MAX_NOTES_LENGTH,
  MAX_SEND_FILE_ID_LENGTH,
  MAX_SEND_FILE_NAME_LENGTH,
  MAX_SEND_FILE_SIZE,
  MAX_SEND_FILE_SIZE_NAME_LENGTH,
  MAX_SEND_TEXT_LENGTH,
  MAX_SYNC_SECRET_LENGTH,
  UUID_PATTERN
} from './limits'
import {
  isRecord,
  normalizeNullableString,
  normalizeRequiredString,
  normalizeString
} from './parse-primitives'
import type { StoredSend } from './types'

export function parseStoredSend(value: unknown): StoredSend {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  const {
    id,
    accessId,
    type,
    name,
    notes,
    text,
    file,
    hidden,
    maxAccessCount,
    accessCount,
    revisionDate,
    expirationDate,
    deletionDate,
    disabled,
    hideEmail,
    authType,
    passwordProtected
  } = value
  if (
    typeof id !== 'string' ||
    !UUID_PATTERN.test(id) ||
    typeof accessId !== 'string' ||
    !/^[A-Za-z0-9_-]{16,128}$/u.test(accessId) ||
    (type !== 'text' && type !== 'file') ||
    typeof name !== 'string' ||
    name.length === 0 ||
    name.length > MAX_NAME_LENGTH ||
    (notes !== null && typeof notes !== 'string') ||
    (typeof notes === 'string' && notes.length > MAX_NOTES_LENGTH) ||
    (type === 'text' && (typeof text !== 'string' || text.length > MAX_SEND_TEXT_LENGTH)) ||
    // A file Send has no text payload (vaultwarden sends null). The app normalizes it to ''
    // end to end, so the stored form accepts both spellings and stays stable across rewrites.
    (type === 'file' && text !== null && text !== undefined && text !== '') ||
    (type === 'file' && !isRecord(file)) ||
    typeof hidden !== 'boolean' ||
    (maxAccessCount !== null &&
      (typeof maxAccessCount !== 'number' ||
        !Number.isSafeInteger(maxAccessCount) ||
        (maxAccessCount as number) < 1)) ||
    typeof accessCount !== 'number' ||
    !Number.isSafeInteger(accessCount) ||
    (accessCount as number) < 0 ||
    typeof revisionDate !== 'string' ||
    typeof deletionDate !== 'string' ||
    !Number.isFinite(Date.parse(revisionDate)) ||
    !Number.isFinite(Date.parse(deletionDate)) ||
    (expirationDate !== null &&
      (typeof expirationDate !== 'string' || !Number.isFinite(Date.parse(expirationDate)))) ||
    typeof disabled !== 'boolean' ||
    typeof hideEmail !== 'boolean' ||
    (authType !== 'none' && authType !== 'password' && authType !== 'email') ||
    typeof passwordProtected !== 'boolean'
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  let parsedFile: SendView['file']
  if (type === 'file') {
    const fileRecord = isRecord(file) ? file : null
    if (!fileRecord) throw new VaultError('CORRUPT_VAULT')
    const { id: fileId, fileName, size, sizeName } = fileRecord
    if (
      typeof fileId !== 'string' ||
      fileId.length === 0 ||
      fileId.length > MAX_SEND_FILE_ID_LENGTH ||
      typeof fileName !== 'string' ||
      fileName.length === 0 ||
      fileName.length > MAX_SEND_FILE_NAME_LENGTH ||
      typeof size !== 'number' ||
      !Number.isSafeInteger(size) ||
      size < 1 ||
      size > MAX_SEND_FILE_SIZE ||
      (sizeName !== null &&
        (typeof sizeName !== 'string' || sizeName.length > MAX_SEND_FILE_SIZE_NAME_LENGTH))
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    parsedFile = { id: fileId, fileName, size, sizeName }
  }
  const parsedMaxAccessCount = maxAccessCount === null ? null : (maxAccessCount as number)
  const parsedAccessCount = accessCount as number
  return {
    id,
    accessId,
    type,
    name,
    notes,
    text: type === 'text' ? (text as string) : '',
    ...(parsedFile ? { file: parsedFile } : {}),
    hidden,
    maxAccessCount: parsedMaxAccessCount,
    accessCount: parsedAccessCount,
    revisionDate,
    expirationDate,
    deletionDate,
    disabled,
    hideEmail,
    authType,
    passwordProtected
  }
}

export function sendViewFromRemote(send: BitwardenSendItem): StoredSend {
  return {
    id: send.id,
    accessId: send.accessId,
    type: send.type,
    name: send.name,
    notes: send.notes,
    text: send.type === 'text' ? send.text : '',
    ...(send.type === 'file' && send.file ? { file: { ...send.file } } : {}),
    hidden: send.hidden,
    maxAccessCount: send.maxAccessCount,
    accessCount: send.accessCount,
    revisionDate: send.revisionDate,
    expirationDate: send.expirationDate,
    deletionDate: send.deletionDate,
    disabled: send.disabled,
    hideEmail: send.hideEmail,
    authType: send.authType === 0 ? 'email' : send.authType === 1 ? 'password' : 'none',
    passwordProtected: send.passwordProtected
  }
}

export interface NormalizedSendOptions {
  name: string
  notes: string | null
  maxAccessCount: number | null
  expirationDate: string | null
  deletionDate: string
  password: string | null | undefined
  disabled: boolean
  hideEmail: boolean
}

export function normalizeSendOptions(
  request: SendCreateRequest | SendUpdateRequest | SendFileCreateRequest
): NormalizedSendOptions {
  const name = normalizeRequiredString(request.name, MAX_NAME_LENGTH)
  const notes = normalizeNullableString(request.notes, MAX_NOTES_LENGTH)
  const maxAccessCount = request.maxAccessCount ?? null
  if (
    maxAccessCount !== null &&
    (!Number.isSafeInteger(maxAccessCount) || maxAccessCount < 1 || maxAccessCount > 2_147_483_647)
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  const expirationDate = request.expirationDate ?? null
  const deletionDate =
    request.deletionDate ?? new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
  for (const value of [expirationDate, deletionDate]) {
    if (value !== null && (typeof value !== 'string' || !Number.isFinite(Date.parse(value)))) {
      throw new VaultError('INVALID_INPUT')
    }
  }
  const password =
    request.password === undefined
      ? undefined
      : normalizeNullableString(request.password, MAX_SYNC_SECRET_LENGTH)
  const disabled = request.disabled ?? false
  const hideEmail = request.hideEmail ?? true
  if (typeof disabled !== 'boolean' || typeof hideEmail !== 'boolean') {
    throw new VaultError('INVALID_INPUT')
  }
  if (expirationDate && Date.parse(expirationDate) <= Date.now()) {
    throw new VaultError('INVALID_INPUT')
  }
  if (
    Date.parse(deletionDate) <= Date.now() ||
    Date.parse(deletionDate) > Date.now() + 31 * 24 * 60 * 60 * 1000
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  if (expirationDate && Date.parse(expirationDate) > Date.parse(deletionDate)) {
    throw new VaultError('INVALID_INPUT')
  }
  return {
    name,
    notes,
    maxAccessCount,
    expirationDate,
    deletionDate,
    password,
    disabled,
    hideEmail
  }
}

export function normalizeSendDraft(
  request: SendCreateRequest | SendUpdateRequest
): BitwardenSendDraft {
  const options = normalizeSendOptions(request)
  const hidden = request.hidden ?? false
  if (typeof hidden !== 'boolean') throw new VaultError('INVALID_INPUT')
  return {
    ...options,
    text: normalizeString(request.text, MAX_SEND_TEXT_LENGTH),
    hidden
  }
}

export function normalizeFileSendDraft(
  request: SendFileCreateRequest
): Omit<BitwardenFileSendDraft, 'fileName' | 'data'> {
  return normalizeSendOptions(request)
}
