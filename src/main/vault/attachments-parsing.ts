import type { VaultAttachmentView } from '../../shared/vault-contract'
import { VaultError } from '../vault-errors'
import {
  MAX_ATTACHMENTS,
  MAX_ATTACHMENT_FILE_NAME_LENGTH,
  MAX_ATTACHMENT_ID_LENGTH,
  MAX_ATTACHMENT_SIZE_NAME_LENGTH
} from './limits'
import { isRecord } from './parse-primitives'

export function parseStoredAttachment(value: unknown): VaultAttachmentView {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  if (
    typeof value.id !== 'string' ||
    value.id.length === 0 ||
    value.id.length > MAX_ATTACHMENT_ID_LENGTH ||
    typeof value.fileName !== 'string' ||
    value.fileName.length === 0 ||
    value.fileName.length > MAX_ATTACHMENT_FILE_NAME_LENGTH ||
    typeof value.size !== 'number' ||
    !Number.isSafeInteger(value.size) ||
    value.size < 0 ||
    typeof value.sizeName !== 'string' ||
    value.sizeName.length > MAX_ATTACHMENT_SIZE_NAME_LENGTH ||
    typeof value.legacy !== 'boolean'
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return {
    id: value.id,
    fileName: value.fileName,
    size: value.size,
    sizeName: value.sizeName,
    legacy: value.legacy
  }
}

export function parseStoredAttachments(value: unknown): VaultAttachmentView[] {
  if (!Array.isArray(value) || value.length > MAX_ATTACHMENTS) {
    throw new VaultError('CORRUPT_VAULT')
  }
  const attachments = value.map(parseStoredAttachment)
  if (new Set(attachments.map((attachment) => attachment.id)).size !== attachments.length) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return attachments
}

export function cloneAttachments(
  attachments: readonly VaultAttachmentView[]
): VaultAttachmentView[] {
  return attachments.map((attachment) => ({ ...attachment }))
}

export function validateRemoteAttachments(value: unknown): VaultAttachmentView[] {
  try {
    return parseStoredAttachments(value)
  } catch {
    throw new VaultError('SYNC_FAILED')
  }
}
