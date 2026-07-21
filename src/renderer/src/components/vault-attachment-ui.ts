import type {
  AttachmentOperationKind,
  AttachmentOperationStage,
  AttachmentProgressEvent
} from '../../../shared/vault-contract'

export interface AttachmentOperationState extends AttachmentProgressEvent {
  fileName: string | null
  canceling: boolean
}

export interface AttachmentDeleteTarget {
  itemId: string
  attachmentId: string
  fileName: string
}

export const initialAttachmentStages: Record<AttachmentOperationKind, AttachmentOperationStage> = {
  download: 'choosing-file',
  upload: 'choosing-file',
  delete: 'deleting',
  'fix-legacy': 'downloading'
}

export function attachmentProgressPercent(progress: AttachmentProgressEvent): number | null {
  if (progress.totalBytes === null || progress.totalBytes <= 0) return null
  return Math.round(
    Math.min(100, Math.max(0, (progress.completedBytes / progress.totalBytes) * 100))
  )
}

export function isAttachmentCanceled(error: unknown): boolean {
  return error instanceof Error && error.message.includes('ATTACHMENT_CANCELED')
}
