import { describe, expect, it } from 'vitest'
import type { AttachmentProgressEvent } from '../../../shared/vault-contract'
import {
  attachmentProgressPercent,
  initialAttachmentStages,
  isCardCoverAttachment,
  isAttachmentCanceled,
  isPreviewableImageAttachment
} from './vault-attachment-ui'

function progress(overrides: Partial<AttachmentProgressEvent> = {}): AttachmentProgressEvent {
  return {
    operationId: 'operation-id',
    itemId: 'item-id',
    kind: 'download',
    stage: 'downloading',
    completedBytes: 0,
    totalBytes: 100,
    ...overrides
  }
}

describe('attachmentProgressPercent', () => {
  it('returns no percentage when the total is unknown or invalid', () => {
    expect(attachmentProgressPercent(progress({ totalBytes: null }))).toBeNull()
    expect(attachmentProgressPercent(progress({ totalBytes: 0 }))).toBeNull()
    expect(attachmentProgressPercent(progress({ totalBytes: -1 }))).toBeNull()
  })

  it('rounds progress and clamps it to the valid range', () => {
    expect(attachmentProgressPercent(progress({ completedBytes: 33, totalBytes: 200 }))).toBe(17)
    expect(attachmentProgressPercent(progress({ completedBytes: -10 }))).toBe(0)
    expect(attachmentProgressPercent(progress({ completedBytes: 150 }))).toBe(100)
  })
})

describe('attachment operation policy', () => {
  it('maps each operation to its initial stage', () => {
    expect(initialAttachmentStages).toEqual({
      download: 'choosing-file',
      preview: 'downloading',
      upload: 'choosing-file',
      delete: 'deleting',
      'fix-legacy': 'downloading'
    })
  })

  it('classifies previewable images and card cover attachments by safe file name', () => {
    expect(isPreviewableImageAttachment('receipt.PNG')).toBe(true)
    expect(isPreviewableImageAttachment('cover.webp')).toBe(true)
    expect(isPreviewableImageAttachment('diagram.svg')).toBe(false)
    expect(isCardCoverAttachment('cover.jpg')).toBe(true)
    expect(isCardCoverAttachment('cover.webp')).toBe(true)
    expect(isCardCoverAttachment('front.webp')).toBe(false)
  })

  it('recognizes only Error instances with the attachment cancellation code', () => {
    expect(isAttachmentCanceled(new Error('ATTACHMENT_CANCELED: user canceled'))).toBe(true)
    expect(isAttachmentCanceled(new Error('ATTACHMENT_FAILED'))).toBe(false)
    expect(isAttachmentCanceled('ATTACHMENT_CANCELED')).toBe(false)
  })
})
