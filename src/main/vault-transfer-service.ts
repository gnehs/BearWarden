import type {
  AttachmentCancelRequest,
  AttachmentCancelResult,
  AttachmentDeleteRequest,
  AttachmentDeleteResult,
  AttachmentDownloadRequest,
  AttachmentDownloadResult,
  AttachmentFixLegacyRequest,
  AttachmentFixLegacyResult,
  AttachmentPreviewRequest,
  AttachmentPreviewResult,
  AttachmentProgressEvent,
  AttachmentUploadCardCoverRequest,
  AttachmentUploadRequest,
  AttachmentUploadResult,
  VaultImportResult
} from '../shared/vault-contract'
import { type BitwardenSyncClient } from './bitwarden-direct'
import { BITWARDEN_POLICY_TYPE } from './bitwarden-policy'
import {
  buildBitwardenJson,
  parseBitwardenJson,
  type PortableVaultSnapshot
} from './vault-portability-codec'
import type {
  NativeAttachmentBackupEntry,
  NativeAttachmentBackupPreview
} from './native-attachment-backup'
import type { BitwardenAttachmentByteSource } from './bitwarden-attachment-stream'
import {
  beginNativeAttachmentRestoreAttempt,
  bindNativeAttachmentRestoreRemoteItem,
  completeNativeAttachmentRestoreAttempt,
  createNativeAttachmentRestoreJournal,
  reconcileNativeAttachmentRestoreMissing,
  reconcileNativeAttachmentRestoreUploaded,
  type NativeAttachmentRestoreAttachmentKey
} from './native-attachment-restore'
import { VaultError } from './vault-errors'
import { MAX_ATTACHMENT_ID_LENGTH } from './vault/limits'
import { assertUuid } from './vault/parse-primitives'
import { cloneData } from './vault/vault-data-parsing'
import {
  assertNoPendingLoginImport,
  assertNoPendingPersonalVaultPurge
} from './vault/sync-data-parsing'
import { cloneCustomFields } from './vault/custom-fields'
import { cloneLoginUris } from './vault/login-uris'
import { clonePasswordHistory } from './vault/password-history'
import type {
  VaultExportSnapshot,
  VaultNativeAttachmentBackupSource,
  VaultNativeAttachmentRestoreSummary
} from './vault/types'
import { type AttachmentAuthorizationValidator } from './vault-service-base'
import { VaultContentService } from './vault-content-service'

const MAX_ATTACHMENT_PREVIEW_BYTES = 10 * 1024 * 1024
const MAX_CARD_COVER_BYTES = 10 * 1024 * 1024
const CARD_COVER_CATALOG_ORIGIN = 'https://tw-card-catalog.gnehs.net'
const CARD_COVER_CATALOG_PATH_PREFIX = '/assets/cards/'

type AttachmentPreviewMediaType = AttachmentPreviewResult['mediaType']

interface CardCoverDownload {
  fileName: 'cover.jpg' | 'cover.webp'
  data: Buffer
}

function previewMediaType(fileName: string, data: Buffer): AttachmentPreviewMediaType | null {
  const extension = fileName.toLocaleLowerCase('en-US').split('.').pop()
  const magic = {
    jpeg: data.length >= 3 && data[0] === 0xff && data[1] === 0xd8 && data[2] === 0xff,
    png:
      data.length >= 8 &&
      data.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])),
    gif:
      data.length >= 6 &&
      (data.subarray(0, 6).equals(Buffer.from('GIF87a', 'ascii')) ||
        data.subarray(0, 6).equals(Buffer.from('GIF89a', 'ascii'))),
    webp:
      data.length >= 12 &&
      data.subarray(0, 4).equals(Buffer.from('RIFF', 'ascii')) &&
      data.subarray(8, 12).equals(Buffer.from('WEBP', 'ascii'))
  }

  if ((extension === 'jpg' || extension === 'jpeg') && magic.jpeg) return 'image/jpeg'
  if (extension === 'png' && magic.png) return 'image/png'
  if (extension === 'gif' && magic.gif) return 'image/gif'
  if (extension === 'webp' && magic.webp) return 'image/webp'
  if (magic.jpeg) return 'image/jpeg'
  if (magic.png) return 'image/png'
  if (magic.gif) return 'image/gif'
  if (magic.webp) return 'image/webp'
  return null
}

function extensionPreviewMediaType(fileName: string): AttachmentPreviewMediaType | null {
  const extension = fileName.toLocaleLowerCase('en-US').split('.').pop()
  if (extension === 'jpg' || extension === 'jpeg') return 'image/jpeg'
  if (extension === 'png') return 'image/png'
  if (extension === 'gif') return 'image/gif'
  if (extension === 'webp') return 'image/webp'
  return null
}

function parseCardCoverCatalogUrl(value: string): {
  url: URL
  fileName: CardCoverDownload['fileName']
} {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new VaultError('INVALID_INPUT')
  }
  if (
    url.origin !== CARD_COVER_CATALOG_ORIGIN ||
    !url.pathname.startsWith(CARD_COVER_CATALOG_PATH_PREFIX)
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  const extension = url.pathname.toLocaleLowerCase('en-US').split('.').pop()
  if (extension === 'webp') return { url, fileName: 'cover.webp' }
  if (extension === 'jpg' || extension === 'jpeg') return { url, fileName: 'cover.jpg' }
  throw new VaultError('INVALID_INPUT')
}

async function downloadCardCover(
  sourceUrl: string,
  signal: AbortSignal
): Promise<CardCoverDownload> {
  const { url, fileName } = parseCardCoverCatalogUrl(sourceUrl)
  const response = await fetch(url, { signal })
  if (!response.ok) throw new VaultError('ATTACHMENT_FAILED')
  const contentLength = response.headers.get('content-length')
  if (contentLength && Number(contentLength) > MAX_CARD_COVER_BYTES) {
    throw new VaultError('ATTACHMENT_TOO_LARGE')
  }
  const bytes = Buffer.from(await response.arrayBuffer())
  if (bytes.length > MAX_CARD_COVER_BYTES) {
    bytes.fill(0)
    throw new VaultError('ATTACHMENT_TOO_LARGE')
  }
  const mediaType = previewMediaType(fileName, bytes)
  if (mediaType !== 'image/jpeg' && mediaType !== 'image/webp') {
    bytes.fill(0)
    throw new VaultError('INVALID_INPUT')
  }
  return { fileName, data: bytes }
}

async function collectPreviewBytes(
  chunks: AsyncIterable<Buffer>,
  expectedSize: number,
  signal: AbortSignal
): Promise<Buffer> {
  if (expectedSize > MAX_ATTACHMENT_PREVIEW_BYTES) throw new VaultError('ATTACHMENT_TOO_LARGE')
  const buffers: Buffer[] = []
  let total = 0
  for await (const chunk of chunks) {
    if (signal.aborted) throw new VaultError('LOCKED')
    total += chunk.length
    if (total > MAX_ATTACHMENT_PREVIEW_BYTES) throw new VaultError('ATTACHMENT_TOO_LARGE')
    buffers.push(Buffer.from(chunk))
  }
  return Buffer.concat(buffers, total)
}

/** Attachment I/O, portable exports/imports, and resumable native attachment restoration. */
export class VaultTransferService extends VaultContentService {
  async downloadAttachment(
    request: AttachmentDownloadRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentDownloadResult> {
    const preflight = await this.exclusive(async () => {
      assertUuid(request.id)
      assertUuid(request.operationId)
      if (
        typeof request.attachmentId !== 'string' ||
        request.attachmentId.length === 0 ||
        request.attachmentId.length > MAX_ATTACHMENT_ID_LENGTH
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const data = this.requireData()
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      this.assertAttachmentAuthorized(login, validateAuthorization)
      const attachment = login.attachments.find((entry) => entry.id === request.attachmentId)
      if (!attachment) throw new VaultError('NOT_FOUND')
      const files = this.attachmentFiles
      if (!files) throw new VaultError('INTERNAL_ERROR')
      const sync = this.requireSyncData()
      const mapping = sync.loginMappings.find((entry) => entry.localId === login.id)
      if (!mapping) throw new VaultError('INVALID_INPUT')
      return { files, fileName: attachment.fileName, generation: this.generation }
    })

    this.reportAttachmentProgress(reportProgress, request, 'download', 'choosing-file', 0, null)
    // Electron's native save dialog is not abortable. Keep it outside the vault
    // mutex so auto-lock can clear keys even while the user leaves the dialog open.
    const destination = await preflight.files.chooseSavePath(preflight.fileName)
    if (destination === null) {
      return { canceled: true, fileName: preflight.fileName }
    }

    return this.exclusive(async () => {
      if (preflight.generation !== this.generation) throw new VaultError('LOCKED')
      assertUuid(request.id)
      const data = this.requireData()
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      this.assertAttachmentAuthorized(login, validateAuthorization)
      const attachment = login.attachments.find((entry) => entry.id === request.attachmentId)
      if (!attachment) throw new VaultError('NOT_FOUND')
      if (attachment.fileName !== preflight.fileName) {
        throw new VaultError('ATTACHMENT_FAILED')
      }
      const sync = this.requireSyncData()
      const mapping = sync.loginMappings.find((entry) => entry.localId === login.id)
      if (!mapping) throw new VaultError('INVALID_INPUT')
      const client = this.getOrCreateSyncClient(sync)
      const operation = this.startAttachmentOperation(request.operationId)
      const { abort } = operation
      let downloadedStream:
        Awaited<ReturnType<NonNullable<typeof client.downloadAttachmentStream>>> | undefined
      let clearText: Buffer | undefined
      try {
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'download',
          'downloading',
          0,
          attachment.size
        )
        if (abort.signal.aborted) throw new VaultError('LOCKED')
        const generation = this.generation
        const downloaded = client.downloadAttachmentStream
          ? await client.downloadAttachmentStream(mapping.remoteId, attachment.id, abort.signal)
          : await client.downloadAttachment(mapping.remoteId, attachment.id, abort.signal)
        if ('dispose' in downloaded) downloadedStream = downloaded
        else clearText = downloaded.data
        if (generation !== this.generation || abort.signal.aborted) {
          throw new VaultError('LOCKED')
        }
        if (downloaded.fileName !== attachment.fileName) {
          throw new VaultError('ATTACHMENT_FAILED')
        }
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'download',
          'downloading',
          attachment.size,
          attachment.size
        )
        if (downloadedStream) {
          await preflight.files.writeStream(destination, downloadedStream.data, abort.signal)
        } else {
          await preflight.files.write(destination, clearText!, abort.signal)
        }
        // The atomic rename is the commit point. Once the requested plaintext file exists,
        // report success even if a lock races with the final chmod/directory sync.
        return { canceled: false, fileName: attachment.fileName }
      } catch (error) {
        throw this.mapAttachmentError(error, operation)
      } finally {
        clearText?.fill(0)
        await downloadedStream?.dispose().catch(() => undefined)
        this.finishAttachmentOperation(operation)
      }
    })
  }

  async previewAttachment(
    request: AttachmentPreviewRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentPreviewResult> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      assertUuid(request.operationId)
      if (
        typeof request.attachmentId !== 'string' ||
        request.attachmentId.length === 0 ||
        request.attachmentId.length > MAX_ATTACHMENT_ID_LENGTH
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const data = this.requireData()
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      this.assertAttachmentAuthorized(login, validateAuthorization)
      const attachment = login.attachments.find((entry) => entry.id === request.attachmentId)
      if (!attachment) throw new VaultError('NOT_FOUND')
      const sync = this.requireSyncData()
      const mapping = sync.loginMappings.find((entry) => entry.localId === login.id)
      if (!mapping) throw new VaultError('INVALID_INPUT')
      const client = this.getOrCreateSyncClient(sync)
      const operation = this.startAttachmentOperation(request.operationId)
      let downloadedStream:
        Awaited<ReturnType<NonNullable<typeof client.downloadAttachmentStream>>> | undefined
      let clearText: Buffer | undefined
      try {
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'preview',
          'downloading',
          0,
          attachment.size
        )
        const downloaded = client.downloadAttachmentStream
          ? await client.downloadAttachmentStream(
              mapping.remoteId,
              attachment.id,
              operation.abort.signal
            )
          : await client.downloadAttachment(mapping.remoteId, attachment.id, operation.abort.signal)
        if (downloaded.fileName !== attachment.fileName) throw new VaultError('ATTACHMENT_FAILED')
        if ('dispose' in downloaded) {
          downloadedStream = downloaded
          clearText = await collectPreviewBytes(
            downloadedStream.data.chunks(operation.abort.signal),
            attachment.size,
            operation.abort.signal
          )
        } else {
          clearText = downloaded.data
          if (clearText.length > MAX_ATTACHMENT_PREVIEW_BYTES) {
            throw new VaultError('ATTACHMENT_TOO_LARGE')
          }
        }
        const mediaType =
          previewMediaType(attachment.fileName, clearText) ??
          extensionPreviewMediaType(attachment.fileName)
        if (!mediaType) throw new VaultError('INVALID_INPUT')
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'preview',
          'downloading',
          attachment.size,
          attachment.size
        )
        const dataUrl = `data:${mediaType};base64,${clearText.toString('base64')}`
        return { canceled: false, fileName: attachment.fileName, mediaType, dataUrl }
      } catch (error) {
        throw this.mapAttachmentError(error, operation)
      } finally {
        clearText?.fill(0)
        await downloadedStream?.dispose().catch(() => undefined)
        this.finishAttachmentOperation(operation)
      }
    })
  }

  async uploadAttachment(
    request: AttachmentUploadRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentUploadResult> {
    const preflight = await this.exclusive(async () => {
      assertUuid(request.id)
      assertUuid(request.operationId)
      const data = this.requireData()
      assertNoPendingPersonalVaultPurge(data.sync)
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      this.assertAttachmentAuthorized(login, validateAuthorization)
      const files = this.attachmentFiles
      if (!files) throw new VaultError('INTERNAL_ERROR')
      const sync = this.requireSyncData()
      if (!sync.loginMappings.some((entry) => entry.localId === login.id)) {
        throw new VaultError('INVALID_INPUT')
      }
      return { files, generation: this.generation }
    })

    this.reportAttachmentProgress(reportProgress, request, 'upload', 'choosing-file', 0, null)
    const selection = await preflight.files.chooseOpenFile()
    if (selection === null) return { canceled: true, attachment: null }

    return this.exclusive(async () => {
      if (preflight.generation !== this.generation) throw new VaultError('LOCKED')
      const data = this.requireData()
      assertNoPendingPersonalVaultPurge(data.sync)
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      this.assertAttachmentAuthorized(login, validateAuthorization)
      if (login.attachments.some((attachment) => attachment.fileName === selection.fileName)) {
        throw new VaultError('DUPLICATE_NAME')
      }
      const sync = this.requireSyncData()
      const mapping = sync.loginMappings.find((entry) => entry.localId === login.id)
      if (!mapping) throw new VaultError('INVALID_INPUT')
      const client = this.getOrCreateSyncClient(sync)
      const operation = this.startAttachmentOperation(request.operationId)
      let clearText: Buffer | undefined
      try {
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'upload',
          'reading-file',
          0,
          selection.size
        )
        const selectedSource = preflight.files.selectedFileSource(selection)
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'upload',
          'reading-file',
          selection.size,
          selection.size
        )
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'upload',
          'encrypting',
          0,
          selection.size
        )
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'upload',
          'uploading',
          0,
          selection.size
        )
        const uploaded = client.uploadAttachmentStream
          ? await client.uploadAttachmentStream(
              mapping.remoteId,
              selection.fileName,
              selectedSource,
              operation.abort.signal,
              () => this.commitAttachmentOperation(operation)
            )
          : await (async () => {
              clearText = await preflight.files.readSelectedFile(selection, operation.abort.signal)
              return client.uploadAttachment(
                mapping.remoteId,
                selection.fileName,
                clearText,
                operation.abort.signal,
                () => this.commitAttachmentOperation(operation)
              )
            })()
        this.commitAttachmentOperation(operation)
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'upload',
          'uploading',
          selection.size,
          selection.size
        )
        this.reportAttachmentProgress(reportProgress, request, 'upload', 'syncing', 0, null)
        await this.persistAttachmentMutation(data, client)
        const updated = this.findLogin(this.requireData(), request.id)
        const attachment = updated.attachments.find((entry) => entry.id === uploaded.id)
        if (!attachment || attachment.fileName !== selection.fileName || attachment.legacy) {
          throw new VaultError('ATTACHMENT_FAILED')
        }
        return { canceled: false, attachment: { ...attachment } }
      } catch (error) {
        throw this.mapAttachmentError(error, operation)
      } finally {
        clearText?.fill(0)
        this.finishAttachmentOperation(operation)
      }
    })
  }

  async uploadCardCoverAttachment(
    request: AttachmentUploadCardCoverRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentUploadResult> {
    const preflight = await this.exclusive(async () => {
      assertUuid(request.id)
      assertUuid(request.operationId)
      if (typeof request.sourceUrl !== 'string' || request.sourceUrl.length > 4096) {
        throw new VaultError('INVALID_INPUT')
      }
      parseCardCoverCatalogUrl(request.sourceUrl)
      const data = this.requireData()
      assertNoPendingPersonalVaultPurge(data.sync)
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      if (login.type !== 'card') throw new VaultError('INVALID_INPUT')
      this.assertAttachmentAuthorized(login, validateAuthorization)
      const sync = this.requireSyncData()
      if (!sync.loginMappings.some((entry) => entry.localId === login.id)) {
        throw new VaultError('INVALID_INPUT')
      }
      const operation = this.startAttachmentOperation(request.operationId)
      return { generation: this.generation, operation }
    })

    let clearText: Buffer | undefined
    try {
      this.reportAttachmentProgress(reportProgress, request, 'upload', 'downloading', 0, null)
      const cover = await downloadCardCover(request.sourceUrl, preflight.operation.abort.signal)
      clearText = cover.data
      this.reportAttachmentProgress(
        reportProgress,
        request,
        'upload',
        'downloading',
        clearText.length,
        clearText.length
      )

      return await this.exclusive(async () => {
        if (preflight.generation !== this.generation) throw new VaultError('LOCKED')
        const data = this.requireData()
        assertNoPendingPersonalVaultPurge(data.sync)
        const login = this.findLogin(data, request.id)
        this.assertActiveLogin(login)
        if (login.type !== 'card') throw new VaultError('INVALID_INPUT')
        this.assertAttachmentAuthorized(login, validateAuthorization)
        if (login.attachments.some((attachment) => attachment.fileName === cover.fileName)) {
          throw new VaultError('DUPLICATE_NAME')
        }
        const sync = this.requireSyncData()
        const mapping = sync.loginMappings.find((entry) => entry.localId === login.id)
        if (!mapping) throw new VaultError('INVALID_INPUT')
        const client = this.getOrCreateSyncClient(sync)
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'upload',
          'encrypting',
          0,
          cover.data.length
        )
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'upload',
          'uploading',
          0,
          cover.data.length
        )
        const uploaded = await client.uploadAttachment(
          mapping.remoteId,
          cover.fileName,
          cover.data,
          preflight.operation.abort.signal,
          () => this.commitAttachmentOperation(preflight.operation)
        )
        this.commitAttachmentOperation(preflight.operation)
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'upload',
          'uploading',
          cover.data.length,
          cover.data.length
        )
        this.reportAttachmentProgress(reportProgress, request, 'upload', 'syncing', 0, null)
        await this.persistAttachmentMutation(data, client)
        const updated = this.findLogin(this.requireData(), request.id)
        const attachment = updated.attachments.find((entry) => entry.id === uploaded.id)
        if (!attachment || attachment.fileName !== cover.fileName || attachment.legacy) {
          throw new VaultError('ATTACHMENT_FAILED')
        }
        return { canceled: false, attachment: { ...attachment } }
      })
    } catch (error) {
      throw this.mapAttachmentError(error, preflight.operation)
    } finally {
      clearText?.fill(0)
      this.finishAttachmentOperation(preflight.operation)
    }
  }

  deleteAttachment(
    request: AttachmentDeleteRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentDeleteResult> {
    return this.exclusive(async () => {
      const { data, attachment, mapping, client } = this.attachmentMutationContext(
        request,
        validateAuthorization
      )
      const operation = this.startAttachmentOperation(request.operationId)
      try {
        this.reportAttachmentProgress(reportProgress, request, 'delete', 'deleting', 0, null)
        await client.deleteAttachment(mapping.remoteId, attachment.id, operation.abort.signal, () =>
          this.commitAttachmentOperation(operation)
        )
        this.commitAttachmentOperation(operation)
        this.reportAttachmentProgress(reportProgress, request, 'delete', 'syncing', 0, null)
        await this.persistAttachmentMutation(data, client)
        const updated = this.findLogin(this.requireData(), request.id)
        if (updated.attachments.some((entry) => entry.id === attachment.id)) {
          throw new VaultError('ATTACHMENT_FAILED')
        }
        return { attachmentId: attachment.id }
      } catch (error) {
        throw this.mapAttachmentError(error, operation)
      } finally {
        this.finishAttachmentOperation(operation)
      }
    })
  }

  fixLegacyAttachment(
    request: AttachmentFixLegacyRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentFixLegacyResult> {
    return this.exclusive(async () => {
      const { data, attachment, mapping, client } = this.attachmentMutationContext(
        request,
        validateAuthorization
      )
      if (!attachment.legacy) throw new VaultError('INVALID_INPUT')
      const operation = this.startAttachmentOperation(request.operationId)
      try {
        this.reportAttachmentProgress(
          reportProgress,
          request,
          'fix-legacy',
          'downloading',
          0,
          attachment.size
        )
        const upgraded = await client.upgradeLegacyAttachment(
          mapping.remoteId,
          attachment.id,
          operation.abort.signal,
          () => this.commitAttachmentOperation(operation)
        )
        this.commitAttachmentOperation(operation)
        this.reportAttachmentProgress(reportProgress, request, 'fix-legacy', 'syncing', 0, null)
        await this.persistAttachmentMutation(data, client)
        const updated = this.findLogin(this.requireData(), request.id)
        if (updated.attachments.some((entry) => entry.id === attachment.id)) {
          throw new VaultError('ATTACHMENT_FAILED')
        }
        const replacement = updated.attachments.find((entry) => entry.id === upgraded.id)
        if (!replacement || replacement.fileName !== attachment.fileName || replacement.legacy) {
          throw new VaultError('ATTACHMENT_FAILED')
        }
        return { attachment: { ...replacement } }
      } catch (error) {
        throw this.mapAttachmentError(error, operation)
      } finally {
        this.finishAttachmentOperation(operation)
      }
    })
  }

  cancelAttachmentOperation(request: AttachmentCancelRequest): AttachmentCancelResult {
    assertUuid(request.operationId)
    const active = this.activeAttachmentOperation
    if (
      !active ||
      active.operationId !== request.operationId ||
      active.committed ||
      active.abort.signal.aborted
    ) {
      return { canceled: false }
    }
    active.canceledByUser = true
    active.abort.abort()
    return { canceled: true }
  }

  verifyPortabilityOwner(masterPassword: string): Promise<void> {
    return this.exclusive(() => this.assertMasterPassword(masterPassword))
  }

  exportPortableSnapshot(masterPassword: string): Promise<VaultExportSnapshot> {
    return this.exclusive(async () => {
      await this.assertMasterPassword(masterPassword)
      const data = this.requireData()
      this.assertBitwardenPolicyDoesNotBlock(
        BITWARDEN_POLICY_TYPE.DisablePersonalVaultExport,
        'POLICY_RESTRICTED',
        data
      )
      const snapshot = this.localSyncSnapshot(data)
      const items = snapshot.logins.filter((item) => item.deletedAt === null)
      return {
        snapshot: {
          folders: snapshot.folders.map((folder) => ({ ...folder })),
          items: items.map((item) => ({
            ...item,
            uris: cloneLoginUris(item.uris),
            passkeys: item.passkeys.map((passkey) => ({ ...passkey })),
            customFields: cloneCustomFields(item.customFields),
            passwordHistory: clonePasswordHistory(item.passwordHistory)
          }))
        },
        skippedTrashItems: snapshot.logins.length - items.length
      }
    })
  }

  async createNativeAttachmentBackupSource(
    masterPassword: string,
    options: { includeLoginWireMetadata?: boolean } = {}
  ): Promise<VaultNativeAttachmentBackupSource> {
    // Bitwarden's attachment metadata contains encrypted-envelope size, while the native archive
    // requires exact plaintext sizes in its authenticated manifest. Preflight therefore downloads,
    // authenticates and counts every plaintext once without retaining it. Each later open (including
    // a resume) deliberately re-downloads and re-authenticates the complete ciphertext before bytes
    // at the committed offset are yielded. A native export consequently transfers attachments twice.
    type Candidate = NativeAttachmentBackupEntry & { remoteItemId: string }
    const prepared = await this.exclusive(async () => {
      await this.assertMasterPassword(masterPassword)
      const data = this.requireData()
      this.assertBitwardenPolicyDoesNotBlock(
        BITWARDEN_POLICY_TYPE.DisablePersonalVaultExport,
        'POLICY_RESTRICTED',
        data
      )
      assertNoPendingPersonalVaultPurge(data.sync)
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const snapshot = this.localSyncSnapshot(data)
      const activeItems = snapshot.logins.filter((item) => item.deletedAt === null)
      const candidates: Candidate[] = []
      for (const item of data.logins.filter((login) => login.deletedAt === null)) {
        const mapping = sync.loginMappings.find((entry) => entry.localId === item.id)
        if (!mapping) continue
        for (const attachment of item.attachments) {
          candidates.push({
            id: attachment.id,
            itemId: item.id,
            fileName: attachment.fileName,
            size: 0,
            remoteItemId: mapping.remoteId
          })
        }
      }
      const abort = new AbortController()
      this.nativeAttachmentBackupAborts.add(abort)
      const portable: PortableVaultSnapshot = {
        folders: snapshot.folders.map((folder) => ({ ...folder })),
        items: activeItems.map((item) => ({
          ...item,
          uris: cloneLoginUris(item.uris),
          passkeys: item.passkeys.map((passkey) => ({ ...passkey })),
          customFields: cloneCustomFields(item.customFields),
          passwordHistory: clonePasswordHistory(item.passwordHistory)
        }))
      }
      return {
        abort,
        candidates,
        client,
        generation: this.generation,
        portable,
        skippedTrashItems: snapshot.logins.length - activeItems.length
      }
    })

    let disposed = false
    const ensureCurrent = (): void => {
      if (
        disposed ||
        prepared.abort.signal.aborted ||
        prepared.generation !== this.generation ||
        this.syncClient !== prepared.client ||
        !this.data?.sync?.state.session
      ) {
        throw new VaultError('LOCKED')
      }
    }
    const download = async (
      candidate: Candidate,
      consume: (chunks: AsyncIterable<Buffer>) => Promise<number>
    ): Promise<number> => {
      ensureCurrent()
      let streamed:
        | Awaited<ReturnType<NonNullable<BitwardenSyncClient['downloadAttachmentStream']>>>
        | undefined
      let clearText: Buffer | undefined
      try {
        const result = prepared.client.downloadAttachmentStream
          ? await prepared.client.downloadAttachmentStream(
              candidate.remoteItemId,
              candidate.id,
              prepared.abort.signal
            )
          : await prepared.client.downloadAttachment(
              candidate.remoteItemId,
              candidate.id,
              prepared.abort.signal
            )
        ensureCurrent()
        if (result.fileName !== candidate.fileName) throw new VaultError('ATTACHMENT_FAILED')
        if ('dispose' in result) streamed = result
        else clearText = result.data
        const chunks: AsyncIterable<Buffer> = streamed
          ? streamed.data.chunks(prepared.abort.signal)
          : (async function* (): AsyncIterable<Buffer> {
              yield clearText!
            })()
        return await consume(chunks)
      } catch (error) {
        if (prepared.abort.signal.aborted || prepared.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof VaultError) throw error
        throw new VaultError('ATTACHMENT_FAILED')
      } finally {
        clearText?.fill(0)
        await streamed?.dispose().catch(() => undefined)
      }
    }

    try {
      const entries: NativeAttachmentBackupEntry[] = []
      for (const candidate of prepared.candidates) {
        const size = await download(candidate, async (chunks) => {
          let bytes = 0
          for await (const chunk of chunks) {
            try {
              bytes += chunk.length
            } finally {
              chunk.fill(0)
            }
          }
          return bytes
        })
        entries.push({
          id: candidate.id,
          itemId: candidate.itemId,
          fileName: candidate.fileName,
          size
        })
      }
      ensureCurrent()
      const source: VaultNativeAttachmentBackupSource = {
        vaultJson: buildBitwardenJson(prepared.portable, {
          includeLoginWireMetadata: options.includeLoginWireMetadata === true
        }),
        attachments: entries,
        exportedFolders: prepared.portable.folders.length,
        exportedItems: prepared.portable.items.length,
        skippedTrashItems: prepared.skippedTrashItems,
        openAttachment: (entry, offset, signal) => {
          const index = entries.findIndex(
            (candidate) =>
              candidate.id === entry.id &&
              candidate.itemId === entry.itemId &&
              candidate.fileName === entry.fileName &&
              candidate.size === entry.size
          )
          if (index < 0 || !Number.isSafeInteger(offset) || offset < 0 || offset > entry.size) {
            throw new VaultError('INVALID_INPUT')
          }
          const candidate = prepared.candidates[index]!
          return (async function* (): AsyncIterable<Buffer> {
            ensureCurrent()
            const operationSignal = signal
              ? AbortSignal.any([prepared.abort.signal, signal])
              : prepared.abort.signal
            let skipped = 0
            let total = 0
            let streamed:
              | Awaited<ReturnType<NonNullable<BitwardenSyncClient['downloadAttachmentStream']>>>
              | undefined
            let clearText: Buffer | undefined
            try {
              const result = prepared.client.downloadAttachmentStream
                ? await prepared.client.downloadAttachmentStream(
                    candidate.remoteItemId,
                    candidate.id,
                    operationSignal
                  )
                : await prepared.client.downloadAttachment(
                    candidate.remoteItemId,
                    candidate.id,
                    operationSignal
                  )
              ensureCurrent()
              if (result.fileName !== candidate.fileName) {
                throw new VaultError('ATTACHMENT_FAILED')
              }
              if ('dispose' in result) streamed = result
              else clearText = result.data
              const chunks: AsyncIterable<Buffer> = streamed
                ? streamed.data.chunks(operationSignal)
                : (async function* (): AsyncIterable<Buffer> {
                    yield clearText!
                  })()
              for await (const chunk of chunks) {
                if (operationSignal.aborted) throw new VaultError('LOCKED')
                total += chunk.length
                if (skipped + chunk.length <= offset) {
                  skipped += chunk.length
                  chunk.fill(0)
                  continue
                }
                const start = Math.max(0, offset - skipped)
                if (start > 0) chunk.subarray(0, start).fill(0)
                skipped += chunk.length
                yield chunk.subarray(start)
              }
              if (total !== entry.size) throw new VaultError('ATTACHMENT_FAILED')
            } catch (error) {
              if (prepared.abort.signal.aborted) {
                throw new VaultError('LOCKED')
              }
              if (error instanceof VaultError) throw error
              throw new VaultError('ATTACHMENT_FAILED')
            } finally {
              clearText?.fill(0)
              await streamed?.dispose().catch(() => undefined)
            }
          })()
        },
        dispose: () => {
          if (disposed) return
          disposed = true
          prepared.abort.abort()
          this.nativeAttachmentBackupAborts.delete(prepared.abort)
        }
      }
      return source
    } catch (error) {
      disposed = true
      prepared.abort.abort()
      this.nativeAttachmentBackupAborts.delete(prepared.abort)
      throw error
    }
  }

  nativeAttachmentRestoreStatus(): Promise<VaultNativeAttachmentRestoreSummary | null> {
    return this.exclusive(async () => {
      const journal = this.requireData().nativeAttachmentRestore
      return journal ? this.nativeAttachmentRestoreSummary(journal) : null
    })
  }

  clearCompletedNativeAttachmentRestore(archiveFingerprint: string): Promise<void> {
    return this.exclusive(async () => {
      const current = this.requireData()
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const journal = this.requireBoundNativeAttachmentRestore(
        current,
        archiveFingerprint,
        sync,
        client
      )
      if (journal.phase !== 'complete') throw new VaultError('INVALID_INPUT')
      const next = cloneData(current)
      next.nativeAttachmentRestore = null
      next.updatedAt = this.nowIso()
      await this.persist(next)
      this.data = next
    })
  }

  beginNativeAttachmentRestore(
    preview: NativeAttachmentBackupPreview,
    masterPassword: string
  ): Promise<VaultNativeAttachmentRestoreSummary> {
    return this.exclusive(async () => {
      await this.assertMasterPassword(masterPassword)
      const current = this.requireData()
      this.assertBitwardenPolicyDoesNotBlock(
        BITWARDEN_POLICY_TYPE.OrganizationDataOwnership,
        'POLICY_RESTRICTED',
        current
      )
      assertNoPendingPersonalVaultPurge(current.sync)
      assertNoPendingLoginImport(current.sync)
      if (current.nativeAttachmentRestore !== null) throw new VaultError('INVALID_INPUT')
      if (
        !preview ||
        typeof preview.vaultJson !== 'string' ||
        !Array.isArray(preview.attachments) ||
        !Array.isArray(preview.attachmentDigests) ||
        preview.attachments.length !== preview.attachmentDigests.length
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const operation = this.startNativeAttachmentRestoreOperation(client)
      try {
        await client.sync(operation.abort.signal)
        this.assertNativeAttachmentRestoreLease(operation)
        const accountFingerprint = this.nativeAttachmentRestoreAccountFingerprint(sync, client)
        const parsed = parseBitwardenJson(preview.vaultJson)
        if (parsed.skippedTrashItems !== 0) throw new VaultError('INVALID_INPUT')
        for (const item of parsed.snapshot.items)
          this.assertPersonalItemTypeAllowed(item.type, current)
        const next = cloneData(this.requireData())
        const imported = this.appendPortableSnapshot(next, parsed.snapshot)
        const sourceItemIds = new Set(parsed.snapshot.items.map((item) => item.id))
        const attachments = preview.attachments.map((attachment, index) => {
          if (!sourceItemIds.has(attachment.itemId)) throw new VaultError('INVALID_INPUT')
          return {
            sourceItemId: attachment.itemId,
            sourceAttachmentId: attachment.id,
            fileName: attachment.fileName,
            size: attachment.size,
            digest: preview.attachmentDigests[index]!
          }
        })
        const now = this.nowIso()
        next.nativeAttachmentRestore = createNativeAttachmentRestoreJournal({
          archiveFingerprint: preview.archiveFingerprint,
          accountFingerprint,
          createdAt: now,
          items: imported.itemMappings,
          attachments
        })
        next.updatedAt = now
        await this.persist(next)
        this.assertNativeAttachmentRestoreLease(operation)
        this.data = next
        return this.nativeAttachmentRestoreSummary(next.nativeAttachmentRestore)
      } catch (error) {
        if (operation.abort.signal.aborted || operation.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof VaultError) throw error
        throw new VaultError('SYNC_FAILED')
      } finally {
        this.finishNativeAttachmentRestoreOperation(operation)
      }
    })
  }

  syncNativeAttachmentRestoreItems(
    archiveFingerprint: string
  ): Promise<VaultNativeAttachmentRestoreSummary> {
    return this.exclusive(async () => {
      const current = this.requireData()
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const journal = this.requireBoundNativeAttachmentRestore(
        current,
        archiveFingerprint,
        sync,
        client
      )
      if (journal.phase !== 'syncing-items') return this.nativeAttachmentRestoreSummary(journal)
      const operation = this.startNativeAttachmentRestoreOperation(client)
      try {
        await this.performSync(current, client, operation.abort.signal)
        this.assertNativeAttachmentRestoreLease(operation)
        const next = cloneData(this.requireData())
        let updated = next.nativeAttachmentRestore
        if (!updated || !next.sync) throw new VaultError('SYNC_FAILED')
        for (const item of updated.items.filter((candidate) => candidate.remoteItemId === null)) {
          const mapping = next.sync.loginMappings.find(
            (entry) => entry.localId === item.localItemId
          )
          if (!mapping) throw new VaultError('SYNC_FAILED')
          updated = bindNativeAttachmentRestoreRemoteItem(
            updated,
            item.sourceItemId,
            mapping.remoteId,
            this.nowIso()
          )
        }
        next.nativeAttachmentRestore = updated
        next.updatedAt = updated.updatedAt
        await this.persist(next)
        this.assertNativeAttachmentRestoreLease(operation)
        this.data = next
        return this.nativeAttachmentRestoreSummary(updated)
      } finally {
        this.finishNativeAttachmentRestoreOperation(operation)
      }
    })
  }

  uploadNativeAttachmentRestoreEntry(
    archiveFingerprint: string,
    key: NativeAttachmentRestoreAttachmentKey,
    source: BitwardenAttachmentByteSource
  ): Promise<VaultNativeAttachmentRestoreSummary> {
    return this.exclusive(async () => {
      const current = this.requireData()
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const journal = this.requireBoundNativeAttachmentRestore(
        current,
        archiveFingerprint,
        sync,
        client
      )
      const target = journal.attachments.find(
        (attachment) =>
          attachment.sourceItemId === key.sourceItemId &&
          attachment.sourceAttachmentId === key.sourceAttachmentId
      )
      const item = journal.items.find((candidate) => candidate.sourceItemId === key.sourceItemId)
      if (!target || !item?.remoteItemId || source?.size !== target.size) {
        throw new VaultError('INVALID_INPUT')
      }
      if (!client.uploadAttachmentStream) throw new VaultError('ATTACHMENT_FAILED')
      const operation = this.startNativeAttachmentRestoreOperation(client)
      try {
        const attempting = cloneData(current)
        if (!attempting.nativeAttachmentRestore) throw new VaultError('INVALID_INPUT')
        attempting.nativeAttachmentRestore = beginNativeAttachmentRestoreAttempt(
          attempting.nativeAttachmentRestore,
          key,
          this.nowIso()
        )
        attempting.updatedAt = attempting.nativeAttachmentRestore.updatedAt
        await this.persist(attempting)
        this.data = attempting
        this.assertNativeAttachmentRestoreLease(operation)
        const uploaded = await client.uploadAttachmentStream(
          item.remoteItemId,
          target.fileName,
          source,
          operation.abort.signal
        )
        this.assertNativeAttachmentRestoreLease(operation)
        await client.sync(operation.abort.signal)
        const [remoteFolders, remoteLogins] = await Promise.all([
          client.listFolders(operation.abort.signal),
          client.listPersonalLogins(operation.abort.signal)
        ])
        this.assertNativeAttachmentRestoreLease(operation)
        const authoritativeItem = remoteLogins.find(
          (candidate) => candidate.id === item.remoteItemId
        )
        if (
          authoritativeItem?.attachments.filter(
            (attachment) => attachment.id === uploaded.id && attachment.fileName === target.fileName
          ).length !== 1
        ) {
          throw new VaultError('ATTACHMENT_FAILED')
        }
        const next = this.applyNativeAttachmentRestoreRemoteSnapshot(
          this.requireData(),
          client,
          remoteFolders,
          remoteLogins
        )
        if (!next.nativeAttachmentRestore) throw new VaultError('ATTACHMENT_FAILED')
        next.nativeAttachmentRestore = completeNativeAttachmentRestoreAttempt(
          next.nativeAttachmentRestore,
          key,
          uploaded.id,
          this.nowIso()
        )
        next.updatedAt = next.nativeAttachmentRestore.updatedAt
        await this.persist(next)
        this.data = next
        return this.nativeAttachmentRestoreSummary(next.nativeAttachmentRestore)
      } catch (error) {
        let reconciliationPersistenceError: unknown = null
        try {
          await this.persistFailedNativeAttachmentRestoreAttempt(key)
        } catch (persistError) {
          reconciliationPersistenceError = persistError
        }
        if (operation.abort.signal.aborted || operation.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (reconciliationPersistenceError) throw reconciliationPersistenceError
        if (error instanceof VaultError) throw error
        throw new VaultError('ATTACHMENT_FAILED')
      } finally {
        this.finishNativeAttachmentRestoreOperation(operation)
      }
    })
  }

  reconcileNativeAttachmentRestoreEntry(
    archiveFingerprint: string,
    key: NativeAttachmentRestoreAttachmentKey
  ): Promise<{
    outcome: 'uploaded' | 'missing' | 'conflict'
    summary: VaultNativeAttachmentRestoreSummary
  }> {
    return this.exclusive(async () => {
      const current = this.requireData()
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      const journal = this.requireBoundNativeAttachmentRestore(
        current,
        archiveFingerprint,
        sync,
        client
      )
      const target = journal.attachments.find(
        (attachment) =>
          attachment.sourceItemId === key.sourceItemId &&
          attachment.sourceAttachmentId === key.sourceAttachmentId
      )
      const item = journal.items.find((candidate) => candidate.sourceItemId === key.sourceItemId)
      if (!target || target.status !== 'needs-reconciliation' || !item?.remoteItemId) {
        throw new VaultError('INVALID_INPUT')
      }
      const operation = this.startNativeAttachmentRestoreOperation(client)
      try {
        await client.sync(operation.abort.signal)
        const [remoteFolders, remoteLogins] = await Promise.all([
          client.listFolders(operation.abort.signal),
          client.listPersonalLogins(operation.abort.signal)
        ])
        this.assertNativeAttachmentRestoreLease(operation)
        const remoteItem = remoteLogins.find((candidate) => candidate.id === item.remoteItemId)
        const candidates =
          remoteItem?.attachments.filter((attachment) => attachment.fileName === target.fileName) ??
          []
        let outcome: 'uploaded' | 'missing' | 'conflict' = 'conflict'
        let remoteAttachmentId: string | null = null
        if (remoteItem && candidates.length === 0) {
          outcome = 'missing'
        } else if (remoteItem && candidates.length === 1) {
          const candidate = candidates[0]!
          if (
            await this.nativeAttachmentRestoreCandidateMatches(
              client,
              item.remoteItemId,
              candidate.id,
              target.fileName,
              target.size,
              target.digest,
              operation.abort.signal
            )
          ) {
            outcome = 'uploaded'
            remoteAttachmentId = candidate.id
          }
        }
        this.assertNativeAttachmentRestoreLease(operation)
        const next = remoteItem
          ? this.applyNativeAttachmentRestoreRemoteSnapshot(
              this.requireData(),
              client,
              remoteFolders,
              remoteLogins
            )
          : (() => {
              const preserved = cloneData(this.requireData())
              if (!preserved.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
              preserved.sync.state = client.exportState()
              preserved.sync.lastSyncAt = this.nowIso()
              return preserved
            })()
        if (!next.nativeAttachmentRestore) throw new VaultError('ATTACHMENT_FAILED')
        if (outcome === 'missing') {
          next.nativeAttachmentRestore = reconcileNativeAttachmentRestoreMissing(
            next.nativeAttachmentRestore,
            key,
            this.nowIso()
          )
        } else if (outcome === 'uploaded' && remoteAttachmentId) {
          next.nativeAttachmentRestore = reconcileNativeAttachmentRestoreUploaded(
            next.nativeAttachmentRestore,
            key,
            remoteAttachmentId,
            this.nowIso()
          )
        }
        next.updatedAt = next.nativeAttachmentRestore.updatedAt
        await this.persist(next)
        this.data = next
        return {
          outcome,
          summary: this.nativeAttachmentRestoreSummary(next.nativeAttachmentRestore)
        }
      } catch (error) {
        if (operation.abort.signal.aborted || operation.generation !== this.generation) {
          throw new VaultError('LOCKED')
        }
        if (error instanceof VaultError) throw error
        throw new VaultError('ATTACHMENT_FAILED')
      } finally {
        this.finishNativeAttachmentRestoreOperation(operation)
      }
    })
  }

  importPortableSnapshot(
    snapshot: PortableVaultSnapshot,
    skippedTrashItems: number,
    masterPassword: string
  ): Promise<Omit<VaultImportResult, 'canceled'>> {
    return this.exclusive(async () => {
      await this.assertMasterPassword(masterPassword)
      const current = this.requireData()
      this.assertBitwardenPolicyDoesNotBlock(
        BITWARDEN_POLICY_TYPE.OrganizationDataOwnership,
        'POLICY_RESTRICTED',
        current
      )
      assertNoPendingPersonalVaultPurge(current.sync)
      if (
        !snapshot ||
        !Array.isArray(snapshot.folders) ||
        !Array.isArray(snapshot.items) ||
        !Number.isSafeInteger(skippedTrashItems) ||
        skippedTrashItems < 0
      ) {
        throw new VaultError('INVALID_INPUT')
      }

      if (snapshot.folders.length === 0 && snapshot.items.length === 0) {
        return { importedFolders: 0, importedItems: 0, skippedTrashItems }
      }

      for (const item of snapshot.items) this.assertPersonalItemTypeAllowed(item.type, current)

      const next = cloneData(current)
      const generation = this.generation
      try {
        this.appendPortableSnapshot(next, snapshot)
      } catch (error) {
        if (error instanceof VaultError && error.code === 'INVALID_INPUT') throw error
        throw new VaultError('INVALID_INPUT')
      }

      next.updatedAt = this.nowIso()
      await this.persist(next)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      this.data = next
      return {
        importedFolders: snapshot.folders.length,
        importedItems: snapshot.items.length,
        skippedTrashItems
      }
    })
  }
}
