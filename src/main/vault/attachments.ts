import type { VaultCore } from './core'
import type { VaultSyncSession } from './sync-session'
import type {
  AttachmentOperationKind,
  AttachmentOperationStage,
  AttachmentProgressEvent,
  AttachmentTargetRequest,
  CardCoverPreviewResult,
  LoginIdRequest,
  VaultAttachmentView,
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
  AttachmentUploadCardCoverRequest,
  AttachmentUploadRequest,
  AttachmentUploadResult
} from '../../shared/vault-contract'
import { BitwardenDirectError, type BitwardenSyncClient } from '../bitwarden-direct'
import {
  clearImageCacheKeys,
  type EncryptedImageCache,
  type ImageCacheKeys
} from '../encrypted-image-cache'
import { ConcurrencyLimiter, ImageMemoryCache } from '../image-memory-cache'
import { VaultError } from '../vault-errors'
import type { VaultAttachmentFileService } from '../vault-attachment-files'
import { MAX_ATTACHMENT_ID_LENGTH } from './limits'
import { assertUuid } from './parse-primitives'
import { cloneData } from './vault-data-parsing'
import { assertNoPendingPersonalVaultPurge } from './sync-data-parsing'
import type {
  StoredLogin,
  SyncEntityMapping,
  PersistedSyncData,
  VaultData,
  AttachmentAuthorizationValidator
} from './types'
import { findLogin, assertActiveLogin } from './data-lookup'
import { reconcileServerAuthoritativeAttachments } from './sync-snapshots'
import { isCardCoverAttachment } from '../../shared/card-cover'

const MAX_ATTACHMENT_PREVIEW_BYTES = 10 * 1024 * 1024

const MAX_CARD_COVER_BYTES = 10 * 1024 * 1024

const CARD_COVER_CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000

const CARD_COVER_CATALOG_ORIGIN = 'https://tw-card-catalog.gnehs.net'

const CARD_COVER_CATALOG_PATH_PREFIX = '/assets/cards/'

type AttachmentPreviewMediaType = AttachmentPreviewResult['mediaType']

interface CardCoverDownload {
  fileName: 'cover.jpg' | 'cover.png' | 'cover.webp'
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
  fileName: Extract<CardCoverDownload['fileName'], 'cover.jpg' | 'cover.webp'>
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

function cardCoverFileName(mediaType: AttachmentPreviewMediaType): CardCoverDownload['fileName'] {
  if (mediaType === 'image/jpeg') return 'cover.jpg'
  if (mediaType === 'image/png') return 'cover.png'
  if (mediaType === 'image/webp') return 'cover.webp'
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

/**
 * Item attachments: download, preview, upload, delete and legacy-key repair, plus card cover
 * images. Every network transfer runs under the session's single sync-operation lease.
 */
export class VaultAttachments {
  private readonly cardCoverCache = new ImageMemoryCache<CardCoverPreviewResult>({
    maxEntries: 256,
    maxSize: 64 * 1024 * 1024
  })
  private readonly cardCoverRequests = new Map<string, Promise<CardCoverPreviewResult | null>>()
  private readonly cardCoverDownloads = new ConcurrencyLimiter(3)
  /** Aborted on lock so detached image downloads stop as soon as the vault key is gone. */
  private readonly imageRequestAborts = new Set<AbortController>()

  constructor(
    private readonly core: VaultCore,
    private readonly syncSession: VaultSyncSession,
    private readonly attachmentFiles: VaultAttachmentFileService | null,
    private readonly imageCache: EncryptedImageCache | null
  ) {
    core.registerResource({
      abort: () => {
        for (const abort of this.imageRequestAborts) abort.abort()
        this.imageRequestAborts.clear()
      },
      clear: () => {
        this.cardCoverCache.clear()
        this.cardCoverRequests.clear()
      }
    })
  }

  /** Callers must zero the keys with `clearImageCacheKeys`. */
  private imageCacheKeys(): ImageCacheKeys | null {
    if (!this.imageCache) return null
    return this.core.imageCacheKeys()
  }

  async downloadAttachment(
    request: AttachmentDownloadRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentDownloadResult> {
    const preflight = await this.core.exclusive(async () => {
      assertUuid(request.id)
      assertUuid(request.operationId)
      if (
        typeof request.attachmentId !== 'string' ||
        request.attachmentId.length === 0 ||
        request.attachmentId.length > MAX_ATTACHMENT_ID_LENGTH
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const data = this.core.requireData()
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      this.assertAttachmentAuthorized(login, validateAuthorization)
      const attachment = login.attachments.find((entry) => entry.id === request.attachmentId)
      if (!attachment) throw new VaultError('NOT_FOUND')
      const files = this.attachmentFiles
      if (!files) throw new VaultError('INTERNAL_ERROR')
      const sync = this.syncSession.requireSyncData()
      const mapping = sync.loginMappings.find((entry) => entry.localId === login.id)
      if (!mapping) throw new VaultError('INVALID_INPUT')
      return { files, fileName: attachment.fileName, generation: this.core.generation }
    })

    this.reportAttachmentProgress(reportProgress, request, 'download', 'choosing-file', 0, null)
    // Electron's native save dialog is not abortable. Keep it outside the vault
    // mutex so auto-lock can clear keys even while the user leaves the dialog open.
    const destination = await preflight.files.chooseSavePath(preflight.fileName)
    if (destination === null) {
      return { canceled: true, fileName: preflight.fileName }
    }

    return this.core.exclusive(async () => {
      if (preflight.generation !== this.core.generation) throw new VaultError('LOCKED')
      assertUuid(request.id)
      const data = this.core.requireData()
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      this.assertAttachmentAuthorized(login, validateAuthorization)
      const attachment = login.attachments.find((entry) => entry.id === request.attachmentId)
      if (!attachment) throw new VaultError('NOT_FOUND')
      if (attachment.fileName !== preflight.fileName) {
        throw new VaultError('ATTACHMENT_FAILED')
      }
      const sync = this.syncSession.requireSyncData()
      const mapping = sync.loginMappings.find((entry) => entry.localId === login.id)
      if (!mapping) throw new VaultError('INVALID_INPUT')
      const client = this.syncSession.getOrCreateSyncClient(sync)
      const operation = this.syncSession.startAttachmentOperation(request.operationId)
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
        const generation = this.core.generation
        const downloaded = client.downloadAttachmentStream
          ? await client.downloadAttachmentStream(mapping.remoteId, attachment.id, abort.signal)
          : await client.downloadAttachment(mapping.remoteId, attachment.id, abort.signal)
        if ('dispose' in downloaded) downloadedStream = downloaded
        else clearText = downloaded.data
        if (generation !== this.core.generation || abort.signal.aborted) {
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
        this.syncSession.finishAttachmentOperation(operation)
      }
    })
  }

  /**
   * Returns the card face shown in the vault list and card details. Unlike `previewAttachment`,
   * this never holds the vault mutex across the network: cache hits are served from a fast read,
   * and misses download through a small concurrency pool that a lock aborts.
   */
  async getCardCoverPreview(
    request: LoginIdRequest,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<CardCoverPreviewResult | null> {
    const target = (() => {
      assertUuid(request.id)
      const data = this.core.requireFastReadData()
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      this.assertAttachmentAuthorized(login, validateAuthorization)
      if (login.type !== 'card' || !data.sync) return null
      const cover = login.attachments.find((attachment) =>
        isCardCoverAttachment(attachment.fileName)
      )
      const mapping = data.sync.loginMappings.find((entry) => entry.localId === login.id)
      if (!cover || !mapping) return null
      return {
        sync: data.sync,
        remoteId: mapping.remoteId,
        attachmentId: cover.id,
        fileName: cover.fileName,
        size: cover.size,
        // Attachment ids are immutable; a replaced cover gets a new id and therefore a new key.
        cacheKey: `${data.sync.serverUrl}\0${mapping.remoteId}\0${cover.id}`
      }
    })()
    if (!target) return null

    const cached = this.cardCoverCache.get(target.cacheKey)
    if (cached) return cached.value
    const existingRequest = this.cardCoverRequests.get(target.cacheKey)
    if (existingRequest) return existingRequest

    const pendingRequest = this.loadCardCover(target).finally(() => {
      if (this.cardCoverRequests.get(target.cacheKey) === pendingRequest) {
        this.cardCoverRequests.delete(target.cacheKey)
      }
    })
    this.cardCoverRequests.set(target.cacheKey, pendingRequest)
    return pendingRequest
  }

  /** Forgets a cover that was replaced or deleted so its plaintext does not linger on disk. */
  private forgetCardCover(sync: PersistedSyncData, remoteId: string, attachmentId: string): void {
    const cacheKey = `${sync.serverUrl}\0${remoteId}\0${attachmentId}`
    this.cardCoverCache.delete(cacheKey)
    const keys = this.imageCacheKeys()
    if (!keys) return
    void this.imageCache
      ?.remove(keys, 'card-cover', cacheKey)
      .finally(() => clearImageCacheKeys(keys))
  }

  private async loadCardCover(target: {
    sync: PersistedSyncData
    remoteId: string
    attachmentId: string
    fileName: string
    size: number
    cacheKey: string
  }): Promise<CardCoverPreviewResult | null> {
    const generation = this.core.generation
    const keys = this.imageCacheKeys()
    const abort = new AbortController()
    this.imageRequestAborts.add(abort)
    let clearText: Buffer | undefined
    try {
      const stored = keys ? await this.imageCache?.read(keys, 'card-cover', target.cacheKey) : null
      if (generation !== this.core.generation) throw new VaultError('LOCKED')
      if (
        stored?.mediaType &&
        stored.data &&
        stored.storedAt + CARD_COVER_CACHE_TTL_MS > this.core.now().getTime()
      ) {
        clearText = stored.data
        const mediaType =
          previewMediaType(target.fileName, clearText) ?? extensionPreviewMediaType(target.fileName)
        if (mediaType) return this.rememberCardCover(target, mediaType, clearText)
      }
      stored?.data?.fill(0)

      clearText = await this.cardCoverDownloads.run(async () => {
        // Only borrow the mutex long enough to obtain the shared sync client.
        const client = await this.core.exclusive(async () => {
          if (generation !== this.core.generation) throw new VaultError('LOCKED')
          return this.syncSession.getOrCreateSyncClient(this.syncSession.requireSyncData())
        })
        const downloaded = client.downloadAttachmentStream
          ? await client.downloadAttachmentStream(
              target.remoteId,
              target.attachmentId,
              abort.signal
            )
          : await client.downloadAttachment(target.remoteId, target.attachmentId, abort.signal)
        try {
          if (downloaded.fileName !== target.fileName) throw new VaultError('ATTACHMENT_FAILED')
          if ('dispose' in downloaded) {
            return await collectPreviewBytes(
              downloaded.data.chunks(abort.signal),
              target.size,
              abort.signal
            )
          }
          if (downloaded.data.length > MAX_ATTACHMENT_PREVIEW_BYTES) {
            downloaded.data.fill(0)
            throw new VaultError('ATTACHMENT_TOO_LARGE')
          }
          return downloaded.data
        } finally {
          if ('dispose' in downloaded) await downloaded.dispose().catch(() => undefined)
        }
      }, abort.signal)
      if (generation !== this.core.generation) throw new VaultError('LOCKED')
      const mediaType =
        previewMediaType(target.fileName, clearText) ?? extensionPreviewMediaType(target.fileName)
      if (!mediaType) throw new VaultError('INVALID_INPUT')
      if (keys) {
        void this.imageCache?.write(keys, 'card-cover', target.cacheKey, {
          mediaType,
          data: clearText,
          storedAt: this.core.now().getTime()
        })
      }
      return this.rememberCardCover(target, mediaType, clearText)
    } catch (error) {
      if (error instanceof VaultError) throw error
      throw abort.signal.aborted ? new VaultError('LOCKED') : new VaultError('ATTACHMENT_FAILED')
    } finally {
      clearText?.fill(0)
      this.imageRequestAborts.delete(abort)
      if (keys) clearImageCacheKeys(keys)
    }
  }

  private rememberCardCover(
    target: { cacheKey: string; attachmentId: string },
    mediaType: CardCoverPreviewResult['mediaType'],
    clearText: Buffer
  ): CardCoverPreviewResult {
    const result: CardCoverPreviewResult = {
      attachmentId: target.attachmentId,
      mediaType,
      dataUrl: `data:${mediaType};base64,${clearText.toString('base64')}`
    }
    this.cardCoverCache.set(target.cacheKey, result, {
      size: result.dataUrl.length,
      ttlMs: CARD_COVER_CACHE_TTL_MS
    })
    return result
  }

  async previewAttachment(
    request: AttachmentPreviewRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentPreviewResult> {
    return this.core.exclusive(async () => {
      assertUuid(request.id)
      assertUuid(request.operationId)
      if (
        typeof request.attachmentId !== 'string' ||
        request.attachmentId.length === 0 ||
        request.attachmentId.length > MAX_ATTACHMENT_ID_LENGTH
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const data = this.core.requireData()
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      this.assertAttachmentAuthorized(login, validateAuthorization)
      const attachment = login.attachments.find((entry) => entry.id === request.attachmentId)
      if (!attachment) throw new VaultError('NOT_FOUND')
      const sync = this.syncSession.requireSyncData()
      const mapping = sync.loginMappings.find((entry) => entry.localId === login.id)
      if (!mapping) throw new VaultError('INVALID_INPUT')
      const client = this.syncSession.getOrCreateSyncClient(sync)
      const operation = this.syncSession.startAttachmentOperation(request.operationId)
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
        this.syncSession.finishAttachmentOperation(operation)
      }
    })
  }

  async uploadAttachment(
    request: AttachmentUploadRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentUploadResult> {
    const preflight = await this.core.exclusive(async () => {
      assertUuid(request.id)
      assertUuid(request.operationId)
      const data = this.core.requireData()
      assertNoPendingPersonalVaultPurge(data.sync)
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      this.assertAttachmentAuthorized(login, validateAuthorization)
      const files = this.attachmentFiles
      if (!files) throw new VaultError('INTERNAL_ERROR')
      const sync = this.syncSession.requireSyncData()
      if (!sync.loginMappings.some((entry) => entry.localId === login.id)) {
        throw new VaultError('INVALID_INPUT')
      }
      return { files, generation: this.core.generation }
    })

    this.reportAttachmentProgress(reportProgress, request, 'upload', 'choosing-file', 0, null)
    const selection = await preflight.files.chooseOpenFile()
    if (selection === null) return { canceled: true, attachment: null }

    return this.core.exclusive(async () => {
      if (preflight.generation !== this.core.generation) throw new VaultError('LOCKED')
      const data = this.core.requireData()
      assertNoPendingPersonalVaultPurge(data.sync)
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      this.assertAttachmentAuthorized(login, validateAuthorization)
      if (login.attachments.some((attachment) => attachment.fileName === selection.fileName)) {
        throw new VaultError('DUPLICATE_NAME')
      }
      const sync = this.syncSession.requireSyncData()
      const mapping = sync.loginMappings.find((entry) => entry.localId === login.id)
      if (!mapping) throw new VaultError('INVALID_INPUT')
      const client = this.syncSession.getOrCreateSyncClient(sync)
      const operation = this.syncSession.startAttachmentOperation(request.operationId)
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
              () => this.syncSession.commitAttachmentOperation(operation)
            )
          : await (async () => {
              clearText = await preflight.files.readSelectedFile(selection, operation.abort.signal)
              return client.uploadAttachment(
                mapping.remoteId,
                selection.fileName,
                clearText,
                operation.abort.signal,
                () => this.syncSession.commitAttachmentOperation(operation)
              )
            })()
        this.syncSession.commitAttachmentOperation(operation)
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
        const updated = findLogin(this.core.requireData(), request.id)
        const attachment = updated.attachments.find((entry) => entry.id === uploaded.id)
        if (!attachment || attachment.fileName !== selection.fileName || attachment.legacy) {
          throw new VaultError('ATTACHMENT_FAILED')
        }
        return { canceled: false, attachment: { ...attachment } }
      } catch (error) {
        throw this.mapAttachmentError(error, operation)
      } finally {
        clearText?.fill(0)
        this.syncSession.finishAttachmentOperation(operation)
      }
    })
  }

  async uploadCardCoverAttachment(
    request: AttachmentUploadCardCoverRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentUploadResult> {
    const preflight = await this.core.exclusive(async () => {
      assertUuid(request.id)
      assertUuid(request.operationId)
      if (typeof request.sourceUrl !== 'string' || request.sourceUrl.length > 4096) {
        throw new VaultError('INVALID_INPUT')
      }
      parseCardCoverCatalogUrl(request.sourceUrl)
      const data = this.core.requireData()
      assertNoPendingPersonalVaultPurge(data.sync)
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      if (login.type !== 'card') throw new VaultError('INVALID_INPUT')
      this.assertAttachmentAuthorized(login, validateAuthorization)
      const sync = this.syncSession.requireSyncData()
      if (!sync.loginMappings.some((entry) => entry.localId === login.id)) {
        throw new VaultError('INVALID_INPUT')
      }
      const operation = this.syncSession.startAttachmentOperation(request.operationId)
      return { generation: this.core.generation, operation }
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

      return await this.commitCardCoverUpload(
        request,
        cover,
        preflight.generation,
        preflight.operation,
        reportProgress,
        validateAuthorization
      )
    } catch (error) {
      throw this.mapAttachmentError(error, preflight.operation)
    } finally {
      clearText?.fill(0)
      this.syncSession.finishAttachmentOperation(preflight.operation)
    }
  }

  async uploadCardCoverFileAttachment(
    request: AttachmentUploadRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentUploadResult> {
    const preflight = await this.core.exclusive(async () => {
      assertUuid(request.id)
      assertUuid(request.operationId)
      const data = this.core.requireData()
      assertNoPendingPersonalVaultPurge(data.sync)
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      if (login.type !== 'card') throw new VaultError('INVALID_INPUT')
      this.assertAttachmentAuthorized(login, validateAuthorization)
      const files = this.attachmentFiles
      if (!files) throw new VaultError('INTERNAL_ERROR')
      const sync = this.syncSession.requireSyncData()
      if (!sync.loginMappings.some((entry) => entry.localId === login.id)) {
        throw new VaultError('INVALID_INPUT')
      }
      return { files, generation: this.core.generation }
    })

    this.reportAttachmentProgress(reportProgress, request, 'upload', 'choosing-file', 0, null)
    const selection = await preflight.files.chooseCardCoverFile()
    if (selection === null) return { canceled: true, attachment: null }
    if (selection.size > MAX_CARD_COVER_BYTES) throw new VaultError('ATTACHMENT_TOO_LARGE')
    const operationPreflight = await this.core.exclusive(async () => {
      if (preflight.generation !== this.core.generation) throw new VaultError('LOCKED')
      const data = this.core.requireData()
      assertNoPendingPersonalVaultPurge(data.sync)
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      if (login.type !== 'card') throw new VaultError('INVALID_INPUT')
      this.assertAttachmentAuthorized(login, validateAuthorization)
      return { operation: this.syncSession.startAttachmentOperation(request.operationId) }
    })
    const { operation } = operationPreflight

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
      clearText = await preflight.files.readSelectedFile(selection, operation.abort.signal)
      this.reportAttachmentProgress(
        reportProgress,
        request,
        'upload',
        'reading-file',
        selection.size,
        selection.size
      )
      if (clearText.length > MAX_CARD_COVER_BYTES) throw new VaultError('ATTACHMENT_TOO_LARGE')
      const mediaType = previewMediaType(selection.fileName, clearText)
      if (!mediaType || mediaType === 'image/gif') throw new VaultError('INVALID_INPUT')
      const cover: CardCoverDownload = {
        fileName: cardCoverFileName(mediaType),
        data: clearText
      }

      return await this.commitCardCoverUpload(
        request,
        cover,
        preflight.generation,
        operation,
        reportProgress,
        validateAuthorization
      )
    } catch (error) {
      throw this.mapAttachmentError(error, operation)
    } finally {
      clearText?.fill(0)
      this.syncSession.finishAttachmentOperation(operation)
    }
  }

  private commitCardCoverUpload(
    request: { id: string; operationId: string },
    cover: CardCoverDownload,
    generation: number,
    operation: { operationId: string; abort: AbortController; committed: boolean },
    reportProgress: ((progress: AttachmentProgressEvent) => void) | undefined,
    validateAuthorization: AttachmentAuthorizationValidator | undefined
  ): Promise<AttachmentUploadResult> {
    return this.core.exclusive(async () => {
      if (generation !== this.core.generation) throw new VaultError('LOCKED')
      const data = this.core.requireData()
      assertNoPendingPersonalVaultPurge(data.sync)
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      if (login.type !== 'card') throw new VaultError('INVALID_INPUT')
      this.assertAttachmentAuthorized(login, validateAuthorization)
      if (login.attachments.some((attachment) => attachment.fileName === cover.fileName)) {
        throw new VaultError('DUPLICATE_NAME')
      }
      const sync = this.syncSession.requireSyncData()
      const mapping = sync.loginMappings.find((entry) => entry.localId === login.id)
      if (!mapping) throw new VaultError('INVALID_INPUT')
      const client = this.syncSession.getOrCreateSyncClient(sync)
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
        operation.abort.signal,
        () => this.syncSession.commitAttachmentOperation(operation)
      )
      this.syncSession.commitAttachmentOperation(operation)
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
      const updated = findLogin(this.core.requireData(), request.id)
      const attachment = updated.attachments.find((entry) => entry.id === uploaded.id)
      if (!attachment || attachment.fileName !== cover.fileName || attachment.legacy) {
        throw new VaultError('ATTACHMENT_FAILED')
      }
      return { canceled: false, attachment: { ...attachment } }
    })
  }

  deleteAttachment(
    request: AttachmentDeleteRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentDeleteResult> {
    return this.core.exclusive(async () => {
      const { data, attachment, mapping, client } = this.attachmentMutationContext(
        request,
        validateAuthorization
      )
      const operation = this.syncSession.startAttachmentOperation(request.operationId)
      try {
        this.reportAttachmentProgress(reportProgress, request, 'delete', 'deleting', 0, null)
        await client.deleteAttachment(mapping.remoteId, attachment.id, operation.abort.signal, () =>
          this.syncSession.commitAttachmentOperation(operation)
        )
        this.syncSession.commitAttachmentOperation(operation)
        if (isCardCoverAttachment(attachment.fileName)) {
          this.forgetCardCover(this.syncSession.requireSyncData(), mapping.remoteId, attachment.id)
        }
        this.reportAttachmentProgress(reportProgress, request, 'delete', 'syncing', 0, null)
        await this.persistAttachmentMutation(data, client)
        const updated = findLogin(this.core.requireData(), request.id)
        if (updated.attachments.some((entry) => entry.id === attachment.id)) {
          throw new VaultError('ATTACHMENT_FAILED')
        }
        return { attachmentId: attachment.id }
      } catch (error) {
        throw this.mapAttachmentError(error, operation)
      } finally {
        this.syncSession.finishAttachmentOperation(operation)
      }
    })
  }

  fixLegacyAttachment(
    request: AttachmentFixLegacyRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentFixLegacyResult> {
    return this.core.exclusive(async () => {
      const { data, attachment, mapping, client } = this.attachmentMutationContext(
        request,
        validateAuthorization
      )
      if (!attachment.legacy) throw new VaultError('INVALID_INPUT')
      const operation = this.syncSession.startAttachmentOperation(request.operationId)
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
          () => this.syncSession.commitAttachmentOperation(operation)
        )
        this.syncSession.commitAttachmentOperation(operation)
        this.reportAttachmentProgress(reportProgress, request, 'fix-legacy', 'syncing', 0, null)
        await this.persistAttachmentMutation(data, client)
        const updated = findLogin(this.core.requireData(), request.id)
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
        this.syncSession.finishAttachmentOperation(operation)
      }
    })
  }

  cancelAttachmentOperation(request: AttachmentCancelRequest): AttachmentCancelResult {
    assertUuid(request.operationId)
    const active = this.syncSession.activeAttachmentOperation
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

  private mapAttachmentError(error: unknown, operation?: { canceledByUser: boolean }): VaultError {
    if (
      operation?.canceledByUser &&
      ((error instanceof VaultError && error.code === 'LOCKED') ||
        (error instanceof BitwardenDirectError && error.code === 'ABORTED'))
    ) {
      return new VaultError('ATTACHMENT_CANCELED')
    }
    if (error instanceof VaultError) return error
    if (error instanceof BitwardenDirectError) {
      if (error.code === 'ABORTED') return new VaultError('LOCKED')
      if (error.code === 'NOT_FOUND') return new VaultError('NOT_FOUND')
      if (error.code === 'STORAGE_LIMIT') return new VaultError('ATTACHMENT_STORAGE_LIMIT')
      if (error.code === 'TOO_LARGE') return new VaultError('ATTACHMENT_TOO_LARGE')
      if (error.code === 'ATTACHMENT_REJECTED') return new VaultError('ATTACHMENT_REJECTED')
      if (
        error.code === 'AUTH_REQUIRED' ||
        error.code === 'TWO_FACTOR_REQUIRED' ||
        error.code === 'NEW_DEVICE_REQUIRED'
      ) {
        return this.syncSession.mapSyncError(error)
      }
    }
    return new VaultError('ATTACHMENT_FAILED')
  }

  private attachmentMutationContext(
    request: AttachmentTargetRequest,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): {
    data: VaultData
    attachment: VaultAttachmentView
    mapping: SyncEntityMapping
    client: BitwardenSyncClient
  } {
    assertUuid(request.id)
    assertUuid(request.operationId)
    if (
      typeof request.attachmentId !== 'string' ||
      request.attachmentId.length === 0 ||
      request.attachmentId.length > MAX_ATTACHMENT_ID_LENGTH
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    const data = this.core.requireData()
    assertNoPendingPersonalVaultPurge(data.sync)
    const login = findLogin(data, request.id)
    assertActiveLogin(login)
    this.assertAttachmentAuthorized(login, validateAuthorization)
    const attachment = login.attachments.find((entry) => entry.id === request.attachmentId)
    if (!attachment) throw new VaultError('NOT_FOUND')
    const sync = this.syncSession.requireSyncData()
    const mapping = sync.loginMappings.find((entry) => entry.localId === login.id)
    if (!mapping) throw new VaultError('INVALID_INPUT')
    return { data, attachment, mapping, client: this.syncSession.getOrCreateSyncClient(sync) }
  }

  private assertAttachmentAuthorized(
    login: StoredLogin,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): void {
    if (
      login.reprompt === 1 &&
      !validateAuthorization?.([login.id], { generation: this.core.generation })
    ) {
      throw new VaultError('REPROMPT_REQUIRED')
    }
  }

  private reportAttachmentProgress(
    report: ((progress: AttachmentProgressEvent) => void) | undefined,
    request: { id: string; operationId: string },
    kind: AttachmentOperationKind,
    stage: AttachmentOperationStage,
    completedBytes: number,
    totalBytes: number | null
  ): void {
    if (!report) return
    try {
      report({
        operationId: request.operationId,
        itemId: request.id,
        kind,
        stage,
        completedBytes,
        totalBytes
      })
    } catch {
      // Renderer progress is advisory and must never decide mutation success.
    }
  }

  private async persistAttachmentMutation(
    current: VaultData,
    client: BitwardenSyncClient
  ): Promise<void> {
    const sync = current.sync
    if (!sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    assertNoPendingPersonalVaultPurge(sync)
    const [remoteFolders, remoteLogins] = await Promise.all([
      client.listFolders(),
      client.listPersonalLogins()
    ])
    const next = cloneData(current)
    reconcileServerAuthoritativeAttachments(next, sync.loginMappings, remoteFolders, remoteLogins)
    const syncedAt = this.core.nowIso()
    if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    next.sync.state = client.exportState()
    next.sync.lastSyncAt = syncedAt
    next.updatedAt = syncedAt
    await this.core.commit(next)
  }
}
