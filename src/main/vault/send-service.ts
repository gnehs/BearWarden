import type {
  SendCreateRequest,
  SendFileCreateRequest,
  SendFileCreateResult,
  SendFileDownloadRequest,
  SendFileDownloadResult,
  SendIdRequest,
  SendUpdateRequest,
  SendView
} from '../../shared/vault-contract'
import { BitwardenDirectError, type BitwardenSyncClient } from '../bitwarden-direct'
import type { VaultAttachmentFileService } from '../vault-attachment-files'
import { VaultError } from '../vault-errors'
import { MAX_SYNC_SECRET_LENGTH } from './limits'
import { assertUuid, normalizeNullableString } from './parse-primitives'
import { normalizeFileSendDraft, normalizeSendDraft, sendViewFromRemote } from './send-parsing'
import type { PersistedSyncData, VaultData } from './types'
import { cloneData } from './vault-data-parsing'
import { compareText } from './views'

export interface VaultSendServiceDependencies {
  readonly attachmentFiles: VaultAttachmentFileService | null
  readonly exclusive: <T>(operation: () => Promise<T>) => Promise<T>
  readonly readData: () => VaultData
  readonly requireSyncData: () => PersistedSyncData
  readonly getSyncClient: (sync: PersistedSyncData) => BitwardenSyncClient
  readonly currentGeneration: () => number
  readonly startSyncOperation: () => AbortController
  readonly finishSyncOperation: (abort: AbortController) => void
  readonly persistData: (data: VaultData) => Promise<void>
  readonly nowIso: () => string
  readonly clearSyncError: () => void
  readonly mapSyncError: (error: unknown) => VaultError
  readonly copyText: (text: string) => void | Promise<void>
  readonly assertMutationAllowed: () => void
}

export class VaultSendService {
  constructor(private readonly dependencies: VaultSendServiceDependencies) {}

  list(): Promise<SendView[]> {
    return this.dependencies.exclusive(async () =>
      this.dependencies
        .readData()
        .sends.map((send) => ({ ...send }))
        .sort(
          (left, right) => compareText(left.name, right.name) || left.id.localeCompare(right.id)
        )
    )
  }

  create(request: SendCreateRequest): Promise<SendView> {
    return this.dependencies.exclusive(async () => {
      this.dependencies.assertMutationAllowed()
      const draft = normalizeSendDraft(request)
      const current = this.dependencies.readData()
      const client = this.syncClient()
      if (!client.createSend) throw new VaultError('SYNC_FAILED')
      const abort = this.dependencies.startSyncOperation()
      try {
        const remote = await client.createSend(draft, abort.signal)
        const next = cloneData(current)
        next.sends = [
          ...next.sends.filter((send) => send.id !== remote.id),
          sendViewFromRemote(remote)
        ]
        if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
        next.sync.state = client.exportState()
        next.updatedAt = this.dependencies.nowIso()
        await this.dependencies.persistData(next)
        this.dependencies.clearSyncError()
        return { ...sendViewFromRemote(remote) }
      } catch (error) {
        throw this.dependencies.mapSyncError(error)
      } finally {
        this.dependencies.finishSyncOperation(abort)
      }
    })
  }

  async createFile(request: SendFileCreateRequest): Promise<SendFileCreateResult> {
    const preflight = await this.dependencies.exclusive(async () => {
      this.dependencies.assertMutationAllowed()
      assertUuid(request.operationId)
      const files = this.dependencies.attachmentFiles
      if (!files) throw new VaultError('INTERNAL_ERROR')
      const client = this.syncClient()
      if (!client.createFileSend) throw new VaultError('SYNC_FAILED')
      return { files, generation: this.dependencies.currentGeneration() }
    })
    const selection = await preflight.files.chooseOpenFile()
    if (selection === null) return { canceled: true, send: null }

    return this.dependencies.exclusive(async () => {
      if (preflight.generation !== this.dependencies.currentGeneration()) {
        throw new VaultError('LOCKED')
      }
      const current = this.dependencies.readData()
      const client = this.syncClient()
      if (!client.createFileSend) throw new VaultError('SYNC_FAILED')
      const normalized = normalizeFileSendDraft(request)
      const abort = this.dependencies.startSyncOperation()
      let plaintext: Buffer | null = null
      try {
        plaintext = await preflight.files.readSelectedFile(selection, abort.signal)
        const remote = await client.createFileSend(
          { ...normalized, fileName: selection.fileName, data: plaintext },
          abort.signal
        )
        const authoritative = (await client.listSends?.(abort.signal))?.find(
          (send) => send.id === remote.id
        )
        if (!authoritative || authoritative.type !== 'file' || !authoritative.file) {
          throw new VaultError('SYNC_FAILED')
        }
        const next = cloneData(current)
        next.sends = [
          ...next.sends.filter((send) => send.id !== authoritative.id),
          sendViewFromRemote(authoritative)
        ]
        if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
        next.sync.state = client.exportState()
        next.sync.lastSyncAt = this.dependencies.nowIso()
        next.updatedAt = this.dependencies.nowIso()
        await this.dependencies.persistData(next)
        this.dependencies.clearSyncError()
        return { canceled: false, send: { ...sendViewFromRemote(authoritative) } }
      } catch (error) {
        throw this.dependencies.mapSyncError(error)
      } finally {
        plaintext?.fill(0)
        this.dependencies.finishSyncOperation(abort)
      }
    })
  }

  async downloadFile(request: SendFileDownloadRequest): Promise<SendFileDownloadResult> {
    const password =
      request.password === undefined
        ? null
        : normalizeNullableString(request.password, MAX_SYNC_SECRET_LENGTH)
    const preflight = await this.dependencies.exclusive(async () => {
      assertUuid(request.id)
      const send = this.dependencies
        .readData()
        .sends.find((candidate) => candidate.id === request.id)
      if (!send || send.type !== 'file' || !send.file) throw new VaultError('NOT_FOUND')
      const files = this.dependencies.attachmentFiles
      if (!files) throw new VaultError('INTERNAL_ERROR')
      const client = this.syncClient()
      if (!client.downloadFileSend) throw new VaultError('SYNC_FAILED')
      return {
        files,
        fileName: send.file.fileName,
        generation: this.dependencies.currentGeneration()
      }
    })
    const destination = await preflight.files.chooseSavePath(preflight.fileName)
    if (destination === null) return { canceled: true, fileName: preflight.fileName }

    return this.dependencies.exclusive(async () => {
      if (preflight.generation !== this.dependencies.currentGeneration()) {
        throw new VaultError('LOCKED')
      }
      const send = this.dependencies
        .readData()
        .sends.find((candidate) => candidate.id === request.id)
      if (
        !send ||
        send.type !== 'file' ||
        !send.file ||
        send.file.fileName !== preflight.fileName
      ) {
        throw new VaultError('NOT_FOUND')
      }
      const client = this.syncClient()
      if (!client.downloadFileSend) throw new VaultError('SYNC_FAILED')
      const abort = this.dependencies.startSyncOperation()
      let clearText: Buffer | null = null
      try {
        clearText = (await client.downloadFileSend(send.id, password, abort.signal)).data
        if (
          preflight.generation !== this.dependencies.currentGeneration() ||
          abort.signal.aborted
        ) {
          throw new VaultError('LOCKED')
        }
        await preflight.files.write(destination, clearText, abort.signal)
        return { canceled: false, fileName: preflight.fileName }
      } catch (error) {
        if (error instanceof BitwardenDirectError && error.code === 'NOT_FOUND') {
          throw new VaultError('NOT_FOUND')
        }
        throw this.dependencies.mapSyncError(error)
      } finally {
        clearText?.fill(0)
        this.dependencies.finishSyncOperation(abort)
      }
    })
  }

  update(request: SendUpdateRequest): Promise<SendView> {
    return this.dependencies.exclusive(async () => {
      this.dependencies.assertMutationAllowed()
      assertUuid(request.id)
      const draft = normalizeSendDraft(request)
      const current = this.dependencies.readData()
      if (!current.sends.some((send) => send.id === request.id)) throw new VaultError('NOT_FOUND')
      const client = this.syncClient()
      if (!client.updateSend) throw new VaultError('SYNC_FAILED')
      const abort = this.dependencies.startSyncOperation()
      try {
        const remote = await client.updateSend(request.id, draft, abort.signal)
        return await this.persistRemoteSend(current, client, remote)
      } catch (error) {
        throw this.dependencies.mapSyncError(error)
      } finally {
        this.dependencies.finishSyncOperation(abort)
      }
    })
  }

  removePassword(request: SendIdRequest): Promise<SendView> {
    return this.dependencies.exclusive(async () => {
      this.dependencies.assertMutationAllowed()
      assertUuid(request.id)
      const current = this.dependencies.readData()
      if (!current.sends.some((send) => send.id === request.id)) throw new VaultError('NOT_FOUND')
      const client = this.syncClient()
      if (!client.removeSendPassword) throw new VaultError('SYNC_FAILED')
      const abort = this.dependencies.startSyncOperation()
      try {
        const remote = await client.removeSendPassword(request.id, abort.signal)
        return await this.persistRemoteSend(current, client, remote)
      } catch (error) {
        throw this.dependencies.mapSyncError(error)
      } finally {
        this.dependencies.finishSyncOperation(abort)
      }
    })
  }

  delete(request: SendIdRequest): Promise<void> {
    return this.dependencies.exclusive(async () => {
      assertUuid(request.id)
      const current = this.dependencies.readData()
      if (!current.sends.some((send) => send.id === request.id)) throw new VaultError('NOT_FOUND')
      const client = this.syncClient()
      if (!client.deleteSend) throw new VaultError('SYNC_FAILED')
      const abort = this.dependencies.startSyncOperation()
      try {
        await client.deleteSend(request.id, abort.signal)
        const next = cloneData(current)
        next.sends = next.sends.filter((send) => send.id !== request.id)
        if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
        next.sync.state = client.exportState()
        next.updatedAt = this.dependencies.nowIso()
        await this.dependencies.persistData(next)
        this.dependencies.clearSyncError()
      } catch (error) {
        throw this.dependencies.mapSyncError(error)
      } finally {
        this.dependencies.finishSyncOperation(abort)
      }
    })
  }

  copyLink(request: SendIdRequest): Promise<void> {
    return this.dependencies.exclusive(async () => {
      assertUuid(request.id)
      const client = this.syncClient()
      if (!client.copySendLink) throw new VaultError('SYNC_FAILED')
      try {
        await client.copySendLink(request.id, this.dependencies.copyText)
      } catch (error) {
        throw this.dependencies.mapSyncError(error)
      }
    })
  }

  private syncClient(): BitwardenSyncClient {
    return this.dependencies.getSyncClient(this.dependencies.requireSyncData())
  }

  private async persistRemoteSend(
    current: VaultData,
    client: BitwardenSyncClient,
    remote: Parameters<typeof sendViewFromRemote>[0]
  ): Promise<SendView> {
    const next = cloneData(current)
    next.sends = [...next.sends.filter((send) => send.id !== remote.id), sendViewFromRemote(remote)]
    if (!next.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
    next.sync.state = client.exportState()
    next.updatedAt = this.dependencies.nowIso()
    await this.dependencies.persistData(next)
    this.dependencies.clearSyncError()
    return { ...sendViewFromRemote(remote) }
  }
}
