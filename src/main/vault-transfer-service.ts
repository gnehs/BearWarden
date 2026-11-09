import type { VaultImportResult } from '../shared/vault-contract'
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
import { VaultAccountService } from './vault-account-service'
import { assertBitwardenPolicyDoesNotBlock, assertPersonalItemTypeAllowed } from './vault/policy'
import { localSyncSnapshot } from './vault/sync-snapshots'
import {
  nativeAttachmentRestoreAccountFingerprint,
  nativeAttachmentRestoreSummary,
  nativeAttachmentRestoreCandidateMatches,
  requireBoundNativeAttachmentRestore
} from './vault/native-restore-binding'

/** Attachment I/O, portable exports/imports, and resumable native attachment restoration. */
export class VaultTransferService extends VaultAccountService {
  verifyPortabilityOwner(masterPassword: string): Promise<void> {
    return this.core.exclusive(() => this.core.assertMasterPassword(masterPassword))
  }

  exportPortableSnapshot(masterPassword: string): Promise<VaultExportSnapshot> {
    return this.core.exclusive(async () => {
      await this.core.assertMasterPassword(masterPassword)
      const data = this.core.requireData()
      assertBitwardenPolicyDoesNotBlock(BITWARDEN_POLICY_TYPE.DisablePersonalVaultExport, data)
      const snapshot = localSyncSnapshot(data)
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
    const prepared = await this.core.exclusive(async () => {
      await this.core.assertMasterPassword(masterPassword)
      const data = this.core.requireData()
      assertBitwardenPolicyDoesNotBlock(BITWARDEN_POLICY_TYPE.DisablePersonalVaultExport, data)
      assertNoPendingPersonalVaultPurge(data.sync)
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      const snapshot = localSyncSnapshot(data)
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
      this.syncSession.nativeAttachmentBackupAborts.add(abort)
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
        generation: this.core.generation,
        portable,
        skippedTrashItems: snapshot.logins.length - activeItems.length
      }
    })

    let disposed = false
    const ensureCurrent = (): void => {
      if (
        disposed ||
        prepared.abort.signal.aborted ||
        prepared.generation !== this.core.generation ||
        this.syncSession.syncClient !== prepared.client ||
        !this.core.currentData()?.sync?.state.session
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
        if (prepared.abort.signal.aborted || prepared.generation !== this.core.generation) {
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
          this.syncSession.nativeAttachmentBackupAborts.delete(prepared.abort)
        }
      }
      return source
    } catch (error) {
      disposed = true
      prepared.abort.abort()
      this.syncSession.nativeAttachmentBackupAborts.delete(prepared.abort)
      throw error
    }
  }

  nativeAttachmentRestoreStatus(): Promise<VaultNativeAttachmentRestoreSummary | null> {
    return this.core.exclusive(async () => {
      const journal = this.core.requireData().nativeAttachmentRestore
      return journal ? nativeAttachmentRestoreSummary(journal) : null
    })
  }

  clearCompletedNativeAttachmentRestore(archiveFingerprint: string): Promise<void> {
    return this.core.exclusive(async () => {
      const current = this.core.requireData()
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      const journal = requireBoundNativeAttachmentRestore(current, archiveFingerprint, sync, client)
      if (journal.phase !== 'complete') throw new VaultError('INVALID_INPUT')
      const next = cloneData(current)
      next.nativeAttachmentRestore = null
      next.updatedAt = this.core.nowIso()
      await this.core.commit(next)
    })
  }

  beginNativeAttachmentRestore(
    preview: NativeAttachmentBackupPreview,
    masterPassword: string
  ): Promise<VaultNativeAttachmentRestoreSummary> {
    return this.core.exclusive(async () => {
      await this.core.assertMasterPassword(masterPassword)
      const current = this.core.requireData()
      assertBitwardenPolicyDoesNotBlock(BITWARDEN_POLICY_TYPE.OrganizationDataOwnership, current)
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
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      const operation = this.startNativeAttachmentRestoreOperation(client)
      try {
        await client.sync(operation.abort.signal)
        this.assertNativeAttachmentRestoreLease(operation)
        const accountFingerprint = nativeAttachmentRestoreAccountFingerprint(sync, client)
        const parsed = parseBitwardenJson(preview.vaultJson)
        if (parsed.skippedTrashItems !== 0) throw new VaultError('INVALID_INPUT')
        for (const item of parsed.snapshot.items) assertPersonalItemTypeAllowed(item.type, current)
        const next = cloneData(this.core.requireData())
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
        const now = this.core.nowIso()
        next.nativeAttachmentRestore = createNativeAttachmentRestoreJournal({
          archiveFingerprint: preview.archiveFingerprint,
          accountFingerprint,
          createdAt: now,
          items: imported.itemMappings,
          attachments
        })
        next.updatedAt = now
        await this.core.commit(next, operation.generation)
        return nativeAttachmentRestoreSummary(next.nativeAttachmentRestore)
      } catch (error) {
        if (operation.abort.signal.aborted || operation.generation !== this.core.generation) {
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
    return this.core.exclusive(async () => {
      const current = this.core.requireData()
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      const journal = requireBoundNativeAttachmentRestore(current, archiveFingerprint, sync, client)
      if (journal.phase !== 'syncing-items') return nativeAttachmentRestoreSummary(journal)
      const operation = this.startNativeAttachmentRestoreOperation(client)
      try {
        await this.performSync(current, client, operation.abort.signal)
        this.assertNativeAttachmentRestoreLease(operation)
        const next = cloneData(this.core.requireData())
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
            this.core.nowIso()
          )
        }
        next.nativeAttachmentRestore = updated
        next.updatedAt = updated.updatedAt
        await this.core.commit(next, operation.generation)
        return nativeAttachmentRestoreSummary(updated)
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
    return this.core.exclusive(async () => {
      const current = this.core.requireData()
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      const journal = requireBoundNativeAttachmentRestore(current, archiveFingerprint, sync, client)
      const target = journal.attachments.find(
        (attachment) =>
          attachment.sourceItemId === key.sourceItemId &&
          attachment.sourceAttachmentId === key.sourceAttachmentId
      )
      const item = journal.items.find((candidate) => candidate.sourceItemId === key.sourceItemId)
      if (!target || !item?.remoteItemId || source.size !== target.size) {
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
          this.core.nowIso()
        )
        attempting.updatedAt = attempting.nativeAttachmentRestore.updatedAt
        await this.core.commit(attempting, operation.generation)
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
          this.core.requireData(),
          client,
          remoteFolders,
          remoteLogins
        )
        if (!next.nativeAttachmentRestore) throw new VaultError('ATTACHMENT_FAILED')
        next.nativeAttachmentRestore = completeNativeAttachmentRestoreAttempt(
          next.nativeAttachmentRestore,
          key,
          uploaded.id,
          this.core.nowIso()
        )
        next.updatedAt = next.nativeAttachmentRestore.updatedAt
        await this.core.commit(next, operation.generation)
        return nativeAttachmentRestoreSummary(next.nativeAttachmentRestore)
      } catch (error) {
        let reconciliationPersistenceError: unknown = null
        try {
          await this.persistFailedNativeAttachmentRestoreAttempt(key)
        } catch (persistError) {
          reconciliationPersistenceError = persistError
        }
        if (operation.abort.signal.aborted || operation.generation !== this.core.generation) {
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
    return this.core.exclusive(async () => {
      const current = this.core.requireData()
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      const journal = requireBoundNativeAttachmentRestore(current, archiveFingerprint, sync, client)
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
            await nativeAttachmentRestoreCandidateMatches(
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
              this.core.requireData(),
              client,
              remoteFolders,
              remoteLogins
            )
          : (() => {
              const preserved = cloneData(this.core.requireData())
              if (!preserved.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
              preserved.sync.state = client.exportState()
              preserved.sync.lastSyncAt = this.core.nowIso()
              return preserved
            })()
        if (!next.nativeAttachmentRestore) throw new VaultError('ATTACHMENT_FAILED')
        if (outcome === 'missing') {
          next.nativeAttachmentRestore = reconcileNativeAttachmentRestoreMissing(
            next.nativeAttachmentRestore,
            key,
            this.core.nowIso()
          )
        } else if (outcome === 'uploaded' && remoteAttachmentId) {
          next.nativeAttachmentRestore = reconcileNativeAttachmentRestoreUploaded(
            next.nativeAttachmentRestore,
            key,
            remoteAttachmentId,
            this.core.nowIso()
          )
        }
        next.updatedAt = next.nativeAttachmentRestore.updatedAt
        await this.core.commit(next, operation.generation)
        return {
          outcome,
          summary: nativeAttachmentRestoreSummary(next.nativeAttachmentRestore)
        }
      } catch (error) {
        if (operation.abort.signal.aborted || operation.generation !== this.core.generation) {
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
    return this.core.exclusive(async () => {
      await this.core.assertMasterPassword(masterPassword)
      const current = this.core.requireData()
      assertBitwardenPolicyDoesNotBlock(BITWARDEN_POLICY_TYPE.OrganizationDataOwnership, current)
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

      for (const item of snapshot.items) assertPersonalItemTypeAllowed(item.type, current)

      const next = cloneData(current)
      const generation = this.core.generation
      try {
        this.appendPortableSnapshot(next, snapshot)
      } catch (error) {
        if (error instanceof VaultError && error.code === 'INVALID_INPUT') throw error
        throw new VaultError('INVALID_INPUT')
      }

      next.updatedAt = this.core.nowIso()
      await this.core.commit(next, generation)
      return {
        importedFolders: snapshot.folders.length,
        importedItems: snapshot.items.length,
        skippedTrashItems
      }
    })
  }
}
