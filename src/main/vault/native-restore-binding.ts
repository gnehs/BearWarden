import { createHash } from 'node:crypto'
import { type BitwardenSyncClient } from '../bitwarden-direct'
import {
  assertNativeAttachmentRestoreBinding,
  type NativeAttachmentRestoreJournal
} from '../native-attachment-restore'
import { VaultError } from '../vault-errors'
import type { PersistedSyncData, VaultData, VaultNativeAttachmentRestoreSummary } from './types'

export function nativeAttachmentRestoreAccountFingerprint(
  sync: PersistedSyncData,
  client: BitwardenSyncClient
): string {
  const state = client.exportState()
  if (!state.session || !state.profileId) throw new VaultError('SYNC_AUTH_REQUIRED')
  return createHash('sha256')
    .update(
      JSON.stringify({
        provider: 'bitwarden',
        serverUrl: sync.serverUrl,
        profileId: state.profileId
      })
    )
    .digest('hex')
}

export function nativeAttachmentRestoreSummary(
  journal: NativeAttachmentRestoreJournal
): VaultNativeAttachmentRestoreSummary {
  return {
    phase: journal.phase,
    totalItems: journal.items.length,
    mappedItems: journal.items.filter((item) => item.remoteItemId !== null).length,
    totalAttachments: journal.attachments.length,
    uploadedAttachments: journal.attachments.filter(
      (attachment) => attachment.status === 'uploaded'
    ).length,
    needsReconciliationAttachments: journal.attachments.filter(
      (attachment) => attachment.status === 'needs-reconciliation'
    ).length,
    totalBytes: journal.attachments.reduce((total, attachment) => total + attachment.size, 0),
    completedBytes: journal.attachments.reduce(
      (total, attachment) => total + (attachment.status === 'uploaded' ? attachment.size : 0),
      0
    )
  }
}

export async function nativeAttachmentRestoreCandidateMatches(
  client: BitwardenSyncClient,
  remoteItemId: string,
  remoteAttachmentId: string,
  expectedFileName: string,
  expectedSize: number,
  expectedDigest: string,
  signal: AbortSignal
): Promise<boolean> {
  let streamed:
    Awaited<ReturnType<NonNullable<BitwardenSyncClient['downloadAttachmentStream']>>> | undefined
  let clearText: Buffer | undefined
  try {
    const downloaded = client.downloadAttachmentStream
      ? await client.downloadAttachmentStream(remoteItemId, remoteAttachmentId, signal)
      : await client.downloadAttachment(remoteItemId, remoteAttachmentId, signal)
    if (downloaded.fileName !== expectedFileName) return false
    if ('dispose' in downloaded) streamed = downloaded
    else clearText = downloaded.data
    const chunks: AsyncIterable<Buffer> = streamed
      ? streamed.data.chunks(signal)
      : (async function* (): AsyncIterable<Buffer> {
          yield clearText!
        })()
    const hash = createHash('sha256')
    let size = 0
    for await (const chunk of chunks) {
      size += chunk.length
      if (size > expectedSize) return false
      hash.update(chunk)
    }
    return size === expectedSize && hash.digest('hex') === expectedDigest
  } catch {
    return false
  } finally {
    clearText?.fill(0)
    await streamed?.dispose().catch(() => undefined)
  }
}

export function requireBoundNativeAttachmentRestore(
  data: VaultData,
  archiveFingerprint: string,
  sync: PersistedSyncData,
  client: BitwardenSyncClient
): NativeAttachmentRestoreJournal {
  if (!data.nativeAttachmentRestore) throw new VaultError('INVALID_INPUT')
  return assertNativeAttachmentRestoreBinding(
    data.nativeAttachmentRestore,
    archiveFingerprint,
    nativeAttachmentRestoreAccountFingerprint(sync, client)
  )
}
