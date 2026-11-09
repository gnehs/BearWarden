import { useLingui } from '@lingui/react/macro'
import { useCallback, useEffect, useRef, useState } from 'react'
import { useShallow } from 'zustand/react/shallow'
import type {
  AttachmentOperationKind,
  AttachmentOperationStage,
  AttachmentProgressEvent,
  LoginView,
  VaultAttachmentView
} from '../../../shared/vault-contract'
import { authorizationTokenField, type LoginDetailCache } from '../components/vault-detail-cache'
import {
  initialAttachmentStages,
  isAttachmentCanceled,
  isCardCoverAttachment,
  upsertAttachment,
  type AttachmentDeleteTarget,
  type AttachmentOperationState
} from '../components/vault-attachment-ui'
import { useCardCoverPreviews } from './use-card-cover-previews'
import { useDescribeVaultError } from './use-describe-vault-error'
import { announce, announceError } from '@renderer/lib/vault-notices'
import type { VaultAuthorization } from '@renderer/stores/vault-authorization-store'
import type { VaultDataSync } from '@renderer/stores/vault-data-sync'
import { useVaultSessionStore, useVaultSessionStoreApi } from '@renderer/stores/vault-session-store'

export interface AttachmentPreview {
  itemId: string
  attachmentId: string
  fileName: string
  dataUrl: string
}

/**
 * Attachment upload, download, preview, delete and repair for the selected item. Only one
 * operation runs at a time; it is canceled in the main process when the selection moves to
 * another item or the vault session unmounts, and its progress events are ignored afterwards.
 */
export interface AttachmentOperations {
  operation: AttachmentOperationState | null
  imagePreview: AttachmentPreview | null
  setImagePreview: (preview: AttachmentPreview | null) => void
  deleteTarget: AttachmentDeleteTarget | null
  setDeleteTarget: (target: AttachmentDeleteTarget | null) => void
  getStageLabel: (progress: AttachmentProgressEvent) => string
  cancelAndClear: () => void
  cancel: () => Promise<void>
  download: (attachmentId: string) => Promise<void>
  preview: (
    attachmentId: string,
    options?: { openDialog?: boolean; quiet?: boolean }
  ) => Promise<void>
  upload: () => Promise<void>
  uploadSelectedCardCover: (
    itemId: string,
    sourceUrl: string
  ) => Promise<VaultAttachmentView | null>
  uploadManualCardCover: (itemId: string) => Promise<void>
  deleteSelected: () => Promise<void>
  fixLegacy: (attachmentId: string) => Promise<void>
}

export function useAttachmentOperations(
  authorization: VaultAuthorization,
  detailCache: LoginDetailCache,
  vaultData: Pick<VaultDataSync, 'refreshItems'>
): AttachmentOperations {
  const { t } = useLingui()
  const describeVaultError = useDescribeVaultError()
  const session = useVaultSessionStoreApi()
  const { selectedId, selectedLogin, setSelectedLogin } = useVaultSessionStore(
    useShallow((state) => ({
      selectedId: state.selectedId,
      selectedLogin: state.selectedLogin,
      setSelectedLogin: state.setSelectedLogin
    }))
  )
  const {
    invalidate: invalidateCardCoverListPreview,
    prefetch: prefetchCardCoverPreview,
    remember: rememberCardCoverPreview
  } = useCardCoverPreviews()
  const [attachmentOperation, setAttachmentOperation] = useState<AttachmentOperationState | null>(
    null
  )
  const [attachmentPreview, setAttachmentPreview] = useState<AttachmentPreview | null>(null)
  const [attachmentDeleteTarget, setAttachmentDeleteTarget] =
    useState<AttachmentDeleteTarget | null>(null)
  const attachmentOperationRef = useRef<AttachmentOperationState | null>(null)

  const getAttachmentStageLabel = (progress: AttachmentProgressEvent): string => {
    if (progress.stage === 'choosing-file' && progress.kind === 'download') {
      return t`Waiting for a save location`
    }
    if (progress.kind === 'preview') {
      return t`Loading image preview`
    }
    const labels: Record<AttachmentOperationStage, string> = {
      'choosing-file': t`Waiting for a file`,
      'reading-file': t`Safely reading the file`,
      encrypting: t`Encrypting locally`,
      downloading: t`Downloading attachment`,
      uploading: t`Uploading encrypted attachment`,
      deleting: t`Deleting attachment`,
      syncing: t`Syncing attachment list`
    }
    return labels[progress.stage]
  }

  const beginAttachmentOperation = useCallback(
    (kind: AttachmentOperationKind, itemId: string, fileName: string | null): string => {
      const operationId = crypto.randomUUID()
      const operation: AttachmentOperationState = {
        operationId,
        itemId,
        kind,
        stage: initialAttachmentStages[kind],
        completedBytes: 0,
        totalBytes: null,
        fileName,
        canceling: false
      }
      attachmentOperationRef.current = operation
      setAttachmentOperation(operation)
      setAttachmentDeleteTarget(null)
      return operationId
    },
    [setAttachmentDeleteTarget]
  )

  const finishAttachmentOperation = useCallback((operationId: string): void => {
    if (attachmentOperationRef.current?.operationId !== operationId) return
    attachmentOperationRef.current = null
    setAttachmentOperation((current) => (current?.operationId === operationId ? null : current))
  }, [])

  const cancelAndClearAttachmentOperation = useCallback((): void => {
    const operation = attachmentOperationRef.current
    attachmentOperationRef.current = null
    setAttachmentOperation(null)
    setAttachmentDeleteTarget(null)
    if (operation) {
      void window.bearwarden.logins
        .cancelAttachment({ operationId: operation.operationId })
        .catch(() => undefined)
    }
  }, [setAttachmentDeleteTarget])

  const isCurrentAttachmentOperation = useCallback(
    (operationId: string, itemId: string): boolean => {
      const current = attachmentOperationRef.current
      return (
        current !== null &&
        current.operationId === operationId &&
        current.itemId === itemId &&
        session.getState().selectedId === itemId
      )
    },
    [session]
  )

  const updateSelectedAttachments = useCallback(
    (
      itemId: string,
      update: (attachments: VaultAttachmentView[]) => VaultAttachmentView[]
    ): LoginView | null => {
      const cached = detailCache.get(itemId)
      const updatedAttachments = cached ? update(cached.attachments) : null
      const updatedCached =
        cached && updatedAttachments
          ? {
              ...cached,
              attachments: updatedAttachments,
              attachmentCount: updatedAttachments.length
            }
          : null
      if (updatedCached) {
        detailCache.remember(updatedCached)
      }
      if (session.getState().selectedId !== itemId) return updatedCached
      setSelectedLogin((current) => {
        if (!current || current.id !== itemId) return current
        if (updatedCached) return updatedCached
        const attachments = update(current.attachments)
        const next = { ...current, attachments, attachmentCount: attachments.length }
        detailCache.remember(next)
        return next
      })
      return updatedCached
    },
    [session, detailCache, setSelectedLogin]
  )

  useEffect(() => {
    let active = true
    queueMicrotask(() => {
      if (!active) return
      const operation = attachmentOperationRef.current
      if (operation && operation.itemId !== selectedId) cancelAndClearAttachmentOperation()
      setAttachmentDeleteTarget((current) => (current?.itemId === selectedId ? current : null))
      setAttachmentPreview((current) => (current?.itemId === selectedId ? current : null))
    })
    return () => {
      active = false
    }
  }, [cancelAndClearAttachmentOperation, selectedId])

  useEffect(() => {
    const unsubscribe = window.bearwarden.logins.onAttachmentProgress((progress) => {
      const current = attachmentOperationRef.current
      if (
        !current ||
        progress.operationId !== current.operationId ||
        progress.itemId !== current.itemId ||
        progress.itemId !== session.getState().selectedId ||
        progress.kind !== current.kind
      ) {
        return
      }
      const next: AttachmentOperationState = {
        ...current,
        ...progress,
        canceling: current.canceling
      }
      attachmentOperationRef.current = next
      setAttachmentOperation((previous) =>
        previous?.operationId === next.operationId ? next : previous
      )
    })
    return () => {
      unsubscribe()
      const operation = attachmentOperationRef.current
      attachmentOperationRef.current = null
      if (operation) {
        void window.bearwarden.logins
          .cancelAttachment({ operationId: operation.operationId })
          .catch(() => undefined)
      }
    }
  }, [session])

  async function downloadAttachment(attachmentId: string): Promise<void> {
    if (!selectedLogin || attachmentOperationRef.current) return
    const itemId = selectedLogin.id
    const attachment = selectedLogin.attachments.find((entry) => entry.id === attachmentId)
    const operationId = beginAttachmentOperation('download', itemId, attachment?.fileName ?? null)
    try {
      const result = await authorization.withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.downloadAttachment({
          id: itemId,
          attachmentId,
          operationId,
          ...authorizationTokenField(tokenFor(itemId))
        })
      )
      if (!result.canceled && session.getState().selectedId === itemId) {
        announce(t`Downloaded “${result.fileName}”.`)
      }
      if (!result.canceled) {
        await vaultData
          .refreshItems()
          .catch(() =>
            announceError(
              t`The attachment was downloaded, but the list could not be refreshed. Sync again later.`
            )
          )
      }
    } catch (downloadError) {
      if (
        isCurrentAttachmentOperation(operationId, itemId) &&
        !isAttachmentCanceled(downloadError)
      ) {
        announceError(describeVaultError(downloadError))
      }
    } finally {
      finishAttachmentOperation(operationId)
    }
  }

  async function previewAttachment(
    attachmentId: string,
    options: { openDialog?: boolean; quiet?: boolean } = {}
  ): Promise<void> {
    if (!selectedLogin || attachmentOperationRef.current) return
    const openDialog = options.openDialog ?? true
    const itemId = selectedLogin.id
    const attachment = selectedLogin.attachments.find((entry) => entry.id === attachmentId)
    if (!attachment) return
    const operationId = beginAttachmentOperation('preview', itemId, attachment.fileName)
    try {
      const result = await authorization.withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.previewAttachment({
          id: itemId,
          attachmentId,
          operationId,
          ...authorizationTokenField(tokenFor(itemId))
        })
      )
      if (session.getState().selectedId !== itemId) return
      const preview = {
        itemId,
        attachmentId,
        fileName: result.fileName,
        dataUrl: result.dataUrl
      }
      if (openDialog) setAttachmentPreview(preview)
      if (selectedLogin.type === 'card' && isCardCoverAttachment(result.fileName)) {
        rememberCardCoverPreview(selectedLogin, attachmentId, result.dataUrl)
      }
    } catch (previewError) {
      if (
        isCurrentAttachmentOperation(operationId, itemId) &&
        !isAttachmentCanceled(previewError) &&
        !options.quiet
      ) {
        announceError(describeVaultError(previewError))
      }
    } finally {
      finishAttachmentOperation(operationId)
    }
  }

  async function uploadAttachment(): Promise<void> {
    if (!selectedLogin || attachmentOperationRef.current) return
    const itemId = selectedLogin.id
    const operationId = beginAttachmentOperation('upload', itemId, null)
    try {
      const result = await authorization.withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.uploadAttachment({
          id: itemId,
          operationId,
          ...authorizationTokenField(tokenFor(itemId))
        })
      )
      if (result.attachment) {
        const updatedLogin = updateSelectedAttachments(itemId, (attachments) =>
          upsertAttachment(attachments, result.attachment!)
        )
        if (isCardCoverAttachment(result.attachment.fileName)) {
          invalidateCardCoverListPreview(itemId)
          if (updatedLogin) prefetchCardCoverPreview(updatedLogin)
        }
        if (session.getState().selectedId === itemId) {
          announce(t`Uploaded “${result.attachment.fileName}”.`)
        }
        await vaultData
          .refreshItems()
          .catch(() =>
            announceError(
              t`The attachment was uploaded, but the list could not be refreshed. Sync again later.`
            )
          )
      }
    } catch (uploadError) {
      if (isCurrentAttachmentOperation(operationId, itemId) && !isAttachmentCanceled(uploadError)) {
        announceError(describeVaultError(uploadError))
      }
    } finally {
      finishAttachmentOperation(operationId)
    }
  }

  async function uploadSelectedCardCover(
    itemId: string,
    sourceUrl: string
  ): Promise<VaultAttachmentView | null> {
    if (attachmentOperationRef.current) return null
    const operationId = beginAttachmentOperation('upload', itemId, 'cover.webp')
    try {
      const result = await authorization.withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.uploadCardCoverAttachment({
          id: itemId,
          operationId,
          sourceUrl,
          ...authorizationTokenField(tokenFor(itemId))
        })
      )
      if (!result.attachment) return null
      const updatedLogin = updateSelectedAttachments(itemId, (attachments) =>
        upsertAttachment(attachments, result.attachment!)
      )
      invalidateCardCoverListPreview(itemId)
      if (updatedLogin) prefetchCardCoverPreview(updatedLogin)
      await vaultData
        .refreshItems()
        .catch(() =>
          announceError(
            t`The card face was uploaded, but the list could not be refreshed. Sync again later.`
          )
        )
      return result.attachment
    } catch (coverError) {
      if (isCurrentAttachmentOperation(operationId, itemId) && !isAttachmentCanceled(coverError)) {
        announceError(describeVaultError(coverError))
      }
      return null
    } finally {
      finishAttachmentOperation(operationId)
    }
  }

  async function uploadManualCardCover(itemId: string): Promise<void> {
    if (attachmentOperationRef.current) return
    const operationId = beginAttachmentOperation('upload', itemId, null)
    try {
      const result = await authorization.withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.uploadCardCoverFileAttachment({
          id: itemId,
          operationId,
          ...authorizationTokenField(tokenFor(itemId))
        })
      )
      if (!result.attachment) return
      const updatedLogin = updateSelectedAttachments(itemId, (attachments) =>
        upsertAttachment(attachments, result.attachment!)
      )
      invalidateCardCoverListPreview(itemId)
      if (updatedLogin) prefetchCardCoverPreview(updatedLogin)
      if (session.getState().selectedId === itemId) {
        announce(t`Uploaded card face “${result.attachment.fileName}”.`)
      }
      await vaultData
        .refreshItems()
        .catch(() =>
          announceError(
            t`The card face was uploaded, but the list could not be refreshed. Sync again later.`
          )
        )
    } catch (coverError) {
      if (isCurrentAttachmentOperation(operationId, itemId) && !isAttachmentCanceled(coverError)) {
        announceError(describeVaultError(coverError))
      }
    } finally {
      finishAttachmentOperation(operationId)
    }
  }

  async function deleteSelectedAttachment(): Promise<void> {
    const target = attachmentDeleteTarget
    if (
      !target ||
      target.itemId !== session.getState().selectedId ||
      attachmentOperationRef.current
    )
      return
    setAttachmentDeleteTarget(null)
    const operationId = beginAttachmentOperation('delete', target.itemId, target.fileName)
    try {
      const result = await authorization.withReprompt([target.itemId], (tokenFor) =>
        window.bearwarden.logins.deleteAttachment({
          id: target.itemId,
          attachmentId: target.attachmentId,
          operationId,
          ...authorizationTokenField(tokenFor(target.itemId))
        })
      )
      const updatedLogin = updateSelectedAttachments(target.itemId, (attachments) =>
        attachments.filter((entry) => entry.id !== result.attachmentId)
      )
      if (isCardCoverAttachment(target.fileName)) {
        invalidateCardCoverListPreview(target.itemId)
        if (updatedLogin) prefetchCardCoverPreview(updatedLogin)
      }
      if (session.getState().selectedId === target.itemId)
        announce(t`Deleted “${target.fileName}”.`)
      await vaultData
        .refreshItems()
        .catch(() =>
          announceError(
            t`The attachment was deleted, but the list could not be refreshed. Sync again later.`
          )
        )
    } catch (deleteError) {
      if (
        isCurrentAttachmentOperation(operationId, target.itemId) &&
        !isAttachmentCanceled(deleteError)
      ) {
        announceError(describeVaultError(deleteError))
      }
    } finally {
      finishAttachmentOperation(operationId)
    }
  }

  async function fixLegacyAttachment(attachmentId: string): Promise<void> {
    if (!selectedLogin || attachmentOperationRef.current) return
    const itemId = selectedLogin.id
    const attachment = selectedLogin.attachments.find((entry) => entry.id === attachmentId)
    if (!attachment?.legacy) return
    const operationId = beginAttachmentOperation('fix-legacy', itemId, attachment.fileName)
    try {
      const result = await authorization.withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.fixLegacyAttachment({
          id: itemId,
          attachmentId,
          operationId,
          ...authorizationTokenField(tokenFor(itemId))
        })
      )
      const updatedLogin = updateSelectedAttachments(itemId, (attachments) => {
        const replacementIndex = attachments.findIndex((entry) => entry.id === attachmentId)
        if (replacementIndex < 0) return [...attachments, result.attachment]
        return attachments.map((entry, index) =>
          index === replacementIndex ? result.attachment : entry
        )
      })
      if (isCardCoverAttachment(attachment.fileName)) {
        invalidateCardCoverListPreview(itemId)
        if (updatedLogin) prefetchCardCoverPreview(updatedLogin)
      }
      if (session.getState().selectedId === itemId) announce(t`Repaired “${attachment.fileName}”.`)
      await vaultData
        .refreshItems()
        .catch(() =>
          announceError(
            t`The attachment was repaired, but the list could not be refreshed. Sync again later.`
          )
        )
    } catch (fixError) {
      if (isCurrentAttachmentOperation(operationId, itemId) && !isAttachmentCanceled(fixError)) {
        announceError(describeVaultError(fixError))
      }
    } finally {
      finishAttachmentOperation(operationId)
    }
  }

  async function cancelAttachmentOperation(): Promise<void> {
    const operation = attachmentOperationRef.current
    if (!operation || operation.canceling) return
    const canceling = { ...operation, canceling: true }
    attachmentOperationRef.current = canceling
    setAttachmentOperation(canceling)
    try {
      const result = await window.bearwarden.logins.cancelAttachment({
        operationId: operation.operationId
      })
      if (
        !result.canceled &&
        attachmentOperationRef.current?.operationId === operation.operationId
      ) {
        const current = { ...attachmentOperationRef.current, canceling: false }
        attachmentOperationRef.current = current
        setAttachmentOperation(current)
      }
    } catch (cancelError) {
      if (attachmentOperationRef.current?.operationId === operation.operationId) {
        const current = { ...attachmentOperationRef.current, canceling: false }
        attachmentOperationRef.current = current
        setAttachmentOperation(current)
        announceError(describeVaultError(cancelError))
      }
    }
  }

  return {
    operation: attachmentOperation,
    imagePreview: attachmentPreview,
    setImagePreview: setAttachmentPreview,
    deleteTarget: attachmentDeleteTarget,
    setDeleteTarget: setAttachmentDeleteTarget,
    getStageLabel: getAttachmentStageLabel,
    cancelAndClear: cancelAndClearAttachmentOperation,
    cancel: cancelAttachmentOperation,
    download: downloadAttachment,
    preview: previewAttachment,
    upload: uploadAttachment,
    uploadSelectedCardCover,
    uploadManualCardCover,
    deleteSelected: deleteSelectedAttachment,
    fixLegacy: fixLegacyAttachment
  }
}
