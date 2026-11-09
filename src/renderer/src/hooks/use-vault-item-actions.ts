import { plural } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import { useCallback } from 'react'
import { toast } from 'sonner'
import { useShallow } from 'zustand/react/shallow'
import { toLoginSummary, toSharedLoginSummary } from '../../../shared/login-summary'
import {
  MAX_LOGIN_BATCH_IDS,
  type FolderView,
  type LoginSummary,
  type LoginView,
  type SharedLoginView,
  type VaultAttachmentView
} from '../../../shared/vault-contract'
import type { LoginDraft } from '../components/LoginEditor'
import { isSharedLoginSummary } from '../components/organizations-ui'
import {
  createLoginWithOptionalSshImport,
  updateLoginWithOptionalSshImport
} from '../components/ssh-key-editor-state'
import { upsertAttachment } from '../components/vault-attachment-ui'
import {
  authorizationTokenField,
  firstAuthorizationToken,
  mergeLoginSummary,
  type LoginDetailCache
} from '../components/vault-detail-cache'
import type {
  BulkActionKind,
  BulkActionSnapshot,
  BulkSelectionState,
  MoveSnapshot
} from '../components/VaultShell-model'
import { useDescribeVaultError } from './use-describe-vault-error'
import { sortFoldersByPosition } from '@renderer/lib/vault-folder-tree'
import { announce, announceError } from '@renderer/lib/vault-notices'
import type { VaultAuthorization } from '@renderer/stores/vault-authorization-store'
import type { VaultDataSync } from '@renderer/stores/vault-data-sync'
import {
  findVaultItem,
  useVaultSessionStore,
  useVaultSessionStoreApi
} from '@renderer/stores/vault-session-store'

export interface VaultItemActionsOptions {
  authorization: VaultAuthorization
  detailCache: LoginDetailCache
  vaultData: Pick<VaultDataSync, 'refreshItems'>
  uploadSelectedCardCover: (
    itemId: string,
    sourceUrl: string
  ) => Promise<VaultAttachmentView | null>
  selectSavedItem: (id: string, login: LoginView | SharedLoginView | null) => void
  clearItemSelection: () => void
  clearEditorDirty: () => void
  resetReveals: () => void
  resetRevealedCustomFields: () => void
}

export interface VaultItemActions {
  toggleFavorite: (item: LoginSummary) => Promise<void>
  snapshotBulkAction: (action: BulkActionKind) => BulkActionSnapshot
  performBulkAction: (snapshot: BulkActionSnapshot) => Promise<boolean>
  moveLogins: (snapshot: MoveSnapshot, folderId: string | null) => Promise<boolean>
  addLoginsToFavorites: (snapshot: MoveSnapshot) => Promise<boolean>
  saveFolder: (target: FolderView | 'new', name: string) => Promise<boolean>
  deleteFolder: (folder: FolderView) => Promise<boolean>
  saveLogin: (draft: LoginDraft) => Promise<boolean>
  deletePasskey: (credentialId: string, expectedUpdatedAt: string) => Promise<LoginView | null>
  cloneLogin: () => Promise<void>
  archiveLogin: () => Promise<void>
  unarchiveLogin: () => Promise<void>
  /** Moves the selected item to Trash, or deletes it permanently when it is already there. */
  deleteLogin: () => Promise<boolean>
  restoreLogin: () => Promise<void>
  emptyTrash: () => Promise<boolean>
}

/**
 * Every item and folder mutation of the vault session. Each action runs behind the reprompt
 * for the items it touches, sets `busy` while it runs, updates the session lists and the
 * detail cache from the main-process response, and reports its outcome as a toast.
 */
export function useVaultItemActions({
  authorization,
  detailCache,
  vaultData,
  uploadSelectedCardCover,
  selectSavedItem,
  clearItemSelection,
  clearEditorDirty,
  resetReveals,
  resetRevealedCustomFields
}: VaultItemActionsOptions): VaultItemActions {
  const { t } = useLingui()
  const describeVaultError = useDescribeVaultError()
  const session = useVaultSessionStoreApi()
  const api = window.bearwarden
  const {
    busy,
    scope,
    folders,
    items,
    selectedLogin,
    editorMode,
    setBusy,
    setScope,
    setFolders,
    setItems,
    setSharedItems,
    setSelectedLogin,
    setEditorMode
  } = useVaultSessionStore(
    useShallow((state) => ({
      busy: state.busy,
      scope: state.scope,
      folders: state.folders,
      items: state.items,
      selectedLogin: state.selectedLogin,
      editorMode: state.editorMode,
      setBusy: state.setBusy,
      setScope: state.setScope,
      setFolders: state.setFolders,
      setItems: state.setItems,
      setSharedItems: state.setSharedItems,
      setSelectedLogin: state.setSelectedLogin,
      setEditorMode: state.setEditorMode
    }))
  )
  const selectedSummary = useVaultSessionStore((state) =>
    state.selectedId ? (findVaultItem(state, state.selectedId) ?? null) : null
  )
  const selectedSharedSummary =
    selectedSummary && isSharedLoginSummary(selectedSummary) ? selectedSummary : null
  const trashItems = items.filter((item) => item.deletedAt)

  function applyUpdatedSummaries(updated: readonly LoginSummary[]): void {
    const updatedById = new Map(updated.map((item) => [item.id, item]))
    for (const item of updated) detailCache.mergeSummary(item)
    setItems((current) => current.map((item) => updatedById.get(item.id) ?? item))
    setSelectedLogin((current) => {
      if (!current) return current
      const summary = updatedById.get(current.id)
      return summary ? mergeLoginSummary(current, summary) : current
    })
  }

  const toggleFavorite = useCallback(
    async (item: LoginSummary): Promise<void> => {
      try {
        const updated = await authorization.withReprompt([item.id], (tokenFor) =>
          api.logins.setFavorite({
            id: item.id,
            favorite: !item.favorite,
            ...authorizationTokenField(tokenFor(item.id))
          })
        )
        detailCache.mergeSummary(updated)
        setItems((current) => current.map((entry) => (entry.id === updated.id ? updated : entry)))
        setSelectedLogin((current) =>
          current?.id === updated.id ? mergeLoginSummary(current, updated) : current
        )
        announce(updated.favorite ? t`Added to favorites.` : t`Removed from favorites.`)
      } catch (favoriteError) {
        announceError(describeVaultError(favoriteError))
      }
    },
    [api.logins, authorization, describeVaultError, detailCache, setItems, setSelectedLogin, t]
  )

  function revalidateBulkSelection(
    ids: readonly string[],
    expectedState: BulkSelectionState
  ): LoginSummary[] | null {
    const uniqueIds = new Set(ids)
    if (ids.length === 0 || uniqueIds.size !== ids.length) return null
    const revalidated: LoginSummary[] = []
    for (const id of ids) {
      const item = findVaultItem(session.getState(), id)
      if (!item) return null
      const stateMatches =
        expectedState === 'trash'
          ? Boolean(item.deletedAt)
          : expectedState === 'archive'
            ? !item.deletedAt && Boolean(item.archivedAt)
            : !item.deletedAt && !item.archivedAt
      if (!stateMatches) return null
      revalidated.push(item)
    }
    return revalidated
  }

  function snapshotBulkAction(action: BulkActionKind): BulkActionSnapshot {
    const state: BulkSelectionState =
      action === 'restore' || action === 'deletePermanently'
        ? 'trash'
        : action === 'unarchive' || (action === 'delete' && scope.kind === 'archive')
          ? 'archive'
          : 'active'
    return { action, ids: [...session.getState().selectedIds], state }
  }

  async function performBulkAction(snapshot: BulkActionSnapshot): Promise<boolean> {
    if (busy) return false
    if (snapshot.ids.length === 0) {
      announceError(t`Select at least one item first.`)
      return false
    }
    if (snapshot.ids.length > MAX_LOGIN_BATCH_IDS) {
      announceError(t`You can process up to ${MAX_LOGIN_BATCH_IDS} items at a time.`)
      return false
    }
    if (!revalidateBulkSelection(snapshot.ids, snapshot.state)) {
      announceError(
        t`The selection changed, so no action was taken. Select the items again and retry.`
      )
      return false
    }

    setBusy(true)
    try {
      let affectedCount = 0
      let updated: LoginSummary[] = []
      try {
        await authorization.withReprompt(snapshot.ids, async (tokenFor) => {
          const request = {
            ids: snapshot.ids,
            ...authorizationTokenField(firstAuthorizationToken(snapshot.ids, tokenFor))
          }
          if (snapshot.action === 'archive') {
            updated = await api.logins.archiveMany(request)
            affectedCount = updated.length
            return
          }
          if (snapshot.action === 'unarchive') {
            updated = await api.logins.unarchiveMany(request)
            affectedCount = updated.length
            return
          }
          if (snapshot.action === 'restore') {
            updated = await api.logins.restoreMany(request)
            affectedCount = updated.length
            return
          }
          affectedCount =
            snapshot.action === 'delete'
              ? await api.logins.deleteMany(request)
              : await api.logins.deletePermanentlyMany(request)
        })
      } catch (bulkError) {
        announceError(describeVaultError(bulkError))
        return false
      }

      if (snapshot.action === 'delete' || snapshot.action === 'deletePermanently') {
        detailCache.invalidate(snapshot.ids)
        const deletedIds = new Set(snapshot.ids)
        setItems((current) => current.filter((item) => !deletedIds.has(item.id)))
        clearItemSelection()
      } else {
        applyUpdatedSummaries(updated)
      }
      const message =
        snapshot.action === 'archive'
          ? t`Archived ${affectedCount} items.`
          : snapshot.action === 'unarchive'
            ? t`Unarchived ${affectedCount} items.`
            : snapshot.action === 'delete'
              ? t`Moved ${affectedCount} items to Trash.`
              : snapshot.action === 'restore'
                ? t`Restored ${affectedCount} items.`
                : t`Permanently deleted ${affectedCount} items.`
      try {
        await vaultData.refreshItems()
      } catch {
        toast.warning(t`${message} The list could not be refreshed. Try again later.`)
        return true
      }
      announce(message)
      return true
    } finally {
      setBusy(false)
    }
  }

  async function moveLogins(snapshot: MoveSnapshot, folderId: string | null): Promise<boolean> {
    const previous = revalidateBulkSelection(snapshot.ids, snapshot.state)
    if (!previous) {
      announceError(
        t`The selection changed, so no action was taken. Select the items again and retry.`
      )
      return false
    }
    const movable = previous.filter((item) => item.folderId !== folderId)
    if (movable.length === 0) {
      return true
    }
    if (movable.length > MAX_LOGIN_BATCH_IDS) {
      announceError(t`You can move up to ${MAX_LOGIN_BATCH_IDS} items at a time.`)
      return false
    }
    const movableIds = new Set(movable.map((item) => item.id))
    setBusy(true)
    for (const item of movable) detailCache.mergeSummary({ ...item, folderId })
    setItems((current) =>
      current.map((item) => (movableIds.has(item.id) ? { ...item, folderId } : item))
    )
    try {
      const movableItemIds = movable.map((item) => item.id)
      const updated = await authorization.withReprompt(movableItemIds, (tokenFor) =>
        api.logins.moveMany({
          ids: movableItemIds,
          folderId,
          ...authorizationTokenField(firstAuthorizationToken(movableItemIds, tokenFor))
        })
      )
      applyUpdatedSummaries(updated)
      const destination = folders.find((folder) => folder.id === folderId)?.name ?? t`Unfiled`
      announce(
        updated.length > 1
          ? t`Moved ${updated.length} items to “${destination}”.`
          : t`Moved to “${destination}”.`
      )
      return true
    } catch (moveError) {
      const previousById = new Map(previous.map((item) => [item.id, item]))
      for (const item of previous) detailCache.mergeSummary(item)
      setItems((current) => current.map((item) => previousById.get(item.id) ?? item))
      announceError(describeVaultError(moveError))
      return false
    } finally {
      setBusy(false)
    }
  }

  async function addLoginsToFavorites(snapshot: MoveSnapshot): Promise<boolean> {
    if (busy) return false
    const previous = revalidateBulkSelection(snapshot.ids, snapshot.state)
    if (!previous) {
      announceError(
        t`The selection changed, so no action was taken. Select the items again and retry.`
      )
      return false
    }
    const itemsToUpdate = previous.filter((item) => !item.favorite)
    if (itemsToUpdate.length === 0) return true
    if (itemsToUpdate.length > MAX_LOGIN_BATCH_IDS) {
      announceError(t`You can process up to ${MAX_LOGIN_BATCH_IDS} items at a time.`)
      return false
    }

    const ids = itemsToUpdate.map((item) => item.id)
    setBusy(true)
    try {
      const updated = await authorization.withReprompt(ids, (tokenFor) =>
        Promise.all(
          ids.map((id) =>
            api.logins.setFavorite({
              id,
              favorite: true,
              ...authorizationTokenField(tokenFor(id))
            })
          )
        )
      )
      applyUpdatedSummaries(updated)
      announce(
        updated.length > 1 ? t`Added ${updated.length} items to favorites.` : t`Added to favorites.`
      )
      return true
    } catch (favoriteError) {
      await vaultData.refreshItems().catch(() => undefined)
      announceError(describeVaultError(favoriteError))
      return false
    } finally {
      setBusy(false)
    }
  }

  async function saveFolder(folderDialog: FolderView | 'new', name: string): Promise<boolean> {
    setBusy(true)
    try {
      if (folderDialog === 'new') {
        const created = await api.folders.create({ name })
        setFolders((current) => sortFoldersByPosition([...current, created]))
        announce(t`Created folder “${created.name}”.`)
      } else if (folderDialog) {
        const updatedFolders = await api.folders.update({
          id: folderDialog.id,
          name
        })
        setFolders(sortFoldersByPosition(updatedFolders))
        const updated = updatedFolders.find((folder) => folder.id === folderDialog.id)
        if (updated) announce(t`Renamed to “${updated.name}”.`)
      }
      return true
    } catch (folderError) {
      announceError(describeVaultError(folderError))
      return false
    } finally {
      setBusy(false)
    }
  }

  async function deleteFolder(folderDialog: FolderView): Promise<boolean> {
    setBusy(true)
    try {
      const containedIds = items
        .filter((item) => item.folderId === folderDialog.id)
        .map((item) => item.id)
      await authorization.withReprompt(containedIds, (tokenFor) =>
        api.folders.delete({
          id: folderDialog.id,
          ...authorizationTokenField(firstAuthorizationToken(containedIds, tokenFor))
        })
      )
      detailCache.moveFolderContentsToUnfiled(folderDialog.id)
      setFolders((current) => current.filter((folder) => folder.id !== folderDialog.id))
      setItems((current) =>
        current.map((item) =>
          item.folderId === folderDialog.id ? { ...item, folderId: null } : item
        )
      )
      if (scope.kind === 'folder' && scope.folderId === folderDialog.id)
        setScope({ kind: 'unfiled' })
      announce(t`Deleted folder “${folderDialog.name}”. Its items were moved to Unfiled.`)
      return true
    } catch (folderError) {
      announceError(describeVaultError(folderError))
      return false
    } finally {
      setBusy(false)
    }
  }

  async function saveLogin(draft: LoginDraft): Promise<boolean> {
    setBusy(true)
    try {
      const changedSecrets = new Set(draft.changedSecrets)
      const customFields = draft.customFields.map((field) => ({
        source: field.source,
        name: field.name,
        type: field.type,
        value: field.value,
        linkedId: field.linkedId
      }))
      const fields = {
        username: draft.username,
        uri: draft.uri || null,
        uris: draft.uris.map((entry) => ({ uri: entry.uri, match: entry.match })),
        cardholderName: draft.cardholderName,
        brand: draft.brand,
        expMonth: draft.expMonth,
        expYear: draft.expYear,
        title: draft.title,
        firstName: draft.firstName,
        middleName: draft.middleName,
        lastName: draft.lastName,
        address1: draft.address1,
        address2: draft.address2,
        address3: draft.address3,
        city: draft.city,
        state: draft.state,
        postalCode: draft.postalCode,
        country: draft.country,
        company: draft.company,
        email: draft.email,
        phone: draft.phone,
        identityUsername: draft.identityUsername,
        publicKey: draft.publicKey,
        fingerprint: draft.fingerprint,
        ...(changedSecrets.has('password') ? { password: draft.password } : {}),
        ...(changedSecrets.has('totp') ? { totp: draft.totp } : {}),
        ...(changedSecrets.has('number') ? { number: draft.number } : {}),
        ...(changedSecrets.has('code') ? { code: draft.code } : {}),
        ...(changedSecrets.has('ssn') ? { ssn: draft.ssn } : {}),
        ...(changedSecrets.has('passportNumber') ? { passportNumber: draft.passportNumber } : {}),
        ...(changedSecrets.has('licenseNumber') ? { licenseNumber: draft.licenseNumber } : {}),
        ...(changedSecrets.has('privateKey') ? { privateKey: draft.privateKey } : {})
      }
      if (editorMode === 'create') {
        const request = {
          type: draft.type,
          name: draft.name,
          ...fields,
          notes: draft.notes || null,
          folderId: draft.folderId,
          favorite: draft.favorite,
          reprompt: draft.reprompt,
          customFields
        }
        if (draft.ownerOrganizationId) {
          if (draft.sshImportToken) throw new Error('Shared SSH key imports are not supported.')
          const created = await api.sharedLogins.create({
            type: draft.type,
            name: draft.name,
            ...fields,
            notes: draft.notes || null,
            organizationId: draft.ownerOrganizationId,
            collectionIds: draft.collectionIds,
            customFields
          })
          detailCache.remember(created)
          setSharedItems((current) => [...current, toSharedLoginSummary(created)])
          setScope({ kind: 'organization', organizationId: created.organizationId })
          selectSavedItem(created.id, created)
          announce(t`Created “${created.name}”.`)
        } else {
          const created = await createLoginWithOptionalSshImport(request, draft.sshImportToken, {
            create: api.logins.create,
            createImported: api.sshKeys.createImported
          })
          const cardCoverAttachment =
            draft.type === 'card' && draft.cardCoverSourceUrl
              ? await uploadSelectedCardCover(created.id, draft.cardCoverSourceUrl)
              : null
          const createdWithCardCover = cardCoverAttachment
            ? {
                ...created,
                attachments: [...created.attachments, cardCoverAttachment],
                attachmentCount: created.attachments.length + 1
              }
            : created
          if (createdWithCardCover.reprompt === 0) {
            detailCache.remember(createdWithCardCover)
          }
          setItems((current) => [...current, toLoginSummary(created)])
          setScope({ kind: 'all' })
          selectSavedItem(
            created.id,
            createdWithCardCover.reprompt === 0 ? createdWithCardCover : null
          )
          announce(t`Created “${created.name}”.`)
        }
      } else if (selectedLogin) {
        const itemId = selectedLogin.id
        if (selectedSharedSummary) {
          if (draft.sshImportToken) throw new Error('Shared SSH key imports are not supported.')
          const updated = await api.sharedLogins.update({
            id: itemId,
            expectedUpdatedAt: draft.expectedUpdatedAt ?? undefined,
            name: draft.name,
            ...fields,
            notes: draft.notes || null,
            customFields
          })
          setSharedItems((current) =>
            current.map((item) => (item.id === updated.id ? toSharedLoginSummary(updated) : item))
          )
          setSelectedLogin(updated)
          announce(t`Saved “${updated.name}”.`)
        } else {
          const updated = await authorization.withReprompt([itemId], (tokenFor) => {
            const request = {
              id: itemId,
              expectedUpdatedAt: draft.expectedUpdatedAt ?? undefined,
              name: draft.name,
              ...fields,
              notes: draft.notes || null,
              folderId: draft.folderId,
              favorite: draft.favorite,
              reprompt: draft.reprompt,
              ...authorizationTokenField(tokenFor(itemId)),
              customFields
            }
            return updateLoginWithOptionalSshImport(request, draft.sshImportToken, {
              update: api.logins.update,
              updateImported: api.sshKeys.updateImported
            })
          })
          const cardCoverAttachment =
            draft.type === 'card' && draft.cardCoverSourceUrl
              ? await uploadSelectedCardCover(itemId, draft.cardCoverSourceUrl)
              : null
          const updatedAttachments = cardCoverAttachment
            ? upsertAttachment(updated.attachments, cardCoverAttachment)
            : null
          const updatedWithCardCover = updatedAttachments
            ? {
                ...updated,
                attachments: updatedAttachments,
                attachmentCount: updatedAttachments.length
              }
            : updated
          if (updatedWithCardCover.reprompt === 0 || authorization.token(itemId)) {
            detailCache.remember(updatedWithCardCover)
          } else {
            detailCache.forget(itemId)
          }
          setItems((current) =>
            current.map((item) =>
              item.id === updatedWithCardCover.id ? toLoginSummary(updatedWithCardCover) : item
            )
          )
          setSelectedLogin(
            updatedWithCardCover.reprompt === 0 || authorization.token(itemId)
              ? updatedWithCardCover
              : null
          )
          announce(t`Saved “${updatedWithCardCover.name}”.`)
        }
      }
      resetRevealedCustomFields()
      clearEditorDirty()
      setEditorMode(null)
      return true
    } catch (saveError) {
      announceError(describeVaultError(saveError))
      return false
    } finally {
      setBusy(false)
    }
  }

  async function deletePasskey(
    credentialId: string,
    expectedUpdatedAt: string
  ): Promise<LoginView | null> {
    if (!selectedLogin || selectedLogin.deletedAt || selectedLogin.type !== 'login') return null
    setBusy(true)
    try {
      const itemId = selectedLogin.id
      let operationAuthorizationToken: string | undefined
      const updated = await authorization.withReprompt([itemId], (tokenFor) => {
        operationAuthorizationToken = tokenFor(itemId)
        return api.passkeys.delete({
          id: itemId,
          credentialId,
          expectedUpdatedAt,
          ...authorizationTokenField(operationAuthorizationToken)
        })
      })
      const canRetainDetail = updated.reprompt === 0 || operationAuthorizationToken !== undefined
      if (canRetainDetail) {
        detailCache.remember(updated)
      } else {
        detailCache.forget(itemId)
      }
      setItems((current) =>
        current.map((item) => (item.id === updated.id ? toLoginSummary(updated) : item))
      )
      setSelectedLogin(canRetainDetail ? updated : null)
      announce(t`Passkey deleted.`)
      return updated
    } catch (deleteError) {
      announceError(describeVaultError(deleteError))
      return null
    } finally {
      setBusy(false)
    }
  }

  async function cloneLogin(): Promise<void> {
    if (!selectedLogin || selectedLogin.deletedAt) return
    setBusy(true)
    try {
      const itemId = selectedLogin.id
      const cloned = await authorization.withReprompt([itemId], (tokenFor) =>
        api.logins.clone({
          id: itemId,
          ...authorizationTokenField(tokenFor(itemId))
        })
      )
      if (cloned.reprompt === 0) detailCache.remember(cloned)
      setItems((current) => [...current, toLoginSummary(cloned)])
      setScope(cloned.archivedAt ? { kind: 'archive' } : { kind: 'all' })
      selectSavedItem(cloned.id, cloned.reprompt === 0 ? cloned : null)
      resetReveals()
      announce(t`Created “${cloned.name}”.`)
    } catch (cloneError) {
      announceError(describeVaultError(cloneError))
    } finally {
      setBusy(false)
    }
  }

  async function archiveLogin(): Promise<void> {
    if (!selectedLogin || selectedLogin.deletedAt || selectedLogin.archivedAt) return
    setBusy(true)
    try {
      const itemId = selectedLogin.id
      const archived = await authorization.withReprompt([itemId], (tokenFor) =>
        api.logins.archive({
          id: itemId,
          ...authorizationTokenField(tokenFor(itemId))
        })
      )
      detailCache.remember(archived)
      await vaultData.refreshItems()
      setScope({ kind: 'archive' })
      selectSavedItem(archived.id, archived)
      announce(t`Archived “${archived.name}”.`)
    } catch (archiveError) {
      announceError(describeVaultError(archiveError))
    } finally {
      setBusy(false)
    }
  }

  async function unarchiveLogin(): Promise<void> {
    if (!selectedLogin || selectedLogin.deletedAt || !selectedLogin.archivedAt) return
    setBusy(true)
    try {
      const itemId = selectedLogin.id
      const restored = await authorization.withReprompt([itemId], (tokenFor) =>
        api.logins.unarchive({
          id: itemId,
          ...authorizationTokenField(tokenFor(itemId))
        })
      )
      detailCache.remember(restored)
      await vaultData.refreshItems()
      setScope({ kind: 'all' })
      selectSavedItem(restored.id, restored)
      announce(t`Unarchived “${restored.name}”.`)
    } catch (unarchiveError) {
      announceError(describeVaultError(unarchiveError))
    } finally {
      setBusy(false)
    }
  }

  async function deleteLogin(): Promise<boolean> {
    if (!selectedSummary) return false
    setBusy(true)
    try {
      const itemId = selectedSummary.id
      await authorization.withReprompt([itemId], (tokenFor) => {
        const request = {
          id: itemId,
          ...authorizationTokenField(tokenFor(itemId))
        }
        return selectedSummary.deletedAt
          ? api.logins.deletePermanently(request)
          : api.logins.delete(request)
      })
      detailCache.forget(selectedSummary.id)
      await vaultData.refreshItems()
      clearItemSelection()
      announce(selectedSummary.deletedAt ? t`Item permanently deleted.` : t`Item moved to Trash.`)
      return true
    } catch (deleteError) {
      announceError(describeVaultError(deleteError))
      return false
    } finally {
      setBusy(false)
    }
  }

  async function restoreLogin(): Promise<void> {
    if (!selectedSummary?.deletedAt) return
    setBusy(true)
    try {
      const itemId = selectedSummary.id
      const restored = await authorization.withReprompt([itemId], (tokenFor) =>
        api.logins.restore({
          id: itemId,
          ...authorizationTokenField(tokenFor(itemId))
        })
      )
      detailCache.remember(restored)
      await vaultData.refreshItems()
      setScope(restored.archivedAt ? { kind: 'archive' } : { kind: 'all' })
      selectSavedItem(restored.id, restored)
      announce(t`Restored “${restored.name}”.`)
    } catch (restoreError) {
      announceError(describeVaultError(restoreError))
    } finally {
      setBusy(false)
    }
  }

  async function emptyTrash(): Promise<boolean> {
    setBusy(true)
    try {
      const trashIds = trashItems.map((item) => item.id)
      const count = await authorization.withReprompt(trashIds, (tokenFor) =>
        api.logins.emptyTrash({
          ...authorizationTokenField(firstAuthorizationToken(trashIds, tokenFor))
        })
      )
      detailCache.clear()
      await vaultData.refreshItems()
      clearItemSelection()
      announce(
        t({
          message: plural(count, {
            one: 'Permanently deleted # item.',
            other: 'Permanently deleted # items.'
          })
        })
      )
      return true
    } catch (emptyError) {
      announceError(describeVaultError(emptyError))
      return false
    } finally {
      setBusy(false)
    }
  }

  return {
    toggleFavorite,
    snapshotBulkAction,
    performBulkAction,
    moveLogins,
    addLoginsToFavorites,
    saveFolder,
    deleteFolder,
    saveLogin,
    deletePasskey,
    cloneLogin,
    archiveLogin,
    unarchiveLogin,
    deleteLogin,
    restoreLogin,
    emptyTrash
  }
}
