import {
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
  type DragOverEvent,
  type DragStartEvent,
  type SensorDescriptor,
  type SensorOptions
} from '@dnd-kit/core'
import { arrayMove, sortableKeyboardCoordinates } from '@dnd-kit/sortable'
import { useLingui } from '@lingui/react/macro'
import { useMemo, useRef, useState } from 'react'
import { useShallow } from 'zustand/react/shallow'
import type { FolderView, LoginSummary } from '../../../shared/vault-contract'
import {
  folderHierarchyDragIntent,
  itemDropPreviewDescription,
  quickAccessDropAction
} from '../components/VaultShell-dnd'
import type { BulkActionSnapshot, MoveSnapshot } from '../components/VaultShell-model'
import type { VaultItemActions } from './use-vault-item-actions'
import { useDescribeVaultError } from './use-describe-vault-error'
import {
  planVaultFolderMove,
  sortFoldersByPosition,
  vaultFolderHierarchyRows
} from '@renderer/lib/vault-folder-tree'
import { announce, announceError } from '@renderer/lib/vault-notices'
import { useVaultSessionStore, useVaultSessionStoreApi } from '@renderer/stores/vault-session-store'

export interface VaultDragAndDropOptions {
  actions: Pick<VaultItemActions, 'addLoginsToFavorites' | 'performBulkAction' | 'moveLogins'>
  selectLogin: (id: string) => void
  setPendingBulkAction: (snapshot: BulkActionSnapshot) => void
}

export interface VaultDragAndDrop {
  sensors: SensorDescriptor<SensorOptions>[]
  activeDragItem: LoginSummary | null
  activeDragItemCount: number
  activeDragDestinationDescription: string | null
  startDrag: (event: DragStartEvent) => void
  dragOver: (event: DragOverEvent) => void
  cancelDrag: () => void
  endDrag: (event: DragEndEvent) => Promise<void>
}

/**
 * Dragging items onto folders and quick-access targets, and dragging folders to reorder or
 * nest them. Folder drags preview the new order locally and roll back if the save fails.
 */
export function useVaultDragAndDrop({
  actions,
  selectLogin,
  setPendingBulkAction
}: VaultDragAndDropOptions): VaultDragAndDrop {
  const { t } = useLingui()
  const describeVaultError = useDescribeVaultError()
  const session = useVaultSessionStoreApi()
  const folderApi = window.bearwarden.folders
  const { folders, items, sharedItems, scope, selectedIds, setFolders } = useVaultSessionStore(
    useShallow((state) => ({
      folders: state.folders,
      items: state.items,
      sharedItems: state.sharedItems,
      scope: state.scope,
      selectedIds: state.selectedIds,
      setFolders: state.setFolders
    }))
  )
  const allItems = useMemo(() => [...items, ...sharedItems], [items, sharedItems])
  const folderIds = useMemo(() => new Set(folders.map((folder) => folder.id)), [folders])
  const itemIds = useMemo(
    () =>
      new Set(
        [
          ...allItems.filter((item) => !item.deletedAt && !item.archivedAt),
          ...items.filter((item) => !item.deletedAt && item.archivedAt)
        ].map((item) => item.id)
      ),
    [allItems, items]
  )
  const [activeDragId, setActiveDragId] = useState<string | null>(null)
  const [activeDragOverId, setActiveDragOverId] = useState<string | null>(null)
  const foldersBeforeDragRef = useRef<FolderView[] | null>(null)
  const foldersDuringDragRef = useRef<FolderView[] | null>(null)

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  )

  const activeDragItem = activeDragId
    ? (allItems.find((item) => item.id === activeDragId) ?? null)
    : null
  const activeDragItemCount =
    activeDragItem && selectedIds.has(activeDragItem.id) ? selectedIds.size : 1
  const activeDragDestinationDescription = activeDragItem
    ? (itemDropPreviewDescription({
        overId: activeDragOverId,
        itemState: scope.kind === 'archive' ? 'archive' : 'active',
        folders,
        count: activeDragItemCount
      }) ?? t`Release to cancel moving`)
    : null

  function startDrag(event: DragStartEvent): void {
    const activeId = String(event.active.id)
    if (itemIds.has(activeId) && !session.getState().selectedIds.has(activeId))
      selectLogin(activeId)
    foldersBeforeDragRef.current = folderIds.has(activeId) ? folders : null
    foldersDuringDragRef.current = folderIds.has(activeId) ? folders : null
    setActiveDragId(activeId)
    setActiveDragOverId(null)
  }

  function dragOver(event: DragOverEvent): void {
    setActiveDragOverId(event.over ? String(event.over.id) : null)
    const activeId = String(event.active.id)
    const overId = event.over ? String(event.over.id) : null
    const previousFolders = foldersBeforeDragRef.current
    if (!previousFolders || !folderIds.has(activeId)) return

    const hierarchyIntent = folderHierarchyDragIntent(overId, event.delta.x)
    if (hierarchyIntent) {
      const plan = planVaultFolderMove(previousFolders, activeId, hierarchyIntent.parentId)
      foldersDuringDragRef.current = previousFolders
      setFolders(plan.kind === 'move' ? plan.folders : previousFolders)
      return
    }

    if (!overId || activeId === overId || !folderIds.has(overId)) return
    const visualFolders = vaultFolderHierarchyRows(previousFolders).map((row) => row.folder)
    const oldIndex = visualFolders.findIndex((folder) => folder.id === activeId)
    const newIndex = visualFolders.findIndex((folder) => folder.id === overId)
    if (oldIndex < 0 || newIndex < 0 || oldIndex === newIndex) return
    const reordered = vaultFolderHierarchyRows(arrayMove(visualFolders, oldIndex, newIndex)).map(
      ({ folder }, position) => ({ ...folder, position })
    )
    foldersDuringDragRef.current = reordered
    setFolders(reordered)
  }

  function cancelDrag(): void {
    const previousFolders = foldersBeforeDragRef.current
    foldersBeforeDragRef.current = null
    foldersDuringDragRef.current = null
    if (previousFolders) setFolders(previousFolders)
    setActiveDragId(null)
    setActiveDragOverId(null)
  }

  async function endDrag(event: DragEndEvent): Promise<void> {
    const previousFolders = foldersBeforeDragRef.current
    const reorderedFolders = foldersDuringDragRef.current
    foldersBeforeDragRef.current = null
    foldersDuringDragRef.current = null
    setActiveDragId(null)
    setActiveDragOverId(null)
    if (!event.over) {
      if (previousFolders) setFolders(previousFolders)
      return
    }
    const activeId = String(event.active.id)
    const overId = String(event.over.id)
    if (itemIds.has(activeId)) {
      const draggedIds = session.getState().selectedIds.has(activeId)
        ? [...session.getState().selectedIds]
        : [activeId]
      const snapshot: MoveSnapshot = {
        ids: draggedIds,
        state: scope.kind === 'archive' ? 'archive' : 'active'
      }
      const quickAction = quickAccessDropAction(overId, snapshot.state)
      if (quickAction === 'favorites') await actions.addLoginsToFavorites(snapshot)
      else if (quickAction === 'archive') {
        await actions.performBulkAction({ action: 'archive', ...snapshot })
      } else if (quickAction === 'trash') {
        setPendingBulkAction({ action: 'delete', ...snapshot })
      } else if (overId === 'folder:none') await actions.moveLogins(snapshot, null)
      else if (folderIds.has(overId)) await actions.moveLogins(snapshot, overId)
      return
    }
    if (!previousFolders || !folderIds.has(activeId)) return
    const hierarchyIntent = folderHierarchyDragIntent(overId, event.delta.x)
    if (hierarchyIntent) {
      const plan = planVaultFolderMove(previousFolders, activeId, hierarchyIntent.parentId)
      setFolders(previousFolders)
      if (plan.kind === 'noop') return
      if (plan.kind === 'invalid') {
        announceError(t`That folder can't be moved there.`)
        return
      }
      try {
        const saved = await folderApi.reparent({
          id: activeId,
          parentId: hierarchyIntent.parentId
        })
        setFolders(sortFoldersByPosition(saved))
        const movedFolder = saved.find((folder) => folder.id === activeId)
        const parentFolder =
          hierarchyIntent.parentId === null
            ? null
            : saved.find((folder) => folder.id === hierarchyIntent.parentId)
        if (movedFolder && parentFolder) {
          announce(t`Moved “${movedFolder.name}” into “${parentFolder.name}”.`)
        } else if (movedFolder) {
          announce(t`Moved “${movedFolder.name}” to the top level.`)
        }
      } catch (moveError) {
        setFolders(previousFolders)
        announceError(describeVaultError(moveError))
      }
      return
    }
    const reordered = reorderedFolders ?? previousFolders
    const orderedIds = reordered.map((folder) => folder.id)
    if (orderedIds.every((id, index) => id === previousFolders[index]?.id)) return
    try {
      const saved = await folderApi.reorder({ orderedIds })
      setFolders(sortFoldersByPosition(saved))
      announce(t`Folder order updated.`)
    } catch (reorderError) {
      setFolders(previousFolders)
      announceError(describeVaultError(reorderError))
    }
  }

  return {
    sensors,
    activeDragItem,
    activeDragItemCount,
    activeDragDestinationDescription,
    startDrag,
    dragOver,
    cancelDrag,
    endDrag
  }
}
