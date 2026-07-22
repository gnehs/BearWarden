import { closestCenter, pointerWithin, type CollisionDetection } from '@dnd-kit/core'
import { i18n } from '@lingui/core'
import { msg } from '@lingui/core/macro'

export const quickAccessDropIds = {
  favorites: 'quick-access:favorites',
  archive: 'quick-access:archive',
  trash: 'quick-access:trash'
} as const

export type QuickAccessDropAction = keyof typeof quickAccessDropIds
export type DraggableItemState = 'active' | 'archive'
export const FOLDER_HIERARCHY_DRAG_THRESHOLD = 18
export const folderRootDropId = 'folder:root'

export interface FolderHierarchyDragIntent {
  parentId: string | null
}

export function folderHierarchyDragIntent(
  overId: string | null,
  deltaX: number
): FolderHierarchyDragIntent | null {
  if (overId === folderRootDropId) return { parentId: null }
  if (deltaX <= -FOLDER_HIERARCHY_DRAG_THRESHOLD) return { parentId: null }
  if (deltaX >= FOLDER_HIERARCHY_DRAG_THRESHOLD && overId) return { parentId: overId }
  return null
}

export const precisePointerCollisionDetection: CollisionDetection = (args) =>
  args.pointerCoordinates === null ? closestCenter(args) : pointerWithin(args)

interface DropPreviewFolder {
  id: string
  name: string
}

interface ItemDropPreviewDescriptionOptions {
  overId: string | null
  itemState: DraggableItemState
  folders: readonly DropPreviewFolder[]
  count: number
}

export function quickAccessDropAction(
  overId: string,
  itemState: DraggableItemState
): QuickAccessDropAction | null {
  if (overId === quickAccessDropIds.trash) return 'trash'
  if (itemState !== 'active') return null
  if (overId === quickAccessDropIds.favorites) return 'favorites'
  if (overId === quickAccessDropIds.archive) return 'archive'
  return null
}

export function itemDropPreviewDescription({
  overId,
  itemState,
  folders,
  count
}: ItemDropPreviewDescriptionOptions): string | null {
  if (!overId) return null
  const quickAction = quickAccessDropAction(overId, itemState)
  if (quickAction === 'favorites') {
    return count > 1 ? i18n._(msg`Add ${count} items to Favorites`) : i18n._(msg`Add to Favorites`)
  }
  if (quickAction === 'archive') {
    return count > 1 ? i18n._(msg`Move ${count} items to Archive`) : i18n._(msg`Move to Archive`)
  }
  if (quickAction === 'trash') {
    return count > 1 ? i18n._(msg`Move ${count} items to Trash`) : i18n._(msg`Move to Trash`)
  }

  const destination =
    overId === 'folder:none'
      ? i18n._(msg`Uncategorized`)
      : folders.find((folder) => folder.id === overId)?.name
  if (!destination) return null
  return count > 1
    ? i18n._(msg`Move ${count} items to “${destination}”`)
    : i18n._(msg`Move to “${destination}”`)
}
