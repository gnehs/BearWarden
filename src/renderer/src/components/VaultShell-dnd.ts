import { closestCenter, pointerWithin, type CollisionDetection } from '@dnd-kit/core'

export const quickAccessDropIds = {
  favorites: 'quick-access:favorites',
  archive: 'quick-access:archive',
  trash: 'quick-access:trash'
} as const

export type QuickAccessDropAction = keyof typeof quickAccessDropIds
export type DraggableItemState = 'active' | 'archive'

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
  const countLabel = count > 1 ? `${count} 個項目` : null
  const quickAction = quickAccessDropAction(overId, itemState)
  if (quickAction === 'favorites') {
    return countLabel ? `新增 ${countLabel}到常用項目` : '新增到常用項目'
  }
  if (quickAction === 'archive') return countLabel ? `將 ${countLabel}移至封存` : '移至封存'
  if (quickAction === 'trash') return countLabel ? `將 ${countLabel}移至垃圾桶` : '移至垃圾桶'

  const destination =
    overId === 'folder:none' ? '未分類' : folders.find((folder) => folder.id === overId)?.name
  if (!destination) return null
  return countLabel ? `移動 ${countLabel}到「${destination}」` : `移動到「${destination}」`
}
