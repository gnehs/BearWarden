export const quickAccessDropIds = {
  favorites: 'quick-access:favorites',
  archive: 'quick-access:archive',
  trash: 'quick-access:trash'
} as const

export type QuickAccessDropAction = keyof typeof quickAccessDropIds
export type DraggableItemState = 'active' | 'archive'

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
