export interface ItemSelectionState {
  selectedIds: Set<string>
  anchorId: string | null
  activeId: string | null
}

export function adjacentItemIndex(
  itemCount: number,
  activeIndex: number,
  direction: 'previous' | 'next'
): number | null {
  if (itemCount <= 0) return null
  if (activeIndex < 0 || activeIndex >= itemCount)
    return direction === 'previous' ? itemCount - 1 : 0

  const offset = direction === 'previous' ? -1 : 1
  return Math.max(0, Math.min(itemCount - 1, activeIndex + offset))
}

export interface NormalizeItemSelectionInput {
  selectedIds: ReadonlySet<string>
  anchorId: string | null
  activeId: string | null
  orderedIds: readonly string[]
}

export interface UpdateItemSelectionInput extends NormalizeItemSelectionInput {
  targetId: string
  toggle?: boolean
  range?: boolean
}

/**
 * Removes IDs that are not currently visible and repairs the selection cursor.
 * Returned IDs always follow the supplied item order.
 */
export function normalizeItemSelection({
  selectedIds,
  anchorId,
  activeId,
  orderedIds
}: NormalizeItemSelectionInput): ItemSelectionState {
  const allowedIds = new Set(orderedIds)
  const normalizedSelectedIds = new Set(orderedIds.filter((id) => selectedIds.has(id)))
  const lastSelectedId = findLastSelectedId(normalizedSelectedIds, orderedIds)
  const normalizedActiveId =
    activeId !== null && normalizedSelectedIds.has(activeId) ? activeId : lastSelectedId
  const normalizedAnchorId =
    anchorId !== null && normalizedSelectedIds.has(anchorId) ? anchorId : normalizedActiveId

  return {
    selectedIds: normalizedSelectedIds,
    anchorId: allowedIds.has(normalizedAnchorId ?? '') ? normalizedAnchorId : null,
    activeId: allowedIds.has(normalizedActiveId ?? '') ? normalizedActiveId : null
  }
}

/**
 * Calculates list selection after a click without mutating the previous state.
 */
export function updateItemSelection({
  selectedIds,
  anchorId,
  activeId,
  orderedIds,
  targetId,
  toggle = false,
  range = false
}: UpdateItemSelectionInput): ItemSelectionState {
  const current = normalizeItemSelection({ selectedIds, anchorId, activeId, orderedIds })
  const targetIndex = orderedIds.indexOf(targetId)

  if (targetIndex === -1) return current

  if (range) {
    const rangeAnchorId = findRangeAnchor(current, targetId, orderedIds)
    const rangeIds = idsInRange(rangeAnchorId, targetId, orderedIds)
    const nextSelectedIds = toggle
      ? new Set([...current.selectedIds, ...rangeIds])
      : new Set(rangeIds)

    return normalizeItemSelection({
      selectedIds: nextSelectedIds,
      anchorId: rangeAnchorId,
      activeId: targetId,
      orderedIds
    })
  }

  if (toggle) {
    const nextSelectedIds = new Set(current.selectedIds)

    if (nextSelectedIds.has(targetId)) {
      nextSelectedIds.delete(targetId)
      const nextActiveId =
        current.activeId === targetId
          ? findLastSelectedId(nextSelectedIds, orderedIds)
          : current.activeId

      return normalizeItemSelection({
        selectedIds: nextSelectedIds,
        anchorId: current.anchorId === targetId ? nextActiveId : current.anchorId,
        activeId: nextActiveId,
        orderedIds
      })
    }

    nextSelectedIds.add(targetId)
    return normalizeItemSelection({
      selectedIds: nextSelectedIds,
      anchorId: targetId,
      activeId: targetId,
      orderedIds
    })
  }

  return {
    selectedIds: new Set([targetId]),
    anchorId: targetId,
    activeId: targetId
  }
}

function findRangeAnchor(
  { anchorId, activeId }: ItemSelectionState,
  targetId: string,
  orderedIds: readonly string[]
): string {
  if (anchorId !== null && orderedIds.includes(anchorId)) return anchorId
  if (activeId !== null && orderedIds.includes(activeId)) return activeId
  return targetId
}

function idsInRange(anchorId: string, targetId: string, orderedIds: readonly string[]): string[] {
  const start = orderedIds.indexOf(anchorId)
  const end = orderedIds.indexOf(targetId)
  return orderedIds.slice(Math.min(start, end), Math.max(start, end) + 1)
}

function findLastSelectedId(
  selectedIds: ReadonlySet<string>,
  orderedIds: readonly string[]
): string | null {
  for (let index = orderedIds.length - 1; index >= 0; index -= 1) {
    const id = orderedIds[index]
    if (selectedIds.has(id)) return id
  }

  return null
}
