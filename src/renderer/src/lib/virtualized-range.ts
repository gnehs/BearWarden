export interface VirtualRangeItem {
  index: number
  start: number
  end: number
}

/** Returns only rows intersecting the viewport; virtualizer overscan rows are excluded. */
export function visibleVirtualIndexes(
  items: readonly VirtualRangeItem[],
  scrollOffset: number,
  viewportSize: number
): number[] {
  if (viewportSize <= 0) return []
  const viewportEnd = scrollOffset + viewportSize
  return items
    .filter((item) => item.end > scrollOffset && item.start < viewportEnd)
    .map((item) => item.index)
}

/** Returns the offset that positions each row at a stable inset from the viewport top. */
export function virtualRowScrollOffsets(rowSizes: readonly number[], topInset: number): number[] {
  const inset = Math.max(0, topInset)
  let rowStart = 0
  return rowSizes.map((size) => {
    const offset = Math.max(0, rowStart - inset)
    rowStart += Math.max(0, size)
    return offset
  })
}
