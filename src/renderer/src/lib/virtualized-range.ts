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
