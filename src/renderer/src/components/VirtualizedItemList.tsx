import { useVirtualizer } from '@tanstack/react-virtual'
import { useCallback, useEffect, useMemo, useRef } from 'react'
import type { LoginSummary } from '../../../shared/vault-contract'
import { cn } from '@renderer/lib/utils'
import { adjacentItemIndex } from '@renderer/lib/item-selection'
import { virtualRowScrollOffsets, visibleVirtualIndexes } from '@renderer/lib/virtualized-range'
import { ItemRow, type ItemSelectionModifiers } from './DndRows'

const GROUP_HEADER_HEIGHT = 31
const ITEM_ROW_HEIGHT = 66

export interface VirtualizedItemGroup {
  key: string
  label: string | null
  items: readonly LoginSummary[]
}

interface VirtualizedItemListProps {
  groups: readonly VirtualizedItemGroup[]
  scopeTitle: string
  activeId: string | null
  selectedIds: ReadonlySet<string>
  onSelect: (id: string, modifiers: ItemSelectionModifiers) => void
  onPrefetch?: (id: string) => void
  onFavorite: (item: LoginSummary) => void
  onContextMenu: (id: string, position: { x: number; y: number }) => void
  showWebsiteIcons: boolean
  readOnly?: boolean
  className?: string
}

type VirtualizedRow =
  | {
      type: 'header'
      key: string
      groupKey: string
      label: string
    }
  | {
      type: 'item'
      key: string
      groupLabel: string | null
      item: LoginSummary
    }

export function VirtualizedItemList({
  groups,
  scopeTitle,
  activeId,
  selectedIds,
  onSelect,
  onPrefetch,
  onFavorite,
  onContextMenu,
  showWebsiteIcons,
  readOnly = false,
  className
}: VirtualizedItemListProps): React.JSX.Element {
  const scrollElementRef = useRef<HTMLDivElement>(null)
  const focusAnimationFrameRef = useRef<number | null>(null)
  const previousVisibleItemIdsRef = useRef(new Set<string>())
  const rows = useMemo<VirtualizedRow[]>(
    () =>
      groups.flatMap((group) => {
        const itemRows: VirtualizedRow[] = group.items.map((item) => ({
          type: 'item',
          key: `item:${item.id}`,
          groupLabel: group.label,
          item
        }))

        if (!group.label) return itemRows
        return [
          {
            type: 'header',
            key: `group:${group.key}`,
            groupKey: group.key,
            label: group.label
          },
          ...itemRows
        ]
      }),
    [groups]
  )
  const getItemKey = useCallback((index: number) => rows[index]?.key ?? index, [rows])
  const itemNavigation = useMemo(() => {
    const rowOffsets = virtualRowScrollOffsets(
      rows.map((row) => (row.type === 'header' ? GROUP_HEADER_HEIGHT : ITEM_ROW_HEIGHT)),
      ITEM_ROW_HEIGHT
    )
    const entries = rows.flatMap((row, rowIndex) =>
      row.type === 'item' ? [{ id: row.item.id, scrollOffset: rowOffsets[rowIndex] ?? 0 }] : []
    )
    return {
      entries,
      indexById: new Map(entries.map((entry, index) => [entry.id, index]))
    }
  }, [rows])
  // TanStack Virtual intentionally returns mutable methods that React Compiler cannot memoize.
  // eslint-disable-next-line react-hooks/incompatible-library
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollElementRef.current,
    estimateSize: (index) =>
      rows[index]?.type === 'header' ? GROUP_HEADER_HEIGHT : ITEM_ROW_HEIGHT,
    getItemKey,
    overscan: 6,
    useFlushSync: false
  })
  const virtualItems = virtualizer.getVirtualItems()
  const scrollOffset = virtualizer.scrollOffset ?? 0
  const viewportSize = virtualizer.scrollRect?.height ?? 0
  const visibleIndexes = visibleVirtualIndexes(virtualItems, scrollOffset, viewportSize)
  const visibleRangeKey = visibleIndexes.join(':')

  useEffect(() => {
    if (!activeId) return

    const handleKeyDown = (event: KeyboardEvent): void => {
      if (
        event.defaultPrevented ||
        event.isComposing ||
        event.altKey ||
        event.ctrlKey ||
        event.metaKey ||
        event.shiftKey ||
        (event.key !== 'ArrowUp' && event.key !== 'ArrowDown')
      ) {
        return
      }

      if (
        event.target instanceof HTMLElement &&
        event.target.closest(
          'input, textarea, select, [contenteditable="true"], [role="dialog"], [role="listbox"], [role="menu"], [role="option"], [role="radio"], [role="slider"], [role="spinbutton"], [role="tab"], [role="treeitem"], [aria-haspopup]'
        )
      ) {
        return
      }

      const activeIndex = itemNavigation.indexById.get(activeId) ?? -1
      const targetIndex = adjacentItemIndex(
        itemNavigation.entries.length,
        activeIndex,
        event.key === 'ArrowUp' ? 'previous' : 'next'
      )
      if (targetIndex === null) return
      const target = itemNavigation.entries[targetIndex]
      if (!target) return

      event.preventDefault()
      virtualizer.scrollToOffset(target.scrollOffset, { align: 'start' })
      if (target.id !== activeId) {
        onSelect(target.id, { toggle: false, range: false })
      }

      if (!window.matchMedia('(max-width: 680px)').matches) {
        if (focusAnimationFrameRef.current !== null) {
          window.cancelAnimationFrame(focusAnimationFrameRef.current)
        }
        focusAnimationFrameRef.current = window.requestAnimationFrame(() => {
          focusAnimationFrameRef.current = null
          const row = Array.from(document.querySelectorAll<HTMLElement>('[data-item-id]')).find(
            (candidate) => candidate.dataset.itemId === target.id
          )
          row?.querySelector<HTMLButtonElement>('.item-row-main')?.focus()
        })
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [activeId, itemNavigation, onSelect, virtualizer])

  useEffect(
    () => () => {
      if (focusAnimationFrameRef.current !== null) {
        window.cancelAnimationFrame(focusAnimationFrameRef.current)
      }
    },
    []
  )

  useEffect(() => {
    if (!onPrefetch || visibleIndexes.length === 0) {
      previousVisibleItemIdsRef.current = new Set()
      return
    }

    const visibleItemIds = new Set<string>()
    for (const index of visibleIndexes) {
      const row = rows[index]
      if (row?.type !== 'item') continue
      visibleItemIds.add(row.item.id)
      if (!previousVisibleItemIdsRef.current.has(row.item.id)) onPrefetch(row.item.id)
    }
    previousVisibleItemIdsRef.current = visibleItemIds
    // visibleRangeKey tracks the primitive indexes without depending on the virtualizer's mutable
    // array identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onPrefetch, rows, visibleRangeKey])

  return (
    <div
      ref={scrollElementRef}
      className={cn(
        'item-list virtualized-item-list scroll-fade-y forced-colors:scroll-fade-none',
        className
      )}
      aria-label={`${scopeTitle}密碼庫項目`}
    >
      <div
        className="virtualized-item-list-content"
        style={{ position: 'relative', height: virtualizer.getTotalSize() }}
      >
        {virtualItems.map((virtualRow) => {
          const row = rows[virtualRow.index]
          if (!row) return null

          const position = {
            position: 'absolute' as const,
            top: 0,
            left: 0,
            width: '100%',
            height: virtualRow.size,
            transform: `translateY(${virtualRow.start}px)`
          }

          if (row.type === 'header') {
            return (
              <div
                key={virtualRow.key}
                className="item-group virtualized-item-group-header"
                style={position}
              >
                <h2 id={`group-${row.groupKey}`}>{row.label}</h2>
              </div>
            )
          }

          return (
            <ul
              key={virtualRow.key}
              className="virtualized-item-row-list"
              aria-label={`${row.groupLabel ?? scopeTitle}項目`}
              style={{ ...position, padding: 0, margin: 0, listStyle: 'none' }}
            >
              <ItemRow
                item={row.item}
                selected={selectedIds.has(row.item.id)}
                onSelect={onSelect}
                onPrefetch={onPrefetch}
                onFavorite={onFavorite}
                onContextMenu={onContextMenu}
                showWebsiteIcons={showWebsiteIcons}
                readOnly={readOnly}
              />
            </ul>
          )
        })}
      </div>
    </div>
  )
}

export default VirtualizedItemList
