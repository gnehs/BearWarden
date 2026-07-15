import { useVirtualizer } from '@tanstack/react-virtual'
import { useCallback, useEffect, useMemo, useRef } from 'react'
import type { LoginSummary } from '../../../shared/vault-contract'
import { cn } from '@renderer/lib/utils'
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
  selectedIds: ReadonlySet<string>
  onSelect: (id: string, modifiers: ItemSelectionModifiers) => void
  onPrefetch?: (id: string) => void
  onFavorite: (item: LoginSummary) => void
  onContextMenu: (id: string, position: { x: number; y: number }) => void
  showWebsiteIcons: boolean
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
  selectedIds,
  onSelect,
  onPrefetch,
  onFavorite,
  onContextMenu,
  showWebsiteIcons,
  className
}: VirtualizedItemListProps): React.JSX.Element {
  const scrollElementRef = useRef<HTMLDivElement>(null)
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
  const firstVirtualIndex = virtualItems[0]?.index ?? -1
  const lastVirtualIndex = virtualItems[virtualItems.length - 1]?.index ?? -1

  useEffect(() => {
    if (!onPrefetch || firstVirtualIndex < 0) {
      previousVisibleItemIdsRef.current = new Set()
      return
    }

    const visibleItemIds = new Set<string>()
    for (let index = firstVirtualIndex; index <= lastVirtualIndex; index += 1) {
      const row = rows[index]
      if (row?.type !== 'item') continue
      visibleItemIds.add(row.item.id)
      if (!previousVisibleItemIdsRef.current.has(row.item.id)) onPrefetch(row.item.id)
    }
    previousVisibleItemIdsRef.current = visibleItemIds
  }, [firstVirtualIndex, lastVirtualIndex, onPrefetch, rows])

  return (
    <div
      ref={scrollElementRef}
      className={cn(
        'item-list virtualized-item-list scroll-fade-y forced-colors:scroll-fade-none',
        className
      )}
      aria-label={`${scopeTitle}保管庫項目`}
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
              />
            </ul>
          )
        })}
      </div>
    </div>
  )
}

export default VirtualizedItemList
