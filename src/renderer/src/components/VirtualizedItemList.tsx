import { useVirtualizer } from '@tanstack/react-virtual'
import { useCallback, useEffect, useMemo, useRef } from 'react'
import { useLingui } from '@lingui/react/macro'
import type { LoginSummary, TotpCodeView } from '../../../shared/vault-contract'
import { cn } from '@renderer/lib/utils'
import { adjacentItemIndex } from '@renderer/lib/item-selection'
import { virtualRowScrollOffsets, visibleVirtualIndexes } from '@renderer/lib/virtualized-range'
import { ItemRow, type ItemSelectionModifiers } from './DndRows'
import { isSharedLoginSummary } from './organizations-ui'

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
  showTotpCodes?: boolean
  totpCodes?: ReadonlyMap<string, TotpCodeView | null>
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
  showTotpCodes = false,
  totpCodes,
  readOnly = false,
  className
}: VirtualizedItemListProps): React.JSX.Element {
  const { t } = useLingui()
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
          row?.querySelector<HTMLButtonElement>('[data-item-row-main]')?.focus()
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
        'scroll-fade-y forced-colors:scroll-fade-none relative m-0 min-h-0 flex-1 [scrollbar-color:var(--border-strong)_transparent] list-none overflow-auto px-4 pb-6',
        className
      )}
      aria-label={t`${scopeTitle} vault items`}
    >
      <div className="relative w-full" style={{ height: virtualizer.getTotalSize() }}>
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
                className="[&>h2]:text-muted-foreground m-0 overflow-hidden p-0 [&>h2]:m-0 [&>h2]:px-[13px] [&>h2]:pt-[7px] [&>h2]:pb-[6px] [&>h2]:text-[11px] [&>h2]:font-[720]"
                style={position}
              >
                <h2 id={`group-${row.groupKey}`}>{row.label}</h2>
              </div>
            )
          }

          return (
            <ul
              key={virtualRow.key}
              className="m-0 list-none p-0 [&:has(+_[data-item-row-list]_>_[data-item-row][data-selected=true])_>_[data-item-row]]:border-b-transparent [&:has(>_[data-item-row][data-selected=true])+_[data-item-row-list]_>_[data-item-row][data-selected=true]]:rounded-t-none [&:has(>_[data-item-row][data-selected=true]):has(+_[data-item-row-list]_>_[data-item-row][data-selected=true])_>_[data-item-row][data-selected=true]]:rounded-b-none [&:has([data-item-row-main]:focus-visible)]:z-1"
              data-item-row-list=""
              aria-label={t`${row.groupLabel ?? scopeTitle} items`}
              style={position}
            >
              <ItemRow
                item={row.item}
                selected={selectedIds.has(row.item.id)}
                onSelect={onSelect}
                onPrefetch={onPrefetch}
                onFavorite={onFavorite}
                onContextMenu={onContextMenu}
                showWebsiteIcons={showWebsiteIcons}
                showTotpCode={showTotpCodes}
                totpCodes={totpCodes}
                readOnly={readOnly || isSharedLoginSummary(row.item)}
              />
            </ul>
          )
        })}
      </div>
    </div>
  )
}

export default VirtualizedItemList
