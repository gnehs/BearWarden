import { useDndContext, useDraggable } from '@dnd-kit/core'
import { useSortable } from '@dnd-kit/sortable'
import { CSS, useCombinedRefs } from '@dnd-kit/utilities'
import NumberFlow from '@number-flow/react'
import { memo, useEffect, useRef } from 'react'
import { useLingui } from '@lingui/react/macro'
import { Folder, FolderOpen, Folders, MoreHorizontal, Star } from 'lucide-react'
import type { FolderView, LoginSummary, TotpCodeView } from '../../../shared/vault-contract'
import { normalizeBitwardenCardBrand } from '../lib/payment-card'
import PaymentCardBrandMark from './PaymentCardBrandMark'
import WebsiteIcon from './WebsiteIcon'
import { itemListIcons } from './vault-item-type-icons'
import {
  sidebarCountClassName,
  sidebarRowClassName,
  sidebarRowDropClassName,
  sidebarRowSelectedClassName
} from './VaultShell-primitives'
import { Button } from '@renderer/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@renderer/components/ui/tooltip'
import { cn } from '@renderer/lib/utils'

interface RowIconButtonProps extends React.ComponentProps<typeof Button> {
  label: string
}

function RowIconButton({ label, children, ...props }: RowIconButtonProps): React.JSX.Element {
  const { active } = useDndContext()
  return (
    <Tooltip disabled={active != null}>
      <TooltipTrigger render={<Button aria-label={label} {...props} />}>{children}</TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}

interface ItemRowProps {
  item: LoginSummary
  cardCoverImageSrc?: string
  selected: boolean
  onSelect: (id: string, modifiers: ItemSelectionModifiers) => void
  onPrefetch?: (id: string) => void
  onFavorite: (item: LoginSummary) => void
  onContextMenu: (id: string, position: { x: number; y: number }) => void
  showWebsiteIcons: boolean
  showTotpCode?: boolean
  totpCodes?: ReadonlyMap<string, TotpCodeView | null>
  readOnly?: boolean
}

export interface ItemSelectionModifiers {
  toggle: boolean
  range: boolean
}

export const ItemRow = memo(function ItemRow({
  item,
  cardCoverImageSrc,
  selected,
  onSelect,
  onPrefetch,
  onFavorite,
  onContextMenu,
  showWebsiteIcons,
  showTotpCode = false,
  totpCodes,
  readOnly = false
}: ItemRowProps): React.JSX.Element {
  const { t } = useLingui()
  const { attributes, listeners, setNodeRef, setActivatorNodeRef, isDragging } = useDraggable({
    id: item.id,
    disabled: readOnly,
    attributes: {
      role: 'listitem',
      roleDescription: t`Draggable item`
    }
  })
  const setRowRef = useCombinedRefs(setNodeRef, setActivatorNodeRef)
  const prefetchTimerRef = useRef<number | null>(null)

  useEffect(
    () => () => {
      if (prefetchTimerRef.current !== null) window.clearTimeout(prefetchTimerRef.current)
    },
    []
  )

  const cancelPrefetch = (): void => {
    if (prefetchTimerRef.current === null) return
    window.clearTimeout(prefetchTimerRef.current)
    prefetchTimerRef.current = null
  }

  const schedulePrefetch = (): void => {
    cancelPrefetch()
    prefetchTimerRef.current = window.setTimeout(() => {
      prefetchTimerRef.current = null
      onPrefetch?.(item.id)
    }, 80)
  }

  const ItemIcon = itemListIcons[item.type]
  const shouldShowTotpCode =
    showTotpCode && !readOnly && item.type === 'login' && Boolean(item.hasTotp)
  const totpCode = shouldShowTotpCode ? totpCodes?.get(item.id) : undefined
  const hasTotpResult = shouldShowTotpCode && totpCodes?.has(item.id)

  return (
    <li
      ref={setRowRef}
      data-item-id={item.id}
      data-item-row=""
      data-selected={selected ? 'true' : 'false'}
      className={cn(
        'group/item has-[[data-item-row-main]:focus-visible]:outline-ring/72 relative grid cursor-grab touch-none items-center rounded-2xl border-0 has-[[data-item-row-main]:focus-visible]:outline-3 has-[[data-item-row-main]:focus-visible]:outline-offset-2',
        shouldShowTotpCode ? 'grid-cols-1' : 'grid-cols-[minmax(0,1fr)_auto] pr-3',
        !selected && 'hover:bg-sidebar-overlay active:bg-sidebar-overlay-hover',
        selected &&
          'text-foreground bg-sidebar-overlay-hover forced-colors:outline-2 forced-colors:outline-offset-[-2px] forced-colors:outline-[Highlight]',
        isDragging && 'cursor-grabbing opacity-0'
      )}
      {...attributes}
      {...listeners}
      onContextMenu={(event) => {
        event.preventDefault()
        if (readOnly) return
        onSelect(item.id, { toggle: false, range: false })
        onContextMenu(item.id, { x: Math.round(event.clientX), y: Math.round(event.clientY) })
      }}
    >
      <button
        className={cn(
          'grid h-16 min-w-0 items-center gap-3 px-3 text-left focus-visible:outline-none',
          shouldShowTotpCode
            ? 'grid-cols-[auto_minmax(0,1fr)_auto]'
            : 'grid-cols-[auto_minmax(0,1fr)]'
        )}
        data-item-row-main=""
        data-slot="item-row-main"
        type="button"
        tabIndex={-1}
        onClick={(event) =>
          onSelect(item.id, {
            toggle: event.metaKey || event.ctrlKey,
            range: event.shiftKey
          })
        }
        onKeyDown={(event) => {
          if (event.key !== ' ' || (!event.metaKey && !event.ctrlKey && !event.shiftKey)) return
          event.preventDefault()
          event.stopPropagation()
          onSelect(item.id, {
            toggle: event.metaKey || event.ctrlKey,
            range: event.shiftKey
          })
        }}
        onPointerEnter={readOnly ? undefined : schedulePrefetch}
        onPointerLeave={cancelPrefetch}
        onFocus={() => {
          cancelPrefetch()
          if (!readOnly) onPrefetch?.(item.id)
        }}
        aria-pressed={selected}
      >
        <span
          className={cn(
            'bg-card text-muted-foreground grid size-10 place-items-center rounded-xl shadow-(--keycap-shadow) forced-colors:[forced-color-adjust:none]',
            item.type === 'login' && 'overflow-hidden',
            item.type === 'card' &&
              'text-chart-4 [[data-theme=dark]_&]:bg-[var(--website-icon-background)]',
            item.type === 'identity' && 'bg-accent text-brand',
            item.type === 'secureNote' && 'text-chart-3',
            item.type === 'sshKey' && 'bg-accent text-chart-2'
          )}
          aria-hidden="true"
        >
          {item.type === 'card' ? (
            <PaymentCardBrandMark
              brand={normalizeBitwardenCardBrand(item.cardBrand)}
              imageSrc={cardCoverImageSrc}
            />
          ) : item.type === 'login' && !readOnly ? (
            <WebsiteIcon id={item.id} uri={item.uri} enabled={showWebsiteIcons} />
          ) : (
            <ItemIcon />
          )}
        </span>
        <span className="grid min-w-0 gap-1">
          <strong
            className={cn(
              'text-foreground flex min-w-0 items-center gap-1.5 truncate text-sm font-medium',
              selected && 'font-semibold'
            )}
          >
            {item.name}
          </strong>
          <small className="text-muted-foreground truncate text-xs">
            {item.deletedAt
              ? t`Deleted item`
              : item.subtitle || item.username || item.uri || t`No summary set`}
          </small>
        </span>
        {shouldShowTotpCode && (
          <span
            className={cn('text-foreground grid min-w-20 justify-items-end text-right')}
            aria-label={
              totpCode
                ? t`Authentication code ${totpCode.code}, ${totpCode.remainingSeconds} seconds remaining`
                : hasTotpResult
                  ? t`Unable to generate authentication code`
                  : t`Generating authentication code`
            }
          >
            <strong className="font-mono text-xl leading-none tracking-widest">
              {totpCode && /^\d+$/.test(totpCode.code) ? (
                <NumberFlow
                  className="tabular-nums"
                  value={Number(totpCode.code)}
                  format={{
                    useGrouping: false,
                    minimumIntegerDigits: totpCode.code.length
                  }}
                  trend={0}
                />
              ) : (
                (totpCode?.code ?? (hasTotpResult ? '—' : '…'))
              )}
            </strong>
          </span>
        )}
      </button>
      {!readOnly && !showTotpCode && (
        <RowIconButton
          variant="ghost"
          size="icon-sm"
          className={cn(
            'text-muted-foreground hover:text-foreground size-7 min-w-7 cursor-pointer self-center opacity-0 transition-opacity duration-150 group-hover/item:opacity-100 hover:bg-transparent focus-visible:opacity-100',
            selected && 'opacity-100 hover:shadow-none active:shadow-none',
            item.favorite && !selected && 'text-chart-4 opacity-100',
            item.favorite && selected && 'opacity-100'
          )}
          type="button"
          label={
            item.favorite ? t`Remove ${item.name} from favorites` : t`Add ${item.name} to favorites`
          }
          aria-pressed={item.favorite}
          onPointerDown={(event) => event.stopPropagation()}
          onClick={() => onFavorite(item)}
        >
          <Star fill={item.favorite ? 'currentColor' : 'none'} aria-hidden="true" />
        </RowIconButton>
      )}
    </li>
  )
})

interface FolderRowProps {
  folder: FolderView
  label?: string
  depth?: number
  selected: boolean
  count: number
  hasChildren?: boolean
  expanded?: boolean
  toggleDisabled?: boolean
  onToggle?: () => void
  onSelect: () => void
  onEdit: () => void
}

export function FolderRow({
  folder,
  label = folder.name,
  depth = 0,
  selected,
  count,
  hasChildren = false,
  expanded = true,
  toggleDisabled = false,
  onToggle,
  onSelect,
  onEdit
}: FolderRowProps): React.JSX.Element {
  const { t } = useLingui()
  const { attributes, listeners, setNodeRef, transform, transition, isDragging, isOver } =
    useSortable({
      id: folder.id,
      attributes: {
        role: 'listitem',
        roleDescription: t`Draggable item`
      }
    })
  const toggleLabel = hasChildren
    ? expanded
      ? t({
          message: `Collapse ${folder.name}`,
          comment: 'Disclosure button label for collapsing a folder subtree in the vault sidebar.'
        })
      : t({
          message: `Expand ${folder.name}`,
          comment: 'Disclosure button label for expanding a folder subtree in the vault sidebar.'
        })
    : ''

  return (
    <li
      ref={setNodeRef}
      {...attributes}
      {...listeners}
      className={cn(
        sidebarRowClassName,
        'group/folder relative grid cursor-grab touch-none grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2.5 py-1 pe-2',
        !selected && !isOver && !isDragging && 'hover:bg-sidebar-overlay-hover',
        selected && !isDragging && sidebarRowSelectedClassName,
        isDragging && [sidebarRowDropClassName, 'relative z-10 cursor-grabbing'],
        isOver && !isDragging && sidebarRowDropClassName
      )}
      style={{
        transform: CSS.Transform.toString(transform),
        transition,
        paddingInlineStart: `${8 + depth * 16}px`
      }}
    >
      <Button
        variant="sidebar"
        className="absolute inset-0 z-0 h-auto border-0 bg-transparent p-0 text-left text-inherit shadow-none hover:bg-transparent hover:shadow-none aria-expanded:bg-transparent aria-expanded:shadow-none"
        type="button"
        aria-label={folder.name}
        aria-current={selected ? 'page' : undefined}
        aria-expanded={hasChildren ? expanded : undefined}
        aria-disabled={hasChildren && toggleDisabled ? true : undefined}
        title={hasChildren ? toggleLabel : undefined}
        onClick={() => {
          onSelect()
          if (hasChildren && !toggleDisabled) onToggle?.()
        }}
      />
      {hasChildren ? (
        <span
          className="text-muted-foreground pointer-events-none z-10 grid size-6 place-items-center [&>svg]:size-4"
          aria-hidden="true"
        >
          {expanded ? (
            <FolderOpen data-icon="inline-start" aria-hidden="true" />
          ) : (
            <Folders data-icon="inline-start" aria-hidden="true" />
          )}
        </span>
      ) : (
        <span
          className="text-muted-foreground pointer-events-none z-10 grid size-6 place-items-center [&>svg]:size-4"
          aria-hidden="true"
        >
          <Folder />
        </span>
      )}
      <span className="pointer-events-none z-10 min-w-0 truncate">{label}</span>
      <span className="relative z-10 grid size-8 justify-self-end">
        <RowIconButton
          variant="ghost"
          size="icon-sm"
          className="peer/edit text-muted-foreground focus-visible:text-muted-foreground hover:text-foreground absolute inset-y-0 -end-2 z-10 grid size-8 place-items-center border-0 bg-transparent p-1 opacity-0 shadow-none transition-opacity group-hover/folder:opacity-100 hover:bg-transparent hover:shadow-none focus-visible:opacity-100"
          type="button"
          label={t`Edit folder ${folder.name}`}
          onClick={onEdit}
        >
          <MoreHorizontal aria-hidden="true" />
        </RowIconButton>
        <small
          className={cn(
            sidebarCountClassName,
            'pointer-events-none absolute end-0 top-1/2 -translate-y-1/2 transition-opacity group-hover/folder:opacity-0 peer-focus-visible/edit:opacity-0'
          )}
          aria-label={t`${count} items`}
        >
          {count}
        </small>
      </span>
    </li>
  )
}
