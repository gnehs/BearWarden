import { useDndContext, useDraggable } from '@dnd-kit/core'
import { useSortable } from '@dnd-kit/sortable'
import { CSS, useCombinedRefs } from '@dnd-kit/utilities'
import NumberFlow from '@number-flow/react'
import { memo, useEffect, useRef } from 'react'
import {
  ContactRound,
  CreditCard,
  FileKey2,
  Folder,
  Globe2,
  GripVertical,
  MoreHorizontal,
  NotebookPen,
  Star
} from 'lucide-react'
import type { FolderView, LoginSummary, TotpCodeView } from '../../../shared/vault-contract'
import { normalizeBitwardenCardBrand } from '../lib/payment-card'
import PaymentCardBrandMark from './PaymentCardBrandMark'
import WebsiteIcon from './WebsiteIcon'
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

const itemTypeMeta = {
  login: { label: '登入', icon: Globe2 },
  card: { label: '卡片', icon: CreditCard },
  identity: { label: '身分資料', icon: ContactRound },
  secureNote: { label: '安全備註', icon: NotebookPen },
  sshKey: { label: 'SSH 金鑰', icon: FileKey2 }
} as const

export const ItemRow = memo(function ItemRow({
  item,
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
  const { attributes, listeners, setNodeRef, setActivatorNodeRef, isDragging } = useDraggable({
    id: item.id,
    disabled: readOnly,
    attributes: {
      role: 'listitem',
      roleDescription: '可拖曳項目'
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

  const meta = itemTypeMeta[item.type]
  const ItemIcon = meta.icon
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
        'group/item border-border has-[[data-item-row-main]:focus-visible]:outline-ring/72 relative grid cursor-grab touch-none grid-cols-[minmax(0,1fr)_28px] items-center rounded-none border-0 border-b pr-3 has-[[data-item-row-main]:focus-visible]:rounded-lg has-[[data-item-row-main]:focus-visible]:outline-[3px] has-[[data-item-row-main]:focus-visible]:outline-offset-2',
        !selected && 'active:bg-accent/85 hover:bg-accent/50 hover:rounded-lg',
        selected &&
          'active:bg-primary active:text-primary-foreground bg-primary text-primary-foreground hover:bg-primary rounded-[11px] border-b-transparent shadow-[0_4px_13px_color-mix(in_oklch,var(--shadow-color)_18%,transparent)] hover:rounded-[11px] has-[[data-item-row-main]:focus-visible]:rounded-[11px] forced-colors:outline-2 forced-colors:outline-offset-[-2px] forced-colors:outline-[Highlight]',
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
          'grid h-[65px] min-w-0 items-center gap-3 px-3 text-left focus-visible:outline-none',
          shouldShowTotpCode
            ? 'grid-cols-[42px_minmax(0,1fr)_auto]'
            : 'grid-cols-[42px_minmax(0,1fr)]'
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
            'bg-muted text-muted-foreground outline-foreground/5 grid size-10 place-items-center rounded-md shadow-(--control-highlight) outline forced-colors:[forced-color-adjust:none]',
            item.type === 'login' && 'overflow-hidden',
            item.type === 'card' &&
              'text-chart-4 [[data-theme=dark]_&]:bg-[var(--website-icon-background)]',
            item.type === 'identity' && 'bg-accent text-primary',
            item.type === 'secureNote' && 'text-chart-3',
            item.type === 'sshKey' && 'bg-accent text-chart-2'
          )}
          aria-hidden="true"
        >
          {item.type === 'card' ? (
            <PaymentCardBrandMark brand={normalizeBitwardenCardBrand(item.cardBrand)} compact />
          ) : item.type === 'login' && !readOnly ? (
            <WebsiteIcon id={item.id} uri={item.uri} enabled={showWebsiteIcons} />
          ) : (
            <ItemIcon />
          )}
        </span>
        <span className={cn('min-w-0', shouldShowTotpCode ? 'flex items-center' : 'grid gap-1')}>
          <strong
            className={cn(
              'text-foreground flex min-w-0 items-center gap-[5px] truncate text-[13px] font-medium',
              selected && 'text-primary-foreground'
            )}
          >
            {item.name}
          </strong>
          {!shouldShowTotpCode && (
            <small
              className={cn(
                'text-muted-foreground truncate text-[11px]',
                selected && 'text-primary-foreground/82'
              )}
            >
              {readOnly
                ? '已刪除的項目'
                : item.subtitle || item.username || item.uri || '尚未設定摘要'}
            </small>
          )}
        </span>
        {shouldShowTotpCode && (
          <span
            className={cn(
              'grid min-w-[84px] justify-items-end gap-1 self-start pt-2 text-right',
              selected ? 'text-primary-foreground' : 'text-foreground'
            )}
            aria-label={
              totpCode
                ? `驗證碼 ${totpCode.code}，剩餘 ${totpCode.remainingSeconds} 秒`
                : hasTotpResult
                  ? '驗證碼無法產生'
                  : '驗證碼產生中'
            }
          >
            <span
              className={cn(
                'text-muted-foreground text-[10px] leading-none tabular-nums',
                selected && 'text-primary-foreground/75'
              )}
            >
              {totpCode ? `${totpCode.remainingSeconds}s` : ' '}
            </span>
            <strong className="font-mono text-[20px] leading-none tracking-[0.12em]">
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
            selected &&
              'text-primary-foreground/82 hover:bg-primary-foreground/10 hover:text-primary-foreground active:bg-primary-foreground/10 active:text-primary-foreground focus-visible:bg-primary-foreground/10 focus-visible:text-primary-foreground opacity-100 hover:shadow-none active:shadow-none',
            item.favorite && !selected && 'text-chart-4 opacity-100',
            item.favorite && selected && 'opacity-100'
          )}
          type="button"
          label={item.favorite ? `將 ${item.name} 從常用項目移除` : `將 ${item.name} 加入常用項目`}
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
  selected: boolean
  count: number
  onSelect: () => void
  onEdit: () => void
}

export function FolderRow({
  folder,
  selected,
  count,
  onSelect,
  onEdit
}: FolderRowProps): React.JSX.Element {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging, isOver } =
    useSortable({ id: folder.id })

  return (
    <li
      ref={setNodeRef}
      className={cn(
        'group/folder text-foreground grid min-h-9 grid-cols-[22px_minmax(0,1fr)_25px] items-center rounded-lg',
        !selected && !isOver && !isDragging && 'hover:bg-sidebar-overlay-hover',
        selected && !isDragging && 'bg-sidebar-overlay-active shadow-none',
        isDragging &&
          'bg-sidebar-overlay-active relative z-10 shadow-[inset_0_0_0_1px_color-mix(in_oklch,var(--sidebar-primary)_55%,transparent)] forced-colors:outline-2 forced-colors:outline-offset-[-2px] forced-colors:outline-[Highlight]',
        isOver &&
          !isDragging &&
          'bg-sidebar-overlay-active shadow-[inset_0_0_0_1px_color-mix(in_oklch,var(--sidebar-primary)_55%,transparent)] forced-colors:outline-2 forced-colors:outline-offset-[-2px] forced-colors:outline-[Highlight]'
      )}
      style={{ transform: CSS.Transform.toString(transform), transition }}
    >
      <RowIconButton
        variant="ghost"
        size="icon-sm"
        className="group-hover/folder:text-muted-foreground focus-visible:text-muted-foreground grid h-[30px] w-6 place-items-center border-0 bg-transparent p-0 text-transparent shadow-none hover:bg-transparent hover:shadow-none"
        type="button"
        label={`重新排列 ${folder.name}`}
        {...attributes}
        {...listeners}
      >
        <GripVertical aria-hidden="true" />
      </RowIconButton>
      <Button
        variant="sidebar"
        className="[&>small]:text-muted-foreground grid h-[34px] min-w-0 grid-cols-[21px_minmax(0,1fr)_auto] items-center gap-1 border-0 bg-transparent p-0 text-left text-inherit hover:bg-transparent hover:shadow-none aria-expanded:bg-transparent aria-expanded:shadow-none [&>small]:min-w-[3ch] [&>small]:pr-1 [&>small]:text-right [&>small]:text-[10px] [&>small]:tabular-nums [&>span]:truncate [&>span]:text-xs"
        type="button"
        aria-current={selected ? 'page' : undefined}
        onClick={onSelect}
      >
        <Folder aria-hidden="true" />
        <span>{folder.name}</span>
        <small aria-label={`${count} 個項目`}>{count}</small>
      </Button>
      <RowIconButton
        variant="ghost"
        size="icon-sm"
        className="group-hover/folder:text-muted-foreground focus-visible:text-muted-foreground grid h-[30px] w-6 place-items-center border-0 bg-transparent p-0 text-transparent shadow-none hover:bg-transparent hover:shadow-none"
        type="button"
        label={`編輯資料夾 ${folder.name}`}
        onClick={onEdit}
      >
        <MoreHorizontal aria-hidden="true" />
      </RowIconButton>
    </li>
  )
}
