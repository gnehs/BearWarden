import { useDraggable } from '@dnd-kit/core'
import { useSortable } from '@dnd-kit/sortable'
import { CSS, useCombinedRefs } from '@dnd-kit/utilities'
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
import type { FolderView, LoginSummary } from '../../../shared/vault-contract'
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
  return (
    <Tooltip>
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
  readOnly = false
}: ItemRowProps): React.JSX.Element {
  const { attributes, listeners, setNodeRef, setActivatorNodeRef, transform, isDragging } =
    useDraggable({
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

  return (
    <li
      ref={setRowRef}
      data-item-id={item.id}
      className={cn(
        'item-row grid-cols-[minmax(0,1fr)_28px] px-[13px]',
        selected && 'selected',
        isDragging && 'dragging'
      )}
      style={{ transform: CSS.Translate.toString(transform) }}
      {...attributes}
      {...listeners}
      onContextMenu={(event) => {
        event.preventDefault()
        if (readOnly) return
        onSelect(item.id, { toggle: false, range: false })
        onContextMenu(item.id, { x: Math.round(event.clientX), y: Math.round(event.clientY) })
      }}
    >
      <Button
        variant="ghost"
        className="item-row-main px-0 hover:shadow-[none]"
        type="button"
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
        <span className={cn('item-icon', item.type)} aria-hidden="true">
          {item.type === 'card' ? (
            <PaymentCardBrandMark brand={normalizeBitwardenCardBrand(item.cardBrand)} compact />
          ) : item.type === 'login' && !readOnly ? (
            <WebsiteIcon id={item.id} uri={item.uri} enabled={showWebsiteIcons} />
          ) : (
            <ItemIcon />
          )}
        </span>
        <span className="item-copy">
          <strong>{item.name}</strong>
          <small>
            {readOnly
              ? '已刪除的項目'
              : item.subtitle || item.username || item.uri || '尚未設定摘要'}
          </small>
        </span>
      </Button>
      {!readOnly && (
        <RowIconButton
          variant="ghost"
          size="icon-sm"
          className={cn('icon-button subtle favorite-button', item.favorite && 'active')}
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
        'folder-row',
        selected && 'selected',
        isDragging && 'dragging',
        isOver && 'drop-target'
      )}
      style={{ transform: CSS.Transform.toString(transform), transition }}
    >
      <RowIconButton
        variant="ghost"
        size="icon-sm"
        className="folder-drag-handle"
        type="button"
        label={`重新排列 ${folder.name}`}
        {...attributes}
        {...listeners}
      >
        <GripVertical aria-hidden="true" />
      </RowIconButton>
      <Button
        variant="sidebar"
        className="folder-row-main hover:bg-transparent hover:shadow-[none] aria-expanded:bg-transparent aria-expanded:shadow-[none]"
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
        className="folder-more"
        type="button"
        label={`編輯資料夾 ${folder.name}`}
        onClick={onEdit}
      >
        <MoreHorizontal aria-hidden="true" />
      </RowIconButton>
    </li>
  )
}
