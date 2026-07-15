import { useDraggable } from '@dnd-kit/core'
import { useSortable } from '@dnd-kit/sortable'
import { CSS } from '@dnd-kit/utilities'
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
  onSelect: (id: string) => void
  onPrefetch?: (id: string) => void
  onFavorite: (item: LoginSummary) => void
  onContextMenu: (id: string, position: { x: number; y: number }) => void
  showWebsiteIcons: boolean
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
  showWebsiteIcons
}: ItemRowProps): React.JSX.Element {
  const { attributes, listeners, setNodeRef, transform, isDragging } = useDraggable({
    id: item.id
  })
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
      ref={setNodeRef}
      data-item-id={item.id}
      className={cn('item-row', selected && 'selected', isDragging && 'dragging')}
      style={{ transform: CSS.Translate.toString(transform) }}
      onContextMenu={(event) => {
        event.preventDefault()
        onSelect(item.id)
        onContextMenu(item.id, { x: Math.round(event.clientX), y: Math.round(event.clientY) })
      }}
    >
      <RowIconButton
        variant="ghost"
        size="icon-sm"
        className="drag-handle"
        type="button"
        label={`拖曳 ${item.name}`}
        {...listeners}
        {...attributes}
      >
        <GripVertical aria-hidden="true" />
      </RowIconButton>
      <Button
        variant="ghost"
        className="item-row-main"
        type="button"
        onClick={() => onSelect(item.id)}
        onPointerEnter={schedulePrefetch}
        onPointerLeave={cancelPrefetch}
        onFocus={() => {
          cancelPrefetch()
          onPrefetch?.(item.id)
        }}
        aria-current={selected}
      >
        <span className={cn('item-icon', item.type)} aria-hidden="true">
          {item.type === 'card' ? (
            <PaymentCardBrandMark brand={normalizeBitwardenCardBrand(item.cardBrand)} compact />
          ) : item.type === 'login' ? (
            <WebsiteIcon id={item.id} uri={item.uri} enabled={showWebsiteIcons} />
          ) : (
            <ItemIcon />
          )}
        </span>
        <span className="item-copy">
          <strong>{item.name}</strong>
          <small>{item.subtitle || item.username || item.uri || '尚未設定摘要'}</small>
        </span>
      </Button>
      <RowIconButton
        variant="ghost"
        size="icon-sm"
        className={cn('icon-button subtle favorite-button', item.favorite && 'active')}
        type="button"
        label={item.favorite ? `將 ${item.name} 從常用項目移除` : `將 ${item.name} 加入常用項目`}
        aria-pressed={item.favorite}
        onClick={() => onFavorite(item)}
      >
        <Star fill={item.favorite ? 'currentColor' : 'none'} aria-hidden="true" />
      </RowIconButton>
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
        variant="ghost"
        className="folder-row-main"
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
