import { useDndContext, useDroppable } from '@dnd-kit/core'
import { Trans, useLingui } from '@lingui/react/macro'
import { ArrowLeft, Folder } from 'lucide-react'
import type { ComponentProps, JSX, ReactNode } from 'react'
import type { LoginSummary } from '../../../shared/vault-contract'
import { normalizeBitwardenCardBrand } from '../lib/payment-card'
import { cn } from '../lib/utils'
import PaymentCardBrandMark from './PaymentCardBrandMark'
import WebsiteIcon from './WebsiteIcon'
import { useItemTypeMeta } from '@renderer/hooks/use-item-type-meta'
import { itemTypeIcons } from './vault-item-type-icons'
import { Button } from './ui/button'
import { Skeleton } from './ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip'
import {
  DetailGroup,
  DetailRow,
  DetailTimestamp,
  DetailTimestamps,
  DetailTitleBlock,
  DetailToolbar,
  detailToolbarButtonClassName
} from './VaultDetailLayout'
import { detailHeaderIconClassName, detailScrollClassName } from './VaultDetailSurface'

export type SidebarTone =
  'blue' | 'indigo' | 'green' | 'yellow' | 'cyan' | 'red' | 'orange' | 'gray'

interface TooltipIconButtonProps extends ComponentProps<typeof Button> {
  label: string
}

export function TooltipIconButton({
  label,
  children,
  className,
  ...props
}: TooltipIconButtonProps): JSX.Element {
  const { active } = useDndContext()

  return (
    <Tooltip disabled={active != null}>
      <TooltipTrigger
        render={
          <Button
            aria-label={label}
            className={cn(
              'text-muted-foreground hover:text-foreground rounded-control size-9 min-w-9 [-webkit-app-region:no-drag]',
              className
            )}
            {...props}
          />
        }
      >
        {children}
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}

// Detail headers and their loading placeholder intentionally share URI label formatting.
// eslint-disable-next-line react-refresh/only-export-components
export function hostLabel(uri: string | null, unsetLabel: string): string {
  if (!uri) return unsetLabel

  try {
    return new URL(uri).hostname
  } catch {
    return uri
  }
}

interface SidebarLinkProps {
  icon: ReactNode
  label: string
  count: number
  active: boolean
  dropTargetId?: string
  onClick: () => void
}

// One saturated hue per vault category, read by the tile as `--tile`.
const sidebarToneClasses: Record<SidebarTone, string> = {
  blue: '[--tile:var(--color-blue-500)]',
  indigo: '[--tile:var(--color-indigo-500)]',
  green: '[--tile:var(--color-green-500)]',
  yellow: '[--tile:var(--color-amber-400)]',
  cyan: '[--tile:var(--color-cyan-500)]',
  red: '[--tile:var(--color-red-500)]',
  orange: '[--tile:var(--color-orange-500)]',
  gray: '[--tile:var(--color-slate-500)]'
}

interface SidebarCategoryTileProps {
  icon: ReactNode
  label: string
  count: number
  active: boolean
  tone: SidebarTone
  onClick: () => void
}

/** A category card: the selected card fills with its category colour. */
export function SidebarCategoryTile({
  icon,
  label,
  count,
  active,
  tone,
  onClick
}: SidebarCategoryTileProps): JSX.Element {
  return (
    <Button
      variant="sidebar"
      className={cn(
        sidebarToneClasses[tone],
        'rounded-pane grid h-auto min-h-[4.5rem] grid-cols-[auto_1fr] grid-rows-[auto_auto] items-center gap-x-2 gap-y-2 p-2.5 text-left whitespace-normal',
        active
          ? 'bg-(--tile) text-white hover:bg-(--tile) hover:text-white aria-expanded:bg-(--tile)'
          : 'bg-sidebar-overlay hover:bg-sidebar-overlay-hover'
      )}
      type="button"
      aria-current={active ? 'page' : undefined}
      onClick={onClick}
    >
      <span
        className={cn(
          'grid size-7 place-items-center rounded-full [&>svg]:size-4',
          active ? 'bg-white text-(--tile)' : 'bg-(--tile) text-white'
        )}
        aria-hidden="true"
      >
        {icon}
      </span>
      <small
        className={cn(
          'self-start justify-self-end pt-0.5 text-sm font-semibold tabular-nums',
          active ? 'text-white/85' : 'text-muted-foreground'
        )}
      >
        {count}
      </small>
      <span className="col-span-2 truncate text-[0.9375rem] leading-tight font-semibold">
        {label}
      </span>
    </Button>
  )
}

/** Sidebar rows sit on the window canvas, so the selected row lifts into a white keycap. */
export const sidebarRowClassName =
  'text-sidebar-foreground min-h-9 rounded-control text-sm font-medium transition-[background-color,box-shadow] duration-150'
export const sidebarRowSelectedClassName =
  'bg-card shadow-(--keycap-shadow) dark:bg-(--segment-thumb)'
export const sidebarRowDropClassName =
  'bg-sidebar-overlay-active shadow-[inset_0_0_0_1.5px_color-mix(in_oklch,var(--brand)_60%,transparent)] forced-colors:outline-2 forced-colors:-outline-offset-2 forced-colors:outline-[Highlight]'
export const sidebarCountClassName =
  'text-muted-foreground min-w-6 text-right text-sm font-medium tabular-nums'

export function SidebarLink({
  icon,
  label,
  count,
  active,
  dropTargetId,
  onClick
}: SidebarLinkProps): JSX.Element {
  const { setNodeRef, isOver } = useDroppable({
    id: dropTargetId ?? `sidebar-link:${label}`,
    disabled: dropTargetId === undefined
  })

  return (
    <Button
      ref={dropTargetId ? setNodeRef : undefined}
      variant="sidebar"
      className={cn(
        sidebarRowClassName,
        'grid h-auto grid-cols-[auto_1fr_auto] items-center gap-2.5 px-2 py-1 text-left',
        active && [sidebarRowSelectedClassName, 'hover:bg-card dark:hover:bg-(--segment-thumb)'],
        isOver && sidebarRowDropClassName
      )}
      type="button"
      aria-current={active ? 'page' : undefined}
      onClick={onClick}
    >
      <span
        className="text-muted-foreground grid size-6 place-items-center [&>svg]:size-4"
        aria-hidden="true"
      >
        {icon}
      </span>
      <span className="truncate">{label}</span>
      <small className={sidebarCountClassName}>{count}</small>
    </Button>
  )
}

interface UnfiledRowProps {
  selected: boolean
  count: number
  onSelect: () => void
}

export function UnfiledRow({ selected, count, onSelect }: UnfiledRowProps): JSX.Element {
  const { t } = useLingui()
  const { setNodeRef, isOver } = useDroppable({ id: 'folder:none' })

  return (
    <li
      ref={setNodeRef}
      className={cn(
        sidebarRowClassName,
        'static grid grid-cols-[auto_minmax(0,1fr)] items-center gap-2.5 px-2',
        !selected && 'hover:bg-sidebar-overlay-hover',
        selected && sidebarRowSelectedClassName,
        isOver && sidebarRowDropClassName
      )}
    >
      <span className="text-muted-foreground grid size-6 place-items-center" aria-hidden="true">
        <Folder size={16} />
      </span>
      <Button
        variant="sidebar"
        className="grid h-9 min-w-0 grid-cols-[minmax(0,1fr)_auto] items-center gap-2 border-0 bg-transparent p-0 text-left text-sm text-inherit hover:bg-transparent aria-expanded:bg-transparent [&>span]:truncate"
        type="button"
        aria-current={selected ? 'page' : undefined}
        onClick={onSelect}
      >
        <span>
          <Trans>Unfiled</Trans>
        </span>
        <small className={sidebarCountClassName} aria-label={t`${count} items`}>
          {count}
        </small>
      </Button>
    </li>
  )
}

interface DetailPlaceholderProps {
  item: LoginSummary
  showWebsiteIcons: boolean
  onBack: () => void
}

export function DetailPlaceholder({
  item,
  showWebsiteIcons,
  onBack
}: DetailPlaceholderProps): JSX.Element {
  const { t } = useLingui()
  const itemTypeMeta = useItemTypeMeta()
  const TypeIcon = itemTypeIcons[item.type]

  return (
    <article
      className="flex size-full min-h-0 min-w-0 flex-col motion-reduce:[&_[data-slot=skeleton]]:animate-none"
      aria-busy="true"
    >
      <DetailToolbar
        back={
          <TooltipIconButton
            variant="ghost"
            size="icon-sm"
            className={cn(detailToolbarButtonClassName, 'hidden max-[680px]:grid')}
            data-detail-back=""
            type="button"
            label={t`Back to item list`}
            onClick={onBack}
          >
            <ArrowLeft />
          </TooltipIconButton>
        }
      >
        {[0, 1, 2].map((action) => (
          <span
            className={cn(detailToolbarButtonClassName, 'grid place-items-center')}
            key={action}
            aria-hidden="true"
          >
            <Skeleton className="rounded-control size-4" />
          </span>
        ))}
        <span className="sr-only" role="status">
          <Trans>Loading item details…</Trans>
        </span>
      </DetailToolbar>
      <DetailTitleBlock
        icon={
          <span
            className={detailHeaderIconClassName(item.type)}
            data-detail-icon=""
            aria-hidden="true"
          >
            {item.type === 'login' ? (
              <WebsiteIcon id={item.id} uri={item.uri} enabled={showWebsiteIcons} />
            ) : item.type === 'card' ? (
              <PaymentCardBrandMark brand={normalizeBitwardenCardBrand(item.cardBrand)} />
            ) : (
              <TypeIcon size={18} />
            )}
          </span>
        }
        title={item.name}
        meta={
          <>
            <span>{itemTypeMeta[item.type].label}</span>
            <span aria-hidden="true">·</span>
            <Skeleton className="h-3 w-14" aria-hidden="true" />
          </>
        }
      />

      <div className={cn('flex flex-col gap-4', detailScrollClassName)} aria-hidden="true">
        <DetailGroup>
          {['w-1/3', 'w-1/2', 'w-2/5'].map((width) => (
            <DetailRow
              key={width}
              label={<Skeleton className="my-0.5 h-3 w-16" />}
              actions={
                <span className="grid size-7 place-items-center">
                  <Skeleton className="rounded-control size-4" />
                </span>
              }
            >
              <Skeleton className={cn('my-1 h-3.5', width)} />
            </DetailRow>
          ))}
        </DetailGroup>
        <DetailTimestamps>
          {[0, 1, 2].map((row) => (
            <DetailTimestamp key={row} label={<Skeleton className="my-1 h-3 w-14" />}>
              <Skeleton className="my-1 h-3 w-40" />
            </DetailTimestamp>
          ))}
        </DetailTimestamps>
      </div>
    </article>
  )
}
