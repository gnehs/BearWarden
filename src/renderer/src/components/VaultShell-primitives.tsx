import { useDndContext, useDroppable } from '@dnd-kit/core'
import { Trans, useLingui } from '@lingui/react/macro'
import { ArrowLeft, Folder } from 'lucide-react'
import type { ComponentProps, JSX, ReactNode } from 'react'
import type { LoginSummary } from '../../../shared/vault-contract'
import { normalizeBitwardenCardBrand } from '../lib/payment-card'
import { cn } from '../lib/utils'
import PaymentCardBrandMark from './PaymentCardBrandMark'
import WebsiteIcon from './WebsiteIcon'
import { itemTypeIcons } from './vault-item-type-icons'
import { Button } from './ui/button'
import { CardContent, CardHeader } from './ui/card'
import { Skeleton } from './ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip'
import {
  DetailCard,
  DetailHeader,
  DetailHeading,
  DetailRowGroup,
  detailFieldClassName,
  detailIconClassName,
  detailScrollClassName
} from './VaultDetailSurface'

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
              'text-muted-foreground hover:text-foreground size-9 min-w-9 rounded-xl [-webkit-app-region:no-drag]',
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
  tone?: SidebarTone
  dropTargetId?: string
  onClick: () => void
}

// Pastel icon chips, one hue per vault category.
const sidebarToneClasses: Record<SidebarTone, string> = {
  blue: 'bg-sky-100 text-sky-700 dark:bg-sky-400/15 dark:text-sky-300',
  indigo: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-400/15 dark:text-indigo-300',
  green: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-400/15 dark:text-emerald-300',
  yellow: 'bg-amber-100 text-amber-700 dark:bg-amber-400/15 dark:text-amber-300',
  cyan: 'bg-cyan-100 text-cyan-700 dark:bg-cyan-400/15 dark:text-cyan-300',
  red: 'bg-rose-100 text-rose-700 dark:bg-rose-400/15 dark:text-rose-300',
  orange: 'bg-orange-100 text-orange-700 dark:bg-orange-400/15 dark:text-orange-300',
  gray: 'bg-slate-200/70 text-slate-700 dark:bg-slate-400/15 dark:text-slate-300'
}

/** Sidebar rows sit on the window canvas, so the selected row lifts into a white keycap. */
export const sidebarRowClassName =
  'text-sidebar-foreground min-h-9 rounded-xl text-[0.8125rem] font-medium transition-[background-color,box-shadow] duration-150'
export const sidebarRowSelectedClassName =
  'bg-card shadow-(--keycap-shadow) dark:bg-(--segment-thumb)'
export const sidebarRowDropClassName =
  'bg-sidebar-overlay-active shadow-[inset_0_0_0_1.5px_color-mix(in_oklch,var(--brand)_60%,transparent)] forced-colors:outline-2 forced-colors:-outline-offset-2 forced-colors:outline-[Highlight]'
export const sidebarCountClassName =
  'text-muted-foreground grid h-5 min-w-6 place-items-center rounded-md border border-(--surface-ring) bg-(--segment-track) px-1.5 text-[0.6875rem] font-medium tabular-nums'

export function SidebarLink({
  icon,
  label,
  count,
  active,
  tone,
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
        className={cn(
          'grid size-6 place-items-center rounded-lg [&>svg]:size-3.5',
          tone ? sidebarToneClasses[tone] : 'text-muted-foreground [&>svg]:size-4'
        )}
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
        className="grid h-9 min-w-0 grid-cols-[minmax(0,1fr)_auto] items-center gap-2 border-0 bg-transparent p-0 text-left text-inherit hover:bg-transparent aria-expanded:bg-transparent [&>span]:truncate"
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
  const TypeIcon = itemTypeIcons[item.type]

  return (
    <article
      className="flex size-full min-h-0 min-w-0 flex-col motion-reduce:[&_[data-slot=skeleton]]:animate-none"
      aria-busy="true"
    >
      <DetailHeader>
        <TooltipIconButton
          variant="outline"
          size="icon"
          className="hidden max-[680px]:grid"
          data-detail-back=""
          type="button"
          label={t`Back to item list`}
          onClick={onBack}
        >
          <ArrowLeft />
        </TooltipIconButton>
        <span className={detailIconClassName(item.type)} data-detail-icon="" aria-hidden="true">
          {item.type === 'login' ? (
            <WebsiteIcon id={item.id} uri={item.uri} enabled={showWebsiteIcons} />
          ) : item.type === 'card' ? (
            <PaymentCardBrandMark brand={normalizeBitwardenCardBrand(item.cardBrand)} />
          ) : (
            <TypeIcon size={18} />
          )}
        </span>
        <DetailHeading
          title={item.name}
          subtitle={
            item.subtitle ||
            (item.type === 'login'
              ? hostLabel(item.uri, t`Website not set`)
              : t`Securely stored item`)
          }
        />
        <Skeleton className="size-9 flex-none rounded-xl" aria-hidden="true" />
        <Skeleton className="size-9 flex-none rounded-xl" aria-hidden="true" />
        <span className="sr-only" role="status">
          <Trans>Loading item details…</Trans>
        </span>
      </DetailHeader>

      <div className={detailScrollClassName} aria-hidden="true">
        <DetailCard variant="placeholder">
          <CardHeader>
            <Skeleton className="h-3 w-20" />
          </CardHeader>
          <CardContent>
            <DetailRowGroup>
              {[0, 1, 2].map((row) => (
                <div className={detailFieldClassName} key={row}>
                  <Skeleton className="h-3 w-16" />
                  <Skeleton className={cn('h-4', row === 1 ? 'w-2/3' : 'w-1/2')} />
                  <Skeleton className="size-8" />
                </div>
              ))}
            </DetailRowGroup>
          </CardContent>
        </DetailCard>
        <DetailCard variant="placeholder">
          <CardHeader>
            <Skeleton className="h-3 w-24" />
          </CardHeader>
          <CardContent>
            <DetailRowGroup>
              {[0, 1].map((row) => (
                <div className={detailFieldClassName} key={row}>
                  <Skeleton className="h-3 w-14" />
                  <Skeleton className="h-4 w-1/3" />
                  <span />
                </div>
              ))}
            </DetailRowGroup>
          </CardContent>
        </DetailCard>
      </div>
    </article>
  )
}
