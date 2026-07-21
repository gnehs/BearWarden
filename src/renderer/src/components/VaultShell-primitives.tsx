import { useDndContext, useDroppable } from '@dnd-kit/core'
import { Trans, useLingui } from '@lingui/react/macro'
import {
  ArrowLeft,
  ContactRound,
  CreditCard,
  FileKey2,
  FolderOpen,
  KeyRound,
  NotebookPen
} from 'lucide-react'
import type { ComponentProps, JSX, ReactNode } from 'react'
import type { LoginSummary, VaultItemType } from '../../../shared/vault-contract'
import { normalizeBitwardenCardBrand } from '../lib/payment-card'
import { cn } from '../lib/utils'
import PaymentCardBrandMark from './PaymentCardBrandMark'
import WebsiteIcon from './WebsiteIcon'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader } from './ui/card'
import { Skeleton } from './ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip'

export type SidebarTone =
  'blue' | 'indigo' | 'green' | 'yellow' | 'cyan' | 'red' | 'orange' | 'gray'

const itemTypeIcons: Record<VaultItemType, typeof KeyRound> = {
  login: KeyRound,
  card: CreditCard,
  identity: ContactRound,
  secureNote: NotebookPen,
  sshKey: FileKey2
}

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
              'border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground dark:bg-card dark:hover:bg-muted size-[34px] min-w-[34px] rounded-md shadow-(--control-highlight) transition-[background,color,border-color,transform] duration-[130ms] [-webkit-app-region:no-drag]',
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

interface DetailCardProps extends Omit<ComponentProps<typeof Card>, 'variant'> {
  variant?: 'default' | 'attachment' | 'placeholder'
}

export function DetailCard({
  className,
  variant = 'default',
  ...props
}: DetailCardProps): JSX.Element {
  return (
    <Card
      variant="item"
      className={cn(
        'mx-auto mb-3 w-full max-w-[720px]',
        '[&_[data-slot=card-description]]:ml-auto',
        variant === 'attachment' &&
          '[&_[data-slot=card-description]]:text-xs [&_[data-slot=card-description]]:leading-normal',
        variant === 'placeholder' && '[&_[data-slot=skeleton]]:opacity-72',
        className
      )}
      {...props}
    />
  )
}

export function DetailHeader({ className, ...props }: ComponentProps<'header'>): JSX.Element {
  return (
    <header
      className={cn(
        'bg-muted/30 flex items-center gap-2.5 px-4 py-3 max-[680px]:px-3 max-[680px]:py-2.5',
        className
      )}
      {...props}
    />
  )
}

export const detailFieldClassName =
  'border-border/60 grid min-h-12 grid-cols-[minmax(90px,0.28fr)_minmax(0,1fr)_repeat(2,34px)] items-center gap-2 border-b py-0.5 last:border-b-0 [&>span]:text-[11px] [&>span]:text-muted-foreground [&>strong]:min-w-0 [&>strong]:truncate [&>strong]:text-xs [&>strong]:font-medium [&>:nth-child(3):last-child]:col-start-[-2] max-[430px]:grid-cols-[1fr_auto_auto] max-[430px]:gap-1.5 max-[430px]:[&>span]:col-span-full max-[430px]:[&>strong]:col-start-1 max-[430px]:[&>[data-field-copy-value]]:col-start-1'

export const detailScrollClassName =
  'bg-muted/30 min-h-0 flex-1 [scrollbar-color:var(--border-strong)_transparent] overflow-auto px-4 pt-4 pb-7 max-[680px]:px-3 max-[680px]:pt-3 max-[680px]:pb-5'

// This colocated helper keeps the shared item-type presentation mapping consistent.
// eslint-disable-next-line react-refresh/only-export-components
export function detailIconClassName(type?: VaultItemType): string {
  return cn(
    'outline-foreground/5 bg-muted text-primary dark:border-border dark:bg-muted dark:text-muted-foreground grid size-9 flex-none place-items-center rounded-md shadow-(--control-highlight) outline max-[430px]:hidden forced-colors:[forced-color-adjust:none]',
    type === 'login' && 'overflow-hidden',
    type === 'card' && 'bg-muted text-chart-4 dark:bg-website-icon-background',
    type === 'identity' && 'bg-accent text-primary',
    type === 'secureNote' && 'bg-muted text-chart-3',
    type === 'sshKey' && 'bg-accent text-chart-2'
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
  variant?: 'row' | 'tile'
  tone?: SidebarTone
  dropTargetId?: string
  onClick: () => void
}

const sidebarToneClasses: Record<SidebarTone, string> = {
  blue: 'bg-sidebar-primary text-sidebar-primary-foreground',
  indigo: 'bg-chart-4 text-primary-foreground',
  green: 'bg-sidebar-primary text-sidebar-primary-foreground',
  yellow: 'bg-chart-1 text-category-light-foreground',
  cyan: 'bg-chart-2 text-primary-foreground',
  red: 'bg-destructive text-destructive-foreground',
  orange: 'bg-chart-3 text-primary-foreground',
  gray: 'bg-muted text-foreground'
}

const sidebarLinkClasses = {
  base: 'h-auto border-none text-left',
  row: 'grid min-h-[38px] grid-cols-[22px_1fr_auto] items-center gap-2 rounded-lg border-0 bg-transparent px-[9px] py-1.5 shadow-[none] hover:shadow-[none]',
  tile: 'bg-sidebar-overlay grid min-h-[72px] grid-cols-[1fr_auto] grid-rows-[31px_auto] items-center gap-2 rounded-[15px] px-3 pt-[11px] pb-2.5 shadow-[var(--sidebar-tile-highlight)] hover:shadow-[var(--sidebar-tile-highlight)]',
  active: {
    row: 'bg-sidebar-overlay-active text-sidebar-foreground hover:bg-sidebar-overlay-active hover:text-sidebar-foreground',
    tile: 'bg-sidebar-primary text-sidebar-primary-foreground shadow-(--control-highlight) hover:bg-sidebar-primary hover:text-sidebar-primary-foreground hover:shadow-(--control-highlight)'
  }
} as const

export function SidebarLink({
  icon,
  label,
  count,
  active,
  variant = 'row',
  tone,
  dropTargetId,
  onClick
}: SidebarLinkProps): JSX.Element {
  const isTile = variant === 'tile'
  const { setNodeRef, isOver } = useDroppable({
    id: dropTargetId ?? `sidebar-link:${label}`,
    disabled: dropTargetId === undefined
  })

  return (
    <Button
      ref={dropTargetId ? setNodeRef : undefined}
      variant="sidebar"
      className={cn(
        sidebarLinkClasses.base,
        sidebarLinkClasses[variant],
        active && sidebarLinkClasses.active[variant],
        isOver &&
          'bg-sidebar-overlay-active text-sidebar-foreground ring-sidebar-ring hover:bg-sidebar-overlay-active hover:text-sidebar-foreground ring-2'
      )}
      type="button"
      aria-current={active ? 'page' : undefined}
      data-sidebar-active={active ? '' : undefined}
      onClick={onClick}
    >
      <span
        className={cn(
          'grid place-items-center',
          isTile
            ? [
                'bg-sidebar-primary text-sidebar-primary-foreground col-start-1 row-start-1 size-[30px] rounded-full',
                tone && sidebarToneClasses[tone],
                active && 'bg-sidebar-primary-foreground text-sidebar-primary'
              ]
            : 'size-[22px]'
        )}
        aria-hidden="true"
      >
        {icon}
      </span>
      <strong
        className={cn(
          isTile
            ? 'col-span-2 row-start-2 self-end text-[13px] leading-[1.15] font-[720]'
            : 'text-xs font-[610]'
        )}
      >
        {label}
      </strong>
      <small
        className={cn(
          'text-muted-foreground group-hover/button:text-sidebar-foreground',
          isTile
            ? 'col-start-2 row-start-1 self-center justify-self-end text-[11px] font-[650]'
            : 'text-[10px]',
          active &&
            isTile &&
            'text-[color-mix(in_oklch,var(--sidebar-primary-foreground)_88%,transparent)] group-hover/button:text-[color-mix(in_oklch,var(--sidebar-primary-foreground)_88%,transparent)]'
        )}
      >
        {count}
      </small>
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
        'text-foreground hover:bg-sidebar-overlay-hover static grid min-h-9 grid-cols-[22px_minmax(0,1fr)_25px] items-center rounded-lg',
        selected && 'bg-sidebar-overlay-active shadow-none',
        isOver &&
          'bg-sidebar-overlay-active text-foreground shadow-[inset_0_0_0_1px_color-mix(in_oklch,var(--sidebar-primary)_55%,transparent)] forced-colors:outline-2 forced-colors:-outline-offset-2 forced-colors:outline-[Highlight]'
      )}
    >
      <span className="w-[22px]" aria-hidden="true" />
      <Button
        variant="sidebar"
        className="[&>small]:text-muted-foreground grid h-[34px] min-w-0 grid-cols-[21px_minmax(0,1fr)_auto] items-center gap-1 border-0 bg-transparent p-0 text-left text-inherit shadow-none hover:bg-transparent hover:shadow-none aria-expanded:bg-transparent aria-expanded:shadow-none [&>small]:min-w-[3ch] [&>small]:pr-1 [&>small]:text-right [&>small]:text-[10px] [&>small]:tabular-nums [&>span]:truncate [&>span]:text-xs"
        type="button"
        aria-current={selected ? 'page' : undefined}
        onClick={onSelect}
      >
        <FolderOpen size={16} aria-hidden="true" />
        <span>
          <Trans>Unfiled</Trans>
        </span>
        <small aria-label={t`${count} items`}>{count}</small>
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
            <PaymentCardBrandMark brand={normalizeBitwardenCardBrand(item.cardBrand)} compact />
          ) : (
            <TypeIcon size={18} />
          )}
        </span>
        <div className="[&>span]:text-muted-foreground min-w-0 flex-1 [&>h2]:m-0 [&>h2]:truncate [&>h2]:text-base [&>h2]:font-medium [&>h2]:tracking-[-0.015em] [&>span]:mt-0.5 [&>span]:block [&>span]:truncate [&>span]:text-[10px]">
          <h2>{item.name}</h2>
          <span>
            {item.subtitle ||
              (item.type === 'login'
                ? hostLabel(item.uri, t`Website not set`)
                : t`Securely stored item`)}
          </span>
        </div>
        <Skeleton className="size-[34px] flex-none rounded-md" aria-hidden="true" />
        <Skeleton
          className="h-8 w-[68px] flex-none rounded-md max-[680px]:w-[34px]"
          aria-hidden="true"
        />
        <span className="sr-only" role="status">
          <Trans>Loading item details…</Trans>
        </span>
      </DetailHeader>

      <div className={detailScrollClassName} aria-hidden="true">
        <DetailCard variant="placeholder">
          <CardHeader>
            <Skeleton className="h-3 w-20" />
          </CardHeader>
          <CardContent className="flex flex-col">
            {[0, 1, 2].map((row) => (
              <div className={detailFieldClassName} key={row}>
                <Skeleton className="h-3 w-16" />
                <Skeleton className={cn('h-4', row === 1 ? 'w-2/3' : 'w-1/2')} />
                <Skeleton className="size-8" />
              </div>
            ))}
          </CardContent>
        </DetailCard>
        <DetailCard variant="placeholder">
          <CardHeader>
            <Skeleton className="h-3 w-24" />
          </CardHeader>
          <CardContent className="flex flex-col">
            {[0, 1].map((row) => (
              <div className={detailFieldClassName} key={row}>
                <Skeleton className="h-3 w-14" />
                <Skeleton className="h-4 w-1/3" />
                <span />
              </div>
            ))}
          </CardContent>
        </DetailCard>
      </div>
    </article>
  )
}
