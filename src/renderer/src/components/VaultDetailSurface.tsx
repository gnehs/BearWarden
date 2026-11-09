import type { ComponentProps, HTMLAttributes, JSX, ReactNode } from 'react'
import type { VaultItemType } from '../../../shared/vault-contract'
import { cn } from '../lib/utils'
import { Card } from './ui/card'

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
      variant="folder"
      className={cn(
        'mx-auto mb-2 w-full max-w-[720px] [--card-spacing:--spacing(2.5)]',
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
        'flex items-center gap-4 border-b border-(--surface-ring) bg-(--glass-surface) px-6 py-5 backdrop-blur-xl backdrop-saturate-150 max-[680px]:gap-2.5 max-[680px]:px-3 max-[680px]:py-3',
        className
      )}
      {...props}
    />
  )
}

interface DetailHeadingProps {
  title: ReactNode
  titleId?: string
  subtitle: ReactNode
  chips?: ReactNode
}

/** The item title block of a detail header: large name, muted source line, then status chips. */
export function DetailHeading({
  title,
  titleId,
  subtitle,
  chips
}: DetailHeadingProps): JSX.Element {
  return (
    <div className="grid min-w-0 flex-1 gap-1">
      <h2
        id={titleId}
        className="m-0 truncate text-xl leading-tight font-semibold tracking-tight max-[680px]:text-base"
      >
        {title}
      </h2>
      <span className="text-muted-foreground block truncate text-xs">{subtitle}</span>
      {chips && <div className="mt-1 flex min-w-0 flex-wrap items-center gap-1.5">{chips}</div>}
    </div>
  )
}

interface DetailMetaRowProps {
  label: ReactNode
  children: ReactNode
  valueClassName?: string
}

interface DetailRowGroupProps extends HTMLAttributes<HTMLElement> {
  as?: 'div' | 'dl'
}

/** One recessed well that stacks a card's rows, separated by hairlines. */
export function DetailRowGroup({
  as: Tag = 'div',
  className,
  ...props
}: DetailRowGroupProps): JSX.Element {
  return <Tag className={cn('m-0 -my-1 flex flex-col overflow-hidden', className)} {...props} />
}

/** A read-only label/value pair inside a `DetailRowGroup` rendered as a `<dl>`. */
export function DetailMetaRow({
  label,
  children,
  valueClassName
}: DetailMetaRowProps): JSX.Element {
  return (
    <div className="grid min-h-10 grid-cols-[minmax(90px,0.28fr)_minmax(0,1fr)] items-center gap-2 border-b border-(--surface-ring) px-3 py-2 last:border-b-0 max-[430px]:grid-cols-1 max-[430px]:items-start max-[430px]:gap-1">
      <dt className="text-muted-foreground text-xs leading-4">{label}</dt>
      <dd className={cn('m-0 min-w-0 text-xs leading-4', valueClassName)}>{children}</dd>
    </div>
  )
}

export const detailFieldClassName =
  'grid min-h-10 grid-cols-[minmax(90px,0.28fr)_minmax(0,1fr)_repeat(2,auto)] items-center gap-1 border-b border-(--surface-ring) py-0.5 pr-1 pl-3 last:border-b-0 [&>span]:text-xs [&>span]:text-muted-foreground [&>strong]:min-w-0 [&>strong]:truncate [&>strong]:text-xs [&>strong]:font-medium [&>:nth-child(3):last-child]:col-start-[-2] max-[430px]:grid-cols-[1fr_auto_auto] max-[430px]:gap-1.5 max-[430px]:[&>span]:col-span-full max-[430px]:[&>strong]:col-start-1 max-[430px]:[&>[data-field-copy-value]]:col-start-1'

/** Row actions stay quiet inside the recessed well until hovered. */
export const detailRowActionClassName =
  'size-7 min-w-7 rounded-lg border-transparent bg-transparent shadow-none dark:bg-transparent'

export const detailScrollClassName =
  'min-h-0 flex-1 [scrollbar-color:var(--ring)_transparent] overflow-auto px-5 pt-1 pb-6 max-[680px]:px-3 max-[680px]:pb-5'

// Detail headers, the editor header, and the loading placeholder share one icon tile.
// eslint-disable-next-line react-refresh/only-export-components
export function detailIconClassName(type?: VaultItemType): string {
  return cn(
    'bg-card text-brand dark:text-muted-foreground grid size-13 flex-none place-items-center rounded-2xl shadow-(--keycap-shadow) max-[680px]:size-10 max-[680px]:rounded-xl max-[430px]:hidden forced-colors:[forced-color-adjust:none] [&>svg]:size-5',
    type === 'login' && 'overflow-hidden',
    type === 'card' && 'bg-muted text-chart-4 dark:bg-website-icon-background',
    type === 'identity' && 'bg-accent text-brand',
    type === 'secureNote' && 'bg-muted text-chart-3',
    type === 'sshKey' && 'bg-accent text-chart-2'
  )
}
