import type { ComponentProps, JSX, ReactNode } from 'react'
import type { VaultItemType } from '../../../shared/vault-contract'
import { cn } from '../lib/utils'

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
        className="m-0 truncate text-lg leading-tight font-semibold tracking-tight max-[680px]:text-base"
      >
        {title}
      </h2>
      <span className="text-muted-foreground block truncate text-xs">{subtitle}</span>
      {chips && <div className="mt-1 flex min-w-0 flex-wrap items-center gap-1.5">{chips}</div>}
    </div>
  )
}

export const detailScrollClassName =
  'min-h-0 flex-1 [scrollbar-color:var(--ring)_transparent] overflow-auto px-(--pane-content-inset) pt-1 pb-(--pane-content-inset)'

// Detail headers, the editor header, and the loading placeholder share one icon tile.
// eslint-disable-next-line react-refresh/only-export-components
export function detailIconClassName(type?: VaultItemType): string {
  return cn(
    'bg-card text-brand dark:bg-muted dark:text-muted-foreground rounded-control grid size-13 flex-none place-items-center shadow-(--keycap-shadow) max-[680px]:size-10 max-[430px]:hidden forced-colors:[forced-color-adjust:none] [&>svg]:size-5',
    type === 'login' && 'overflow-hidden',
    type === 'card' && 'bg-muted text-chart-4 dark:bg-(--website-icon-background)',
    type === 'identity' && 'bg-accent text-brand',
    type === 'secureNote' && 'bg-muted text-chart-3',
    type === 'sshKey' && 'bg-accent text-chart-2',
    type === 'bankAccount' && 'bg-muted text-chart-1',
    (type === 'driversLicense' || type === 'passport') && 'bg-accent text-chart-5'
  )
}

/** The ~40px item icon tile of a detail header; it stays visible on narrow panes. */
// eslint-disable-next-line react-refresh/only-export-components
export function detailHeaderIconClassName(type?: VaultItemType): string {
  return cn(detailIconClassName(type), 'size-10 max-[680px]:size-10 max-[430px]:grid')
}
