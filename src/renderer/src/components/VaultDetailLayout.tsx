import { useId, type ComponentProps, type JSX, type ReactNode } from 'react'
import { cn } from '../lib/utils'

/** Quiet 28px ghost icon buttons used for the actions at the end of every detail row. */
export const detailActionClassName = 'size-7 min-w-7'

/** Value text of a stacked row; copy buttons and plain values share it. */
export const detailValueClassName = 'min-w-0 truncate text-sm font-medium'

/**
 * The value of a row that copies on click. Its hit area stretches over the whole row, so
 * clicking anywhere outside the action buttons copies; the row draws the hover and focus.
 */
export const detailValueButtonClassName =
  "h-auto min-w-0 flex-1 justify-start overflow-hidden px-0 py-0.5 text-sm hover:bg-transparent focus-visible:ring-0 active:not-aria-[haspopup]:scale-100 after:absolute after:inset-0 after:content-[''] focus-visible:after:ring-3 focus-visible:after:ring-ring/50 focus-visible:after:ring-inset"

interface DetailGroupProps extends Omit<ComponentProps<'section'>, 'children'> {
  /** Small caption above the card; omit for the primary card. */
  caption?: ReactNode
  /** Accessible name for a group without a visible caption. */
  label?: string
  children: ReactNode
}

/** One card of stacked rows, preceded only by an optional 11px caption. */
export function DetailGroup({
  caption,
  label,
  className,
  children,
  ...props
}: DetailGroupProps): JSX.Element {
  const captionId = useId()
  return (
    <section
      className={cn('mx-auto w-full max-w-[720px] shrink-0', className)}
      aria-labelledby={caption ? captionId : undefined}
      aria-label={caption ? undefined : label}
      {...props}
    >
      {caption && (
        <h3
          id={captionId}
          className="text-muted-foreground m-0 mb-1.5 px-3 text-[11px] leading-4 font-semibold"
        >
          {caption}
        </h3>
      )}
      <div className="bg-card rounded-nested divide-y divide-(--surface-ring) overflow-hidden shadow-(--surface-shadow) ring-1 ring-(--surface-ring)">
        {children}
      </div>
    </section>
  )
}

interface DetailRowProps extends Omit<ComponentProps<'div'>, 'children'> {
  /** 11px muted caption stacked above the value. */
  label?: ReactNode
  /** Tile before the text, such as an attachment or passkey icon. */
  leading?: ReactNode
  /** Buttons at the right edge; always visible. */
  actions?: ReactNode
  children: ReactNode
}

/** A stacked row: muted label above the value, actions at the right. */
export function DetailRow({
  label,
  leading,
  actions,
  className,
  children,
  ...props
}: DetailRowProps): JSX.Element {
  return (
    <div
      className={cn(
        'relative flex min-w-0 items-center gap-1 py-1.5 pr-1.5 pl-3 transition-colors duration-150 has-[[data-field-copy-value]:not(:disabled):hover]:bg-[color-mix(in_oklch,var(--card),var(--foreground)_3%)]',
        className
      )}
      {...props}
    >
      {leading && <span className="mr-1.5 flex flex-none">{leading}</span>}
      <div className="min-w-0 flex-1">
        {label && (
          <span className="text-muted-foreground block truncate text-[11px] leading-4">
            {label}
          </span>
        )}
        {children}
      </div>
      {actions && <div className="relative flex flex-none items-center">{actions}</div>}
    </div>
  )
}

/** Two rows sharing one line, such as a card's expiry and security code. */
export function DetailRowPair({ children }: { children: ReactNode }): JSX.Element {
  return (
    <div className="grid grid-cols-2 divide-x divide-(--surface-ring) max-[430px]:grid-cols-1 max-[430px]:divide-x-0 max-[430px]:divide-y">
      {children}
    </div>
  )
}

/** Square neutral tile that leads attachment, passkey and notice rows. */
export function DetailLeadingTile({ children }: { children: ReactNode }): JSX.Element {
  return (
    <span
      className="bg-muted text-muted-foreground rounded-control grid size-7 flex-none place-items-center [&>svg]:size-3.5"
      aria-hidden="true"
    >
      {children}
    </span>
  )
}

/** Multi-line value that wraps instead of truncating, used for notes and addresses. */
export function DetailWrappedText({ className, ...props }: ComponentProps<'p'>): JSX.Element {
  return (
    <p
      className={cn(
        'm-0 py-0.5 text-sm leading-relaxed break-words whitespace-pre-wrap select-text',
        className
      )}
      {...props}
    />
  )
}

/** Quiet two-column footer for timestamps below the cards. */
export function DetailTimestamps({ children }: { children: ReactNode }): JSX.Element {
  return (
    <dl className="text-muted-foreground m-0 mx-auto grid w-full max-w-[720px] shrink-0 grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-0.5 px-3 text-xs leading-5">
      {children}
    </dl>
  )
}

export function DetailTimestamp({
  label,
  children
}: {
  label: ReactNode
  children: ReactNode
}): JSX.Element {
  return (
    <>
      <dt className="min-w-0">{label}</dt>
      <dd className="m-0 min-w-0">{children}</dd>
    </>
  )
}

/** Top-right toolbar row of the detail pane; the compact back button sits at the left. */
export function DetailToolbar({
  back,
  children
}: {
  back?: ReactNode
  children?: ReactNode
}): JSX.Element {
  return (
    <div className="flex min-h-11 flex-none items-center justify-between gap-1 px-2.5 pt-2">
      <span className="flex">{back}</span>
      <div className="flex items-center gap-0.5">{children}</div>
    </div>
  )
}

interface DetailTitleBlockProps {
  icon: ReactNode
  title: ReactNode
  meta: ReactNode
}

/** Icon, a title that may wrap to two lines, and one muted meta line. */
export function DetailTitleBlock({ icon, title, meta }: DetailTitleBlockProps): JSX.Element {
  return (
    <div className="flex flex-none items-start gap-3 px-5 pt-1 pb-4 max-[680px]:px-3">
      {icon}
      <div className="grid min-w-0 flex-1 gap-0.5">
        <h2 className="m-0 line-clamp-2 text-lg leading-tight font-semibold tracking-tight break-words">
          {title}
        </h2>
        <div className="text-muted-foreground flex min-w-0 flex-wrap items-center gap-x-1.5 text-xs leading-5">
          {meta}
        </div>
      </div>
    </div>
  )
}

/** Size of the ghost icon buttons in the detail toolbar. */
export const detailToolbarButtonClassName = 'size-7.5 min-w-7.5'
