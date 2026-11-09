import * as React from 'react'

import { cn } from '@renderer/lib/utils'

type CardTone = 'neutral' | 'brand' | 'amber' | 'sky' | 'violet' | 'rose'
type CardVariant = 'default' | 'folder'

// Titles follow their nearest card, so a plain card nested in a folder card keeps a plain title.
const CardVariantContext = React.createContext<CardVariant>('default')

// Folder tabs read their colours from these variables so each tone stays a single map entry.
const folderToneClasses: Record<CardTone, string> = {
  neutral:
    '[--tab-from:var(--color-slate-50)] [--tab-to:var(--color-slate-100)] [--tab-fg:var(--color-slate-700)] [--tab-border:var(--color-slate-200)] dark:[--tab-from:var(--color-slate-800)] dark:[--tab-to:var(--color-slate-900)] dark:[--tab-fg:var(--color-slate-200)] dark:[--tab-border:var(--color-slate-700)]',
  brand:
    '[--tab-from:var(--color-emerald-50)] [--tab-to:var(--color-emerald-100)] [--tab-fg:var(--color-emerald-800)] [--tab-border:var(--color-emerald-200)] dark:[--tab-from:var(--color-emerald-900)] dark:[--tab-to:var(--color-emerald-950)] dark:[--tab-fg:var(--color-emerald-200)] dark:[--tab-border:var(--color-emerald-800)]',
  amber:
    '[--tab-from:var(--color-amber-50)] [--tab-to:var(--color-amber-100)] [--tab-fg:var(--color-amber-800)] [--tab-border:var(--color-amber-200)] dark:[--tab-from:var(--color-amber-900)] dark:[--tab-to:var(--color-amber-950)] dark:[--tab-fg:var(--color-amber-200)] dark:[--tab-border:var(--color-amber-800)]',
  sky: '[--tab-from:var(--color-sky-50)] [--tab-to:var(--color-sky-100)] [--tab-fg:var(--color-sky-800)] [--tab-border:var(--color-sky-200)] dark:[--tab-from:var(--color-sky-900)] dark:[--tab-to:var(--color-sky-950)] dark:[--tab-fg:var(--color-sky-200)] dark:[--tab-border:var(--color-sky-800)]',
  violet:
    '[--tab-from:var(--color-violet-50)] [--tab-to:var(--color-violet-100)] [--tab-fg:var(--color-violet-800)] [--tab-border:var(--color-violet-200)] dark:[--tab-from:var(--color-violet-900)] dark:[--tab-to:var(--color-violet-950)] dark:[--tab-fg:var(--color-violet-200)] dark:[--tab-border:var(--color-violet-800)]',
  rose: '[--tab-from:var(--color-rose-50)] [--tab-to:var(--color-rose-100)] [--tab-fg:var(--color-rose-800)] [--tab-border:var(--color-rose-200)] dark:[--tab-from:var(--color-rose-900)] dark:[--tab-to:var(--color-rose-950)] dark:[--tab-fg:var(--color-rose-200)] dark:[--tab-border:var(--color-rose-800)]'
}

const folderFieldClasses =
  '[&_[data-slot=input]]:bg-(--inset-surface) [&_[data-slot=input-group]]:bg-(--inset-surface) [&_[data-slot=select-trigger]]:bg-(--inset-surface) [&_[data-slot=textarea]]:bg-(--inset-surface) [&_[data-slot=button]]:rounded-lg [&_[data-slot=input-group]]:rounded-xl [&_[data-slot=input-group]]:border-transparent [&_[data-slot=input-group]]:shadow-(--inset-shadow) [&_[data-slot=input-group]:has(>input)]:h-9 [&_[data-slot=input]]:h-9 [&_[data-slot=input]]:rounded-xl [&_[data-slot=input]]:border-transparent [&_[data-slot=input]]:px-3 [&_[data-slot=input]]:shadow-(--inset-shadow) [&_[data-slot=select-trigger]]:h-9 [&_[data-slot=select-trigger]]:rounded-xl [&_[data-slot=select-trigger]]:border-transparent [&_[data-slot=select-trigger]]:px-3 [&_[data-slot=select-trigger]]:shadow-(--inset-shadow) [&_[data-slot=textarea]]:min-h-20 [&_[data-slot=textarea]]:rounded-xl [&_[data-slot=textarea]]:border-transparent [&_[data-slot=textarea]]:px-3 [&_[data-slot=textarea]]:py-2 [&_[data-slot=textarea]]:shadow-(--inset-shadow)'

function Card({
  className,
  size = 'default',
  variant = 'default',
  tone = 'neutral',
  ...props
}: React.ComponentProps<'div'> & {
  size?: 'default' | 'sm'
  /** `folder` hangs the card title above the card as a coloured folder tab. */
  variant?: CardVariant
  tone?: CardTone
}) {
  return (
    <CardVariantContext.Provider value={variant}>
      <div
        data-slot="card"
        data-size={size}
        data-variant={variant}
        data-tone={variant === 'folder' ? tone : undefined}
        className={cn(
          'group/card bg-card text-card-foreground flex flex-col gap-(--card-spacing) rounded-3xl py-(--card-spacing) text-sm shadow-(--surface-shadow) ring-1 ring-(--surface-ring) [--card-spacing:--spacing(4)] has-data-[slot=card-footer]:pb-0 has-[>img:first-child]:pt-0 data-[size=sm]:[--card-spacing:--spacing(3)] data-[size=sm]:has-data-[slot=card-footer]:pb-0 *:[img:first-child]:rounded-t-3xl *:[img:last-child]:rounded-b-3xl',
          variant === 'default' && 'overflow-hidden',
          variant === 'folder' && [
            'relative mt-7 rounded-2xl',
            folderToneClasses[tone],
            folderFieldClasses
          ],
          className
        )}
        {...props}
      />
    </CardVariantContext.Provider>
  )
}

function CardHeader({ className, ...props }: React.ComponentProps<'div'>) {
  const folder = React.useContext(CardVariantContext) === 'folder'
  return (
    <div
      data-slot="card-header"
      className={cn(
        'group/card-header @container/card-header grid auto-rows-min items-start gap-1 rounded-t-3xl px-(--card-spacing) has-data-[slot=card-action]:grid-cols-[1fr_auto] has-data-[slot=card-description]:grid-rows-[auto_auto] [.border-b]:pb-(--card-spacing)',
        // The tab title positions against the card, so the header must not become its containing
        // block; a header holding only that title has no in-flow content left inside the card.
        folder && '[container-type:normal] has-[>[data-slot=card-title]:only-child]:contents',
        className
      )}
      {...props}
    />
  )
}

function CardTitle({ className, ...props }: React.ComponentProps<'div'>) {
  const folder = React.useContext(CardVariantContext) === 'folder'
  return (
    <div
      data-slot="card-title"
      className={cn(
        'text-base leading-snug font-medium group-data-[size=sm]/card:text-sm',
        folder &&
          "absolute bottom-full left-4 flex h-7 max-w-[calc(100%-2rem)] items-center gap-1.5 truncate rounded-t-[0.625rem] border border-b-0 border-(--tab-border) bg-linear-to-b from-(--tab-from) to-(--tab-to) px-2.5 text-xs font-semibold whitespace-nowrap text-(--tab-fg) [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-3.5",
        className
      )}
      {...props}
    />
  )
}

function CardDescription({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="card-description"
      className={cn('text-muted-foreground text-sm', className)}
      {...props}
    />
  )
}

function CardAction({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="card-action"
      className={cn('col-start-2 row-span-2 row-start-1 self-start justify-self-end', className)}
      {...props}
    />
  )
}

function CardContent({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div data-slot="card-content" className={cn('px-(--card-spacing)', className)} {...props} />
  )
}

function CardFooter({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="card-footer"
      className={cn(
        'bg-muted/50 flex items-center rounded-b-3xl border-t p-(--card-spacing)',
        className
      )}
      {...props}
    />
  )
}

export type { CardTone }
export { Card, CardHeader, CardFooter, CardTitle, CardAction, CardDescription, CardContent }
