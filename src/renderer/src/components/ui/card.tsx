import * as React from 'react'

import { cn } from '@renderer/lib/utils'

type CardTone = 'neutral' | 'brand' | 'amber' | 'sky' | 'violet' | 'rose'
type CardVariant = 'default' | 'folder'

// Titles follow their nearest card, so a plain card nested in a folder card keeps a plain title.
const CardVariantContext = React.createContext<CardVariant>('default')

// A folder card names its section above the card; the tone only tints the heading icon.
const folderToneClasses: Record<CardTone, string> = {
  neutral: '[--tab-icon:var(--color-slate-500)] dark:[--tab-icon:var(--color-slate-400)]',
  brand: '[--tab-icon:var(--color-emerald-600)] dark:[--tab-icon:var(--color-emerald-400)]',
  amber: '[--tab-icon:var(--color-amber-600)] dark:[--tab-icon:var(--color-amber-400)]',
  sky: '[--tab-icon:var(--color-sky-600)] dark:[--tab-icon:var(--color-sky-400)]',
  violet: '[--tab-icon:var(--color-violet-600)] dark:[--tab-icon:var(--color-violet-400)]',
  rose: '[--tab-icon:var(--color-rose-600)] dark:[--tab-icon:var(--color-rose-400)]'
}

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
          'group/card bg-card text-card-foreground flex flex-col gap-(--card-spacing) rounded-3xl bg-(image:--surface-sheen) py-(--card-spacing) text-sm shadow-(--surface-shadow) ring-1 ring-(--surface-ring) [--card-spacing:--spacing(4)] has-data-[slot=card-footer]:pb-0 has-[>img:first-child]:pt-0 data-[size=sm]:[--card-spacing:--spacing(3)] data-[size=sm]:has-data-[slot=card-footer]:pb-0 *:[img:first-child]:rounded-t-3xl *:[img:last-child]:rounded-b-3xl',
          variant === 'default' && 'overflow-hidden',
          variant === 'folder' && [
            'relative mt-12 rounded-2xl shadow-(--card-shadow)',
            folderToneClasses[tone]
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
          "text-foreground absolute bottom-[calc(100%+0.5rem)] left-1 flex h-6 max-w-[calc(100%-0.5rem)] items-center gap-2 truncate text-[0.8125rem] font-semibold whitespace-nowrap [&_svg]:shrink-0 [&_svg]:text-(--tab-icon) [&_svg:not([class*='size-'])]:size-4",
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
      className={cn('flex items-center rounded-b-3xl border-t p-(--card-spacing)', className)}
      {...props}
    />
  )
}

export type { CardTone }
export { Card, CardHeader, CardFooter, CardTitle, CardAction, CardDescription, CardContent }
