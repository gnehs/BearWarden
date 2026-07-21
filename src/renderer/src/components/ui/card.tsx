import * as React from 'react'

import { cn } from '@renderer/lib/utils'

function Card({
  className,
  size = 'default',
  variant = 'default',
  ...props
}: React.ComponentProps<'div'> & {
  size?: 'default' | 'sm'
  variant?: 'default' | 'item'
}) {
  return (
    <div
      data-slot="card"
      data-size={size}
      data-variant={variant}
      className={cn(
        'group/card bg-card text-card-foreground ring-foreground/10 flex flex-col gap-(--card-spacing) overflow-hidden py-(--card-spacing) text-sm ring-1 [--card-spacing:--spacing(4)] has-data-[slot=card-footer]:pb-0 has-[>img:first-child]:pt-0 data-[size=sm]:[--card-spacing:--spacing(3)] data-[size=sm]:has-data-[slot=card-footer]:pb-0 *:[img:first-child]:rounded-t-xl *:[img:last-child]:rounded-b-xl',
        variant === 'default' && 'rounded-xl',
        variant === 'item' &&
          'ring-border/70 [&_[data-slot=input]]:bg-muted [&_[data-slot=input-group]]:bg-muted [&_[data-slot=select-trigger]]:bg-muted [&_[data-slot=textarea]]:bg-muted rounded-[14px] shadow-[0_2px_8px_color-mix(in_oklch,var(--shadow-color)_6%,transparent)] [--card-spacing:--spacing(3)] [&_[data-slot=button]]:rounded-md [&_[data-slot=input-group]]:rounded-lg [&_[data-slot=input-group]]:border-transparent [&_[data-slot=input-group]]:shadow-none [&_[data-slot=input-group]:has(>input)]:h-9 [&_[data-slot=input]]:h-9 [&_[data-slot=input]]:rounded-lg [&_[data-slot=input]]:border-transparent [&_[data-slot=input]]:px-3 [&_[data-slot=input]]:shadow-none [&_[data-slot=select-trigger]]:h-9 [&_[data-slot=select-trigger]]:rounded-lg [&_[data-slot=select-trigger]]:border-transparent [&_[data-slot=select-trigger]]:px-3 [&_[data-slot=select-trigger]]:shadow-none [&_[data-slot=textarea]]:min-h-20 [&_[data-slot=textarea]]:rounded-lg [&_[data-slot=textarea]]:border-transparent [&_[data-slot=textarea]]:px-3 [&_[data-slot=textarea]]:py-2 [&_[data-slot=textarea]]:shadow-none',
        className
      )}
      {...props}
    />
  )
}

function CardHeader({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="card-header"
      className={cn(
        'group/card-header @container/card-header grid auto-rows-min items-start gap-1 rounded-t-xl px-(--card-spacing) group-data-[variant=item]/card:rounded-t-[14px] has-data-[slot=card-action]:grid-cols-[1fr_auto] has-data-[slot=card-description]:grid-rows-[auto_auto] [.border-b]:pb-(--card-spacing)',
        className
      )}
      {...props}
    />
  )
}

function CardTitle({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="card-title"
      className={cn(
        "text-base leading-snug font-medium group-data-[size=sm]/card:text-sm group-data-[variant=item]/card:flex group-data-[variant=item]/card:items-center group-data-[variant=item]/card:gap-1.5 group-data-[variant=item]/card:text-sm group-data-[variant=item]/card:font-medium group-data-[variant=item]/card:tracking-[-0.01em] group-data-[variant=item]/card:[&_svg]:shrink-0 group-data-[variant=item]/card:[&_svg:not([class*='size-'])]:size-4",
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
        'bg-muted/50 flex items-center rounded-b-xl border-t p-(--card-spacing) group-data-[variant=item]/card:rounded-b-[14px]',
        className
      )}
      {...props}
    />
  )
}

export { Card, CardHeader, CardFooter, CardTitle, CardAction, CardDescription, CardContent }
