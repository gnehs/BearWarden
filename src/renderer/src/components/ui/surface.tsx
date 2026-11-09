import * as React from 'react'

import { cn } from '@renderer/lib/utils'

/**
 * The decorative dot-grid canvas drawn behind card layouts. It fills its positioned parent and
 * sits at `-z-10`, so the parent must also be `isolate` to keep it above outer backgrounds.
 */
function DotGridBackdrop({
  className,
  translucent = false,
  ...props
}: React.ComponentProps<'div'> & {
  /** Leave the canvas colour out so a native window material shows between the dots. */
  translucent?: boolean
}) {
  return (
    <div
      data-slot="dot-grid-backdrop"
      aria-hidden="true"
      className={cn(
        'pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(circle,var(--dot-grid-color)_1px,transparent_1.5px)] bg-size-[16px_16px] bg-center forced-colors:hidden',
        !translucent && 'bg-(color:--canvas)',
        className
      )}
      {...props}
    />
  )
}

/** A recessed grey well, used for rows and previews that sit inside a card. */
function InsetPanel({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="inset-panel"
      className={cn('rounded-2xl bg-(--inset-surface) shadow-(--inset-shadow)', className)}
      {...props}
    />
  )
}

export { DotGridBackdrop, InsetPanel }
