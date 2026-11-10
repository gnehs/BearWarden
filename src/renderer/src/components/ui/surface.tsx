import * as React from 'react'

import { cn } from '@renderer/lib/utils'

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

export { InsetPanel }
