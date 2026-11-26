import type { JSX, ReactNode, RefObject } from 'react'
import { cn } from '@renderer/lib/utils'

/** Trigger style for the category list of a two-pane workspace dialog. */
export const workspaceNavTriggerClassName =
  'data-active:bg-primary! data-active:text-primary-foreground! h-8 flex-none justify-start gap-2 px-2 text-sm data-active:font-semibold max-[680px]:min-w-max [&>[data-slot=badge]]:ml-auto'

/** List style that stacks the categories and turns into a scrolling strip on narrow windows. */
export const workspaceNavListClassName =
  'scroll-fade-x scroll-fade-4 forced-colors:scroll-fade-none w-full items-stretch max-[680px]:flex-row max-[680px]:justify-start max-[680px]:overflow-x-auto'

interface WorkspaceDialogSidebarProps {
  title: ReactNode
  titleId: string
  /** Pinned to the bottom of the column; hidden on narrow windows. */
  footer?: ReactNode
  children?: ReactNode
}

/** Left column of a two-pane workspace dialog: its title, then the category list. */
export function WorkspaceDialogSidebar({
  title,
  titleId,
  footer,
  children
}: WorkspaceDialogSidebarProps): JSX.Element {
  return (
    <div className="flex w-52 shrink-0 flex-col gap-3 border-r border-(--surface-ring) p-3 max-[680px]:w-full max-[680px]:border-r-0 max-[680px]:border-b max-[680px]:pr-14">
      <h1
        id={titleId}
        className="m-0 px-2 pt-1.5 text-base leading-tight font-semibold tracking-tight"
      >
        {title}
      </h1>
      {children}
      {footer && <div className="mt-auto grid gap-2 max-[680px]:hidden">{footer}</div>}
    </div>
  )
}

interface WorkspaceDialogContentProps {
  scrollRef?: RefObject<HTMLDivElement | null>
  className?: string
  children: ReactNode
}

/** Right column of a two-pane workspace dialog; it scrolls on its own. */
export function WorkspaceDialogContent({
  scrollRef,
  className,
  children
}: WorkspaceDialogContentProps): JSX.Element {
  return (
    <div
      ref={scrollRef}
      className={cn(
        'scroll-fade scroll-fade-4 forced-colors:scroll-fade-none min-h-0 min-w-0 flex-1 [scrollbar-color:var(--ring)_transparent] overflow-auto bg-(--canvas) p-5 max-[680px]:p-3',
        className
      )}
    >
      {children}
    </div>
  )
}

interface WorkspaceDialogHeadingProps {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
}

/** Heading of the right column: the active category, its summary, and its actions. */
export function WorkspaceDialogHeading({
  title,
  description,
  actions
}: WorkspaceDialogHeadingProps): JSX.Element {
  return (
    <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 pt-0.5 pr-10 max-[680px]:pr-0">
      <div className="min-w-0">
        <h2 className="text-sm font-semibold">{title}</h2>
        {description && <p className="text-muted-foreground mt-0.5 text-xs">{description}</p>}
      </div>
      {actions}
    </div>
  )
}
