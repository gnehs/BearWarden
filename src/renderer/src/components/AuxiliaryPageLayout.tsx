import type { ReactNode, RefObject } from 'react'
import { cn } from '@renderer/lib/utils'

interface AuxiliaryPageLayoutProps {
  title: string
  titleId: string
  subtitle?: string
  children: ReactNode
  headerActions?: ReactNode
  headerIcon?: ReactNode
  scrollRef?: RefObject<HTMLDivElement | null>
  scrollClassName?: string
}

interface AuxiliaryPageContentProps {
  children: ReactNode
  className?: string
}

export function AuxiliaryPageContent({
  children,
  className
}: AuxiliaryPageContentProps): React.JSX.Element {
  return (
    <div
      className={cn(
        'mx-auto grid w-full max-w-4xl grid-cols-[10rem_minmax(0,1fr)] items-start justify-center gap-5 max-[880px]:max-w-3xl max-[880px]:grid-cols-[minmax(0,1fr)]',
        className
      )}
    >
      {children}
    </div>
  )
}

function AuxiliaryPageLayout({
  title,
  titleId,
  subtitle,
  children,
  headerActions,
  headerIcon,
  scrollRef,
  scrollClassName
}: AuxiliaryPageLayoutProps): React.JSX.Element {
  return (
    <div
      className="relative isolate flex min-h-0 flex-1 flex-col bg-(--canvas)"
      aria-labelledby={titleId}
    >
      <header className="flex min-w-0 items-center justify-between gap-4 border-b border-(--surface-ring) py-3.5 pr-14 pl-5 max-[680px]:flex-col max-[680px]:items-start max-[680px]:gap-2.5 max-[680px]:pl-3">
        <div className="flex min-w-0 items-center gap-3">
          {headerIcon && (
            <span
              className="text-brand bg-card rounded-control grid size-9 shrink-0 place-items-center shadow-(--keycap-shadow) [&>svg]:size-4.5"
              aria-hidden="true"
            >
              {headerIcon}
            </span>
          )}
          <div className="min-w-0">
            <h1 id={titleId} className="m-0 text-lg leading-tight font-semibold tracking-tight">
              {title}
            </h1>
            {subtitle && (
              <p className="text-muted-foreground mt-0.5 text-xs leading-[1.45]">{subtitle}</p>
            )}
          </div>
        </div>
        {headerActions}
      </header>
      <div
        ref={scrollRef}
        className={cn(
          'min-h-0 flex-1 [scrollbar-color:var(--ring)_transparent] overflow-auto p-5 max-[680px]:px-3 max-[680px]:pt-3.5 max-[680px]:pb-6',
          scrollClassName
        )}
      >
        {children}
      </div>
    </div>
  )
}

export default AuxiliaryPageLayout
