import type { ReactNode, RefObject } from 'react'
import { cn } from '@renderer/lib/utils'

interface AuxiliaryPageLayoutProps {
  title: string
  titleId: string
  subtitle: string
  children: ReactNode
  headerActions?: ReactNode
  headerNavigation?: ReactNode
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
  headerNavigation,
  headerIcon,
  scrollRef,
  scrollClassName
}: AuxiliaryPageLayoutProps): React.JSX.Element {
  return (
    <div className="flex min-h-0 flex-1 flex-col" aria-labelledby={titleId}>
      <header
        className={cn(
          'border-border min-h-24 border-b bg-[color-mix(in_oklch,var(--card)_94%,transparent)] px-[clamp(1.25rem,3vw,2.5rem)] backdrop-blur-lg max-[680px]:min-h-0',
          headerNavigation ? 'pt-4' : 'py-4'
        )}
      >
        <div className="mx-auto grid w-full max-w-4xl grid-cols-[minmax(0,1fr)] items-center justify-center gap-5">
          <div className="flex min-w-0 items-center justify-between gap-6 max-[680px]:flex-col max-[680px]:items-start max-[680px]:gap-2.5">
            <div className="flex min-w-0 items-center gap-3">
              {headerIcon && (
                <span
                  className="text-primary grid size-11 shrink-0 place-items-center rounded-xl bg-[var(--accent-soft)] [&>svg]:size-5"
                  aria-hidden="true"
                >
                  {headerIcon}
                </span>
              )}
              <div className="min-w-0">
                <h1 id={titleId} className="m-0 text-2xl leading-tight">
                  {title}
                </h1>
                <p className="text-muted-foreground mt-1 text-xs leading-[1.45]">{subtitle}</p>
              </div>
            </div>
            {headerActions}
          </div>
          {headerNavigation && <div className="w-full min-w-0">{headerNavigation}</div>}
        </div>
      </header>
      <div
        ref={scrollRef}
        className={cn(
          'min-h-0 flex-1 [scrollbar-color:var(--border-strong)_transparent] overflow-auto bg-[color-mix(in_oklch,var(--muted)_34%,var(--background))] p-[clamp(1rem,3vw,2rem)] max-[680px]:px-3 max-[680px]:pt-3.5 max-[680px]:pb-6',
          scrollClassName
        )}
      >
        {children}
      </div>
    </div>
  )
}

export default AuxiliaryPageLayout
