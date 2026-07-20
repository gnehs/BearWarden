import type { ReactNode, RefObject } from 'react'
import { cn } from '@renderer/lib/utils'

interface AuxiliaryPageLayoutProps {
  eyebrow?: string
  title: string
  titleId: string
  subtitle: string
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
        'mx-auto grid w-full max-w-[910px] grid-cols-[162px_minmax(0,720px)] items-start justify-center gap-[18px] max-[880px]:max-w-[720px] max-[880px]:grid-cols-[minmax(0,1fr)]',
        className
      )}
    >
      {children}
    </div>
  )
}

function AuxiliaryPageLayout({
  eyebrow,
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
    <div className="flex min-h-0 flex-1 flex-col" aria-labelledby={titleId}>
      <header className="border-border min-h-[94px] border-b bg-[color-mix(in_oklch,var(--card)_94%,transparent)] px-[clamp(20px,3vw,38px)] py-4 backdrop-blur-[18px] max-[680px]:min-h-0">
        <div className="mx-auto grid w-full max-w-[910px] grid-cols-[minmax(0,1fr)] items-center justify-center gap-[18px]">
          <div className="flex min-w-0 items-center justify-between gap-6 max-[680px]:flex-col max-[680px]:items-start max-[680px]:gap-2.5">
            <div className="flex min-w-0 items-center gap-[13px]">
              {headerIcon && (
                <span
                  className="text-primary grid size-[42px] shrink-0 place-items-center rounded-[13px] bg-[var(--accent-soft)] [&>svg]:size-5"
                  aria-hidden="true"
                >
                  {headerIcon}
                </span>
              )}
              <div className="min-w-0">
                {eyebrow && (
                  <p className="text-primary mb-px text-[9px] font-extrabold tracking-[0.11em] uppercase">
                    {eyebrow}
                  </p>
                )}
                <h1 id={titleId} className="m-0 text-[23px] leading-[1.2] tracking-[-0.035em]">
                  {title}
                </h1>
                <p className="text-muted-foreground mt-1 text-xs leading-[1.45]">{subtitle}</p>
              </div>
            </div>
            {headerActions}
          </div>
        </div>
      </header>
      <div
        ref={scrollRef}
        className={cn(
          'min-h-0 flex-1 [scrollbar-color:var(--border-strong)_transparent] overflow-auto bg-[color-mix(in_oklch,var(--muted)_34%,var(--background))] p-[clamp(18px,3vw,32px)] max-[680px]:px-3 max-[680px]:pt-3.5 max-[680px]:pb-6',
          scrollClassName
        )}
      >
        {children}
      </div>
    </div>
  )
}

export default AuxiliaryPageLayout
