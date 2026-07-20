import bearIconUrl from '../../../../resources/icon.svg'
import { cn } from '@renderer/lib/utils'

interface BrandMarkProps {
  compact?: boolean
  hideMark?: boolean
  stacked?: boolean
  className?: string
}

function BrandMark({
  compact = false,
  hideMark = false,
  stacked = false,
  className
}: BrandMarkProps): React.JSX.Element {
  return (
    <div
      className={cn(
        'inline-flex min-w-max items-center gap-[9px] font-semibold tracking-[-0.02em]',
        stacked && 'flex-col gap-1',
        className
      )}
      role="img"
      aria-label="BearWarden"
    >
      <span
        className={cn('grid size-10 place-items-center', compact && 'size-8', hideMark && 'hidden')}
        aria-hidden="true"
      >
        <img
          className="block size-full"
          src={bearIconUrl}
          alt=""
          width={compact ? 32 : 40}
          height={compact ? 32 : 40}
        />
      </span>
      {!compact && <span className="text-base">BearWarden</span>}
    </div>
  )
}

export default BrandMark
