import bearIconUrl from '../assets/icon.svg'
import { cn } from '@renderer/lib/utils'

interface BrandMarkProps {
  compact?: boolean
  hideMark?: boolean
  className?: string
}

function BrandMark({
  compact = false,
  hideMark = false,
  className
}: BrandMarkProps): React.JSX.Element {
  return (
    <div
      className={cn(
        'inline-flex min-w-max items-center gap-[9px] font-semibold tracking-[-0.02em]',
        className
      )}
      role="img"
      aria-label="BearWarden"
    >
      <span
        className={cn(
          'grid size-8 place-items-center rounded-[10px] bg-[linear-gradient(145deg,#a5794b,#684728)] text-[#fff9ed] shadow-[inset_0_1px_rgb(255_255_255_/_22%)]',
          hideMark && 'hidden'
        )}
        aria-hidden="true"
      >
        <img
          className="block size-full rounded-[inherit]"
          src={bearIconUrl}
          alt=""
          width={compact ? 18 : 24}
          height={compact ? 18 : 24}
        />
      </span>
      {!compact && <span className="text-base">BearWarden</span>}
    </div>
  )
}

export default BrandMark
