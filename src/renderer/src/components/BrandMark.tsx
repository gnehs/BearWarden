import bearIconUrl from '../../../../resources/icon.svg'
import { cn } from '@renderer/lib/utils'

interface BrandMarkProps {
  hideMark?: boolean
  stacked?: boolean
  className?: string
}

function BrandMark({
  hideMark = false,
  stacked = false,
  className
}: BrandMarkProps): React.JSX.Element {
  return (
    <div
      className={cn(
        'inline-flex min-w-max items-center gap-2 font-semibold',
        stacked && 'flex-col gap-1',
        className
      )}
      role="img"
      aria-label="BearWarden"
    >
      <span
        className={cn('grid size-10 place-items-center', hideMark && 'hidden')}
        aria-hidden="true"
      >
        <img className="block size-full" src={bearIconUrl} alt="" width={40} height={40} />
      </span>
      <span className="text-base">BearWarden</span>
    </div>
  )
}

export default BrandMark
