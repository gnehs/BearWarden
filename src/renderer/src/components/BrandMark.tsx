import bearIconUrl from '../assets/icon.svg'

interface BrandMarkProps {
  compact?: boolean
}

function BrandMark({ compact = false }: BrandMarkProps): React.JSX.Element {
  return (
    <div className="brand" role="img" aria-label="BearWarden">
      <span className="brand-mark" aria-hidden="true">
        <img src={bearIconUrl} alt="" width={compact ? 18 : 24} height={compact ? 18 : 24} />
      </span>
      {!compact && <span className="brand-name">BearWarden</span>}
    </div>
  )
}

export default BrandMark
