import { cn } from '@renderer/lib/utils'

interface TotpCountdownIndicatorProps {
  remainingSeconds: number | null
  period: number
  className?: string
}

export default function TotpCountdownIndicator({
  remainingSeconds,
  period,
  className
}: TotpCountdownIndicatorProps): React.JSX.Element {
  const value = remainingSeconds === null ? null : Math.min(period, Math.max(0, remainingSeconds))
  const percentage = value === null || period <= 0 ? 0 : (value / period) * 100

  return (
    <div
      className={cn(
        'bg-card text-foreground relative grid size-11 place-items-center rounded-full shadow-[0_6px_18px_color-mix(in_oklch,var(--shadow-color)_24%,transparent)] ring-2 ring-white',
        className
      )}
      data-slot="totp-countdown-indicator"
      role="progressbar"
      aria-label="驗證碼剩餘時間"
      aria-valuemin={0}
      aria-valuemax={period}
      aria-valuenow={value ?? undefined}
      aria-valuetext={value === null ? '正在取得驗證碼' : `剩餘 ${value} 秒`}
    >
      <svg className="size-full -rotate-90" viewBox="0 0 100 100" aria-hidden="true">
        <circle className="stroke-muted fill-none" cx="50" cy="50" r="40" strokeWidth="18" />
        <circle
          className="stroke-primary fill-none [transition-property:stroke-dashoffset] duration-[1s] ease-linear motion-reduce:duration-0"
          cx="50"
          cy="50"
          r="40"
          pathLength="100"
          strokeDasharray="100"
          strokeLinecap="round"
          strokeWidth="18"
          style={{ strokeDashoffset: 100 - percentage }}
        />
      </svg>
      <span className="absolute inset-0 grid place-items-center text-[11px] font-medium tracking-tight tabular-nums">
        {value ?? '…'}
      </span>
    </div>
  )
}
