import { Check, Copy, type LucideIcon } from 'lucide-react'

interface CopyFeedbackIconProps {
  copied: boolean
  idleIcon?: LucideIcon
  placement?: 'inline-start' | 'inline-end'
}

export function CopyFeedbackIcon({
  copied,
  idleIcon: IdleIcon = Copy,
  placement
}: CopyFeedbackIconProps): React.JSX.Element {
  return (
    <span
      className="t-icon-swap"
      data-state={copied ? 'b' : 'a'}
      data-icon={placement}
      aria-hidden="true"
    >
      <IdleIcon className="t-icon" data-icon="a" />
      <Check className="t-icon" data-icon="b" />
    </span>
  )
}
