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
      className="relative inline-grid"
      data-slot="copy-feedback-icon"
      data-state={copied ? 'b' : 'a'}
      data-icon={placement}
      aria-hidden="true"
    >
      <span
        className="relative inline-grid data-[state=a]:[&>svg[data-icon=a]]:[transform:scale(1)] data-[state=a]:[&>svg[data-icon=a]]:opacity-100 data-[state=a]:[&>svg[data-icon=a]]:[filter:blur(0)] data-[state=b]:[&>svg[data-icon=a]]:[transform:scale(var(--icon-swap-start-scale))] data-[state=b]:[&>svg[data-icon=a]]:opacity-0 data-[state=b]:[&>svg[data-icon=a]]:[filter:blur(var(--icon-swap-blur))] data-[state=a]:[&>svg[data-icon=b]]:[transform:scale(var(--icon-swap-start-scale))] data-[state=a]:[&>svg[data-icon=b]]:opacity-0 data-[state=a]:[&>svg[data-icon=b]]:[filter:blur(var(--icon-swap-blur))] data-[state=b]:[&>svg[data-icon=b]]:[transform:scale(1)] data-[state=b]:[&>svg[data-icon=b]]:opacity-100 data-[state=b]:[&>svg[data-icon=b]]:[filter:blur(0)] [[data-slot=input-group-button]>_*_&]:size-[0.875rem] [[data-slot=input-group-button]>_*_&]:[&>[data-icon]]:size-[0.875rem]"
        data-state={copied ? 'b' : 'a'}
      >
        <IdleIcon
          className="col-start-1 row-start-1 transition-[opacity,filter,transform] duration-[var(--icon-swap-dur)] ease-[var(--icon-swap-ease)] will-change-[opacity,filter,transform] motion-reduce:transition-none!"
          data-icon="a"
        />
        <Check
          className="col-start-1 row-start-1 transition-[opacity,filter,transform] duration-[var(--icon-swap-dur)] ease-[var(--icon-swap-ease)] will-change-[opacity,filter,transform] motion-reduce:transition-none!"
          data-icon="b"
        />
      </span>
    </span>
  )
}
