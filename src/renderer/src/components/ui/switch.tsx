'use client'

import { Switch as SwitchPrimitive } from '@base-ui/react/switch'
import { useLayoutEffect, useRef, useState } from 'react'

import { cn } from '@renderer/lib/utils'

function Switch({
  className,
  size = 'default',
  checked,
  defaultChecked,
  onCheckedChange,
  ...props
}: SwitchPrimitive.Root.Props & {
  size?: 'sm' | 'default'
}) {
  const [isInitialized, setIsInitialized] = useState(false)
  const [uncontrolledChecked, setUncontrolledChecked] = useState(defaultChecked ?? false)
  const currentChecked = checked ?? uncontrolledChecked
  const previousControlledCheckedRef = useRef(checked)

  useLayoutEffect(() => {
    if (
      checked !== undefined &&
      previousControlledCheckedRef.current !== undefined &&
      checked !== previousControlledCheckedRef.current
    ) {
      setIsInitialized(true)
    }
    previousControlledCheckedRef.current = checked
  }, [checked])

  const handleCheckedChange: NonNullable<SwitchPrimitive.Root.Props['onCheckedChange']> = (
    nextChecked,
    eventDetails
  ) => {
    onCheckedChange?.(nextChecked, eventDetails)
    if (eventDetails.isCanceled) return

    if (checked === undefined) {
      setIsInitialized(true)
      setUncontrolledChecked(nextChecked)
    }
  }

  return (
    <SwitchPrimitive.Root
      data-slot="switch"
      data-size={size}
      data-on={currentChecked ? 'true' : 'false'}
      className={cn(
        'peer group/switch focus-visible:border-ring focus-visible:ring-ring/50 aria-invalid:border-destructive aria-invalid:ring-destructive/20 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40 data-checked:bg-brand relative inline-flex shrink-0 items-center rounded-full border border-transparent shadow-[inset_0_1px_2px_color-mix(in_oklch,var(--shadow-color)_14%,transparent)] transition-[background] duration-[var(--toggle-track)] ease-[var(--toggle-ease)] outline-none [--toggle-travel:14px] after:absolute after:-inset-x-3 after:-inset-y-2 focus-visible:ring-3 aria-invalid:ring-3 data-checked:shadow-(--control-highlight) data-disabled:cursor-not-allowed data-disabled:opacity-50 data-unchecked:bg-[color-mix(in_oklch,var(--foreground)_14%,var(--card))] data-[size=default]:h-[22px] data-[size=default]:w-[38px] data-[size=sm]:h-[14px] data-[size=sm]:w-[24px] data-[size=sm]:[--toggle-travel:10px]',
        className
      )}
      checked={checked}
      defaultChecked={defaultChecked}
      onCheckedChange={handleCheckedChange}
      {...props}
    >
      <SwitchPrimitive.Thumb
        data-slot="switch-thumb"
        className={cn(
          'pointer-events-none block translate-x-0 rounded-full bg-white shadow-[0_1px_2px_oklch(0_0_0/20%),0_2px_4px_oklch(0_0_0/8%)] ring-0 will-change-[translate] group-data-[on=true]/switch:translate-x-[var(--toggle-travel)] group-data-[size=default]/switch:ml-[2px] group-data-[size=default]/switch:size-[18px] group-data-[size=sm]/switch:size-3 motion-reduce:animate-none!',
          isInitialized &&
            'group-data-[on=false]/switch:animate-[t-toggle-off_var(--toggle-dur)_var(--toggle-ease)_both] group-data-[on=true]/switch:animate-[t-toggle-on_var(--toggle-dur)_var(--toggle-ease)_both]'
        )}
      />
    </SwitchPrimitive.Root>
  )
}

export { Switch }
