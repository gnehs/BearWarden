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
        't-toggle peer group/switch focus-visible:border-ring focus-visible:ring-ring/50 aria-invalid:border-destructive aria-invalid:ring-destructive/20 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40 data-checked:bg-primary data-unchecked:bg-input dark:data-unchecked:bg-input/80 relative inline-flex shrink-0 items-center rounded-full border border-transparent outline-none [--toggle-travel:14px] after:absolute after:-inset-x-3 after:-inset-y-2 focus-visible:ring-3 aria-invalid:ring-3 data-checked:shadow-[var(--control-highlight)] data-disabled:cursor-not-allowed data-disabled:opacity-50 data-[size=default]:h-[18.4px] data-[size=default]:w-[32px] data-[size=sm]:h-[14px] data-[size=sm]:w-[24px] data-[size=sm]:[--toggle-travel:10px]',
        isInitialized && 'is-init',
        className
      )}
      checked={checked}
      defaultChecked={defaultChecked}
      onCheckedChange={handleCheckedChange}
      {...props}
    >
      <SwitchPrimitive.Thumb
        data-slot="switch-thumb"
        className="t-toggle-thumb bg-background dark:data-checked:bg-primary-foreground dark:data-unchecked:bg-foreground pointer-events-none block rounded-full ring-0 group-data-[size=default]/switch:size-4 group-data-[size=sm]/switch:size-3"
      />
    </SwitchPrimitive.Root>
  )
}

export { Switch }
