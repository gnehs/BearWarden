import { Checkbox as CheckboxPrimitive } from '@base-ui/react/checkbox'

import { cn } from '@renderer/lib/utils'
import { CheckIcon, MinusIcon } from 'lucide-react'

function Checkbox({ className, ...props }: CheckboxPrimitive.Root.Props) {
  return (
    <CheckboxPrimitive.Root
      data-slot="checkbox"
      className={cn(
        "peer border-input focus-visible:border-ring focus-visible:ring-ring/50 aria-invalid:border-destructive aria-invalid:ring-destructive/20 aria-invalid:aria-checked:border-primary dark:bg-input/30 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40 data-checked:border-primary data-checked:bg-primary data-checked:text-primary-foreground dark:data-checked:bg-primary relative flex size-4 shrink-0 items-center justify-center rounded-[4px] border transition-[background,box-shadow] duration-[var(--check-box)] ease-[var(--check-ease)] outline-none [--check-len:23] group-has-disabled/field:opacity-50 after:absolute after:-inset-x-3 after:-inset-y-2 focus-visible:ring-3 disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:ring-3 data-checked:shadow-(--control-highlight) motion-reduce:!transition-none [&_svg_path]:transition-[stroke-dashoffset] [&_svg_path]:duration-[var(--check-uncheck)] [&_svg_path]:ease-[var(--check-ease)] [&_svg_path]:[stroke-dasharray:var(--check-len,15)] [&_svg_path]:[stroke-dashoffset:var(--check-len,15)] motion-reduce:[&_svg_path]:!transition-none [&[aria-checked='mixed']_svg_path]:delay-[var(--check-delay)] [&[aria-checked='mixed']_svg_path]:duration-[var(--check-draw)] [&[aria-checked='mixed']_svg_path]:[stroke-dashoffset:0] [&[aria-checked='true']_svg_path]:delay-[var(--check-delay)] [&[aria-checked='true']_svg_path]:duration-[var(--check-draw)] [&[aria-checked='true']_svg_path]:[stroke-dashoffset:0]",
        className
      )}
      {...props}
    >
      <CheckboxPrimitive.Indicator
        keepMounted
        data-slot="checkbox-indicator"
        className="grid place-content-center text-current transition-none [&>svg]:size-3.5"
        render={(indicatorProps, state) => (
          <span {...indicatorProps}>{state.indeterminate ? <MinusIcon /> : <CheckIcon />}</span>
        )}
      />
    </CheckboxPrimitive.Root>
  )
}

export { Checkbox }
