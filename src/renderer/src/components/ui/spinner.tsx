import { cn } from '@renderer/lib/utils'
import { useLingui } from '@lingui/react/macro'
import { Loader2Icon } from 'lucide-react'

function Spinner({ className, ...props }: React.ComponentProps<'svg'>) {
  const { t } = useLingui()

  return (
    <Loader2Icon
      data-slot="spinner"
      role="status"
      aria-label={t`Loading`}
      className={cn('size-4 animate-spin', className)}
      {...props}
    />
  )
}

export { Spinner }
