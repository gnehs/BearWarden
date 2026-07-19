import * as React from 'react'
import { Card, CardContent } from '@renderer/components/ui/card'
import { Field } from '@renderer/components/ui/field'
import { cn } from '@renderer/lib/utils'

function SettingsCard({
  className,
  ...props
}: React.ComponentProps<typeof Card>): React.JSX.Element {
  return (
    <Card
      className={cn(
        'border-border gap-0 border py-0 shadow-[0_1px_2px_color-mix(in_oklch,var(--shadow-color)_4%,transparent)] [&_[data-slot=card-description]]:mt-0.5 [&_[data-slot=card-description]]:text-xs [&_[data-slot=card-description]]:leading-[1.5] [&_[data-slot=card-footer]]:justify-end [&_[data-slot=card-title]]:scroll-mt-[18px] [&_[data-slot=card-title]]:text-sm [&_[data-slot=card-title]]:font-[680] [&>[data-slot=card-header]]:items-center [&>[data-slot=card-header]]:px-[18px] [&>[data-slot=card-header]]:pt-[17px] [&>[data-slot=card-header]]:pb-[15px]',
        className
      )}
      {...props}
    />
  )
}

function SettingsCardContent({
  className,
  ...props
}: React.ComponentProps<typeof CardContent>): React.JSX.Element {
  return (
    <CardContent
      className={cn(
        'px-0 [&>[data-slot=separator]]:mx-[18px] [&>[data-slot=separator]]:w-auto',
        className
      )}
      {...props}
    />
  )
}

const settingsRowClassName =
  'min-h-[70px] gap-6 px-[18px] py-[13px] [&_[data-slot=field-label]]:text-[13px] [&_[data-slot=field-label]]:font-[630] [&_[data-slot=field-description]]:max-w-[58ch] [&_[data-slot=field-description]]:text-xs [&_[data-slot=field-description]]:leading-[1.5] [&>[data-slot=switch]]:shrink-0 [&>[data-slot=select-trigger]]:shrink-0 max-[680px]:flex-col max-[680px]:items-stretch max-[680px]:gap-2.5'

type SettingsRowProps = React.ComponentProps<typeof Field>
type SettingsRowVariantProps = Omit<SettingsRowProps, 'orientation'>

function SettingsRow({
  className,
  orientation = 'horizontal',
  ...props
}: SettingsRowProps): React.JSX.Element {
  return (
    <Field className={cn(settingsRowClassName, className)} orientation={orientation} {...props} />
  )
}

function SettingsSelectRow({ className, ...props }: SettingsRowVariantProps): React.JSX.Element {
  return (
    <SettingsRow
      className={cn(
        '[&>[data-slot=select-trigger]]:w-[150px] max-[680px]:[&>[data-slot=select-trigger]]:w-full',
        className
      )}
      orientation="horizontal"
      {...props}
    />
  )
}

function SettingsStackedRow({ className, ...props }: SettingsRowVariantProps): React.JSX.Element {
  return (
    <SettingsRow
      className={cn('items-stretch gap-2 [&>[data-slot=select-trigger]]:w-full', className)}
      orientation="vertical"
      {...props}
    />
  )
}

export { SettingsCard, SettingsCardContent, SettingsRow, SettingsSelectRow, SettingsStackedRow }
