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
        'outline-border gap-0 rounded-2xl py-0 shadow-[0_1px_2px_color-mix(in_oklch,var(--shadow-color)_4%,transparent)] outline [&_[data-slot=card-description]]:mt-0.5 [&_[data-slot=card-description]]:text-xs [&_[data-slot=card-description]]:leading-[1.5] [&_[data-slot=card-footer]]:justify-end [&_[data-slot=card-title]]:scroll-mt-5 [&_[data-slot=card-title]]:text-sm [&_[data-slot=card-title]]:font-[680] [&>[data-slot=card-header]]:items-center [&>[data-slot=card-header]]:px-5 [&>[data-slot=card-header]]:py-5',
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
        'px-0 [&>[data-slot=separator]]:mx-5 [&>[data-slot=separator]]:w-auto',
        className
      )}
      {...props}
    />
  )
}

const settingsRowClassName =
  'min-h-16 gap-5 px-5 py-3.5 [&_[data-slot=field-label]]:text-[13px] [&_[data-slot=field-label]]:font-[630] [&_[data-slot=field-description]]:max-w-[64ch] [&_[data-slot=field-description]]:text-xs [&_[data-slot=field-description]]:leading-[1.5] [&>[data-slot=switch]]:shrink-0 [&>[data-slot=select-trigger]]:shrink-0 max-[680px]:flex-col max-[680px]:items-stretch max-[680px]:gap-3 max-[680px]:[&>[data-slot=switch]]:self-start'

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
        '[&>[data-slot=select-trigger]]:w-[184px] max-[680px]:[&>[data-slot=select-trigger]]:w-full',
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
      className={cn(
        'items-stretch gap-2.5 [&>[data-slot=select-trigger]]:w-full [&>[data-slot=select-trigger]]:max-w-[240px] max-[680px]:[&>[data-slot=select-trigger]]:max-w-none',
        className
      )}
      orientation="vertical"
      {...props}
    />
  )
}

export { SettingsCard, SettingsCardContent, SettingsRow, SettingsSelectRow, SettingsStackedRow }
