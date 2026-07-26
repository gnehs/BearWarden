import * as React from 'react'
import { Card, CardContent, CardDescription, CardTitle } from '@renderer/components/ui/card'
import { Field } from '@renderer/components/ui/field'
import { TabsContent } from '@renderer/components/ui/tabs'
import { cn } from '@renderer/lib/utils'
import type { LucideIcon } from 'lucide-react'

function SettingsCard({
  className,
  ...props
}: React.ComponentProps<typeof Card>): React.JSX.Element {
  return (
    <Card
      className={cn(
        'outline-border gap-0 rounded-2xl py-0 shadow-[0_1px_2px_color-mix(in_oklch,var(--shadow-color)_4%,transparent)] outline [--card-spacing:--spacing(5)] [&_[data-slot=card-description]]:mt-0.5 [&_[data-slot=card-description]]:text-xs [&_[data-slot=card-description]]:leading-normal [&_[data-slot=card-footer]]:justify-end [&_[data-slot=card-title]]:scroll-mt-5 [&_[data-slot=card-title]]:text-sm [&_[data-slot=card-title]]:font-semibold [&_[data-slot=field-description]]:max-w-[64ch] [&_[data-slot=field-description]]:text-xs [&_[data-slot=field-description]]:leading-normal [&_[data-slot=field-label]]:text-sm [&_[data-slot=field-label]]:font-semibold [&>[data-slot=card-header]]:items-center [&>[data-slot=card-header]]:py-(--card-spacing)',
        className
      )}
      {...props}
    />
  )
}

function SettingsCardContent({
  flush = false,
  className,
  ...props
}: React.ComponentProps<typeof CardContent> & { flush?: boolean }): React.JSX.Element {
  return (
    <CardContent
      className={cn(
        !flush && 'pb-(--card-spacing)',
        flush &&
          'px-0 [&>[data-slot=separator]]:mx-(--card-spacing) [&>[data-slot=separator]]:w-auto',
        className
      )}
      {...props}
    />
  )
}

const settingsRowClassName =
  'min-h-16 gap-5 px-(--card-spacing) py-3.5 [&>[data-slot=switch]]:shrink-0 [&>[data-slot=select-trigger]]:shrink-0 max-[680px]:flex-col max-[680px]:items-stretch max-[680px]:gap-3 max-[680px]:[&>[data-slot=switch]]:self-start'

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

interface SettingsCardHeadingProps {
  id: string
  icon: LucideIcon
  title: string
  description: React.ReactNode
}

function SettingsCardHeading({
  id,
  icon: Icon,
  title,
  description
}: SettingsCardHeadingProps): React.JSX.Element {
  return (
    <div className="flex min-w-0 items-center gap-3">
      <span
        className="text-primary grid size-9 shrink-0 place-items-center rounded-xl bg-[var(--accent-soft)] [&>svg]:size-4"
        aria-hidden="true"
      >
        <Icon />
      </span>
      <div className="min-w-0">
        <CardTitle id={id} role="heading" aria-level={2}>
          {title}
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </div>
    </div>
  )
}

function SettingsCategoryContent({
  className,
  ...props
}: React.ComponentProps<typeof TabsContent>): React.JSX.Element {
  return <TabsContent className={cn('grid min-w-0 gap-4', className)} {...props} />
}

export {
  SettingsCard,
  SettingsCardContent,
  SettingsCardHeading,
  SettingsCategoryContent,
  SettingsRow,
  SettingsSelectRow,
  SettingsStackedRow
}
