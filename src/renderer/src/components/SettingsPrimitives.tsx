import * as React from 'react'
import { Card, CardContent, CardDescription, CardTitle } from '@renderer/components/ui/card'
import { Field } from '@renderer/components/ui/field'
import { TabsContent } from '@renderer/components/ui/tabs'
import { cn } from '@renderer/lib/utils'
import type { LucideIcon } from 'lucide-react'

function SettingsCard({
  className,
  tone = 'brand',
  ...props
}: Omit<React.ComponentProps<typeof Card>, 'variant'>): React.JSX.Element {
  return (
    <Card
      variant="folder"
      tone={tone}
      className={cn(
        'gap-0 py-0 [--card-spacing:--spacing(5)] [&_[data-slot=card-description]]:mt-0.5 [&_[data-slot=card-description]]:text-xs [&_[data-slot=card-description]]:leading-normal [&_[data-slot=card-footer]]:justify-end [&_[data-slot=card-title]]:scroll-mt-14 [&_[data-slot=field-description]]:max-w-[64ch] [&_[data-slot=field-description]]:text-xs [&_[data-slot=field-description]]:leading-normal [&_[data-slot=field-label]]:text-sm [&_[data-slot=field-label]]:font-semibold [&>[data-slot=card-header]]:items-center [&>[data-slot=card-header]]:pt-(--card-spacing) [&>[data-slot=card-header]]:pb-1',
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
    <>
      <CardTitle id={id} role="heading" aria-level={2}>
        <Icon aria-hidden="true" />
        {title}
      </CardTitle>
      <CardDescription>{description}</CardDescription>
    </>
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
