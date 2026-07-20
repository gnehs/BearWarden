import {
  AlertTriangle,
  ExternalLink,
  Globe,
  KeyRound,
  LockKeyhole,
  ShieldAlert
} from 'lucide-react'
import { useLingui } from '@lingui/react/macro'
import { Badge } from '@renderer/components/ui/badge'
import { Button } from '@renderer/components/ui/button'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList
} from '@renderer/components/ui/command'
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle
} from '@renderer/components/ui/empty'
import { Kbd } from '@renderer/components/ui/kbd'
import { Separator } from '@renderer/components/ui/separator'
import { Skeleton } from '@renderer/components/ui/skeleton'
import {
  autofillPickerHostname,
  autofillPickerSearchValue,
  type AutofillPickerChoice
} from './autofill-picker-ui'

export type AutofillPickerPermission = 'granted' | 'not-determined' | 'denied'

export interface AutofillPickerProps {
  requestId: string
  choices: readonly AutofillPickerChoice[]
  loading?: boolean
  error?: string | null
  locked?: boolean
  permission?: AutofillPickerPermission
  onSelect: (id: string) => void
  onCancel: () => void
  onOpenMain: () => void
}

interface PickerMessageProps {
  icon: typeof LockKeyhole
  title: string
  description: string
  alert?: boolean
}

function PickerMessage({
  icon: Icon,
  title,
  description,
  alert = false
}: PickerMessageProps): React.JSX.Element {
  return (
    <Empty role={alert ? 'alert' : 'status'} className="min-h-64 border-0">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <Icon aria-hidden="true" />
        </EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        <EmptyDescription>{description}</EmptyDescription>
      </EmptyHeader>
    </Empty>
  )
}

function LoadingState(): React.JSX.Element {
  const { t } = useLingui()

  return (
    <div
      role="status"
      aria-label={t`Finding logins to autofill`}
      className="flex min-h-64 flex-col gap-3 p-4"
    >
      <div className="flex items-center gap-3">
        <Skeleton className="size-8" />
        <div className="flex flex-1 flex-col gap-2">
          <Skeleton className="h-3 w-2/5" />
          <Skeleton className="h-3 w-3/5" />
        </div>
      </div>
      <div className="flex items-center gap-3">
        <Skeleton className="size-8" />
        <div className="flex flex-1 flex-col gap-2">
          <Skeleton className="h-3 w-1/3" />
          <Skeleton className="h-3 w-1/2" />
        </div>
      </div>
      <span className="sr-only">{t`Finding logins to autofill…`}</span>
    </div>
  )
}

function PickerFooter({
  onCancel,
  onOpenMain
}: Pick<AutofillPickerProps, 'onCancel' | 'onOpenMain'>): React.JSX.Element {
  const { t } = useLingui()

  return (
    <>
      <Separator />
      <div className="flex items-center justify-between gap-3 px-3 py-2">
        <Button variant="ghost" size="xs" onClick={onOpenMain}>
          {t`Open BearWarden`}
          <ExternalLink data-icon="inline-end" aria-hidden="true" />
        </Button>
        <div className="text-muted-foreground flex items-center gap-3 text-xs">
          <span className="flex items-center gap-1">
            {t`Select`} <Kbd>↵</Kbd>
          </span>
          <Button variant="ghost" size="xs" onClick={onCancel}>
            {t`Cancel`} <Kbd>Esc</Kbd>
          </Button>
        </div>
      </div>
    </>
  )
}

export default function AutofillPicker({
  requestId,
  choices,
  loading = false,
  error = null,
  locked = false,
  permission = 'granted',
  onSelect,
  onCancel,
  onOpenMain
}: AutofillPickerProps): React.JSX.Element {
  const { t } = useLingui()
  let content: React.JSX.Element

  if (error) {
    content = (
      <PickerMessage
        icon={AlertTriangle}
        title={t`Unable to load logins`}
        description={error}
        alert
      />
    )
  } else if (permission !== 'granted') {
    content = (
      <PickerMessage
        icon={ShieldAlert}
        title={
          permission === 'denied'
            ? t`Accessibility permission required`
            : t`Accessibility permission not granted`
        }
        description={t`BearWarden needs this permission to identify the current browser and website. Allow it in System Settings, then try again.`}
      />
    )
  } else if (locked) {
    content = (
      <PickerMessage
        icon={LockKeyhole}
        title={t`Vault locked`}
        description={t`Unlock your vault in BearWarden, then return to the browser to use autofill.`}
      />
    )
  } else if (loading) {
    content = <LoadingState />
  } else {
    content = (
      <Command className="rounded-none" aria-label={t`Choose a login to autofill`}>
        <CommandInput
          autoFocus
          placeholder={t`Search by name, username, or website…`}
          aria-label={t`Search logins`}
        />
        <CommandList className="min-h-56">
          <CommandEmpty>{t`No matching logins found`}</CommandEmpty>
          <CommandGroup heading={choices.length > 0 ? t`${choices.length} matches` : t`Matches`}>
            {choices.map((choice) => {
              const hostname = autofillPickerHostname(choice)
              return (
                <CommandItem
                  key={choice.id}
                  value={autofillPickerSearchValue(choice)}
                  onSelect={() => onSelect(choice.id)}
                  className="min-h-12"
                >
                  <div className="bg-muted flex size-8 shrink-0 items-center justify-center rounded-lg">
                    {hostname ? <Globe aria-hidden="true" /> : <KeyRound aria-hidden="true" />}
                  </div>
                  <div className="flex min-w-0 flex-1 flex-col">
                    <span className="truncate font-medium">{choice.name}</span>
                    <span className="text-muted-foreground truncate text-xs">
                      {[choice.username, hostname].filter(Boolean).join(' · ') ||
                        t`No username provided`}
                    </span>
                  </div>
                  {choice.reprompt ? (
                    <Badge variant="secondary">{t`Reauthentication required`}</Badge>
                  ) : null}
                </CommandItem>
              )
            })}
          </CommandGroup>
        </CommandList>
      </Command>
    )
  }

  return (
    <section
      data-request-id={requestId}
      aria-label={t`BearWarden autofill`}
      className="bg-popover text-popover-foreground overflow-hidden rounded-xl border shadow-lg"
      onKeyDown={(event) => {
        if (event.key !== 'Escape') return
        event.preventDefault()
        onCancel()
      }}
    >
      {content}
      <PickerFooter onCancel={onCancel} onOpenMain={onOpenMain} />
    </section>
  )
}

export type { AutofillPickerChoice }
