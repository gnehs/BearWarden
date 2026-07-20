import {
  AlertTriangle,
  ExternalLink,
  Globe,
  KeyRound,
  LockKeyhole,
  ShieldAlert
} from 'lucide-react'
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
  return (
    <div
      role="status"
      aria-label="正在尋找可自動填入的登入項目"
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
      <span className="sr-only">正在尋找可自動填入的登入項目…</span>
    </div>
  )
}

function PickerFooter({
  onCancel,
  onOpenMain
}: Pick<AutofillPickerProps, 'onCancel' | 'onOpenMain'>): React.JSX.Element {
  return (
    <>
      <Separator />
      <div className="flex items-center justify-between gap-3 px-3 py-2">
        <Button variant="ghost" size="xs" onClick={onOpenMain}>
          開啟 BearWarden
          <ExternalLink data-icon="inline-end" aria-hidden="true" />
        </Button>
        <div className="text-muted-foreground flex items-center gap-3 text-xs">
          <span className="flex items-center gap-1">
            選取 <Kbd>↵</Kbd>
          </span>
          <Button variant="ghost" size="xs" onClick={onCancel}>
            取消 <Kbd>Esc</Kbd>
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
  let content: React.JSX.Element

  if (error) {
    content = (
      <PickerMessage icon={AlertTriangle} title="無法載入登入項目" description={error} alert />
    )
  } else if (permission !== 'granted') {
    content = (
      <PickerMessage
        icon={ShieldAlert}
        title={permission === 'denied' ? '需要輔助使用權限' : '尚未允許輔助使用權限'}
        description="BearWarden 需要這項權限才能辨識目前瀏覽器與網站。請在系統設定中允許後再試一次。"
      />
    )
  } else if (locked) {
    content = (
      <PickerMessage
        icon={LockKeyhole}
        title="密碼庫已鎖定"
        description="請先在 BearWarden 解鎖密碼庫，再回到瀏覽器使用自動填入。"
      />
    )
  } else if (loading) {
    content = <LoadingState />
  } else {
    content = (
      <Command className="rounded-none" aria-label="選擇要自動填入的登入項目">
        <CommandInput autoFocus placeholder="搜尋名稱、帳號或網站…" aria-label="搜尋登入項目" />
        <CommandList className="min-h-56">
          <CommandEmpty>找不到符合的登入項目</CommandEmpty>
          <CommandGroup heading={choices.length > 0 ? `${choices.length} 個相符項目` : '相符項目'}>
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
                      {[choice.username, hostname].filter(Boolean).join(' · ') || '未提供帳號'}
                    </span>
                  </div>
                  {choice.reprompt ? <Badge variant="secondary">需重新驗證</Badge> : null}
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
      aria-label="BearWarden 自動填入"
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
