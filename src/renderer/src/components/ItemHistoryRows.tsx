import type { LoginView } from '../../../shared/vault-contract'
import { useLingui } from '@lingui/react/macro'
import { Button } from '@renderer/components/ui/button'
import { History } from 'lucide-react'
import { formatVaultDate } from '../lib/vault-date'

interface ItemHistoryRowsProps {
  item: Pick<LoginView, 'updatedAt' | 'createdAt' | 'passwordUpdatedAt' | 'passwordHistoryCount'>
  formatDate?: (value: string | null) => string
  onViewPasswordHistory?: () => void
  busy?: boolean
}

function HistoryRow({
  label,
  children
}: {
  label: string
  children: React.ReactNode
}): React.JSX.Element {
  return (
    <div className="border-border grid grid-cols-[minmax(90px,0.28fr)_minmax(0,1fr)] items-center gap-2 border-b py-2.5 last:border-b-0 max-[430px]:grid-cols-1 max-[430px]:items-start max-[430px]:gap-1">
      <dt className="text-muted-foreground text-[11px] leading-4">{label}</dt>
      <dd className="m-0 min-w-0 text-xs leading-4">{children}</dd>
    </div>
  )
}

export function ItemHistoryRows({
  item,
  formatDate = formatVaultDate,
  onViewPasswordHistory,
  busy = false
}: ItemHistoryRowsProps): React.JSX.Element {
  const { t } = useLingui()

  return (
    <dl className="m-0 px-[15px] py-1">
      <HistoryRow label={t`Last edited`}>{formatDate(item.updatedAt)}</HistoryRow>
      <HistoryRow label={t`Created`}>{formatDate(item.createdAt)}</HistoryRow>
      {item.passwordUpdatedAt !== null && (
        <HistoryRow label={t`Password last updated`}>
          {formatDate(item.passwordUpdatedAt)}
        </HistoryRow>
      )}
      {item.passwordHistoryCount > 0 && onViewPasswordHistory && (
        <HistoryRow label={t`Password history`}>
          <div className="flex min-w-0 items-center gap-2">
            <span className="min-w-0 flex-1 truncate">{t`${item.passwordHistoryCount} records`}</span>
            <Button
              variant="ghost"
              size="icon-sm"
              className="-my-1.5 ml-auto"
              type="button"
              aria-label={t`View password history`}
              disabled={busy}
              onClick={onViewPasswordHistory}
            >
              <History aria-hidden="true" />
            </Button>
          </div>
        </HistoryRow>
      )}
    </dl>
  )
}
