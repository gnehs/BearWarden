import type { LoginView } from '../../../shared/vault-contract'
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
  return (
    <dl className="m-0 px-[15px] py-1">
      <HistoryRow label="最後編輯紀錄">{formatDate(item.updatedAt)}</HistoryRow>
      <HistoryRow label="建立於">{formatDate(item.createdAt)}</HistoryRow>
      {item.passwordUpdatedAt !== null && (
        <HistoryRow label="密碼最後更新">{formatDate(item.passwordUpdatedAt)}</HistoryRow>
      )}
      {item.passwordHistoryCount > 0 && onViewPasswordHistory && (
        <HistoryRow label="密碼歷史">
          <div className="flex min-w-0 items-center gap-2">
            <span className="min-w-0 flex-1 truncate">{item.passwordHistoryCount} 筆紀錄</span>
            <Button
              variant="ghost"
              size="icon-sm"
              className="-my-1.5 ml-auto"
              type="button"
              aria-label="查看密碼歷史"
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
