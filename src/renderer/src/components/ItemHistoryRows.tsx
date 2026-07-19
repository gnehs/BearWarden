import type { LoginView } from '../../../shared/vault-contract'
import { formatVaultDate } from '../lib/vault-date'

interface ItemHistoryRowsProps {
  item: Pick<LoginView, 'updatedAt' | 'createdAt' | 'passwordUpdatedAt'>
  formatDate?: (value: string | null) => string
}

function HistoryRow({ label, value }: { label: string; value: string }): React.JSX.Element {
  return (
    <div className="border-border grid grid-cols-[minmax(90px,0.28fr)_1fr] border-b py-2.5 last:border-b-0 max-[430px]:grid-cols-1 max-[430px]:gap-1">
      <dt className="text-muted-foreground text-[11px]">{label}</dt>
      <dd className="m-0 text-[11px]">{value}</dd>
    </div>
  )
}

export function ItemHistoryRows({
  item,
  formatDate = formatVaultDate
}: ItemHistoryRowsProps): React.JSX.Element {
  return (
    <dl className="m-0 px-[15px] py-1">
      <HistoryRow label="最後編輯紀錄" value={formatDate(item.updatedAt)} />
      <HistoryRow label="建立於" value={formatDate(item.createdAt)} />
      {item.passwordUpdatedAt !== null && (
        <HistoryRow label="密碼最後更新" value={formatDate(item.passwordUpdatedAt)} />
      )}
    </dl>
  )
}
