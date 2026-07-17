import type { LoginView } from '../../../shared/vault-contract'
import { formatVaultDate } from '../lib/vault-date'

interface ItemHistoryRowsProps {
  item: Pick<LoginView, 'updatedAt' | 'createdAt' | 'passwordUpdatedAt'>
  formatDate?: (value: string | null) => string
}

export function ItemHistoryRows({
  item,
  formatDate = formatVaultDate
}: ItemHistoryRowsProps): React.JSX.Element {
  return (
    <dl>
      <div>
        <dt>最後編輯紀錄</dt>
        <dd>{formatDate(item.updatedAt)}</dd>
      </div>
      <div>
        <dt>建立於</dt>
        <dd>{formatDate(item.createdAt)}</dd>
      </div>
      {item.passwordUpdatedAt !== null && (
        <div>
          <dt>密碼最後更新</dt>
          <dd>{formatDate(item.passwordUpdatedAt)}</dd>
        </div>
      )}
    </dl>
  )
}
