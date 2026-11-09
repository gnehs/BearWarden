import type { LoginView } from '../../../shared/vault-contract'
import { useLingui } from '@lingui/react/macro'
import { Button } from '@renderer/components/ui/button'
import { History } from 'lucide-react'
import { formatVaultDate } from '../lib/vault-date'
import { DetailMetaRow, DetailRowGroup } from './VaultDetailSurface'

interface ItemHistoryRowsProps {
  item: Pick<LoginView, 'updatedAt' | 'createdAt' | 'passwordUpdatedAt' | 'passwordHistoryCount'>
  formatDate?: (value: string | null) => string
  onViewPasswordHistory?: () => void
  busy?: boolean
}

export function ItemHistoryRows({
  item,
  formatDate = formatVaultDate,
  onViewPasswordHistory,
  busy = false
}: ItemHistoryRowsProps): React.JSX.Element {
  const { t } = useLingui()

  return (
    <DetailRowGroup as="dl">
      <DetailMetaRow
        label={t({
          message: 'Last edited',
          comment: 'Metadata label showing when this vault item was last modified.'
        })}
      >
        {formatDate(item.updatedAt)}
      </DetailMetaRow>
      <DetailMetaRow
        label={t({
          message: 'Created',
          context: 'item-created',
          comment: 'Metadata label showing when this vault item was first created.'
        })}
      >
        {formatDate(item.createdAt)}
      </DetailMetaRow>
      {item.passwordUpdatedAt !== null && (
        <DetailMetaRow
          label={t({
            message: 'Password last updated',
            comment: 'Metadata label showing when the password in this login item was last changed.'
          })}
        >
          {formatDate(item.passwordUpdatedAt)}
        </DetailMetaRow>
      )}
      {item.passwordHistoryCount > 0 && onViewPasswordHistory && (
        <DetailMetaRow label={t`Password history`}>
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
        </DetailMetaRow>
      )}
    </DetailRowGroup>
  )
}
