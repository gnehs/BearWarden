import { ContactRound, CreditCard, FileKey2, Folder, Globe2, NotebookPen } from 'lucide-react'
import type { FolderView, LoginSummary } from '../../../shared/vault-contract'
import { Badge } from '@renderer/components/ui/badge'
import { cn } from '@renderer/lib/utils'
import { normalizeBitwardenCardBrand } from '../lib/payment-card'
import PaymentCardBrandMark from './PaymentCardBrandMark'
import WebsiteIcon from './WebsiteIcon'

interface ItemDragPreviewProps {
  item: LoginSummary
  count: number
  showWebsiteIcons: boolean
}

interface FolderDragPreviewProps {
  folder: FolderView
  count: number
}

const itemTypeMeta = {
  login: { label: '登入', icon: Globe2 },
  card: { label: '卡片', icon: CreditCard },
  identity: { label: '身分資料', icon: ContactRound },
  secureNote: { label: '安全備註', icon: NotebookPen },
  sshKey: { label: 'SSH 金鑰', icon: FileKey2 }
} as const

export function ItemDragPreview({
  item,
  count,
  showWebsiteIcons
}: ItemDragPreviewProps): React.JSX.Element {
  const meta = itemTypeMeta[item.type]
  const ItemIcon = meta.icon

  return (
    <div className={cn('drag-overlay item-drag-preview', count > 1 && 'multiple')} aria-hidden>
      <span className={cn('item-icon drag-preview-icon', item.type)}>
        {item.type === 'card' ? (
          <PaymentCardBrandMark brand={normalizeBitwardenCardBrand(item.cardBrand)} compact />
        ) : item.type === 'login' ? (
          <WebsiteIcon id={item.id} uri={item.uri} enabled={showWebsiteIcons} />
        ) : (
          <ItemIcon />
        )}
      </span>
      <span className="drag-preview-copy">
        <strong>{item.name}</strong>
        <small>
          {count > 1 ? `與其他 ${count - 1} 個項目一起移動` : `${meta.label} · 拖曳至資料夾`}
        </small>
      </span>
      {count > 1 && <Badge variant="secondary">{count}</Badge>}
    </div>
  )
}

export function FolderDragPreview({ folder, count }: FolderDragPreviewProps): React.JSX.Element {
  return (
    <div className="drag-overlay folder-drag-preview" aria-hidden>
      <span className="drag-preview-icon folder">
        <Folder />
      </span>
      <span className="drag-preview-copy">
        <strong>{folder.name}</strong>
        <small>重新排列 · {count} 個項目</small>
      </span>
    </div>
  )
}
