import { ContactRound, CreditCard, FileKey2, Folder, Globe2, NotebookPen } from 'lucide-react'
import type { FolderView, LoginSummary } from '../../../shared/vault-contract'
import { Badge } from '@renderer/components/ui/badge'
import { normalizeBitwardenCardBrand } from '../lib/payment-card'
import PaymentCardBrandMark from './PaymentCardBrandMark'
import WebsiteIcon from './WebsiteIcon'

interface ItemDragPreviewProps {
  item: LoginSummary
  count: number
  showWebsiteIcons: boolean
  destinationDescription?: string | null
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
  showWebsiteIcons,
  destinationDescription
}: ItemDragPreviewProps): React.JSX.Element {
  const meta = itemTypeMeta[item.type]
  const ItemIcon = meta.icon

  return (
    <div
      className="bg-popover/95 text-foreground grid min-h-14 w-full max-w-[calc(100vw-24px)] grid-cols-[36px_minmax(0,1fr)_auto] items-center gap-2.5 rounded-xl border px-2.5 py-2 shadow-lg backdrop-blur-md forced-colors:outline-2 forced-colors:outline-[CanvasText]"
      aria-hidden
    >
      <span className="bg-muted text-primary outline-foreground/5 grid size-9 shrink-0 place-items-center overflow-hidden rounded-md shadow-(--control-highlight) outline">
        {item.type === 'card' ? (
          <PaymentCardBrandMark brand={normalizeBitwardenCardBrand(item.cardBrand)} compact />
        ) : item.type === 'login' ? (
          <WebsiteIcon id={item.id} uri={item.uri} enabled={showWebsiteIcons} />
        ) : (
          <ItemIcon />
        )}
      </span>
      <span className="grid min-w-0 gap-0.5">
        <strong className="truncate text-sm font-semibold">{item.name}</strong>
        <small className="text-muted-foreground truncate text-xs">
          {destinationDescription ??
            (count > 1 ? `與其他 ${count - 1} 個項目一起移動` : `${meta.label} · 拖曳以移動`)}
        </small>
      </span>
      {count > 1 && <Badge variant="secondary">{count}</Badge>}
    </div>
  )
}

export function FolderDragPreview({ folder, count }: FolderDragPreviewProps): React.JSX.Element {
  return (
    <div
      className="bg-popover/95 text-foreground grid min-h-14 w-64 max-w-[calc(100vw-24px)] grid-cols-[36px_minmax(0,1fr)] items-center gap-2.5 rounded-xl border px-2.5 py-2 shadow-lg backdrop-blur-md forced-colors:outline-2 forced-colors:outline-[CanvasText]"
      aria-hidden
    >
      <span className="bg-accent text-primary grid size-9 place-items-center rounded-lg border">
        <Folder />
      </span>
      <span className="grid min-w-0 gap-0.5">
        <strong className="truncate text-sm font-semibold">{folder.name}</strong>
        <small className="text-muted-foreground truncate text-xs">重新排列 · {count} 個項目</small>
      </span>
    </div>
  )
}
