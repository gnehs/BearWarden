import { ContactRound, CreditCard, FileKey2, Globe2, NotebookPen } from 'lucide-react'
import { useLingui } from '@lingui/react/macro'
import type { LoginSummary } from '../../../shared/vault-contract'
import { Badge } from '@renderer/components/ui/badge'
import { cn } from '@renderer/lib/utils'
import { normalizeBitwardenCardBrand } from '../lib/payment-card'
import PaymentCardBrandMark from './PaymentCardBrandMark'
import WebsiteIcon from './WebsiteIcon'

interface ItemDragPreviewProps {
  item: LoginSummary
  count: number
  showWebsiteIcons: boolean
  destinationDescription?: string | null
}

const itemTypeMeta = {
  login: { icon: Globe2 },
  card: { icon: CreditCard },
  identity: { icon: ContactRound },
  secureNote: { icon: NotebookPen },
  sshKey: { icon: FileKey2 }
} as const

export function ItemDragPreview({
  item,
  count,
  showWebsiteIcons,
  destinationDescription
}: ItemDragPreviewProps): React.JSX.Element {
  const { t } = useLingui()
  const meta = itemTypeMeta[item.type]
  const ItemIcon = meta.icon
  const itemTypeLabel = {
    login: t`Login`,
    card: t`Card`,
    identity: t`Identity`,
    secureNote: t`Secure note`,
    sshKey: t`SSH key`
  }[item.type]
  const stackDepth = Math.min(Math.max(count - 1, 0), 2)

  return (
    <div className="relative w-full max-w-[calc(100vw-24px)]" aria-hidden>
      {Array.from({ length: stackDepth }, (_, index) => {
        const depth = stackDepth - index
        return (
          <span
            key={depth}
            data-drag-preview-layer={depth}
            className={cn(
              'absolute inset-0 rounded-xl border shadow-sm',
              depth === 2
                ? 'bg-popover/65 translate-x-2 translate-y-2 rotate-2 opacity-70'
                : 'bg-popover/80 translate-x-1 translate-y-1 rotate-1 opacity-85'
            )}
          />
        )
      })}
      <div className="bg-popover/95 text-foreground relative grid min-h-14 w-full grid-cols-[36px_minmax(0,1fr)_auto] items-center gap-2.5 rounded-xl border px-2.5 py-2 shadow-lg backdrop-blur-md forced-colors:outline-2 forced-colors:outline-[CanvasText]">
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
              (count > 1
                ? t`Moving with ${count - 1} other items`
                : t`${itemTypeLabel} · Drag to move`)}
          </small>
        </span>
        {count > 1 && <Badge variant="secondary">{count}</Badge>}
      </div>
    </div>
  )
}
