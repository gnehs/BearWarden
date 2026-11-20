import { useLingui } from '@lingui/react/macro'
import { X } from 'lucide-react'
import type { PolicyBannerView } from '../../../shared/vault-contract'
import { usePolicyBanner } from '@renderer/hooks/use-policy-banner'
import { Alert, AlertAction, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import { Button } from '@renderer/components/ui/button'
import { cn } from '@renderer/lib/utils'

interface PolicyBannerNoticeProps {
  banner: PolicyBannerView
  onDismiss: () => void
  className?: string
}

/**
 * Organization-authored notice. The text is untrusted server content, so it is rendered only as
 * React text children, never as HTML, Markdown or a link. As in the official clients, a banner
 * with a header and a button label is acknowledged through that button; every other banner
 * offers a close control.
 */
export function PolicyBannerNotice({
  banner,
  onDismiss,
  className
}: PolicyBannerNoticeProps): React.JSX.Element {
  const { t } = useLingui()
  const acknowledgeLabel = banner.header !== null ? banner.buttonText : null

  return (
    <Alert role="status" className={cn('shrink-0', className)}>
      {banner.header !== null && <AlertTitle>{banner.header}</AlertTitle>}
      <AlertDescription className="text-foreground">{banner.description}</AlertDescription>
      {acknowledgeLabel !== null ? (
        <Button size="sm" className="mt-2 w-fit" onClick={onDismiss}>
          {acknowledgeLabel}
        </Button>
      ) : (
        <AlertAction>
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label={t({
              message: 'Dismiss organization message',
              comment:
                'Accessible label of the close button on the message banner an organization administrator shows at the top of the vault.'
            })}
            onClick={onDismiss}
          >
            <X aria-hidden="true" className="text-muted-foreground" />
          </Button>
        </AlertAction>
      )}
    </Alert>
  )
}

export default function PolicyBanner({
  className
}: {
  className?: string
}): React.JSX.Element | null {
  const { banner, dismiss } = usePolicyBanner()
  if (banner === null) return null
  return <PolicyBannerNotice banner={banner} onDismiss={dismiss} className={className} />
}
