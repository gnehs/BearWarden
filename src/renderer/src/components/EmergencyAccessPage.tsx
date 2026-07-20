import { CalendarDays, Clock3, RefreshCw, ShieldAlert } from 'lucide-react'
import { plural } from '@lingui/core/macro'
import { Trans, useLingui } from '@lingui/react/macro'
import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import type { EmergencyAccessView } from '../../../shared/vault-contract'
import { Badge } from '@renderer/components/ui/badge'
import { Button } from '@renderer/components/ui/button'
import { cn } from '@renderer/lib/utils'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle
} from '@renderer/components/ui/card'
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle
} from '@renderer/components/ui/empty'
import { Spinner } from '@renderer/components/ui/spinner'
import AuxiliaryPageLayout from './AuxiliaryPageLayout'
import FeatureUnderConstructionNotice from './FeatureUnderConstructionNotice'
import { emergencyAccessDisplayName, safeEmergencyAccessAvatarColor } from './emergency-access-ui'

interface EmergencyAccessContentProps {
  entries: EmergencyAccessView[]
  loading: boolean
  failed: boolean
  onRetry: () => void
}

export function EmergencyAccessContent({
  entries,
  loading,
  failed,
  onRetry
}: EmergencyAccessContentProps): React.JSX.Element {
  const { i18n, t } = useLingui()
  if (loading) {
    return (
      <div className="flex items-center justify-center gap-2 py-16" role="status">
        <Spinner />
        <Trans>Loading Emergency Access…</Trans>
      </div>
    )
  }

  if (failed) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <ShieldAlert />
          </EmptyMedia>
          <EmptyTitle>
            <Trans>Could not load Emergency Access</Trans>
          </EmptyTitle>
          <EmptyDescription>
            <Trans>Check the network connection and server status, then try again.</Trans>
          </EmptyDescription>
        </EmptyHeader>
        <Button variant="outline" onClick={onRetry}>
          <RefreshCw data-icon="inline-start" aria-hidden="true" />
          <Trans>Try again</Trans>
        </Button>
      </Empty>
    )
  }

  if (entries.length === 0) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <ShieldAlert />
          </EmptyMedia>
          <EmptyTitle>
            <Trans>Emergency Access is not configured</Trans>
          </EmptyTitle>
          <EmptyDescription>
            <Trans>The server did not return any trusted contacts or grantors.</Trans>
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }

  return (
    <div className="grid gap-3">
      {entries.map((entry) => {
        const displayName = emergencyAccessDisplayName(entry)
        const initial = Array.from(displayName)[0]?.toLocaleUpperCase(i18n.locale) ?? '?'
        const creationDate = entry.creationDate ? new Date(entry.creationDate) : null
        const creationLabel =
          creationDate && Number.isFinite(creationDate.getTime())
            ? new Intl.DateTimeFormat(i18n.locale, {
                dateStyle: 'medium',
                timeStyle: 'short'
              }).format(creationDate)
            : null
        const avatarColor = safeEmergencyAccessAvatarColor(entry.avatarColor)
        const waitTimeLabel = t({
          message: plural(entry.waitTimeDays, { one: 'Wait # day', other: 'Wait # days' })
        })
        return (
          <Card key={`${entry.role}:${entry.id}`}>
            <CardHeader className="flex-row items-start justify-between gap-4">
              <div className="flex min-w-0 items-center gap-3">
                <span
                  className={cn(
                    'flex size-9 shrink-0 items-center justify-center rounded-full text-sm font-semibold',
                    avatarColor ? 'text-white' : 'bg-muted text-muted-foreground'
                  )}
                  style={{ backgroundColor: avatarColor }}
                  aria-hidden="true"
                >
                  {initial}
                </span>
                <div className="min-w-0">
                  <CardTitle className="truncate">{displayName}</CardTitle>
                  {displayName !== entry.email ? (
                    <CardDescription className="truncate">{entry.email}</CardDescription>
                  ) : null}
                </div>
              </div>
              <Badge variant="outline">
                {entry.role === 'trusted' ? (
                  <Trans>Granted by me</Trans>
                ) : (
                  <Trans>Granted to me</Trans>
                )}
              </Badge>
            </CardHeader>
            <CardContent className="text-muted-foreground flex flex-wrap gap-x-4 gap-y-2 text-sm">
              <span>
                <Trans>Permission:</Trans>{' '}
                {entry.type === 0 ? (
                  <Trans>View</Trans>
                ) : entry.type === 1 ? (
                  <Trans>Takeover</Trans>
                ) : (
                  <Trans>Unknown type ({entry.type})</Trans>
                )}
              </span>
              <span>
                <Trans>Status:</Trans>{' '}
                {entry.status === 0 ? (
                  <Trans>Invited</Trans>
                ) : entry.status === 1 ? (
                  <Trans>Invitation accepted</Trans>
                ) : entry.status === 2 ? (
                  <Trans>Confirmed</Trans>
                ) : entry.status === 3 ? (
                  <Trans>Access requested</Trans>
                ) : (
                  <Trans>Access approved</Trans>
                )}
              </span>
              <span className="inline-flex items-center gap-1">
                <Clock3 className="size-3.5" aria-hidden="true" />
                {waitTimeLabel}
              </span>
              {creationLabel ? (
                <span className="inline-flex items-center gap-1">
                  <CalendarDays className="size-3.5" aria-hidden="true" />
                  <Trans>Created {creationLabel}</Trans>
                </span>
              ) : null}
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}

function EmergencyAccessPage(): React.JSX.Element {
  const { t } = useLingui()
  const [entries, setEntries] = useState<EmergencyAccessView[]>([])
  const [loading, setLoading] = useState(true)
  const [failed, setFailed] = useState(false)
  const [loadAttempt, setLoadAttempt] = useState(0)

  useEffect(() => {
    let active = true
    void window.bearwarden.emergencyAccess.list().then(
      (value) => {
        if (!active) return
        setEntries(value)
        setFailed(false)
        setLoading(false)
      },
      () => {
        if (!active) return
        setFailed(true)
        setLoading(false)
        toast.error(t`Could not load Emergency Access`)
      }
    )
    return () => {
      active = false
    }
  }, [loadAttempt, t])

  function retry(): void {
    setFailed(false)
    setLoading(true)
    setLoadAttempt((attempt) => attempt + 1)
  }

  return (
    <AuxiliaryPageLayout
      title={t`Emergency Access`}
      titleId="emergency-access-title"
      subtitle={t`Currently read-only. Inviting, confirming, viewing, and taking over are not available yet.`}
    >
      <FeatureUnderConstructionNotice>
        <Trans>
          Currently you can only view Emergency Access grants and statuses. Inviting, accepting,
          confirming, accessing, taking over grants, and key rotation are not supported yet.
        </Trans>
      </FeatureUnderConstructionNotice>
      <EmergencyAccessContent entries={entries} loading={loading} failed={failed} onRetry={retry} />
    </AuxiliaryPageLayout>
  )
}

export default EmergencyAccessPage
