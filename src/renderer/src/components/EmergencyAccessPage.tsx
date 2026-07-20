import { CalendarDays, Clock3, RefreshCw, ShieldAlert } from 'lucide-react'
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
import {
  emergencyAccessCreationLabel,
  emergencyAccessDisplayName,
  emergencyAccessInitial,
  emergencyAccessStatusLabel,
  emergencyAccessTypeLabel,
  safeEmergencyAccessAvatarColor
} from './emergency-access-ui'

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
  if (loading) {
    return (
      <div className="flex items-center justify-center gap-2 py-16" role="status">
        <Spinner />
        載入 Emergency Access…
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
          <EmptyTitle>無法載入 Emergency Access</EmptyTitle>
          <EmptyDescription>請檢查網路連線與伺服器狀態後再試一次。</EmptyDescription>
        </EmptyHeader>
        <Button variant="outline" onClick={onRetry}>
          <RefreshCw data-icon="inline-start" aria-hidden="true" />
          重試
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
          <EmptyTitle>尚未設定 Emergency Access</EmptyTitle>
          <EmptyDescription>伺服器沒有回傳授權聯絡人或授權來源。</EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }

  return (
    <div className="grid gap-3">
      {entries.map((entry) => {
        const displayName = emergencyAccessDisplayName(entry)
        const creationLabel = emergencyAccessCreationLabel(entry.creationDate)
        const avatarColor = safeEmergencyAccessAvatarColor(entry.avatarColor)
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
                  {emergencyAccessInitial(entry)}
                </span>
                <div className="min-w-0">
                  <CardTitle className="truncate">{displayName}</CardTitle>
                  {displayName !== entry.email ? (
                    <CardDescription className="truncate">{entry.email}</CardDescription>
                  ) : null}
                </div>
              </div>
              <Badge variant="outline">{entry.role === 'trusted' ? '我授權' : '授權給我'}</Badge>
            </CardHeader>
            <CardContent className="text-muted-foreground flex flex-wrap gap-x-4 gap-y-2 text-sm">
              <span>權限：{emergencyAccessTypeLabel(entry.type)}</span>
              <span>狀態：{emergencyAccessStatusLabel(entry.status)}</span>
              <span className="inline-flex items-center gap-1">
                <Clock3 className="size-3.5" aria-hidden="true" />
                等待 {entry.waitTimeDays} 天
              </span>
              {creationLabel ? (
                <span className="inline-flex items-center gap-1">
                  <CalendarDays className="size-3.5" aria-hidden="true" />
                  建立於 {creationLabel}
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
        toast.error('無法載入 Emergency Access')
      }
    )
    return () => {
      active = false
    }
  }, [loadAttempt])

  function retry(): void {
    setFailed(false)
    setLoading(true)
    setLoadAttempt((attempt) => attempt + 1)
  }

  return (
    <AuxiliaryPageLayout
      title="Emergency Access"
      titleId="emergency-access-title"
      subtitle="目前提供唯讀狀態；邀請、確認、檢視與接管尚未開放。"
    >
      <FeatureUnderConstructionNotice>
        目前僅可檢視 Emergency Access
        的授權關係與狀態；尚不支援邀請、接受、確認、取用或接管授權，以及金鑰輪替。
      </FeatureUnderConstructionNotice>
      <EmergencyAccessContent entries={entries} loading={loading} failed={failed} onRetry={retry} />
    </AuxiliaryPageLayout>
  )
}

export default EmergencyAccessPage
