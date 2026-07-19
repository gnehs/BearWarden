import { Clock3, ShieldAlert, UserRound } from 'lucide-react'
import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import type { EmergencyAccessView } from '../../../shared/vault-contract'
import { Badge } from '@renderer/components/ui/badge'
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

function statusLabel(status: number): string {
  return (
    {
      0: '已邀請',
      1: '已接受',
      2: '已確認',
      3: '恢復請求中',
      4: '已核准',
      5: '已拒絕',
      6: '已撤銷'
    }[status] ?? `狀態 ${status}`
  )
}

function typeLabel(type: number): string {
  return type === 0 ? '檢視' : type === 1 ? '接管' : `類型 ${type}`
}

function EmergencyAccessPage(): React.JSX.Element {
  const [entries, setEntries] = useState<EmergencyAccessView[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    void window.bearwarden.emergencyAccess.list().then(
      (value) => {
        if (!active) return
        setEntries(value)
        setLoading(false)
      },
      () => {
        if (!active) return
        setLoading(false)
        toast.error('無法載入 Emergency Access')
      }
    )
    return () => {
      active = false
    }
  }, [])

  return (
    <AuxiliaryPageLayout
      eyebrow="Bitwarden Emergency Access"
      title="Emergency Access"
      titleId="emergency-access-title"
      subtitle="目前提供唯讀狀態；邀請、確認、檢視與接管尚未開放。"
    >
      <FeatureUnderConstructionNotice>
        目前僅可檢視 Emergency Access
        的授權關係與狀態；尚不支援邀請、接受、確認、取用或接管授權，以及金鑰輪替。
      </FeatureUnderConstructionNotice>
      {loading ? (
        <div className="flex items-center justify-center gap-2 py-16" role="status">
          <Spinner />
          載入 Emergency Access…
        </div>
      ) : entries.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <ShieldAlert />
            </EmptyMedia>
            <EmptyTitle>尚未設定 Emergency Access</EmptyTitle>
            <EmptyDescription>伺服器沒有回傳授權聯絡人或授權來源。</EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <div className="grid gap-3">
          {entries.map((entry) => (
            <Card key={`${entry.role}:${entry.id}`}>
              <CardHeader className="flex-row items-start justify-between gap-4">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <UserRound className="size-4" aria-hidden="true" />
                    {entry.name}
                  </CardTitle>
                  <CardDescription>{entry.email}</CardDescription>
                </div>
                <Badge variant="outline">{entry.role === 'trusted' ? '我授權' : '授權給我'}</Badge>
              </CardHeader>
              <CardContent className="text-muted-foreground flex flex-wrap gap-2 text-sm">
                <span>{typeLabel(entry.type)}</span>
                <span>{statusLabel(entry.status)}</span>
                <span className="inline-flex items-center gap-1">
                  <Clock3 className="size-3.5" aria-hidden="true" />
                  等待 {entry.waitTimeDays} 天
                </span>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </AuxiliaryPageLayout>
  )
}

export default EmergencyAccessPage
