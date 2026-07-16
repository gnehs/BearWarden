import { AlertTriangle, ArrowLeft, CheckCircle2, RefreshCw, ShieldCheck } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import type {
  VaultHealthReport,
  VaultHealthReusedFinding,
  VaultHealthWeakFinding
} from '../../../shared/vault-contract'
import { Alert, AlertAction, AlertDescription, AlertTitle } from './ui/alert'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from './ui/empty'
import { Spinner } from './ui/spinner'
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs'
import { weakPasswordLabel } from '../lib/vault-health-ui'

type HealthTab = 'reused' | 'weak'

interface VaultHealthPageProps {
  revision: string
  onBack: () => void
  onOpenItem: (id: string) => void
}

function HealthLoading(): React.JSX.Element {
  return (
    <Empty className="min-h-72" aria-live="polite">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <Spinner />
        </EmptyMedia>
        <EmptyTitle>正在本機分析保管庫</EmptyTitle>
        <EmptyDescription>密碼只會留在主程序，不會傳到畫面程序或外部服務。</EmptyDescription>
      </EmptyHeader>
    </Empty>
  )
}

function HealthEmpty({ kind }: { kind: HealthTab }): React.JSX.Element {
  return (
    <Empty className="min-h-56">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <CheckCircle2 />
        </EmptyMedia>
        <EmptyTitle>{kind === 'reused' ? '沒有重複使用的密碼' : '沒有弱密碼'}</EmptyTitle>
        <EmptyDescription>
          {kind === 'reused'
            ? '目前分析到的登入項目沒有共用相同密碼。'
            : '目前分析到的登入項目都高於弱密碼門檻。'}
        </EmptyDescription>
      </EmptyHeader>
    </Empty>
  )
}

function ReusedFindingCard({
  finding,
  onOpenItem
}: {
  finding: VaultHealthReusedFinding
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle>{finding.name}</CardTitle>
        <CardDescription>{finding.subtitle || '登入項目'}</CardDescription>
        <CardAction className="flex items-center gap-2">
          <Badge variant="destructive">重複 {finding.reuseCount} 次</Badge>
          <Button
            variant="outline"
            size="sm"
            type="button"
            aria-label={`查看${finding.name}`}
            onClick={() => onOpenItem(finding.id)}
          >
            查看
          </Button>
        </CardAction>
      </CardHeader>
    </Card>
  )
}

function WeakFindingCard({
  finding,
  onOpenItem
}: {
  finding: VaultHealthWeakFinding
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle>{finding.name}</CardTitle>
        <CardDescription>{finding.subtitle || '登入項目'}</CardDescription>
        <CardAction className="flex items-center gap-2">
          <Badge variant={finding.score <= 1 ? 'destructive' : 'outline'}>
            {weakPasswordLabel(finding.score)}
          </Badge>
          <Button
            variant="outline"
            size="sm"
            type="button"
            aria-label={`查看${finding.name}`}
            onClick={() => onOpenItem(finding.id)}
          >
            查看
          </Button>
        </CardAction>
      </CardHeader>
    </Card>
  )
}

export default function VaultHealthPage({
  revision,
  onBack,
  onOpenItem
}: VaultHealthPageProps): React.JSX.Element {
  const [tab, setTab] = useState<HealthTab>('reused')
  const [report, setReport] = useState<VaultHealthReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [failed, setFailed] = useState(false)
  const requestIdRef = useRef(0)

  const loadReport = useCallback(async (): Promise<void> => {
    const requestId = ++requestIdRef.current
    setLoading(true)
    setFailed(false)
    try {
      const nextReport = await window.bearwarden.health.report()
      if (requestId !== requestIdRef.current) return
      setReport(nextReport)
    } catch {
      if (requestId !== requestIdRef.current) return
      setFailed(true)
    } finally {
      if (requestId === requestIdRef.current) setLoading(false)
    }
  }, [])

  useEffect(() => {
    const timeout = window.setTimeout(() => void loadReport(), 0)
    return () => {
      window.clearTimeout(timeout)
      requestIdRef.current += 1
    }
  }, [loadReport, revision])

  return (
    <section className="flex min-h-0 flex-1 flex-col" aria-labelledby="health-title">
      <header className="settings-header">
        <div className="settings-header-inner">
          <Button variant="outline" type="button" onClick={onBack}>
            <ArrowLeft data-icon="inline-start" />
            返回保管庫
          </Button>
          <div className="settings-header-content">
            <div className="settings-title-group">
              <span className="settings-title-icon" aria-hidden="true">
                <ShieldCheck />
              </span>
              <div>
                <p className="eyebrow">Vault Health</p>
                <h1 id="health-title">保管庫健康報告</h1>
                <p className="settings-subtitle">找出重複或容易猜中的登入密碼。</p>
              </div>
            </div>
            <Button
              variant="outline"
              type="button"
              disabled={loading}
              onClick={() => void loadReport()}
            >
              {loading ? (
                <Spinner data-icon="inline-start" />
              ) : (
                <RefreshCw data-icon="inline-start" />
              )}
              重新分析
            </Button>
          </div>
        </div>
      </header>

      <div className="min-h-0 flex-1 overflow-y-auto p-4 md:p-6">
        <div className="mx-auto flex w-full max-w-5xl flex-col gap-6">
          {failed && (
            <Alert variant="destructive">
              <AlertTriangle />
              <AlertTitle>無法產生健康報告</AlertTitle>
              <AlertDescription>請確認保管庫仍為解鎖狀態，再重新分析。</AlertDescription>
              <AlertAction>
                <Button variant="outline" size="sm" type="button" onClick={() => void loadReport()}>
                  重試
                </Button>
              </AlertAction>
            </Alert>
          )}

          {!report && loading ? (
            <HealthLoading />
          ) : report ? (
            <>
              <div className="grid gap-3 md:grid-cols-3">
                <Card>
                  <CardHeader>
                    <CardTitle>已分析</CardTitle>
                    <CardDescription>未受重新提示保護的有效登入項目</CardDescription>
                    <CardAction>
                      <Badge variant="secondary">{report.totals.analyzedCount}</Badge>
                    </CardAction>
                  </CardHeader>
                  <CardContent>分析只在本機主程序記憶體內進行。</CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle>重複密碼</CardTitle>
                    <CardDescription>與至少另一個登入項目使用完全相同的密碼</CardDescription>
                    <CardAction>
                      <Badge
                        variant={report.totals.reusedPasswordCount ? 'destructive' : 'secondary'}
                      >
                        {report.totals.reusedPasswordCount}
                      </Badge>
                    </CardAction>
                  </CardHeader>
                  <CardContent>每個受影響的登入項目都會列在報告中。</CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle>弱密碼</CardTitle>
                    <CardDescription>zxcvbn 評分為 0、1 或 2 的登入密碼</CardDescription>
                    <CardAction>
                      <Badge
                        variant={report.totals.weakPasswordCount ? 'destructive' : 'secondary'}
                      >
                        {report.totals.weakPasswordCount}
                      </Badge>
                    </CardAction>
                  </CardHeader>
                  <CardContent>評分會納入登入使用者名稱中的可辨識字詞。</CardContent>
                </Card>
              </div>

              {report.totals.protectedSkippedCount > 0 && (
                <Alert>
                  <ShieldCheck />
                  <AlertTitle>受保護項目未分析</AlertTitle>
                  <AlertDescription>
                    {report.totals.protectedSkippedCount}{' '}
                    個啟用主密碼重新提示的登入項目已略過，避免健康標籤洩漏受保護密碼的特徵。
                  </AlertDescription>
                </Alert>
              )}

              <Tabs value={tab} onValueChange={(value) => setTab(value as HealthTab)}>
                <TabsList className="w-full sm:w-fit">
                  <TabsTrigger value="reused">
                    重複密碼
                    <Badge variant="secondary">{report.totals.reusedPasswordCount}</Badge>
                  </TabsTrigger>
                  <TabsTrigger value="weak">
                    弱密碼
                    <Badge variant="secondary">{report.totals.weakPasswordCount}</Badge>
                  </TabsTrigger>
                </TabsList>
                <TabsContent value="reused" className="flex flex-col gap-3 pt-3">
                  {report.reusedPasswords.length ? (
                    report.reusedPasswords.map((finding) => (
                      <ReusedFindingCard
                        key={finding.id}
                        finding={finding}
                        onOpenItem={onOpenItem}
                      />
                    ))
                  ) : (
                    <HealthEmpty kind="reused" />
                  )}
                </TabsContent>
                <TabsContent value="weak" className="flex flex-col gap-3 pt-3">
                  {report.weakPasswords.length ? (
                    report.weakPasswords.map((finding) => (
                      <WeakFindingCard key={finding.id} finding={finding} onOpenItem={onOpenItem} />
                    ))
                  ) : (
                    <HealthEmpty kind="weak" />
                  )}
                </TabsContent>
              </Tabs>
            </>
          ) : null}
        </div>
      </div>
    </section>
  )
}
