import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  ExternalLink,
  KeyRound,
  MailSearch,
  RefreshCw,
  Search,
  ShieldCheck,
  ShieldQuestion,
  WifiOff,
  X
} from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { toast } from 'sonner'
import type {
  InactiveTwoFactorFinding,
  InactiveTwoFactorReport,
  VaultHealthAccountBreachFinding,
  VaultHealthReport,
  VaultHealthExposedFinding,
  VaultHealthExposedReport,
  VaultHealthReusedFinding,
  VaultHealthUnsecuredWebsiteFinding,
  VaultHealthWeakFinding
} from '../../../shared/vault-contract'
import { Alert, AlertAction, AlertDescription, AlertTitle } from './ui/alert'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle
} from './ui/empty'
import { Spinner } from './ui/spinner'
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs'
import { Input } from './ui/input'
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from './ui/field'
import {
  beginAccountBreachCheck,
  beginExposedPasswordCheck,
  cancelAccountBreachCheck,
  cancelExposedPasswordCheck,
  createAccountBreachIdleState,
  createExposedPasswordIdleState,
  failAccountBreachCheck,
  failExposedPasswordCheck,
  invalidateAccountBreachCheck,
  resolveAccountBreachCheck,
  resolveExposedPasswordCheck,
  weakPasswordLabel,
  type AccountBreachCheckState,
  type ExposedPasswordCheckState
} from '../lib/vault-health-ui'

type HealthTab = 'reused' | 'weak' | 'unsecured' | 'inactive-two-factor' | 'exposed' | 'account'

export type InactiveTwoFactorCheckState =
  | { status: 'idle'; revision: string }
  | { status: 'loading'; revision: string; requestId: number }
  | { status: 'failed'; revision: string }
  | { status: 'success'; revision: string; report: InactiveTwoFactorReport }

// Exported for security-state regression tests; this file otherwise remains the page boundary.
// eslint-disable-next-line react-refresh/only-export-components
export function createInactiveTwoFactorIdleState(revision: string): InactiveTwoFactorCheckState {
  return { status: 'idle', revision }
}

// eslint-disable-next-line react-refresh/only-export-components
export function resolveInactiveTwoFactorCheck(
  current: InactiveTwoFactorCheckState,
  revision: string,
  requestId: number,
  report: InactiveTwoFactorReport
): InactiveTwoFactorCheckState {
  if (
    current.status !== 'loading' ||
    current.revision !== revision ||
    current.requestId !== requestId
  ) {
    return current
  }
  return { status: 'success', revision, report }
}

// eslint-disable-next-line react-refresh/only-export-components
export function failInactiveTwoFactorCheck(
  current: InactiveTwoFactorCheckState,
  revision: string,
  requestId: number
): InactiveTwoFactorCheckState {
  if (
    current.status !== 'loading' ||
    current.revision !== revision ||
    current.requestId !== requestId
  ) {
    return current
  }
  return { status: 'failed', revision }
}

// eslint-disable-next-line react-refresh/only-export-components
export async function openInactiveTwoFactorDocumentation(
  finding: Pick<InactiveTwoFactorFinding, 'matchedDomain' | 'documentationUrl'>
): Promise<void> {
  if (finding.documentationUrl === null) return
  try {
    await window.bearwarden.health.openTwoFactorDocumentation({
      matchedDomain: finding.matchedDomain
    })
  } catch {
    toast.error('無法開啟雙因素驗證設定說明')
  }
}

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

function HealthEmpty({
  kind
}: {
  kind: Exclude<HealthTab, 'exposed' | 'account'>
}): React.JSX.Element {
  const copy =
    kind === 'reused'
      ? ['沒有重複使用的密碼', '目前分析到的登入項目沒有共用相同密碼。']
      : kind === 'weak'
        ? ['沒有弱密碼', '目前分析到的登入項目都高於弱密碼門檻。']
        : ['沒有不安全網站', '有效的個人登入項目都沒有使用 http:// URI。']
  return (
    <Empty className="min-h-56">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <CheckCircle2 />
        </EmptyMedia>
        <EmptyTitle>{copy[0]}</EmptyTitle>
        <EmptyDescription>{copy[1]}</EmptyDescription>
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

function UnsecuredWebsiteFindingCard({
  finding,
  onOpenItem
}: {
  finding: VaultHealthUnsecuredWebsiteFinding
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle>{finding.name}</CardTitle>
        <CardDescription>至少一個 URI 明確使用 http://</CardDescription>
        <CardAction className="flex items-center gap-2">
          <Badge variant="destructive">未加密連線</Badge>
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

function InactiveTwoFactorFindingCard({
  finding,
  onOpenItem
}: {
  finding: InactiveTwoFactorFinding
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle>{finding.name}</CardTitle>
        <CardDescription>2fa.directory 服務：{finding.matchedDomain}</CardDescription>
        <CardAction className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            type="button"
            aria-label={`查看${finding.name}`}
            onClick={() => onOpenItem(finding.id)}
          >
            查看項目
          </Button>
          {finding.documentationUrl !== null && (
            <Button
              variant="outline"
              size="sm"
              type="button"
              aria-label={`開啟${finding.name}的雙因素驗證設定說明`}
              onClick={() => {
                void openInactiveTwoFactorDocumentation(finding)
              }}
            >
              <ExternalLink data-icon="inline-start" />
              設定說明
            </Button>
          )}
        </CardAction>
      </CardHeader>
    </Card>
  )
}

function InactiveTwoFactorPrivacyNotice(): React.JSX.Element {
  return (
    <Alert>
      <ShieldCheck />
      <AlertTitle>只在你要求時下載服務清單</AlertTitle>
      <AlertDescription>
        按下檢查後，主程序只會下載 2fa.directory 的靜態 TOTP
        服務清單並在本機比對；保管庫網域、URI、密碼與 TOTP 都不會上傳。
      </AlertDescription>
    </Alert>
  )
}

function InactiveTwoFactorIdle({ onStart }: { onStart: () => void }): React.JSX.Element {
  return (
    <Empty className="min-h-56">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <KeyRound />
        </EmptyMedia>
        <EmptyTitle>尚未檢查未啟用雙因素驗證的登入項目</EmptyTitle>
        <EmptyDescription>
          只有在你按下按鈕後才會載入服務清單；垃圾桶、封存與已有 TOTP 的項目會略過。
        </EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <Button type="button" onClick={onStart}>
          <Search data-icon="inline-start" />
          檢查雙因素驗證
        </Button>
      </EmptyContent>
    </Empty>
  )
}

function InactiveTwoFactorLoading(): React.JSX.Element {
  return (
    <Empty className="min-h-56" aria-live="polite" aria-busy="true">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <Spinner />
        </EmptyMedia>
        <EmptyTitle>正在載入 2fa.directory 服務清單</EmptyTitle>
        <EmptyDescription>主程序正在本機比對服務網域，不會上傳任何保管庫資料。</EmptyDescription>
      </EmptyHeader>
    </Empty>
  )
}

function InactiveTwoFactorFailed({ onRetry }: { onRetry: () => void }): React.JSX.Element {
  return (
    <Alert variant="destructive">
      <WifiOff />
      <AlertTitle>無法完成雙因素驗證檢查</AlertTitle>
      <AlertDescription>
        2fa.directory 網路、服務清單或回應驗證失敗，本次結果為未知；請稍後重試。
      </AlertDescription>
      <AlertAction>
        <Button variant="outline" size="sm" type="button" onClick={onRetry}>
          重試
        </Button>
      </AlertAction>
    </Alert>
  )
}

function InactiveTwoFactorSuccess({
  report,
  onOpenItem
}: {
  report: InactiveTwoFactorReport
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  return (
    <div className="flex flex-col gap-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>本次已分析</CardTitle>
            <CardDescription>本次檢查納入的有效個人登入項目</CardDescription>
            <CardAction>
              <Badge variant="secondary">{report.analyzedCount}</Badge>
            </CardAction>
          </CardHeader>
          <CardContent>服務網域只在本機與靜態清單比對。</CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>可啟用 TOTP</CardTitle>
            <CardDescription>服務支援 TOTP，但登入項目尚未設定</CardDescription>
            <CardAction>
              <Badge variant={report.findings.length ? 'destructive' : 'secondary'}>
                {report.findings.length}
              </Badge>
            </CardAction>
          </CardHeader>
          <CardContent>可從項目檢視進入編輯流程，或查看服務提供的設定說明。</CardContent>
        </Card>
      </div>

      <Alert>
        <ShieldCheck />
        <AlertTitle>已略過不適用的項目</AlertTitle>
        <AlertDescription className="flex flex-wrap gap-2">
          <Badge variant="outline">已有 TOTP {report.excludedTotpCount}</Badge>
          <Badge variant="outline">垃圾桶 {report.excludedDeletedCount}</Badge>
          <Badge variant="outline">封存 {report.excludedArchivedCount}</Badge>
        </AlertDescription>
      </Alert>

      {report.findings.length ? (
        report.findings.map((finding) => (
          <InactiveTwoFactorFindingCard
            key={finding.id}
            finding={finding}
            onOpenItem={onOpenItem}
          />
        ))
      ) : (
        <Empty className="min-h-56">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <CheckCircle2 />
            </EmptyMedia>
            <EmptyTitle>沒有找到尚未設定 TOTP 的支援服務</EmptyTitle>
            <EmptyDescription>
              本次已分析的登入項目，沒有符合 2fa.directory TOTP 清單且尚未設定 TOTP 的服務。
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      )}
    </div>
  )
}

export function InactiveTwoFactorPanel({
  state,
  onStart,
  onOpenItem
}: {
  state: InactiveTwoFactorCheckState
  onStart: () => void
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  return (
    <div className="flex flex-col gap-3">
      <InactiveTwoFactorPrivacyNotice />
      {state.status === 'idle' ? (
        <InactiveTwoFactorIdle onStart={onStart} />
      ) : state.status === 'loading' ? (
        <InactiveTwoFactorLoading />
      ) : state.status === 'failed' ? (
        <InactiveTwoFactorFailed onRetry={onStart} />
      ) : (
        <InactiveTwoFactorSuccess report={state.report} onOpenItem={onOpenItem} />
      )}
    </div>
  )
}

function ExposedFindingCard({
  finding,
  onOpenItem
}: {
  finding: VaultHealthExposedFinding
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle>{finding.name}</CardTitle>
        <CardDescription>{finding.subtitle || '登入項目'}</CardDescription>
        <CardAction className="flex items-center gap-2">
          <Badge variant="destructive">已知外洩紀錄 {finding.exposedCount.toLocaleString()}</Badge>
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

function ExposedPrivacyNotice(): React.JSX.Element {
  return (
    <Alert>
      <ShieldCheck />
      <AlertTitle>使用 k-anonymity 保護查詢內容</AlertTitle>
      <AlertDescription>
        BearWarden 只會送出密碼 SHA-1 雜湊的前 5 碼，下載 HIBP Pwned Passwords 的 padded range
        回應，再由主程序以完整 SHA-1 在本機比對。密碼與完整雜湊都不會傳給 HIBP 或畫面程序。
      </AlertDescription>
    </Alert>
  )
}

function ExposedIdle({ onStart }: { onStart: () => void }): React.JSX.Element {
  return (
    <Empty className="min-h-56">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <ShieldQuestion />
        </EmptyMedia>
        <EmptyTitle>尚未檢查已知外洩紀錄</EmptyTitle>
        <EmptyDescription>
          這項檢查會連線至 HIBP，只有在你按下按鈕後才會開始，不會因開啟此頁面自動查詢。
        </EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <Button type="button" onClick={onStart}>
          <Search data-icon="inline-start" />
          檢查外洩密碼
        </Button>
      </EmptyContent>
    </Empty>
  )
}

function ExposedLoading({ onCancel }: { onCancel: () => void }): React.JSX.Element {
  return (
    <Empty className="min-h-56" aria-live="polite" aria-busy="true">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <Spinner />
        </EmptyMedia>
        <EmptyTitle>正在查詢 HIBP padded ranges</EmptyTitle>
        <EmptyDescription>
          主程序正在逐一比對完整 SHA-1；密碼與完整雜湊不會離開本機。
        </EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <Button variant="outline" type="button" onClick={onCancel}>
          <X data-icon="inline-start" />
          取消檢查
        </Button>
      </EmptyContent>
    </Empty>
  )
}

function ExposedFailed({ onRetry }: { onRetry: () => void }): React.JSX.Element {
  return (
    <Alert variant="destructive">
      <WifiOff />
      <AlertTitle>無法判定是否有外洩密碼</AlertTitle>
      <AlertDescription>
        HIBP 網路或回應驗證失敗，本次結果為未知；BearWarden 不會因此把任何登入項目標示為安全。
      </AlertDescription>
      <AlertAction>
        <Button variant="outline" size="sm" type="button" onClick={onRetry}>
          重試
        </Button>
      </AlertAction>
    </Alert>
  )
}

function ExposedSuccess({
  report,
  onOpenItem
}: {
  report: VaultHealthExposedReport
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  return (
    <div className="flex flex-col gap-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>本次已檢查</CardTitle>
            <CardDescription>未受重新提示保護的有效登入密碼</CardDescription>
            <CardAction>
              <Badge variant="secondary">{report.totals.analyzedCount}</Badge>
            </CardAction>
          </CardHeader>
          <CardContent>完整 SHA-1 僅在主程序記憶體中進行比對。</CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>找到已知外洩紀錄</CardTitle>
            <CardDescription>在 HIBP padded range 中完整雜湊相符的登入項目</CardDescription>
            <CardAction>
              <Badge variant={report.totals.exposedPasswordCount ? 'destructive' : 'secondary'}>
                {report.totals.exposedPasswordCount}
              </Badge>
            </CardAction>
          </CardHeader>
          <CardContent>紀錄次數來自 HIBP，並不代表密碼仍在特定網站流通。</CardContent>
        </Card>
      </div>

      {report.totals.protectedSkippedCount > 0 && (
        <Alert>
          <ShieldCheck />
          <AlertTitle>受保護項目未送出查詢</AlertTitle>
          <AlertDescription>
            {report.totals.protectedSkippedCount} 個啟用主密碼重新提示的登入項目已略過，未建立 SHA-1
            或發出 HIBP range 查詢。
          </AlertDescription>
        </Alert>
      )}

      {report.exposedPasswords.length ? (
        report.exposedPasswords.map((finding) => (
          <ExposedFindingCard key={finding.id} finding={finding} onOpenItem={onOpenItem} />
        ))
      ) : (
        <Empty className="min-h-56">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <CheckCircle2 />
            </EmptyMedia>
            <EmptyTitle>本次未找到已知外洩紀錄</EmptyTitle>
            <EmptyDescription>
              已檢查的完整 SHA-1 沒有出現在 HIBP 回應中；這是本次查詢結果，不代表密碼永遠安全。
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      )}
    </div>
  )
}

function ExposedPasswordPanel({
  state,
  onStart,
  onCancel,
  onOpenItem
}: {
  state: ExposedPasswordCheckState
  onStart: () => void
  onCancel: () => void
  onOpenItem: (id: string) => void
}): React.JSX.Element {
  return (
    <div className="flex flex-col gap-3">
      <ExposedPrivacyNotice />
      {state.status === 'idle' ? (
        <ExposedIdle onStart={onStart} />
      ) : state.status === 'loading' ? (
        <ExposedLoading onCancel={onCancel} />
      ) : state.status === 'failed' ? (
        <ExposedFailed onRetry={onStart} />
      ) : (
        <ExposedSuccess report={state.report} onOpenItem={onOpenItem} />
      )}
    </div>
  )
}

function HibpWebsiteLink(): React.JSX.Element {
  return (
    <a
      href="https://haveibeenpwned.com/"
      onClick={(event) => {
        event.preventDefault()
        void window.bearwarden.health.openHibpWebsite().catch(() => {
          // Attribution remains visible even if the system browser cannot be opened.
        })
      }}
    >
      Have I Been Pwned (HIBP)
    </a>
  )
}

function AccountBreachPrivacyNotice(): React.JSX.Element {
  return (
    <Alert>
      <MailSearch />
      <AlertTitle>完整電子郵件會離開此裝置</AlertTitle>
      <AlertDescription>
        只有在你送出查詢後，BearWarden 才會把完整電子郵件傳給已設定的 Vaultwarden
        server；該伺服器會再將它傳給 <HibpWebsiteLink />
        。這不是 k-anonymity 密碼檢查，請只查詢你有權檢查的帳號。
      </AlertDescription>
    </Alert>
  )
}

function isValidAccountBreachEmail(email: string): boolean {
  return email.length > 0 && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
}

function AccountBreachForm({
  email,
  invalid,
  loading,
  onEmailChange,
  onSubmit,
  onCancel
}: {
  email: string
  invalid: boolean
  loading: boolean
  onEmailChange: (value: string) => void
  onSubmit: () => void
  onCancel: () => void
}): React.JSX.Element {
  return (
    <Card>
      <CardHeader>
        <CardTitle>查詢帳號外洩紀錄</CardTitle>
        <CardDescription>輸入要透過 Vaultwarden 與 HIBP 查詢的電子郵件。</CardDescription>
      </CardHeader>
      <CardContent>
        <form
          noValidate
          onSubmit={(event) => {
            event.preventDefault()
            onSubmit()
          }}
        >
          <FieldGroup>
            <Field data-invalid={invalid || undefined} data-disabled={loading || undefined}>
              <FieldLabel htmlFor="account-breach-email">電子郵件</FieldLabel>
              <Input
                id="account-breach-email"
                type="email"
                autoComplete="email"
                maxLength={254}
                value={email}
                aria-invalid={invalid || undefined}
                aria-describedby={invalid ? 'account-breach-email-error' : undefined}
                disabled={loading}
                onChange={(event) => onEmailChange(event.target.value)}
              />
              <FieldDescription>完整地址只會在按下「查詢帳號外洩」後送出。</FieldDescription>
              {invalid && (
                <FieldError id="account-breach-email-error">
                  請輸入有效且不超過 254 個字元的電子郵件地址。
                </FieldError>
              )}
            </Field>
            <div className="flex flex-wrap gap-2">
              <Button type="submit" disabled={loading}>
                {loading ? (
                  <Spinner data-icon="inline-start" />
                ) : (
                  <Search data-icon="inline-start" />
                )}
                查詢帳號外洩
              </Button>
              {loading && (
                <Button variant="outline" type="button" onClick={onCancel}>
                  <X data-icon="inline-start" />
                  取消查詢
                </Button>
              )}
            </div>
          </FieldGroup>
        </form>
      </CardContent>
    </Card>
  )
}

function AccountBreachFindingCard({
  breach
}: {
  breach: VaultHealthAccountBreachFinding
}): React.JSX.Element {
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle>{breach.title}</CardTitle>
        <CardDescription>{breach.domain || breach.name}</CardDescription>
        <CardAction className="flex items-center gap-2">
          <Badge variant={breach.isVerified ? 'secondary' : 'outline'}>
            {breach.isVerified ? '已驗證' : '未驗證'}
          </Badge>
          <Badge variant="outline">{breach.pwnCount.toLocaleString()} 筆帳號</Badge>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <p className="text-muted-foreground text-sm">
          外洩日期：{breach.breachDate}；加入 HIBP：
          {new Date(breach.addedDate).toLocaleDateString()}
        </p>
        {breach.dataClasses.length > 0 && (
          <div className="flex flex-wrap gap-2" aria-label="受影響資料類別">
            {breach.dataClasses.map((dataClass, index) => (
              <Badge key={`${dataClass}-${index}`} variant="outline">
                {dataClass}
              </Badge>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function AccountBreachResults({
  state
}: {
  state: AccountBreachCheckState
}): React.JSX.Element | null {
  if (state.status === 'idle') return null

  if (state.status === 'loading') {
    return (
      <Alert aria-live="polite" aria-busy="true">
        <Spinner />
        <AlertTitle>正在查詢帳號外洩紀錄</AlertTitle>
        <AlertDescription>
          完整電子郵件正由已設定的 Vaultwarden server 轉送至 HIBP。
        </AlertDescription>
      </Alert>
    )
  }

  if (state.status === 'failed') {
    return (
      <Alert variant="destructive">
        <WifiOff />
        <AlertTitle>無法判定帳號是否出現在外洩事件</AlertTitle>
        <AlertDescription>
          Vaultwarden、HIBP 網路或回應驗證失敗，本次結果為未知；這不代表帳號安全。
        </AlertDescription>
      </Alert>
    )
  }

  if (state.status === 'unavailable') {
    return (
      <Alert>
        <ShieldQuestion />
        <AlertTitle>Vaultwarden 尚未設定 HIBP API key</AlertTitle>
        <AlertDescription>
          伺服器回傳的是未設定 API key 的提示，不是查詢結果；請由伺服器管理者設定 HIBP API key
          後再試。
        </AlertDescription>
      </Alert>
    )
  }

  return state.report.breaches.length ? (
    <div className="flex flex-col gap-3">
      <Alert>
        <AlertTriangle />
        <AlertTitle>找到 {state.report.breaches.length} 個已知外洩事件</AlertTitle>
        <AlertDescription>
          資料由 <HibpWebsiteLink /> 提供；請依受影響資料與密碼重複使用情況採取行動。
        </AlertDescription>
      </Alert>
      {state.report.breaches.map((breach) => (
        <AccountBreachFindingCard key={breach.name} breach={breach} />
      ))}
    </div>
  ) : (
    <Empty className="min-h-56">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <CheckCircle2 />
        </EmptyMedia>
        <EmptyTitle>本次未找到已知外洩事件</EmptyTitle>
        <EmptyDescription>
          HIBP 沒有回傳此帳號的已知外洩事件；這是本次查詢結果，不代表帳號永遠安全。
        </EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <p className="text-muted-foreground text-sm">
          資料來源： <HibpWebsiteLink />
        </p>
      </EmptyContent>
    </Empty>
  )
}

function AccountBreachPanel({
  email,
  invalid,
  state,
  onEmailChange,
  onStart,
  onCancel
}: {
  email: string
  invalid: boolean
  state: AccountBreachCheckState
  onEmailChange: (value: string) => void
  onStart: () => void
  onCancel: () => void
}): React.JSX.Element {
  return (
    <div className="flex flex-col gap-3">
      <AccountBreachPrivacyNotice />
      <AccountBreachForm
        email={email}
        invalid={invalid}
        loading={state.status === 'loading'}
        onEmailChange={onEmailChange}
        onSubmit={onStart}
        onCancel={onCancel}
      />
      <AccountBreachResults state={state} />
    </div>
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
  const [exposedState, setExposedState] = useState<ExposedPasswordCheckState>(() =>
    createExposedPasswordIdleState(revision)
  )
  const exposedRequestIdRef = useRef(0)
  const exposedRevisionRef = useRef(revision)
  const exposedRequestActiveRef = useRef(false)
  const [inactiveTwoFactorState, setInactiveTwoFactorState] = useState<InactiveTwoFactorCheckState>(
    () => createInactiveTwoFactorIdleState(revision)
  )
  const inactiveTwoFactorRequestIdRef = useRef(0)
  const inactiveTwoFactorRevisionRef = useRef(revision)
  const [accountBreachEmail, setAccountBreachEmail] = useState('')
  const [accountBreachEmailInvalid, setAccountBreachEmailInvalid] = useState(false)
  const [accountBreachState, setAccountBreachState] = useState<AccountBreachCheckState>(() =>
    createAccountBreachIdleState(revision)
  )
  const accountBreachRequestIdRef = useRef(0)
  const accountBreachRevisionRef = useRef(revision)
  const accountBreachRequestActiveRef = useRef(false)

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

  const startExposedPasswordCheck = useCallback(async (): Promise<void> => {
    const requestId = ++exposedRequestIdRef.current
    const requestRevision = revision
    exposedRequestActiveRef.current = true
    setExposedState(beginExposedPasswordCheck(requestRevision, requestId))

    try {
      const nextReport = await window.bearwarden.health.exposedPasswords()
      if (requestId !== exposedRequestIdRef.current) return
      exposedRequestActiveRef.current = false
      setExposedState((current) =>
        resolveExposedPasswordCheck(current, requestRevision, requestId, nextReport)
      )
    } catch {
      if (requestId !== exposedRequestIdRef.current) return
      exposedRequestActiveRef.current = false
      setExposedState((current) => failExposedPasswordCheck(current, requestRevision, requestId))
    }
  }, [revision])

  const cancelExposedPasswordRequest = useCallback((): void => {
    const wasActive = exposedRequestActiveRef.current
    exposedRequestActiveRef.current = false
    exposedRequestIdRef.current += 1
    setExposedState(cancelExposedPasswordCheck(revision))
    if (!wasActive) return
    void window.bearwarden.health.cancelExposedPasswords().catch(() => {
      // Cancellation is best effort; stale request IDs keep late responses from reaching the UI.
    })
  }, [revision])

  const startInactiveTwoFactorCheck = useCallback(async (): Promise<void> => {
    const requestId = ++inactiveTwoFactorRequestIdRef.current
    const requestRevision = revision
    setInactiveTwoFactorState({ status: 'loading', revision: requestRevision, requestId })

    try {
      const nextReport = await window.bearwarden.health.inactiveTwoFactor()
      if (requestId !== inactiveTwoFactorRequestIdRef.current) return
      setInactiveTwoFactorState((current) =>
        resolveInactiveTwoFactorCheck(current, requestRevision, requestId, nextReport)
      )
    } catch {
      if (requestId !== inactiveTwoFactorRequestIdRef.current) return
      setInactiveTwoFactorState((current) =>
        failInactiveTwoFactorCheck(current, requestRevision, requestId)
      )
    }
  }, [revision])

  const startAccountBreachCheck = useCallback(async (): Promise<void> => {
    const email = accountBreachEmail.trim().toLowerCase()
    if (!isValidAccountBreachEmail(email)) {
      setAccountBreachEmailInvalid(true)
      return
    }

    setAccountBreachEmail(email)
    setAccountBreachEmailInvalid(false)
    const requestId = ++accountBreachRequestIdRef.current
    const requestRevision = revision
    accountBreachRequestActiveRef.current = true
    setAccountBreachState(beginAccountBreachCheck(requestRevision, requestId, email))

    try {
      const nextReport = await window.bearwarden.health.accountBreaches({ email })
      if (requestId !== accountBreachRequestIdRef.current) return
      accountBreachRequestActiveRef.current = false
      setAccountBreachState((current) =>
        resolveAccountBreachCheck(current, requestRevision, requestId, nextReport)
      )
    } catch {
      if (requestId !== accountBreachRequestIdRef.current) return
      accountBreachRequestActiveRef.current = false
      setAccountBreachState((current) =>
        failAccountBreachCheck(current, requestRevision, requestId)
      )
    }
  }, [accountBreachEmail, revision])

  const cancelAccountBreachRequest = useCallback((): void => {
    const wasActive = accountBreachRequestActiveRef.current
    accountBreachRequestActiveRef.current = false
    accountBreachRequestIdRef.current += 1
    setAccountBreachState(cancelAccountBreachCheck(revision))
    if (!wasActive) return
    void window.bearwarden.health.cancelAccountBreaches().catch(() => {
      // Cancellation is best effort; stale request IDs keep late responses from reaching the UI.
    })
  }, [revision])

  useEffect(() => {
    if (exposedRevisionRef.current === revision) return
    exposedRevisionRef.current = revision
    const wasActive = exposedRequestActiveRef.current
    exposedRequestActiveRef.current = false
    exposedRequestIdRef.current += 1
    if (!wasActive) return
    void window.bearwarden.health.cancelExposedPasswords().catch(() => {
      // A revision change invalidates the renderer state even if the main request already ended.
    })
  }, [revision])

  useEffect(() => {
    if (accountBreachRevisionRef.current === revision) return
    accountBreachRevisionRef.current = revision
    const wasActive = accountBreachRequestActiveRef.current
    accountBreachRequestActiveRef.current = false
    accountBreachRequestIdRef.current += 1
    setAccountBreachState((current) => invalidateAccountBreachCheck(current, revision))
    if (!wasActive) return
    void window.bearwarden.health.cancelAccountBreaches().catch(() => {
      // A revision change invalidates the renderer state even if the main request already ended.
    })
  }, [revision])

  useEffect(() => {
    if (inactiveTwoFactorRevisionRef.current === revision) return
    inactiveTwoFactorRevisionRef.current = revision
    inactiveTwoFactorRequestIdRef.current += 1
    setInactiveTwoFactorState(createInactiveTwoFactorIdleState(revision))
  }, [revision])

  useEffect(
    () => () => {
      if (!exposedRequestActiveRef.current) return
      exposedRequestActiveRef.current = false
      exposedRequestIdRef.current += 1
      void window.bearwarden.health.cancelExposedPasswords().catch(() => {
        // Unmount cancellation must not surface as a failed exposure report.
      })
    },
    []
  )

  useEffect(
    () => () => {
      if (!accountBreachRequestActiveRef.current) return
      accountBreachRequestActiveRef.current = false
      accountBreachRequestIdRef.current += 1
      void window.bearwarden.health.cancelAccountBreaches().catch(() => {
        // Unmount cancellation must not surface as a failed account-breach report.
      })
    },
    []
  )

  const visibleExposedState =
    exposedState.revision === revision ? exposedState : createExposedPasswordIdleState(revision)
  const visibleInactiveTwoFactorState =
    inactiveTwoFactorState.revision === revision
      ? inactiveTwoFactorState
      : createInactiveTwoFactorIdleState(revision)
  const visibleAccountBreachState =
    accountBreachState.revision === revision
      ? accountBreachState
      : createAccountBreachIdleState(revision)

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
                <p className="settings-subtitle">
                  找出重複、容易猜中、出現在已知外洩紀錄的密碼、未加密網站
                  URI，以及可啟用雙因素驗證的服務。
                </p>
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
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                <Card>
                  <CardHeader>
                    <CardTitle>已分析</CardTitle>
                    <CardDescription>具有密碼且未受重新提示保護的有效登入項目</CardDescription>
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
                <Card>
                  <CardHeader>
                    <CardTitle>不安全網站</CardTitle>
                    <CardDescription>至少一個 URI 以 http:// 開頭的個人登入項目</CardDescription>
                    <CardAction>
                      <Badge
                        variant={report.totals.unsecuredWebsiteCount ? 'destructive' : 'secondary'}
                      >
                        {report.totals.unsecuredWebsiteCount}
                      </Badge>
                    </CardAction>
                  </CardHeader>
                  <CardContent>URI 僅在本機比對，完整網址與查詢參數不會傳到畫面。</CardContent>
                </Card>
              </div>

              {report.totals.protectedSkippedCount > 0 && (
                <Alert>
                  <ShieldCheck />
                  <AlertTitle>受保護項目未分析</AlertTitle>
                  <AlertDescription>
                    {report.totals.protectedSkippedCount}{' '}
                    個啟用主密碼重新提示的登入項目已略過，避免健康標籤洩漏受保護內容的特徵。
                  </AlertDescription>
                </Alert>
              )}

              <Tabs value={tab} onValueChange={(value) => setTab(value as HealthTab)}>
                <TabsList className="h-auto w-full flex-wrap sm:w-fit">
                  <TabsTrigger value="reused">
                    重複密碼
                    <Badge variant="secondary">{report.totals.reusedPasswordCount}</Badge>
                  </TabsTrigger>
                  <TabsTrigger value="weak">
                    弱密碼
                    <Badge variant="secondary">{report.totals.weakPasswordCount}</Badge>
                  </TabsTrigger>
                  <TabsTrigger value="unsecured">
                    不安全網站
                    <Badge variant="secondary">{report.totals.unsecuredWebsiteCount}</Badge>
                  </TabsTrigger>
                  <TabsTrigger value="inactive-two-factor">
                    未啟用雙因素驗證
                    {visibleInactiveTwoFactorState.status === 'loading' ? (
                      <Spinner />
                    ) : visibleInactiveTwoFactorState.status === 'success' ? (
                      <Badge
                        variant={
                          visibleInactiveTwoFactorState.report.findings.length
                            ? 'destructive'
                            : 'secondary'
                        }
                      >
                        {visibleInactiveTwoFactorState.report.findings.length}
                      </Badge>
                    ) : visibleInactiveTwoFactorState.status === 'failed' ? (
                      <Badge variant="outline">未知</Badge>
                    ) : null}
                  </TabsTrigger>
                  <TabsTrigger value="exposed">
                    外洩密碼
                    {visibleExposedState.status === 'loading' ? (
                      <Spinner />
                    ) : visibleExposedState.status === 'success' ? (
                      <Badge
                        variant={
                          visibleExposedState.report.totals.exposedPasswordCount
                            ? 'destructive'
                            : 'secondary'
                        }
                      >
                        {visibleExposedState.report.totals.exposedPasswordCount}
                      </Badge>
                    ) : visibleExposedState.status === 'failed' ? (
                      <Badge variant="outline">未知</Badge>
                    ) : null}
                  </TabsTrigger>
                  <TabsTrigger value="account">
                    帳號外洩
                    {visibleAccountBreachState.status === 'loading' ? (
                      <Spinner />
                    ) : visibleAccountBreachState.status === 'success' ? (
                      <Badge
                        variant={
                          visibleAccountBreachState.report.breaches.length
                            ? 'destructive'
                            : 'secondary'
                        }
                      >
                        {visibleAccountBreachState.report.breaches.length}
                      </Badge>
                    ) : visibleAccountBreachState.status === 'unavailable' ? (
                      <Badge variant="outline">未設定</Badge>
                    ) : visibleAccountBreachState.status === 'failed' ? (
                      <Badge variant="outline">未知</Badge>
                    ) : null}
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
                <TabsContent value="unsecured" className="flex flex-col gap-3 pt-3">
                  {report.unsecuredWebsites.length ? (
                    report.unsecuredWebsites.map((finding) => (
                      <UnsecuredWebsiteFindingCard
                        key={finding.id}
                        finding={finding}
                        onOpenItem={onOpenItem}
                      />
                    ))
                  ) : (
                    <HealthEmpty kind="unsecured" />
                  )}
                </TabsContent>
                <TabsContent value="inactive-two-factor" className="pt-3">
                  <InactiveTwoFactorPanel
                    state={visibleInactiveTwoFactorState}
                    onStart={() => void startInactiveTwoFactorCheck()}
                    onOpenItem={onOpenItem}
                  />
                </TabsContent>
                <TabsContent value="exposed" className="pt-3">
                  <ExposedPasswordPanel
                    state={visibleExposedState}
                    onStart={() => void startExposedPasswordCheck()}
                    onCancel={cancelExposedPasswordRequest}
                    onOpenItem={onOpenItem}
                  />
                </TabsContent>
                <TabsContent value="account" className="pt-3">
                  <AccountBreachPanel
                    email={accountBreachEmail}
                    invalid={accountBreachEmailInvalid}
                    state={visibleAccountBreachState}
                    onEmailChange={(value) => {
                      setAccountBreachEmail(value)
                      setAccountBreachEmailInvalid(false)
                    }}
                    onStart={() => void startAccountBreachCheck()}
                    onCancel={cancelAccountBreachRequest}
                  />
                </TabsContent>
              </Tabs>
            </>
          ) : null}
        </div>
      </div>
    </section>
  )
}
