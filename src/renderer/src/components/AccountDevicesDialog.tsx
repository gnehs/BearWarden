import { Laptop, LogOut, RefreshCw, TriangleAlert } from 'lucide-react'
import { useRef, useState, type FormEvent, type MutableRefObject } from 'react'
import {
  ACCOUNT_SESSION_DEAUTHORIZATION_CONFIRMATION,
  type AccountDevicesResult,
  type LoginApprovalPrompt,
  type AccountSessionDeauthorizationRequest
} from '../../../shared/vault-contract'
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import { Badge } from '@renderer/components/ui/badge'
import { Button } from '@renderer/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger
} from '@renderer/components/ui/dialog'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import { Spinner } from '@renderer/components/ui/spinner'
import LoginApprovalDialog from './LoginApprovalDialog'

export const DEAUTHORIZE_SESSIONS_CONFIRMATION = ACCOUNT_SESSION_DEAUTHORIZATION_CONFIRMATION

type DeauthorizeSessionsRequest = AccountSessionDeauthorizationRequest

interface ExecuteDeauthorizeSessionsOptions {
  lease: MutableRefObject<boolean>
  request: DeauthorizeSessionsRequest
  deauthorize: (request: DeauthorizeSessionsRequest) => Promise<void>
  onAcquired: () => void
}

/** A ref-backed lease prevents two destructive requests before React commits `busy`. */
// eslint-disable-next-line react-refresh/only-export-components
export async function executeDeauthorizeSessions({
  lease,
  request,
  deauthorize,
  onAcquired
}: ExecuteDeauthorizeSessionsOptions): Promise<boolean> {
  if (lease.current) {
    request.masterPassword = ''
    ;(request as { confirmation: string }).confirmation = ''
    return false
  }
  lease.current = true
  try {
    onAcquired()
    await deauthorize(request)
    return true
  } finally {
    request.masterPassword = ''
    ;(request as { confirmation: string }).confirmation = ''
    lease.current = false
  }
}

// eslint-disable-next-line react-refresh/only-export-components
export function deauthorizeSessionsError(error: unknown): string {
  if (error instanceof Error && error.message.includes('INVALID_MASTER_PASSWORD')) {
    return '主密碼驗證失敗；若要再試，請重新輸入主密碼與確認文字。'
  }
  if (error instanceof Error && error.message.includes('SESSION_DEAUTHORIZATION_UNKNOWN')) {
    return '連線在取消過程中中斷，結果無法判定。可能已成功；請先重新登入或確認其他裝置狀態，不要直接重試。'
  }
  if (error instanceof Error && error.message.includes('SYNC_AUTH_REQUIRED')) {
    return '目前登入已失效，請先重新登入。'
  }
  return '無法確認是否已取消所有工作階段。請先確認登入與其他裝置狀態，不要直接重試。'
}

interface DeauthorizeSessionsFormProps {
  masterPassword: string
  confirmation: string
  busy: boolean
  error: string
  onMasterPasswordChange: (value: string) => void
  onConfirmationChange: (value: string) => void
  onCancel: () => void
}

export function DeauthorizeSessionsForm({
  masterPassword,
  confirmation,
  busy,
  error,
  onMasterPasswordChange,
  onConfirmationChange,
  onCancel
}: DeauthorizeSessionsFormProps): React.JSX.Element {
  const confirmed = confirmation === DEAUTHORIZE_SESSIONS_CONFIRMATION

  return (
    <div className="border-destructive/40 grid gap-4 rounded-lg border p-4">
      <Alert variant="destructive">
        <TriangleAlert aria-hidden="true" />
        <AlertTitle>這會取消所有工作階段</AlertTitle>
        <AlertDescription>
          包含目前裝置。所有裝置都必須重新登入，並在已啟用時再次完成雙重驗證。其他裝置可能最長約一小時才失效。
          BearWarden 會保留這台電腦上的本機加密 vault，但在重新登入前不會再同步。
        </AlertDescription>
      </Alert>
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor="deauthorize-sessions-master-password">主密碼</FieldLabel>
          <Input
            id="deauthorize-sessions-master-password"
            type="password"
            autoComplete="current-password"
            maxLength={1024}
            value={masterPassword}
            disabled={busy}
            autoFocus
            onChange={(event) => onMasterPasswordChange(event.target.value)}
          />
          <FieldDescription>每次嘗試都必須重新輸入，只用於這一次伺服器驗證。</FieldDescription>
        </Field>
        <Field>
          <FieldLabel htmlFor="deauthorize-sessions-confirmation">
            輸入「{DEAUTHORIZE_SESSIONS_CONFIRMATION}」確認
          </FieldLabel>
          <Input
            id="deauthorize-sessions-confirmation"
            type="text"
            autoComplete="off"
            maxLength={DEAUTHORIZE_SESSIONS_CONFIRMATION.length}
            value={confirmation}
            disabled={busy}
            spellCheck={false}
            onChange={(event) => onConfirmationChange(event.target.value)}
          />
          <FieldDescription>必須完全符合，不會自動修正空白或字元。</FieldDescription>
        </Field>
      </FieldGroup>
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <div className="flex flex-wrap justify-end gap-2">
        <Button variant="secondary" type="button" disabled={busy} onClick={onCancel}>
          取消
        </Button>
        <Button
          variant="destructive"
          type="submit"
          disabled={busy || !masterPassword || !confirmed}
        >
          {busy ? (
            <Spinner data-icon="inline-start" aria-hidden="true" />
          ) : (
            <LogOut data-icon="inline-start" aria-hidden="true" />
          )}
          取消所有工作階段
        </Button>
      </div>
    </div>
  )
}

const deviceTypeNames: Record<number, string> = {
  0: 'Android',
  1: 'iPhone / iPad',
  2: 'Chrome 擴充功能',
  3: 'Firefox 擴充功能',
  4: 'Opera 擴充功能',
  5: 'Edge 擴充功能',
  6: 'Windows 桌面版',
  7: 'macOS 桌面版',
  8: 'Linux 桌面版',
  9: 'Chrome 網頁版',
  10: 'Firefox 網頁版',
  11: 'Opera 網頁版',
  12: 'Edge 網頁版',
  13: 'Internet Explorer 網頁版',
  14: '未知瀏覽器',
  15: 'Android（Amazon）',
  16: 'Windows UWP',
  17: 'Safari 網頁版',
  18: 'Vivaldi 網頁版',
  19: 'Vivaldi 擴充功能',
  20: 'Safari 擴充功能',
  21: 'SDK',
  22: '伺服器',
  23: 'Windows CLI',
  24: 'macOS CLI',
  25: 'Linux CLI',
  26: 'DuckDuckGo 網頁版'
}

function formatDeviceDate(value: string | null): string {
  if (value === null) return '沒有紀錄'
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return '日期不可用'
  return new Intl.DateTimeFormat('zh-TW', {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(date)
}

function AccountDevicesDialog(): React.JSX.Element {
  const [open, setOpen] = useState(false)
  const [result, setResult] = useState<AccountDevicesResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [deauthorizeOpen, setDeauthorizeOpen] = useState(false)
  const [masterPassword, setMasterPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [deauthorizeError, setDeauthorizeError] = useState('')
  const [success, setSuccess] = useState('')
  const [pendingApprovals, setPendingApprovals] = useState<LoginApprovalPrompt[]>([])
  const [selectedApproval, setSelectedApproval] = useState<LoginApprovalPrompt | null>(null)
  const submissionLease = useRef(false)

  function clearDeauthorizationSecrets(): void {
    setMasterPassword('')
    setConfirmation('')
  }

  async function load(): Promise<void> {
    setBusy(true)
    setError('')
    try {
      const [devices, approvals] = await Promise.all([
        window.bearwarden.accountSecurity.devices(),
        // Login-with-device is optional on some self-hosted servers. A missing or
        // temporarily unavailable auth-request endpoint must not hide the device list.
        window.bearwarden.accountSecurity.pendingLoginApprovals().catch(() => [])
      ])
      setResult(devices)
      setPendingApprovals(approvals)
    } catch {
      setResult(null)
      setError('無法讀取帳號裝置，請稍後再試。')
    } finally {
      setBusy(false)
    }
  }

  function changeOpen(next: boolean): void {
    if (busy || submissionLease.current) return
    setOpen(next)
    setResult(null)
    setPendingApprovals([])
    setError('')
    setSuccess('')
    setDeauthorizeOpen(false)
    setDeauthorizeError('')
    clearDeauthorizationSecrets()
    if (next) void load()
  }

  function changeDeauthorizeOpen(next: boolean): void {
    if (busy || submissionLease.current) return
    setDeauthorizeOpen(next)
    setDeauthorizeError('')
    setSuccess('')
    clearDeauthorizationSecrets()
  }

  async function submitDeauthorization(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (busy || !masterPassword || confirmation !== DEAUTHORIZE_SESSIONS_CONFIRMATION) {
      return
    }
    const request: DeauthorizeSessionsRequest = {
      masterPassword,
      confirmation: DEAUTHORIZE_SESSIONS_CONFIRMATION,
      confirm: true
    }
    let acquired = false
    try {
      acquired = await executeDeauthorizeSessions({
        lease: submissionLease,
        request,
        deauthorize: (deauthorizeRequest) =>
          window.bearwarden.accountSecurity.deauthorizeSessions(deauthorizeRequest),
        onAcquired: () => {
          acquired = true
          setBusy(true)
          setError('')
          setSuccess('')
          setDeauthorizeError('')
          clearDeauthorizationSecrets()
        }
      })
      if (!acquired) return
      setDeauthorizeOpen(false)
      setResult(null)
      setSuccess('已送出取消要求。目前裝置也必須重新登入才能繼續同步。')
    } catch (deauthorizeFailure) {
      if (!acquired) return
      setDeauthorizeError(deauthorizeSessionsError(deauthorizeFailure))
    } finally {
      clearDeauthorizationSecrets()
      if (acquired) setBusy(false)
    }
  }

  return (
    <>
      <Dialog open={open} onOpenChange={changeOpen}>
        <DialogTrigger
          render={<Button className="w-full" variant="outline" size="sm" type="button" />}
        >
          <Laptop data-icon="inline-start" aria-hidden="true" />
          帳號裝置
        </DialogTrigger>
        <DialogContent
          className="max-h-[min(42rem,calc(100vh-2rem))] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-lg"
          forceOverlay
        >
          <DialogHeader>
            <DialogTitle>帳號裝置</DialogTitle>
            <DialogDescription>
              顯示伺服器上的裝置活動與信任狀態，並可取消所有工作階段。不會顯示裝置識別碼或網路資訊。
            </DialogDescription>
          </DialogHeader>
          <div className="scroll-fade-y forced-colors:scroll-fade-none -mx-4 min-h-0 overflow-y-auto px-4">
            <div className="flex flex-col gap-4 pb-1">
              {pendingApprovals.length > 0 && (
                <section className="grid gap-3 rounded-lg border p-3">
                  <div>
                    <h3 className="font-medium">待處理登入要求</h3>
                    <p className="text-muted-foreground text-sm">
                      僅允許你本人剛在另一部裝置發出的要求，並先核對驗證詞組。
                    </p>
                  </div>
                  {pendingApprovals.map((approval) => (
                    <div
                      key={approval.token}
                      className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-2"
                    >
                      <div className="text-sm">
                        <p className="font-medium">{approval.requestDeviceType || '未知裝置'}</p>
                        <p className="text-muted-foreground">
                          {formatDeviceDate(approval.createdAt)}
                        </p>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        type="button"
                        disabled={busy}
                        onClick={() => {
                          setOpen(false)
                          setSelectedApproval(approval)
                        }}
                      >
                        檢視要求
                      </Button>
                    </div>
                  ))}
                </section>
              )}
              {busy && result === null ? (
                <div
                  className="text-muted-foreground flex items-center gap-2 text-sm"
                  role="status"
                >
                  <Spinner aria-hidden="true" />
                  正在讀取裝置…
                </div>
              ) : result?.status === 'unavailable' ? (
                <Alert>
                  <AlertDescription>目前的伺服器不支援帳號裝置清單。</AlertDescription>
                </Alert>
              ) : result?.status === 'available' && result.devices.length === 0 ? (
                <p className="text-muted-foreground text-sm">伺服器沒有回傳任何帳號裝置。</p>
              ) : result?.status === 'available' ? (
                <div className="grid gap-3">
                  {result.devices.map((device, index) => (
                    <section
                      key={`${device.name}-${device.createdAt}-${index}`}
                      className="grid gap-3 rounded-lg border p-3"
                    >
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <div>
                          <h3 className="font-medium">{device.name}</h3>
                          <p className="text-muted-foreground text-sm">
                            {deviceTypeNames[device.type] ?? `未知裝置類型（${device.type}）`}
                          </p>
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {device.current && <Badge>此裝置</Badge>}
                          <Badge variant="outline">{device.trusted ? '已信任' : '未信任'}</Badge>
                          {device.pendingAuthRequest && <Badge variant="secondary">待確認</Badge>}
                        </div>
                      </div>
                      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
                        <dt className="text-muted-foreground">建立時間</dt>
                        <dd>{formatDeviceDate(device.createdAt)}</dd>
                        <dt className="text-muted-foreground">最近活動</dt>
                        <dd>{formatDeviceDate(device.lastActivityAt)}</dd>
                        <dt className="text-muted-foreground">目前裝置</dt>
                        <dd>{device.current ? '是' : '否'}</dd>
                        <dt className="text-muted-foreground">信任狀態</dt>
                        <dd>{device.trusted ? '已信任' : '未信任'}</dd>
                        <dt className="text-muted-foreground">待處理登入要求</dt>
                        <dd>{device.pendingAuthRequest ? '有' : '無'}</dd>
                      </dl>
                    </section>
                  ))}
                </div>
              ) : null}
              {error && (
                <Alert variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
              {success && (
                <Alert>
                  <AlertDescription>{success}</AlertDescription>
                </Alert>
              )}
              {deauthorizeOpen ? (
                <form
                  className="grid gap-4"
                  onSubmit={(event) => void submitDeauthorization(event)}
                >
                  <DeauthorizeSessionsForm
                    masterPassword={masterPassword}
                    confirmation={confirmation}
                    busy={busy}
                    error={deauthorizeError}
                    onMasterPasswordChange={setMasterPassword}
                    onConfirmationChange={setConfirmation}
                    onCancel={() => changeDeauthorizeOpen(false)}
                  />
                </form>
              ) : (
                <div className="grid gap-2 rounded-lg border p-3">
                  <div>
                    <h3 className="font-medium">取消所有工作階段</h3>
                    <p className="text-muted-foreground text-sm">
                      強制這個帳號的所有裝置重新登入，不會刪除本機加密 vault。
                    </p>
                  </div>
                  <Button
                    className="justify-self-start"
                    variant="destructive"
                    type="button"
                    disabled={busy || Boolean(success)}
                    onClick={() => changeDeauthorizeOpen(true)}
                  >
                    <LogOut data-icon="inline-start" aria-hidden="true" />
                    開始取消工作階段
                  </Button>
                </div>
              )}
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="secondary"
              type="button"
              disabled={busy}
              onClick={() => changeOpen(false)}
            >
              關閉
            </Button>
            {!deauthorizeOpen && (
              <Button
                variant="outline"
                type="button"
                disabled={busy || Boolean(success)}
                onClick={() => void load()}
              >
                {busy ? (
                  <Spinner data-icon="inline-start" aria-hidden="true" />
                ) : (
                  <RefreshCw data-icon="inline-start" aria-hidden="true" />
                )}
                重新整理
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {selectedApproval && (
        <LoginApprovalDialog
          key={selectedApproval.token}
          prompt={selectedApproval}
          onClose={() => setSelectedApproval(null)}
        />
      )}
    </>
  )
}

export default AccountDevicesDialog
