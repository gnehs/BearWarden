import {
  AlertTriangle,
  CheckCircle2,
  CircleAlert,
  Cloud,
  Eye,
  EyeOff,
  KeyRound,
  RefreshCw,
  Server,
  ShieldCheck,
  Unplug,
  X
} from 'lucide-react'
import { useState } from 'react'
import type { SyncResult, SyncStatus } from '../../../shared/vault-contract'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogMedia,
  AlertDialogTitle,
  AlertDialogTrigger
} from '@renderer/components/ui/alert-dialog'
import { Alert, AlertDescription } from '@renderer/components/ui/alert'
import { Button } from '@renderer/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from '@renderer/components/ui/dialog'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@renderer/components/ui/field'
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput
} from '@renderer/components/ui/input-group'
import { Input } from '@renderer/components/ui/input'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue
} from '@renderer/components/ui/select'
import { Spinner } from '@renderer/components/ui/spinner'

const BITWARDEN_CLOUD_URL = 'https://bitwarden.com'

type TwoFactorMethod = '0' | '1' | '3'

const twoFactorMethods: { label: string; value: TwoFactorMethod }[] = [
  { label: '驗證器應用程式', value: '0' },
  { label: '電子郵件', value: '1' },
  { label: 'YubiKey OTP', value: '3' }
]

interface SyncDialogProps {
  status: SyncStatus
  onClose: () => void
  onStatusChange: (status: SyncStatus) => void
  onSynced: () => Promise<void>
}

function describeSyncError(error: unknown): string {
  if (!(error instanceof Error)) return '同步未完成，請稍後再試。'
  if (error.message.includes('NEW_DEVICE_REQUIRED'))
    return '伺服器要求新裝置驗證碼。請從 Bitwarden 寄送的郵件取得驗證碼後，在進階選項輸入。'
  if (error.message.includes('AUTH_REQUIRED')) return 'Bitwarden 保管庫需要重新登入或解鎖。'
  if (error.message.includes('UNSUPPORTED_ACCOUNT'))
    return '此帳號使用尚未支援的新版帳號加密或登入方式；為避免資料損毀，BearWarden 不會進行任何遠端寫入。'
  if (error.message.includes('LOCKED')) return '保管庫已鎖定，請輸入主密碼後再試。'
  if (error.message.includes('TWO_FACTOR')) return '雙重驗證碼無效或已過期，請重新輸入。'
  if (error.message.includes('INVALID_URL')) return '請輸入有效的 HTTPS 伺服器網址。'
  return '同步未完成，請檢查連線與登入資訊後再試。'
}

function formatSyncTime(value?: string): string {
  if (!value) return '尚未同步'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '尚未同步'
  return new Intl.DateTimeFormat('zh-TW', { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}

function syncSummary(result: SyncResult): string {
  const { pulled, pushed, deleted, conflicts } = result
  const fragments = [`取得 ${pulled}`, `上傳 ${pushed}`, `刪除 ${deleted}`]
  if (conflicts) fragments.push(`衝突 ${conflicts}`)
  return fragments.join(' · ')
}

function SyncDialog({
  status,
  onClose,
  onStatusChange,
  onSynced
}: SyncDialogProps): React.JSX.Element {
  const [serverUrl, setServerUrl] = useState(status.serverUrl ?? BITWARDEN_CLOUD_URL)
  const [email, setEmail] = useState(status.email ?? '')
  const [masterPassword, setMasterPassword] = useState('')
  const [twoFactorMethod, setTwoFactorMethod] = useState<TwoFactorMethod>('0')
  const [twoFactorCode, setTwoFactorCode] = useState('')
  const [newDeviceOtp, setNewDeviceOtp] = useState('')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [confirmingDisconnect, setConfirmingDisconnect] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const configured = status.configured
  const requiresCredentials = !configured || status.state === 'locked'
  const isSyncing = busy || status.state === 'syncing'

  function clearSecrets(): void {
    setMasterPassword('')
    setTwoFactorCode('')
    setNewDeviceOtp('')
    setShowPassword(false)
  }

  function close(): void {
    if (busy) return
    clearSecrets()
    onClose()
  }

  function validateServerUrl(): string | null {
    try {
      const url = new URL(serverUrl.trim())
      if (url.protocol !== 'https:') return null
      return url.toString().replace(/\/$/, '')
    } catch {
      return null
    }
  }

  async function refreshAfterSuccess(result: SyncResult, message: string): Promise<void> {
    onStatusChange(result)
    clearSecrets()
    await onSynced()
    setSuccess(`${message} ${syncSummary(result)}。`)
  }

  async function connect(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    const normalizedUrl = validateServerUrl()
    if (!normalizedUrl) {
      setError('請輸入有效的 HTTPS 伺服器網址。')
      return
    }
    if (!email.trim() || !masterPassword) {
      setError('請輸入電子郵件與主密碼。')
      return
    }
    setBusy(true)
    setError('')
    setSuccess('')
    try {
      const result = await window.bearwarden.sync.connect({
        serverUrl: normalizedUrl,
        email: email.trim(),
        masterPassword,
        ...(newDeviceOtp.trim() ? { newDeviceOtp: newDeviceOtp.trim() } : {}),
        ...(twoFactorCode.trim() ? { twoFactorMethod, twoFactorCode: twoFactorCode.trim() } : {})
      })
      await refreshAfterSuccess(result, '已連線並完成同步。')
    } catch (connectError) {
      setError(describeSyncError(connectError))
    } finally {
      setBusy(false)
    }
  }

  async function unlock(): Promise<void> {
    if (!masterPassword) {
      setError('請輸入主密碼。')
      return
    }
    setBusy(true)
    setError('')
    setSuccess('')
    try {
      const nextStatus = await window.bearwarden.sync.unlock({
        masterPassword,
        ...(newDeviceOtp.trim() ? { newDeviceOtp: newDeviceOtp.trim() } : {}),
        ...(twoFactorCode.trim() ? { twoFactorMethod, twoFactorCode: twoFactorCode.trim() } : {})
      })
      onStatusChange(nextStatus)
      clearSecrets()
      const result = await window.bearwarden.sync.now()
      await refreshAfterSuccess(result, '已解鎖並完成同步。')
    } catch (unlockError) {
      setError(describeSyncError(unlockError))
    } finally {
      setBusy(false)
    }
  }

  async function syncNow(): Promise<void> {
    setBusy(true)
    setError('')
    setSuccess('')
    try {
      const result = await window.bearwarden.sync.now()
      await refreshAfterSuccess(result, '同步完成。')
    } catch (syncError) {
      setError(describeSyncError(syncError))
    } finally {
      setBusy(false)
    }
  }

  async function disconnect(): Promise<void> {
    setBusy(true)
    setError('')
    try {
      const nextStatus = await window.bearwarden.sync.disconnect()
      onStatusChange(nextStatus)
      clearSecrets()
      setConfirmingDisconnect(false)
      setSuccess('已中斷 Bitwarden 同步連線。')
    } catch (disconnectError) {
      setError(describeSyncError(disconnectError))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) close()
      }}
    >
      <DialogContent className="modal modal-card sync-dialog" showCloseButton={false}>
        <DialogHeader className="modal-header sync-dialog-header">
          <span
            className={`sync-dialog-icon ${status.state === 'error' ? 'error' : ''}`}
            aria-hidden="true"
          >
            {status.state === 'error' ? <CircleAlert /> : <Cloud />}
          </span>
          <div>
            <DialogTitle>Bitwarden 同步</DialogTitle>
            <DialogDescription>
              {configured
                ? '直接連線並加密同步你的保管庫。'
                : '連線 Bitwarden 雲端或你的 Vaultwarden 伺服器。'}
            </DialogDescription>
          </div>
          <Button
            variant="ghost"
            size="icon-sm"
            type="button"
            aria-label="關閉"
            onClick={close}
            disabled={busy}
          >
            <X aria-hidden="true" />
          </Button>
        </DialogHeader>

        <div className="modal-body sync-dialog-body">
          <Alert className="sync-status-card" role="status" aria-live="polite">
            <span
              className={`sync-status-indicator ${isSyncing ? 'syncing' : status.state}`}
              aria-hidden="true"
            />
            <div>
              <strong>
                {isSyncing
                  ? '正在同步…'
                  : status.state === 'ready'
                    ? '已連線，保管庫已解鎖'
                    : status.state === 'locked'
                      ? '已連線，保管庫已鎖定'
                      : status.state === 'error'
                        ? '需要處理同步問題'
                        : '尚未設定同步'}
              </strong>
              <small>
                {status.lastError
                  ? '上次同步發生問題。'
                  : status.lastSyncAt
                    ? `上次同步：${formatSyncTime(status.lastSyncAt)}`
                    : '主密碼與驗證碼只用於本次操作，不會儲存在此裝置。'}
              </small>
            </div>
            {isSyncing && <Spinner aria-label="同步中" />}
          </Alert>

          {requiresCredentials ? (
            <form
              className="sync-form"
              onSubmit={
                configured
                  ? (event) => {
                      event.preventDefault()
                      void unlock()
                    }
                  : connect
              }
            >
              <FieldGroup className="mx-[18px]">
                {!configured && (
                  <>
                    <Field className="field">
                      <FieldLabel htmlFor="server-url">伺服器網址</FieldLabel>
                      <Input
                        id="server-url"
                        autoFocus
                        type="url"
                        inputMode="url"
                        autoComplete="url"
                        value={serverUrl}
                        onChange={(event) => setServerUrl(event.target.value)}
                        placeholder={BITWARDEN_CLOUD_URL}
                        disabled={busy}
                        required
                      />
                      <FieldDescription>
                        Bitwarden 雲端請使用 bitwarden.com；Vaultwarden 請使用 HTTPS 網址。
                      </FieldDescription>
                    </Field>
                    <Field className="field">
                      <FieldLabel htmlFor="sync-email">電子郵件</FieldLabel>
                      <Input
                        id="sync-email"
                        type="email"
                        autoComplete="username"
                        value={email}
                        onChange={(event) => setEmail(event.target.value)}
                        disabled={busy}
                        required
                      />
                    </Field>
                  </>
                )}
                {configured && (
                  <Alert className="sync-account" role="status">
                    <ShieldCheck aria-hidden="true" />
                    <AlertDescription>{status.email ?? '已設定的帳號'}</AlertDescription>
                  </Alert>
                )}
                <Field className="field">
                  <FieldLabel htmlFor="sync-master-password">主密碼</FieldLabel>
                  <InputGroup>
                    <InputGroupInput
                      id="sync-master-password"
                      autoFocus={configured}
                      type={showPassword ? 'text' : 'password'}
                      autoComplete="current-password"
                      value={masterPassword}
                      onChange={(event) => setMasterPassword(event.target.value)}
                      disabled={busy}
                      required
                    />
                    <InputGroupAddon align="inline-end">
                      <InputGroupButton
                        size="icon-xs"
                        aria-label={showPassword ? '隱藏主密碼' : '顯示主密碼'}
                        aria-pressed={showPassword}
                        onClick={() => setShowPassword((visible) => !visible)}
                        disabled={busy}
                      >
                        {showPassword ? <EyeOff /> : <Eye />}
                      </InputGroupButton>
                    </InputGroupAddon>
                  </InputGroup>
                </Field>
              </FieldGroup>
              <Button
                className="sync-advanced-toggle"
                variant="ghost"
                type="button"
                aria-expanded={showAdvanced}
                onClick={() => setShowAdvanced((open) => !open)}
                disabled={busy}
              >
                {showAdvanced ? '隱藏進階選項' : '顯示雙重驗證'}
              </Button>
              {showAdvanced && (
                <FieldGroup className="sync-advanced-fields">
                  <Field>
                    <FieldLabel htmlFor="two-factor-method">雙重驗證方式（選填）</FieldLabel>
                    <Select
                      items={twoFactorMethods}
                      value={twoFactorMethod}
                      onValueChange={(value) => setTwoFactorMethod(value as TwoFactorMethod)}
                      disabled={busy}
                    >
                      <SelectTrigger id="two-factor-method" className="w-full">
                        <SelectValue placeholder="選擇驗證方式" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          {twoFactorMethods.map((method) => (
                            <SelectItem key={method.value} value={method.value}>
                              {method.label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="two-factor-code">雙重驗證碼（選填）</FieldLabel>
                    <Input
                      id="two-factor-code"
                      autoComplete="one-time-code"
                      autoCapitalize="none"
                      value={twoFactorCode}
                      onChange={(event) => setTwoFactorCode(event.target.value)}
                      disabled={busy}
                    />
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="new-device-otp">新裝置驗證碼（選填）</FieldLabel>
                    <Input
                      id="new-device-otp"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      value={newDeviceOtp}
                      onChange={(event) => setNewDeviceOtp(event.target.value)}
                      disabled={busy}
                    />
                    <FieldDescription>僅在 Bitwarden 要求驗證新裝置時使用。</FieldDescription>
                  </Field>
                </FieldGroup>
              )}
              {error && (
                <Alert className="form-error" variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
              {success && (
                <Alert className="sync-success" role="status">
                  <CheckCircle2 aria-hidden="true" />
                  <AlertDescription>{success}</AlertDescription>
                </Alert>
              )}
              <DialogFooter className="modal-actions sync-form-actions mx-0 mb-0">
                <Button variant="secondary" type="button" onClick={close} disabled={busy}>
                  取消
                </Button>
                <Button type="submit" disabled={isSyncing}>
                  {isSyncing && <Spinner data-icon="inline-start" aria-hidden="true" />}
                  {configured ? '解鎖並同步' : '連線並同步'}
                </Button>
              </DialogFooter>
            </form>
          ) : (
            <>
              <section className="sync-connection-details" aria-label="同步連線資訊">
                <div>
                  <Server aria-hidden="true" />
                  <span>伺服器</span>
                  <strong>{status.serverUrl ?? BITWARDEN_CLOUD_URL}</strong>
                </div>
                <div>
                  <KeyRound aria-hidden="true" />
                  <span>帳號</span>
                  <strong>{status.email ?? '未提供'}</strong>
                </div>
                <div>
                  <RefreshCw aria-hidden="true" />
                  <span>上次同步</span>
                  <strong>{formatSyncTime(status.lastSyncAt)}</strong>
                </div>
              </section>
              {error && (
                <Alert className="form-error" variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
              {success && (
                <Alert className="sync-success" role="status">
                  <CheckCircle2 aria-hidden="true" />
                  <AlertDescription>{success}</AlertDescription>
                </Alert>
              )}
              <DialogFooter className="modal-actions split -mx-[18px] mb-0">
                <AlertDialog
                  open={confirmingDisconnect}
                  onOpenChange={(open) => {
                    if (!busy) setConfirmingDisconnect(open)
                  }}
                >
                  <AlertDialogTrigger
                    render={<Button variant="ghost" type="button" disabled={isSyncing} />}
                  >
                    <Unplug data-icon="inline-start" aria-hidden="true" />
                    中斷連線
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogMedia>
                        <AlertTriangle aria-hidden="true" />
                      </AlertDialogMedia>
                      <AlertDialogTitle>中斷同步連線？</AlertDialogTitle>
                      <AlertDialogDescription>
                        這不會刪除本機保管庫，但之後不會再和 Bitwarden 同步。
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel disabled={busy}>返回</AlertDialogCancel>
                      <AlertDialogAction
                        variant="destructive"
                        type="button"
                        disabled={busy}
                        onClick={() => void disconnect()}
                      >
                        {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                        中斷連線
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
                <div className="action-group">
                  <Button variant="secondary" type="button" onClick={close} disabled={isSyncing}>
                    關閉
                  </Button>
                  <Button type="button" onClick={() => void syncNow()} disabled={isSyncing}>
                    {isSyncing && <Spinner data-icon="inline-start" aria-hidden="true" />}
                    立即同步
                  </Button>
                </div>
              </DialogFooter>
            </>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}

export default SyncDialog
