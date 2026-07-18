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
import { useEffect, useState } from 'react'
import type {
  AccountSecurityProfile,
  SyncErrorCode,
  SyncInvalidResponseStage,
  SyncResult,
  SyncStatus
} from '../../../shared/vault-contract'
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
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import { Badge } from '@renderer/components/ui/badge'
import { Button } from '@renderer/components/ui/button'
import { Checkbox } from '@renderer/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from '@renderer/components/ui/dialog'
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel
} from '@renderer/components/ui/field'
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
import { Separator } from '@renderer/components/ui/separator'
import AccountApiKeyDialog from './AccountApiKeyDialog'
import AccountDevicesDialog from './AccountDevicesDialog'
import AccountProfileCard from './AccountProfileCard'
import AccountTwoFactorDialog from './AccountTwoFactorDialog'
import { PendingImportWarning } from './PendingImportWarning'
import {
  buildSyncTwoFactorRequest,
  WEB_AUTHN_TWO_FACTOR_METHOD,
  type SyncTwoFactorFormMethod
} from './sync-two-factor-request'

const BITWARDEN_CLOUD_URL = 'https://bitwarden.com'

// Exported solely for the account-switch race regression test.
// eslint-disable-next-line react-refresh/only-export-components
export function accountProfileIdentity(serverUrl?: string, email?: string): string {
  return `${serverUrl ?? ''}\0${email?.toLowerCase() ?? ''}`
}

// eslint-disable-next-line react-refresh/only-export-components
export function shouldAcceptAccountProfile(
  responseIdentity: string,
  currentIdentity: string
): boolean {
  return responseIdentity === currentIdentity
}

interface AccountProfileState {
  owner: string
  profile: AccountSecurityProfile | null
}

// Keep the current account card mounted while a sync refresh is in flight.
// eslint-disable-next-line react-refresh/only-export-components
export function accountProfileStateForStatus(
  current: AccountProfileState,
  identity: string,
  state: SyncStatus['state']
): AccountProfileState {
  if (current.owner !== identity) return { owner: identity, profile: null }
  if (state === 'ready' || state === 'syncing') return current
  return { owner: identity, profile: null }
}

// eslint-disable-next-line react-refresh/only-export-components
export function applyAccountProfileIfCurrent(
  current: AccountProfileState,
  responseIdentity: string,
  profile: AccountSecurityProfile
): AccountProfileState {
  return shouldAcceptAccountProfile(responseIdentity, current.owner)
    ? { owner: current.owner, profile }
    : current
}

const twoFactorMethods: { label: string; value: SyncTwoFactorFormMethod }[] = [
  { label: '驗證器應用程式', value: '0' },
  { label: '電子郵件', value: '1' },
  { label: 'YubiKey OTP', value: '3' },
  { label: '安全金鑰', value: WEB_AUTHN_TWO_FACTOR_METHOD }
]

interface SyncDialogProps {
  status: SyncStatus
  onClose: () => void
  onStatusChange: (status: SyncStatus) => void
  onSynced: () => Promise<void>
}

function describeSyncError(error: unknown): string {
  if (!(error instanceof Error)) return '同步未完成，請稍後再試。'
  if (/(?:CANCEL|ABORT)/i.test(error.message)) return '操作已取消。'
  if (error.message.includes('NEW_DEVICE_REQUIRED'))
    return '伺服器要求新裝置驗證碼。請從 Bitwarden 寄送的郵件取得驗證碼後，在進階選項輸入。'
  if (error.message.includes('AUTH_REQUIRED')) return 'Bitwarden 保管庫需要重新登入或解鎖。'
  if (error.message.includes('UNSUPPORTED_ACCOUNT'))
    return '此帳號使用尚未支援的新版帳號加密或登入方式；為避免資料損毀，BearWarden 不會進行任何遠端寫入。'
  if (error.message.includes('SYNC_NETWORK'))
    return '無法連線到同步伺服器。請檢查網路、伺服器網址與 TLS 憑證後再試。'
  if (error.message.includes('SYNC_INVALID_RESPONSE'))
    return '伺服器回傳了 BearWarden 無法安全處理的資料。請確認伺服器版本與相容性。'
  if (error.message.includes('SYNC_INVALID_SSH_KEY'))
    return '伺服器包含一筆不完整的 SSH Key。請先使用 Bitwarden 或 Vaultwarden 修復或刪除該項目。'
  if (error.message.includes('SYNC_CONFLICT'))
    return '遠端資料已變更，這次同步未套用。請重新同步以取得最新版本。'
  if (error.message.includes('LOCKED')) return '保管庫已鎖定，請輸入主密碼後再試。'
  if (error.message.includes('INVALID_MASTER_PASSWORD')) return '主密碼不正確。'
  if (error.message.includes('TWO_FACTOR')) return '雙重驗證無效、已過期或已取消，請重新嘗試。'
  if (error.message.includes('INVALID_URL')) return '請輸入有效的 HTTPS 伺服器網址。'
  return '同步未完成，請檢查連線與登入資訊後再試。'
}

export interface SyncErrorPresentation {
  title: string
  description: string
}

// eslint-disable-next-line react-refresh/only-export-components
export function syncInvalidResponseStageLabel(stage: SyncInvalidResponseStage): string {
  switch (stage) {
    case 'response':
      return '伺服器同步回應'
    case 'account':
      return '帳號與加密資訊'
    case 'organization':
      return '組織金鑰與成員資料'
    case 'folder':
      return '資料夾資料'
    case 'cipher':
      return '保管庫項目資料'
    case 'collection':
      return '組織集合關聯'
    case 'send':
      return 'Send 資料'
    case 'snapshot':
      return '同步狀態提交'
  }
}

// eslint-disable-next-line react-refresh/only-export-components
export function syncErrorPresentation(code: SyncErrorCode): SyncErrorPresentation {
  switch (code) {
    case 'SYNC_AUTH_REQUIRED':
      return {
        title: '登入已失效',
        description: '請重新輸入主密碼；如果伺服器要求，也請完成雙重驗證。'
      }
    case 'SYNC_NEW_DEVICE_REQUIRED':
      return {
        title: '需要新裝置驗證碼',
        description: '請從 Bitwarden 寄送的郵件取得驗證碼，並在進階選項中輸入。'
      }
    case 'SYNC_UNSUPPORTED_ACCOUNT':
      return {
        title: '不支援此帳號的加密方式',
        description: '為避免資料損毀，BearWarden 已停止遠端寫入。請更新應用程式後再試。'
      }
    case 'SYNC_NETWORK':
      return {
        title: '無法連線到同步伺服器',
        description: '請檢查網路、伺服器網址與 TLS 憑證，並確認伺服器目前可連線。'
      }
    case 'SYNC_INVALID_RESPONSE':
      return {
        title: '伺服器回應不相容',
        description: '伺服器回傳的資料無法安全處理。請確認 Bitwarden 或 Vaultwarden 版本與相容性。'
      }
    case 'SYNC_INVALID_SSH_KEY':
      return {
        title: '伺服器包含不完整的 SSH Key',
        description:
          'Vaultwarden 回傳了一筆缺少必要金鑰欄位的 SSH Key。請先使用官方 Web Vault 修復或刪除該項目，再重新同步。'
      }
    case 'SYNC_CONFLICT':
      return {
        title: '遠端資料已變更',
        description: '這次變更未套用。請再次同步以取得最新版本後重試。'
      }
    case 'SYNC_FAILED':
      return {
        title: '同步程序未完成',
        description: '請再試一次；如果問題持續發生，請記下下方錯誤代碼以便診斷。'
      }
  }
}

export function SyncFailureAlert({
  code,
  detail
}: {
  code: SyncErrorCode
  detail?: SyncInvalidResponseStage
}): React.JSX.Element {
  const presentation = syncErrorPresentation(code)
  return (
    <Alert variant="destructive">
      <CircleAlert aria-hidden="true" />
      <AlertTitle>{presentation.title}</AlertTitle>
      <AlertDescription className="flex flex-col gap-1">
        <span>{presentation.description}</span>
        {code === 'SYNC_INVALID_RESPONSE' && detail && (
          <small>問題區段：{syncInvalidResponseStageLabel(detail)}</small>
        )}
        <small>錯誤代碼：{code}</small>
      </AlertDescription>
    </Alert>
  )
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
  const [twoFactorMethod, setTwoFactorMethod] = useState<SyncTwoFactorFormMethod>('0')
  const [twoFactorCode, setTwoFactorCode] = useState('')
  const [webAuthnRemember, setWebAuthnRemember] = useState(false)
  const [newDeviceOtp, setNewDeviceOtp] = useState('')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [confirmingDisconnect, setConfirmingDisconnect] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [accountProfileState, setAccountProfileState] = useState<AccountProfileState>({
    owner: '',
    profile: null
  })
  const [accountSecurityError, setAccountSecurityError] = useState('')
  const [accountSecurityBusy, setAccountSecurityBusy] = useState(false)

  const configured = status.configured
  const requiresCredentials =
    !configured ||
    status.state === 'locked' ||
    status.lastError === 'SYNC_AUTH_REQUIRED' ||
    status.lastError === 'SYNC_NEW_DEVICE_REQUIRED'
  const isSyncing = busy || status.state === 'syncing'
  const currentAccountProfileIdentity = accountProfileIdentity(status.serverUrl, status.email)
  const visibleAccountProfile =
    accountProfileState.owner === currentAccountProfileIdentity ? accountProfileState.profile : null

  useEffect(() => {
    let active = true
    void Promise.resolve().then(async () => {
      if (!active) return
      setAccountProfileState((current) =>
        accountProfileStateForStatus(current, currentAccountProfileIdentity, status.state)
      )
      setAccountSecurityError('')
      if (status.state !== 'ready') {
        setAccountSecurityBusy(false)
        return
      }
      setAccountSecurityBusy(true)
      try {
        const profile = await window.bearwarden.accountSecurity.profile()
        if (active) {
          setAccountProfileState((current) =>
            applyAccountProfileIfCurrent(current, currentAccountProfileIdentity, profile)
          )
        }
      } catch {
        if (active) setAccountSecurityError('無法讀取帳號安全狀態。')
      } finally {
        if (active) setAccountSecurityBusy(false)
      }
    })
    return () => {
      active = false
    }
  }, [currentAccountProfileIdentity, status.state])

  async function resendVerification(): Promise<void> {
    setAccountSecurityBusy(true)
    setAccountSecurityError('')
    try {
      await window.bearwarden.accountSecurity.resendVerification()
      setSuccess('驗證信寄送要求已送出；若伺服器已設定郵件服務，請至信箱完成驗證。')
    } catch {
      setAccountSecurityError('無法寄送驗證信；請確認 Vaultwarden 已設定郵件服務。')
    } finally {
      setAccountSecurityBusy(false)
    }
  }

  function clearSecrets(): void {
    setMasterPassword('')
    setTwoFactorMethod('0')
    setTwoFactorCode('')
    setWebAuthnRemember(false)
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
        ...buildSyncTwoFactorRequest({ twoFactorMethod, twoFactorCode, webAuthnRemember })
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
        ...buildSyncTwoFactorRequest({ twoFactorMethod, twoFactorCode, webAuthnRemember })
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

  async function resolvePendingImport(): Promise<void> {
    if (!masterPassword) {
      setError('請輸入主密碼。')
      return
    }
    setBusy(true)
    setError('')
    setSuccess('')
    try {
      const nextStatus = await window.bearwarden.sync.resolvePendingImport({
        masterPassword,
        confirmRetry: true
      })
      onStatusChange(nextStatus)
      clearSecrets()
      setSuccess('已允許重新傳送。按「立即同步」開始重試。')
    } catch (resolveError) {
      setError(describeSyncError(resolveError))
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
                  ? status.lastErrorAt
                    ? `同步失敗：${formatSyncTime(status.lastErrorAt)}`
                    : '上次同步發生問題。'
                  : status.lastSyncAt
                    ? `上次同步：${formatSyncTime(status.lastSyncAt)}`
                    : '主密碼與驗證碼只用於本次操作，不會儲存在此裝置。'}
              </small>
            </div>
            {isSyncing && <Spinner aria-label="同步中" />}
          </Alert>

          {status.lastError && (
            <SyncFailureAlert code={status.lastError} detail={status.lastErrorDetail} />
          )}

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
                      onValueChange={(value) =>
                        setTwoFactorMethod(value as SyncTwoFactorFormMethod)
                      }
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
                  {twoFactorMethod === WEB_AUTHN_TWO_FACTOR_METHOD ? (
                    <Field orientation="horizontal" data-disabled={busy || undefined}>
                      <Checkbox
                        id="webauthn-remember"
                        checked={webAuthnRemember}
                        onCheckedChange={setWebAuthnRemember}
                        disabled={busy}
                      />
                      <FieldContent>
                        <FieldLabel htmlFor="webauthn-remember">記住這台裝置</FieldLabel>
                        <FieldDescription>讓伺服器在這台裝置上暫時略過雙重驗證。</FieldDescription>
                      </FieldContent>
                    </Field>
                  ) : (
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
                  )}
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
              {status.pendingImport && (
                <PendingImportWarning
                  count={status.pendingImport.count}
                  startedAt={status.pendingImport.startedAt}
                  masterPassword={masterPassword}
                  showPassword={showPassword}
                  busy={busy}
                  onMasterPasswordChange={setMasterPassword}
                  onTogglePassword={() => setShowPassword((visible) => !visible)}
                  onConfirm={() => void resolvePendingImport()}
                />
              )}
              {visibleAccountProfile && (
                <section
                  className="bg-card overflow-hidden rounded-xl border"
                  aria-label="帳號管理"
                >
                  <AccountProfileCard
                    key={currentAccountProfileIdentity}
                    profile={visibleAccountProfile}
                    onProfileChange={(profile) => {
                      setAccountProfileState((current) =>
                        applyAccountProfileIfCurrent(
                          current,
                          currentAccountProfileIdentity,
                          profile
                        )
                      )
                    }}
                  />
                  <Separator />
                  <div
                    className="flex flex-wrap items-center gap-2 px-4 py-3"
                    role="group"
                    aria-label="帳號安全狀態"
                  >
                    <ShieldCheck className="text-muted-foreground size-4" aria-hidden="true" />
                    <div className="flex min-w-0 flex-1 flex-wrap gap-2">
                      <Badge
                        variant={visibleAccountProfile.emailVerified ? 'secondary' : 'outline'}
                      >
                        Email {visibleAccountProfile.emailVerified ? '已驗證' : '尚未驗證'}
                      </Badge>
                      <Badge
                        variant={visibleAccountProfile.twoFactorEnabled ? 'secondary' : 'outline'}
                      >
                        雙重驗證
                        {visibleAccountProfile.twoFactorEnabled ? '已啟用' : '尚未啟用'}
                      </Badge>
                    </div>
                    {!visibleAccountProfile.emailVerified && (
                      <Button
                        variant="outline"
                        size="sm"
                        type="button"
                        disabled={accountSecurityBusy}
                        onClick={() => void resendVerification()}
                      >
                        {accountSecurityBusy && (
                          <Spinner data-icon="inline-start" aria-hidden="true" />
                        )}
                        重新寄送驗證信
                      </Button>
                    )}
                  </div>
                  <Separator />
                  <div className="grid grid-cols-1 gap-2 p-3 sm:grid-cols-3">
                    <AccountDevicesDialog />
                    <AccountApiKeyDialog />
                    <AccountTwoFactorDialog />
                  </div>
                </section>
              )}
              {accountSecurityError && (
                <Alert variant="destructive">
                  <AlertDescription>{accountSecurityError}</AlertDescription>
                </Alert>
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
