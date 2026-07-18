import { useRef, useState, type FormEvent, type MutableRefObject } from 'react'
import { Eye, EyeOff, Trash2, TriangleAlert } from 'lucide-react'
import type {
  SyncPurgePersonalVaultRequest,
  SyncPurgePersonalVaultResult,
  SyncStatus
} from '../../../shared/vault-contract'
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogMedia,
  AlertDialogTitle,
  AlertDialogTrigger
} from '@renderer/components/ui/alert-dialog'
import { Button } from '@renderer/components/ui/button'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@renderer/components/ui/field'
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput
} from '@renderer/components/ui/input-group'
import { Spinner } from '@renderer/components/ui/spinner'

type PendingPurge = NonNullable<SyncStatus['pendingPurge']>

function personalVaultPurgeActionLabel(pending: boolean): string {
  return pending ? '再次清除剩餘項目' : '永久清除個人密碼庫'
}

interface PersonalVaultPurgeExecutionOptions {
  lease: MutableRefObject<boolean>
  request: SyncPurgePersonalVaultRequest
  purge: (request: SyncPurgePersonalVaultRequest) => Promise<SyncPurgePersonalVaultResult>
  refresh: () => void | Promise<void>
  onAcquired: () => void
}

/** The ref-backed lease closes React's same-render double-submit window before the first await. */
// eslint-disable-next-line react-refresh/only-export-components
export async function executePersonalVaultPurge({
  lease,
  request,
  purge,
  refresh,
  onAcquired
}: PersonalVaultPurgeExecutionOptions): Promise<
  { acquired: false } | { acquired: true; result: SyncPurgePersonalVaultResult }
> {
  if (lease.current) {
    request.masterPassword = ''
    ;(request as { confirmation: string }).confirmation = ''
    return { acquired: false }
  }
  lease.current = true
  const refreshBestEffort = async (): Promise<void> => {
    try {
      await refresh()
    } catch {
      // Refresh is advisory and must never replace the authoritative purge outcome.
    }
  }
  try {
    onAcquired()
    let result: SyncPurgePersonalVaultResult
    try {
      result = await purge(request)
    } catch (cause) {
      await refreshBestEffort()
      throw cause
    }
    await refreshBestEffort()
    return { acquired: true, result }
  } finally {
    request.masterPassword = ''
    ;(request as { confirmation: string }).confirmation = ''
    lease.current = false
  }
}

interface PersonalVaultPurgeFormProps {
  pendingPurge?: PendingPurge
  masterPassword: string
  confirmation: string
  showPassword: boolean
  busy: boolean
  error: string
  onMasterPasswordChange: (value: string) => void
  onConfirmationChange: (value: string) => void
  onTogglePassword: () => void
}

export function PersonalVaultPurgeForm({
  pendingPurge,
  masterPassword,
  confirmation,
  showPassword,
  busy,
  error,
  onMasterPasswordChange,
  onConfirmationChange,
  onTogglePassword
}: PersonalVaultPurgeFormProps): React.JSX.Element {
  return (
    <div className="grid gap-4">
      <Alert variant="destructive">
        <TriangleAlert aria-hidden="true" />
        <AlertTitle>這項操作無法復原</AlertTitle>
        <AlertDescription>
          會永久刪除伺服器上的所有個人物件、資料夾與附件，包含垃圾桶與封存項目。共享組織的項目會保留。建議先匯出備份。
        </AlertDescription>
      </Alert>
      {pendingPurge && (
        <Alert variant="destructive">
          <AlertTitle>上次清除的結果未知</AlertTitle>
          <AlertDescription>
            伺服器仍有 {pendingPurge.remainingItems} 個個人物件與 {pendingPurge.remainingFolders}{' '}
            個資料夾。BearWarden 不會自動重送；再次操作只會清除剩餘資料。
          </AlertDescription>
        </Alert>
      )}
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor="purge-personal-vault-password">遠端主密碼</FieldLabel>
          <InputGroup>
            <InputGroupInput
              id="purge-personal-vault-password"
              type={showPassword ? 'text' : 'password'}
              autoComplete="current-password"
              maxLength={1024}
              value={masterPassword}
              disabled={busy}
              autoFocus
              onChange={(event) => onMasterPasswordChange(event.target.value)}
            />
            <InputGroupAddon align="inline-end">
              <InputGroupButton
                aria-label={showPassword ? '隱藏主密碼' : '顯示主密碼'}
                disabled={busy}
                onClick={onTogglePassword}
              >
                {showPassword ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
              </InputGroupButton>
            </InputGroupAddon>
          </InputGroup>
          <FieldDescription>每次嘗試都必須重新輸入，且只用於這一次遠端驗證。</FieldDescription>
        </Field>
        <Field>
          <FieldLabel htmlFor="purge-personal-vault-confirmation">輸入 PURGE 確認</FieldLabel>
          <InputGroup>
            <InputGroupInput
              id="purge-personal-vault-confirmation"
              type="text"
              autoComplete="off"
              maxLength={5}
              value={confirmation}
              disabled={busy}
              spellCheck={false}
              onChange={(event) => onConfirmationChange(event.target.value)}
            />
          </InputGroup>
          <FieldDescription>必須完全符合大寫 PURGE。</FieldDescription>
        </Field>
      </FieldGroup>
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
    </div>
  )
}

interface PersonalVaultPurgeDialogProps {
  pendingPurge?: PendingPurge
  disabled?: boolean
  onVaultChanged?: () => void | Promise<void>
}

function PersonalVaultPurgeDialog({
  pendingPurge,
  disabled = false,
  onVaultChanged
}: PersonalVaultPurgeDialogProps): React.JSX.Element {
  const [open, setOpen] = useState(false)
  const [masterPassword, setMasterPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [latestPending, setLatestPending] = useState<PendingPurge | undefined>()
  const submissionLease = useRef(false)
  const visiblePending = latestPending ?? pendingPurge

  function clearSecrets(): void {
    setMasterPassword('')
    setConfirmation('')
    setShowPassword(false)
  }

  function changeOpen(nextOpen: boolean): void {
    if (busy || submissionLease.current) return
    setOpen(nextOpen)
    setError('')
    clearSecrets()
    if (!nextOpen) setLatestPending(undefined)
  }

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (busy || !masterPassword || confirmation !== 'PURGE') return
    const request = { masterPassword, confirmation: 'PURGE' as const, confirmPurge: true as const }
    let acquired = false
    try {
      const execution = await executePersonalVaultPurge({
        lease: submissionLease,
        request,
        purge: (candidate) => window.bearwarden.sync.purgePersonalVault(candidate),
        refresh: () => onVaultChanged?.(),
        onAcquired: () => {
          acquired = true
          clearSecrets()
          setError('')
          setBusy(true)
        }
      })
      if (!execution.acquired) return
      const { result } = execution
      if (result.status === 'complete') {
        setOpen(false)
        setLatestPending(undefined)
      } else {
        setLatestPending({
          startedAt: result.startedAt,
          remainingItems: result.remainingItems,
          remainingFolders: result.remainingFolders
        })
      }
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : ''
      setError(
        /INVALID_MASTER_PASSWORD|USER_VERIFICATION_FAILED/u.test(message)
          ? '遠端主密碼驗證失敗。'
          : '無法確認清除結果。請先重新同步確認剩餘資料；BearWarden 不會自動重送。'
      )
    } finally {
      if (acquired) setBusy(false)
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={changeOpen}>
      <AlertDialogTrigger
        render={
          <Button variant="destructive" size="sm" type="button" disabled={disabled || busy} />
        }
      >
        <Trash2 data-icon="inline-start" aria-hidden="true" />
        {visiblePending ? '處理未完成的清除' : '清除個人密碼庫'}
      </AlertDialogTrigger>
      <AlertDialogContent>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <AlertDialogHeader>
            <AlertDialogMedia>
              <TriangleAlert aria-hidden="true" />
            </AlertDialogMedia>
            <AlertDialogTitle>永久清除個人密碼庫？</AlertDialogTitle>
            <AlertDialogDescription>
              這只清除目前同步帳號的個人資料，不會刪除共享組織項目。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <PersonalVaultPurgeForm
            pendingPurge={visiblePending}
            masterPassword={masterPassword}
            confirmation={confirmation}
            showPassword={showPassword}
            busy={busy}
            error={error}
            onMasterPasswordChange={setMasterPassword}
            onConfirmationChange={setConfirmation}
            onTogglePassword={() => setShowPassword((value) => !value)}
          />
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>返回</AlertDialogCancel>
            <Button
              type="submit"
              variant="destructive"
              disabled={busy || !masterPassword || confirmation !== 'PURGE'}
            >
              {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
              {personalVaultPurgeActionLabel(visiblePending !== undefined)}
            </Button>
          </AlertDialogFooter>
        </form>
      </AlertDialogContent>
    </AlertDialog>
  )
}

export default PersonalVaultPurgeDialog
