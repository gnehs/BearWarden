import { useCallback, useRef, useState } from 'react'
import { KeyRound, ShieldAlert, TriangleAlert } from 'lucide-react'
import type {
  MasterPasswordChangeState,
  MasterPasswordChangeStatus
} from '../../../shared/vault-contract'
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogMedia,
  AlertDialogTitle
} from '@renderer/components/ui/alert-dialog'
import { Button } from '@renderer/components/ui/button'
import { Checkbox } from '@renderer/components/ui/checkbox'
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger
} from '@renderer/components/ui/dialog'
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel
} from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import { Spinner } from '@renderer/components/ui/spinner'

const MIN_PASSWORD_LENGTH = 12
const MAX_PASSWORD_LENGTH = 1_024
const MAX_HINT_LENGTH = 50

interface MasterPasswordChangeDialogProps {
  onReconnect: () => void
}

function stateGuidance(state: MasterPasswordChangeState): {
  title: string
  description: string
} | null {
  if (state === 'completed') {
    return {
      title: '主密碼已變更',
      description: '遠端帳號與本機加密密碼庫已完成更新。請使用新主密碼重新連線。'
    }
  }
  if (state === 'remote-not-changed') {
    return {
      title: '伺服器確認主密碼尚未變更',
      description:
        '先前的不確定操作沒有改變遠端帳號。這不是重新嘗試；若要開始新的變更，請先明確確認並重新連線。'
    }
  }
  if (state === 'needs-reconnect') {
    return {
      title: '必須重新連線後才能確認',
      description:
        'BearWarden 無法在目前連線中安全判斷遠端結果。為避免重複變更，現在不會送出任何新操作。'
    }
  }
  if (state === 'indeterminate') {
    return {
      title: '遠端結果仍無法判定',
      description:
        '請停止操作並重新連線。確認帳號可使用哪一組主密碼登入前，不要再次送出主密碼變更。'
    }
  }
  return null
}

function operationForState(
  state: MasterPasswordChangeState | undefined
): 'change' | 'verify-remote' | 'resume-local' | 'blocked' {
  if (state === 'idle') return 'change'
  if (state === 'needs-remote-verification') return 'verify-remote'
  if (state === 'resume-required') return 'resume-local'
  return 'blocked'
}

function MasterPasswordChangeDialog({
  onReconnect
}: MasterPasswordChangeDialogProps): React.JSX.Element {
  const requestId = useRef(0)
  const [open, setOpen] = useState(false)
  const [status, setStatus] = useState<MasterPasswordChangeStatus | null>(null)
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState(false)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [acknowledgedRemoteNotChanged, setAcknowledgedRemoteNotChanged] = useState(false)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [hint, setHint] = useState('')
  const [error, setError] = useState('')

  const scrub = useCallback((): void => {
    setCurrentPassword('')
    setNewPassword('')
    setConfirmPassword('')
    setHint('')
  }, [])

  const loadStatus = useCallback(async (): Promise<void> => {
    const activeRequest = ++requestId.current
    setLoading(true)
    setError('')
    try {
      const next = await window.bearwarden.vault.masterPasswordChangeStatus()
      if (activeRequest === requestId.current) setStatus(next)
    } catch {
      if (activeRequest === requestId.current) {
        setStatus({ state: 'indeterminate', requiresReconnect: true })
        setError('無法安全讀取主密碼變更狀態。請重新連線後再檢查。')
      }
    } finally {
      if (activeRequest === requestId.current) setLoading(false)
    }
  }, [])

  function changeOpen(nextOpen: boolean): void {
    if (busy) return
    setOpen(nextOpen)
    setConfirmOpen(false)
    setAcknowledgedRemoteNotChanged(false)
    scrub()
    setError('')
    if (nextOpen) void loadStatus()
    else {
      requestId.current += 1
      setStatus(null)
    }
  }

  const operation = operationForState(status?.state)
  const verifyingRemote = operation === 'verify-remote'
  const resumingLocal = operation === 'resume-local'
  const recovery = verifyingRemote || resumingLocal
  const formAvailable = operation !== 'blocked'
  const normalizedCurrent = currentPassword.normalize('NFC')
  const normalizedNew = newPassword.normalize('NFC')
  const normalizedConfirmation = confirmPassword.normalize('NFC')

  function validate(): boolean {
    if (
      normalizedCurrent.length < MIN_PASSWORD_LENGTH ||
      normalizedCurrent.length > MAX_PASSWORD_LENGTH
    ) {
      setError('目前的主密碼必須是 12 到 1024 個字元。')
      return false
    }
    if (normalizedNew.length < MIN_PASSWORD_LENGTH || normalizedNew.length > MAX_PASSWORD_LENGTH) {
      setError('新主密碼必須是 12 到 1024 個字元。')
      return false
    }
    if (normalizedCurrent === normalizedNew) {
      setError('新主密碼必須和目前的主密碼不同。')
      return false
    }
    if (normalizedConfirmation !== normalizedNew) {
      setError('兩次輸入的新主密碼不一致。')
      return false
    }
    if (hint.normalize('NFC').length > MAX_HINT_LENGTH) {
      setError('主密碼提示最多 50 個字元。')
      return false
    }
    setError('')
    return true
  }

  function requestConfirmation(event: React.FormEvent<HTMLFormElement>): void {
    event.preventDefault()
    if (!formAvailable || busy || !validate()) return
    setConfirmOpen(true)
  }

  async function submitConfirmed(): Promise<void> {
    if (!formAvailable || busy) return
    setConfirmOpen(false)
    setBusy(true)
    const request = {
      currentPassword: normalizedCurrent,
      newPassword: normalizedNew,
      ...(verifyingRemote
        ? {}
        : { hint: resumingLocal ? null : hint.normalize('NFC').trim() || null })
    }
    try {
      const next = verifyingRemote
        ? await window.bearwarden.vault.resolveMasterPasswordChange(request)
        : await window.bearwarden.vault.changeMasterPassword(request)
      setStatus(next)
      setAcknowledgedRemoteNotChanged(false)
      setError('')
    } catch (submitError) {
      setError(
        submitError instanceof Error && submitError.message.includes('INVALID_MASTER_PASSWORD')
          ? '目前的主密碼驗證失敗。'
          : '無法安全完成主密碼變更。請重新開啟此畫面檢查交易狀態。'
      )
    } finally {
      request.currentPassword = ''
      request.newPassword = ''
      if ('hint' in request) request.hint = null
      scrub()
      setBusy(false)
    }
  }

  function reconnect(): void {
    scrub()
    setOpen(false)
    onReconnect()
  }

  const guidance = status ? stateGuidance(status.state) : null

  return (
    <>
      <Dialog open={open} onOpenChange={changeOpen}>
        <DialogTrigger render={<Button variant="outline" size="sm" type="button" />}>
          <KeyRound data-icon="inline-start" aria-hidden="true" />
          變更主密碼
        </DialogTrigger>
        <DialogContent className="sm:max-w-lg" showCloseButton={false}>
          <DialogHeader>
            <DialogTitle>變更主密碼</DialogTitle>
            <DialogDescription>
              更新 Vaultwarden／Bitwarden 帳號密碼與本機密碼庫解鎖密碼。
            </DialogDescription>
          </DialogHeader>

          {loading ? (
            <div className="flex items-center gap-2 py-6 text-sm" role="status">
              <Spinner /> 正在確認先前的變更狀態…
            </div>
          ) : (
            <div className="flex flex-col gap-4">
              <Alert>
                <ShieldAlert aria-hidden="true" />
                <AlertTitle>不會輪替帳號加密金鑰</AlertTitle>
                <AlertDescription>
                  此操作只變更主密碼與保護方式，不會建立新的帳號加密金鑰。完成後 Touch ID
                  會停用，且必須使用新主密碼重新連線。
                </AlertDescription>
              </Alert>

              {verifyingRemote && (
                <Alert>
                  <TriangleAlert aria-hidden="true" />
                  <AlertTitle>確認遠端結果並恢復既有變更</AlertTitle>
                  <AlertDescription>
                    請輸入原本的舊主密碼與當時設定的新主密碼。這只會確認遠端狀態並完成本機恢復，不會重新送出主密碼變更。
                  </AlertDescription>
                </Alert>
              )}

              {resumingLocal && (
                <Alert>
                  <TriangleAlert aria-hidden="true" />
                  <AlertTitle>完成已由遠端確認的本機變更</AlertTitle>
                  <AlertDescription>
                    遠端主密碼已確認變更。請輸入變更前的舊主密碼與當時設定的新主密碼，讓 BearWarden
                    完成本機密碼庫重新加密；交易紀錄會阻止再次送出遠端變更。
                  </AlertDescription>
                </Alert>
              )}

              {guidance && (
                <Alert variant={status?.state === 'completed' ? 'default' : 'destructive'}>
                  <TriangleAlert aria-hidden="true" />
                  <AlertTitle>{guidance.title}</AlertTitle>
                  <AlertDescription>{guidance.description}</AlertDescription>
                </Alert>
              )}

              {status?.state === 'remote-not-changed' && (
                <Field orientation="horizontal">
                  <Checkbox
                    id="master-password-remote-not-changed-ack"
                    checked={acknowledgedRemoteNotChanged}
                    onCheckedChange={(checked) => setAcknowledgedRemoteNotChanged(checked === true)}
                  />
                  <FieldContent>
                    <FieldLabel htmlFor="master-password-remote-not-changed-ack">
                      我了解先前操作未變更遠端主密碼
                    </FieldLabel>
                    <FieldDescription>
                      確認後會前往重新連線；重新連線完成後，才能開始一筆全新的主密碼變更。
                    </FieldDescription>
                  </FieldContent>
                </Field>
              )}

              {formAvailable && (
                <form onSubmit={requestConfirmation}>
                  <FieldGroup>
                    <Field data-invalid={Boolean(error)}>
                      <FieldLabel htmlFor="master-password-current">
                        {recovery ? '變更前的舊主密碼' : '目前的主密碼'}
                      </FieldLabel>
                      <Input
                        id="master-password-current"
                        type="password"
                        autoComplete="current-password"
                        autoFocus
                        value={currentPassword}
                        disabled={busy}
                        minLength={MIN_PASSWORD_LENGTH}
                        maxLength={MAX_PASSWORD_LENGTH}
                        aria-invalid={Boolean(error)}
                        onChange={(event) => setCurrentPassword(event.target.value)}
                      />
                    </Field>
                    <Field data-invalid={Boolean(error)}>
                      <FieldLabel htmlFor="master-password-new">
                        {recovery ? '當時設定的新主密碼' : '新主密碼'}
                      </FieldLabel>
                      <Input
                        id="master-password-new"
                        type="password"
                        autoComplete="new-password"
                        value={newPassword}
                        disabled={busy}
                        minLength={MIN_PASSWORD_LENGTH}
                        maxLength={MAX_PASSWORD_LENGTH}
                        aria-invalid={Boolean(error)}
                        onChange={(event) => setNewPassword(event.target.value)}
                      />
                      <FieldDescription>
                        至少 12 個字元；請妥善保存，BearWarden 無法復原。
                      </FieldDescription>
                    </Field>
                    <Field data-invalid={Boolean(error)}>
                      <FieldLabel htmlFor="master-password-confirm">再次輸入新主密碼</FieldLabel>
                      <Input
                        id="master-password-confirm"
                        type="password"
                        autoComplete="new-password"
                        value={confirmPassword}
                        disabled={busy}
                        minLength={MIN_PASSWORD_LENGTH}
                        maxLength={MAX_PASSWORD_LENGTH}
                        aria-invalid={Boolean(error)}
                        onChange={(event) => setConfirmPassword(event.target.value)}
                      />
                    </Field>
                    {!recovery && (
                      <Field data-invalid={hint.normalize('NFC').length > MAX_HINT_LENGTH}>
                        <FieldLabel htmlFor="master-password-hint">主密碼提示（選填）</FieldLabel>
                        <Input
                          id="master-password-hint"
                          value={hint}
                          disabled={busy}
                          maxLength={MAX_HINT_LENGTH}
                          aria-invalid={hint.normalize('NFC').length > MAX_HINT_LENGTH}
                          onChange={(event) => setHint(event.target.value)}
                        />
                        <FieldDescription>最多 50 個字元；請勿直接填入主密碼。</FieldDescription>
                      </Field>
                    )}
                    {error && <FieldError>{error}</FieldError>}
                    <Button type="submit" disabled={busy}>
                      {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                      {verifyingRemote
                        ? '確認遠端結果'
                        : resumingLocal
                          ? '完成本機變更'
                          : '檢查並繼續'}
                    </Button>
                  </FieldGroup>
                </form>
              )}

              {!formAvailable && error && <FieldError>{error}</FieldError>}
            </div>
          )}

          <DialogFooter>
            <DialogClose render={<Button variant="outline" type="button" disabled={busy} />}>
              關閉
            </DialogClose>
            {status?.requiresReconnect && (
              <Button
                type="button"
                disabled={
                  busy || (status.state === 'remote-not-changed' && !acknowledgedRemoteNotChanged)
                }
                onClick={reconnect}
              >
                前往重新連線
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={confirmOpen} onOpenChange={(next) => !busy && setConfirmOpen(next)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogMedia>
              <KeyRound aria-hidden="true" />
            </AlertDialogMedia>
            <AlertDialogTitle>
              {verifyingRemote
                ? '確認遠端主密碼結果？'
                : resumingLocal
                  ? '完成已確認的本機主密碼變更？'
                  : '確定要變更主密碼？'}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {verifyingRemote
                ? '這會使用你輸入的舊、新主密碼確認遠端結果並完成本機恢復，不會重新送出變更。'
                : resumingLocal
                  ? '遠端變更已經確認。這只會完成本機密碼庫重新加密；交易紀錄會阻止遠端變更被重送。'
                  : '這會更新遠端帳號密碼與本機加密密碼庫。帳號加密金鑰不會輪替；完成後必須重新連線。'}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>返回檢查</AlertDialogCancel>
            <AlertDialogAction disabled={busy} onClick={() => void submitConfirmed()}>
              {verifyingRemote ? '確認遠端結果' : resumingLocal ? '完成本機變更' : '變更主密碼'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

export default MasterPasswordChangeDialog
