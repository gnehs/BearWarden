import { Copy, KeyRound, RotateCw } from 'lucide-react'
import { useState } from 'react'
import { Alert, AlertDescription } from '@renderer/components/ui/alert'
import { Button } from '@renderer/components/ui/button'
import { Checkbox } from '@renderer/components/ui/checkbox'
import {
  Dialog,
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
  FieldLabel,
  FieldTitle
} from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import { Spinner } from '@renderer/components/ui/spinner'

function apiKeyError(error: unknown, rotate: boolean): string {
  if (!(error instanceof Error)) return '個人 API key 操作失敗。'
  if (error.message.includes('INVALID_MASTER_PASSWORD')) return '主密碼驗證失敗。'
  if (error.message.includes('API_KEY_ROTATION_UNKNOWN')) {
    return '連線在輪替期間中斷，結果無法判定。請不要再次輪替；重新輸入主密碼並選擇「複製目前 Client Secret」確認目前值。'
  }
  if (error.message.includes('SYNC_AUTH_REQUIRED')) return '同步登入已失效，請先重新登入。'
  return rotate ? '無法輪替個人 API key；既有 Client Secret 可能仍有效。' : '無法取得個人 API key。'
}

function AccountApiKeyDialog(): React.JSX.Element {
  const [open, setOpen] = useState(false)
  const [masterPassword, setMasterPassword] = useState('')
  const [rotate, setRotate] = useState(false)
  const [confirmRotation, setConfirmRotation] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  function clearSecrets(): void {
    setMasterPassword('')
    setRotate(false)
    setConfirmRotation(false)
  }

  function changeOpen(next: boolean): void {
    if (busy) return
    setOpen(next)
    setError('')
    setSuccess('')
    if (!next) clearSecrets()
  }

  async function copyClientId(): Promise<void> {
    setBusy(true)
    setError('')
    setSuccess('')
    try {
      await window.bearwarden.accountSecurity.copyApiClientId()
      setSuccess('Client ID 已複製。')
    } catch (copyError) {
      setError(apiKeyError(copyError, false))
    } finally {
      setBusy(false)
    }
  }

  async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (!masterPassword || (rotate && !confirmRotation)) {
      setError(rotate ? '請輸入主密碼並確認輪替影響。' : '請輸入主密碼。')
      return
    }
    setBusy(true)
    setError('')
    setSuccess('')
    try {
      await window.bearwarden.accountSecurity.copyApiKey({
        masterPassword,
        rotate,
        confirmRotation: rotate && confirmRotation
      })
      setMasterPassword('')
      setSuccess(
        rotate
          ? '新的 Client Secret 已複製；舊值已失效，剪貼簿最晚 30 秒後清除。'
          : '目前 Client Secret 已複製，剪貼簿最晚 30 秒後清除。'
      )
    } catch (copyError) {
      setMasterPassword('')
      setError(apiKeyError(copyError, rotate))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={changeOpen}>
      <DialogTrigger
        render={<Button className="w-full" variant="outline" size="sm" type="button" />}
      >
        <KeyRound data-icon="inline-start" aria-hidden="true" />
        個人 API key
      </DialogTrigger>
      <DialogContent showOverlay={false}>
        <DialogHeader>
          <DialogTitle>個人 API key</DialogTitle>
          <DialogDescription>
            用於 Bitwarden CLI 的 client credentials。Client Secret 不會保存於 BearWarden。
          </DialogDescription>
        </DialogHeader>
        <Button variant="outline" type="button" disabled={busy} onClick={() => void copyClientId()}>
          <Copy data-icon="inline-start" aria-hidden="true" />
          複製 Client ID
        </Button>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <Field>
            <FieldLabel htmlFor="api-key-master-password">主密碼</FieldLabel>
            <Input
              id="api-key-master-password"
              type="password"
              autoComplete="current-password"
              value={masterPassword}
              disabled={busy}
              onChange={(event) => setMasterPassword(event.target.value)}
            />
            <FieldDescription>只在主程序產生一次性 server proof，不會保存。</FieldDescription>
          </Field>
          <Field orientation="horizontal" data-disabled={busy || undefined}>
            <Checkbox
              id="api-key-rotate"
              checked={rotate}
              disabled={busy}
              onCheckedChange={(checked) => {
                setRotate(checked)
                if (!checked) setConfirmRotation(false)
              }}
            />
            <FieldContent>
              <FieldLabel htmlFor="api-key-rotate">
                <FieldTitle>輪替 API key</FieldTitle>
              </FieldLabel>
              <FieldDescription>建立新 Client Secret，舊值會立即失效。</FieldDescription>
            </FieldContent>
          </Field>
          {rotate && (
            <Field orientation="horizontal" data-disabled={busy || undefined}>
              <Checkbox
                id="api-key-confirm-rotation"
                checked={confirmRotation}
                disabled={busy}
                onCheckedChange={setConfirmRotation}
              />
              <FieldContent>
                <FieldLabel htmlFor="api-key-confirm-rotation">
                  <FieldTitle>我了解現有 CLI session 可能需要重新登入</FieldTitle>
                </FieldLabel>
              </FieldContent>
            </Field>
          )}
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
          <DialogFooter>
            <Button
              variant="secondary"
              type="button"
              disabled={busy}
              onClick={() => changeOpen(false)}
            >
              關閉
            </Button>
            <Button type="submit" variant={rotate ? 'destructive' : 'default'} disabled={busy}>
              {busy ? (
                <Spinner data-icon="inline-start" aria-hidden="true" />
              ) : rotate ? (
                <RotateCw data-icon="inline-start" aria-hidden="true" />
              ) : (
                <Copy data-icon="inline-start" aria-hidden="true" />
              )}
              {rotate ? '輪替並複製新 Secret' : '複製目前 Client Secret'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export default AccountApiKeyDialog
