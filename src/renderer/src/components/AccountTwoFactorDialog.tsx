import { Copy, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import type { AccountTwoFactorProvider } from '../../../shared/vault-contract'
import { Alert, AlertDescription } from '@renderer/components/ui/alert'
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
import { Field, FieldDescription, FieldLabel } from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import { Spinner } from '@renderer/components/ui/spinner'

const providerNames: Record<number, string> = {
  0: '驗證器應用程式',
  1: 'Email',
  2: 'Duo',
  3: 'YubiKey OTP',
  4: 'U2F',
  5: '記住此裝置',
  6: '組織 Duo',
  7: 'FIDO2 WebAuthn',
  8: 'Recovery Code'
}

function AccountTwoFactorDialog(): React.JSX.Element {
  const [open, setOpen] = useState(false)
  const [providers, setProviders] = useState<AccountTwoFactorProvider[]>([])
  const [masterPassword, setMasterPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  async function load(): Promise<void> {
    setBusy(true)
    setError('')
    try {
      setProviders(await window.bearwarden.accountSecurity.twoFactorStatus())
    } catch {
      setError('無法讀取雙重驗證狀態。')
    } finally {
      setBusy(false)
    }
  }

  function changeOpen(next: boolean): void {
    if (busy) return
    setOpen(next)
    setMasterPassword('')
    setError('')
    setSuccess('')
    if (next) void load()
  }

  async function copyRecoveryCode(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (!masterPassword) {
      setError('請輸入主密碼。')
      return
    }
    setBusy(true)
    setError('')
    setSuccess('')
    try {
      await window.bearwarden.accountSecurity.copyRecoveryCode({ masterPassword })
      setMasterPassword('')
      setSuccess('Recovery Code 已複製，剪貼簿最晚 30 秒後清除。')
    } catch (copyError) {
      setMasterPassword('')
      setError(
        copyError instanceof Error && copyError.message.includes('INVALID_MASTER_PASSWORD')
          ? '主密碼驗證失敗。'
          : '無法取得 Recovery Code。'
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={changeOpen}>
      <DialogTrigger render={<Button variant="outline" size="sm" type="button" />}>
        <ShieldCheck data-icon="inline-start" aria-hidden="true" />
        雙重驗證
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>雙重驗證</DialogTitle>
          <DialogDescription>
            檢視伺服器目前啟用的 provider，並安全複製 Recovery Code。
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-wrap gap-2" aria-label="已啟用的雙重驗證方式">
          {providers.filter((provider) => provider.enabled).length > 0 ? (
            providers
              .filter((provider) => provider.enabled)
              .map((provider) => (
                <Badge key={provider.type} variant="outline">
                  {providerNames[provider.type] ?? `Provider ${provider.type}`}
                </Badge>
              ))
          ) : (
            <span className="text-muted-foreground text-sm">尚未啟用雙重驗證方式。</span>
          )}
        </div>
        <form className="grid gap-4" onSubmit={(event) => void copyRecoveryCode(event)}>
          <Field>
            <FieldLabel htmlFor="recovery-code-master-password">主密碼</FieldLabel>
            <Input
              id="recovery-code-master-password"
              type="password"
              autoComplete="current-password"
              value={masterPassword}
              disabled={busy}
              onChange={(event) => setMasterPassword(event.target.value)}
            />
            <FieldDescription>
              Recovery Code 不會回傳 renderer 或保存於 BearWarden。
            </FieldDescription>
          </Field>
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
            <Button type="submit" disabled={busy || providers.length === 0}>
              {busy ? (
                <Spinner data-icon="inline-start" aria-hidden="true" />
              ) : (
                <Copy data-icon="inline-start" aria-hidden="true" />
              )}
              複製 Recovery Code
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export default AccountTwoFactorDialog
