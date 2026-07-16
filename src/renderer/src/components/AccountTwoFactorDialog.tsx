import { Copy, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import type {
  AccountAuthenticatorSetup,
  AccountTwoFactorProvider
} from '../../../shared/vault-contract'
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
  const [authenticatorPassword, setAuthenticatorPassword] = useState('')
  const [completionPassword, setCompletionPassword] = useState('')
  const [authenticatorToken, setAuthenticatorToken] = useState('')
  const [authenticatorSetup, setAuthenticatorSetup] = useState<AccountAuthenticatorSetup | null>(
    null
  )
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
    setAuthenticatorPassword('')
    setCompletionPassword('')
    setAuthenticatorToken('')
    setAuthenticatorSetup(null)
    setError('')
    setSuccess('')
    if (next) void load()
  }

  async function beginAuthenticatorSetup(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (!authenticatorPassword) {
      setError('請輸入主密碼。')
      return
    }
    setBusy(true)
    setError('')
    setSuccess('')
    try {
      const setup = await window.bearwarden.accountSecurity.beginAuthenticatorSetup({
        masterPassword: authenticatorPassword
      })
      setAuthenticatorPassword('')
      setAuthenticatorSetup(setup)
    } catch (setupError) {
      setAuthenticatorPassword('')
      setError(
        setupError instanceof Error && setupError.message.includes('INVALID_MASTER_PASSWORD')
          ? '主密碼驗證失敗。'
          : '無法開始設定驗證器。'
      )
    } finally {
      setBusy(false)
    }
  }

  async function copyAuthenticatorKey(): Promise<void> {
    if (!authenticatorSetup) return
    setBusy(true)
    setError('')
    try {
      await window.bearwarden.accountSecurity.copyAuthenticatorKey({
        sessionId: authenticatorSetup.sessionId
      })
      setSuccess('設定金鑰已複製，剪貼簿最晚 30 秒後清除。')
    } catch {
      setAuthenticatorSetup(null)
      setError('設定工作階段已失效，請重新開始。')
    } finally {
      setBusy(false)
    }
  }

  async function completeAuthenticatorSetup(
    event: React.FormEvent<HTMLFormElement>
  ): Promise<void> {
    event.preventDefault()
    if (!authenticatorSetup || !/^\d{6}$/.test(authenticatorToken)) {
      setError('請輸入驗證器顯示的 6 位數驗證碼。')
      return
    }
    if (authenticatorSetup.requiresMasterPassword && !completionPassword) {
      setError('此伺服器要求再次輸入主密碼。')
      return
    }
    setBusy(true)
    setError('')
    setSuccess('')
    try {
      await window.bearwarden.accountSecurity.completeAuthenticatorSetup({
        sessionId: authenticatorSetup.sessionId,
        token: authenticatorToken,
        ...(authenticatorSetup.requiresMasterPassword ? { masterPassword: completionPassword } : {})
      })
      setAuthenticatorSetup(null)
      setAuthenticatorToken('')
      setCompletionPassword('')
      setSuccess('驗證器應用程式已啟用。')
      await load()
    } catch (setupError) {
      setAuthenticatorSetup(null)
      setAuthenticatorToken('')
      setCompletionPassword('')
      if (
        setupError instanceof Error &&
        setupError.message.includes('TWO_FACTOR_MUTATION_UNKNOWN')
      ) {
        await load()
        setError('伺服器回應中斷，啟用結果不明；已重新整理狀態，請勿直接重試。')
      } else if (
        setupError instanceof Error &&
        setupError.message.includes('INVALID_MASTER_PASSWORD')
      ) {
        setError('主密碼驗證失敗，請重新開始設定。')
      } else {
        setError('無法啟用驗證器，請重新開始設定。')
      }
    } finally {
      setBusy(false)
    }
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
        {!providers.some((provider) => provider.type === 0 && provider.enabled) && (
          <div className="grid gap-4 border-t pt-4">
            <div>
              <h3 className="text-sm font-medium">設定驗證器應用程式</h3>
              <p className="text-muted-foreground text-sm">
                使用 1Password、Bitwarden、Google Authenticator 等相容應用程式加入下方金鑰。
              </p>
            </div>
            {!authenticatorSetup ? (
              <form
                className="grid gap-4"
                onSubmit={(event) => void beginAuthenticatorSetup(event)}
              >
                <Field>
                  <FieldLabel htmlFor="authenticator-setup-master-password">主密碼</FieldLabel>
                  <Input
                    id="authenticator-setup-master-password"
                    type="password"
                    autoComplete="current-password"
                    value={authenticatorPassword}
                    disabled={busy}
                    onChange={(event) => setAuthenticatorPassword(event.target.value)}
                  />
                </Field>
                <Button type="submit" disabled={busy}>
                  開始設定
                </Button>
              </form>
            ) : (
              <form
                className="grid gap-4"
                onSubmit={(event) => void completeAuthenticatorSetup(event)}
              >
                <Field>
                  <FieldLabel htmlFor="authenticator-setup-key">手動設定金鑰</FieldLabel>
                  <div className="flex gap-2">
                    <Input
                      id="authenticator-setup-key"
                      value={authenticatorSetup.key}
                      readOnly
                      spellCheck={false}
                      className="font-mono"
                    />
                    <Button
                      variant="outline"
                      type="button"
                      disabled={busy}
                      aria-label="複製設定金鑰"
                      onClick={() => void copyAuthenticatorKey()}
                    >
                      <Copy aria-hidden="true" />
                    </Button>
                  </div>
                  <FieldDescription>金鑰只會在這個短期設定工作階段顯示。</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor="authenticator-token">6 位數驗證碼</FieldLabel>
                  <Input
                    id="authenticator-token"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    maxLength={6}
                    value={authenticatorToken}
                    disabled={busy}
                    onChange={(event) =>
                      setAuthenticatorToken(event.target.value.replace(/\D/g, '').slice(0, 6))
                    }
                  />
                </Field>
                {authenticatorSetup.requiresMasterPassword && (
                  <Field>
                    <FieldLabel htmlFor="authenticator-completion-password">
                      再次輸入主密碼
                    </FieldLabel>
                    <Input
                      id="authenticator-completion-password"
                      type="password"
                      autoComplete="current-password"
                      value={completionPassword}
                      disabled={busy}
                      onChange={(event) => setCompletionPassword(event.target.value)}
                    />
                    <FieldDescription>Vaultwarden 會在啟用時重新驗證主密碼。</FieldDescription>
                  </Field>
                )}
                <Button type="submit" disabled={busy || authenticatorToken.length !== 6}>
                  啟用驗證器
                </Button>
              </form>
            )}
          </div>
        )}
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
