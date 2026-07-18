import { Copy, KeyRound, Plus, ShieldCheck, ShieldOff, Trash2, TriangleAlert } from 'lucide-react'
import { useState } from 'react'
import type {
  AccountAuthenticatorSetup,
  AccountEmailTwoFactorSetup,
  AccountTwoFactorProvider,
  AccountWebAuthnKeyView
} from '../../../shared/vault-contract'
import { Alert, AlertDescription } from '@renderer/components/ui/alert'
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
import {
  canEnrollWebAuthnKey,
  canRemoveWebAuthnKey,
  hiddenProviderEscapeTargets,
  isDisableablePersonalProvider,
  isLastVisiblePersonalTwoFactorMethod,
  isWebAuthnMutationOutcomeUnknown,
  type DisableablePersonalProvider,
  webAuthnActionError,
  webAuthnKeyPresentation
} from './account-webauthn-ui'

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

interface AccountWebAuthnKeyListProps {
  keys: readonly AccountWebAuthnKeyView[]
  busy: boolean
  onRemove: (key: AccountWebAuthnKeyView) => void
}

export function AccountWebAuthnKeyList({
  keys,
  busy,
  onRemove
}: AccountWebAuthnKeyListProps): React.JSX.Element {
  const keyViews = webAuthnKeyPresentation(keys)

  return (
    <FieldGroup>
      <Field>
        <FieldLabel>已註冊的安全金鑰</FieldLabel>
        {keyViews.length === 0 ? (
          <FieldDescription>尚未註冊安全金鑰。您可以新增第一把金鑰。</FieldDescription>
        ) : (
          <div className="flex flex-col gap-2">
            {keyViews.map((key) => (
              <div key={key.id} className="flex flex-wrap items-center gap-2">
                <Badge variant="outline">{key.name}</Badge>
                {key.migrated && <Badge variant="secondary">已移轉</Badge>}
                {canRemoveWebAuthnKey(busy, keyViews.length) && (
                  <Button
                    type="button"
                    size="sm"
                    variant="destructive"
                    disabled={busy}
                    onClick={() => onRemove(key)}
                  >
                    <Trash2 data-icon="inline-start" aria-hidden="true" />
                    移除
                  </Button>
                )}
              </div>
            ))}
          </div>
        )}
        {keyViews.length === 1 && (
          <FieldDescription>至少保留一把安全金鑰；此處不提供移除最後一把金鑰。</FieldDescription>
        )}
      </Field>
    </FieldGroup>
  )
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
  const [emailSetup, setEmailSetup] = useState<AccountEmailTwoFactorSetup | null>(null)
  const [emailSetupPassword, setEmailSetupPassword] = useState('')
  const [emailAddress, setEmailAddress] = useState('')
  const [emailSendPassword, setEmailSendPassword] = useState('')
  const [emailToken, setEmailToken] = useState('')
  const [emailCompletionPassword, setEmailCompletionPassword] = useState('')
  const [emailCodeSent, setEmailCodeSent] = useState(false)
  const [disableTarget, setDisableTarget] = useState<DisableablePersonalProvider | null>(null)
  const [disablePassword, setDisablePassword] = useState('')
  const [disableError, setDisableError] = useState('')
  const [webAuthnKeys, setWebAuthnKeys] = useState<AccountWebAuthnKeyView[] | null>(null)
  const [webAuthnListPassword, setWebAuthnListPassword] = useState('')
  const [webAuthnName, setWebAuthnName] = useState('')
  const [webAuthnEnrollmentPassword, setWebAuthnEnrollmentPassword] = useState('')
  const [webAuthnRemovalTarget, setWebAuthnRemovalTarget] = useState<AccountWebAuthnKeyView | null>(
    null
  )
  const [webAuthnRemovalPassword, setWebAuthnRemovalPassword] = useState('')
  const [webAuthnError, setWebAuthnError] = useState('')
  const [webAuthnSuccess, setWebAuthnSuccess] = useState('')
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
    setEmailSetup(null)
    setEmailSetupPassword('')
    setEmailAddress('')
    setEmailSendPassword('')
    setEmailToken('')
    setEmailCompletionPassword('')
    setEmailCodeSent(false)
    setDisableTarget(null)
    setDisablePassword('')
    setDisableError('')
    setWebAuthnKeys(null)
    setWebAuthnListPassword('')
    setWebAuthnName('')
    setWebAuthnEnrollmentPassword('')
    setWebAuthnRemovalTarget(null)
    setWebAuthnRemovalPassword('')
    setWebAuthnError('')
    setWebAuthnSuccess('')
    setError('')
    setSuccess('')
    if (next) void load()
  }

  function changeDisableTarget(type: DisableablePersonalProvider | null): void {
    if (busy) return
    setDisableTarget(type)
    setDisablePassword('')
    setDisableError('')
    if (type !== null) {
      setError('')
      setSuccess('')
    }
  }

  async function disableProvider(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (disableTarget === null || !disablePassword) {
      setDisableError('請輸入主密碼。')
      return
    }
    const type = disableTarget
    const request = { type, masterPassword: disablePassword, confirm: true as const }
    setDisablePassword('')
    setBusy(true)
    setDisableError('')
    setError('')
    setSuccess('')
    try {
      await window.bearwarden.accountSecurity.disableTwoFactorProvider(request)
      setDisableTarget(null)
      setSuccess(`${providerNames[type]}已停用。`)
      await load()
    } catch (disableFailure) {
      if (
        disableFailure instanceof Error &&
        disableFailure.message.includes('TWO_FACTOR_MUTATION_UNKNOWN')
      ) {
        setDisableTarget(null)
        await load()
        setError(
          `${providerNames[type]}的停用結果不明；已重新整理狀態。請先確認目前狀態，勿直接重試。`
        )
      } else if (
        disableFailure instanceof Error &&
        disableFailure.message.includes('INVALID_MASTER_PASSWORD')
      ) {
        setDisableError('主密碼驗證失敗；若要再試，請重新輸入主密碼。')
      } else {
        setDisableError(`無法停用${providerNames[type]}，請稍後再試。`)
      }
    } finally {
      request.masterPassword = ''
      setBusy(false)
    }
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

  function resetEmailSetup(): void {
    setEmailSetup(null)
    setEmailAddress('')
    setEmailSendPassword('')
    setEmailToken('')
    setEmailCompletionPassword('')
    setEmailCodeSent(false)
  }

  async function beginEmailSetup(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (!emailSetupPassword) {
      setError('請輸入主密碼。')
      return
    }
    setBusy(true)
    setError('')
    setSuccess('')
    try {
      const setup = await window.bearwarden.accountSecurity.beginEmailTwoFactorSetup({
        masterPassword: emailSetupPassword
      })
      setEmailSetup(setup)
      setEmailSetupPassword('')
    } catch (setupError) {
      setEmailSetupPassword('')
      setError(
        setupError instanceof Error && setupError.message.includes('INVALID_MASTER_PASSWORD')
          ? '主密碼驗證失敗。'
          : '無法開始設定 Email 雙重驗證。'
      )
    } finally {
      setBusy(false)
    }
  }

  async function sendEmailSetupCode(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (!emailSetup || !/^[^\s@]+@[^\s@]+$/.test(emailAddress)) {
      setError('請輸入有效的 Email 地址。')
      return
    }
    if (emailSetup.requiresMasterPassword && !emailSendPassword) {
      setError('此伺服器要求再次輸入主密碼。')
      return
    }
    setBusy(true)
    setError('')
    setSuccess('')
    try {
      await window.bearwarden.accountSecurity.sendEmailTwoFactorSetup({
        sessionId: emailSetup.sessionId,
        email: emailAddress,
        ...(emailSetup.requiresMasterPassword ? { masterPassword: emailSendPassword } : {})
      })
      setEmailSendPassword('')
      setEmailCodeSent(true)
      setSuccess('驗證碼已寄出。')
    } catch (setupError) {
      const outcomeUnknown =
        setupError instanceof Error && setupError.message.includes('TWO_FACTOR_MUTATION_UNKNOWN')
      resetEmailSetup()
      if (outcomeUnknown) {
        await load()
        setError('寄送結果不明；已重新整理狀態，請勿直接重送。')
      } else if (
        setupError instanceof Error &&
        setupError.message.includes('INVALID_MASTER_PASSWORD')
      ) {
        setError('主密碼驗證失敗，請重新開始設定。')
      } else {
        setError('無法寄出驗證碼，請重新開始設定。')
      }
    } finally {
      setBusy(false)
    }
  }

  async function completeEmailSetup(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (!emailSetup || !emailCodeSent || !/^\d{1,50}$/.test(emailToken)) {
      setError('請輸入 Email 中的數字驗證碼。')
      return
    }
    if (emailSetup.requiresMasterPassword && !emailCompletionPassword) {
      setError('此伺服器要求再次輸入主密碼。')
      return
    }
    setBusy(true)
    setError('')
    setSuccess('')
    try {
      await window.bearwarden.accountSecurity.completeEmailTwoFactorSetup({
        sessionId: emailSetup.sessionId,
        token: emailToken,
        ...(emailSetup.requiresMasterPassword ? { masterPassword: emailCompletionPassword } : {})
      })
      resetEmailSetup()
      setSuccess('Email 雙重驗證已啟用。')
      await load()
    } catch (setupError) {
      const outcomeUnknown =
        setupError instanceof Error && setupError.message.includes('TWO_FACTOR_MUTATION_UNKNOWN')
      resetEmailSetup()
      if (outcomeUnknown) {
        await load()
        setError('啟用結果不明；已重新整理狀態，請勿直接重試。')
      } else if (
        setupError instanceof Error &&
        setupError.message.includes('INVALID_MASTER_PASSWORD')
      ) {
        setError('主密碼驗證失敗，請重新開始設定。')
      } else {
        setError('無法啟用 Email 雙重驗證，請重新開始設定。')
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

  async function listWebAuthnKeys(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (busy) return
    if (!webAuthnListPassword) {
      setWebAuthnError('請輸入主密碼。')
      return
    }
    const request = { masterPassword: webAuthnListPassword }
    setWebAuthnListPassword('')
    setBusy(true)
    setWebAuthnError('')
    setWebAuthnSuccess('')
    try {
      setWebAuthnKeys(await window.bearwarden.accountSecurity.listWebAuthnKeys(request))
    } catch (listFailure) {
      setWebAuthnError(webAuthnActionError(listFailure, 'list'))
    } finally {
      request.masterPassword = ''
      setBusy(false)
    }
  }

  async function refreshWebAuthnSecurity(masterPassword: string): Promise<void> {
    const [nextProviders, nextKeys] = await Promise.all([
      window.bearwarden.accountSecurity.twoFactorStatus(),
      window.bearwarden.accountSecurity.listWebAuthnKeys({ masterPassword })
    ])
    setProviders(nextProviders)
    setWebAuthnKeys(nextKeys)
  }

  async function enrollWebAuthnKey(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (busy || webAuthnKeys === null) return
    if (!canEnrollWebAuthnKey(busy, webAuthnName, webAuthnEnrollmentPassword)) {
      setWebAuthnError('請輸入安全金鑰名稱與主密碼。')
      return
    }
    const request = {
      masterPassword: webAuthnEnrollmentPassword,
      name: webAuthnName.trim()
    }
    let enrollmentCompleted = false
    setWebAuthnName('')
    setWebAuthnEnrollmentPassword('')
    setBusy(true)
    setWebAuthnError('')
    setWebAuthnSuccess('')
    try {
      await window.bearwarden.accountSecurity.enrollWebAuthnKey(request)
      enrollmentCompleted = true
      await refreshWebAuthnSecurity(request.masterPassword)
      setWebAuthnSuccess('安全金鑰已新增，已重新整理雙重驗證與金鑰清單。')
    } catch (enrollmentFailure) {
      if (isWebAuthnMutationOutcomeUnknown(enrollmentFailure) || enrollmentCompleted) {
        setWebAuthnKeys(null)
        try {
          await refreshWebAuthnSecurity(request.masterPassword)
        } catch {
          // The renderer must not retain a possibly stale list after a failed refresh.
        }
      }
      setWebAuthnError(
        enrollmentCompleted
          ? '安全金鑰可能已新增，但無法重新整理清單。請重新輸入主密碼確認，勿直接重試。'
          : webAuthnActionError(enrollmentFailure, 'enroll')
      )
    } finally {
      request.masterPassword = ''
      request.name = ''
      setBusy(false)
    }
  }

  function changeWebAuthnRemovalTarget(target: AccountWebAuthnKeyView | null): void {
    if (busy) return
    setWebAuthnRemovalTarget(target)
    setWebAuthnRemovalPassword('')
    setWebAuthnError('')
    setWebAuthnSuccess('')
  }

  async function removeWebAuthnKey(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (
      busy ||
      !webAuthnRemovalTarget ||
      !webAuthnRemovalPassword ||
      !canRemoveWebAuthnKey(busy, webAuthnKeys?.length ?? 0)
    ) {
      return
    }
    const request = {
      id: webAuthnRemovalTarget.id,
      masterPassword: webAuthnRemovalPassword,
      confirm: true as const
    }
    let removalCompleted = false
    setWebAuthnRemovalPassword('')
    setBusy(true)
    setWebAuthnError('')
    setWebAuthnSuccess('')
    try {
      await window.bearwarden.accountSecurity.removeWebAuthnKey(request)
      removalCompleted = true
      await refreshWebAuthnSecurity(request.masterPassword)
      setWebAuthnRemovalTarget(null)
      setWebAuthnSuccess('安全金鑰已移除，已重新整理雙重驗證與金鑰清單。')
    } catch (removalFailure) {
      if (isWebAuthnMutationOutcomeUnknown(removalFailure) || removalCompleted) {
        setWebAuthnRemovalTarget(null)
        setWebAuthnKeys(null)
        try {
          await refreshWebAuthnSecurity(request.masterPassword)
        } catch {
          // The renderer must not retain a possibly stale list after a failed refresh.
        }
      }
      setWebAuthnError(
        removalCompleted
          ? '安全金鑰可能已移除，但無法重新整理清單。請重新輸入主密碼確認，勿直接重試。'
          : webAuthnActionError(removalFailure, 'remove')
      )
    } finally {
      request.masterPassword = ''
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={changeOpen}>
      <DialogTrigger
        render={<Button className="w-full" variant="outline" size="sm" type="button" />}
      >
        <ShieldCheck data-icon="inline-start" aria-hidden="true" />
        雙重驗證
      </DialogTrigger>
      <DialogContent
        className="max-h-[min(42rem,calc(100vh-2rem))] overflow-y-auto sm:max-w-lg"
        forceOverlay
      >
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
              .map((provider) => {
                const canDisable = isDisableablePersonalProvider(provider.type)
                return (
                  <div key={provider.type} className="flex items-center gap-1">
                    <Badge variant="outline">
                      {providerNames[provider.type] ?? `Provider ${provider.type}`}
                    </Badge>
                    {canDisable && (
                      <Button
                        type="button"
                        size="sm"
                        variant="destructive"
                        disabled={busy}
                        onClick={() =>
                          changeDisableTarget(provider.type as DisableablePersonalProvider)
                        }
                      >
                        <ShieldOff data-icon="inline-start" aria-hidden="true" />
                        停用
                      </Button>
                    )}
                  </div>
                )
              })
          ) : (
            <span className="text-muted-foreground text-sm">尚未啟用雙重驗證方式。</span>
          )}
        </div>
        {hiddenProviderEscapeTargets(providers).length > 0 && (
          <div className="grid gap-2 border-t pt-4">
            <p className="text-muted-foreground text-sm">
              若伺服器的 Duo 或 YubiKey 整合已失效，provider
              可能不會出現在狀態清單，但仍會阻擋登入。可用下方逃生門以新的主密碼要求伺服器移除註冊。
            </p>
            <div className="flex flex-wrap gap-2">
              {hiddenProviderEscapeTargets(providers).map((type) => (
                <Button
                  key={type}
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  onClick={() => changeDisableTarget(type)}
                >
                  <ShieldOff data-icon="inline-start" aria-hidden="true" />
                  強制停用{providerNames[type]}
                </Button>
              ))}
            </div>
          </div>
        )}
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
        {!providers.some((provider) => provider.type === 1 && provider.enabled) && (
          <div className="grid gap-4 border-t pt-4">
            <div>
              <h3 className="text-sm font-medium">設定 Email 雙重驗證</h3>
              <p className="text-muted-foreground text-sm">
                驗證碼會寄到指定地址。Email 地址只保留在這次短期設定流程中。
              </p>
            </div>
            {!emailSetup ? (
              <form className="grid gap-4" onSubmit={(event) => void beginEmailSetup(event)}>
                <Field>
                  <FieldLabel htmlFor="email-2fa-setup-password">主密碼</FieldLabel>
                  <Input
                    id="email-2fa-setup-password"
                    type="password"
                    autoComplete="current-password"
                    value={emailSetupPassword}
                    disabled={busy}
                    onChange={(event) => setEmailSetupPassword(event.target.value)}
                  />
                </Field>
                <Button type="submit" disabled={busy}>
                  開始設定
                </Button>
              </form>
            ) : !emailCodeSent ? (
              <form className="grid gap-4" onSubmit={(event) => void sendEmailSetupCode(event)}>
                <Field>
                  <FieldLabel htmlFor="email-2fa-address">接收驗證碼的 Email</FieldLabel>
                  <Input
                    id="email-2fa-address"
                    type="email"
                    autoComplete="email"
                    maxLength={256}
                    value={emailAddress}
                    disabled={busy}
                    onChange={(event) => setEmailAddress(event.target.value)}
                  />
                </Field>
                {emailSetup.requiresMasterPassword && (
                  <Field>
                    <FieldLabel htmlFor="email-2fa-send-password">再次輸入主密碼</FieldLabel>
                    <Input
                      id="email-2fa-send-password"
                      type="password"
                      autoComplete="current-password"
                      value={emailSendPassword}
                      disabled={busy}
                      onChange={(event) => setEmailSendPassword(event.target.value)}
                    />
                    <FieldDescription>Vaultwarden 會在寄送前重新驗證主密碼。</FieldDescription>
                  </Field>
                )}
                <Button type="submit" disabled={busy || emailAddress.length === 0}>
                  寄送驗證碼
                </Button>
              </form>
            ) : (
              <form className="grid gap-4" onSubmit={(event) => void completeEmailSetup(event)}>
                <Field>
                  <FieldLabel htmlFor="email-2fa-token">Email 驗證碼</FieldLabel>
                  <Input
                    id="email-2fa-token"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    maxLength={50}
                    value={emailToken}
                    disabled={busy}
                    onChange={(event) =>
                      setEmailToken(event.target.value.replace(/\D/g, '').slice(0, 50))
                    }
                  />
                  <FieldDescription>驗證碼已寄至 {emailAddress}。</FieldDescription>
                </Field>
                {emailSetup.requiresMasterPassword && (
                  <Field>
                    <FieldLabel htmlFor="email-2fa-completion-password">再次輸入主密碼</FieldLabel>
                    <Input
                      id="email-2fa-completion-password"
                      type="password"
                      autoComplete="current-password"
                      value={emailCompletionPassword}
                      disabled={busy}
                      onChange={(event) => setEmailCompletionPassword(event.target.value)}
                    />
                    <FieldDescription>Vaultwarden 會在啟用時再次驗證主密碼。</FieldDescription>
                  </Field>
                )}
                <Button type="submit" disabled={busy || emailToken.length === 0}>
                  啟用 Email 雙重驗證
                </Button>
              </form>
            )}
          </div>
        )}
        <div className="flex flex-col gap-4 border-t pt-4">
          <div className="flex flex-col gap-1">
            <h3 className="text-sm font-medium">管理 FIDO2 安全金鑰</h3>
            <p className="text-muted-foreground text-sm">
              新增時會開啟系統提示；依金鑰設定，您可能需要觸碰金鑰或輸入 PIN。
            </p>
          </div>
          <Alert>
            <KeyRound aria-hidden="true" />
            <AlertDescription>
              請先安全保存 Recovery Code。安全金鑰遺失時，Recovery Code 可協助您重新取得帳號存取權。
            </AlertDescription>
          </Alert>
          {webAuthnKeys === null ? (
            <form
              className="flex flex-col gap-4"
              onSubmit={(event) => void listWebAuthnKeys(event)}
            >
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="webauthn-list-master-password">主密碼</FieldLabel>
                  <Input
                    id="webauthn-list-master-password"
                    type="password"
                    autoComplete="current-password"
                    value={webAuthnListPassword}
                    disabled={busy}
                    onChange={(event) => setWebAuthnListPassword(event.target.value)}
                  />
                  <FieldDescription>驗證後才會讀取帳號目前註冊的安全金鑰。</FieldDescription>
                </Field>
              </FieldGroup>
              <Button type="submit" disabled={busy || webAuthnListPassword.length === 0}>
                {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                驗證並讀取安全金鑰
              </Button>
            </form>
          ) : (
            <div className="flex flex-col gap-4">
              <AccountWebAuthnKeyList
                keys={webAuthnKeys}
                busy={busy}
                onRemove={changeWebAuthnRemovalTarget}
              />
              <form
                className="flex flex-col gap-4"
                onSubmit={(event) => void enrollWebAuthnKey(event)}
              >
                <FieldGroup>
                  <Field>
                    <FieldLabel htmlFor="webauthn-key-name">安全金鑰名稱</FieldLabel>
                    <Input
                      id="webauthn-key-name"
                      autoComplete="off"
                      maxLength={256}
                      value={webAuthnName}
                      disabled={busy}
                      onChange={(event) => setWebAuthnName(event.target.value)}
                    />
                    <FieldDescription>
                      例如「辦公室 USB 安全金鑰」。名稱只用於辨識這把金鑰。
                    </FieldDescription>
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="webauthn-enrollment-master-password">主密碼</FieldLabel>
                    <Input
                      id="webauthn-enrollment-master-password"
                      type="password"
                      autoComplete="current-password"
                      value={webAuthnEnrollmentPassword}
                      disabled={busy}
                      onChange={(event) => setWebAuthnEnrollmentPassword(event.target.value)}
                    />
                    <FieldDescription>
                      主密碼只會用於這次新增請求，送出後立即清空。
                    </FieldDescription>
                  </Field>
                </FieldGroup>
                <Button
                  type="submit"
                  disabled={!canEnrollWebAuthnKey(busy, webAuthnName, webAuthnEnrollmentPassword)}
                >
                  {busy ? (
                    <Spinner data-icon="inline-start" aria-hidden="true" />
                  ) : (
                    <Plus data-icon="inline-start" aria-hidden="true" />
                  )}
                  新增安全金鑰
                </Button>
              </form>
            </div>
          )}
          {webAuthnError && (
            <Alert variant="destructive">
              <AlertDescription>{webAuthnError}</AlertDescription>
            </Alert>
          )}
          {webAuthnSuccess && (
            <Alert>
              <AlertDescription>{webAuthnSuccess}</AlertDescription>
            </Alert>
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
        <AlertDialog
          open={disableTarget !== null}
          onOpenChange={(next) => {
            if (!next) changeDisableTarget(null)
          }}
        >
          <AlertDialogContent>
            <form className="grid gap-4" onSubmit={(event) => void disableProvider(event)}>
              <AlertDialogHeader>
                <AlertDialogMedia>
                  <TriangleAlert aria-hidden="true" />
                </AlertDialogMedia>
                <AlertDialogTitle>
                  停用{disableTarget === null ? '雙重驗證' : providerNames[disableTarget]}？
                </AlertDialogTitle>
                <AlertDialogDescription>
                  這會從伺服器移除這個雙重驗證方式。請輸入主密碼確認；主密碼只用於這一次請求。
                </AlertDialogDescription>
              </AlertDialogHeader>
              {disableTarget !== null &&
                isLastVisiblePersonalTwoFactorMethod(providers, disableTarget) && (
                  <Alert variant="destructive">
                    <AlertDescription>
                      這是目前最後一個可用的個人雙重驗證方式。停用後帳號將不再要求 Recovery Code
                      或其他雙重驗證；若組織政策強制
                      2FA，伺服器也可能撤銷組織成員資格。你仍可繼續停用。
                    </AlertDescription>
                  </Alert>
                )}
              {disableTarget !== null &&
                (disableTarget === 2 || disableTarget === 3) &&
                !providers.some(
                  (provider) => provider.type === disableTarget && provider.enabled
                ) && (
                  <Alert variant="destructive">
                    <AlertDescription>
                      伺服器目前無法顯示這個 provider
                      的真實狀態。強制停用可能移除仍在使用的登入方式；若它是最後一個方式，帳號將不再受雙重驗證保護。
                    </AlertDescription>
                  </Alert>
                )}
              <Field>
                <FieldLabel htmlFor="disable-2fa-master-password">主密碼</FieldLabel>
                <Input
                  id="disable-2fa-master-password"
                  type="password"
                  autoComplete="current-password"
                  value={disablePassword}
                  disabled={busy}
                  autoFocus
                  onChange={(event) => setDisablePassword(event.target.value)}
                />
                <FieldDescription>每次停用都必須重新輸入，不會沿用先前的驗證。</FieldDescription>
              </Field>
              {disableError && (
                <Alert variant="destructive">
                  <AlertDescription>{disableError}</AlertDescription>
                </Alert>
              )}
              <AlertDialogFooter>
                <AlertDialogCancel disabled={busy}>返回</AlertDialogCancel>
                <AlertDialogAction
                  type="submit"
                  variant="destructive"
                  disabled={busy || disablePassword.length === 0}
                >
                  {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                  確認停用{disableTarget === null ? '' : providerNames[disableTarget]}
                </AlertDialogAction>
              </AlertDialogFooter>
            </form>
          </AlertDialogContent>
        </AlertDialog>
        <AlertDialog
          open={webAuthnRemovalTarget !== null}
          onOpenChange={(next) => {
            if (!next) changeWebAuthnRemovalTarget(null)
          }}
        >
          <AlertDialogContent>
            <form
              className="flex flex-col gap-4"
              onSubmit={(event) => void removeWebAuthnKey(event)}
            >
              <AlertDialogHeader>
                <AlertDialogMedia>
                  <TriangleAlert aria-hidden="true" />
                </AlertDialogMedia>
                <AlertDialogTitle>移除這把安全金鑰？</AlertDialogTitle>
                <AlertDialogDescription>
                  移除後將無法用這把安全金鑰登入。請輸入新的主密碼確認；不會沿用任何先前的驗證。
                </AlertDialogDescription>
              </AlertDialogHeader>
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="webauthn-removal-master-password">主密碼</FieldLabel>
                  <Input
                    id="webauthn-removal-master-password"
                    type="password"
                    autoComplete="current-password"
                    value={webAuthnRemovalPassword}
                    disabled={busy}
                    autoFocus
                    onChange={(event) => setWebAuthnRemovalPassword(event.target.value)}
                  />
                  <FieldDescription>每次移除都必須重新輸入主密碼。</FieldDescription>
                </Field>
              </FieldGroup>
              <AlertDialogFooter>
                <AlertDialogCancel disabled={busy}>返回</AlertDialogCancel>
                <AlertDialogAction
                  type="submit"
                  variant="destructive"
                  disabled={
                    busy ||
                    webAuthnRemovalPassword.length === 0 ||
                    !canRemoveWebAuthnKey(busy, webAuthnKeys?.length ?? 0)
                  }
                >
                  {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                  確認移除安全金鑰
                </AlertDialogAction>
              </AlertDialogFooter>
            </form>
          </AlertDialogContent>
        </AlertDialog>
      </DialogContent>
    </Dialog>
  )
}

export default AccountTwoFactorDialog
