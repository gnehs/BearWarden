import { useEffect, useRef, useState } from 'react'
import { ArrowRight, Fingerprint, KeyRound, RotateCcw, ShieldAlert } from 'lucide-react'
import type { AppSettings, PinUnlockStatus } from '../../../shared/vault-contract'
import BrandMark from './BrandMark'
import { Alert, AlertDescription } from '@renderer/components/ui/alert'
import { Button } from '@renderer/components/ui/button'
import { Field, FieldGroup, FieldLabel } from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import { Spinner } from '@renderer/components/ui/spinner'
import { touchIdUnlockFallback } from './auth-screen-ui'

interface AuthScreenProps {
  state: 'loading' | 'unavailable' | 'uninitialized' | 'locked'
  onAuthenticated: (source: 'setup' | 'unlock') => void
  onRetry: () => void
}

function describeError(error: unknown): string {
  if (!(error instanceof Error)) return '發生未知錯誤，請稍後再試。'
  if (error.message.includes('INVALID_MASTER_PASSWORD')) return '主密碼不正確。'
  if (error.message.includes('INVALID_PIN')) return 'PIN 不正確。'
  if (error.message.includes('PIN_DISABLED')) return 'PIN 解鎖已停用，請改用主密碼。'
  if (error.message.includes('RATE_LIMITED')) return '嘗試次數過多，請稍後再試。'
  if (error.message.includes('INVALID_INPUT')) return '請檢查輸入內容。'
  return '目前無法開啟密碼庫，請稍後再試。'
}

function AuthScreen({ state, onAuthenticated, onRetry }: AuthScreenProps): React.JSX.Element {
  const [masterPassword, setMasterPassword] = useState('')
  const [pin, setPin] = useState('')
  const [unlockMethod, setUnlockMethod] = useState<'master-password' | 'pin'>('master-password')
  const [pinStatus, setPinStatus] = useState<PinUnlockStatus>({
    available: false,
    remainingAttempts: 0
  })
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [settings, setSettings] = useState<AppSettings | null>(null)
  const passwordRef = useRef<HTMLInputElement>(null)
  const pinRef = useRef<HTMLInputElement>(null)
  const focusPasswordAfterTouchIdRef = useRef(false)
  const isSetup = state === 'uninitialized'

  useEffect(() => {
    if (!submitting && (state === 'locked' || state === 'uninitialized')) {
      if (unlockMethod === 'pin') pinRef.current?.focus()
      else {
        passwordRef.current?.focus()
        if (focusPasswordAfterTouchIdRef.current) {
          passwordRef.current?.select()
          focusPasswordAfterTouchIdRef.current = false
        }
      }
    }
  }, [state, submitting, unlockMethod])

  useEffect(() => {
    let active = true
    if (state !== 'locked') {
      return () => {
        active = false
      }
    }
    void window.bearwarden.vault.pinStatus().then(
      (status) => {
        if (active) setPinStatus(status)
      },
      () => {
        if (active) setPinStatus({ available: false, remainingAttempts: 0 })
      }
    )
    void window.bearwarden.settings.get().then(
      (nextSettings) => {
        if (active) setSettings(nextSettings)
      },
      () => {
        // A missing settings service must not block master-password unlock.
      }
    )
    return () => {
      active = false
    }
  }, [state])

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    setError('')

    if (!isSetup && unlockMethod === 'pin') {
      if (pin.normalize('NFC').length < 4) {
        setError('PIN 至少需要 4 個字元。')
        return
      }
      const request = { pin }
      setPin('')
      setSubmitting(true)
      try {
        const status = await window.bearwarden.vault.unlockPin(request)
        if (status.state === 'unlocked') onAuthenticated('unlock')
      } catch (submitError) {
        const nextStatus = await window.bearwarden.vault
          .pinStatus()
          .catch(() => ({ available: false, remainingAttempts: 0 }))
        setPinStatus(nextStatus)
        if (!nextStatus.available) setUnlockMethod('master-password')
        const base = describeError(submitError)
        setError(
          nextStatus.available
            ? `${base} 還可嘗試 ${nextStatus.remainingAttempts} 次。`
            : 'PIN 解鎖已失效，請輸入主密碼。'
        )
      } finally {
        request.pin = ''
        setSubmitting(false)
      }
      return
    }

    if (!masterPassword) {
      setError('請輸入主密碼。')
      return
    }
    if (isSetup && masterPassword.length < 12) {
      setError('主密碼至少需要 12 個字元。')
      return
    }
    if (isSetup && masterPassword !== confirmation) {
      setError('兩次輸入的主密碼不一致。')
      return
    }

    setSubmitting(true)
    try {
      const status = isSetup
        ? await window.bearwarden.vault.setup({ masterPassword })
        : await window.bearwarden.vault.unlock({ masterPassword })
      setMasterPassword('')
      setConfirmation('')
      if (status.state === 'unlocked') onAuthenticated(isSetup ? 'setup' : 'unlock')
    } catch (submitError) {
      setError(describeError(submitError))
      passwordRef.current?.select()
    } finally {
      setSubmitting(false)
    }
  }

  async function unlockWithTouchId(): Promise<void> {
    setError('')
    setSubmitting(true)
    try {
      const status = await window.bearwarden.settings.unlockTouchId()
      if (status.state === 'unlocked') onAuthenticated('unlock')
    } catch (touchIdError) {
      const fallback = touchIdUnlockFallback(touchIdError)
      focusPasswordAfterTouchIdRef.current = true
      setPin('')
      setUnlockMethod(fallback.unlockMethod)
      setError(fallback.error)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="relative grid min-h-full place-items-center bg-[radial-gradient(circle_at_50%_8%,color-mix(in_oklch,var(--primary)_18%,transparent),transparent_34%),linear-gradient(145deg,var(--muted),var(--background)_55%,var(--accent))] px-6 pt-[72px] pb-[34px]">
      <div className="window-drag-region" aria-hidden="true" />
      <div className="flex flex-col items-center justify-center gap-4">
        <BrandMark />
        <section
          className="w-full max-w-[440px] rounded-[20px] bg-[color-mix(in_oklch,var(--card)_91%,transparent)] p-7 shadow-[var(--shadow)] outline outline-black/5 backdrop-blur-[22px]"
          aria-labelledby="auth-title"
        >
          {state === 'loading' && (
            <div className="grid justify-items-start gap-3" role="status">
              <Spinner className="size-7" aria-hidden="true" />
              <h1 className="m-0 text-[23px] leading-[1.2] tracking-[-0.025em]" id="auth-title">
                正在開啟安全密碼庫
              </h1>
              <p className="text-muted-foreground m-0 leading-[1.6]">
                所有資料都會在這部裝置上解密。
              </p>
            </div>
          )}

          {state === 'unavailable' && (
            <div className="grid justify-items-start gap-3" role="status">
              <span
                className="bg-destructive/10 text-destructive grid size-11 place-items-center rounded-[13px]"
                aria-hidden="true"
              >
                <ShieldAlert size={27} />
              </span>
              <h1 className="m-0 text-[23px] leading-[1.2] tracking-[-0.025em]" id="auth-title">
                無法連線至安全服務
              </h1>
              <p className="text-muted-foreground m-0 leading-[1.6]">
                BearWarden 沒有載入密碼庫服務。你的資料沒有被更動。
              </p>
              <Button className="mt-2" type="button" onClick={onRetry}>
                <RotateCcw data-icon="inline-start" aria-hidden="true" />
                再試一次
              </Button>
            </div>
          )}

          {(state === 'locked' || state === 'uninitialized') && (
            <form className="grid gap-[18px]" onSubmit={handleSubmit}>
              <div className="grid grid-cols-[auto_1fr] items-start gap-3.5">
                <div>
                  <h1 className="m-0 text-[23px] leading-[1.2] tracking-[-0.025em]" id="auth-title">
                    {isSetup ? '建立你的密碼庫' : '歡迎回來'}
                  </h1>
                  <p className="text-muted-foreground mt-[7px] mb-0 leading-[1.6]">
                    {isSetup
                      ? '設定只有你知道的主密碼；BearWarden 無法替你復原。'
                      : unlockMethod === 'pin'
                        ? '輸入這次執行期間設定的 PIN。'
                        : '輸入主密碼以解鎖儲存在這部裝置上的項目。'}
                  </p>
                </div>
              </div>

              <FieldGroup>
                {!isSetup && unlockMethod === 'pin' ? (
                  <Field data-invalid={Boolean(error)}>
                    <FieldLabel htmlFor="vault-pin">PIN</FieldLabel>
                    <Input
                      ref={pinRef}
                      id="vault-pin"
                      type="password"
                      name="vault-pin"
                      autoComplete="off"
                      value={pin}
                      onChange={(event) => setPin(event.target.value)}
                      disabled={submitting}
                      aria-invalid={Boolean(error)}
                      aria-describedby={error ? 'auth-error' : undefined}
                    />
                  </Field>
                ) : (
                  <Field data-invalid={Boolean(error)}>
                    <FieldLabel htmlFor="master-password">主密碼</FieldLabel>
                    <Input
                      ref={passwordRef}
                      id="master-password"
                      type="password"
                      name="master-password"
                      autoComplete={isSetup ? 'new-password' : 'current-password'}
                      value={masterPassword}
                      onChange={(event) => setMasterPassword(event.target.value)}
                      disabled={submitting}
                      aria-invalid={Boolean(error)}
                      aria-describedby={error ? 'auth-error' : undefined}
                    />
                  </Field>
                )}

                {isSetup && (
                  <Field data-invalid={Boolean(error)}>
                    <FieldLabel htmlFor="master-password-confirmation">再次輸入主密碼</FieldLabel>
                    <Input
                      id="master-password-confirmation"
                      type="password"
                      name="master-password-confirmation"
                      autoComplete="new-password"
                      value={confirmation}
                      onChange={(event) => setConfirmation(event.target.value)}
                      disabled={submitting}
                      aria-invalid={Boolean(error)}
                      aria-describedby={error ? 'auth-error' : undefined}
                    />
                  </Field>
                )}
              </FieldGroup>

              {error && (
                <Alert id="auth-error" variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <Button className="h-10 w-full" type="submit" disabled={submitting}>
                {submitting ? (
                  <Spinner data-icon="inline-start" aria-hidden="true" />
                ) : (
                  <ArrowRight data-icon="inline-start" aria-hidden="true" />
                )}
                {isSetup ? '建立並解鎖' : unlockMethod === 'pin' ? '使用 PIN 解鎖' : '解鎖密碼庫'}
              </Button>
              {!isSetup && pinStatus.available && (
                <Button
                  className="h-10 w-full"
                  variant="outline"
                  type="button"
                  disabled={submitting}
                  onClick={() => {
                    setError('')
                    setMasterPassword('')
                    setPin('')
                    setUnlockMethod((current) => (current === 'pin' ? 'master-password' : 'pin'))
                  }}
                >
                  <KeyRound data-icon="inline-start" aria-hidden="true" />
                  {unlockMethod === 'pin' ? '改用主密碼' : '使用 PIN 解鎖'}
                </Button>
              )}
              {!isSetup && settings?.touchIdAvailable && settings.touchIdEnabled && (
                <Button
                  className="h-10 w-full"
                  variant="secondary"
                  type="button"
                  disabled={submitting}
                  onClick={() => void unlockWithTouchId()}
                >
                  {submitting ? (
                    <Spinner data-icon="inline-start" aria-hidden="true" />
                  ) : (
                    <Fingerprint data-icon="inline-start" aria-hidden="true" />
                  )}
                  使用 Touch ID 解鎖
                </Button>
              )}
            </form>
          )}
        </section>
      </div>
      <p className="text-muted-foreground absolute bottom-[18px] m-0 text-[11px]">
        你的主密碼和解密後的資料不會離開這部裝置。
      </p>
    </main>
  )
}

export default AuthScreen
