import { useEffect, useRef, useState } from 'react'
import { ArrowRight, Fingerprint, KeyRound, RotateCcw, ShieldAlert } from 'lucide-react'
import type { AppSettings } from '../../../shared/vault-contract'
import BrandMark from './BrandMark'
import { Alert, AlertDescription } from '@renderer/components/ui/alert'
import { Button } from '@renderer/components/ui/button'
import { Field, FieldGroup, FieldLabel } from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import { Spinner } from '@renderer/components/ui/spinner'

interface AuthScreenProps {
  state: 'loading' | 'unavailable' | 'uninitialized' | 'locked'
  onAuthenticated: () => void
  onRetry: () => void
}

function describeError(error: unknown): string {
  if (!(error instanceof Error)) return '發生未知錯誤，請稍後再試。'
  if (error.message.includes('INVALID_MASTER_PASSWORD')) return '主密碼不正確。'
  if (error.message.includes('RATE_LIMITED')) return '嘗試次數過多，請稍後再試。'
  if (error.message.includes('INVALID_INPUT')) return '請檢查輸入內容。'
  return '目前無法開啟保管庫，請稍後再試。'
}

function AuthScreen({ state, onAuthenticated, onRetry }: AuthScreenProps): React.JSX.Element {
  const [masterPassword, setMasterPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [settings, setSettings] = useState<AppSettings | null>(null)
  const passwordRef = useRef<HTMLInputElement>(null)
  const isSetup = state === 'uninitialized'

  useEffect(() => {
    if (state === 'locked' || state === 'uninitialized') passwordRef.current?.focus()
  }, [state])

  useEffect(() => {
    let active = true
    if (state !== 'locked') {
      return () => {
        active = false
      }
    }
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
      if (status.state === 'unlocked') onAuthenticated()
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
      if (status.state === 'unlocked') onAuthenticated()
    } catch (touchIdError) {
      setError(describeError(touchIdError))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="auth-shell">
      <div className="window-drag-region" aria-hidden="true" />
      <section className="auth-panel" aria-labelledby="auth-title">
        <BrandMark />

        {state === 'loading' && (
          <div className="auth-state" role="status">
            <Spinner className="size-7" aria-hidden="true" />
            <h1 id="auth-title">正在開啟安全保管庫</h1>
            <p>所有資料都會在這部裝置上解密。</p>
          </div>
        )}

        {state === 'unavailable' && (
          <div className="auth-state">
            <span className="auth-state-icon danger" aria-hidden="true">
              <ShieldAlert size={27} />
            </span>
            <h1 id="auth-title">無法連線至安全服務</h1>
            <p>BearWarden 沒有載入保管庫服務。你的資料沒有被更動。</p>
            <Button type="button" onClick={onRetry}>
              <RotateCcw data-icon="inline-start" aria-hidden="true" />
              再試一次
            </Button>
          </div>
        )}

        {(state === 'locked' || state === 'uninitialized') && (
          <form className="auth-form" onSubmit={handleSubmit}>
            <div className="auth-heading">
              <span className="auth-state-icon" aria-hidden="true">
                <KeyRound size={25} />
              </span>
              <div>
                <h1 id="auth-title">{isSetup ? '建立你的保管庫' : '歡迎回來'}</h1>
                <p>
                  {isSetup
                    ? '設定只有你知道的主密碼；BearWarden 無法替你復原。'
                    : '輸入主密碼以解鎖儲存在這部裝置上的項目。'}
                </p>
              </div>
            </div>

            <FieldGroup>
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

            <Button className="w-full" type="submit" disabled={submitting}>
              {submitting ? (
                <Spinner data-icon="inline-start" aria-hidden="true" />
              ) : (
                <ArrowRight data-icon="inline-start" aria-hidden="true" />
              )}
              {isSetup ? '建立並解鎖' : '解鎖保管庫'}
            </Button>
            {!isSetup && settings?.touchIdAvailable && settings.touchIdEnabled && (
              <Button
                className="w-full"
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
      <p className="auth-footnote">你的主密碼和解密後的資料不會離開這部裝置。</p>
    </main>
  )
}

export default AuthScreen
