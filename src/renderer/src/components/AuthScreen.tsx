import { useEffect, useRef, useState } from 'react'
import { plural } from '@lingui/core/macro'
import { Trans, useLingui } from '@lingui/react/macro'
import { ArrowRight, Fingerprint, KeyRound, RotateCcw, ShieldAlert } from 'lucide-react'
import type { AccountStatus, PinUnlockStatus } from '../../../shared/vault-contract'
import BrandMark from './BrandMark'
import ApplicationTitlebarMenu from './ApplicationTitlebarMenu'
import AuthMeshGradientBackground from './AuthMeshGradientBackground'
import { Alert, AlertDescription } from '@renderer/components/ui/alert'
import { Button } from '@renderer/components/ui/button'
import { Field, FieldGroup, FieldLabel } from '@renderer/components/ui/field'
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
import { cn } from '@renderer/lib/utils'
import { shouldUseApplicationTitlebarMenu } from '../lib/application-titlebar-menu'
import { useSettingsStore } from '../stores/settings-runtime'
import { accountMutationError, accountMutationKeepsBusy } from './account-switcher-ui'
import { authAccountItems } from './auth-screen-ui'

const usesWindowControlsOverlay = shouldUseApplicationTitlebarMenu(navigator.userAgent)
const isMac = navigator.userAgent.includes('Mac')
const isWindows = navigator.userAgent.includes('Windows')

interface AuthScreenProps {
  state: 'loading' | 'unavailable' | 'uninitialized' | 'locked'
  onAuthenticated: (source: 'setup' | 'unlock') => void
  onRetry: () => void
}

function AuthScreen({ state, onAuthenticated, onRetry }: AuthScreenProps): React.JSX.Element {
  const { t } = useLingui()
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
  const [accountStatus, setAccountStatus] = useState<AccountStatus | null>(null)
  const [accountError, setAccountError] = useState('')
  const [accountSwitching, setAccountSwitching] = useState(false)
  const settings = useSettingsStore((store) => store.settings)
  const loadSettings = useSettingsStore((store) => store.load)
  const passwordRef = useRef<HTMLInputElement>(null)
  const pinRef = useRef<HTMLInputElement>(null)
  const focusPasswordAfterTouchIdRef = useRef(false)
  const authOperationRef = useRef(false)
  const accountStatusRequestRef = useRef(0)
  const isSetup = state === 'uninitialized'
  const accountItems = authAccountItems(accountStatus)

  function describeError(error: unknown): string {
    if (!(error instanceof Error)) return t`An unknown error occurred. Please try again later.`
    if (error.message.includes('INVALID_MASTER_PASSWORD'))
      return t`The master password is incorrect.`
    if (error.message.includes('INVALID_PIN')) return t`The PIN is incorrect.`
    if (error.message.includes('PIN_DISABLED'))
      return t`PIN unlock is disabled. Enter your master password instead.`
    if (error.message.includes('RATE_LIMITED')) return t`Too many attempts. Please try again later.`
    if (error.message.includes('INVALID_INPUT')) return t`Check your input and try again.`
    if (error.message.includes('LOCKED')) return t`The vault is locked. Please try again.`
    if (error.message.includes('CORRUPT_VAULT')) {
      return t`The vault data could not be read. Try again; if this continues, the vault file may be corrupted.`
    }
    if (error.message.includes('NOT_INITIALIZED')) {
      return t`The vault file could not be found. Check that it has not been moved or deleted.`
    }
    return t`The vault cannot be opened right now. Please try again later.`
  }

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
    return () => {
      active = false
    }
  }, [state])

  useEffect(() => {
    if (state !== 'locked' || settings) return
    void loadSettings().catch(() => {
      // A missing settings service must not block master-password unlock.
    })
  }, [loadSettings, settings, state])

  useEffect(() => {
    if (state !== 'locked' && state !== 'uninitialized') return
    let active = true
    const requestId = ++accountStatusRequestRef.current
    queueMicrotask(() => {
      if (!active) return
      setAccountStatus(null)
      setAccountError('')
      void window.bearwarden.accounts.status().then(
        (status) => {
          if (active && requestId === accountStatusRequestRef.current) setAccountStatus(status)
        },
        () => {
          if (active && requestId === accountStatusRequestRef.current) {
            setAccountStatus(null)
            setAccountError(t`The local account list could not be loaded. Try again later.`)
          }
        }
      )
    })
    return () => {
      active = false
    }
  }, [state, t])

  async function switchLocalAccount(accountId: string): Promise<void> {
    if (!accountStatus || accountId === accountStatus.activeAccountId || authOperationRef.current)
      return
    authOperationRef.current = true
    accountStatusRequestRef.current += 1
    setMasterPassword('')
    setConfirmation('')
    setPin('')
    setError('')
    setAccountError('')
    setAccountSwitching(true)
    try {
      const result = await window.bearwarden.accounts.switch(accountId)
      setAccountStatus(result.status)
      if (!accountMutationKeepsBusy(result)) {
        authOperationRef.current = false
        setAccountSwitching(false)
      }
    } catch (switchError) {
      setAccountError(accountMutationError(switchError))
      authOperationRef.current = false
      setAccountSwitching(false)
    }
  }

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    setError('')

    if (!isSetup && unlockMethod === 'pin') {
      if (authOperationRef.current) return
      if (pin.normalize('NFC').length < 4) {
        setError(t`The PIN must contain at least 4 characters.`)
        return
      }
      const request = { pin }
      authOperationRef.current = true
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
        // A concurrent lock invalidates the attempt without consuming PIN retries.
        const invalidatedByLock =
          submitError instanceof Error && submitError.message.includes('LOCKED')
        setError(
          nextStatus.available && !invalidatedByLock
            ? t({
                message: plural(nextStatus.remainingAttempts, {
                  one: `${base} You have # attempt remaining.`,
                  other: `${base} You have # attempts remaining.`
                })
              })
            : nextStatus.available
              ? base
              : t`PIN unlock is no longer available. Enter your master password.`
        )
      } finally {
        request.pin = ''
        authOperationRef.current = false
        setSubmitting(false)
      }
      return
    }

    if (!masterPassword) {
      setError(t`Enter your master password.`)
      return
    }
    if (isSetup && masterPassword.length < 12) {
      setError(t`The master password must contain at least 12 characters.`)
      return
    }
    if (isSetup && masterPassword !== confirmation) {
      setError(t`The master passwords do not match.`)
      return
    }

    if (authOperationRef.current) return
    authOperationRef.current = true
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
      authOperationRef.current = false
      setSubmitting(false)
    }
  }

  async function unlockWithTouchId(): Promise<void> {
    if (authOperationRef.current) return
    authOperationRef.current = true
    setError('')
    setSubmitting(true)
    try {
      const status = await window.bearwarden.settings.unlockTouchId()
      if (status.state === 'unlocked') onAuthenticated('unlock')
    } catch (touchIdError) {
      focusPasswordAfterTouchIdRef.current = true
      setPin('')
      setUnlockMethod('master-password')
      setError(
        touchIdError instanceof Error && touchIdError.message.includes('TOUCH_ID_UNAVAILABLE')
          ? t`Biometric unlock is unavailable right now. Enter your master password.`
          : t`The vault could not be unlocked with biometrics. Enter your master password.`
      )
    } finally {
      authOperationRef.current = false
      setSubmitting(false)
    }
  }

  return (
    <main
      className={cn(
        'bg-background relative flex min-h-full flex-col items-center overflow-y-auto px-6',
        isMac && 'platform-macos',
        isWindows && 'platform-windows',
        (isMac || isWindows) && 'bg-transparent'
      )}
    >
      <AuthMeshGradientBackground />
      <div
        className="pointer-events-auto absolute inset-x-0 top-0 z-10 h-[52px] [-webkit-app-region:drag]"
        aria-hidden="true"
      />
      {usesWindowControlsOverlay && (
        <div className="absolute top-0 left-[env(titlebar-area-x,0px)] z-20 flex h-[env(titlebar-area-height,54px)] w-[env(titlebar-area-width,100%)] items-center px-3.5">
          <ApplicationTitlebarMenu />
        </div>
      )}
      <div className="relative z-10 mt-[20vh] mb-8 flex w-full max-w-[440px] shrink-0 flex-col items-center gap-4">
        <BrandMark stacked />
        <section
          className="w-full max-w-[440px] rounded-[20px] bg-[color-mix(in_oklch,var(--card)_84%,transparent)] p-7 shadow-[var(--shadow)] outline outline-[color-mix(in_oklch,var(--foreground)_8%,transparent)] backdrop-blur-[28px]"
          aria-labelledby="auth-title"
        >
          {state === 'loading' && (
            <div className="grid justify-items-start gap-3" role="status">
              <Spinner className="size-7" aria-hidden="true" />
              <h1 className="m-0 text-[23px] leading-[1.2] tracking-[-0.025em]" id="auth-title">
                <Trans>Opening secure vault</Trans>
              </h1>
              <p className="text-muted-foreground m-0 leading-[1.6]">
                <Trans>All data is decrypted on this device.</Trans>
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
                <Trans>Unable to connect to the security service</Trans>
              </h1>
              <p className="text-muted-foreground m-0 leading-[1.6]">
                <Trans>
                  BearWarden could not load the vault service. Your data has not been changed.
                </Trans>
              </p>
              <Button className="mt-2" type="button" onClick={onRetry}>
                <RotateCcw data-icon="inline-start" aria-hidden="true" />
                <Trans>Try again</Trans>
              </Button>
            </div>
          )}

          {(state === 'locked' || state === 'uninitialized') && (
            <form className="grid gap-[18px]" onSubmit={handleSubmit}>
              <div className="grid grid-cols-[auto_1fr] items-start gap-3.5">
                <div>
                  <h1 className="m-0 text-[23px] leading-[1.2] tracking-[-0.025em]" id="auth-title">
                    {isSetup ? t`Create your vault` : t`Welcome back`}
                  </h1>
                  <p className="text-muted-foreground mt-[7px] mb-0 leading-[1.6]">
                    {isSetup
                      ? t`Set a master password that only you know. BearWarden cannot recover it for you.`
                      : unlockMethod === 'pin'
                        ? t`Enter the PIN set for this session.`
                        : t`Enter your master password to unlock items stored on this device.`}
                  </p>
                </div>
              </div>

              <FieldGroup>
                {accountStatus && accountStatus.accounts.length > 1 && (
                  <Field>
                    <FieldLabel htmlFor="auth-local-account">
                      <Trans
                        context="local-account-selector"
                        comment="Field label for choosing which device-local vault account to unlock; this is not a remote Bitwarden profile."
                      >
                        Local account
                      </Trans>
                    </FieldLabel>
                    <Select
                      items={accountItems}
                      value={accountStatus.activeAccountId}
                      disabled={submitting || accountSwitching}
                      onValueChange={(value) => {
                        if (typeof value === 'string' && value.length > 0) {
                          void switchLocalAccount(value)
                        }
                      }}
                    >
                      <SelectTrigger id="auth-local-account" className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          {accountItems.map((account) => (
                            <SelectItem key={account.value} value={account.value}>
                              {account.label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </Field>
                )}
                {!isSetup && unlockMethod === 'pin' ? (
                  <Field data-invalid={Boolean(error)}>
                    <FieldLabel htmlFor="vault-pin">{t`PIN`}</FieldLabel>
                    <Input
                      ref={pinRef}
                      id="vault-pin"
                      type="password"
                      name="vault-pin"
                      autoComplete="off"
                      value={pin}
                      onChange={(event) => setPin(event.target.value)}
                      disabled={submitting || accountSwitching}
                      aria-invalid={Boolean(error)}
                      aria-describedby={error ? 'auth-error' : undefined}
                    />
                  </Field>
                ) : (
                  <Field data-invalid={Boolean(error)}>
                    <FieldLabel htmlFor="master-password">
                      <Trans>Master password</Trans>
                    </FieldLabel>
                    <Input
                      ref={passwordRef}
                      id="master-password"
                      type="password"
                      name="master-password"
                      autoComplete={isSetup ? 'new-password' : 'current-password'}
                      value={masterPassword}
                      onChange={(event) => setMasterPassword(event.target.value)}
                      disabled={submitting || accountSwitching}
                      aria-invalid={Boolean(error)}
                      aria-describedby={error ? 'auth-error' : undefined}
                    />
                  </Field>
                )}

                {isSetup && (
                  <Field data-invalid={Boolean(error)}>
                    <FieldLabel htmlFor="master-password-confirmation">
                      <Trans>Confirm master password</Trans>
                    </FieldLabel>
                    <Input
                      id="master-password-confirmation"
                      type="password"
                      name="master-password-confirmation"
                      autoComplete="new-password"
                      value={confirmation}
                      onChange={(event) => setConfirmation(event.target.value)}
                      disabled={submitting || accountSwitching}
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

              {accountError && (
                <Alert id="auth-account-error" variant="destructive">
                  <AlertDescription>{accountError}</AlertDescription>
                </Alert>
              )}

              {accountSwitching && (
                <p
                  className="text-muted-foreground m-0 flex items-center gap-2 text-sm"
                  role="status"
                >
                  <Spinner className="size-4" aria-hidden="true" />
                  <Trans>Securely switching accounts and restarting</Trans>
                </p>
              )}

              <Button
                className="h-10 w-full"
                type="submit"
                disabled={submitting || accountSwitching}
              >
                {submitting ? (
                  <Spinner data-icon="inline-start" aria-hidden="true" />
                ) : (
                  <ArrowRight data-icon="inline-start" aria-hidden="true" />
                )}
                {isSetup
                  ? t`Create and unlock`
                  : unlockMethod === 'pin'
                    ? t`Unlock with PIN`
                    : t`Unlock vault`}
              </Button>
              {!isSetup && pinStatus.available && (
                <Button
                  className="h-10 w-full"
                  variant="outline"
                  type="button"
                  disabled={submitting || accountSwitching}
                  onClick={() => {
                    setError('')
                    setMasterPassword('')
                    setPin('')
                    setUnlockMethod((current) => (current === 'pin' ? 'master-password' : 'pin'))
                  }}
                >
                  <KeyRound data-icon="inline-start" aria-hidden="true" />
                  {unlockMethod === 'pin' ? t`Use master password` : t`Unlock with PIN`}
                </Button>
              )}
              {!isSetup && settings?.touchIdAvailable && settings.touchIdEnabled && (
                <Button
                  className="h-10 w-full"
                  variant="secondary"
                  type="button"
                  disabled={submitting || accountSwitching}
                  onClick={() => void unlockWithTouchId()}
                >
                  {submitting ? (
                    <Spinner data-icon="inline-start" aria-hidden="true" />
                  ) : (
                    <Fingerprint data-icon="inline-start" aria-hidden="true" />
                  )}
                  <Trans>Unlock with biometrics</Trans>
                </Button>
              )}
            </form>
          )}
        </section>
      </div>
      <p className="text-muted-foreground relative z-10 m-0 mt-auto mb-[18px] shrink-0 text-[11px]">
        <Trans>Your master password and decrypted data never leave this device.</Trans>
      </p>
    </main>
  )
}

export default AuthScreen
