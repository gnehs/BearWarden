import { Copy, KeyRound, Plus, ShieldCheck, ShieldOff, Trash2, TriangleAlert } from 'lucide-react'
import { useState } from 'react'
import { Trans, useLingui } from '@lingui/react/macro'
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
import { useCopyFeedback } from '@renderer/hooks/use-copy-feedback'
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
import { CopyFeedbackIcon } from './CopyFeedbackIcon'

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
        <FieldLabel>
          <Trans>Registered security keys</Trans>
        </FieldLabel>
        {keyViews.length === 0 ? (
          <FieldDescription>
            <Trans>No security keys are registered yet. You can add your first key.</Trans>
          </FieldDescription>
        ) : (
          <div className="flex flex-col gap-2">
            {keyViews.map((key) => (
              <div key={key.id} className="flex flex-wrap items-center gap-2">
                <Badge variant="outline">{key.name}</Badge>
                {key.migrated && (
                  <Badge variant="secondary">
                    <Trans>Migrated</Trans>
                  </Badge>
                )}
                {canRemoveWebAuthnKey(busy, keyViews.length) && (
                  <Button
                    type="button"
                    size="sm"
                    variant="destructive"
                    disabled={busy}
                    onClick={() => onRemove(key)}
                  >
                    <Trash2 data-icon="inline-start" aria-hidden="true" />
                    <Trans>Remove</Trans>
                  </Button>
                )}
              </div>
            ))}
          </div>
        )}
        {keyViews.length === 1 && (
          <FieldDescription>
            <Trans>Keep at least one security key. The last key cannot be removed here.</Trans>
          </FieldDescription>
        )}
      </Field>
    </FieldGroup>
  )
}

function AccountTwoFactorDialog(): React.JSX.Element {
  const { t } = useLingui()
  const providerNames: Record<number, string> = {
    0: t`Authenticator app`,
    1: t`Email`,
    2: t`Duo`,
    3: t`YubiKey OTP`,
    4: t`U2F`,
    5: t`Remember this device`,
    6: t`Organization Duo`,
    7: t`FIDO2 WebAuthn`,
    8: t`Recovery code`
  }
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
  const { copiedKey, clearCopied, showCopied } = useCopyFeedback()
  const disableTargetName =
    disableTarget === null ? t`two-factor authentication` : providerNames[disableTarget]

  async function load(): Promise<void> {
    setBusy(true)
    setError('')
    try {
      setProviders(await window.bearwarden.accountSecurity.twoFactorStatus())
    } catch {
      setError(t`Unable to read the two-factor authentication status.`)
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
    clearCopied()
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
      setDisableError(t`Enter your master password.`)
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
      const providerName = providerNames[type]
      setSuccess(t`${providerName} has been disabled.`)
      await load()
    } catch (disableFailure) {
      if (
        disableFailure instanceof Error &&
        disableFailure.message.includes('TWO_FACTOR_MUTATION_UNKNOWN')
      ) {
        setDisableTarget(null)
        await load()
        const providerName = providerNames[type]
        setError(
          t`The result of disabling ${providerName} is unknown. The status has been refreshed. Check the current status before retrying.`
        )
      } else if (
        disableFailure instanceof Error &&
        disableFailure.message.includes('INVALID_MASTER_PASSWORD')
      ) {
        setDisableError(
          t`Master password verification failed. Enter your master password again to retry.`
        )
      } else {
        const providerName = providerNames[type]
        setDisableError(t`Unable to disable ${providerName}. Try again later.`)
      }
    } finally {
      request.masterPassword = ''
      setBusy(false)
    }
  }

  async function beginAuthenticatorSetup(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (!authenticatorPassword) {
      setError(t`Enter your master password.`)
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
          ? t`Master password verification failed.`
          : t`Unable to start authenticator setup.`
      )
    } finally {
      setBusy(false)
    }
  }

  async function copyAuthenticatorKey(): Promise<void> {
    if (!authenticatorSetup) return
    setBusy(true)
    setError('')
    clearCopied()
    try {
      await window.bearwarden.accountSecurity.copyAuthenticatorKey({
        sessionId: authenticatorSetup.sessionId
      })
      showCopied('authenticator-key')
      setSuccess(t`The setup key has been copied. The clipboard will be cleared within 30 seconds.`)
    } catch {
      setAuthenticatorSetup(null)
      setError(t`The setup session has expired. Start again.`)
    } finally {
      setBusy(false)
    }
  }

  async function completeAuthenticatorSetup(
    event: React.FormEvent<HTMLFormElement>
  ): Promise<void> {
    event.preventDefault()
    if (!authenticatorSetup || !/^\d{6}$/.test(authenticatorToken)) {
      setError(t`Enter the 6-digit verification code shown by your authenticator.`)
      return
    }
    if (authenticatorSetup.requiresMasterPassword && !completionPassword) {
      setError(t`This server requires your master password again.`)
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
      setSuccess(t`The authenticator app has been enabled.`)
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
        setError(
          t`The server response was interrupted, so the activation result is unknown. The status has been refreshed. Do not retry immediately.`
        )
      } else if (
        setupError instanceof Error &&
        setupError.message.includes('INVALID_MASTER_PASSWORD')
      ) {
        setError(t`Master password verification failed. Restart setup.`)
      } else {
        setError(t`Unable to enable the authenticator. Restart setup.`)
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
      setError(t`Enter your master password.`)
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
          ? t`Master password verification failed.`
          : t`Unable to start email two-factor authentication setup.`
      )
    } finally {
      setBusy(false)
    }
  }

  async function sendEmailSetupCode(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (!emailSetup || !/^[^\s@]+@[^\s@]+$/.test(emailAddress)) {
      setError(t`Enter a valid email address.`)
      return
    }
    if (emailSetup.requiresMasterPassword && !emailSendPassword) {
      setError(t`This server requires your master password again.`)
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
      setSuccess(t`The verification code has been sent.`)
    } catch (setupError) {
      const outcomeUnknown =
        setupError instanceof Error && setupError.message.includes('TWO_FACTOR_MUTATION_UNKNOWN')
      resetEmailSetup()
      if (outcomeUnknown) {
        await load()
        setError(
          t`The send result is unknown. The status has been refreshed. Do not resend immediately.`
        )
      } else if (
        setupError instanceof Error &&
        setupError.message.includes('INVALID_MASTER_PASSWORD')
      ) {
        setError(t`Master password verification failed. Restart setup.`)
      } else {
        setError(t`Unable to send the verification code. Restart setup.`)
      }
    } finally {
      setBusy(false)
    }
  }

  async function completeEmailSetup(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (!emailSetup || !emailCodeSent || !/^\d{1,50}$/.test(emailToken)) {
      setError(t`Enter the numeric verification code from the email.`)
      return
    }
    if (emailSetup.requiresMasterPassword && !emailCompletionPassword) {
      setError(t`This server requires your master password again.`)
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
      setSuccess(t`Email two-factor authentication has been enabled.`)
      await load()
    } catch (setupError) {
      const outcomeUnknown =
        setupError instanceof Error && setupError.message.includes('TWO_FACTOR_MUTATION_UNKNOWN')
      resetEmailSetup()
      if (outcomeUnknown) {
        await load()
        setError(
          t`The activation result is unknown. The status has been refreshed. Do not retry immediately.`
        )
      } else if (
        setupError instanceof Error &&
        setupError.message.includes('INVALID_MASTER_PASSWORD')
      ) {
        setError(t`Master password verification failed. Restart setup.`)
      } else {
        setError(t`Unable to enable email two-factor authentication. Restart setup.`)
      }
    } finally {
      setBusy(false)
    }
  }

  async function copyRecoveryCode(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (!masterPassword) {
      setError(t`Enter your master password.`)
      return
    }
    setBusy(true)
    setError('')
    setSuccess('')
    clearCopied()
    try {
      await window.bearwarden.accountSecurity.copyRecoveryCode({ masterPassword })
      setMasterPassword('')
      showCopied('recovery-code')
      setSuccess(
        t`The recovery code has been copied. The clipboard will be cleared within 30 seconds.`
      )
    } catch (copyError) {
      setMasterPassword('')
      setError(
        copyError instanceof Error && copyError.message.includes('INVALID_MASTER_PASSWORD')
          ? t`Master password verification failed.`
          : t`Unable to retrieve the recovery code.`
      )
    } finally {
      setBusy(false)
    }
  }

  async function listWebAuthnKeys(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (busy) return
    if (!webAuthnListPassword) {
      setWebAuthnError(t`Enter your master password.`)
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
      setWebAuthnError(t`Enter a security key name and your master password.`)
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
      setWebAuthnSuccess(
        t`The security key has been added. The two-factor authentication status and key list have been refreshed.`
      )
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
          ? t`The security key may have been added, but the list could not be refreshed. Enter your master password again to check before retrying.`
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
      setWebAuthnSuccess(
        t`The security key has been removed. The two-factor authentication status and key list have been refreshed.`
      )
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
          ? t`The security key may have been removed, but the list could not be refreshed. Enter your master password again to check before retrying.`
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
        <Trans>Two-factor authentication</Trans>
      </DialogTrigger>
      <DialogContent
        className="max-h-[min(42rem,calc(100vh-2rem))] overflow-y-auto sm:max-w-lg"
        forceOverlay
      >
        <DialogHeader>
          <DialogTitle>
            <Trans>Two-factor authentication</Trans>
          </DialogTitle>
          <DialogDescription>
            <Trans>
              Review the authentication providers currently enabled on the server and securely copy
              your recovery code.
            </Trans>
          </DialogDescription>
        </DialogHeader>
        <div
          className="flex flex-wrap gap-2"
          aria-label={t`Enabled two-factor authentication methods`}
        >
          {providers.filter((provider) => provider.enabled).length > 0 ? (
            providers
              .filter((provider) => provider.enabled)
              .map((provider) => {
                const canDisable = isDisableablePersonalProvider(provider.type)
                const providerType = provider.type
                const providerName = providerNames[providerType] ?? t`Provider ${providerType}`
                return (
                  <div key={provider.type} className="flex items-center gap-1">
                    <Badge variant="outline">{providerName}</Badge>
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
                        <Trans>Disable</Trans>
                      </Button>
                    )}
                  </div>
                )
              })
          ) : (
            <span className="text-muted-foreground text-sm">
              <Trans>No two-factor authentication methods are enabled.</Trans>
            </span>
          )}
        </div>
        {hiddenProviderEscapeTargets(providers).length > 0 && (
          <div className="grid gap-2 border-t pt-4">
            <p className="text-muted-foreground text-sm">
              <Trans>
                If the server’s Duo or YubiKey integration has stopped working, the provider may not
                appear in the status list but may still block sign-in. Use the options below with a
                fresh master password to ask the server to remove the enrollment.
              </Trans>
            </p>
            <div className="flex flex-wrap gap-2">
              {hiddenProviderEscapeTargets(providers).map((type) => {
                const providerName = providerNames[type]
                return (
                  <Button
                    key={type}
                    type="button"
                    size="sm"
                    variant="outline"
                    disabled={busy}
                    onClick={() => changeDisableTarget(type)}
                  >
                    <ShieldOff data-icon="inline-start" aria-hidden="true" />
                    <Trans>Force disable {providerName}</Trans>
                  </Button>
                )
              })}
            </div>
          </div>
        )}
        {!providers.some((provider) => provider.type === 0 && provider.enabled) && (
          <div className="grid gap-4 border-t pt-4">
            <div>
              <h3 className="text-sm font-medium">
                <Trans>Set up an authenticator app</Trans>
              </h3>
              <p className="text-muted-foreground text-sm">
                <Trans>
                  Add the key below to a compatible app such as 1Password, Bitwarden, or Google
                  Authenticator.
                </Trans>
              </p>
            </div>
            {!authenticatorSetup ? (
              <form
                className="grid gap-4"
                onSubmit={(event) => void beginAuthenticatorSetup(event)}
              >
                <Field>
                  <FieldLabel htmlFor="authenticator-setup-master-password">
                    <Trans>Master password</Trans>
                  </FieldLabel>
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
                  <Trans>Start setup</Trans>
                </Button>
              </form>
            ) : (
              <form
                className="grid gap-4"
                onSubmit={(event) => void completeAuthenticatorSetup(event)}
              >
                <Field>
                  <FieldLabel htmlFor="authenticator-setup-key">
                    <Trans>Manual setup key</Trans>
                  </FieldLabel>
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
                      aria-label={
                        copiedKey === 'authenticator-key' ? t`Setup key copied` : t`Copy setup key`
                      }
                      onClick={() => void copyAuthenticatorKey()}
                    >
                      <CopyFeedbackIcon copied={copiedKey === 'authenticator-key'} />
                    </Button>
                  </div>
                  <FieldDescription>
                    <Trans>The key is shown only during this short-lived setup session.</Trans>
                  </FieldDescription>
                </Field>
                <Field>
                  <FieldLabel htmlFor="authenticator-token">
                    <Trans>6-digit verification code</Trans>
                  </FieldLabel>
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
                      <Trans>Enter master password again</Trans>
                    </FieldLabel>
                    <Input
                      id="authenticator-completion-password"
                      type="password"
                      autoComplete="current-password"
                      value={completionPassword}
                      disabled={busy}
                      onChange={(event) => setCompletionPassword(event.target.value)}
                    />
                    <FieldDescription>
                      <Trans>
                        Vaultwarden verifies your master password again during activation.
                      </Trans>
                    </FieldDescription>
                  </Field>
                )}
                <Button type="submit" disabled={busy || authenticatorToken.length !== 6}>
                  <Trans>Enable authenticator</Trans>
                </Button>
              </form>
            )}
          </div>
        )}
        {!providers.some((provider) => provider.type === 1 && provider.enabled) && (
          <div className="grid gap-4 border-t pt-4">
            <div>
              <h3 className="text-sm font-medium">
                <Trans>Set up email two-factor authentication</Trans>
              </h3>
              <p className="text-muted-foreground text-sm">
                <Trans>
                  The verification code will be sent to the specified address. The email address is
                  retained only during this short-lived setup flow.
                </Trans>
              </p>
            </div>
            {!emailSetup ? (
              <form className="grid gap-4" onSubmit={(event) => void beginEmailSetup(event)}>
                <Field>
                  <FieldLabel htmlFor="email-2fa-setup-password">
                    <Trans>Master password</Trans>
                  </FieldLabel>
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
                  <Trans>Start setup</Trans>
                </Button>
              </form>
            ) : !emailCodeSent ? (
              <form className="grid gap-4" onSubmit={(event) => void sendEmailSetupCode(event)}>
                <Field>
                  <FieldLabel htmlFor="email-2fa-address">
                    <Trans>Email address for verification codes</Trans>
                  </FieldLabel>
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
                    <FieldLabel htmlFor="email-2fa-send-password">
                      <Trans>Enter master password again</Trans>
                    </FieldLabel>
                    <Input
                      id="email-2fa-send-password"
                      type="password"
                      autoComplete="current-password"
                      value={emailSendPassword}
                      disabled={busy}
                      onChange={(event) => setEmailSendPassword(event.target.value)}
                    />
                    <FieldDescription>
                      <Trans>Vaultwarden verifies your master password again before sending.</Trans>
                    </FieldDescription>
                  </Field>
                )}
                <Button type="submit" disabled={busy || emailAddress.length === 0}>
                  <Trans>Send verification code</Trans>
                </Button>
              </form>
            ) : (
              <form className="grid gap-4" onSubmit={(event) => void completeEmailSetup(event)}>
                <Field>
                  <FieldLabel htmlFor="email-2fa-token">
                    <Trans>Email verification code</Trans>
                  </FieldLabel>
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
                  <FieldDescription>
                    <Trans>The verification code was sent to {emailAddress}.</Trans>
                  </FieldDescription>
                </Field>
                {emailSetup.requiresMasterPassword && (
                  <Field>
                    <FieldLabel htmlFor="email-2fa-completion-password">
                      <Trans>Enter master password again</Trans>
                    </FieldLabel>
                    <Input
                      id="email-2fa-completion-password"
                      type="password"
                      autoComplete="current-password"
                      value={emailCompletionPassword}
                      disabled={busy}
                      onChange={(event) => setEmailCompletionPassword(event.target.value)}
                    />
                    <FieldDescription>
                      <Trans>
                        Vaultwarden verifies your master password again during activation.
                      </Trans>
                    </FieldDescription>
                  </Field>
                )}
                <Button type="submit" disabled={busy || emailToken.length === 0}>
                  <Trans>Enable email two-factor authentication</Trans>
                </Button>
              </form>
            )}
          </div>
        )}
        <div className="flex flex-col gap-4 border-t pt-4">
          <div className="flex flex-col gap-1">
            <h3 className="text-sm font-medium">
              <Trans>Manage FIDO2 security keys</Trans>
            </h3>
            <p className="text-muted-foreground text-sm">
              <Trans>
                Adding a key opens a system prompt. Depending on the key, you may need to touch it
                or enter a PIN.
              </Trans>
            </p>
          </div>
          <Alert>
            <KeyRound aria-hidden="true" />
            <AlertDescription>
              <Trans>
                Store your recovery code securely first. It can help you regain access to your
                account if you lose your security key.
              </Trans>
            </AlertDescription>
          </Alert>
          {webAuthnKeys === null ? (
            <form
              className="flex flex-col gap-4"
              onSubmit={(event) => void listWebAuthnKeys(event)}
            >
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="webauthn-list-master-password">
                    <Trans>Master password</Trans>
                  </FieldLabel>
                  <Input
                    id="webauthn-list-master-password"
                    type="password"
                    autoComplete="current-password"
                    value={webAuthnListPassword}
                    disabled={busy}
                    onChange={(event) => setWebAuthnListPassword(event.target.value)}
                  />
                  <FieldDescription>
                    <Trans>
                      Your account’s registered security keys are read only after verification.
                    </Trans>
                  </FieldDescription>
                </Field>
              </FieldGroup>
              <Button type="submit" disabled={busy || webAuthnListPassword.length === 0}>
                {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                <Trans>Verify and read security keys</Trans>
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
                    <FieldLabel htmlFor="webauthn-key-name">
                      <Trans>Security key name</Trans>
                    </FieldLabel>
                    <Input
                      id="webauthn-key-name"
                      autoComplete="off"
                      maxLength={256}
                      value={webAuthnName}
                      disabled={busy}
                      onChange={(event) => setWebAuthnName(event.target.value)}
                    />
                    <FieldDescription>
                      <Trans>
                        For example, “Office USB security key.” The name is used only to identify
                        this key.
                      </Trans>
                    </FieldDescription>
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="webauthn-enrollment-master-password">
                      <Trans>Master password</Trans>
                    </FieldLabel>
                    <Input
                      id="webauthn-enrollment-master-password"
                      type="password"
                      autoComplete="current-password"
                      value={webAuthnEnrollmentPassword}
                      disabled={busy}
                      onChange={(event) => setWebAuthnEnrollmentPassword(event.target.value)}
                    />
                    <FieldDescription>
                      <Trans>
                        Your master password is used only for this add request and is cleared
                        immediately after submission.
                      </Trans>
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
                  <Trans>Add security key</Trans>
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
            <FieldLabel htmlFor="recovery-code-master-password">
              <Trans>Master password</Trans>
            </FieldLabel>
            <Input
              id="recovery-code-master-password"
              type="password"
              autoComplete="current-password"
              value={masterPassword}
              disabled={busy}
              onChange={(event) => setMasterPassword(event.target.value)}
            />
            <FieldDescription>
              <Trans>
                The recovery code is never returned to the renderer or stored by BearWarden.
              </Trans>
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
              <Trans>Close</Trans>
            </Button>
            <Button type="submit" disabled={busy || providers.length === 0}>
              {busy ? (
                <Spinner data-icon="inline-start" aria-hidden="true" />
              ) : (
                <CopyFeedbackIcon
                  copied={copiedKey === 'recovery-code'}
                  idleIcon={Copy}
                  placement="inline-start"
                />
              )}
              <Trans>Copy recovery code</Trans>
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
                  <Trans>Disable {disableTargetName}?</Trans>
                </AlertDialogTitle>
                <AlertDialogDescription>
                  <Trans>
                    This removes the two-factor authentication method from the server. Enter your
                    master password to confirm; it is used only for this request.
                  </Trans>
                </AlertDialogDescription>
              </AlertDialogHeader>
              {disableTarget !== null &&
                isLastVisiblePersonalTwoFactorMethod(providers, disableTarget) && (
                  <Alert variant="destructive">
                    <AlertDescription>
                      <Trans>
                        This is your last available personal two-factor authentication method. After
                        disabling it, your account will no longer require a recovery code or another
                        two-factor method. If your organization requires 2FA, the server may also
                        revoke your organization membership. You can still continue.
                      </Trans>
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
                      <Trans>
                        The server cannot currently report this provider’s actual status. Forcing it
                        off may remove a sign-in method that is still in use. If it is the last
                        method, your account will no longer be protected by two-factor
                        authentication.
                      </Trans>
                    </AlertDescription>
                  </Alert>
                )}
              <Field>
                <FieldLabel htmlFor="disable-2fa-master-password">
                  <Trans>Master password</Trans>
                </FieldLabel>
                <Input
                  id="disable-2fa-master-password"
                  type="password"
                  autoComplete="current-password"
                  value={disablePassword}
                  disabled={busy}
                  autoFocus
                  onChange={(event) => setDisablePassword(event.target.value)}
                />
                <FieldDescription>
                  <Trans>
                    Enter it again for every disable request; previous verification is never reused.
                  </Trans>
                </FieldDescription>
              </Field>
              {disableError && (
                <Alert variant="destructive">
                  <AlertDescription>{disableError}</AlertDescription>
                </Alert>
              )}
              <AlertDialogFooter>
                <AlertDialogCancel disabled={busy}>
                  <Trans>Back</Trans>
                </AlertDialogCancel>
                <AlertDialogAction
                  type="submit"
                  variant="destructive"
                  disabled={busy || disablePassword.length === 0}
                >
                  {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                  <Trans>Confirm disabling {disableTargetName}</Trans>
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
                <AlertDialogTitle>
                  <Trans>Remove this security key?</Trans>
                </AlertDialogTitle>
                <AlertDialogDescription>
                  <Trans>
                    You will no longer be able to sign in with this security key after removing it.
                    Enter your master password again to confirm; previous verification is never
                    reused.
                  </Trans>
                </AlertDialogDescription>
              </AlertDialogHeader>
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="webauthn-removal-master-password">
                    <Trans>Master password</Trans>
                  </FieldLabel>
                  <Input
                    id="webauthn-removal-master-password"
                    type="password"
                    autoComplete="current-password"
                    value={webAuthnRemovalPassword}
                    disabled={busy}
                    autoFocus
                    onChange={(event) => setWebAuthnRemovalPassword(event.target.value)}
                  />
                  <FieldDescription>
                    <Trans>Enter your master password again for every removal.</Trans>
                  </FieldDescription>
                </Field>
              </FieldGroup>
              <AlertDialogFooter>
                <AlertDialogCancel disabled={busy}>
                  <Trans>Back</Trans>
                </AlertDialogCancel>
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
                  <Trans>Confirm removing security key</Trans>
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
