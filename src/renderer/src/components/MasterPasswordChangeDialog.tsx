import { useCallback, useRef, useState } from 'react'
import { KeyRound, ShieldAlert, TriangleAlert } from 'lucide-react'
import { Trans, useLingui } from '@lingui/react/macro'
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
  const { t } = useLingui()
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

  function stateGuidance(state: MasterPasswordChangeState): {
    title: string
    description: string
  } | null {
    if (state === 'completed') {
      return {
        title: t`Master password changed`,
        description: t`Your remote account and local encrypted vault have been updated. Reconnect using your new master password.`
      }
    }
    if (state === 'remote-not-changed') {
      return {
        title: t`Server confirms master password was not changed`,
        description: t`The previous uncertain operation did not change your remote account. This is not a retry; to start a new change, explicitly acknowledge it and reconnect first.`
      }
    }
    if (state === 'needs-reconnect') {
      return {
        title: t`Reconnect required before confirmation`,
        description: t`BearWarden can't safely determine the remote outcome on the current connection. No new action will be submitted now to prevent duplicate changes.`
      }
    }
    if (state === 'indeterminate') {
      return {
        title: t`Remote outcome remains indeterminate`,
        description: t`Stop and reconnect. Do not submit another master-password change until you confirm which master password lets you sign in.`
      }
    }
    return null
  }

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
        setError(
          t`Unable to safely read the master-password change status. Reconnect and check again.`
        )
      }
    } finally {
      if (activeRequest === requestId.current) setLoading(false)
    }
  }, [t])

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
      setError(
        t`Your current master password must be ${MIN_PASSWORD_LENGTH} to ${MAX_PASSWORD_LENGTH} characters.`
      )
      return false
    }
    if (normalizedNew.length < MIN_PASSWORD_LENGTH || normalizedNew.length > MAX_PASSWORD_LENGTH) {
      setError(
        t`Your new master password must be ${MIN_PASSWORD_LENGTH} to ${MAX_PASSWORD_LENGTH} characters.`
      )
      return false
    }
    if (normalizedCurrent === normalizedNew) {
      setError(t`Your new master password must be different from your current master password.`)
      return false
    }
    if (normalizedConfirmation !== normalizedNew) {
      setError(t`The new master passwords do not match.`)
      return false
    }
    if (hint.normalize('NFC').length > MAX_HINT_LENGTH) {
      setError(t`Your master-password hint can be at most ${MAX_HINT_LENGTH} characters.`)
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
          ? t`Your current master password could not be verified.`
          : t`Unable to safely complete the master-password change. Reopen this screen to check the transaction status.`
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
          <Trans>Change master password</Trans>
        </DialogTrigger>
        <DialogContent className="sm:max-w-lg" showCloseButton={false}>
          <DialogHeader>
            <DialogTitle>
              <Trans>Change master password</Trans>
            </DialogTitle>
            <DialogDescription>
              <Trans>
                Update your Vaultwarden or Bitwarden account password and local vault unlock
                password.
              </Trans>
            </DialogDescription>
          </DialogHeader>

          {loading ? (
            <div className="flex items-center gap-2 py-6 text-sm" role="status">
              <Spinner /> <Trans>Checking the status of the previous change…</Trans>
            </div>
          ) : (
            <div className="flex flex-col gap-4">
              <Alert>
                <ShieldAlert aria-hidden="true" />
                <AlertTitle>
                  <Trans>Your account encryption key will not be rotated</Trans>
                </AlertTitle>
                <AlertDescription>
                  <Trans>
                    This only changes your master password and its protection. It does not create a
                    new account encryption key. After it is complete, biometrics will be disabled
                    and you must reconnect using your new master password.
                  </Trans>
                </AlertDescription>
              </Alert>

              {verifyingRemote && (
                <Alert>
                  <TriangleAlert aria-hidden="true" />
                  <AlertTitle>
                    <Trans>Confirm the remote outcome and recover the existing change</Trans>
                  </AlertTitle>
                  <AlertDescription>
                    <Trans>
                      Enter the original master password and the new password you set. This only
                      confirms the remote state and completes local recovery; it does not resubmit
                      the master-password change.
                    </Trans>
                  </AlertDescription>
                </Alert>
              )}

              {resumingLocal && (
                <Alert>
                  <TriangleAlert aria-hidden="true" />
                  <AlertTitle>
                    <Trans>Complete the locally pending change confirmed by the server</Trans>
                  </AlertTitle>
                  <AlertDescription>
                    <Trans>
                      The remote master password has been confirmed as changed. Enter the original
                      master password and the new password you set so BearWarden can re-encrypt your
                      local vault; the transaction record prevents the remote change from being sent
                      again.
                    </Trans>
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
                      <Trans>
                        I understand the previous operation did not change the remote master
                        password
                      </Trans>
                    </FieldLabel>
                    <FieldDescription>
                      <Trans>
                        After you acknowledge this, reconnect. You can start a new master-password
                        change only after reconnecting.
                      </Trans>
                    </FieldDescription>
                  </FieldContent>
                </Field>
              )}

              {formAvailable && (
                <form onSubmit={requestConfirmation}>
                  <FieldGroup>
                    <Field data-invalid={Boolean(error)}>
                      <FieldLabel htmlFor="master-password-current">
                        {recovery ? t`Original master password` : t`Current master password`}
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
                        {recovery ? t`New master password you set` : t`New master password`}
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
                        {t`At least ${MIN_PASSWORD_LENGTH} characters. Keep it safe: BearWarden cannot recover it.`}
                      </FieldDescription>
                    </Field>
                    <Field data-invalid={Boolean(error)}>
                      <FieldLabel htmlFor="master-password-confirm">
                        <Trans>Confirm new master password</Trans>
                      </FieldLabel>
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
                        <FieldLabel htmlFor="master-password-hint">
                          <Trans>Master-password hint (optional)</Trans>
                        </FieldLabel>
                        <Input
                          id="master-password-hint"
                          value={hint}
                          disabled={busy}
                          maxLength={MAX_HINT_LENGTH}
                          aria-invalid={hint.normalize('NFC').length > MAX_HINT_LENGTH}
                          onChange={(event) => setHint(event.target.value)}
                        />
                        <FieldDescription>
                          {t`At most ${MAX_HINT_LENGTH} characters. Do not enter your master password directly.`}
                        </FieldDescription>
                      </Field>
                    )}
                    {error && <FieldError>{error}</FieldError>}
                    <Button type="submit" disabled={busy}>
                      {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                      {verifyingRemote
                        ? t`Confirm remote outcome`
                        : resumingLocal
                          ? t`Complete local change`
                          : t`Check and continue`}
                    </Button>
                  </FieldGroup>
                </form>
              )}

              {!formAvailable && error && <FieldError>{error}</FieldError>}
            </div>
          )}

          <DialogFooter>
            <DialogClose render={<Button variant="outline" type="button" disabled={busy} />}>
              <Trans>Close</Trans>
            </DialogClose>
            {status?.requiresReconnect && (
              <Button
                type="button"
                disabled={
                  busy || (status.state === 'remote-not-changed' && !acknowledgedRemoteNotChanged)
                }
                onClick={reconnect}
              >
                <Trans>Reconnect</Trans>
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
                ? t`Confirm the remote master-password outcome?`
                : resumingLocal
                  ? t`Complete the confirmed local master-password change?`
                  : t`Change your master password?`}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {verifyingRemote
                ? t`This uses the original and new master passwords you entered to confirm the remote outcome and complete local recovery. It does not resubmit the change.`
                : resumingLocal
                  ? t`The remote change has already been confirmed. This only completes local vault re-encryption; the transaction record prevents the remote change from being resent.`
                  : t`This updates your remote account password and local encrypted vault. Your account encryption key will not be rotated; you must reconnect when it is complete.`}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>
              <Trans>Back to review</Trans>
            </AlertDialogCancel>
            <AlertDialogAction disabled={busy} onClick={() => void submitConfirmed()}>
              {verifyingRemote
                ? t`Confirm remote outcome`
                : resumingLocal
                  ? t`Complete local change`
                  : t`Change master password`}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

export default MasterPasswordChangeDialog
