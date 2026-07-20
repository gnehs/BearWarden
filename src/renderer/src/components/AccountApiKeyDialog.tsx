import { Copy, KeyRound, RotateCw } from 'lucide-react'
import { useState } from 'react'
import { t } from '@lingui/core/macro'
import { Trans, useLingui } from '@lingui/react/macro'
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
import { useCopyFeedback } from '@renderer/hooks/use-copy-feedback'
import { CopyFeedbackIcon } from './CopyFeedbackIcon'

function apiKeyError(error: unknown, rotate: boolean): string {
  if (!(error instanceof Error)) return t`Personal API key operation failed.`
  if (error.message.includes('INVALID_MASTER_PASSWORD'))
    return t`Master password verification failed.`
  if (error.message.includes('API_KEY_ROTATION_UNKNOWN')) {
    return t`The connection was interrupted during rotation, so the result is unknown. Do not rotate again; re-enter your master password and select “Copy current Client Secret” to verify the current value.`
  }
  if (error.message.includes('SYNC_AUTH_REQUIRED'))
    return t`Your sync session has expired. Please sign in again.`
  return rotate
    ? t`Unable to rotate your personal API key. The existing Client Secret may still be valid.`
    : t`Unable to retrieve your personal API key.`
}

function AccountApiKeyDialog(): React.JSX.Element {
  const { t: translate } = useLingui()
  const [open, setOpen] = useState(false)
  const [masterPassword, setMasterPassword] = useState('')
  const [rotate, setRotate] = useState(false)
  const [confirmRotation, setConfirmRotation] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const { copiedKey, clearCopied, showCopied } = useCopyFeedback()

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
    clearCopied()
    if (!next) clearSecrets()
  }

  async function copyClientId(): Promise<void> {
    setBusy(true)
    setError('')
    setSuccess('')
    clearCopied()
    try {
      await window.bearwarden.accountSecurity.copyApiClientId()
      showCopied('client-id')
      setSuccess(translate`Client ID copied.`)
    } catch (copyError) {
      setError(apiKeyError(copyError, false))
    } finally {
      setBusy(false)
    }
  }

  async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (!masterPassword || (rotate && !confirmRotation)) {
      setError(
        rotate
          ? translate`Enter your master password and confirm the impact of rotating your API key.`
          : translate`Enter your master password.`
      )
      return
    }
    setBusy(true)
    setError('')
    setSuccess('')
    clearCopied()
    try {
      await window.bearwarden.accountSecurity.copyApiKey({
        masterPassword,
        rotate,
        confirmRotation: rotate && confirmRotation
      })
      setMasterPassword('')
      showCopied('client-secret')
      setSuccess(
        rotate
          ? translate`Your new Client Secret was copied. The old value is no longer valid, and the clipboard will be cleared within 30 seconds.`
          : translate`Your current Client Secret was copied, and the clipboard will be cleared within 30 seconds.`
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
        <Trans>Personal API key</Trans>
      </DialogTrigger>
      <DialogContent forceOverlay>
        <DialogHeader>
          <DialogTitle>
            <Trans>Personal API key</Trans>
          </DialogTitle>
          <DialogDescription>
            <Trans>
              Used for Bitwarden CLI client credentials. BearWarden does not store your Client
              Secret.
            </Trans>
          </DialogDescription>
        </DialogHeader>
        <Button variant="outline" type="button" disabled={busy} onClick={() => void copyClientId()}>
          <CopyFeedbackIcon copied={copiedKey === 'client-id'} placement="inline-start" />
          <Trans>Copy Client ID</Trans>
        </Button>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <Field>
            <FieldLabel htmlFor="api-key-master-password">
              <Trans>Master password</Trans>
            </FieldLabel>
            <Input
              id="api-key-master-password"
              type="password"
              autoComplete="current-password"
              value={masterPassword}
              disabled={busy}
              onChange={(event) => setMasterPassword(event.target.value)}
            />
            <FieldDescription>
              <Trans>
                Used only by the main process to create a one-time server proof. It is not stored.
              </Trans>
            </FieldDescription>
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
                <FieldTitle>
                  <Trans>Rotate API key</Trans>
                </FieldTitle>
              </FieldLabel>
              <FieldDescription>
                <Trans>
                  Create a new Client Secret. The old value becomes invalid immediately.
                </Trans>
              </FieldDescription>
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
                  <FieldTitle>
                    <Trans>I understand that existing CLI sessions may need to sign in again</Trans>
                  </FieldTitle>
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
              <Trans>Close</Trans>
            </Button>
            <Button type="submit" variant={rotate ? 'destructive' : 'default'} disabled={busy}>
              {busy ? (
                <Spinner data-icon="inline-start" aria-hidden="true" />
              ) : rotate ? (
                <CopyFeedbackIcon
                  copied={copiedKey === 'client-secret'}
                  idleIcon={RotateCw}
                  placement="inline-start"
                />
              ) : (
                <CopyFeedbackIcon
                  copied={copiedKey === 'client-secret'}
                  idleIcon={Copy}
                  placement="inline-start"
                />
              )}
              {rotate ? (
                <Trans>Rotate and copy new Secret</Trans>
              ) : (
                <Trans>Copy current Client Secret</Trans>
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export default AccountApiKeyDialog
