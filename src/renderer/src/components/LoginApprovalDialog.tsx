import { Fingerprint, ShieldCheck, ShieldX } from 'lucide-react'
import { useState } from 'react'
import { useLingui } from '@lingui/react/macro'
import type { LoginApprovalPrompt } from '../../../shared/vault-contract'
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import { Button } from '@renderer/components/ui/button'
import { Checkbox } from '@renderer/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from '@renderer/components/ui/dialog'
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldLabel,
  FieldTitle
} from '@renderer/components/ui/field'
import { Spinner } from '@renderer/components/ui/spinner'

interface LoginApprovalDialogProps {
  prompt: LoginApprovalPrompt
  onClose: () => void
  onSettled?: (approved: boolean) => void | Promise<void>
}

export default function LoginApprovalDialog({
  prompt,
  onClose,
  onSettled
}: LoginApprovalDialogProps): React.JSX.Element {
  const { i18n, t } = useLingui()
  const [fingerprintMatches, setFingerprintMatches] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  function formatRequestTime(value: string): string {
    const date = new Date(value)
    if (!Number.isFinite(date.getTime())) return t`Time unavailable`
    return new Intl.DateTimeFormat(i18n.locale, {
      dateStyle: 'medium',
      timeStyle: 'short'
    }).format(date)
  }

  function loginApprovalError(responseError: unknown): string {
    if (responseError instanceof Error && responseError.message.includes('INVALID_INPUT')) {
      return t`This login request has expired, was handled on another device, or its verification phrase changed. Refresh and check again.`
    }
    if (responseError instanceof Error && responseError.message.includes('SYNC_AUTH_REQUIRED')) {
      return t`Your Bitwarden sign-in has expired, so this request can't be handled.`
    }
    return t`We couldn't confirm that the server received the response. Refresh your pending requests before trying again.`
  }

  async function respond(approved: boolean): Promise<void> {
    if (busy || (approved && !fingerprintMatches)) return
    setBusy(true)
    setError('')
    try {
      await window.bearwarden.accountSecurity.respondLoginApproval({
        token: prompt.token,
        fingerprint: prompt.fingerprint,
        approved
      })
      await onSettled?.(approved)
      onClose()
    } catch (responseError) {
      setError(loginApprovalError(responseError))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-lg" forceOverlay>
        <DialogHeader>
          <DialogTitle>{t`Confirm Bitwarden login request`}</DialogTitle>
          <DialogDescription>
            {t`Allow this only if you're signing in on another device and both devices show the exact same verification phrase.`}
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4">
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
            <dt className="text-muted-foreground">{t`Requesting device`}</dt>
            <dd>{prompt.requestDeviceType || t`Unknown device`}</dd>
            <dt className="text-muted-foreground">{t`Requested at`}</dt>
            <dd>{formatRequestTime(prompt.createdAt)}</dd>
            <dt className="text-muted-foreground">{t`Expires at`}</dt>
            <dd>{formatRequestTime(prompt.expiresAt)}</dd>
          </dl>
          <Alert>
            <Fingerprint aria-hidden="true" />
            <AlertTitle>{t`Verification phrase`}</AlertTitle>
            <AlertDescription>
              <code className="mt-2 block font-mono text-sm font-semibold break-words select-all">
                {prompt.fingerprint}
              </code>
            </AlertDescription>
          </Alert>
          <Field orientation="horizontal" data-disabled={busy || undefined}>
            <Checkbox
              id={`login-approval-fingerprint-${prompt.token}`}
              checked={fingerprintMatches}
              disabled={busy}
              onCheckedChange={setFingerprintMatches}
            />
            <FieldContent>
              <FieldLabel htmlFor={`login-approval-fingerprint-${prompt.token}`}>
                <FieldTitle>{t`The other device shows the exact same phrase`}</FieldTitle>
              </FieldLabel>
              <FieldDescription>{t`If you didn't make this request, deny it and check your account security.`}</FieldDescription>
            </FieldContent>
          </Field>
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </div>
        <DialogFooter>
          <Button
            variant="destructive"
            type="button"
            disabled={busy}
            onClick={() => void respond(false)}
          >
            <ShieldX data-icon="inline-start" aria-hidden="true" />
            {t`Deny`}
          </Button>
          <Button
            type="button"
            disabled={busy || !fingerprintMatches}
            onClick={() => void respond(true)}
          >
            {busy ? (
              <Spinner data-icon="inline-start" aria-hidden="true" />
            ) : (
              <ShieldCheck data-icon="inline-start" aria-hidden="true" />
            )}
            {t`Allow login`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
