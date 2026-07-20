import { useEffect, useRef, useState } from 'react'
import { useLingui } from '@lingui/react/macro'
import { AlertTriangle, Check, GitBranch, KeyRound, ShieldAlert } from 'lucide-react'
import type {
  SshAgentApprovalPrompt,
  SshAgentApprovalResponse
} from '../../../shared/vault-contract'
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import { Badge } from '@renderer/components/ui/badge'
import { Button } from '@renderer/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from '@renderer/components/ui/dialog'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import { Spinner } from '@renderer/components/ui/spinner'
import { canApproveSshAgentApproval } from '@renderer/lib/ssh-agent-ui'

export type SshAgentApprovalView = SshAgentApprovalPrompt

interface SshAgentApprovalDialogProps {
  request: SshAgentApprovalView
  onRespond: (response: SshAgentApprovalResponse) => Promise<void>
  onSettled: () => void
}

/**
 * This is intentionally a controlled modal: closing it, pressing Escape, and refusing all use
 * the same fail-closed response path. The renderer receives no private key or data-to-sign.
 */
export default function SshAgentApprovalDialog({
  request,
  onRespond,
  onSettled
}: SshAgentApprovalDialogProps): React.JSX.Element {
  const { i18n, t } = useLingui()
  const [renderedAt] = useState(() => Date.now())
  const [masterPassword, setMasterPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [expired, setExpired] = useState(() => request.expiresAt <= Date.now())
  const settledRef = useRef(false)
  const processingRef = useRef(false)
  const mountedRef = useRef(true)
  const onSettledRef = useRef(onSettled)
  const purpose = (() => {
    switch (request.namespace) {
      case 'git':
        return {
          label: t`Git signing`,
          detail: t`This app wants to use the SSH key to sign Git content.`
        }
      case 'file':
        return {
          label: t`File signing`,
          detail: t`This app wants to use the SSH key to sign file content.`
        }
      case 'unsupported':
        return {
          label: t`Unknown SSHSIG`,
          detail: t`The signing purpose isn't in an SSHSIG namespace that BearWarden recognizes.`
        }
      default:
        return {
          label: t`SSH authentication`,
          detail: t`This app wants to use the SSH key for authentication or signing.`
        }
    }
  })()
  const remainingSeconds = Math.max(0, Math.ceil((request.expiresAt - renderedAt) / 1_000))
  const formattedRemainingSeconds = new Intl.NumberFormat(i18n.locale).format(remainingSeconds)
  const expiryMessage =
    remainingSeconds > 0
      ? t`This request expires in about ${formattedRemainingSeconds} seconds.`
      : t`This request has expired.`

  useEffect(() => {
    onSettledRef.current = onSettled
  }, [onSettled])

  useEffect(() => {
    return () => {
      mountedRef.current = false
    }
  }, [])

  useEffect(() => {
    const delay = Math.max(0, request.expiresAt - Date.now())
    const timeout = window.setTimeout(() => {
      setExpired(true)
      onSettledRef.current()
    }, delay)
    return () => window.clearTimeout(timeout)
  }, [request.expiresAt])

  async function settle(approved: boolean): Promise<void> {
    if (settledRef.current || processingRef.current || busy) return
    if (approved && !canApproveSshAgentApproval(request, masterPassword)) {
      setError(
        expired
          ? t`This signing request has expired. Run the original SSH operation again.`
          : t`Enter your master password to approve this protected SSH key.`
      )
      return
    }

    processingRef.current = true
    setBusy(true)
    setError('')
    try {
      let authorizationToken: string | undefined
      if (approved && request.requiresReprompt) {
        const authorization = await window.bearwarden.logins.authorize({
          id: request.itemId,
          masterPassword
        })
        authorizationToken = authorization.token
      }
      settledRef.current = true
      await onRespond({ requestId: request.requestId, approved, authorizationToken })
      if (mountedRef.current) setMasterPassword('')
      onSettled()
    } catch {
      settledRef.current = false
      if (mountedRef.current) {
        setError(
          approved
            ? t`Couldn't approve this signing request. Check your master password and try again.`
            : t`Couldn't deny this signing request. Wait for it to expire or lock the vault again.`
        )
      }
    } finally {
      processingRef.current = false
      if (mountedRef.current) setBusy(false)
    }
  }

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) void settle(false)
      }}
    >
      <DialogContent className="max-w-lg" showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>{t`Approve SSH key signing?`}</DialogTitle>
          <DialogDescription>
            {t`BearWarden uses the selected SSH key only after you approve; the private key and content to sign never leave the main process.`}
          </DialogDescription>
        </DialogHeader>

        <FieldGroup>
          <Field>
            <FieldLabel>{t`Key`}</FieldLabel>
            <FieldDescription>{request.itemName}</FieldDescription>
            <Badge variant="outline">{request.fingerprint}</Badge>
          </Field>
          <Field>
            <FieldLabel>{t`Purpose`}</FieldLabel>
            <FieldDescription>{purpose.detail}</FieldDescription>
            <Badge variant="secondary">
              {request.namespace === 'git' ? <GitBranch /> : <KeyRound />}
              {purpose.label}
            </Badge>
          </Field>
          {request.processName && (
            <Field>
              <FieldLabel>{t`Requesting app`}</FieldLabel>
              <FieldDescription>{request.processName}</FieldDescription>
            </Field>
          )}
        </FieldGroup>

        {request.forwarded && (
          <Alert variant="destructive">
            <ShieldAlert aria-hidden="true" />
            <AlertTitle>{t`This request came through SSH agent forwarding`}</AlertTitle>
            <AlertDescription>
              {request.hostFingerprint
                ? t`Verified remote host fingerprint: ${request.hostFingerprint}`
                : t`The remote host hasn't provided a verifiable host fingerprint. Approve only on an SSH connection you trust.`}
            </AlertDescription>
          </Alert>
        )}

        {request.requiresReprompt && (
          <FieldGroup>
            <Field data-invalid={Boolean(error)}>
              <FieldLabel htmlFor="ssh-agent-master-password">{t`Confirm master password`}</FieldLabel>
              <Input
                id="ssh-agent-master-password"
                type="password"
                autoComplete="current-password"
                value={masterPassword}
                disabled={busy || expired}
                aria-invalid={Boolean(error)}
                onChange={(event) => setMasterPassword(event.target.value)}
              />
              <FieldDescription>
                {t`Your master password is sent only to the local main process for verification. Approval grants a one-time capability token.`}
              </FieldDescription>
            </Field>
          </FieldGroup>
        )}

        <Alert>
          <AlertTriangle aria-hidden="true" />
          <AlertTitle>{expiryMessage}</AlertTitle>
          <AlertDescription>{t`If you aren't sure where this request came from, deny it.`}</AlertDescription>
        </Alert>
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <DialogFooter>
          <Button
            variant="outline"
            type="button"
            disabled={busy}
            onClick={() => void settle(false)}
          >
            {t`Deny`}
          </Button>
          <Button
            type="button"
            disabled={busy || !canApproveSshAgentApproval(request, masterPassword)}
            onClick={() => void settle(true)}
          >
            {busy ? (
              <Spinner data-icon="inline-start" aria-hidden="true" />
            ) : (
              <Check data-icon="inline-start" aria-hidden="true" />
            )}
            {t`Approve signing`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
