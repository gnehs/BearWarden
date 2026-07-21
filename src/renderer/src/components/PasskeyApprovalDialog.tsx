import { useEffect, useRef, useState } from 'react'
import { useLingui } from '@lingui/react/macro'
import { AlertTriangle, Check, Fingerprint, KeyRound, ShieldAlert, X } from 'lucide-react'
import type {
  PasskeyApprovalPrompt,
  PasskeyApprovalResponse,
  PasskeyApprovalVerificationRequest
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
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue
} from '@renderer/components/ui/select'
import { Spinner } from '@renderer/components/ui/spinner'
import { ToggleGroup, ToggleGroupItem } from '@renderer/components/ui/toggle-group'
import {
  canApprovePasskeyApproval,
  initialPasskeyApprovalChoice,
  initialPasskeyApprovalVerificationMethod,
  isPasskeyApprovalExpired,
  passkeyApprovalResponseVerificationMethod,
  requiresPasskeyApprovalPasswordVerification,
  selectedPasskeyApprovalChoiceRequiresReprompt,
  type PasskeyApprovalUiVerificationMethod
} from '@renderer/lib/passkey-approval-ui'

export type PasskeyApprovalView = PasskeyApprovalPrompt

interface PasskeyApprovalDialogProps {
  request: PasskeyApprovalView
  onVerifyPassword: (request: PasskeyApprovalVerificationRequest) => Promise<void>
  onRespond: (response: PasskeyApprovalResponse) => Promise<void>
  onSettled: () => void
}

/**
 * A controlled, fail-closed prompt. The renderer sends consent and method selection only; it
 * never manufactures a user-verified signal or keeps a password after a verification attempt.
 */
export default function PasskeyApprovalDialog({
  request,
  onVerifyPassword,
  onRespond,
  onSettled
}: PasskeyApprovalDialogProps): React.JSX.Element {
  const { i18n, t } = useLingui()
  const [renderedAt] = useState(() => Date.now())
  const [selectedChoiceId, setSelectedChoiceId] = useState<string | undefined>(() =>
    initialPasskeyApprovalChoice(request)
  )
  const [verificationMethod, setVerificationMethod] = useState<
    PasskeyApprovalUiVerificationMethod | undefined
  >(() => initialPasskeyApprovalVerificationMethod(request))
  const [masterPassword, setMasterPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [expired, setExpired] = useState(() => isPasskeyApprovalExpired(request))
  const [settled, setSettled] = useState(false)
  const mountedRef = useRef(true)
  const processingRef = useRef(false)
  const settledRef = useRef(false)
  const passwordRef = useRef('')
  const onSettledRef = useRef(onSettled)
  const ceremony =
    request.kind === 'create'
      ? {
          label: t`Create a passkey`,
          detail: t`This website wants to create a new passkey for your account.`
        }
      : {
          label: t`Sign in with a passkey`,
          detail: t`This website wants to use a saved passkey to sign in.`
        }
  const registrationUser =
    request.kind === 'create' && request.userDisplayName && request.userName
      ? t`${request.userDisplayName} (${request.userName})`
      : (request.userDisplayName ?? request.userName)
  const verificationMethodLabels: Record<PasskeyApprovalUiVerificationMethod, string> = {
    'touch-id': t`Biometric authentication`,
    'master-password': t`Master password`
  }
  const requiresPassword = requiresPasskeyApprovalPasswordVerification(
    request,
    selectedChoiceId,
    verificationMethod
  )
  const canApprove = canApprovePasskeyApproval(request, {
    selectedChoiceId,
    verificationMethod,
    masterPassword
  })
  const selectableMethods =
    request.userVerification === 'discouraged'
      ? []
      : request.verificationMethods.filter(
          (method): method is PasskeyApprovalUiVerificationMethod =>
            method === 'touch-id' || method === 'master-password'
        )
  const choiceItems = [
    { label: t`Choose a passkey`, value: null },
    ...request.choices.map((choice) => ({ label: choice.label, value: choice.id }))
  ]
  const remainingSeconds = Math.max(0, Math.ceil((request.expiresAt - renderedAt) / 1_000))
  const formattedRemainingSeconds = new Intl.NumberFormat(i18n.locale).format(remainingSeconds)
  const expiryMessage =
    remainingSeconds > 0
      ? t`This request expires in about ${formattedRemainingSeconds} seconds.`
      : t`This request has expired.`

  function clearPassword(): void {
    passwordRef.current = ''
    if (mountedRef.current) setMasterPassword('')
  }

  useEffect(() => {
    onSettledRef.current = onSettled
  }, [onSettled])

  useEffect(() => {
    return () => {
      mountedRef.current = false
      passwordRef.current = ''
    }
  }, [])

  useEffect(() => {
    const delay = Math.max(0, request.expiresAt - Date.now())
    const timeout = window.setTimeout(() => {
      if (settledRef.current) return
      settledRef.current = true
      clearPassword()
      if (mountedRef.current) {
        setExpired(true)
        setSettled(true)
      }
      onSettledRef.current()
    }, delay)
    return () => window.clearTimeout(timeout)
  }, [request.expiresAt, request.requestId])

  async function settle(approved: boolean): Promise<void> {
    if (settledRef.current || processingRef.current || busy) return
    if (isPasskeyApprovalExpired(request)) {
      settledRef.current = true
      clearPassword()
      setExpired(true)
      setSettled(true)
      onSettledRef.current()
      return
    }
    if (
      approved &&
      !canApprovePasskeyApproval(request, {
        selectedChoiceId,
        verificationMethod,
        masterPassword
      })
    ) {
      setError(
        request.choices.length === 0
          ? t`This request has no passkey that can be approved. Deny it and start again.`
          : requiresPassword
            ? t`Enter your master password to continue.`
            : t`Choose a passkey and an available verification method.`
      )
      return
    }

    processingRef.current = true
    setBusy(true)
    setError('')
    if (!approved) clearPassword()
    try {
      if (approved && requiresPassword) {
        const password = passwordRef.current
        clearPassword()
        await onVerifyPassword({
          requestId: request.requestId,
          ...(selectedChoiceId === undefined ? {} : { selectedChoiceId }),
          masterPassword: password
        })
      }

      if (settledRef.current || isPasskeyApprovalExpired(request)) return
      settledRef.current = true
      const response: PasskeyApprovalResponse = approved
        ? {
            requestId: request.requestId,
            approved: true,
            selectedChoiceId,
            verificationMethod: passkeyApprovalResponseVerificationMethod(
              request,
              verificationMethod
            )
          }
        : { requestId: request.requestId, approved: false }
      await onRespond(response)
      clearPassword()
      if (mountedRef.current) setSettled(true)
      onSettledRef.current()
    } catch {
      settledRef.current = false
      clearPassword()
      if (mountedRef.current) {
        setError(
          approved
            ? t`Couldn't complete verification or approve this passkey request. Check your master password and try again.`
            : t`Couldn't deny this passkey request. Wait for it to expire or lock the vault again.`
        )
      }
    } finally {
      processingRef.current = false
      if (mountedRef.current) setBusy(false)
    }
  }

  if (settled) return <></>

  return (
    <Dialog
      open={!expired}
      onOpenChange={(open) => {
        if (!open) void settle(false)
      }}
    >
      <DialogContent className="max-w-lg" showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>{t`Approve passkey request?`}</DialogTitle>
          <DialogDescription>
            {t`BearWarden sends only the approval result to the local main process and never shares private passkey data with the website.`}
          </DialogDescription>
        </DialogHeader>

        <FieldGroup>
          <Field>
            <FieldLabel>{t`Website`}</FieldLabel>
            <FieldDescription>{request.rpName}</FieldDescription>
            <Badge variant="outline">{request.rpId}</Badge>
          </Field>
          <Field>
            <FieldLabel>
              {t({
                message: 'Action',
                comment:
                  'Field label showing what the website is asking the user to do with a passkey, such as sign in or register.'
              })}
            </FieldLabel>
            <FieldDescription>{ceremony.detail}</FieldDescription>
            <Badge variant="secondary">{ceremony.label}</Badge>
          </Field>
          {registrationUser && (
            <Field>
              <FieldLabel>{t`Registration user`}</FieldLabel>
              <FieldDescription>{registrationUser}</FieldDescription>
            </Field>
          )}
        </FieldGroup>

        {request.choices.length === 1 && (
          <Field>
            <FieldLabel>{t`Passkey`}</FieldLabel>
            <FieldDescription>
              {request.choices[0]?.detail ??
                t`The only available passkey was selected automatically.`}
            </FieldDescription>
            <Badge variant="outline">{request.choices[0]?.label}</Badge>
          </Field>
        )}

        {request.choices.length >= 2 && request.choices.length <= 7 && (
          <Field>
            <FieldLabel>{t`Choose a passkey`}</FieldLabel>
            <ToggleGroup
              multiple={false}
              value={selectedChoiceId === undefined ? [] : [selectedChoiceId]}
              onValueChange={(value) => {
                setSelectedChoiceId(value[0])
                clearPassword()
                setError('')
              }}
              disabled={busy || expired}
              spacing={2}
              aria-label={t`Choose a passkey`}
            >
              {request.choices.map((choice) => (
                <ToggleGroupItem key={choice.id} value={choice.id} className="flex-1">
                  {choice.label}
                </ToggleGroupItem>
              ))}
            </ToggleGroup>
            <FieldDescription>
              {selectedChoiceId === undefined
                ? t`Choose a passkey.`
                : request.choices.find((choice) => choice.id === selectedChoiceId)?.detail}
            </FieldDescription>
          </Field>
        )}

        {request.choices.length > 7 && (
          <Field>
            <FieldLabel htmlFor="passkey-choice">{t`Choose a passkey`}</FieldLabel>
            <Select
              items={choiceItems}
              value={selectedChoiceId ?? null}
              onValueChange={(value) => {
                setSelectedChoiceId(value ?? undefined)
                clearPassword()
                setError('')
              }}
              disabled={busy || expired}
            >
              <SelectTrigger id="passkey-choice" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  {choiceItems.map((choice) => (
                    <SelectItem key={choice.value ?? 'placeholder'} value={choice.value}>
                      {choice.label}
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
            <FieldDescription>
              {request.choices.find((choice) => choice.id === selectedChoiceId)?.detail}
            </FieldDescription>
          </Field>
        )}

        {request.choices.length === 0 && (
          <Alert variant="destructive">
            <ShieldAlert aria-hidden="true" />
            <AlertTitle>{t`No passkey is available`}</AlertTitle>
            <AlertDescription>{t`This request can't be approved safely. Deny it and start the operation again.`}</AlertDescription>
          </Alert>
        )}

        {request.userVerification !== 'discouraged' && (
          <Field>
            <FieldLabel>{t`User verification`}</FieldLabel>
            {selectableMethods.length > 1 ? (
              <ToggleGroup
                multiple={false}
                value={verificationMethod === undefined ? [] : [verificationMethod]}
                onValueChange={(value) => {
                  setVerificationMethod(value[0] as PasskeyApprovalUiVerificationMethod | undefined)
                  clearPassword()
                  setError('')
                }}
                disabled={busy || expired}
                spacing={2}
                aria-label={t`Choose a user verification method`}
              >
                {selectableMethods.map((method) => (
                  <ToggleGroupItem key={method} value={method} className="flex-1">
                    {method === 'touch-id' ? (
                      <Fingerprint data-icon="inline-start" aria-hidden="true" />
                    ) : (
                      <KeyRound data-icon="inline-start" aria-hidden="true" />
                    )}
                    {verificationMethodLabels[method]}
                  </ToggleGroupItem>
                ))}
              </ToggleGroup>
            ) : selectableMethods.length === 1 ? (
              <Badge variant="secondary">
                {selectableMethods[0] === 'touch-id' ? (
                  <Fingerprint data-icon="inline-start" aria-hidden="true" />
                ) : (
                  <KeyRound data-icon="inline-start" aria-hidden="true" />
                )}
                {verificationMethodLabels[selectableMethods[0]]}
              </Badge>
            ) : (
              <Alert variant="destructive">
                <AlertTitle>{t`No verification method is available`}</AlertTitle>
                <AlertDescription>{t`This website requires user verification, but this device can't provide it right now.`}</AlertDescription>
              </Alert>
            )}
            <FieldDescription>
              {request.userVerification === 'required'
                ? t`This website requires user verification.`
                : t`This website prefers user verification.`}
            </FieldDescription>
          </Field>
        )}

        {selectedPasskeyApprovalChoiceRequiresReprompt(request, selectedChoiceId) && (
          <Alert>
            <ShieldAlert aria-hidden="true" />
            <AlertTitle>{t`This passkey is protected`}</AlertTitle>
            <AlertDescription>{t`Confirm your master password before approving.`}</AlertDescription>
          </Alert>
        )}

        {requiresPassword && (
          <Field data-invalid={Boolean(error)}>
            <FieldLabel htmlFor="passkey-approval-master-password">{t`Confirm master password`}</FieldLabel>
            <Input
              id="passkey-approval-master-password"
              type="password"
              autoComplete="current-password"
              autoFocus
              value={masterPassword}
              disabled={busy || expired}
              aria-invalid={Boolean(error)}
              onChange={(event) => {
                passwordRef.current = event.target.value
                setMasterPassword(event.target.value)
              }}
            />
            <FieldDescription>
              {t`Your master password is sent directly to the local main process for verification and cleared immediately afterward.`}
            </FieldDescription>
          </Field>
        )}

        <Alert variant={expired ? 'destructive' : 'default'}>
          <AlertTriangle aria-hidden="true" />
          <AlertTitle>{expiryMessage}</AlertTitle>
          <AlertDescription>{t`If you aren't sure where this request came from, deny it.`}</AlertDescription>
        </Alert>

        {error && (
          <Alert variant="destructive" role="alert">
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
            <X data-icon="inline-start" aria-hidden="true" />
            {t`Deny`}
          </Button>
          <Button type="button" disabled={busy || !canApprove} onClick={() => void settle(true)}>
            {busy ? (
              <Spinner data-icon="inline-start" aria-hidden="true" />
            ) : (
              <Check data-icon="inline-start" aria-hidden="true" />
            )}
            {t`Approve`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
