import { useEffect, useRef, useState } from 'react'
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
  formatPasskeyApprovalExpiry,
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

const verificationMethodLabels: Record<PasskeyApprovalUiVerificationMethod, string> = {
  'touch-id': 'Touch ID',
  'master-password': '主密碼'
}

function ceremonyPresentation(kind: PasskeyApprovalPrompt['kind']): {
  label: string
  detail: string
} {
  return kind === 'create'
    ? { label: '建立通行密鑰', detail: '此網站要求為帳號建立新的通行密鑰。' }
    : { label: '使用通行密鑰登入', detail: '此網站要求使用已儲存的通行密鑰登入。' }
}

function registrationUserPresentation(request: PasskeyApprovalPrompt): string | undefined {
  if (request.kind !== 'create') return undefined
  if (request.userDisplayName && request.userName) {
    return `${request.userDisplayName}（${request.userName}）`
  }
  return request.userDisplayName ?? request.userName
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
  const ceremony = ceremonyPresentation(request.kind)
  const registrationUser = registrationUserPresentation(request)
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
    { label: '選擇通行密鑰', value: null },
    ...request.choices.map((choice) => ({ label: choice.label, value: choice.id }))
  ]

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
          ? '此要求沒有可核准的通行密鑰。請拒絕要求並重新開始。'
          : requiresPassword
            ? '請輸入主密碼以繼續。'
            : '請選擇通行密鑰與可用的驗證方式。'
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
            ? '無法完成驗證或核准此通行密鑰要求。請確認主密碼後再試。'
            : '無法拒絕此通行密鑰要求。請等候它過期，或重新鎖定保管庫。'
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
          <DialogTitle>核准通行密鑰要求？</DialogTitle>
          <DialogDescription>
            BearWarden 只會將核准結果交給本機主程序，不會將通行密鑰私密資料交給網站。
          </DialogDescription>
        </DialogHeader>

        <FieldGroup>
          <Field>
            <FieldLabel>網站</FieldLabel>
            <FieldDescription>{request.rpName}</FieldDescription>
            <Badge variant="outline">{request.rpId}</Badge>
          </Field>
          <Field>
            <FieldLabel>動作</FieldLabel>
            <FieldDescription>{ceremony.detail}</FieldDescription>
            <Badge variant="secondary">{ceremony.label}</Badge>
          </Field>
          {registrationUser && (
            <Field>
              <FieldLabel>註冊使用者</FieldLabel>
              <FieldDescription>{registrationUser}</FieldDescription>
            </Field>
          )}
        </FieldGroup>

        {request.choices.length === 1 && (
          <Field>
            <FieldLabel>通行密鑰</FieldLabel>
            <FieldDescription>
              {request.choices[0]?.detail ?? '已自動選擇唯一可用的通行密鑰。'}
            </FieldDescription>
            <Badge variant="outline">{request.choices[0]?.label}</Badge>
          </Field>
        )}

        {request.choices.length >= 2 && request.choices.length <= 7 && (
          <Field>
            <FieldLabel>選擇通行密鑰</FieldLabel>
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
              aria-label="選擇通行密鑰"
            >
              {request.choices.map((choice) => (
                <ToggleGroupItem key={choice.id} value={choice.id} className="flex-1">
                  {choice.label}
                </ToggleGroupItem>
              ))}
            </ToggleGroup>
            <FieldDescription>
              {selectedChoiceId === undefined
                ? '請選擇一個通行密鑰。'
                : request.choices.find((choice) => choice.id === selectedChoiceId)?.detail}
            </FieldDescription>
          </Field>
        )}

        {request.choices.length > 7 && (
          <Field>
            <FieldLabel htmlFor="passkey-choice">選擇通行密鑰</FieldLabel>
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
            <AlertTitle>沒有可用的通行密鑰</AlertTitle>
            <AlertDescription>此要求無法安全地核准。請拒絕並重新開始操作。</AlertDescription>
          </Alert>
        )}

        {request.userVerification !== 'discouraged' && (
          <Field>
            <FieldLabel>使用者驗證</FieldLabel>
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
                aria-label="選擇使用者驗證方式"
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
                <AlertTitle>沒有可用的驗證方式</AlertTitle>
                <AlertDescription>此網站要求使用者驗證，但本機目前無法提供。</AlertDescription>
              </Alert>
            )}
            <FieldDescription>
              {request.userVerification === 'required'
                ? '網站要求完成使用者驗證。'
                : '網站偏好完成使用者驗證。'}
            </FieldDescription>
          </Field>
        )}

        {selectedPasskeyApprovalChoiceRequiresReprompt(request, selectedChoiceId) && (
          <Alert>
            <ShieldAlert aria-hidden="true" />
            <AlertTitle>此通行密鑰受保護</AlertTitle>
            <AlertDescription>核准前需要重新確認主密碼。</AlertDescription>
          </Alert>
        )}

        {requiresPassword && (
          <Field data-invalid={Boolean(error)}>
            <FieldLabel htmlFor="passkey-approval-master-password">確認主密碼</FieldLabel>
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
              主密碼只會直接送到本機主程序驗證，完成後會立即清除。
            </FieldDescription>
          </Field>
        )}

        <Alert variant={expired ? 'destructive' : 'default'}>
          <AlertTriangle aria-hidden="true" />
          <AlertTitle>{formatPasskeyApprovalExpiry(request.expiresAt)}</AlertTitle>
          <AlertDescription>不確定要求來源時，請選擇拒絕。</AlertDescription>
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
            拒絕
          </Button>
          <Button type="button" disabled={busy || !canApprove} onClick={() => void settle(true)}>
            {busy ? (
              <Spinner data-icon="inline-start" aria-hidden="true" />
            ) : (
              <Check data-icon="inline-start" aria-hidden="true" />
            )}
            核准
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
