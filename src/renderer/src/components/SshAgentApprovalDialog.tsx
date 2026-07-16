import { useEffect, useRef, useState } from 'react'
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
import {
  canApproveSshAgentApproval,
  formatSshAgentExpiry,
  sshAgentSigningPurpose
} from '@renderer/lib/ssh-agent-ui'

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
  const [masterPassword, setMasterPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [expired, setExpired] = useState(() => request.expiresAt <= Date.now())
  const settledRef = useRef(false)
  const processingRef = useRef(false)
  const mountedRef = useRef(true)
  const onSettledRef = useRef(onSettled)
  const purpose = sshAgentSigningPurpose(request.namespace)

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
          ? '此簽署要求已過期，請重新執行原本的 SSH 操作。'
          : '請輸入主密碼以核准這把受保護的 SSH 金鑰。'
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
            ? '無法核准此簽署要求。請確認主密碼後再試。'
            : '無法拒絕此簽署要求。請等候它過期或重新鎖定保管庫。'
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
          <DialogTitle>核准 SSH 金鑰簽署？</DialogTitle>
          <DialogDescription>
            BearWarden 只會在你核准後使用指定的 SSH 金鑰；私鑰與待簽內容不會離開主程序。
          </DialogDescription>
        </DialogHeader>

        <FieldGroup>
          <Field>
            <FieldLabel>金鑰</FieldLabel>
            <FieldDescription>{request.itemName}</FieldDescription>
            <Badge variant="outline">{request.fingerprint}</Badge>
          </Field>
          <Field>
            <FieldLabel>用途</FieldLabel>
            <FieldDescription>{purpose.detail}</FieldDescription>
            <Badge variant="secondary">
              {purpose.label === 'Git 簽署' ? <GitBranch /> : <KeyRound />}
              {purpose.label}
            </Badge>
          </Field>
          {request.processName && (
            <Field>
              <FieldLabel>提出要求的程式</FieldLabel>
              <FieldDescription>{request.processName}</FieldDescription>
            </Field>
          )}
        </FieldGroup>

        {request.forwarded && (
          <Alert variant="destructive">
            <ShieldAlert aria-hidden="true" />
            <AlertTitle>此要求來自 SSH Agent Forwarding</AlertTitle>
            <AlertDescription>
              {request.hostFingerprint
                ? `已驗證遠端主機指紋：${request.hostFingerprint}`
                : '遠端主機尚未提供可驗證的主機指紋；只在你信任的 SSH 連線中核准。'}
            </AlertDescription>
          </Alert>
        )}

        {request.requiresReprompt && (
          <FieldGroup>
            <Field data-invalid={Boolean(error)}>
              <FieldLabel htmlFor="ssh-agent-master-password">確認主密碼</FieldLabel>
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
                主密碼只會送到本機主程序驗證，核准後會取得一次性能力權杖。
              </FieldDescription>
            </Field>
          </FieldGroup>
        )}

        <Alert>
          <AlertTriangle aria-hidden="true" />
          <AlertTitle>{formatSshAgentExpiry(request.expiresAt)}</AlertTitle>
          <AlertDescription>不確定要求來源時，請選擇拒絕。</AlertDescription>
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
            拒絕
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
            核准簽署
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
