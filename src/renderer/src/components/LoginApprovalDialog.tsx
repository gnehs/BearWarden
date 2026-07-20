import { Fingerprint, ShieldCheck, ShieldX } from 'lucide-react'
import { useState } from 'react'
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

function formatRequestTime(value: string): string {
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return '時間不可用'
  return new Intl.DateTimeFormat('zh-TW', {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(date)
}

function loginApprovalError(error: unknown): string {
  if (error instanceof Error && error.message.includes('INVALID_INPUT')) {
    return '登入要求已過期、已由其他裝置處理，或驗證詞組已變更。請重新整理後再確認。'
  }
  if (error instanceof Error && error.message.includes('SYNC_AUTH_REQUIRED')) {
    return 'Bitwarden 登入已失效，無法處理這個要求。'
  }
  return '無法確認伺服器是否已收到回覆。請先重新整理待處理要求，不要直接重試。'
}

export default function LoginApprovalDialog({
  prompt,
  onClose,
  onSettled
}: LoginApprovalDialogProps): React.JSX.Element {
  const [fingerprintMatches, setFingerprintMatches] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

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
          <DialogTitle>確認 Bitwarden 登入要求</DialogTitle>
          <DialogDescription>
            只有在你正於另一部裝置登入，且兩邊顯示完全相同的驗證詞組時才允許。
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4">
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
            <dt className="text-muted-foreground">要求裝置</dt>
            <dd>{prompt.requestDeviceType || '未知裝置'}</dd>
            <dt className="text-muted-foreground">要求時間</dt>
            <dd>{formatRequestTime(prompt.createdAt)}</dd>
            <dt className="text-muted-foreground">到期時間</dt>
            <dd>{formatRequestTime(prompt.expiresAt)}</dd>
          </dl>
          <Alert>
            <Fingerprint aria-hidden="true" />
            <AlertTitle>驗證詞組</AlertTitle>
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
                <FieldTitle>另一部裝置顯示完全相同的詞組</FieldTitle>
              </FieldLabel>
              <FieldDescription>若不是你發出的要求，請拒絕並檢查帳號安全性。</FieldDescription>
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
            拒絕
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
            允許登入
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
