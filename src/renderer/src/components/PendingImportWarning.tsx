import { Eye, EyeOff } from 'lucide-react'

import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import { Button } from '@renderer/components/ui/button'
import { Field, FieldGroup, FieldLabel } from '@renderer/components/ui/field'
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput
} from '@renderer/components/ui/input-group'
import { Spinner } from '@renderer/components/ui/spinner'

interface PendingImportWarningProps {
  count: number
  startedAt: string
  masterPassword: string
  showPassword: boolean
  busy: boolean
  onMasterPasswordChange: (value: string) => void
  onTogglePassword: () => void
  onConfirm: () => void
}

function formatStartedAt(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '時間不明'
  return new Intl.DateTimeFormat('zh-TW', { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}

export function PendingImportWarning({
  count,
  startedAt,
  masterPassword,
  showPassword,
  busy,
  onMasterPasswordChange,
  onTogglePassword,
  onConfirm
}: PendingImportWarningProps): React.JSX.Element {
  return (
    <Alert variant="destructive">
      <AlertTitle>批次匯入的伺服器結果未知</AlertTitle>
      <AlertDescription className="flex flex-col gap-3 text-left">
        <p>
          伺服器是否已建立這 {count} 筆項目目前無法確認。BearWarden 不會自動重送，以免產生重複項目。
        </p>
        <p>開始時間：{formatStartedAt(startedAt)}</p>
        <p>輸入主密碼並明確確認後，下一次同步會再次送出未確認的項目，伺服器上可能出現重複項目。</p>
        <p>若不想承擔重複風險，可中斷連線；本機密碼庫資料會保留。</p>
        <FieldGroup>
          <Field data-disabled={busy || undefined}>
            <FieldLabel htmlFor="pending-import-master-password">主密碼</FieldLabel>
            <InputGroup>
              <InputGroupInput
                id="pending-import-master-password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                maxLength={1_024}
                value={masterPassword}
                onChange={(event) => onMasterPasswordChange(event.target.value)}
                disabled={busy}
                required
              />
              <InputGroupAddon align="inline-end">
                <InputGroupButton
                  size="icon-xs"
                  aria-label={showPassword ? '隱藏主密碼' : '顯示主密碼'}
                  aria-pressed={showPassword}
                  onClick={onTogglePassword}
                  disabled={busy}
                >
                  {showPassword ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
                </InputGroupButton>
              </InputGroupAddon>
            </InputGroup>
          </Field>
        </FieldGroup>
        <Button
          variant="destructive"
          type="button"
          disabled={busy || masterPassword.length === 0}
          onClick={onConfirm}
        >
          {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
          {busy ? '正在確認…' : '我了解風險，允許重新傳送'}
        </Button>
      </AlertDescription>
    </Alert>
  )
}
