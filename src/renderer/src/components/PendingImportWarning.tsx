import { Eye, EyeOff } from 'lucide-react'
import { i18n } from '@lingui/core'
import { plural, t } from '@lingui/core/macro'

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

function formatStartedAt(value: string, locale: string, unknownDate: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return unknownDate
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
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
      <AlertTitle>{t`The server result for this batch import is unknown`}</AlertTitle>
      <AlertDescription className="flex flex-col gap-3 text-left">
        <p>
          {t({
            message: plural(count, {
              one: `It is unknown whether the server created this item. BearWarden will not resend it automatically to avoid duplicates.`,
              other: `It is unknown whether the server created these # items. BearWarden will not resend them automatically to avoid duplicates.`
            })
          })}
        </p>
        <p>
          {t`Started:`}
          {formatStartedAt(startedAt, i18n.locale, t`Unknown time`)}
        </p>
        <p>
          {t`After you enter your master password and explicitly confirm, the next sync will resend unconfirmed items. This may create duplicates on the server.`}
        </p>
        <p>
          {t`If you do not want to risk duplicates, disconnect instead. Your local vault data will be kept.`}
        </p>
        <FieldGroup>
          <Field data-disabled={busy || undefined}>
            <FieldLabel htmlFor="pending-import-master-password">{t`Master password`}</FieldLabel>
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
                  aria-label={showPassword ? t`Hide master password` : t`Show master password`}
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
          {busy ? t`Confirming…` : t`I understand the risk. Allow resend`}
        </Button>
      </AlertDescription>
    </Alert>
  )
}
