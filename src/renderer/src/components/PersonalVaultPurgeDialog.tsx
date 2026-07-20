import { useRef, useState, type FormEvent, type MutableRefObject } from 'react'
import { plural, t } from '@lingui/core/macro'
import { Trans, useLingui } from '@lingui/react/macro'
import { Eye, EyeOff, Trash2, TriangleAlert } from 'lucide-react'
import type {
  SyncPurgePersonalVaultRequest,
  SyncPurgePersonalVaultResult,
  SyncStatus
} from '../../../shared/vault-contract'
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogMedia,
  AlertDialogTitle,
  AlertDialogTrigger
} from '@renderer/components/ui/alert-dialog'
import { Button } from '@renderer/components/ui/button'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@renderer/components/ui/field'
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput
} from '@renderer/components/ui/input-group'
import { Spinner } from '@renderer/components/ui/spinner'

type PendingPurge = NonNullable<SyncStatus['pendingPurge']>

interface PersonalVaultPurgeExecutionOptions {
  lease: MutableRefObject<boolean>
  request: SyncPurgePersonalVaultRequest
  purge: (request: SyncPurgePersonalVaultRequest) => Promise<SyncPurgePersonalVaultResult>
  refresh: () => void | Promise<void>
  onAcquired: () => void
}

/** The ref-backed lease closes React's same-render double-submit window before the first await. */
// eslint-disable-next-line react-refresh/only-export-components
export async function executePersonalVaultPurge({
  lease,
  request,
  purge,
  refresh,
  onAcquired
}: PersonalVaultPurgeExecutionOptions): Promise<
  { acquired: false } | { acquired: true; result: SyncPurgePersonalVaultResult }
> {
  if (lease.current) {
    request.masterPassword = ''
    ;(request as { confirmation: string }).confirmation = ''
    return { acquired: false }
  }
  lease.current = true
  const refreshBestEffort = async (): Promise<void> => {
    try {
      await refresh()
    } catch {
      // Refresh is advisory and must never replace the authoritative purge outcome.
    }
  }
  try {
    onAcquired()
    let result: SyncPurgePersonalVaultResult
    try {
      result = await purge(request)
    } catch (cause) {
      await refreshBestEffort()
      throw cause
    }
    await refreshBestEffort()
    return { acquired: true, result }
  } finally {
    request.masterPassword = ''
    ;(request as { confirmation: string }).confirmation = ''
    lease.current = false
  }
}

interface PersonalVaultPurgeFormProps {
  pendingPurge?: PendingPurge
  masterPassword: string
  confirmation: string
  showPassword: boolean
  busy: boolean
  error: string
  onMasterPasswordChange: (value: string) => void
  onConfirmationChange: (value: string) => void
  onTogglePassword: () => void
}

export function PersonalVaultPurgeForm({
  pendingPurge,
  masterPassword,
  confirmation,
  showPassword,
  busy,
  error,
  onMasterPasswordChange,
  onConfirmationChange,
  onTogglePassword
}: PersonalVaultPurgeFormProps): React.JSX.Element {
  return (
    <div className="grid gap-4">
      <Alert variant="destructive">
        <TriangleAlert aria-hidden="true" />
        <AlertTitle>{t`This action cannot be undone`}</AlertTitle>
        <AlertDescription>
          {t`This permanently deletes all personal items, folders, and attachments from the server, including trash and archived items. Shared organization items are kept. Export a backup first.`}
        </AlertDescription>
      </Alert>
      {pendingPurge && (
        <Alert variant="destructive">
          <AlertTitle>{t`The result of the previous purge is unknown`}</AlertTitle>
          <AlertDescription>
            {t({
              message: plural(pendingPurge.remainingItems, {
                one: plural(pendingPurge.remainingFolders, {
                  one: `The server still has ${pendingPurge.remainingItems} personal item and # folder. BearWarden will not resend automatically; trying again only removes remaining data.`,
                  other: `The server still has ${pendingPurge.remainingItems} personal item and # folders. BearWarden will not resend automatically; trying again only removes remaining data.`
                }),
                other: plural(pendingPurge.remainingFolders, {
                  one: `The server still has ${pendingPurge.remainingItems} personal items and # folder. BearWarden will not resend automatically; trying again only removes remaining data.`,
                  other: `The server still has ${pendingPurge.remainingItems} personal items and # folders. BearWarden will not resend automatically; trying again only removes remaining data.`
                })
              })
            })}
          </AlertDescription>
        </Alert>
      )}
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor="purge-personal-vault-password">{t`Remote master password`}</FieldLabel>
          <InputGroup>
            <InputGroupInput
              id="purge-personal-vault-password"
              type={showPassword ? 'text' : 'password'}
              autoComplete="current-password"
              maxLength={1024}
              value={masterPassword}
              disabled={busy}
              autoFocus
              onChange={(event) => onMasterPasswordChange(event.target.value)}
            />
            <InputGroupAddon align="inline-end">
              <InputGroupButton
                aria-label={showPassword ? t`Hide master password` : t`Show master password`}
                disabled={busy}
                onClick={onTogglePassword}
              >
                {showPassword ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
              </InputGroupButton>
            </InputGroupAddon>
          </InputGroup>
          <FieldDescription>{t`Enter it again for every attempt. It is used only for this remote verification.`}</FieldDescription>
        </Field>
        <Field>
          <FieldLabel htmlFor="purge-personal-vault-confirmation">{t`Enter PURGE to confirm`}</FieldLabel>
          <InputGroup>
            <InputGroupInput
              id="purge-personal-vault-confirmation"
              type="text"
              autoComplete="off"
              maxLength={5}
              value={confirmation}
              disabled={busy}
              spellCheck={false}
              onChange={(event) => onConfirmationChange(event.target.value)}
            />
          </InputGroup>
          <FieldDescription>{t`It must exactly match the uppercase word PURGE.`}</FieldDescription>
        </Field>
      </FieldGroup>
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
    </div>
  )
}

interface PersonalVaultPurgeDialogProps {
  pendingPurge?: PendingPurge
  disabled?: boolean
  onVaultChanged?: () => void | Promise<void>
}

function PersonalVaultPurgeDialog({
  pendingPurge,
  disabled = false,
  onVaultChanged
}: PersonalVaultPurgeDialogProps): React.JSX.Element {
  const { t } = useLingui()
  const [open, setOpen] = useState(false)
  const [masterPassword, setMasterPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [latestPending, setLatestPending] = useState<PendingPurge | undefined>()
  const submissionLease = useRef(false)
  const visiblePending = latestPending ?? pendingPurge

  function clearSecrets(): void {
    setMasterPassword('')
    setConfirmation('')
    setShowPassword(false)
  }

  function changeOpen(nextOpen: boolean): void {
    if (busy || submissionLease.current) return
    setOpen(nextOpen)
    setError('')
    clearSecrets()
    if (!nextOpen) setLatestPending(undefined)
  }

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (busy || !masterPassword || confirmation !== 'PURGE') return
    const request = { masterPassword, confirmation: 'PURGE' as const, confirmPurge: true as const }
    let acquired = false
    try {
      const execution = await executePersonalVaultPurge({
        lease: submissionLease,
        request,
        purge: (candidate) => window.bearwarden.sync.purgePersonalVault(candidate),
        refresh: () => onVaultChanged?.(),
        onAcquired: () => {
          acquired = true
          clearSecrets()
          setError('')
          setBusy(true)
        }
      })
      if (!execution.acquired) return
      const { result } = execution
      if (result.status === 'complete') {
        setOpen(false)
        setLatestPending(undefined)
      } else {
        setLatestPending({
          startedAt: result.startedAt,
          remainingItems: result.remainingItems,
          remainingFolders: result.remainingFolders
        })
      }
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : ''
      setError(
        /INVALID_MASTER_PASSWORD|USER_VERIFICATION_FAILED/u.test(message)
          ? t`Remote master password verification failed.`
          : t`The purge result could not be confirmed. Sync again to check remaining data; BearWarden will not resend automatically.`
      )
    } finally {
      if (acquired) setBusy(false)
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={changeOpen}>
      <AlertDialogTrigger
        render={
          <Button variant="destructive" size="sm" type="button" disabled={disabled || busy} />
        }
      >
        <Trash2 data-icon="inline-start" aria-hidden="true" />
        {visiblePending ? t`Handle incomplete purge` : t`Purge personal vault`}
      </AlertDialogTrigger>
      <AlertDialogContent>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <AlertDialogHeader>
            <AlertDialogMedia>
              <TriangleAlert aria-hidden="true" />
            </AlertDialogMedia>
            <AlertDialogTitle>
              <Trans>Permanently purge personal vault?</Trans>
            </AlertDialogTitle>
            <AlertDialogDescription>
              <Trans>
                This only deletes personal data for the currently synced account. Shared
                organization items are not deleted.
              </Trans>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <PersonalVaultPurgeForm
            pendingPurge={visiblePending}
            masterPassword={masterPassword}
            confirmation={confirmation}
            showPassword={showPassword}
            busy={busy}
            error={error}
            onMasterPasswordChange={setMasterPassword}
            onConfirmationChange={setConfirmation}
            onTogglePassword={() => setShowPassword((value) => !value)}
          />
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>
              <Trans>Back</Trans>
            </AlertDialogCancel>
            <Button
              type="submit"
              variant="destructive"
              disabled={busy || !masterPassword || confirmation !== 'PURGE'}
            >
              {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
              {visiblePending
                ? t`Purge remaining items again`
                : t`Permanently purge personal vault`}
            </Button>
          </AlertDialogFooter>
        </form>
      </AlertDialogContent>
    </AlertDialog>
  )
}

export default PersonalVaultPurgeDialog
