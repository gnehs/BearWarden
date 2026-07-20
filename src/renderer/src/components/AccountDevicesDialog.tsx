import { Laptop, LogOut, RefreshCw, TriangleAlert } from 'lucide-react'
import { useRef, useState, type FormEvent, type MutableRefObject } from 'react'
import { t } from '@lingui/core/macro'
import { Trans, useLingui } from '@lingui/react/macro'
import {
  ACCOUNT_SESSION_DEAUTHORIZATION_CONFIRMATION,
  type AccountDevicesResult,
  type LoginApprovalPrompt,
  type AccountSessionDeauthorizationRequest
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
  DialogTitle,
  DialogTrigger
} from '@renderer/components/ui/dialog'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import { Spinner } from '@renderer/components/ui/spinner'
import LoginApprovalDialog from './LoginApprovalDialog'

export const DEAUTHORIZE_SESSIONS_CONFIRMATION = ACCOUNT_SESSION_DEAUTHORIZATION_CONFIRMATION

type DeauthorizeSessionsRequest = AccountSessionDeauthorizationRequest

interface ExecuteDeauthorizeSessionsOptions {
  lease: MutableRefObject<boolean>
  request: DeauthorizeSessionsRequest
  deauthorize: (request: DeauthorizeSessionsRequest) => Promise<void>
  onAcquired: () => void
}

/** A ref-backed lease prevents two destructive requests before React commits `busy`. */
// eslint-disable-next-line react-refresh/only-export-components
export async function executeDeauthorizeSessions({
  lease,
  request,
  deauthorize,
  onAcquired
}: ExecuteDeauthorizeSessionsOptions): Promise<boolean> {
  if (lease.current) {
    request.masterPassword = ''
    ;(request as { confirmation: string }).confirmation = ''
    return false
  }
  lease.current = true
  try {
    onAcquired()
    await deauthorize(request)
    return true
  } finally {
    request.masterPassword = ''
    ;(request as { confirmation: string }).confirmation = ''
    lease.current = false
  }
}

// eslint-disable-next-line react-refresh/only-export-components
export function deauthorizeSessionsError(error: unknown): string {
  if (error instanceof Error && error.message.includes('INVALID_MASTER_PASSWORD')) {
    return t`Master password verification failed. Enter your master password and confirmation text again to retry.`
  }
  if (error instanceof Error && error.message.includes('SESSION_DEAUTHORIZATION_UNKNOWN')) {
    return t`The connection was interrupted during deauthorization, so the result is unknown. It may have succeeded; sign in again or check your other devices before retrying.`
  }
  if (error instanceof Error && error.message.includes('SYNC_AUTH_REQUIRED')) {
    return t`Your current session has expired. Please sign in again.`
  }
  return t`Unable to confirm whether all sessions were deauthorized. Check your sign-in status and other devices before retrying.`
}

interface DeauthorizeSessionsFormProps {
  masterPassword: string
  confirmation: string
  busy: boolean
  error: string
  onMasterPasswordChange: (value: string) => void
  onConfirmationChange: (value: string) => void
  onCancel: () => void
}

export function DeauthorizeSessionsForm({
  masterPassword,
  confirmation,
  busy,
  error,
  onMasterPasswordChange,
  onConfirmationChange,
  onCancel
}: DeauthorizeSessionsFormProps): React.JSX.Element {
  const confirmed = confirmation === DEAUTHORIZE_SESSIONS_CONFIRMATION

  return (
    <div className="border-destructive/40 grid gap-4 rounded-lg border p-4">
      <Alert variant="destructive">
        <TriangleAlert aria-hidden="true" />
        <AlertTitle>
          <Trans>This will deauthorize all sessions</Trans>
        </AlertTitle>
        <AlertDescription>
          <Trans>
            This includes the current device. Every device must sign in again and complete two-step
            login if enabled. Other devices may remain active for up to an hour. BearWarden keeps
            this computer’s local encrypted vault, but it will not sync until you sign in again.
          </Trans>
        </AlertDescription>
      </Alert>
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor="deauthorize-sessions-master-password">
            <Trans>Master password</Trans>
          </FieldLabel>
          <Input
            id="deauthorize-sessions-master-password"
            type="password"
            autoComplete="current-password"
            maxLength={1024}
            value={masterPassword}
            disabled={busy}
            autoFocus
            onChange={(event) => onMasterPasswordChange(event.target.value)}
          />
          <FieldDescription>
            <Trans>
              Enter it again for every attempt. It is used only for this server verification.
            </Trans>
          </FieldDescription>
        </Field>
        <Field>
          <FieldLabel htmlFor="deauthorize-sessions-confirmation">
            <Trans>Enter “{DEAUTHORIZE_SESSIONS_CONFIRMATION}” to confirm</Trans>
          </FieldLabel>
          <Input
            id="deauthorize-sessions-confirmation"
            type="text"
            autoComplete="off"
            maxLength={DEAUTHORIZE_SESSIONS_CONFIRMATION.length}
            value={confirmation}
            disabled={busy}
            spellCheck={false}
            onChange={(event) => onConfirmationChange(event.target.value)}
          />
          <FieldDescription>
            <Trans>
              It must match exactly. Spaces and characters will not be corrected automatically.
            </Trans>
          </FieldDescription>
        </Field>
      </FieldGroup>
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <div className="flex flex-wrap justify-end gap-2">
        <Button variant="secondary" type="button" disabled={busy} onClick={onCancel}>
          <Trans>Cancel</Trans>
        </Button>
        <Button
          variant="destructive"
          type="submit"
          disabled={busy || !masterPassword || !confirmed}
        >
          {busy ? (
            <Spinner data-icon="inline-start" aria-hidden="true" />
          ) : (
            <LogOut data-icon="inline-start" aria-hidden="true" />
          )}
          <Trans>Deauthorize all sessions</Trans>
        </Button>
      </div>
    </div>
  )
}

function deviceTypeName(type: number): string {
  switch (type) {
    case 0:
      return t`Android`
    case 1:
      return t`iPhone / iPad`
    case 2:
      return t`Chrome extension`
    case 3:
      return t`Firefox extension`
    case 4:
      return t`Opera extension`
    case 5:
      return t`Edge extension`
    case 6:
      return t`Windows desktop app`
    case 7:
      return t`macOS desktop app`
    case 8:
      return t`Linux desktop app`
    case 9:
      return t`Chrome web app`
    case 10:
      return t`Firefox web app`
    case 11:
      return t`Opera web app`
    case 12:
      return t`Edge web app`
    case 13:
      return t`Internet Explorer web app`
    case 14:
      return t`Unknown browser`
    case 15:
      return t`Android (Amazon)`
    case 16:
      return t`Windows UWP`
    case 17:
      return t`Safari web app`
    case 18:
      return t`Vivaldi web app`
    case 19:
      return t`Vivaldi extension`
    case 20:
      return t`Safari extension`
    case 21:
      return t`SDK`
    case 22:
      return t`Server`
    case 23:
      return t`Windows CLI`
    case 24:
      return t`macOS CLI`
    case 25:
      return t`Linux CLI`
    case 26:
      return t`DuckDuckGo web app`
    default:
      return t`Unknown device type (${type})`
  }
}

function formatDeviceDate(value: string | null, locale: string): string {
  if (value === null) return t`No record`
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return t`Date unavailable`
  return new Intl.DateTimeFormat(locale, {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(date)
}

function AccountDevicesDialog(): React.JSX.Element {
  const { i18n, t: translate } = useLingui()
  const [open, setOpen] = useState(false)
  const [result, setResult] = useState<AccountDevicesResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [deauthorizeOpen, setDeauthorizeOpen] = useState(false)
  const [masterPassword, setMasterPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [deauthorizeError, setDeauthorizeError] = useState('')
  const [success, setSuccess] = useState('')
  const [pendingApprovals, setPendingApprovals] = useState<LoginApprovalPrompt[]>([])
  const [selectedApproval, setSelectedApproval] = useState<LoginApprovalPrompt | null>(null)
  const submissionLease = useRef(false)

  function clearDeauthorizationSecrets(): void {
    setMasterPassword('')
    setConfirmation('')
  }

  async function load(): Promise<void> {
    setBusy(true)
    setError('')
    try {
      const [devices, approvals] = await Promise.all([
        window.bearwarden.accountSecurity.devices(),
        // Login-with-device is optional on some self-hosted servers. A missing or
        // temporarily unavailable auth-request endpoint must not hide the device list.
        window.bearwarden.accountSecurity.pendingLoginApprovals().catch(() => [])
      ])
      setResult(devices)
      setPendingApprovals(approvals)
    } catch {
      setResult(null)
      setError(translate`Unable to load account devices. Please try again later.`)
    } finally {
      setBusy(false)
    }
  }

  function changeOpen(next: boolean): void {
    if (busy || submissionLease.current) return
    setOpen(next)
    setResult(null)
    setPendingApprovals([])
    setError('')
    setSuccess('')
    setDeauthorizeOpen(false)
    setDeauthorizeError('')
    clearDeauthorizationSecrets()
    if (next) void load()
  }

  function changeDeauthorizeOpen(next: boolean): void {
    if (busy || submissionLease.current) return
    setDeauthorizeOpen(next)
    setDeauthorizeError('')
    setSuccess('')
    clearDeauthorizationSecrets()
  }

  async function submitDeauthorization(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (busy || !masterPassword || confirmation !== DEAUTHORIZE_SESSIONS_CONFIRMATION) {
      return
    }
    const request: DeauthorizeSessionsRequest = {
      masterPassword,
      confirmation: DEAUTHORIZE_SESSIONS_CONFIRMATION,
      confirm: true
    }
    let acquired = false
    try {
      acquired = await executeDeauthorizeSessions({
        lease: submissionLease,
        request,
        deauthorize: (deauthorizeRequest) =>
          window.bearwarden.accountSecurity.deauthorizeSessions(deauthorizeRequest),
        onAcquired: () => {
          acquired = true
          setBusy(true)
          setError('')
          setSuccess('')
          setDeauthorizeError('')
          clearDeauthorizationSecrets()
        }
      })
      if (!acquired) return
      setDeauthorizeOpen(false)
      setResult(null)
      setSuccess(
        translate`The deauthorization request was sent. This device must also sign in again before it can continue syncing.`
      )
    } catch (deauthorizeFailure) {
      if (!acquired) return
      setDeauthorizeError(deauthorizeSessionsError(deauthorizeFailure))
    } finally {
      clearDeauthorizationSecrets()
      if (acquired) setBusy(false)
    }
  }

  return (
    <>
      <Dialog open={open} onOpenChange={changeOpen}>
        <DialogTrigger
          render={<Button className="w-full" variant="outline" size="sm" type="button" />}
        >
          <Laptop data-icon="inline-start" aria-hidden="true" />
          <Trans>Account devices</Trans>
        </DialogTrigger>
        <DialogContent
          className="max-h-[min(42rem,calc(100vh-2rem))] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-lg"
          forceOverlay
        >
          <DialogHeader>
            <DialogTitle>
              <Trans>Account devices</Trans>
            </DialogTitle>
            <DialogDescription>
              <Trans>
                View device activity and trusted status on the server, and deauthorize all sessions.
                Device identifiers and network information are not shown.
              </Trans>
            </DialogDescription>
          </DialogHeader>
          <div className="scroll-fade-y forced-colors:scroll-fade-none -mx-4 min-h-0 overflow-y-auto px-4">
            <div className="flex flex-col gap-4 pb-1">
              {pendingApprovals.length > 0 && (
                <section className="grid gap-3 rounded-lg border p-3">
                  <div>
                    <h3 className="font-medium">
                      <Trans>Pending sign-in requests</Trans>
                    </h3>
                    <p className="text-muted-foreground text-sm">
                      <Trans>
                        Only approve a request you just made on another device, after verifying the
                        verification phrase.
                      </Trans>
                    </p>
                  </div>
                  {pendingApprovals.map((approval) => (
                    <div
                      key={approval.token}
                      className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-2"
                    >
                      <div className="text-sm">
                        <p className="font-medium">
                          {approval.requestDeviceType || translate`Unknown device`}
                        </p>
                        <p className="text-muted-foreground">
                          {formatDeviceDate(approval.createdAt, i18n.locale)}
                        </p>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        type="button"
                        disabled={busy}
                        onClick={() => {
                          setOpen(false)
                          setSelectedApproval(approval)
                        }}
                      >
                        <Trans>Review request</Trans>
                      </Button>
                    </div>
                  ))}
                </section>
              )}
              {busy && result === null ? (
                <div
                  className="text-muted-foreground flex items-center gap-2 text-sm"
                  role="status"
                >
                  <Spinner aria-hidden="true" />
                  <Trans>Loading devices…</Trans>
                </div>
              ) : result?.status === 'unavailable' ? (
                <Alert>
                  <AlertDescription>
                    <Trans>The current server does not support account device lists.</Trans>
                  </AlertDescription>
                </Alert>
              ) : result?.status === 'available' && result.devices.length === 0 ? (
                <p className="text-muted-foreground text-sm">
                  <Trans>The server did not return any account devices.</Trans>
                </p>
              ) : result?.status === 'available' ? (
                <div className="grid gap-3">
                  {result.devices.map((device, index) => (
                    <section
                      key={`${device.name}-${device.createdAt}-${index}`}
                      className="grid gap-3 rounded-lg border p-3"
                    >
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <div>
                          <h3 className="font-medium">{device.name}</h3>
                          <p className="text-muted-foreground text-sm">
                            {deviceTypeName(device.type)}
                          </p>
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {device.current && (
                            <Badge>
                              <Trans>This device</Trans>
                            </Badge>
                          )}
                          <Badge variant="outline">
                            {device.trusted ? <Trans>Trusted</Trans> : <Trans>Not trusted</Trans>}
                          </Badge>
                          {device.pendingAuthRequest && (
                            <Badge variant="secondary">
                              <Trans>Pending confirmation</Trans>
                            </Badge>
                          )}
                        </div>
                      </div>
                      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
                        <dt className="text-muted-foreground">
                          <Trans>Created</Trans>
                        </dt>
                        <dd>{formatDeviceDate(device.createdAt, i18n.locale)}</dd>
                        <dt className="text-muted-foreground">
                          <Trans>Last activity</Trans>
                        </dt>
                        <dd>{formatDeviceDate(device.lastActivityAt, i18n.locale)}</dd>
                        <dt className="text-muted-foreground">
                          <Trans>Current device</Trans>
                        </dt>
                        <dd>{device.current ? <Trans>Yes</Trans> : <Trans>No</Trans>}</dd>
                        <dt className="text-muted-foreground">
                          <Trans>Trust status</Trans>
                        </dt>
                        <dd>
                          {device.trusted ? <Trans>Trusted</Trans> : <Trans>Not trusted</Trans>}
                        </dd>
                        <dt className="text-muted-foreground">
                          <Trans>Pending sign-in request</Trans>
                        </dt>
                        <dd>
                          {device.pendingAuthRequest ? <Trans>Yes</Trans> : <Trans>No</Trans>}
                        </dd>
                      </dl>
                    </section>
                  ))}
                </div>
              ) : null}
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
              {deauthorizeOpen ? (
                <form
                  className="grid gap-4"
                  onSubmit={(event) => void submitDeauthorization(event)}
                >
                  <DeauthorizeSessionsForm
                    masterPassword={masterPassword}
                    confirmation={confirmation}
                    busy={busy}
                    error={deauthorizeError}
                    onMasterPasswordChange={setMasterPassword}
                    onConfirmationChange={setConfirmation}
                    onCancel={() => changeDeauthorizeOpen(false)}
                  />
                </form>
              ) : (
                <div className="grid gap-2 rounded-lg border p-3">
                  <div>
                    <h3 className="font-medium">
                      <Trans>Deauthorize all sessions</Trans>
                    </h3>
                    <p className="text-muted-foreground text-sm">
                      <Trans>
                        Force every device for this account to sign in again without deleting the
                        local encrypted vault.
                      </Trans>
                    </p>
                  </div>
                  <Button
                    className="justify-self-start"
                    variant="destructive"
                    type="button"
                    disabled={busy || Boolean(success)}
                    onClick={() => changeDeauthorizeOpen(true)}
                  >
                    <LogOut data-icon="inline-start" aria-hidden="true" />
                    <Trans>Start deauthorization</Trans>
                  </Button>
                </div>
              )}
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="secondary"
              type="button"
              disabled={busy}
              onClick={() => changeOpen(false)}
            >
              <Trans>Close</Trans>
            </Button>
            {!deauthorizeOpen && (
              <Button
                variant="outline"
                type="button"
                disabled={busy || Boolean(success)}
                onClick={() => void load()}
              >
                {busy ? (
                  <Spinner data-icon="inline-start" aria-hidden="true" />
                ) : (
                  <RefreshCw data-icon="inline-start" aria-hidden="true" />
                )}
                <Trans>Refresh</Trans>
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {selectedApproval && (
        <LoginApprovalDialog
          key={selectedApproval.token}
          prompt={selectedApproval}
          onClose={() => setSelectedApproval(null)}
        />
      )}
    </>
  )
}

export default AccountDevicesDialog
