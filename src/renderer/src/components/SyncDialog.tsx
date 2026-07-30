import {
  AlertTriangle,
  CheckCircle2,
  CircleAlert,
  ChevronDown,
  Cloud,
  Eye,
  EyeOff,
  KeyRound,
  RefreshCw,
  Server,
  ShieldCheck,
  Unplug,
  X
} from 'lucide-react'
import { plural, t } from '@lingui/core/macro'
import { Trans, useLingui } from '@lingui/react/macro'
import { useEffect, useRef, useState } from 'react'
import {
  IPC_ERROR_PREFIX,
  type AccountSecurityProfile,
  type SyncErrorCode,
  type SyncInvalidResponseReason,
  type SyncInvalidResponseStage,
  type SyncResult,
  type SyncStatus,
  type SyncTwoFactorProvider
} from '../../../shared/vault-contract'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogMedia,
  AlertDialogTitle,
  AlertDialogTrigger
} from '@renderer/components/ui/alert-dialog'
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import { Badge } from '@renderer/components/ui/badge'
import { Button } from '@renderer/components/ui/button'
import { Checkbox } from '@renderer/components/ui/checkbox'
import { Dialog, DialogTitle } from '@renderer/components/ui/dialog'
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel
} from '@renderer/components/ui/field'
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput
} from '@renderer/components/ui/input-group'
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
import { Separator } from '@renderer/components/ui/separator'
import { cn } from '@renderer/lib/utils'
import AccountApiKeyDialog from './AccountApiKeyDialog'
import AccountDevicesDialog from './AccountDevicesDialog'
import AccountProfileCard from './AccountProfileCard'
import AccountTwoFactorDialog from './AccountTwoFactorDialog'
import { ModalActionGroup, ModalBody, ModalContent, ModalFooter, ModalHeader } from './ModalLayout'
import { PendingImportWarning } from './PendingImportWarning'
import { SyncErrorDetailsDialog } from './SyncErrorDetailsDialog'
import {
  buildSyncTwoFactorRequest,
  resolveSyncTwoFactorMethod,
  syncTwoFactorProviderForMethod,
  WEB_AUTHN_TWO_FACTOR_METHOD,
  type SyncTwoFactorFormMethod
} from './sync-two-factor-request'

const BITWARDEN_CLOUD_URL = 'https://bitwarden.com'

// Exported solely for the account-switch race regression test.
// eslint-disable-next-line react-refresh/only-export-components
export function accountProfileIdentity(serverUrl?: string, email?: string): string {
  return `${serverUrl ?? ''}\0${email?.toLowerCase() ?? ''}`
}

// eslint-disable-next-line react-refresh/only-export-components
export function shouldAcceptAccountProfile(
  responseIdentity: string,
  currentIdentity: string
): boolean {
  return responseIdentity === currentIdentity
}

interface AccountProfileState {
  owner: string
  profile: AccountSecurityProfile | null
}

// Keep the current account card mounted while a sync refresh is in flight.
// eslint-disable-next-line react-refresh/only-export-components
export function accountProfileStateForStatus(
  current: AccountProfileState,
  identity: string,
  state: SyncStatus['state']
): AccountProfileState {
  if (current.owner !== identity) return { owner: identity, profile: null }
  if (state === 'ready' || state === 'syncing') return current
  return { owner: identity, profile: null }
}

// eslint-disable-next-line react-refresh/only-export-components
export function applyAccountProfileIfCurrent(
  current: AccountProfileState,
  responseIdentity: string,
  profile: AccountSecurityProfile
): AccountProfileState {
  return shouldAcceptAccountProfile(responseIdentity, current.owner)
    ? { owner: current.owner, profile }
    : current
}

interface SyncDialogProps {
  status: SyncStatus
  onClose: () => void
  onStatusChange: (status: SyncStatus) => void
  onSynced: () => Promise<void>
}

function describeSyncError(error: unknown): string {
  if (!(error instanceof Error)) return t`Sync did not complete. Please try again later.`
  if (/(?:CANCEL|ABORT)/i.test(error.message)) return t`The operation was canceled.`
  if (error.message.includes('NEW_DEVICE_REQUIRED'))
    return t`The server requires a new device verification code. Get the code from the email sent by Bitwarden, then enter it under advanced options.`
  if (error.message.includes('SYNC_SSO_REQUIRED'))
    return t`This organization requires single sign-on. Sign in with the official Bitwarden client because BearWarden does not support SSO sign-in yet.`
  if (error.message.includes('SYNC_DUO_UNSUPPORTED'))
    return t`This account requires Duo two-step verification, which BearWarden does not support yet. Use another enabled verification method or the official Bitwarden client.`
  if (error.message.includes('SYNC_KEY_CONNECTOR_UNSUPPORTED'))
    return t`This organization uses Key Connector. BearWarden cannot unlock this account safely; use the official Bitwarden client.`
  if (error.message.includes('SYNC_TRUSTED_DEVICE_UNSUPPORTED'))
    return t`This account requires trusted-device encryption. BearWarden cannot unlock it safely; use the official Bitwarden client.`
  if (error.message.includes('POLICY_RESTRICTED'))
    return t`This operation is restricted by your organization's policy.`
  if (error.message.includes('AUTH_REQUIRED'))
    return t`The Bitwarden vault must be signed in to or unlocked again.`
  if (error.message.includes('UNSUPPORTED_ACCOUNT'))
    return t`This account uses a newer account encryption or sign-in method that is not yet supported. To prevent data loss, BearWarden will not write any changes to the server.`
  if (error.message.includes('SYNC_NETWORK'))
    return t`Could not connect to the sync server. Check your network, server URL, and TLS certificate, then try again.`
  if (error.message.includes('SYNC_INVALID_RESPONSE'))
    return t`The server returned data that BearWarden cannot process safely. Check the server version and compatibility.`
  if (error.message.includes('SYNC_INVALID_SSH_KEY'))
    return t`The server contains an incomplete SSH key. Repair or delete it in Bitwarden or Vaultwarden first.`
  if (error.message.includes('SYNC_CONFLICT'))
    return t`The server data changed, so this sync was not applied. Sync again to get the latest version.`
  if (error.message.includes('LOCKED'))
    return t`The vault is locked. Enter your master password and try again.`
  if (error.message.includes('INVALID_MASTER_PASSWORD')) return t`The master password is incorrect.`
  if (error.message.includes('TWO_FACTOR'))
    return t`Two-step verification was invalid, expired, or canceled. Please try again.`
  if (error.message.includes('INVALID_URL')) return t`Enter a valid HTTPS server URL.`
  return t`Sync did not complete. Check your connection and sign-in information, then try again.`
}

export interface SyncErrorPresentation {
  title: string
  description: string
}

const SYNC_ERROR_CODES: readonly SyncErrorCode[] = [
  'SYNC_AUTH_REQUIRED',
  'SYNC_NEW_DEVICE_REQUIRED',
  'SYNC_SSO_REQUIRED',
  'SYNC_DUO_UNSUPPORTED',
  'SYNC_KEY_CONNECTOR_UNSUPPORTED',
  'SYNC_TRUSTED_DEVICE_UNSUPPORTED',
  'SYNC_UNSUPPORTED_ACCOUNT',
  'SYNC_NETWORK',
  'SYNC_INVALID_RESPONSE',
  'SYNC_INVALID_SSH_KEY',
  'SYNC_CONFLICT',
  'SYNC_FAILED'
]

// eslint-disable-next-line react-refresh/only-export-components
export function syncErrorCodeFromThrown(error: unknown): SyncErrorCode | undefined {
  if (!(error instanceof Error)) return undefined
  return SYNC_ERROR_CODES.find((code) => {
    const marker = `${IPC_ERROR_PREFIX}${code}`
    const markerIndex = error.message.indexOf(marker)
    if (markerIndex < 0) return false
    const nextCharacter = error.message[markerIndex + marker.length]
    return nextCharacter === undefined || !/[A-Z0-9_]/u.test(nextCharacter)
  })
}

// eslint-disable-next-line react-refresh/only-export-components
export function shouldOfferNewDeviceOtpResend(code?: SyncErrorCode): boolean {
  return code === 'SYNC_NEW_DEVICE_REQUIRED'
}

// eslint-disable-next-line react-refresh/only-export-components
export function shouldAutoOpenSyncErrorDetails(
  code: SyncErrorCode | undefined,
  occurredAt: string | undefined,
  previousOccurredAt: string | undefined,
  initial = false
): boolean {
  if (code !== 'SYNC_INVALID_RESPONSE') return false
  return initial || (!!occurredAt && occurredAt !== previousOccurredAt)
}

// eslint-disable-next-line react-refresh/only-export-components
export function syncInvalidResponseStageLabel(stage: SyncInvalidResponseStage): string {
  switch (stage) {
    case 'prelogin':
      return t({
        message: 'Account key derivation settings',
        comment:
          'Privacy-safe sync diagnostic stage for the prelogin KDF settings response, before credentials are submitted.'
      })
    case 'authentication':
      return t({
        message: 'Sign-in token response',
        comment:
          'Privacy-safe sync diagnostic stage for the password or two-factor token exchange response.'
      })
    case 'access-token':
      return t({
        message: 'Access token refresh',
        comment:
          'Privacy-safe sync diagnostic stage for refreshing an expired access token before downloading vault data.'
      })
    case 'response':
      return t`Server sync response`
    case 'account':
      return t`Account and encryption information`
    case 'organization':
      return t`Organization keys and member data`
    case 'folder':
      return t`Folder data`
    case 'cipher':
      return t`Vault item data`
    case 'collection':
      return t`Organization collection relationships`
    case 'send':
      return t`Send data`
    case 'snapshot':
      return t`Sync state commit`
  }
}

// Reasons are closed, value-free categories mirrored from the main-process parser. Never render
// connector messages here because they may contain account or vault identifiers.
// eslint-disable-next-line react-refresh/only-export-components
export function syncInvalidResponseReasonLabel(reason: SyncInvalidResponseReason): string {
  switch (reason) {
    case 'response-shape':
      return t`Sync response structure`
    case 'empty-response':
      return t({
        message: 'Empty server response',
        comment: 'Privacy-safe sync diagnostic reason shown when a successful response has no body.'
      })
    case 'invalid-json':
      return t({
        message: 'Server response is not valid JSON',
        comment:
          'Privacy-safe sync diagnostic reason shown when a successful server or proxy response cannot be parsed as JSON.'
      })
    case 'non-object-response':
      return t({
        message: 'Server response is not a JSON object',
        comment:
          'Privacy-safe sync diagnostic reason shown when JSON was returned but the top-level sync value has the wrong type.'
      })
    case 'session-response':
      return t({
        message: 'Session refresh response',
        comment:
          'Privacy-safe sync diagnostic reason for incompatible sign-in or access-token refresh metadata.'
      })
    case 'prelogin-route-response':
      return t({
        message: 'Account key derivation endpoint response',
        comment:
          'Privacy-safe sync diagnostic reason shown when a prelogin endpoint returns an error envelope instead of KDF fields.'
      })
    case 'kdf-settings':
      return t({
        message: 'Account key derivation settings',
        comment:
          'Privacy-safe sync diagnostic reason shown when prelogin KDF fields are missing or have incompatible types.'
      })
    case 'kdf-parameters':
      return t({
        message: 'Account key derivation parameters',
        comment:
          'Privacy-safe sync diagnostic reason shown when parsed account KDF parameters exceed supported security or resource bounds.'
      })
    case 'account-profile':
      return t`Account profile data`
    case 'user-decryption-data':
      return t`Account decryption options`
    case 'organization-profile':
      return t`Organization profile data`
    case 'organization-key':
      return t`Organization encryption key`
    case 'provider-organization-key':
      return t`Provider-managed organization key`
    case 'folder-data':
      return t`Folder data`
    case 'unsupported-cipher-type':
      return t`Unsupported vault item type`
    case 'cipher-data':
      return t`Vault item data`
    case 'collection-data':
      return t`Organization collection data`
    case 'send-data':
      return t`Send data`
    case 'snapshot-limit':
      return t`Local sync snapshot limit`
  }
}

// eslint-disable-next-line react-refresh/only-export-components
export function syncErrorPresentation(code: SyncErrorCode): SyncErrorPresentation {
  switch (code) {
    case 'SYNC_AUTH_REQUIRED':
      return {
        title: t`Your sign-in has expired`,
        description: t`Enter your master password again and complete two-step verification if the server requests it.`
      }
    case 'SYNC_NEW_DEVICE_REQUIRED':
      return {
        title: t`New device verification code required`,
        description: t`Get the verification code from the email sent by Bitwarden and enter it under advanced options.`
      }
    case 'SYNC_SSO_REQUIRED':
      return {
        title: t`Single sign-on is required`,
        description: t`This organization requires SSO sign-in, which BearWarden does not support yet. Use the official Bitwarden client to sign in.`
      }
    case 'SYNC_DUO_UNSUPPORTED':
      return {
        title: t`Duo verification is not supported`,
        description: t`Use another enabled two-step verification method, or sign in with the official Bitwarden client.`
      }
    case 'SYNC_KEY_CONNECTOR_UNSUPPORTED':
      return {
        title: t`Key Connector accounts are not supported`,
        description: t`BearWarden cannot unlock this organization's account safely. Use the official Bitwarden client.`
      }
    case 'SYNC_TRUSTED_DEVICE_UNSUPPORTED':
      return {
        title: t`Trusted-device encryption is not supported`,
        description: t`BearWarden cannot unlock this account safely without its trusted-device keys. Use the official Bitwarden client.`
      }
    case 'SYNC_UNSUPPORTED_ACCOUNT':
      return {
        title: t`This account's encryption method is not supported`,
        description: t`To prevent data loss, BearWarden stopped writing changes to the server. Update the app and try again.`
      }
    case 'SYNC_NETWORK':
      return {
        title: t`Could not connect to the sync server`,
        description: t`Check your network, server URL, and TLS certificate, and make sure the server is reachable.`
      }
    case 'SYNC_INVALID_RESPONSE':
      return {
        title: t`The server response is incompatible`,
        description: t`The data returned by the server cannot be processed safely. Check the Bitwarden or Vaultwarden version and compatibility.`
      }
    case 'SYNC_INVALID_SSH_KEY':
      return {
        title: t`The server contains an incomplete SSH key`,
        description: t`Vaultwarden returned an SSH key that is missing required key fields. Repair or delete it in the official web vault, then sync again.`
      }
    case 'SYNC_CONFLICT':
      return {
        title: t`The server data has changed`,
        description: t`This change was not applied. Sync again to get the latest version, then retry.`
      }
    case 'SYNC_FAILED':
      return {
        title: t`Sync did not complete`,
        description: t`Try again. If the problem persists, note the error code below for troubleshooting.`
      }
  }
}

export function SyncFailureAlert({
  code,
  detail,
  onShowDetails
}: {
  code: SyncErrorCode
  detail?: SyncInvalidResponseStage
  onShowDetails?: () => void
}): React.JSX.Element {
  const presentation = syncErrorPresentation(code)
  const detailLabel = detail ? syncInvalidResponseStageLabel(detail) : null
  const problemSection = detailLabel ? t`Problem section: ${detailLabel}` : null
  const errorCode = t`Error code: ${code}`
  return (
    <Alert variant="destructive">
      <CircleAlert aria-hidden="true" />
      <AlertTitle>{presentation.title}</AlertTitle>
      <AlertDescription className="flex flex-col gap-1">
        <span>{presentation.description}</span>
        {code === 'SYNC_INVALID_RESPONSE' && problemSection && <small>{problemSection}</small>}
        <small>{errorCode}</small>
        {onShowDetails && (
          <Button
            className="mt-1 self-start"
            variant="outline"
            size="xs"
            type="button"
            onClick={onShowDetails}
          >
            <Trans>View details</Trans>
          </Button>
        )}
      </AlertDescription>
    </Alert>
  )
}

export function SyncOperationFailureAlert({
  className,
  message,
  onShowDetails
}: {
  className?: string
  message: string
  onShowDetails?: () => void
}): React.JSX.Element {
  return (
    <Alert
      className={cn(
        '-mt-1 rounded-lg bg-[var(--danger-soft)] px-3 py-2 text-xs leading-normal',
        className
      )}
      variant="destructive"
    >
      <AlertDescription className="flex flex-col items-start gap-1">
        <span>{message}</span>
        {onShowDetails && (
          <Button variant="outline" size="xs" type="button" onClick={onShowDetails}>
            <Trans>View details</Trans>
          </Button>
        )}
      </AlertDescription>
    </Alert>
  )
}

function formatSyncTime(locale: string, value?: string): string {
  if (!value) return t`Never synced`
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return t`Never synced`
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}

function syncSummary(result: SyncResult): string {
  const { pulled, pushed, deleted, conflicts } = result
  const fragments = [
    t({ message: plural(pulled, { one: 'Pulled # item', other: 'Pulled # items' }) }),
    t({ message: plural(pushed, { one: 'Pushed # item', other: 'Pushed # items' }) }),
    t({ message: plural(deleted, { one: 'Deleted # item', other: 'Deleted # items' }) })
  ]
  if (conflicts)
    fragments.push(t({ message: plural(conflicts, { one: '# conflict', other: '# conflicts' }) }))
  return fragments.join(' · ')
}

function SyncDialog({
  status,
  onClose,
  onStatusChange,
  onSynced
}: SyncDialogProps): React.JSX.Element {
  const { i18n, t } = useLingui()
  const [serverUrl, setServerUrl] = useState(status.serverUrl ?? BITWARDEN_CLOUD_URL)
  const [email, setEmail] = useState(status.email ?? '')
  const [masterPassword, setMasterPassword] = useState('')
  const [twoFactorMethod, setTwoFactorMethod] = useState<SyncTwoFactorFormMethod>('0')
  const [twoFactorCode, setTwoFactorCode] = useState('')
  const [twoFactorProviders, setTwoFactorProviders] = useState<readonly SyncTwoFactorProvider[]>([])
  const [twoFactorChallengeActive, setTwoFactorChallengeActive] = useState(false)
  const [emailCodeBusy, setEmailCodeBusy] = useState(false)
  const [emailCodeSent, setEmailCodeSent] = useState(false)
  const [webAuthnRemember, setWebAuthnRemember] = useState(false)
  const [newDeviceOtp, setNewDeviceOtp] = useState('')
  const [newDeviceOtpBusy, setNewDeviceOtpBusy] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(shouldOfferNewDeviceOtpResend(status.lastError))
  const [showPassword, setShowPassword] = useState(false)
  const [confirmingDisconnect, setConfirmingDisconnect] = useState(false)
  const [errorDetailsOpen, setErrorDetailsOpen] = useState(() =>
    shouldAutoOpenSyncErrorDetails(status.lastError, status.lastErrorAt, status.lastErrorAt, true)
  )
  const [operationErrorDiagnostic, setOperationErrorDiagnostic] = useState<{
    code: SyncErrorCode
    occurredAt: string
  } | null>(null)
  const previousErrorAt = useRef(status.lastErrorAt)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [accountProfileState, setAccountProfileState] = useState<AccountProfileState>({
    owner: '',
    profile: null
  })
  const [accountSecurityError, setAccountSecurityError] = useState('')
  const [accountSecurityBusy, setAccountSecurityBusy] = useState(false)
  const twoFactorMethods: { label: string; value: SyncTwoFactorFormMethod }[] = [
    { label: t`Authenticator app`, value: '0' },
    { label: t`Email`, value: '1' },
    { label: t`YubiKey OTP`, value: '3' },
    { label: t`Security key`, value: WEB_AUTHN_TWO_FACTOR_METHOD }
  ]
  const availableTwoFactorMethods = twoFactorChallengeActive
    ? twoFactorMethods.filter(({ value }) =>
        twoFactorProviders.includes(syncTwoFactorProviderForMethod(value))
      )
    : twoFactorMethods
  const unsupportedTwoFactorChallenge =
    twoFactorChallengeActive && availableTwoFactorMethods.length === 0

  const configured = status.configured
  const requiresCredentials =
    !configured ||
    status.state === 'locked' ||
    status.lastError === 'SYNC_AUTH_REQUIRED' ||
    status.lastError === 'SYNC_NEW_DEVICE_REQUIRED'
  const isSyncing = busy || status.state === 'syncing'
  const currentAccountProfileIdentity = accountProfileIdentity(status.serverUrl, status.email)
  const visibleAccountProfile =
    accountProfileState.owner === currentAccountProfileIdentity ? accountProfileState.profile : null

  useEffect(() => {
    let active = true
    void Promise.resolve().then(async () => {
      if (!active) return
      setAccountProfileState((current) =>
        accountProfileStateForStatus(current, currentAccountProfileIdentity, status.state)
      )
      setAccountSecurityError('')
      if (status.state !== 'ready') {
        setAccountSecurityBusy(false)
        return
      }
      setAccountSecurityBusy(true)
      try {
        const profile = await window.bearwarden.accountSecurity.profile()
        if (active) {
          setAccountProfileState((current) =>
            applyAccountProfileIfCurrent(current, currentAccountProfileIdentity, profile)
          )
        }
      } catch {
        if (active) setAccountSecurityError(t`Could not load the account security status.`)
      } finally {
        if (active) setAccountSecurityBusy(false)
      }
    })
    return () => {
      active = false
    }
  }, [currentAccountProfileIdentity, status.state, t])

  useEffect(() => {
    const previous = previousErrorAt.current
    previousErrorAt.current = status.lastErrorAt
    if (shouldAutoOpenSyncErrorDetails(status.lastError, status.lastErrorAt, previous)) {
      setErrorDetailsOpen(true)
    }
  }, [status.lastError, status.lastErrorAt])

  async function resendVerification(): Promise<void> {
    setAccountSecurityBusy(true)
    setAccountSecurityError('')
    try {
      await window.bearwarden.accountSecurity.resendVerification()
      setSuccess(
        t`The verification email request was sent. If email is configured on the server, check your inbox to complete verification.`
      )
    } catch {
      setAccountSecurityError(
        t`Could not send the verification email. Make sure email is configured in Vaultwarden.`
      )
    } finally {
      setAccountSecurityBusy(false)
    }
  }

  function clearSecrets(): void {
    setMasterPassword('')
    setTwoFactorMethod('0')
    setTwoFactorCode('')
    setTwoFactorProviders([])
    setTwoFactorChallengeActive(false)
    setEmailCodeBusy(false)
    setEmailCodeSent(false)
    setWebAuthnRemember(false)
    setNewDeviceOtp('')
    setShowPassword(false)
  }

  function close(): void {
    if (busy || newDeviceOtpBusy) return
    clearSecrets()
    onClose()
  }

  function validateServerUrl(): string | null {
    try {
      const url = new URL(serverUrl.trim())
      if (url.protocol !== 'https:') return null
      return url.toString().replace(/\/$/, '')
    } catch {
      return null
    }
  }

  async function refreshAfterSuccess(
    result: SyncResult,
    formatMessage: (summary: string) => string
  ): Promise<void> {
    setOperationErrorDiagnostic(null)
    setErrorDetailsOpen(false)
    onStatusChange(result)
    clearSecrets()
    await onSynced()
    setSuccess(formatMessage(syncSummary(result)))
  }

  async function presentSyncOperationFailure(syncError: unknown): Promise<void> {
    const fallbackCode = syncErrorCodeFromThrown(syncError)
    let nextStatus: SyncStatus | null = null
    try {
      nextStatus = await window.bearwarden.sync.status()
      onStatusChange(nextStatus)
    } catch {
      // The original operation failure remains authoritative if status refresh also fails.
    }
    if (fallbackCode && nextStatus?.lastError === fallbackCode) {
      setOperationErrorDiagnostic(null)
      setError('')
      if (nextStatus.lastError === 'SYNC_INVALID_RESPONSE') setErrorDetailsOpen(true)
      return
    }
    setError(describeSyncError(syncError))
    if (!fallbackCode) {
      setOperationErrorDiagnostic(null)
      return
    }
    setOperationErrorDiagnostic({
      code: fallbackCode,
      occurredAt: new Date().toISOString()
    })
    if (fallbackCode === 'SYNC_INVALID_RESPONSE') setErrorDetailsOpen(true)
  }

  function applyTwoFactorChallenge(
    providers: readonly SyncTwoFactorProvider[]
  ): SyncTwoFactorFormMethod | null {
    const method = resolveSyncTwoFactorMethod(twoFactorMethod, providers)
    setTwoFactorProviders(providers)
    setTwoFactorChallengeActive(true)
    setShowAdvanced(true)
    setTwoFactorCode('')
    setEmailCodeSent(false)
    if (method) {
      setTwoFactorMethod(method)
      setError(t`Two-step verification is required. Enter a current verification code to continue.`)
    } else {
      setError(
        t`This account requires a two-step verification method that BearWarden does not support.`
      )
    }
    return method
  }

  async function sendEmailTwoFactorCode(
    normalizedUrl: string,
    showConfirmation: boolean
  ): Promise<boolean> {
    if (!email.trim() || !masterPassword || emailCodeBusy) return false
    setEmailCodeBusy(true)
    try {
      await window.bearwarden.sync.sendEmailTwoFactorCode({
        serverUrl: normalizedUrl,
        email: email.trim(),
        masterPassword
      })
      setEmailCodeSent(true)
      if (showConfirmation) setSuccess(t`A two-step verification code was sent by email.`)
      return true
    } catch (sendError) {
      setError(describeSyncError(sendError))
      return false
    } finally {
      setEmailCodeBusy(false)
    }
  }

  async function resendNewDeviceOtp(): Promise<void> {
    const normalizedUrl = validateServerUrl()
    if (!normalizedUrl) {
      setError(t`Enter a valid HTTPS server URL.`)
      return
    }
    if (!email.trim() || !masterPassword || newDeviceOtpBusy) return
    setNewDeviceOtpBusy(true)
    setError('')
    setSuccess('')
    try {
      await window.bearwarden.sync.resendNewDeviceOtp({
        serverUrl: normalizedUrl,
        email: email.trim(),
        masterPassword
      })
      setSuccess(t`A new device verification code was sent by email.`)
    } catch (resendError) {
      setError(describeSyncError(resendError))
    } finally {
      setNewDeviceOtpBusy(false)
    }
  }

  async function connect(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    const normalizedUrl = validateServerUrl()
    if (!normalizedUrl) {
      setError(t`Enter a valid HTTPS server URL.`)
      return
    }
    if (!email.trim() || !masterPassword) {
      setError(t`Enter your email and master password.`)
      return
    }
    setBusy(true)
    setError('')
    setOperationErrorDiagnostic(null)
    setErrorDetailsOpen(false)
    setSuccess('')
    try {
      const response = await window.bearwarden.sync.connect({
        serverUrl: normalizedUrl,
        email: email.trim(),
        masterPassword,
        ...(newDeviceOtp.trim() ? { newDeviceOtp: newDeviceOtp.trim() } : {}),
        ...buildSyncTwoFactorRequest({ twoFactorMethod, twoFactorCode, webAuthnRemember })
      })
      if (response.kind === 'two-factor-required') {
        const method = applyTwoFactorChallenge(response.providers)
        if (method === '1') await sendEmailTwoFactorCode(normalizedUrl, false)
        return
      }
      await refreshAfterSuccess(response.result, (summary) => t`Connected and synced. ${summary}.`)
    } catch (connectError) {
      if (connectError instanceof Error && connectError.message.includes('NEW_DEVICE_REQUIRED')) {
        setShowAdvanced(true)
      }
      await presentSyncOperationFailure(connectError)
    } finally {
      setBusy(false)
    }
  }

  async function unlock(): Promise<void> {
    if (!masterPassword) {
      setError(t`Enter your master password.`)
      return
    }
    setBusy(true)
    setError('')
    setOperationErrorDiagnostic(null)
    setErrorDetailsOpen(false)
    setSuccess('')
    try {
      const response = await window.bearwarden.sync.unlock({
        masterPassword,
        ...(newDeviceOtp.trim() ? { newDeviceOtp: newDeviceOtp.trim() } : {}),
        ...buildSyncTwoFactorRequest({ twoFactorMethod, twoFactorCode, webAuthnRemember })
      })
      if (response.kind === 'two-factor-required') {
        const method = applyTwoFactorChallenge(response.providers)
        const normalizedUrl = validateServerUrl()
        if (method === '1' && normalizedUrl) {
          await sendEmailTwoFactorCode(normalizedUrl, false)
        }
        return
      }
      await refreshAfterSuccess(response.result, (summary) => t`Unlocked and synced. ${summary}.`)
    } catch (unlockError) {
      if (unlockError instanceof Error && unlockError.message.includes('NEW_DEVICE_REQUIRED')) {
        setShowAdvanced(true)
      }
      await presentSyncOperationFailure(unlockError)
    } finally {
      setBusy(false)
    }
  }

  async function syncNow(): Promise<void> {
    setBusy(true)
    setError('')
    setOperationErrorDiagnostic(null)
    setErrorDetailsOpen(false)
    setSuccess('')
    try {
      const result = await window.bearwarden.sync.now()
      await refreshAfterSuccess(result, (summary) => t`Sync complete. ${summary}.`)
    } catch (syncError) {
      await presentSyncOperationFailure(syncError)
    } finally {
      setBusy(false)
    }
  }

  async function resolvePendingImport(): Promise<void> {
    if (!masterPassword) {
      setError(t`Enter your master password.`)
      return
    }
    setBusy(true)
    setError('')
    setSuccess('')
    try {
      const nextStatus = await window.bearwarden.sync.resolvePendingImport({
        masterPassword,
        confirmRetry: true
      })
      onStatusChange(nextStatus)
      clearSecrets()
      setSuccess(t`Resending is now allowed. Select “Sync now” to retry.`)
    } catch (resolveError) {
      setError(describeSyncError(resolveError))
    } finally {
      setBusy(false)
    }
  }

  async function disconnect(): Promise<void> {
    setBusy(true)
    setError('')
    try {
      const nextStatus = await window.bearwarden.sync.disconnect()
      onStatusChange(nextStatus)
      clearSecrets()
      setConfirmingDisconnect(false)
      setSuccess(t`Disconnected from Bitwarden sync.`)
    } catch (disconnectError) {
      setError(describeSyncError(disconnectError))
    } finally {
      setBusy(false)
    }
  }

  const lastErrorTime = formatSyncTime(i18n.locale, status.lastErrorAt)
  const lastSyncTime = formatSyncTime(i18n.locale, status.lastSyncAt)
  const diagnosticCode = operationErrorDiagnostic?.code ?? status.lastError
  const diagnosticOccurredAt = operationErrorDiagnostic?.occurredAt ?? status.lastErrorAt
  const diagnosticDetail = operationErrorDiagnostic ? undefined : status.lastErrorDetail
  const diagnosticReason = operationErrorDiagnostic ? undefined : status.lastErrorReason

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) close()
      }}
    >
      <ModalContent
        className="grid w-[min(calc(100%-32px),530px)] max-w-[min(calc(100%-32px),530px)] grid-rows-[auto_minmax(0,1fr)]"
        showCloseButton={false}
      >
        <ModalHeader className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-start">
          <span
            className={cn(
              'text-primary grid size-11 place-items-center rounded-xl bg-[var(--accent-soft)]',
              status.state === 'error' && 'bg-[var(--danger-soft)] text-[var(--danger)]'
            )}
            aria-hidden="true"
          >
            {status.state === 'error' ? <CircleAlert /> : <Cloud />}
          </span>
          <div>
            <DialogTitle className="m-0 text-lg">
              <Trans>Sync</Trans>
            </DialogTitle>
          </div>
          <Button
            variant="ghost"
            size="icon-sm"
            type="button"
            aria-label={t`Close`}
            onClick={close}
            disabled={busy || newDeviceOtpBusy}
          >
            <X aria-hidden="true" />
          </Button>
        </ModalHeader>

        <ModalBody className="min-h-0 gap-3.5 overflow-y-auto overscroll-contain px-5 pt-4 pb-0">
          <Alert
            className="[&_small]:text-muted-foreground grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2.5 rounded-lg bg-[var(--panel-muted)] px-3 py-2.5 [&_small]:text-xs [&_small]:leading-snug [&_strong]:text-xs [&>div]:grid [&>div]:gap-1"
            role="status"
            aria-live="polite"
          >
            <span
              className={cn(
                'size-2 rounded-full bg-[var(--subtle)]',
                isSyncing
                  ? 'animate-[pulse_1.1s_ease-in-out_infinite] bg-[var(--focus)]'
                  : status.state === 'ready'
                    ? 'bg-[var(--success)] shadow-[0_0_0_3px_color-mix(in_srgb,var(--success),transparent_80%)]'
                    : status.state === 'locked' || status.state === 'unconfigured'
                      ? 'bg-[var(--gold)]'
                      : status.state === 'error'
                        ? 'bg-[var(--danger)]'
                        : undefined
              )}
              aria-hidden="true"
            />
            <div>
              <strong>
                {isSyncing
                  ? t`Syncing…`
                  : status.state === 'ready'
                    ? t`Connected, vault unlocked`
                    : status.state === 'locked'
                      ? t`Connected, vault locked`
                      : status.state === 'error'
                        ? t`A sync issue needs attention`
                        : t`Sync is not configured`}
              </strong>
              <small>
                {status.lastError
                  ? status.lastErrorAt
                    ? t`Sync failed: ${lastErrorTime}`
                    : t`The last sync encountered a problem.`
                  : status.lastSyncAt
                    ? t`Last synced: ${lastSyncTime}`
                    : t`Your master password and verification codes are used only for this operation and are not stored on this device.`}
              </small>
            </div>
            {isSyncing && <Spinner aria-label={t`Syncing`} />}
          </Alert>

          {status.lastError && (
            <SyncFailureAlert
              code={status.lastError}
              detail={status.lastErrorDetail}
              onShowDetails={() => setErrorDetailsOpen(true)}
            />
          )}

          {requiresCredentials ? (
            <form
              className="-mx-5 grid gap-3"
              onSubmit={
                configured
                  ? (event) => {
                      event.preventDefault()
                      void unlock()
                    }
                  : connect
              }
            >
              <FieldGroup className="mx-5 w-auto">
                {!configured && (
                  <>
                    <Field className="grid gap-2">
                      <FieldLabel htmlFor="server-url">
                        <Trans>Server URL</Trans>
                      </FieldLabel>
                      <Input
                        id="server-url"
                        autoFocus
                        type="url"
                        inputMode="url"
                        autoComplete="url"
                        value={serverUrl}
                        onChange={(event) => setServerUrl(event.target.value)}
                        placeholder={BITWARDEN_CLOUD_URL}
                        disabled={busy}
                        required
                      />
                      <FieldDescription>
                        <Trans>
                          Use bitwarden.com for Bitwarden Cloud. For Vaultwarden, use an HTTPS URL.
                        </Trans>
                      </FieldDescription>
                    </Field>
                    <Field className="grid gap-2">
                      <FieldLabel htmlFor="sync-email">
                        <Trans>Email</Trans>
                      </FieldLabel>
                      <Input
                        id="sync-email"
                        type="email"
                        autoComplete="username"
                        value={email}
                        onChange={(event) => setEmail(event.target.value)}
                        disabled={busy}
                        required
                      />
                    </Field>
                  </>
                )}
                {configured && (
                  <Alert
                    className="text-primary m-0 flex items-center gap-2 rounded-lg border-0 bg-[color-mix(in_oklch,var(--primary)_10%,var(--background))] px-2.5 py-2 text-xs [&_[data-slot=alert-description]]:text-xs"
                    role="status"
                  >
                    <ShieldCheck aria-hidden="true" />
                    <AlertDescription>{status.email ?? t`Configured account`}</AlertDescription>
                  </Alert>
                )}
                <Field className="grid gap-2">
                  <FieldLabel htmlFor="sync-master-password">
                    <Trans>Master password</Trans>
                  </FieldLabel>
                  <InputGroup>
                    <InputGroupInput
                      id="sync-master-password"
                      autoFocus={configured}
                      type={showPassword ? 'text' : 'password'}
                      autoComplete="current-password"
                      value={masterPassword}
                      onChange={(event) => setMasterPassword(event.target.value)}
                      disabled={busy}
                      required
                    />
                    <InputGroupAddon align="inline-end">
                      <InputGroupButton
                        size="icon-xs"
                        aria-label={
                          showPassword ? t`Hide master password` : t`Show master password`
                        }
                        aria-pressed={showPassword}
                        onClick={() => setShowPassword((visible) => !visible)}
                        disabled={busy}
                      >
                        {showPassword ? <EyeOff /> : <Eye />}
                      </InputGroupButton>
                    </InputGroupAddon>
                  </InputGroup>
                </Field>
              </FieldGroup>
              <div
                className="mx-5 [&[data-open=true]_[data-slot=sync-accordion-chevron]]:scale-y-[-1] [&[data-open=true]_[data-slot=sync-accordion-panel-inner]]:opacity-100 [&[data-open=true]_[data-slot=sync-accordion-panel-inner]]:blur-none [&[data-open=true]_[data-slot=sync-accordion-panel-inner]]:duration-[var(--acc-expand)] [&[data-open=true]_[data-slot=sync-accordion-panel]]:grid-rows-[1fr] [&[data-open=true]_[data-slot=sync-accordion-panel]]:duration-[var(--acc-expand)]"
                data-open={showAdvanced ? 'true' : 'false'}
              >
                <Button
                  className="gap-1 justify-self-start border-0 bg-transparent px-0 py-1 text-xs font-bold text-[var(--accent-hover)] underline underline-offset-3"
                  variant="ghost"
                  type="button"
                  aria-expanded={showAdvanced}
                  onClick={() => setShowAdvanced((open) => !open)}
                  disabled={busy}
                >
                  {showAdvanced ? t`Hide advanced options` : t`Show two-step verification`}
                  <span
                    data-slot="sync-accordion-chevron"
                    className="inline-flex origin-center scale-y-100 transition-transform duration-[var(--acc-chevron)] ease-[var(--acc-ease)] motion-reduce:!transition-none [&_path]:[vector-effect:non-scaling-stroke]"
                    aria-hidden="true"
                  >
                    <ChevronDown />
                  </span>
                </Button>
                <div
                  data-slot="sync-accordion-panel"
                  className="grid grid-rows-[0fr] transition-[grid-template-rows] duration-[var(--acc-collapse)] ease-[var(--acc-ease)] motion-reduce:!transition-none"
                  aria-hidden={!showAdvanced}
                >
                  <div
                    data-slot="sync-accordion-panel-inner"
                    className="overflow-hidden pt-3 opacity-0 blur-[2px] transition-[opacity,filter] duration-[var(--acc-collapse)] ease-[var(--acc-ease)] motion-reduce:!transition-none"
                    inert={!showAdvanced}
                  >
                    <FieldGroup className="grid w-auto gap-3 rounded-lg border bg-[var(--panel-muted)] p-3">
                      <Field>
                        <FieldLabel htmlFor="two-factor-method">
                          {twoFactorChallengeActive ? (
                            <Trans>Two-step verification method</Trans>
                          ) : (
                            <Trans>Two-step verification method (optional)</Trans>
                          )}
                        </FieldLabel>
                        <Select
                          items={availableTwoFactorMethods}
                          value={twoFactorMethod}
                          onValueChange={(value) => {
                            const method = value as SyncTwoFactorFormMethod
                            setTwoFactorMethod(method)
                            setTwoFactorCode('')
                            if (method === '1' && !emailCodeSent) {
                              const normalizedUrl = validateServerUrl()
                              if (normalizedUrl) {
                                void sendEmailTwoFactorCode(normalizedUrl, false)
                              }
                            }
                          }}
                          disabled={busy || unsupportedTwoFactorChallenge}
                        >
                          <SelectTrigger id="two-factor-method" className="w-full">
                            <SelectValue placeholder={t`Select a verification method`} />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectGroup>
                              {availableTwoFactorMethods.map((method) => (
                                <SelectItem key={method.value} value={method.value}>
                                  {method.label}
                                </SelectItem>
                              ))}
                            </SelectGroup>
                          </SelectContent>
                        </Select>
                        {unsupportedTwoFactorChallenge && (
                          <FieldDescription>
                            <Trans>
                              None of the verification methods offered by this server are supported
                              by BearWarden.
                            </Trans>
                          </FieldDescription>
                        )}
                      </Field>
                      {twoFactorMethod === WEB_AUTHN_TWO_FACTOR_METHOD ? (
                        <Field orientation="horizontal" data-disabled={busy || undefined}>
                          <Checkbox
                            id="webauthn-remember"
                            checked={webAuthnRemember}
                            onCheckedChange={setWebAuthnRemember}
                            disabled={busy}
                          />
                          <FieldContent>
                            <FieldLabel htmlFor="webauthn-remember">
                              <Trans>Remember this device</Trans>
                            </FieldLabel>
                            <FieldDescription>
                              <Trans>
                                Let the server temporarily skip two-step verification on this
                                device.
                              </Trans>
                            </FieldDescription>
                          </FieldContent>
                        </Field>
                      ) : (
                        <Field>
                          <FieldLabel htmlFor="two-factor-code">
                            {twoFactorChallengeActive ? (
                              <Trans>Two-step verification code</Trans>
                            ) : (
                              <Trans>Two-step verification code (optional)</Trans>
                            )}
                          </FieldLabel>
                          <Input
                            id="two-factor-code"
                            autoComplete="one-time-code"
                            autoCapitalize="none"
                            value={twoFactorCode}
                            onChange={(event) => setTwoFactorCode(event.target.value)}
                            disabled={busy || unsupportedTwoFactorChallenge}
                          />
                          {twoFactorMethod === '1' && twoFactorProviders.includes('1') && (
                            <Button
                              className="justify-self-start"
                              variant="outline"
                              type="button"
                              disabled={busy || emailCodeBusy || !masterPassword}
                              onClick={() => {
                                const normalizedUrl = validateServerUrl()
                                if (normalizedUrl) {
                                  void sendEmailTwoFactorCode(normalizedUrl, true)
                                }
                              }}
                            >
                              {emailCodeBusy ? (
                                <Spinner />
                              ) : emailCodeSent ? (
                                <Trans>Resend email code</Trans>
                              ) : (
                                <Trans>Send email code</Trans>
                              )}
                            </Button>
                          )}
                        </Field>
                      )}
                      <Field>
                        <FieldLabel htmlFor="new-device-otp">
                          <Trans>New device verification code (optional)</Trans>
                        </FieldLabel>
                        <Input
                          id="new-device-otp"
                          inputMode="numeric"
                          autoComplete="one-time-code"
                          value={newDeviceOtp}
                          onChange={(event) => setNewDeviceOtp(event.target.value)}
                          disabled={busy}
                        />
                        <FieldDescription>
                          <Trans>Use only when Bitwarden asks you to verify a new device.</Trans>
                        </FieldDescription>
                        {shouldOfferNewDeviceOtpResend(status.lastError) && (
                          <Button
                            className="justify-self-start"
                            variant="outline"
                            type="button"
                            disabled={busy || newDeviceOtpBusy || !email.trim() || !masterPassword}
                            onClick={() => void resendNewDeviceOtp()}
                          >
                            {newDeviceOtpBusy && (
                              <Spinner data-icon="inline-start" aria-hidden="true" />
                            )}
                            <Trans>Resend verification code</Trans>
                          </Button>
                        )}
                      </Field>
                    </FieldGroup>
                  </div>
                </div>
              </div>
              {error && (
                <SyncOperationFailureAlert
                  className="mx-5"
                  message={error}
                  onShowDetails={
                    operationErrorDiagnostic ? () => setErrorDetailsOpen(true) : undefined
                  }
                />
              )}
              {success && (
                <Alert
                  className="text-primary m-0 mx-5 flex items-start gap-2 rounded-lg border-0 bg-[color-mix(in_oklch,var(--primary)_10%,var(--background))] px-2.5 py-2 text-xs leading-normal [&_[data-slot=alert-description]]:text-xs"
                  role="status"
                >
                  <CheckCircle2 aria-hidden="true" />
                  <AlertDescription>{success}</AlertDescription>
                </Alert>
              )}
              <ModalFooter className="mt-px">
                <Button
                  variant="secondary"
                  type="button"
                  onClick={close}
                  disabled={busy || newDeviceOtpBusy}
                >
                  <Trans>Cancel</Trans>
                </Button>
                <Button type="submit" disabled={isSyncing || unsupportedTwoFactorChallenge}>
                  {isSyncing && <Spinner data-icon="inline-start" aria-hidden="true" />}
                  {configured ? t`Unlock and sync` : t`Connect and sync`}
                </Button>
              </ModalFooter>
            </form>
          ) : (
            <>
              <section
                className="[&_svg]:text-primary [&_span]:text-muted-foreground grid gap-px overflow-hidden rounded-lg border [&_strong]:truncate [&_strong]:text-right [&_strong]:font-semibold [&>div]:grid [&>div]:min-w-0 [&>div]:grid-cols-[16px_76px_minmax(0,1fr)] [&>div]:items-center [&>div]:gap-1.5 [&>div]:border-b [&>div]:p-2.5 [&>div]:text-xs [&>div:last-child]:border-b-0"
                aria-label={t`Sync connection information`}
              >
                <div>
                  <Server size={16} aria-hidden="true" />
                  <span>
                    <Trans>Server</Trans>
                  </span>
                  <strong>{status.serverUrl ?? BITWARDEN_CLOUD_URL}</strong>
                </div>
                <div>
                  <KeyRound size={16} aria-hidden="true" />
                  <span>
                    <Trans>Account</Trans>
                  </span>
                  <strong>{status.email ?? t`Not provided`}</strong>
                </div>
                <div>
                  <RefreshCw size={16} aria-hidden="true" />
                  <span>
                    <Trans>Last sync</Trans>
                  </span>
                  <strong>{lastSyncTime}</strong>
                </div>
              </section>
              {status.pendingImport && (
                <PendingImportWarning
                  count={status.pendingImport.count}
                  startedAt={status.pendingImport.startedAt}
                  masterPassword={masterPassword}
                  showPassword={showPassword}
                  busy={busy}
                  onMasterPasswordChange={setMasterPassword}
                  onTogglePassword={() => setShowPassword((visible) => !visible)}
                  onConfirm={() => void resolvePendingImport()}
                />
              )}
              {visibleAccountProfile && (
                <section
                  className="bg-card overflow-hidden rounded-xl border"
                  aria-label={t`Account management`}
                >
                  <AccountProfileCard
                    key={currentAccountProfileIdentity}
                    profile={visibleAccountProfile}
                    onProfileChange={(profile) => {
                      setAccountProfileState((current) =>
                        applyAccountProfileIfCurrent(
                          current,
                          currentAccountProfileIdentity,
                          profile
                        )
                      )
                    }}
                  />
                  <Separator />
                  <div
                    className="flex flex-wrap items-center gap-2 px-4 py-3"
                    role="group"
                    aria-label={t`Account security status`}
                  >
                    <ShieldCheck className="text-muted-foreground size-4" aria-hidden="true" />
                    <div className="flex min-w-0 flex-1 flex-wrap gap-2">
                      <Badge
                        variant={visibleAccountProfile.emailVerified ? 'secondary' : 'outline'}
                      >
                        {visibleAccountProfile.emailVerified
                          ? t`Email verified`
                          : t`Email not verified`}
                      </Badge>
                      <Badge
                        variant={visibleAccountProfile.twoFactorEnabled ? 'secondary' : 'outline'}
                      >
                        {visibleAccountProfile.twoFactorEnabled
                          ? t`Two-step verification enabled`
                          : t`Two-step verification not enabled`}
                      </Badge>
                    </div>
                    {!visibleAccountProfile.emailVerified && (
                      <Button
                        variant="outline"
                        size="sm"
                        type="button"
                        disabled={accountSecurityBusy}
                        onClick={() => void resendVerification()}
                      >
                        {accountSecurityBusy && (
                          <Spinner data-icon="inline-start" aria-hidden="true" />
                        )}
                        <Trans>Resend verification email</Trans>
                      </Button>
                    )}
                  </div>
                  <Separator />
                  <div className="grid grid-cols-1 gap-2 p-3 sm:grid-cols-3">
                    <AccountDevicesDialog />
                    <AccountApiKeyDialog />
                    <AccountTwoFactorDialog />
                  </div>
                </section>
              )}
              {accountSecurityError && (
                <Alert variant="destructive">
                  <AlertDescription>{accountSecurityError}</AlertDescription>
                </Alert>
              )}
              {error && (
                <SyncOperationFailureAlert
                  message={error}
                  onShowDetails={
                    operationErrorDiagnostic ? () => setErrorDetailsOpen(true) : undefined
                  }
                />
              )}
              {success && (
                <Alert
                  className="text-primary m-0 flex items-start gap-2 rounded-lg border-0 bg-[color-mix(in_oklch,var(--primary)_10%,var(--background))] px-2.5 py-2 text-xs leading-normal [&_[data-slot=alert-description]]:text-xs"
                  role="status"
                >
                  <CheckCircle2 aria-hidden="true" />
                  <AlertDescription>{success}</AlertDescription>
                </Alert>
              )}
              <ModalFooter split className="-mx-5">
                <AlertDialog
                  open={confirmingDisconnect}
                  onOpenChange={(open) => {
                    if (!busy) setConfirmingDisconnect(open)
                  }}
                >
                  <AlertDialogTrigger
                    render={<Button variant="ghost" type="button" disabled={isSyncing} />}
                  >
                    <Unplug data-icon="inline-start" aria-hidden="true" />
                    <Trans>Disconnect</Trans>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogMedia>
                        <AlertTriangle aria-hidden="true" />
                      </AlertDialogMedia>
                      <AlertDialogTitle>
                        <Trans>Disconnect sync?</Trans>
                      </AlertDialogTitle>
                      <AlertDialogDescription>
                        <Trans>
                          This will not delete your local vault, but it will no longer sync with
                          Bitwarden.
                        </Trans>
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel disabled={busy}>
                        <Trans>Go back</Trans>
                      </AlertDialogCancel>
                      <AlertDialogAction
                        variant="destructive"
                        type="button"
                        disabled={busy}
                        onClick={() => void disconnect()}
                      >
                        {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                        <Trans>Disconnect</Trans>
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
                <ModalActionGroup>
                  <Button variant="secondary" type="button" onClick={close} disabled={isSyncing}>
                    <Trans>Close</Trans>
                  </Button>
                  <Button type="button" onClick={() => void syncNow()} disabled={isSyncing}>
                    {isSyncing && <Spinner data-icon="inline-start" aria-hidden="true" />}
                    <Trans>Sync now</Trans>
                  </Button>
                </ModalActionGroup>
              </ModalFooter>
            </>
          )}
        </ModalBody>
      </ModalContent>
      {diagnosticCode && (
        <SyncErrorDetailsDialog
          open={errorDetailsOpen}
          onOpenChange={setErrorDetailsOpen}
          code={diagnosticCode}
          detail={diagnosticDetail}
          reason={diagnosticCode === 'SYNC_INVALID_RESPONSE' ? diagnosticReason : undefined}
          occurredAt={diagnosticOccurredAt}
          serverUrl={status.serverUrl ?? serverUrl}
          title={syncErrorPresentation(diagnosticCode).title}
          description={syncErrorPresentation(diagnosticCode).description}
          detailLabel={
            diagnosticDetail ? syncInvalidResponseStageLabel(diagnosticDetail) : undefined
          }
          reasonLabel={
            diagnosticCode === 'SYNC_INVALID_RESPONSE' && diagnosticReason
              ? syncInvalidResponseReasonLabel(diagnosticReason)
              : undefined
          }
        />
      )}
    </Dialog>
  )
}

export default SyncDialog
