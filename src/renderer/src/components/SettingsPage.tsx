import { useEffect, useRef, useState } from 'react'
import { Plural, Trans, useLingui } from '@lingui/react/macro'
import {
  ClipboardCheck,
  Cloud,
  DatabaseBackup,
  Download,
  Fingerprint,
  Info,
  Keyboard,
  KeyRound,
  LockKeyhole,
  LockKeyholeOpen,
  Palette,
  Settings2,
  ShieldCheck,
  Upload
} from 'lucide-react'
import type {
  AccountStatus,
  AppLanguagePreference,
  AppSettings,
  AppSettingsUpdate,
  AutofillFeatureStatus,
  PinUnlockStatus,
  SshAgentPromptBehavior,
  SshAgentStatus,
  SyncStatus,
  VaultTimeoutPolicy
} from '../../../shared/vault-contract'
import { MAX_VAULT_TIMEOUT_MINUTES } from '../../../shared/vault-contract'
import { AUTOFILL_SHORTCUTS, isAutofillShortcut } from '../../../shared/autofill-shortcuts'
import { Badge } from '@renderer/components/ui/badge'
import { Button } from '@renderer/components/ui/button'
import { CardAction, CardFooter, CardHeader } from '@renderer/components/ui/card'
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle
} from '@renderer/components/ui/empty'
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel
} from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput
} from '@renderer/components/ui/input-group'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue
} from '@renderer/components/ui/select'
import { Separator } from '@renderer/components/ui/separator'
import { Spinner } from '@renderer/components/ui/spinner'
import { Switch } from '@renderer/components/ui/switch'
import { Tabs, TabsList, TabsTrigger } from '@renderer/components/ui/tabs'
import { ToggleGroup, ToggleGroupItem } from '@renderer/components/ui/toggle-group'
import { useCopyFeedback } from '@renderer/hooks/use-copy-feedback'
import {
  isWindowsSshAgentEndpoint,
  sshAgentSocketExportCommand,
  sshAgentStatusPresentation
} from '@renderer/lib/ssh-agent-ui'
import EquivalentDomainsDialog from './EquivalentDomainsDialog'
import MasterPasswordChangeDialog from './MasterPasswordChangeDialog'
import AccountSwitcherCard from './AccountSwitcherCard'
import PersonalVaultPurgeDialog from './PersonalVaultPurgeDialog'
import AuxiliaryPageLayout, { AuxiliaryPageContent } from './AuxiliaryPageLayout'
import AboutPage from './AboutPage'
import { AutofillAccessibilityGuide } from './AutofillAccessibilityGuide'
import { CopyFeedbackIcon } from './CopyFeedbackIcon'
import AutofillShortcut from './AutofillShortcut'
import {
  SettingsCard,
  SettingsCardContent,
  SettingsCardHeading,
  SettingsCategoryContent,
  SettingsRow,
  SettingsSelectRow,
  SettingsStackedRow
} from './SettingsPrimitives'

const vaultTimeoutPresetMinutes = [1, 5, 15, 30, 60, 240] as const
const maxVaultTimeoutMinutes = MAX_VAULT_TIMEOUT_MINUTES
const maxVaultTimeoutHours = Math.floor(maxVaultTimeoutMinutes / 60)

export const contentProtectionDescription =
  'When enabled, BearWarden may be hidden in Windows Remote Desktop, screen sharing, and recordings. If only the taskbar icon remains visible, turn this option off in a local session.'

// eslint-disable-next-line react-refresh/only-export-components
export function autofillStatusPresentation(
  enabled: boolean,
  status: AutofillFeatureStatus | null
): { label: string; variant: 'default' | 'secondary' | 'destructive' } {
  if (!status) return { label: 'Checking', variant: 'secondary' }
  if (!status.available) return { label: 'macOS only', variant: 'secondary' }
  if (!enabled) return { label: 'Disabled', variant: 'secondary' }
  if (!status.shortcutRegistered) return { label: 'Shortcut conflict', variant: 'destructive' }
  if (!status.accessibilityTrusted) return { label: 'Permission required', variant: 'destructive' }
  return { label: 'Available', variant: 'default' }
}

// eslint-disable-next-line react-refresh/only-export-components
export const settingsCategories = [
  { id: 'general', label: 'General', description: 'Appearance and defaults', icon: Palette },
  {
    id: 'security',
    label: 'Security & unlock',
    description: 'Locking and unlocking',
    icon: ShieldCheck
  },
  {
    id: 'privacy',
    label: 'Privacy',
    description: 'Clipboard and website icons',
    icon: ClipboardCheck
  },
  {
    id: 'accounts',
    label: 'Accounts & sync',
    description: 'Local accounts and cloud connections',
    icon: Cloud
  },
  {
    id: 'tools',
    label: 'Tools & data',
    description: 'Autofill, SSH Agent, and backups',
    icon: KeyRound
  },
  { id: 'about', label: 'About', description: 'Version and update information', icon: Info }
] as const

type SettingsCategoryId = (typeof settingsCategories)[number]['id']

// eslint-disable-next-line react-refresh/only-export-components
export const vaultTimeoutItems = [
  { label: 'When the app restarts', value: 'onRestart' },
  { label: 'After 5 minutes of system inactivity', value: 'systemIdle' },
  ...vaultTimeoutPresetMinutes.map((minutes) => ({
    label: `${minutes} ${minutes === 1 ? 'minute' : 'minutes'}`,
    value: String(minutes)
  })),
  { label: 'Custom', value: 'custom' }
] as const

// eslint-disable-next-line react-refresh/only-export-components
export const languageItems: ReadonlyArray<{
  label: string
  value: AppLanguagePreference
}> = [
  { label: 'System', value: 'system' },
  { label: 'English', value: 'en' },
  { label: 'Simplified Chinese', value: 'zh-CN' },
  { label: 'Traditional Chinese', value: 'zh-TW' },
  { label: 'Japanese', value: 'ja' }
]

type VaultTimeoutSelectValue = (typeof vaultTimeoutItems)[number]['value']

// These presentation helpers are exported solely for focused renderer tests.
// eslint-disable-next-line react-refresh/only-export-components
export function vaultTimeoutSelectValue(policy: VaultTimeoutPolicy): VaultTimeoutSelectValue {
  if (policy.type === 'onRestart') return 'onRestart'
  if (policy.type === 'systemIdle') return 'systemIdle'
  return vaultTimeoutPresetMinutes.includes(
    policy.minutes as (typeof vaultTimeoutPresetMinutes)[number]
  )
    ? String(policy.minutes)
    : 'custom'
}

// eslint-disable-next-line react-refresh/only-export-components
export function vaultTimeoutCustomFields(policy: VaultTimeoutPolicy): {
  hours: string
  minutes: string
} {
  if (policy.type !== 'appInactivity') return { hours: '0', minutes: '1' }
  return {
    hours: String(Math.floor(policy.minutes / 60)),
    minutes: String(policy.minutes % 60)
  }
}

// eslint-disable-next-line react-refresh/only-export-components
export function vaultTimeoutPolicyFromCustomFields(
  hours: string,
  minutes: string
): VaultTimeoutPolicy | null {
  if (!/^\d+$/.test(hours) || !/^\d+$/.test(minutes)) return null
  const parsedHours = Number(hours)
  const parsedMinutes = Number(minutes)
  if (
    !Number.isSafeInteger(parsedHours) ||
    !Number.isSafeInteger(parsedMinutes) ||
    parsedHours > maxVaultTimeoutHours ||
    parsedMinutes > 59
  ) {
    return null
  }
  const totalMinutes = parsedHours * 60 + parsedMinutes
  if (totalMinutes < 1 || totalMinutes > maxVaultTimeoutMinutes) return null
  return { type: 'appInactivity', minutes: totalMinutes }
}

// eslint-disable-next-line react-refresh/only-export-components
export function vaultTimeoutCustomValidationMessage(hours: string, minutes: string): string | null {
  if (!/^\d+$/.test(hours) || !/^\d+$/.test(minutes)) {
    return 'Enter whole numbers for hours and minutes.'
  }
  const parsedHours = Number(hours)
  const parsedMinutes = Number(minutes)
  if (parsedMinutes > 59) return 'Minutes must be between 0 and 59.'
  if (
    parsedHours > maxVaultTimeoutHours ||
    parsedHours * 60 + parsedMinutes > maxVaultTimeoutMinutes
  ) {
    return 'The custom inactivity timeout cannot exceed 8,760 hours.'
  }
  if (!vaultTimeoutPolicyFromCustomFields(hours, minutes)) {
    return 'The custom inactivity timeout must be at least 1 minute.'
  }
  return null
}

// eslint-disable-next-line react-refresh/only-export-components
export function applyVaultTimeoutCustomFields(
  hours: string,
  minutes: string,
  onUpdate: (update: AppSettingsUpdate) => Promise<unknown>
): string | null {
  const validationMessage = vaultTimeoutCustomValidationMessage(hours, minutes)
  if (validationMessage) return validationMessage
  const policy = vaultTimeoutPolicyFromCustomFields(hours, minutes)
  if (!policy) return 'Check the custom inactivity timeout.'
  void onUpdate({ vaultTimeoutPolicy: policy })
  return null
}

interface VaultTimeoutCustomFieldsProps {
  policy: VaultTimeoutPolicy
  disabled: boolean
  onUpdate: (update: AppSettingsUpdate) => Promise<unknown>
}

function VaultTimeoutCustomFields({
  policy,
  disabled,
  onUpdate
}: VaultTimeoutCustomFieldsProps): React.JSX.Element {
  const { t } = useLingui()
  const initialFields = vaultTimeoutCustomFields(policy)
  const [hours, setHours] = useState(initialFields.hours)
  const [minutes, setMinutes] = useState(initialFields.minutes)
  const validationMessage = (() => {
    if (!/^\d+$/.test(hours) || !/^\d+$/.test(minutes)) {
      return t`Enter whole numbers for hours and minutes.`
    }
    const parsedHours = Number(hours)
    const parsedMinutes = Number(minutes)
    if (parsedMinutes > 59) return t`Minutes must be between 0 and 59.`
    if (
      parsedHours > maxVaultTimeoutHours ||
      parsedHours * 60 + parsedMinutes > maxVaultTimeoutMinutes
    ) {
      return t`The custom inactivity timeout cannot exceed 8,760 hours.`
    }
    if (!vaultTimeoutPolicyFromCustomFields(hours, minutes)) {
      return t`The custom inactivity timeout must be at least 1 minute.`
    }
    return null
  })()

  const apply = (): void => {
    if (validationMessage) return
    const policy = vaultTimeoutPolicyFromCustomFields(hours, minutes)
    if (!policy) return
    void onUpdate({ vaultTimeoutPolicy: policy })
  }

  return (
    <SettingsSelectRow>
      <FieldContent>
        <FieldLabel>
          <Trans>Custom inactivity timeout</Trans>
        </FieldLabel>
        <FieldDescription id="vault-timeout-custom-description">
          <Trans>Minimum 1 minute, maximum 8,760 hours; minutes must be between 0 and 59.</Trans>
        </FieldDescription>
      </FieldContent>
      <div className="flex items-center gap-2" aria-describedby="vault-timeout-custom-description">
        <Input
          aria-label={t`Custom inactivity timeout hours`}
          type="number"
          inputMode="numeric"
          min={0}
          max={maxVaultTimeoutHours}
          step={1}
          value={hours}
          disabled={disabled}
          aria-invalid={Boolean(validationMessage)}
          onChange={(event) => setHours(event.target.value)}
        />
        <span aria-hidden="true">
          <Trans>hours</Trans>
        </span>
        <Input
          aria-label={t`Custom inactivity timeout minutes`}
          type="number"
          inputMode="numeric"
          min={0}
          max={59}
          step={1}
          value={minutes}
          disabled={disabled}
          aria-invalid={Boolean(validationMessage)}
          onChange={(event) => setMinutes(event.target.value)}
        />
        <span aria-hidden="true">
          <Trans>minutes</Trans>
        </span>
        <Button
          type="button"
          size="sm"
          disabled={disabled || Boolean(validationMessage)}
          onClick={apply}
        >
          <Trans>Apply</Trans>
        </Button>
        {validationMessage && (
          <p className="text-destructive text-sm" role="alert">
            {validationMessage}
          </p>
        )}
      </div>
    </SettingsSelectRow>
  )
}

const initialSshAgentStatus: SshAgentStatus = {
  enabled: false,
  running: false,
  state: 'stopped',
  identityCount: 0
}

interface SettingsPageProps {
  settings: AppSettings | null
  settingsBusy: boolean
  syncStatus: SyncStatus
  touchIdPassword: string
  onUpdate: (update: AppSettingsUpdate) => Promise<boolean | void>
  onTouchIdPasswordChange: (value: string) => void
  onEnableTouchId: () => Promise<void>
  onDisableTouchId: () => Promise<void>
  onOpenSync: () => void
  onVaultPurged: () => void | Promise<void>
  onExportVault: () => void
  onImportVault: () => void
  accountStatus: AccountStatus | null
  accountBusy: boolean
  accountBusyLabel: string
  accountError: string
  onRequestAccountAdd: (proceed: () => void) => void
  onRequestAccountSwitch: (proceed: () => void) => void
  onRequestAccountRemove: (proceed: () => void) => void
  onAddAccount: () => Promise<void>
  onSwitchAccount: (accountId: string) => Promise<void>
  onRenameAccount: (
    accountId: string,
    displayName: string,
    expectedRevision: number
  ) => Promise<void>
  onReorderAccounts: (accountIds: readonly string[], expectedRevision: number) => Promise<void>
  onRemoveAccount: (accountId: string) => Promise<void>
}

function SettingsPage({
  settings,
  settingsBusy,
  syncStatus,
  touchIdPassword,
  onUpdate,
  onTouchIdPasswordChange,
  onEnableTouchId,
  onDisableTouchId,
  onOpenSync,
  onVaultPurged,
  onExportVault,
  onImportVault,
  accountStatus,
  accountBusy,
  accountBusyLabel,
  accountError,
  onRequestAccountAdd,
  onRequestAccountSwitch,
  onRequestAccountRemove,
  onAddAccount,
  onSwitchAccount,
  onRenameAccount,
  onReorderAccounts,
  onRemoveAccount
}: SettingsPageProps): React.JSX.Element {
  const { t } = useLingui()
  const [sshAgentStatus, setSshAgentStatus] = useState<SshAgentStatus>(initialSshAgentStatus)
  const [autofillStatus, setAutofillStatus] = useState<AutofillFeatureStatus | null>(null)
  const [autofillPermissionBusy, setAutofillPermissionBusy] = useState(false)
  const [autofillOperationBusy, setAutofillOperationBusy] = useState(false)
  const [autofillFeedback, setAutofillFeedback] = useState('')
  const autofillStatusEpochRef = useRef(0)
  const { copiedKey, clearCopied, showCopied } = useCopyFeedback()
  const [pinStatus, setPinStatus] = useState<PinUnlockStatus>({
    available: false,
    remainingAttempts: 0
  })
  const [pin, setPin] = useState('')
  const [pinConfirmation, setPinConfirmation] = useState('')
  const [pinMasterPassword, setPinMasterPassword] = useState('')
  const [pinBusy, setPinBusy] = useState(false)
  const [pinFeedback, setPinFeedback] = useState('')
  const [customTimeoutSelected, setCustomTimeoutSelected] = useState(false)
  const settingsScrollRef = useRef<HTMLDivElement>(null)
  const [activeSettingsCategory, setActiveSettingsCategory] = useState<SettingsCategoryId>(
    settingsCategories[0].id
  )
  const localizedSettingsCategories = [
    {
      id: 'general',
      label: t`General`,
      description: t`Appearance and defaults`,
      icon: Palette
    },
    {
      id: 'security',
      label: t`Security & unlock`,
      description: t`Locking and unlocking`,
      icon: ShieldCheck
    },
    {
      id: 'privacy',
      label: t`Privacy`,
      description: t`Clipboard and website icons`,
      icon: ClipboardCheck
    },
    {
      id: 'accounts',
      label: t`Accounts & sync`,
      description: t`Local accounts and cloud connections`,
      icon: Cloud
    },
    {
      id: 'tools',
      label: t`Tools & data`,
      description: t`Autofill, SSH Agent, and backups`,
      icon: KeyRound
    },
    { id: 'about', label: t`About`, description: t`Version and update information`, icon: Info }
  ] as const
  const localizedVaultTimeoutItems = [
    { label: t`When the app restarts`, value: 'onRestart' },
    { label: t`After 5 minutes of system inactivity`, value: 'systemIdle' },
    { label: t`1 minute`, value: '1' },
    { label: t`5 minutes`, value: '5' },
    { label: t`15 minutes`, value: '15' },
    { label: t`30 minutes`, value: '30' },
    { label: t`60 minutes`, value: '60' },
    { label: t`240 minutes`, value: '240' },
    { label: t`Custom`, value: 'custom' }
  ] as const
  const localizedClipboardClearItems = [
    { label: t`Never`, value: 0 },
    { label: t`After 15 seconds`, value: 15 },
    { label: t`After 30 seconds`, value: 30 },
    { label: t`After 1 minute`, value: 60 },
    { label: t`After 2 minutes`, value: 120 }
  ] as const
  const localizedDefaultSortItems = [
    {
      label: t({
        message: 'Recently used',
        context: 'recent-items-filter',
        comment: 'Sort label for vault items that have been used most recently.'
      }),
      value: 'recent'
    },
    { label: t`Most used`, value: 'frequency' },
    { label: t`Name`, value: 'name' }
  ] as const
  const localizedThemeItems = [
    { label: t`System`, value: 'system' },
    { label: t`Light`, value: 'light' },
    { label: t`Dark`, value: 'dark' }
  ] as const
  const localizedLanguageItems: ReadonlyArray<{
    label: string
    value: AppLanguagePreference
  }> = [
    { label: t`System`, value: 'system' },
    { label: t`English`, value: 'en' },
    { label: t`Simplified Chinese`, value: 'zh-CN' },
    { label: t`Traditional Chinese`, value: 'zh-TW' },
    { label: t`Japanese`, value: 'ja' }
  ]
  const localizedSshAgentPromptItems: ReadonlyArray<{
    label: string
    value: SshAgentPromptBehavior
  }> = [
    { label: t`Ask before every signature`, value: 'always' },
    { label: t`Never ask (approve automatically)`, value: 'never' },
    { label: t`Remember approvals until locked`, value: 'rememberUntilLock' }
  ]
  const localizedSyncLabels: Record<SyncStatus['state'], string> = {
    unconfigured: t`Not configured`,
    locked: t`Unlock required`,
    ready: t`Connected`,
    syncing: t`Syncing…`,
    error: t`Action required`
  }

  useEffect(() => {
    let active = true
    void window.bearwarden.sshAgent.status().then(
      (status) => {
        if (active) setSshAgentStatus(status)
      },
      () => {
        if (active) {
          setSshAgentStatus({
            ...initialSshAgentStatus,
            state: 'error',
            lastError: 'START_FAILED'
          })
        }
      }
    )
    const unsubscribe = window.bearwarden.sshAgent.onStatusChanged((status) => {
      if (active) setSshAgentStatus(status)
    })
    return () => {
      active = false
      unsubscribe()
    }
  }, [])

  useEffect(() => {
    let active = true
    const refresh = (): void => {
      const epoch = ++autofillStatusEpochRef.current
      void window.bearwarden.autofill.status().then(
        (status) => {
          if (active && epoch === autofillStatusEpochRef.current) setAutofillStatus(status)
        },
        () => {
          if (active) setAutofillFeedback(t`Unable to read the autofill status.`)
        }
      )
    }
    refresh()
    window.addEventListener('focus', refresh)
    return () => {
      active = false
      autofillStatusEpochRef.current += 1
      window.removeEventListener('focus', refresh)
    }
  }, [t])

  useEffect(() => {
    let active = true
    void window.bearwarden.vault.pinStatus().then(
      (status) => {
        if (active) setPinStatus(status)
      },
      () => {
        if (active) setPinFeedback(t`Unable to read the PIN unlock status.`)
      }
    )
    return () => {
      active = false
    }
  }, [t])

  async function enablePinUnlock(): Promise<void> {
    setPinFeedback('')
    if (pin.normalize('NFC').length < 4) {
      setPinFeedback(t`The PIN must contain at least 4 characters.`)
      return
    }
    if (pin !== pinConfirmation) {
      setPinFeedback(t`The PINs do not match.`)
      return
    }
    if (!pinMasterPassword) {
      setPinFeedback(t`Enter your master password to confirm.`)
      return
    }
    const request = { pin, masterPassword: pinMasterPassword }
    setPin('')
    setPinConfirmation('')
    setPinMasterPassword('')
    setPinBusy(true)
    try {
      setPinStatus(await window.bearwarden.vault.enablePin(request))
      setPinFeedback(t`PIN unlock is enabled for this session only.`)
    } catch (error) {
      setPinFeedback(
        error instanceof Error && error.message.includes('INVALID_MASTER_PASSWORD')
          ? t`The master password is incorrect.`
          : t`Unable to enable PIN unlock.`
      )
    } finally {
      request.pin = ''
      request.masterPassword = ''
      setPinBusy(false)
    }
  }

  async function disablePinUnlock(): Promise<void> {
    setPinBusy(true)
    setPinFeedback('')
    try {
      setPinStatus(await window.bearwarden.vault.disablePin())
      setPinFeedback(t`PIN unlock is disabled.`)
    } catch {
      setPinFeedback(t`Unable to disable PIN unlock.`)
    } finally {
      setPin('')
      setPinConfirmation('')
      setPinMasterPassword('')
      setPinBusy(false)
    }
  }

  const sshAgentStatusPresentationValue = sshAgentStatusPresentation(
    settings?.sshAgentEnabled ?? false,
    sshAgentStatus
  )
  const sshAgentStatusLabel = !(settings?.sshAgentEnabled ?? false)
    ? t`Disabled`
    : sshAgentStatus.state === 'ready'
      ? t`Ready`
      : sshAgentStatus.state === 'starting'
        ? t`Starting`
        : sshAgentStatus.state === 'error'
          ? t`Action required`
          : t`Stopped`
  const autofillStatusPresentationValue = autofillStatusPresentation(
    settings?.autofillEnabled ?? false,
    autofillStatus
  )
  const autofillStatusLabel = !autofillStatus
    ? t`Checking`
    : !autofillStatus.available
      ? t`macOS only`
      : !settings?.autofillEnabled
        ? t`Disabled`
        : !autofillStatus.shortcutRegistered
          ? t`Shortcut conflict`
          : !autofillStatus.accessibilityTrusted
            ? t`Permission required`
            : t`Available`
  const sshAgentEndpoint = sshAgentStatus.endpoint
  const usesWindowsNamedPipe = isWindowsSshAgentEndpoint(sshAgentEndpoint)
  const sshAgentCommand = usesWindowsNamedPipe
    ? undefined
    : sshAgentSocketExportCommand(sshAgentEndpoint)

  async function copySshAgentCommand(): Promise<void> {
    clearCopied()
    try {
      if (!sshAgentCommand) return
      await navigator.clipboard.writeText(sshAgentCommand)
      showCopied('ssh-agent-command')
    } catch {
      clearCopied()
    }
  }

  async function refreshAutofillStatus(): Promise<void> {
    const epoch = ++autofillStatusEpochRef.current
    try {
      const status = await window.bearwarden.autofill.status()
      if (epoch !== autofillStatusEpochRef.current) return
      setAutofillStatus(status)
      setAutofillFeedback(t`Accessibility and shortcut status checked again.`)
    } catch {
      if (epoch !== autofillStatusEpochRef.current) return
      setAutofillFeedback(t`Unable to read the autofill status.`)
    }
  }

  async function updateAutofillEnabled(enabled: boolean): Promise<void> {
    if (autofillOperationBusy) return
    setAutofillOperationBusy(true)
    setAutofillFeedback('')
    try {
      const saved = await onUpdate({ autofillEnabled: enabled })
      if (saved === false) {
        setAutofillFeedback(
          t`The autofill setting could not be saved, so the shortcut status was not changed.`
        )
        return
      }
      const epoch = ++autofillStatusEpochRef.current
      const status = await window.bearwarden.autofill.status()
      if (epoch !== autofillStatusEpochRef.current) return
      setAutofillStatus(status)
      if (enabled && !status.shortcutRegistered) {
        setAutofillFeedback(
          t`The global autofill shortcut is already used by another app. Disable the same shortcut in that app first.`
        )
      }
    } catch {
      setAutofillFeedback(t`Unable to update the autofill setting.`)
    } finally {
      setAutofillOperationBusy(false)
    }
  }

  async function updateAutofillShortcut(shortcut: AppSettings['autofillShortcut']): Promise<void> {
    if (autofillOperationBusy || shortcut === settings?.autofillShortcut) return
    setAutofillOperationBusy(true)
    setAutofillFeedback('')
    try {
      const saved = await onUpdate({ autofillShortcut: shortcut })
      if (saved === false) {
        setAutofillFeedback(t`That shortcut is unavailable. Your previous shortcut remains active.`)
        return
      }
      const epoch = ++autofillStatusEpochRef.current
      const status = await window.bearwarden.autofill.status()
      if (epoch !== autofillStatusEpochRef.current) return
      setAutofillStatus(status)
      setAutofillFeedback(t`Autofill shortcut updated.`)
    } catch {
      setAutofillFeedback(t`Unable to update the autofill shortcut.`)
    } finally {
      setAutofillOperationBusy(false)
    }
  }

  async function requestAutofillAccessibility(): Promise<void> {
    if (autofillOperationBusy) return
    setAutofillOperationBusy(true)
    setAutofillPermissionBusy(true)
    setAutofillFeedback('')
    const epoch = ++autofillStatusEpochRef.current
    try {
      const status = await window.bearwarden.autofill.requestAccessibility()
      if (epoch !== autofillStatusEpochRef.current) return
      setAutofillStatus(status)
      setAutofillFeedback(
        status.accessibilityTrusted
          ? t`Accessibility permission is enabled. Cross-browser autofill is ready to use.`
          : t`Allow BearWarden under System Settings → Privacy & Security → Accessibility, then return and check again.`
      )
    } catch {
      if (epoch !== autofillStatusEpochRef.current) return
      setAutofillFeedback(
        t`Unable to request accessibility permission. Enable it manually in System Settings.`
      )
    } finally {
      setAutofillPermissionBusy(false)
      setAutofillOperationBusy(false)
    }
  }

  return (
    <Tabs
      value={activeSettingsCategory}
      className="min-h-0 min-w-0 flex-1 gap-0"
      onValueChange={(value) => {
        if (typeof value !== 'string') return
        setActiveSettingsCategory(value as SettingsCategoryId)
        settingsScrollRef.current?.scrollTo({ top: 0 })
      }}
    >
      <AuxiliaryPageLayout
        title={t`Settings`}
        titleId="settings-title"
        subtitle={t`Manage security, appearance, and sync on this device.`}
        headerIcon={<Settings2 />}
        scrollRef={settingsScrollRef}
        scrollClassName="scroll-fade scroll-fade-4 forced-colors:scroll-fade-none"
        headerNavigation={
          settings ? (
            <TabsList
              variant="line"
              sliding
              aria-label={t`Settings categories`}
              className="scroll-fade-x scroll-fade-4 forced-colors:scroll-fade-none w-full justify-start gap-1 overflow-x-auto px-1 group-data-horizontal/tabs:h-10"
            >
              {localizedSettingsCategories.map(({ id, label, description, icon: Icon }) => (
                <TabsTrigger
                  key={id}
                  value={id}
                  title={description}
                  className="min-w-max gap-2 px-3"
                >
                  <Icon aria-hidden="true" />
                  {label}
                </TabsTrigger>
              ))}
            </TabsList>
          ) : undefined
        }
        headerActions={
          settingsBusy ? (
            <span
              className="text-muted-foreground inline-flex shrink-0 items-center gap-1.5 text-[11px]"
              role="status"
            >
              <Spinner />
              <Trans>Saving</Trans>
            </span>
          ) : undefined
        }
      >
        {!settings ? (
          <div
            className="text-muted-foreground flex min-h-0 flex-1 flex-row items-center justify-center gap-2.5 p-7 text-center text-[11px]"
            role="status"
          >
            <Spinner /> <Trans>Loading settings…</Trans>
          </div>
        ) : (
          <AuxiliaryPageContent className="max-w-[910px] !grid-cols-[minmax(0,1fr)] gap-4">
            <SettingsCategoryContent value="general">
              <SettingsCard aria-labelledby="general-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="general-settings-title"
                    icon={Palette}
                    title={t`General`}
                    description={t`Customize the vault's appearance and default sorting.`}
                  />
                </CardHeader>
                <SettingsCardContent flush>
                  <FieldGroup className="gap-0">
                    <SettingsStackedRow>
                      <FieldLabel htmlFor="theme-select">
                        <Trans>Theme</Trans>
                      </FieldLabel>
                      <Select
                        items={localizedThemeItems}
                        value={settings.theme}
                        disabled={settingsBusy}
                        onValueChange={(value) =>
                          void onUpdate({ theme: value as AppSettings['theme'] })
                        }
                      >
                        <SelectTrigger id="theme-select">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            {localizedThemeItems.map((item) => (
                              <SelectItem key={item.value} value={item.value}>
                                {item.label}
                              </SelectItem>
                            ))}
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </SettingsStackedRow>
                    <Separator />
                    <SettingsStackedRow>
                      <FieldLabel htmlFor="language-select">
                        <Trans>Language</Trans>
                      </FieldLabel>
                      <Select
                        items={localizedLanguageItems}
                        value={settings.language}
                        disabled={settingsBusy}
                        onValueChange={(value) =>
                          void onUpdate({ language: value as AppLanguagePreference })
                        }
                      >
                        <SelectTrigger id="language-select">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            {localizedLanguageItems.map((item) => (
                              <SelectItem key={item.value} value={item.value}>
                                {item.label}
                              </SelectItem>
                            ))}
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </SettingsStackedRow>
                    <Separator />
                    <SettingsStackedRow>
                      <FieldLabel htmlFor="default-sort-select">
                        <Trans>Default sort</Trans>
                      </FieldLabel>
                      <Select
                        items={localizedDefaultSortItems}
                        value={settings.defaultSort}
                        disabled={settingsBusy}
                        onValueChange={(value) =>
                          void onUpdate({ defaultSort: value as AppSettings['defaultSort'] })
                        }
                      >
                        <SelectTrigger id="default-sort-select">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            {localizedDefaultSortItems.map((item) => (
                              <SelectItem key={item.value} value={item.value}>
                                {item.label}
                              </SelectItem>
                            ))}
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </SettingsStackedRow>
                    <Separator />
                    <SettingsRow data-disabled={!settings.startAtLoginAvailable}>
                      <FieldContent>
                        <FieldLabel htmlFor="start-at-login-switch">
                          <Trans>Launch BearWarden at login</Trans>
                        </FieldLabel>
                        <FieldDescription id="start-at-login-description">
                          {settings.startAtLoginAvailable
                            ? settings.startAtLoginNeedsApproval
                              ? t`Registered, but you still need to allow BearWarden in Login Items under macOS System Settings.`
                              : t`Launch BearWarden automatically after you log in to this computer.`
                            : t`Automatic launch is available only in installed versions for macOS and Windows.`}
                        </FieldDescription>
                      </FieldContent>
                      <Switch
                        id="start-at-login-switch"
                        checked={settings.startAtLogin}
                        disabled={settingsBusy || !settings.startAtLoginAvailable}
                        aria-describedby="start-at-login-description"
                        onCheckedChange={(checked) => void onUpdate({ startAtLogin: checked })}
                      />
                    </SettingsRow>
                  </FieldGroup>
                </SettingsCardContent>
              </SettingsCard>
            </SettingsCategoryContent>
            <SettingsCategoryContent value="security">
              <SettingsCard aria-labelledby="security-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="security-settings-title"
                    icon={ShieldCheck}
                    title={t`Security`}
                    description={t`Choose when the vault locks and how window content is protected.`}
                  />
                  <CardAction>
                    <Badge variant="secondary">
                      <Trans>This device</Trans>
                    </Badge>
                  </CardAction>
                </CardHeader>
                <SettingsCardContent flush>
                  <FieldGroup className="gap-0">
                    <SettingsRow>
                      <FieldContent>
                        <FieldLabel htmlFor="content-protection-switch">
                          <Trans>Block screenshots</Trans>
                        </FieldLabel>
                        <FieldDescription id="content-protection-description">
                          <Trans>
                            When enabled, BearWarden may be hidden in Windows Remote Desktop, screen
                            sharing, and recordings. If only the taskbar icon remains visible, turn
                            this option off in a local session.
                          </Trans>
                        </FieldDescription>
                      </FieldContent>
                      <Switch
                        id="content-protection-switch"
                        checked={settings.contentProtection}
                        disabled={settingsBusy}
                        aria-describedby="content-protection-description"
                        onCheckedChange={(checked) => void onUpdate({ contentProtection: checked })}
                      />
                    </SettingsRow>
                    <Separator />
                    <SettingsRow>
                      <FieldContent>
                        <FieldLabel htmlFor="screen-lock-switch">
                          <Trans>Lock when the screen is locked</Trans>
                        </FieldLabel>
                        <FieldDescription id="screen-lock-description">
                          <Trans>Lock the vault immediately when you lock the screen.</Trans>
                        </FieldDescription>
                      </FieldContent>
                      <Switch
                        id="screen-lock-switch"
                        checked={settings.lockOnScreenLock}
                        disabled={settingsBusy}
                        aria-describedby="screen-lock-description"
                        onCheckedChange={(checked) => void onUpdate({ lockOnScreenLock: checked })}
                      />
                    </SettingsRow>
                    <Separator />
                    <SettingsRow>
                      <FieldContent>
                        <FieldLabel htmlFor="suspend-lock-switch">
                          <Trans>Lock when the computer sleeps</Trans>
                        </FieldLabel>
                        <FieldDescription id="suspend-lock-description">
                          <Trans>Lock the vault immediately when the computer goes to sleep.</Trans>
                        </FieldDescription>
                      </FieldContent>
                      <Switch
                        id="suspend-lock-switch"
                        checked={settings.lockOnSuspend}
                        disabled={settingsBusy}
                        aria-describedby="suspend-lock-description"
                        onCheckedChange={(checked) => void onUpdate({ lockOnSuspend: checked })}
                      />
                    </SettingsRow>
                    <Separator />
                    <SettingsSelectRow>
                      <FieldContent>
                        <FieldLabel htmlFor="vault-timeout-select">
                          <Trans>Lock after inactivity</Trans>
                        </FieldLabel>
                        <FieldDescription id="vault-timeout-description">
                          <Trans>
                            Lock automatically after a period of inactivity. The vault always locks
                            when the app closes.
                          </Trans>
                        </FieldDescription>
                      </FieldContent>
                      <Select
                        items={localizedVaultTimeoutItems}
                        value={
                          customTimeoutSelected
                            ? 'custom'
                            : vaultTimeoutSelectValue(settings.vaultTimeoutPolicy)
                        }
                        disabled={settingsBusy}
                        onValueChange={(value) => {
                          if (value === 'onRestart') {
                            setCustomTimeoutSelected(false)
                            void onUpdate({ vaultTimeoutPolicy: { type: 'onRestart' } })
                            return
                          }
                          if (value === 'systemIdle') {
                            setCustomTimeoutSelected(false)
                            void onUpdate({ vaultTimeoutPolicy: { type: 'systemIdle' } })
                            return
                          }
                          if (value === 'custom') {
                            setCustomTimeoutSelected(true)
                            return
                          }
                          setCustomTimeoutSelected(false)
                          void onUpdate({
                            vaultTimeoutPolicy: { type: 'appInactivity', minutes: Number(value) }
                          })
                        }}
                      >
                        <SelectTrigger
                          id="vault-timeout-select"
                          aria-describedby="vault-timeout-description"
                        >
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            {localizedVaultTimeoutItems.map((item) => (
                              <SelectItem key={item.value} value={item.value}>
                                {item.label}
                              </SelectItem>
                            ))}
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </SettingsSelectRow>
                    {(customTimeoutSelected ||
                      vaultTimeoutSelectValue(settings.vaultTimeoutPolicy) === 'custom') && (
                      <>
                        <Separator />
                        <VaultTimeoutCustomFields
                          key={
                            settings.vaultTimeoutPolicy.type === 'appInactivity'
                              ? settings.vaultTimeoutPolicy.minutes
                              : settings.vaultTimeoutPolicy.type
                          }
                          policy={settings.vaultTimeoutPolicy}
                          disabled={settingsBusy}
                          onUpdate={onUpdate}
                        />
                      </>
                    )}
                  </FieldGroup>
                </SettingsCardContent>
              </SettingsCard>

              <SettingsCard aria-labelledby="pin-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="pin-settings-title"
                    icon={LockKeyholeOpen}
                    title={t`PIN unlock`}
                    description={t`Unlock the local vault with a temporary PIN.`}
                  />
                  <CardAction>
                    <Badge variant={pinStatus.available ? 'default' : 'secondary'}>
                      {pinStatus.available ? t`Enabled` : t`Disabled`}
                    </Badge>
                  </CardAction>
                </CardHeader>
                {pinStatus.available ? (
                  <>
                    <SettingsCardContent className="grid gap-2">
                      <p className="text-muted-foreground m-0 text-xs leading-[1.6]">
                        <Trans>
                          The encrypted PIN credential remains in memory only. You must use the
                          master password after restarting, signing out, disconnecting, or switching
                          accounts.
                        </Trans>
                      </p>
                      <p className="text-muted-foreground m-0 text-xs leading-[1.5]">
                        <Plural
                          value={pinStatus.remainingAttempts}
                          one="PIN unlock is disabled after 5 consecutive failures. You have # attempt remaining."
                          other="PIN unlock is disabled after 5 consecutive failures. You have # attempts remaining."
                        />
                      </p>
                      {pinFeedback && (
                        <p className="text-muted-foreground m-0 text-xs leading-[1.5]">
                          {pinFeedback}
                        </p>
                      )}
                    </SettingsCardContent>
                    <CardFooter>
                      <Button
                        variant="outline"
                        size="sm"
                        type="button"
                        disabled={pinBusy || settingsBusy}
                        onClick={() => void disablePinUnlock()}
                      >
                        <Trans>Disable PIN unlock</Trans>
                      </Button>
                    </CardFooter>
                  </>
                ) : (
                  <>
                    <SettingsCardContent className="grid gap-4">
                      <p className="text-muted-foreground m-0 text-xs leading-[1.6]">
                        <Trans>
                          The PIN and encrypted credential are never written to disk. You can use
                          the PIN after a normal lock, but restarting the app always requires the
                          master password.
                        </Trans>
                      </p>
                      <FieldGroup>
                        <Field>
                          <FieldLabel htmlFor="pin-unlock-pin">
                            <Trans>PIN</Trans>
                          </FieldLabel>
                          <Input
                            id="pin-unlock-pin"
                            type="password"
                            autoComplete="new-password"
                            value={pin}
                            disabled={pinBusy || settingsBusy}
                            onChange={(event) => setPin(event.target.value)}
                          />
                          <FieldDescription>
                            <Trans>
                              Use at least 4 characters and avoid numbers that are easy to guess.
                            </Trans>
                          </FieldDescription>
                        </Field>
                        <Field>
                          <FieldLabel htmlFor="pin-unlock-confirmation">
                            <Trans>Enter PIN again</Trans>
                          </FieldLabel>
                          <Input
                            id="pin-unlock-confirmation"
                            type="password"
                            autoComplete="new-password"
                            value={pinConfirmation}
                            disabled={pinBusy || settingsBusy}
                            onChange={(event) => setPinConfirmation(event.target.value)}
                          />
                        </Field>
                        <Field>
                          <FieldLabel htmlFor="pin-unlock-master-password">
                            <Trans>Confirm master password</Trans>
                          </FieldLabel>
                          <Input
                            id="pin-unlock-master-password"
                            type="password"
                            autoComplete="current-password"
                            value={pinMasterPassword}
                            disabled={pinBusy || settingsBusy}
                            onChange={(event) => setPinMasterPassword(event.target.value)}
                          />
                          <FieldDescription>
                            <Trans>
                              The master password is verified again in the main process each time
                              PIN unlock is enabled.
                            </Trans>
                          </FieldDescription>
                        </Field>
                      </FieldGroup>
                      {pinFeedback && (
                        <p className="text-muted-foreground m-0 text-xs leading-[1.5]">
                          {pinFeedback}
                        </p>
                      )}
                    </SettingsCardContent>
                    <CardFooter>
                      <Button
                        size="sm"
                        type="button"
                        disabled={
                          pinBusy ||
                          settingsBusy ||
                          pin.length < 4 ||
                          pinConfirmation.length < 4 ||
                          !pinMasterPassword
                        }
                        onClick={() => void enablePinUnlock()}
                      >
                        {pinBusy ? (
                          <Spinner data-icon="inline-start" aria-hidden="true" />
                        ) : (
                          <LockKeyhole data-icon="inline-start" aria-hidden="true" />
                        )}
                        <Trans>Enable PIN unlock</Trans>
                      </Button>
                    </CardFooter>
                  </>
                )}
              </SettingsCard>

              <SettingsCard aria-labelledby="touch-id-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="touch-id-settings-title"
                    icon={Fingerprint}
                    title={t`Biometrics`}
                    description={t`Unlock quickly with device biometrics. Currently, only macOS Touch ID is supported.`}
                  />
                  <CardAction>
                    <Badge variant={settings.touchIdEnabled ? 'default' : 'secondary'}>
                      {!settings.touchIdAvailable
                        ? t`Unavailable`
                        : settings.touchIdEnabled
                          ? t`Enabled`
                          : t`Disabled`}
                    </Badge>
                  </CardAction>
                </CardHeader>
                {!settings.touchIdAvailable ? (
                  <SettingsCardContent>
                    <Empty className="min-h-40 p-4">
                      <EmptyHeader>
                        <EmptyMedia variant="icon">
                          <Fingerprint />
                        </EmptyMedia>
                        <EmptyTitle>
                          <Trans>Biometrics are unavailable on this device</Trans>
                        </EmptyTitle>
                        <EmptyDescription>
                          <Trans>
                            Currently, only macOS Touch ID is supported. You can still unlock the
                            vault with your master password.
                          </Trans>
                        </EmptyDescription>
                      </EmptyHeader>
                    </Empty>
                  </SettingsCardContent>
                ) : settings.touchIdEnabled ? (
                  <>
                    <SettingsCardContent>
                      <p className="text-muted-foreground m-0 text-xs leading-[1.6]">
                        <Trans>You can use biometrics to unlock after the next lock.</Trans>
                      </p>
                    </SettingsCardContent>
                    <CardFooter>
                      <Button
                        variant="outline"
                        size="sm"
                        type="button"
                        disabled={settingsBusy}
                        onClick={() => void onDisableTouchId()}
                      >
                        <Trans>Disable biometrics</Trans>
                      </Button>
                    </CardFooter>
                  </>
                ) : (
                  <>
                    <SettingsCardContent>
                      <Field>
                        <FieldLabel htmlFor="touch-id-password">
                          <Trans>Confirm master password</Trans>
                        </FieldLabel>
                        <Input
                          id="touch-id-password"
                          type="password"
                          autoComplete="current-password"
                          value={touchIdPassword}
                          disabled={settingsBusy}
                          onChange={(event) => onTouchIdPasswordChange(event.target.value)}
                        />
                        <FieldDescription>
                          <Trans>
                            The master password is sent only to the local process for verification.
                          </Trans>
                        </FieldDescription>
                      </Field>
                    </SettingsCardContent>
                    <CardFooter>
                      <Button
                        size="sm"
                        type="button"
                        disabled={settingsBusy || !touchIdPassword}
                        onClick={() => void onEnableTouchId()}
                      >
                        <LockKeyhole data-icon="inline-start" aria-hidden="true" />
                        <Trans>Enable biometrics</Trans>
                      </Button>
                    </CardFooter>
                  </>
                )}
              </SettingsCard>
            </SettingsCategoryContent>
            <SettingsCategoryContent value="privacy">
              <SettingsCard aria-labelledby="privacy-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="privacy-settings-title"
                    icon={ClipboardCheck}
                    title={t`Privacy & clipboard`}
                    description={t`Reduce how long sensitive data remains on screen or in the clipboard.`}
                  />
                </CardHeader>
                <SettingsCardContent flush>
                  <FieldGroup className="gap-0">
                    <SettingsSelectRow>
                      <FieldContent>
                        <FieldLabel htmlFor="clipboard-clear-select">
                          <Trans>Clear clipboard</Trans>
                        </FieldLabel>
                        <FieldDescription id="clipboard-clear-description">
                          <Trans>
                            Clear only content written by BearWarden that you have not overwritten.
                          </Trans>
                        </FieldDescription>
                      </FieldContent>
                      <Select
                        items={localizedClipboardClearItems}
                        value={settings.clearClipboardSeconds}
                        disabled={settingsBusy}
                        onValueChange={(value) =>
                          void onUpdate({
                            clearClipboardSeconds: value as AppSettings['clearClipboardSeconds']
                          })
                        }
                      >
                        <SelectTrigger
                          id="clipboard-clear-select"
                          aria-describedby="clipboard-clear-description"
                        >
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            {localizedClipboardClearItems.map((item) => (
                              <SelectItem key={item.value} value={item.value}>
                                {item.label}
                              </SelectItem>
                            ))}
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </SettingsSelectRow>
                    <Separator />
                    <SettingsRow>
                      <FieldContent>
                        <FieldLabel htmlFor="website-icons-switch">
                          <Trans>Show website icons</Trans>
                        </FieldLabel>
                        <FieldDescription id="website-icons-description">
                          <Trans>
                            Load icons through the configured Bitwarden or Vaultwarden icon service.
                            When disabled, local initials are used instead.
                          </Trans>
                        </FieldDescription>
                      </FieldContent>
                      <Switch
                        id="website-icons-switch"
                        checked={settings.showWebsiteIcons}
                        disabled={settingsBusy}
                        aria-describedby="website-icons-description"
                        onCheckedChange={(checked) => void onUpdate({ showWebsiteIcons: checked })}
                      />
                    </SettingsRow>
                  </FieldGroup>
                </SettingsCardContent>
              </SettingsCard>
            </SettingsCategoryContent>
            <SettingsCategoryContent value="accounts">
              <AccountSwitcherCard
                accountStatus={accountStatus}
                busy={accountBusy}
                busyLabel={accountBusyLabel}
                error={accountError}
                onRequestAdd={onRequestAccountAdd}
                onRequestSwitch={onRequestAccountSwitch}
                onRequestRemove={onRequestAccountRemove}
                onAdd={onAddAccount}
                onSwitch={onSwitchAccount}
                onRename={onRenameAccount}
                onReorder={onReorderAccounts}
                onRemove={onRemoveAccount}
              />

              <SettingsCard aria-labelledby="sync-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="sync-settings-title"
                    icon={Cloud}
                    title={t`Sync & accounts`}
                    description={t`Connect to Bitwarden or Vaultwarden to sync the vault.`}
                  />
                  <CardAction>
                    <Badge
                      variant={
                        syncStatus.state === 'error'
                          ? 'destructive'
                          : syncStatus.state === 'ready'
                            ? 'default'
                            : 'secondary'
                      }
                    >
                      {localizedSyncLabels[syncStatus.state]}
                    </Badge>
                  </CardAction>
                </CardHeader>
                <SettingsCardContent>
                  <div className="flex min-w-0 items-center gap-2.5">
                    <span
                      className="text-primary grid size-[34px] shrink-0 place-items-center rounded-[10px] bg-[var(--accent-soft)] [&>svg]:size-[17px]"
                      aria-hidden="true"
                    >
                      <Cloud />
                    </span>
                    <div className="grid min-w-0 gap-0.5">
                      <strong className="text-xs">{localizedSyncLabels[syncStatus.state]}</strong>
                      <small className="text-muted-foreground truncate text-[11px]">
                        {syncStatus.email ??
                          syncStatus.serverUrl ??
                          t`No Bitwarden account connected`}
                      </small>
                    </div>
                  </div>
                </SettingsCardContent>
                <CardFooter className="gap-2">
                  {syncStatus.configured && <EquivalentDomainsDialog />}
                  {syncStatus.configured && <MasterPasswordChangeDialog onReconnect={onOpenSync} />}
                  {syncStatus.configured && (
                    <PersonalVaultPurgeDialog
                      pendingPurge={syncStatus.pendingPurge}
                      disabled={syncStatus.state === 'syncing'}
                      onVaultChanged={onVaultPurged}
                    />
                  )}
                  <Button variant="outline" size="sm" type="button" onClick={onOpenSync}>
                    {syncStatus.configured ? t`Manage sync & accounts` : t`Set up Bitwarden sync`}
                  </Button>
                </CardFooter>
              </SettingsCard>
            </SettingsCategoryContent>
            <SettingsCategoryContent value="tools">
              <SettingsCard aria-labelledby="autofill-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="autofill-settings-title"
                    icon={Keyboard}
                    title={t`Cross-browser autofill`}
                    description={
                      <Trans>
                        Press <AutofillShortcut shortcut={settings.autofillShortcut} /> in a
                        supported browser to match the current site and fill in login details.
                      </Trans>
                    }
                  />
                  <CardAction>
                    <Badge variant={autofillStatusPresentationValue.variant}>
                      {autofillStatusLabel}
                    </Badge>
                  </CardAction>
                </CardHeader>
                <SettingsCardContent flush>
                  <FieldGroup className="gap-0">
                    <SettingsRow data-disabled={autofillStatus?.available === false}>
                      <FieldContent>
                        <FieldLabel htmlFor="autofill-switch">
                          <Trans>
                            Enable <AutofillShortcut shortcut={settings.autofillShortcut} />{' '}
                            autofill
                          </Trans>
                        </FieldLabel>
                        <FieldDescription id="autofill-description">
                          <Trans>
                            Read the foreground browser’s URL and form only when you press the
                            shortcut. Multiple matches appear in a mini picker.
                          </Trans>
                        </FieldDescription>
                      </FieldContent>
                      <Switch
                        id="autofill-switch"
                        checked={settings.autofillEnabled}
                        disabled={
                          settingsBusy || autofillOperationBusy || !autofillStatus?.available
                        }
                        aria-describedby="autofill-description"
                        onCheckedChange={(checked) => void updateAutofillEnabled(checked)}
                      />
                    </SettingsRow>
                    {autofillStatus?.available && (
                      <>
                        <Separator />
                        <SettingsStackedRow>
                          <FieldLabel id="autofill-shortcut-label">
                            <Trans>Autofill shortcut</Trans>
                          </FieldLabel>
                          <FieldDescription id="autofill-shortcut-description">
                            <Trans>
                              Choose a global shortcut that is not used by your browser or another
                              password manager.
                            </Trans>
                          </FieldDescription>
                          <ToggleGroup
                            variant="outline"
                            size="sm"
                            value={[settings.autofillShortcut]}
                            aria-labelledby="autofill-shortcut-label"
                            aria-describedby="autofill-shortcut-description"
                            disabled={settingsBusy || autofillOperationBusy}
                            className="flex-wrap justify-start"
                            onValueChange={(values) => {
                              const shortcut = values.at(-1)
                              if (isAutofillShortcut(shortcut)) {
                                void updateAutofillShortcut(shortcut)
                              }
                            }}
                          >
                            {AUTOFILL_SHORTCUTS.map((shortcut) => (
                              <ToggleGroupItem key={shortcut} value={shortcut}>
                                <AutofillShortcut shortcut={shortcut} />
                                {shortcut === 'Control+\\' ? (
                                  <span className="text-muted-foreground">
                                    <Trans>Recommended</Trans>
                                  </span>
                                ) : null}
                              </ToggleGroupItem>
                            ))}
                          </ToggleGroup>
                        </SettingsStackedRow>
                      </>
                    )}
                    {settings.autofillEnabled && autofillStatus?.available && (
                      <>
                        <Separator />
                        <SettingsStackedRow>
                          <FieldLabel>
                            <Trans>Accessibility permission</Trans>
                          </FieldLabel>
                          <FieldDescription>
                            {autofillStatus.accessibilityTrusted
                              ? t`BearWarden can control the current browser and perform autofill.`
                              : t`Follow the steps below to let BearWarden identify the current website and fill the focused login form.`}
                          </FieldDescription>
                          {!autofillStatus.accessibilityTrusted && (
                            <AutofillAccessibilityGuide shortcut={settings.autofillShortcut} />
                          )}
                          <div className="flex flex-wrap gap-2">
                            {!autofillStatus.accessibilityTrusted && (
                              <Button
                                variant="default"
                                size="sm"
                                type="button"
                                disabled={autofillPermissionBusy || autofillOperationBusy}
                                onClick={() => void requestAutofillAccessibility()}
                              >
                                {autofillPermissionBusy ? <Spinner /> : null}
                                <Trans>Request accessibility permission</Trans>
                              </Button>
                            )}
                            <Button
                              variant="outline"
                              size="sm"
                              type="button"
                              disabled={autofillPermissionBusy || autofillOperationBusy}
                              onClick={() => void refreshAutofillStatus()}
                            >
                              <Trans>Check again</Trans>
                            </Button>
                          </div>
                        </SettingsStackedRow>
                        {!autofillStatus.shortcutRegistered && (
                          <>
                            <Separator />
                            <SettingsStackedRow>
                              <FieldLabel>
                                <Trans>
                                  <AutofillShortcut shortcut={settings.autofillShortcut} /> could
                                  not be registered
                                </Trans>
                              </FieldLabel>
                              <FieldDescription>
                                <Trans>
                                  Another app, such as 1Password, already uses this shortcut. Choose
                                  another shortcut above, or disable the same shortcut in that app
                                  and check again.
                                </Trans>
                              </FieldDescription>
                            </SettingsStackedRow>
                          </>
                        )}
                      </>
                    )}
                    {autofillFeedback && (
                      <>
                        <Separator />
                        <SettingsStackedRow>
                          <FieldLabel>
                            <Trans>Setting status</Trans>
                          </FieldLabel>
                          <FieldDescription role="status">{autofillFeedback}</FieldDescription>
                        </SettingsStackedRow>
                      </>
                    )}
                  </FieldGroup>
                </SettingsCardContent>
              </SettingsCard>

              <SettingsCard aria-labelledby="ssh-agent-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="ssh-agent-settings-title"
                    icon={KeyRound}
                    title={t`SSH Agent`}
                    description={t`Let terminals and Git use SSH keys from the vault through a local socket.`}
                  />
                  <CardAction>
                    <Badge variant={sshAgentStatusPresentationValue.variant}>
                      {sshAgentStatusLabel}
                    </Badge>
                  </CardAction>
                </CardHeader>
                <SettingsCardContent flush>
                  <FieldGroup className="gap-0">
                    <SettingsRow>
                      <FieldContent>
                        <FieldLabel htmlFor="ssh-agent-switch">
                          <Trans>Enable SSH Agent</Trans>
                        </FieldLabel>
                        <FieldDescription id="ssh-agent-description">
                          <Trans>
                            BearWarden provides only unarchived, undeleted SSH keys. Each signature
                            is approved according to the rule below.
                          </Trans>
                        </FieldDescription>
                      </FieldContent>
                      <Switch
                        id="ssh-agent-switch"
                        checked={settings.sshAgentEnabled}
                        disabled={settingsBusy}
                        aria-describedby="ssh-agent-description"
                        onCheckedChange={(checked) => void onUpdate({ sshAgentEnabled: checked })}
                      />
                    </SettingsRow>
                    <Separator />
                    <SettingsSelectRow data-disabled={!settings.sshAgentEnabled}>
                      <FieldContent>
                        <FieldLabel htmlFor="ssh-agent-prompt-select">
                          <Trans>Signature approval</Trans>
                        </FieldLabel>
                        <FieldDescription id="ssh-agent-prompt-description">
                          <Trans>
                            Remember until locked distinguishes local requests. Forwarded requests
                            must also match a verified remote host fingerprint. Approvals are
                            cleared when the vault locks.
                          </Trans>
                        </FieldDescription>
                      </FieldContent>
                      <Select
                        items={localizedSshAgentPromptItems}
                        value={settings.sshAgentPromptBehavior}
                        disabled={settingsBusy || !settings.sshAgentEnabled}
                        onValueChange={(value) =>
                          void onUpdate({
                            sshAgentPromptBehavior: value as SshAgentPromptBehavior
                          })
                        }
                      >
                        <SelectTrigger
                          id="ssh-agent-prompt-select"
                          aria-describedby="ssh-agent-prompt-description"
                        >
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            {localizedSshAgentPromptItems.map((item) => (
                              <SelectItem key={item.value} value={item.value}>
                                {item.label}
                              </SelectItem>
                            ))}
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </SettingsSelectRow>
                    <Separator />
                    <SettingsStackedRow>
                      <FieldLabel htmlFor="ssh-agent-command">
                        <Trans>Terminal setup</Trans>
                      </FieldLabel>
                      {usesWindowsNamedPipe ? (
                        <FieldDescription>
                          <Trans>
                            BearWarden uses the fixed <code>\\.\pipe\openssh-ssh-agent</code> named
                            pipe. Disable the system OpenSSH Authentication Agent first so the two
                            agents do not compete for the same pipe.
                          </Trans>
                        </FieldDescription>
                      ) : sshAgentCommand ? (
                        <>
                          <FieldDescription>
                            <Trans>
                              Set <code>SSH_AUTH_SOCK</code> in the terminal environment so SSH and
                              Git use BearWarden’s local socket.
                            </Trans>
                          </FieldDescription>
                          <InputGroup>
                            <InputGroupInput
                              id="ssh-agent-command"
                              value={sshAgentCommand}
                              readOnly
                              aria-label={t`SSH Agent terminal setup command`}
                            />
                            <InputGroupAddon align="inline-end">
                              <InputGroupButton
                                aria-label={
                                  copiedKey === 'ssh-agent-command'
                                    ? t`SSH Agent setup command copied`
                                    : t`Copy SSH Agent setup command`
                                }
                                onClick={() => void copySshAgentCommand()}
                              >
                                <CopyFeedbackIcon
                                  copied={copiedKey === 'ssh-agent-command'}
                                  placement="inline-start"
                                />
                                {copiedKey === 'ssh-agent-command' ? t`Copied` : t`Copy`}
                              </InputGroupButton>
                            </InputGroupAddon>
                          </InputGroup>
                        </>
                      ) : (
                        <FieldDescription>
                          <Trans>
                            The Agent endpoint contains control characters that cannot be safely
                            placed in a shell command, so no copyable command is available. Fix
                            <code>BEARWARDEN_SSH_AUTH_SOCK</code>, then enable the Agent again.
                          </Trans>
                        </FieldDescription>
                      )}
                    </SettingsStackedRow>
                    {sshAgentStatus.state === 'error' && (
                      <>
                        <Separator />
                        <SettingsStackedRow>
                          <FieldLabel>
                            <Trans>Agent could not start</Trans>
                          </FieldLabel>
                          <FieldDescription>
                            {sshAgentStatus.lastError === 'SOCKET_IN_USE' ||
                            sshAgentStatus.lastError === 'PIPE_IN_USE'
                              ? t`Another SSH Agent is using the same endpoint. Stop that Agent, then enable BearWarden SSH Agent again.`
                              : t`BearWarden could not create the SSH Agent endpoint safely. Check the home directory permissions and socket path, then try again.`}
                          </FieldDescription>
                        </SettingsStackedRow>
                      </>
                    )}
                  </FieldGroup>
                </SettingsCardContent>
                <CardFooter>
                  <p className="text-muted-foreground m-0 text-xs leading-[1.6]">
                    <Plural
                      value={sshAgentStatus.identityCount}
                      one="# SSH key is available. Private keys and signing data are never sent to the renderer process."
                      other="# SSH keys are available. Private keys and signing data are never sent to the renderer process."
                    />
                  </p>
                </CardFooter>
              </SettingsCard>

              <SettingsCard aria-labelledby="portability-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="portability-settings-title"
                    icon={DatabaseBackup}
                    title={t`Data portability`}
                    description={t`Import Bitwarden JSON or create a password-protected portable backup.`}
                  />
                </CardHeader>
                <SettingsCardContent>
                  <p className="text-muted-foreground m-0 text-xs leading-[1.6]">
                    <Trans>
                      File contents and paths are handled only by the local main process and are
                      never sent back to the renderer process.
                    </Trans>
                  </p>
                </SettingsCardContent>
                <CardFooter className="gap-2">
                  <Button variant="outline" size="sm" type="button" onClick={onImportVault}>
                    <Upload data-icon="inline-start" aria-hidden="true" />
                    <Trans>Import JSON</Trans>
                  </Button>
                  <Button size="sm" type="button" onClick={onExportVault}>
                    <Download data-icon="inline-start" aria-hidden="true" />
                    <Trans>Export encrypted backup</Trans>
                  </Button>
                </CardFooter>
              </SettingsCard>
            </SettingsCategoryContent>
            <SettingsCategoryContent value="about">
              <AboutPage onOpenRepository={() => window.bearwarden.updater.openRepositoryPage()} />
            </SettingsCategoryContent>
          </AuxiliaryPageContent>
        )}
      </AuxiliaryPageLayout>
    </Tabs>
  )
}

export default SettingsPage
