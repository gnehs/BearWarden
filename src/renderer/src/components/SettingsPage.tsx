import { useEffect, useRef, useState } from 'react'
import {
  ClipboardCheck,
  Cloud,
  DatabaseBackup,
  Download,
  Fingerprint,
  Info,
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
  AppSettings,
  AppSettingsUpdate,
  PinUnlockStatus,
  SshAgentPromptBehavior,
  SshAgentStatus,
  SyncStatus,
  VaultTimeoutPolicy
} from '../../../shared/vault-contract'
import { MAX_VAULT_TIMEOUT_MINUTES } from '../../../shared/vault-contract'
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
import { CopyFeedbackIcon } from './CopyFeedbackIcon'
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
  '啟用後，Windows 遠端桌面、螢幕分享與錄影可能看不到 BearWarden 視窗。若只剩工作列圖示，請在本機工作階段關閉此選項。'

// eslint-disable-next-line react-refresh/only-export-components
export const settingsCategories = [
  { id: 'general', label: '一般', description: '外觀與預設行為', icon: Palette },
  { id: 'security', label: '安全與解鎖', description: '鎖定與解鎖方式', icon: ShieldCheck },
  { id: 'privacy', label: '隱私', description: '剪貼簿與網站圖示', icon: ClipboardCheck },
  { id: 'accounts', label: '帳號與同步', description: '本機帳號與雲端連線', icon: Cloud },
  { id: 'tools', label: '工具與資料', description: 'SSH Agent 與備份', icon: KeyRound },
  { id: 'about', label: '關於', description: '版本與更新資訊', icon: Info }
] as const

type SettingsCategoryId = (typeof settingsCategories)[number]['id']

// eslint-disable-next-line react-refresh/only-export-components
export const vaultTimeoutItems = [
  { label: 'App 重新啟動時鎖定', value: 'onRestart' },
  { label: '系統閒置 5 分鐘', value: 'systemIdle' },
  ...vaultTimeoutPresetMinutes.map((minutes) => ({
    label: `${minutes} 分鐘`,
    value: String(minutes)
  })),
  { label: '自訂', value: 'custom' }
] as const

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
    return '請輸入整數的小時與分鐘。'
  }
  const parsedHours = Number(hours)
  const parsedMinutes = Number(minutes)
  if (parsedMinutes > 59) return '分鐘必須介於 0 到 59。'
  if (
    parsedHours > maxVaultTimeoutHours ||
    parsedHours * 60 + parsedMinutes > maxVaultTimeoutMinutes
  ) {
    return '自訂閒置時間最長為 8,760 小時。'
  }
  if (!vaultTimeoutPolicyFromCustomFields(hours, minutes)) {
    return '自訂閒置時間至少為 0 小時 1 分鐘。'
  }
  return null
}

// eslint-disable-next-line react-refresh/only-export-components
export function applyVaultTimeoutCustomFields(
  hours: string,
  minutes: string,
  onUpdate: (update: AppSettingsUpdate) => Promise<void>
): string | null {
  const validationMessage = vaultTimeoutCustomValidationMessage(hours, minutes)
  if (validationMessage) return validationMessage
  const policy = vaultTimeoutPolicyFromCustomFields(hours, minutes)
  if (!policy) return '請確認自訂閒置時間。'
  void onUpdate({ vaultTimeoutPolicy: policy })
  return null
}

interface VaultTimeoutCustomFieldsProps {
  policy: VaultTimeoutPolicy
  disabled: boolean
  onUpdate: (update: AppSettingsUpdate) => Promise<void>
}

function VaultTimeoutCustomFields({
  policy,
  disabled,
  onUpdate
}: VaultTimeoutCustomFieldsProps): React.JSX.Element {
  const initialFields = vaultTimeoutCustomFields(policy)
  const [hours, setHours] = useState(initialFields.hours)
  const [minutes, setMinutes] = useState(initialFields.minutes)
  const validationMessage = vaultTimeoutCustomValidationMessage(hours, minutes)

  const apply = (): void => {
    applyVaultTimeoutCustomFields(hours, minutes, onUpdate)
  }

  return (
    <SettingsSelectRow>
      <FieldContent>
        <FieldLabel>自訂閒置時間</FieldLabel>
        <FieldDescription id="vault-timeout-custom-description">
          最短 0 小時 1 分鐘，最長 8,760 小時；分鐘必須介於 0 到 59。
        </FieldDescription>
      </FieldContent>
      <div className="flex items-center gap-2" aria-describedby="vault-timeout-custom-description">
        <Input
          aria-label="自訂閒置時間小時"
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
        <span aria-hidden="true">小時</span>
        <Input
          aria-label="自訂閒置時間分鐘"
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
        <span aria-hidden="true">分鐘</span>
        <Button
          type="button"
          size="sm"
          disabled={disabled || Boolean(validationMessage)}
          onClick={apply}
        >
          套用
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

const clipboardClearItems = [
  { label: '不自動清除', value: 0 },
  { label: '15 秒後', value: 15 },
  { label: '30 秒後', value: 30 },
  { label: '1 分鐘後', value: 60 },
  { label: '2 分鐘後', value: 120 }
] as const

const defaultSortItems = [
  { label: '最近使用', value: 'recent' },
  { label: '使用頻率', value: 'frequency' },
  { label: '依名稱', value: 'name' }
] as const

const themeItems = [
  { label: '跟隨系統', value: 'system' },
  { label: '淺色', value: 'light' },
  { label: '深色', value: 'dark' }
] as const

const sshAgentPromptItems: ReadonlyArray<{ label: string; value: SshAgentPromptBehavior }> = [
  { label: '每次簽署都詢問', value: 'always' },
  { label: '從不詢問（自動核准）', value: 'never' },
  { label: '鎖定前記住核准結果', value: 'rememberUntilLock' }
]

const initialSshAgentStatus: SshAgentStatus = {
  enabled: false,
  running: false,
  state: 'stopped',
  identityCount: 0
}

const syncLabels: Record<SyncStatus['state'], string> = {
  unconfigured: '尚未設定',
  locked: '需要解鎖',
  ready: '已連線',
  syncing: '同步中…',
  error: '需要處理'
}

interface SettingsPageProps {
  settings: AppSettings | null
  settingsBusy: boolean
  syncStatus: SyncStatus
  touchIdPassword: string
  onUpdate: (update: AppSettingsUpdate) => Promise<void>
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
  onReorderAccounts,
  onRemoveAccount
}: SettingsPageProps): React.JSX.Element {
  const [sshAgentStatus, setSshAgentStatus] = useState<SshAgentStatus>(initialSshAgentStatus)
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
    void window.bearwarden.vault.pinStatus().then(
      (status) => {
        if (active) setPinStatus(status)
      },
      () => {
        if (active) setPinFeedback('無法讀取 PIN 解鎖狀態。')
      }
    )
    return () => {
      active = false
    }
  }, [])

  async function enablePinUnlock(): Promise<void> {
    setPinFeedback('')
    if (pin.normalize('NFC').length < 4) {
      setPinFeedback('PIN 至少需要 4 個字元。')
      return
    }
    if (pin !== pinConfirmation) {
      setPinFeedback('兩次輸入的 PIN 不一致。')
      return
    }
    if (!pinMasterPassword) {
      setPinFeedback('請輸入主密碼以確認。')
      return
    }
    const request = { pin, masterPassword: pinMasterPassword }
    setPin('')
    setPinConfirmation('')
    setPinMasterPassword('')
    setPinBusy(true)
    try {
      setPinStatus(await window.bearwarden.vault.enablePin(request))
      setPinFeedback('PIN 解鎖已啟用；只在這次執行期間有效。')
    } catch (error) {
      setPinFeedback(
        error instanceof Error && error.message.includes('INVALID_MASTER_PASSWORD')
          ? '主密碼驗證失敗。'
          : '無法啟用 PIN 解鎖。'
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
      setPinFeedback('PIN 解鎖已停用。')
    } catch {
      setPinFeedback('無法停用 PIN 解鎖。')
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

  return (
    <AuxiliaryPageLayout
      eyebrow="應用程式"
      title="設定"
      titleId="settings-title"
      subtitle="調整這台裝置上的安全性、外觀與同步方式。"
      headerIcon={<Settings2 />}
      scrollRef={settingsScrollRef}
      scrollClassName="scroll-fade scroll-fade-4 forced-colors:scroll-fade-none"
      headerActions={
        settingsBusy ? (
          <span
            className="text-muted-foreground inline-flex shrink-0 items-center gap-1.5 text-[11px]"
            role="status"
          >
            <Spinner />
            正在儲存
          </span>
        ) : undefined
      }
    >
      {!settings ? (
        <div
          className="text-muted-foreground flex min-h-0 flex-1 flex-row items-center justify-center gap-2.5 p-7 text-center text-[11px]"
          role="status"
        >
          <Spinner /> 正在讀取設定…
        </div>
      ) : (
        <AuxiliaryPageContent className="max-w-[760px] !grid-cols-[minmax(0,1fr)] gap-0">
          <Tabs
            value={activeSettingsCategory}
            className="min-w-0 gap-4"
            onValueChange={(value) => {
              if (typeof value !== 'string') return
              setActiveSettingsCategory(value as SettingsCategoryId)
              settingsScrollRef.current?.scrollTo({ top: 0 })
            }}
          >
            <TabsList
              variant="line"
              sliding
              aria-label="設定分類"
              className="scroll-fade-x scroll-fade-4 forced-colors:scroll-fade-none w-full justify-start gap-1 overflow-x-auto px-1 group-data-horizontal/tabs:h-10"
            >
              {settingsCategories.map(({ id, label, description, icon: Icon }) => (
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

            <SettingsCategoryContent value="general">
              <SettingsCard aria-labelledby="general-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="general-settings-title"
                    icon={Palette}
                    title="一般"
                    description="調整密碼庫的外觀與預設排列方式。"
                  />
                </CardHeader>
                <SettingsCardContent flush>
                  <FieldGroup className="gap-0">
                    <SettingsStackedRow>
                      <FieldLabel htmlFor="theme-select">主題</FieldLabel>
                      <Select
                        items={themeItems}
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
                            {themeItems.map((item) => (
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
                      <FieldLabel htmlFor="default-sort-select">預設排序</FieldLabel>
                      <Select
                        items={defaultSortItems}
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
                            {defaultSortItems.map((item) => (
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
                          登入時啟動 BearWarden
                        </FieldLabel>
                        <FieldDescription id="start-at-login-description">
                          {settings.startAtLoginAvailable
                            ? settings.startAtLoginNeedsApproval
                              ? '已登錄，但仍需在 macOS「系統設定」的「登入項目」中允許。'
                              : '登入這台電腦後，自動啟動 BearWarden。'
                            : '僅 macOS 與 Windows 的安裝版支援自動啟動。'}
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
                    title="安全性"
                    description="決定密碼庫何時鎖定，以及視窗內容如何受到保護。"
                  />
                  <CardAction>
                    <Badge variant="secondary">此裝置</Badge>
                  </CardAction>
                </CardHeader>
                <SettingsCardContent flush>
                  <FieldGroup className="gap-0">
                    <SettingsRow>
                      <FieldContent>
                        <FieldLabel htmlFor="content-protection-switch">禁止螢幕截圖</FieldLabel>
                        <FieldDescription id="content-protection-description">
                          {contentProtectionDescription}
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
                        <FieldLabel htmlFor="screen-lock-switch">螢幕鎖定時自動鎖定</FieldLabel>
                        <FieldDescription id="screen-lock-description">
                          離開電腦並鎖定螢幕時，立即鎖定密碼庫。
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
                        <FieldLabel htmlFor="suspend-lock-switch">電腦休眠時自動鎖定</FieldLabel>
                        <FieldDescription id="suspend-lock-description">
                          電腦進入休眠狀態時，立即鎖定密碼庫。
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
                        <FieldLabel htmlFor="vault-timeout-select">閒置自動鎖定</FieldLabel>
                        <FieldDescription id="vault-timeout-description">
                          一段時間沒有操作後自動鎖定；關閉 App 時一律鎖定密碼庫。
                        </FieldDescription>
                      </FieldContent>
                      <Select
                        items={vaultTimeoutItems}
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
                            {vaultTimeoutItems.map((item) => (
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
                    title="PIN 解鎖"
                    description="使用短期 PIN 解鎖本機密碼庫。"
                  />
                  <CardAction>
                    <Badge variant={pinStatus.available ? 'default' : 'secondary'}>
                      {pinStatus.available ? '已啟用' : '未啟用'}
                    </Badge>
                  </CardAction>
                </CardHeader>
                {pinStatus.available ? (
                  <>
                    <SettingsCardContent className="grid gap-2">
                      <p className="text-muted-foreground m-0 text-xs leading-[1.6]">
                        PIN
                        加密憑證只保留在記憶體中；重新啟動、登出、斷開或切換帳號後，必須使用主密碼。
                      </p>
                      <p className="text-muted-foreground m-0 text-xs leading-[1.5]">
                        PIN 連續錯誤 5 次會自動停用。目前可嘗試 {pinStatus.remainingAttempts} 次。
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
                        停用 PIN 解鎖
                      </Button>
                    </CardFooter>
                  </>
                ) : (
                  <>
                    <SettingsCardContent className="grid gap-4">
                      <p className="text-muted-foreground m-0 text-xs leading-[1.6]">
                        PIN 與加密憑證不會寫入磁碟。普通鎖定後可用
                        PIN，但程式重新啟動時一定需要主密碼。
                      </p>
                      <FieldGroup>
                        <Field>
                          <FieldLabel htmlFor="pin-unlock-pin">PIN</FieldLabel>
                          <Input
                            id="pin-unlock-pin"
                            type="password"
                            autoComplete="new-password"
                            value={pin}
                            disabled={pinBusy || settingsBusy}
                            onChange={(event) => setPin(event.target.value)}
                          />
                          <FieldDescription>
                            至少 4 個字元，建議不要使用容易猜測的數字。
                          </FieldDescription>
                        </Field>
                        <Field>
                          <FieldLabel htmlFor="pin-unlock-confirmation">再次輸入 PIN</FieldLabel>
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
                          <FieldLabel htmlFor="pin-unlock-master-password">確認主密碼</FieldLabel>
                          <Input
                            id="pin-unlock-master-password"
                            type="password"
                            autoComplete="current-password"
                            value={pinMasterPassword}
                            disabled={pinBusy || settingsBusy}
                            onChange={(event) => setPinMasterPassword(event.target.value)}
                          />
                          <FieldDescription>
                            主密碼每次啟用時都會在 main process 重新驗證。
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
                        啟用 PIN 解鎖
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
                    title="生物辨識"
                    description="使用裝置的生物辨識快速解鎖，目前僅支援 macOS Touch ID。"
                  />
                  <CardAction>
                    <Badge variant={settings.touchIdEnabled ? 'default' : 'secondary'}>
                      {!settings.touchIdAvailable
                        ? '不可用'
                        : settings.touchIdEnabled
                          ? '已啟用'
                          : '未啟用'}
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
                        <EmptyTitle>這台裝置無法使用生物辨識</EmptyTitle>
                        <EmptyDescription>
                          目前僅支援 macOS Touch ID；你仍可使用主密碼解鎖密碼庫。
                        </EmptyDescription>
                      </EmptyHeader>
                    </Empty>
                  </SettingsCardContent>
                ) : settings.touchIdEnabled ? (
                  <>
                    <SettingsCardContent>
                      <p className="text-muted-foreground m-0 text-xs leading-[1.6]">
                        下次鎖定後即可直接使用生物辨識解鎖。
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
                        停用生物辨識
                      </Button>
                    </CardFooter>
                  </>
                ) : (
                  <>
                    <SettingsCardContent>
                      <Field>
                        <FieldLabel htmlFor="touch-id-password">確認主密碼</FieldLabel>
                        <Input
                          id="touch-id-password"
                          type="password"
                          autoComplete="current-password"
                          value={touchIdPassword}
                          disabled={settingsBusy}
                          onChange={(event) => onTouchIdPasswordChange(event.target.value)}
                        />
                        <FieldDescription>主密碼只會送到本機程序進行驗證。</FieldDescription>
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
                        啟用生物辨識
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
                    title="隱私與剪貼簿"
                    description="降低敏感資料留在螢幕或剪貼簿中的時間。"
                  />
                </CardHeader>
                <SettingsCardContent flush>
                  <FieldGroup className="gap-0">
                    <SettingsSelectRow>
                      <FieldContent>
                        <FieldLabel htmlFor="clipboard-clear-select">清除剪貼簿</FieldLabel>
                        <FieldDescription id="clipboard-clear-description">
                          只清除由 BearWarden 寫入且尚未被你覆蓋的內容。
                        </FieldDescription>
                      </FieldContent>
                      <Select
                        items={clipboardClearItems}
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
                            {clipboardClearItems.map((item) => (
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
                        <FieldLabel htmlFor="website-icons-switch">顯示網站圖示</FieldLabel>
                        <FieldDescription id="website-icons-description">
                          透過已設定的 Bitwarden／Vaultwarden 圖示服務載入；停用後使用本機縮寫。
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
                onReorder={onReorderAccounts}
                onRemove={onRemoveAccount}
              />

              <SettingsCard aria-labelledby="sync-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="sync-settings-title"
                    icon={Cloud}
                    title="同步與帳號"
                    description="連接 Bitwarden 或 Vaultwarden 以同步密碼庫。"
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
                      {syncLabels[syncStatus.state]}
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
                      <strong className="text-xs">{syncLabels[syncStatus.state]}</strong>
                      <small className="text-muted-foreground truncate text-[11px]">
                        {syncStatus.email ?? syncStatus.serverUrl ?? '尚未連接 Bitwarden 帳號'}
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
                    {syncStatus.configured ? '管理同步與帳號' : '設定 Bitwarden 同步'}
                  </Button>
                </CardFooter>
              </SettingsCard>
            </SettingsCategoryContent>
            <SettingsCategoryContent value="tools">
              <SettingsCard aria-labelledby="ssh-agent-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="ssh-agent-settings-title"
                    icon={KeyRound}
                    title="SSH Agent"
                    description="讓終端機與 Git 經由本機 socket 使用密碼庫中的 SSH 金鑰。"
                  />
                  <CardAction>
                    <Badge variant={sshAgentStatusPresentationValue.variant}>
                      {sshAgentStatusPresentationValue.label}
                    </Badge>
                  </CardAction>
                </CardHeader>
                <SettingsCardContent flush>
                  <FieldGroup className="gap-0">
                    <SettingsRow>
                      <FieldContent>
                        <FieldLabel htmlFor="ssh-agent-switch">啟用 SSH Agent</FieldLabel>
                        <FieldDescription id="ssh-agent-description">
                          BearWarden 只會提供未封存、未刪除的 SSH 金鑰；每次簽署依下方規則核准。
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
                        <FieldLabel htmlFor="ssh-agent-prompt-select">簽署核准方式</FieldLabel>
                        <FieldDescription id="ssh-agent-prompt-description">
                          「鎖定前記住」會區分本機請求；透過 forwarding
                          的請求還必須對應已驗證的遠端主機指紋。鎖定後會清除。
                        </FieldDescription>
                      </FieldContent>
                      <Select
                        items={sshAgentPromptItems}
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
                            {sshAgentPromptItems.map((item) => (
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
                      <FieldLabel htmlFor="ssh-agent-command">終端機設定</FieldLabel>
                      {usesWindowsNamedPipe ? (
                        <FieldDescription>
                          BearWarden 使用固定的 <code>\\.\pipe\openssh-ssh-agent</code> named
                          pipe。請先停用系統的 OpenSSH Authentication Agent，避免兩個 agent
                          爭用同一個 pipe。
                        </FieldDescription>
                      ) : sshAgentCommand ? (
                        <>
                          <FieldDescription>
                            在終端機環境中設定 <code>SSH_AUTH_SOCK</code>，讓 SSH 與 Git 使用
                            BearWarden 的本機 socket。
                          </FieldDescription>
                          <InputGroup>
                            <InputGroupInput
                              id="ssh-agent-command"
                              value={sshAgentCommand}
                              readOnly
                              aria-label="SSH Agent 終端機設定指令"
                            />
                            <InputGroupAddon align="inline-end">
                              <InputGroupButton
                                aria-label={
                                  copiedKey === 'ssh-agent-command'
                                    ? 'SSH Agent 設定指令已複製'
                                    : '複製 SSH Agent 設定指令'
                                }
                                onClick={() => void copySshAgentCommand()}
                              >
                                <CopyFeedbackIcon
                                  copied={copiedKey === 'ssh-agent-command'}
                                  placement="inline-start"
                                />
                                {copiedKey === 'ssh-agent-command' ? '已複製' : '複製'}
                              </InputGroupButton>
                            </InputGroupAddon>
                          </InputGroup>
                        </>
                      ) : (
                        <FieldDescription>
                          Agent endpoint 含有無法安全放入 shell
                          指令的控制字元，因此未提供複製指令。請在修正
                          <code>BEARWARDEN_SSH_AUTH_SOCK</code> 後重新啟用 Agent。
                        </FieldDescription>
                      )}
                    </SettingsStackedRow>
                    {sshAgentStatus.state === 'error' && (
                      <>
                        <Separator />
                        <SettingsStackedRow>
                          <FieldLabel>Agent 無法啟動</FieldLabel>
                          <FieldDescription>
                            {sshAgentStatus.lastError === 'SOCKET_IN_USE' ||
                            sshAgentStatus.lastError === 'PIPE_IN_USE'
                              ? '既有 SSH Agent 正在使用相同 endpoint。請停止該 Agent 後重新啟用 BearWarden SSH Agent。'
                              : 'BearWarden 無法安全地建立 SSH Agent endpoint。請確認家目錄權限與 socket 路徑後再試。'}
                          </FieldDescription>
                        </SettingsStackedRow>
                      </>
                    )}
                  </FieldGroup>
                </SettingsCardContent>
                <CardFooter>
                  <p className="text-muted-foreground m-0 text-xs leading-[1.6]">
                    {sshAgentStatus.identityCount} 把可用 SSH
                    金鑰。私鑰與實際簽署資料不會傳到畫面程序。
                  </p>
                </CardFooter>
              </SettingsCard>

              <SettingsCard aria-labelledby="portability-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="portability-settings-title"
                    icon={DatabaseBackup}
                    title="資料可攜性"
                    description="匯入 Bitwarden JSON，或建立密碼保護的可攜備份。"
                  />
                </CardHeader>
                <SettingsCardContent>
                  <p className="text-muted-foreground m-0 text-xs leading-[1.6]">
                    檔案內容與路徑只會由本機主程序處理，不會傳回畫面程序。
                  </p>
                </SettingsCardContent>
                <CardFooter className="gap-2">
                  <Button variant="outline" size="sm" type="button" onClick={onImportVault}>
                    <Upload data-icon="inline-start" aria-hidden="true" />
                    匯入 JSON
                  </Button>
                  <Button size="sm" type="button" onClick={onExportVault}>
                    <Download data-icon="inline-start" aria-hidden="true" />
                    匯出加密備份
                  </Button>
                </CardFooter>
              </SettingsCard>
            </SettingsCategoryContent>
            <SettingsCategoryContent value="about">
              <AboutPage onOpenRepository={() => window.bearwarden.updater.openRepositoryPage()} />
            </SettingsCategoryContent>
          </Tabs>
        </AuxiliaryPageContent>
      )}
    </AuxiliaryPageLayout>
  )
}

export default SettingsPage
