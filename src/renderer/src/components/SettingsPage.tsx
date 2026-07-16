import { useEffect, useState } from 'react'
import type { LucideIcon } from 'lucide-react'
import {
  ArrowLeft,
  ClipboardCheck,
  Cloud,
  Copy,
  DatabaseBackup,
  Download,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  Palette,
  Settings2,
  ShieldCheck,
  Upload
} from 'lucide-react'
import type {
  AppSettings,
  AppSettingsUpdate,
  SshAgentPromptBehavior,
  SshAgentStatus,
  SyncStatus
} from '../../../shared/vault-contract'
import { Badge } from '@renderer/components/ui/badge'
import { Button } from '@renderer/components/ui/button'
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle
} from '@renderer/components/ui/card'
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
import {
  isWindowsSshAgentEndpoint,
  sshAgentSocketExportCommand,
  sshAgentStatusPresentation
} from '@renderer/lib/ssh-agent-ui'
import EquivalentDomainsDialog from './EquivalentDomainsDialog'

const autoLockItems = [
  { label: '永不自動鎖定', value: 0 },
  { label: '1 分鐘', value: 1 },
  { label: '5 分鐘', value: 5 },
  { label: '15 分鐘', value: 15 },
  { label: '30 分鐘', value: 30 },
  { label: '60 分鐘', value: 60 }
] as const

const clipboardClearItems = [
  { label: '不自動清除', value: 0 },
  { label: '15 秒後', value: 15 },
  { label: '30 秒後', value: 30 },
  { label: '1 分鐘後', value: 60 },
  { label: '2 分鐘後', value: 120 }
] as const

const defaultSortItems = [
  { label: '最近使用', value: 'recent' },
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
  onBack: () => void
  onUpdate: (update: AppSettingsUpdate) => Promise<void>
  onTouchIdPasswordChange: (value: string) => void
  onEnableTouchId: () => Promise<void>
  onDisableTouchId: () => Promise<void>
  onOpenSync: () => void
  onExportVault: () => void
  onImportVault: () => void
}

interface SettingsCardHeadingProps {
  id: string
  icon: LucideIcon
  title: string
  description: string
}

function SettingsCardHeading({
  id,
  icon: Icon,
  title,
  description
}: SettingsCardHeadingProps): React.JSX.Element {
  return (
    <div className="settings-card-heading">
      <span className="settings-section-icon" aria-hidden="true">
        <Icon />
      </span>
      <div>
        <CardTitle id={id} role="heading" aria-level={2}>
          {title}
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </div>
    </div>
  )
}

function SettingsPage({
  settings,
  settingsBusy,
  syncStatus,
  touchIdPassword,
  onBack,
  onUpdate,
  onTouchIdPasswordChange,
  onEnableTouchId,
  onDisableTouchId,
  onOpenSync,
  onExportVault,
  onImportVault
}: SettingsPageProps): React.JSX.Element {
  const [sshAgentStatus, setSshAgentStatus] = useState<SshAgentStatus>(initialSshAgentStatus)
  const [copySucceeded, setCopySucceeded] = useState(false)

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
    try {
      if (!sshAgentCommand) return
      await navigator.clipboard.writeText(sshAgentCommand)
      setCopySucceeded(true)
      window.setTimeout(() => setCopySucceeded(false), 2_000)
    } catch {
      setCopySucceeded(false)
    }
  }

  return (
    <div className="settings-page" aria-labelledby="settings-title">
      <header className="settings-header">
        <div className="settings-header-inner">
          <Button variant="outline" size="sm" type="button" autoFocus onClick={onBack}>
            <ArrowLeft data-icon="inline-start" aria-hidden="true" />
            返回保管庫
          </Button>
          <div className="settings-header-content">
            <div className="settings-title-group">
              <span className="settings-title-icon" aria-hidden="true">
                <Settings2 />
              </span>
              <div>
                <p className="eyebrow">應用程式</p>
                <h1 id="settings-title">設定</h1>
                <p className="settings-subtitle">調整這台裝置上的安全性、外觀與同步方式。</p>
              </div>
            </div>
            {settingsBusy && (
              <span className="settings-saving" role="status">
                <Spinner />
                正在儲存
              </span>
            )}
          </div>
        </div>
      </header>

      <div className="settings-scroll">
        {!settings ? (
          <div className="detail-loading" role="status">
            <Spinner /> 正在讀取設定…
          </div>
        ) : (
          <div className="settings-layout">
            <nav className="settings-nav" aria-label="設定章節">
              <p>設定章節</p>
              <a href="#security-settings-title">安全性</a>
              <a href="#ssh-agent-settings-title">SSH Agent</a>
              <a href="#privacy-settings-title">隱私與剪貼簿</a>
              <a href="#general-settings-title">一般</a>
              <a href="#touch-id-settings-title">Touch ID</a>
              <a href="#sync-settings-title">同步與帳號</a>
              <a href="#portability-settings-title">資料可攜性</a>
            </nav>
            <div className="settings-main">
              <Card className="settings-card" aria-labelledby="security-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="security-settings-title"
                    icon={ShieldCheck}
                    title="安全性"
                    description="決定保管庫何時鎖定，以及視窗內容如何受到保護。"
                  />
                  <CardAction>
                    <Badge variant="secondary">此裝置</Badge>
                  </CardAction>
                </CardHeader>
                <CardContent className="settings-card-content">
                  <FieldGroup className="gap-0">
                    <Field className="settings-row" orientation="horizontal">
                      <FieldContent>
                        <FieldLabel htmlFor="content-protection-switch">禁止螢幕截圖</FieldLabel>
                        <FieldDescription id="content-protection-description">
                          要求系統避免擷取 BearWarden 視窗內容。
                        </FieldDescription>
                      </FieldContent>
                      <Switch
                        id="content-protection-switch"
                        checked={settings.contentProtection}
                        disabled={settingsBusy}
                        aria-describedby="content-protection-description"
                        onCheckedChange={(checked) => void onUpdate({ contentProtection: checked })}
                      />
                    </Field>
                    <Separator />
                    <Field className="settings-row" orientation="horizontal">
                      <FieldContent>
                        <FieldLabel htmlFor="screen-lock-switch">螢幕鎖定時自動鎖定</FieldLabel>
                        <FieldDescription id="screen-lock-description">
                          離開電腦並鎖定螢幕時，立即鎖定保管庫。
                        </FieldDescription>
                      </FieldContent>
                      <Switch
                        id="screen-lock-switch"
                        checked={settings.lockOnScreenLock}
                        disabled={settingsBusy}
                        aria-describedby="screen-lock-description"
                        onCheckedChange={(checked) => void onUpdate({ lockOnScreenLock: checked })}
                      />
                    </Field>
                    <Separator />
                    <Field className="settings-row" orientation="horizontal">
                      <FieldContent>
                        <FieldLabel htmlFor="suspend-lock-switch">電腦休眠時自動鎖定</FieldLabel>
                        <FieldDescription id="suspend-lock-description">
                          電腦進入休眠狀態時，立即鎖定保管庫。
                        </FieldDescription>
                      </FieldContent>
                      <Switch
                        id="suspend-lock-switch"
                        checked={settings.lockOnSuspend}
                        disabled={settingsBusy}
                        aria-describedby="suspend-lock-description"
                        onCheckedChange={(checked) => void onUpdate({ lockOnSuspend: checked })}
                      />
                    </Field>
                    <Separator />
                    <Field className="settings-row settings-row-select" orientation="horizontal">
                      <FieldContent>
                        <FieldLabel htmlFor="auto-lock-select">閒置自動鎖定</FieldLabel>
                        <FieldDescription id="auto-lock-description">
                          一段時間沒有操作後，自動鎖定保管庫。
                        </FieldDescription>
                      </FieldContent>
                      <Select
                        items={autoLockItems}
                        value={settings.autoLockMinutes}
                        disabled={settingsBusy}
                        onValueChange={(value) =>
                          void onUpdate({
                            autoLockMinutes: value as AppSettings['autoLockMinutes']
                          })
                        }
                      >
                        <SelectTrigger
                          id="auto-lock-select"
                          aria-describedby="auto-lock-description"
                        >
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            {autoLockItems.map((item) => (
                              <SelectItem key={item.value} value={item.value}>
                                {item.label}
                              </SelectItem>
                            ))}
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </Field>
                  </FieldGroup>
                </CardContent>
              </Card>

              <Card className="settings-card" aria-labelledby="ssh-agent-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="ssh-agent-settings-title"
                    icon={KeyRound}
                    title="SSH Agent"
                    description="讓終端機與 Git 經由本機 socket 使用保管庫中的 SSH 金鑰。"
                  />
                  <CardAction>
                    <Badge variant={sshAgentStatusPresentationValue.variant}>
                      {sshAgentStatusPresentationValue.label}
                    </Badge>
                  </CardAction>
                </CardHeader>
                <CardContent className="settings-card-content">
                  <FieldGroup className="gap-0">
                    <Field className="settings-row" orientation="horizontal">
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
                    </Field>
                    <Separator />
                    <Field
                      className="settings-row settings-row-select"
                      orientation="horizontal"
                      data-disabled={!settings.sshAgentEnabled}
                    >
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
                    </Field>
                    <Separator />
                    <Field className="settings-row settings-row-stacked">
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
                                aria-label="複製 SSH Agent 設定指令"
                                onClick={() => void copySshAgentCommand()}
                              >
                                <Copy data-icon="inline-start" aria-hidden="true" />
                                {copySucceeded ? '已複製' : '複製'}
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
                    </Field>
                    {sshAgentStatus.state === 'error' && (
                      <>
                        <Separator />
                        <Field className="settings-row settings-row-stacked">
                          <FieldLabel>Agent 無法啟動</FieldLabel>
                          <FieldDescription>
                            {sshAgentStatus.lastError === 'SOCKET_IN_USE' ||
                            sshAgentStatus.lastError === 'PIPE_IN_USE'
                              ? '既有 SSH Agent 正在使用相同 endpoint。請停止該 Agent 後重新啟用 BearWarden SSH Agent。'
                              : 'BearWarden 無法安全地建立 SSH Agent endpoint。請確認家目錄權限與 socket 路徑後再試。'}
                          </FieldDescription>
                        </Field>
                      </>
                    )}
                  </FieldGroup>
                </CardContent>
                <CardFooter>
                  <p className="settings-card-note">
                    {sshAgentStatus.identityCount} 把可用 SSH
                    金鑰。私鑰與實際簽署資料不會傳到畫面程序。
                  </p>
                </CardFooter>
              </Card>

              <Card className="settings-card" aria-labelledby="privacy-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="privacy-settings-title"
                    icon={ClipboardCheck}
                    title="隱私與剪貼簿"
                    description="降低敏感資料留在螢幕或剪貼簿中的時間。"
                  />
                </CardHeader>
                <CardContent className="settings-card-content">
                  <FieldGroup className="gap-0">
                    <Field className="settings-row settings-row-select" orientation="horizontal">
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
                    </Field>
                    <Separator />
                    <Field className="settings-row" orientation="horizontal">
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
                    </Field>
                  </FieldGroup>
                </CardContent>
              </Card>
            </div>

            <div className="settings-aside">
              <Card className="settings-card" aria-labelledby="general-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="general-settings-title"
                    icon={Palette}
                    title="一般"
                    description="調整保管庫的外觀與預設排列方式。"
                  />
                </CardHeader>
                <CardContent className="settings-card-content">
                  <FieldGroup className="gap-0">
                    <Field className="settings-row settings-row-stacked">
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
                    </Field>
                    <Separator />
                    <Field className="settings-row settings-row-stacked">
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
                    </Field>
                    <Separator />
                    <Field
                      className="settings-row"
                      orientation="horizontal"
                      data-disabled={!settings.startAtLoginAvailable}
                    >
                      <FieldContent>
                        <FieldLabel htmlFor="start-at-login-switch">
                          登入時啟動 BearWarden
                        </FieldLabel>
                        <FieldDescription id="start-at-login-description">
                          {settings.startAtLoginAvailable
                            ? '登入這台電腦後，自動啟動 BearWarden。'
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
                    </Field>
                  </FieldGroup>
                </CardContent>
              </Card>

              <Card className="settings-card" aria-labelledby="touch-id-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="touch-id-settings-title"
                    icon={Fingerprint}
                    title="Touch ID"
                    description="使用這台裝置安全儲存的主密碼快速解鎖。"
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
                  <CardContent>
                    <Empty className="settings-empty">
                      <EmptyHeader>
                        <EmptyMedia variant="icon">
                          <Fingerprint />
                        </EmptyMedia>
                        <EmptyTitle>這台裝置無法使用 Touch ID</EmptyTitle>
                        <EmptyDescription>你仍可使用主密碼解鎖保管庫。</EmptyDescription>
                      </EmptyHeader>
                    </Empty>
                  </CardContent>
                ) : settings.touchIdEnabled ? (
                  <>
                    <CardContent>
                      <p className="settings-card-note">下次鎖定後即可直接使用 Touch ID 解鎖。</p>
                    </CardContent>
                    <CardFooter>
                      <Button
                        variant="outline"
                        size="sm"
                        type="button"
                        disabled={settingsBusy}
                        onClick={() => void onDisableTouchId()}
                      >
                        停用 Touch ID
                      </Button>
                    </CardFooter>
                  </>
                ) : (
                  <>
                    <CardContent>
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
                    </CardContent>
                    <CardFooter>
                      <Button
                        size="sm"
                        type="button"
                        disabled={settingsBusy || !touchIdPassword}
                        onClick={() => void onEnableTouchId()}
                      >
                        <LockKeyhole data-icon="inline-start" aria-hidden="true" />
                        啟用 Touch ID
                      </Button>
                    </CardFooter>
                  </>
                )}
              </Card>

              <Card className="settings-card" aria-labelledby="sync-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="sync-settings-title"
                    icon={Cloud}
                    title="同步與帳號"
                    description="連接 Bitwarden 或 Vaultwarden 以同步保管庫。"
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
                <CardContent>
                  <div className="settings-account-summary">
                    <span className="settings-account-icon" aria-hidden="true">
                      <Cloud />
                    </span>
                    <div>
                      <strong>{syncLabels[syncStatus.state]}</strong>
                      <small>
                        {syncStatus.email ?? syncStatus.serverUrl ?? '尚未連接 Bitwarden 帳號'}
                      </small>
                    </div>
                  </div>
                </CardContent>
                <CardFooter className="gap-2">
                  {syncStatus.configured && <EquivalentDomainsDialog />}
                  <Button variant="outline" size="sm" type="button" onClick={onOpenSync}>
                    {syncStatus.configured ? '管理同步與帳號' : '設定 Bitwarden 同步'}
                  </Button>
                </CardFooter>
              </Card>

              <Card className="settings-card" aria-labelledby="portability-settings-title">
                <CardHeader>
                  <SettingsCardHeading
                    id="portability-settings-title"
                    icon={DatabaseBackup}
                    title="資料可攜性"
                    description="匯入 Bitwarden JSON，或建立密碼保護的可攜備份。"
                  />
                </CardHeader>
                <CardContent>
                  <p className="settings-card-note">
                    檔案內容與路徑只會由本機主程序處理，不會傳回畫面程序。
                  </p>
                </CardContent>
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
              </Card>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default SettingsPage
