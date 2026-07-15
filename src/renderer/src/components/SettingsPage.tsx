import type { LucideIcon } from 'lucide-react'
import {
  ArrowLeft,
  ClipboardCheck,
  Cloud,
  Fingerprint,
  LockKeyhole,
  Palette,
  Settings2,
  ShieldCheck
} from 'lucide-react'
import type { AppSettings, AppSettingsUpdate, SyncStatus } from '../../../shared/vault-contract'
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
  onOpenSync
}: SettingsPageProps): React.JSX.Element {
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
              <a href="#privacy-settings-title">隱私與剪貼簿</a>
              <a href="#general-settings-title">一般</a>
              <a href="#touch-id-settings-title">Touch ID</a>
              <a href="#sync-settings-title">同步與帳號</a>
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
                <CardFooter>
                  <Button variant="outline" size="sm" type="button" onClick={onOpenSync}>
                    {syncStatus.configured ? '管理同步與帳號' : '設定 Bitwarden 同步'}
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
