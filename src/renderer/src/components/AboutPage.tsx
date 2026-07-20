import { useEffect, useState } from 'react'
import type { AppUpdateState } from '../../../shared/vault-contract'
import { Badge } from '@renderer/components/ui/badge'
import { Button } from '@renderer/components/ui/button'
import {
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle
} from '@renderer/components/ui/card'
import { Progress, ProgressLabel, ProgressValue } from '@renderer/components/ui/progress'
import { Separator } from '@renderer/components/ui/separator'
import { Spinner } from '@renderer/components/ui/spinner'
import { ExternalLink, GitFork, Info, RefreshCw } from 'lucide-react'
import { SettingsCard } from './SettingsPrimitives'

const initialUpdateState: AppUpdateState = {
  status: 'idle',
  currentVersion: '',
  availableVersion: null,
  progress: null,
  canAutoInstall: false
}

interface AboutPageProps {
  onOpenRepository: () => Promise<void>
}

function updateStatusLabel(state: AppUpdateState, hasChecked: boolean): string {
  switch (state.status) {
    case 'checking':
      return '檢查中'
    case 'available':
      return '有新版本'
    case 'downloading':
      return '下載中'
    case 'downloaded':
      return '已準備好'
    case 'error':
      return '檢查失敗'
    case 'disabled':
      return '手動更新'
    case 'idle':
      return hasChecked ? '已是最新版本' : '尚未檢查'
  }
}

function updateDescription(state: AppUpdateState, hasChecked: boolean): string {
  switch (state.status) {
    case 'checking':
      return '正在向更新服務確認是否有新版。'
    case 'available':
      return state.canAutoInstall
        ? `版本 ${state.availableVersion ?? '新版'} 已可下載。`
        : '這個安裝格式需從 GitHub Releases 手動下載。'
    case 'downloading':
      return '更新檔會在背景下載，完成後可選擇何時重新啟動。'
    case 'downloaded':
      return `版本 ${state.availableVersion ?? '新版'} 已下載完成。`
    case 'error':
      return '無法完成更新檢查，請確認網路連線後再試。'
    case 'disabled':
      return '開發版本不提供自動更新，請從 GitHub Releases 取得安裝檔。'
    case 'idle':
      return hasChecked ? '目前沒有可用更新。' : '手動檢查 BearWarden 是否有新版本。'
  }
}

export default function AboutPage({ onOpenRepository }: AboutPageProps): React.JSX.Element {
  const [updateState, setUpdateState] = useState<AppUpdateState>(initialUpdateState)
  const [hasChecked, setHasChecked] = useState(false)
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState('')

  useEffect(() => {
    let active = true
    const unsubscribe = window.bearwarden.updater.onStateChanged((state) => {
      if (active) setUpdateState(state)
    })
    void window.bearwarden.updater.state().then(
      (state) => {
        if (active) setUpdateState(state)
      },
      () => {
        if (active) setActionError('無法讀取更新狀態。')
      }
    )
    return () => {
      active = false
      unsubscribe()
    }
  }, [])

  async function runUpdateAction(action: () => Promise<AppUpdateState | void>): Promise<void> {
    setBusy(true)
    setActionError('')
    try {
      const nextState = await action()
      if (nextState) setUpdateState(nextState)
    } catch {
      setActionError('無法執行更新操作，請稍後再試。')
    } finally {
      setBusy(false)
    }
  }

  const currentVersion = updateState.currentVersion || '讀取中…'
  const statusLabel = updateStatusLabel(updateState, hasChecked)
  const canCheck = updateState.status === 'idle' || updateState.status === 'error'
  const showProgress = updateState.status === 'downloading'
  const progress = Math.min(100, Math.max(0, updateState.progress ?? 0))

  return (
    <div className="grid min-w-0 gap-4 pt-1">
      <SettingsCard aria-labelledby="about-settings-title">
        <CardHeader>
          <div className="flex min-w-0 items-center gap-3">
            <span
              className="text-primary grid size-9 shrink-0 place-items-center rounded-[11px] bg-[var(--accent-soft)] [&>svg]:size-[17px]"
              aria-hidden="true"
            >
              <Info />
            </span>
            <div className="min-w-0">
              <CardTitle id="about-settings-title" role="heading" aria-level={2}>
                關於 BearWarden
              </CardTitle>
              <CardDescription>查看目前版本、更新狀態與專案資訊。</CardDescription>
            </div>
          </div>
          <CardAction>
            <Badge variant={updateState.status === 'available' ? 'default' : 'secondary'}>
              {statusLabel}
            </Badge>
          </CardAction>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="flex items-center justify-between gap-4">
            <div className="grid gap-0.5">
              <strong className="text-xs">目前版本</strong>
              <span className="text-muted-foreground text-xs">BearWarden Desktop</span>
            </div>
            <Badge variant="outline" className="font-mono tabular-nums">
              {currentVersion === '讀取中…' ? currentVersion : `v${currentVersion}`}
            </Badge>
          </div>
          <Separator />
          <div className="flex items-start justify-between gap-4 max-[680px]:flex-col">
            <div className="grid min-w-0 gap-1">
              <strong className="text-xs">版本更新</strong>
              <p className="text-muted-foreground m-0 text-xs leading-[1.5]">
                {updateDescription(updateState, hasChecked)}
              </p>
            </div>
            {updateState.status === 'available' ? (
              <Button
                size="sm"
                type="button"
                disabled={busy}
                onClick={() =>
                  void runUpdateAction(
                    updateState.canAutoInstall
                      ? () => window.bearwarden.updater.download()
                      : () => window.bearwarden.updater.openReleasePage().then(() => undefined)
                  )
                }
              >
                {updateState.canAutoInstall ? '下載更新' : '前往 Releases'}
              </Button>
            ) : updateState.status === 'downloaded' ? (
              <Button
                size="sm"
                type="button"
                disabled={busy}
                onClick={() => void runUpdateAction(() => window.bearwarden.updater.install())}
              >
                重新啟動並安裝
              </Button>
            ) : (
              <Button
                variant="outline"
                size="sm"
                type="button"
                disabled={busy || !canCheck}
                onClick={() =>
                  void runUpdateAction(() => {
                    setHasChecked(true)
                    return window.bearwarden.updater.check()
                  })
                }
              >
                {busy || updateState.status === 'checking' ? (
                  <Spinner data-icon="inline-start" aria-hidden="true" />
                ) : (
                  <RefreshCw data-icon="inline-start" aria-hidden="true" />
                )}
                檢查更新
              </Button>
            )}
          </div>
          {showProgress && (
            <Progress value={progress} className="gap-1.5">
              <ProgressLabel className="text-muted-foreground text-xs">下載進度</ProgressLabel>
              <ProgressValue className="text-xs" />
            </Progress>
          )}
          {actionError && (
            <p className="text-destructive m-0 text-xs" role="alert">
              {actionError}
            </p>
          )}
        </CardContent>
      </SettingsCard>

      <SettingsCard aria-labelledby="about-project-title">
        <CardHeader>
          <CardTitle id="about-project-title" role="heading" aria-level={2}>
            專案資訊
          </CardTitle>
          <CardDescription>BearWarden 是一個以本機優先為核心的桌面密碼管理器。</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground m-0 text-xs leading-[1.6]">
            查看原始碼、回報問題，或取得最新發行版本。
          </p>
        </CardContent>
        <CardFooter className="gap-2">
          <Button
            variant="outline"
            size="sm"
            type="button"
            disabled={busy}
            onClick={() => void runUpdateAction(() => onOpenRepository())}
          >
            <GitFork data-icon="inline-start" aria-hidden="true" />
            GitHub
          </Button>
          <Button
            variant="ghost"
            size="sm"
            type="button"
            disabled={busy}
            onClick={() => void runUpdateAction(() => window.bearwarden.updater.openReleasePage())}
          >
            <ExternalLink data-icon="inline-start" aria-hidden="true" />
            Releases
          </Button>
        </CardFooter>
      </SettingsCard>
    </div>
  )
}
