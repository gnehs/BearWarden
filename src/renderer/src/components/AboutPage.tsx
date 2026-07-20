import { useEffect, useState } from 'react'
import { useLingui } from '@lingui/react/macro'
import type { AppUpdateState } from '../../../shared/vault-contract'
import { Badge } from '@renderer/components/ui/badge'
import { Button } from '@renderer/components/ui/button'
import {
  CardAction,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle
} from '@renderer/components/ui/card'
import { Progress, ProgressLabel, ProgressValue } from '@renderer/components/ui/progress'
import { Separator } from '@renderer/components/ui/separator'
import { Spinner } from '@renderer/components/ui/spinner'
import { ExternalLink, GitFork, Info, RefreshCw } from 'lucide-react'
import { SettingsCard, SettingsCardContent, SettingsCardHeading } from './SettingsPrimitives'

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

export default function AboutPage({ onOpenRepository }: AboutPageProps): React.JSX.Element {
  const { t } = useLingui()
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
        if (active) setActionError(t`Unable to read update status.`)
      }
    )
    return () => {
      active = false
      unsubscribe()
    }
  }, [t])

  async function runUpdateAction(action: () => Promise<AppUpdateState | void>): Promise<void> {
    setBusy(true)
    setActionError('')
    try {
      const nextState = await action()
      if (nextState) setUpdateState(nextState)
    } catch {
      setActionError(t`Unable to complete the update action. Please try again later.`)
    } finally {
      setBusy(false)
    }
  }

  const currentVersion = updateState.currentVersion || t`Loading…`
  const availableVersion = updateState.availableVersion ?? t`a new version`
  const statusLabel = (() => {
    switch (updateState.status) {
      case 'checking':
        return t`Checking`
      case 'available':
        return t`Update available`
      case 'downloading':
        return t`Downloading`
      case 'downloaded':
        return t`Ready to install`
      case 'error':
        return t`Check failed`
      case 'disabled':
        return t`Manual update`
      case 'idle':
        return hasChecked ? t`Up to date` : t`Not checked`
    }
  })()
  const updateDescription = (() => {
    switch (updateState.status) {
      case 'checking':
        return t`Checking the update service for a new version.`
      case 'available':
        return updateState.canAutoInstall
          ? t`Version ${availableVersion} is available to download.`
          : t`This installation format must be downloaded manually from GitHub Releases.`
      case 'downloading':
        return t`The update downloads in the background. You can choose when to restart after it finishes.`
      case 'downloaded':
        return t`Version ${availableVersion} has finished downloading.`
      case 'error':
        return t`Unable to check for updates. Check your network connection and try again.`
      case 'disabled':
        return t`Development builds do not support automatic updates. Download an installer from GitHub Releases.`
      case 'idle':
        return hasChecked
          ? t`No updates are currently available.`
          : t`Check manually for a new version of BearWarden.`
    }
  })()
  const canCheck = updateState.status === 'idle' || updateState.status === 'error'
  const showProgress = updateState.status === 'downloading'
  const progress = Math.min(100, Math.max(0, updateState.progress ?? 0))

  return (
    <>
      <SettingsCard aria-labelledby="about-settings-title">
        <CardHeader>
          <SettingsCardHeading
            id="about-settings-title"
            icon={Info}
            title={t`About BearWarden`}
            description={t`View the current version, update status, and project information.`}
          />
          <CardAction>
            <Badge variant={updateState.status === 'available' ? 'default' : 'secondary'}>
              {statusLabel}
            </Badge>
          </CardAction>
        </CardHeader>
        <SettingsCardContent className="grid gap-4">
          <div className="flex items-center justify-between gap-4">
            <div className="grid gap-0.5">
              <strong className="text-xs">{t`Current version`}</strong>
              <span className="text-muted-foreground text-xs">{t`BearWarden Desktop`}</span>
            </div>
            <Badge variant="outline" className="font-mono tabular-nums">
              {updateState.currentVersion ? `v${currentVersion}` : currentVersion}
            </Badge>
          </div>
          <Separator />
          <div className="flex items-start justify-between gap-4 max-[680px]:flex-col">
            <div className="grid min-w-0 gap-1">
              <strong className="text-xs">{t`Version updates`}</strong>
              <p className="text-muted-foreground m-0 text-xs leading-[1.5]">{updateDescription}</p>
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
                {updateState.canAutoInstall ? t`Download update` : t`Go to Releases`}
              </Button>
            ) : updateState.status === 'downloaded' ? (
              <Button
                size="sm"
                type="button"
                disabled={busy}
                onClick={() => void runUpdateAction(() => window.bearwarden.updater.install())}
              >
                {t`Restart and install`}
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
                {t`Check for updates`}
              </Button>
            )}
          </div>
          {showProgress && (
            <Progress value={progress} className="gap-1.5">
              <ProgressLabel className="text-muted-foreground text-xs">
                {t`Download progress`}
              </ProgressLabel>
              <ProgressValue className="text-xs" />
            </Progress>
          )}
          {actionError && (
            <p className="text-destructive m-0 text-xs" role="alert">
              {actionError}
            </p>
          )}
        </SettingsCardContent>
      </SettingsCard>

      <SettingsCard aria-labelledby="about-project-title">
        <CardHeader>
          <CardTitle id="about-project-title" role="heading" aria-level={2}>
            {t`Project information`}
          </CardTitle>
          <CardDescription>{t`BearWarden is a local-first desktop password manager.`}</CardDescription>
        </CardHeader>
        <SettingsCardContent>
          <p className="text-muted-foreground m-0 text-xs leading-[1.6]">
            {t`View the source code, report an issue, or get the latest release.`}
          </p>
        </SettingsCardContent>
        <CardFooter className="gap-2">
          <Button
            variant="outline"
            size="sm"
            type="button"
            disabled={busy}
            onClick={() => void runUpdateAction(() => onOpenRepository())}
          >
            <GitFork data-icon="inline-start" aria-hidden="true" />
            {t`GitHub`}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            type="button"
            disabled={busy}
            onClick={() => void runUpdateAction(() => window.bearwarden.updater.openReleasePage())}
          >
            <ExternalLink data-icon="inline-start" aria-hidden="true" />
            {t`Releases`}
          </Button>
        </CardFooter>
      </SettingsCard>
    </>
  )
}
