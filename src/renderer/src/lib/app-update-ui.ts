import { msg } from '@lingui/core/macro'
import { toast } from 'sonner'
import { match, P } from 'ts-pattern'
import type { AppUpdateState } from '../../../shared/vault-contract'
import { i18n } from '../i18n'

const updateToastId = 'app-update'

function runUpdateAction(action: () => Promise<unknown>): void {
  void action().catch(() => {
    toast.error(i18n._(msg`Unable to perform the update action. Please try again later.`), {
      id: updateToastId
    })
  })
}

export function presentAppUpdateState(state: AppUpdateState, showError = false): void {
  const version = state.availableVersion ? ` ${state.availableVersion}` : ''

  match(state.status)
    .with('available', () => {
      toast.info(i18n._(msg`BearWarden${version} update available`), {
        id: updateToastId,
        duration: Infinity,
        description: state.canAutoInstall
          ? i18n._(msg`When the download is complete, you can choose when to restart and install.`)
          : state.manualUpdateSource === 'homebrew'
            ? i18n._(
                msg`On macOS, update by running brew upgrade --cask gnehs/tap/bearwarden in Terminal. You can also download the latest version from GitHub Releases.`
              )
            : i18n._(
                msg`This installation format must currently be downloaded manually from GitHub Releases.`
              ),
        action: {
          label: state.canAutoInstall ? i18n._(msg`Download update`) : i18n._(msg`Go to download`),
          onClick: () =>
            runUpdateAction(
              state.canAutoInstall
                ? () => window.bearwarden.updater.download()
                : () => window.bearwarden.updater.openReleasePage()
            )
        }
      })
    })
    .with('downloading', () => {
      const progress = Math.round(state.progress ?? 0)
      toast.loading(i18n._(msg`Downloading BearWarden${version}`), {
        id: updateToastId,
        duration: Infinity,
        description: `${progress}%`
      })
    })
    .with('downloaded', () => {
      toast.success(i18n._(msg`BearWarden${version} is ready`), {
        id: updateToastId,
        duration: Infinity,
        description: i18n._(msg`The new version will be installed after restarting.`),
        action: {
          label: i18n._(msg`Restart and install`),
          onClick: () => runUpdateAction(() => window.bearwarden.updater.install())
        }
      })
    })
    .with('error', () => {
      if (showError) {
        toast.error(i18n._(msg`Unable to download update`), {
          id: updateToastId,
          description: i18n._(msg`Check your network connection and try again later.`)
        })
      }
    })
    .with(P.union('disabled', 'idle'), () => {
      toast.dismiss(updateToastId)
    })
    .with('checking', () => undefined)
    .exhaustive()
}
