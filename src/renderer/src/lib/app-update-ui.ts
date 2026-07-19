import { toast } from 'sonner'
import type { AppUpdateState } from '../../../shared/vault-contract'

const updateToastId = 'app-update'

function runUpdateAction(action: () => Promise<unknown>): void {
  void action().catch(() => {
    toast.error('無法執行更新操作，請稍後再試。', { id: updateToastId })
  })
}

export function presentAppUpdateState(state: AppUpdateState, showError = false): void {
  const version = state.availableVersion ? ` ${state.availableVersion}` : ''

  switch (state.status) {
    case 'available':
      toast.info(`BearWarden${version} 可供更新`, {
        id: updateToastId,
        duration: Infinity,
        description: state.canAutoInstall
          ? '下載完成後，你可以選擇何時重新啟動並安裝。'
          : '這個安裝格式目前需從 GitHub Releases 手動下載。',
        action: {
          label: state.canAutoInstall ? '下載更新' : '前往下載',
          onClick: () =>
            runUpdateAction(
              state.canAutoInstall
                ? () => window.bearwarden.updater.download()
                : () => window.bearwarden.updater.openReleasePage()
            )
        }
      })
      break
    case 'downloading': {
      const progress = Math.round(state.progress ?? 0)
      toast.loading(`正在下載 BearWarden${version}`, {
        id: updateToastId,
        duration: Infinity,
        description: `${progress}%`
      })
      break
    }
    case 'downloaded':
      toast.success(`BearWarden${version} 已準備好`, {
        id: updateToastId,
        duration: Infinity,
        description: '重新啟動後會安裝新版。',
        action: {
          label: '重新啟動並安裝',
          onClick: () => runUpdateAction(() => window.bearwarden.updater.install())
        }
      })
      break
    case 'error':
      if (showError) {
        toast.error('無法下載更新', {
          id: updateToastId,
          description: '請確認網路連線後稍後再試。'
        })
      }
      break
    case 'disabled':
    case 'idle':
      toast.dismiss(updateToastId)
      break
    case 'checking':
      break
  }
}
