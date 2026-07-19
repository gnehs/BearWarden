import { useEffect, useRef } from 'react'
import type { AppUpdateState, AppUpdateStatus } from '../../../shared/vault-contract'
import { presentAppUpdateState } from '../lib/app-update-ui'

const updateCheckIntervalMs = 6 * 60 * 60 * 1_000

export default function AppUpdateNotifier(): null {
  const previousStatus = useRef<AppUpdateStatus>('idle')

  useEffect(() => {
    let active = true
    const handleState = (state: AppUpdateState): void => {
      presentAppUpdateState(state, previousStatus.current === 'downloading')
      previousStatus.current = state.status
    }
    const unsubscribe = window.bearwarden.updater.onStateChanged(handleState)
    const checkForUpdates = (): void => {
      void window.bearwarden.updater.check().then(
        (state) => {
          if (active) handleState(state)
        },
        () => undefined
      )
    }

    checkForUpdates()
    const interval = window.setInterval(checkForUpdates, updateCheckIntervalMs)
    return () => {
      active = false
      window.clearInterval(interval)
      unsubscribe()
    }
  }, [])

  return null
}
