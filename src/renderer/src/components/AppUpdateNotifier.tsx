import { useEffect } from 'react'
import { presentAppUpdateState } from '../lib/app-update-ui'
import { appUpdates } from '../stores/app-update-store'

const updateCheckIntervalMs = 6 * 60 * 60 * 1_000

export default function AppUpdateNotifier(): null {
  useEffect(() => {
    let active = true
    const disconnect = appUpdates.connect()
    const unsubscribe = appUpdates.store.subscribe((current, previous) => {
      if (!current.updateState || current.updateState === previous.updateState) return
      presentAppUpdateState(current.updateState, previous.updateState?.status === 'downloading')
    })
    const checkForUpdates = (): void => {
      void window.bearwarden.updater.check().then(
        (state) => {
          if (active) appUpdates.apply(state)
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
      disconnect()
    }
  }, [])

  return null
}
