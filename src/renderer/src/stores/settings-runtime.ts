import { useStore } from 'zustand'
import {
  createSettingsStore,
  type SettingsPersistenceApi,
  type SettingsStoreState
} from './settings-store'

const settingsApi: SettingsPersistenceApi = {
  get: (...args) => window.bearwarden.settings.get(...args),
  update: (...args) => window.bearwarden.settings.update(...args),
  enableTouchId: (...args) => window.bearwarden.settings.enableTouchId(...args),
  disableTouchId: (...args) => window.bearwarden.settings.disableTouchId(...args)
}

export const settingsStore = createSettingsStore(settingsApi)

export function useSettingsStore<T>(selector: (state: SettingsStoreState) => T): T {
  return useStore(settingsStore, selector)
}
