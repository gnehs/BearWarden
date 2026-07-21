import type {
  AppSettings,
  AppSettingsUpdate,
  BearWardenAPI,
  TouchIdEnableRequest
} from '../../../shared/vault-contract'
import { createStore, type StoreApi } from 'zustand/vanilla'

export type SettingsPersistenceApi = Pick<
  BearWardenAPI['settings'],
  'get' | 'update' | 'enableTouchId' | 'disableTouchId'
>

export interface SettingsStoreState {
  settings: AppSettings | null
  loaded: boolean
  loading: boolean
  busy: boolean
  hydrate: (settings: AppSettings) => void
  load: () => Promise<AppSettings>
  update: (request: AppSettingsUpdate) => Promise<AppSettings>
  enableTouchId: (request: TouchIdEnableRequest) => Promise<AppSettings>
  disableTouchId: () => Promise<AppSettings>
  reset: () => void
}

export type SettingsStore = StoreApi<SettingsStoreState>

interface SettingsStoreSnapshot {
  settings: AppSettings | null
  loaded: boolean
  loading: boolean
  busy: boolean
}

function initialSnapshot(): SettingsStoreSnapshot {
  return {
    settings: null,
    loaded: false,
    loading: false,
    busy: false
  }
}

export function createSettingsStore(api: SettingsPersistenceApi): SettingsStore {
  return createStore<SettingsStoreState>()((set, get) => {
    let snapshotGeneration = 0
    let loadGeneration = 0
    let mutationEpoch = 0
    let pendingMutations = 0
    let mutationQueue: Promise<void> | null = null

    const hydrate = (settings: AppSettings): void => {
      snapshotGeneration += 1
      loadGeneration += 1
      mutationEpoch += 1
      set({ settings, loaded: true, loading: false, busy: false })
    }

    const mutate = async (operation: () => Promise<AppSettings>): Promise<AppSettings> => {
      const epoch = mutationEpoch

      // The main process serializes settings writes. Mirror that ordering here so an earlier
      // success is not discarded merely because a later queued write fails.
      snapshotGeneration += 1
      loadGeneration += 1
      pendingMutations += 1
      set({ busy: true, loading: false })

      let result: Promise<AppSettings>
      if (mutationQueue) {
        result = mutationQueue.then(operation)
      } else {
        try {
          result = operation()
        } catch (error) {
          result = Promise.reject(error)
        }
      }
      const nextQueue = result.then(
        () => undefined,
        () => undefined
      )
      mutationQueue = nextQueue
      void nextQueue.then(() => {
        if (mutationQueue === nextQueue) mutationQueue = null
      })

      try {
        const settings = await result
        if (epoch === mutationEpoch) {
          snapshotGeneration += 1
          loadGeneration += 1
          set({ settings, loaded: true, loading: false })
        }
        return settings
      } finally {
        pendingMutations -= 1
        if (epoch === mutationEpoch && pendingMutations === 0) set({ busy: false })
      }
    }

    return {
      ...initialSnapshot(),
      hydrate,
      load: async () => {
        const generation = ++loadGeneration
        const startingSnapshotGeneration = snapshotGeneration
        set({ loading: true })

        try {
          const settings = await api.get()
          if (
            generation === loadGeneration &&
            startingSnapshotGeneration === snapshotGeneration &&
            !get().busy
          ) {
            snapshotGeneration += 1
            set({ settings, loaded: true })
          }
          return settings
        } finally {
          if (generation === loadGeneration) set({ loading: false })
        }
      },
      update: (request) => mutate(() => api.update(request)),
      enableTouchId: (request) => mutate(() => api.enableTouchId(request)),
      disableTouchId: () => mutate(() => api.disableTouchId()),
      reset: () => {
        snapshotGeneration += 1
        loadGeneration += 1
        mutationEpoch += 1
        set(initialSnapshot())
      }
    }
  })
}
