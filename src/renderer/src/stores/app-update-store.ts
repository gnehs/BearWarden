import { createStore, type StoreApi } from 'zustand/vanilla'
import type { AppUpdateState, BearWardenAPI } from '../../../shared/vault-contract'

export type AppUpdaterApi = Pick<BearWardenAPI['updater'], 'state' | 'onStateChanged'>

export interface AppUpdateStoreState {
  /** Null until the first snapshot or change event arrives. */
  updateState: AppUpdateState | null
  readFailed: boolean
}

export interface AppUpdateStore {
  store: StoreApi<AppUpdateStoreState>
  /** Starts the shared updater subscription; the returned function releases this consumer. */
  connect: () => () => void
  /** Records a state returned by an updater action, such as a check or download. */
  apply: (state: AppUpdateState) => void
}

/**
 * One updater-state subscription shared by every consumer. The first `connect` subscribes
 * to change events and reads a snapshot; the snapshot is dropped if an event or action
 * result already arrived, so it can never replace a newer state.
 */
export function createAppUpdateStore(getApi: () => AppUpdaterApi): AppUpdateStore {
  const store = createStore<AppUpdateStoreState>()(() => ({ updateState: null, readFailed: false }))
  let consumers = 0
  let unsubscribe: (() => void) | null = null
  let revision = 0
  let connection = 0

  function apply(state: AppUpdateState): void {
    revision += 1
    store.setState({ updateState: state, readFailed: false })
  }

  function start(): void {
    const api = getApi()
    unsubscribe = api.onStateChanged(apply)
    const snapshotConnection = ++connection
    const snapshotRevision = revision
    const isCurrent = (): boolean =>
      unsubscribe !== null && connection === snapshotConnection && revision === snapshotRevision
    void api.state().then(
      (state) => {
        if (isCurrent()) apply(state)
      },
      () => {
        if (isCurrent()) store.setState({ readFailed: true })
      }
    )
  }

  return {
    store,
    apply,
    connect: () => {
      consumers += 1
      if (consumers === 1) start()
      let released = false
      return () => {
        if (released) return
        released = true
        consumers -= 1
        if (consumers > 0) return
        unsubscribe?.()
        unsubscribe = null
        connection += 1
      }
    }
  }
}

export const appUpdates = createAppUpdateStore(() => window.bearwarden.updater)
