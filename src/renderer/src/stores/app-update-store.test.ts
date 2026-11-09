import { describe, expect, it, vi } from 'vitest'
import type { AppUpdateState } from '../../../shared/vault-contract'
import { createAppUpdateStore, type AppUpdaterApi } from './app-update-store'

function updateState(status: AppUpdateState['status']): AppUpdateState {
  return {
    status,
    currentVersion: '1.0.0',
    availableVersion: null,
    progress: null,
    canAutoInstall: true,
    manualUpdateSource: 'github'
  }
}

interface FakeUpdater {
  api: AppUpdaterApi
  emit: (state: AppUpdateState) => void
  resolveSnapshot: (state: AppUpdateState) => void
  rejectSnapshot: () => void
  subscriptions: () => number
}

function fakeUpdater(): FakeUpdater {
  const listeners = new Set<(state: AppUpdateState) => void>()
  let resolveSnapshot!: (state: AppUpdateState) => void
  let rejectSnapshot!: () => void
  const api: AppUpdaterApi = {
    state: vi.fn(
      () =>
        new Promise<AppUpdateState>((resolve, reject) => {
          resolveSnapshot = resolve
          rejectSnapshot = () => reject(new Error('UNAVAILABLE'))
        })
    ),
    onStateChanged: (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    }
  }
  return {
    api,
    emit: (state) => {
      for (const listener of listeners) listener(state)
    },
    resolveSnapshot: (state) => resolveSnapshot(state),
    rejectSnapshot: () => rejectSnapshot(),
    subscriptions: () => listeners.size
  }
}

describe('createAppUpdateStore', () => {
  it('shares one updater subscription and snapshot read across consumers', async () => {
    const updater = fakeUpdater()
    const updates = createAppUpdateStore(() => updater.api)

    const releaseAbout = updates.connect()
    const releaseNotifier = updates.connect()
    updater.resolveSnapshot(updateState('idle'))
    await Promise.resolve()

    expect(updater.subscriptions()).toBe(1)
    expect(updater.api.state).toHaveBeenCalledTimes(1)
    expect(updates.store.getState().updateState?.status).toBe('idle')

    updater.emit(updateState('available'))
    expect(updates.store.getState().updateState?.status).toBe('available')

    releaseAbout()
    expect(updater.subscriptions()).toBe(1)
    releaseNotifier()
    expect(updater.subscriptions()).toBe(0)
  })

  it('never lets the initial snapshot replace a newer event or action result', async () => {
    const updater = fakeUpdater()
    const updates = createAppUpdateStore(() => updater.api)
    updates.connect()

    updater.emit(updateState('downloading'))
    updater.resolveSnapshot(updateState('idle'))
    await Promise.resolve()

    expect(updates.store.getState().updateState?.status).toBe('downloading')
  })

  it('reports a failed snapshot read until a state arrives', async () => {
    const updater = fakeUpdater()
    const updates = createAppUpdateStore(() => updater.api)
    updates.connect()

    updater.rejectSnapshot()
    await Promise.resolve()
    expect(updates.store.getState().readFailed).toBe(true)

    updates.apply(updateState('checking'))
    expect(updates.store.getState()).toMatchObject({
      readFailed: false,
      updateState: { status: 'checking' }
    })
  })
})
