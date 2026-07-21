// @vitest-environment node

import { describe, expect, it, vi } from 'vitest'
import type { AppSettings, AppSettingsUpdate } from '../../../shared/vault-contract'
import { createSettingsStore, type SettingsPersistenceApi } from './settings-store'

function settings(overrides: Partial<AppSettings> = {}): AppSettings {
  return {
    contentProtection: false,
    showWebsiteIcons: true,
    startAtLogin: false,
    startAtLoginAvailable: true,
    startAtLoginNeedsApproval: false,
    vaultTimeoutPolicy: { type: 'appInactivity', minutes: 15 },
    lockOnScreenLock: true,
    lockOnSuspend: true,
    clearClipboardSeconds: 30,
    defaultSort: 'recent',
    theme: 'system',
    language: 'system',
    autofillEnabled: false,
    autofillShortcut: 'Control+\\',
    sshAgentEnabled: false,
    sshAgentPromptBehavior: 'always',
    touchIdAvailable: true,
    touchIdEnabled: false,
    ...overrides
  }
}

function deferred<T>(): {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (reason?: unknown) => void
} {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((onResolve, onReject) => {
    resolve = onResolve
    reject = onReject
  })
  return { promise, resolve, reject }
}

function api(overrides: Partial<SettingsPersistenceApi> = {}): SettingsPersistenceApi {
  const initial = settings()
  return {
    get: vi.fn(async () => initial),
    update: vi.fn(async () => initial),
    enableTouchId: vi.fn(async () => initial),
    disableTouchId: vi.fn(async () => initial),
    ...overrides
  }
}

describe('settings store', () => {
  it('hydrates an authoritative snapshot and reset returns to the unloaded state', () => {
    const store = createSettingsStore(api())
    const hydrated = settings({ theme: 'dark' })

    expect(store.getState()).toMatchObject({
      settings: null,
      loaded: false,
      loading: false,
      busy: false
    })

    store.getState().hydrate(hydrated)
    expect(store.getState()).toMatchObject({ settings: hydrated, loaded: true })

    store.getState().reset()
    expect(store.getState()).toMatchObject({
      settings: null,
      loaded: false,
      loading: false,
      busy: false
    })
  })

  it('does not let a stale load overwrite a newer hydrated snapshot', async () => {
    const pending = deferred<AppSettings>()
    const store = createSettingsStore(api({ get: vi.fn(() => pending.promise) }))
    const stale = settings({ theme: 'light' })
    const current = settings({ theme: 'dark' })

    const load = store.getState().load()
    expect(store.getState().loading).toBe(true)

    store.getState().hydrate(current)
    pending.resolve(stale)
    await expect(load).resolves.toBe(stale)

    expect(store.getState()).toMatchObject({
      settings: current,
      loaded: true,
      loading: false
    })
  })

  it('keeps the newest result when concurrent loads resolve out of order', async () => {
    const first = deferred<AppSettings>()
    const second = deferred<AppSettings>()
    const get = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise)
    const store = createSettingsStore(api({ get }))
    const oldSnapshot = settings({ language: 'en' })
    const newSnapshot = settings({ language: 'zh-TW' })

    const firstLoad = store.getState().load()
    const secondLoad = store.getState().load()
    second.resolve(newSnapshot)
    await secondLoad
    first.resolve(oldSnapshot)
    await firstLoad

    expect(store.getState()).toMatchObject({
      settings: newSnapshot,
      loaded: true,
      loading: false
    })
  })

  it('commits only the main-process snapshot after a successful update', async () => {
    const pending = deferred<AppSettings>()
    const update = vi.fn(() => pending.promise)
    const store = createSettingsStore(api({ update }))
    const original = settings({ theme: 'light' })
    const authoritative = settings({ theme: 'dark', startAtLoginNeedsApproval: true })
    const request: AppSettingsUpdate = { theme: 'dark' }
    store.getState().hydrate(original)

    const mutation = store.getState().update(request)
    expect(update).toHaveBeenCalledWith(request)
    expect(store.getState()).toMatchObject({ settings: original, busy: true })

    pending.resolve(authoritative)
    await expect(mutation).resolves.toBe(authoritative)
    expect(store.getState()).toMatchObject({
      settings: authoritative,
      loaded: true,
      busy: false
    })
  })

  it('keeps a mutation result authoritative over a load started while it was busy', async () => {
    const pendingUpdate = deferred<AppSettings>()
    const pendingLoad = deferred<AppSettings>()
    const store = createSettingsStore(
      api({
        get: vi.fn(() => pendingLoad.promise),
        update: vi.fn(() => pendingUpdate.promise)
      })
    )
    const authoritative = settings({ theme: 'dark' })

    const mutation = store.getState().update({ theme: 'dark' })
    const load = store.getState().load()
    pendingUpdate.resolve(authoritative)
    await mutation
    pendingLoad.resolve(settings({ theme: 'light' }))
    await load

    expect(store.getState()).toMatchObject({
      settings: authoritative,
      loaded: true,
      loading: false,
      busy: false
    })
  })

  it('retains the last snapshot and clears busy after a failed update', async () => {
    const failure = new Error('settings update failed')
    const store = createSettingsStore(api({ update: vi.fn(async () => Promise.reject(failure)) }))
    const original = settings({ theme: 'light' })
    store.getState().hydrate(original)

    await expect(store.getState().update({ theme: 'dark' })).rejects.toBe(failure)
    expect(store.getState()).toMatchObject({
      settings: original,
      loaded: true,
      busy: false
    })
  })

  it('does not clear busy when an older mutation settles before the current mutation', async () => {
    const first = deferred<AppSettings>()
    const second = deferred<AppSettings>()
    const update = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise)
    const store = createSettingsStore(api({ update }))

    const firstMutation = store.getState().update({ theme: 'light' })
    const secondMutation = store.getState().update({ theme: 'dark' })
    first.resolve(settings({ theme: 'light' }))
    await firstMutation

    expect(store.getState().busy).toBe(true)

    const authoritative = settings({ theme: 'dark' })
    second.resolve(authoritative)
    await secondMutation
    expect(store.getState()).toMatchObject({ settings: authoritative, busy: false })
  })

  it('retains an earlier authoritative success when a later queued mutation fails', async () => {
    const first = deferred<AppSettings>()
    const failure = new Error('later settings update failed')
    const update = vi.fn().mockReturnValueOnce(first.promise).mockRejectedValueOnce(failure)
    const store = createSettingsStore(api({ update }))
    const original = settings({ theme: 'system' })
    const authoritative = settings({ theme: 'dark' })
    store.getState().hydrate(original)

    const firstMutation = store.getState().update({ theme: 'dark' })
    const secondMutation = store.getState().update({ language: 'zh-TW' })
    expect(update).toHaveBeenCalledOnce()

    first.resolve(authoritative)
    await expect(firstMutation).resolves.toBe(authoritative)
    await expect(secondMutation).rejects.toBe(failure)

    expect(update).toHaveBeenCalledTimes(2)
    expect(store.getState()).toMatchObject({ settings: authoritative, busy: false })
  })

  it('passes Touch ID credentials directly to IPC and reset invalidates the pending result', async () => {
    const pending = deferred<AppSettings>()
    const enableTouchId = vi.fn(() => pending.promise)
    const store = createSettingsStore(api({ enableTouchId }))
    const request = { masterPassword: 'test-only-master-password' }

    const mutation = store.getState().enableTouchId(request)
    expect(enableTouchId).toHaveBeenCalledWith(request)
    expect(store.getState().busy).toBe(true)
    expect(JSON.stringify(store.getState())).not.toContain(request.masterPassword)

    store.getState().reset()
    pending.resolve(settings({ touchIdEnabled: true }))
    await mutation

    expect(store.getState()).toMatchObject({
      settings: null,
      loaded: false,
      loading: false,
      busy: false
    })
  })

  it('clears busy when disabling Touch ID fails', async () => {
    const failure = new Error('Touch ID unavailable')
    const store = createSettingsStore(
      api({ disableTouchId: vi.fn(async () => Promise.reject(failure)) })
    )

    await expect(store.getState().disableTouchId()).rejects.toBe(failure)
    expect(store.getState().busy).toBe(false)
  })
})
