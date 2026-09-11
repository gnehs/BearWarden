import { describe, expect, it, vi } from 'vitest'
import type { AppSettings, VaultStatus } from '../shared/vault-contract'
import {
  FocusTouchIdUnlockController,
  type FocusTouchIdUnlockRuntime
} from './focus-touch-id-unlock'

function deferred<T>(): {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (reason?: unknown) => void
} {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function createRuntime(
  overrides: Partial<FocusTouchIdUnlockRuntime> = {}
): FocusTouchIdUnlockRuntime {
  const enabledSettings: AppSettings = {
    contentProtection: true,
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
    touchIdEnabled: true
  }
  return {
    isActive: vi.fn(() => true),
    isFocused: vi.fn(() => true),
    isDestroyed: vi.fn(() => false),
    lockGeneration: vi.fn(() => 0),
    vaultStatus: vi.fn(async (): Promise<VaultStatus> => ({ state: 'locked' })),
    settings: vi.fn(async () => enabledSettings),
    unlock: vi.fn(async (): Promise<VaultStatus> => ({ state: 'unlocked' })),
    lock: vi.fn(async () => undefined),
    notifyUnlocked: vi.fn(),
    ...overrides
  }
}

describe('FocusTouchIdUnlockController', () => {
  it('unlocks an enabled locked vault once when the window gains focus', async () => {
    const runtime = createRuntime()
    const controller = new FocusTouchIdUnlockController(runtime)

    await controller.focus()
    await controller.focus()

    expect(runtime.unlock).toHaveBeenCalledTimes(1)
    expect(runtime.notifyUnlocked).toHaveBeenCalledTimes(1)
  })

  it('does not start overlapping biometric prompts', async () => {
    const pending = deferred<VaultStatus>()
    const runtime = createRuntime({ unlock: vi.fn(() => pending.promise) })
    const controller = new FocusTouchIdUnlockController(runtime)

    const first = controller.focus()
    const second = controller.focus()
    await vi.waitFor(() => expect(runtime.unlock).toHaveBeenCalledTimes(1))
    pending.resolve({ state: 'unlocked' })
    await Promise.all([first, second])

    expect(runtime.notifyUnlocked).toHaveBeenCalledTimes(1)
  })

  it('stays locked after cancellation and retries only after a real blur-focus cycle', async () => {
    const runtime = createRuntime({
      unlock: vi
        .fn<() => Promise<VaultStatus>>()
        .mockRejectedValueOnce(new Error('cancelled'))
        .mockResolvedValueOnce({ state: 'unlocked' })
    })
    const controller = new FocusTouchIdUnlockController(runtime)

    await controller.focus()
    await controller.focus()
    expect(runtime.unlock).toHaveBeenCalledTimes(1)

    controller.blur()
    await controller.focus()

    expect(runtime.unlock).toHaveBeenCalledTimes(2)
    expect(runtime.notifyUnlocked).toHaveBeenCalledTimes(1)
  })

  it('prompts once when an unlocked focused vault is auto-locked', async () => {
    let state: VaultStatus['state'] = 'unlocked'
    const runtime = createRuntime({
      vaultStatus: vi.fn(async () => ({ state }))
    })
    const controller = new FocusTouchIdUnlockController(runtime)

    await controller.focus()
    expect(runtime.unlock).not.toHaveBeenCalled()

    state = 'locked'
    await controller.lockedWhileFocused()

    expect(runtime.unlock).toHaveBeenCalledTimes(1)
    expect(runtime.notifyUnlocked).toHaveBeenCalledTimes(1)
  })

  it('does not automatically retry a failed auto-lock prompt until a later blur-focus cycle', async () => {
    const runtime = createRuntime({
      unlock: vi
        .fn<() => Promise<VaultStatus>>()
        .mockRejectedValueOnce(new Error('cancelled'))
        .mockResolvedValueOnce({ state: 'unlocked' })
    })
    const controller = new FocusTouchIdUnlockController(runtime)

    await controller.lockedWhileFocused()
    await controller.lockedWhileFocused()
    await controller.focus()
    expect(runtime.unlock).toHaveBeenCalledTimes(1)

    controller.blur()
    await controller.focus()

    expect(runtime.unlock).toHaveBeenCalledTimes(2)
    expect(runtime.notifyUnlocked).toHaveBeenCalledTimes(1)
  })

  it('ignores prompt-owned blur-focus events and does not reopen after cancellation', async () => {
    const pending = deferred<VaultStatus>()
    const runtime = createRuntime({ unlock: vi.fn(() => pending.promise) })
    const controller = new FocusTouchIdUnlockController(runtime)

    const attempt = controller.focus()
    await vi.waitFor(() => expect(runtime.unlock).toHaveBeenCalledTimes(1))
    controller.blur()
    const restoredFocus = controller.focus()
    pending.reject(new Error('cancelled'))
    await Promise.all([attempt, restoredFocus])
    await controller.focus()

    expect(runtime.unlock).toHaveBeenCalledTimes(1)
    expect(runtime.notifyUnlocked).not.toHaveBeenCalled()
  })

  it('does not prompt on auto-lock when the window is not focused', async () => {
    const runtime = createRuntime({ isFocused: vi.fn(() => false) })
    const controller = new FocusTouchIdUnlockController(runtime)

    await controller.lockedWhileFocused()

    expect(runtime.unlock).not.toHaveBeenCalled()
  })

  it('does not reopen a vault that was locked while authentication was pending', async () => {
    let lockGeneration = 0
    const pending = deferred<VaultStatus>()
    const runtime = createRuntime({
      lockGeneration: vi.fn(() => lockGeneration),
      unlock: vi.fn(() => pending.promise)
    })
    const controller = new FocusTouchIdUnlockController(runtime)

    const focus = controller.focus()
    await vi.waitFor(() => expect(runtime.unlock).toHaveBeenCalledTimes(1))
    lockGeneration += 1
    pending.resolve({ state: 'unlocked' })
    await focus

    expect(runtime.lock).toHaveBeenCalledTimes(1)
    expect(runtime.notifyUnlocked).not.toHaveBeenCalled()
  })

  it('relocks a stale Touch ID result after fail-closed teardown rejects', async () => {
    let lockGeneration = 0
    let state: VaultStatus['state'] = 'locked'
    const pendingUnlock = deferred<VaultStatus>()
    const pendingTeardown = deferred<void>()
    const lock = vi.fn(async () => {
      lockGeneration += 1
      try {
        await pendingTeardown.promise
      } catch {
        // Equivalent to the main-process fail-closed barrier: the vault is already locked.
        state = 'locked'
      }
    })
    const runtime = createRuntime({
      lockGeneration: vi.fn(() => lockGeneration),
      vaultStatus: vi.fn(async () => ({ state })),
      unlock: vi.fn(() => pendingUnlock.promise),
      lock
    })
    const controller = new FocusTouchIdUnlockController(runtime)

    const focus = controller.focus()
    await vi.waitFor(() => expect(runtime.unlock).toHaveBeenCalledOnce())

    const teardown = lock()
    pendingTeardown.reject(new Error('teardown failed'))
    await teardown

    state = 'unlocked'
    pendingUnlock.resolve({ state: 'unlocked' })
    await focus

    expect(lock).toHaveBeenCalledTimes(2)
    expect(state).toBe('locked')
    expect(runtime.notifyUnlocked).not.toHaveBeenCalled()
  })

  it('does not prompt when Touch ID is disabled', async () => {
    const runtime = createRuntime({
      settings: vi.fn(async () => ({
        ...(await createRuntime().settings()),
        touchIdEnabled: false
      }))
    })
    const controller = new FocusTouchIdUnlockController(runtime)

    await controller.focus()

    expect(runtime.unlock).not.toHaveBeenCalled()
    expect(runtime.notifyUnlocked).not.toHaveBeenCalled()
  })

  it('relocks when authentication finishes after the app has lost focus', async () => {
    let active = true
    const pending = deferred<VaultStatus>()
    const runtime = createRuntime({
      isActive: vi.fn(() => active),
      unlock: vi.fn(() => pending.promise)
    })
    const controller = new FocusTouchIdUnlockController(runtime)

    const focus = controller.focus()
    await vi.waitFor(() => expect(runtime.unlock).toHaveBeenCalledTimes(1))
    active = false
    pending.resolve({ state: 'unlocked' })
    await focus

    expect(runtime.lock).toHaveBeenCalledTimes(1)
    expect(runtime.notifyUnlocked).not.toHaveBeenCalled()
  })

  it('does not consume the focus arm when focus arrives before the window is interactable', async () => {
    let focused = false
    const runtime = createRuntime({ isFocused: vi.fn(() => focused) })
    const controller = new FocusTouchIdUnlockController(runtime)

    await controller.focus()
    focused = true
    await controller.focus()

    expect(runtime.unlock).toHaveBeenCalledOnce()
    expect(runtime.notifyUnlocked).toHaveBeenCalledOnce()
  })

  it('rearms after losing focus during preflight and retries after returning', async () => {
    let focused = true
    const pendingStatus = deferred<VaultStatus>()
    const runtime = createRuntime({
      isFocused: vi.fn(() => focused),
      vaultStatus: vi.fn(() => pendingStatus.promise)
    })
    const controller = new FocusTouchIdUnlockController(runtime)

    const firstAttempt = controller.focus()
    await vi.waitFor(() => expect(runtime.vaultStatus).toHaveBeenCalledOnce())
    focused = false
    controller.blur()
    pendingStatus.resolve({ state: 'locked' })
    await firstAttempt

    focused = true
    await controller.focus()

    expect(runtime.unlock).toHaveBeenCalledOnce()
    expect(runtime.notifyUnlocked).toHaveBeenCalledOnce()
  })

  it('allows a retry after a canceled prompt finishes while the window is unfocused', async () => {
    let focused = true
    const pending = deferred<VaultStatus>()
    const runtime = createRuntime({
      isFocused: vi.fn(() => focused),
      unlock: vi
        .fn<() => Promise<VaultStatus>>()
        .mockImplementationOnce(() => pending.promise)
        .mockResolvedValueOnce({ state: 'unlocked' })
    })
    const controller = new FocusTouchIdUnlockController(runtime)

    const firstAttempt = controller.focus()
    await vi.waitFor(() => expect(runtime.unlock).toHaveBeenCalledOnce())
    focused = false
    controller.blur()
    pending.reject(new Error('cancelled'))
    await firstAttempt

    focused = true
    await controller.focus()

    expect(runtime.unlock).toHaveBeenCalledTimes(2)
    expect(runtime.notifyUnlocked).toHaveBeenCalledOnce()
  })

  it('allows a retry after relocking a successful prompt that finished unfocused', async () => {
    let focused = true
    const pending = deferred<VaultStatus>()
    const runtime = createRuntime({
      isFocused: vi.fn(() => focused),
      unlock: vi.fn(() => pending.promise)
    })
    const controller = new FocusTouchIdUnlockController(runtime)

    const firstAttempt = controller.focus()
    await vi.waitFor(() => expect(runtime.unlock).toHaveBeenCalledOnce())
    focused = false
    controller.blur()
    pending.resolve({ state: 'unlocked' })
    await firstAttempt

    expect(runtime.lock).toHaveBeenCalledOnce()
    expect(runtime.notifyUnlocked).not.toHaveBeenCalled()

    focused = true
    await controller.focus()

    expect(runtime.unlock).toHaveBeenCalledTimes(2)
    expect(runtime.notifyUnlocked).toHaveBeenCalledOnce()
  })
})
