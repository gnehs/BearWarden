import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('electron', () => ({
  safeStorage: {
    isAsyncEncryptionAvailable: vi.fn(),
    encryptStringAsync: vi.fn(),
    decryptStringAsync: vi.fn()
  },
  systemPreferences: {
    canPromptTouchID: vi.fn(),
    promptTouchID: vi.fn().mockResolvedValue(undefined)
  }
}))

import { safeStorage, systemPreferences } from 'electron'
import { AppSettingsService } from './app-settings'
import type { EncryptedVaultStore } from './encrypted-vault-store'
import { VaultError } from './vault-errors'

type TestMock = ReturnType<typeof vi.fn>

interface TestRuntime {
  applyContentProtection: TestMock
  applyClipboardTimeout: TestMock
  lockVault: TestMock
  unlockVault: TestMock
}

describe('AppSettingsService', () => {
  let directory: string
  const originalPlatform = process.platform

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), 'bearwarden-settings-'))
    vi.mocked(safeStorage.isAsyncEncryptionAvailable).mockResolvedValue(true)
    vi.mocked(safeStorage.encryptStringAsync).mockImplementation(async (value) =>
      Buffer.from(`encrypted:${value}`, 'utf8')
    )
    vi.mocked(safeStorage.decryptStringAsync).mockImplementation(async (value) => ({
      result: value.toString('utf8').replace(/^encrypted:/, ''),
      shouldReEncrypt: false
    }))
    vi.mocked(systemPreferences.canPromptTouchID).mockReturnValue(true)
    vi.mocked(systemPreferences.promptTouchID).mockResolvedValue(undefined)
  })

  afterEach(async () => {
    vi.useRealTimers()
    Object.defineProperty(process, 'platform', { value: originalPlatform })
    await rm(directory, { recursive: true, force: true })
    vi.clearAllMocks()
  })

  function createService(settingsPath = join(directory, 'settings.json')): {
    service: AppSettingsService
    store: EncryptedVaultStore<unknown>
    runtime: TestRuntime
    touchIdPath: string
  } {
    const store = {
      unlock: vi.fn().mockResolvedValue({ data: {}, key: Buffer.alloc(32), salt: Buffer.alloc(16) })
    } as unknown as EncryptedVaultStore<unknown>
    const runtime = {
      applyContentProtection: vi.fn(),
      applyClipboardTimeout: vi.fn(),
      lockVault: vi.fn().mockResolvedValue(undefined),
      unlockVault: vi.fn().mockResolvedValue({ state: 'unlocked' as const })
    }
    const service = new AppSettingsService(
      settingsPath,
      join(directory, 'vault', 'touch-id.bin'),
      store,
      runtime
    )
    return { service, store, runtime, touchIdPath: join(directory, 'vault', 'touch-id.bin') }
  }

  it('uses secure defaults and persists validated updates', async () => {
    const { service, runtime } = createService()
    await service.initialize()
    expect(await service.get()).toMatchObject({
      contentProtection: true,
      showWebsiteIcons: true,
      autoLockMinutes: 15,
      lockOnScreenLock: true,
      lockOnSuspend: true,
      clearClipboardSeconds: 30,
      defaultSort: 'recent',
      theme: 'system'
    })

    const updated = await service.update({
      contentProtection: false,
      showWebsiteIcons: false,
      autoLockMinutes: 0,
      clearClipboardSeconds: 60,
      theme: 'dark'
    })
    expect(updated).toMatchObject({
      contentProtection: false,
      showWebsiteIcons: false,
      autoLockMinutes: 0,
      clearClipboardSeconds: 60,
      theme: 'dark'
    })
    expect(runtime.applyContentProtection).toHaveBeenLastCalledWith(false)
    expect(runtime.applyClipboardTimeout).toHaveBeenLastCalledWith(60)
    expect(JSON.parse(await readFile(join(directory, 'settings.json'), 'utf8'))).not.toHaveProperty(
      'masterPassword'
    )
    service.dispose()
  })

  it('migrates version 1 settings without silently enabling remote website icons', async () => {
    const settingsPath = join(directory, 'settings.json')
    await writeFile(
      settingsPath,
      JSON.stringify({
        version: 1,
        contentProtection: true,
        autoLockMinutes: 15,
        lockOnScreenLock: true,
        lockOnSuspend: true,
        clearClipboardSeconds: 30,
        defaultSort: 'recent',
        theme: 'system'
      })
    )
    const { service } = createService(settingsPath)
    await service.initialize()
    expect(await service.get()).toMatchObject({ showWebsiteIcons: false })
    service.dispose()
  })

  it('gates the encrypted local unlock secret behind Touch ID', async () => {
    Object.defineProperty(process, 'platform', { value: 'darwin' })
    const { service, store, runtime } = createService()
    await service.initialize()

    expect((await service.get()).touchIdAvailable).toBe(true)
    expect((await service.enableTouchId('fake-master-password')).touchIdEnabled).toBe(true)
    expect(store.unlock).toHaveBeenCalledWith('fake-master-password')
    expect(await service.unlockTouchId()).toEqual({ state: 'unlocked' })
    expect(runtime.unlockVault).toHaveBeenCalledWith('fake-master-password')

    expect((await service.disableTouchId()).touchIdEnabled).toBe(false)
    service.dispose()
  })

  it('does not apply a settings update when its atomic write fails', async () => {
    const settingsPath = join(directory, 'settings-directory')
    await mkdir(settingsPath)
    const { service, runtime } = createService(settingsPath)
    await service.initialize()

    await expect(
      service.update({ contentProtection: false, clearClipboardSeconds: 120 })
    ).rejects.toThrow()
    expect(await service.get()).toMatchObject({
      contentProtection: true,
      clearClipboardSeconds: 30
    })
    expect(runtime.applyContentProtection).toHaveBeenLastCalledWith(true)
    expect(runtime.applyClipboardTimeout).toHaveBeenLastCalledWith(30)
    service.dispose()
  })

  it('maps rejected Touch ID and stale local secrets to a generic failure', async () => {
    Object.defineProperty(process, 'platform', { value: 'darwin' })
    const { service, store, runtime, touchIdPath } = createService()
    const key = Buffer.alloc(32, 7)
    const salt = Buffer.alloc(16, 9)
    vi.mocked(store.unlock).mockResolvedValue({ data: {}, key, salt })
    await service.initialize()

    vi.mocked(systemPreferences.promptTouchID).mockRejectedValueOnce(new Error('cancelled'))
    await expect(service.enableTouchId('fake-master-password')).rejects.toMatchObject({
      code: 'TOUCH_ID_FAILED'
    })
    await expect(readFile(touchIdPath)).rejects.toMatchObject({ code: 'ENOENT' })
    expect(key.every((value) => value === 0)).toBe(true)
    expect(salt.every((value) => value === 0)).toBe(true)

    await service.enableTouchId('fake-master-password')
    vi.mocked(runtime.unlockVault).mockRejectedValue(new VaultError('INVALID_MASTER_PASSWORD'))
    await expect(service.unlockTouchId()).rejects.toMatchObject({ code: 'TOUCH_ID_FAILED' })
    service.dispose()
  })

  it('shares one Touch ID prompt between concurrent unlock requests', async () => {
    Object.defineProperty(process, 'platform', { value: 'darwin' })
    const { service, runtime } = createService()
    await service.initialize()
    await service.enableTouchId('fake-master-password')
    vi.mocked(systemPreferences.promptTouchID).mockClear()

    let finishPrompt!: () => void
    vi.mocked(systemPreferences.promptTouchID).mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          finishPrompt = resolve
        })
    )

    const first = service.unlockTouchId()
    const second = service.unlockTouchId()
    expect(first).toBe(second)
    await vi.waitFor(() => expect(systemPreferences.promptTouchID).toHaveBeenCalledTimes(1))
    finishPrompt()

    await expect(Promise.all([first, second])).resolves.toEqual([
      { state: 'unlocked' },
      { state: 'unlocked' }
    ])
    expect(runtime.unlockVault).toHaveBeenCalledTimes(1)
    service.dispose()
  })

  it('disables Touch ID when asynchronous safe storage is unavailable', async () => {
    Object.defineProperty(process, 'platform', { value: 'darwin' })
    vi.mocked(safeStorage.isAsyncEncryptionAvailable).mockResolvedValue(false)
    const { service } = createService()
    await service.initialize()

    await expect(service.get()).resolves.toMatchObject({
      touchIdAvailable: false,
      touchIdEnabled: false
    })
    await expect(service.enableTouchId('fake-master-password')).rejects.toMatchObject({
      code: 'TOUCH_ID_UNAVAILABLE'
    })
    service.dispose()
  })

  it('resets auto-lock after activity and honours the disabled setting', async () => {
    const { service, runtime } = createService()
    await service.initialize()
    vi.useFakeTimers()
    service.activity()

    await vi.advanceTimersByTimeAsync(15 * 60_000)
    expect(runtime.lockVault).toHaveBeenCalledTimes(1)

    await service.update({ autoLockMinutes: 0 })
    await vi.advanceTimersByTimeAsync(60 * 60_000)
    expect(runtime.lockVault).toHaveBeenCalledTimes(1)
    service.dispose()
  })
})
