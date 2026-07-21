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
import type { VaultTimeoutCoordinator } from './vault-timeout-coordinator'

type TestMock = ReturnType<typeof vi.fn>

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

interface TestRuntime {
  applyContentProtection: TestMock
  applyClipboardTimeout: TestMock
  applyAutofillSettings: TestMock
  applyLanguage: TestMock
  applySshAgentSettings: TestMock
  getStartAtLoginStatus: TestMock
  setStartAtLogin: TestMock
  unlockVault: TestMock
}

interface TestTimeoutCoordinator {
  updatePolicy: TestMock
  activity: TestMock
  cancel: TestMock
  dispose: TestMock
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

  function createService(
    settingsPath = join(directory, 'settings.json'),
    writeSettings?: (path: string, data: string | Buffer) => Promise<void>
  ): {
    service: AppSettingsService
    store: EncryptedVaultStore<unknown>
    runtime: TestRuntime
    timeoutCoordinator: TestTimeoutCoordinator
    touchIdPath: string
  } {
    const store = {
      unlock: vi.fn().mockResolvedValue({ data: {}, key: Buffer.alloc(32), salt: Buffer.alloc(16) })
    } as unknown as EncryptedVaultStore<unknown>
    const runtime = {
      applyContentProtection: vi.fn(),
      applyClipboardTimeout: vi.fn(),
      applyAutofillSettings: vi.fn(() => true),
      applyLanguage: vi.fn(),
      applySshAgentSettings: vi.fn(),
      getStartAtLoginStatus: vi.fn(() => ({
        available: false,
        enabled: false,
        needsApproval: false
      })),
      setStartAtLogin: vi.fn(() => false),
      unlockVault: vi.fn().mockResolvedValue({ state: 'unlocked' as const })
    }
    const timeoutCoordinator = {
      updatePolicy: vi.fn(),
      activity: vi.fn(),
      cancel: vi.fn(),
      dispose: vi.fn()
    }
    const service = new AppSettingsService(
      settingsPath,
      join(directory, 'vault', 'touch-id.bin'),
      store,
      runtime,
      timeoutCoordinator as unknown as VaultTimeoutCoordinator,
      writeSettings
    )
    return {
      service,
      store,
      runtime,
      timeoutCoordinator,
      touchIdPath: join(directory, 'vault', 'touch-id.bin')
    }
  }

  it('uses secure defaults and persists validated updates', async () => {
    const { service, runtime } = createService()
    await service.initialize()
    expect(await service.get()).toMatchObject({
      contentProtection: false,
      showWebsiteIcons: true,
      startAtLogin: false,
      startAtLoginAvailable: false,
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
      sshAgentPromptBehavior: 'always'
    })

    const updated = await service.update({
      contentProtection: true,
      showWebsiteIcons: false,
      vaultTimeoutPolicy: { type: 'onRestart' },
      clearClipboardSeconds: 60,
      defaultSort: 'frequency',
      theme: 'dark',
      language: 'ja',
      autofillEnabled: true,
      autofillShortcut: 'Command+Control+K',
      sshAgentEnabled: true,
      sshAgentPromptBehavior: 'rememberUntilLock'
    })
    expect(updated).toMatchObject({
      contentProtection: true,
      showWebsiteIcons: false,
      vaultTimeoutPolicy: { type: 'onRestart' },
      clearClipboardSeconds: 60,
      defaultSort: 'frequency',
      theme: 'dark',
      language: 'ja',
      autofillEnabled: true,
      autofillShortcut: 'Command+Control+K',
      sshAgentEnabled: true,
      sshAgentPromptBehavior: 'rememberUntilLock'
    })
    expect(runtime.applyContentProtection).toHaveBeenLastCalledWith(true)
    expect(runtime.applyClipboardTimeout).toHaveBeenLastCalledWith(60)
    expect(runtime.applyAutofillSettings).toHaveBeenLastCalledWith({
      enabled: true,
      shortcut: 'Command+Control+K'
    })
    expect(runtime.applyLanguage).toHaveBeenLastCalledWith('ja')
    expect(runtime.applySshAgentSettings).toHaveBeenLastCalledWith({
      enabled: true,
      promptBehavior: 'rememberUntilLock'
    })
    expect(JSON.parse(await readFile(join(directory, 'settings.json'), 'utf8'))).toMatchObject({
      version: 9,
      startAtLogin: false,
      defaultSort: 'frequency',
      autofillShortcut: 'Command+Control+K',
      sshAgentEnabled: true,
      sshAgentPromptBehavior: 'rememberUntilLock'
    })
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
    expect(await service.get()).toMatchObject({
      showWebsiteIcons: false,
      sshAgentEnabled: false,
      sshAgentPromptBehavior: 'always',
      vaultTimeoutPolicy: { type: 'appInactivity', minutes: 15 }
    })
    expect(JSON.parse(await readFile(settingsPath, 'utf8'))).toMatchObject({
      version: 9,
      autofillEnabled: false
    })
    service.dispose()
  })

  it('migrates version 2 settings without silently enabling the SSH agent', async () => {
    const settingsPath = join(directory, 'settings.json')
    await writeFile(
      settingsPath,
      JSON.stringify({
        version: 2,
        contentProtection: true,
        showWebsiteIcons: true,
        autoLockMinutes: 15,
        lockOnScreenLock: true,
        lockOnSuspend: true,
        clearClipboardSeconds: 30,
        defaultSort: 'recent',
        theme: 'system'
      })
    )
    const { service, runtime } = createService(settingsPath)
    await service.initialize()
    expect(await service.get()).toMatchObject({
      sshAgentEnabled: false,
      sshAgentPromptBehavior: 'always'
    })
    expect(runtime.applySshAgentSettings).toHaveBeenLastCalledWith({
      enabled: false,
      promptBehavior: 'always'
    })
    service.dispose()
  })

  it('migrates version 3 settings and adopts the existing OS login item state', async () => {
    const settingsPath = join(directory, 'settings.json')
    await writeFile(
      settingsPath,
      JSON.stringify({
        version: 3,
        contentProtection: true,
        showWebsiteIcons: true,
        autoLockMinutes: 15,
        lockOnScreenLock: true,
        lockOnSuspend: true,
        clearClipboardSeconds: 30,
        defaultSort: 'recent',
        theme: 'system',
        sshAgentEnabled: false,
        sshAgentPromptBehavior: 'always'
      })
    )
    const { service, runtime } = createService(settingsPath)
    runtime.getStartAtLoginStatus.mockReturnValue({
      available: true,
      enabled: true,
      needsApproval: true
    })
    await service.initialize()

    await expect(service.get()).resolves.toMatchObject({
      startAtLogin: true,
      startAtLoginAvailable: true,
      startAtLoginNeedsApproval: true
    })
    expect(runtime.setStartAtLogin).not.toHaveBeenCalled()
    service.dispose()
  })

  it.each([
    [0, { type: 'onRestart' }],
    [1, { type: 'appInactivity', minutes: 1 }],
    [5, { type: 'appInactivity', minutes: 5 }],
    [15, { type: 'appInactivity', minutes: 15 }],
    [30, { type: 'appInactivity', minutes: 30 }],
    [60, { type: 'appInactivity', minutes: 60 }]
  ] as const)(
    'migrates the version 4 timeout value %i to the v8 discriminated policy',
    async (autoLockMinutes, expectedPolicy) => {
      const settingsPath = join(directory, 'settings.json')
      await writeFile(
        settingsPath,
        JSON.stringify({
          version: 4,
          contentProtection: true,
          showWebsiteIcons: true,
          startAtLogin: false,
          autoLockMinutes,
          lockOnScreenLock: true,
          lockOnSuspend: true,
          clearClipboardSeconds: 30,
          defaultSort: 'recent',
          theme: 'system',
          sshAgentEnabled: false,
          sshAgentPromptBehavior: 'always'
        })
      )
      const { service } = createService(settingsPath)
      await service.initialize()

      await expect(service.get()).resolves.toMatchObject({
        vaultTimeoutPolicy: expectedPolicy
      })
      const migrated = JSON.parse(await readFile(settingsPath, 'utf8'))
      expect(migrated).toMatchObject({
        version: 9,
        autofillEnabled: false,
        vaultTimeoutPolicy: expectedPolicy
      })
      expect(migrated).not.toHaveProperty('autoLockMinutes')
      service.dispose()
    }
  )

  it.each([{ type: 'onRestart' }, { type: 'appInactivity', minutes: 240 }] as const)(
    'migrates a valid version 5 policy to version 8: $type',
    async (vaultTimeoutPolicy) => {
      const settingsPath = join(directory, 'settings.json')
      await writeFile(
        settingsPath,
        JSON.stringify({
          version: 5,
          contentProtection: true,
          showWebsiteIcons: true,
          startAtLogin: false,
          vaultTimeoutPolicy,
          lockOnScreenLock: true,
          lockOnSuspend: true,
          clearClipboardSeconds: 30,
          defaultSort: 'recent',
          theme: 'system',
          sshAgentEnabled: false,
          sshAgentPromptBehavior: 'always'
        })
      )
      const { service } = createService(settingsPath)
      await service.initialize()

      await expect(service.get()).resolves.toMatchObject({ vaultTimeoutPolicy })
      await expect(readFile(settingsPath, 'utf8')).resolves.toContain('"version":9')
      service.dispose()
    }
  )

  it('migrates the version 6 system-idle policy without losing it', async () => {
    const settingsPath = join(directory, 'settings.json')
    await writeFile(
      settingsPath,
      JSON.stringify({
        version: 6,
        contentProtection: true,
        showWebsiteIcons: true,
        startAtLogin: false,
        vaultTimeoutPolicy: { type: 'systemIdle' },
        lockOnScreenLock: true,
        lockOnSuspend: true,
        clearClipboardSeconds: 30,
        defaultSort: 'recent',
        theme: 'system',
        sshAgentEnabled: false,
        sshAgentPromptBehavior: 'always'
      })
    )
    const { service } = createService(settingsPath)
    await service.initialize()
    await expect(service.get()).resolves.toMatchObject({
      vaultTimeoutPolicy: { type: 'systemIdle' },
      autofillEnabled: false
    })
    expect(JSON.parse(await readFile(settingsPath, 'utf8'))).toMatchObject({ version: 9 })
    service.dispose()
  })

  it('migrates version 7 without losing the AutoFill preference', async () => {
    const settingsPath = join(directory, 'settings.json')
    await writeFile(
      settingsPath,
      JSON.stringify({
        version: 7,
        contentProtection: true,
        showWebsiteIcons: true,
        startAtLogin: false,
        vaultTimeoutPolicy: { type: 'appInactivity', minutes: 30 },
        lockOnScreenLock: true,
        lockOnSuspend: true,
        clearClipboardSeconds: 30,
        defaultSort: 'recent',
        theme: 'system',
        autofillEnabled: true,
        sshAgentEnabled: false,
        sshAgentPromptBehavior: 'always'
      })
    )
    const { service, runtime } = createService(settingsPath)
    await service.initialize()

    await expect(service.get()).resolves.toMatchObject({
      language: 'system',
      autofillEnabled: true
    })
    expect(runtime.applyAutofillSettings).toHaveBeenLastCalledWith({
      enabled: true,
      shortcut: 'Control+\\'
    })
    expect(runtime.applyLanguage).toHaveBeenLastCalledWith('system')
    expect(JSON.parse(await readFile(settingsPath, 'utf8'))).toMatchObject({
      version: 9,
      language: 'system',
      autofillEnabled: true
    })
    service.dispose()
  })

  it('migrates version 8 with the default AutoFill shortcut', async () => {
    const settingsPath = join(directory, 'settings.json')
    await writeFile(
      settingsPath,
      JSON.stringify({
        version: 8,
        contentProtection: true,
        showWebsiteIcons: true,
        startAtLogin: false,
        vaultTimeoutPolicy: { type: 'appInactivity', minutes: 30 },
        lockOnScreenLock: true,
        lockOnSuspend: true,
        clearClipboardSeconds: 30,
        defaultSort: 'recent',
        theme: 'system',
        language: 'zh-TW',
        autofillEnabled: true,
        sshAgentEnabled: false,
        sshAgentPromptBehavior: 'always'
      })
    )
    const { service } = createService(settingsPath)
    await service.initialize()

    await expect(service.get()).resolves.toMatchObject({
      language: 'zh-TW',
      autofillEnabled: true,
      autofillShortcut: 'Control+\\'
    })
    expect(JSON.parse(await readFile(settingsPath, 'utf8'))).toMatchObject({
      version: 9,
      autofillShortcut: 'Control+\\'
    })
    service.dispose()
  })

  it('preserves legacy settings bytes and blocks ordinary updates when copy-on-write migration fails', async () => {
    const settingsPath = join(directory, 'settings.json')
    const legacyBytes = JSON.stringify({
      version: 4,
      contentProtection: true,
      showWebsiteIcons: true,
      startAtLogin: false,
      autoLockMinutes: 15,
      lockOnScreenLock: true,
      lockOnSuspend: true,
      clearClipboardSeconds: 30,
      defaultSort: 'recent',
      theme: 'system',
      sshAgentEnabled: false,
      sshAgentPromptBehavior: 'always'
    })
    await writeFile(settingsPath, legacyBytes)
    const failedWrite = vi
      .fn<(path: string, data: string | Buffer) => Promise<void>>()
      .mockRejectedValue(new Error('disk full'))
    const { service } = createService(settingsPath, failedWrite)
    await service.initialize()

    await expect(readFile(settingsPath, 'utf8')).resolves.toBe(legacyBytes)
    await expect(service.update({ theme: 'dark' })).rejects.toMatchObject({
      code: 'INTERNAL_ERROR'
    })
    expect(failedWrite).toHaveBeenCalledOnce()
    service.dispose()

    const retry = createService(settingsPath)
    await retry.service.initialize()
    await expect(retry.service.get()).resolves.toMatchObject({
      vaultTimeoutPolicy: { type: 'appInactivity', minutes: 15 }
    })
    await expect(readFile(settingsPath, 'utf8')).resolves.toMatchObject(
      expect.stringContaining('"version":9')
    )
    retry.service.dispose()
  })

  it('updates and confirms the installed OS login item before persisting it', async () => {
    const { service, runtime } = createService()
    let enabled = false
    runtime.getStartAtLoginStatus.mockImplementation(() => ({
      available: true,
      enabled,
      needsApproval: false
    }))
    runtime.setStartAtLogin.mockImplementation((next: boolean) => {
      enabled = next
      return true
    })
    await service.initialize()

    await expect(service.update({ startAtLogin: true })).resolves.toMatchObject({
      startAtLogin: true,
      startAtLoginAvailable: true,
      startAtLoginNeedsApproval: false
    })
    expect(runtime.setStartAtLogin).toHaveBeenCalledWith(true)
    expect(JSON.parse(await readFile(join(directory, 'settings.json'), 'utf8'))).toMatchObject({
      version: 9,
      startAtLogin: true
    })
    service.dispose()
  })

  it('rejects enabling login startup when the platform does not support it', async () => {
    const { service, runtime } = createService()
    await service.initialize()

    await expect(service.update({ startAtLogin: true })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    expect(runtime.setStartAtLogin).not.toHaveBeenCalled()
    await expect(readFile(join(directory, 'settings.json'))).rejects.toMatchObject({
      code: 'ENOENT'
    })
    service.dispose()
  })

  it('restores the previous OS state when the requested login item cannot be confirmed', async () => {
    const { service, runtime } = createService()
    runtime.getStartAtLoginStatus.mockReturnValue({
      available: true,
      enabled: false,
      needsApproval: false
    })
    runtime.setStartAtLogin.mockReturnValue(false)
    await service.initialize()

    await expect(service.update({ startAtLogin: true })).rejects.toThrow()
    expect(runtime.setStartAtLogin.mock.calls).toEqual([[true], [false]])
    await expect(readFile(join(directory, 'settings.json'))).rejects.toMatchObject({
      code: 'ENOENT'
    })
    service.dispose()
  })

  it('does not touch the OS login item when the settings file is unavailable', async () => {
    const settingsPath = join(directory, 'settings-directory')
    await mkdir(settingsPath)
    const { service, runtime } = createService(settingsPath)
    let enabled = false
    runtime.getStartAtLoginStatus.mockImplementation(() => ({
      available: true,
      enabled,
      needsApproval: false
    }))
    runtime.setStartAtLogin.mockImplementation((next: boolean) => {
      enabled = next
      return true
    })
    await service.initialize()

    await expect(service.update({ startAtLogin: true })).rejects.toMatchObject({
      code: 'INTERNAL_ERROR'
    })
    expect(runtime.setStartAtLogin).not.toHaveBeenCalled()
    expect(enabled).toBe(false)
    service.dispose()
  })

  it('rejects malformed persisted SSH agent settings and keeps secure defaults', async () => {
    const settingsPath = join(directory, 'settings.json')
    await writeFile(
      settingsPath,
      JSON.stringify({
        version: 3,
        contentProtection: true,
        showWebsiteIcons: true,
        autoLockMinutes: 15,
        lockOnScreenLock: true,
        lockOnSuspend: true,
        clearClipboardSeconds: 30,
        defaultSort: 'recent',
        theme: 'system',
        sshAgentEnabled: true,
        sshAgentPromptBehavior: 'ask-every-time'
      })
    )
    const { service } = createService(settingsPath)
    await service.initialize()
    await expect(service.get()).resolves.toMatchObject({
      sshAgentEnabled: false,
      sshAgentPromptBehavior: 'always'
    })
    service.dispose()
  })

  it.each([
    '{"version":10,"unknown":"future"}',
    '{"version":5,"contentProtection":true,"showWebsiteIcons":true,"startAtLogin":false,"vaultTimeoutPolicy":{"type":"systemIdle"},"lockOnScreenLock":true,"lockOnSuspend":true,"clearClipboardSeconds":30,"defaultSort":"recent","theme":"system","sshAgentEnabled":false,"sshAgentPromptBehavior":"always"}',
    '{"version":5,"contentProtection":true,"showWebsiteIcons":true,"startAtLogin":false,"vaultTimeoutPolicy":{"type":"appInactivity","minutes":0},"lockOnScreenLock":true,"lockOnSuspend":true,"clearClipboardSeconds":30,"defaultSort":"recent","theme":"system","sshAgentEnabled":false,"sshAgentPromptBehavior":"always"}',
    '{"version":5,"contentProtection":true,"showWebsiteIcons":true,"startAtLogin":false,"vaultTimeoutPolicy":{"type":"onRestart","minutes":15},"lockOnScreenLock":true,"lockOnSuspend":true,"clearClipboardSeconds":30,"defaultSort":"recent","theme":"system","sshAgentEnabled":false,"sshAgentPromptBehavior":"always"}',
    '{"version":5,"contentProtection":true,"showWebsiteIcons":true,"startAtLogin":false,"vaultTimeoutPolicy":{"type":"onRestart"},"lockOnScreenLock":true,"lockOnSuspend":true,"clearClipboardSeconds":30,"defaultSort":"recent","theme":"system","sshAgentEnabled":false,"sshAgentPromptBehavior":"always","unexpected":true}',
    '{not json'
  ])('fails closed without overwriting corrupt or future settings bytes: %s', async (bytes) => {
    const settingsPath = join(directory, 'settings.json')
    await writeFile(settingsPath, bytes)
    const { service } = createService(settingsPath)
    await service.initialize()

    await expect(service.get()).resolves.toMatchObject({
      vaultTimeoutPolicy: { type: 'appInactivity', minutes: 15 }
    })
    await expect(service.update({ theme: 'dark' })).rejects.toMatchObject({
      code: 'INTERNAL_ERROR'
    })
    await expect(readFile(settingsPath, 'utf8')).resolves.toBe(bytes)
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
    const failedWrite = vi
      .fn<(path: string, data: string | Buffer) => Promise<void>>()
      .mockRejectedValue(new Error('disk full'))
    const { service, runtime } = createService(undefined, failedWrite)
    await service.initialize()

    await expect(
      service.update({ contentProtection: true, clearClipboardSeconds: 120 })
    ).rejects.toThrow()
    expect(await service.get()).toMatchObject({
      contentProtection: false,
      clearClipboardSeconds: 30
    })
    expect(runtime.applyContentProtection).toHaveBeenLastCalledWith(false)
    expect(runtime.applyClipboardTimeout).toHaveBeenLastCalledWith(30)
    expect(failedWrite).toHaveBeenCalledOnce()
    service.dispose()
  })

  it('keeps the persisted and runtime shortcut when a replacement is unavailable', async () => {
    const { service, runtime } = createService()
    await service.initialize()
    await service.update({ autofillEnabled: true })
    runtime.applyAutofillSettings.mockImplementation(
      ({ shortcut }: { shortcut: string }) => shortcut !== 'Command+Control+K'
    )

    await expect(service.update({ autofillShortcut: 'Command+Control+K' })).rejects.toThrow(
      'failed to register global autofill shortcut'
    )
    await expect(service.get()).resolves.toMatchObject({
      autofillEnabled: true,
      autofillShortcut: 'Control+\\'
    })
    expect(runtime.applyAutofillSettings).toHaveBeenLastCalledWith({
      enabled: true,
      shortcut: 'Control+\\'
    })
    expect(JSON.parse(await readFile(join(directory, 'settings.json'), 'utf8'))).toMatchObject({
      autofillShortcut: 'Control+\\'
    })
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

  it('gives an interactive request a fresh attempt after an automatic unlock fails', async () => {
    Object.defineProperty(process, 'platform', { value: 'darwin' })
    const { service, runtime } = createService()
    await service.initialize()
    await service.enableTouchId('fake-master-password')
    vi.mocked(systemPreferences.promptTouchID).mockClear()

    const automaticPrompt = deferred<void>()
    vi.mocked(systemPreferences.promptTouchID)
      .mockImplementationOnce(() => automaticPrompt.promise)
      .mockResolvedValueOnce(undefined)

    const automatic = service.unlockTouchId('automatic')
    await vi.waitFor(() => expect(systemPreferences.promptTouchID).toHaveBeenCalledOnce())
    const interactive = service.unlockTouchId()
    automaticPrompt.reject(new Error('cancelled'))

    await expect(automatic).rejects.toMatchObject({ code: 'TOUCH_ID_FAILED' })
    await expect(interactive).resolves.toEqual({ state: 'unlocked' })
    expect(systemPreferences.promptTouchID).toHaveBeenCalledTimes(2)
    expect(runtime.unlockVault).toHaveBeenCalledOnce()
    service.dispose()
  })

  it('retries decryption to complete safe storage key rotation without rewriting the capsule', async () => {
    Object.defineProperty(process, 'platform', { value: 'darwin' })
    const { service, runtime, touchIdPath } = createService()
    await service.initialize()
    await service.enableTouchId('fake-master-password')
    const originalCapsule = await readFile(touchIdPath)
    vi.mocked(safeStorage.encryptStringAsync).mockClear()
    vi.mocked(safeStorage.decryptStringAsync)
      .mockResolvedValueOnce({ result: '', shouldReEncrypt: true })
      .mockResolvedValueOnce({ result: 'fake-master-password', shouldReEncrypt: false })

    await expect(service.unlockTouchId()).resolves.toEqual({ state: 'unlocked' })

    expect(safeStorage.decryptStringAsync).toHaveBeenCalledTimes(2)
    expect(safeStorage.encryptStringAsync).not.toHaveBeenCalled()
    expect(await readFile(touchIdPath)).toEqual(originalCapsule)
    expect(runtime.unlockVault).toHaveBeenCalledWith('fake-master-password')
    service.dispose()
  })

  it('fails closed when a pending Touch ID unlock belongs to a disposed service', async () => {
    Object.defineProperty(process, 'platform', { value: 'darwin' })
    const { service, runtime } = createService()
    await service.initialize()
    await service.enableTouchId('fake-master-password')
    vi.mocked(systemPreferences.promptTouchID).mockClear()
    vi.mocked(safeStorage.decryptStringAsync).mockClear()

    let finishPrompt!: () => void
    vi.mocked(systemPreferences.promptTouchID).mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          finishPrompt = resolve
        })
    )

    const pending = service.unlockTouchId()
    await vi.waitFor(() => expect(systemPreferences.promptTouchID).toHaveBeenCalledOnce())
    service.dispose()
    service.dispose()
    finishPrompt()

    await expect(pending).rejects.toMatchObject({ code: 'TOUCH_ID_FAILED' })
    expect(safeStorage.decryptStringAsync).not.toHaveBeenCalled()
    expect(runtime.unlockVault).not.toHaveBeenCalled()
  })

  it('verifies one passkey operation without decrypting the stored unlock secret', async () => {
    Object.defineProperty(process, 'platform', { value: 'darwin' })
    const { service, store, runtime } = createService()
    await service.initialize()
    await service.enableTouchId('fake-master-password')
    vi.mocked(systemPreferences.promptTouchID).mockClear()
    vi.mocked(safeStorage.decryptStringAsync).mockClear()
    vi.mocked(store.unlock).mockClear()

    await expect(service.verifyTouchIdOperation('createPasskey')).resolves.toBeUndefined()
    await expect(service.verifyTouchIdOperation('usePasskey')).resolves.toBeUndefined()

    expect(systemPreferences.promptTouchID).toHaveBeenNthCalledWith(
      1,
      'Create a new BearWarden passkey'
    )
    expect(systemPreferences.promptTouchID).toHaveBeenNthCalledWith(
      2,
      'Sign in with a BearWarden passkey'
    )
    expect(safeStorage.decryptStringAsync).not.toHaveBeenCalled()
    expect(store.unlock).not.toHaveBeenCalled()
    expect(runtime.unlockVault).not.toHaveBeenCalled()
    service.dispose()
  })

  it('does not share one Touch ID verification across concurrent passkey requests', async () => {
    Object.defineProperty(process, 'platform', { value: 'darwin' })
    const { service } = createService()
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
    const first = service.verifyTouchIdOperation('usePasskey')
    await vi.waitFor(() => expect(systemPreferences.promptTouchID).toHaveBeenCalledOnce())
    await expect(service.verifyTouchIdOperation('usePasskey')).rejects.toMatchObject({
      code: 'TOUCH_ID_FAILED'
    })
    finishPrompt()
    await expect(first).resolves.toBeUndefined()
    expect(systemPreferences.promptTouchID).toHaveBeenCalledOnce()
    service.dispose()
  })

  it('requires Touch ID to be enabled and maps a canceled operation verification safely', async () => {
    Object.defineProperty(process, 'platform', { value: 'darwin' })
    const { service } = createService()
    await service.initialize()

    await expect(service.verifyTouchIdOperation('usePasskey')).rejects.toMatchObject({
      code: 'TOUCH_ID_UNAVAILABLE'
    })
    await service.enableTouchId('fake-master-password')
    vi.mocked(systemPreferences.promptTouchID).mockRejectedValueOnce(new Error('cancelled'))
    await expect(service.verifyTouchIdOperation('createPasskey')).rejects.toMatchObject({
      code: 'TOUCH_ID_FAILED'
    })
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

  it('forwards the persisted timeout policy and renderer activity to the main-process coordinator', async () => {
    const { service, timeoutCoordinator } = createService()
    await service.initialize()
    expect(timeoutCoordinator.updatePolicy).toHaveBeenLastCalledWith({
      type: 'appInactivity',
      minutes: 15
    })

    service.activity()
    expect(timeoutCoordinator.activity).toHaveBeenCalledOnce()

    await service.update({ vaultTimeoutPolicy: { type: 'onRestart' } })
    expect(timeoutCoordinator.updatePolicy).toHaveBeenLastCalledWith({ type: 'onRestart' })
    service.dispose()
    expect(timeoutCoordinator.dispose).toHaveBeenCalledOnce()
  })
})
