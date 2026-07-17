import { randomUUID } from 'node:crypto'
import { chmod, mkdir, open, readFile, rename, stat, unlink } from 'node:fs/promises'
import { dirname } from 'node:path'
import { safeStorage, systemPreferences } from 'electron'
import { MAX_VAULT_TIMEOUT_MINUTES } from '../shared/vault-contract'
import type {
  AppSettings,
  AppSettingsUpdate,
  VaultStatus,
  VaultTimeoutPolicy
} from '../shared/vault-contract'
import type { EncryptedVaultStore } from './encrypted-vault-store'
import { VaultError } from './vault-errors'
import type { VaultTimeoutCoordinator } from './vault-timeout-coordinator'

const SETTINGS_VERSION = 5
const MAX_SETTINGS_BYTES = 16 * 1024
const MAX_TOUCH_ID_BYTES = 64 * 1024

interface StoredSettings extends Omit<
  AppSettings,
  'startAtLoginAvailable' | 'startAtLoginNeedsApproval' | 'touchIdAvailable' | 'touchIdEnabled'
> {
  version: typeof SETTINGS_VERSION
}

export interface StartAtLoginStatus {
  available: boolean
  enabled: boolean
  needsApproval: boolean
}

export interface AppSettingsRuntime {
  applyContentProtection: (enabled: boolean) => void
  applyClipboardTimeout: (seconds: AppSettings['clearClipboardSeconds']) => void
  /**
   * Synchronously publishes persisted SSH-agent preferences to the main-process owner.
   * The runtime owns any asynchronous socket lifecycle work.
   */
  applySshAgentSettings: (settings: {
    enabled: boolean
    promptBehavior: AppSettings['sshAgentPromptBehavior']
  }) => void
  getStartAtLoginStatus: () => StartAtLoginStatus
  /** Applies the preference and confirms the OS reports the requested state. */
  setStartAtLogin: (enabled: boolean) => boolean
  unlockVault: (masterPassword: string) => Promise<VaultStatus>
}

function defaultSettings(): StoredSettings {
  return {
    version: SETTINGS_VERSION,
    contentProtection: true,
    showWebsiteIcons: true,
    startAtLogin: false,
    vaultTimeoutPolicy: { type: 'appInactivity', minutes: 15 },
    lockOnScreenLock: true,
    lockOnSuspend: true,
    clearClipboardSeconds: 30,
    defaultSort: 'recent',
    theme: 'system',
    sshAgentEnabled: false,
    sshAgentPromptBehavior: 'always'
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function parseVaultTimeoutPolicy(value: unknown): VaultTimeoutPolicy {
  if (!isRecord(value)) throw new Error('invalid settings')
  const keys = Object.keys(value)
  if (value.type === 'onRestart' && keys.length === 1 && keys[0] === 'type') {
    return { type: 'onRestart' }
  }
  if (
    value.type === 'appInactivity' &&
    keys.length === 2 &&
    keys.includes('type') &&
    keys.includes('minutes') &&
    typeof value.minutes === 'number' &&
    Number.isSafeInteger(value.minutes) &&
    value.minutes >= 1 &&
    value.minutes <= MAX_VAULT_TIMEOUT_MINUTES
  ) {
    return { type: 'appInactivity', minutes: value.minutes }
  }
  throw new Error('invalid settings')
}

function parseSettings(value: unknown): { settings: StoredSettings; needsMigration: boolean } {
  if (
    !isRecord(value) ||
    (value.version !== 1 &&
      value.version !== 2 &&
      value.version !== 3 &&
      value.version !== 4 &&
      value.version !== SETTINGS_VERSION)
  ) {
    throw new Error('invalid settings')
  }
  const isV5 = value.version === SETTINGS_VERSION
  const autoLockMinutes = value.autoLockMinutes
  const clearClipboardSeconds = value.clearClipboardSeconds
  const legacyTimeoutValid =
    autoLockMinutes === 0 ||
    autoLockMinutes === 1 ||
    autoLockMinutes === 5 ||
    autoLockMinutes === 15 ||
    autoLockMinutes === 30 ||
    autoLockMinutes === 60
  if (
    isV5 &&
    (Object.keys(value).length !== 12 ||
      ![
        'version',
        'contentProtection',
        'showWebsiteIcons',
        'startAtLogin',
        'vaultTimeoutPolicy',
        'lockOnScreenLock',
        'lockOnSuspend',
        'clearClipboardSeconds',
        'defaultSort',
        'theme',
        'sshAgentEnabled',
        'sshAgentPromptBehavior'
      ].every((key) => Object.prototype.hasOwnProperty.call(value, key)))
  ) {
    throw new Error('invalid settings')
  }
  if (
    typeof value.contentProtection !== 'boolean' ||
    (value.version !== 1 && typeof value.showWebsiteIcons !== 'boolean') ||
    (value.version >= 4 && typeof value.startAtLogin !== 'boolean') ||
    (!isV5 && !legacyTimeoutValid) ||
    typeof value.lockOnScreenLock !== 'boolean' ||
    typeof value.lockOnSuspend !== 'boolean' ||
    (clearClipboardSeconds !== 0 &&
      clearClipboardSeconds !== 15 &&
      clearClipboardSeconds !== 30 &&
      clearClipboardSeconds !== 60 &&
      clearClipboardSeconds !== 120) ||
    (value.defaultSort !== 'recent' && value.defaultSort !== 'name') ||
    (value.theme !== 'system' && value.theme !== 'light' && value.theme !== 'dark') ||
    (value.version >= 3 && typeof value.sshAgentEnabled !== 'boolean') ||
    (value.version >= 3 &&
      value.sshAgentPromptBehavior !== 'always' &&
      value.sshAgentPromptBehavior !== 'never' &&
      value.sshAgentPromptBehavior !== 'rememberUntilLock')
  ) {
    throw new Error('invalid settings')
  }
  const vaultTimeoutPolicy = isV5
    ? parseVaultTimeoutPolicy(value.vaultTimeoutPolicy)
    : autoLockMinutes === 0
      ? ({ type: 'onRestart' } as const)
      : ({ type: 'appInactivity', minutes: autoLockMinutes as number } as const)
  return {
    needsMigration: !isV5,
    settings: {
      version: SETTINGS_VERSION,
      contentProtection: value.contentProtection,
      showWebsiteIcons: value.version === 1 ? false : (value.showWebsiteIcons as boolean),
      startAtLogin: value.version >= 4 ? (value.startAtLogin as boolean) : false,
      vaultTimeoutPolicy,
      lockOnScreenLock: value.lockOnScreenLock,
      lockOnSuspend: value.lockOnSuspend,
      clearClipboardSeconds,
      defaultSort: value.defaultSort,
      theme: value.theme,
      sshAgentEnabled: value.version >= 3 ? (value.sshAgentEnabled as boolean) : false,
      sshAgentPromptBehavior:
        value.version >= 3
          ? (value.sshAgentPromptBehavior as AppSettings['sshAgentPromptBehavior'])
          : 'always'
    }
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isFile()
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false
    throw error
  }
}

async function atomicWrite(path: string, data: string | Buffer): Promise<void> {
  const directory = dirname(path)
  await mkdir(directory, { recursive: true, mode: 0o700 })
  const temporaryPath = `${path}.${randomUUID()}.tmp`
  let handle: Awaited<ReturnType<typeof open>> | undefined
  try {
    handle = await open(temporaryPath, 'wx', 0o600)
    await handle.writeFile(data)
    await handle.sync()
    await handle.close()
    handle = undefined
    // Set the final mode before replacement so a failure cannot report an uncommitted write
    // after rename has already made the new settings authoritative.
    await chmod(temporaryPath, 0o600)
    await rename(temporaryPath, path)
    await syncDirectory(directory)
  } catch (error) {
    await handle?.close()
    await unlink(temporaryPath).catch(() => undefined)
    throw error
  }
}

async function syncDirectory(path: string): Promise<void> {
  let handle: Awaited<ReturnType<typeof open>> | undefined
  try {
    handle = await open(path, 'r')
    await handle.sync()
  } catch {
    // Directory fsync is not supported on every Electron target, notably Windows.
  } finally {
    // The rename is already authoritative; durability hints must not make callers believe it
    // failed to commit if a directory close is unsupported or transiently rejected.
    await handle?.close().catch(() => undefined)
  }
}

export class AppSettingsService {
  private settings: StoredSettings = defaultSettings()
  private touchIdUnlock: Promise<VaultStatus> | null = null
  private touchIdOperationInProgress = false
  private settingsUpdateTail: Promise<void> = Promise.resolve()
  private disposed = false
  private lifecycleEpoch = 0
  /** Corrupt or future bytes are readable only through secure defaults, never overwritten. */
  private persistenceUnavailable = false

  constructor(
    private readonly settingsPath: string,
    private readonly touchIdPath: string,
    private readonly vaultStore: EncryptedVaultStore<unknown>,
    private readonly runtime: AppSettingsRuntime,
    private readonly vaultTimeoutCoordinator: VaultTimeoutCoordinator,
    /** Test seam; production persists settings through durable copy-on-write replacement. */
    private readonly writeSettings: (
      path: string,
      data: string | Buffer
    ) => Promise<void> = atomicWrite
  ) {}

  async initialize(): Promise<void> {
    this.persistenceUnavailable = false
    this.settings = defaultSettings()
    let needsMigration = false
    try {
      const file = await readFile(this.settingsPath)
      if (file.length === 0 || file.length > MAX_SETTINGS_BYTES) throw new Error('invalid settings')
      const parsed = parseSettings(JSON.parse(file.toString('utf8')))
      this.settings = parsed.settings
      needsMigration = parsed.needsMigration
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        this.settings = defaultSettings()
        this.persistenceUnavailable = true
      }
    }
    const startAtLoginStatus = this.runtime.getStartAtLoginStatus()
    this.settings.startAtLogin = startAtLoginStatus.available ? startAtLoginStatus.enabled : false
    if (needsMigration) {
      // Copy-on-write: a failed migration leaves the original v1-v4 bytes untouched and can be
      // retried safely the next time this account runtime initializes.
      try {
        await this.writeSettings(this.settingsPath, `${JSON.stringify(this.settings)}\n`)
      } catch {
        // Keep using the parsed legacy policy for this process, but never let a later update
        // overwrite legacy bytes after a failed copy-on-write migration.
        this.persistenceUnavailable = true
      }
    }
    this.applyRuntimeSettings()
    this.vaultTimeoutCoordinator.updatePolicy(this.settings.vaultTimeoutPolicy)
  }

  async get(): Promise<AppSettings> {
    const touchIdAvailable = await this.touchIdAvailable()
    const startAtLoginStatus = this.runtime.getStartAtLoginStatus()
    return {
      ...this.settings,
      startAtLogin: startAtLoginStatus.available ? startAtLoginStatus.enabled : false,
      startAtLoginAvailable: startAtLoginStatus.available,
      startAtLoginNeedsApproval: startAtLoginStatus.available && startAtLoginStatus.needsApproval,
      touchIdAvailable,
      touchIdEnabled: touchIdAvailable && (await exists(this.touchIdPath))
    }
  }

  websiteIconsEnabled(): boolean {
    return this.settings.showWebsiteIcons
  }

  update(update: AppSettingsUpdate): Promise<AppSettings> {
    const operation = this.settingsUpdateTail.then(() => this.performUpdate(update))
    this.settingsUpdateTail = operation.then(
      () => undefined,
      () => undefined
    )
    return operation
  }

  private async performUpdate(update: AppSettingsUpdate): Promise<AppSettings> {
    if (this.persistenceUnavailable) throw new VaultError('INTERNAL_ERROR')
    const candidate = parseSettings({
      ...this.settings,
      ...update,
      version: SETTINGS_VERSION
    }).settings
    const previousStartAtLogin = this.runtime.getStartAtLoginStatus()
    if (update.startAtLogin !== undefined) {
      if (!previousStartAtLogin.available && update.startAtLogin) {
        throw new VaultError('INVALID_INPUT')
      }
      candidate.startAtLogin = previousStartAtLogin.available ? update.startAtLogin : false
      if (
        previousStartAtLogin.available &&
        candidate.startAtLogin !== previousStartAtLogin.enabled &&
        !this.runtime.setStartAtLogin(candidate.startAtLogin)
      ) {
        this.runtime.setStartAtLogin(previousStartAtLogin.enabled)
        throw new Error('failed to update OS login item')
      }
    } else {
      candidate.startAtLogin = previousStartAtLogin.available ? previousStartAtLogin.enabled : false
    }
    try {
      await this.writeSettings(this.settingsPath, `${JSON.stringify(candidate)}\n`)
    } catch (error) {
      if (
        update.startAtLogin !== undefined &&
        previousStartAtLogin.available &&
        candidate.startAtLogin !== previousStartAtLogin.enabled
      ) {
        this.runtime.setStartAtLogin(previousStartAtLogin.enabled)
      }
      throw error
    }
    this.settings = candidate
    this.applyRuntimeSettings()
    this.vaultTimeoutCoordinator.updatePolicy(this.settings.vaultTimeoutPolicy)
    return this.get()
  }

  async enableTouchId(masterPassword: string): Promise<AppSettings> {
    if (!(await this.touchIdAvailable())) throw new VaultError('TOUCH_ID_UNAVAILABLE')
    if (
      typeof masterPassword !== 'string' ||
      masterPassword.length === 0 ||
      masterPassword.length > 1024
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    const verified = await this.vaultStore.unlock(masterPassword)
    try {
      await systemPreferences.promptTouchID('啟用 Touch ID 解鎖 BearWarden')
      const encrypted = await safeStorage.encryptStringAsync(masterPassword)
      try {
        await atomicWrite(this.touchIdPath, encrypted)
      } finally {
        encrypted.fill(0)
      }
    } catch {
      throw new VaultError('TOUCH_ID_FAILED')
    } finally {
      verified.key.fill(0)
      verified.salt.fill(0)
    }
    return this.get()
  }

  async disableTouchId(): Promise<AppSettings> {
    await unlink(this.touchIdPath).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== 'ENOENT') throw error
    })
    return this.get()
  }

  unlockTouchId(): Promise<VaultStatus> {
    if (this.disposed) return Promise.reject(new VaultError('TOUCH_ID_FAILED'))
    if (this.touchIdUnlock) return this.touchIdUnlock

    const operation = this.performTouchIdUnlock().finally(() => {
      if (this.touchIdUnlock === operation) this.touchIdUnlock = null
    })
    this.touchIdUnlock = operation
    return operation
  }

  /**
   * Performs one operation-scoped biometric verification without decrypting or returning the
   * stored master password. Concurrent requests never share one successful Touch ID prompt.
   */
  async verifyTouchIdOperation(operation: 'createPasskey' | 'usePasskey'): Promise<void> {
    if (!(await this.touchIdAvailable()) || !(await exists(this.touchIdPath))) {
      throw new VaultError('TOUCH_ID_UNAVAILABLE')
    }
    if (this.touchIdOperationInProgress) throw new VaultError('TOUCH_ID_FAILED')
    this.touchIdOperationInProgress = true
    try {
      await systemPreferences.promptTouchID(
        operation === 'createPasskey'
          ? '建立新的 BearWarden 通行密鑰'
          : '使用 BearWarden 通行密鑰登入'
      )
    } catch {
      throw new VaultError('TOUCH_ID_FAILED')
    } finally {
      this.touchIdOperationInProgress = false
    }
  }

  private async performTouchIdUnlock(): Promise<VaultStatus> {
    const operationEpoch = this.lifecycleEpoch
    this.assertCurrent(operationEpoch)
    if (!(await this.touchIdAvailable())) {
      throw new VaultError('TOUCH_ID_UNAVAILABLE')
    }
    this.assertCurrent(operationEpoch)
    if (!(await exists(this.touchIdPath))) throw new VaultError('TOUCH_ID_UNAVAILABLE')
    this.assertCurrent(operationEpoch)
    let encrypted: Buffer | undefined
    let masterPassword: string | undefined
    try {
      await systemPreferences.promptTouchID('使用 Touch ID 解鎖 BearWarden')
      this.assertCurrent(operationEpoch)
      encrypted = await readFile(this.touchIdPath)
      this.assertCurrent(operationEpoch)
      if (encrypted.length === 0 || encrypted.length > MAX_TOUCH_ID_BYTES) {
        throw new VaultError('TOUCH_ID_FAILED')
      }
      const decrypted = await safeStorage.decryptStringAsync(encrypted)
      masterPassword = decrypted.result
      this.assertCurrent(operationEpoch)
      if (decrypted.shouldReEncrypt) {
        const refreshed = await safeStorage.encryptStringAsync(masterPassword)
        try {
          this.assertCurrent(operationEpoch)
          await atomicWrite(this.touchIdPath, refreshed)
        } finally {
          refreshed.fill(0)
        }
        this.assertCurrent(operationEpoch)
      }
      const status = await this.runtime.unlockVault(masterPassword)
      this.assertCurrent(operationEpoch)
      return status
    } catch {
      throw new VaultError('TOUCH_ID_FAILED')
    } finally {
      encrypted?.fill(0)
      masterPassword = undefined
    }
  }

  activity(): void {
    this.vaultTimeoutCoordinator.activity()
  }

  shouldLockOnScreenLock(): boolean {
    return this.settings.lockOnScreenLock
  }

  shouldLockOnSuspend(): boolean {
    return this.settings.lockOnSuspend
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.lifecycleEpoch += 1
    this.vaultTimeoutCoordinator.dispose()
  }

  private assertCurrent(operationEpoch: number): void {
    if (this.disposed || operationEpoch !== this.lifecycleEpoch) {
      throw new VaultError('TOUCH_ID_FAILED')
    }
  }

  private async touchIdAvailable(): Promise<boolean> {
    if (process.platform !== 'darwin') return false
    try {
      return (
        systemPreferences.canPromptTouchID() && (await safeStorage.isAsyncEncryptionAvailable())
      )
    } catch {
      return false
    }
  }

  private applyRuntimeSettings(): void {
    this.runtime.applyContentProtection(this.settings.contentProtection)
    this.runtime.applyClipboardTimeout(this.settings.clearClipboardSeconds)
    this.runtime.applySshAgentSettings({
      enabled: this.settings.sshAgentEnabled,
      promptBehavior: this.settings.sshAgentPromptBehavior
    })
  }
}
