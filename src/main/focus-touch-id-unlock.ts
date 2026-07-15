import type { AppSettings, VaultStatus } from '../shared/vault-contract'

export interface FocusTouchIdUnlockRuntime {
  isActive: () => boolean
  isFocused: () => boolean
  isDestroyed: () => boolean
  lockGeneration: () => number
  vaultStatus: () => Promise<VaultStatus>
  settings: () => Promise<AppSettings>
  unlock: () => Promise<VaultStatus>
  lock: () => Promise<void>
  notifyUnlocked: () => void
}

export class FocusTouchIdUnlockController {
  private armed = true
  private blockedUntilBlur = false
  private inFlight: Promise<void> | null = null

  constructor(private readonly runtime: FocusTouchIdUnlockRuntime) {}

  focus(): Promise<void> {
    if (!this.armed || this.blockedUntilBlur || this.inFlight) {
      return this.inFlight ?? Promise.resolve()
    }
    this.armed = false

    const operation = this.tryUnlock()
      .catch(() => {
        // Cancellation and unavailable biometrics leave the vault locked without noisy UI.
      })
      .finally(() => {
        if (this.inFlight === operation) this.inFlight = null
      })
    this.inFlight = operation
    return operation
  }

  blur(): void {
    if (this.inFlight) return
    this.armed = true
    this.blockedUntilBlur = false
  }

  lockedWhileFocused(): Promise<void> {
    if (this.blockedUntilBlur || this.inFlight || !this.canInteract()) {
      return this.inFlight ?? Promise.resolve()
    }
    this.armed = true
    return this.focus()
  }

  private async tryUnlock(): Promise<void> {
    if (!this.canInteract()) return
    const lockGeneration = this.runtime.lockGeneration()
    if ((await this.runtime.vaultStatus()).state !== 'locked' || !this.canInteract()) return

    const settings = await this.runtime.settings()
    if (!settings.touchIdAvailable || !settings.touchIdEnabled || !this.canInteract()) return

    this.blockedUntilBlur = true
    const status = await this.runtime.unlock()
    if (status.state !== 'unlocked') return

    if (this.runtime.lockGeneration() !== lockGeneration || !this.canInteract()) {
      this.armed = true
      await this.runtime.lock()
      return
    }
    this.blockedUntilBlur = false
    this.runtime.notifyUnlocked()
  }

  private canInteract(): boolean {
    return !this.runtime.isDestroyed() && this.runtime.isActive() && this.runtime.isFocused()
  }
}
