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
  private inFlight: Promise<void> | null = null

  constructor(private readonly runtime: FocusTouchIdUnlockRuntime) {}

  focus(): Promise<void> {
    if (!this.armed || this.inFlight) return this.inFlight ?? Promise.resolve()
    this.armed = false

    const operation = this.tryUnlock()
      .catch(() => {
        // Cancellation and unavailable biometrics leave the vault locked without noisy UI.
      })
      .finally(() => {
        if (this.inFlight === operation) this.inFlight = null
        if (!this.runtime.isActive()) this.armed = true
      })
    this.inFlight = operation
    return operation
  }

  blur(): void {
    if (!this.inFlight) this.armed = true
  }

  private async tryUnlock(): Promise<void> {
    if (!this.canInteract()) return
    const lockGeneration = this.runtime.lockGeneration()
    if ((await this.runtime.vaultStatus()).state !== 'locked' || !this.canInteract()) return

    const settings = await this.runtime.settings()
    if (!settings.touchIdAvailable || !settings.touchIdEnabled || !this.canInteract()) return

    const status = await this.runtime.unlock()
    if (status.state !== 'unlocked') return

    if (this.runtime.lockGeneration() !== lockGeneration || !this.canInteract()) {
      this.armed = true
      await this.runtime.lock()
      return
    }
    this.runtime.notifyUnlocked()
  }

  private canInteract(): boolean {
    return !this.runtime.isDestroyed() && this.runtime.isActive() && this.runtime.isFocused()
  }
}
