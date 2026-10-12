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

/**
 * The system biometric prompt takes key focus and app activation away from the window, and macOS
 * hands them back only shortly after the prompt promise settles. Wait this long for that return
 * before treating the window as genuinely abandoned.
 */
const PROMPT_FOCUS_RETURN_GRACE_MS = 1000

export class FocusTouchIdUnlockController {
  private armed = true
  private blockedUntilBlur = false
  private inFlight: Promise<void> | null = null
  private focusReturned: (() => void) | null = null

  constructor(
    private readonly runtime: FocusTouchIdUnlockRuntime,
    private readonly focusReturnGraceMs = PROMPT_FOCUS_RETURN_GRACE_MS
  ) {}

  focus(): Promise<void> {
    if (!this.canInteract()) return this.inFlight ?? Promise.resolve()
    this.focusReturned?.()
    if (!this.armed || this.blockedUntilBlur || this.inFlight) {
      return this.inFlight ?? Promise.resolve()
    }
    this.armed = false

    const operation = this.tryUnlock()
      .catch(() => {
        // Cancellation and unavailable biometrics leave the vault locked without noisy UI.
      })
      .finally(() => {
        if (this.inFlight !== operation) return
        this.inFlight = null
        // A prompt-owned blur/focus cycle must not reopen a canceled prompt. If the user
        // is still away when it settles, however, the next focus is a fresh attempt.
        if (!this.canInteract()) {
          this.armed = true
          this.blockedUntilBlur = false
        }
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
    // A rejected prompt still has to consume its own focus return below.
    const status = await this.runtime.unlock().catch(() => null)
    const interactable = await this.waitForPromptFocusReturn()
    if (status?.state !== 'unlocked') return

    if (this.runtime.lockGeneration() !== lockGeneration || !interactable) {
      this.armed = true
      await this.runtime.lock()
      return
    }
    this.blockedUntilBlur = false
    this.runtime.notifyUnlocked()
  }

  /**
   * Resolves once the window is interactable again after the prompt closes, or with `false` when
   * the user really is elsewhere. Without this, the prompt-owned focus return would be mistaken
   * for a fresh focus and reopen a canceled prompt, or a successful unlock would be relocked.
   */
  private waitForPromptFocusReturn(): Promise<boolean> {
    if (this.canInteract() || this.runtime.isDestroyed()) return Promise.resolve(this.canInteract())
    return new Promise((resolve) => {
      const settle = (): void => {
        clearTimeout(timer)
        this.focusReturned = null
        resolve(this.canInteract())
      }
      const timer = setTimeout(settle, this.focusReturnGraceMs)
      this.focusReturned = settle
    })
  }

  private canInteract(): boolean {
    return !this.runtime.isDestroyed() && this.runtime.isActive() && this.runtime.isFocused()
  }
}
