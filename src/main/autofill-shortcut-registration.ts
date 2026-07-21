import type { AutofillShortcut } from '../shared/autofill-shortcuts'

interface ShortcutRegistry {
  register(accelerator: string, callback: () => void): boolean
  unregister(accelerator: string): void
}

export class AutofillShortcutRegistration {
  private activeShortcut: AutofillShortcut | null = null
  private desiredEnabled = false
  private desiredShortcut: AutofillShortcut

  constructor(
    private readonly registry: ShortcutRegistry,
    initialShortcut: AutofillShortcut,
    private readonly onTrigger: () => void
  ) {
    this.desiredShortcut = initialShortcut
  }

  get enabled(): boolean {
    return this.desiredEnabled
  }

  get registered(): boolean {
    return this.activeShortcut === this.desiredShortcut
  }

  get shortcut(): AutofillShortcut {
    return this.desiredShortcut
  }

  apply(enabled: boolean, shortcut: AutofillShortcut): boolean {
    this.desiredEnabled = enabled
    this.desiredShortcut = shortcut
    if (!enabled) {
      this.unregisterActive()
      return true
    }
    if (this.activeShortcut === shortcut) return true

    let registered = false
    try {
      registered = this.registry.register(shortcut, this.onTrigger)
    } catch {
      registered = false
    }
    if (!registered) return false

    const previous = this.activeShortcut
    this.activeShortcut = shortcut
    if (previous) this.safeUnregister(previous)
    return true
  }

  retry(): boolean {
    return this.apply(this.desiredEnabled, this.desiredShortcut)
  }

  dispose(): void {
    this.desiredEnabled = false
    this.unregisterActive()
  }

  private unregisterActive(): void {
    const active = this.activeShortcut
    this.activeShortcut = null
    if (active) this.safeUnregister(active)
  }

  private safeUnregister(shortcut: AutofillShortcut): void {
    try {
      this.registry.unregister(shortcut)
    } catch {
      // Electron teardown must remain best-effort if the native registry is unavailable.
    }
  }
}
