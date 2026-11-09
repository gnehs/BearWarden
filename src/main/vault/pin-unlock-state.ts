import type { PinUnlockCapability } from '../pin-unlock'

/**
 * The enrolled PIN unlock capability and its lifecycle epoch. Every invalidation advances the
 * epoch, so a PIN enrollment or unlock that started before it fails instead of reinstalling or
 * using a revoked capability.
 */
export class VaultPinUnlockState {
  private enrolled: PinUnlockCapability | null = null
  private lifecycleEpoch = 0

  get capability(): PinUnlockCapability | null {
    return this.enrolled
  }

  get epoch(): number {
    return this.lifecycleEpoch
  }

  /** Replaces the enrolled capability, disposing the previous one. */
  install(capability: PinUnlockCapability): void {
    this.enrolled?.dispose()
    this.enrolled = capability
  }

  /** Forgets a capability that disabled itself, unless another one replaced it meanwhile. */
  forget(capability: PinUnlockCapability): void {
    if (this.enrolled === capability) this.enrolled = null
  }

  invalidate(): void {
    this.lifecycleEpoch += 1
    this.enrolled?.dispose()
    this.enrolled = null
  }
}

/** The one PIN operation sync and account flows need: revoking the enrolled capability. */
export type PinUnlockInvalidator = Pick<VaultPinUnlockState, 'invalidate'>
