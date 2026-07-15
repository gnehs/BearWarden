import type { SyncResult, SyncStatus } from '../shared/vault-contract'

const DEFAULT_AUTO_SYNC_DELAY_MS = 250

export interface AutoSyncVault {
  syncStatus: () => Promise<SyncStatus>
  syncNow: () => Promise<SyncResult>
}

export interface AutoSyncCoordinatorOptions {
  vault: AutoSyncVault
  onSyncChanged: (status: SyncStatus) => void
  onVaultChanged: () => void
  delayMs?: number
}

export class AutoSyncCoordinator {
  private timer: ReturnType<typeof setTimeout> | null = null
  private requested = false
  private running = false
  private disposed = false
  private readonly delayMs: number

  constructor(private readonly options: AutoSyncCoordinatorOptions) {
    this.delayMs = options.delayMs ?? DEFAULT_AUTO_SYNC_DELAY_MS
  }

  request(): void {
    if (this.disposed) return
    this.requested = true
    this.schedule()
  }

  cancel(): void {
    this.requested = false
    if (this.timer) clearTimeout(this.timer)
    this.timer = null
  }

  dispose(): void {
    this.disposed = true
    this.cancel()
  }

  private schedule(): void {
    if (this.disposed || this.running || this.timer || !this.requested) return
    this.timer = setTimeout(() => {
      this.timer = null
      void this.run()
    }, this.delayMs)
    this.timer.unref?.()
  }

  private async run(): Promise<void> {
    if (this.disposed || this.running || !this.requested) return
    this.requested = false
    this.running = true

    try {
      const status = await this.options.vault.syncStatus()
      if (status.state !== 'ready' && status.state !== 'error') {
        this.notifySyncChanged(status)
        return
      }

      const syncingStatus: SyncStatus = { ...status, state: 'syncing' }
      delete syncingStatus.lastError
      this.notifySyncChanged(syncingStatus)
      const result = await this.options.vault.syncNow()
      this.notifySyncChanged(result)
      this.notifyVaultChanged()
    } catch {
      try {
        this.notifySyncChanged(await this.options.vault.syncStatus())
      } catch {
        // Automatic sync is best-effort and must never reject a successful local change.
      }
    } finally {
      this.running = false
      this.schedule()
    }
  }

  private notifySyncChanged(status: SyncStatus): void {
    try {
      this.options.onSyncChanged(status)
    } catch {
      // Renderer notifications must not block or fail synchronization.
    }
  }

  private notifyVaultChanged(): void {
    try {
      this.options.onVaultChanged()
    } catch {
      // Renderer notifications must not block or fail synchronization.
    }
  }
}
