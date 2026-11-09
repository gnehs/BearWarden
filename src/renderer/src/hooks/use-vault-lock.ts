import { useCallback, useEffect, useEffectEvent } from 'react'

export interface VaultLockOptions {
  /** Drops decrypted renderer state before the main process locks. */
  clearSessionSecrets: () => void
  onLocked: () => void
  onError: (error: unknown) => void
  onNotLocked: () => void
  isEditorDirty: () => boolean
  requestEditorTransition: (action: () => void) => void
}

/**
 * Locks the vault from the UI or on a main-process lock request, and reports the renderer
 * ready for lock requests only while the vault session is mounted.
 */
export function useVaultLock({
  clearSessionSecrets,
  onLocked,
  onError,
  onNotLocked,
  isEditorDirty,
  requestEditorTransition
}: VaultLockOptions): () => Promise<void> {
  const performLock = useCallback(async (): Promise<void> => {
    clearSessionSecrets()
    try {
      const status = await window.bearwarden.vault.lock()
      if (status.state === 'locked') onLocked()
      else onNotLocked()
    } catch (error) {
      onError(error)
    }
  }, [clearSessionSecrets, onError, onLocked, onNotLocked])

  const lock = useCallback(async (): Promise<void> => {
    if (isEditorDirty()) {
      requestEditorTransition(() => void performLock())
      return
    }
    await performLock()
  }, [isEditorDirty, performLock, requestEditorTransition])

  const onLockRequested = useEffectEvent(() => void lock())
  useEffect(() => {
    const unsubscribe = window.bearwarden.vault.onLockRequested(() => onLockRequested())
    window.bearwarden.vault.setLockRequestReady(true)
    return () => {
      window.bearwarden.vault.setLockRequestReady(false)
      unsubscribe()
    }
  }, [])

  return lock
}
