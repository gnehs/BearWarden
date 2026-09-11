import { i18n } from '@lingui/core'
import { msg } from '@lingui/core/macro'
import type { AccountStatus } from '../../../shared/vault-contract'
import { localAccountDisplayLabel } from './account-switcher-ui'

export interface AuthSettingsRefreshTargets {
  window: Pick<Window, 'addEventListener' | 'removeEventListener'>
  document: Pick<Document, 'addEventListener' | 'removeEventListener' | 'visibilityState'>
}

/**
 * Refreshes settings while the lock screen is active so a transient Touch ID outage can recover
 * when the app regains focus or becomes visible again. The settings store owns stale-load ordering;
 * this helper only owns the browser subscriptions and their lifecycle.
 */
export function subscribeToAuthSettingsRefresh(
  loadSettings: () => Promise<unknown>,
  targets: AuthSettingsRefreshTargets = { window, document }
): () => void {
  let active = true
  const refresh = (): void => {
    if (!active) return
    void loadSettings().catch(() => undefined)
  }
  const refreshWhenVisible = (): void => {
    if (targets.document.visibilityState === 'visible') refresh()
  }

  refresh()
  targets.window.addEventListener('focus', refresh)
  targets.document.addEventListener('visibilitychange', refreshWhenVisible)

  return () => {
    active = false
    targets.window.removeEventListener('focus', refresh)
    targets.document.removeEventListener('visibilitychange', refreshWhenVisible)
  }
}

export function authAccountItems(
  status: AccountStatus | null
): readonly { readonly value: string; readonly label: string }[] {
  return (
    status?.accounts.map((account) => ({
      value: account.id,
      label: localAccountDisplayLabel(account)
    })) ?? []
  )
}

/**
 * Maps unlock/setup failures to stable, renderer-safe messages. `LOCKED` surfaces when a
 * concurrent lock (screen lock, suspend, timeout) wins against an in-flight unlock KDF; the
 * master password was not rejected, so the message must invite a retry instead of alarming.
 */
export function describeError(error: unknown): string {
  if (!(error instanceof Error)) return i18n._(msg`An unknown error occurred. Try again later.`)
  if (error.message.includes('INVALID_MASTER_PASSWORD'))
    return i18n._(msg`The master password is incorrect.`)
  if (error.message.includes('INVALID_PIN')) return i18n._(msg`The PIN is incorrect.`)
  if (error.message.includes('PIN_DISABLED'))
    return i18n._(msg`PIN unlock is disabled. Use your master password instead.`)
  if (error.message.includes('RATE_LIMITED'))
    return i18n._(msg`Too many attempts. Try again later.`)
  if (error.message.includes('INVALID_INPUT')) return i18n._(msg`Check your input.`)
  if (error.message.includes('LOCKED')) return i18n._(msg`The vault is locked. Try again.`)
  if (error.message.includes('CORRUPT_VAULT')) {
    return i18n._(
      msg`Unable to read vault data. Try again. If this continues, the vault file may be corrupted.`
    )
  }
  if (error.message.includes('NOT_INITIALIZED'))
    return i18n._(msg`The vault file was not found. Check that it has not been moved or deleted.`)
  return i18n._(msg`Unable to open the vault right now. Try again later.`)
}

export function touchIdUnlockFallback(error: unknown): {
  unlockMethod: 'master-password'
  error: string
} {
  return {
    unlockMethod: 'master-password',
    error:
      error instanceof Error && error.message.includes('TOUCH_ID_UNAVAILABLE')
        ? i18n._(
            msg`Biometric authentication is currently unavailable. Enter your master password.`
          )
        : i18n._(
            msg`Unable to open the vault with biometric authentication. Enter your master password.`
          )
  }
}
