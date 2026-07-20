import { useMatch, useNavigate, useRouterState } from '@tanstack/react-router'
import { useEffect, useRef, useState } from 'react'
import type {
  PasskeyApprovalPrompt,
  SshAgentApprovalPrompt,
  VaultState
} from '../../shared/vault-contract'
import AuthScreen from './components/AuthScreen'
import PasskeyApprovalDialog from './components/PasskeyApprovalDialog'
import SshAgentApprovalDialog from './components/SshAgentApprovalDialog'
import VaultShell from './components/VaultShell'
import { shouldDenyPasskeyApproval } from './lib/passkey-approval-ui'
import { shouldPromptSyncSetup } from './lib/sync-setup-prompt'
import { applyThemePreference } from './lib/theme'
import { isVaultPagePath } from './lib/vault-paths'

type AppState = VaultState | 'loading' | 'unavailable'
const activityThrottleMs = 10_000

// eslint-disable-next-line react-refresh/only-export-components
export function vaultNavigationTarget(
  state: AppState,
  pathname: string
): '/vault' | '/unlock' | null {
  if (state === 'loading') return null
  if (state !== 'unlocked') return pathname === '/unlock' ? null : '/unlock'

  return isVaultPagePath(pathname) ? null : '/vault'
}

// The vault route hooks require an active /vault match. Authentication can complete one render
// before the route-guard effect commits its navigation, so do not mount VaultShell during that gap.
// eslint-disable-next-line react-refresh/only-export-components
export function shouldRenderVault(state: AppState, hasVaultMatch: boolean): boolean {
  return state === 'unlocked' && hasVaultMatch
}

/** Returns the timestamp to retain when renderer activity should reach the main process. */
// eslint-disable-next-line react-refresh/only-export-components
export function nextVaultActivityTimestamp(
  now: number,
  lastActivityAt: number,
  force = false
): number | null {
  return force || now - lastActivityAt >= activityThrottleMs ? now : null
}

function denySshAgentApproval(request: SshAgentApprovalPrompt): void {
  void window.bearwarden.sshAgent
    .respondApproval({ requestId: request.requestId, approved: false })
    .catch(() => undefined)
}

function denyPasskeyApproval(request: PasskeyApprovalPrompt): void {
  void window.bearwarden.passkeys
    .respondApproval({ requestId: request.requestId, approved: false })
    .catch(() => undefined)
}

function App(): React.JSX.Element {
  const navigate = useNavigate()
  const pathname = useRouterState({ select: (routerState) => routerState.location.pathname })
  const vaultMatch = useMatch({ from: '/vault', shouldThrow: false })
  const [state, setState] = useState<AppState>('loading')
  const [retryKey, setRetryKey] = useState(0)
  const [syncSetupPromptPending, setSyncSetupPromptPending] = useState(false)
  const [sshAgentApproval, setSshAgentApproval] = useState<SshAgentApprovalPrompt | null>(null)
  const [passkeyApproval, setPasskeyApproval] = useState<PasskeyApprovalPrompt | null>(null)
  const lastActivityAt = useRef(0)
  const stateRef = useRef<AppState>('loading')
  const sshAgentApprovalRef = useRef<SshAgentApprovalPrompt | null>(null)
  const passkeyApprovalRef = useRef<PasskeyApprovalPrompt | null>(null)

  function updateState(nextState: AppState): void {
    stateRef.current = nextState
    setState(nextState)
  }

  useEffect(() => {
    const target = vaultNavigationTarget(state, pathname)
    if (target) void navigate({ to: target, replace: true })
  }, [navigate, pathname, state])

  useEffect(() => {
    let active = true
    const darkMode = window.matchMedia('(prefers-color-scheme: dark)')
    const handleSystemTheme = (): void => {
      if (document.documentElement.dataset.themePreference === 'system') {
        applyThemePreference('system', darkMode)
      }
    }

    void window.bearwarden.settings.get().then(
      (settings) => {
        if (active) applyThemePreference(settings.theme, darkMode)
      },
      () => applyThemePreference('system', darkMode)
    )
    darkMode.addEventListener('change', handleSystemTheme)
    return () => {
      active = false
      darkMode.removeEventListener('change', handleSystemTheme)
    }
  }, [])

  useEffect(() => {
    let active = true
    let receivedStateEvent = false
    const unsubscribeLocked = window.bearwarden.vault.onLocked(() => {
      receivedStateEvent = true
      const pendingSshAgentApproval = sshAgentApprovalRef.current
      const pendingPasskeyApproval = passkeyApprovalRef.current
      sshAgentApprovalRef.current = null
      passkeyApprovalRef.current = null
      setSshAgentApproval(null)
      setPasskeyApproval(null)
      setSyncSetupPromptPending(false)
      if (pendingSshAgentApproval) denySshAgentApproval(pendingSshAgentApproval)
      if (pendingPasskeyApproval) denyPasskeyApproval(pendingPasskeyApproval)
      updateState('locked')
    })
    const unsubscribeUnlocked = window.bearwarden.vault.onUnlocked(() => {
      receivedStateEvent = true
      updateState('unlocked')
    })

    window.bearwarden.vault
      .status()
      .then((status) => {
        if (active && !receivedStateEvent) updateState(status.state)
      })
      .catch(() => {
        if (active && !receivedStateEvent) updateState('unavailable')
      })

    return () => {
      active = false
      unsubscribeLocked()
      unsubscribeUnlocked()
    }
  }, [retryKey])

  useEffect(() => {
    const unsubscribe = window.bearwarden.sshAgent.onApprovalRequested((request) => {
      // A prompt must never become an implicit approval while the UI is unavailable or locked.
      if (
        shouldDenyPasskeyApproval(
          stateRef.current,
          Boolean(sshAgentApprovalRef.current || passkeyApprovalRef.current)
        )
      ) {
        denySshAgentApproval(request)
        return
      }
      sshAgentApprovalRef.current = request
      setSshAgentApproval(request)
    })

    return () => {
      unsubscribe()
      const pending = sshAgentApprovalRef.current
      sshAgentApprovalRef.current = null
      if (pending) denySshAgentApproval(pending)
    }
  }, [])

  useEffect(() => {
    const unsubscribe = window.bearwarden.passkeys.onApprovalRequested((request) => {
      if (
        shouldDenyPasskeyApproval(
          stateRef.current,
          Boolean(sshAgentApprovalRef.current || passkeyApprovalRef.current)
        )
      ) {
        denyPasskeyApproval(request)
        return
      }
      passkeyApprovalRef.current = request
      setPasskeyApproval(request)
    })

    return () => {
      unsubscribe()
      const pending = passkeyApprovalRef.current
      passkeyApprovalRef.current = null
      if (pending) denyPasskeyApproval(pending)
    }
  }, [])

  useEffect(() => {
    if (state !== 'unlocked') return
    const reportActivity = (force = false): void => {
      const now = Date.now()
      const nextActivityAt = nextVaultActivityTimestamp(now, lastActivityAt.current, force)
      if (nextActivityAt === null) return
      lastActivityAt.current = nextActivityAt
      void window.bearwarden.settings.activity().catch(() => undefined)
    }
    const reportActivityFromEvent = (): void => reportActivity()
    window.addEventListener('pointerdown', reportActivityFromEvent, { passive: true })
    window.addEventListener('keydown', reportActivityFromEvent)
    window.addEventListener('wheel', reportActivityFromEvent, { passive: true })
    window.addEventListener('scroll', reportActivityFromEvent, { passive: true, capture: true })
    // A vault may have just been locked and unlocked within the throttle window.
    // Its new timeout epoch must still be armed without waiting for another UI event.
    lastActivityAt.current = 0
    reportActivity(true)
    return () => {
      window.removeEventListener('pointerdown', reportActivityFromEvent)
      window.removeEventListener('keydown', reportActivityFromEvent)
      window.removeEventListener('wheel', reportActivityFromEvent)
      window.removeEventListener('scroll', reportActivityFromEvent, { capture: true })
      lastActivityAt.current = 0
    }
  }, [state])

  if (shouldRenderVault(state, Boolean(vaultMatch))) {
    return (
      <>
        <VaultShell
          onLocked={() => updateState('locked')}
          promptSyncSetup={syncSetupPromptPending}
          onSyncSetupPromptHandled={() => setSyncSetupPromptPending(false)}
        />
        {sshAgentApproval && (
          <SshAgentApprovalDialog
            request={sshAgentApproval}
            onRespond={(response) => window.bearwarden.sshAgent.respondApproval(response)}
            onSettled={() => {
              if (sshAgentApprovalRef.current?.requestId !== sshAgentApproval.requestId) return
              sshAgentApprovalRef.current = null
              setSshAgentApproval(null)
            }}
          />
        )}
        {passkeyApproval && (
          <PasskeyApprovalDialog
            request={passkeyApproval}
            onVerifyPassword={(request) => window.bearwarden.passkeys.verifyApproval(request)}
            onRespond={(response) => window.bearwarden.passkeys.respondApproval(response)}
            onSettled={() => {
              if (passkeyApprovalRef.current?.requestId !== passkeyApproval.requestId) return
              passkeyApprovalRef.current = null
              setPasskeyApproval(null)
            }}
          />
        )}
      </>
    )
  }

  return (
    <AuthScreen
      state={state === 'unlocked' ? 'loading' : state}
      onAuthenticated={(source) => {
        setSyncSetupPromptPending(shouldPromptSyncSetup(source))
        updateState('unlocked')
      }}
      onRetry={() => {
        updateState('loading')
        setRetryKey((key) => key + 1)
      }}
    />
  )
}

export default App
