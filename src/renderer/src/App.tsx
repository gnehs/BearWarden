import { useEffect, useRef, useState } from 'react'
import type { SshAgentApprovalPrompt, VaultState } from '../../shared/vault-contract'
import AuthScreen from './components/AuthScreen'
import SshAgentApprovalDialog from './components/SshAgentApprovalDialog'
import VaultShell from './components/VaultShell'
import { shouldDenySshAgentApproval } from './lib/ssh-agent-ui'
import { applyThemePreference } from './lib/theme'

type AppState = VaultState | 'loading' | 'unavailable'

function denySshAgentApproval(request: SshAgentApprovalPrompt): void {
  void window.bearwarden.sshAgent
    .respondApproval({ requestId: request.requestId, approved: false })
    .catch(() => undefined)
}

function App(): React.JSX.Element {
  const [state, setState] = useState<AppState>('loading')
  const [retryKey, setRetryKey] = useState(0)
  const [sshAgentApproval, setSshAgentApproval] = useState<SshAgentApprovalPrompt | null>(null)
  const lastActivityAt = useRef(0)
  const stateRef = useRef<AppState>('loading')
  const sshAgentApprovalRef = useRef<SshAgentApprovalPrompt | null>(null)

  function updateState(nextState: AppState): void {
    stateRef.current = nextState
    setState(nextState)
  }

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
      const pending = sshAgentApprovalRef.current
      sshAgentApprovalRef.current = null
      setSshAgentApproval(null)
      if (pending) denySshAgentApproval(pending)
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
      if (shouldDenySshAgentApproval(stateRef.current, Boolean(sshAgentApprovalRef.current))) {
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
    if (state !== 'unlocked') return
    const reportActivity = (): void => {
      const now = Date.now()
      if (now - lastActivityAt.current < 10_000) return
      lastActivityAt.current = now
      void window.bearwarden.settings.activity().catch(() => undefined)
    }
    window.addEventListener('pointerdown', reportActivity, { passive: true })
    window.addEventListener('keydown', reportActivity)
    reportActivity()
    return () => {
      window.removeEventListener('pointerdown', reportActivity)
      window.removeEventListener('keydown', reportActivity)
    }
  }, [state])

  if (state === 'unlocked') {
    return (
      <>
        <VaultShell onLocked={() => updateState('locked')} />
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
      </>
    )
  }

  return (
    <AuthScreen
      state={state}
      onAuthenticated={() => updateState('unlocked')}
      onRetry={() => {
        updateState('loading')
        setRetryKey((key) => key + 1)
      }}
    />
  )
}

export default App
