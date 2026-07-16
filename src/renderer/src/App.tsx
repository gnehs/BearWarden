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
import { applyThemePreference } from './lib/theme'

type AppState = VaultState | 'loading' | 'unavailable'

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
  const [state, setState] = useState<AppState>('loading')
  const [retryKey, setRetryKey] = useState(0)
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
