import { useEffect, useRef, useState } from 'react'
import type { VaultState } from '../../shared/vault-contract'
import AuthScreen from './components/AuthScreen'
import VaultShell from './components/VaultShell'
import { applyThemePreference } from './lib/theme'

type AppState = VaultState | 'loading' | 'unavailable'

function App(): React.JSX.Element {
  const [state, setState] = useState<AppState>('loading')
  const [retryKey, setRetryKey] = useState(0)
  const lastActivityAt = useRef(0)

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
    const unsubscribe = window.bearwarden.vault.onLocked(() => setState('locked'))

    window.bearwarden.vault
      .status()
      .then((status) => {
        if (active) setState(status.state)
      })
      .catch(() => {
        if (active) setState('unavailable')
      })

    return () => {
      active = false
      unsubscribe()
    }
  }, [retryKey])

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
    return <VaultShell onLocked={() => setState('locked')} />
  }

  return (
    <AuthScreen
      state={state}
      onAuthenticated={() => setState('unlocked')}
      onRetry={() => {
        setState('loading')
        setRetryKey((key) => key + 1)
      }}
    />
  )
}

export default App
