import type { AppTheme } from '../../../shared/vault-contract'

export function applyThemePreference(
  preference: AppTheme,
  darkMode = window.matchMedia('(prefers-color-scheme: dark)')
): void {
  const resolvedTheme = preference === 'system' ? (darkMode.matches ? 'dark' : 'light') : preference
  const root = document.documentElement
  root.dataset.themePreference = preference
  root.dataset.theme = resolvedTheme
  root.classList.toggle('dark', resolvedTheme === 'dark')
  root.classList.toggle('light', resolvedTheme === 'light')
}
