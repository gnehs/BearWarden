import { useNavigate, useRouterState } from '@tanstack/react-router'
import type { Dispatch, SetStateAction } from 'react'
import { vaultPagePathFromPathname, type VaultPagePath } from './vault-paths'

export { vaultPagePathFromPathname } from './vault-paths'

interface VaultRouteState {
  settingsOpen: boolean
  setSettingsOpen: Dispatch<SetStateAction<boolean>>
  healthOpen: boolean
  setHealthOpen: Dispatch<SetStateAction<boolean>>
  sendsOpen: boolean
  setSendsOpen: Dispatch<SetStateAction<boolean>>
  organizationsOpen: boolean
  setOrganizationsOpen: Dispatch<SetStateAction<boolean>>
  emergencyAccessOpen: boolean
  setEmergencyAccessOpen: Dispatch<SetStateAction<boolean>>
}

type AuxiliaryVaultPagePath = Exclude<VaultPagePath, '/vault'>

function resolveValue<T>(value: SetStateAction<T>, current: T): T {
  return typeof value === 'function' ? (value as (current: T) => T)(current) : value
}

export function nextVaultPagePath(
  currentPath: VaultPagePath,
  targetPath: AuxiliaryVaultPagePath,
  value: SetStateAction<boolean>
): VaultPagePath | null {
  const isOpen = currentPath === targetPath
  const next = resolveValue(value, isOpen)
  if (next === isOpen) return null
  return next ? targetPath : '/vault'
}

export function useVaultRouteState(): VaultRouteState {
  const navigate = useNavigate()
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  const currentPath = vaultPagePathFromPathname(pathname)

  const navigatePage = (path: VaultPagePath): void => {
    void navigate({ to: path })
  }

  const pageSetter =
    (path: AuxiliaryVaultPagePath): Dispatch<SetStateAction<boolean>> =>
    (value) => {
      const nextPath = nextVaultPagePath(currentPath, path, value)
      if (nextPath) navigatePage(nextPath)
    }

  return {
    settingsOpen: currentPath === '/vault/settings',
    setSettingsOpen: pageSetter('/vault/settings'),
    healthOpen: currentPath === '/vault/health',
    setHealthOpen: pageSetter('/vault/health'),
    sendsOpen: currentPath === '/vault/sends',
    setSendsOpen: pageSetter('/vault/sends'),
    organizationsOpen: currentPath === '/vault/organizations',
    setOrganizationsOpen: pageSetter('/vault/organizations'),
    emergencyAccessOpen: currentPath === '/vault/emergency-access',
    setEmergencyAccessOpen: pageSetter('/vault/emergency-access')
  }
}
