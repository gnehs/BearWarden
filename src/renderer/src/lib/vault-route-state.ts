import { useNavigate, useRouterState } from '@tanstack/react-router'
import type { Dispatch, SetStateAction } from 'react'
import { vaultRoute, type VaultPagePath } from '../router'
import type { VaultCategoryFilter } from './vault-category'
import type { VaultSortMode } from './vault-sort'

export type VaultScope =
  | { kind: 'all' }
  | { kind: 'favorites' }
  | { kind: 'recent' }
  | { kind: 'folder'; folderId: string }
  | { kind: 'unfiled' }
  | { kind: 'archive' }
  | { kind: 'trash' }

interface VaultRouteState {
  scope: VaultScope
  setScope: Dispatch<SetStateAction<VaultScope>>
  typeFilter: VaultCategoryFilter
  setTypeFilter: Dispatch<SetStateAction<VaultCategoryFilter>>
  query: string
  setQuery: Dispatch<SetStateAction<string>>
  selectedId: string | null
  setSelectedId: Dispatch<SetStateAction<string | null>>
  editorMode: 'create' | 'edit' | null
  setEditorMode: Dispatch<SetStateAction<'create' | 'edit' | null>>
  sortMode: VaultSortMode
  setSortMode: Dispatch<SetStateAction<VaultSortMode>>
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

function scopeFromSearch(search: ReturnType<typeof vaultRoute.useSearch>): VaultScope {
  if (search.scope === 'folder' && search.folder) return { kind: 'folder', folderId: search.folder }
  if (search.scope && search.scope !== 'folder') return { kind: search.scope }
  return { kind: 'all' }
}

export function vaultPagePathFromPathname(pathname: string): VaultPagePath {
  const normalizedPathname = pathname.replace(/\/+$/, '') || '/'
  switch (normalizedPathname) {
    case '/vault/settings':
      return '/vault/settings'
    case '/vault/health':
      return '/vault/health'
    case '/vault/sends':
      return '/vault/sends'
    case '/vault/organizations':
      return '/vault/organizations'
    case '/vault/emergency-access':
      return '/vault/emergency-access'
    default:
      return '/vault'
  }
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
  const search = vaultRoute.useSearch()
  const scope = scopeFromSearch(search)
  const typeFilter = search.category ?? 'all'
  const query = search.q ?? ''
  const selectedId = search.item ?? null
  const editorMode = search.editor ?? null
  const sortMode = search.sort ?? 'title'
  const currentPath = vaultPagePathFromPathname(pathname)

  const updateSearch = (
    update: (current: typeof search) => typeof search,
    replace = false
  ): void => {
    void navigate({ to: currentPath, search: update, replace })
  }

  const navigatePage = (path: VaultPagePath): void => {
    void navigate({ to: path, search: (current) => current })
  }

  const pageSetter =
    (path: AuxiliaryVaultPagePath): Dispatch<SetStateAction<boolean>> =>
    (value) => {
      const nextPath = nextVaultPagePath(currentPath, path, value)
      if (nextPath) navigatePage(nextPath)
    }

  return {
    scope,
    setScope: (value) => {
      const next = resolveValue(value, scope)
      updateSearch((current) => ({
        ...current,
        scope: next.kind === 'all' ? undefined : next.kind,
        folder: next.kind === 'folder' ? next.folderId : undefined
      }))
    },
    typeFilter,
    setTypeFilter: (value) => {
      const next = resolveValue(value, typeFilter)
      updateSearch((current) => ({
        ...current,
        category: next === 'all' ? undefined : next
      }))
    },
    query,
    setQuery: (value) => {
      const next = resolveValue(value, query)
      updateSearch((current) => ({ ...current, q: next || undefined }), true)
    },
    selectedId,
    setSelectedId: (value) => {
      const next = resolveValue(value, selectedId)
      updateSearch((current) => ({ ...current, item: next || undefined }))
    },
    editorMode,
    setEditorMode: (value) => {
      const next = resolveValue(value, editorMode)
      updateSearch((current) => ({ ...current, editor: next || undefined }))
    },
    sortMode,
    setSortMode: (value) => {
      const next = resolveValue(value, sortMode)
      updateSearch((current) => ({ ...current, sort: next === 'title' ? undefined : next }), true)
    },
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
