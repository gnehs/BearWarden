import {
  createHashHistory,
  createRootRoute,
  createRoute,
  createRouter,
  redirect
} from '@tanstack/react-router'
import App from './App'
import type { VaultCategoryFilter } from './lib/vault-category'
import type { VaultSortMode } from './lib/vault-sort'

const vaultScopes = ['all', 'favorites', 'recent', 'folder', 'unfiled', 'archive', 'trash'] as const
const vaultCategories = [
  'all',
  'login',
  'card',
  'identity',
  'secureNote',
  'sshKey',
  'totp',
  'passkey'
] as const satisfies readonly VaultCategoryFilter[]
const vaultSortModes = ['title', 'recent', 'frequency', 'modified'] as const satisfies readonly VaultSortMode[]

export interface VaultSearch {
  scope?: (typeof vaultScopes)[number]
  folder?: string
  category?: VaultCategoryFilter
  item?: string
  editor?: 'create' | 'edit'
  sort?: VaultSortMode
  q?: string
}

function oneOf<T extends string>(value: unknown, values: readonly T[]): T | undefined {
  return typeof value === 'string' && values.includes(value as T) ? (value as T) : undefined
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

const rootRoute = createRootRoute({ component: App })

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  beforeLoad: () => {
    throw redirect({ to: '/unlock', replace: true })
  }
})

export const unlockRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'unlock'
})

export const vaultRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'vault',
  validateSearch: (search: Record<string, unknown>): VaultSearch => {
    const scope = oneOf(search.scope, vaultScopes)
    const folder = optionalString(search.folder)
    const category = oneOf(search.category, vaultCategories)
    const item = optionalString(search.item)
    const editor = oneOf(search.editor, ['create', 'edit'] as const)
    const sort = oneOf(search.sort, vaultSortModes)
    const q = optionalString(search.q)
    return {
      ...(scope ? { scope } : {}),
      ...(scope === 'folder' && folder ? { folder } : {}),
      ...(category && category !== 'all' ? { category } : {}),
      ...(item ? { item } : {}),
      ...(editor ? { editor } : {}),
      ...(sort && sort !== 'title' ? { sort } : {}),
      ...(q ? { q } : {})
    }
  }
})

const settingsRoute = createRoute({
  getParentRoute: () => vaultRoute,
  path: 'settings'
})
const healthRoute = createRoute({
  getParentRoute: () => vaultRoute,
  path: 'health'
})
const sendsRoute = createRoute({
  getParentRoute: () => vaultRoute,
  path: 'sends'
})
const organizationsRoute = createRoute({
  getParentRoute: () => vaultRoute,
  path: 'organizations'
})
const emergencyAccessRoute = createRoute({
  getParentRoute: () => vaultRoute,
  path: 'emergency-access'
})

const routeTree = rootRoute.addChildren([
  indexRoute,
  unlockRoute,
  vaultRoute.addChildren([
    settingsRoute,
    healthRoute,
    sendsRoute,
    organizationsRoute,
    emergencyAccessRoute
  ])
])

export type VaultPagePath =
  | '/vault'
  | '/vault/settings'
  | '/vault/health'
  | '/vault/sends'
  | '/vault/organizations'
  | '/vault/emergency-access'

export const router = createRouter({
  routeTree,
  history: createHashHistory()
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
