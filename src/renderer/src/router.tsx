import {
  createHashHistory,
  createRootRoute,
  createRoute,
  createRouter,
  redirect
} from '@tanstack/react-router'
import App from './App'

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
  path: 'vault'
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

export type { VaultPagePath } from './lib/vault-paths'

export const router = createRouter({
  routeTree,
  history: createHashHistory()
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
