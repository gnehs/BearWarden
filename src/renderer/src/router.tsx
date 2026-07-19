import {
  createHashHistory,
  createRootRoute,
  createRoute,
  createRouter,
  redirect
} from '@tanstack/react-router'
import App from './App'

const rootRoute = createRootRoute({
  component: App
})

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  beforeLoad: () => {
    throw redirect({ to: '/unlock', replace: true })
  }
})

export const unlockRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/unlock'
})

export const vaultRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/vault'
})

const routeTree = rootRoute.addChildren([indexRoute, unlockRoute, vaultRoute])

export const router = createRouter({
  routeTree,
  history: createHashHistory()
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
