import {
  createHashHistory,
  createRootRoute,
  createRoute,
  createRouter,
  redirect
} from '@tanstack/react-router'
import App from './App'

const rootRoute = createRootRoute({
  component: App,
  notFoundComponent: App
})

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  beforeLoad: () => {
    throw redirect({ to: '/unlock', replace: true })
  }
})

export const unlockRoute = createRoute({
 