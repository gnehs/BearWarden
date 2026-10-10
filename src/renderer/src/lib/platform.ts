import { shouldUseApplicationTitlebarMenu } from './application-titlebar-menu'

export const isMac = navigator.userAgent.includes('Mac')
export const isWindows = navigator.userAgent.includes('Windows')
export const usesWindowControlsOverlay = shouldUseApplicationTitlebarMenu(navigator.userAgent)
