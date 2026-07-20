/// <reference types="vite/client" />
/// <reference types="unplugin-icons/types/react" />

declare module '*.po' {
  import type { Messages } from '@lingui/core'

  export const messages: Messages
}
