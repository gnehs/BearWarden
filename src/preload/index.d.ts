import type { BearWardenAPI } from '../shared/ipc-api'

declare global {
  interface Window {
    bearwarden: BearWardenAPI
  }
}

export {}
