import type { BearWardenAPI } from '../shared/vault-contract'

declare global {
  interface Window {
    bearwarden: BearWardenAPI
  }
}

export {}
