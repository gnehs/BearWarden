import type { VaultReprompt } from '../shared/vault-contract'

/** Renderer-safe metadata for one login that matches the explicitly requested browser URL. */
export interface AutofillCandidate {
  readonly id: string
  readonly name: string
  readonly username: string
  readonly hostname: string
  readonly reprompt: VaultReprompt
  readonly updatedAt: string
}

export interface AutofillDiscoveryResult {
  readonly generation: number
  readonly targetUrl: string
  readonly candidates: readonly AutofillCandidate[]
}

/** Main-process-only secret material. It must never cross preload or renderer IPC. */
export interface AutofillCredentials {
  readonly username: string
  readonly password: string
}

export interface AutofillExecutionRequest {
  readonly itemId: string
  readonly targetUrl: string
  readonly expectedGeneration: number
  readonly expectedUpdatedAt: string
}

export type AutofillAuthorizationValidator = (
  ids: readonly string[],
  state: { generation: number }
) => boolean

export type AutofillCredentialConsumer = (credentials: AutofillCredentials) => Promise<void>
