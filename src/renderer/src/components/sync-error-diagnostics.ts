import type { SyncErrorCode, SyncInvalidResponseStage } from '../../../shared/vault-contract'

export interface SyncDiagnosticInput {
  appVersion?: string
  code: SyncErrorCode
  detail?: SyncInvalidResponseStage
  occurredAt?: string
  serverUrl?: string
}

function diagnosticServerKind(serverUrl?: string): 'bitwarden-cloud' | 'self-hosted' | 'unknown' {
  if (!serverUrl) return 'unknown'
  try {
    const hostname = new URL(serverUrl).hostname.toLowerCase()
    return hostname === 'bitwarden.com' || hostname.endsWith('.bitwarden.com')
      ? 'bitwarden-cloud'
      : 'self-hosted'
  } catch {
    return 'unknown'
  }
}

/** Builds an allowlisted report. Account identifiers, URLs, payloads, and vault data are excluded. */
export function buildSyncDiagnosticReport(input: SyncDiagnosticInput): string {
  return [
    'BearWarden sync diagnostic',
    `App version: ${input.appVersion || 'unknown'}`,
    `Error code: ${input.code}`,
    `Problem section: ${input.detail || 'unknown'}`,
    `Occurred at: ${input.occurredAt || 'unknown'}`,
    `Server kind: ${diagnosticServerKind(input.serverUrl)}`,
    'Privacy: no account identifiers, server address, or vault contents are included.'
  ].join('\n')
}
