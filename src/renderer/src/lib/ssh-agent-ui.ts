import { msg } from '@lingui/core/macro'
import type {
  SshAgentApprovalPrompt,
  SshAgentStatus,
  VaultState
} from '../../../shared/vault-contract'
import { i18n } from '../i18n'

const DEFAULT_UNIX_SOCKET = '$HOME/.bearwarden-ssh-agent.sock'

export function shouldDenySshAgentApproval(
  state: VaultState | 'loading' | 'unavailable',
  hasPendingApproval: boolean
): boolean {
  return state !== 'unlocked' || hasPendingApproval
}

export function canApproveSshAgentApproval(
  request: Pick<SshAgentApprovalPrompt, 'expiresAt' | 'requiresReprompt'>,
  masterPassword: string,
  now = Date.now()
): boolean {
  return request.expiresAt > now && (!request.requiresReprompt || masterPassword.length > 0)
}

export function sshAgentSigningPurpose(namespace: SshAgentApprovalPrompt['namespace']): {
  label: string
  detail: string
} {
  switch (namespace) {
    case 'git':
      return {
        label: i18n._(msg`Git signing`),
        detail: i18n._(msg`This application is requesting an SSH key to sign Git content.`)
      }
    case 'file':
      return {
        label: i18n._(msg`File signing`),
        detail: i18n._(msg`This application is requesting an SSH key to sign file content.`)
      }
    case 'unsupported':
      return {
        label: i18n._(msg`Unknown SSHSIG`),
        detail: i18n._(
          msg`The signing purpose is not in an SSHSIG namespace recognized by BearWarden.`
        )
      }
    default:
      return {
        label: i18n._(msg`SSH authentication`),
        detail: i18n._(
          msg`This application is requesting an SSH key for authentication or signing.`
        )
      }
  }
}

export function formatSshAgentExpiry(expiresAt: number, now = Date.now()): string {
  const remainingSeconds = Math.max(0, Math.ceil((expiresAt - now) / 1_000))
  return remainingSeconds > 0
    ? i18n._(msg`This request expires in about ${remainingSeconds} seconds.`)
    : i18n._(msg`This request has expired.`)
}

export function sshAgentStatusPresentation(
  enabled: boolean,
  status: Pick<SshAgentStatus, 'state'>
): { label: string; variant: 'default' | 'secondary' | 'destructive' } {
  if (!enabled) return { label: i18n._(msg`Disabled`), variant: 'secondary' }
  if (status.state === 'ready') return { label: i18n._(msg`Ready`), variant: 'default' }
  if (status.state === 'starting') return { label: i18n._(msg`Starting`), variant: 'secondary' }
  if (status.state === 'error')
    return { label: i18n._(msg`Action required`), variant: 'destructive' }
  return { label: i18n._(msg`Stopped`), variant: 'secondary' }
}

/** Safely prepares a shell assignment for a path supplied by the main process. */
export function sshAgentSocketExportCommand(endpoint: string | undefined): string | undefined {
  const socketPath = endpoint ?? DEFAULT_UNIX_SOCKET
  for (const character of socketPath) {
    const codePoint = character.codePointAt(0)
    if (codePoint !== undefined && (codePoint <= 0x1f || codePoint === 0x7f)) return undefined
  }
  if (endpoint === undefined) return `export SSH_AUTH_SOCK="${DEFAULT_UNIX_SOCKET}"`
  return `export SSH_AUTH_SOCK='${socketPath.replaceAll("'", "'\\''")}'`
}

export function isWindowsSshAgentEndpoint(endpoint: string | undefined): boolean {
  return endpoint?.startsWith('\\\\.\\pipe\\') ?? false
}
