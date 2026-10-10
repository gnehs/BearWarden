import { msg } from '@lingui/core/macro'
import type { SshAgentApprovalPrompt, SshAgentStatus } from '../../../shared/vault-contract'
import { i18n } from '../i18n'

const DEFAULT_UNIX_SOCKET = '$HOME/.bearwarden-ssh-agent.sock'

export function canApproveSshAgentApproval(
  request: Pick<SshAgentApprovalPrompt, 'expiresAt' | 'requiresReprompt'>,
  masterPassword: string,
  now = Date.now()
): boolean {
  return request.expiresAt > now && (!request.requiresReprompt || masterPassword.length > 0)
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
