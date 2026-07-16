import type {
  SshAgentApprovalPrompt,
  SshAgentStatus,
  VaultState
} from '../../../shared/vault-contract'

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
      return { label: 'Git 簽署', detail: '此程式要求使用 SSH 金鑰簽署 Git 內容。' }
    case 'file':
      return { label: '檔案簽署', detail: '此程式要求使用 SSH 金鑰簽署檔案內容。' }
    case 'unsupported':
      return {
        label: '未知 SSHSIG',
        detail: '簽署用途不在 BearWarden 可辨識的 SSHSIG 命名空間內。'
      }
    default:
      return { label: 'SSH 驗證', detail: '此程式要求使用 SSH 金鑰進行驗證或簽署。' }
  }
}

export function formatSshAgentExpiry(expiresAt: number, now = Date.now()): string {
  const remainingSeconds = Math.max(0, Math.ceil((expiresAt - now) / 1_000))
  return remainingSeconds > 0 ? `此要求將在約 ${remainingSeconds} 秒後過期。` : '此要求已過期。'
}

export function sshAgentStatusPresentation(
  enabled: boolean,
  status: Pick<SshAgentStatus, 'state'>
): { label: string; variant: 'default' | 'secondary' | 'destructive' } {
  if (!enabled) return { label: '未啟用', variant: 'secondary' }
  if (status.state === 'ready') return { label: '已就緒', variant: 'default' }
  if (status.state === 'starting') return { label: '正在啟動', variant: 'secondary' }
  if (status.state === 'error') return { label: '需要處理', variant: 'destructive' }
  return { label: '已停止', variant: 'secondary' }
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
