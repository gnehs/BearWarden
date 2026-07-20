import { describe, expect, it } from 'vitest'
import {
  canApproveSshAgentApproval,
  isWindowsSshAgentEndpoint,
  shouldDenySshAgentApproval,
  sshAgentSocketExportCommand,
  sshAgentStatusPresentation
} from './ssh-agent-ui'

describe('SSH Agent renderer policy', () => {
  it('fails closed for locked, unavailable, and concurrent approval events', () => {
    expect(shouldDenySshAgentApproval('locked', false)).toBe(true)
    expect(shouldDenySshAgentApproval('unavailable', false)).toBe(true)
    expect(shouldDenySshAgentApproval('unlocked', true)).toBe(true)
    expect(shouldDenySshAgentApproval('unlocked', false)).toBe(false)
  })

  it('requires a current master password only for reprompt-protected keys', () => {
    const request = { expiresAt: 2_000, requiresReprompt: true }
    expect(canApproveSshAgentApproval(request, '', 1_000)).toBe(false)
    expect(canApproveSshAgentApproval(request, 'correct horse', 1_000)).toBe(true)
    expect(canApproveSshAgentApproval(request, 'correct horse', 2_000)).toBe(false)
    expect(canApproveSshAgentApproval({ ...request, requiresReprompt: false }, '', 1_000)).toBe(
      true
    )
  })

  it('renders lifecycle states with a conservative status badge', () => {
    expect(sshAgentStatusPresentation(false, { state: 'ready' })).toEqual({
      label: '已停用',
      variant: 'secondary'
    })
    expect(sshAgentStatusPresentation(true, { state: 'ready' })).toEqual({
      label: '就緒',
      variant: 'default'
    })
    expect(sshAgentStatusPresentation(true, { state: 'error' })).toEqual({
      label: '需要處理',
      variant: 'destructive'
    })
  })

  it('quotes socket paths as POSIX literals and rejects line-oriented injection', () => {
    expect(sshAgentSocketExportCommand('/tmp/agent socket')).toBe(
      "export SSH_AUTH_SOCK='/tmp/agent socket'"
    )
    expect(sshAgentSocketExportCommand("/tmp/agent's socket")).toBe(
      "export SSH_AUTH_SOCK='/tmp/agent'\\''s socket'"
    )
    expect(sshAgentSocketExportCommand('/tmp/$(unsafe)')).toBe(
      "export SSH_AUTH_SOCK='/tmp/$(unsafe)'"
    )
    expect(sshAgentSocketExportCommand('/tmp/agent\nunsafe')).toBeUndefined()
    expect(sshAgentSocketExportCommand('/tmp/agent\tunsafe')).toBeUndefined()
    expect(isWindowsSshAgentEndpoint('\\\\.\\pipe\\openssh-ssh-agent')).toBe(true)
    expect(isWindowsSshAgentEndpoint('/tmp/agent')).toBe(false)
  })
})
