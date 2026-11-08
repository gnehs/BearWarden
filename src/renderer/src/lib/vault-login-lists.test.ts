import { describe, expect, it, vi } from 'vitest'
import type { LoginListRequest, LoginSummary } from '../../../shared/vault-contract'
import { listLoginsInAllStates } from './vault-login-lists'

function summariesFor(request: LoginListRequest | undefined): LoginSummary[] {
  const state = request?.deleted ? 'deleted' : request?.archived ? 'archived' : 'active'
  return [{ id: `${state}:${request?.query ?? ''}` } as LoginSummary]
}

describe('listLoginsInAllStates', () => {
  it('lists active, archived and trashed logins sorted by name', async () => {
    const list = vi.fn(async (request?: LoginListRequest) => summariesFor(request))

    const logins = await listLoginsInAllStates({ list })

    expect(logins.map((login) => login.id)).toEqual(['active:', 'archived:', 'deleted:'])
    expect(list.mock.calls).toEqual([
      [{ sort: 'name' }],
      [{ sort: 'name', archived: true }],
      [{ sort: 'name', deleted: true }]
    ])
  })

  it('applies the search query to every state', async () => {
    const list = vi.fn(async (request?: LoginListRequest) => summariesFor(request))

    const logins = await listLoginsInAllStates({ list }, 'github')

    expect(logins.map((login) => login.id)).toEqual([
      'active:github',
      'archived:github',
      'deleted:github'
    ])
  })
})
