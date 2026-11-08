import { describe, expect, it, vi, type Mock } from 'vitest'
import { toLoginSummary } from '../../../shared/login-summary'
import type { LoginSummary, SharedLoginSummary } from '../../../shared/vault-contract'
import {
  createVaultItemAccess,
  tracksItemUsage,
  type CustomFieldLocator,
  type VaultItemAccess
} from './vault-item-access'
import { makeLoginView } from './vault-detail-test-fixtures'

const methods = [
  'revealSecret',
  'copyField',
  'revealCustomField',
  'copyCustomField',
  'getTotp',
  'copyTotp',
  'openUri'
] as const

type FakeNamespace = Record<(typeof methods)[number], Mock>

function fakeNamespace(): FakeNamespace {
  return Object.fromEntries(
    methods.map((method) => [method, vi.fn(async () => `${method}-result`)])
  ) as FakeNamespace
}

const personalItem: LoginSummary = toLoginSummary(makeLoginView({ id: 'personal', reprompt: 1 }))
const sharedItem: SharedLoginSummary = {
  ...toLoginSummary(makeLoginView({ id: 'shared' })),
  organizationId: 'org',
  collectionIds: [],
  shared: true,
  edit: true,
  viewPassword: true,
  delete: false,
  restore: false
}

interface Harness {
  access: VaultItemAccess
  logins: FakeNamespace
  sharedLogins: FakeNamespace
  withReprompt: Mock
}

function setup(): Harness {
  const logins = fakeNamespace()
  const sharedLogins = fakeNamespace()
  const withReprompt = vi.fn(
    (_ids: readonly string[], operation: (tokenFor: (id: string) => string) => Promise<unknown>) =>
      operation(() => 'reprompt-token')
  )
  const access = createVaultItemAccess({
    logins,
    sharedLogins,
    authorization: {
      token: (id) => (id === 'personal' ? 'cached-token' : undefined),
      withReprompt: withReprompt as never
    }
  })
  return { access, logins, sharedLogins, withReprompt }
}

const locator: CustomFieldLocator = {
  expectedUpdatedAt: '2026-07-16T00:00:00.000Z',
  source: { index: 0, name: 'PIN', type: 'hidden', linkedId: null }
}

describe('createVaultItemAccess', () => {
  it('sends personal item access through the reprompt with its token', async () => {
    const { access, logins, sharedLogins, withReprompt } = setup()

    await expect(access.revealSecret(personalItem, 'password')).resolves.toBe('revealSecret-result')
    await access.copyField(personalItem, 'uri', 1)
    await access.revealCustomField(personalItem, locator)
    await access.copyCustomField(personalItem, locator)
    await access.copyTotp(personalItem)
    await access.openUri(personalItem, 0)

    const token = { authorizationToken: 'reprompt-token' }
    expect(logins.revealSecret).toHaveBeenCalledWith({
      id: 'personal',
      field: 'password',
      ...token
    })
    expect(logins.copyField).toHaveBeenCalledWith({
      id: 'personal',
      field: 'uri',
      uriIndex: 1,
      ...token
    })
    expect(logins.revealCustomField).toHaveBeenCalledWith({ id: 'personal', ...locator, ...token })
    expect(logins.copyCustomField).toHaveBeenCalledWith({ id: 'personal', ...locator, ...token })
    expect(logins.copyTotp).toHaveBeenCalledWith({ id: 'personal', ...token })
    expect(logins.openUri).toHaveBeenCalledWith({ id: 'personal', uriIndex: 0, ...token })
    expect(withReprompt).toHaveBeenCalledTimes(6)
    for (const method of methods) expect(sharedLogins[method]).not.toHaveBeenCalled()
  })

  it('sends shared item access to the shared-login API without a reprompt or token', async () => {
    const { access, logins, sharedLogins, withReprompt } = setup()

    await access.revealSecret(sharedItem, 'password')
    await access.copyField(sharedItem, 'username')
    await access.revealCustomField(sharedItem, locator)
    await access.copyCustomField(sharedItem, locator)
    await access.copyTotp(sharedItem)
    await access.openUri(sharedItem, 2)
    await access.getTotp(sharedItem)

    expect(sharedLogins.revealSecret).toHaveBeenCalledWith({ id: 'shared', field: 'password' })
    expect(sharedLogins.copyField).toHaveBeenCalledWith({ id: 'shared', field: 'username' })
    expect(sharedLogins.revealCustomField).toHaveBeenCalledWith({ id: 'shared', ...locator })
    expect(sharedLogins.copyCustomField).toHaveBeenCalledWith({ id: 'shared', ...locator })
    expect(sharedLogins.copyTotp).toHaveBeenCalledWith({ id: 'shared' })
    expect(sharedLogins.openUri).toHaveBeenCalledWith({ id: 'shared', uriIndex: 2 })
    expect(sharedLogins.getTotp).toHaveBeenCalledWith({ id: 'shared' })
    expect(withReprompt).not.toHaveBeenCalled()
    for (const method of methods) expect(logins[method]).not.toHaveBeenCalled()
  })

  it('reads a personal TOTP code with the cached token and never prompts for it', async () => {
    const { access, logins, withReprompt } = setup()

    await access.getTotp(personalItem)

    expect(logins.getTotp).toHaveBeenCalledWith({
      id: 'personal',
      authorizationToken: 'cached-token'
    })
    expect(withReprompt).not.toHaveBeenCalled()
  })

  it('tracks usage only for personal items', () => {
    expect(tracksItemUsage(personalItem)).toBe(true)
    expect(tracksItemUsage(sharedItem)).toBe(false)
  })
})
