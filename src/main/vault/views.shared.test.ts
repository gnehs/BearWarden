import { describe, expect, it } from 'vitest'
import type { StoredSharedLogin } from './types'
import { toSharedSummary, toSharedView } from './views'

function sharedLogin(overrides: Partial<StoredSharedLogin> = {}): StoredSharedLogin {
  return {
    id: '80000000-0000-4000-8000-000000000001',
    type: 'login',
    name: 'Shared login',
    username: 'member@example.invalid',
    password: 'not-renderer-visible',
    totp: 'NOT-RENDERER-VISIBLE',
    uri: 'https://example.invalid',
    uris: [{ uri: 'https://example.invalid', match: null }],
    notes: 'private note preview',
    folderId: null,
    favorite: false,
    lastUsedAt: null,
    deletedAt: null,
    archivedAt: null,
    reprompt: 0,
    cardholderName: '',
    brand: '',
    number: '',
    expMonth: '',
    expYear: '',
    code: '',
    title: '',
    firstName: '',
    middleName: '',
    lastName: '',
    address1: '',
    address2: '',
    address3: '',
    city: '',
    state: '',
    postalCode: '',
    country: '',
    company: '',
    email: '',
    phone: '',
    ssn: '',
    identityUsername: '',
    passportNumber: '',
    licenseNumber: '',
    privateKey: '',
    publicKey: '',
    fingerprint: '',
    passkeys: [],
    customFields: [],
    passwordHistory: [],
    passwordRevisionDate: '2026-07-13T00:00:00.000Z',
    autofillOnPageLoad: false,
    attachments: [],
    createdAt: '2026-07-13T00:00:00.000Z',
    updatedAt: '2026-07-14T00:00:00.000Z',
    usageCount: 0,
    organizationId: '60000000-0000-4000-8000-000000000001',
    collectionIds: ['70000000-0000-4000-8000-000000000001'],
    shared: true,
    edit: false,
    viewPassword: false,
    delete: false,
    restore: false,
    ...overrides
  }
}

describe('shared organization views', () => {
  it.each([
    { type: 'login' as const, username: 'sensitive username' },
    { type: 'secureNote' as const, notes: 'sensitive note preview' },
    { type: 'card' as const, number: '4111111111111234', brand: 'Visa' },
    { type: 'identity' as const, firstName: 'Sensitive', lastName: 'Identity' },
    { type: 'sshKey' as const, fingerprint: 'sensitive fingerprint' }
  ])('redacts $type list subtitles when passwords are hidden', (overrides) => {
    const summary = toSharedSummary(sharedLogin(overrides))

    expect(summary.subtitle).toBe('')
    expect(summary.username).toBe('')
    expect(summary.cardBrand).toBeUndefined()
    if (summary.type === 'login') expect(summary.hasTotp).toBe(false)
  })

  it('keeps editable non-secret detail fields while redacting hidden custom fields', () => {
    const view = toSharedView(
      sharedLogin({
        customFields: [
          { name: 'Environment', value: 'production', type: 'text', linkedId: null },
          { name: 'PIN', value: '1234', type: 'hidden', linkedId: null }
        ]
      })
    )

    expect(view.subtitle).toBe('member@example.invalid')
    expect(view.username).toBe('member@example.invalid')
    expect(view.notes).toBe('private note preview')
    expect(view.passwordUpdatedAt).toBe('2026-07-13T00:00:00.000Z')
    expect(view.customFields).toEqual([
      expect.objectContaining({ name: 'Environment', value: 'production' }),
      expect.objectContaining({ name: 'PIN', value: null })
    ])
  })

  it('keeps non-secret summary fields for general-view items', () => {
    const summary = toSharedSummary(sharedLogin({ viewPassword: true }))

    expect(summary.subtitle).toBe('member@example.invalid')
    expect(summary.username).toBe('member@example.invalid')
    expect(summary.hasTotp).toBe(true)
  })
})
