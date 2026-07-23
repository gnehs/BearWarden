import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import type { LoginView } from '../../../shared/vault-contract'
import { VaultItemMetadataCards } from './VaultItemMetadataCards'

vi.mock('./PaymentCardBrandMark', () => ({ default: () => <span /> }))
vi.mock('./WebsiteIcon', () => ({ default: () => <span /> }))

const login: LoginView = {
  id: 'shared-login',
  type: 'login',
  name: 'Router',
  subtitle: 'admin',
  username: 'admin',
  uri: 'https://router.example',
  uris: [{ uri: 'https://router.example', match: null }],
  passwordHistoryCount: 1,
  attachmentCount: 0,
  folderId: null,
  favorite: false,
  usageCount: 0,
  lastUsedAt: null,
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-02T00:00:00.000Z',
  deletedAt: null,
  archivedAt: null,
  reprompt: 0,
  passwordUpdatedAt: null,
  notes: 'Network closet',
  hasTotp: false,
  passkeys: [
    {
      credentialId: 'credential',
      rpId: 'router.example',
      rpName: 'Router',
      userHandle: 'user',
      userName: 'admin',
      userDisplayName: 'Admin',
      discoverable: true,
      creationDate: '2026-01-01T00:00:00.000Z'
    }
  ],
  customFields: [],
  attachments: [],
  cardholderName: '',
  brand: '',
  expMonth: '',
  expYear: '',
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
  identityUsername: '',
  publicKey: '',
  fingerprint: ''
}

describe('VaultItemMetadataCards shared presentation', () => {
  it('reuses the standard cards while replacing personal-only organization actions', () => {
    const markup = renderToStaticMarkup(
      <VaultItemMetadataCards
        selectedLogin={login}
        folders={[]}
        formatDate={(value) => value ?? 'Never'}
        busy={false}
        onMoveToFolder={vi.fn()}
        onViewPasswordHistory={vi.fn()}
        sharedContext={{
          organization: {
            id: 'organization',
            name: 'Home',
            status: 2,
            type: 0,
            enabled: true,
            identifier: null,
            hasPublicAndPrivateKeys: true
          },
          collections: [
            {
              id: 'collection',
              organizationId: 'organization',
              name: 'Default collection',
              externalId: null,
              readOnly: true,
              hidePasswords: false,
              manage: false,
              type: 0,
              assigned: true
            }
          ]
        }}
      />
    )

    expect(markup).toContain('data-variant="item"')
    expect(markup).toContain('>Home</dd>')
    expect(markup).toContain('>Default collection</dd>')
    expect(markup).toContain('>Network closet</p>')
    expect(markup).not.toContain('aria-label="Move to folder"')
    expect(markup).not.toContain('aria-label="View password history"')
    expect(markup).not.toContain('safely delete passkeys')
  })
})
