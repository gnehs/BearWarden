import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import type { LoginView } from '../../../shared/vault-contract'
import {
  VaultItemMetadataCards,
  VaultItemNotesGroup,
  VaultItemPasskeyFootnote
} from './VaultItemMetadataCards'
import { emptyDocumentViewFields } from './vault-detail-test-fixtures'

vi.mock('./PaymentCardBrandMark', () => ({ default: () => <span /> }))
vi.mock('./WebsiteIcon', () => ({ default: () => <span /> }))

const login: LoginView = {
  ...emptyDocumentViewFields,
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
  it('shows organization and Collections while hiding personal-only actions', () => {
    const markup = renderToStaticMarkup(
      <VaultItemMetadataCards
        selectedLogin={login}
        formatDate={(value) => value ?? 'Never'}
        busy={false}
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

    expect(markup).toContain('>Home</strong>')
    expect(markup).toContain('>Default collection</strong>')
    expect(markup).not.toContain('aria-label="View password history"')
  })

  it('renders notes under a caption and a secure note without one', () => {
    const login_ = renderToStaticMarkup(<VaultItemNotesGroup selectedLogin={login} />)
    const note = renderToStaticMarkup(
      <VaultItemNotesGroup selectedLogin={{ type: 'secureNote', notes: '' }} />
    )

    expect(login_).toContain('<h3')
    expect(login_).toContain('>Network closet</p>')
    expect(note).not.toContain('<h3')
    expect(renderToStaticMarkup(<VaultItemPasskeyFootnote />)).toContain('<p')
  })

  it('shows personal password history and timestamps as a quiet footer', () => {
    const markup = renderToStaticMarkup(
      <VaultItemMetadataCards
        selectedLogin={{ ...login, passwordUpdatedAt: '2026-01-03T00:00:00.000Z' }}
        formatDate={(value) => `d:${value}`}
        busy={false}
        onViewPasswordHistory={vi.fn()}
      />
    )

    expect(markup).toContain('aria-label="檢視密碼歷程"')
    expect(markup).toContain('>d:2026-01-03T00:00:00.000Z</dd>')
    expect(markup).toContain('>d:2026-01-02T00:00:00.000Z</dd>')
    expect(markup).not.toContain('data-slot="card"')
  })
})
