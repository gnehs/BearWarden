import { DndContext } from '@dnd-kit/core'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import type {
  CollectionView,
  OrganizationView,
  SharedLoginSummary
} from '../../../shared/vault-contract'
import { VaultOrganizationSidebarSection } from './VaultOrganizationSidebarSection'

vi.mock('./PaymentCardBrandMark', () => ({ default: () => <span /> }))
vi.mock('./WebsiteIcon', () => ({ default: () => <span /> }))

const organizations: OrganizationView[] = [
  {
    id: 'acme',
    name: 'Acme',
    status: 2,
    type: 0,
    enabled: true,
    identifier: null,
    hasPublicAndPrivateKeys: true
  },
  {
    id: 'northwind',
    name: 'Northwind',
    status: 2,
    type: 0,
    enabled: true,
    identifier: null,
    hasPublicAndPrivateKeys: true
  }
]

const collections: CollectionView[] = [
  {
    id: 'engineering',
    organizationId: 'acme',
    name: 'Engineering',
    externalId: null,
    readOnly: true,
    hidePasswords: false,
    manage: false,
    type: 0,
    assigned: true
  },
  {
    id: 'operations',
    organizationId: 'acme',
    name: 'Operations',
    externalId: null,
    readOnly: true,
    hidePasswords: false,
    manage: false,
    type: 0,
    assigned: true
  }
]

const sharedItems = [
  {
    id: 'multi-collection-login',
    organizationId: 'acme',
    collectionIds: ['engineering', 'operations']
  },
  {
    id: 'engineering-login',
    organizationId: 'acme',
    collectionIds: ['engineering']
  },
  {
    id: 'northwind-login',
    organizationId: 'northwind',
    collectionIds: []
  }
] as SharedLoginSummary[]

describe('VaultOrganizationSidebarSection', () => {
  it('renders organization hierarchy, deduplicated counts, and the active collection', () => {
    const markup = renderToStaticMarkup(
      <DndContext>
        <VaultOrganizationSidebarSection
          organizations={organizations}
          collections={collections}
          sharedItems={sharedItems}
          scope={{
            kind: 'collection',
            organizationId: 'acme',
            collectionId: 'engineering'
          }}
          onSelectAllShared={vi.fn()}
          onSelectOrganization={vi.fn()}
          onSelectCollection={vi.fn()}
        />
      </DndContext>
    )

    expect(markup).toContain('所有共用項目')
    expect(markup).toMatch(/所有共用項目<\/strong><small[^>]*>3<\/small>/)
    expect(markup).toMatch(/Acme<\/strong><small[^>]*>2<\/small>/)
    expect(markup).toMatch(/Engineering<\/strong><small[^>]*>2<\/small>/)
    expect(markup).toMatch(/Operations<\/strong><small[^>]*>1<\/small>/)
    expect(markup).toMatch(/aria-current="page"[\s\S]*Engineering/)
    expect(markup.indexOf('Acme')).toBeLessThan(markup.indexOf('Engineering'))
    expect(markup.indexOf('Engineering')).toBeLessThan(markup.indexOf('Northwind'))
  })
})
