import { describe, expect, it } from 'vitest'
import { vaultOrganizationSidebarCounts } from './vault-organization-sidebar'

describe('vault organization sidebar counts', () => {
  it('counts a multi-collection item once in its organization and once in each collection', () => {
    const counts = vaultOrganizationSidebarCounts([
      {
        id: 'shared-login',
        organizationId: 'organization',
        collectionIds: ['engineering', 'production']
      },
      {
        id: 'second-login',
        organizationId: 'organization',
        collectionIds: ['engineering']
      }
    ])

    expect(counts.allSharedItems).toBe(2)
    expect(Object.fromEntries(counts.byOrganization)).toEqual({ organization: 2 })
    expect(Object.fromEntries(counts.byCollection.get('organization') ?? [])).toEqual({
      engineering: 2,
      production: 1
    })
  })

  it('deduplicates repeated item records and repeated collection memberships', () => {
    const counts = vaultOrganizationSidebarCounts([
      {
        id: 'shared-login',
        organizationId: 'organization',
        collectionIds: ['engineering', 'engineering']
      },
      {
        id: 'shared-login',
        organizationId: 'organization',
        collectionIds: ['engineering', 'production']
      }
    ])

    expect(counts.allSharedItems).toBe(1)
    expect(counts.byOrganization.get('organization')).toBe(1)
    expect(counts.byCollection.get('organization')?.get('engineering')).toBe(1)
    expect(counts.byCollection.get('organization')?.get('production')).toBe(1)
  })

  it('keeps organization counts independent when collections have no items', () => {
    const counts = vaultOrganizationSidebarCounts([
      {
        id: 'first-login',
        organizationId: 'first-organization',
        collectionIds: []
      },
      {
        id: 'second-login',
        organizationId: 'second-organization',
        collectionIds: ['second-collection']
      }
    ])

    expect(counts.allSharedItems).toBe(2)
    expect(Object.fromEntries(counts.byOrganization)).toEqual({
      'first-organization': 1,
      'second-organization': 1
    })
    expect(counts.byCollection.get('first-organization')).toBeUndefined()
    expect(counts.byCollection.get('second-organization')?.get('second-collection')).toBe(1)
  })

  it('does not merge matching collection IDs across organizations', () => {
    const counts = vaultOrganizationSidebarCounts([
      {
        id: 'first-login',
        organizationId: 'first-organization',
        collectionIds: ['shared-collection-id']
      },
      {
        id: 'second-login',
        organizationId: 'second-organization',
        collectionIds: ['shared-collection-id']
      }
    ])

    expect(counts.byCollection.get('first-organization')?.get('shared-collection-id')).toBe(1)
    expect(counts.byCollection.get('second-organization')?.get('shared-collection-id')).toBe(1)
  })
})
