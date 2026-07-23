import type { SharedLoginSummary } from '../../../shared/vault-contract'

export interface VaultOrganizationSidebarCounts {
  allSharedItems: number
  byOrganization: ReadonlyMap<string, number>
  byCollection: ReadonlyMap<string, ReadonlyMap<string, number>>
}

type SharedItemMembership = Pick<SharedLoginSummary, 'id' | 'organizationId' | 'collectionIds'>

export function vaultOrganizationSidebarCounts(
  sharedItems: readonly SharedItemMembership[]
): VaultOrganizationSidebarCounts {
  const allSharedItemIds = new Set<string>()
  const organizationItemIds = new Map<string, Set<string>>()
  const collectionItemIds = new Map<string, Map<string, Set<string>>>()

  for (const item of sharedItems) {
    allSharedItemIds.add(item.id)

    const organizationIds = organizationItemIds.get(item.organizationId) ?? new Set<string>()
    organizationIds.add(item.id)
    organizationItemIds.set(item.organizationId, organizationIds)

    for (const collectionId of new Set(item.collectionIds)) {
      const organizationCollections =
        collectionItemIds.get(item.organizationId) ?? new Map<string, Set<string>>()
      const itemIds = organizationCollections.get(collectionId) ?? new Set<string>()
      itemIds.add(item.id)
      organizationCollections.set(collectionId, itemIds)
      collectionItemIds.set(item.organizationId, organizationCollections)
    }
  }

  return {
    allSharedItems: allSharedItemIds.size,
    byOrganization: new Map(
      [...organizationItemIds].map(([organizationId, itemIds]) => [organizationId, itemIds.size])
    ),
    byCollection: new Map(
      [...collectionItemIds].map(([organizationId, organizationCollections]) => [
        organizationId,
        new Map(
          [...organizationCollections].map(([collectionId, itemIds]) => [
            collectionId,
            itemIds.size
          ])
        )
      ])
    )
  }
}
