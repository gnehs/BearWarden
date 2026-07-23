import { Trans, useLingui } from '@lingui/react/macro'
import { Building2, Library, UsersRound } from 'lucide-react'
import { useMemo, type JSX } from 'react'
import type {
  CollectionView,
  OrganizationView,
  SharedLoginSummary
} from '../../../shared/vault-contract'
import { vaultOrganizationSidebarCounts } from '../lib/vault-organization-sidebar'
import type { Scope } from './VaultShell-model'
import { SidebarLink } from './VaultShell-primitives'

export interface VaultOrganizationSidebarSectionProps {
  organizations: OrganizationView[]
  collections: CollectionView[]
  sharedItems: SharedLoginSummary[]
  scope: Scope
  onSelectAllShared: () => void
  onSelectOrganization: (id: string) => void
  onSelectCollection: (organizationId: string, collectionId: string) => void
}

export function VaultOrganizationSidebarSection({
  organizations,
  collections,
  sharedItems,
  scope,
  onSelectAllShared,
  onSelectOrganization,
  onSelectCollection
}: VaultOrganizationSidebarSectionProps): JSX.Element {
  const { t } = useLingui()
  const counts = useMemo(() => vaultOrganizationSidebarCounts(sharedItems), [sharedItems])
  const collectionsByOrganization = useMemo(() => {
    const grouped = new Map<string, CollectionView[]>()

    for (const collection of collections) {
      const organizationCollections = grouped.get(collection.organizationId) ?? []
      organizationCollections.push(collection)
      grouped.set(collection.organizationId, organizationCollections)
    }

    return grouped
  }, [collections])

  return (
    <section
      className="flex flex-none flex-col px-[9px] py-1"
      aria-labelledby="organizations-title"
    >
      <header className="flex items-center justify-between pt-0 pr-1.5 pb-1 pl-[9px]">
        <h2
          className="text-muted-foreground m-0 text-[10px] font-[760] tracking-[0.11em] uppercase"
          id="organizations-title"
        >
          <Trans>Organizations</Trans>
        </h2>
      </header>
      <ul className="m-0 list-none p-0">
        <li className="grid">
          <SidebarLink
            icon={<UsersRound size={16} />}
            label={t`All shared items`}
            count={counts.allSharedItems}
            active={scope.kind === 'shared'}
            onClick={onSelectAllShared}
          />
        </li>
        {organizations.map((organization) => (
          <li className="grid" key={organization.id}>
            <SidebarLink
              icon={<Building2 size={16} />}
              label={organization.name}
              count={counts.byOrganization.get(organization.id) ?? 0}
              active={scope.kind === 'organization' && scope.organizationId === organization.id}
              onClick={() => onSelectOrganization(organization.id)}
            />
            <ul className="m-0 list-none p-0 pl-4">
              {(collectionsByOrganization.get(organization.id) ?? []).map((collection) => (
                <li className="grid" key={collection.id}>
                  <SidebarLink
                    icon={<Library size={15} />}
                    label={collection.name}
                    count={counts.byCollection.get(organization.id)?.get(collection.id) ?? 0}
                    active={
                      scope.kind === 'collection' &&
                      scope.organizationId === organization.id &&
                      scope.collectionId === collection.id
                    }
                    onClick={() => onSelectCollection(organization.id, collection.id)}
                  />
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ul>
    </section>
  )
}
