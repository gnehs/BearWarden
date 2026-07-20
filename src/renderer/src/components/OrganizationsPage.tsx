import { FolderOpen, LockKeyhole, RefreshCw, TriangleAlert, UsersRound } from 'lucide-react'
import { Trans, useLingui } from '@lingui/react/macro'
import { useEffect, useMemo, useRef, useState } from 'react'
import type {
  CollectionView,
  OrganizationView,
  SharedLoginSummary,
  SharedLoginView
} from '../../../shared/vault-contract'
import { Badge } from '@renderer/components/ui/badge'
import { Button } from '@renderer/components/ui/button'
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle
} from '@renderer/components/ui/card'
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle
} from '@renderer/components/ui/empty'
import { Spinner } from '@renderer/components/ui/spinner'
import AuxiliaryPageLayout, { AuxiliaryPageContent } from './AuxiliaryPageLayout'
import FeatureUnderConstructionNotice from './FeatureUnderConstructionNotice'
import { createLatestRequestGuard } from './organizations-ui'

function OrganizationRoleBadge({ type }: Pick<OrganizationView, 'type'>): React.JSX.Element {
  return (
    <Badge variant="secondary">
      {type === null ? (
        <Trans>Role unavailable</Trans>
      ) : type === 0 ? (
        <Trans>Owner</Trans>
      ) : type === 1 ? (
        <Trans>Administrator</Trans>
      ) : type === 2 ? (
        <Trans>User</Trans>
      ) : type === 4 ? (
        <Trans>Custom role</Trans>
      ) : (
        <Trans>Unknown role ({type})</Trans>
      )}
    </Badge>
  )
}

function OrganizationStatusBadge({
  organization
}: {
  organization: OrganizationView
}): React.JSX.Element {
  return (
    <Badge variant="outline">
      {!organization.enabled ? (
        <Trans>Disabled</Trans>
      ) : organization.status === null ? (
        <Trans>Status unavailable</Trans>
      ) : organization.status === 0 ? (
        <Trans>Invited</Trans>
      ) : organization.status === 1 ? (
        <Trans>Accepted</Trans>
      ) : organization.status === 2 ? (
        <Trans>Confirmed</Trans>
      ) : organization.status === 3 ? (
        <Trans>Provisioned</Trans>
      ) : (
        <Trans>Unknown status ({organization.status})</Trans>
      )}
    </Badge>
  )
}

function CollectionPermissionLabel({
  collection
}: {
  collection: CollectionView
}): React.JSX.Element {
  return (
    <>
      {collection.manage ? (
        <Trans>Manage Collection</Trans>
      ) : collection.readOnly && collection.hidePasswords ? (
        <Trans>View items, hide passwords</Trans>
      ) : collection.readOnly ? (
        <Trans>View items</Trans>
      ) : collection.hidePasswords ? (
        <Trans>Edit items, hide passwords</Trans>
      ) : (
        <Trans>Edit items</Trans>
      )}
    </>
  )
}

function CollectionAssignmentBadge({
  collection
}: {
  collection: CollectionView
}): React.JSX.Element {
  return (
    <Badge variant="secondary">
      {collection.assigned ? <Trans>Direct assignment</Trans> : <Trans>Indirect assignment</Trans>}
    </Badge>
  )
}

function SharedItemPermissionBadges({ item }: { item: SharedLoginSummary }): React.JSX.Element {
  return (
    <div className="flex flex-wrap gap-1">
      <Badge variant="outline">
        {item.edit ? <Trans>Can edit</Trans> : <Trans>Read-only</Trans>}
      </Badge>
      <Badge variant="outline">
        {item.viewPassword ? <Trans>Standard view</Trans> : <Trans>Passwords hidden</Trans>}
      </Badge>
      <Badge variant="outline">
        {item.delete ? <Trans>Can delete</Trans> : <Trans>Cannot delete</Trans>}
      </Badge>
      <Badge variant="outline">
        {item.restore ? <Trans>Can restore</Trans> : <Trans>Cannot restore</Trans>}
      </Badge>
    </div>
  )
}

function OrganizationsPage(): React.JSX.Element {
  const { t } = useLingui()
  const [organizations, setOrganizations] = useState<OrganizationView[]>([])
  const [collections, setCollections] = useState<CollectionView[]>([])
  const [items, setItems] = useState<SharedLoginSummary[]>([])
  const [organizationId, setOrganizationId] = useState<string | null>(null)
  const [collectionId, setCollectionId] = useState<string | null>(null)
  const [selected, setSelected] = useState<SharedLoginView | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [retryVersion, setRetryVersion] = useState(0)
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null)
  const [selectedLoading, setSelectedLoading] = useState(false)
  const [selectedError, setSelectedError] = useState(false)
  const selectedRequest = useRef(createLatestRequestGuard())

  const visibleCollections = useMemo(
    () =>
      collections.filter(
        (collection) => organizationId === null || collection.organizationId === organizationId
      ),
    [collections, organizationId]
  )

  const visibleItems = useMemo(
    () =>
      items.filter(
        (item) =>
          (organizationId === null || item.organizationId === organizationId) &&
          (collectionId === null || item.collectionIds.includes(collectionId))
      ),
    [collectionId, items, organizationId]
  )

  const selectedCollections = useMemo(
    () =>
      selected
        ? collections.filter((collection) => selected.collectionIds.includes(collection.id))
        : [],
    [collections, selected]
  )

  useEffect(() => {
    let active = true
    const requestGuard = selectedRequest.current
    Promise.all([
      window.bearwarden.organizations.list(),
      window.bearwarden.collections.list(),
      window.bearwarden.sharedLogins.list()
    ]).then(
      ([nextOrganizations, nextCollections, nextItems]) => {
        if (!active) return
        setOrganizations(nextOrganizations)
        setCollections(nextCollections)
        setItems(nextItems)
        setOrganizationId(nextOrganizations[0]?.id ?? null)
        setLoading(false)
      },
      () => {
        if (!active) return
        setLoading(false)
        setLoadError(true)
      }
    )
    return () => {
      active = false
      requestGuard.invalidate()
    }
  }, [retryVersion])

  async function selectItem(item: SharedLoginSummary): Promise<void> {
    const requestId = selectedRequest.current.next()
    setSelectedItemId(item.id)
    setSelected(null)
    setSelectedError(false)
    setSelectedLoading(true)
    try {
      const nextSelected = await window.bearwarden.sharedLogins.get({ id: item.id })
      if (!selectedRequest.current.isCurrent(requestId)) return
      setSelected(nextSelected)
    } catch {
      if (!selectedRequest.current.isCurrent(requestId)) return
      setSelectedError(true)
    } finally {
      if (selectedRequest.current.isCurrent(requestId)) setSelectedLoading(false)
    }
  }

  function clearSelected(): void {
    selectedRequest.current.invalidate()
    setSelectedItemId(null)
    setSelected(null)
    setSelectedError(false)
    setSelectedLoading(false)
  }

  function retryLoad(): void {
    clearSelected()
    setLoading(true)
    setLoadError(false)
    setRetryVersion((value) => value + 1)
  }

  function selectOrganization(id: string | null): void {
    setOrganizationId(id)
    setCollectionId(null)
    clearSelected()
  }

  return (
    <AuxiliaryPageLayout
      title={t`Organization items`}
      titleId="organizations-title"
      subtitle={t`A read-only mirror of shared items. The server determines permissions and password visibility.`}
    >
      <FeatureUnderConstructionNotice>
        <Trans>
          You can currently browse synced organizations and shared items in read-only mode.
          Creating, editing, deleting, sharing, and other management actions are not supported yet.
        </Trans>
      </FeatureUnderConstructionNotice>
      {loading ? (
        <div className="flex items-center justify-center gap-2 py-16" role="status">
          <Spinner />
          <Trans>Loading organization items…</Trans>
        </div>
      ) : loadError ? (
        <Alert variant="destructive">
          <TriangleAlert aria-hidden="true" />
          <AlertTitle>
            <Trans>Could not load organization items</Trans>
          </AlertTitle>
          <AlertDescription>
            <p>
              <Trans>Confirm that the vault is unlocked, then try again later.</Trans>
            </p>
            <Button type="button" variant="outline" onClick={retryLoad}>
              <RefreshCw data-icon="inline-start" />
              <Trans>Try again</Trans>
            </Button>
          </AlertDescription>
        </Alert>
      ) : organizations.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <UsersRound />
            </EmptyMedia>
            <EmptyTitle>
              <Trans>No organizations have been synced</Trans>
            </EmptyTitle>
            <EmptyDescription>
              <Trans>
                After Bitwarden sync completes, shared items that you have permission to access will
                appear here.
              </Trans>
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <AuxiliaryPageContent>
          <Card>
            <CardHeader>
              <CardTitle>
                <Trans>Organizations</Trans>
              </CardTitle>
            </CardHeader>
            <CardContent className="grid gap-2">
              <Button
                variant={organizationId === null ? 'secondary' : 'ghost'}
                className="justify-start"
                type="button"
                aria-pressed={organizationId === null}
                onClick={() => selectOrganization(null)}
              >
                <Trans>All organizations</Trans>
              </Button>
              {organizations.map((organization) => (
                <div key={organization.id} className="flex flex-col gap-1">
                  <Button
                    variant={organizationId === organization.id ? 'secondary' : 'ghost'}
                    className="justify-start"
                    type="button"
                    aria-pressed={organizationId === organization.id}
                    onClick={() => selectOrganization(organization.id)}
                  >
                    <UsersRound data-icon="inline-start" />
                    {organization.name}
                  </Button>
                  <div className="flex flex-wrap gap-1 px-2">
                    <OrganizationRoleBadge type={organization.type} />
                    <OrganizationStatusBadge organization={organization} />
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
          <div className="grid content-start gap-4">
            <Card>
              <CardHeader>
                <CardTitle>
                  <Trans>Collections</Trans>
                </CardTitle>
                <CardDescription>
                  <Trans>Filter shared items by Collection.</Trans>
                </CardDescription>
              </CardHeader>
              <CardContent className="flex flex-wrap gap-2">
                <Button
                  variant={collectionId === null ? 'secondary' : 'outline'}
                  type="button"
                  aria-pressed={collectionId === null}
                  onClick={() => {
                    setCollectionId(null)
                    clearSelected()
                  }}
                >
                  <Trans>All</Trans>
                </Button>
                {visibleCollections.map((collection) => (
                  <Button
                    key={collection.id}
                    variant={collectionId === collection.id ? 'secondary' : 'outline'}
                    className="h-auto whitespace-normal"
                    type="button"
                    aria-pressed={collectionId === collection.id}
                    onClick={() => {
                      setCollectionId(collection.id)
                      clearSelected()
                    }}
                  >
                    <FolderOpen data-icon="inline-start" />
                    {collection.name}
                    <Badge variant="outline">
                      <CollectionPermissionLabel collection={collection} />
                    </Badge>
                    <CollectionAssignmentBadge collection={collection} />
                  </Button>
                ))}
              </CardContent>
            </Card>
            <div className="grid gap-3">
              {visibleItems.map((item) => (
                <Card key={item.id}>
                  <CardHeader className="flex-row items-start justify-between gap-4">
                    <div className="flex min-w-0 flex-col gap-2">
                      <CardTitle>{item.name}</CardTitle>
                      <CardDescription>
                        {item.subtitle || item.username || <Trans>Shared item</Trans>}
                      </CardDescription>
                      <SharedItemPermissionBadges item={item} />
                    </div>
                    <Button
                      type="button"
                      variant={selectedItemId === item.id ? 'secondary' : 'outline'}
                      aria-pressed={selectedItemId === item.id}
                      aria-label={t`View ${item.name}`}
                      onClick={() => void selectItem(item)}
                    >
                      <Trans>View</Trans>
                    </Button>
                  </CardHeader>
                </Card>
              ))}
              {visibleItems.length === 0 && (
                <Empty>
                  <EmptyHeader>
                    <EmptyMedia variant="icon">
                      <FolderOpen />
                    </EmptyMedia>
                    <EmptyTitle>
                      <Trans>No shared items</Trans>
                    </EmptyTitle>
                    <EmptyDescription>
                      <Trans>
                        The current organization or Collection has no items you can read.
                      </Trans>
                    </EmptyDescription>
                  </EmptyHeader>
                </Empty>
              )}
            </div>
            {selectedLoading && (
              <div className="flex items-center gap-2" role="status">
                <Spinner />
                <Trans>Loading shared item…</Trans>
              </div>
            )}
            {selectedError && selectedItemId && (
              <Alert variant="destructive">
                <TriangleAlert aria-hidden="true" />
                <AlertTitle>
                  <Trans>Could not load shared item</Trans>
                </AlertTitle>
                <AlertDescription>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => {
                      const item = items.find((candidate) => candidate.id === selectedItemId)
                      if (item) void selectItem(item)
                    }}
                  >
                    <RefreshCw data-icon="inline-start" />
                    <Trans>Try again</Trans>
                  </Button>
                </AlertDescription>
              </Alert>
            )}
            {selected && (
              <Card>
                <CardHeader>
                  <CardTitle>{selected.name}</CardTitle>
                  <CardDescription>
                    {selected.viewPassword ? (
                      <Trans>
                        The server allows standard viewing. This read-only page does not show or
                        copy passwords.
                      </Trans>
                    ) : (
                      <Trans>
                        The server applies hidden-password permissions, so sensitive fields are
                        masked.
                      </Trans>
                    )}
                  </CardDescription>
                </CardHeader>
                <CardContent className="grid gap-2 text-sm">
                  <div className="flex items-center gap-2">
                    <LockKeyhole className="size-4" aria-hidden="true" />
                    <span>
                      {selected.viewPassword ? (
                        <Trans>Standard view permission</Trans>
                      ) : (
                        <Trans>Passwords and sensitive fields are masked</Trans>
                      )}
                    </span>
                  </div>
                  {selected.username && (
                    <div>
                      <Trans>Username: {selected.username}</Trans>
                    </div>
                  )}
                  {selected.uri && (
                    <div className="truncate">
                      <Trans>Website: {selected.uri}</Trans>
                    </div>
                  )}
                  {selectedCollections.length > 0 && (
                    <div className="flex flex-col gap-1">
                      <span>
                        <Trans>Collection:</Trans>
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {selectedCollections.map((collection) => (
                          <Badge key={collection.id} variant="outline">
                            {collection.name} ·{' '}
                            <CollectionPermissionLabel collection={collection} />
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
          </div>
        </AuxiliaryPageContent>
      )}
    </AuxiliaryPageLayout>
  )
}

export default OrganizationsPage
