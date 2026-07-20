import { FolderOpen, LockKeyhole, RefreshCw, TriangleAlert, UsersRound } from 'lucide-react'
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
import {
  collectionPermissionLabel,
  collectionAssignmentLabel,
  createLatestRequestGuard,
  organizationRoleLabel,
  organizationStatusLabel,
  sharedItemPermissionLabels
} from './organizations-ui'

function OrganizationsPage(): React.JSX.Element {
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
      title="組織項目"
      titleId="organizations-title"
      subtitle="共享項目只讀鏡像；權限與密碼可見性由伺服器決定。"
    >
      <FeatureUnderConstructionNotice>
        目前可唯讀瀏覽已同步的組織與共享項目；建立、編輯、刪除、分享與其他管理操作尚未支援。
      </FeatureUnderConstructionNotice>
      {loading ? (
        <div className="flex items-center justify-center gap-2 py-16" role="status">
          <Spinner />
          載入組織項目…
        </div>
      ) : loadError ? (
        <Alert variant="destructive">
          <TriangleAlert aria-hidden="true" />
          <AlertTitle>無法載入組織項目</AlertTitle>
          <AlertDescription>
            <p>請確認保管庫已解鎖，或稍後再試一次。</p>
            <Button type="button" variant="outline" onClick={retryLoad}>
              <RefreshCw data-icon="inline-start" />
              重試
            </Button>
          </AlertDescription>
        </Alert>
      ) : organizations.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <UsersRound />
            </EmptyMedia>
            <EmptyTitle>尚未同步到組織</EmptyTitle>
            <EmptyDescription>
              完成 Bitwarden 同步後，具備權限的共享項目會顯示在這裡。
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <AuxiliaryPageContent>
          <Card>
            <CardHeader>
              <CardTitle>組織</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-2">
              <Button
                variant={organizationId === null ? 'secondary' : 'ghost'}
                className="justify-start"
                type="button"
                aria-pressed={organizationId === null}
                onClick={() => selectOrganization(null)}
              >
                全部組織
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
                    <Badge variant="secondary">{organizationRoleLabel(organization.type)}</Badge>
                    <Badge variant="outline">{organizationStatusLabel(organization)}</Badge>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
          <div className="grid content-start gap-4">
            <Card>
              <CardHeader>
                <CardTitle>Collections</CardTitle>
                <CardDescription>依 Collection 篩選共享項目。</CardDescription>
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
                  全部
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
                    <Badge variant="outline">{collectionPermissionLabel(collection)}</Badge>
                    <Badge variant="secondary">{collectionAssignmentLabel(collection)}</Badge>
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
                        {item.subtitle || item.username || '共享項目'}
                      </CardDescription>
                      <div className="flex flex-wrap gap-1">
                        {sharedItemPermissionLabels(item).map((label) => (
                          <Badge key={label} variant="outline">
                            {label}
                          </Badge>
                        ))}
                      </div>
                    </div>
                    <Button
                      type="button"
                      variant={selectedItemId === item.id ? 'secondary' : 'outline'}
                      aria-pressed={selectedItemId === item.id}
                      aria-label={`查看 ${item.name}`}
                      onClick={() => void selectItem(item)}
                    >
                      查看
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
                    <EmptyTitle>沒有共享項目</EmptyTitle>
                    <EmptyDescription>目前的組織或 Collection 沒有可讀取項目。</EmptyDescription>
                  </EmptyHeader>
                </Empty>
              )}
            </div>
            {selectedLoading && (
              <div className="flex items-center gap-2" role="status">
                <Spinner />
                載入共享項目…
              </div>
            )}
            {selectedError && selectedItemId && (
              <Alert variant="destructive">
                <TriangleAlert aria-hidden="true" />
                <AlertTitle>無法載入共享項目</AlertTitle>
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
                    重試
                  </Button>
                </AlertDescription>
              </Alert>
            )}
            {selected && (
              <Card>
                <CardHeader>
                  <CardTitle>{selected.name}</CardTitle>
                  <CardDescription>
                    {selected.viewPassword
                      ? '伺服器允許一般檢視；此唯讀頁不顯示或複製密碼。'
                      : '伺服器套用隱藏密碼權限，敏感欄位已遮罩。'}
                  </CardDescription>
                </CardHeader>
                <CardContent className="grid gap-2 text-sm">
                  <div className="flex items-center gap-2">
                    <LockKeyhole className="size-4" aria-hidden="true" />
                    <span>{selected.viewPassword ? '一般檢視權限' : '密碼與敏感欄位已遮罩'}</span>
                  </div>
                  {selected.username && <div>使用者名稱：{selected.username}</div>}
                  {selected.uri && <div className="truncate">網站：{selected.uri}</div>}
                  {selectedCollections.length > 0 && (
                    <div className="flex flex-col gap-1">
                      <span>Collection：</span>
                      <div className="flex flex-wrap gap-1">
                        {selectedCollections.map((collection) => (
                          <Badge key={collection.id} variant="outline">
                            {collection.name} · {collectionPermissionLabel(collection)}
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
