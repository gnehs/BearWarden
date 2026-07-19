import { FolderOpen, LockKeyhole, UsersRound } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'
import type {
  CollectionView,
  OrganizationView,
  SharedLoginSummary,
  SharedLoginView
} from '../../../shared/vault-contract'
import { Badge } from '@renderer/components/ui/badge'
import { Button } from '@renderer/components/ui/button'
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

function OrganizationsPage(): React.JSX.Element {
  const [organizations, setOrganizations] = useState<OrganizationView[]>([])
  const [collections, setCollections] = useState<CollectionView[]>([])
  const [items, setItems] = useState<SharedLoginSummary[]>([])
  const [organizationId, setOrganizationId] = useState<string | null>(null)
  const [collectionId, setCollectionId] = useState<string | null>(null)
  const [selected, setSelected] = useState<SharedLoginView | null>(null)
  const [loading, setLoading] = useState(true)

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

  useEffect(() => {
    let active = true
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
        toast.error('無法載入組織項目')
      }
    )
    return () => {
      active = false
    }
  }, [])

  async function selectItem(item: SharedLoginSummary): Promise<void> {
    try {
      setSelected(await window.bearwarden.sharedLogins.get({ id: item.id }))
    } catch {
      toast.error('無法載入共享項目')
    }
  }

  function selectOrganization(id: string | null): void {
    setOrganizationId(id)
    setCollectionId(null)
    setSelected(null)
  }

  return (
    <AuxiliaryPageLayout
      eyebrow="Bitwarden Organizations"
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
                onClick={() => selectOrganization(null)}
              >
                全部組織
              </Button>
              {organizations.map((organization) => (
                <Button
                  key={organization.id}
                  variant={organizationId === organization.id ? 'secondary' : 'ghost'}
                  className="justify-start"
                  type="button"
                  onClick={() => selectOrganization(organization.id)}
                >
                  <UsersRound data-icon="inline-start" />
                  {organization.name}
                </Button>
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
                  onClick={() => setCollectionId(null)}
                >
                  全部
                </Button>
                {visibleCollections.map((collection) => (
                  <Button
                    key={collection.id}
                    variant={collectionId === collection.id ? 'secondary' : 'outline'}
                    type="button"
                    onClick={() => {
                      setCollectionId(collection.id)
                      setSelected(null)
                    }}
                  >
                    <FolderOpen data-icon="inline-start" />
                    {collection.name}
                  </Button>
                ))}
              </CardContent>
            </Card>
            <div className="grid gap-3">
              {visibleItems.map((item) => (
                <Card
                  key={item.id}
                  className="cursor-pointer"
                  onClick={() => void selectItem(item)}
                >
                  <CardHeader className="flex-row items-start justify-between gap-4">
                    <div>
                      <CardTitle>{item.name}</CardTitle>
                      <CardDescription>
                        {item.subtitle || item.username || '共享項目'}
                      </CardDescription>
                    </div>
                    <Badge variant="outline">{item.viewPassword ? '可查看密碼' : '隱藏密碼'}</Badge>
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
            {selected && (
              <Card>
                <CardHeader>
                  <CardTitle>{selected.name}</CardTitle>
                  <CardDescription>
                    {selected.viewPassword
                      ? '依伺服器權限提供可查看欄位。'
                      : '伺服器禁止查看敏感欄位。'}
                  </CardDescription>
                </CardHeader>
                <CardContent className="grid gap-2 text-sm">
                  <div className="flex items-center gap-2">
                    <LockKeyhole className="size-4" aria-hidden="true" />
                    <span>{selected.viewPassword ? '可查看密碼' : '密碼與敏感欄位已遮罩'}</span>
                  </div>
                  {selected.username && <div>使用者名稱：{selected.username}</div>}
                  {selected.uri && <div className="truncate">網站：{selected.uri}</div>}
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
