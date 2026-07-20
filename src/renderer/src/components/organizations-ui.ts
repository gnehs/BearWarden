import type {
  CollectionView,
  OrganizationView,
  SharedLoginSummary
} from '../../../shared/vault-contract'

const ORGANIZATION_ROLE_LABELS: Readonly<Record<number, string>> = {
  0: '擁有者',
  1: '管理員',
  2: '使用者',
  4: '自訂角色'
}

const ORGANIZATION_STATUS_LABELS: Readonly<Record<number, string>> = {
  0: '已邀請',
  1: '已接受邀請',
  2: '已確認',
  3: '已佈建'
}

export function organizationRoleLabel(type: OrganizationView['type']): string {
  if (type === null) return '角色未提供'
  return ORGANIZATION_ROLE_LABELS[type] ?? `未知角色（${type}）`
}

export function organizationStatusLabel(organization: OrganizationView): string {
  if (!organization.enabled) return '已停用'
  if (organization.status === null) return '狀態未提供'
  return ORGANIZATION_STATUS_LABELS[organization.status] ?? `未知狀態（${organization.status}）`
}

export function collectionPermissionLabel(collection: CollectionView): string {
  if (collection.manage) return '管理 Collection'
  if (collection.readOnly && collection.hidePasswords) return '檢視項目、隱藏密碼'
  if (collection.readOnly) return '檢視項目'
  if (collection.hidePasswords) return '編輯項目、隱藏密碼'
  return '編輯項目'
}

export function collectionAssignmentLabel(collection: CollectionView): string {
  return collection.assigned ? '直接指派' : '非直接指派'
}

export function sharedItemPermissionLabels(item: SharedLoginSummary): string[] {
  return [
    item.edit ? '可編輯' : '唯讀',
    item.viewPassword ? '一般檢視' : '隱藏密碼',
    item.delete ? '可刪除' : '不可刪除',
    item.restore ? '可還原' : '不可還原'
  ]
}

export interface LatestRequestGuard {
  next(): number
  invalidate(): void
  isCurrent(requestId: number): boolean
}

export function createLatestRequestGuard(): LatestRequestGuard {
  let latestRequestId = 0
  return {
    next: () => ++latestRequestId,
    invalidate: () => {
      latestRequestId += 1
    },
    isCurrent: (requestId) => requestId === latestRequestId
  }
}
