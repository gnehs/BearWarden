import { i18n } from '@lingui/core'
import { msg } from '@lingui/core/macro'
import type {
  CollectionView,
  OrganizationView,
  SharedLoginSummary
} from '../../../shared/vault-contract'

const ORGANIZATION_ROLE_LABELS = {
  0: msg`Owner`,
  1: msg`Administrator`,
  2: msg`User`,
  4: msg`Custom role`
}

const ORGANIZATION_STATUS_LABELS = {
  0: msg`Invited`,
  1: msg`Invitation accepted`,
  2: msg`Confirmed`,
  3: msg`Provisioned`
}

export function organizationRoleLabel(type: OrganizationView['type']): string {
  if (type === null) return i18n._(msg`Role unavailable`)
  return i18n._(ORGANIZATION_ROLE_LABELS[type] ?? msg`Unknown role (${type})`)
}

export function organizationStatusLabel(organization: OrganizationView): string {
  if (!organization.enabled) return i18n._(msg`Disabled`)
  if (organization.status === null) return i18n._(msg`Status unavailable`)
  return i18n._(
    ORGANIZATION_STATUS_LABELS[organization.status] ?? msg`Unknown status (${organization.status})`
  )
}

export function collectionPermissionLabel(collection: CollectionView): string {
  if (collection.manage) return i18n._(msg`Manage collection`)
  if (collection.readOnly && collection.hidePasswords)
    return i18n._(msg`View items, hide passwords`)
  if (collection.readOnly) return i18n._(msg`View items`)
  if (collection.hidePasswords) return i18n._(msg`Edit items, hide passwords`)
  return i18n._(msg`Edit items`)
}

export function collectionAssignmentLabel(collection: CollectionView): string {
  return collection.assigned ? i18n._(msg`Direct assignment`) : i18n._(msg`Not directly assigned`)
}

export function sharedItemPermissionLabels(item: SharedLoginSummary): string[] {
  return [
    item.edit ? i18n._(msg`Can edit`) : i18n._(msg`Read-only`),
    item.viewPassword ? i18n._(msg`Can view passwords`) : i18n._(msg`Passwords hidden`),
    item.delete ? i18n._(msg`Can delete`) : i18n._(msg`Cannot delete`),
    item.restore ? i18n._(msg`Can restore`) : i18n._(msg`Cannot restore`)
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
