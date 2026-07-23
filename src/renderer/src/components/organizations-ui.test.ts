import { describe, expect, it } from 'vitest'
import type {
  CollectionView,
  OrganizationView,
  SharedLoginSummary
} from '../../../shared/vault-contract'
import {
  collectionPermissionLabel,
  collectionAssignmentLabel,
  createLatestRequestGuard,
  isSharedLoginSummary,
  organizationRoleLabel,
  organizationStatusLabel,
  sharedItemPermissionLabels
} from './organizations-ui'

const organization: OrganizationView = {
  id: '60000000-0000-4000-8000-000000000001',
  name: 'Example team',
  status: 2,
  type: 2,
  enabled: true,
  identifier: null,
  hasPublicAndPrivateKeys: false
}

const collection: CollectionView = {
  id: '70000000-0000-4000-8000-000000000001',
  organizationId: organization.id,
  name: 'Support',
  externalId: null,
  readOnly: true,
  hidePasswords: true,
  manage: false,
  type: 0,
  assigned: true
}

describe('Organizations UI labels', () => {
  it('maps Bitwarden organization roles and membership states with safe fallbacks', () => {
    expect(organizationRoleLabel(0)).toBe('擁有者')
    expect(organizationRoleLabel(4)).toBe('自訂角色')
    expect(organizationRoleLabel(9)).toBe('未知的角色 (9)')
    expect(organizationStatusLabel(organization)).toBe('已確認')
    expect(organizationStatusLabel({ ...organization, enabled: false })).toBe('已停用')
    expect(organizationStatusLabel({ ...organization, status: 9 })).toBe('未知的狀態 (9)')
  })

  it.each([
    [{ manage: true }, '管理集合'],
    [{ readOnly: true, hidePasswords: true }, '檢視項目，隱藏密碼'],
    [{ readOnly: true, hidePasswords: false }, '檢視項目'],
    [{ readOnly: false, hidePasswords: true }, '編輯項目並隱藏密碼'],
    [{ readOnly: false, hidePasswords: false }, '編輯項目']
  ] as const)('describes Collection permissions for %o', (overrides, label) => {
    expect(collectionPermissionLabel({ ...collection, manage: false, ...overrides })).toBe(label)
  })

  it('shows whether Collection access is explicitly assigned', () => {
    expect(collectionAssignmentLabel(collection)).toBe('直接指派')
    expect(collectionAssignmentLabel({ ...collection, assigned: false })).toBe('未直接指派')
  })

  it('describes item capabilities without exposing item content', () => {
    const secretContent = 'must-not-be-rendered'
    const item = {
      edit: false,
      viewPassword: true,
      delete: false,
      restore: true,
      password: secretContent
    } as unknown as SharedLoginSummary

    const labels = sharedItemPermissionLabels(item)
    expect(labels).toEqual(['唯讀', '可檢視密碼', '無法刪除', '可還原'])
    expect(labels.join('')).not.toContain(secretContent)
  })

  it('distinguishes shared summaries before routing item actions', () => {
    const shared = {
      id: 'shared',
      shared: true,
      organizationId: organization.id,
      collectionIds: [collection.id]
    } as SharedLoginSummary

    expect(isSharedLoginSummary(shared)).toBe(true)
    expect(
      isSharedLoginSummary({ ...shared, shared: false } as unknown as SharedLoginSummary)
    ).toBe(false)
  })
})

describe('latest organization item request guard', () => {
  it('rejects an older response after a newer selection starts', () => {
    const guard = createLatestRequestGuard()
    const first = guard.next()
    const second = guard.next()

    expect(guard.isCurrent(first)).toBe(false)
    expect(guard.isCurrent(second)).toBe(true)
  })

  it('rejects an in-flight response when the current filter clears selection', () => {
    const guard = createLatestRequestGuard()
    const request = guard.next()
    guard.invalidate()

    expect(guard.isCurrent(request)).toBe(false)
  })
})
