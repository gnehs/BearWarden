import { describe, expect, it } from 'vitest'
import type {
  CollectionView,
  FolderView,
  LoginSummary,
  OrganizationView,
  SharedLoginSummary
} from '../../../shared/vault-contract'
import { createVaultSessionStore } from './vault-session-store'

const folder: FolderView = {
  id: 'folder-1',
  name: 'Personal',
  position: 0,
  createdAt: '2026-07-22T00:00:00.000Z',
  updatedAt: '2026-07-22T00:00:00.000Z'
}

const item: LoginSummary = {
  id: 'item-1',
  type: 'login',
  name: 'Example login',
  subtitle: 'example.invalid',
  username: 'sample-user',
  uri: 'https://example.invalid',
  uris: [{ uri: 'https://example.invalid', match: null }],
  passwordHistoryCount: 0,
  attachmentCount: 0,
  folderId: null,
  favorite: false,
  usageCount: 0,
  lastUsedAt: null,
  createdAt: '2026-07-22T00:00:00.000Z',
  updatedAt: '2026-07-22T00:00:00.000Z',
  deletedAt: null,
  archivedAt: null,
  reprompt: 0
}

const organization: OrganizationView = {
  id: 'organization-1',
  name: 'Example team',
  status: 2,
  type: 2,
  enabled: true,
  identifier: null,
  hasPublicAndPrivateKeys: false
}

const collection: CollectionView = {
  id: 'collection-1',
  organizationId: organization.id,
  name: 'Shared',
  externalId: null,
  readOnly: true,
  hidePasswords: false,
  manage: false,
  type: 0,
  assigned: true
}

const sharedItem: SharedLoginSummary = {
  ...item,
  id: 'shared-item-1',
  organizationId: organization.id,
  collectionIds: [collection.id],
  shared: true,
  edit: false,
  viewPassword: true,
  delete: false,
  restore: false
}

describe('createVaultSessionStore', () => {
  it('supports React SetStateAction functional updates', () => {
    const store = createVaultSessionStore()

    store.getState().setFolders((current) => [...current, folder])
    store.getState().setItems((current) => [...current, item])
    store.getState().setOrganizations([organization])
    store.getState().setCollections([collection])
    store.getState().setSharedItems([sharedItem])
    store.getState().setScope({ kind: 'favorites' })
    store.getState().setSortMode('recent')
    store.getState().setTypeFilter('login')
    store.getState().setQuery('example')
    store.getState().setSelectedIds((current) => new Set([...current, item.id]))
    store.getState().setSelectedId(item.id)
    store.getState().setEditorMode('edit')
    store.getState().setLoading((current) => !current)
    store.getState().setBusy((current) => !current)

    expect(store.getState()).toMatchObject({
      folders: [folder],
      items: [item],
      organizations: [organization],
      collections: [collection],
      sharedItems: [sharedItem],
      scope: { kind: 'favorites' },
      sortMode: 'recent',
      typeFilter: 'login',
      query: 'example',
      selectedId: item.id,
      editorMode: 'edit',
      loading: false,
      busy: true
    })
    expect(store.getState().selectedIds).toEqual(new Set([item.id]))
  })

  it('keeps selection updates immutable for direct and functional values', () => {
    const store = createVaultSessionStore()
    const directSelection = new Set(['item-1'])

    store.getState().setSelectedIds(directSelection)
    const firstStoredSelection = store.getState().selectedIds
    directSelection.add('outside-mutation')

    store.getState().setSelectedIds((current) => new Set([...current, 'item-2']))
    const secondStoredSelection = store.getState().selectedIds

    expect(firstStoredSelection).not.toBe(directSelection)
    expect(firstStoredSelection).toEqual(new Set(['item-1']))
    expect(secondStoredSelection).not.toBe(firstStoredSelection)
    expect(secondStoredSelection).toEqual(new Set(['item-1', 'item-2']))

    store.getState().setSelectedIds((current) => current)

    expect(store.getState().selectedIds).not.toBe(secondStoredSelection)
    expect(store.getState().selectedIds).toEqual(secondStoredSelection)
  })

  it('creates independent store instances instead of sharing module state', () => {
    const firstStore = createVaultSessionStore()
    const secondStore = createVaultSessionStore()

    firstStore.getState().setItems([item])

    expect(firstStore.getState().items).toEqual([item])
    expect(secondStore.getState().items).toEqual([])
    expect(firstStore.getState().selectedIds).not.toBe(secondStore.getState().selectedIds)
  })

  it('resets all session state with a fresh selection', () => {
    const store = createVaultSessionStore()

    store.getState().setFolders([folder])
    store.getState().setItems([item])
    store.getState().setOrganizations([organization])
    store.getState().setCollections([collection])
    store.getState().setSharedItems([sharedItem])
    store.getState().setSelectedIds(new Set([item.id]))
    store.getState().setLoading(false)
    store.getState().setBusy(true)
    const previousSelection = store.getState().selectedIds

    store.getState().reset()

    expect(store.getState()).toMatchObject({
      folders: [],
      items: [],
      organizations: [],
      collections: [],
      sharedItems: [],
      scope: { kind: 'all' },
      sortMode: 'title',
      typeFilter: 'all',
      query: '',
      selectedId: null,
      editorMode: null,
      loading: true,
      busy: false
    })
    expect(store.getState().selectedIds).toEqual(new Set())
    expect(store.getState().selectedIds).not.toBe(previousSelection)
  })

  it('clears session data and rejects writes after disposal', () => {
    const store = createVaultSessionStore()
    const staleSetItems = store.getState().setItems

    store.getState().setItems([item])
    store.getState().setSharedItems([sharedItem])
    store.getState().setQuery('example')
    store.getState().dispose()
    staleSetItems([item])

    expect(store.getState()).toMatchObject({
      items: [],
      sharedItems: [],
      query: '',
      loading: true,
      busy: false
    })
  })
})
