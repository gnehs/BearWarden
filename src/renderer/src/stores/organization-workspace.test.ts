import { describe, expect, it, vi } from 'vitest'
import type {
  CollectionView,
  OrganizationView,
  SharedLoginSummary,
  SharedLoginView
} from '../../../shared/vault-contract'
import {
  createOrganizationWorkspace,
  type OrganizationWorkspaceApi
} from './organization-workspace'

function deferred<T>(): {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (error: Error) => void
} {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

const organization = (id: string): OrganizationView => ({ id, name: id }) as OrganizationView
const collection = (id: string, organizationId: string): CollectionView =>
  ({ id, organizationId, name: id }) as CollectionView
const item = (id: string): SharedLoginSummary => ({ id, name: id }) as SharedLoginSummary
const view = (id: string): SharedLoginView => ({ id, name: id }) as SharedLoginView

function api(
  overrides: Partial<{
    organizations: () => Promise<OrganizationView[]>
    collections: () => Promise<CollectionView[]>
    items: () => Promise<SharedLoginSummary[]>
    get: (request: { id: string }) => Promise<SharedLoginView>
  }> = {}
): OrganizationWorkspaceApi {
  return {
    organizations: {
      list: vi.fn(overrides.organizations ?? (async () => [organization('org-a')]))
    },
    collections: {
      list: vi.fn(overrides.collections ?? (async () => [collection('col-a', 'org-a')]))
    },
    sharedLogins: {
      list: vi.fn(overrides.items ?? (async () => [item('item-a')])),
      get: vi.fn(overrides.get ?? (async ({ id }: { id: string }) => view(id)))
    }
  } as unknown as OrganizationWorkspaceApi
}

describe('createOrganizationWorkspace', () => {
  it('loads the lists and opens the first organization', async () => {
    const workspace = createOrganizationWorkspace(() => api())

    await workspace.load()

    expect(workspace.store.getState()).toMatchObject({
      organizations: [{ id: 'org-a' }],
      collections: [{ id: 'col-a' }],
      items: [{ id: 'item-a' }],
      organizationId: 'org-a',
      loading: false,
      loadError: false
    })
  })

  it('reports a failed load and recovers on retry', async () => {
    let fail = true
    const workspace = createOrganizationWorkspace(() =>
      api({
        organizations: async () => {
          if (fail) throw new Error('offline')
          return [organization('org-a')]
        }
      })
    )

    await workspace.load()
    expect(workspace.store.getState()).toMatchObject({ loading: false, loadError: true })

    fail = false
    await workspace.load()
    expect(workspace.store.getState()).toMatchObject({
      loading: false,
      loadError: false,
      organizationId: 'org-a'
    })
  })

  it('keeps a newer load when an older one resolves after it', async () => {
    const older = deferred<OrganizationView[]>()
    let calls = 0
    const workspace = createOrganizationWorkspace(() =>
      api({
        organizations: async () => {
          calls += 1
          return calls === 1 ? older.promise : [organization('newer')]
        }
      })
    )

    const first = workspace.load()
    await workspace.load()
    older.resolve([organization('older')])
    await first

    expect(workspace.store.getState().organizationId).toBe('newer')
  })

  it('shows only the most recently selected item', async () => {
    const slow = deferred<SharedLoginView>()
    const workspace = createOrganizationWorkspace(() =>
      api({ get: ({ id }) => (id === 'slow' ? slow.promise : Promise.resolve(view(id))) })
    )

    const first = workspace.selectItem(item('slow'))
    await workspace.selectItem(item('fast'))
    slow.resolve(view('slow'))
    await first

    expect(workspace.store.getState()).toMatchObject({
      selectedItemId: 'fast',
      selected: { id: 'fast' },
      selectedLoading: false
    })
  })

  it('clears the selection when the organization or collection changes', async () => {
    const workspace = createOrganizationWorkspace(() => api())
    await workspace.load()
    await workspace.selectItem(item('item-a'))

    workspace.selectCollection('col-a')
    expect(workspace.store.getState()).toMatchObject({ collectionId: 'col-a', selected: null })

    await workspace.selectItem(item('item-a'))
    workspace.selectOrganization(null)
    expect(workspace.store.getState()).toMatchObject({
      organizationId: null,
      collectionId: null,
      selectedItemId: null,
      selected: null
    })
  })

  it('drops responses that were still in flight when disposed', async () => {
    const lists = deferred<OrganizationView[]>()
    const detail = deferred<SharedLoginView>()
    const workspace = createOrganizationWorkspace(() =>
      api({ organizations: () => lists.promise, get: () => detail.promise })
    )

    const loading = workspace.load()
    const selecting = workspace.selectItem(item('item-a'))
    workspace.dispose()
    lists.resolve([organization('org-a')])
    detail.resolve(view('item-a'))
    await Promise.all([loading, selecting])

    expect(workspace.store.getState()).toMatchObject({
      organizations: [],
      organizationId: null,
      selected: null
    })
  })

  it('loads again after a dispose, as a remount does', async () => {
    const workspace = createOrganizationWorkspace(() => api())

    workspace.dispose()
    await workspace.load()

    expect(workspace.store.getState()).toMatchObject({ organizationId: 'org-a', loading: false })
  })
})
