import { describe, expect, it, vi, type Mock } from 'vitest'
import { toLoginSummary } from '../../../shared/login-summary'
import type {
  CollectionView,
  FolderView,
  LoginListRequest,
  LoginSummary,
  OrganizationView,
  SharedLoginSummary
} from '../../../shared/vault-contract'
import { makeLoginView } from '../components/vault-detail-test-fixtures'
import { createVaultDataSync, type VaultDataApi, type VaultDataSync } from './vault-data-sync'
import { createVaultSessionStore, type VaultSessionStoreApi } from './vault-session-store'

interface Deferred<T> {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (error: Error) => void
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function summary(id: string, overrides: Partial<LoginSummary> = {}): LoginSummary {
  return { ...toLoginSummary(makeLoginView({ id })), ...overrides }
}

function folder(id: string, position: number): FolderView {
  return {
    id,
    name: id,
    position,
    createdAt: '2026-07-22T00:00:00.000Z',
    updatedAt: '2026-07-22T00:00:00.000Z'
  }
}

interface FakeVault {
  api: VaultDataApi
  activeLists: Deferred<LoginSummary[]>[]
  folderLists: Deferred<FolderView[]>[]
}

/** A fake main process whose list responses the test resolves explicitly. */
function fakeVault(): FakeVault {
  const activeLists: Deferred<LoginSummary[]>[] = []
  const folderLists: Deferred<FolderView[]>[] = []
  const api: VaultDataApi = {
    folders: {
      list: () => {
        const response = deferred<FolderView[]>()
        folderLists.push(response)
        return response.promise
      }
    },
    logins: {
      list: (request?: LoginListRequest) => {
        if (request?.archived || request?.deleted) return Promise.resolve([])
        const response = deferred<LoginSummary[]>()
        activeLists.push(response)
        return response.promise
      }
    },
    organizations: { list: async (): Promise<OrganizationView[]> => [] },
    collections: { list: async (): Promise<CollectionView[]> => [] },
    sharedLogins: { list: async (): Promise<SharedLoginSummary[]> => [] }
  }
  return { api, activeLists, folderLists }
}

interface Harness extends FakeVault {
  session: VaultSessionStoreApi
  detailCache: { clear: Mock; invalidate: Mock; retainSummaries: Mock }
  sync: VaultDataSync
  events: { selectedDetailInvalidated: Mock; loadStarted: Mock; loadFailed: Mock }
}

function setup(hasAuthorization: (id: string) => boolean = () => false): Harness {
  const vault = fakeVault()
  const session = createVaultSessionStore()
  const detailCache = { clear: vi.fn(), invalidate: vi.fn(), retainSummaries: vi.fn() }
  const sync = createVaultDataSync({ api: vault.api, session, detailCache, hasAuthorization })
  const events = { selectedDetailInvalidated: vi.fn(), loadStarted: vi.fn(), loadFailed: vi.fn() }
  sync.subscribe(events)
  return { ...vault, session, detailCache, sync, events }
}

describe('createVaultDataSync load', () => {
  it('fills the session lists, sorts folders and ends the loading state', async () => {
    const { sync, session, activeLists, folderLists } = setup()

    const load = sync.load()
    folderLists[0].resolve([folder('second', 1), folder('first', 0)])
    activeLists[0].resolve([summary('item')])
    await load

    expect(session.getState().folders.map((entry) => entry.id)).toEqual(['first', 'second'])
    expect(session.getState().items.map((entry) => entry.id)).toEqual(['item'])
    expect(session.getState().loading).toBe(false)
  })

  it('falls back to all items when the scoped folder is gone and drops a removed selection', async () => {
    const { sync, session, activeLists, folderLists } = setup()
    session.getState().setScope({ kind: 'folder', folderId: 'deleted-folder' })
    session.getState().setSelectedId('removed')
    session.getState().setSelectedLogin(makeLoginView({ id: 'removed' }))

    const load = sync.load()
    folderLists[0].resolve([])
    activeLists[0].resolve([summary('kept')])
    await load

    expect(session.getState().scope).toEqual({ kind: 'all' })
    expect(session.getState().selectedId).toBeNull()
    expect(session.getState().selectedLogin).toBeNull()
  })

  it('closes the selected detail when its item became protected without authorization', async () => {
    const { sync, session, activeLists, folderLists, detailCache, events } = setup()
    session.getState().setSelectedId('item')
    session.getState().setSelectedLogin(makeLoginView({ id: 'item' }))
    session.getState().setEditorMode('edit')

    const load = sync.load()
    folderLists[0].resolve([])
    activeLists[0].resolve([summary('item', { reprompt: 1 })])
    await load

    expect(detailCache.invalidate).toHaveBeenCalledWith(new Set(['item']))
    expect(session.getState().selectedLogin).toBeNull()
    expect(session.getState().editorMode).toBeNull()
    expect(events.selectedDetailInvalidated).toHaveBeenCalledTimes(1)
  })

  it('ignores a load that a newer load superseded, including its failure', async () => {
    const { sync, session, activeLists, folderLists, events } = setup()

    const older = sync.load()
    const newer = sync.load()
    folderLists[1].resolve([])
    activeLists[1].resolve([summary('newer')])
    await newer
    folderLists[0].reject(new Error('NETWORK'))
    activeLists[0].resolve([summary('older')])
    await older

    expect(session.getState().items.map((entry) => entry.id)).toEqual(['newer'])
    expect(events.loadFailed).not.toHaveBeenCalled()
  })

  it('reports the failure of the latest load', async () => {
    const { sync, session, folderLists, events } = setup()

    const load = sync.load()
    folderLists[0].reject(new Error('LOCKED'))
    await load

    expect(events.loadFailed).toHaveBeenCalledWith(new Error('LOCKED'))
    expect(session.getState().loading).toBe(false)
  })

  it('writes nothing once disposed', async () => {
    const { sync, session, activeLists, folderLists } = setup()

    const load = sync.load()
    sync.dispose()
    folderLists[0].resolve([folder('late', 0)])
    activeLists[0].resolve([summary('late')])
    await load

    expect(session.getState().items).toEqual([])
    expect(session.getState().folders).toEqual([])
    expect(session.getState().loading).toBe(true)
  })
})

describe('createVaultDataSync refreshItems', () => {
  it('replaces the item list and merges the new summary into the selected detail', async () => {
    const { sync, session, activeLists, detailCache } = setup()
    session.getState().setSelectedId('item')
    session.getState().setSelectedLogin(makeLoginView({ id: 'item', notes: 'kept detail' }))

    const refresh = sync.refreshItems()
    activeLists[0].resolve([summary('item', { name: 'Renamed' })])
    await refresh

    expect(session.getState().items.map((entry) => entry.name)).toEqual(['Renamed'])
    expect(session.getState().selectedLogin).toMatchObject({
      name: 'Renamed',
      notes: 'kept detail'
    })
    expect(detailCache.retainSummaries).toHaveBeenCalledWith([summary('item', { name: 'Renamed' })])
  })

  it('keeps a newer refresh when an older one resolves after it', async () => {
    const { sync, session, activeLists } = setup()

    const older = sync.refreshItems()
    const newer = sync.refreshItems()
    activeLists[1].resolve([summary('item', { name: 'Newer' })])
    await newer
    activeLists[0].resolve([summary('item', { name: 'Older' })])
    await older

    expect(session.getState().items.map((entry) => entry.name)).toEqual(['Newer'])
  })

  it('keeps refreshed items when an earlier full load resolves after the refresh', async () => {
    const { sync, session, activeLists, folderLists } = setup()

    const load = sync.load()
    const refresh = sync.refreshItems()
    activeLists[1].resolve([summary('item', { name: 'Refreshed' })])
    await refresh
    folderLists[0].resolve([folder('folder', 0)])
    activeLists[0].resolve([summary('item', { name: 'Loaded earlier' })])
    await load

    expect(session.getState().items.map((entry) => entry.name)).toEqual(['Refreshed'])
    expect(session.getState().folders.map((entry) => entry.id)).toEqual(['folder'])
    expect(session.getState().loading).toBe(false)
  })

  it('drops a refresh that started before a newer full load', async () => {
    const { sync, session, activeLists, folderLists } = setup()

    const refresh = sync.refreshItems()
    const load = sync.load()
    folderLists[0].resolve([])
    activeLists[1].resolve([summary('item', { name: 'Loaded' })])
    await load
    activeLists[0].resolve([summary('item', { name: 'Refreshed earlier' })])
    await refresh

    expect(session.getState().items.map((entry) => entry.name)).toEqual(['Loaded'])
  })

  it('writes nothing once disposed', async () => {
    const { sync, session, activeLists } = setup()

    const refresh = sync.refreshItems()
    sync.dispose()
    activeLists[0].resolve([summary('late')])
    await refresh

    expect(session.getState().items).toEqual([])
  })
})
