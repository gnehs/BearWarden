import type { BearWardenAPI, LoginSummary } from '../../../shared/vault-contract'
import type { LoginDetailCache } from '../components/vault-detail-cache'
import { mergeLoginSummary } from '../components/vault-detail-cache'
import {
  isCurrentVaultLoad,
  protectedDetailInvalidationIds
} from '../components/VaultShell-security'
import { sortFoldersByPosition } from '../lib/vault-folder-tree'
import { listLoginsInAllStates } from '../lib/vault-login-lists'
import type { Scope } from '../components/VaultShell-model'
import type { VaultSessionStoreApi } from './vault-session-store'

export interface VaultDataApi {
  folders: Pick<BearWardenAPI['folders'], 'list'>
  logins: Pick<BearWardenAPI['logins'], 'list'>
  organizations: Pick<BearWardenAPI['organizations'], 'list'>
  collections: Pick<BearWardenAPI['collections'], 'list'>
  sharedLogins: Pick<BearWardenAPI['sharedLogins'], 'list'>
}

export interface VaultDataSyncOptions {
  api: VaultDataApi
  session: VaultSessionStoreApi
  detailCache: Pick<LoginDetailCache, 'clear' | 'invalidate' | 'retainSummaries'>
  hasAuthorization: (id: string) => boolean
}

export interface VaultDataSyncEvents {
  /** The selected item became protected or trashed, so its open detail must close. */
  selectedDetailInvalidated: () => void
  loadStarted: () => void
  loadFailed: (error: unknown) => void
}

export interface VaultDataSync {
  /** Reloads folders, items, organizations, collections and shared items. */
  load: () => Promise<void>
  /** Reloads only personal items, after a mutation that changed them. */
  refreshItems: () => Promise<void>
  subscribe: (events: VaultDataSyncEvents) => () => void
  dispose: () => void
}

function scopeStillExists(
  scope: Scope,
  lists: {
    folders: readonly { id: string }[]
    organizations: readonly { id: string }[]
    collections: readonly { id: string; organizationId: string }[]
  }
): boolean {
  if (scope.kind === 'folder') return lists.folders.some((folder) => folder.id === scope.folderId)
  if (scope.kind === 'organization') {
    return lists.organizations.some((organization) => organization.id === scope.organizationId)
  }
  if (scope.kind === 'collection') {
    return lists.collections.some(
      (collection) =>
        collection.id === scope.collectionId && collection.organizationId === scope.organizationId
    )
  }
  return true
}

/**
 * Keeps the session store's vault lists in step with the main process. Full loads and item
 * refreshes share one item-request sequence, so an item list applies only while no newer
 * load or refresh has started; folders and organizations follow the newest full load.
 * Nothing applies after `dispose`.
 */
export function createVaultDataSync(options: VaultDataSyncOptions): VaultDataSync {
  const { api, session, detailCache } = options
  let latestLoad = 0
  let latestItemsRequest = 0
  let events: VaultDataSyncEvents | null = null

  function invalidateProtectedDetails(summaries: readonly LoginSummary[]): void {
    const invalidIds = protectedDetailInvalidationIds(summaries, options.hasAuthorization)
    if (invalidIds.size === 0) return
    detailCache.invalidate(invalidIds)
    const selectedId = session.getState().selectedId
    if (selectedId && invalidIds.has(selectedId)) {
      session.getState().setSelectedLogin(null)
      session.getState().setEditorMode(null)
      events?.selectedDetailInvalidated()
    }
  }

  async function load(): Promise<void> {
    const requestId = ++latestLoad
    const itemsRequestId = ++latestItemsRequest
    detailCache.clear()
    try {
      events?.loadStarted()
      const [folders, items, organizations, collections, sharedItems] = await Promise.all([
        api.folders.list(),
        listLoginsInAllStates(api.logins),
        api.organizations.list(),
        api.collections.list(),
        api.sharedLogins.list({ sort: 'name' })
      ])
      if (!isCurrentVaultLoad(requestId, latestLoad)) return
      const itemsCurrent = isCurrentVaultLoad(itemsRequestId, latestItemsRequest)
      if (itemsCurrent) invalidateProtectedDetails(items)
      const state = session.getState()
      const listed = new Set(
        [...(itemsCurrent ? items : state.items), ...sharedItems].map((item) => item.id)
      )
      state.setFolders(sortFoldersByPosition(folders))
      if (itemsCurrent) state.setItems(items)
      state.setOrganizations(organizations)
      state.setCollections(collections)
      state.setSharedItems(sharedItems)
      state.setScope((current) =>
        scopeStillExists(current, { folders, organizations, collections })
          ? current
          : { kind: 'all' }
      )
      state.setSelectedId((current) => (current && !listed.has(current) ? null : current))
      state.setSelectedLogin((current) => (current && !listed.has(current.id) ? null : current))
    } catch (error) {
      if (isCurrentVaultLoad(requestId, latestLoad)) events?.loadFailed(error)
    } finally {
      if (isCurrentVaultLoad(requestId, latestLoad)) session.getState().setLoading(false)
    }
  }

  async function refreshItems(): Promise<void> {
    const itemsRequestId = ++latestItemsRequest
    const items = await listLoginsInAllStates(api.logins)
    if (!isCurrentVaultLoad(itemsRequestId, latestItemsRequest)) return
    invalidateProtectedDetails(items)
    detailCache.retainSummaries(items)
    const state = session.getState()
    state.setItems(items)
    state.setSelectedLogin((current) => {
      if (!current) return current
      const summary = items.find((item) => item.id === current.id)
      return summary ? mergeLoginSummary(current, summary) : current
    })
  }

  return {
    load,
    refreshItems,
    subscribe: (nextEvents) => {
      events = nextEvents
      return () => {
        if (events === nextEvents) events = null
      }
    },
    dispose: () => {
      latestLoad += 1
      latestItemsRequest += 1
    }
  }
}
