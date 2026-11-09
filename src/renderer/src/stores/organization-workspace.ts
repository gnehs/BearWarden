import { createStore, type StoreApi } from 'zustand/vanilla'
import type {
  BearWardenAPI,
  CollectionView,
  OrganizationView,
  SharedLoginSummary,
  SharedLoginView
} from '../../../shared/vault-contract'

export interface OrganizationWorkspaceApi {
  organizations: Pick<BearWardenAPI['organizations'], 'list'>
  collections: Pick<BearWardenAPI['collections'], 'list'>
  sharedLogins: Pick<BearWardenAPI['sharedLogins'], 'list' | 'get'>
}

export interface OrganizationWorkspaceState {
  organizations: OrganizationView[]
  collections: CollectionView[]
  items: SharedLoginSummary[]
  organizationId: string | null
  collectionId: string | null
  loading: boolean
  loadError: boolean
  selectedItemId: string | null
  selected: SharedLoginView | null
  selectedLoading: boolean
  selectedError: boolean
}

export interface OrganizationWorkspace {
  store: StoreApi<OrganizationWorkspaceState>
  /** Loads organizations, collections and shared items, replacing any load still in flight. */
  load: () => Promise<void>
  selectItem: (item: SharedLoginSummary) => Promise<void>
  clearSelected: () => void
  selectOrganization: (id: string | null) => void
  selectCollection: (id: string | null) => void
  dispose: () => void
}

const EMPTY_SELECTION = {
  selectedItemId: null,
  selected: null,
  selectedLoading: false,
  selectedError: false
} satisfies Partial<OrganizationWorkspaceState>

/**
 * The read-only organization browser. Each load and each detail request carries a sequence
 * number, so a slower older response never replaces a newer one. `dispose` drops every response
 * still in flight; a later `load` (a remount) starts fresh.
 */
export function createOrganizationWorkspace(
  getApi: () => OrganizationWorkspaceApi
): OrganizationWorkspace {
  const store = createStore<OrganizationWorkspaceState>()(() => ({
    organizations: [],
    collections: [],
    items: [],
    organizationId: null,
    collectionId: null,
    loading: true,
    loadError: false,
    ...EMPTY_SELECTION
  }))
  let loadSequence = 0
  let selectionSequence = 0

  function clearSelected(): void {
    selectionSequence += 1
    store.setState(EMPTY_SELECTION)
  }

  async function load(): Promise<void> {
    const sequence = ++loadSequence
    clearSelected()
    store.setState({ loading: true, loadError: false })
    try {
      const api = getApi()
      const [organizations, collections, items] = await Promise.all([
        api.organizations.list(),
        api.collections.list(),
        api.sharedLogins.list()
      ])
      if (sequence !== loadSequence) return
      store.setState({
        organizations,
        collections,
        items,
        organizationId: organizations[0]?.id ?? null,
        collectionId: null,
        loading: false
      })
    } catch {
      if (sequence !== loadSequence) return
      store.setState({ loading: false, loadError: true })
    }
  }

  async function selectItem(item: SharedLoginSummary): Promise<void> {
    const sequence = ++selectionSequence
    store.setState({ ...EMPTY_SELECTION, selectedItemId: item.id, selectedLoading: true })
    const isCurrent = (): boolean => sequence === selectionSequence
    try {
      const selected = await getApi().sharedLogins.get({ id: item.id })
      if (isCurrent()) store.setState({ selected, selectedLoading: false })
    } catch {
      if (isCurrent()) store.setState({ selectedError: true, selectedLoading: false })
    }
  }

  function selectCollection(id: string | null): void {
    store.setState({ collectionId: id })
    clearSelected()
  }

  function selectOrganization(id: string | null): void {
    store.setState({ organizationId: id })
    selectCollection(null)
  }

  function dispose(): void {
    loadSequence += 1
    selectionSequence += 1
  }

  return { store, load, selectItem, clearSelected, selectOrganization, selectCollection, dispose }
}
