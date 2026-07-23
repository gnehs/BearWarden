import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
  type SetStateAction
} from 'react'
import { useStore } from 'zustand'
import { createStore, type StoreApi } from 'zustand/vanilla'
import type {
  CollectionView,
  FolderView,
  LoginSummary,
  OrganizationView,
  SharedLoginSummary
} from '../../../shared/vault-contract'
import type { Scope, TypeFilter } from '../components/VaultShell-model'
import type { VaultSortMode } from '../lib/vault-sort'

export type VaultEditorMode = 'create' | 'edit' | null

export interface VaultSessionState {
  folders: FolderView[]
  items: LoginSummary[]
  organizations: OrganizationView[]
  collections: CollectionView[]
  sharedItems: SharedLoginSummary[]
  scope: Scope
  sortMode: VaultSortMode
  typeFilter: TypeFilter
  query: string
  selectedIds: ReadonlySet<string>
  selectedId: string | null
  editorMode: VaultEditorMode
  loading: boolean
  busy: boolean
}

export interface VaultSessionActions {
  setFolders: (value: SetStateAction<FolderView[]>) => void
  setItems: (value: SetStateAction<LoginSummary[]>) => void
  setOrganizations: (value: SetStateAction<OrganizationView[]>) => void
  setCollections: (value: SetStateAction<CollectionView[]>) => void
  setSharedItems: (value: SetStateAction<SharedLoginSummary[]>) => void
  setScope: (value: SetStateAction<Scope>) => void
  setSortMode: (value: SetStateAction<VaultSortMode>) => void
  setTypeFilter: (value: SetStateAction<TypeFilter>) => void
  setQuery: (value: SetStateAction<string>) => void
  setSelectedIds: (value: SetStateAction<ReadonlySet<string>>) => void
  setSelectedId: (value: SetStateAction<string | null>) => void
  setEditorMode: (value: SetStateAction<VaultEditorMode>) => void
  setLoading: (value: SetStateAction<boolean>) => void
  setBusy: (value: SetStateAction<boolean>) => void
  reset: () => void
  activate: () => void
  dispose: () => void
}

export type VaultSessionStore = VaultSessionState & VaultSessionActions
export type VaultSessionStoreApi = StoreApi<VaultSessionStore>

function createInitialState(): VaultSessionState {
  return {
    folders: [],
    items: [],
    organizations: [],
    collections: [],
    sharedItems: [],
    scope: { kind: 'all' },
    sortMode: 'title',
    typeFilter: 'all',
    query: '',
    selectedIds: new Set(),
    selectedId: null,
    editorMode: null,
    loading: true,
    busy: false
  }
}

function resolveValue<T>(value: SetStateAction<T>, current: T): T {
  return typeof value === 'function' ? (value as (current: T) => T)(current) : value
}

// eslint-disable-next-line react-refresh/only-export-components
export function createVaultSessionStore(): VaultSessionStoreApi {
  return createStore<VaultSessionStore>()((set) => {
    let active = true
    const setIfActive = (
      update: (state: VaultSessionStore) => Partial<VaultSessionStore>
    ): void => {
      if (active) set(update)
    }

    return {
      ...createInitialState(),
      setFolders: (value) =>
        setIfActive((state) => ({ folders: resolveValue(value, state.folders) })),
      setItems: (value) => setIfActive((state) => ({ items: resolveValue(value, state.items) })),
      setOrganizations: (value) =>
        setIfActive((state) => ({
          organizations: resolveValue(value, state.organizations)
        })),
      setCollections: (value) =>
        setIfActive((state) => ({ collections: resolveValue(value, state.collections) })),
      setSharedItems: (value) =>
        setIfActive((state) => ({ sharedItems: resolveValue(value, state.sharedItems) })),
      setScope: (value) => setIfActive((state) => ({ scope: resolveValue(value, state.scope) })),
      setSortMode: (value) =>
        setIfActive((state) => ({ sortMode: resolveValue(value, state.sortMode) })),
      setTypeFilter: (value) =>
        setIfActive((state) => ({ typeFilter: resolveValue(value, state.typeFilter) })),
      setQuery: (value) => setIfActive((state) => ({ query: resolveValue(value, state.query) })),
      setSelectedIds: (value) =>
        setIfActive((state) => ({
          selectedIds: new Set(resolveValue(value, state.selectedIds))
        })),
      setSelectedId: (value) =>
        setIfActive((state) => ({ selectedId: resolveValue(value, state.selectedId) })),
      setEditorMode: (value) =>
        setIfActive((state) => ({ editorMode: resolveValue(value, state.editorMode) })),
      setLoading: (value) =>
        setIfActive((state) => ({ loading: resolveValue(value, state.loading) })),
      setBusy: (value) => setIfActive((state) => ({ busy: resolveValue(value, state.busy) })),
      reset: () => set(createInitialState()),
      activate: () => {
        active = true
      },
      dispose: () => {
        active = false
        set(createInitialState())
      }
    }
  })
}

const VaultSessionStoreContext = createContext<VaultSessionStoreApi | null>(null)

export interface VaultSessionStoreProviderProps {
  children: ReactNode
}

export function VaultSessionStoreProvider({
  children
}: VaultSessionStoreProviderProps): React.JSX.Element {
  const [store] = useState(() => createVaultSessionStore())

  useEffect(() => {
    store.getState().activate()
    return () => store.getState().dispose()
  }, [store])

  return (
    <VaultSessionStoreContext.Provider value={store}>{children}</VaultSessionStoreContext.Provider>
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export function useVaultSessionStore<T>(selector: (state: VaultSessionStore) => T): T {
  const store = useVaultSessionStoreApi()

  return useStore(store, selector)
}

// eslint-disable-next-line react-refresh/only-export-components
export function useVaultSessionStoreApi(): VaultSessionStoreApi {
  const store = useContext(VaultSessionStoreContext)

  if (!store) {
    throw new Error('Vault session store must be used within a VaultSessionStoreProvider')
  }

  return store
}
