import { DndContext, DragOverlay } from '@dnd-kit/core'
import { plural } from '@lingui/core/macro'
import { Trans, useLingui } from '@lingui/react/macro'
import {
  BadgeCheck,
  CloudAlert,
  CloudCheck,
  CloudCog,
  CloudSync,
  ContactRound,
  CreditCard,
  FileKey2,
  Fingerprint,
  KeyRound,
  NotebookPen
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { toast } from 'sonner'
import { useShallow } from 'zustand/react/shallow'
import type {
  AppSettingsUpdate,
  FolderView,
  LoginSummary,
  LoginView,
  SyncStatus,
  SharedLoginView,
  VaultExportResult,
  VaultImportResult
} from '../../../shared/vault-contract'
import bearCutUrl from '../assets/bear-cut.svg'
import { ItemDragPreview } from './DragPreview'
import { type ItemSelectionModifiers } from './DndRows'
import LoginEditor from './LoginEditor'
import { precisePointerCollisionDetection } from './VaultShell-dnd'
import SettingsPage from './SettingsPage'
import SendsPage from './SendsPage'
import OrganizationsPage from './OrganizationsPage'
import EmergencyAccessPage from './EmergencyAccessPage'
import VaultHealthPage from './VaultHealthPage'
import { type VaultPortabilityMode } from './VaultPortabilityDialog'
import VaultShellDialogs from './VaultShellDialogs'
import { formatVaultExportResult, formatVaultImportResult } from '../lib/vault-portability-ui'
import { groupItemsByDate } from '../lib/item-date-groups'
import { matchesVaultCategory } from '../lib/vault-category'
import { shouldShowSyncSetupPrompt } from '../lib/sync-setup-prompt'
import { normalizeItemSelection, updateItemSelection } from '../lib/item-selection'
import { isMac, isWindows, usesWindowControlsOverlay } from '../lib/platform'
import { vaultHealthRevision } from '../lib/vault-health-ui'
import { useEditorTransitionGuard } from '@renderer/hooks/use-editor-transition-guard'
import { useVaultAccounts } from '@renderer/hooks/use-vault-accounts'
import { useVaultSearch } from '@renderer/hooks/use-vault-search'
import { useDescribeVaultError } from '@renderer/hooks/use-describe-vault-error'
import { announce, announceError, vaultErrorToastId } from '@renderer/lib/vault-notices'
import { useVaultAuthorization } from '@renderer/hooks/use-vault-authorization'
import { useLoginDetailCache } from '@renderer/hooks/use-login-detail-cache'
import { useVaultDataSync } from '@renderer/hooks/use-vault-data-sync'
import { useAttachmentOperations } from '@renderer/hooks/use-attachment-operations'
import { useSelectedItemTotp, useTotpListCodes } from '@renderer/hooks/use-totp-codes'
import { useSelectedItemSecrets } from '@renderer/hooks/use-selected-item-secrets'
import { useVaultItemActions } from '@renderer/hooks/use-vault-item-actions'
import { useSyncStatus } from '@renderer/hooks/use-sync-status'
import { useLoginApprovalQueue } from '@renderer/hooks/use-login-approval-queue'
import { useVaultItemAccess } from '@renderer/hooks/use-vault-item-access'
import { useVaultLock } from '@renderer/hooks/use-vault-lock'
import { useVaultShortcuts } from '@renderer/hooks/use-vault-shortcuts'
import { useVaultDragAndDrop } from '@renderer/hooks/use-vault-drag-and-drop'
import { useCardCoverPreviews } from '@renderer/hooks/use-card-cover-previews'
import { VaultItemListPane } from './VaultItemListPane'
import type { VirtualizedItemGroup } from './VirtualizedItemList'
import { Button } from '@renderer/components/ui/button'
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle
} from '@renderer/components/ui/empty'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle
} from '@renderer/components/ui/dialog'
import { cn } from '@renderer/lib/utils'
import { activateLanguagePreference } from '@renderer/i18n'
import { useVaultRouteState } from '@renderer/lib/vault-route-state'
import {
  VaultSessionStoreProvider,
  findVaultItem,
  useVaultSessionStore,
  useVaultSessionStoreApi
} from '@renderer/stores/vault-session-store'
import { VaultImageStoreProvider } from '@renderer/stores/vault-image-store'
import { useSettingsStore } from '@renderer/stores/settings-runtime'
import { requestAccountAction } from './account-switcher-ui'
import { DetailPlaceholder, type SidebarTone } from './VaultShell-primitives'
import { VaultShellSidebar } from './VaultShellSidebar'
import { SelectedItemDetail, TrashedItemDetail } from './VaultItemDetailViews'
import { useItemTypeMeta } from '@renderer/hooks/use-item-type-meta'
import {
  type BulkActionSnapshot,
  type MoveSnapshot,
  type Scope,
  type TypeFilter
} from './VaultShell-model'
import { VaultSearchDialog, VaultShellLoading, VaultShellTitlebar } from './VaultShellChrome'
import { isSharedLoginSummary } from './organizations-ui'

const categoryDefinitions: Array<{
  id: TypeFilter
  icon: typeof KeyRound
  tone: SidebarTone
}> = [
  { id: 'all', icon: KeyRound, tone: 'blue' },
  { id: 'login', icon: FileKey2, tone: 'indigo' },
  { id: 'passkey', icon: Fingerprint, tone: 'green' },
  { id: 'totp', icon: BadgeCheck, tone: 'yellow' },
  { id: 'card', icon: CreditCard, tone: 'cyan' },
  { id: 'identity', icon: ContactRound, tone: 'red' },
  { id: 'secureNote', icon: NotebookPen, tone: 'orange' },
  { id: 'sshKey', icon: FileKey2, tone: 'gray' }
]

const syncStateIcons = {
  unconfigured: CloudCog,
  locked: CloudAlert,
  ready: CloudCheck,
  syncing: CloudSync,
  error: CloudAlert
} satisfies Record<SyncStatus['state'], typeof CloudCheck>

const commandLabel = isMac ? '⌘' : 'Ctrl'

interface VaultShellProps {
  onLocked: () => void
  promptSyncSetup: boolean
  onSyncSetupPromptHandled: () => void
}

function VaultShellContent({
  onLocked,
  promptSyncSetup,
  onSyncSetupPromptHandled
}: VaultShellProps): React.JSX.Element {
  const { t } = useLingui()
  const itemTypeMeta = useItemTypeMeta()
  const categoryMeta = useMemo(() => {
    const labels: Record<TypeFilter, string> = {
      all: t`All`,
      login: t`Logins`,
      passkey: t`Passkeys`,
      totp: t`Codes`,
      card: t`Cards`,
      identity: t`Identities`,
      secureNote: t`Notes`,
      sshKey: t`SSH keys`
    }
    return categoryDefinitions.map((category) => ({ ...category, label: labels[category.id] }))
  }, [t])
  const syncStateMeta = {
    unconfigured: { label: t`Not configured`, icon: syncStateIcons.unconfigured },
    locked: { label: t`Unlock required`, icon: syncStateIcons.locked },
    ready: { label: t`Connected`, icon: syncStateIcons.ready },
    syncing: { label: t`Syncing…`, icon: syncStateIcons.syncing },
    error: { label: t`Needs attention`, icon: syncStateIcons.error }
  } satisfies Record<SyncStatus['state'], { label: string; icon: typeof CloudCheck }>
  const sortItemsOptions = [
    { label: t`Name`, value: 'title' },
    {
      label: t({
        message: 'Recently used',
        context: 'recent-items-filter',
        comment: 'Sort label for vault items that have been used most recently.'
      }),
      value: 'recent'
    },
    { label: t`Most used`, value: 'frequency' },
    { label: t`Recently modified`, value: 'modified' }
  ] as const
  const describeVaultError = useDescribeVaultError()
  const {
    settingsOpen,
    setSettingsOpen,
    healthOpen,
    setHealthOpen,
    sendsOpen,
    setSendsOpen,
    organizationsOpen,
    setOrganizationsOpen,
    emergencyAccessOpen,
    setEmergencyAccessOpen
  } = useVaultRouteState()
  const {
    folders,
    items,
    organizations,
    collections,
    sharedItems,
    scope,
    sortMode,
    typeFilter,
    query,
    selectedIds,
    selectedId,
    selectedLogin,
    editorMode,
    loading,
    busy,
    setScope,
    setSortMode,
    setTypeFilter,
    setQuery,
    setSelectedIds,
    setSelectedId,
    setSelectedLogin,
    setEditorMode
  } = useVaultSessionStore(
    useShallow((state) => ({
      folders: state.folders,
      items: state.items,
      organizations: state.organizations,
      collections: state.collections,
      sharedItems: state.sharedItems,
      scope: state.scope,
      sortMode: state.sortMode,
      typeFilter: state.typeFilter,
      query: state.query,
      selectedIds: state.selectedIds,
      selectedId: state.selectedId,
      selectedLogin: state.selectedLogin,
      editorMode: state.editorMode,
      loading: state.loading,
      busy: state.busy,
      setScope: state.setScope,
      setSortMode: state.setSortMode,
      setTypeFilter: state.setTypeFilter,
      setQuery: state.setQuery,
      setSelectedIds: state.setSelectedIds,
      setSelectedId: state.setSelectedId,
      setSelectedLogin: state.setSelectedLogin,
      setEditorMode: state.setEditorMode
    }))
  )
  const sessionStore = useVaultSessionStoreApi()
  const findItem = useCallback(
    (id: string): LoginSummary | undefined => findVaultItem(sessionStore.getState(), id),
    [sessionStore]
  )
  const currentSelectedId = useCallback(
    (): string | null => sessionStore.getState().selectedId,
    [sessionStore]
  )
  const currentSelectedIds = useCallback(
    (): ReadonlySet<string> => sessionStore.getState().selectedIds,
    [sessionStore]
  )
  const allItems = useMemo<LoginSummary[]>(() => [...items, ...sharedItems], [items, sharedItems])
  const { searchOpen, searchRef, scopedItems, setSearchOpen } = useVaultSearch({
    items,
    sharedItems,
    scope,
    typeFilter,
    sortMode,
    query,
    describeError: describeVaultError,
    onError: announceError
  })
  const selectedSummary = allItems.find((item) => item.id === selectedId) ?? null
  const selectedSharedSummary =
    selectedSummary && isSharedLoginSummary(selectedSummary) ? selectedSummary : null
  const [editorSessionId, setEditorSessionId] = useState(0)
  const {
    editorDirty,
    discardEditorDialogOpen,
    handleEditorDirtyChange,
    clearEditorDirty,
    isEditorDirty,
    requestEditorTransition,
    confirmEditorDiscard,
    handleDiscardEditorDialogOpenChange
  } = useEditorTransitionGuard()
  const [folderDialog, setFolderDialog] = useState<FolderView | 'new' | null>(null)
  const [moveSnapshot, setMoveSnapshot] = useState<MoveSnapshot | null>(null)
  const [pendingBulkAction, setPendingBulkAction] = useState<BulkActionSnapshot | null>(null)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [emptyTrashDialogOpen, setEmptyTrashDialogOpen] = useState(false)
  const [passwordHistoryDialogOpen, setPasswordHistoryDialogOpen] = useState(false)
  const [generatorDialogOpen, setGeneratorDialogOpen] = useState(false)
  const {
    previews: cardCoverListPreviews,
    clear: clearCardCoverListPreviews,
    prefetch: prefetchCardCoverPreview
  } = useCardCoverPreviews()
  const {
    authorization,
    prompt: repromptRequest,
    busy: repromptBusy,
    tokens: authorizationTokens
  } = useVaultAuthorization()
  const detailCache = useLoginDetailCache(authorization, prefetchCardCoverPreview)
  const itemAccess = useVaultItemAccess(authorization)
  const vaultData = useVaultDataSync(authorization, detailCache, {
    selectedDetailInvalidated: () => {
      setPasswordHistoryDialogOpen(false)
      clearEditorDirty()
      resetReveals()
    },
    loadStarted: () => toast.dismiss(vaultErrorToastId),
    loadFailed: (error) => announceError(describeVaultError(error))
  })
  const attachments = useAttachmentOperations(authorization, detailCache, vaultData)
  const cancelAndClearAttachment = attachments.cancelAndClear
  const secrets = useSelectedItemSecrets(authorization, itemAccess, vaultData)
  const resetReveals = secrets.resetReveals
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [syncDialogOpen, setSyncDialogOpen] = useState(false)
  const loginApprovals = useLoginApprovalQueue()
  const {
    status: syncStatus,
    loaded: syncStatusLoaded,
    setStatus: setSyncStatus,
    refresh: refreshSyncStatus
  } = useSyncStatus()
  const showSyncSetupPrompt = shouldShowSyncSetupPrompt(promptSyncSetup, syncStatusLoaded)
  const SyncSidebarIcon = syncStateMeta[syncStatus.state].icon
  const settings = useSettingsStore((state) => state.settings)
  const settingsBusy = useSettingsStore((state) => state.busy)
  const loadSettings = useSettingsStore((state) => state.load)
  const persistSettings = useSettingsStore((state) => state.update)
  const persistTouchIdEnable = useSettingsStore((state) => state.enableTouchId)
  const persistTouchIdDisable = useSettingsStore((state) => state.disableTouchId)
  const [touchIdPassword, setTouchIdPassword] = useState('')
  const [portabilityDialogMode, setPortabilityDialogMode] = useState<VaultPortabilityMode | null>(
    null
  )
  const sidebarMenuTriggerRef = useRef<HTMLButtonElement>(null)
  const settingsReturnFocusRef = useRef<HTMLElement | null>(null)
  const defaultSortInitializedRef = useRef(false)
  const compactReturnIdRef = useRef<string | null>(null)
  const compactDetailFocusIdRef = useRef<string | null>(null)
  const selectionAnchorIdRef = useRef<string | null>(null)

  const openEditor = useCallback(
    (mode: 'create' | 'edit'): void => {
      requestEditorTransition(() => {
        setEditorSessionId((current) => current + 1)
        setEditorMode(mode)
      })
    },
    [requestEditorTransition, setEditorMode]
  )

  const clearItemSelection = useCallback((): void => {
    setSelectedIds(new Set())
    selectionAnchorIdRef.current = null
    setSelectedId(null)
    setSelectedLogin(null)
    setPasswordHistoryDialogOpen(false)
  }, [setSelectedId, setSelectedIds, setSelectedLogin])
  const actions = useVaultItemActions({
    authorization,
    detailCache,
    vaultData,
    uploadSelectedCardCover: attachments.uploadSelectedCardCover,
    selectSavedItem,
    clearItemSelection,
    clearEditorDirty,
    resetReveals,
    resetRevealedCustomFields: secrets.resetRevealedCustomFields
  })
  const selectedTotp = useSelectedItemTotp(authorization, itemAccess, clearItemSelection)
  const totpList = useTotpListCodes(authorization, scopedItems, typeFilter === 'totp')

  useEffect(
    () =>
      authorization.subscribeRevoked((id, { preservePasswordHistoryDialog }) => {
        if (currentSelectedId() !== id) return
        if (!preservePasswordHistoryDialog) setPasswordHistoryDialogOpen(false)
        setSelectedLogin(null)
        setEditorMode(null)
        resetReveals()
      }),
    [authorization, currentSelectedId, resetReveals, setEditorMode, setSelectedLogin]
  )

  const activateLogin = useCallback(
    (id: string | null): void => {
      requestEditorTransition(() => {
        if (id) compactReturnIdRef.current = id
        const cached = id ? detailCache.usable(id) : undefined
        if (cached) setSelectedLogin(cached)
        else if (!id) setSelectedLogin(null)
        setSelectedId(id)
        resetReveals()
        setPasswordHistoryDialogOpen(false)
        setEditorMode(null)
      })
    },
    [
      detailCache,
      requestEditorTransition,
      resetReveals,
      setEditorMode,
      setSelectedId,
      setSelectedLogin
    ]
  )

  const selectLogin = useCallback(
    (id: string): void => {
      requestEditorTransition(() => {
        setSelectedIds(new Set([id]))
        selectionAnchorIdRef.current = id
        activateLogin(id)
      })
    },
    [activateLogin, requestEditorTransition, setSelectedIds]
  )
  const dragAndDrop = useVaultDragAndDrop({ actions, selectLogin, setPendingBulkAction })

  const refreshAfterSync = useCallback(async (): Promise<void> => {
    const applyRefresh = async (): Promise<void> => {
      await vaultData.load()
      setEditorMode(null)
      clearItemSelection()
      resetReveals()
    }
    if (isEditorDirty()) {
      requestEditorTransition(() => void applyRefresh())
      return
    }
    await applyRefresh()
  }, [
    clearItemSelection,
    isEditorDirty,
    requestEditorTransition,
    resetReveals,
    setEditorMode,
    vaultData
  ])

  const syncState = syncStatus.state
  useEffect(() => {
    // Re-runs once a sync settles, so a cover that failed while syncing is retried.
    if (!selectedLogin || selectedSharedSummary || syncState === 'syncing') return
    prefetchCardCoverPreview(selectedLogin)
  }, [prefetchCardCoverPreview, selectedLogin, selectedSharedSummary, syncState])

  useEffect(() => {
    if (!settings) {
      void loadSettings().catch(() => {
        // Settings must not prevent access to a successfully unlocked local vault.
      })
      return
    }
    if (defaultSortInitializedRef.current) return
    defaultSortInitializedRef.current = true
    setSortMode(settings.defaultSort === 'name' ? 'title' : settings.defaultSort)
  }, [loadSettings, setSortMode, settings])

  useEffect(() => {
    let active = true
    queueMicrotask(() => {
      if (!active) return
      if (!selectedId) setSelectedLogin(null)
      resetReveals()
    })
    if (!selectedId) {
      return () => {
        active = false
      }
    }

    const summary = allItems.find((item) => item.id === selectedId)
    if (summary?.deletedAt) {
      queueMicrotask(() => {
        if (active) setSelectedLogin(null)
      })
      return () => {
        active = false
      }
    }

    const detailRequest = detailCache.load(selectedId)
    detailRequest
      .then((login) => {
        if (!active) return
        setSelectedLogin(login)
      })
      .catch((detailError) => {
        if (!active) return
        announceError(describeVaultError(detailError))
        clearItemSelection()
      })
    return () => {
      active = false
    }
  }, [
    allItems,
    clearItemSelection,
    describeVaultError,
    detailCache,
    resetReveals,
    selectedId,
    setSelectedLogin
  ])

  const scopedItemIds = useMemo(() => scopedItems.map((item) => item.id), [scopedItems])
  const selectItems = useCallback(
    (id: string, modifiers: ItemSelectionModifiers): void => {
      requestEditorTransition(() => {
        const target = findItem(id)
        if (target && isSharedLoginSummary(target)) {
          setSelectedIds(new Set([id]))
          selectionAnchorIdRef.current = id
          activateLogin(id)
          return
        }
        const nextSelection = updateItemSelection({
          selectedIds: currentSelectedIds(),
          anchorId: selectionAnchorIdRef.current,
          activeId: currentSelectedId(),
          orderedIds: scopedItemIds,
          targetId: id,
          toggle: modifiers.toggle,
          range: modifiers.range
        })
        const containsSharedItem = [...nextSelection.selectedIds].some((selectedItemId) => {
          const selectedItem = findItem(selectedItemId)
          return selectedItem ? isSharedLoginSummary(selectedItem) : false
        })
        const selectedIds = containsSharedItem ? new Set([id]) : nextSelection.selectedIds
        setSelectedIds(selectedIds)
        selectionAnchorIdRef.current = containsSharedItem ? id : nextSelection.anchorId
        activateLogin(containsSharedItem ? id : nextSelection.activeId)
      })
    },
    [
      activateLogin,
      currentSelectedId,
      currentSelectedIds,
      findItem,
      requestEditorTransition,
      scopedItemIds,
      setSelectedIds
    ]
  )

  useEffect(() => {
    const nextSelection = normalizeItemSelection({
      selectedIds: currentSelectedIds(),
      anchorId: selectionAnchorIdRef.current,
      activeId: currentSelectedId(),
      orderedIds: scopedItemIds
    })
    const selectionChanged =
      nextSelection.selectedIds.size !== currentSelectedIds().size ||
      [...nextSelection.selectedIds].some((id) => !currentSelectedIds().has(id))
    if (selectionChanged) setSelectedIds(nextSelection.selectedIds)
    selectionAnchorIdRef.current = nextSelection.anchorId
    if (nextSelection.activeId !== currentSelectedId()) activateLogin(nextSelection.activeId)
  }, [activateLogin, currentSelectedId, currentSelectedIds, scopedItemIds, setSelectedIds])

  useEffect(() => {
    if (!window.matchMedia('(max-width: 680px)').matches) {
      compactDetailFocusIdRef.current = null
      return
    }

    if (selectedId && selectedLogin?.id === selectedId) {
      if (compactDetailFocusIdRef.current !== selectedId) {
        compactDetailFocusIdRef.current = selectedId
        queueMicrotask(() =>
          document.querySelector<HTMLButtonElement>('[data-detail-back]')?.focus()
        )
      }
      return
    }

    if (!selectedId && compactDetailFocusIdRef.current) {
      const returnId = compactReturnIdRef.current
      compactDetailFocusIdRef.current = null
      queueMicrotask(() => {
        const row = Array.from(document.querySelectorAll<HTMLElement>('[data-item-id]')).find(
          (candidate) => candidate.dataset.itemId === returnId
        )
        row?.querySelector<HTMLButtonElement>('[data-item-row-main]')?.focus()
      })
    }
  }, [selectedId, selectedLogin])

  const selectedSummaries = useMemo(
    () => allItems.filter((item) => selectedIds.has(item.id)),
    [allItems, selectedIds]
  )
  const moveSummaries = useMemo(() => {
    if (!moveSnapshot) return []
    const byId = new Map(allItems.map((item) => [item.id, item]))
    return moveSnapshot.ids.flatMap((id) => {
      const item = byId.get(id)
      return item ? [item] : []
    })
  }, [allItems, moveSnapshot])
  const moveFolderId = useMemo(() => {
    const firstFolderId = moveSummaries[0]?.folderId
    if (firstFolderId === undefined) return undefined
    return moveSummaries.every((item) => item.folderId === firstFolderId)
      ? firstFolderId
      : undefined
  }, [moveSummaries])
  const openMoveDialogForSelection = useCallback((): void => {
    if (busy || scope.kind === 'trash') return
    const ids = [...currentSelectedIds()]
    if (ids.length === 0) return
    setMoveSnapshot({ ids, state: scope.kind === 'archive' ? 'archive' : 'active' })
  }, [busy, currentSelectedIds, scope.kind])
  const selectedSharedContext = useMemo(() => {
    if (!selectedSharedSummary) return undefined
    const collectionIds = new Set(selectedSharedSummary.collectionIds)
    return {
      organization:
        organizations.find(
          (organization) => organization.id === selectedSharedSummary.organizationId
        ) ?? null,
      collections: collections.filter(
        (collection) =>
          collection.organizationId === selectedSharedSummary.organizationId &&
          collectionIds.has(collection.id)
      )
    }
  }, [collections, organizations, selectedSharedSummary])
  const itemGroups = useMemo<VirtualizedItemGroup[]>(() => {
    if (sortMode === 'title' || sortMode === 'frequency') {
      return [{ key: 'name', label: null, items: scopedItems }]
    }
    return groupItemsByDate(
      scopedItems,
      new Date(),
      sortMode === 'modified' ? 'updatedAt' : 'activity'
    ).filter((group) => group.items.length > 0)
  }, [scopedItems, sortMode])
  const activeItems = useMemo(
    () => allItems.filter((item) => !item.deletedAt && !item.archivedAt),
    [allItems]
  )
  const archivedItems = useMemo(
    () => items.filter((item) => !item.deletedAt && item.archivedAt),
    [items]
  )
  const trashItems = useMemo(() => items.filter((item) => item.deletedAt), [items])
  const folderCounts = useMemo(() => {
    const counts = new Map<string | null, number>()
    for (const item of activeItems) counts.set(item.folderId, (counts.get(item.folderId) ?? 0) + 1)
    return counts
  }, [activeItems])
  const categoryCounts = useMemo(() => {
    const counts = new Map<TypeFilter, number>()
    for (const category of categoryMeta) {
      counts.set(
        category.id,
        activeItems.filter((item) => matchesVaultCategory(item, category.id)).length
      )
    }
    return counts
  }, [activeItems, categoryMeta])
  const healthRevision = useMemo(() => vaultHealthRevision(items), [items])

  const scopeTitle = useMemo(() => {
    if (scope.kind === 'favorites') return t`Favorites`
    if (scope.kind === 'unfiled') return t`Unfiled`
    if (scope.kind === 'shared') return t`Shared items`
    if (scope.kind === 'organization')
      return (
        organizations.find((organization) => organization.id === scope.organizationId)?.name ??
        t`Organization`
      )
    if (scope.kind === 'collection')
      return (
        collections.find((collection) => collection.id === scope.collectionId)?.name ??
        t({
          message: 'Collection',
          context: 'organization-collection',
          comment:
            'Fallback vault list title for a Bitwarden organization Collection when its name is unavailable.'
        })
      )
    if (scope.kind === 'archive') return t`Archive`
    if (scope.kind === 'trash') return t`Trash`
    if (scope.kind === 'folder')
      return folders.find((folder) => folder.id === scope.folderId)?.name ?? t`Folder`
    if (typeFilter === 'totp') return t`Codes`
    if (typeFilter === 'passkey') return t`Passkeys`
    if (typeFilter !== 'all') return itemTypeMeta[typeFilter].label
    return t`All items`
  }, [collections, folders, itemTypeMeta, organizations, scope, t, typeFilter])
  const sharedScope =
    scope.kind === 'shared' || scope.kind === 'organization' || scope.kind === 'collection'

  const {
    accountStatus,
    accountBusy,
    accountBusyLabel,
    accountError,
    sidebarAccountProfileName,
    refreshAccountProfile,
    addLocalAccount,
    switchLocalAccount,
    renameLocalAccount,
    reorderLocalAccounts,
    removeLocalAccount
  } = useVaultAccounts({ settingsOpen, syncStatus, announce })
  const sidebarAccountName =
    sidebarAccountProfileName || (syncStatus.configured ? t`Connected account` : t`Local vault`)

  const clearSessionSecrets = useCallback(() => {
    cancelAndClearAttachment()
    detailCache.clear()
    clearCardCoverListPreviews()
    resetReveals()
    setTouchIdPassword('')
    setSelectedLogin(null)
  }, [
    cancelAndClearAttachment,
    clearCardCoverListPreviews,
    detailCache,
    resetReveals,
    setSelectedLogin
  ])
  const lockVault = useVaultLock({
    clearSessionSecrets,
    onLocked,
    onNotLocked: () => announceError(t`The vault is not locked yet. Try again.`),
    onError: (error) => announceError(describeVaultError(error)),
    isEditorDirty,
    requestEditorTransition
  })
  useVaultShortcuts({
    auxiliaryPageOpen:
      settingsOpen || healthOpen || sendsOpen || organizationsOpen || emergencyAccessOpen,
    editorMode,
    searchOpen,
    busy,
    canCreate: scope.kind !== 'trash' && scope.kind !== 'archive',
    selectedLogin,
    selectedSummary,
    copyField: secrets.copyField,
    copyTotp: secrets.copyTotp,
    selectAll: () => {
      const nextIds = new Set(scopedItemIds)
      setSelectedIds(nextIds)
      selectionAnchorIdRef.current = scopedItemIds[0] ?? null
      const activeId = currentSelectedId()
      activateLogin(activeId && nextIds.has(activeId) ? activeId : (scopedItemIds[0] ?? null))
    },
    openSearch: () => setSearchOpen(true),
    openEditor,
    openMoveDialog: openMoveDialogForSelection
  })

  useEffect(() => {
    if (!searchOpen) return
    queueMicrotask(() => {
      searchRef.current?.focus()
      searchRef.current?.select()
    })
  }, [searchOpen, searchRef])

  useEffect(() => {
    if (
      settingsOpen ||
      healthOpen ||
      sendsOpen ||
      organizationsOpen ||
      emergencyAccessOpen ||
      !settingsReturnFocusRef.current?.isConnected
    )
      return
    queueMicrotask(() => settingsReturnFocusRef.current?.focus())
  }, [emergencyAccessOpen, healthOpen, organizationsOpen, sendsOpen, settingsOpen])

  useEffect(() => {
    if (!settingsOpen) return
    return () => {
      queueMicrotask(() => setTouchIdPassword(''))
    }
  }, [settingsOpen, t])

  function showVaultList(nextScope: Scope, type: TypeFilter): void {
    requestEditorTransition(() => {
      setScope(nextScope)
      setTypeFilter(type)
      setSidebarOpen(false)
      setSettingsOpen(false)
      setHealthOpen(false)
      setSendsOpen(false)
      setOrganizationsOpen(false)
      setEmergencyAccessOpen(false)
      setTouchIdPassword('')
      setEditorMode(null)
      setMoveSnapshot(null)
    })
  }

  function selectScope(nextScope: Scope): void {
    showVaultList(nextScope, 'all')
  }

  function selectType(type: TypeFilter): void {
    showVaultList({ kind: 'all' }, type)
  }

  function rememberNavigationReturnFocus(): void {
    const activeElement =
      document.activeElement instanceof HTMLElement ? document.activeElement : null
    settingsReturnFocusRef.current = activeElement?.closest('[data-slot="dropdown-menu-content"]')
      ? sidebarMenuTriggerRef.current
      : activeElement
  }

  function openAuxiliaryPage(setPageOpen: (open: boolean) => void): void {
    requestEditorTransition(() => {
      rememberNavigationReturnFocus()
      setPageOpen(true)
      setSearchOpen(false)
      setSidebarOpen(false)
      setEditorMode(null)
      setMoveSnapshot(null)
      clearItemSelection()
      resetReveals()
    })
  }

  function openSettings(): void {
    requestEditorTransition(() => {
      rememberNavigationReturnFocus()
      setSettingsOpen(true)
      setSidebarOpen(false)
      setEditorMode(null)
      setMoveSnapshot(null)
      clearItemSelection()
      resetReveals()
    })
  }

  function closeSettings(): void {
    setSettingsOpen(false)
    setTouchIdPassword('')
  }

  function openHealth(): void {
    openAuxiliaryPage(setHealthOpen)
  }

  function closeHealth(): void {
    setHealthOpen(false)
  }

  function openSends(): void {
    openAuxiliaryPage(setSendsOpen)
  }

  function closeSends(): void {
    setSendsOpen(false)
  }

  function closeOrganizations(): void {
    setOrganizationsOpen(false)
  }

  function openEmergencyAccess(): void {
    openAuxiliaryPage(setEmergencyAccessOpen)
  }

  function closeEmergencyAccess(): void {
    setEmergencyAccessOpen(false)
  }

  function openHealthItem(id: string): void {
    setHealthOpen(false)
    setScope({ kind: 'all' })
    setTypeFilter('login')
    setQuery('')
    selectLogin(id)
  }

  async function updateSettings(update: AppSettingsUpdate): Promise<boolean> {
    try {
      const next = await persistSettings(update)
      if (update.language) await activateLanguagePreference(next.language).catch(() => undefined)
      if (update.defaultSort) {
        setSortMode(update.defaultSort === 'name' ? 'title' : update.defaultSort)
      }
      announce(t`Settings saved.`)
      return true
    } catch (settingsError) {
      announceError(describeVaultError(settingsError))
      return false
    }
  }

  async function enableTouchId(): Promise<void> {
    if (!touchIdPassword) {
      announceError(t`Enter your master password before enabling biometrics.`)
      return
    }
    try {
      await persistTouchIdEnable({
        masterPassword: touchIdPassword
      })
      setTouchIdPassword('')
      announce(t`Biometrics enabled.`)
    } catch (touchIdError) {
      announceError(describeVaultError(touchIdError))
    }
  }

  async function disableTouchId(): Promise<void> {
    try {
      await persistTouchIdDisable()
      announce(t`Biometrics disabled.`)
    } catch (touchIdError) {
      announceError(describeVaultError(touchIdError))
    }
  }

  function announceExported(result: VaultExportResult): void {
    announce(formatVaultExportResult(result))
  }

  async function refreshAfterImport(result: VaultImportResult): Promise<void> {
    await vaultData.load()
    announce(formatVaultImportResult(result))
  }

  function selectSavedItem(id: string, login: LoginView | SharedLoginView | null): void {
    setSelectedIds(new Set([id]))
    selectionAnchorIdRef.current = id
    setSelectedId(id)
    setSelectedLogin(login)
  }

  const closeAuxiliaryPage = healthOpen
    ? closeHealth
    : organizationsOpen
      ? closeOrganizations
      : emergencyAccessOpen
        ? closeEmergencyAccess
        : sendsOpen
          ? closeSends
          : settingsOpen
            ? closeSettings
            : null
  const auxiliaryPageOpen = closeAuxiliaryPage !== null

  if (loading) {
    return <VaultShellLoading appearance={{ isMac, usesWindowControlsOverlay }} />
  }

  return (
    <DndContext
      sensors={dragAndDrop.sensors}
      collisionDetection={precisePointerCollisionDetection}
      onDragStart={dragAndDrop.startDrag}
      onDragOver={dragAndDrop.dragOver}
      onDragCancel={dragAndDrop.cancelDrag}
      onDragEnd={(event) => void dragAndDrop.endDrag(event)}
    >
      <main
        className={cn(
          'bg-background flex size-full min-w-0 flex-col',
          isMac && 'platform-macos',
          isWindows && 'platform-windows',
          (isMac || isWindows) && 'bg-transparent',
          usesWindowControlsOverlay && 'platform-window-controls-overlay'
        )}
        data-has-detail={selectedId || editorMode ? 'true' : 'false'}
      >
        <VaultShellTitlebar
          appearance={{ isMac }}
          navigation={{
            auxiliaryPageOpen,
            closeAuxiliaryPage,
            sidebarOpen,
            onToggleSidebar: () => setSidebarOpen((open) => !open)
          }}
          search={{
            query,
            open: searchOpen,
            shortcutLabel: commandLabel,
            onOpen: () => setSearchOpen(true),
            onClear: () => setQuery('')
          }}
          itemCreation={{
            visible:
              !auxiliaryPageOpen &&
              !sharedScope &&
              scope.kind !== 'archive' &&
              scope.kind !== 'trash',
            onCreate: () => openEditor('create')
          }}
          onLockVault={lockVault}
        />

        <Button
          variant="ghost"
          className={cn(
            'hidden max-[880px]:pointer-events-none max-[880px]:fixed max-[880px]:inset-0 max-[880px]:z-30 max-[880px]:block max-[880px]:size-full max-[880px]:rounded-none max-[880px]:border-0 max-[880px]:bg-[color-mix(in_oklch,var(--foreground)_34%,transparent)] max-[880px]:p-0 max-[880px]:opacity-0 max-[880px]:shadow-none max-[880px]:transition-opacity max-[880px]:duration-180 max-[880px]:hover:bg-[color-mix(in_oklch,var(--foreground)_34%,transparent)] max-[880px]:active:bg-[color-mix(in_oklch,var(--foreground)_34%,transparent)]',
            sidebarOpen && 'max-[880px]:pointer-events-auto max-[880px]:opacity-100'
          )}
          type="button"
          aria-label={t`Close sidebar`}
          aria-hidden={!sidebarOpen}
          tabIndex={sidebarOpen ? 0 : -1}
          onClick={() => setSidebarOpen(false)}
        />

        <VaultSearchDialog
          state={{ open: searchOpen, query, items: scopedItems, scopeTitle }}
          inputRef={searchRef}
          presentation={{
            itemTypes: itemTypeMeta,
            showWebsiteIcons: settings?.showWebsiteIcons ?? false,
            isTrash: scope.kind === 'trash'
          }}
          actions={{
            onOpenChange: setSearchOpen,
            onQueryChange: setQuery,
            onSelectItem: (id) => {
              selectLogin(id)
              setSearchOpen(false)
            }
          }}
        />

        <div
          className={cn(
            'relative grid min-h-0 min-w-0 flex-1 overflow-hidden max-[680px]:block',

            auxiliaryPageOpen
              ? 'grid-cols-[minmax(0,1fr)] [&>[data-vault-pane-group]>[data-vault-detail-pane]]:hidden [&>[data-vault-pane-group]>[data-vault-list-pane]]:border-r-0 [&>[data-vault-sidebar]]:hidden'
              : 'grid-cols-[260px_minmax(0,1fr)] max-[1050px]:grid-cols-[220px_minmax(0,1fr)] max-[880px]:grid-cols-[minmax(0,1fr)]',

            (isMac || isWindows) && 'gap-3 overflow-visible pr-3 pb-3 max-[880px]:pl-3',
            auxiliaryPageOpen && (isMac || isWindows) && 'pl-3'
          )}
        >
          <VaultShellSidebar
            appearance={{ isMac, isWindows, open: sidebarOpen }}
            navigation={{
              categories: categoryMeta,
              categoryCounts,
              specialFolderCounts: {
                favorites: activeItems.filter((item) => item.favorite).length,
                archive: archivedItems.length,
                trash: trashItems.length
              },
              folderCounts,
              organizations,
              collections,
              sharedItems
            }}
            account={{
              name: sidebarAccountName,
              syncState: syncStatus.state,
              syncLabel: syncStateMeta[syncStatus.state].label,
              syncIcon: SyncSidebarIcon,
              commandLabel
            }}
            actions={{
              onSelectType: selectType,
              onSelectScope: selectScope,
              onAddFolder: () => setFolderDialog('new'),
              onEditFolder: setFolderDialog,
              onOpenGenerator: () => setGeneratorDialogOpen(true),
              onOpenEmergencyAccess: openEmergencyAccess,
              onOpenSends: openSends,
              onOpenHealth: openHealth,
              onOpenSettings: openSettings,
              onLockVault: lockVault,
              onOpenSync: () => setSyncDialogOpen(true)
            }}
            accountMenuTriggerRef={sidebarMenuTriggerRef}
          />

          <div
            className={cn(
              'bg-card grid min-h-0 min-w-0 overflow-hidden max-[680px]:block max-[680px]:size-full',

              auxiliaryPageOpen
                ? 'grid-cols-[minmax(0,1fr)]'
                : 'grid-cols-[minmax(340px,390px)_minmax(0,1fr)] max-[1050px]:grid-cols-[minmax(290px,330px)_minmax(0,1fr)] max-[880px]:grid-cols-[minmax(260px,300px)_minmax(0,1fr)]',

              (isMac || isWindows) && 'gap-3 overflow-visible bg-transparent max-[680px]:gap-0'
            )}
            data-vault-pane-group=""
          >
            <section
              className={cn(
                'border-border relative flex min-h-0 min-w-0 flex-col border-r bg-transparent max-[680px]:size-full [[data-has-detail=true]_&]:max-[680px]:hidden',
                (isMac || isWindows) &&
                  'overflow-hidden rounded-[1.75rem] border-0 bg-(--glass-surface) bg-(image:--surface-sheen) shadow-(--surface-shadow) ring-1 ring-(--surface-ring) backdrop-blur-2xl backdrop-saturate-150'
              )}
              data-vault-list-pane=""
              aria-labelledby={
                healthOpen
                  ? 'health-title'
                  : organizationsOpen
                    ? 'organizations-title'
                    : emergencyAccessOpen
                      ? 'emergency-access-title'
                      : sendsOpen
                        ? 'sends-title'
                        : settingsOpen
                          ? 'settings-title'
                          : 'list-title'
              }
            >
              {healthOpen ? (
                <VaultHealthPage revision={healthRevision} onOpenItem={openHealthItem} />
              ) : organizationsOpen ? (
                <OrganizationsPage />
              ) : emergencyAccessOpen ? (
                <EmergencyAccessPage />
              ) : sendsOpen ? (
                <SendsPage />
              ) : settingsOpen ? (
                <SettingsPage
                  settings={settings}
                  settingsBusy={settingsBusy}
                  syncStatus={syncStatus}
                  touchIdPassword={touchIdPassword}
                  onUpdate={updateSettings}
                  onTouchIdPasswordChange={setTouchIdPassword}
                  onEnableTouchId={enableTouchId}
                  onDisableTouchId={disableTouchId}
                  onOpenSync={() => setSyncDialogOpen(true)}
                  onVaultPurged={async () => {
                    await Promise.allSettled([vaultData.load(), refreshSyncStatus()])
                  }}
                  onExportVault={() => setPortabilityDialogMode('export')}
                  onImportVault={() => setPortabilityDialogMode('import')}
                  accountStatus={accountStatus}
                  accountBusy={accountBusy}
                  accountBusyLabel={accountBusyLabel}
                  accountError={accountError}
                  onRequestAccountAdd={(proceed) =>
                    requestAccountAction(requestEditorTransition, proceed)
                  }
                  onRequestAccountSwitch={(proceed) =>
                    requestAccountAction(requestEditorTransition, proceed)
                  }
                  onRequestAccountRemove={(proceed) =>
                    requestAccountAction(requestEditorTransition, proceed)
                  }
                  onAddAccount={addLocalAccount}
                  onSwitchAccount={switchLocalAccount}
                  onRenameAccount={renameLocalAccount}
                  onReorderAccounts={reorderLocalAccounts}
                  onRemoveAccount={removeLocalAccount}
                />
              ) : (
                <VaultItemListPane
                  list={{
                    scopeTitle,
                    itemCount: scopedItems.length,
                    groups: itemGroups,
                    cardCoverPreviews: cardCoverListPreviews,
                    sortOptions: sortItemsOptions,
                    showWebsiteIcons: settings?.showWebsiteIcons ?? false,
                    totpCodes: totpList.codes,
                    totpCountdown: totpList.countdown,
                    trashItemCount: trashItems.length,
                    readOnly: sharedScope
                  }}
                  selection={{
                    selectedItemCount: selectedSummaries.length
                  }}
                  actions={{
                    onPrefetch: detailCache.prefetch,
                    onSelect: selectItems,
                    onToggleFavorite: actions.toggleFavorite,
                    onContextMenu: secrets.showLoginContextMenu,
                    onOpenCreate: () => openEditor('create'),
                    snapshotBulkAction: actions.snapshotBulkAction,
                    onPerformBulkAction: actions.performBulkAction,
                    onSetPendingBulkAction: setPendingBulkAction,
                    onOpenMove: openMoveDialogForSelection,
                    onEmptyTrash: () => setEmptyTrashDialogOpen(true)
                  }}
                />
              )}
            </section>

            <section
              className={cn(
                'relative isolate flex min-h-0 min-w-0 overflow-hidden bg-(--canvas) max-[680px]:hidden max-[680px]:size-full [[data-has-detail=true]_&]:max-[680px]:flex',
                (isMac || isWindows) &&
                  'rounded-[1.75rem] shadow-(--surface-shadow) ring-1 ring-(--surface-ring)'
              )}
              data-vault-detail-pane=""
              aria-label={t`Item details`}
            >
              {editorMode ? (
                <LoginEditor
                  key={`${editorSessionId}:${editorMode}:${selectedLogin?.id ?? 'new'}`}
                  login={editorMode === 'edit' ? (selectedLogin ?? undefined) : undefined}
                  folders={folders}
                  organizations={organizations}
                  collections={collections}
                  sharedContext={
                    editorMode === 'edit' && selectedSharedSummary && selectedSharedContext
                      ? {
                          organizationName: selectedSharedContext.organization?.name ?? '',
                          collectionNames: selectedSharedContext.collections.map(
                            (collection) => collection.name
                          ),
                          canEditSecrets: selectedSharedSummary.viewPassword
                        }
                      : undefined
                  }
                  busy={busy}
                  authorizationToken={
                    selectedLogin ? authorizationTokens[selectedLogin.id] : undefined
                  }
                  attachmentUpload={
                    editorMode === 'edit' && selectedLogin && !selectedSharedSummary
                      ? {
                          attachmentCount: selectedLogin.attachments.length,
                          operation: attachments.operation,
                          syncReady: syncStatus.state === 'ready',
                          getOperationStageLabel: attachments.getStageLabel,
                          onUpload: attachments.upload,
                          onUploadCardCover: attachments.uploadManualCardCover,
                          onCancelOperation: attachments.cancel
                        }
                      : undefined
                  }
                  onCancel={() => requestEditorTransition(() => setEditorMode(null))}
                  onDirtyChange={handleEditorDirtyChange}
                  onDeletePasskey={actions.deletePasskey}
                  onSave={actions.saveLogin}
                />
              ) : selectedSummary?.deletedAt ? (
                <TrashedItemDetail
                  summary={selectedSummary}
                  folders={folders}
                  busy={busy}
                  onBack={clearItemSelection}
                  onViewPasswordHistory={() => setPasswordHistoryDialogOpen(true)}
                  onRestore={() => void actions.restoreLogin()}
                  onDelete={() => setDeleteDialogOpen(true)}
                />
              ) : selectedId && selectedSummary && selectedLogin?.id !== selectedId ? (
                <DetailPlaceholder
                  item={selectedSummary}
                  showWebsiteIcons={settings?.showWebsiteIcons ?? false}
                  onBack={clearItemSelection}
                />
              ) : selectedLogin && selectedLogin.id === selectedId ? (
                <SelectedItemDetail
                  login={selectedLogin}
                  sharedSummary={selectedSharedSummary}
                  sharedContext={selectedSharedContext}
                  folders={folders}
                  busy={busy}
                  showWebsiteIcons={settings?.showWebsiteIcons ?? false}
                  cardCoverPreview={cardCoverListPreviews.get(selectedLogin.id)}
                  syncReady={syncStatus.state === 'ready'}
                  showTotpCountdown={typeFilter !== 'totp'}
                  secrets={secrets}
                  attachments={attachments}
                  totp={selectedTotp}
                  actions={{
                    onBack: clearItemSelection,
                    onEdit: () => openEditor('edit'),
                    onToggleFavorite: () => void actions.toggleFavorite(selectedLogin),
                    onClone: () => void actions.cloneLogin(),
                    onToggleArchive: () =>
                      void (selectedLogin.archivedAt
                        ? actions.unarchiveLogin()
                        : actions.archiveLogin()),
                    onDelete: () => setDeleteDialogOpen(true),
                    onMoveToFolder: openMoveDialogForSelection,
                    onViewPasswordHistory: () => setPasswordHistoryDialogOpen(true)
                  }}
                />
              ) : (
                <Empty className="min-h-0 flex-1 gap-0 p-7">
                  <EmptyHeader>
                    <EmptyMedia
                      className="text-muted-foreground mb-4 h-48 bg-transparent"
                      aria-hidden="true"
                    >
                      <img className="size-48 object-contain" src={bearCutUrl} alt="" />
                    </EmptyMedia>
                    <EmptyTitle className="text-foreground m-0 text-xl font-bold">
                      <Trans>No item selected</Trans>
                    </EmptyTitle>
                    <EmptyDescription className="text-muted-foreground mt-2 mb-4 max-w-[290px] text-xs leading-relaxed">
                      <Trans>Select an item to view and manage its secure data.</Trans>
                    </EmptyDescription>
                  </EmptyHeader>
                </Empty>
              )}
            </section>
          </div>
        </div>

        <VaultShellDialogs
          itemDialogs={{
            busy,
            folder: {
              value: folderDialog,
              folders,
              onClose: () => setFolderDialog(null),
              onSave: async (name) => {
                if (folderDialog && (await actions.saveFolder(folderDialog, name))) {
                  setFolderDialog(null)
                }
              },
              onDelete: async () => {
                if (!folderDialog || folderDialog === 'new') return
                if (await actions.deleteFolder(folderDialog)) setFolderDialog(null)
              }
            },
            move: {
              snapshot: moveSnapshot,
              itemName: moveSummaries[0]?.name,
              currentFolderId: moveFolderId,
              folders,
              onClose: () => setMoveSnapshot(null),
              onMove: actions.moveLogins
            },
            deletion: {
              selectedSummary,
              deleteOpen: deleteDialogOpen,
              onCloseDelete: () => setDeleteDialogOpen(false),
              onDelete: async () => {
                if (await actions.deleteLogin()) setDeleteDialogOpen(false)
              },
              trashItemCount: trashItems.length,
              emptyTrashOpen: emptyTrashDialogOpen,
              onCloseEmptyTrash: () => setEmptyTrashDialogOpen(false),
              onEmptyTrash: async () => {
                if (await actions.emptyTrash()) setEmptyTrashDialogOpen(false)
              },
              pendingBulkAction,
              onCloseBulkAction: () => setPendingBulkAction(null),
              onPerformBulkAction: actions.performBulkAction
            },
            passwordHistory: {
              open: passwordHistoryDialogOpen,
              selectedSummary,
              onClose: () => setPasswordHistoryDialogOpen(false),
              onLoad: secrets.loadPasswordHistory,
              onReveal: secrets.revealPasswordHistory,
              onCopy: secrets.copyPasswordHistory
            },
            passwordZoom: {
              value: secrets.passwordZoomValue,
              onClose: secrets.closePasswordZoom
            },
            generator: {
              open: generatorDialogOpen,
              onClose: () => setGeneratorDialogOpen(false)
            },
            attachment: {
              deleteTarget: attachments.deleteTarget,
              onCloseDelete: () => attachments.setDeleteTarget(null),
              onDelete: attachments.deleteSelected
            }
          }}
          securityDialogs={{
            reprompt: {
              prompt: repromptRequest && {
                itemName:
                  repromptRequest.count === 1
                    ? (repromptRequest.itemName ?? t`This item`)
                    : t({
                        message: plural(repromptRequest.count, {
                          one: '# protected item',
                          other: '# protected items'
                        })
                      })
              },
              busy: repromptBusy,
              onCancel: authorization.cancel,
              onAuthorize: authorization.submit
            },
            loginApproval: {
              prompt: loginApprovals.current,
              onClose: loginApprovals.dismissCurrent
            },
            editorDiscard: {
              open: discardEditorDialogOpen && editorDirty,
              busy,
              onOpenChange: handleDiscardEditorDialogOpenChange,
              onConfirm: confirmEditorDiscard
            }
          }}
          syncDialogs={{
            sync: {
              open: syncDialogOpen || showSyncSetupPrompt,
              status: syncStatus,
              onClose: () => {
                setSyncDialogOpen(false)
                onSyncSetupPromptHandled()
                refreshAccountProfile()
              },
              onStatusChange: setSyncStatus,
              onSynced: refreshAfterSync
            },
            portability: {
              mode: portabilityDialogMode,
              onClose: () => setPortabilityDialogMode(null),
              onExported: announceExported,
              onImported: refreshAfterImport
            }
          }}
        />
        <Dialog
          open={attachments.imagePreview !== null}
          onOpenChange={(open) => {
            if (!open) attachments.setImagePreview(null)
          }}
        >
          <DialogContent className="max-w-[min(920px,calc(100vw-32px))] gap-4">
            <DialogHeader>
              <DialogTitle>
                {attachments.imagePreview?.fileName ?? t`Attachment preview`}
              </DialogTitle>
              <DialogDescription>
                <Trans>Image attachment preview</Trans>
              </DialogDescription>
            </DialogHeader>
            {attachments.imagePreview && (
              <div className="bg-muted grid max-h-[min(70vh,720px)] place-items-center overflow-auto rounded-md border p-2">
                <img
                  className="max-h-[min(66vh,680px)] max-w-full object-contain"
                  src={attachments.imagePreview.dataUrl}
                  alt={attachments.imagePreview.fileName}
                />
              </div>
            )}
          </DialogContent>
        </Dialog>
      </main>

      <DragOverlay dropAnimation={null} style={{ pointerEvents: 'none' }}>
        {dragAndDrop.activeDragItem ? (
          <ItemDragPreview
            item={dragAndDrop.activeDragItem}
            count={dragAndDrop.activeDragItemCount}
            showWebsiteIcons={settings?.showWebsiteIcons ?? false}
            destinationDescription={dragAndDrop.activeDragDestinationDescription}
          />
        ) : null}
      </DragOverlay>
    </DndContext>
  )
}

function VaultShell(props: VaultShellProps): React.JSX.Element {
  return (
    <VaultSessionStoreProvider>
      <VaultImageStoreProvider>
        <VaultShellContent {...props} />
      </VaultImageStoreProvider>
    </VaultSessionStoreProvider>
  )
}

export default VaultShell
