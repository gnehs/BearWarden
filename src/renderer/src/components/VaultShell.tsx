import {
  DndContext,
  DragOverlay,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
  type DragOverEvent,
  type DragStartEvent
} from '@dnd-kit/core'
import { arrayMove, sortableKeyboardCoordinates } from '@dnd-kit/sortable'
import { plural } from '@lingui/core/macro'
import { Trans, useLingui } from '@lingui/react/macro'
import {
  ArrowLeft,
  Archive,
  ArchiveRestore,
  BadgeCheck,
  CloudAlert,
  CloudCheck,
  CloudCog,
  CloudSync,
  ContactRound,
  Copy,
  CreditCard,
  Edit3,
  FileKey2,
  Fingerprint,
  History,
  KeyRound,
  MoreHorizontal,
  NotebookPen,
  RotateCcw,
  Settings2,
  Star,
  Trash2,
  Upload
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { toast } from 'sonner'
import { useStore } from 'zustand'
import { useShallow } from 'zustand/react/shallow'
import type {
  AppSettingsUpdate,
  AttachmentOperationKind,
  AttachmentOperationStage,
  AttachmentProgressEvent,
  FolderView,
  LoginSummary,
  LoginView,
  LoginAuthorization,
  LoginApprovalPrompt,
  PasswordHistoryEntryRequest,
  SyncStatus,
  TotpCodeView,
  VaultCopyField,
  VaultCustomFieldSource,
  VaultCustomFieldView,
  VaultExportResult,
  VaultImportResult,
  VaultItemType,
  VaultSecretField,
  VaultAttachmentView
} from '../../../shared/vault-contract'
import {
  MAX_LOGIN_BATCH_IDS,
  MAX_LOGIN_MOVE_MANY_IDS,
  MAX_LOGIN_PREFETCH_IDS
} from '../../../shared/vault-contract'
import bearCutUrl from '../assets/bear-cut.svg'
import { ItemDragPreview } from './DragPreview'
import { type ItemSelectionModifiers } from './DndRows'
import LoginEditor, { type LoginDraft } from './LoginEditor'
import {
  createLoginWithOptionalSshImport,
  updateLoginWithOptionalSshImport
} from './ssh-key-editor-state'
import {
  canUseCachedLoginDetail,
  hasTrashPasswordHistory,
  isCurrentPrefetchedDetailResponse,
  isCurrentVaultLoad,
  isCurrentSelectedDetailResponse,
  protectedDetailInvalidationIds
} from './VaultShell-security'
import {
  itemDropPreviewDescription,
  precisePointerCollisionDetection,
  quickAccessDropAction
} from './VaultShell-dnd'
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
import { normalizeBitwardenCardBrand } from '../lib/payment-card'
import { shouldShowSyncSetupPrompt } from '../lib/sync-setup-prompt'
import { normalizeItemSelection, updateItemSelection } from '../lib/item-selection'
import { vaultHealthRevision } from '../lib/vault-health-ui'
import { useCopyFeedback } from '@renderer/hooks/use-copy-feedback'
import { useEditorTransitionGuard } from '@renderer/hooks/use-editor-transition-guard'
import { useVaultAccounts } from '@renderer/hooks/use-vault-accounts'
import { useVaultSearch } from '@renderer/hooks/use-vault-search'
import { resolveTotpRefreshTarget } from './totp-refresh-target'
import PaymentCardBrandMark from './PaymentCardBrandMark'
import WebsiteIcon from './WebsiteIcon'
import { VaultCustomFieldRows, VaultDetailFieldRows } from './VaultDetailFieldRows'
import { VaultItemMetadataCards } from './VaultItemMetadataCards'
import { VaultItemListPane } from './VaultItemListPane'
import { VaultItemAttachmentsCard, VaultItemTotpCard } from './VaultItemAccessCards'
import { Button } from '@renderer/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger
} from '@renderer/components/ui/dropdown-menu'
import { CardContent, CardDescription, CardHeader, CardTitle } from '@renderer/components/ui/card'
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle
} from '@renderer/components/ui/empty'
import { Tooltip, TooltipContent, TooltipTrigger } from '@renderer/components/ui/tooltip'
import { cn } from '@renderer/lib/utils'
import { activateLanguagePreference } from '@renderer/i18n'
import { useVaultRouteState } from '@renderer/lib/vault-route-state'
import {
  VaultSessionStoreProvider,
  useVaultSessionStore
} from '@renderer/stores/vault-session-store'
import {
  createSyncStatusStore,
  startSyncStatusSubscription
} from '@renderer/stores/sync-status-store'
import { useSettingsStore } from '@renderer/stores/settings-runtime'
import { requestAccountAction } from './account-switcher-ui'
import {
  DetailCard,
  DetailHeader,
  DetailPlaceholder,
  TooltipIconButton,
  detailIconClassName,
  detailScrollClassName,
  hostLabel,
  type SidebarTone
} from './VaultShell-primitives'
import { VaultShellSidebar } from './VaultShellSidebar'
import {
  emptyRevealedCustomFields,
  emptyRevealedSecrets,
  totpListCountdownPeriodSeconds,
  type BulkActionKind,
  type BulkActionSnapshot,
  type BulkSelectionState,
  type MoveSnapshot,
  type PendingReprompt,
  type RepromptPromptState,
  type RevealedCustomFieldsState,
  type RevealedSecretsState,
  type Scope,
  type TotpGenerationErrorState,
  type TotpListEntry,
  type TypeFilter
} from './VaultShell-model'
import {
  initialAttachmentStages,
  isAttachmentCanceled,
  type AttachmentDeleteTarget,
  type AttachmentOperationState
} from './vault-attachment-ui'
import {
  customFieldCopyFeedbackKey,
  detailFields,
  matchesCustomFieldSource
} from './vault-detail-view-model'
import {
  cacheLoginDetail,
  firstAuthorizationToken,
  mergeCachedSummary,
  mergeLoginSummary,
  toLoginSummary
} from './vault-detail-cache'
import { describeError, isRepromptRequired } from './vault-error-ui'
import { VaultSearchDialog, VaultShellLoading, VaultShellTitlebar } from './VaultShellChrome'

interface ItemTypeMeta {
  label: string
  icon: typeof KeyRound
}

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

const isMac = navigator.userAgent.includes('Mac')
const isWindows = navigator.userAgent.includes('Windows')
const usesWindowControlsOverlay = !isMac
const commandLabel = isMac ? '⌘' : 'Ctrl'

interface VaultShellProps {
  onLocked: () => void
  promptSyncSetup: boolean
  onSyncSetupPromptHandled: () => void
}

const vaultErrorToastId = 'vault-error'

function announceError(message: string): void {
  toast.error(message, {
    id: vaultErrorToastId,
    duration: 7_000
  })
}

function VaultShellContent({
  onLocked,
  promptSyncSetup,
  onSyncSetupPromptHandled
}: VaultShellProps): React.JSX.Element {
  const { i18n, t } = useLingui()
  const itemTypeMeta = useMemo<Record<VaultItemType, ItemTypeMeta>>(
    () => ({
      login: { label: t`Login`, icon: KeyRound },
      card: {
        label: t({
          message: 'Card',
          comment: 'Vault item category label for payment card records.'
        }),
        icon: CreditCard
      },
      identity: { label: t`Identity`, icon: ContactRound },
      secureNote: { label: t`Secure note`, icon: NotebookPen },
      sshKey: { label: t`SSH key`, icon: FileKey2 }
    }),
    [t]
  )
  const categoryMeta = useMemo(
    () =>
      categoryDefinitions.map((category) => ({
        ...category,
        label:
          category.id === 'all'
            ? t`All`
            : category.id === 'login'
              ? t`Logins`
              : category.id === 'passkey'
                ? t`Passkeys`
                : category.id === 'totp'
                  ? t`Codes`
                  : category.id === 'card'
                    ? t`Cards`
                    : category.id === 'identity'
                      ? t`Identities`
                      : category.id === 'secureNote'
                        ? t`Notes`
                        : t`SSH keys`
      })),
    [t]
  )
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
        comment: 'Navigation and sort label for vault items that have been used most recently.'
      }),
      value: 'recent'
    },
    { label: t`Most used`, value: 'frequency' },
    { label: t`Recently modified`, value: 'modified' }
  ] as const
  const detailFieldLabels = useMemo<Record<string, string>>(
    () => ({
      username: t`Username`,
      password: t`Password`,
      website: t`Website`,
      cardNumber: t`Card number`,
      securityCode: t`Security code`,
      cardholder: t`Cardholder`,
      brand: t({
        message: 'Brand',
        comment:
          'Field label for the payment card issuer or network brand, such as Visa or Mastercard.'
      }),
      expirationDate: t`Expiration date`,
      name: t`Name`,
      company: t({
        message: 'Company',
        comment: 'Field label for the company name in an identity item.'
      }),
      email: t`Email`,
      phone: t`Phone`,
      address: t`Address`,
      ssn: t`ID / Social Security number`,
      passportNumber: t`Passport number`,
      licenseNumber: t`Driver's license number`,
      privateKey: t`Private key`,
      publicKey: t`Public key`,
      keyFingerprint: t`Key fingerprint`
    }),
    [t]
  )
  const linkedFieldLabels: Record<number, string> = {
    100: t`Username`,
    101: t`Password`,
    300: t`Cardholder`,
    301: t`Expiration month`,
    302: t`Expiration year`,
    303: t`Security code`,
    304: t`Brand`,
    305: t`Card number`,
    400: t`Title`,
    401: t`Middle name`,
    402: t`Address 1`,
    403: t`Address 2`,
    404: t`Address 3`,
    405: t`City`,
    406: t`State / Province`,
    407: t`Postal code`,
    408: t`Country`,
    409: t`Company`,
    410: t`Email`,
    411: t`Phone`,
    412: t`ID / Social Security number`,
    413: t`Username`,
    414: t`Passport number`,
    415: t`Driver's license number`,
    416: t`First name`,
    417: t`Last name`,
    418: t`Full name`
  }
  const customFieldLabels = {
    yes: t`Yes`,
    no: t`No`,
    linkedTo: (label: string): string => t`Linked to ${label}`,
    itemField: t`Item field`,
    linkedFields: linkedFieldLabels,
    unset: t`Not set`
  }
  const getAttachmentStageLabel = (progress: AttachmentProgressEvent): string => {
    if (progress.stage === 'choosing-file' && progress.kind === 'download') {
      return t`Waiting for a save location`
    }
    const labels: Record<AttachmentOperationStage, string> = {
      'choosing-file': t`Waiting for a file`,
      'reading-file': t`Safely reading the file`,
      encrypting: t`Encrypting locally`,
      downloading: t`Downloading attachment`,
      uploading: t`Uploading encrypted attachment`,
      deleting: t`Deleting attachment`,
      syncing: t`Syncing attachment list`
    }
    return labels[progress.stage]
  }
  const errorMessages = useMemo<Record<string, string>>(
    () => ({
      LOCKED: t`The vault is locked. Unlock it and try again.`,
      NOT_FOUND: t`The requested item could not be found.`,
      INVALID_INPUT: t`The input is invalid. Check it and try again.`,
      DUPLICATE_NAME: t`That name is already in use. Choose another name.`,
      INVALID_URL: t`The website URL is invalid.`,
      ATTACHMENT_FAILED: t`The attachment operation failed. The server content may have changed; sync and try again.`,
      ATTACHMENT_TOO_LARGE: t`The attachment is too large to encrypt within the safe memory limit.`,
      ATTACHMENT_STORAGE_LIMIT: t`There is not enough Bitwarden attachment storage. Free some space and try again.`,
      ATTACHMENT_REJECTED: t`This server or account does not currently allow this attachment to be added.`,
      ATTACHMENT_CANCELED: t`The attachment operation was canceled.`
    }),
    [t]
  )
  const describeVaultError = useCallback(
    (error: unknown): string =>
      describeError(
        error,
        errorMessages,
        t`An unknown error occurred.`,
        t`The operation did not finish. Refresh and confirm the current state.`
      ),
    [errorMessages, t]
  )
  const formatDate = (value: string | null): string => {
    if (!value) return t`Never used`
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return t`Unknown`
    return new Intl.DateTimeFormat(i18n.locale, {
      dateStyle: 'medium',
      timeStyle: 'short'
    }).format(date)
  }
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
    scope,
    sortMode,
    typeFilter,
    query,
    selectedIds,
    selectedId,
    editorMode,
    loading,
    busy,
    setFolders,
    setItems,
    setScope,
    setSortMode,
    setTypeFilter,
    setQuery,
    setSelectedIds,
    setSelectedId,
    setEditorMode,
    setLoading,
    setBusy
  } = useVaultSessionStore(
    useShallow((state) => ({
      folders: state.folders,
      items: state.items,
      scope: state.scope,
      sortMode: state.sortMode,
      typeFilter: state.typeFilter,
      query: state.query,
      selectedIds: state.selectedIds,
      selectedId: state.selectedId,
      editorMode: state.editorMode,
      loading: state.loading,
      busy: state.busy,
      setFolders: state.setFolders,
      setItems: state.setItems,
      setScope: state.setScope,
      setSortMode: state.setSortMode,
      setTypeFilter: state.setTypeFilter,
      setQuery: state.setQuery,
      setSelectedIds: state.setSelectedIds,
      setSelectedId: state.setSelectedId,
      setEditorMode: state.setEditorMode,
      setLoading: state.setLoading,
      setBusy: state.setBusy
    }))
  )
  const { searchOpen, searchRef, scopedItems, updateQuery, setSearchOpen } = useVaultSearch({
    items,
    scope,
    typeFilter,
    sortMode,
    query,
    setQuery,
    describeError: describeVaultError,
    onError: announceError
  })
  const [selectedLogin, setSelectedLogin] = useState<LoginView | null>(null)
  const { copiedKey, clearCopied, showCopied } = useCopyFeedback()
  const selectedSummary = items.find((item) => item.id === selectedId) ?? null
  const [totpCodeState, setTotpCodeState] = useState<{
    itemId: string
    code: TotpCodeView
    cycle: number
  } | null>(null)
  const [totpGenerationErrorState, setTotpGenerationErrorState] =
    useState<TotpGenerationErrorState | null>(null)
  const [totpListState, setTotpListState] = useState<Map<string, TotpListEntry>>(() => new Map())
  const totpListStateRef = useRef(new Map<string, TotpListEntry>())
  const totpCode =
    selectedLogin && totpCodeState?.itemId === selectedLogin.id ? totpCodeState.code : null
  const totpGenerationError =
    selectedLogin && totpGenerationErrorState?.itemId === selectedLogin.id
      ? totpGenerationErrorState.kind
      : null
  const totpRevealReady = totpCode !== null || totpGenerationError !== null
  const [showTotpSkeleton, setShowTotpSkeleton] = useState(false)
  const totpRefreshTarget = resolveTotpRefreshTarget(selectedLogin, selectedId, editorMode !== null)
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
  const [revealedSecrets, setRevealedSecrets] = useState<RevealedSecretsState>(emptyRevealedSecrets)
  const [revealedCustomFields, setRevealedCustomFields] =
    useState<RevealedCustomFieldsState>(emptyRevealedCustomFields)
  const [folderDialog, setFolderDialog] = useState<FolderView | 'new' | null>(null)
  const [moveSnapshot, setMoveSnapshot] = useState<MoveSnapshot | null>(null)
  const [pendingBulkAction, setPendingBulkAction] = useState<BulkActionSnapshot | null>(null)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [emptyTrashDialogOpen, setEmptyTrashDialogOpen] = useState(false)
  const [passwordHistoryDialogOpen, setPasswordHistoryDialogOpen] = useState(false)
  const [passwordZoom, setPasswordZoom] = useState<{ itemId: string; value: string } | null>(null)
  if (passwordZoom !== null && passwordZoom.itemId !== selectedLogin?.id) {
    setPasswordZoom(null)
  }
  const passwordZoomValue =
    passwordZoom !== null && passwordZoom.itemId === selectedLogin?.id ? passwordZoom.value : null
  const hoveringSecretFieldsRef = useRef(new Set<VaultSecretField>())
  const hoverRevealedSecretFieldsRef = useRef(new Set<VaultSecretField>())
  const passwordZoomOpenRef = useRef(false)
  const [generatorDialogOpen, setGeneratorDialogOpen] = useState(false)
  const [attachmentOperation, setAttachmentOperation] = useState<AttachmentOperationState | null>(
    null
  )
  const [attachmentDeleteTarget, setAttachmentDeleteTarget] =
    useState<AttachmentDeleteTarget | null>(null)
  const [repromptPrompt, setRepromptPrompt] = useState<RepromptPromptState | null>(null)
  const [repromptBusy, setRepromptBusy] = useState(false)
  const [authorizationTokenState, setAuthorizationTokenState] = useState<Record<string, string>>({})
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [syncDialogOpen, setSyncDialogOpen] = useState(false)
  const [loginApprovalPrompts, setLoginApprovalPrompts] = useState<LoginApprovalPrompt[]>([])
  const [syncStatusStore] = useState(() => createSyncStatusStore())
  const syncStatus = useStore(syncStatusStore, (state) => state.status)
  const syncStatusLoaded = useStore(syncStatusStore, (state) => state.loaded)
  const setSyncStatus = syncStatusStore.getState().setStatus
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
  const [activeDragId, setActiveDragId] = useState<string | null>(null)
  const [activeDragOverId, setActiveDragOverId] = useState<string | null>(null)
  const foldersBeforeDragRef = useRef<FolderView[] | null>(null)
  const foldersDuringDragRef = useRef<FolderView[] | null>(null)
  const sidebarMenuTriggerRef = useRef<HTMLButtonElement>(null)
  const settingsReturnFocusRef = useRef<HTMLElement | null>(null)
  const defaultSortInitializedRef = useRef(false)
  const compactReturnIdRef = useRef<string | null>(null)
  const compactDetailFocusIdRef = useRef<string | null>(null)
  const selectedIdRef = useRef<string | null>(null)
  const selectedIdsRef = useRef<ReadonlySet<string>>(new Set())
  const selectionAnchorIdRef = useRef<string | null>(null)
  const detailRequestsRef = useRef(new Map<string, Promise<LoginView>>())
  const detailPrefetchRequestsRef = useRef(new Map<string, Promise<LoginView | undefined>>())
  const detailPrefetchQueueRef = useRef(new Set<string>())
  const detailPrefetchScheduledRef = useRef(false)
  const detailCacheRef = useRef(new Map<string, LoginView>())
  const detailCacheGenerationRef = useRef(0)
  // A successful list load may invalidate protected details, so list freshness needs its own epoch.
  const vaultLoadRequestIdRef = useRef(0)
  const itemsRef = useRef<LoginSummary[]>([])
  const authorizationCacheRef = useRef(new Map<string, LoginAuthorization>())
  const authorizationExpiryTimersRef = useRef(new Map<string, number>())
  const pendingRepromptRef = useRef<PendingReprompt | null>(null)
  const attachmentOperationRef = useRef<AttachmentOperationState | null>(null)

  const beginAttachmentOperation = useCallback(
    (kind: AttachmentOperationKind, itemId: string, fileName: string | null): string => {
      const operationId = crypto.randomUUID()
      const operation: AttachmentOperationState = {
        operationId,
        itemId,
        kind,
        stage: initialAttachmentStages[kind],
        completedBytes: 0,
        totalBytes: null,
        fileName,
        canceling: false
      }
      attachmentOperationRef.current = operation
      setAttachmentOperation(operation)
      setAttachmentDeleteTarget(null)
      return operationId
    },
    [setAttachmentDeleteTarget]
  )

  const finishAttachmentOperation = useCallback((operationId: string): void => {
    if (attachmentOperationRef.current?.operationId !== operationId) return
    attachmentOperationRef.current = null
    setAttachmentOperation((current) => (current?.operationId === operationId ? null : current))
  }, [])

  const cancelAndClearAttachmentOperation = useCallback((): void => {
    const operation = attachmentOperationRef.current
    attachmentOperationRef.current = null
    setAttachmentOperation(null)
    setAttachmentDeleteTarget(null)
    if (operation) {
      void window.bearwarden.logins
        .cancelAttachment({ operationId: operation.operationId })
        .catch(() => undefined)
    }
  }, [setAttachmentDeleteTarget])

  const isCurrentAttachmentOperation = useCallback(
    (operationId: string, itemId: string): boolean => {
      const current = attachmentOperationRef.current
      return (
        current !== null &&
        current.operationId === operationId &&
        current.itemId === itemId &&
        selectedIdRef.current === itemId
      )
    },
    []
  )

  const openEditor = useCallback(
    (mode: 'create' | 'edit'): void => {
      requestEditorTransition(() => {
        setEditorSessionId((current) => current + 1)
        setEditorMode(mode)
      })
    },
    [requestEditorTransition, setEditorMode]
  )

  const updateSelectedIds = useCallback(
    (nextIds: ReadonlySet<string>): void => {
      selectedIdsRef.current = nextIds
      setSelectedIds(nextIds)
    },
    [setSelectedIds]
  )

  const clearItemSelection = useCallback((): void => {
    updateSelectedIds(new Set())
    selectionAnchorIdRef.current = null
    selectedIdRef.current = null
    setSelectedId(null)
    setSelectedLogin(null)
    setPasswordHistoryDialogOpen(false)
  }, [setPasswordHistoryDialogOpen, setSelectedId, updateSelectedIds])

  const clearDetailCache = useCallback((): void => {
    detailCacheGenerationRef.current += 1
    detailRequestsRef.current.clear()
    detailPrefetchRequestsRef.current.clear()
    detailPrefetchQueueRef.current.clear()
    detailCacheRef.current.clear()
  }, [])

  const authorizationToken = useCallback(
    (id: string): string | undefined => {
      const authorization = authorizationCacheRef.current.get(id)
      if (!authorization) return undefined
      if (authorization.expiresAt <= Date.now()) {
        detailCacheGenerationRef.current += 1
        detailRequestsRef.current.clear()
        authorizationCacheRef.current.delete(id)
        detailCacheRef.current.delete(id)
        const timer = authorizationExpiryTimersRef.current.get(id)
        if (timer !== undefined) window.clearTimeout(timer)
        authorizationExpiryTimersRef.current.delete(id)
        setAuthorizationTokenState((current) => {
          const next = { ...current }
          delete next[id]
          return next
        })
        if (selectedIdRef.current === id) {
          setPasswordHistoryDialogOpen(false)
          setSelectedLogin(null)
          setEditorMode(null)
          setTotpCodeState(null)
          setRevealedSecrets(emptyRevealedSecrets)
          setRevealedCustomFields(emptyRevealedCustomFields)
        }
        return undefined
      }
      return authorization.token
    },
    [setEditorMode, setPasswordHistoryDialogOpen]
  )

  const invalidateProtectedDetails = useCallback(
    (summaries: readonly LoginSummary[]): void => {
      const invalidIds = protectedDetailInvalidationIds(summaries, (id) =>
        Boolean(authorizationToken(id))
      )
      if (invalidIds.size === 0) return
      detailCacheGenerationRef.current += 1
      detailRequestsRef.current.clear()
      for (const id of invalidIds) detailCacheRef.current.delete(id)
      if (selectedIdRef.current && invalidIds.has(selectedIdRef.current)) {
        setPasswordHistoryDialogOpen(false)
        setSelectedLogin(null)
        setEditorMode(null)
        clearEditorDirty()
        setTotpCodeState(null)
        setRevealedSecrets(emptyRevealedSecrets)
        setRevealedCustomFields(emptyRevealedCustomFields)
      }
    },
    [authorizationToken, clearEditorDirty, setEditorMode, setPasswordHistoryDialogOpen]
  )

  const discardAuthorizationToken = useCallback((id: string): void => {
    authorizationCacheRef.current.delete(id)
    setAuthorizationTokenState((current) => {
      if (!(id in current)) return current
      const next = { ...current }
      delete next[id]
      return next
    })
    const timer = authorizationExpiryTimersRef.current.get(id)
    if (timer !== undefined) window.clearTimeout(timer)
    authorizationExpiryTimersRef.current.delete(id)
  }, [])

  const invalidateAuthorization = useCallback(
    (id: string, preservePasswordHistoryDialog = false): void => {
      detailCacheGenerationRef.current += 1
      detailRequestsRef.current.clear()
      discardAuthorizationToken(id)
      detailCacheRef.current.delete(id)
      if (selectedIdRef.current === id) {
        if (!preservePasswordHistoryDialog) setPasswordHistoryDialogOpen(false)
        setSelectedLogin(null)
        setEditorMode(null)
        setRevealedSecrets(emptyRevealedSecrets)
        setRevealedCustomFields(emptyRevealedCustomFields)
      }
    },
    [discardAuthorizationToken, setEditorMode, setPasswordHistoryDialogOpen]
  )

  const cacheAuthorization = useCallback(
    (id: string, authorization: LoginAuthorization): void => {
      // Replacing an authorization token must not dismiss the operation that requested it.
      discardAuthorizationToken(id)
      authorizationCacheRef.current.set(id, authorization)
      setAuthorizationTokenState((current) => ({
        ...current,
        [id]: authorization.token
      }))
      const delay = Math.max(0, authorization.expiresAt - Date.now())
      const timer = window.setTimeout(() => {
        const current = authorizationCacheRef.current.get(id)
        if (current?.token === authorization.token) invalidateAuthorization(id)
      }, delay)
      authorizationExpiryTimersRef.current.set(id, timer)
    },
    [discardAuthorizationToken, invalidateAuthorization]
  )

  const requestReprompt = useCallback(
    (ids: readonly string[]): Promise<LoginAuthorization> => {
      const normalizedIds = [...ids].sort()
      if (normalizedIds.length === 1) {
        const cached = authorizationCacheRef.current.get(normalizedIds[0]!)
        if (cached && authorizationToken(normalizedIds[0]!)) return Promise.resolve(cached)
      }
      const key = normalizedIds.join('\n')
      const pending = pendingRepromptRef.current
      if (pending) {
        if (pending.key === key) return pending.promise
        return Promise.reject(new Error('REPROMPT_REQUIRED'))
      }
      let resolve!: (authorization: LoginAuthorization) => void
      let reject!: (error: Error) => void
      const promise = new Promise<LoginAuthorization>((resolvePromise, rejectPromise) => {
        resolve = resolvePromise
        reject = rejectPromise
      })
      pendingRepromptRef.current = { key, ids: normalizedIds, promise, resolve, reject }
      const item = itemsRef.current.find((candidate) => candidate.id === normalizedIds[0])
      setRepromptPrompt({
        itemName:
          normalizedIds.length === 1
            ? (item?.name ?? t`This item`)
            : t({
                message: plural(normalizedIds.length, {
                  one: '# protected item',
                  other: '# protected items'
                })
              })
      })
      return promise
    },
    [authorizationToken, t]
  )

  const withReprompt = useCallback(
    async <T,>(
      ids: readonly string[],
      operation: (tokenFor: (id: string) => string | undefined) => Promise<T>,
      preservePasswordHistoryDialog = false
    ): Promise<T> => {
      const protectedIds = ids.filter(
        (id) => itemsRef.current.find((item) => item.id === id)?.reprompt === 1
      )
      const authorization = protectedIds.length > 0 ? await requestReprompt(ids) : undefined
      const tokenFor = (id: string): string | undefined =>
        authorization ? authorization.token : authorizationToken(id)
      try {
        return await operation(tokenFor)
      } catch (error) {
        if (!isRepromptRequired(error) || ids.length === 0) throw error
        for (const id of ids) invalidateAuthorization(id, preservePasswordHistoryDialog)
        const retryIds = ids
        const retryAuthorization = await requestReprompt(retryIds)
        return operation((id) =>
          retryIds.includes(id) ? retryAuthorization.token : authorizationToken(id)
        )
      }
    },
    [authorizationToken, invalidateAuthorization, requestReprompt]
  )

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  )

  const loadVault = useCallback(async (): Promise<void> => {
    const requestId = ++vaultLoadRequestIdRef.current
    clearDetailCache()
    try {
      toast.dismiss(vaultErrorToastId)
      const [folderList, activeItems, archivedItems, deletedItems] = await Promise.all([
        window.bearwarden.folders.list(),
        window.bearwarden.logins.list({ sort: 'name' }),
        window.bearwarden.logins.list({ sort: 'name', archived: true }),
        window.bearwarden.logins.list({ sort: 'name', deleted: true })
      ])
      const loginList = [...activeItems, ...archivedItems, ...deletedItems]
      if (!isCurrentVaultLoad(requestId, vaultLoadRequestIdRef.current)) return
      invalidateProtectedDetails(loginList)
      setFolders([...folderList].sort((left, right) => left.position - right.position))
      setItems(loginList)
      setScope((current) =>
        current.kind === 'folder' && !folderList.some((folder) => folder.id === current.folderId)
          ? { kind: 'all' }
          : current
      )
      setSelectedId((current) =>
        current && !loginList.some((item) => item.id === current) ? null : current
      )
      setSelectedLogin((current) =>
        current && !loginList.some((item) => item.id === current.id) ? null : current
      )
    } catch (loadError) {
      if (isCurrentVaultLoad(requestId, vaultLoadRequestIdRef.current)) {
        announceError(describeVaultError(loadError))
      }
    } finally {
      if (isCurrentVaultLoad(requestId, vaultLoadRequestIdRef.current)) setLoading(false)
    }
  }, [
    clearDetailCache,
    describeVaultError,
    invalidateProtectedDetails,
    setFolders,
    setItems,
    setLoading,
    setScope,
    setSelectedId
  ])

  const loadLoginDetail = useCallback(
    (id: string): Promise<LoginView> => {
      const summary = itemsRef.current.find((item) => item.id === id)
      if (summary?.deletedAt) return Promise.reject(new Error('INVALID_INPUT'))
      const cached = detailCacheRef.current.get(id)
      if (
        cached &&
        canUseCachedLoginDetail(summary, cached.reprompt, Boolean(authorizationToken(id)))
      ) {
        detailCacheRef.current.delete(id)
        detailCacheRef.current.set(id, cached)
        return Promise.resolve(cached)
      }

      const pending = detailRequestsRef.current.get(id)
      if (pending) return pending

      const startSelectedRequest = (): Promise<LoginView> => {
        let requestGeneration = detailCacheGenerationRef.current
        return withReprompt([id], (tokenFor) => {
          requestGeneration = detailCacheGenerationRef.current
          return window.bearwarden.logins.get({
            id,
            ...(tokenFor(id) ? { authorizationToken: tokenFor(id) } : {})
          })
        }).then((login) => {
          if (
            !isCurrentSelectedDetailResponse({
              id,
              selectedId: selectedIdRef.current,
              requestGeneration,
              currentGeneration: detailCacheGenerationRef.current,
              reprompt: login.reprompt,
              authorizationToken: authorizationToken(id)
            })
          ) {
            throw new Error('DETAIL_REQUEST_INVALIDATED')
          }
          cacheLoginDetail(detailCacheRef.current, login)
          return login
        })
      }

      const pendingPrefetch = detailPrefetchRequestsRef.current.get(id)
      const promise = pendingPrefetch
        ? pendingPrefetch.then((prefetched) => {
            const currentSummary = itemsRef.current.find((item) => item.id === id)
            const currentCached = detailCacheRef.current.get(id) ?? prefetched
            if (
              currentCached &&
              canUseCachedLoginDetail(
                currentSummary,
                currentCached.reprompt,
                Boolean(authorizationToken(id))
              )
            ) {
              cacheLoginDetail(detailCacheRef.current, currentCached)
              return currentCached
            }
            if (selectedIdRef.current !== id) throw new Error('DETAIL_REQUEST_INVALIDATED')
            return startSelectedRequest()
          })
        : startSelectedRequest()
      detailRequestsRef.current.set(id, promise)
      void promise
        .catch(() => undefined)
        .finally(() => {
          if (detailRequestsRef.current.get(id) === promise) detailRequestsRef.current.delete(id)
        })
      return promise
    },
    [authorizationToken, withReprompt]
  )

  const prefetchLoginDetail = useCallback((id: string): void => {
    const summary = itemsRef.current.find((item) => item.id === id)
    // Never speculatively cross the authorization boundary or hydrate inactive items.
    if (
      !summary ||
      summary.reprompt !== 0 ||
      summary.deletedAt !== null ||
      summary.archivedAt !== null ||
      detailCacheRef.current.has(id) ||
      detailRequestsRef.current.has(id) ||
      detailPrefetchRequestsRef.current.has(id)
    ) {
      return
    }

    detailPrefetchQueueRef.current.add(id)
    if (detailPrefetchScheduledRef.current) return
    detailPrefetchScheduledRef.current = true
    queueMicrotask(() => {
      detailPrefetchScheduledRef.current = false
      const queuedIds = [...detailPrefetchQueueRef.current]
      detailPrefetchQueueRef.current.clear()
      const eligibleIds = queuedIds.filter((queuedId) => {
        const queuedSummary = itemsRef.current.find((item) => item.id === queuedId)
        return Boolean(
          queuedSummary &&
          queuedSummary.reprompt === 0 &&
          queuedSummary.deletedAt === null &&
          queuedSummary.archivedAt === null &&
          !detailCacheRef.current.has(queuedId) &&
          !detailRequestsRef.current.has(queuedId) &&
          !detailPrefetchRequestsRef.current.has(queuedId)
        )
      })

      for (let offset = 0; offset < eligibleIds.length; offset += MAX_LOGIN_PREFETCH_IDS) {
        const ids = eligibleIds.slice(offset, offset + MAX_LOGIN_PREFETCH_IDS)
        const requestGeneration = detailCacheGenerationRef.current
        const batchPromise = window.bearwarden.logins.prefetch({ ids })
        for (const queuedId of ids) {
          const itemPromise = batchPromise
            .then((logins) => {
              const login = logins.find((candidate) => candidate.id === queuedId)
              if (
                !login ||
                !isCurrentPrefetchedDetailResponse({
                  requestGeneration,
                  currentGeneration: detailCacheGenerationRef.current,
                  response: login,
                  summary: itemsRef.current.find((item) => item.id === queuedId)
                })
              ) {
                return undefined
              }
              cacheLoginDetail(detailCacheRef.current, login)
              return login
            })
            .catch(() => undefined)
            .finally(() => {
              if (detailPrefetchRequestsRef.current.get(queuedId) === itemPromise) {
                detailPrefetchRequestsRef.current.delete(queuedId)
              }
            })
          detailPrefetchRequestsRef.current.set(queuedId, itemPromise)
        }
      }
    })
  }, [])

  const activateLogin = useCallback(
    (id: string | null): void => {
      requestEditorTransition(() => {
        if (id) compactReturnIdRef.current = id
        selectedIdRef.current = id
        const cached = id ? detailCacheRef.current.get(id) : undefined
        const summary = id ? itemsRef.current.find((item) => item.id === id) : undefined
        const canUseCached =
          cached &&
          canUseCachedLoginDetail(summary, cached.reprompt, Boolean(authorizationToken(cached.id)))
        if (canUseCached) setSelectedLogin(cached)
        else if (!id) setSelectedLogin(null)
        setSelectedId(id)
        setRevealedSecrets(emptyRevealedSecrets)
        setRevealedCustomFields(emptyRevealedCustomFields)
        setPasswordHistoryDialogOpen(false)
        setEditorMode(null)
      })
    },
    [
      authorizationToken,
      requestEditorTransition,
      setEditorMode,
      setPasswordHistoryDialogOpen,
      setSelectedId
    ]
  )

  const selectLogin = useCallback(
    (id: string): void => {
      requestEditorTransition(() => {
        updateSelectedIds(new Set([id]))
        selectionAnchorIdRef.current = id
        activateLogin(id)
      })
    },
    [activateLogin, requestEditorTransition, updateSelectedIds]
  )

  const showLoginContextMenu = useCallback(
    (id: string, position: { x: number; y: number }): void => {
      void withReprompt([id], (tokenFor) =>
        window.bearwarden.logins.showContextMenu({
          id,
          ...position,
          ...(tokenFor(id) ? { authorizationToken: tokenFor(id) } : {})
        })
      ).catch((menuError) => announceError(describeVaultError(menuError)))
    },
    [describeVaultError, withReprompt]
  )

  const loadPasswordHistory = useCallback(async () => {
    const summary = selectedSummary
    if (!summary || summary.passwordHistoryCount === 0) throw new Error('INVALID_INPUT')
    const itemId = summary.id
    return withReprompt(
      [itemId],
      (tokenFor) =>
        window.bearwarden.logins.getPasswordHistory({
          id: itemId,
          ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {})
        }),
      true
    )
  }, [selectedSummary, withReprompt])

  const revealPasswordHistory = useCallback(
    async (
      locator: Omit<PasswordHistoryEntryRequest, 'id' | 'authorizationToken'>
    ): Promise<string> => {
      const summary = selectedSummary
      if (!summary) throw new Error('INVALID_INPUT')
      const itemId = summary.id
      return withReprompt(
        [itemId],
        (tokenFor) =>
          window.bearwarden.logins.revealPasswordHistory({
            id: itemId,
            ...locator,
            ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {})
          }),
        true
      )
    },
    [selectedSummary, withReprompt]
  )

  const copyPasswordHistory = useCallback(
    async (
      locator: Omit<PasswordHistoryEntryRequest, 'id' | 'authorizationToken'>
    ): Promise<void> => {
      const summary = selectedSummary
      if (!summary) throw new Error('INVALID_INPUT')
      const itemId = summary.id
      await withReprompt(
        [itemId],
        (tokenFor) =>
          window.bearwarden.logins.copyPasswordHistory({
            id: itemId,
            ...locator,
            ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {})
          }),
        true
      )
    },
    [selectedSummary, withReprompt]
  )

  const refreshItems = useCallback(async (): Promise<void> => {
    const [activeItems, archivedItems, deletedItems] = await Promise.all([
      window.bearwarden.logins.list({ sort: 'name' }),
      window.bearwarden.logins.list({ sort: 'name', archived: true }),
      window.bearwarden.logins.list({ sort: 'name', deleted: true })
    ])
    const loginList = [...activeItems, ...archivedItems, ...deletedItems]
    invalidateProtectedDetails(loginList)
    const currentIds = new Set(loginList.map((login) => login.id))
    for (const cachedId of detailCacheRef.current.keys()) {
      if (!currentIds.has(cachedId)) detailCacheRef.current.delete(cachedId)
    }
    for (const summary of loginList) mergeCachedSummary(detailCacheRef.current, summary)
    setItems(loginList)
    setSelectedLogin((current) => {
      if (!current) return current
      const summary = loginList.find((item) => item.id === current.id)
      return summary ? mergeLoginSummary(current, summary) : current
    })
  }, [invalidateProtectedDetails, setItems])

  const updateSelectedAttachments = useCallback(
    (
      itemId: string,
      update: (attachments: VaultAttachmentView[]) => VaultAttachmentView[]
    ): void => {
      if (selectedIdRef.current !== itemId) return
      setSelectedLogin((current) => {
        if (!current || current.id !== itemId) return current
        const attachments = update(current.attachments)
        const next = { ...current, attachments, attachmentCount: attachments.length }
        cacheLoginDetail(detailCacheRef.current, next)
        return next
      })
    },
    []
  )

  const refreshAfterSync = useCallback(async (): Promise<void> => {
    const applyRefresh = async (): Promise<void> => {
      await loadVault()
      setEditorMode(null)
      clearItemSelection()
      setRevealedSecrets(emptyRevealedSecrets)
      setRevealedCustomFields(emptyRevealedCustomFields)
    }
    if (isEditorDirty()) {
      requestEditorTransition(() => void applyRefresh())
      return
    }
    await applyRefresh()
  }, [clearItemSelection, isEditorDirty, loadVault, requestEditorTransition, setEditorMode])

  useEffect(() => {
    queueMicrotask(() => void loadVault())
  }, [loadVault])

  useEffect(
    () => () => {
      vaultLoadRequestIdRef.current += 1
      clearDetailCache()
    },
    [clearDetailCache]
  )

  useEffect(() => {
    itemsRef.current = items
  }, [items])

  useEffect(
    () => () => {
      for (const timer of authorizationExpiryTimersRef.current.values()) {
        window.clearTimeout(timer)
      }
      authorizationExpiryTimersRef.current.clear()
      authorizationCacheRef.current.clear()
      pendingRepromptRef.current?.reject(new Error('REPROMPT_REQUIRED'))
      pendingRepromptRef.current = null
    },
    []
  )

  useEffect(() => {
    selectedIdRef.current = selectedId
    let active = true
    queueMicrotask(() => {
      if (!active) return
      const operation = attachmentOperationRef.current
      if (operation && operation.itemId !== selectedId) cancelAndClearAttachmentOperation()
      setAttachmentDeleteTarget((current) => (current?.itemId === selectedId ? current : null))
    })
    return () => {
      active = false
    }
  }, [cancelAndClearAttachmentOperation, selectedId])

  useEffect(() => {
    const unsubscribe = window.bearwarden.logins.onAttachmentProgress((progress) => {
      const current = attachmentOperationRef.current
      if (
        !current ||
        progress.operationId !== current.operationId ||
        progress.itemId !== current.itemId ||
        progress.itemId !== selectedIdRef.current ||
        progress.kind !== current.kind
      ) {
        return
      }
      const next: AttachmentOperationState = {
        ...current,
        ...progress,
        canceling: current.canceling
      }
      attachmentOperationRef.current = next
      setAttachmentOperation((previous) =>
        previous?.operationId === next.operationId ? next : previous
      )
    })
    return () => {
      unsubscribe()
      const operation = attachmentOperationRef.current
      attachmentOperationRef.current = null
      if (operation) {
        void window.bearwarden.logins
          .cancelAttachment({ operationId: operation.operationId })
          .catch(() => undefined)
      }
    }
  }, [])

  useEffect(() => {
    return window.bearwarden.accountSecurity.onLoginApprovalRequested((prompt) => {
      setLoginApprovalPrompts((current) =>
        current.some((entry) => entry.token === prompt.token) ? current : [...current, prompt]
      )
    })
  }, [])

  useEffect(() => {
    const unsubscribe = window.bearwarden.vault.onChanged(() => {
      void loadVault()
    })
    return unsubscribe
  }, [loadVault])

  useEffect(() => {
    return startSyncStatusSubscription(syncStatusStore, window.bearwarden.sync)
  }, [syncStatusStore])

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
      setRevealedSecrets(emptyRevealedSecrets)
      setRevealedCustomFields(emptyRevealedCustomFields)
    })
    if (!selectedId) {
      return () => {
        active = false
      }
    }

    const summary = items.find((item) => item.id === selectedId)
    if (summary?.deletedAt) {
      queueMicrotask(() => {
        if (active) setSelectedLogin(null)
      })
      return () => {
        active = false
      }
    }

    const detailRequest = loadLoginDetail(selectedId)
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
  }, [clearItemSelection, describeVaultError, items, loadLoginDetail, selectedId])

  useEffect(() => {
    let active = true
    const itemId = totpRefreshTarget?.itemId
    const sourceRevision = totpRefreshTarget?.sourceRevision
    queueMicrotask(() => {
      if (!active) return
      setTotpCodeState(null)
      setTotpGenerationErrorState(null)
    })
    if (!itemId || !sourceRevision) {
      return () => {
        active = false
      }
    }

    let stopped = false
    let refreshing = false
    const refresh = (): void => {
      if (stopped || refreshing) return
      refreshing = true
      const token = authorizationToken(itemId)
      window.bearwarden.logins
        .getTotp({
          id: itemId,
          ...(token ? { authorizationToken: token } : {})
        })
        .then(
          (nextCode) => {
            if (!active) return
            setTotpCodeState({
              itemId,
              code: nextCode,
              cycle: Math.floor(Date.now() / (nextCode.period * 1_000))
            })
            setTotpGenerationErrorState(null)
          },
          (totpError) => {
            if (!active) return
            if (isRepromptRequired(totpError)) {
              stopped = true
              window.clearInterval(timer)
              setTotpCodeState(null)
              invalidateAuthorization(itemId)
              clearItemSelection()
              announceError(
                t`Authorization expired. Select the item again and verify your master password.`
              )
              return
            }
            stopped = true
            window.clearInterval(timer)
            setTotpCodeState(null)
            setTotpGenerationErrorState({ itemId, kind: 'unsupported' })
          }
        )
        .finally(() => {
          refreshing = false
        })
    }
    const timer = window.setInterval(refresh, 1_000)
    refresh()
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [
    authorizationToken,
    clearItemSelection,
    invalidateAuthorization,
    t,
    totpRefreshTarget?.itemId,
    totpRefreshTarget?.sourceRevision
  ])

  useEffect(() => {
    if (totpRevealReady || !totpRefreshTarget?.itemId) {
      queueMicrotask(() => setShowTotpSkeleton(false))
      return
    }
    const timer = window.setTimeout(() => setShowTotpSkeleton(true), 100)
    return () => window.clearTimeout(timer)
  }, [totpRefreshTarget?.itemId, totpRefreshTarget?.sourceRevision, totpRevealReady])

  useEffect(() => {
    if (Object.keys(revealedSecrets.values).length === 0) return
    const timeout = window.setTimeout(() => setRevealedSecrets(emptyRevealedSecrets), 30_000)
    return () => window.clearTimeout(timeout)
  }, [revealedSecrets])

  useEffect(() => {
    hoveringSecretFieldsRef.current.clear()
    hoverRevealedSecretFieldsRef.current.clear()
    passwordZoomOpenRef.current = false
  }, [selectedLogin?.id])

  useEffect(() => {
    if (Object.keys(revealedCustomFields.values).length === 0) return
    const timeout = window.setTimeout(
      () => setRevealedCustomFields(emptyRevealedCustomFields),
      30_000
    )
    return () => window.clearTimeout(timeout)
  }, [revealedCustomFields])

  const scopedItemIds = useMemo(() => scopedItems.map((item) => item.id), [scopedItems])
  const totpListItemIds = useMemo(
    () =>
      scopedItems
        .filter((item) => item.type === 'login' && Boolean(item.hasTotp))
        .map((item) => item.id),
    [scopedItems]
  )
  const totpListRevision = useMemo(
    () =>
      scopedItems
        .filter((item) => item.type === 'login' && Boolean(item.hasTotp))
        .map((item) => `${item.id}:${item.updatedAt}`)
        .join('\0'),
    [scopedItems]
  )
  const totpListCodes = useMemo(() => {
    const codes = new Map<string, TotpCodeView | null>()
    for (const [id, entry] of totpListState) codes.set(id, entry?.code ?? null)
    return codes
  }, [totpListState])
  const totpListCountdown = useMemo(() => {
    for (const code of totpListCodes.values()) {
      if (code) return code
    }
    return null
  }, [totpListCodes])

  useEffect(() => {
    if (typeFilter !== 'totp' || totpListItemIds.length === 0) {
      totpListStateRef.current = new Map()
      queueMicrotask(() => setTotpListState(new Map()))
      return
    }

    let active = true
    let refreshing = false
    let listAuthorization: LoginAuthorization | undefined
    totpListStateRef.current = new Map()
    queueMicrotask(() => {
      if (active) setTotpListState(new Map())
    })

    const readCodes = async (
      tokenFor: (id: string) => string | undefined
    ): Promise<Array<{ id: string; code: TotpCodeView | null; fetchedAt: number }>> =>
      Promise.all(
        totpListItemIds.map(async (id) => {
          try {
            const code = await window.bearwarden.logins.getTotp({
              id,
              ...(tokenFor(id) ? { authorizationToken: tokenFor(id) } : {})
            })
            return { id, code, fetchedAt: Date.now() }
          } catch (error) {
            if (isRepromptRequired(error)) throw error
            return { id, code: null, fetchedAt: Date.now() }
          }
        })
      )

    const refresh = async (): Promise<void> => {
      if (!active || refreshing) return
      refreshing = true
      try {
        const now = Date.now()
        if (listAuthorization && listAuthorization.expiresAt <= now) listAuthorization = undefined
        const requiresListAuthorization = totpListItemIds.some(
          (id) =>
            itemsRef.current.find((item) => item.id === id)?.reprompt === 1 &&
            !authorizationToken(id)
        )
        if (!listAuthorization && requiresListAuthorization) {
          listAuthorization = await requestReprompt(totpListItemIds)
        }

        const tokenFor = (id: string): string | undefined =>
          listAuthorization?.token ?? authorizationToken(id)
        let results: Array<{ id: string; code: TotpCodeView | null; fetchedAt: number }>
        try {
          results = await readCodes(tokenFor)
        } catch (error) {
          if (!isRepromptRequired(error)) throw error
          listAuthorization = await requestReprompt(totpListItemIds)
          results = await readCodes(() => listAuthorization?.token)
        }
        if (!active) return

        const next = new Map<string, TotpListEntry>()
        for (const entry of results) {
          next.set(
            entry.id,
            entry.code
              ? {
                  code: entry.code,
                  expiresAt: entry.fetchedAt + entry.code.remainingSeconds * 1_000
                }
              : null
          )
        }
        totpListStateRef.current = next
        setTotpListState(next)
      } catch (error) {
        if (active) announceError(describeVaultError(error))
      } finally {
        refreshing = false
      }
    }

    const tick = (): void => {
      const now = Date.now()
      const current = totpListStateRef.current
      if (current.size === 0) return
      let shouldRefresh = false
      let changed = false
      const next = new Map<string, TotpListEntry>()
      for (const [id, entry] of current) {
        if (!entry) {
          next.set(id, null)
          continue
        }
        const remainingSeconds = Math.max(0, Math.ceil((entry.expiresAt - now) / 1_000))
        if (remainingSeconds === 0) shouldRefresh = true
        if (remainingSeconds !== entry.code.remainingSeconds) changed = true
        next.set(id, {
          ...entry,
          code: { ...entry.code, remainingSeconds }
        })
      }
      if (changed || shouldRefresh) {
        totpListStateRef.current = next
        setTotpListState(next)
      }
      if (shouldRefresh) void refresh()
    }

    void refresh()
    const timer = window.setInterval(tick, 1_000)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [
    authorizationToken,
    describeVaultError,
    requestReprompt,
    totpListItemIds,
    totpListRevision,
    typeFilter
  ])

  const selectItems = useCallback(
    (id: string, modifiers: ItemSelectionModifiers): void => {
      requestEditorTransition(() => {
        const nextSelection = updateItemSelection({
          selectedIds: selectedIdsRef.current,
          anchorId: selectionAnchorIdRef.current,
          activeId: selectedIdRef.current,
          orderedIds: scopedItemIds,
          targetId: id,
          toggle: modifiers.toggle,
          range: modifiers.range
        })
        updateSelectedIds(nextSelection.selectedIds)
        selectionAnchorIdRef.current = nextSelection.anchorId
        activateLogin(nextSelection.activeId)
      })
    },
    [activateLogin, requestEditorTransition, scopedItemIds, updateSelectedIds]
  )

  useEffect(() => {
    const nextSelection = normalizeItemSelection({
      selectedIds: selectedIdsRef.current,
      anchorId: selectionAnchorIdRef.current,
      activeId: selectedIdRef.current,
      orderedIds: scopedItemIds
    })
    const selectionChanged =
      nextSelection.selectedIds.size !== selectedIdsRef.current.size ||
      [...nextSelection.selectedIds].some((id) => !selectedIdsRef.current.has(id))
    if (selectionChanged) updateSelectedIds(nextSelection.selectedIds)
    selectionAnchorIdRef.current = nextSelection.anchorId
    if (nextSelection.activeId !== selectedIdRef.current) activateLogin(nextSelection.activeId)
  }, [activateLogin, scopedItemIds, updateSelectedIds])

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
    () => items.filter((item) => selectedIds.has(item.id)),
    [items, selectedIds]
  )
  const moveSummaries = useMemo(() => {
    if (!moveSnapshot) return []
    const byId = new Map(items.map((item) => [item.id, item]))
    return moveSnapshot.ids.flatMap((id) => {
      const item = byId.get(id)
      return item ? [item] : []
    })
  }, [items, moveSnapshot])
  const moveFolderId = useMemo(() => {
    const firstFolderId = moveSummaries[0]?.folderId
    if (firstFolderId === undefined) return undefined
    return moveSummaries.every((item) => item.folderId === firstFolderId)
      ? firstFolderId
      : undefined
  }, [moveSummaries])
  const openMoveDialogForSelection = useCallback((): void => {
    if (busy || scope.kind === 'trash') return
    const ids = [...selectedIdsRef.current]
    if (ids.length === 0) return
    setMoveSnapshot({ ids, state: scope.kind === 'archive' ? 'archive' : 'active' })
  }, [busy, scope.kind, setMoveSnapshot])
  const activeDragItem = activeDragId
    ? (items.find((item) => item.id === activeDragId) ?? null)
    : null
  const activeDragItemCount =
    activeDragItem && selectedIds.has(activeDragItem.id) ? selectedIds.size : 1
  const activeDragDestinationDescription = activeDragItem
    ? (itemDropPreviewDescription({
        overId: activeDragOverId,
        itemState: scope.kind === 'archive' ? 'archive' : 'active',
        folders,
        count: activeDragItemCount
      }) ?? t`Release to cancel moving`)
    : null
  const selectedDetailFields = useMemo(
    () => (selectedLogin ? detailFields(selectedLogin, detailFieldLabels) : []),
    [detailFieldLabels, selectedLogin]
  )
  const itemGroups = useMemo(() => {
    const effectiveSort = scope.kind === 'recent' ? 'recent' : sortMode
    if (effectiveSort === 'title' || effectiveSort === 'frequency') {
      return [{ key: 'name', label: null, items: scopedItems }]
    }
    return groupItemsByDate(
      scopedItems,
      new Date(),
      effectiveSort === 'modified' ? 'updatedAt' : 'activity'
    )
      .filter((group) => group.items.length > 0)
      .map((group) => ({ ...group, label: group.label as string | null }))
  }, [scope.kind, scopedItems, sortMode])
  const folderIds = useMemo(() => new Set(folders.map((folder) => folder.id)), [folders])
  const activeItems = useMemo(
    () => items.filter((item) => !item.deletedAt && !item.archivedAt),
    [items]
  )
  const archivedItems = useMemo(
    () => items.filter((item) => !item.deletedAt && item.archivedAt),
    [items]
  )
  const trashItems = useMemo(() => items.filter((item) => item.deletedAt), [items])
  const itemIds = useMemo(
    () => new Set([...activeItems, ...archivedItems].map((item) => item.id)),
    [activeItems, archivedItems]
  )
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
    if (scope.kind === 'recent') {
      return t({
        message: 'Recently used',
        context: 'recent-items-filter',
        comment: 'Navigation and sort label for vault items that have been used most recently.'
      })
    }
    if (scope.kind === 'unfiled') return t`Unfiled`
    if (scope.kind === 'archive') return t`Archive`
    if (scope.kind === 'trash') return t`Trash`
    if (scope.kind === 'folder')
      return folders.find((folder) => folder.id === scope.folderId)?.name ?? t`Folder`
    if (typeFilter === 'totp') return t`Codes`
    if (typeFilter === 'passkey') return t`Passkeys`
    if (typeFilter !== 'all') return itemTypeMeta[typeFilter].label
    return t`All items`
  }, [folders, itemTypeMeta, scope, t, typeFilter])

  const announce = useCallback((message: string): void => {
    toast.success(message)
  }, [])
  const {
    accountStatus,
    accountBusy,
    accountBusyLabel,
    accountError,
    sidebarAccountProfileName,
    refreshAccountProfile,
    addLocalAccount,
    switchLocalAccount,
    reorderLocalAccounts,
    removeLocalAccount
  } = useVaultAccounts({ settingsOpen, syncStatus, announce })
  const sidebarAccountName =
    sidebarAccountProfileName || (syncStatus.configured ? t`Connected account` : t`Local vault`)

  const performLockVault = useCallback(async (): Promise<void> => {
    cancelAndClearAttachmentOperation()
    clearDetailCache()
    setRevealedSecrets(emptyRevealedSecrets)
    setRevealedCustomFields(emptyRevealedCustomFields)
    setTouchIdPassword('')
    setSelectedLogin(null)
    try {
      const status = await window.bearwarden.vault.lock()
      if (status.state === 'locked') onLocked()
      else announceError(t`The vault is not locked yet. Try again.`)
    } catch (lockError) {
      announceError(describeVaultError(lockError))
    }
  }, [cancelAndClearAttachmentOperation, clearDetailCache, describeVaultError, onLocked, t])

  const lockVault = useCallback(async (): Promise<void> => {
    if (isEditorDirty()) {
      requestEditorTransition(() => void performLockVault())
      return
    }
    await performLockVault()
  }, [isEditorDirty, performLockVault, requestEditorTransition])

  useEffect(() => {
    const unsubscribe = window.bearwarden.vault.onLockRequested(() => void lockVault())
    window.bearwarden.vault.setLockRequestReady(true)
    return () => {
      window.bearwarden.vault.setLockRequestReady(false)
      unsubscribe()
    }
  }, [lockVault])

  useEffect(() => {
    function handleShortcut(event: KeyboardEvent): void {
      const command = event.metaKey || event.ctrlKey
      if (!command) return
      const key = event.key.toLocaleLowerCase()
      if (settingsOpen || healthOpen || sendsOpen || organizationsOpen || emergencyAccessOpen)
        return
      if (
        key === 'a' &&
        !editorMode &&
        !searchOpen &&
        event.target instanceof HTMLElement &&
        !event.target.matches('input, textarea, select, [contenteditable="true"]')
      ) {
        event.preventDefault()
        const nextIds = new Set(scopedItemIds)
        updateSelectedIds(nextIds)
        selectionAnchorIdRef.current = scopedItemIds[0] ?? null
        const nextActiveId =
          selectedIdRef.current && nextIds.has(selectedIdRef.current)
            ? selectedIdRef.current
            : (scopedItemIds[0] ?? null)
        activateLogin(nextActiveId)
      }
      if (key === 'f') {
        event.preventDefault()
        setSearchOpen(true)
      }
      if (key === 'n' && !editorMode && scope.kind !== 'trash' && scope.kind !== 'archive') {
        event.preventDefault()
        openEditor('create')
      }
      if (key === 'e' && selectedLogin && !selectedLogin.deletedAt && !editorMode) {
        event.preventDefault()
        openEditor('edit')
      }
      if (key === 's' && editorMode && !busy) {
        event.preventDefault()
        document.querySelector<HTMLFormElement>('form[data-vault-editor]')?.requestSubmit()
      }
      if (key === 'm' && event.shiftKey && selectedSummary && !selectedSummary.deletedAt) {
        event.preventDefault()
        openMoveDialogForSelection()
      }
    }
    window.addEventListener('keydown', handleShortcut)
    return () => window.removeEventListener('keydown', handleShortcut)
  }, [
    activateLogin,
    busy,
    editorMode,
    healthOpen,
    openMoveDialogForSelection,
    openEditor,
    scopedItemIds,
    searchOpen,
    setSearchOpen,
    selectedLogin,
    selectedSummary,
    scope.kind,
    organizationsOpen,
    emergencyAccessOpen,
    sendsOpen,
    settingsOpen,
    updateSelectedIds
  ])

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

  function selectScope(nextScope: Scope): void {
    requestEditorTransition(() => {
      setScope(nextScope)
      setTypeFilter('all')
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

  function selectType(type: TypeFilter): void {
    requestEditorTransition(() => {
      setScope({ kind: 'all' })
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

  function rememberNavigationReturnFocus(): void {
    const activeElement =
      document.activeElement instanceof HTMLElement ? document.activeElement : null
    settingsReturnFocusRef.current = activeElement?.closest('[data-slot="dropdown-menu-content"]')
      ? sidebarMenuTriggerRef.current
      : activeElement
  }

  function openSettings(): void {
    requestEditorTransition(() => {
      rememberNavigationReturnFocus()
      setSettingsOpen(true)
      setSidebarOpen(false)
      setEditorMode(null)
      setMoveSnapshot(null)
      clearItemSelection()
      setRevealedSecrets(emptyRevealedSecrets)
      setRevealedCustomFields(emptyRevealedCustomFields)
    })
  }

  function closeSettings(): void {
    setSettingsOpen(false)
    setTouchIdPassword('')
  }

  function openHealth(): void {
    requestEditorTransition(() => {
      rememberNavigationReturnFocus()
      setHealthOpen(true)
      setSearchOpen(false)
      setSidebarOpen(false)
      setEditorMode(null)
      setMoveSnapshot(null)
      clearItemSelection()
      setRevealedSecrets(emptyRevealedSecrets)
      setRevealedCustomFields(emptyRevealedCustomFields)
    })
  }

  function closeHealth(): void {
    setHealthOpen(false)
  }

  function openSends(): void {
    requestEditorTransition(() => {
      rememberNavigationReturnFocus()
      setSendsOpen(true)
      setSearchOpen(false)
      setSidebarOpen(false)
      setEditorMode(null)
      setMoveSnapshot(null)
      clearItemSelection()
      setRevealedSecrets(emptyRevealedSecrets)
      setRevealedCustomFields(emptyRevealedCustomFields)
    })
  }

  function closeSends(): void {
    setSendsOpen(false)
  }

  function openOrganizations(): void {
    requestEditorTransition(() => {
      rememberNavigationReturnFocus()
      setOrganizationsOpen(true)
      setSearchOpen(false)
      setSidebarOpen(false)
      setEditorMode(null)
      setMoveSnapshot(null)
      clearItemSelection()
      setRevealedSecrets(emptyRevealedSecrets)
      setRevealedCustomFields(emptyRevealedCustomFields)
    })
  }

  function closeOrganizations(): void {
    setOrganizationsOpen(false)
  }

  function openEmergencyAccess(): void {
    requestEditorTransition(() => {
      rememberNavigationReturnFocus()
      setEmergencyAccessOpen(true)
      setSearchOpen(false)
      setSidebarOpen(false)
      setEditorMode(null)
      setMoveSnapshot(null)
      clearItemSelection()
      setRevealedSecrets(emptyRevealedSecrets)
      setRevealedCustomFields(emptyRevealedCustomFields)
    })
  }

  function closeEmergencyAccess(): void {
    setEmergencyAccessOpen(false)
  }

  function openHealthItem(id: string): void {
    setHealthOpen(false)
    setScope({ kind: 'all' })
    setTypeFilter('login')
    updateQuery('')
    selectLogin(id)
  }

  async function submitReprompt(masterPassword: string): Promise<void> {
    const pending = pendingRepromptRef.current
    if (!pending) throw new Error('REPROMPT_REQUIRED')
    setRepromptBusy(true)
    try {
      const authorization = await window.bearwarden.logins.authorizeMany({
        ids: pending.ids,
        masterPassword
      })
      if (pending.ids.length === 1) cacheAuthorization(pending.ids[0]!, authorization)
      pending.resolve(authorization)
      pendingRepromptRef.current = null
      setRepromptPrompt(null)
    } finally {
      setRepromptBusy(false)
    }
  }

  function cancelReprompt(): void {
    if (repromptBusy) return
    const pending = pendingRepromptRef.current
    pendingRepromptRef.current = null
    setRepromptPrompt(null)
    pending?.reject(new Error('REPROMPT_REQUIRED'))
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
    await loadVault()
    announce(formatVaultImportResult(result))
  }

  const toggleFavorite = useCallback(
    async (item: LoginSummary): Promise<void> => {
      try {
        const updated = await withReprompt([item.id], (tokenFor) =>
          window.bearwarden.logins.setFavorite({
            id: item.id,
            favorite: !item.favorite,
            ...(tokenFor(item.id) ? { authorizationToken: tokenFor(item.id) } : {})
          })
        )
        mergeCachedSummary(detailCacheRef.current, updated)
        setItems((current) => current.map((entry) => (entry.id === updated.id ? updated : entry)))
        setSelectedLogin((current) =>
          current?.id === updated.id ? mergeLoginSummary(current, updated) : current
        )
        announce(updated.favorite ? t`Added to favorites.` : t`Removed from favorites.`)
      } catch (favoriteError) {
        announceError(describeVaultError(favoriteError))
      }
    },
    [announce, describeVaultError, setItems, t, withReprompt]
  )

  function revalidateBulkSelection(
    ids: readonly string[],
    expectedState: BulkSelectionState
  ): LoginSummary[] | null {
    const uniqueIds = new Set(ids)
    if (ids.length === 0 || uniqueIds.size !== ids.length) return null
    const currentById = new Map(itemsRef.current.map((item) => [item.id, item]))
    const currentItems: LoginSummary[] = []
    for (const id of ids) {
      const item = currentById.get(id)
      if (!item) return null
      const stateMatches =
        expectedState === 'trash'
          ? Boolean(item.deletedAt)
          : expectedState === 'archive'
            ? !item.deletedAt && Boolean(item.archivedAt)
            : !item.deletedAt && !item.archivedAt
      if (!stateMatches) return null
      currentItems.push(item)
    }
    return currentItems
  }

  function snapshotBulkAction(action: BulkActionKind): BulkActionSnapshot {
    const state: BulkSelectionState =
      action === 'restore' || action === 'deletePermanently'
        ? 'trash'
        : action === 'unarchive' || (action === 'delete' && scope.kind === 'archive')
          ? 'archive'
          : 'active'
    return { action, ids: [...selectedIdsRef.current], state }
  }

  async function performBulkAction(snapshot: BulkActionSnapshot): Promise<boolean> {
    if (busy) return false
    if (snapshot.ids.length === 0) {
      announceError(t`Select at least one item first.`)
      return false
    }
    if (snapshot.ids.length > MAX_LOGIN_BATCH_IDS) {
      announceError(t`You can process up to ${MAX_LOGIN_BATCH_IDS} items at a time.`)
      return false
    }
    if (!revalidateBulkSelection(snapshot.ids, snapshot.state)) {
      announceError(
        t`The selection changed, so no action was taken. Select the items again and retry.`
      )
      return false
    }

    setBusy(true)
    try {
      let affectedCount = 0
      let updated: LoginSummary[] = []
      try {
        await withReprompt(snapshot.ids, async (tokenFor) => {
          const authorizationToken = firstAuthorizationToken(snapshot.ids, tokenFor)
          const request = {
            ids: snapshot.ids,
            ...(authorizationToken ? { authorizationToken } : {})
          }
          if (snapshot.action === 'archive') {
            updated = await window.bearwarden.logins.archiveMany(request)
            affectedCount = updated.length
            return
          }
          if (snapshot.action === 'unarchive') {
            updated = await window.bearwarden.logins.unarchiveMany(request)
            affectedCount = updated.length
            return
          }
          if (snapshot.action === 'restore') {
            updated = await window.bearwarden.logins.restoreMany(request)
            affectedCount = updated.length
            return
          }
          affectedCount =
            snapshot.action === 'delete'
              ? await window.bearwarden.logins.deleteMany(request)
              : await window.bearwarden.logins.deletePermanentlyMany(request)
        })
      } catch (bulkError) {
        announceError(describeVaultError(bulkError))
        return false
      }

      if (snapshot.action === 'delete' || snapshot.action === 'deletePermanently') {
        detailCacheGenerationRef.current += 1
        detailRequestsRef.current.clear()
        for (const id of snapshot.ids) detailCacheRef.current.delete(id)
        const deletedIds = new Set(snapshot.ids)
        setItems((current) => current.filter((item) => !deletedIds.has(item.id)))
        clearItemSelection()
      } else {
        const updatedById = new Map(updated.map((item) => [item.id, item]))
        for (const item of updated) mergeCachedSummary(detailCacheRef.current, item)
        setItems((current) => current.map((item) => updatedById.get(item.id) ?? item))
        setSelectedLogin((current) => {
          if (!current) return current
          const summary = updatedById.get(current.id)
          return summary ? mergeLoginSummary(current, summary) : current
        })
      }
      const message =
        snapshot.action === 'archive'
          ? t`Archived ${affectedCount} items.`
          : snapshot.action === 'unarchive'
            ? t`Unarchived ${affectedCount} items.`
            : snapshot.action === 'delete'
              ? t`Moved ${affectedCount} items to Trash.`
              : snapshot.action === 'restore'
                ? t`Restored ${affectedCount} items.`
                : t`Permanently deleted ${affectedCount} items.`
      try {
        await refreshItems()
      } catch {
        toast.warning(t`${message} The list could not be refreshed. Try again later.`)
        return true
      }
      announce(message)
      return true
    } finally {
      setBusy(false)
    }
  }

  async function moveLogins(snapshot: MoveSnapshot, folderId: string | null): Promise<boolean> {
    const previous = revalidateBulkSelection(snapshot.ids, snapshot.state)
    if (!previous) {
      announceError(
        t`The selection changed, so no action was taken. Select the items again and retry.`
      )
      return false
    }
    const movable = previous.filter((item) => item.folderId !== folderId)
    if (movable.length === 0) {
      return true
    }
    if (movable.length > MAX_LOGIN_MOVE_MANY_IDS) {
      announceError(t`You can move up to ${MAX_LOGIN_MOVE_MANY_IDS} items at a time.`)
      return false
    }
    const movableIds = new Set(movable.map((item) => item.id))
    setBusy(true)
    for (const item of movable) mergeCachedSummary(detailCacheRef.current, { ...item, folderId })
    setItems((current) =>
      current.map((item) => (movableIds.has(item.id) ? { ...item, folderId } : item))
    )
    try {
      const movableItemIds = movable.map((item) => item.id)
      const updated = await withReprompt(movableItemIds, (tokenFor) =>
        window.bearwarden.logins.moveMany({
          ids: movableItemIds,
          folderId,
          ...(firstAuthorizationToken(movableItemIds, tokenFor)
            ? { authorizationToken: firstAuthorizationToken(movableItemIds, tokenFor) }
            : {})
        })
      )
      const updatedById = new Map(updated.map((item) => [item.id, item]))
      for (const item of updated) mergeCachedSummary(detailCacheRef.current, item)
      setItems((current) => current.map((item) => updatedById.get(item.id) ?? item))
      setSelectedLogin((current) => {
        if (!current) return current
        const summary = updatedById.get(current.id)
        return summary ? mergeLoginSummary(current, summary) : current
      })
      const destination = folders.find((folder) => folder.id === folderId)?.name ?? t`Unfiled`
      announce(
        updated.length > 1
          ? t`Moved ${updated.length} items to “${destination}”.`
          : t`Moved to “${destination}”.`
      )
      return true
    } catch (moveError) {
      const previousById = new Map(previous.map((item) => [item.id, item]))
      for (const item of previous) mergeCachedSummary(detailCacheRef.current, item)
      setItems((current) => current.map((item) => previousById.get(item.id) ?? item))
      announceError(describeVaultError(moveError))
      return false
    } finally {
      setBusy(false)
    }
  }

  async function addLoginsToFavorites(snapshot: MoveSnapshot): Promise<boolean> {
    if (busy) return false
    const previous = revalidateBulkSelection(snapshot.ids, snapshot.state)
    if (!previous) {
      announceError(
        t`The selection changed, so no action was taken. Select the items again and retry.`
      )
      return false
    }
    const itemsToUpdate = previous.filter((item) => !item.favorite)
    if (itemsToUpdate.length === 0) return true
    if (itemsToUpdate.length > MAX_LOGIN_BATCH_IDS) {
      announceError(t`You can process up to ${MAX_LOGIN_BATCH_IDS} items at a time.`)
      return false
    }

    const ids = itemsToUpdate.map((item) => item.id)
    setBusy(true)
    try {
      const updated = await withReprompt(ids, (tokenFor) =>
        Promise.all(
          ids.map((id) =>
            window.bearwarden.logins.setFavorite({
              id,
              favorite: true,
              ...(tokenFor(id) ? { authorizationToken: tokenFor(id) } : {})
            })
          )
        )
      )
      const updatedById = new Map(updated.map((item) => [item.id, item]))
      for (const item of updated) mergeCachedSummary(detailCacheRef.current, item)
      setItems((current) => current.map((item) => updatedById.get(item.id) ?? item))
      setSelectedLogin((current) => {
        if (!current) return current
        const summary = updatedById.get(current.id)
        return summary ? mergeLoginSummary(current, summary) : current
      })
      announce(
        updated.length > 1 ? t`Added ${updated.length} items to favorites.` : t`Added to favorites.`
      )
      return true
    } catch (favoriteError) {
      await refreshItems().catch(() => undefined)
      announceError(describeVaultError(favoriteError))
      return false
    } finally {
      setBusy(false)
    }
  }

  async function saveFolder(name: string): Promise<void> {
    setBusy(true)
    try {
      if (folderDialog === 'new') {
        const created = await window.bearwarden.folders.create({ name })
        setFolders((current) => [...current, created].sort((a, b) => a.position - b.position))
        announce(t`Created folder “${created.name}”.`)
      } else if (folderDialog) {
        const updated = await window.bearwarden.folders.update({ id: folderDialog.id, name })
        setFolders((current) =>
          current.map((folder) => (folder.id === updated.id ? updated : folder))
        )
        announce(t`Renamed to “${updated.name}”.`)
      }
      setFolderDialog(null)
    } catch (folderError) {
      announceError(describeVaultError(folderError))
    } finally {
      setBusy(false)
    }
  }

  async function deleteFolder(): Promise<void> {
    if (!folderDialog || folderDialog === 'new') return
    setBusy(true)
    try {
      const containedIds = items
        .filter((item) => item.folderId === folderDialog.id)
        .map((item) => item.id)
      await withReprompt(containedIds, (tokenFor) =>
        window.bearwarden.folders.delete({
          id: folderDialog.id,
          ...(firstAuthorizationToken(containedIds, tokenFor)
            ? { authorizationToken: firstAuthorizationToken(containedIds, tokenFor) }
            : {})
        })
      )
      for (const [id, cached] of detailCacheRef.current) {
        if (cached.folderId === folderDialog.id) {
          detailCacheRef.current.set(id, { ...cached, folderId: null })
        }
      }
      setFolders((current) => current.filter((folder) => folder.id !== folderDialog.id))
      setItems((current) =>
        current.map((item) =>
          item.folderId === folderDialog.id ? { ...item, folderId: null } : item
        )
      )
      if (scope.kind === 'folder' && scope.folderId === folderDialog.id)
        setScope({ kind: 'unfiled' })
      announce(t`Deleted folder “${folderDialog.name}”. Its items were moved to Unfiled.`)
      setFolderDialog(null)
    } catch (folderError) {
      announceError(describeVaultError(folderError))
    } finally {
      setBusy(false)
    }
  }

  async function saveLogin(draft: LoginDraft): Promise<boolean> {
    setBusy(true)
    try {
      const changedSecrets = new Set(draft.changedSecrets)
      const customFields = draft.customFields.map((field) => ({
        source: field.source,
        name: field.name,
        type: field.type,
        value: field.value,
        linkedId: field.linkedId
      }))
      const fields = {
        username: draft.username,
        uri: draft.uri || null,
        uris: draft.uris.map((entry) => ({ uri: entry.uri, match: entry.match })),
        cardholderName: draft.cardholderName,
        brand: draft.brand,
        expMonth: draft.expMonth,
        expYear: draft.expYear,
        title: draft.title,
        firstName: draft.firstName,
        middleName: draft.middleName,
        lastName: draft.lastName,
        address1: draft.address1,
        address2: draft.address2,
        address3: draft.address3,
        city: draft.city,
        state: draft.state,
        postalCode: draft.postalCode,
        country: draft.country,
        company: draft.company,
        email: draft.email,
        phone: draft.phone,
        identityUsername: draft.identityUsername,
        publicKey: draft.publicKey,
        fingerprint: draft.fingerprint,
        ...(changedSecrets.has('password') ? { password: draft.password } : {}),
        ...(changedSecrets.has('totp') ? { totp: draft.totp } : {}),
        ...(changedSecrets.has('number') ? { number: draft.number } : {}),
        ...(changedSecrets.has('code') ? { code: draft.code } : {}),
        ...(changedSecrets.has('ssn') ? { ssn: draft.ssn } : {}),
        ...(changedSecrets.has('passportNumber') ? { passportNumber: draft.passportNumber } : {}),
        ...(changedSecrets.has('licenseNumber') ? { licenseNumber: draft.licenseNumber } : {}),
        ...(changedSecrets.has('privateKey') ? { privateKey: draft.privateKey } : {})
      }
      if (editorMode === 'create') {
        const request = {
          type: draft.type,
          name: draft.name,
          ...fields,
          notes: draft.notes || null,
          folderId: draft.folderId,
          favorite: draft.favorite,
          reprompt: draft.reprompt,
          customFields
        }
        const created = await createLoginWithOptionalSshImport(request, draft.sshImportToken, {
          create: window.bearwarden.logins.create,
          createImported: window.bearwarden.sshKeys.createImported
        })
        if (created.reprompt === 0) cacheLoginDetail(detailCacheRef.current, created)
        setItems((current) => [...current, toLoginSummary(created)])
        setScope({ kind: 'all' })
        updateSelectedIds(new Set([created.id]))
        selectionAnchorIdRef.current = created.id
        selectedIdRef.current = created.id
        setSelectedId(created.id)
        setSelectedLogin(created.reprompt === 0 ? created : null)
        announce(t`Created “${created.name}”.`)
      } else if (selectedLogin) {
        const itemId = selectedLogin.id
        const updated = await withReprompt([itemId], (tokenFor) => {
          const request = {
            id: itemId,
            expectedUpdatedAt: draft.expectedUpdatedAt ?? undefined,
            name: draft.name,
            ...fields,
            notes: draft.notes || null,
            folderId: draft.folderId,
            favorite: draft.favorite,
            reprompt: draft.reprompt,
            ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {}),
            customFields
          }
          return updateLoginWithOptionalSshImport(request, draft.sshImportToken, {
            update: window.bearwarden.logins.update,
            updateImported: window.bearwarden.sshKeys.updateImported
          })
        })
        if (updated.reprompt === 0 || authorizationToken(itemId)) {
          cacheLoginDetail(detailCacheRef.current, updated)
        } else {
          detailCacheRef.current.delete(itemId)
        }
        setItems((current) =>
          current.map((item) => (item.id === updated.id ? toLoginSummary(updated) : item))
        )
        setSelectedLogin(updated.reprompt === 0 || authorizationToken(itemId) ? updated : null)
        announce(t`Saved “${updated.name}”.`)
      }
      setRevealedCustomFields(emptyRevealedCustomFields)
      clearEditorDirty()
      setEditorMode(null)
      return true
    } catch (saveError) {
      announceError(describeVaultError(saveError))
      return false
    } finally {
      setBusy(false)
    }
  }

  async function deletePasskey(
    credentialId: string,
    expectedUpdatedAt: string
  ): Promise<LoginView | null> {
    if (!selectedLogin || selectedLogin.deletedAt || selectedLogin.type !== 'login') return null
    setBusy(true)
    try {
      const itemId = selectedLogin.id
      let operationAuthorizationToken: string | undefined
      const updated = await withReprompt([itemId], (tokenFor) => {
        operationAuthorizationToken = tokenFor(itemId)
        return window.bearwarden.passkeys.delete({
          id: itemId,
          credentialId,
          expectedUpdatedAt,
          ...(operationAuthorizationToken
            ? { authorizationToken: operationAuthorizationToken }
            : {})
        })
      })
      const canRetainDetail = updated.reprompt === 0 || operationAuthorizationToken !== undefined
      if (canRetainDetail) {
        cacheLoginDetail(detailCacheRef.current, updated)
      } else {
        detailCacheRef.current.delete(itemId)
      }
      setItems((current) =>
        current.map((item) => (item.id === updated.id ? toLoginSummary(updated) : item))
      )
      setSelectedLogin(canRetainDetail ? updated : null)
      announce(t`Passkey deleted.`)
      return updated
    } catch (deleteError) {
      announceError(describeVaultError(deleteError))
      return null
    } finally {
      setBusy(false)
    }
  }

  async function cloneLogin(): Promise<void> {
    if (!selectedLogin || selectedLogin.deletedAt) return
    setBusy(true)
    try {
      const itemId = selectedLogin.id
      const cloned = await withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.clone({
          id: itemId,
          ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {})
        })
      )
      if (cloned.reprompt === 0) cacheLoginDetail(detailCacheRef.current, cloned)
      setItems((current) => [...current, toLoginSummary(cloned)])
      setScope(cloned.archivedAt ? { kind: 'archive' } : { kind: 'all' })
      updateSelectedIds(new Set([cloned.id]))
      selectionAnchorIdRef.current = cloned.id
      selectedIdRef.current = cloned.id
      setSelectedId(cloned.id)
      setSelectedLogin(cloned.reprompt === 0 ? cloned : null)
      setRevealedSecrets(emptyRevealedSecrets)
      setRevealedCustomFields(emptyRevealedCustomFields)
      announce(t`Created “${cloned.name}”.`)
    } catch (cloneError) {
      announceError(describeVaultError(cloneError))
    } finally {
      setBusy(false)
    }
  }

  async function archiveLogin(): Promise<void> {
    if (!selectedLogin || selectedLogin.deletedAt || selectedLogin.archivedAt) return
    setBusy(true)
    try {
      const itemId = selectedLogin.id
      const archived = await withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.archive({
          id: itemId,
          ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {})
        })
      )
      cacheLoginDetail(detailCacheRef.current, archived)
      await refreshItems()
      setScope({ kind: 'archive' })
      updateSelectedIds(new Set([archived.id]))
      selectionAnchorIdRef.current = archived.id
      selectedIdRef.current = archived.id
      setSelectedId(archived.id)
      setSelectedLogin(archived)
      announce(t`Archived “${archived.name}”.`)
    } catch (archiveError) {
      announceError(describeVaultError(archiveError))
    } finally {
      setBusy(false)
    }
  }

  async function unarchiveLogin(): Promise<void> {
    if (!selectedLogin || selectedLogin.deletedAt || !selectedLogin.archivedAt) return
    setBusy(true)
    try {
      const itemId = selectedLogin.id
      const restored = await withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.unarchive({
          id: itemId,
          ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {})
        })
      )
      cacheLoginDetail(detailCacheRef.current, restored)
      await refreshItems()
      setScope({ kind: 'all' })
      updateSelectedIds(new Set([restored.id]))
      selectionAnchorIdRef.current = restored.id
      selectedIdRef.current = restored.id
      setSelectedId(restored.id)
      setSelectedLogin(restored)
      announce(t`Unarchived “${restored.name}”.`)
    } catch (unarchiveError) {
      announceError(describeVaultError(unarchiveError))
    } finally {
      setBusy(false)
    }
  }

  async function deleteLogin(): Promise<void> {
    if (!selectedSummary) return
    setBusy(true)
    try {
      const itemId = selectedSummary.id
      await withReprompt([itemId], (tokenFor) => {
        const request = {
          id: itemId,
          ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {})
        }
        return selectedSummary.deletedAt
          ? window.bearwarden.logins.deletePermanently(request)
          : window.bearwarden.logins.delete(request)
      })
      detailCacheRef.current.delete(selectedSummary.id)
      await refreshItems()
      clearItemSelection()
      setDeleteDialogOpen(false)
      announce(selectedSummary.deletedAt ? t`Item permanently deleted.` : t`Item moved to Trash.`)
    } catch (deleteError) {
      announceError(describeVaultError(deleteError))
    } finally {
      setBusy(false)
    }
  }

  async function restoreLogin(): Promise<void> {
    if (!selectedSummary?.deletedAt) return
    setBusy(true)
    try {
      const itemId = selectedSummary.id
      const restored = await withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.restore({
          id: itemId,
          ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {})
        })
      )
      cacheLoginDetail(detailCacheRef.current, restored)
      await refreshItems()
      setScope(restored.archivedAt ? { kind: 'archive' } : { kind: 'all' })
      updateSelectedIds(new Set([restored.id]))
      selectionAnchorIdRef.current = restored.id
      selectedIdRef.current = restored.id
      setSelectedId(restored.id)
      setSelectedLogin(restored)
      announce(t`Restored “${restored.name}”.`)
    } catch (restoreError) {
      announceError(describeVaultError(restoreError))
    } finally {
      setBusy(false)
    }
  }

  async function emptyTrash(): Promise<void> {
    setBusy(true)
    try {
      const trashIds = trashItems.map((item) => item.id)
      const count = await withReprompt(trashIds, (tokenFor) =>
        window.bearwarden.logins.emptyTrash({
          ...(firstAuthorizationToken(trashIds, tokenFor)
            ? { authorizationToken: firstAuthorizationToken(trashIds, tokenFor) }
            : {})
        })
      )
      clearDetailCache()
      await refreshItems()
      clearItemSelection()
      setEmptyTrashDialogOpen(false)
      announce(
        t({
          message: plural(count, {
            one: 'Permanently deleted # item.',
            other: 'Permanently deleted # items.'
          })
        })
      )
    } catch (emptyError) {
      announceError(describeVaultError(emptyError))
    } finally {
      setBusy(false)
    }
  }

  async function revealSecret(
    field: VaultSecretField,
    options: { quiet?: boolean; forceShow?: boolean } = {}
  ): Promise<string | undefined> {
    if (!selectedSummary) return undefined
    const itemId = selectedSummary.id
    const revealedValue =
      revealedSecrets.itemId === itemId ? revealedSecrets.values[field] : undefined
    if (revealedValue !== undefined) {
      if (options.forceShow) return revealedValue
      setRevealedSecrets((current) => {
        if (current.itemId !== itemId) return current
        const next = { ...current.values }
        delete next[field]
        return Object.keys(next).length ? { itemId, values: next } : emptyRevealedSecrets
      })
      return undefined
    }
    try {
      const value = await withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.revealSecret({
          id: itemId,
          field,
          ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {})
        })
      )
      if (selectedIdRef.current !== itemId) return undefined
      if (
        options.quiet &&
        !hoveringSecretFieldsRef.current.has(field) &&
        !(field === 'password' && passwordZoomOpenRef.current)
      ) {
        return value
      }
      setRevealedSecrets((current) => ({
        itemId,
        values: {
          ...(current.itemId === itemId ? current.values : {}),
          [field]: value
        }
      }))
      if (!options.quiet) {
        const revealedLabel = field === 'privateKey' ? t`Private key` : t`Sensitive data`
        announce(t`${revealedLabel} is visible and will be hidden automatically in 30 seconds.`)
      }
      return value
    } catch (revealError) {
      announceError(describeVaultError(revealError))
      return undefined
    }
  }

  function hideRevealedSecret(field: VaultSecretField): void {
    if (!selectedSummary) return
    const itemId = selectedSummary.id
    setRevealedSecrets((current) => {
      if (current.itemId !== itemId || current.values[field] === undefined) return current
      const next = { ...current.values }
      delete next[field]
      return Object.keys(next).length ? { itemId, values: next } : emptyRevealedSecrets
    })
  }

  async function openPasswordZoom(): Promise<void> {
    if (!selectedSummary) return
    const itemId = selectedSummary.id
    passwordZoomOpenRef.current = true
    const value = await revealSecret('password', { quiet: true, forceShow: true })
    if (value === undefined) {
      passwordZoomOpenRef.current = false
      return
    }
    setPasswordZoom({ itemId, value })
  }

  function closePasswordZoom(): void {
    passwordZoomOpenRef.current = false
    setPasswordZoom(null)
    if (!hoveringSecretFieldsRef.current.has('password')) {
      hoverRevealedSecretFieldsRef.current.delete('password')
      hideRevealedSecret('password')
    }
  }

  async function copyField(field: VaultCopyField, uriIndex?: number): Promise<void> {
    if (!selectedSummary) return
    clearCopied()
    try {
      const itemId = selectedSummary.id
      await withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.copyField({
          id: itemId,
          field,
          ...(uriIndex === undefined ? {} : { uriIndex }),
          ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {})
        })
      )
      showCopied(`field:${itemId}:${field}:${uriIndex ?? ''}`)
      await refreshItems()
    } catch (copyError) {
      announceError(describeVaultError(copyError))
    }
  }

  async function revealCustomField(index: number, field: VaultCustomFieldView): Promise<void> {
    if (!selectedLogin) return
    const itemId = selectedLogin.id
    const revealedEntry =
      revealedCustomFields.itemId === itemId ? revealedCustomFields.values[index] : undefined
    if (
      revealedEntry &&
      revealedEntry.expectedUpdatedAt === selectedLogin.updatedAt &&
      matchesCustomFieldSource(field, index, revealedEntry.source)
    ) {
      setRevealedCustomFields((current) => {
        if (current.itemId !== itemId) return current
        const next = { ...current.values }
        delete next[index]
        return Object.keys(next).length ? { itemId, values: next } : emptyRevealedCustomFields
      })
      return
    }
    try {
      const expectedUpdatedAt = selectedLogin.updatedAt
      const source: VaultCustomFieldSource = {
        index,
        name: field.name,
        type: field.type,
        linkedId: field.linkedId
      }
      const value = await withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.revealCustomField({
          id: itemId,
          expectedUpdatedAt,
          source,
          ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {})
        })
      )
      if (selectedIdRef.current !== itemId) return
      setRevealedCustomFields((current) => ({
        itemId,
        values: {
          ...(current.itemId === itemId ? current.values : {}),
          [index]: { value, source, expectedUpdatedAt }
        }
      }))
      announce(t`The hidden field is visible and will be hidden automatically in 30 seconds.`)
    } catch (revealError) {
      announceError(describeVaultError(revealError))
    }
  }

  async function copyCustomField(index: number, field: VaultCustomFieldView): Promise<void> {
    if (!selectedLogin) return
    clearCopied()
    try {
      const itemId = selectedLogin.id
      await withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.copyCustomField({
          id: itemId,
          expectedUpdatedAt: selectedLogin.updatedAt,
          source: { index, name: field.name, type: field.type, linkedId: field.linkedId },
          ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {})
        })
      )
      showCopied(customFieldCopyFeedbackKey(itemId, index, field))
      await refreshItems()
    } catch (copyError) {
      announceError(describeVaultError(copyError))
    }
  }

  async function downloadAttachment(attachmentId: string): Promise<void> {
    if (!selectedLogin || attachmentOperationRef.current) return
    const itemId = selectedLogin.id
    const attachment = selectedLogin.attachments.find((entry) => entry.id === attachmentId)
    const operationId = beginAttachmentOperation('download', itemId, attachment?.fileName ?? null)
    try {
      const result = await withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.downloadAttachment({
          id: itemId,
          attachmentId,
          operationId,
          ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {})
        })
      )
      if (!result.canceled && selectedIdRef.current === itemId) {
        announce(t`Downloaded “${result.fileName}”.`)
      }
      if (!result.canceled) {
        await refreshItems().catch(() =>
          announceError(
            t`The attachment was downloaded, but the list could not be refreshed. Sync again later.`
          )
        )
      }
    } catch (downloadError) {
      if (
        isCurrentAttachmentOperation(operationId, itemId) &&
        !isAttachmentCanceled(downloadError)
      ) {
        announceError(describeVaultError(downloadError))
      }
    } finally {
      finishAttachmentOperation(operationId)
    }
  }

  async function uploadAttachment(): Promise<void> {
    if (!selectedLogin || attachmentOperationRef.current) return
    const itemId = selectedLogin.id
    const operationId = beginAttachmentOperation('upload', itemId, null)
    try {
      const result = await withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.uploadAttachment({
          id: itemId,
          operationId,
          ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {})
        })
      )
      if (result.attachment) {
        updateSelectedAttachments(itemId, (attachments) =>
          attachments.some((entry) => entry.id === result.attachment!.id)
            ? attachments.map((entry) =>
                entry.id === result.attachment!.id ? result.attachment! : entry
              )
            : [...attachments, result.attachment!]
        )
        if (selectedIdRef.current === itemId) {
          announce(t`Uploaded “${result.attachment.fileName}”.`)
        }
        await refreshItems().catch(() =>
          announceError(
            t`The attachment was uploaded, but the list could not be refreshed. Sync again later.`
          )
        )
      }
    } catch (uploadError) {
      if (isCurrentAttachmentOperation(operationId, itemId) && !isAttachmentCanceled(uploadError)) {
        announceError(describeVaultError(uploadError))
      }
    } finally {
      finishAttachmentOperation(operationId)
    }
  }

  async function deleteSelectedAttachment(): Promise<void> {
    const target = attachmentDeleteTarget
    if (!target || target.itemId !== selectedIdRef.current || attachmentOperationRef.current) return
    setAttachmentDeleteTarget(null)
    const operationId = beginAttachmentOperation('delete', target.itemId, target.fileName)
    try {
      const result = await withReprompt([target.itemId], (tokenFor) =>
        window.bearwarden.logins.deleteAttachment({
          id: target.itemId,
          attachmentId: target.attachmentId,
          operationId,
          ...(tokenFor(target.itemId) ? { authorizationToken: tokenFor(target.itemId) } : {})
        })
      )
      updateSelectedAttachments(target.itemId, (attachments) =>
        attachments.filter((entry) => entry.id !== result.attachmentId)
      )
      if (selectedIdRef.current === target.itemId) announce(t`Deleted “${target.fileName}”.`)
      await refreshItems().catch(() =>
        announceError(
          t`The attachment was deleted, but the list could not be refreshed. Sync again later.`
        )
      )
    } catch (deleteError) {
      if (
        isCurrentAttachmentOperation(operationId, target.itemId) &&
        !isAttachmentCanceled(deleteError)
      ) {
        announceError(describeVaultError(deleteError))
      }
    } finally {
      finishAttachmentOperation(operationId)
    }
  }

  async function fixLegacyAttachment(attachmentId: string): Promise<void> {
    if (!selectedLogin || attachmentOperationRef.current) return
    const itemId = selectedLogin.id
    const attachment = selectedLogin.attachments.find((entry) => entry.id === attachmentId)
    if (!attachment?.legacy) return
    const operationId = beginAttachmentOperation('fix-legacy', itemId, attachment.fileName)
    try {
      const result = await withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.fixLegacyAttachment({
          id: itemId,
          attachmentId,
          operationId,
          ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {})
        })
      )
      updateSelectedAttachments(itemId, (attachments) => {
        const replacementIndex = attachments.findIndex((entry) => entry.id === attachmentId)
        if (replacementIndex < 0) return [...attachments, result.attachment]
        return attachments.map((entry, index) =>
          index === replacementIndex ? result.attachment : entry
        )
      })
      if (selectedIdRef.current === itemId) announce(t`Repaired “${attachment.fileName}”.`)
      await refreshItems().catch(() =>
        announceError(
          t`The attachment was repaired, but the list could not be refreshed. Sync again later.`
        )
      )
    } catch (fixError) {
      if (isCurrentAttachmentOperation(operationId, itemId) && !isAttachmentCanceled(fixError)) {
        announceError(describeVaultError(fixError))
      }
    } finally {
      finishAttachmentOperation(operationId)
    }
  }

  async function cancelAttachmentOperation(): Promise<void> {
    const operation = attachmentOperationRef.current
    if (!operation || operation.canceling) return
    const canceling = { ...operation, canceling: true }
    attachmentOperationRef.current = canceling
    setAttachmentOperation(canceling)
    try {
      const result = await window.bearwarden.logins.cancelAttachment({
        operationId: operation.operationId
      })
      if (
        !result.canceled &&
        attachmentOperationRef.current?.operationId === operation.operationId
      ) {
        const current = { ...attachmentOperationRef.current, canceling: false }
        attachmentOperationRef.current = current
        setAttachmentOperation(current)
      }
    } catch (cancelError) {
      if (attachmentOperationRef.current?.operationId === operation.operationId) {
        const current = { ...attachmentOperationRef.current, canceling: false }
        attachmentOperationRef.current = current
        setAttachmentOperation(current)
        announceError(describeVaultError(cancelError))
      }
    }
  }

  async function copyTotp(): Promise<void> {
    if (!selectedLogin?.hasTotp) return
    clearCopied()
    try {
      const itemId = selectedLogin.id
      await withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.copyTotp({
          id: itemId,
          ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {})
        })
      )
      showCopied(`totp:${itemId}`)
      await refreshItems()
    } catch (copyError) {
      announceError(describeVaultError(copyError))
    }
  }

  async function openWebsite(uriIndex = 0): Promise<void> {
    if (!selectedSummary?.uris[uriIndex]?.uri) return
    try {
      const itemId = selectedSummary.id
      await withReprompt([itemId], (tokenFor) =>
        window.bearwarden.logins.openUri({
          id: itemId,
          uriIndex,
          ...(tokenFor(itemId) ? { authorizationToken: tokenFor(itemId) } : {})
        })
      )
      announce(t`Website opened.`)
      await refreshItems()
    } catch (openError) {
      announceError(describeVaultError(openError))
    }
  }

  function startDrag(event: DragStartEvent): void {
    const activeId = String(event.active.id)
    if (itemIds.has(activeId) && !selectedIdsRef.current.has(activeId)) selectLogin(activeId)
    foldersBeforeDragRef.current = folderIds.has(activeId) ? folders : null
    foldersDuringDragRef.current = folderIds.has(activeId) ? folders : null
    setActiveDragId(activeId)
    setActiveDragOverId(null)
  }

  function dragOver(event: DragOverEvent): void {
    setActiveDragOverId(event.over ? String(event.over.id) : null)
    const activeId = String(event.active.id)
    const overId = event.over ? String(event.over.id) : null
    if (!overId || activeId === overId) return
    if (!folderIds.has(activeId) || !folderIds.has(overId)) return
    setFolders((previous) => {
      const oldIndex = previous.findIndex((folder) => folder.id === activeId)
      const newIndex = previous.findIndex((folder) => folder.id === overId)
      if (oldIndex < 0 || newIndex < 0 || oldIndex === newIndex) return previous
      const reordered = arrayMove(previous, oldIndex, newIndex).map((folder, position) => ({
        ...folder,
        position
      }))
      foldersDuringDragRef.current = reordered
      return reordered
    })
  }

  function cancelDrag(): void {
    const previousFolders = foldersBeforeDragRef.current
    foldersBeforeDragRef.current = null
    foldersDuringDragRef.current = null
    if (previousFolders) setFolders(previousFolders)
    setActiveDragId(null)
    setActiveDragOverId(null)
  }

  async function endDrag(event: DragEndEvent): Promise<void> {
    const previousFolders = foldersBeforeDragRef.current
    const reorderedFolders = foldersDuringDragRef.current
    foldersBeforeDragRef.current = null
    foldersDuringDragRef.current = null
    setActiveDragId(null)
    setActiveDragOverId(null)
    if (!event.over) {
      if (previousFolders) setFolders(previousFolders)
      return
    }
    const activeId = String(event.active.id)
    const overId = String(event.over.id)
    if (itemIds.has(activeId)) {
      const draggedIds = selectedIdsRef.current.has(activeId)
        ? [...selectedIdsRef.current]
        : [activeId]
      const snapshot: MoveSnapshot = {
        ids: draggedIds,
        state: scope.kind === 'archive' ? 'archive' : 'active'
      }
      const quickAction = quickAccessDropAction(overId, snapshot.state)
      if (quickAction === 'favorites') await addLoginsToFavorites(snapshot)
      else if (quickAction === 'archive') {
        await performBulkAction({ action: 'archive', ...snapshot })
      } else if (quickAction === 'trash') {
        setPendingBulkAction({ action: 'delete', ...snapshot })
      } else if (overId === 'folder:none') await moveLogins(snapshot, null)
      else if (folderIds.has(overId)) await moveLogins(snapshot, overId)
      return
    }
    if (!previousFolders || !folderIds.has(activeId)) return
    const reordered = reorderedFolders ?? previousFolders
    const orderedIds = reordered.map((folder) => folder.id)
    if (orderedIds.every((id, index) => id === previousFolders[index]?.id)) return
    try {
      const saved = await window.bearwarden.folders.reorder({ orderedIds })
      setFolders([...saved].sort((left, right) => left.position - right.position))
      announce(t`Folder order updated.`)
    } catch (reorderError) {
      setFolders(previousFolders)
      announceError(describeVaultError(reorderError))
    }
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
      sensors={sensors}
      collisionDetection={precisePointerCollisionDetection}
      onDragStart={startDrag}
      onDragOver={dragOver}
      onDragCancel={cancelDrag}
      onDragEnd={(event) => void endDrag(event)}
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
            onClear: () => updateQuery('')
          }}
          itemCreation={{
            visible: !auxiliaryPageOpen && scope.kind !== 'archive' && scope.kind !== 'trash',
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
            onQueryChange: updateQuery,
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

            (isMac || isWindows) && 'gap-2 pr-2 pb-2 max-[880px]:pl-2',
            auxiliaryPageOpen && (isMac || isWindows) && 'pl-2'
          )}
        >
          <VaultShellSidebar
            appearance={{ isMac, isWindows, open: sidebarOpen }}
            navigation={{
              categories: categoryMeta,
              categoryCounts,
              quickAccessCounts: {
                favorites: activeItems.filter((item) => item.favorite).length,
                recentlyUsed: activeItems.filter((item) => item.lastUsedAt).length,
                archive: archivedItems.length,
                trash: trashItems.length
              },
              folderCounts
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
              onOpenOrganizations: openOrganizations,
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

              (isMac || isWindows) &&
                '[@media(prefers-reduced-transparency:reduce)]:bg-card rounded-2xl border border-(--native-material-border) bg-(--native-panel-material) shadow-(--native-material-shadow) [backdrop-filter:saturate(145%)_blur(24px)] [-webkit-backdrop-filter:saturate(145%)_blur(24px)] [@media(prefers-reduced-transparency:reduce)]:[backdrop-filter:none] [@media(prefers-reduced-transparency:reduce)]:[-webkit-backdrop-filter:none]'
            )}
            data-vault-pane-group=""
          >
            <section
              className={cn(
                'border-border relative flex min-h-0 min-w-0 flex-col border-r bg-transparent max-[680px]:size-full [[data-has-detail=true]_&]:max-[680px]:hidden',
                (isMac || isWindows) && 'border-r-(--native-material-border)'
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
                    await Promise.allSettled([
                      loadVault(),
                      syncStatusStore
                        .getState()
                        .refreshStatus(() => window.bearwarden.sync.status())
                    ])
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
                  onReorderAccounts={reorderLocalAccounts}
                  onRemoveAccount={removeLocalAccount}
                />
              ) : (
                <VaultItemListPane
                  list={{
                    scopeTitle,
                    itemCount: scopedItems.length,
                    groups: itemGroups,
                    sortOptions: sortItemsOptions,
                    showWebsiteIcons: settings?.showWebsiteIcons ?? false,
                    totpCodes: totpListCodes,
                    totpCountdown: totpListCountdown,
                    trashItemCount: trashItems.length
                  }}
                  selection={{
                    selectedItemCount: selectedSummaries.length
                  }}
                  actions={{
                    onPrefetch: prefetchLoginDetail,
                    onSelect: selectItems,
                    onToggleFavorite: toggleFavorite,
                    onContextMenu: showLoginContextMenu,
                    onOpenCreate: () => openEditor('create'),
                    snapshotBulkAction,
                    onPerformBulkAction: performBulkAction,
                    onSetPendingBulkAction: setPendingBulkAction,
                    onOpenMove: openMoveDialogForSelection,
                    onEmptyTrash: () => setEmptyTrashDialogOpen(true)
                  }}
                />
              )}
            </section>

            <section
              className="relative flex min-h-0 min-w-0 overflow-hidden bg-transparent max-[680px]:hidden max-[680px]:size-full [[data-has-detail=true]_&]:max-[680px]:flex"
              data-vault-detail-pane=""
              aria-label={t`Item details`}
            >
              {editorMode ? (
                <LoginEditor
                  key={`${editorSessionId}:${editorMode}:${selectedLogin?.id ?? 'new'}`}
                  login={editorMode === 'edit' ? (selectedLogin ?? undefined) : undefined}
                  folders={folders}
                  busy={busy}
                  authorizationToken={
                    selectedLogin ? authorizationTokenState[selectedLogin.id] : undefined
                  }
                  onCancel={() => requestEditorTransition(() => setEditorMode(null))}
                  onDirtyChange={handleEditorDirtyChange}
                  onDeletePasskey={deletePasskey}
                  onSave={saveLogin}
                />
              ) : selectedSummary?.deletedAt ? (
                <article className="flex size-full min-h-0 min-w-0 flex-col">
                  <DetailHeader>
                    <TooltipIconButton
                      variant="outline"
                      size="icon"
                      className="hidden max-[680px]:grid"
                      data-detail-back=""
                      type="button"
                      label={t`Back to Trash`}
                      onClick={clearItemSelection}
                    >
                      <ArrowLeft />
                    </TooltipIconButton>
                    <span className={detailIconClassName()} aria-hidden="true">
                      <Trash2 />
                    </span>
                    <div className="[&>span]:text-muted-foreground min-w-0 flex-1 [&>h2]:m-0 [&>h2]:truncate [&>h2]:text-base [&>h2]:font-medium [&>h2]:tracking-[-0.015em] [&>span]:mt-0.5 [&>span]:block [&>span]:truncate [&>span]:text-[10px]">
                      <p className="text-primary m-0 mb-[3px] text-[9px] font-extrabold tracking-[0.11em] uppercase">
                        <Trans>Trash</Trans>
                      </p>
                      <h2>{selectedSummary.name}</h2>
                      <span>{itemTypeMeta[selectedSummary.type].label}</span>
                    </div>
                  </DetailHeader>
                  <div
                    className={cn(
                      'scroll-fade-y forced-colors:scroll-fade-none',
                      detailScrollClassName
                    )}
                  >
                    <DetailCard>
                      <CardHeader>
                        <CardTitle>
                          <Trash2 aria-hidden="true" />
                          <Trans>This item is in Trash</Trans>
                        </CardTitle>
                        <CardDescription>
                          <Trans>
                            To protect deleted sensitive data, restore the item before viewing or
                            editing its contents.
                          </Trans>
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <dl className="m-0 px-(--card-spacing) py-1">
                          <div className="border-border grid grid-cols-[minmax(90px,0.28fr)_1fr] border-b py-2.5 last:border-b-0 max-[430px]:grid-cols-1 max-[430px]:gap-1">
                            <dt className="text-muted-foreground text-[11px]">
                              <Trans>Deleted</Trans>
                            </dt>
                            <dd className="m-0 text-[11px]">
                              {formatDate(selectedSummary.deletedAt)}
                            </dd>
                          </div>
                          <div className="border-border grid grid-cols-[minmax(90px,0.28fr)_1fr] border-b py-2.5 last:border-b-0 max-[430px]:grid-cols-1 max-[430px]:gap-1">
                            <dt className="text-muted-foreground text-[11px]">
                              <Trans>Original folder</Trans>
                            </dt>
                            <dd className="m-0 text-[11px]">
                              {folders.find((folder) => folder.id === selectedSummary.folderId)
                                ?.name ?? t`Unfiled`}
                            </dd>
                          </div>
                        </dl>
                      </CardContent>
                    </DetailCard>
                    {hasTrashPasswordHistory(selectedSummary) && (
                      <DetailCard role="region" aria-labelledby="trash-password-history-title">
                        <CardHeader>
                          <CardTitle id="trash-password-history-title">
                            <History aria-hidden="true" />
                            <Trans>Item history</Trans>
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="contents">
                          <dl className="m-0 px-(--card-spacing) py-1">
                            <div className="border-border grid grid-cols-[minmax(90px,0.28fr)_minmax(0,1fr)] items-center gap-2 border-b py-2.5 last:border-b-0 max-[430px]:grid-cols-1 max-[430px]:items-start max-[430px]:gap-1">
                              <dt className="text-muted-foreground text-[11px] leading-4">
                                <Trans>Password history</Trans>
                              </dt>
                              <dd className="m-0 flex min-w-0 items-center gap-2 text-xs leading-4">
                                <span className="min-w-0 flex-1 truncate">
                                  <Trans>
                                    {selectedSummary.passwordHistoryCount} read-only records
                                  </Trans>
                                </span>
                                <Button
                                  variant="ghost"
                                  size="icon-sm"
                                  className="-my-1.5 ml-auto"
                                  type="button"
                                  aria-label={t`View password history`}
                                  disabled={busy}
                                  onClick={() => setPasswordHistoryDialogOpen(true)}
                                >
                                  <History aria-hidden="true" />
                                </Button>
                              </dd>
                            </div>
                          </dl>
                        </CardContent>
                      </DetailCard>
                    )}
                    <div className="mx-auto flex max-w-[720px] flex-wrap justify-end gap-2">
                      <Button type="button" disabled={busy} onClick={() => void restoreLogin()}>
                        <RotateCcw data-icon="inline-start" />
                        <Trans>Restore item</Trans>
                      </Button>
                      <Button
                        variant="destructive"
                        type="button"
                        disabled={busy}
                        onClick={() => setDeleteDialogOpen(true)}
                      >
                        <Trash2 data-icon="inline-start" />
                        <Trans>Delete permanently</Trans>
                      </Button>
                    </div>
                  </div>
                </article>
              ) : selectedId && selectedSummary && selectedLogin?.id !== selectedId ? (
                <DetailPlaceholder
                  item={selectedSummary}
                  showWebsiteIcons={settings?.showWebsiteIcons ?? false}
                  onBack={clearItemSelection}
                />
              ) : selectedLogin && selectedLogin.id === selectedId ? (
                <article className="flex size-full min-h-0 min-w-0 flex-col">
                  <DetailHeader>
                    <TooltipIconButton
                      variant="outline"
                      size="icon"
                      className="hidden max-[680px]:grid"
                      data-detail-back=""
                      type="button"
                      label={t`Back to item list`}
                      onClick={clearItemSelection}
                    >
                      <ArrowLeft />
                    </TooltipIconButton>
                    <span
                      className={detailIconClassName(selectedLogin.type)}
                      data-detail-icon=""
                      aria-hidden="true"
                    >
                      {selectedLogin.type === 'login' ? (
                        <WebsiteIcon
                          id={selectedLogin.id}
                          uri={selectedLogin.uri}
                          enabled={settings?.showWebsiteIcons ?? false}
                        />
                      ) : selectedLogin.type === 'card' ? (
                        <PaymentCardBrandMark
                          brand={normalizeBitwardenCardBrand(selectedLogin.brand)}
                          compact
                        />
                      ) : (
                        (() => {
                          const TypeIcon = itemTypeMeta[selectedLogin.type].icon
                          return <TypeIcon size={18} />
                        })()
                      )}
                    </span>
                    <div className="[&>span]:text-muted-foreground min-w-0 flex-1 [&>h2]:m-0 [&>h2]:truncate [&>h2]:text-base [&>h2]:font-medium [&>h2]:tracking-[-0.015em] [&>span]:mt-0.5 [&>span]:block [&>span]:truncate [&>span]:text-[10px]">
                      <h2>{selectedLogin.name}</h2>
                      <span>
                        {selectedLogin.subtitle ||
                          (selectedLogin.type === 'login'
                            ? hostLabel(selectedLogin.uri, t`Website not set`)
                            : t`Securely stored item`)}
                      </span>
                    </div>
                    <TooltipIconButton
                      variant="outline"
                      size="icon"
                      className={cn(selectedLogin.favorite && 'text-chart-4')}
                      type="button"
                      label={
                        selectedLogin.favorite ? t`Remove from favorites` : t`Add to favorites`
                      }
                      aria-pressed={selectedLogin.favorite}
                      onClick={() => void toggleFavorite(selectedLogin)}
                    >
                      <Star fill={selectedLogin.favorite ? 'currentColor' : 'none'} />
                    </TooltipIconButton>
                    <DropdownMenu>
                      <Tooltip>
                        <TooltipTrigger
                          render={
                            <DropdownMenuTrigger
                              render={
                                <Button
                                  variant="outline"
                                  size="icon"
                                  className="border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground dark:bg-card dark:hover:bg-muted size-[34px] min-w-[34px] rounded-md shadow-(--control-highlight)"
                                  type="button"
                                  aria-label={t`More actions`}
                                  disabled={busy}
                                />
                              }
                            >
                              <MoreHorizontal aria-hidden="true" />
                            </DropdownMenuTrigger>
                          }
                        />
                        <TooltipContent>
                          <Trans>More actions</Trans>
                        </TooltipContent>
                      </Tooltip>
                      <DropdownMenuContent align="end">
                        <DropdownMenuGroup>
                          <DropdownMenuItem disabled={busy} onClick={() => void cloneLogin()}>
                            <Copy data-icon="inline-start" />
                            <Trans>Duplicate item</Trans>
                          </DropdownMenuItem>
                          <DropdownMenuItem
                            disabled={busy}
                            onClick={() =>
                              void (selectedLogin.archivedAt ? unarchiveLogin() : archiveLogin())
                            }
                          >
                            {selectedLogin.archivedAt ? (
                              <ArchiveRestore data-icon="inline-start" />
                            ) : (
                              <Archive data-icon="inline-start" />
                            )}
                            {selectedLogin.archivedAt ? t`Unarchive` : t`Archive item`}
                          </DropdownMenuItem>
                          <DropdownMenuItem disabled={busy} onClick={() => openEditor('edit')}>
                            <Edit3 data-icon="inline-start" />
                            <Trans>Edit</Trans>
                          </DropdownMenuItem>
                          {selectedLogin.attachments.length === 0 && (
                            <DropdownMenuItem
                              disabled={
                                busy || attachmentOperation !== null || syncStatus.state !== 'ready'
                              }
                              onClick={() => void uploadAttachment()}
                            >
                              <Upload data-icon="inline-start" />
                              <Trans>Upload attachment</Trans>
                            </DropdownMenuItem>
                          )}
                        </DropdownMenuGroup>
                        <DropdownMenuSeparator />
                        <DropdownMenuGroup>
                          <DropdownMenuItem
                            variant="destructive"
                            disabled={busy}
                            onClick={() => setDeleteDialogOpen(true)}
                          >
                            <Trash2 data-icon="inline-start" />
                            <Trans>Move to Trash</Trans>
                          </DropdownMenuItem>
                        </DropdownMenuGroup>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </DetailHeader>

                  <div
                    className={cn(
                      'scroll-fade-y forced-colors:scroll-fade-none',
                      detailScrollClassName
                    )}
                  >
                    {selectedDetailFields.length > 0 && (
                      <DetailCard
                        role="region"
                        aria-labelledby="credentials-title"
                        className="gap-1 pb-0"
                      >
                        <CardHeader>
                          <CardTitle id="credentials-title">
                            {(() => {
                              const TypeIcon = itemTypeMeta[selectedLogin.type].icon
                              return <TypeIcon aria-hidden="true" />
                            })()}
                            {t`${itemTypeMeta[selectedLogin.type].label} details`}
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="flex flex-col">
                          <VaultDetailFieldRows
                            fields={selectedDetailFields.filter(
                              (field) => field.secret || Boolean(field.value)
                            )}
                            copy={{
                              copiedKey,
                              itemId: selectedSummary?.id,
                              copyField
                            }}
                            reveal={{
                              state: revealedSecrets,
                              selectedItemId: selectedLogin.id,
                              hoveringFieldsRef: hoveringSecretFieldsRef,
                              hoverRevealedFieldsRef: hoverRevealedSecretFieldsRef,
                              passwordZoomOpenRef,
                              reveal: revealSecret,
                              hide: hideRevealedSecret,
                              openPasswordZoom
                            }}
                            website={{ openWebsite }}
                          />
                        </CardContent>
                      </DetailCard>
                    )}

                    {selectedLogin.customFields.length > 0 && (
                      <DetailCard
                        role="region"
                        aria-labelledby="custom-fields-title"
                        className="gap-1 pb-0"
                      >
                        <CardHeader>
                          <CardTitle id="custom-fields-title">
                            <Settings2 aria-hidden="true" />
                            <Trans>Custom fields</Trans>
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="flex flex-col">
                          <VaultCustomFieldRows
                            fields={selectedLogin.customFields}
                            item={{ id: selectedLogin.id, updatedAt: selectedLogin.updatedAt }}
                            labels={customFieldLabels}
                            copy={{ copiedKey, copyField: copyCustomField }}
                            reveal={{ state: revealedCustomFields, reveal: revealCustomField }}
                          />
                        </CardContent>
                      </DetailCard>
                    )}

                    <VaultItemAttachmentsCard
                      itemId={selectedLogin.id}
                      attachments={selectedLogin.attachments}
                      busy={busy}
                      syncReady={syncStatus.state === 'ready'}
                      operation={attachmentOperation}
                      getOperationStageLabel={getAttachmentStageLabel}
                      onUpload={uploadAttachment}
                      onCancelOperation={cancelAttachmentOperation}
                      onFixLegacy={fixLegacyAttachment}
                      onDownload={downloadAttachment}
                      onDelete={setAttachmentDeleteTarget}
                    />

                    {selectedLogin.type === 'login' && selectedLogin.hasTotp && (
                      <VaultItemTotpCard
                        code={totpCode}
                        generationError={totpGenerationError}
                        revealReady={totpRevealReady}
                        showSkeleton={showTotpSkeleton}
                        codeCycle={totpCodeState?.cycle ?? null}
                        showCountdown={typeFilter !== 'totp'}
                        copied={copiedKey === `totp:${selectedLogin.id}`}
                        defaultCountdownPeriodSeconds={totpListCountdownPeriodSeconds}
                        onCopy={copyTotp}
                      />
                    )}

                    <VaultItemMetadataCards
                      selectedLogin={selectedLogin}
                      folders={folders}
                      formatDate={formatDate}
                      busy={busy}
                      onMoveToFolder={openMoveDialogForSelection}
                      onViewPasswordHistory={() => setPasswordHistoryDialogOpen(true)}
                    />
                  </div>
                </article>
              ) : (
                <Empty className="min-h-0 flex-1 gap-0 p-7">
                  <EmptyHeader>
                    <EmptyMedia
                      className="text-muted-foreground mb-4 h-48 bg-transparent"
                      aria-hidden="true"
                    >
                      <img className="size-48 object-contain" src={bearCutUrl} alt="" />
                    </EmptyMedia>
                    <EmptyTitle className="text-foreground m-0 text-xl font-[720]">
                      <Trans>No item selected</Trans>
                    </EmptyTitle>
                    <EmptyDescription className="text-muted-foreground mt-[7px] mb-4 max-w-[290px] text-xs leading-[1.55]">
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
              onClose: () => setFolderDialog(null),
              onSave: saveFolder,
              onDelete: deleteFolder
            },
            move: {
              snapshot: moveSnapshot,
              itemName: moveSummaries[0]?.name,
              currentFolderId: moveFolderId,
              folders,
              onClose: () => setMoveSnapshot(null),
              onMove: moveLogins
            },
            deletion: {
              selectedSummary,
              deleteOpen: deleteDialogOpen,
              onCloseDelete: () => setDeleteDialogOpen(false),
              onDelete: deleteLogin,
              trashItemCount: trashItems.length,
              emptyTrashOpen: emptyTrashDialogOpen,
              onCloseEmptyTrash: () => setEmptyTrashDialogOpen(false),
              onEmptyTrash: emptyTrash,
              pendingBulkAction,
              onCloseBulkAction: () => setPendingBulkAction(null),
              onPerformBulkAction: performBulkAction
            },
            passwordHistory: {
              open: passwordHistoryDialogOpen,
              selectedSummary,
              onClose: () => setPasswordHistoryDialogOpen(false),
              onLoad: loadPasswordHistory,
              onReveal: revealPasswordHistory,
              onCopy: copyPasswordHistory
            },
            passwordZoom: {
              value: passwordZoomValue,
              onClose: closePasswordZoom
            },
            generator: {
              open: generatorDialogOpen,
              onClose: () => setGeneratorDialogOpen(false),
              onGenerate: window.bearwarden.generator.generate,
              onCopyGenerated: (token) => window.bearwarden.generator.copyGenerated({ token }),
              onListHistory: window.bearwarden.generator.history,
              onCopyHistory: window.bearwarden.generator.copyHistory,
              onClearHistory: window.bearwarden.generator.clearHistory
            },
            attachment: {
              deleteTarget: attachmentDeleteTarget,
              onCloseDelete: () => setAttachmentDeleteTarget(null),
              onDelete: deleteSelectedAttachment
            }
          }}
          securityDialogs={{
            reprompt: {
              prompt: repromptPrompt,
              busy: repromptBusy,
              onCancel: cancelReprompt,
              onAuthorize: submitReprompt
            },
            loginApproval: {
              prompt: loginApprovalPrompts[0],
              onClose: () => setLoginApprovalPrompts((current) => current.slice(1))
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
              onExport: (request) => window.bearwarden.portability.export(request),
              onImport: (request) => window.bearwarden.portability.import(request),
              onExported: announceExported,
              onImported: refreshAfterImport
            }
          }}
        />
      </main>

      <DragOverlay dropAnimation={null} style={{ pointerEvents: 'none' }}>
        {activeDragItem ? (
          <ItemDragPreview
            item={activeDragItem}
            count={activeDragItemCount}
            showWebsiteIcons={settings?.showWebsiteIcons ?? false}
            destinationDescription={activeDragDestinationDescription}
          />
        ) : null}
      </DragOverlay>
    </DndContext>
  )
}

function VaultShell(props: VaultShellProps): React.JSX.Element {
  return (
    <VaultSessionStoreProvider>
      <VaultShellContent {...props} />
    </VaultSessionStoreProvider>
  )
}

export default VaultShell
