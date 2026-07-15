import {
  closestCenter,
  DndContext,
  DragOverlay,
  KeyboardSensor,
  PointerSensor,
  useDroppable,
  useSensor,
  useSensors,
  type DragEndEvent,
  type DragStartEvent
} from '@dnd-kit/core'
import {
  arrayMove,
  SortableContext,
  sortableKeyboardCoordinates,
  verticalListSortingStrategy
} from '@dnd-kit/sortable'
import {
  ArrowLeft,
  ArrowUpRight,
  BadgeCheck,
  Clipboard,
  Clock3,
  CloudAlert,
  CloudCheck,
  CloudCog,
  CloudSync,
  ContactRound,
  Copy,
  CreditCard,
  Edit3,
  Eye,
  EyeOff,
  FileKey2,
  Fingerprint,
  Folder,
  FolderOpen,
  KeyRound,
  ListFilter,
  Menu,
  NotebookPen,
  Plus,
  Settings2,
  Search,
  Star,
  Trash2,
  X
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { toast } from 'sonner'
import type {
  AppSettings,
  AppSettingsUpdate,
  FolderView,
  LoginSummary,
  LoginView,
  SyncStatus,
  TotpCodeView,
  VaultCopyField,
  VaultCustomFieldSource,
  VaultCustomFieldView,
  VaultItemType,
  VaultSecretField
} from '../../../shared/vault-contract'
import { MAX_LOGIN_MOVE_MANY_IDS } from '../../../shared/vault-contract'
import bearCutUrl from '../assets/bear-cut.svg'
import BrandMark from './BrandMark'
import { DeleteLoginDialog, FolderDialog, MoveDialog } from './Dialogs'
import { FolderDragPreview, ItemDragPreview } from './DragPreview'
import { FolderRow, type ItemSelectionModifiers } from './DndRows'
import LoginEditor, { type LoginDraft } from './LoginEditor'
import SyncDialog from './SyncDialog'
import SettingsPage from './SettingsPage'
import VirtualizedItemList from './VirtualizedItemList'
import { groupItemsByDate } from '../lib/item-date-groups'
import { matchesVaultCategory, type VaultCategoryFilter } from '../lib/vault-category'
import { formatPaymentCardNumber } from '../lib/payment-card'
import { normalizeBitwardenCardBrand } from '../lib/payment-card'
import { normalizeItemSelection, updateItemSelection } from '../lib/item-selection'
import PaymentCardBrandMark from './PaymentCardBrandMark'
import WebsiteIcon from './WebsiteIcon'
import { Button } from '@renderer/components/ui/button'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle
} from '@renderer/components/ui/alert-dialog'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle
} from '@renderer/components/ui/card'
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle
} from '@renderer/components/ui/empty'
import { InputGroup, InputGroupAddon, InputGroupButton } from '@renderer/components/ui/input-group'
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList
} from '@renderer/components/ui/command'
import { Kbd } from '@renderer/components/ui/kbd'
import { Progress } from '@renderer/components/ui/progress'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue
} from '@renderer/components/ui/select'
import { Skeleton } from '@renderer/components/ui/skeleton'
import { Spinner } from '@renderer/components/ui/spinner'
import { Tooltip, TooltipContent, TooltipTrigger } from '@renderer/components/ui/tooltip'
import { cn } from '@renderer/lib/utils'
import { applyThemePreference } from '@renderer/lib/theme'

type Scope =
  | { kind: 'all' }
  | { kind: 'favorites' }
  | { kind: 'recent' }
  | { kind: 'folder'; folderId: string }
  | { kind: 'unfiled' }

type SortMode = 'title' | 'recent' | 'modified'

type TypeFilter = VaultCategoryFilter

interface ItemTypeMeta {
  label: string
  icon: typeof KeyRound
}

interface DetailField {
  field: VaultCopyField
  label: string
  value?: string | null
  secret?: boolean
  copyable?: boolean
  openUri?: boolean
}

const itemTypeMeta: Record<VaultItemType, ItemTypeMeta> = {
  login: { label: '登入', icon: KeyRound },
  card: { label: '卡片', icon: CreditCard },
  identity: { label: '身分資料', icon: ContactRound },
  secureNote: { label: '安全備註', icon: NotebookPen },
  sshKey: { label: 'SSH 金鑰', icon: FileKey2 }
}

const categoryMeta: Array<{
  id: TypeFilter
  label: string
  icon: typeof KeyRound
  tone: string
}> = [
  { id: 'all', label: '全部', icon: KeyRound, tone: 'blue' },
  { id: 'login', label: '登入', icon: FileKey2, tone: 'indigo' },
  { id: 'passkey', label: '通行密鑰', icon: Fingerprint, tone: 'green' },
  { id: 'totp', label: '驗證碼', icon: BadgeCheck, tone: 'yellow' },
  { id: 'card', label: '支付卡', icon: CreditCard, tone: 'cyan' },
  { id: 'identity', label: '身分', icon: ContactRound, tone: 'red' },
  { id: 'secureNote', label: '備註', icon: NotebookPen, tone: 'orange' },
  { id: 'sshKey', label: 'SSH 金鑰', icon: FileKey2, tone: 'gray' }
]

const initialSyncStatus: SyncStatus = { configured: false, state: 'unconfigured' }

const syncStateMeta = {
  unconfigured: { label: '尚未設定', icon: CloudCog },
  locked: { label: '需要解鎖', icon: CloudAlert },
  ready: { label: '已連線', icon: CloudCheck },
  syncing: { label: '同步中…', icon: CloudSync },
  error: { label: '需要處理問題', icon: CloudAlert }
} satisfies Record<SyncStatus['state'], { label: string; icon: typeof CloudCheck }>

const sortItemsOptions = [
  { label: '依名稱', value: 'title' },
  { label: '最近使用', value: 'recent' },
  { label: '最近修改', value: 'modified' }
] as const

const isMac = navigator.userAgent.includes('Mac')
const commandLabel = isMac ? '⌘' : 'Ctrl'
const moveShortcutLabel = isMac ? '⇧⌘M' : 'Ctrl+Shift+M'
const dateTimeFormatter = new Intl.DateTimeFormat('zh-TW', {
  dateStyle: 'medium',
  timeStyle: 'short'
})
const detailCacheLimit = 48

interface VaultShellProps {
  onLocked: () => void
}

interface RevealedSecretsState {
  itemId: string | null
  values: Partial<Record<VaultSecretField, string>>
}

const emptyRevealedSecrets: RevealedSecretsState = { itemId: null, values: {} }

interface RevealedCustomFieldsState {
  itemId: string | null
  values: Record<
    number,
    { value: string; source: VaultCustomFieldSource; expectedUpdatedAt: string }
  >
}

const emptyRevealedCustomFields: RevealedCustomFieldsState = { itemId: null, values: {} }

interface TooltipIconButtonProps extends React.ComponentProps<typeof Button> {
  label: string
}

function TooltipIconButton({
  label,
  children,
  ...props
}: TooltipIconButtonProps): React.JSX.Element {
  return (
    <Tooltip>
      <TooltipTrigger render={<Button aria-label={label} {...props} />}>{children}</TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}

function describeError(error: unknown): string {
  if (!(error instanceof Error)) return '發生未知錯誤。'
  const messages: Record<string, string> = {
    LOCKED: '保管庫已鎖定，請重新解鎖。',
    NOT_FOUND: '找不到指定的項目。',
    INVALID_INPUT: '輸入內容無效，請檢查後再試。',
    DUPLICATE_NAME: '名稱已被使用，請換一個名稱。',
    INVALID_URL: '網站網址格式不正確。'
  }
  const code = Object.keys(messages).find((key) => error.message.includes(key))
  return code ? messages[code] : '操作未完成，你的資料沒有被更動。'
}

const vaultErrorToastId = 'vault-error'

function announceError(message: string): void {
  toast.error(message, {
    id: vaultErrorToastId,
    duration: 7_000
  })
}

function compareNullableDate(left: string | null, right: string | null): number {
  if (left === right) return 0
  if (left === null) return 1
  if (right === null) return -1
  return Date.parse(right) - Date.parse(left)
}

function sortItems(items: LoginSummary[], mode: SortMode): LoginSummary[] {
  const collator = new Intl.Collator('zh-Hant', { numeric: true, sensitivity: 'base' })
  return [...items].sort((left, right) => {
    let result = 0
    if (mode === 'recent') result = compareNullableDate(left.lastUsedAt, right.lastUsedAt)
    if (mode === 'modified') result = Date.parse(right.updatedAt) - Date.parse(left.updatedAt)
    if (result !== 0) return result
    const nameResult = collator.compare(left.name, right.name)
    return nameResult || left.id.localeCompare(right.id)
  })
}

function formatDate(value: string | null): string {
  if (!value) return '尚未使用'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '未知'
  return dateTimeFormatter.format(date)
}

function hostLabel(uri: string | null): string {
  if (!uri) return '未設定網站'
  try {
    return new URL(uri).hostname
  } catch {
    return uri
  }
}

const linkedFieldLabels: Record<number, string> = {
  100: '使用者名稱',
  101: '密碼',
  300: '持卡人',
  301: '到期月份',
  302: '到期年份',
  303: '安全碼',
  304: '品牌',
  305: '卡號',
  400: '稱謂',
  401: '中間名',
  402: '地址 1',
  403: '地址 2',
  404: '地址 3',
  405: '城市',
  406: '州／省',
  407: '郵遞區號',
  408: '國家',
  409: '公司',
  410: '電子郵件',
  411: '電話',
  412: '身分證／社會安全號',
  413: '使用者名稱',
  414: '護照號碼',
  415: '駕照號碼',
  416: '名字',
  417: '姓氏',
  418: '完整姓名'
}

function customFieldDisplayValue(field: VaultCustomFieldView): string {
  if (field.type === 'boolean')
    return field.value?.toLocaleLowerCase('en-US') === 'true' ? '是' : '否'
  if (field.type === 'linked') {
    return `連結至${field.linkedId === null ? '項目欄位' : (linkedFieldLabels[field.linkedId] ?? '項目欄位')}`
  }
  return field.value || '未設定'
}

function matchesCustomFieldSource(
  field: VaultCustomFieldView,
  index: number,
  source: VaultCustomFieldSource
): boolean {
  return (
    source.index === index &&
    source.name === field.name &&
    source.type === field.type &&
    source.linkedId === field.linkedId
  )
}

function detailFields(login: LoginView): DetailField[] {
  if (login.type === 'login') {
    return [
      { field: 'username', label: '使用者名稱', value: login.username, copyable: true },
      { field: 'password', label: '密碼', secret: true },
      { field: 'uri', label: '網站', value: login.uri, copyable: true, openUri: true }
    ]
  }
  if (login.type === 'card') {
    return [
      { field: 'number', label: '卡號', secret: true },
      { field: 'code', label: '安全碼', secret: true },
      { field: 'username', label: '持卡人', value: login.cardholderName },
      { field: 'username', label: '品牌', value: login.brand },
      {
        field: 'username',
        label: '到期日',
        value: [login.expMonth, login.expYear].filter(Boolean).join(' / ')
      }
    ]
  }
  if (login.type === 'identity') {
    return [
      {
        field: 'username',
        label: '姓名',
        value: [login.title, login.firstName, login.middleName, login.lastName]
          .filter(Boolean)
          .join(' ')
      },
      { field: 'username', label: '公司', value: login.company },
      { field: 'email', label: '電子郵件', value: login.email, copyable: true },
      { field: 'phone', label: '電話', value: login.phone, copyable: true },
      {
        field: 'identityUsername',
        label: '使用者名稱',
        value: login.identityUsername,
        copyable: true
      },
      {
        field: 'username',
        label: '地址',
        value: [
          login.address1,
          login.address2,
          login.address3,
          login.city,
          login.state,
          login.postalCode,
          login.country
        ]
          .filter(Boolean)
          .join('，')
      },
      { field: 'ssn', label: '身分證／社會安全號', secret: true },
      { field: 'passportNumber', label: '護照號碼', secret: true },
      { field: 'licenseNumber', label: '駕照號碼', secret: true }
    ]
  }
  if (login.type === 'sshKey') {
    return [
      { field: 'privateKey', label: '私鑰', secret: true },
      { field: 'publicKey', label: '公鑰', value: login.publicKey, copyable: true },
      { field: 'fingerprint', label: '金鑰指紋', value: login.fingerprint, copyable: true }
    ]
  }
  return []
}

function mergeCachedSummary(cache: Map<string, LoginView>, summary: LoginSummary): void {
  const cached = cache.get(summary.id)
  if (cached) cache.set(summary.id, { ...cached, ...summary })
}

function cacheLoginDetail(cache: Map<string, LoginView>, login: LoginView): void {
  cache.delete(login.id)
  while (cache.size >= detailCacheLimit) {
    const oldestId = cache.keys().next().value
    if (!oldestId) break
    cache.delete(oldestId)
  }
  cache.set(login.id, login)
}

function toLoginSummary(login: LoginView): LoginSummary {
  return {
    id: login.id,
    type: login.type,
    name: login.name,
    subtitle: login.subtitle,
    username: login.username,
    uri: login.uri,
    ...(login.cardBrand === undefined ? {} : { cardBrand: login.cardBrand }),
    hasTotp: login.hasTotp,
    ...(login.passkeyCount === undefined ? {} : { passkeyCount: login.passkeyCount }),
    folderId: login.folderId,
    favorite: login.favorite,
    lastUsedAt: login.lastUsedAt,
    createdAt: login.createdAt,
    updatedAt: login.updatedAt
  }
}

interface SidebarLinkProps {
  icon: React.ReactNode
  label: string
  count: number
  active: boolean
  variant?: 'row' | 'tile'
  tone?: string
  onClick: () => void
}

function SidebarLink({
  icon,
  label,
  count,
  active,
  variant = 'row',
  tone,
  onClick
}: SidebarLinkProps): React.JSX.Element {
  return (
    <Button
      variant="ghost"
      className={cn('sidebar-link', variant, tone && `tone-${tone}`, active && 'active')}
      type="button"
      aria-current={active ? 'page' : undefined}
      onClick={onClick}
    >
      <span className="sidebar-link-icon" aria-hidden="true">
        {icon}
      </span>
      <strong>{label}</strong>
      <small>{count}</small>
    </Button>
  )
}

interface UnfiledRowProps {
  selected: boolean
  count: number
  onSelect: () => void
}

function UnfiledRow({ selected, count, onSelect }: UnfiledRowProps): React.JSX.Element {
  const { setNodeRef, isOver } = useDroppable({ id: 'folder:none' })
  return (
    <li
      ref={setNodeRef}
      className={cn('folder-row static', selected && 'selected', isOver && 'drop-target')}
    >
      <span className="folder-static-spacer" aria-hidden="true" />
      <Button
        variant="ghost"
        className="folder-row-main"
        type="button"
        aria-current={selected ? 'page' : undefined}
        onClick={onSelect}
      >
        <FolderOpen size={16} aria-hidden="true" />
        <span>未分類</span>
        <small aria-label={`${count} 個項目`}>{count}</small>
      </Button>
    </li>
  )
}

interface DetailPlaceholderProps {
  item: LoginSummary
  showWebsiteIcons: boolean
  onBack: () => void
}

function DetailPlaceholder({
  item,
  showWebsiteIcons,
  onBack
}: DetailPlaceholderProps): React.JSX.Element {
  const TypeIcon = itemTypeMeta[item.type].icon

  return (
    <article className="detail-content detail-placeholder" aria-busy="true">
      <header className="detail-header">
        <TooltipIconButton
          variant="outline"
          size="icon"
          className="icon-button detail-back"
          type="button"
          label="返回項目列表"
          onClick={onBack}
        >
          <ArrowLeft />
        </TooltipIconButton>
        <span className={cn('detail-icon', item.type)} aria-hidden="true">
          {item.type === 'login' ? (
            <WebsiteIcon id={item.id} uri={item.uri} enabled={showWebsiteIcons} />
          ) : item.type === 'card' ? (
            <PaymentCardBrandMark
              brand={normalizeBitwardenCardBrand(item.cardBrand)}
              compact
            />
          ) : (
            <TypeIcon size={23} />
          )}
        </span>
        <div className="detail-heading">
          <p className="eyebrow">{itemTypeMeta[item.type].label}</p>
          <h2>{item.name}</h2>
          <span>
            {item.subtitle || (item.type === 'login' ? hostLabel(item.uri) : '安全保管的項目')}
          </span>
        </div>
        <Skeleton className="detail-placeholder-icon" aria-hidden="true" />
        <Skeleton className="detail-placeholder-button" aria-hidden="true" />
        <span className="sr-only" role="status">
          正在載入項目詳細資料…
        </span>
      </header>

      <div className="detail-scroll" aria-hidden="true">
        <Card className="detail-card detail-placeholder-card gap-0 py-0">
          <CardHeader className="bg-muted rounded-none border-b">
            <Skeleton className="h-3 w-20" />
          </CardHeader>
          <CardContent className="contents">
            {[0, 1, 2].map((row) => (
              <div className="detail-field" key={row}>
                <Skeleton className="h-3 w-16" />
                <Skeleton className={cn('h-4', row === 1 ? 'w-2/3' : 'w-1/2')} />
                <Skeleton className="size-8" />
              </div>
            ))}
          </CardContent>
        </Card>
        <Card className="detail-card detail-placeholder-card gap-0 py-0">
          <CardHeader className="bg-muted rounded-none border-b">
            <Skeleton className="h-3 w-24" />
          </CardHeader>
          <CardContent className="contents">
            {[0, 1].map((row) => (
              <div className="detail-field" key={row}>
                <Skeleton className="h-3 w-14" />
                <Skeleton className="h-4 w-1/3" />
                <span />
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </article>
  )
}

function VaultShell({ onLocked }: VaultShellProps): React.JSX.Element {
  const [folders, setFolders] = useState<FolderView[]>([])
  const [items, setItems] = useState<LoginSummary[]>([])
  const [scope, setScope] = useState<Scope>({ kind: 'all' })
  const [sortMode, setSortMode] = useState<SortMode>('title')
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('all')
  const [query, setQuery] = useState('')
  const [searchOpen, setSearchOpen] = useState(false)
  const [selectedIds, setSelectedIds] = useState<ReadonlySet<string>>(() => new Set())
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [selectedLogin, setSelectedLogin] = useState<LoginView | null>(null)
  const [totpCode, setTotpCode] = useState<TotpCodeView | null>(null)
  const [editorMode, setEditorMode] = useState<'create' | 'edit' | null>(null)
  const [editorSessionId, setEditorSessionId] = useState(0)
  const [editorDirty, setEditorDirty] = useState(false)
  const [discardEditorDialogOpen, setDiscardEditorDialogOpen] = useState(false)
  const [revealedSecrets, setRevealedSecrets] = useState<RevealedSecretsState>(emptyRevealedSecrets)
  const [revealedCustomFields, setRevealedCustomFields] =
    useState<RevealedCustomFieldsState>(emptyRevealedCustomFields)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [folderDialog, setFolderDialog] = useState<FolderView | 'new' | null>(null)
  const [moveDialogOpen, setMoveDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [syncDialogOpen, setSyncDialogOpen] = useState(false)
  const [syncStatus, setSyncStatus] = useState<SyncStatus>(initialSyncStatus)
  const SyncSidebarIcon = syncStateMeta[syncStatus.state].icon
  const [settings, setSettings] = useState<AppSettings | null>(null)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [settingsBusy, setSettingsBusy] = useState(false)
  const [touchIdPassword, setTouchIdPassword] = useState('')
  const [activeDragId, setActiveDragId] = useState<string | null>(null)
  const searchRef = useRef<HTMLInputElement>(null)
  const settingsReturnFocusRef = useRef<HTMLElement | null>(null)
  const compactReturnIdRef = useRef<string | null>(null)
  const compactDetailFocusIdRef = useRef<string | null>(null)
  const selectedIdRef = useRef<string | null>(null)
  const selectedIdsRef = useRef<ReadonlySet<string>>(new Set())
  const selectionAnchorIdRef = useRef<string | null>(null)
  const detailRequestsRef = useRef(new Map<string, Promise<LoginView>>())
  const detailCacheRef = useRef(new Map<string, LoginView>())
  const detailCacheGenerationRef = useRef(0)
  const editorDirtyRef = useRef(false)
  const editorTransitionApprovedRef = useRef(false)
  const pendingEditorActionRef = useRef<(() => void) | null>(null)

  const handleEditorDirtyChange = useCallback((dirty: boolean): void => {
    editorDirtyRef.current = dirty
    setEditorDirty(dirty)
  }, [])

  const requestEditorTransition = useCallback((action: () => void): void => {
    if (editorTransitionApprovedRef.current || !editorDirtyRef.current) {
      action()
      return
    }
    pendingEditorActionRef.current = action
    setDiscardEditorDialogOpen(true)
  }, [])

  const confirmEditorDiscard = useCallback((): void => {
    const action = pendingEditorActionRef.current
    pendingEditorActionRef.current = null
    setDiscardEditorDialogOpen(false)
    if (!action) return
    editorTransitionApprovedRef.current = true
    try {
      action()
    } finally {
      editorTransitionApprovedRef.current = false
    }
  }, [])

  const openEditor = useCallback(
    (mode: 'create' | 'edit'): void => {
      requestEditorTransition(() => {
        setEditorSessionId((current) => current + 1)
        setEditorMode(mode)
      })
    },
    [requestEditorTransition]
  )

  const updateSelectedIds = useCallback((nextIds: ReadonlySet<string>): void => {
    selectedIdsRef.current = nextIds
    setSelectedIds(nextIds)
  }, [])

  const clearItemSelection = useCallback((): void => {
    updateSelectedIds(new Set())
    selectionAnchorIdRef.current = null
    selectedIdRef.current = null
    setSelectedId(null)
    setSelectedLogin(null)
  }, [updateSelectedIds])

  const clearDetailCache = useCallback((): void => {
    detailCacheGenerationRef.current += 1
    detailRequestsRef.current.clear()
    detailCacheRef.current.clear()
  }, [])

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  )

  const loadVault = useCallback(async (): Promise<void> => {
    clearDetailCache()
    const generation = detailCacheGenerationRef.current
    try {
      toast.dismiss(vaultErrorToastId)
      const [folderList, loginList] = await Promise.all([
        window.bearwarden.folders.list(),
        window.bearwarden.logins.list({ sort: 'name' })
      ])
      if (detailCacheGenerationRef.current !== generation) return
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
      if (detailCacheGenerationRef.current === generation) {
        announceError(describeError(loadError))
      }
    } finally {
      if (detailCacheGenerationRef.current === generation) setLoading(false)
    }
  }, [clearDetailCache])

  const loadLoginDetail = useCallback((id: string): Promise<LoginView> => {
    const cached = detailCacheRef.current.get(id)
    if (cached) {
      detailCacheRef.current.delete(id)
      detailCacheRef.current.set(id, cached)
      return Promise.resolve(cached)
    }

    const pending = detailRequestsRef.current.get(id)
    if (pending) return pending

    const generation = detailCacheGenerationRef.current
    const promise = window.bearwarden.logins.get({ id })
    detailRequestsRef.current.set(id, promise)
    void promise
      .then((login) => {
        if (detailCacheGenerationRef.current !== generation) return
        cacheLoginDetail(detailCacheRef.current, login)
      })
      .catch(() => undefined)
      .finally(() => {
        if (detailRequestsRef.current.get(id) === promise) detailRequestsRef.current.delete(id)
      })
    return promise
  }, [])

  const prefetchLoginDetail = useCallback(
    (id: string): void => {
      if (selectedIdRef.current === id) return
      void loadLoginDetail(id).catch(() => {
        // Selection handles user-visible errors; speculative prefetch stays silent.
      })
    },
    [loadLoginDetail]
  )

  const activateLogin = useCallback(
    (id: string | null): void => {
      requestEditorTransition(() => {
        if (id) compactReturnIdRef.current = id
        selectedIdRef.current = id
        const cached = id ? detailCacheRef.current.get(id) : undefined
        if (cached) setSelectedLogin(cached)
        else if (!id) setSelectedLogin(null)
        setSelectedId(id)
        setRevealedSecrets(emptyRevealedSecrets)
        setRevealedCustomFields(emptyRevealedCustomFields)
        setEditorMode(null)
      })
    },
    [requestEditorTransition]
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
      void window.bearwarden.logins
        .showContextMenu({ id, ...position })
        .catch((menuError) => announceError(describeError(menuError)))
    },
    []
  )

  const refreshItems = useCallback(async (): Promise<void> => {
    const loginList = await window.bearwarden.logins.list({ sort: 'name' })
    const currentIds = new Set(loginList.map((login) => login.id))
    for (const cachedId of detailCacheRef.current.keys()) {
      if (!currentIds.has(cachedId)) detailCacheRef.current.delete(cachedId)
    }
    for (const summary of loginList) mergeCachedSummary(detailCacheRef.current, summary)
    setItems(loginList)
    setSelectedLogin((current) => {
      if (!current) return current
      const summary = loginList.find((item) => item.id === current.id)
      return summary ? { ...current, ...summary } : current
    })
  }, [])

  const refreshAfterSync = useCallback(async (): Promise<void> => {
    const applyRefresh = async (): Promise<void> => {
      await loadVault()
      setEditorMode(null)
      clearItemSelection()
      setRevealedSecrets(emptyRevealedSecrets)
      setRevealedCustomFields(emptyRevealedCustomFields)
    }
    if (editorDirtyRef.current) {
      requestEditorTransition(() => void applyRefresh())
      return
    }
    await applyRefresh()
  }, [clearItemSelection, loadVault, requestEditorTransition])

  useEffect(() => {
    queueMicrotask(() => void loadVault())
  }, [loadVault])

  useEffect(() => clearDetailCache, [clearDetailCache])

  useEffect(() => {
    selectedIdRef.current = selectedId
  }, [selectedId])

  useEffect(() => {
    const unsubscribe = window.bearwarden.vault.onChanged(() => {
      void loadVault()
    })
    return unsubscribe
  }, [loadVault])

  useEffect(() => {
    let active = true
    void window.bearwarden.sync.status().then(
      (status) => {
        if (active) setSyncStatus(status)
      },
      () => {
        // A missing sync service should not prevent the local vault from being usable.
      }
    )
    const unsubscribe = window.bearwarden.sync.onChanged((status) => {
      if (active) setSyncStatus(status)
    })
    return () => {
      active = false
      unsubscribe()
    }
  }, [])

  useEffect(() => {
    let active = true
    void window.bearwarden.settings.get().then(
      (nextSettings) => {
        if (!active) return
        setSettings(nextSettings)
        setSortMode(nextSettings.defaultSort === 'recent' ? 'recent' : 'title')
      },
      () => {
        // Settings must not prevent access to a successfully unlocked local vault.
      }
    )
    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    if (!settings) return
    const darkMode = window.matchMedia('(prefers-color-scheme: dark)')
    const applyTheme = (): void => {
      applyThemePreference(settings.theme, darkMode)
    }
    applyTheme()
    if (settings.theme === 'system') darkMode.addEventListener('change', applyTheme)
    return () => {
      darkMode.removeEventListener('change', applyTheme)
    }
  }, [settings])

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

    const detailRequest = loadLoginDetail(selectedId)
    detailRequest
      .then((login) => {
        if (!active) return
        setSelectedLogin(login)
      })
      .catch((detailError) => {
        if (!active) return
        announceError(describeError(detailError))
        clearItemSelection()
      })
    return () => {
      active = false
    }
  }, [clearItemSelection, loadLoginDetail, selectedId])

  useEffect(() => {
    let active = true
    const login = selectedLogin
    if (!login?.hasTotp || login.id !== selectedId || editorMode) {
      queueMicrotask(() => {
        if (active) setTotpCode(null)
      })
      return () => {
        active = false
      }
    }

    const refresh = (): void => {
      window.bearwarden.logins.getTotp({ id: login.id }).then(
        (nextCode) => {
          if (active) setTotpCode(nextCode)
        },
        (totpError) => {
          if (active) announceError(describeError(totpError))
        }
      )
    }
    refresh()
    const timer = window.setInterval(refresh, 1_000)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [editorMode, selectedId, selectedLogin])

  useEffect(() => {
    if (Object.keys(revealedSecrets.values).length === 0) return
    const timeout = window.setTimeout(() => setRevealedSecrets(emptyRevealedSecrets), 30_000)
    return () => window.clearTimeout(timeout)
  }, [revealedSecrets])

  useEffect(() => {
    if (Object.keys(revealedCustomFields.values).length === 0) return
    const timeout = window.setTimeout(
      () => setRevealedCustomFields(emptyRevealedCustomFields),
      30_000
    )
    return () => window.clearTimeout(timeout)
  }, [revealedCustomFields])

  const scopedItems = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase('zh-Hant')
    const scoped = items.filter((item) => {
      if (scope.kind === 'favorites' && !item.favorite) return false
      if (scope.kind === 'recent' && !item.lastUsedAt) return false
      if (scope.kind === 'folder' && item.folderId !== scope.folderId) return false
      if (scope.kind === 'unfiled' && item.folderId !== null) return false
      if (!matchesVaultCategory(item, typeFilter)) return false
      if (!normalizedQuery) return true
      return [
        item.name,
        item.subtitle,
        item.username,
        item.uri ?? '',
        itemTypeMeta[item.type].label
      ].some((value) => value.toLocaleLowerCase('zh-Hant').includes(normalizedQuery))
    })
    return sortItems(scoped, scope.kind === 'recent' ? 'recent' : sortMode)
  }, [items, query, scope, sortMode, typeFilter])
  const scopedItemIds = useMemo(() => scopedItems.map((item) => item.id), [scopedItems])

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
        queueMicrotask(() => document.querySelector<HTMLButtonElement>('.detail-back')?.focus())
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
        row?.querySelector<HTMLButtonElement>('.item-row-main')?.focus()
      })
    }
  }, [selectedId, selectedLogin])

  const selectedSummary = items.find((item) => item.id === selectedId) ?? null
  const selectedSummaries = useMemo(
    () => items.filter((item) => selectedIds.has(item.id)),
    [items, selectedIds]
  )
  const selectedFolderId = useMemo(() => {
    const firstFolderId = selectedSummaries[0]?.folderId
    if (firstFolderId === undefined) return undefined
    return selectedSummaries.every((item) => item.folderId === firstFolderId)
      ? firstFolderId
      : undefined
  }, [selectedSummaries])
  const activeDragItem = activeDragId
    ? (items.find((item) => item.id === activeDragId) ?? null)
    : null
  const activeDragFolder = activeDragId
    ? (folders.find((folder) => folder.id === activeDragId) ?? null)
    : null
  const activeDragItemCount =
    activeDragItem && selectedIds.has(activeDragItem.id) ? selectedIds.size : 1
  const selectedDetailFields = useMemo(
    () => (selectedLogin ? detailFields(selectedLogin) : []),
    [selectedLogin]
  )
  const itemGroups = useMemo(() => {
    const effectiveSort = scope.kind === 'recent' ? 'recent' : sortMode
    if (effectiveSort === 'title') {
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
  const itemIds = useMemo(() => new Set(items.map((item) => item.id)), [items])
  const folderCounts = useMemo(() => {
    const counts = new Map<string | null, number>()
    for (const item of items) counts.set(item.folderId, (counts.get(item.folderId) ?? 0) + 1)
    return counts
  }, [items])
  const categoryCounts = useMemo(() => {
    const counts = new Map<TypeFilter, number>()
    for (const category of categoryMeta) {
      counts.set(
        category.id,
        items.filter((item) => matchesVaultCategory(item, category.id)).length
      )
    }
    return counts
  }, [items])

  const scopeTitle = useMemo(() => {
    if (scope.kind === 'favorites') return '常用項目'
    if (scope.kind === 'recent') return '最近使用'
    if (scope.kind === 'unfiled') return '未分類'
    if (scope.kind === 'folder')
      return folders.find((folder) => folder.id === scope.folderId)?.name ?? '資料夾'
    if (typeFilter === 'totp') return '驗證碼'
    if (typeFilter === 'passkey') return '通行密鑰'
    if (typeFilter !== 'all') return itemTypeMeta[typeFilter].label
    return '所有項目'
  }, [folders, scope, typeFilter])

  const announce = useCallback((message: string): void => {
    toast.success(message)
  }, [])

  const performLockVault = useCallback(async (): Promise<void> => {
    clearDetailCache()
    setRevealedSecrets(emptyRevealedSecrets)
    setRevealedCustomFields(emptyRevealedCustomFields)
    setTouchIdPassword('')
    setSelectedLogin(null)
    try {
      const status = await window.bearwarden.vault.lock()
      if (status.state === 'locked') onLocked()
      else announceError('保管庫尚未鎖定，請再試一次。')
    } catch (lockError) {
      announceError(describeError(lockError))
    }
  }, [clearDetailCache, onLocked])

  const lockVault = useCallback(async (): Promise<void> => {
    if (editorDirtyRef.current) {
      requestEditorTransition(() => void performLockVault())
      return
    }
    await performLockVault()
  }, [performLockVault, requestEditorTransition])

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
      if (
        key === 'a' &&
        !settingsOpen &&
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
      if (key === 'f' && !settingsOpen) {
        event.preventDefault()
        setSearchOpen(true)
      }
      if (key === 'n' && !editorMode) {
        event.preventDefault()
        openEditor('create')
      }
      if (key === 'e' && selectedLogin && !editorMode) {
        event.preventDefault()
        openEditor('edit')
      }
      if (key === 's' && editorMode && !busy) {
        event.preventDefault()
        document.querySelector<HTMLFormElement>('form.editor')?.requestSubmit()
      }
      if (key === 'm' && event.shiftKey && selectedSummary) {
        event.preventDefault()
        setMoveDialogOpen(true)
      }
    }
    window.addEventListener('keydown', handleShortcut)
    return () => window.removeEventListener('keydown', handleShortcut)
  }, [
    activateLogin,
    busy,
    editorMode,
    openEditor,
    scopedItemIds,
    searchOpen,
    selectedLogin,
    selectedSummary,
    settingsOpen,
    updateSelectedIds
  ])

  useEffect(() => {
    if (!searchOpen) return
    queueMicrotask(() => {
      searchRef.current?.focus()
      searchRef.current?.select()
    })
  }, [searchOpen])

  useEffect(() => {
    if (settingsOpen || !settingsReturnFocusRef.current?.isConnected) return
    queueMicrotask(() => settingsReturnFocusRef.current?.focus())
  }, [settingsOpen])

  function selectScope(nextScope: Scope): void {
    requestEditorTransition(() => {
      setScope(nextScope)
      setTypeFilter('all')
      setSidebarOpen(false)
      setSettingsOpen(false)
      setTouchIdPassword('')
      setEditorMode(null)
      setMoveDialogOpen(false)
    })
  }

  function selectType(type: TypeFilter): void {
    requestEditorTransition(() => {
      setScope({ kind: 'all' })
      setTypeFilter(type)
      setSidebarOpen(false)
      setSettingsOpen(false)
      setTouchIdPassword('')
      setEditorMode(null)
      setMoveDialogOpen(false)
    })
  }

  function openSettings(): void {
    requestEditorTransition(() => {
      settingsReturnFocusRef.current =
        document.activeElement instanceof HTMLElement ? document.activeElement : null
      setSettingsOpen(true)
      setSidebarOpen(false)
      setEditorMode(null)
      setMoveDialogOpen(false)
      clearItemSelection()
      setRevealedSecrets(emptyRevealedSecrets)
      setRevealedCustomFields(emptyRevealedCustomFields)
    })
  }

  function closeSettings(): void {
    setSettingsOpen(false)
    setTouchIdPassword('')
  }

  async function updateSettings(update: AppSettingsUpdate): Promise<void> {
    setSettingsBusy(true)
    try {
      const next = await window.bearwarden.settings.update(update)
      setSettings(next)
      if (update.defaultSort) setSortMode(update.defaultSort === 'recent' ? 'recent' : 'title')
      announce('設定已儲存。')
    } catch (settingsError) {
      announceError(describeError(settingsError))
    } finally {
      setSettingsBusy(false)
    }
  }

  async function enableTouchId(): Promise<void> {
    if (!touchIdPassword) {
      announceError('請先輸入主密碼以啟用 Touch ID。')
      return
    }
    setSettingsBusy(true)
    try {
      const next = await window.bearwarden.settings.enableTouchId({
        masterPassword: touchIdPassword
      })
      setSettings(next)
      setTouchIdPassword('')
      announce('Touch ID 已啟用。')
    } catch (touchIdError) {
      announceError(describeError(touchIdError))
    } finally {
      setSettingsBusy(false)
    }
  }

  async function disableTouchId(): Promise<void> {
    setSettingsBusy(true)
    try {
      const next = await window.bearwarden.settings.disableTouchId()
      setSettings(next)
      announce('Touch ID 已停用。')
    } catch (touchIdError) {
      announceError(describeError(touchIdError))
    } finally {
      setSettingsBusy(false)
    }
  }

  const toggleFavorite = useCallback(
    async (item: LoginSummary): Promise<void> => {
      try {
        const updated = await window.bearwarden.logins.setFavorite({
          id: item.id,
          favorite: !item.favorite
        })
        mergeCachedSummary(detailCacheRef.current, updated)
        setItems((current) => current.map((entry) => (entry.id === updated.id ? updated : entry)))
        setSelectedLogin((current) =>
          current?.id === updated.id ? { ...current, ...updated } : current
        )
        announce(updated.favorite ? '已加入常用項目。' : '已從常用項目移除。')
      } catch (favoriteError) {
        announceError(describeError(favoriteError))
      }
    },
    [announce]
  )

  async function moveLogins(ids: readonly string[], folderId: string | null): Promise<void> {
    const idSet = new Set(ids)
    const previous = items.filter((item) => idSet.has(item.id))
    const movable = previous.filter((item) => item.folderId !== folderId)
    if (movable.length === 0) {
      setMoveDialogOpen(false)
      return
    }
    if (movable.length > MAX_LOGIN_MOVE_MANY_IDS) {
      announceError(`一次最多可移動 ${MAX_LOGIN_MOVE_MANY_IDS} 個項目。`)
      return
    }
    const movableIds = new Set(movable.map((item) => item.id))
    setBusy(true)
    for (const item of movable) mergeCachedSummary(detailCacheRef.current, { ...item, folderId })
    setItems((current) =>
      current.map((item) => (movableIds.has(item.id) ? { ...item, folderId } : item))
    )
    try {
      const updated = await window.bearwarden.logins.moveMany({
        ids: movable.map((item) => item.id),
        folderId
      })
      const updatedById = new Map(updated.map((item) => [item.id, item]))
      for (const item of updated) mergeCachedSummary(detailCacheRef.current, item)
      setItems((current) => current.map((item) => updatedById.get(item.id) ?? item))
      setSelectedLogin((current) => {
        if (!current) return current
        const summary = updatedById.get(current.id)
        return summary ? { ...current, ...summary } : current
      })
      const destination = folders.find((folder) => folder.id === folderId)?.name ?? '未分類'
      announce(
        updated.length > 1
          ? `已將 ${updated.length} 個項目移至「${destination}」。`
          : `已移至「${destination}」。`
      )
      setMoveDialogOpen(false)
    } catch (moveError) {
      const previousById = new Map(previous.map((item) => [item.id, item]))
      for (const item of previous) mergeCachedSummary(detailCacheRef.current, item)
      setItems((current) => current.map((item) => previousById.get(item.id) ?? item))
      announceError(describeError(moveError))
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
        announce(`已建立資料夾「${created.name}」。`)
      } else if (folderDialog) {
        const updated = await window.bearwarden.folders.update({ id: folderDialog.id, name })
        setFolders((current) =>
          current.map((folder) => (folder.id === updated.id ? updated : folder))
        )
        announce(`已重新命名為「${updated.name}」。`)
      }
      setFolderDialog(null)
    } catch (folderError) {
      announceError(describeError(folderError))
    } finally {
      setBusy(false)
    }
  }

  async function deleteFolder(): Promise<void> {
    if (!folderDialog || folderDialog === 'new') return
    setBusy(true)
    try {
      await window.bearwarden.folders.delete({ id: folderDialog.id })
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
      announce(`已刪除資料夾「${folderDialog.name}」，其中項目已移至未分類。`)
      setFolderDialog(null)
    } catch (folderError) {
      announceError(describeError(folderError))
    } finally {
      setBusy(false)
    }
  }

  async function saveLogin(draft: LoginDraft): Promise<void> {
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
        const created = await window.bearwarden.logins.create({
          type: draft.type,
          name: draft.name,
          ...fields,
          notes: draft.notes || null,
          folderId: draft.folderId,
          favorite: draft.favorite,
          customFields
        })
        cacheLoginDetail(detailCacheRef.current, created)
        setItems((current) => [...current, toLoginSummary(created)])
        setScope({ kind: 'all' })
        updateSelectedIds(new Set([created.id]))
        selectionAnchorIdRef.current = created.id
        selectedIdRef.current = created.id
        setSelectedId(created.id)
        setSelectedLogin(created)
        announce(`已建立「${created.name}」。`)
      } else if (selectedLogin) {
        const updated = await window.bearwarden.logins.update({
          id: selectedLogin.id,
          expectedUpdatedAt: draft.expectedUpdatedAt ?? undefined,
          name: draft.name,
          ...fields,
          notes: draft.notes || null,
          folderId: draft.folderId,
          favorite: draft.favorite,
          customFields
        })
        cacheLoginDetail(detailCacheRef.current, updated)
        setItems((current) =>
          current.map((item) => (item.id === updated.id ? toLoginSummary(updated) : item))
        )
        setSelectedLogin(updated)
        announce(`已儲存「${updated.name}」。`)
      }
      setRevealedCustomFields(emptyRevealedCustomFields)
      editorDirtyRef.current = false
      setEditorDirty(false)
      setEditorMode(null)
    } catch (saveError) {
      announceError(describeError(saveError))
    } finally {
      setBusy(false)
    }
  }

  async function deleteLogin(): Promise<void> {
    if (!selectedSummary) return
    setBusy(true)
    try {
      await window.bearwarden.logins.delete({ id: selectedSummary.id })
      detailCacheRef.current.delete(selectedSummary.id)
      setItems((current) => current.filter((item) => item.id !== selectedSummary.id))
      clearItemSelection()
      setDeleteDialogOpen(false)
      announce('項目已永久刪除。')
    } catch (deleteError) {
      announceError(describeError(deleteError))
    } finally {
      setBusy(false)
    }
  }

  async function revealSecret(field: VaultSecretField): Promise<void> {
    if (!selectedSummary) return
    const itemId = selectedSummary.id
    const revealedValue =
      revealedSecrets.itemId === itemId ? revealedSecrets.values[field] : undefined
    if (revealedValue !== undefined) {
      setRevealedSecrets((current) => {
        if (current.itemId !== itemId) return current
        const next = { ...current.values }
        delete next[field]
        return Object.keys(next).length ? { itemId, values: next } : emptyRevealedSecrets
      })
      return
    }
    try {
      const value = await window.bearwarden.logins.revealSecret({ id: itemId, field })
      if (selectedIdRef.current !== itemId) return
      setRevealedSecrets((current) => ({
        itemId,
        values: {
          ...(current.itemId === itemId ? current.values : {}),
          [field]: value
        }
      }))
      announce(`${field === 'privateKey' ? '私鑰' : '敏感資料'}已顯示，將在 30 秒後自動隱藏。`)
    } catch (revealError) {
      announceError(describeError(revealError))
    }
  }

  async function copyField(field: VaultCopyField): Promise<void> {
    if (!selectedSummary) return
    try {
      await window.bearwarden.logins.copyField({ id: selectedSummary.id, field })
      announce('欄位已複製。')
      await refreshItems()
    } catch (copyError) {
      announceError(describeError(copyError))
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
      const value = await window.bearwarden.logins.revealCustomField({
        id: itemId,
        expectedUpdatedAt,
        source
      })
      if (selectedIdRef.current !== itemId) return
      setRevealedCustomFields((current) => ({
        itemId,
        values: {
          ...(current.itemId === itemId ? current.values : {}),
          [index]: { value, source, expectedUpdatedAt }
        }
      }))
      announce('隱藏欄位已顯示，將在 30 秒後自動隱藏。')
    } catch (revealError) {
      announceError(describeError(revealError))
    }
  }

  async function copyCustomField(index: number, field: VaultCustomFieldView): Promise<void> {
    if (!selectedLogin) return
    try {
      await window.bearwarden.logins.copyCustomField({
        id: selectedLogin.id,
        expectedUpdatedAt: selectedLogin.updatedAt,
        source: { index, name: field.name, type: field.type, linkedId: field.linkedId }
      })
      announce('自訂欄位已複製。')
      await refreshItems()
    } catch (copyError) {
      announceError(describeError(copyError))
    }
  }

  async function copyTotp(): Promise<void> {
    if (!selectedLogin?.hasTotp) return
    try {
      await window.bearwarden.logins.copyTotp({ id: selectedLogin.id })
      announce('驗證碼已複製，剪貼簿會依安全設定自動清除。')
      await refreshItems()
    } catch (copyError) {
      announceError(describeError(copyError))
    }
  }

  async function openWebsite(): Promise<void> {
    if (!selectedSummary?.uri) return
    try {
      await window.bearwarden.logins.openUri({ id: selectedSummary.id })
      announce('已在預設瀏覽器開啟網站。')
      await refreshItems()
    } catch (openError) {
      announceError(describeError(openError))
    }
  }

  function startDrag(event: DragStartEvent): void {
    const activeId = String(event.active.id)
    if (itemIds.has(activeId) && !selectedIdsRef.current.has(activeId)) selectLogin(activeId)
    setActiveDragId(activeId)
  }

  async function endDrag(event: DragEndEvent): Promise<void> {
    setActiveDragId(null)
    if (!event.over) return
    const activeId = String(event.active.id)
    const overId = String(event.over.id)
    if (itemIds.has(activeId)) {
      const draggedIds = selectedIdsRef.current.has(activeId)
        ? [...selectedIdsRef.current]
        : [activeId]
      if (overId === 'folder:none') await moveLogins(draggedIds, null)
      else if (folderIds.has(overId)) await moveLogins(draggedIds, overId)
      return
    }
    if (!folderIds.has(activeId) || !folderIds.has(overId) || activeId === overId) return
    const previous = folders
    const oldIndex = previous.findIndex((folder) => folder.id === activeId)
    const newIndex = previous.findIndex((folder) => folder.id === overId)
    const reordered = arrayMove(previous, oldIndex, newIndex).map((folder, position) => ({
      ...folder,
      position
    }))
    setFolders(reordered)
    try {
      const saved = await window.bearwarden.folders.reorder({
        orderedIds: reordered.map((folder) => folder.id)
      })
      setFolders([...saved].sort((left, right) => left.position - right.position))
      announce('資料夾順序已更新。')
    } catch (reorderError) {
      setFolders(previous)
      announceError(describeError(reorderError))
    }
  }

  function renderDetailField(field: DetailField): React.JSX.Element {
    const secretField = field.field as VaultSecretField
    const revealedValue =
      field.secret && revealedSecrets.itemId === selectedLogin?.id
        ? revealedSecrets.values[secretField]
        : undefined
    const hasExtraAction = Boolean(field.copyable) && Boolean(field.openUri)
    return (
      <div
        className={cn(
          'detail-field',
          field.secret && 'password-field',
          hasExtraAction && 'multi-action'
        )}
        key={`${field.label}:${field.field}`}
      >
        <span>{field.label}</span>
        <strong
          className={
            field.secret
              ? revealedValue === undefined
                ? 'masked-value'
                : 'revealed-value'
              : undefined
          }
        >
          {field.secret
            ? revealedValue === undefined
              ? '••••••••••••'
              : field.field === 'number'
                ? formatPaymentCardNumber(revealedValue) || '未設定'
                : revealedValue || '未設定'
            : field.value || '未設定'}
        </strong>
        {field.secret ? (
          <>
            <TooltipIconButton
              variant="outline"
              size="icon"
              className="icon-button"
              type="button"
              label={revealedValue === undefined ? `顯示${field.label}` : `隱藏${field.label}`}
              aria-pressed={revealedValue !== undefined}
              onClick={() => void revealSecret(secretField)}
            >
              {revealedValue === undefined ? <Eye /> : <EyeOff />}
            </TooltipIconButton>
            <TooltipIconButton
              variant="outline"
              size="icon"
              className="icon-button"
              type="button"
              label={`複製${field.label}`}
              onClick={() => void copyField(field.field)}
            >
              <Clipboard />
            </TooltipIconButton>
          </>
        ) : (
          <>
            {field.copyable && (
              <TooltipIconButton
                variant="outline"
                size="icon"
                className="icon-button"
                type="button"
                label={`複製${field.label}`}
                disabled={!field.value}
                onClick={() => void copyField(field.field)}
              >
                <Copy />
              </TooltipIconButton>
            )}
            {field.openUri && (
              <TooltipIconButton
                variant="outline"
                size="icon"
                className="icon-button"
                type="button"
                label="在預設瀏覽器開啟網站"
                disabled={!field.value}
                onClick={() => void openWebsite()}
              >
                <ArrowUpRight />
              </TooltipIconButton>
            )}
          </>
        )}
      </div>
    )
  }

  function renderCustomField(field: VaultCustomFieldView, index: number): React.JSX.Element {
    const revealedEntry =
      revealedCustomFields.itemId === selectedLogin?.id
        ? revealedCustomFields.values[index]
        : undefined
    const revealedValue =
      revealedEntry &&
      revealedEntry.expectedUpdatedAt === selectedLogin?.updatedAt &&
      matchesCustomFieldSource(field, index, revealedEntry.source)
        ? revealedEntry.value
        : undefined
    const hidden = field.type === 'hidden'
    const label = field.name || '未命名欄位'
    return (
      <div
        className={cn('detail-field', hidden && 'password-field', hidden && 'multi-action')}
        key={`${index}:${field.name}:${field.type}`}
      >
        <span>{label}</span>
        <strong
          className={
            hidden ? (revealedValue === undefined ? 'masked-value' : 'revealed-value') : undefined
          }
        >
          {hidden
            ? revealedValue === undefined
              ? '••••••••••••'
              : revealedValue || '未設定'
            : customFieldDisplayValue(field)}
        </strong>
        {hidden && (
          <TooltipIconButton
            variant="outline"
            size="icon"
            className="icon-button"
            type="button"
            label={revealedValue === undefined ? `顯示${label}` : `隱藏${label}`}
            aria-pressed={revealedValue !== undefined}
            onClick={() => void revealCustomField(index, field)}
          >
            {revealedValue === undefined ? <Eye /> : <EyeOff />}
          </TooltipIconButton>
        )}
        <TooltipIconButton
          variant="outline"
          size="icon"
          className="icon-button"
          type="button"
          label={`複製${label}`}
          disabled={field.type !== 'linked' && !field.value && !hidden}
          onClick={() => void copyCustomField(index, field)}
        >
          <Copy />
        </TooltipIconButton>
      </div>
    )
  }

  if (loading) {
    return (
      <main className="vault-loading" role="status">
        <BrandMark />
        <Spinner className="size-6" aria-hidden="true" />
        <p>正在解密你的項目…</p>
      </main>
    )
  }

  return (
    <DndContext
      sensors={sensors}
      collisionDetection={closestCenter}
      onDragStart={startDrag}
      onDragCancel={() => setActiveDragId(null)}
      onDragEnd={(event) => void endDrag(event)}
    >
      <main
        className={cn(
          'app-shell',
          isMac && 'platform-macos',
          (selectedId || editorMode) && 'has-detail'
        )}
      >
        <header className="titlebar">
          {!settingsOpen && (
            <TooltipIconButton
              variant="outline"
              size="icon"
              className="icon-button titlebar-menu"
              type="button"
              label={sidebarOpen ? '關閉側邊欄' : '開啟側邊欄'}
              aria-expanded={sidebarOpen}
              onClick={() => setSidebarOpen((open) => !open)}
            >
              {sidebarOpen ? <X /> : <Menu />}
            </TooltipIconButton>
          )}
          <BrandMark />
          {!settingsOpen && (
            <InputGroup className="search-field titlebar-search">
              <Button
                variant="ghost"
                className="titlebar-search-trigger"
                type="button"
                aria-label={query ? `搜尋保管庫項目，目前為 ${query}` : '搜尋保管庫項目'}
                aria-haspopup="dialog"
                aria-expanded={searchOpen}
                onClick={() => setSearchOpen(true)}
              >
                <span className={cn('truncate', !query && 'text-muted-foreground')}>
                  {query || '搜尋名稱、摘要或網站'}
                </span>
              </Button>
              <InputGroupAddon align="inline-start">
                <Search aria-hidden="true" />
              </InputGroupAddon>
              {query && (
                <InputGroupAddon align="inline-end">
                  <InputGroupButton
                    size="icon-xs"
                    type="button"
                    aria-label="清除搜尋"
                    onClick={() => setQuery('')}
                  >
                    <X />
                  </InputGroupButton>
                </InputGroupAddon>
              )}
              <InputGroupAddon align="inline-end">
                <Kbd>{commandLabel} F</Kbd>
              </InputGroupAddon>
            </InputGroup>
          )}
          <div className="titlebar-drag" aria-hidden="true" />
          {!settingsOpen && (
            <TooltipIconButton
              variant="outline"
              size="icon"
              className="icon-button titlebar-add-button"
              type="button"
              label="新增項目"
              onClick={() => openEditor('create')}
            >
              <Plus aria-hidden="true" />
            </TooltipIconButton>
          )}
        </header>

        <CommandDialog
          open={searchOpen}
          onOpenChange={setSearchOpen}
          title="搜尋保管庫"
          description="依名稱、摘要、使用者名稱或網站搜尋保管庫項目。"
        >
          <Command className="vault-command" label="搜尋保管庫項目" loop shouldFilter={false}>
            <CommandInput
              ref={searchRef}
              placeholder="搜尋名稱、摘要或網站"
              value={query}
              onValueChange={setQuery}
              endAdornment={
                query ? (
                  <InputGroupAddon align="inline-end">
                    <InputGroupButton
                      size="icon-xs"
                      type="button"
                      aria-label="清除搜尋"
                      onClick={() => {
                        setQuery('')
                        window.requestAnimationFrame(() => searchRef.current?.focus())
                      }}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' || event.key === ' ') event.stopPropagation()
                      }}
                    >
                      <X />
                    </InputGroupButton>
                  </InputGroupAddon>
                ) : undefined
              }
            />
            <CommandList className="vault-command-list">
              <CommandEmpty>找不到符合的保管庫項目</CommandEmpty>
              {scopedItems.length > 0 && (
                <CommandGroup heading={`${scopeTitle} · ${scopedItems.length} 個項目`}>
                  {scopedItems.map((item) => {
                    const ItemIcon = itemTypeMeta[item.type].icon
                    return (
                      <CommandItem
                        key={item.id}
                        value={item.id}
                        onSelect={() => {
                          selectLogin(item.id)
                          setSearchOpen(false)
                        }}
                      >
                        <span className="command-result-icon" aria-hidden="true">
                          <ItemIcon />
                        </span>
                        <span className="command-result-copy">
                          <strong className="block truncate">{item.name}</strong>
                          <small className="block truncate">
                            {item.subtitle || item.username || item.uri || '尚未設定摘要'}
                          </small>
                        </span>
                        <span className="command-result-type">{itemTypeMeta[item.type].label}</span>
                      </CommandItem>
                    )
                  })}
                </CommandGroup>
              )}
            </CommandList>
          </Command>
        </CommandDialog>

        <div className={cn('workspace', settingsOpen && 'settings-mode')}>
          {sidebarOpen && (
            <Button
              variant="ghost"
              className="sidebar-scrim"
              type="button"
              aria-label="關閉側邊欄"
              onClick={() => setSidebarOpen(false)}
            />
          )}
          <aside className={cn('sidebar', sidebarOpen && 'open')} aria-label="保管庫導覽">
            <div className="sidebar-scroll">
              <section
                className="folder-section category-section"
                aria-labelledby="categories-title"
              >
                <header>
                  <h2 id="categories-title">分類</h2>
                </header>
                <nav className="sidebar-nav sidebar-category-grid" aria-label="保管庫分類">
                  {categoryMeta.map((category) => {
                    const Icon = category.icon
                    return (
                      <SidebarLink
                        key={category.id}
                        icon={<Icon size={17} />}
                        label={category.label}
                        count={categoryCounts.get(category.id) ?? 0}
                        active={scope.kind === 'all' && typeFilter === category.id}
                        variant="tile"
                        tone={category.tone}
                        onClick={() => selectType(category.id)}
                      />
                    )
                  })}
                </nav>
              </section>

              <section className="folder-section quick-section" aria-labelledby="quick-title">
                <header>
                  <h2 id="quick-title">快速取用</h2>
                </header>
                <nav className="sidebar-nav" aria-label="快速取用">
                  <SidebarLink
                    icon={<Star size={16} />}
                    label="常用項目"
                    count={items.filter((item) => item.favorite).length}
                    active={scope.kind === 'favorites'}
                    onClick={() => selectScope({ kind: 'favorites' })}
                  />
                  <SidebarLink
                    icon={<Clock3 size={16} />}
                    label="最近使用"
                    count={items.filter((item) => item.lastUsedAt).length}
                    active={scope.kind === 'recent'}
                    onClick={() => selectScope({ kind: 'recent' })}
                  />
                </nav>
              </section>

              <section className="folder-section" aria-labelledby="folders-title">
                <header>
                  <h2 id="folders-title">資料夾</h2>
                  <TooltipIconButton
                    variant="ghost"
                    size="icon"
                    className="icon-button subtle"
                    type="button"
                    label="新增資料夾"
                    onClick={() => setFolderDialog('new')}
                  >
                    <Plus aria-hidden="true" />
                  </TooltipIconButton>
                </header>
                <ul className="folder-list">
                  <UnfiledRow
                    selected={scope.kind === 'unfiled'}
                    count={folderCounts.get(null) ?? 0}
                    onSelect={() => selectScope({ kind: 'unfiled' })}
                  />
                  <SortableContext
                    items={folders.map((folder) => folder.id)}
                    strategy={verticalListSortingStrategy}
                  >
                    {folders.map((folder) => (
                      <FolderRow
                        key={folder.id}
                        folder={folder}
                        count={folderCounts.get(folder.id) ?? 0}
                        selected={scope.kind === 'folder' && scope.folderId === folder.id}
                        onSelect={() => selectScope({ kind: 'folder', folderId: folder.id })}
                        onEdit={() => setFolderDialog(folder)}
                      />
                    ))}
                  </SortableContext>
                </ul>
              </section>
            </div>

            <footer className="sidebar-footer">
              <Button
                variant="ghost"
                className={cn('sidebar-settings-control', settingsOpen && 'active')}
                type="button"
                onClick={openSettings}
                aria-current={settingsOpen ? 'page' : undefined}
              >
                <Settings2 data-icon="inline-start" aria-hidden="true" />
                設定
              </Button>
              <TooltipIconButton
                variant="ghost"
                size="icon"
                className={cn('sync-sidebar-control', syncStatus.state)}
                type="button"
                label={`開啟 Bitwarden 同步：${syncStateMeta[syncStatus.state].label}`}
                onClick={() => setSyncDialogOpen(true)}
              >
                <SyncSidebarIcon aria-hidden="true" />
              </TooltipIconButton>
            </footer>
          </aside>

          <section
            className="list-pane"
            aria-labelledby={settingsOpen ? 'settings-title' : 'list-title'}
          >
            {settingsOpen ? (
              <SettingsPage
                settings={settings}
                settingsBusy={settingsBusy}
                syncStatus={syncStatus}
                touchIdPassword={touchIdPassword}
                onBack={closeSettings}
                onUpdate={updateSettings}
                onTouchIdPasswordChange={setTouchIdPassword}
                onEnableTouchId={enableTouchId}
                onDisableTouchId={disableTouchId}
                onOpenSync={() => setSyncDialogOpen(true)}
              />
            ) : (
              <>
                <header className="list-header">
                  <div className="list-heading">
                    <h1 id="list-title">{scopeTitle}</h1>
                    <small>
                      {selectedIds.size > 1
                        ? `已選取 ${selectedIds.size} 個 · 共 ${scopedItems.length} 個項目`
                        : `${scopedItems.length} 個項目`}
                    </small>
                  </div>
                  <div className="list-header-actions">
                    <div className="sort-control">
                      <ListFilter size={16} aria-hidden="true" />
                      <Select
                        items={sortItemsOptions}
                        value={sortMode}
                        disabled={scope.kind === 'recent'}
                        onValueChange={(value) => setSortMode(value as SortMode)}
                      >
                        <SelectTrigger
                          size="sm"
                          className="border-0 bg-transparent shadow-none"
                          aria-label="排序方式"
                        >
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            {sortItemsOptions.map((item) => (
                              <SelectItem key={item.value} value={item.value}>
                                {item.label}
                              </SelectItem>
                            ))}
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                </header>
                {query && (
                  <div className="result-summary" role="status">
                    <span>搜尋「{query}」</span>
                    <span>{scopedItems.length} 筆結果</span>
                  </div>
                )}

                {scopedItems.length ? (
                  <VirtualizedItemList
                    groups={itemGroups}
                    scopeTitle={scopeTitle}
                    selectedIds={selectedIds}
                    onPrefetch={prefetchLoginDetail}
                    onSelect={selectItems}
                    onFavorite={toggleFavorite}
                    onContextMenu={showLoginContextMenu}
                    showWebsiteIcons={settings?.showWebsiteIcons ?? false}
                  />
                ) : (
                  <Empty className="empty-state">
                    <EmptyHeader>
                      <EmptyMedia variant="icon">{query ? <Search /> : <KeyRound />}</EmptyMedia>
                      <EmptyTitle>{query ? '找不到符合的項目' : '這裡還沒有保管庫項目'}</EmptyTitle>
                      <EmptyDescription>
                        {query
                          ? '試試較短的關鍵字，或切換到所有項目。'
                          : '新增第一筆資料，BearWarden 會安全地替你保管。'}
                      </EmptyDescription>
                    </EmptyHeader>
                    <EmptyContent>
                      {query ? (
                        <Button
                          variant="outline"
                          className="button secondary"
                          type="button"
                          onClick={() => setQuery('')}
                        >
                          清除搜尋
                        </Button>
                      ) : (
                        <Button
                          className="button primary"
                          type="button"
                          onClick={() => openEditor('create')}
                        >
                          <Plus data-icon="inline-start" />
                          新增項目
                        </Button>
                      )}
                    </EmptyContent>
                  </Empty>
                )}
              </>
            )}
          </section>

          <section className="detail-pane" aria-label="項目詳細資料">
            {editorMode ? (
              <LoginEditor
                key={`${editorSessionId}:${editorMode}:${selectedLogin?.id ?? 'new'}`}
                login={editorMode === 'edit' ? (selectedLogin ?? undefined) : undefined}
                folders={folders}
                busy={busy}
                onCancel={() => requestEditorTransition(() => setEditorMode(null))}
                onDirtyChange={handleEditorDirtyChange}
                onSave={saveLogin}
              />
            ) : selectedId && selectedSummary && selectedLogin?.id !== selectedId ? (
              <DetailPlaceholder
                item={selectedSummary}
                showWebsiteIcons={settings?.showWebsiteIcons ?? false}
                onBack={clearItemSelection}
              />
            ) : selectedLogin && selectedLogin.id === selectedId ? (
              <article className="detail-content">
                <header className="detail-header">
                  <TooltipIconButton
                    variant="outline"
                    size="icon"
                    className="icon-button detail-back"
                    type="button"
                    label="返回項目列表"
                    onClick={clearItemSelection}
                  >
                    <ArrowLeft />
                  </TooltipIconButton>
                  <span className={cn('detail-icon', selectedLogin.type)} aria-hidden="true">
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
                        return <TypeIcon size={23} />
                      })()
                    )}
                  </span>
                  <div className="detail-heading">
                    <p className="eyebrow">{itemTypeMeta[selectedLogin.type].label}</p>
                    <h2>{selectedLogin.name}</h2>
                    <span>
                      {selectedLogin.subtitle ||
                        (selectedLogin.type === 'login'
                          ? hostLabel(selectedLogin.uri)
                          : '安全保管的項目')}
                    </span>
                  </div>
                  <TooltipIconButton
                    variant="outline"
                    size="icon"
                    className={cn('icon-button', selectedLogin.favorite && 'favorite-active')}
                    type="button"
                    label={selectedLogin.favorite ? '從常用項目移除' : '加入常用項目'}
                    aria-pressed={selectedLogin.favorite}
                    onClick={() => void toggleFavorite(selectedLogin)}
                  >
                    <Star fill={selectedLogin.favorite ? 'currentColor' : 'none'} />
                  </TooltipIconButton>
                  <Button
                    variant="outline"
                    size="sm"
                    className="button secondary compact"
                    type="button"
                    onClick={() => openEditor('edit')}
                  >
                    <Edit3 data-icon="inline-start" />
                    編輯
                  </Button>
                </header>

                <div className="detail-scroll">
                  {selectedDetailFields.length > 0 && (
                    <Card
                      className="detail-card gap-0 py-0"
                      role="region"
                      aria-labelledby="credentials-title"
                    >
                      <CardHeader className="bg-muted rounded-none border-b">
                        <CardTitle id="credentials-title">
                          {itemTypeMeta[selectedLogin.type].label}資料
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="contents">
                        {selectedDetailFields
                          .filter((field) => field.secret || Boolean(field.value))
                          .map(renderDetailField)}
                      </CardContent>
                    </Card>
                  )}

                  {selectedLogin.customFields.length > 0 && (
                    <Card
                      className="detail-card gap-0 py-0"
                      role="region"
                      aria-labelledby="custom-fields-title"
                    >
                      <CardHeader className="bg-muted rounded-none border-b">
                        <CardTitle id="custom-fields-title">自訂欄位</CardTitle>
                        <CardDescription>
                          {selectedLogin.customFields.length} 個欄位
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="contents">
                        {selectedLogin.customFields.map(renderCustomField)}
                      </CardContent>
                    </Card>
                  )}

                  {selectedLogin.type === 'login' && selectedLogin.hasTotp && (
                    <Card
                      className="detail-card totp-card gap-0 py-0"
                      role="region"
                      aria-labelledby="totp-title"
                    >
                      <CardHeader className="bg-muted rounded-none border-b">
                        <CardTitle id="totp-title">一次性驗證碼</CardTitle>
                        <CardDescription>
                          {totpCode ? `${totpCode.remainingSeconds} 秒後更新` : '產生中…'}
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="contents">
                        <div className="totp-value">
                          <strong>{totpCode?.code ?? '••••••'}</strong>
                          <TooltipIconButton
                            variant="outline"
                            size="icon"
                            className="icon-button"
                            type="button"
                            label="複製一次性驗證碼"
                            disabled={!totpCode}
                            onClick={() => void copyTotp()}
                          >
                            <Copy />
                          </TooltipIconButton>
                        </div>
                        <Progress
                          aria-label="驗證碼剩餘時間"
                          max={totpCode?.period ?? 30}
                          value={totpCode?.remainingSeconds ?? 0}
                        />
                      </CardContent>
                    </Card>
                  )}

                  {selectedLogin.type === 'login' && selectedLogin.passkeys.length > 0 && (
                    <Card
                      className="detail-card passkey-card gap-0 py-0"
                      role="region"
                      aria-labelledby="passkeys-title"
                    >
                      <CardHeader className="bg-muted rounded-none border-b">
                        <CardTitle id="passkeys-title">Passkeys</CardTitle>
                        <CardDescription>{selectedLogin.passkeys.length} 組</CardDescription>
                      </CardHeader>
                      <CardContent className="contents">
                        <div className="passkey-list">
                          {selectedLogin.passkeys.map((passkey) => (
                            <article key={passkey.credentialId} className="passkey-item">
                              <span className="passkey-icon" aria-hidden="true">
                                <KeyRound size={17} />
                              </span>
                              <div>
                                <strong>{passkey.rpName || passkey.rpId}</strong>
                                <span>
                                  {passkey.userDisplayName || passkey.userName || '未命名使用者'}
                                </span>
                                <small>
                                  {passkey.rpId} · {formatDate(passkey.creationDate)}
                                  {passkey.discoverable ? ' · 可探索' : ''}
                                </small>
                              </div>
                            </article>
                          ))}
                        </div>
                        <p className="passkey-note">
                          BearWarden 會完整同步既有 Passkey；私鑰材料不會傳到顯示程序。
                        </p>
                      </CardContent>
                    </Card>
                  )}

                  {(selectedLogin.type === 'secureNote' || selectedLogin.notes) && (
                    <Card
                      className="detail-card notes-card gap-0 py-0"
                      role="region"
                      aria-labelledby="notes-title"
                    >
                      <CardHeader className="bg-muted rounded-none border-b">
                        <CardTitle id="notes-title">
                          {selectedLogin.type === 'secureNote' ? '安全備註' : '備註'}
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="contents">
                        <p className={cn(!selectedLogin.notes?.trim() && 'empty-note')}>
                          {selectedLogin.notes?.trim() ? selectedLogin.notes : '尚未加入內容'}
                        </p>
                      </CardContent>
                    </Card>
                  )}

                  <Card
                    className="detail-card organization-card gap-0 py-0"
                    role="region"
                    aria-labelledby="organization-title"
                  >
                    <CardHeader className="bg-muted rounded-none border-b">
                      <CardTitle id="organization-title">整理與活動</CardTitle>
                    </CardHeader>
                    <CardContent className="contents">
                      <dl>
                        <div>
                          <dt>資料夾</dt>
                          <dd>
                            {folders.find((folder) => folder.id === selectedLogin.folderId)?.name ??
                              '未分類'}
                          </dd>
                        </div>
                        <div>
                          <dt>最近使用</dt>
                          <dd>{formatDate(selectedLogin.lastUsedAt)}</dd>
                        </div>
                      </dl>
                      <Button
                        variant="outline"
                        className="button secondary"
                        type="button"
                        onClick={() => setMoveDialogOpen(true)}
                      >
                        <Folder data-icon="inline-start" />
                        移動至資料夾… <Kbd>{moveShortcutLabel}</Kbd>
                      </Button>
                    </CardContent>
                  </Card>

                  <Card
                    className="detail-card organization-card gap-0 py-0"
                    role="region"
                    aria-labelledby="history-title"
                  >
                    <CardHeader className="bg-muted rounded-none border-b">
                      <CardTitle id="history-title">項目歷史記錄</CardTitle>
                    </CardHeader>
                    <CardContent className="contents">
                      <dl>
                        <div>
                          <dt>最後編輯紀錄</dt>
                          <dd>{formatDate(selectedLogin.updatedAt)}</dd>
                        </div>
                        <div>
                          <dt>建立於</dt>
                          <dd>{formatDate(selectedLogin.createdAt)}</dd>
                        </div>
                      </dl>
                    </CardContent>
                  </Card>

                  <div className="danger-zone">
                    <Button
                      variant="destructive"
                      className="button ghost danger-text"
                      type="button"
                      onClick={() => setDeleteDialogOpen(true)}
                    >
                      <Trash2 data-icon="inline-start" />
                      永久刪除這筆項目
                    </Button>
                  </div>
                </div>
              </article>
            ) : (
              <Empty className="detail-empty">
                <EmptyHeader>
                  <EmptyMedia className="mb-4 h-16 w-[78px]" aria-hidden="true">
                    <img className="size-16 object-contain" src={bearCutUrl} alt="" />
                  </EmptyMedia>
                  <EmptyTitle>未選取項目</EmptyTitle>
                  <EmptyDescription>選取項目以查看並管理安全資料。</EmptyDescription>
                </EmptyHeader>
              </Empty>
            )}
          </section>
        </div>

        {folderDialog && (
          <FolderDialog
            folder={folderDialog === 'new' ? undefined : folderDialog}
            busy={busy}
            onClose={() => setFolderDialog(null)}
            onSave={saveFolder}
            onDelete={folderDialog === 'new' ? undefined : deleteFolder}
          />
        )}
        {moveDialogOpen && selectedSummary && (
          <MoveDialog
            itemName={selectedSummary.name}
            itemCount={selectedSummaries.length}
            currentFolderId={selectedFolderId}
            folders={folders}
            busy={busy}
            onClose={() => setMoveDialogOpen(false)}
            onMove={(folderId) =>
              moveLogins(
                selectedSummaries.map((item) => item.id),
                folderId
              )
            }
          />
        )}
        {deleteDialogOpen && selectedSummary && (
          <DeleteLoginDialog
            itemName={selectedSummary.name}
            busy={busy}
            onClose={() => setDeleteDialogOpen(false)}
            onDelete={deleteLogin}
          />
        )}
        {syncDialogOpen && (
          <SyncDialog
            status={syncStatus}
            onClose={() => setSyncDialogOpen(false)}
            onStatusChange={setSyncStatus}
            onSynced={refreshAfterSync}
          />
        )}
        <AlertDialog
          open={discardEditorDialogOpen && editorDirty}
          onOpenChange={(open) => {
            setDiscardEditorDialogOpen(open)
            if (!open) pendingEditorActionRef.current = null
          }}
        >
          <AlertDialogContent size="sm">
            <AlertDialogHeader>
              <AlertDialogTitle>捨棄尚未儲存的變更？</AlertDialogTitle>
              <AlertDialogDescription>這些變更尚未儲存。捨棄後將無法復原。</AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel type="button">繼續編輯</AlertDialogCancel>
              <AlertDialogAction
                type="button"
                variant="destructive"
                onClick={confirmEditorDiscard}
                disabled={busy}
              >
                捨棄變更
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </main>

      <DragOverlay dropAnimation={null} style={{ pointerEvents: 'none' }}>
        {activeDragItem ? (
          <ItemDragPreview
            item={activeDragItem}
            count={activeDragItemCount}
            showWebsiteIcons={settings?.showWebsiteIcons ?? false}
          />
        ) : activeDragFolder ? (
          <FolderDragPreview
            folder={activeDragFolder}
            count={folderCounts.get(activeDragFolder.id) ?? 0}
          />
        ) : null}
      </DragOverlay>
    </DndContext>
  )
}

export default VaultShell
