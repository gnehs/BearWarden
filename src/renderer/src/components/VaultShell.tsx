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
  ChevronDown,
  Clipboard,
  Clock3,
  Cloud,
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
  LockKeyhole,
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
  VaultItemType,
  VaultSecretField
} from '../../../shared/vault-contract'
import bearCutUrl from '../assets/bear-cut.svg'
import BrandMark from './BrandMark'
import { DeleteLoginDialog, FolderDialog, MoveDialog } from './Dialogs'
import { FolderRow, ItemRow } from './DndRows'
import LoginEditor, { type LoginDraft } from './LoginEditor'
import SyncDialog from './SyncDialog'
import { groupItemsByDate } from '../lib/item-date-groups'
import { matchesVaultCategory, type VaultCategoryFilter } from '../lib/vault-category'
import { formatPaymentCardNumber } from '../lib/payment-card'
import { normalizeBitwardenCardBrand } from '../lib/payment-card'
import PaymentCardBrandMark from './PaymentCardBrandMark'
import WebsiteIcon from './WebsiteIcon'
import { Button } from '@renderer/components/ui/button'
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
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldLabel,
  FieldTitle
} from '@renderer/components/ui/field'
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput
} from '@renderer/components/ui/input-group'
import { Input } from '@renderer/components/ui/input'
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
import { Spinner } from '@renderer/components/ui/spinner'
import { Switch } from '@renderer/components/ui/switch'
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

const settingsLabels = {
  contentProtection: '禁止螢幕截圖',
  lockOnScreenLock: '螢幕鎖定時自動鎖定',
  lockOnSuspend: '電腦休眠時自動鎖定'
} as const

const autoLockItems = [
  { label: '永不自動鎖定', value: 0 },
  { label: '1 分鐘', value: 1 },
  { label: '5 分鐘', value: 5 },
  { label: '15 分鐘', value: 15 },
  { label: '30 分鐘', value: 30 },
  { label: '60 分鐘', value: 60 }
] as const

const clipboardClearItems = [
  { label: '不自動清除', value: 0 },
  { label: '15 秒後', value: 15 },
  { label: '30 秒後', value: 30 },
  { label: '1 分鐘後', value: 60 },
  { label: '2 分鐘後', value: 120 }
] as const

const defaultSortItems = [
  { label: '最近使用', value: 'recent' },
  { label: '依名稱', value: 'name' }
] as const

const themeItems = [
  { label: '跟隨系統', value: 'system' },
  { label: '淺色', value: 'light' },
  { label: '深色', value: 'dark' }
] as const

const sortItemsOptions = [
  { label: '依名稱', value: 'title' },
  { label: '最近使用', value: 'recent' },
  { label: '最近修改', value: 'modified' }
] as const

const isMac = navigator.userAgent.includes('Mac')
const commandLabel = isMac ? '⌘' : 'Ctrl'
const moveShortcutLabel = isMac ? '⇧⌘M' : 'Ctrl+Shift+M'

interface VaultShellProps {
  onLocked: () => void
}

interface RevealedSecretsState {
  itemId: string | null
  values: Partial<Record<VaultSecretField, string>>
}

const emptyRevealedSecrets: RevealedSecretsState = { itemId: null, values: {} }

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
  return new Intl.DateTimeFormat('zh-TW', {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(date)
}

function hostLabel(uri: string | null): string {
  if (!uri) return '未設定網站'
  try {
    return new URL(uri).hostname
  } catch {
    return uri
  }
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

function VaultShell({ onLocked }: VaultShellProps): React.JSX.Element {
  const [folders, setFolders] = useState<FolderView[]>([])
  const [items, setItems] = useState<LoginSummary[]>([])
  const [scope, setScope] = useState<Scope>({ kind: 'all' })
  const [sortMode, setSortMode] = useState<SortMode>('title')
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('all')
  const [query, setQuery] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [selectedLogin, setSelectedLogin] = useState<LoginView | null>(null)
  const [totpCode, setTotpCode] = useState<TotpCodeView | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [editorMode, setEditorMode] = useState<'create' | 'edit' | null>(null)
  const [revealedSecrets, setRevealedSecrets] = useState<RevealedSecretsState>(emptyRevealedSecrets)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [folderDialog, setFolderDialog] = useState<FolderView | 'new' | null>(null)
  const [moveDialogOpen, setMoveDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [syncDialogOpen, setSyncDialogOpen] = useState(false)
  const [syncStatus, setSyncStatus] = useState<SyncStatus>(initialSyncStatus)
  const [settings, setSettings] = useState<AppSettings | null>(null)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [settingsBusy, setSettingsBusy] = useState(false)
  const [touchIdPassword, setTouchIdPassword] = useState('')
  const [activeDragId, setActiveDragId] = useState<string | null>(null)
  const searchRef = useRef<HTMLInputElement>(null)
  const compactReturnIdRef = useRef<string | null>(null)
  const compactDetailFocusIdRef = useRef<string | null>(null)
  const selectedIdRef = useRef<string | null>(null)

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  )

  const loadVault = useCallback(async (): Promise<void> => {
    try {
      toast.dismiss(vaultErrorToastId)
      const [folderList, loginList] = await Promise.all([
        window.bearwarden.folders.list(),
        window.bearwarden.logins.list({ sort: 'name' })
      ])
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
      announceError(describeError(loadError))
    } finally {
      setLoading(false)
    }
  }, [])

  const refreshItems = useCallback(async (): Promise<void> => {
    const loginList = await window.bearwarden.logins.list({ sort: 'name' })
    setItems(loginList)
    setSelectedLogin((current) => {
      if (!current) return current
      const summary = loginList.find((item) => item.id === current.id)
      return summary ? { ...current, ...summary } : current
    })
  }, [])

  const refreshAfterSync = useCallback(async (): Promise<void> => {
    await loadVault()
    setEditorMode(null)
    setSelectedId(null)
    setSelectedLogin(null)
    setRevealedSecrets(emptyRevealedSecrets)
  }, [loadVault])

  useEffect(() => {
    queueMicrotask(() => void loadVault())
  }, [loadVault])

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
      if (!selectedId || editorMode === 'create') {
        setSelectedLogin(null)
        setRevealedSecrets(emptyRevealedSecrets)
        return
      }
      setDetailLoading(true)
      window.bearwarden.logins
        .get({ id: selectedId })
        .then((login) => {
          if (active) setSelectedLogin(login)
        })
        .catch((detailError) => {
          if (active) announceError(describeError(detailError))
        })
        .finally(() => {
          if (active) setDetailLoading(false)
        })
    })
    return () => {
      active = false
    }
  }, [selectedId, editorMode])

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

  useEffect(() => {
    if (editorMode || settingsOpen) return
    if (selectedId && scopedItems.some((item) => item.id === selectedId)) return
    queueMicrotask(() => setSelectedId(null))
  }, [editorMode, scopedItems, selectedId, settingsOpen])

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

  const lockVault = useCallback(async (): Promise<void> => {
    setRevealedSecrets(emptyRevealedSecrets)
    setTouchIdPassword('')
    setSelectedLogin(null)
    try {
      const status = await window.bearwarden.vault.lock()
      if (status.state === 'locked') onLocked()
      else announceError('保管庫尚未鎖定，請再試一次。')
    } catch (lockError) {
      announceError(describeError(lockError))
    }
  }, [onLocked])

  useEffect(() => {
    function handleShortcut(event: KeyboardEvent): void {
      const command = event.metaKey || event.ctrlKey
      if (!command) return
      const key = event.key.toLocaleLowerCase()
      if (key === 'f') {
        event.preventDefault()
        searchRef.current?.focus()
        searchRef.current?.select()
      }
      if (key === 'n') {
        event.preventDefault()
        setEditorMode('create')
      }
      if (key === 'e' && selectedLogin) {
        event.preventDefault()
        setEditorMode('edit')
      }
      if (key === 's' && editorMode && !busy) {
        event.preventDefault()
        document.querySelector<HTMLFormElement>('form.editor')?.requestSubmit()
      }
      if (key === 'l') {
        event.preventDefault()
        void lockVault()
      }
      if (key === 'm' && event.shiftKey && selectedSummary) {
        event.preventDefault()
        setMoveDialogOpen(true)
      }
    }
    window.addEventListener('keydown', handleShortcut)
    return () => window.removeEventListener('keydown', handleShortcut)
  }, [busy, editorMode, lockVault, selectedLogin, selectedSummary])

  function selectScope(nextScope: Scope): void {
    setScope(nextScope)
    setTypeFilter('all')
    setSidebarOpen(false)
    setSettingsOpen(false)
    setTouchIdPassword('')
    setEditorMode(null)
    setMoveDialogOpen(false)
  }

  function selectType(type: TypeFilter): void {
    setScope({ kind: 'all' })
    setTypeFilter(type)
    setSidebarOpen(false)
    setSettingsOpen(false)
    setTouchIdPassword('')
    setEditorMode(null)
    setMoveDialogOpen(false)
  }

  function openSettings(): void {
    setSettingsOpen(true)
    setSidebarOpen(false)
    setEditorMode(null)
    setMoveDialogOpen(false)
    setSelectedId(null)
    setSelectedLogin(null)
    setRevealedSecrets(emptyRevealedSecrets)
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

  async function toggleFavorite(item: LoginSummary): Promise<void> {
    try {
      const updated = await window.bearwarden.logins.setFavorite({
        id: item.id,
        favorite: !item.favorite
      })
      setItems((current) => current.map((entry) => (entry.id === updated.id ? updated : entry)))
      setSelectedLogin((current) =>
        current?.id === updated.id ? { ...current, ...updated } : current
      )
      announce(updated.favorite ? '已加入常用項目。' : '已從常用項目移除。')
    } catch (favoriteError) {
      announceError(describeError(favoriteError))
    }
  }

  async function moveLogin(id: string, folderId: string | null): Promise<void> {
    const previous = items.find((item) => item.id === id)
    if (!previous || previous.folderId === folderId) {
      setMoveDialogOpen(false)
      return
    }
    setBusy(true)
    setItems((current) => current.map((item) => (item.id === id ? { ...item, folderId } : item)))
    try {
      const updated = await window.bearwarden.logins.move({ id, folderId })
      setItems((current) => current.map((item) => (item.id === id ? updated : item)))
      setSelectedLogin((current) => (current?.id === id ? { ...current, ...updated } : current))
      const destination = folders.find((folder) => folder.id === folderId)?.name ?? '未分類'
      announce(`已移至「${destination}」。`)
      setMoveDialogOpen(false)
    } catch (moveError) {
      setItems((current) => current.map((item) => (item.id === id ? previous : item)))
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
          favorite: draft.favorite
        })
        setItems((current) => [...current, created])
        setScope({ kind: 'all' })
        setSelectedId(created.id)
        setSelectedLogin(created)
        announce(`已建立「${created.name}」。`)
      } else if (selectedLogin) {
        const updated = await window.bearwarden.logins.update({
          id: selectedLogin.id,
          name: draft.name,
          ...fields,
          notes: draft.notes || null,
          folderId: draft.folderId,
          favorite: draft.favorite
        })
        setItems((current) => current.map((item) => (item.id === updated.id ? updated : item)))
        setSelectedLogin(updated)
        announce(`已儲存「${updated.name}」。`)
      }
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
      setItems((current) => current.filter((item) => item.id !== selectedSummary.id))
      setSelectedId(null)
      setSelectedLogin(null)
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
    setActiveDragId(String(event.active.id))
  }

  async function endDrag(event: DragEndEvent): Promise<void> {
    setActiveDragId(null)
    if (!event.over) return
    const activeId = String(event.active.id)
    const overId = String(event.over.id)
    if (itemIds.has(activeId)) {
      if (overId === 'folder:none') await moveLogin(activeId, null)
      else if (folderIds.has(overId)) await moveLogin(activeId, overId)
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
          <BrandMark />
          <div className="titlebar-drag" aria-hidden="true" />
          <Button
            variant="outline"
            className="button lock-button"
            type="button"
            onClick={() => void lockVault()}
          >
            <LockKeyhole data-icon="inline-start" aria-hidden="true" />
            鎖定
            <Kbd>{commandLabel} L</Kbd>
          </Button>
        </header>

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
            <div className="vault-switcher">
              <span className="vault-avatar" aria-hidden="true">
                <KeyRound size={18} />
              </span>
              <span>
                <strong>我的保管庫</strong>
                <small>{items.length} 個保管庫項目</small>
              </span>
              <ChevronDown size={15} aria-hidden="true" />
            </div>

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
                className="sync-sidebar-control"
                type="button"
                onClick={() => setSyncDialogOpen(true)}
                aria-label="開啟 Bitwarden 同步"
              >
                <span
                  className={cn('sync-status-indicator', syncStatus.state)}
                  aria-hidden="true"
                />
                <span>
                  <strong>Bitwarden 同步</strong>
                  <small>
                    {syncStatus.state === 'ready'
                      ? '已連線'
                      : syncStatus.state === 'syncing'
                        ? '同步中…'
                        : syncStatus.state === 'locked'
                          ? '需要解鎖'
                          : syncStatus.state === 'error'
                            ? '需要處理問題'
                            : '尚未設定'}
                  </small>
                </span>
                <Cloud size={16} aria-hidden="true" />
              </Button>
              <Button
                variant="ghost"
                className={cn('sidebar-settings-control', settingsOpen && 'active')}
                type="button"
                onClick={openSettings}
                aria-current={settingsOpen ? 'page' : undefined}
              >
                <Settings2 size={15} aria-hidden="true" />
                設定
              </Button>
            </footer>
          </aside>

          <section className="list-pane" aria-labelledby="list-title">
            {settingsOpen ? (
              <div className="settings-page" aria-labelledby="settings-title">
                <header className="list-header settings-header">
                  <div>
                    <p className="eyebrow">應用程式</p>
                    <h1 id="settings-title">設定</h1>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    className="button secondary compact"
                    type="button"
                    onClick={closeSettings}
                  >
                    <ArrowLeft data-icon="inline-start" aria-hidden="true" />
                    返回保管庫
                  </Button>
                </header>
                <div className="settings-scroll">
                  {!settings ? (
                    <div className="detail-loading" role="status">
                      <Spinner /> 正在讀取設定…
                    </div>
                  ) : (
                    <>
                      <Card
                        className="settings-card gap-0 py-0"
                        aria-labelledby="privacy-settings-title"
                      >
                        <CardHeader className="bg-muted rounded-none border-b">
                          <CardTitle id="privacy-settings-title">保護與鎖定</CardTitle>
                          <CardDescription>這些選項會立即套用到這台裝置。</CardDescription>
                        </CardHeader>
                        <CardContent className="contents">
                          {(
                            ['contentProtection', 'lockOnScreenLock', 'lockOnSuspend'] as const
                          ).map((key) => (
                            <Field className="settings-toggle" orientation="horizontal" key={key}>
                              <FieldContent>
                                <FieldTitle>{settingsLabels[key]}</FieldTitle>
                                <FieldDescription>
                                  {key === 'contentProtection'
                                    ? '啟用後會要求系統避免擷取此視窗內容。'
                                    : '保管庫會在此事件發生時立即鎖定。'}
                                </FieldDescription>
                              </FieldContent>
                              <Switch
                                checked={settings[key]}
                                disabled={settingsBusy}
                                aria-label={settingsLabels[key]}
                                onCheckedChange={(checked) =>
                                  void updateSettings({ [key]: checked })
                                }
                              />
                            </Field>
                          ))}
                          <Field className="field settings-select">
                            <FieldLabel htmlFor="auto-lock-select">閒置自動鎖定</FieldLabel>
                            <Select
                              items={autoLockItems}
                              value={settings.autoLockMinutes}
                              disabled={settingsBusy}
                              onValueChange={(value) =>
                                void updateSettings({
                                  autoLockMinutes: value as AppSettings['autoLockMinutes']
                                })
                              }
                            >
                              <SelectTrigger id="auto-lock-select" className="w-full">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectGroup>
                                  {autoLockItems.map((item) => (
                                    <SelectItem key={item.value} value={item.value}>
                                      {item.label}
                                    </SelectItem>
                                  ))}
                                </SelectGroup>
                              </SelectContent>
                            </Select>
                          </Field>
                        </CardContent>
                      </Card>

                      <Card
                        className="settings-card gap-0 py-0"
                        aria-labelledby="clipboard-settings-title"
                      >
                        <CardHeader className="bg-muted rounded-none border-b">
                          <CardTitle id="clipboard-settings-title">剪貼簿與顯示</CardTitle>
                          <CardDescription>
                            剪貼簿清除僅會清除由 BearWarden 寫入且尚未被你覆蓋的內容。
                          </CardDescription>
                        </CardHeader>
                        <CardContent className="contents">
                          <Field className="settings-toggle" orientation="horizontal">
                            <FieldContent>
                              <FieldTitle>顯示網站圖示</FieldTitle>
                              <FieldDescription>
                                僅透過已設定的 Bitwarden／Vaultwarden
                                圖示服務載入；停用後改用本機縮寫圖示。
                              </FieldDescription>
                            </FieldContent>
                            <Switch
                              checked={settings.showWebsiteIcons}
                              disabled={settingsBusy}
                              aria-label="顯示網站圖示"
                              onCheckedChange={(checked) =>
                                void updateSettings({ showWebsiteIcons: checked })
                              }
                            />
                          </Field>
                          <Field className="field settings-select">
                            <FieldLabel htmlFor="clipboard-clear-select">清除剪貼簿</FieldLabel>
                            <Select
                              items={clipboardClearItems}
                              value={settings.clearClipboardSeconds}
                              disabled={settingsBusy}
                              onValueChange={(value) =>
                                void updateSettings({
                                  clearClipboardSeconds:
                                    value as AppSettings['clearClipboardSeconds']
                                })
                              }
                            >
                              <SelectTrigger id="clipboard-clear-select" className="w-full">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectGroup>
                                  {clipboardClearItems.map((item) => (
                                    <SelectItem key={item.value} value={item.value}>
                                      {item.label}
                                    </SelectItem>
                                  ))}
                                </SelectGroup>
                              </SelectContent>
                            </Select>
                          </Field>
                          <Field className="field settings-select">
                            <FieldLabel htmlFor="default-sort-select">預設排序</FieldLabel>
                            <Select
                              items={defaultSortItems}
                              value={settings.defaultSort}
                              disabled={settingsBusy}
                              onValueChange={(value) =>
                                void updateSettings({
                                  defaultSort: value as AppSettings['defaultSort']
                                })
                              }
                            >
                              <SelectTrigger id="default-sort-select" className="w-full">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectGroup>
                                  {defaultSortItems.map((item) => (
                                    <SelectItem key={item.value} value={item.value}>
                                      {item.label}
                                    </SelectItem>
                                  ))}
                                </SelectGroup>
                              </SelectContent>
                            </Select>
                          </Field>
                          <Field className="field settings-select">
                            <FieldLabel htmlFor="theme-select">主題</FieldLabel>
                            <Select
                              items={themeItems}
                              value={settings.theme}
                              disabled={settingsBusy}
                              onValueChange={(value) =>
                                void updateSettings({ theme: value as AppSettings['theme'] })
                              }
                            >
                              <SelectTrigger id="theme-select" className="w-full">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectGroup>
                                  {themeItems.map((item) => (
                                    <SelectItem key={item.value} value={item.value}>
                                      {item.label}
                                    </SelectItem>
                                  ))}
                                </SelectGroup>
                              </SelectContent>
                            </Select>
                          </Field>
                        </CardContent>
                      </Card>

                      <Card
                        className="settings-card gap-0 py-0"
                        aria-labelledby="touch-id-settings-title"
                      >
                        <CardHeader className="bg-muted rounded-none border-b">
                          <CardTitle id="touch-id-settings-title">Touch ID</CardTitle>
                          <CardDescription>
                            Touch ID 僅用來授權以此裝置安全儲存的主密碼解鎖。
                          </CardDescription>
                        </CardHeader>
                        <CardContent className="contents">
                          {!settings.touchIdAvailable ? (
                            <Empty className="settings-empty min-h-24 p-3">
                              <EmptyHeader>
                                <EmptyDescription>這台裝置目前無法使用 Touch ID。</EmptyDescription>
                              </EmptyHeader>
                            </Empty>
                          ) : settings.touchIdEnabled ? (
                            <div className="settings-inline-action">
                              <span>
                                <strong>Touch ID 已啟用</strong>
                                <small>下次鎖定後可直接使用 Touch ID 解鎖。</small>
                              </span>
                              <Button
                                variant="outline"
                                size="sm"
                                className="button secondary compact"
                                type="button"
                                disabled={settingsBusy}
                                onClick={() => void disableTouchId()}
                              >
                                停用
                              </Button>
                            </div>
                          ) : (
                            <div className="touch-id-enable">
                              <Field className="field">
                                <FieldLabel htmlFor="touch-id-password">
                                  確認主密碼以啟用
                                </FieldLabel>
                                <Input
                                  id="touch-id-password"
                                  type="password"
                                  autoComplete="current-password"
                                  value={touchIdPassword}
                                  disabled={settingsBusy}
                                  onChange={(event) => setTouchIdPassword(event.target.value)}
                                />
                              </Field>
                              <Button
                                size="sm"
                                className="button primary compact"
                                type="button"
                                disabled={settingsBusy}
                                onClick={() => void enableTouchId()}
                              >
                                啟用 Touch ID
                              </Button>
                            </div>
                          )}
                        </CardContent>
                      </Card>

                      <Card
                        className="settings-card gap-0 py-0"
                        aria-labelledby="sync-settings-title"
                      >
                        <CardHeader className="bg-muted rounded-none border-b">
                          <CardTitle id="sync-settings-title">Bitwarden 同步與帳號</CardTitle>
                          <CardDescription>同步設定保留在這台裝置的加密保管庫中。</CardDescription>
                        </CardHeader>
                        <CardContent className="contents">
                          <div className="settings-sync-status">
                            <span
                              className={cn('sync-status-indicator', syncStatus.state)}
                              aria-hidden="true"
                            />
                            <div>
                              <strong>
                                {syncStatus.state === 'ready'
                                  ? '已連線'
                                  : syncStatus.state === 'syncing'
                                    ? '同步中…'
                                    : syncStatus.state === 'locked'
                                      ? '需要解鎖'
                                      : syncStatus.state === 'error'
                                        ? '需要處理問題'
                                        : '尚未設定'}
                              </strong>
                              <small>
                                {syncStatus.email ??
                                  syncStatus.serverUrl ??
                                  '尚未連接 Bitwarden 帳號'}
                              </small>
                            </div>
                          </div>
                          <Button
                            variant="outline"
                            size="sm"
                            className="button secondary compact m-3 self-start"
                            type="button"
                            onClick={() => setSyncDialogOpen(true)}
                          >
                            {syncStatus.configured ? '管理同步與帳號' : '設定 Bitwarden 同步'}
                          </Button>
                        </CardContent>
                      </Card>
                    </>
                  )}
                </div>
              </div>
            ) : (
              <>
                <header className="list-header">
                  <div className="list-heading">
                    <h1 id="list-title">{scopeTitle}</h1>
                    <small>{scopedItems.length} 個項目</small>
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
                    <TooltipIconButton
                      variant="outline"
                      size="icon"
                      className="icon-button list-add-button"
                      type="button"
                      label="新增項目"
                      onClick={() => setEditorMode('create')}
                    >
                      <Plus aria-hidden="true" />
                    </TooltipIconButton>
                  </div>
                </header>
                <div className="list-tools">
                  <InputGroup className="search-field">
                    <InputGroupAddon>
                      <Search aria-hidden="true" />
                    </InputGroupAddon>
                    <InputGroupInput
                      ref={searchRef}
                      type="search"
                      aria-label="搜尋保管庫項目"
                      placeholder="搜尋名稱、摘要或網站"
                      value={query}
                      onChange={(event) => setQuery(event.target.value)}
                    />
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
                </div>
                {query && (
                  <div className="result-summary" role="status">
                    <span>搜尋「{query}」</span>
                    <span>{scopedItems.length} 筆結果</span>
                  </div>
                )}

                {scopedItems.length ? (
                  <div className="item-list" aria-label={`${scopeTitle}保管庫項目`}>
                    {itemGroups.map((group) => (
                      <section
                        className={cn('item-group', !group.label && 'ungrouped')}
                        key={group.key}
                        aria-labelledby={group.label ? `group-${group.key}` : undefined}
                        aria-label={group.label ? undefined : `${scopeTitle}項目`}
                      >
                        {group.label && <h2 id={`group-${group.key}`}>{group.label}</h2>}
                        <ul aria-label={group.label ? `${group.label}項目` : `${scopeTitle}項目`}>
                          {group.items.map((item) => (
                            <ItemRow
                              key={item.id}
                              item={item}
                              selected={selectedId === item.id}
                              onSelect={() => {
                                compactReturnIdRef.current = item.id
                                setSelectedId(item.id)
                                setEditorMode(null)
                              }}
                              onFavorite={() => void toggleFavorite(item)}
                              onContextMenu={(position) =>
                                void window.bearwarden.logins
                                  .showContextMenu({ id: item.id, ...position })
                                  .catch((menuError) => announceError(describeError(menuError)))
                              }
                              showWebsiteIcons={settings?.showWebsiteIcons ?? false}
                            />
                          ))}
                        </ul>
                      </section>
                    ))}
                  </div>
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
                          onClick={() => setEditorMode('create')}
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
                key={`${editorMode}:${selectedLogin?.id ?? 'new'}`}
                login={editorMode === 'edit' ? (selectedLogin ?? undefined) : undefined}
                folders={folders}
                busy={busy}
                onCancel={() => setEditorMode(null)}
                onSave={saveLogin}
              />
            ) : detailLoading ? (
              <div className="detail-loading" role="status">
                <Spinner />
                <span>正在解密詳細資料…</span>
              </div>
            ) : selectedLogin && selectedLogin.id === selectedId ? (
              <article className="detail-content">
                <header className="detail-header">
                  <TooltipIconButton
                    variant="outline"
                    size="icon"
                    className="icon-button detail-back"
                    type="button"
                    label="返回項目列表"
                    onClick={() => setSelectedId(null)}
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
                    onClick={() => setEditorMode('edit')}
                  >
                    <Edit3 data-icon="inline-start" />
                    編輯
                  </Button>
                </header>

                <div className="detail-scroll">
                  {detailFields(selectedLogin).length > 0 && (
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
                        {detailFields(selectedLogin)
                          .filter((field) => field.secret || Boolean(field.value))
                          .map(renderDetailField)}
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
            currentFolderId={selectedSummary.folderId}
            folders={folders}
            busy={busy}
            onClose={() => setMoveDialogOpen(false)}
            onMove={(folderId) => moveLogin(selectedSummary.id, folderId)}
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
      </main>

      <DragOverlay dropAnimation={null}>
        {activeDragId && (
          <div className="drag-overlay">
            {itemIds.has(activeDragId) ? <KeyRound size={16} /> : <Folder size={16} />}
            <span>{itemIds.has(activeDragId) ? '移動登入項目' : '重新排列資料夾'}</span>
          </div>
        )}
      </DragOverlay>
    </DndContext>
  )
}

export default VaultShell
