import {
  DndContext,
  DragOverlay,
  KeyboardSensor,
  PointerSensor,
  useDndContext,
  useDroppable,
  useSensor,
  useSensors,
  type DragEndEvent,
  type DragOverEvent,
  type DragStartEvent
} from '@dnd-kit/core'
import {
  arrayMove,
  SortableContext,
  sortableKeyboardCoordinates,
  verticalListSortingStrategy
} from '@dnd-kit/sortable'
import NumberFlow from '@number-flow/react'
import {
  AlertTriangle,
  ArrowLeft,
  ArrowUpRight,
  Archive,
  ArchiveRestore,
  BadgeCheck,
  Clock3,
  CloudAlert,
  CloudCheck,
  CloudCog,
  CloudSync,
  ChevronUp,
  ContactRound,
  Copy,
  CreditCard,
  Download,
  Edit3,
  Eye,
  EyeOff,
  FileKey2,
  Fingerprint,
  FolderOpen,
  History,
  KeyRound,
  ListFilter,
  LockKeyhole,
  Menu,
  MoreHorizontal,
  NotebookPen,
  Paperclip,
  Pencil,
  Plus,
  RotateCcw,
  Settings2,
  Search,
  Send as SendIcon,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Star,
  Trash2,
  Upload,
  UserRound,
  UsersRound,
  Wrench,
  X,
  ZoomIn
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { toast } from 'sonner'
import type {
  AppSettings,
  AppSettingsUpdate,
  AccountSecurityProfile,
  AccountMutationResult,
  AccountStatus,
  AttachmentOperationKind,
  AttachmentOperationStage,
  AttachmentProgressEvent,
  FolderView,
  LoginSummary,
  LoginView,
  LoginAuthorization,
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
import BrandMark from './BrandMark'
import { ColoredPassword } from './ColoredPassword'
import ApplicationTitlebarMenu from './ApplicationTitlebarMenu'
import {
  DeleteLoginDialog,
  FolderDialog,
  Modal,
  MoveDialog,
  PasswordHistoryDialog,
  RepromptDialog
} from './Dialogs'
import { ModalBody } from './ModalLayout'
import { ItemDragPreview } from './DragPreview'
import { FolderRow, type ItemSelectionModifiers } from './DndRows'
import LoginEditor, { type LoginDraft } from './LoginEditor'
import {
  createLoginWithOptionalSshImport,
  updateLoginWithOptionalSshImport
} from './ssh-key-editor-state'
import CredentialGeneratorDialog from './CredentialGeneratorDialog'
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
  quickAccessDropAction,
  quickAccessDropIds
} from './VaultShell-dnd'
import SyncDialog from './SyncDialog'
import SettingsPage from './SettingsPage'
import SendsPage from './SendsPage'
import OrganizationsPage from './OrganizationsPage'
import EmergencyAccessPage from './EmergencyAccessPage'
import VaultHealthPage from './VaultHealthPage'
import VaultPortabilityDialog, { type VaultPortabilityMode } from './VaultPortabilityDialog'
import { formatVaultExportResult, formatVaultImportResult } from '../lib/vault-portability-ui'
import VirtualizedItemList from './VirtualizedItemList'
import { groupItemsByDate } from '../lib/item-date-groups'
import { matchesVaultCategory, type VaultCategoryFilter } from '../lib/vault-category'
import { formatPaymentCardNumber } from '../lib/payment-card'
import { normalizeBitwardenCardBrand } from '../lib/payment-card'
import { shouldShowSyncSetupPrompt } from '../lib/sync-setup-prompt'
import { normalizeItemSelection, updateItemSelection } from '../lib/item-selection'
import {
  boundedVaultSearchQuery,
  filterVaultSearchMatches,
  isCurrentVaultSearchResponse,
  MAX_VAULT_SEARCH_QUERY_LENGTH,
  matchesVaultSearchNavigation,
  normalizedVaultSearchQuery,
  VAULT_SEARCH_DEBOUNCE_MS,
  vaultSearchListRequests,
  type VaultSearchMatches
} from '../lib/vault-search-ui'
import { vaultHealthRevision } from '../lib/vault-health-ui'
import { formatVaultDate as formatDate } from '../lib/vault-date'
import { useCopyFeedback } from '@renderer/hooks/use-copy-feedback'
import { resolveTotpRefreshTarget } from './totp-refresh-target'
import PaymentCardBrandMark from './PaymentCardBrandMark'
import WebsiteIcon from './WebsiteIcon'
import { ItemHistoryRows } from './ItemHistoryRows'
import { CopyFeedbackIcon } from './CopyFeedbackIcon'
import { Button } from '@renderer/components/ui/button'
import { Badge } from '@renderer/components/ui/badge'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogMedia,
  AlertDialogTitle
} from '@renderer/components/ui/alert-dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuTrigger
} from '@renderer/components/ui/dropdown-menu'
import {
  Card,
  CardAction,
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
import { Progress, ProgressLabel, ProgressValue } from '@renderer/components/ui/progress'
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
import { sortVaultItems, type VaultSortMode } from '@renderer/lib/vault-sort'
import {
  accountMutationError,
  isCurrentAccountRefresh,
  accountMutationKeepsBusy,
  AccountMutationGate,
  requestAccountAction
} from './account-switcher-ui'

type Scope =
  | { kind: 'all' }
  | { kind: 'favorites' }
  | { kind: 'recent' }
  | { kind: 'folder'; folderId: string }
  | { kind: 'unfiled' }
  | { kind: 'archive' }
  | { kind: 'trash' }

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
  uriIndex?: number
}

const itemTypeMeta: Record<VaultItemType, ItemTypeMeta> = {
  login: { label: '登入', icon: KeyRound },
  card: { label: '卡片', icon: CreditCard },
  identity: { label: '身分資料', icon: ContactRound },
  secureNote: { label: '安全備註', icon: NotebookPen },
  sshKey: { label: 'SSH 金鑰', icon: FileKey2 }
}

type SidebarTone = 'blue' | 'indigo' | 'green' | 'yellow' | 'cyan' | 'red' | 'orange' | 'gray'

const categoryMeta: Array<{
  id: TypeFilter
  label: string
  icon: typeof KeyRound
  tone: SidebarTone
}> = [
  { id: 'all', label: '全部', icon: KeyRound, tone: 'blue' },
  { id: 'login', label: '登入', icon: FileKey2, tone: 'indigo' },
  { id: 'passkey', label: '通行密鑰', icon: Fingerprint, tone: 'green' },
  { id: 'totp', label: '驗證碼', icon: BadgeCheck, tone: 'yellow' },
  { id: 'card', label: '卡片', icon: CreditCard, tone: 'cyan' },
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
  { label: '使用頻率', value: 'frequency' },
  { label: '最近修改', value: 'modified' }
] as const

const isMac = navigator.userAgent.includes('Mac')
const isWindows = navigator.userAgent.includes('Windows')
const usesWindowControlsOverlay = !isMac
const commandLabel = isMac ? '⌘' : 'Ctrl'
const detailCacheLimit = 48

interface VaultShellProps {
  onLocked: () => void
  promptSyncSetup: boolean
  onSyncSetupPromptHandled: () => void
}

interface RevealedSecretsState {
  itemId: string | null
  values: Partial<Record<VaultSecretField, string>>
}

const emptyRevealedSecrets: RevealedSecretsState = { itemId: null, values: {} }

interface TotpGenerationErrorState {
  itemId: string
  kind: 'unsupported'
}

interface RevealedCustomFieldsState {
  itemId: string | null
  values: Record<
    number,
    { value: string; source: VaultCustomFieldSource; expectedUpdatedAt: string }
  >
}

interface RepromptPromptState {
  itemName: string
}

interface PendingReprompt {
  key: string
  ids: string[]
  promise: Promise<LoginAuthorization>
  resolve: (authorization: LoginAuthorization) => void
  reject: (error: Error) => void
}

interface AttachmentOperationState extends AttachmentProgressEvent {
  fileName: string | null
  canceling: boolean
}

interface AttachmentDeleteTarget {
  itemId: string
  attachmentId: string
  fileName: string
}

type BulkSelectionState = 'active' | 'archive' | 'trash'
type BulkActionKind = 'archive' | 'unarchive' | 'delete' | 'restore' | 'deletePermanently'

interface BulkActionSnapshot {
  action: BulkActionKind
  ids: string[]
  state: BulkSelectionState
}

interface MoveSnapshot {
  ids: string[]
  state: Exclude<BulkSelectionState, 'trash'>
}

const initialAttachmentStages: Record<AttachmentOperationKind, AttachmentOperationStage> = {
  download: 'choosing-file',
  upload: 'choosing-file',
  delete: 'deleting',
  'fix-legacy': 'downloading'
}

const attachmentStageLabels: Record<AttachmentOperationStage, string> = {
  'choosing-file': '等待選擇檔案',
  'reading-file': '正在安全讀取檔案',
  encrypting: '正在本機加密',
  downloading: '正在下載附件',
  uploading: '正在上傳加密附件',
  deleting: '正在刪除附件',
  syncing: '正在同步附件清單'
}

function attachmentProgressPercent(progress: AttachmentProgressEvent): number | null {
  if (progress.totalBytes === null || progress.totalBytes <= 0) return null
  return Math.round(
    Math.min(100, Math.max(0, (progress.completedBytes / progress.totalBytes) * 100))
  )
}

function attachmentStageLabel(progress: AttachmentProgressEvent): string {
  if (progress.stage === 'choosing-file' && progress.kind === 'download') {
    return '等待選擇儲存位置'
  }
  return attachmentStageLabels[progress.stage]
}

function isAttachmentCanceled(error: unknown): boolean {
  return error instanceof Error && error.message.includes('ATTACHMENT_CANCELED')
}

const emptyRevealedCustomFields: RevealedCustomFieldsState = { itemId: null, values: {} }

interface TooltipIconButtonProps extends React.ComponentProps<typeof Button> {
  label: string
}

function TooltipIconButton({
  label,
  children,
  className,
  ...props
}: TooltipIconButtonProps): React.JSX.Element {
  const { active } = useDndContext()
  return (
    <Tooltip disabled={active != null}>
      <TooltipTrigger
        render={
          <Button
            aria-label={label}
            className={cn(
              'border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground dark:bg-card dark:hover:bg-muted size-[34px] min-w-[34px] rounded-[9px] shadow-(--control-highlight) transition-[background,color,border-color,transform] duration-[130ms] [-webkit-app-region:no-drag]',
              className
            )}
            {...props}
          />
        }
      >
        {children}
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}

interface DetailCardProps extends React.ComponentProps<typeof Card> {
  variant?: 'default' | 'attachment' | 'placeholder'
}

function DetailCard({
  className,
  variant = 'default',
  ...props
}: DetailCardProps): React.JSX.Element {
  return (
    <Card
      className={cn(
        'border-border dark:bg-card mx-auto mb-3.5 w-full max-w-[720px] gap-0 overflow-hidden rounded-md bg-[color-mix(in_oklch,var(--card)_94%,transparent)] py-0 shadow-[0_1px_2px_color-mix(in_oklch,var(--shadow-color)_3%,transparent)]',
        // header
        '[&>[data-slot=card-header]]:border-border [&>[data-slot=card-header]]:bg-muted [&>[data-slot=card-header]]:flex [&>[data-slot=card-header]]:items-center [&>[data-slot=card-header]]:gap-2 [&>[data-slot=card-header]]:border-b [&>[data-slot=card-header]]:px-3.5 [&>[data-slot=card-header]]:py-2.5',
        // title
        '[&_[data-slot=card-title]]:text-muted-foreground [&_[data-slot=card-title]]:m-0 [&_[data-slot=card-title]]:text-[10px] [&_[data-slot=card-title]]:leading-[1.4] [&_[data-slot=card-title]]:font-medium [&_[data-slot=card-title]]:uppercase',
        // description
        '[&_[data-slot=card-description]]:ml-auto [&_[data-slot=card-description]]:text-[10px] [&_[data-slot=card-description]]:leading-[1.4]',
        variant === 'attachment' &&
          '[&_[data-slot=card-description]]:text-xs [&_[data-slot=card-description]]:leading-normal [&_[data-slot=card-title]]:text-sm [&_[data-slot=card-title]]:font-[650] [&_[data-slot=card-title]]:tracking-normal [&_[data-slot=card-title]]:normal-case',
        variant === 'placeholder' && '[&_[data-slot=skeleton]]:opacity-72',
        className
      )}
      {...props}
    />
  )
}

function DetailHeader({ className, ...props }: React.ComponentProps<'header'>): React.JSX.Element {
  return (
    <header
      className={cn(
        'border-border bg-card flex items-center gap-3 border-b px-[22px] py-[15px] max-[680px]:px-3 max-[680px]:py-[11px]',
        className
      )}
      {...props}
    />
  )
}

const detailFieldClassName =
  'grid min-h-[59px] grid-cols-[minmax(90px,0.28fr)_minmax(0,1fr)_repeat(2,34px)] items-center gap-2 border-b border-border py-[9px] pr-3 pl-[15px] last:border-b-0 [&>span]:text-[11px] [&>span]:text-muted-foreground [&>strong]:min-w-0 [&>strong]:truncate [&>strong]:text-xs [&>strong]:font-[590] [&>:nth-child(3):last-child]:col-start-[-2] max-[430px]:grid-cols-[1fr_auto_auto] max-[430px]:gap-1.5 max-[430px]:[&>span]:col-span-full max-[430px]:[&>strong]:col-start-1 max-[430px]:[&>[data-field-copy-value]]:col-start-1'

const titlebarClassName =
  'relative z-20 flex h-[54px] min-h-[54px] select-none items-center gap-3 border-b border-border bg-[color-mix(in_oklch,var(--card)_86%,transparent)] py-0 pr-3.5 pl-[78px] shadow-[inset_0_1px_color-mix(in_oklch,var(--shadow-color)_5%,transparent)] [-webkit-app-region:drag] [-webkit-backdrop-filter:saturate(180%)_blur(24px)] [backdrop-filter:saturate(180%)_blur(24px)] max-[1050px]:pl-[70px] max-[880px]:pl-3.5 max-[680px]:h-[52px] max-[680px]:min-h-[52px] max-[430px]:gap-2 max-[430px]:px-[9px] [.platform-macos_&]:border-b-transparent [.platform-macos_&]:bg-transparent [.platform-macos_&]:pl-[94px] [.platform-macos_&]:shadow-none [.platform-macos_&]:[-webkit-backdrop-filter:none] [.platform-macos_&]:[backdrop-filter:none] max-[880px]:[.platform-macos_&]:pl-[82px] max-[430px]:[.platform-macos_&]:py-0 max-[430px]:[.platform-macos_&]:pr-[9px] max-[430px]:[.platform-macos_&]:pl-[82px] [.platform-windows_&]:border-b-transparent [.platform-windows_&]:bg-transparent [.platform-windows_&]:pl-3.5 [.platform-windows_&]:shadow-none [.platform-windows_&]:[-webkit-backdrop-filter:none] [.platform-windows_&]:[backdrop-filter:none] max-[430px]:[.platform-windows_&]:px-[9px] [.platform-window-controls-overlay_&]:h-[env(titlebar-area-height,54px)] [.platform-window-controls-overlay_&]:min-h-[env(titlebar-area-height,54px)] [.platform-window-controls-overlay_&]:pr-[calc(14px+100vw-env(titlebar-area-x,0px)-env(titlebar-area-width,100vw))] [.platform-window-controls-overlay_&]:pl-[calc(14px+env(titlebar-area-x,0px))] max-[430px]:[.platform-window-controls-overlay_&]:pr-[calc(9px+100vw-env(titlebar-area-x,0px)-env(titlebar-area-width,100vw))] max-[430px]:[.platform-window-controls-overlay_&]:pl-[calc(9px+env(titlebar-area-x,0px))]'

const folderSectionClassName =
  'flex flex-none flex-col [&>header]:flex [&>header]:items-center [&>header]:justify-between [&>header]:pt-0 [&>header]:pr-1.5 [&>header]:pb-1 [&>header]:pl-[9px] [&_h2]:m-0 [&_h2]:text-[10px] [&_h2]:font-[760] [&_h2]:tracking-[0.11em] [&_h2]:text-muted-foreground [&_h2]:uppercase'

function detailIconClassName(type?: VaultItemType): string {
  return cn(
    'outline-foreground/5 bg-muted text-primary dark:border-border dark:bg-muted dark:text-muted-foreground grid size-12 flex-none place-items-center rounded-lg shadow-(--control-highlight) outline max-[430px]:hidden forced-colors:[forced-color-adjust:none]',
    type === 'login' && 'overflow-hidden',
    type === 'card' && 'bg-muted text-chart-4 dark:bg-website-icon-background',
    type === 'identity' && 'bg-accent text-primary',
    type === 'secureNote' && 'bg-muted text-chart-3',
    type === 'sshKey' && 'bg-accent text-chart-2'
  )
}

function describeError(error: unknown): string {
  if (!(error instanceof Error)) return '發生未知錯誤。'
  const messages: Record<string, string> = {
    LOCKED: '密碼庫已鎖定，請重新解鎖。',
    NOT_FOUND: '找不到指定的項目。',
    INVALID_INPUT: '輸入內容無效，請檢查後再試。',
    DUPLICATE_NAME: '名稱已被使用，請換一個名稱。',
    INVALID_URL: '網站網址格式不正確。',
    ATTACHMENT_FAILED: '附件操作失敗；伺服器內容可能已變更，請同步後再試。',
    ATTACHMENT_TOO_LARGE: '附件太大，無法在安全的記憶體上限內完成加密。',
    ATTACHMENT_STORAGE_LIMIT: 'Bitwarden 附件儲存空間不足，請釋出空間後再試。',
    ATTACHMENT_REJECTED: '此伺服器或帳號目前不允許新增這個附件。',
    ATTACHMENT_CANCELED: '附件操作已取消。'
  }
  const code = Object.keys(messages).find((key) => error.message.includes(key))
  return code ? messages[code] : '操作未完成，請重新整理後確認目前狀態。'
}

function isRepromptRequired(error: unknown): boolean {
  return error instanceof Error && error.message.includes('REPROMPT_REQUIRED')
}

const vaultErrorToastId = 'vault-error'

function announceError(message: string): void {
  toast.error(message, {
    id: vaultErrorToastId,
    duration: 7_000
  })
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

function customFieldCopyFeedbackKey(
  itemId: string,
  index: number,
  field: VaultCustomFieldView
): string {
  return JSON.stringify(['custom', itemId, index, field.name, field.type, field.linkedId])
}

function detailFields(login: LoginView): DetailField[] {
  if (login.type === 'login') {
    return [
      { field: 'username', label: '使用者名稱', value: login.username, copyable: true },
      { field: 'password', label: '密碼', secret: true },
      ...login.uris.map((entry, uriIndex) => ({
        field: 'uri' as const,
        label: uriIndex === 0 ? '網站' : `網站 ${uriIndex + 1}`,
        value: entry.uri,
        copyable: true,
        openUri: true,
        uriIndex
      }))
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
  if (cached) cache.set(summary.id, mergeLoginSummary(cached, summary))
}

function mergeLoginSummary(login: LoginView, summary: LoginSummary): LoginView {
  if (summary.reprompt === 0 || summary.deletedAt) return { ...login, ...summary }
  return {
    ...login,
    id: summary.id,
    type: summary.type,
    name: summary.name,
    folderId: summary.folderId,
    favorite: summary.favorite,
    usageCount: summary.usageCount,
    lastUsedAt: summary.lastUsedAt,
    createdAt: summary.createdAt,
    updatedAt: summary.updatedAt,
    deletedAt: summary.deletedAt,
    archivedAt: summary.archivedAt,
    reprompt: summary.reprompt,
    passwordHistoryCount: summary.passwordHistoryCount,
    attachmentCount: summary.attachmentCount
  }
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

function firstAuthorizationToken(
  ids: readonly string[],
  tokenFor: (id: string) => string | undefined
): string | undefined {
  for (const id of ids) {
    const token = tokenFor(id)
    if (token) return token
  }
  return undefined
}

function toLoginSummary(login: LoginView): LoginSummary {
  return {
    id: login.id,
    type: login.type,
    name: login.name,
    subtitle: login.subtitle,
    username: login.username,
    uri: login.uri,
    uris: login.uris.map((entry) => ({ ...entry })),
    ...(login.cardBrand === undefined ? {} : { cardBrand: login.cardBrand }),
    hasTotp: login.hasTotp,
    ...(login.passkeyCount === undefined ? {} : { passkeyCount: login.passkeyCount }),
    passwordHistoryCount: login.passwordHistoryCount,
    attachmentCount: login.attachmentCount,
    folderId: login.folderId,
    favorite: login.favorite,
    usageCount: login.usageCount,
    lastUsedAt: login.lastUsedAt,
    createdAt: login.createdAt,
    updatedAt: login.updatedAt,
    deletedAt: login.deletedAt,
    archivedAt: login.archivedAt,
    reprompt: login.reprompt
  }
}

interface SidebarLinkProps {
  icon: React.ReactNode
  label: string
  count: number
  active: boolean
  variant?: 'row' | 'tile'
  tone?: SidebarTone
  dropTargetId?: string
  onClick: () => void
}

const sidebarToneClasses: Record<SidebarTone, string> = {
  blue: 'bg-sidebar-primary text-sidebar-primary-foreground',
  indigo: 'bg-chart-4 text-primary-foreground',
  green: 'bg-sidebar-primary text-sidebar-primary-foreground',
  yellow: 'bg-chart-1 text-category-light-foreground',
  cyan: 'bg-chart-2 text-primary-foreground',
  red: 'bg-destructive text-destructive-foreground',
  orange: 'bg-chart-3 text-primary-foreground',
  gray: 'bg-muted text-foreground'
}

const sidebarLinkClasses = {
  base: 'h-auto border-none text-left',
  row: 'grid min-h-[38px] grid-cols-[22px_1fr_auto] items-center gap-2 rounded-lg border-0 bg-transparent px-[9px] py-1.5 shadow-[none] hover:shadow-[none]',
  tile: 'bg-sidebar-overlay grid min-h-[72px] grid-cols-[1fr_auto] grid-rows-[31px_auto] items-center gap-2 rounded-[15px] px-3 pt-[11px] pb-2.5 shadow-[var(--sidebar-tile-highlight)] hover:shadow-[var(--sidebar-tile-highlight)]',
  active: {
    row: 'bg-sidebar-overlay-active text-sidebar-foreground hover:bg-sidebar-overlay-active hover:text-sidebar-foreground',
    tile: 'bg-sidebar-primary text-sidebar-primary-foreground shadow-(--control-highlight) hover:bg-sidebar-primary hover:text-sidebar-primary-foreground hover:shadow-(--control-highlight)'
  }
} as const

function SidebarLink({
  icon,
  label,
  count,
  active,
  variant = 'row',
  tone,
  dropTargetId,
  onClick
}: SidebarLinkProps): React.JSX.Element {
  const isTile = variant === 'tile'
  const { setNodeRef, isOver } = useDroppable({
    id: dropTargetId ?? `sidebar-link:${label}`,
    disabled: dropTargetId === undefined
  })

  return (
    <Button
      ref={dropTargetId ? setNodeRef : undefined}
      variant="sidebar"
      className={cn(
        sidebarLinkClasses.base,
        sidebarLinkClasses[variant],
        active && sidebarLinkClasses.active[variant],
        isOver &&
          'bg-sidebar-overlay-active text-sidebar-foreground ring-sidebar-ring hover:bg-sidebar-overlay-active hover:text-sidebar-foreground ring-2'
      )}
      type="button"
      aria-current={active ? 'page' : undefined}
      data-sidebar-active={active ? '' : undefined}
      onClick={onClick}
    >
      <span
        className={cn(
          'grid place-items-center',
          isTile
            ? [
                'bg-sidebar-primary text-sidebar-primary-foreground col-start-1 row-start-1 size-[30px] rounded-full',
                tone && sidebarToneClasses[tone],
                active && 'bg-sidebar-primary-foreground text-sidebar-primary'
              ]
            : 'size-[22px]'
        )}
        aria-hidden="true"
      >
        {icon}
      </span>
      <strong
        className={cn(
          isTile
            ? 'col-span-2 row-start-2 self-end text-[13px] leading-[1.15] font-[720]'
            : 'text-xs font-[610]'
        )}
      >
        {label}
      </strong>
      <small
        className={cn(
          'text-muted-foreground group-hover/button:text-sidebar-foreground',
          isTile
            ? 'col-start-2 row-start-1 self-center justify-self-end text-[11px] font-[650]'
            : 'text-[10px]',
          active &&
            isTile &&
            'text-[color-mix(in_oklch,var(--sidebar-primary-foreground)_88%,transparent)] group-hover/button:text-[color-mix(in_oklch,var(--sidebar-primary-foreground)_88%,transparent)]'
        )}
      >
        {count}
      </small>
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
      className={cn(
        'text-foreground hover:bg-sidebar-overlay-hover static grid min-h-9 grid-cols-[22px_minmax(0,1fr)_25px] items-center rounded-lg',
        selected && 'bg-sidebar-overlay-active shadow-none',
        isOver &&
          'bg-sidebar-overlay-active text-foreground shadow-[inset_0_0_0_1px_color-mix(in_oklch,var(--sidebar-primary)_55%,transparent)] forced-colors:outline-2 forced-colors:-outline-offset-2 forced-colors:outline-[Highlight]'
      )}
    >
      <span className="w-[22px]" aria-hidden="true" />
      <Button
        variant="sidebar"
        className="[&>small]:text-muted-foreground grid h-[34px] min-w-0 grid-cols-[21px_minmax(0,1fr)_auto] items-center gap-1 border-0 bg-transparent p-0 text-left text-inherit shadow-none hover:bg-transparent hover:shadow-none aria-expanded:bg-transparent aria-expanded:shadow-none [&>small]:min-w-[3ch] [&>small]:pr-1 [&>small]:text-right [&>small]:text-[10px] [&>small]:tabular-nums [&>span]:truncate [&>span]:text-xs"
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
    <article
      className="flex size-full min-h-0 min-w-0 flex-col motion-reduce:[&_[data-slot=skeleton]]:animate-none"
      aria-busy="true"
    >
      <DetailHeader>
        <TooltipIconButton
          variant="outline"
          size="icon"
          className="hidden max-[680px]:grid"
          data-detail-back=""
          type="button"
          label="返回項目列表"
          onClick={onBack}
        >
          <ArrowLeft />
        </TooltipIconButton>
        <span className={detailIconClassName(item.type)} data-detail-icon="" aria-hidden="true">
          {item.type === 'login' ? (
            <WebsiteIcon id={item.id} uri={item.uri} enabled={showWebsiteIcons} />
          ) : item.type === 'card' ? (
            <PaymentCardBrandMark brand={normalizeBitwardenCardBrand(item.cardBrand)} compact />
          ) : (
            <TypeIcon size={23} />
          )}
        </span>
        <div className="[&>span]:text-muted-foreground min-w-0 flex-1 [&>h2]:m-0 [&>h2]:truncate [&>h2]:text-xl [&>h2]:tracking-[-0.025em] [&>span]:mt-[3px] [&>span]:block [&>span]:truncate [&>span]:text-[10px]">
          <h2>{item.name}</h2>
          <span>
            {item.subtitle || (item.type === 'login' ? hostLabel(item.uri) : '安全保管的項目')}
          </span>
        </div>
        <Skeleton className="size-[34px] flex-none rounded-[9px]" aria-hidden="true" />
        <Skeleton
          className="h-8 w-[68px] flex-none rounded-lg max-[680px]:w-[34px]"
          aria-hidden="true"
        />
        <span className="sr-only" role="status">
          正在載入項目詳細資料…
        </span>
      </DetailHeader>

      <div
        className="min-h-0 flex-1 [scrollbar-color:var(--border-strong)_transparent] overflow-auto px-5 pt-5 pb-10 max-[680px]:px-3 max-[680px]:pt-[13px] max-[680px]:pb-7"
        aria-hidden="true"
      >
        <DetailCard variant="placeholder">
          <CardHeader className="bg-muted rounded-none border-b">
            <Skeleton className="h-3 w-20" />
          </CardHeader>
          <CardContent className="contents">
            {[0, 1, 2].map((row) => (
              <div className={detailFieldClassName} key={row}>
                <Skeleton className="h-3 w-16" />
                <Skeleton className={cn('h-4', row === 1 ? 'w-2/3' : 'w-1/2')} />
                <Skeleton className="size-8" />
              </div>
            ))}
          </CardContent>
        </DetailCard>
        <DetailCard variant="placeholder">
          <CardHeader className="bg-muted rounded-none border-b">
            <Skeleton className="h-3 w-24" />
          </CardHeader>
          <CardContent className="contents">
            {[0, 1].map((row) => (
              <div className={detailFieldClassName} key={row}>
                <Skeleton className="h-3 w-14" />
                <Skeleton className="h-4 w-1/3" />
                <span />
              </div>
            ))}
          </CardContent>
        </DetailCard>
      </div>
    </article>
  )
}

function VaultShell({
  onLocked,
  promptSyncSetup,
  onSyncSetupPromptHandled
}: VaultShellProps): React.JSX.Element {
  const [folders, setFolders] = useState<FolderView[]>([])
  const [items, setItems] = useState<LoginSummary[]>([])
  const [scope, setScope] = useState<Scope>({ kind: 'all' })
  const [sortMode, setSortMode] = useState<VaultSortMode>('title')
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('all')
  const [query, setQuery] = useState('')
  const [searchMatches, setSearchMatches] = useState<VaultSearchMatches | null>(null)
  const [searchOpen, setSearchOpen] = useState(false)
  const [selectedIds, setSelectedIds] = useState<ReadonlySet<string>>(() => new Set())
  const [selectedId, setSelectedId] = useState<string | null>(null)
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
  const totpCode =
    selectedLogin && totpCodeState?.itemId === selectedLogin.id ? totpCodeState.code : null
  const totpGenerationError =
    selectedLogin && totpGenerationErrorState?.itemId === selectedLogin.id
      ? totpGenerationErrorState.kind
      : null
  const totpRevealReady = totpCode !== null || totpGenerationError !== null
  const [showTotpSkeleton, setShowTotpSkeleton] = useState(false)
  const [editorMode, setEditorMode] = useState<'create' | 'edit' | null>(null)
  const totpRefreshTarget = resolveTotpRefreshTarget(selectedLogin, selectedId, editorMode !== null)
  const [editorSessionId, setEditorSessionId] = useState(0)
  const [editorDirty, setEditorDirty] = useState(false)
  const [discardEditorDialogOpen, setDiscardEditorDialogOpen] = useState(false)
  const [revealedSecrets, setRevealedSecrets] = useState<RevealedSecretsState>(emptyRevealedSecrets)
  const [revealedCustomFields, setRevealedCustomFields] =
    useState<RevealedCustomFieldsState>(emptyRevealedCustomFields)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [folderDialog, setFolderDialog] = useState<FolderView | 'new' | null>(null)
  const [moveSnapshot, setMoveSnapshot] = useState<MoveSnapshot | null>(null)
  const [pendingBulkAction, setPendingBulkAction] = useState<BulkActionSnapshot | null>(null)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [emptyTrashDialogOpen, setEmptyTrashDialogOpen] = useState(false)
  const [passwordHistoryDialogOpen, setPasswordHistoryDialogOpen] = useState(false)
  const [passwordZoomValue, setPasswordZoomValue] = useState<string | null>(null)
  const passwordHoveringRef = useRef(false)
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
  const [syncStatus, setSyncStatus] = useState<SyncStatus>(initialSyncStatus)
  const [syncStatusLoaded, setSyncStatusLoaded] = useState(false)
  const showSyncSetupPrompt = shouldShowSyncSetupPrompt(promptSyncSetup, syncStatusLoaded)
  const [accountProfileRefreshRevision, setAccountProfileRefreshRevision] = useState(0)
  const [sidebarAccountProfile, setSidebarAccountProfile] = useState<{
    owner: string
    profile: AccountSecurityProfile | null
  }>({ owner: '', profile: null })
  const SyncSidebarIcon = syncStateMeta[syncStatus.state].icon
  const [settings, setSettings] = useState<AppSettings | null>(null)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [accountStatus, setAccountStatus] = useState<AccountStatus | null>(null)
  const [accountBusy, setAccountBusy] = useState(false)
  const [accountBusyLabel, setAccountBusyLabel] = useState('')
  const [accountError, setAccountError] = useState('')
  const [healthOpen, setHealthOpen] = useState(false)
  const [sendsOpen, setSendsOpen] = useState(false)
  const [organizationsOpen, setOrganizationsOpen] = useState(false)
  const [emergencyAccessOpen, setEmergencyAccessOpen] = useState(false)
  const [settingsBusy, setSettingsBusy] = useState(false)
  const [touchIdPassword, setTouchIdPassword] = useState('')
  const [portabilityDialogMode, setPortabilityDialogMode] = useState<VaultPortabilityMode | null>(
    null
  )
  const [activeDragId, setActiveDragId] = useState<string | null>(null)
  const [activeDragOverId, setActiveDragOverId] = useState<string | null>(null)
  const foldersBeforeDragRef = useRef<FolderView[] | null>(null)
  const foldersRef = useRef(folders)
  foldersRef.current = folders
  const searchRef = useRef<HTMLInputElement>(null)
  const queryRef = useRef(query)
  const searchRequestIdRef = useRef(0)
  const updateQuery = useCallback((value: string): void => {
    const bounded = boundedVaultSearchQuery(value)
    queryRef.current = bounded
    setQuery(bounded)
  }, [])
  const sidebarMenuTriggerRef = useRef<HTMLButtonElement>(null)
  const settingsReturnFocusRef = useRef<HTMLElement | null>(null)
  const accountStatusRequestRef = useRef(0)
  const accountMutationRequestRef = useRef(0)
  const accountMutationGateRef = useRef(new AccountMutationGate())
  const accountStaleRefreshPendingRef = useRef(false)
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
  const editorDirtyRef = useRef(false)
  const editorTransitionApprovedRef = useRef(false)
  const pendingEditorActionRef = useRef<(() => void) | null>(null)
  const attachmentOperationRef = useRef<AttachmentOperationState | null>(null)

  const handleEditorDirtyChange = useCallback((dirty: boolean): void => {
    editorDirtyRef.current = dirty
    setEditorDirty(dirty)
  }, [])

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
    []
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
  }, [])

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
    setPasswordHistoryDialogOpen(false)
  }, [updateSelectedIds])

  const clearDetailCache = useCallback((): void => {
    detailCacheGenerationRef.current += 1
    detailRequestsRef.current.clear()
    detailPrefetchRequestsRef.current.clear()
    detailPrefetchQueueRef.current.clear()
    detailCacheRef.current.clear()
  }, [])

  const authorizationToken = useCallback((id: string): string | undefined => {
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
  }, [])

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
        editorDirtyRef.current = false
        setEditorDirty(false)
        setTotpCodeState(null)
        setRevealedSecrets(emptyRevealedSecrets)
        setRevealedCustomFields(emptyRevealedCustomFields)
      }
    },
    [authorizationToken]
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
    [discardAuthorizationToken]
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
            ? (item?.name ?? '這個項目')
            : `${normalizedIds.length} 個受保護項目`
      })
      return promise
    },
    [authorizationToken]
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
        announceError(describeError(loadError))
      }
    } finally {
      if (isCurrentVaultLoad(requestId, vaultLoadRequestIdRef.current)) setLoading(false)
    }
  }, [clearDetailCache, invalidateProtectedDetails])

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
    [authorizationToken, requestEditorTransition]
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
      ).catch((menuError) => announceError(describeError(menuError)))
    },
    [withReprompt]
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
  }, [invalidateProtectedDetails])

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
    if (editorDirtyRef.current) {
      requestEditorTransition(() => void applyRefresh())
      return
    }
    await applyRefresh()
  }, [clearItemSelection, loadVault, requestEditorTransition])

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
    const unsubscribe = window.bearwarden.vault.onChanged(() => {
      void loadVault()
    })
    return unsubscribe
  }, [loadVault])

  useEffect(() => {
    let active = true
    void window.bearwarden.sync.status().then(
      (status) => {
        if (active) {
          setSyncStatus(status)
          setSyncStatusLoaded(true)
        }
      },
      () => {
        // A missing sync service should not prevent the local vault from being usable.
      }
    )
    const unsubscribe = window.bearwarden.sync.onChanged((status) => {
      if (active) {
        setSyncStatus(status)
        setSyncStatusLoaded(true)
      }
    })
    return () => {
      active = false
      unsubscribe()
    }
  }, [])

  const syncAccountIdentity = `${syncStatus.serverUrl ?? ''}\0${syncStatus.email?.toLowerCase() ?? ''}`
  const visibleSidebarAccountProfile =
    sidebarAccountProfile.owner === syncAccountIdentity ? sidebarAccountProfile.profile : null
  const sidebarAccountName =
    visibleSidebarAccountProfile?.name.trim() ||
    (syncStatus.configured ? '已連線帳號' : '本機密碼庫')

  useEffect(() => {
    let active = true
    if (syncStatus.state === 'ready') {
      void window.bearwarden.accountSecurity.profile().then(
        (profile) => {
          if (active) setSidebarAccountProfile({ owner: syncAccountIdentity, profile })
        },
        () => {
          // The footer stays usable when the remote profile is temporarily unavailable.
        }
      )
    }
    return () => {
      active = false
    }
  }, [accountProfileRefreshRevision, syncAccountIdentity, syncStatus.state])

  useEffect(() => {
    let active = true
    void window.bearwarden.settings.get().then(
      (nextSettings) => {
        if (!active) return
        setSettings(nextSettings)
        setSortMode(nextSettings.defaultSort === 'name' ? 'title' : nextSettings.defaultSort)
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
        announceError(describeError(detailError))
        clearItemSelection()
      })
    return () => {
      active = false
    }
  }, [clearItemSelection, items, loadLoginDetail, selectedId])

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
              announceError('授權已過期，請重新選取項目並驗證主密碼')
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
    passwordHoveringRef.current = false
    passwordZoomOpenRef.current = false
    setPasswordZoomValue(null)
  }, [selectedLogin?.id])

  useEffect(() => {
    if (Object.keys(revealedCustomFields.values).length === 0) return
    const timeout = window.setTimeout(
      () => setRevealedCustomFields(emptyRevealedCustomFields),
      30_000
    )
    return () => window.clearTimeout(timeout)
  }, [revealedCustomFields])

  useEffect(() => {
    const searchQuery = normalizedVaultSearchQuery(query)
    const requestId = ++searchRequestIdRef.current
    if (!searchQuery) return

    const timeout = window.setTimeout(() => {
      const [activeRequest, archivedRequest, deletedRequest] = vaultSearchListRequests(searchQuery)
      void Promise.all([
        window.bearwarden.logins.list(activeRequest),
        window.bearwarden.logins.list(archivedRequest),
        window.bearwarden.logins.list(deletedRequest)
      ]).then(
        ([activeItems, archivedItems, deletedItems]) => {
          if (
            !isCurrentVaultSearchResponse({
              requestId,
              currentRequestId: searchRequestIdRef.current,
              query: searchQuery,
              currentQuery: queryRef.current
            })
          ) {
            return
          }
          setSearchMatches({
            query: searchQuery,
            ids: new Set([...activeItems, ...archivedItems, ...deletedItems].map((item) => item.id))
          })
        },
        (searchError) => {
          if (
            !isCurrentVaultSearchResponse({
              requestId,
              currentRequestId: searchRequestIdRef.current,
              query: searchQuery,
              currentQuery: queryRef.current
            })
          ) {
            return
          }
          setSearchMatches({ query: searchQuery, ids: new Set() })
          announceError(describeError(searchError))
        }
      )
    }, VAULT_SEARCH_DEBOUNCE_MS)

    return () => window.clearTimeout(timeout)
  }, [items, query])

  const scopedItems = useMemo(() => {
    const matchedItems = filterVaultSearchMatches(items, query, searchMatches)
    const scoped = matchedItems.filter((item) =>
      matchesVaultSearchNavigation(item, query, scope, typeFilter)
    )
    return sortVaultItems(scoped, scope.kind === 'recent' ? 'recent' : sortMode)
  }, [items, query, scope, searchMatches, sortMode, typeFilter])
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
  }, [busy, scope.kind])
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
      }) ?? '放開以取消移動')
    : null
  const selectedDetailFields = useMemo(
    () => (selectedLogin ? detailFields(selectedLogin) : []),
    [selectedLogin]
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
  }, [activeItems])
  const healthRevision = useMemo(() => vaultHealthRevision(items), [items])

  const scopeTitle = useMemo(() => {
    if (scope.kind === 'favorites') return '常用項目'
    if (scope.kind === 'recent') return '最近使用'
    if (scope.kind === 'unfiled') return '未分類'
    if (scope.kind === 'archive') return '封存'
    if (scope.kind === 'trash') return '垃圾桶'
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
    cancelAndClearAttachmentOperation()
    clearDetailCache()
    setRevealedSecrets(emptyRevealedSecrets)
    setRevealedCustomFields(emptyRevealedCustomFields)
    setTouchIdPassword('')
    setSelectedLogin(null)
    try {
      const status = await window.bearwarden.vault.lock()
      if (status.state === 'locked') onLocked()
      else announceError('密碼庫尚未鎖定，請再試一次。')
    } catch (lockError) {
      announceError(describeError(lockError))
    }
  }, [cancelAndClearAttachmentOperation, clearDetailCache, onLocked])

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
  }, [searchOpen])

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
    if (accountStaleRefreshPendingRef.current) {
      accountStaleRefreshPendingRef.current = false
      accountMutationGateRef.current.leave()
      setAccountBusy(false)
      setAccountBusyLabel('')
    }
    let active = true
    const requestId = ++accountStatusRequestRef.current
    queueMicrotask(() => {
      if (!active) return
      setAccountStatus(null)
      setAccountError('')
      void window.bearwarden.accounts.status().then(
        (status) => {
          if (active && requestId === accountStatusRequestRef.current) setAccountStatus(status)
        },
        () => {
          if (active && requestId === accountStatusRequestRef.current) {
            setAccountError('無法讀取本機帳號清單，請稍後再試。')
          }
        }
      )
    })
    return () => {
      active = false
    }
  }, [settingsOpen])

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
      setHealthOpen(false)
      setSendsOpen(false)
      setOrganizationsOpen(false)
      setEmergencyAccessOpen(false)
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
      setSettingsOpen(false)
      setSendsOpen(false)
      setOrganizationsOpen(false)
      setEmergencyAccessOpen(false)
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
      setSettingsOpen(false)
      setHealthOpen(false)
      setOrganizationsOpen(false)
      setEmergencyAccessOpen(false)
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
      setSettingsOpen(false)
      setHealthOpen(false)
      setSendsOpen(false)
      setEmergencyAccessOpen(false)
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
      setSettingsOpen(false)
      setHealthOpen(false)
      setSendsOpen(false)
      setOrganizationsOpen(false)
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

  async function updateSettings(update: AppSettingsUpdate): Promise<void> {
    setSettingsBusy(true)
    try {
      const next = await window.bearwarden.settings.update(update)
      setSettings(next)
      if (update.defaultSort) {
        setSortMode(update.defaultSort === 'name' ? 'title' : update.defaultSort)
      }
      announce('設定已儲存。')
    } catch (settingsError) {
      announceError(describeError(settingsError))
    } finally {
      setSettingsBusy(false)
    }
  }

  async function enableTouchId(): Promise<void> {
    if (!touchIdPassword) {
      announceError('請先輸入主密碼以啟用生物辨識。')
      return
    }
    setSettingsBusy(true)
    try {
      const next = await window.bearwarden.settings.enableTouchId({
        masterPassword: touchIdPassword
      })
      setSettings(next)
      setTouchIdPassword('')
      announce('生物辨識已啟用。')
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
      announce('生物辨識已停用。')
    } catch (touchIdError) {
      announceError(describeError(touchIdError))
    } finally {
      setSettingsBusy(false)
    }
  }

  async function runAccountMutation(
    operation: 'add' | 'switch' | 'reorder' | 'remove',
    mutation: () => Promise<AccountMutationResult>
  ): Promise<void> {
    if (!accountMutationGateRef.current.tryEnter()) return
    accountStatusRequestRef.current += 1
    const mutationRequestId = ++accountMutationRequestRef.current
    setAccountBusy(true)
    setAccountBusyLabel(
      operation === 'add' || operation === 'switch'
        ? '正在安全切換並重新啟動'
        : operation === 'remove'
          ? '正在安全移除本機帳號'
          : '正在更新本機帳號順序'
    )
    setAccountError('')
    try {
      const result = await mutation()
      if (mutationRequestId !== accountMutationRequestRef.current) return
      accountStatusRequestRef.current += 1
      setAccountStatus(result.status)
      if (!accountMutationKeepsBusy(result)) {
        accountMutationGateRef.current.leave()
        setAccountBusy(false)
        setAccountBusyLabel('')
        if (operation === 'remove') {
          announce(
            result.kind === 'updated' && result.cleanupPending
              ? '本機帳號已移除；剩餘的加密本機資料會在下次啟動時再次安全清理。'
              : '本機帳號與這台裝置上的資料已移除。'
          )
        } else if (operation === 'reorder' && result.kind === 'updated') {
          announce('本機帳號順序已更新。')
        }
      }
    } catch (accountMutationFailure) {
      if (mutationRequestId !== accountMutationRequestRef.current) return
      const message = accountMutationError(accountMutationFailure)
      setAccountError(message)
      if (
        accountMutationFailure instanceof Error &&
        accountMutationFailure.message.includes('ACCOUNT_STALE_STATE')
      ) {
        const statusRequestId = ++accountStatusRequestRef.current
        accountStaleRefreshPendingRef.current = true
        setAccountBusy(true)
        setAccountBusyLabel('正在重新讀取本機帳號')
        void window.bearwarden.accounts.status().then(
          (status) => {
            if (
              !isCurrentAccountRefresh(
                mutationRequestId,
                accountMutationRequestRef.current,
                statusRequestId,
                accountStatusRequestRef.current
              )
            )
              return
            accountStaleRefreshPendingRef.current = false
            setAccountStatus(status)
            accountMutationGateRef.current.leave()
            setAccountBusy(false)
            setAccountBusyLabel('')
          },
          () => {
            if (
              !isCurrentAccountRefresh(
                mutationRequestId,
                accountMutationRequestRef.current,
                statusRequestId,
                accountStatusRequestRef.current
              )
            )
              return
            accountStaleRefreshPendingRef.current = false
            setAccountError(`${message} 無法重新讀取清單，請關閉設定後再試。`)
            accountMutationGateRef.current.leave()
            setAccountBusy(false)
            setAccountBusyLabel('')
          }
        )
        return
      }
      accountMutationGateRef.current.leave()
      setAccountBusy(false)
      setAccountBusyLabel('')
    }
  }

  async function addLocalAccount(): Promise<void> {
    await runAccountMutation('add', () => window.bearwarden.accounts.add())
  }

  async function switchLocalAccount(accountId: string): Promise<void> {
    await runAccountMutation('switch', () => window.bearwarden.accounts.switch(accountId))
  }

  async function reorderLocalAccounts(
    accountIds: readonly string[],
    expectedRevision: number
  ): Promise<void> {
    await runAccountMutation('reorder', () =>
      window.bearwarden.accounts.reorder(accountIds, expectedRevision)
    )
  }

  async function removeLocalAccount(accountId: string): Promise<void> {
    await runAccountMutation('remove', () => window.bearwarden.accounts.remove(accountId, true))
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
        announce(updated.favorite ? '已加入常用項目。' : '已從常用項目移除。')
      } catch (favoriteError) {
        announceError(describeError(favoriteError))
      }
    },
    [announce, withReprompt]
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
      announceError('請先選取要處理的項目。')
      return false
    }
    if (snapshot.ids.length > MAX_LOGIN_BATCH_IDS) {
      announceError(`一次最多可處理 ${MAX_LOGIN_BATCH_IDS} 個項目。`)
      return false
    }
    if (!revalidateBulkSelection(snapshot.ids, snapshot.state)) {
      announceError('選取的項目已變更，未執行任何操作。請重新選取後再試。')
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
        announceError(describeError(bulkError))
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
          ? `已封存 ${affectedCount} 個項目。`
          : snapshot.action === 'unarchive'
            ? `已取消封存 ${affectedCount} 個項目。`
            : snapshot.action === 'delete'
              ? `已將 ${affectedCount} 個項目移至垃圾桶。`
              : snapshot.action === 'restore'
                ? `已還原 ${affectedCount} 個項目。`
                : `已永久刪除 ${affectedCount} 個項目。`
      try {
        await refreshItems()
      } catch {
        toast.warning(`${message.slice(0, -1)}，但清單重新整理失敗，請稍後重試。`)
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
      announceError('選取的項目已變更，未執行任何操作。請重新選取後再試。')
      return false
    }
    const movable = previous.filter((item) => item.folderId !== folderId)
    if (movable.length === 0) {
      return true
    }
    if (movable.length > MAX_LOGIN_MOVE_MANY_IDS) {
      announceError(`一次最多可移動 ${MAX_LOGIN_MOVE_MANY_IDS} 個項目。`)
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
      const destination = folders.find((folder) => folder.id === folderId)?.name ?? '未分類'
      announce(
        updated.length > 1
          ? `已將 ${updated.length} 個項目移至「${destination}」。`
          : `已移至「${destination}」。`
      )
      return true
    } catch (moveError) {
      const previousById = new Map(previous.map((item) => [item.id, item]))
      for (const item of previous) mergeCachedSummary(detailCacheRef.current, item)
      setItems((current) => current.map((item) => previousById.get(item.id) ?? item))
      announceError(describeError(moveError))
      return false
    } finally {
      setBusy(false)
    }
  }

  async function addLoginsToFavorites(snapshot: MoveSnapshot): Promise<boolean> {
    if (busy) return false
    const previous = revalidateBulkSelection(snapshot.ids, snapshot.state)
    if (!previous) {
      announceError('選取的項目已變更，未執行任何操作。請重新選取後再試。')
      return false
    }
    const itemsToUpdate = previous.filter((item) => !item.favorite)
    if (itemsToUpdate.length === 0) return true
    if (itemsToUpdate.length > MAX_LOGIN_BATCH_IDS) {
      announceError(`一次最多可處理 ${MAX_LOGIN_BATCH_IDS} 個項目。`)
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
        updated.length > 1 ? `已將 ${updated.length} 個項目加入常用項目。` : '已加入常用項目。'
      )
      return true
    } catch (favoriteError) {
      await refreshItems().catch(() => undefined)
      announceError(describeError(favoriteError))
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
      announce(`已刪除資料夾「${folderDialog.name}」，其中項目已移至未分類。`)
      setFolderDialog(null)
    } catch (folderError) {
      announceError(describeError(folderError))
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
        uris: draft.uris.map((entry) => ({ ...entry })),
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
        announce(`已建立「${created.name}」。`)
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
        announce(`已儲存「${updated.name}」。`)
      }
      setRevealedCustomFields(emptyRevealedCustomFields)
      editorDirtyRef.current = false
      setEditorDirty(false)
      setEditorMode(null)
      return true
    } catch (saveError) {
      announceError(describeError(saveError))
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
      announce('已刪除通行密鑰。')
      return updated
    } catch (deleteError) {
      announceError(describeError(deleteError))
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
      announce(`已建立「${cloned.name}」。`)
    } catch (cloneError) {
      announceError(describeError(cloneError))
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
      announce(`已封存「${archived.name}」。`)
    } catch (archiveError) {
      announceError(describeError(archiveError))
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
      announce(`已取消封存「${restored.name}」。`)
    } catch (unarchiveError) {
      announceError(describeError(unarchiveError))
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
      announce(selectedSummary.deletedAt ? '項目已永久刪除。' : '項目已移至垃圾桶。')
    } catch (deleteError) {
      announceError(describeError(deleteError))
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
      announce(`已還原「${restored.name}」。`)
    } catch (restoreError) {
      announceError(describeError(restoreError))
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
      announce(count === 1 ? '已永久刪除 1 個項目。' : `已永久刪除 ${count} 個項目。`)
    } catch (emptyError) {
      announceError(describeError(emptyError))
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
        field === 'password' &&
        options.quiet &&
        !passwordHoveringRef.current &&
        !passwordZoomOpenRef.current
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
        announce(`${field === 'privateKey' ? '私鑰' : '敏感資料'}已顯示，將在 30 秒後自動隱藏。`)
      }
      return value
    } catch (revealError) {
      announceError(describeError(revealError))
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
    passwordZoomOpenRef.current = true
    const value = await revealSecret('password', { quiet: true, forceShow: true })
    if (value === undefined) {
      passwordZoomOpenRef.current = false
      return
    }
    setPasswordZoomValue(value)
  }

  function closePasswordZoom(): void {
    passwordZoomOpenRef.current = false
    setPasswordZoomValue(null)
    if (!passwordHoveringRef.current) hideRevealedSecret('password')
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
      announce('隱藏欄位已顯示，將在 30 秒後自動隱藏。')
    } catch (revealError) {
      announceError(describeError(revealError))
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
      announceError(describeError(copyError))
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
        announce(`已下載「${result.fileName}」。`)
      }
      if (!result.canceled) {
        await refreshItems().catch(() =>
          announceError('附件已下載，但無法重新整理清單；請稍後再同步。')
        )
      }
    } catch (downloadError) {
      if (
        isCurrentAttachmentOperation(operationId, itemId) &&
        !isAttachmentCanceled(downloadError)
      ) {
        announceError(describeError(downloadError))
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
          announce(`已上傳「${result.attachment.fileName}」。`)
        }
        await refreshItems().catch(() =>
          announceError('附件已上傳，但無法重新整理清單；請稍後再同步。')
        )
      }
    } catch (uploadError) {
      if (isCurrentAttachmentOperation(operationId, itemId) && !isAttachmentCanceled(uploadError)) {
        announceError(describeError(uploadError))
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
      if (selectedIdRef.current === target.itemId) announce(`已刪除「${target.fileName}」。`)
      await refreshItems().catch(() =>
        announceError('附件已刪除，但無法重新整理清單；請稍後再同步。')
      )
    } catch (deleteError) {
      if (
        isCurrentAttachmentOperation(operationId, target.itemId) &&
        !isAttachmentCanceled(deleteError)
      ) {
        announceError(describeError(deleteError))
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
      if (selectedIdRef.current === itemId) announce(`已修復「${attachment.fileName}」。`)
      await refreshItems().catch(() =>
        announceError('附件已修復，但無法重新整理清單；請稍後再同步。')
      )
    } catch (fixError) {
      if (isCurrentAttachmentOperation(operationId, itemId) && !isAttachmentCanceled(fixError)) {
        announceError(describeError(fixError))
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
        announceError(describeError(cancelError))
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
      announceError(describeError(copyError))
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
      announce('已開啟網站。')
      await refreshItems()
    } catch (openError) {
      announceError(describeError(openError))
    }
  }

  function startDrag(event: DragStartEvent): void {
    const activeId = String(event.active.id)
    if (itemIds.has(activeId) && !selectedIdsRef.current.has(activeId)) selectLogin(activeId)
    foldersBeforeDragRef.current = folderIds.has(activeId) ? foldersRef.current : null
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
      return arrayMove(previous, oldIndex, newIndex).map((folder, position) => ({
        ...folder,
        position
      }))
    })
  }

  function cancelDrag(): void {
    const previousFolders = foldersBeforeDragRef.current
    foldersBeforeDragRef.current = null
    if (previousFolders) setFolders(previousFolders)
    setActiveDragId(null)
    setActiveDragOverId(null)
  }

  async function endDrag(event: DragEndEvent): Promise<void> {
    const previousFolders = foldersBeforeDragRef.current
    foldersBeforeDragRef.current = null
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
    const reordered = foldersRef.current
    const orderedIds = reordered.map((folder) => folder.id)
    if (orderedIds.every((id, index) => id === previousFolders[index]?.id)) return
    try {
      const saved = await window.bearwarden.folders.reorder({ orderedIds })
      setFolders([...saved].sort((left, right) => left.position - right.position))
      announce('資料夾順序已更新。')
    } catch (reorderError) {
      setFolders(previousFolders)
      announceError(describeError(reorderError))
    }
  }

  function renderDetailField(field: DetailField): React.JSX.Element {
    const secretField = field.field as VaultSecretField
    const isPasswordField = field.field === 'password'
    const revealedValue =
      field.secret && revealedSecrets.itemId === selectedLogin?.id
        ? revealedSecrets.values[secretField]
        : undefined
    const hasExtraAction = Boolean(field.copyable) && Boolean(field.openUri)
    const canCopyFromValue = field.field === 'username' || field.field === 'password'
    const copyKey = `field:${selectedSummary?.id}:${field.field}:${field.uriIndex ?? ''}`
    const valueClassName = field.secret
      ? revealedValue === undefined
        ? 'tracking-[0.13em]'
        : isPasswordField
          ? 'min-w-0 select-text'
          : 'font-mono select-text'
      : undefined
    const displayValue =
      field.secret && revealedValue !== undefined && isPasswordField ? (
        revealedValue ? (
          <ColoredPassword value={revealedValue} className="text-xs font-[590]" />
        ) : (
          '未設定'
        )
      ) : field.secret ? (
        revealedValue === undefined ? (
          field.field === 'code' ? (
            '•••'
          ) : (
            '••••••••••••'
          )
        ) : field.field === 'number' ? (
          formatPaymentCardNumber(revealedValue) || '未設定'
        ) : (
          revealedValue || '未設定'
        )
      ) : (
        field.value || '未設定'
      )
    const value = <strong className={valueClassName}>{displayValue}</strong>
    const passwordHoverHandlers = isPasswordField
      ? {
          onMouseEnter: () => {
            passwordHoveringRef.current = true
            void revealSecret('password', { quiet: true, forceShow: true })
          },
          onMouseLeave: () => {
            passwordHoveringRef.current = false
            if (passwordZoomOpenRef.current) return
            hideRevealedSecret('password')
          }
        }
      : undefined
    return (
      <div
        className={cn(
          detailFieldClassName,
          !field.secret && !hasExtraAction && 'max-[430px]:grid-cols-[1fr_auto]'
        )}
        key={`${field.label}:${field.field}:${field.uriIndex ?? ''}`}
      >
        <span>{field.label}</span>
        {canCopyFromValue ? (
          <Button
            variant="ghost"
            size="sm"
            className="-ml-2 w-[calc(100%+8px)] min-w-0 justify-start overflow-hidden px-2 [&>strong]:min-w-0 [&>strong]:truncate [&>strong]:text-xs [&>strong]:font-[590]"
            data-field-copy-value=""
            type="button"
            aria-label={copiedKey === copyKey ? `${field.label}已複製` : `複製${field.label}`}
            disabled={field.field === 'username' && !field.value}
            onClick={() => void copyField(field.field)}
            {...passwordHoverHandlers}
          >
            {value}
          </Button>
        ) : (
          value
        )}
        {field.secret ? (
          <>
            {isPasswordField ? (
              <TooltipIconButton
                variant="outline"
                size="icon"
                type="button"
                label="放大顯示密碼"
                onClick={() => void openPasswordZoom()}
              >
                <ZoomIn />
              </TooltipIconButton>
            ) : (
              <TooltipIconButton
                variant="outline"
                size="icon"
                type="button"
                label={revealedValue === undefined ? `顯示${field.label}` : `隱藏${field.label}`}
                aria-pressed={revealedValue !== undefined}
                onClick={() => void revealSecret(secretField)}
              >
                {revealedValue === undefined ? <Eye /> : <EyeOff />}
              </TooltipIconButton>
            )}
            <TooltipIconButton
              variant="outline"
              size="icon"
              type="button"
              label={copiedKey === copyKey ? `${field.label}已複製` : `複製${field.label}`}
              onClick={() => void copyField(field.field)}
            >
              <CopyFeedbackIcon copied={copiedKey === copyKey} />
            </TooltipIconButton>
          </>
        ) : (
          <>
            {field.copyable && (
              <TooltipIconButton
                variant="outline"
                size="icon"
                type="button"
                label={
                  copiedKey ===
                  `field:${selectedSummary?.id}:${field.field}:${field.uriIndex ?? ''}`
                    ? `${field.label}已複製`
                    : `複製${field.label}`
                }
                disabled={!field.value}
                onClick={() => void copyField(field.field, field.uriIndex)}
              >
                <CopyFeedbackIcon
                  copied={
                    copiedKey ===
                    `field:${selectedSummary?.id}:${field.field}:${field.uriIndex ?? ''}`
                  }
                />
              </TooltipIconButton>
            )}
            {field.openUri && (
              <TooltipIconButton
                variant="outline"
                size="icon"
                type="button"
                label="開啟網站"
                disabled={!field.value}
                onClick={() => void openWebsite(field.uriIndex)}
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
    const copyFeedbackKey = selectedLogin
      ? customFieldCopyFeedbackKey(selectedLogin.id, index, field)
      : null
    return (
      <div
        className={cn(detailFieldClassName, !hidden && 'max-[430px]:grid-cols-[1fr_auto]')}
        key={`${index}:${field.name}:${field.type}`}
      >
        <span>{label}</span>
        <strong
          className={cn(
            hidden && (revealedValue === undefined ? 'tracking-[0.13em]' : 'font-mono select-text')
          )}
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
          type="button"
          label={
            copyFeedbackKey !== null && copiedKey === copyFeedbackKey
              ? `${label}已複製`
              : `複製${label}`
          }
          disabled={field.type !== 'linked' && !field.value && !hidden}
          onClick={() => void copyCustomField(index, field)}
        >
          <CopyFeedbackIcon copied={copyFeedbackKey !== null && copiedKey === copyFeedbackKey} />
        </TooltipIconButton>
      </div>
    )
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
    if (isMac) {
      return (
        <main
          className="bg-background text-muted-foreground flex size-full items-center justify-center gap-3.5"
          role="status"
        >
          <BrandMark className="absolute top-[25px] left-1/2 -translate-x-1/2" />
          <Spinner className="size-6" aria-hidden="true" />
          <p>正在解密你的項目…</p>
        </main>
      )
    }

    return (
      <main
        className={cn(
          'bg-background flex size-full min-w-0 flex-col',
          usesWindowControlsOverlay && 'platform-window-controls-overlay'
        )}
      >
        <header className={titlebarClassName}>
          <ApplicationTitlebarMenu />
          <div className="flex-1 self-stretch" aria-hidden="true" />
        </header>
        <div
          className="bg-background text-muted-foreground flex size-full items-center justify-center gap-3.5"
          role="status"
        >
          <Spinner className="size-6" aria-hidden="true" />
          <p>正在解密你的項目…</p>
        </div>
      </main>
    )
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
        <header className={titlebarClassName}>
          <ApplicationTitlebarMenu onLockVault={lockVault} />
          {!settingsOpen &&
            !healthOpen &&
            !sendsOpen &&
            !organizationsOpen &&
            !emergencyAccessOpen && (
              <TooltipIconButton
                variant="outline"
                size="icon"
                className="hidden max-[880px]:grid"
                type="button"
                label={sidebarOpen ? '關閉側邊欄' : '開啟側邊欄'}
                aria-expanded={sidebarOpen}
                onClick={() => setSidebarOpen((open) => !open)}
              >
                <span
                  className="group/icon-swap relative inline-grid"
                  data-state={sidebarOpen ? 'b' : 'a'}
                  aria-hidden="true"
                >
                  <Menu
                    className="col-start-1 row-start-1 scale-(--icon-swap-start-scale) opacity-0 blur-(--icon-swap-blur) transition-[opacity,filter,transform] duration-(--icon-swap-dur) ease-(--icon-swap-ease) will-change-[opacity,filter,transform] group-data-[state=a]/icon-swap:scale-100 group-data-[state=a]/icon-swap:opacity-100 group-data-[state=a]/icon-swap:blur-none motion-reduce:transition-none"
                    data-icon="a"
                  />
                  <X
                    className="col-start-1 row-start-1 scale-(--icon-swap-start-scale) opacity-0 blur-(--icon-swap-blur) transition-[opacity,filter,transform] duration-(--icon-swap-dur) ease-(--icon-swap-ease) will-change-[opacity,filter,transform] group-data-[state=b]/icon-swap:scale-100 group-data-[state=b]/icon-swap:opacity-100 group-data-[state=b]/icon-swap:blur-none motion-reduce:transition-none"
                    data-icon="b"
                  />
                </span>
              </TooltipIconButton>
            )}
          {closeAuxiliaryPage && (
            <Button variant="outline" size="sm" type="button" onClick={closeAuxiliaryPage}>
              <ArrowLeft data-icon="inline-start" />
              密碼庫
            </Button>
          )}
          {isMac && (
            <div className="inline-flex items-center gap-2 max-[680px]:hidden">
              <BrandMark hideMark />
              <Badge variant="secondary" className="bg-black/5 shadow-(--control-highlight)">
                Beta
              </Badge>
            </div>
          )}
          {!settingsOpen &&
            !healthOpen &&
            !sendsOpen &&
            !organizationsOpen &&
            !emergencyAccessOpen && (
              <InputGroup
                className={cn(
                  'text-muted-foreground [@media(prefers-reduced-transparency:reduce)]:bg-card bg-card/50 absolute left-1/2 h-[38px] w-[clamp(300px,44vw,560px)] min-w-0 -translate-x-1/2 gap-[7px] rounded-[11px] border-0 py-0 pr-2 pl-2.5 focus-within:border-(--focus) max-[880px]:static max-[880px]:max-w-none max-[880px]:flex-1 max-[880px]:translate-x-0 max-[680px]:[&_kbd]:hidden',
                  'shadow-(--control-highlight)',
                  '[-webkit-app-region:no-drag] **:[-webkit-app-region:no-drag]'
                )}
              >
                <Button
                  variant="ghost"
                  className="text-foreground h-full min-w-0 flex-1 justify-start bg-transparent p-0 text-xs font-normal shadow-none hover:bg-transparent focus-visible:border-transparent focus-visible:ring-0 focus-visible:outline-none aria-expanded:bg-transparent [&>span]:w-full [&>span]:min-w-0 [&>span]:text-left"
                  type="button"
                  aria-label={query ? `搜尋密碼庫項目，目前為 ${query}` : '搜尋密碼庫項目'}
                  aria-haspopup="dialog"
                  aria-expanded={searchOpen}
                  onClick={() => setSearchOpen(true)}
                >
                  <span className={cn('truncate', !query && 'text-muted-foreground')}>
                    {query || '搜尋密碼庫'}
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
                      onClick={() => updateQuery('')}
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
          <div
            className={cn('flex-1 self-stretch', !auxiliaryPageOpen && 'max-[880px]:hidden')}
            aria-hidden="true"
          />
          {!settingsOpen &&
            !healthOpen &&
            !sendsOpen &&
            !organizationsOpen &&
            !emergencyAccessOpen &&
            scope.kind !== 'archive' &&
            scope.kind !== 'trash' && (
              <TooltipIconButton
                variant="outline"
                size="icon"
                className="border-border text-foreground rounded-[10px] bg-[color-mix(in_oklch,var(--card)_32%,transparent)] shadow-[var(--control-highlight),0_1px_2px_color-mix(in_oklch,var(--shadow-color)_12%,transparent)]"
                type="button"
                label="新增項目"
                onClick={() => openEditor('create')}
              >
                <Plus aria-hidden="true" />
              </TooltipIconButton>
            )}
        </header>

        <Button
          variant="ghost"
          className={cn(
            'hidden max-[880px]:pointer-events-none max-[880px]:fixed max-[880px]:inset-0 max-[880px]:z-30 max-[880px]:block max-[880px]:size-full max-[880px]:rounded-none max-[880px]:border-0 max-[880px]:bg-[color-mix(in_oklch,var(--foreground)_34%,transparent)] max-[880px]:p-0 max-[880px]:opacity-0 max-[880px]:shadow-none max-[880px]:transition-opacity max-[880px]:duration-180 max-[880px]:hover:bg-[color-mix(in_oklch,var(--foreground)_34%,transparent)] max-[880px]:active:bg-[color-mix(in_oklch,var(--foreground)_34%,transparent)]',
            sidebarOpen && 'max-[880px]:pointer-events-auto max-[880px]:opacity-100'
          )}
          type="button"
          aria-label="關閉側邊欄"
          aria-hidden={!sidebarOpen}
          tabIndex={sidebarOpen ? 0 : -1}
          onClick={() => setSidebarOpen(false)}
        />

        <CommandDialog
          open={searchOpen}
          onOpenChange={setSearchOpen}
          title="搜尋密碼庫"
          description="搜尋名稱、摘要、網站與內容；以 > 開始可指定欄位的進階搜尋。"
        >
          <Command
            className="max-h-[min(480px,70vh)] [&_[data-slot=command-input-wrapper]]:px-2 [&_[data-slot=command-input-wrapper]]:pt-2 [&_[data-slot=command-input-wrapper]]:pb-0"
            label="搜尋密碼庫項目"
            loop
            shouldFilter={false}
          >
            <CommandInput
              ref={searchRef}
              placeholder="搜尋密碼庫；例如 >name:github"
              maxLength={MAX_VAULT_SEARCH_QUERY_LENGTH}
              value={query}
              onValueChange={updateQuery}
              endAdornment={
                query ? (
                  <InputGroupAddon align="inline-end">
                    <InputGroupButton
                      size="icon-xs"
                      type="button"
                      aria-label="清除搜尋"
                      onClick={() => {
                        updateQuery('')
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
            <CommandList className="max-h-[min(420px,calc(70vh-54px))] p-1.5">
              <CommandEmpty>找不到符合的密碼庫項目</CommandEmpty>
              {scopedItems.length > 0 && (
                <CommandGroup
                  heading={`${normalizedVaultSearchQuery(query) ? '搜尋結果' : scopeTitle} · ${scopedItems.length} 個項目`}
                >
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
                        <span
                          className="bg-foreground/5 text-muted-foreground grid size-[30px] flex-none place-items-center rounded"
                          aria-hidden="true"
                        >
                          <ItemIcon />
                        </span>
                        <span className="min-w-0 flex-1">
                          <strong className="block truncate">{item.name}</strong>
                          <small className="text-muted-foreground block truncate text-[10px]">
                            {item.subtitle || item.username || item.uri || '尚未設定摘要'}
                          </small>
                        </span>
                        <span className="text-muted-foreground flex-none text-[10px]">
                          {itemTypeMeta[item.type].label}
                        </span>
                      </CommandItem>
                    )
                  })}
                </CommandGroup>
              )}
            </CommandList>
          </Command>
        </CommandDialog>

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
          <aside
            className={cn(
              'border-sidebar-border bg-sidebar text-foreground z-11 flex min-h-0 min-w-0 flex-col overflow-hidden border-r bg-[linear-gradient(color-mix(in_oklch,var(--sidebar-foreground)_3%,transparent),transparent)] [backdrop-filter:saturate(165%)_blur(28px)] [-webkit-backdrop-filter:saturate(165%)_blur(28px)] max-[880px]:absolute max-[880px]:inset-y-0 max-[880px]:left-0 max-[880px]:z-31 max-[880px]:w-[248px] max-[880px]:-translate-x-full max-[880px]:transition-transform max-[880px]:duration-180 max-[880px]:ease-out',
              (isMac || isWindows) &&
                'max-[880px]:bg-sidebar mb-[-8px] border-0 bg-transparent bg-none shadow-none [backdrop-filter:none] [-webkit-backdrop-filter:none] max-[880px]:[inset:0_auto_8px_8px] max-[880px]:mb-0 max-[880px]:translate-x-[calc(-100%-8px)] max-[880px]:rounded-2xl max-[880px]:border max-[880px]:border-(--native-material-border) max-[880px]:shadow-(--native-material-shadow) max-[880px]:[backdrop-filter:saturate(165%)_blur(28px)] max-[880px]:[-webkit-backdrop-filter:saturate(165%)_blur(28px)] [@media(max-width:880px)_and_(prefers-reduced-transparency:reduce)]:[backdrop-filter:none] [@media(max-width:880px)_and_(prefers-reduced-transparency:reduce)]:[-webkit-backdrop-filter:none]',
              sidebarOpen &&
                'max-[880px]:translate-x-0 max-[880px]:shadow-[14px_0_40px_color-mix(in_oklch,var(--shadow-color)_30%,transparent)]',
              sidebarOpen && (isMac || isWindows) && 'max-[880px]:shadow-(--native-material-shadow)'
            )}
            data-vault-sidebar=""
            aria-label="密碼庫導覽"
          >
            <div className="scroll-fade-y forced-colors:scroll-fade-none min-h-0 flex-1 [scrollbar-color:color-mix(in_oklch,var(--muted-foreground)_25%,transparent)_transparent] overflow-y-auto overscroll-contain max-[880px]:pt-2">
              <section
                className={cn(folderSectionClassName, 'px-[11px] pb-1')}
                aria-labelledby="categories-title"
              >
                <h2 className="hidden" id="categories-title">
                  分類
                </h2>
                <nav className="grid grid-cols-2 gap-2 p-0 pt-px" aria-label="密碼庫分類">
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

              <section
                className={cn(folderSectionClassName, 'px-[9px] py-1')}
                aria-labelledby="quick-title"
              >
                <header>
                  <h2 id="quick-title">快速取用</h2>
                </header>
                <nav className="grid gap-[3px] px-2.5 py-1" aria-label="快速取用">
                  <SidebarLink
                    icon={<Star size={16} />}
                    label="常用項目"
                    count={activeItems.filter((item) => item.favorite).length}
                    active={scope.kind === 'favorites'}
                    dropTargetId={
                      scope.kind === 'archive' || scope.kind === 'trash'
                        ? undefined
                        : quickAccessDropIds.favorites
                    }
                    onClick={() => selectScope({ kind: 'favorites' })}
                  />
                  <SidebarLink
                    icon={<Clock3 size={16} />}
                    label="最近使用"
                    count={activeItems.filter((item) => item.lastUsedAt).length}
                    active={scope.kind === 'recent'}
                    onClick={() => selectScope({ kind: 'recent' })}
                  />
                  <SidebarLink
                    icon={<Archive size={16} />}
                    label="封存"
                    count={archivedItems.length}
                    active={scope.kind === 'archive'}
                    dropTargetId={
                      scope.kind === 'archive' || scope.kind === 'trash'
                        ? undefined
                        : quickAccessDropIds.archive
                    }
                    onClick={() => selectScope({ kind: 'archive' })}
                  />
                  <SidebarLink
                    icon={<Trash2 size={16} />}
                    label="垃圾桶"
                    count={trashItems.length}
                    active={scope.kind === 'trash'}
                    dropTargetId={scope.kind === 'trash' ? undefined : quickAccessDropIds.trash}
                    onClick={() => selectScope({ kind: 'trash' })}
                  />
                </nav>
              </section>

              <section
                className={cn(folderSectionClassName, 'px-[9px] py-1')}
                aria-labelledby="folders-title"
              >
                <header>
                  <h2 id="folders-title">資料夾</h2>
                  <TooltipIconButton
                    variant="sidebar"
                    size="icon"
                    className="hover:bg-sidebar-overlay-hover hover:text-foreground border-transparent bg-transparent shadow-none hover:shadow-(--control-highlight) dark:bg-transparent"
                    type="button"
                    label="新增資料夾"
                    onClick={() => setFolderDialog('new')}
                  >
                    <Plus aria-hidden="true" />
                  </TooltipIconButton>
                </header>
                <ul className="m-0 [scrollbar-color:var(--sidebar-ring)_transparent] list-none overflow-visible p-0">
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

            <footer className="text-muted-foreground grid grid-cols-[minmax(0,1fr)_auto] items-center gap-1 border-t-0 bg-transparent px-[9px] pt-[7px] pb-[9px] text-[10px]">
              <DropdownMenu>
                <DropdownMenuTrigger
                  render={
                    <Button
                      ref={sidebarMenuTriggerRef}
                      variant="sidebar"
                      className="text-sidebar-foreground hover:bg-sidebar-overlay-hover data-popup-open:bg-sidebar-overlay-active h-auto min-h-9 w-full justify-start gap-[7px] rounded-[9px] px-1.5 py-1"
                      type="button"
                      aria-label={`開啟 ${sidebarAccountName} 選單`}
                    />
                  }
                >
                  <span
                    className="text-muted-foreground grid size-5 flex-none place-items-center [&>svg]:size-[18px]"
                    aria-hidden="true"
                  >
                    <UserRound />
                  </span>
                  <span className="block min-w-0 flex-1 text-left">
                    <strong className="text-sidebar-foreground block truncate text-xs font-bold">
                      {sidebarAccountName}
                    </strong>
                  </span>
                  <ChevronUp className="text-muted-foreground ml-auto" aria-hidden="true" />
                </DropdownMenuTrigger>
                <DropdownMenuContent
                  side="top"
                  align="start"
                  sideOffset={8}
                  className="min-w-[220px] p-[5px] [&_[data-slot=dropdown-menu-item]]:min-h-[34px] [&_[data-slot=dropdown-menu-item]]:gap-2 [&_[data-slot=dropdown-menu-item]]:px-[9px]"
                >
                  <DropdownMenuGroup>
                    <DropdownMenuLabel className="flex items-center gap-[7px] p-[7px]">
                      <span
                        className="text-muted-foreground grid size-5 flex-none place-items-center [&>svg]:size-[18px]"
                        aria-hidden="true"
                      >
                        <UserRound />
                      </span>
                      <span className="grid min-w-0 gap-px">
                        <strong className="text-sidebar-foreground block truncate text-xs font-bold">
                          {sidebarAccountName}
                        </strong>
                        <small className="text-muted-foreground block truncate text-[10px] font-medium">
                          {syncStateMeta[syncStatus.state].label}
                        </small>
                      </span>
                    </DropdownMenuLabel>
                  </DropdownMenuGroup>
                  <DropdownMenuSeparator />
                  <DropdownMenuGroup>
                    <DropdownMenuItem onClick={() => setGeneratorDialogOpen(true)}>
                      <Sparkles data-icon="inline-start" />
                      產生器
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={openOrganizations}>
                      <UsersRound data-icon="inline-start" />
                      組織
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={openEmergencyAccess}>
                      <ShieldAlert data-icon="inline-start" />
                      Emergency Access
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={openSends}>
                      <SendIcon data-icon="inline-start" />
                      Sends
                    </DropdownMenuItem>
                  </DropdownMenuGroup>
                  <DropdownMenuSeparator />
                  <DropdownMenuGroup>
                    <DropdownMenuItem onClick={openHealth}>
                      <ShieldCheck data-icon="inline-start" />
                      健康報告
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={openSettings}>
                      <Settings2 data-icon="inline-start" />
                      設定
                    </DropdownMenuItem>
                  </DropdownMenuGroup>
                  <DropdownMenuSeparator />
                  <DropdownMenuGroup>
                    <DropdownMenuItem onClick={() => void lockVault()}>
                      <LockKeyhole data-icon="inline-start" />
                      鎖定密碼庫
                      <DropdownMenuShortcut>
                        <Kbd>{commandLabel} L</Kbd>
                      </DropdownMenuShortcut>
                    </DropdownMenuItem>
                  </DropdownMenuGroup>
                </DropdownMenuContent>
              </DropdownMenu>
              <TooltipIconButton
                variant="sidebar"
                size="icon"
                className="size-[34px] rounded-[9px]"
                type="button"
                label={`雲端同步：${syncStateMeta[syncStatus.state].label}`}
                onClick={() => setSyncDialogOpen(true)}
              >
                <SyncSidebarIcon
                  className={cn(
                    'text-muted-foreground',
                    syncStatus.state === 'ready' && 'text-sidebar-status-success',
                    (syncStatus.state === 'locked' || syncStatus.state === 'unconfigured') &&
                      'text-chart-4',
                    syncStatus.state === 'error' && 'text-destructive',
                    syncStatus.state === 'syncing' &&
                      'text-ring animate-[sync-pulse_1.1s_ease-in-out_infinite]'
                  )}
                  aria-hidden="true"
                />
              </TooltipIconButton>
            </footer>
          </aside>

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
                'border-border flex min-h-0 min-w-0 flex-col border-r bg-transparent max-[680px]:size-full [[data-has-detail=true]_&]:max-[680px]:hidden',
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
                      window.bearwarden.sync.status().then(setSyncStatus)
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
                <>
                  <header className="flex min-h-[82px] items-center justify-between gap-3 px-[18px] pt-[15px] pb-[11px] max-[430px]:px-[11px]">
                    <div className="grid gap-0.5">
                      <h1
                        className="m-0 text-[21px] leading-[1.2] font-[760] tracking-[-0.025em]"
                        id="list-title"
                      >
                        {scopeTitle}
                      </h1>
                      <small className="text-muted-foreground text-[11px]">
                        {selectedIds.size > 1
                          ? `已選取 ${selectedIds.size} 個 · 共 ${scopedItems.length} 個項目`
                          : `${scopedItems.length} 個項目`}
                      </small>
                    </div>
                    <div className="border-border flex items-center gap-[7px] rounded-[14px] border bg-[color-mix(in_oklch,var(--card)_78%,transparent)] p-1 shadow-none dark:bg-[color-mix(in_oklch,var(--card)_70%,transparent)]">
                      <div className="text-muted-foreground flex h-8 items-center gap-1 border-0 bg-transparent py-0 pr-1 pl-1.5 shadow-none">
                        <ListFilter size={16} aria-hidden="true" />
                        <Select
                          items={sortItemsOptions}
                          value={sortMode}
                          disabled={scope.kind === 'recent'}
                          onValueChange={(value) => setSortMode(value as VaultSortMode)}
                        >
                          <SelectTrigger size="sm" variant="embedded" aria-label="排序方式">
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
                    <div
                      className="text-muted-foreground flex min-h-7 items-center justify-between gap-2.5 px-[19px] pt-0 pb-[7px] text-[10px]"
                      role="status"
                    >
                      <span>搜尋「{query}」</span>
                      <span>{scopedItems.length} 筆結果</span>
                    </div>
                  )}

                  {scopedItems.length ? (
                    <VirtualizedItemList
                      groups={itemGroups}
                      scopeTitle={scopeTitle}
                      activeId={editorMode ? null : selectedId}
                      selectedIds={selectedIds}
                      onPrefetch={scope.kind === 'trash' ? undefined : prefetchLoginDetail}
                      onSelect={selectItems}
                      onFavorite={toggleFavorite}
                      onContextMenu={showLoginContextMenu}
                      showWebsiteIcons={
                        scope.kind !== 'trash' && (settings?.showWebsiteIcons ?? false)
                      }
                      readOnly={scope.kind === 'trash'}
                    />
                  ) : (
                    <Empty className="min-h-0 flex-1 gap-0 p-7">
                      <EmptyHeader>
                        <EmptyMedia
                          variant="icon"
                          className="text-primary mb-[13px] size-[52px] rounded-2xl bg-(--accent-soft)"
                        >
                          {query ? <Search /> : scope.kind === 'trash' ? <Trash2 /> : <KeyRound />}
                        </EmptyMedia>
                        <EmptyTitle className="m-0 text-[15px]">
                          {query
                            ? '找不到符合的項目'
                            : scope.kind === 'trash'
                              ? '垃圾桶是空的'
                              : '這裡還沒有密碼庫項目'}
                        </EmptyTitle>
                        <EmptyDescription className="text-muted-foreground mt-[7px] mb-4 max-w-[290px] text-[11px] leading-[1.55]">
                          {query
                            ? '試試較短的關鍵字，或切換到所有項目。'
                            : scope.kind === 'trash'
                              ? '刪除的項目會留在這裡，直到你還原、永久刪除，或伺服器依保留政策清除。'
                              : '新增第一筆資料，BearWarden 會安全地替你保管。'}
                        </EmptyDescription>
                      </EmptyHeader>
                      <EmptyContent>
                        {query ? (
                          <Button variant="outline" type="button" onClick={() => updateQuery('')}>
                            清除搜尋
                          </Button>
                        ) : scope.kind !== 'trash' && scope.kind !== 'archive' ? (
                          <Button
                            className="before:ring-primary-foreground/20 relative h-[38px] gap-2 rounded-[9px] border-0 px-3.5 font-[680] shadow-[var(--subtle-primary-action-shadow)] before:pointer-events-none before:absolute before:inset-0 before:rounded-[inherit] before:ring-1 before:ring-inset has-data-[icon=inline-start]:pl-3.5"
                            type="button"
                            onClick={() => openEditor('create')}
                          >
                            <Plus data-icon="inline-start" />
                            新增項目
                          </Button>
                        ) : null}
                      </EmptyContent>
                    </Empty>
                  )}
                  {(selectedSummaries.length >= 2 ||
                    (scope.kind === 'trash' && trashItems.length > 0)) && (
                    <footer
                      className="border-border bg-muted flex min-h-16 flex-none flex-wrap items-center justify-end gap-2 border-t px-5 py-1"
                      aria-label="列表操作"
                    >
                      {selectedSummaries.length >= 2 && (
                        <div
                          className={cn(
                            'flex flex-wrap items-center gap-2',
                            scope.kind !== 'trash' && 'flex-1'
                          )}
                          role="toolbar"
                          aria-label="已選取項目的批次操作"
                          aria-busy={busy}
                        >
                          <span className="sr-only" aria-live="polite">
                            已選取 {selectedSummaries.length} 個項目
                          </span>
                          {scope.kind === 'trash' ? (
                            <>
                              <Button
                                variant="outline"
                                size="sm"
                                type="button"
                                disabled={busy}
                                onClick={() =>
                                  void performBulkAction(snapshotBulkAction('restore'))
                                }
                              >
                                <RotateCcw data-icon="inline-start" />
                                還原
                              </Button>
                              <Button
                                variant="destructive"
                                size="sm"
                                type="button"
                                disabled={busy}
                                onClick={() =>
                                  setPendingBulkAction(snapshotBulkAction('deletePermanently'))
                                }
                              >
                                <Trash2 data-icon="inline-start" />
                                永久刪除
                              </Button>
                            </>
                          ) : (
                            <>
                              <Button
                                variant="destructive"
                                size="sm"
                                type="button"
                                disabled={busy}
                                onClick={() => setPendingBulkAction(snapshotBulkAction('delete'))}
                              >
                                <Trash2 data-icon="inline-start" />
                                刪除
                              </Button>
                              <div className="ml-auto flex flex-wrap items-center gap-2">
                                <Button
                                  variant="outline"
                                  size="sm"
                                  type="button"
                                  disabled={busy}
                                  onClick={openMoveDialogForSelection}
                                >
                                  <FolderOpen data-icon="inline-start" />
                                  移動
                                </Button>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  type="button"
                                  disabled={busy}
                                  onClick={() =>
                                    void performBulkAction(
                                      snapshotBulkAction(
                                        scope.kind === 'archive' ? 'unarchive' : 'archive'
                                      )
                                    )
                                  }
                                >
                                  {scope.kind === 'archive' ? (
                                    <ArchiveRestore data-icon="inline-start" />
                                  ) : (
                                    <Archive data-icon="inline-start" />
                                  )}
                                  {scope.kind === 'archive' ? '取消封存' : '封存'}
                                </Button>
                              </div>
                            </>
                          )}
                        </div>
                      )}
                      {scope.kind === 'trash' && trashItems.length > 0 && (
                        <Button
                          variant="outline"
                          size="sm"
                          type="button"
                          disabled={busy}
                          onClick={() => setEmptyTrashDialogOpen(true)}
                        >
                          <Trash2 data-icon="inline-start" />
                          清空垃圾桶
                        </Button>
                      )}
                    </footer>
                  )}
                </>
              )}
            </section>

            <section
              className="relative flex min-h-0 min-w-0 overflow-hidden bg-transparent max-[680px]:hidden max-[680px]:size-full [[data-has-detail=true]_&]:max-[680px]:flex"
              data-vault-detail-pane=""
              aria-label="項目詳細資料"
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
                      label="返回垃圾桶"
                      onClick={clearItemSelection}
                    >
                      <ArrowLeft />
                    </TooltipIconButton>
                    <span className={detailIconClassName()} aria-hidden="true">
                      <Trash2 />
                    </span>
                    <div className="[&>span]:text-muted-foreground min-w-0 flex-1 [&>h2]:m-0 [&>h2]:truncate [&>h2]:text-xl [&>h2]:tracking-[-0.025em] [&>span]:mt-[3px] [&>span]:block [&>span]:truncate [&>span]:text-[10px]">
                      <p className="text-primary m-0 mb-[3px] text-[9px] font-extrabold tracking-[0.11em] uppercase">
                        垃圾桶
                      </p>
                      <h2>{selectedSummary.name}</h2>
                      <span>{itemTypeMeta[selectedSummary.type].label}</span>
                    </div>
                  </DetailHeader>
                  <div className="scroll-fade-y forced-colors:scroll-fade-none min-h-0 flex-1 [scrollbar-color:var(--border-strong)_transparent] overflow-auto px-5 pt-5 pb-10 max-[680px]:px-3 max-[680px]:pt-[13px] max-[680px]:pb-7">
                    <DetailCard>
                      <CardHeader>
                        <CardTitle>這個項目已移至垃圾桶</CardTitle>
                        <CardDescription>
                          為了保護已刪除的敏感資料，請先還原項目再查看或編輯目前內容。
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <dl className="m-0 px-[15px] py-1">
                          <div className="border-border grid grid-cols-[minmax(90px,0.28fr)_1fr] border-b py-2.5 last:border-b-0 max-[430px]:grid-cols-1 max-[430px]:gap-1">
                            <dt className="text-muted-foreground text-[11px]">刪除時間</dt>
                            <dd className="m-0 text-[11px]">
                              {formatDate(selectedSummary.deletedAt)}
                            </dd>
                          </div>
                          <div className="border-border grid grid-cols-[minmax(90px,0.28fr)_1fr] border-b py-2.5 last:border-b-0 max-[430px]:grid-cols-1 max-[430px]:gap-1">
                            <dt className="text-muted-foreground text-[11px]">原資料夾</dt>
                            <dd className="m-0 text-[11px]">
                              {folders.find((folder) => folder.id === selectedSummary.folderId)
                                ?.name ?? '未分類'}
                            </dd>
                          </div>
                        </dl>
                      </CardContent>
                    </DetailCard>
                    {hasTrashPasswordHistory(selectedSummary) && (
                      <DetailCard role="region" aria-labelledby="trash-password-history-title">
                        <CardHeader className="bg-muted rounded-none border-b">
                          <CardTitle id="trash-password-history-title">項目歷史記錄</CardTitle>
                        </CardHeader>
                        <CardContent className="contents">
                          <dl className="m-0 px-[15px] py-1">
                            <div className="border-border grid grid-cols-[minmax(90px,0.28fr)_minmax(0,1fr)] items-center gap-2 border-b py-2.5 last:border-b-0 max-[430px]:grid-cols-1 max-[430px]:items-start max-[430px]:gap-1">
                              <dt className="text-muted-foreground text-[11px] leading-4">
                                密碼歷史
                              </dt>
                              <dd className="m-0 flex min-w-0 items-center gap-2 text-xs leading-4">
                                <span className="min-w-0 flex-1 truncate">
                                  {selectedSummary.passwordHistoryCount} 筆唯讀紀錄
                                </span>
                                <Button
                                  variant="ghost"
                                  size="icon-sm"
                                  className="-my-1.5 ml-auto"
                                  type="button"
                                  aria-label="查看密碼歷史"
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
                        還原項目
                      </Button>
                      <Button
                        variant="destructive"
                        type="button"
                        disabled={busy}
                        onClick={() => setDeleteDialogOpen(true)}
                      >
                        <Trash2 data-icon="inline-start" />
                        永久刪除
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
                      label="返回項目列表"
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
                          return <TypeIcon size={23} />
                        })()
                      )}
                    </span>
                    <div className="[&>span]:text-muted-foreground min-w-0 flex-1 [&>h2]:m-0 [&>h2]:truncate [&>h2]:text-xl [&>h2]:tracking-[-0.025em] [&>span]:mt-[3px] [&>span]:block [&>span]:truncate [&>span]:text-[10px]">
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
                      className={cn(selectedLogin.favorite && 'text-chart-4')}
                      type="button"
                      label={selectedLogin.favorite ? '從常用項目移除' : '加入常用項目'}
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
                                  className="border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground dark:bg-card dark:hover:bg-muted size-[34px] min-w-[34px] rounded-[9px] shadow-(--control-highlight)"
                                  type="button"
                                  aria-label="更多操作"
                                  disabled={busy}
                                />
                              }
                            >
                              <MoreHorizontal aria-hidden="true" />
                            </DropdownMenuTrigger>
                          }
                        />
                        <TooltipContent>更多操作</TooltipContent>
                      </Tooltip>
                      <DropdownMenuContent align="end">
                        <DropdownMenuGroup>
                          <DropdownMenuItem disabled={busy} onClick={() => void cloneLogin()}>
                            <Copy data-icon="inline-start" />
                            複製項目
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
                            {selectedLogin.archivedAt ? '取消封存' : '封存項目'}
                          </DropdownMenuItem>
                          <DropdownMenuItem disabled={busy} onClick={() => openEditor('edit')}>
                            <Edit3 data-icon="inline-start" />
                            編輯
                          </DropdownMenuItem>
                          {selectedLogin.attachments.length === 0 && (
                            <DropdownMenuItem
                              disabled={
                                busy || attachmentOperation !== null || syncStatus.state !== 'ready'
                              }
                              onClick={() => void uploadAttachment()}
                            >
                              <Upload data-icon="inline-start" />
                              上傳附件
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
                            移至垃圾桶
                          </DropdownMenuItem>
                        </DropdownMenuGroup>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </DetailHeader>

                  <div className="scroll-fade-y forced-colors:scroll-fade-none min-h-0 flex-1 [scrollbar-color:var(--border-strong)_transparent] overflow-auto px-5 pt-5 pb-10 max-[680px]:px-3 max-[680px]:pt-[13px] max-[680px]:pb-7">
                    {selectedDetailFields.length > 0 && (
                      <DetailCard role="region" aria-labelledby="credentials-title">
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
                      </DetailCard>
                    )}

                    {selectedLogin.customFields.length > 0 && (
                      <DetailCard role="region" aria-labelledby="custom-fields-title">
                        <CardHeader className="bg-muted rounded-none border-b">
                          <CardTitle id="custom-fields-title">自訂欄位</CardTitle>
                          <CardDescription>
                            {selectedLogin.customFields.length} 個欄位
                          </CardDescription>
                        </CardHeader>
                        <CardContent className="contents">
                          {selectedLogin.customFields.map(renderCustomField)}
                        </CardContent>
                      </DetailCard>
                    )}

                    {(selectedLogin.attachments.length > 0 ||
                      attachmentOperation?.itemId === selectedLogin.id) && (
                      <DetailCard
                        variant="attachment"
                        role="region"
                        aria-labelledby="attachments-title"
                      >
                        <CardHeader className="bg-muted rounded-none border-b">
                          <CardTitle id="attachments-title">附件</CardTitle>
                          <CardDescription>
                            {selectedLogin.attachments.length} 個檔案
                          </CardDescription>
                          <CardAction>
                            <Button
                              variant="outline"
                              size="sm"
                              type="button"
                              disabled={
                                busy || attachmentOperation !== null || syncStatus.state !== 'ready'
                              }
                              onClick={() => void uploadAttachment()}
                            >
                              {attachmentOperation?.kind === 'upload' ? (
                                <Spinner data-icon="inline-start" />
                              ) : (
                                <Upload data-icon="inline-start" />
                              )}
                              上傳附件
                            </Button>
                          </CardAction>
                        </CardHeader>
                        <CardContent className="flex flex-col gap-4">
                          {attachmentOperation?.itemId === selectedLogin.id && (
                            <section className="flex flex-col gap-3" aria-live="polite">
                              <Progress value={attachmentProgressPercent(attachmentOperation)}>
                                <ProgressLabel>
                                  {attachmentStageLabel(attachmentOperation)}
                                  {attachmentOperation.fileName
                                    ? `：${attachmentOperation.fileName}`
                                    : ''}
                                </ProgressLabel>
                                <ProgressValue>
                                  {() =>
                                    attachmentProgressPercent(attachmentOperation) === null
                                      ? '處理中'
                                      : `${attachmentProgressPercent(attachmentOperation)}%`
                                  }
                                </ProgressValue>
                              </Progress>
                              <Button
                                className="self-end"
                                variant="outline"
                                size="sm"
                                type="button"
                                disabled={attachmentOperation.canceling}
                                onClick={() => void cancelAttachmentOperation()}
                              >
                                {attachmentOperation.canceling ? (
                                  <Spinner data-icon="inline-start" />
                                ) : (
                                  <X data-icon="inline-start" />
                                )}
                                {attachmentOperation.canceling ? '正在取消' : '取消'}
                              </Button>
                            </section>
                          )}
                          {selectedLogin.attachments.length > 0 && (
                            <div className="-mx-(--card-spacing) -mb-(--card-spacing) grid">
                              {selectedLogin.attachments.map((attachment) => (
                                <article
                                  key={attachment.id}
                                  className="border-border [&_small]:text-muted-foreground grid grid-cols-[34px_minmax(0,1fr)_auto] items-center gap-2.5 border-b px-[15px] py-3 [&_small]:truncate [&_small]:text-[10px] [&_span]:truncate [&_span]:text-[11px] [&_strong]:truncate [&_strong]:text-xs [&>div]:grid [&>div]:min-w-0 [&>div]:gap-[3px]"
                                >
                                  <span
                                    className="text-primary grid size-8 place-items-center rounded-[9px] bg-(--accent-soft)"
                                    aria-hidden="true"
                                  >
                                    <Paperclip size={17} />
                                  </span>
                                  <div>
                                    <strong>{attachment.fileName}</strong>
                                    <span>
                                      {attachment.sizeName}
                                      {attachment.legacy ? ' · 舊式未驗證加密' : ''}
                                    </span>
                                  </div>
                                  <section
                                    className="flex flex-wrap items-center justify-end gap-1"
                                    aria-label={`${attachment.fileName} 的附件操作`}
                                  >
                                    {attachment.legacy && (
                                      <Button
                                        variant="outline"
                                        size="sm"
                                        type="button"
                                        disabled={
                                          busy ||
                                          attachmentOperation !== null ||
                                          syncStatus.state !== 'ready'
                                        }
                                        onClick={() => void fixLegacyAttachment(attachment.id)}
                                      >
                                        <Wrench data-icon="inline-start" />
                                        修復
                                      </Button>
                                    )}
                                    <TooltipIconButton
                                      variant="outline"
                                      size="icon"
                                      type="button"
                                      label={`下載 ${attachment.fileName}`}
                                      disabled={
                                        busy ||
                                        attachmentOperation !== null ||
                                        syncStatus.state !== 'ready'
                                      }
                                      onClick={() => void downloadAttachment(attachment.id)}
                                    >
                                      <Download data-icon="inline-start" />
                                    </TooltipIconButton>
                                    <TooltipIconButton
                                      variant="destructive"
                                      size="icon"
                                      type="button"
                                      label={`刪除 ${attachment.fileName}`}
                                      disabled={
                                        busy ||
                                        attachmentOperation !== null ||
                                        syncStatus.state !== 'ready'
                                      }
                                      onClick={() =>
                                        setAttachmentDeleteTarget({
                                          itemId: selectedLogin.id,
                                          attachmentId: attachment.id,
                                          fileName: attachment.fileName
                                        })
                                      }
                                    >
                                      <Trash2 data-icon="inline-start" />
                                    </TooltipIconButton>
                                  </section>
                                </article>
                              ))}
                            </div>
                          )}
                        </CardContent>
                      </DetailCard>
                    )}

                    {selectedLogin.type === 'login' && selectedLogin.hasTotp && (
                      <DetailCard
                        role="region"
                        aria-labelledby="totp-title"
                        aria-busy={!totpRevealReady}
                      >
                        <CardHeader className="bg-muted rounded-none border-b">
                          <CardTitle id="totp-title">一次性驗證碼</CardTitle>
                          {totpGenerationError === 'unsupported' && (
                            <CardDescription>密鑰格式不受支援</CardDescription>
                          )}
                          {!totpRevealReady && <span className="sr-only">產生中…</span>}
                        </CardHeader>
                        <CardContent className="contents">
                          <div className="grid grid-cols-[minmax(0,1fr)_34px] items-center gap-2 px-[15px] pt-3.5 pb-2 [&_strong]:font-mono [&_strong]:text-[25px] [&_strong]:tracking-[0.18em]">
                            <div className="flex h-8 min-w-0 items-center">
                              {totpCode ? (
                                <strong>
                                  {/^\d+$/.test(totpCode.code) ? (
                                    <NumberFlow
                                      className="tabular-nums"
                                      value={Number(totpCode.code)}
                                      format={{
                                        useGrouping: false,
                                        minimumIntegerDigits: totpCode.code.length
                                      }}
                                      trend={0}
                                    />
                                  ) : (
                                    totpCode.code
                                  )}
                                </strong>
                              ) : totpGenerationError ? (
                                <strong>—</strong>
                              ) : showTotpSkeleton ? (
                                <Skeleton className="h-8 w-36" aria-hidden="true" />
                              ) : null}
                            </div>
                            <TooltipIconButton
                              variant="outline"
                              size="icon"
                              type="button"
                              label={
                                copiedKey === `totp:${selectedLogin.id}`
                                  ? '一次性驗證碼已複製'
                                  : '複製一次性驗證碼'
                              }
                              disabled={!totpCode || totpGenerationError !== null}
                              onClick={() => void copyTotp()}
                            >
                              <CopyFeedbackIcon copied={copiedKey === `totp:${selectedLogin.id}`} />
                            </TooltipIconButton>
                          </div>
                          {!totpGenerationError && (
                            <div className="h-[19px]">
                              {totpCode ? (
                                <Progress
                                  key={totpCodeState?.cycle}
                                  className="mx-[15px] mb-[15px] block w-[calc(100%-30px)] [&_[data-slot=progress-indicator]]:duration-[1s] [&_[data-slot=progress-indicator]]:ease-linear motion-reduce:[&_[data-slot=progress-indicator]]:duration-0"
                                  aria-label="驗證碼剩餘時間"
                                  max={totpCode.period}
                                  value={totpCode.remainingSeconds}
                                />
                              ) : showTotpSkeleton ? (
                                <Skeleton
                                  className="mx-[15px] mb-[15px] block h-1 w-[calc(100%-30px)]"
                                  aria-hidden="true"
                                />
                              ) : null}
                            </div>
                          )}
                        </CardContent>
                      </DetailCard>
                    )}

                    {selectedLogin.type === 'login' && selectedLogin.passkeys.length > 0 && (
                      <DetailCard role="region" aria-labelledby="passkeys-title">
                        <CardHeader className="bg-muted rounded-none border-b">
                          <CardTitle id="passkeys-title">通行密鑰</CardTitle>
                          <CardDescription>{selectedLogin.passkeys.length} 組</CardDescription>
                        </CardHeader>
                        <CardContent className="contents">
                          <div className="grid">
                            {selectedLogin.passkeys.map((passkey) => (
                              <article
                                key={passkey.credentialId}
                                className="border-border [&_small]:text-muted-foreground grid grid-cols-[34px_minmax(0,1fr)] items-start gap-2.5 border-b px-[15px] py-3 [&_small]:truncate [&_small]:text-[10px] [&_span]:truncate [&_span]:text-[11px] [&_strong]:truncate [&_strong]:text-xs [&>div]:grid [&>div]:min-w-0 [&>div]:gap-[3px]"
                              >
                                <span
                                  className="text-primary grid size-8 place-items-center rounded-[9px] bg-(--accent-soft)"
                                  aria-hidden="true"
                                >
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
                          <p className="text-muted-foreground m-0 px-[15px] pt-2.5 pb-[13px] text-[10px] leading-normal">
                            可從編輯項目安全刪除通行密鑰；私鑰材料不會傳到顯示程序。
                          </p>
                        </CardContent>
                      </DetailCard>
                    )}

                    {(selectedLogin.type === 'secureNote' || selectedLogin.notes) && (
                      <DetailCard role="region" aria-labelledby="notes-title">
                        <CardHeader className="bg-muted rounded-none border-b">
                          <CardTitle id="notes-title">
                            {selectedLogin.type === 'secureNote' ? '安全備註' : '備註'}
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="contents">
                          <p
                            className={cn(
                              'm-0 px-[15px] pt-3.5 pb-[17px] text-xs leading-[1.65] whitespace-pre-wrap',
                              !selectedLogin.notes?.trim() && 'text-muted-foreground'
                            )}
                          >
                            {selectedLogin.notes?.trim() ? selectedLogin.notes : '尚未加入內容'}
                          </p>
                        </CardContent>
                      </DetailCard>
                    )}

                    <DetailCard role="region" aria-labelledby="organization-title">
                      <CardHeader className="bg-muted rounded-none border-b">
                        <CardTitle id="organization-title">整理與活動</CardTitle>
                      </CardHeader>
                      <CardContent className="contents">
                        <dl className="m-0 px-[15px] py-1">
                          <div className="border-border grid grid-cols-[minmax(90px,0.28fr)_minmax(0,1fr)] items-center gap-2 border-b py-2.5 last:border-b-0 max-[430px]:grid-cols-1 max-[430px]:items-start max-[430px]:gap-1">
                            <dt className="text-muted-foreground text-[11px] leading-4">資料夾</dt>
                            <dd className="m-0 flex min-w-0 items-center gap-2 text-xs leading-4">
                              <span className="min-w-0 flex-1 truncate">
                                {folders.find((folder) => folder.id === selectedLogin.folderId)
                                  ?.name ?? '未分類'}
                              </span>
                              <Button
                                variant="ghost"
                                size="icon-sm"
                                className="-my-1.5 ml-auto"
                                type="button"
                                aria-label="移動至資料夾"
                                disabled={busy}
                                onClick={openMoveDialogForSelection}
                              >
                                <Pencil aria-hidden="true" />
                              </Button>
                            </dd>
                          </div>
                          <div className="border-border grid grid-cols-[minmax(90px,0.28fr)_minmax(0,1fr)] items-center gap-2 border-b py-2.5 last:border-b-0 max-[430px]:grid-cols-1 max-[430px]:items-start max-[430px]:gap-1">
                            <dt className="text-muted-foreground text-[11px] leading-4">
                              最近使用
                            </dt>
                            <dd className="m-0 min-w-0 text-xs leading-4">
                              {formatDate(selectedLogin.lastUsedAt)}
                            </dd>
                          </div>
                        </dl>
                      </CardContent>
                    </DetailCard>

                    <DetailCard role="region" aria-labelledby="history-title">
                      <CardHeader className="bg-muted rounded-none border-b">
                        <CardTitle id="history-title">項目歷史記錄</CardTitle>
                      </CardHeader>
                      <CardContent className="contents">
                        <ItemHistoryRows
                          item={selectedLogin}
                          formatDate={formatDate}
                          busy={busy}
                          onViewPasswordHistory={() => setPasswordHistoryDialogOpen(true)}
                        />
                      </CardContent>
                    </DetailCard>
                  </div>
                </article>
              ) : (
                <Empty className="min-h-0 flex-1 gap-0 p-7">
                  <EmptyHeader>
                    <EmptyMedia
                      className="text-muted-foreground mb-4 h-16 w-[78px] bg-transparent"
                      aria-hidden="true"
                    >
                      <img className="size-16 object-contain" src={bearCutUrl} alt="" />
                    </EmptyMedia>
                    <EmptyTitle className="text-foreground m-0 text-xl font-[720]">
                      未選取項目
                    </EmptyTitle>
                    <EmptyDescription className="text-muted-foreground mt-[7px] mb-4 max-w-[290px] text-xs leading-[1.55]">
                      選取項目以查看並管理安全資料。
                    </EmptyDescription>
                  </EmptyHeader>
                </Empty>
              )}
            </section>
          </div>
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
        {moveSnapshot && (
          <MoveDialog
            itemName={moveSummaries[0]?.name ?? '選取的項目'}
            itemCount={moveSnapshot.ids.length}
            currentFolderId={moveFolderId}
            folders={folders}
            busy={busy}
            onClose={() => setMoveSnapshot(null)}
            onMove={(folderId) => moveLogins(moveSnapshot, folderId)}
          />
        )}
        {deleteDialogOpen && selectedSummary && (
          <DeleteLoginDialog
            itemName={selectedSummary.name}
            busy={busy}
            permanent={Boolean(selectedSummary.deletedAt)}
            onClose={() => setDeleteDialogOpen(false)}
            onDelete={deleteLogin}
          />
        )}
        {emptyTrashDialogOpen && trashItems.length > 0 && (
          <DeleteLoginDialog
            itemName={`垃圾桶中的 ${trashItems.length} 個項目`}
            busy={busy}
            permanent
            onClose={() => setEmptyTrashDialogOpen(false)}
            onDelete={emptyTrash}
          />
        )}
        {pendingBulkAction &&
          (pendingBulkAction.action === 'delete' ||
            pendingBulkAction.action === 'deletePermanently') && (
            <AlertDialog
              open
              onOpenChange={(open) => {
                if (!open && !busy) setPendingBulkAction(null)
              }}
            >
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogMedia>
                    <AlertTriangle aria-hidden="true" />
                  </AlertDialogMedia>
                  <AlertDialogTitle>
                    {pendingBulkAction.action === 'deletePermanently'
                      ? `永久刪除 ${pendingBulkAction.ids.length} 個項目？`
                      : `將 ${pendingBulkAction.ids.length} 個項目移至垃圾桶？`}
                  </AlertDialogTitle>
                  <AlertDialogDescription>
                    {pendingBulkAction.action === 'deletePermanently'
                      ? '這個動作無法復原。BearWarden 不會保留可復原的明文副本。'
                      : '項目會保留在加密的垃圾桶中，之後仍可還原。'}
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel disabled={busy}>取消</AlertDialogCancel>
                  <AlertDialogAction
                    variant="destructive"
                    type="button"
                    disabled={busy}
                    onClick={() => {
                      const snapshot = pendingBulkAction
                      void performBulkAction(snapshot).then((completed) => {
                        if (completed) setPendingBulkAction(null)
                      })
                    }}
                  >
                    {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                    {pendingBulkAction.action === 'deletePermanently' ? '永久刪除' : '移至垃圾桶'}
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          )}
        {passwordHistoryDialogOpen && selectedSummary && (
          <PasswordHistoryDialog
            itemName={selectedSummary.name}
            count={selectedSummary.passwordHistoryCount}
            onClose={() => setPasswordHistoryDialogOpen(false)}
            onLoad={loadPasswordHistory}
            onReveal={revealPasswordHistory}
            onCopy={copyPasswordHistory}
          />
        )}
        {passwordZoomValue !== null && (
          <Modal
            title="密碼"
            description="符號、數字與英文以不同顏色標示，方便辨認。"
            onClose={closePasswordZoom}
          >
            <ModalBody>
              <div className="bg-muted/60 rounded-xl px-4 py-5">
                <ColoredPassword
                  value={passwordZoomValue}
                  className="text-[22px] leading-[1.7] select-text"
                />
              </div>
            </ModalBody>
          </Modal>
        )}
        {generatorDialogOpen && (
          <CredentialGeneratorDialog
            onClose={() => setGeneratorDialogOpen(false)}
            onGenerate={window.bearwarden.generator.generate}
            onCopyGenerated={(token) => window.bearwarden.generator.copyGenerated({ token })}
            onListHistory={window.bearwarden.generator.history}
            onCopyHistory={window.bearwarden.generator.copyHistory}
            onClearHistory={window.bearwarden.generator.clearHistory}
          />
        )}
        {repromptPrompt && (
          <RepromptDialog
            itemName={repromptPrompt.itemName}
            busy={repromptBusy}
            onCancel={cancelReprompt}
            onAuthorize={submitReprompt}
          />
        )}
        {(syncDialogOpen || showSyncSetupPrompt) && (
          <SyncDialog
            status={syncStatus}
            onClose={() => {
              setSyncDialogOpen(false)
              onSyncSetupPromptHandled()
              setAccountProfileRefreshRevision((revision) => revision + 1)
            }}
            onStatusChange={setSyncStatus}
            onSynced={refreshAfterSync}
          />
        )}
        {portabilityDialogMode && (
          <VaultPortabilityDialog
            mode={portabilityDialogMode}
            onClose={() => setPortabilityDialogMode(null)}
            onExport={(request) => window.bearwarden.portability.export(request)}
            onImport={(request) => window.bearwarden.portability.import(request)}
            onExported={announceExported}
            onImported={refreshAfterImport}
          />
        )}
        <AlertDialog
          open={attachmentDeleteTarget !== null}
          onOpenChange={(open) => {
            if (!open) setAttachmentDeleteTarget(null)
          }}
        >
          <AlertDialogContent size="sm">
            <AlertDialogHeader>
              <AlertDialogTitle>刪除附件？</AlertDialogTitle>
              <AlertDialogDescription>
                「{attachmentDeleteTarget?.fileName ?? '這個附件'}」會從 Bitwarden
                永久刪除，且無法復原。
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel type="button">保留附件</AlertDialogCancel>
              <AlertDialogAction
                type="button"
                variant="destructive"
                onClick={() => void deleteSelectedAttachment()}
              >
                <Trash2 data-icon="inline-start" />
                刪除附件
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
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
            destinationDescription={activeDragDestinationDescription}
          />
        ) : null}
      </DragOverlay>
    </DndContext>
  )
}

export default VaultShell
