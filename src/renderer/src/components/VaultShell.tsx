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
import { plural } from '@lingui/core/macro'
import { Trans, useLingui } from '@lingui/react/macro'
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
import LoginApprovalDialog from './LoginApprovalDialog'
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
import { useCopyFeedback } from '@renderer/hooks/use-copy-feedback'
import { resolveTotpRefreshTarget } from './totp-refresh-target'
import TotpCountdownIndicator from './TotpCountdownIndicator'
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
import { activateLanguagePreference } from '@renderer/i18n'
import { sortVaultItems, type VaultSortMode } from '@renderer/lib/vault-sort'
import { useVaultRouteState } from '@renderer/lib/vault-route-state'
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

const itemTypeIcons: Record<VaultItemType, typeof KeyRound> = {
  login: KeyRound,
  card: CreditCard,
  identity: ContactRound,
  secureNote: NotebookPen,
  sshKey: FileKey2
}

type SidebarTone = 'blue' | 'indigo' | 'green' | 'yellow' | 'cyan' | 'red' | 'orange' | 'gray'

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

const initialSyncStatus: SyncStatus = { configured: false, state: 'unconfigured' }

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
const detailCacheLimit = 48
const totpListCountdownPeriodSeconds = 30

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

type TotpListEntry = { code: TotpCodeView; expiresAt: number } | null

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

function attachmentProgressPercent(progress: AttachmentProgressEvent): number | null {
  if (progress.totalBytes === null || progress.totalBytes <= 0) return null
  return Math.round(
    Math.min(100, Math.max(0, (progress.completedBytes / progress.totalBytes) * 100))
  )
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
              'border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground dark:bg-card dark:hover:bg-muted size-[34px] min-w-[34px] rounded-md shadow-(--control-highlight) transition-[background,color,border-color,transform] duration-[130ms] [-webkit-app-region:no-drag]',
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

interface DetailCardProps extends Omit<React.ComponentProps<typeof Card>, 'variant'> {
  variant?: 'default' | 'attachment' | 'placeholder'
}

function DetailCard({
  className,
  variant = 'default',
  ...props
}: DetailCardProps): React.JSX.Element {
  return (
    <Card
      variant="item"
      className={cn(
        'mx-auto mb-3 w-full max-w-[720px]',
        '[&_[data-slot=card-description]]:ml-auto',
        variant === 'attachment' &&
          '[&_[data-slot=card-description]]:text-xs [&_[data-slot=card-description]]:leading-normal',
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
        'bg-muted/30 flex items-center gap-2.5 px-4 py-3 max-[680px]:px-3 max-[680px]:py-2.5',
        className
      )}
      {...props}
    />
  )
}

const detailFieldClassName =
  'border-border/60 grid min-h-12 grid-cols-[minmax(90px,0.28fr)_minmax(0,1fr)_repeat(2,34px)] items-center gap-2 border-b py-0.5 last:border-b-0 [&>span]:text-[11px] [&>span]:text-muted-foreground [&>strong]:min-w-0 [&>strong]:truncate [&>strong]:text-xs [&>strong]:font-medium [&>:nth-child(3):last-child]:col-start-[-2] max-[430px]:grid-cols-[1fr_auto_auto] max-[430px]:gap-1.5 max-[430px]:[&>span]:col-span-full max-[430px]:[&>strong]:col-start-1 max-[430px]:[&>[data-field-copy-value]]:col-start-1'

const detailScrollClassName =
  'bg-muted/30 min-h-0 flex-1 [scrollbar-color:var(--border-strong)_transparent] overflow-auto px-4 pt-4 pb-7 max-[680px]:px-3 max-[680px]:pt-3 max-[680px]:pb-5'

const titlebarClassName = cn(
  // Base titlebar layout and appearance.
  'border-border relative z-20 flex h-[54px] min-h-[54px] items-center gap-3 border-b bg-[color-mix(in_oklch,var(--card)_86%,transparent)] py-0 pr-3.5 pl-[78px] shadow-[inset_0_1px_color-mix(in_oklch,var(--shadow-color)_5%,transparent)] backdrop-blur-xl backdrop-saturate-180 select-none [-webkit-app-region:drag]',
  // Compact layouts.
  'max-[1050px]:pl-[70px] max-[880px]:pl-3.5 max-[680px]:h-[52px] max-[680px]:min-h-[52px] max-[430px]:gap-2 max-[430px]:px-[9px]',
  // Leave space for the macOS traffic-light controls.
  '[.platform-macos_&]:border-b-transparent [.platform-macos_&]:bg-transparent [.platform-macos_&]:pl-[94px] [.platform-macos_&]:shadow-none [.platform-macos_&]:backdrop-filter-none max-[880px]:[.platform-macos_&]:pl-[82px] max-[430px]:[.platform-macos_&]:py-0 max-[430px]:[.platform-macos_&]:pr-[9px] max-[430px]:[.platform-macos_&]:pl-[82px]',
  // Windows draws its native controls outside the titlebar content.
  '[.platform-windows_&]:border-b-transparent [.platform-windows_&]:bg-transparent [.platform-windows_&]:pl-3.5 [.platform-windows_&]:shadow-none [.platform-windows_&]:backdrop-filter-none max-[430px]:[.platform-windows_&]:px-[9px]',
  // Respect the browser-provided safe area when Window Controls Overlay is active.
  '[.platform-window-controls-overlay_&]:h-[env(titlebar-area-height,54px)] [.platform-window-controls-overlay_&]:min-h-[env(titlebar-area-height,54px)] [.platform-window-controls-overlay_&]:pr-[calc(14px+100vw-env(titlebar-area-x,0px)-env(titlebar-area-width,100vw))] [.platform-window-controls-overlay_&]:pl-[calc(14px+env(titlebar-area-x,0px))] max-[430px]:[.platform-window-controls-overlay_&]:pr-[calc(9px+100vw-env(titlebar-area-x,0px)-env(titlebar-area-width,100vw))] max-[430px]:[.platform-window-controls-overlay_&]:pl-[calc(9px+env(titlebar-area-x,0px))]'
)

const folderSectionClassName =
  'flex flex-none flex-col [&>header]:flex [&>header]:items-center [&>header]:justify-between [&>header]:pt-0 [&>header]:pr-1.5 [&>header]:pb-1 [&>header]:pl-[9px] [&_h2]:m-0 [&_h2]:text-[10px] [&_h2]:font-[760] [&_h2]:tracking-[0.11em] [&_h2]:text-muted-foreground [&_h2]:uppercase'

function detailIconClassName(type?: VaultItemType): string {
  return cn(
    'outline-foreground/5 bg-muted text-primary dark:border-border dark:bg-muted dark:text-muted-foreground grid size-9 flex-none place-items-center rounded-md shadow-(--control-highlight) outline max-[430px]:hidden forced-colors:[forced-color-adjust:none]',
    type === 'login' && 'overflow-hidden',
    type === 'card' && 'bg-muted text-chart-4 dark:bg-website-icon-background',
    type === 'identity' && 'bg-accent text-primary',
    type === 'secureNote' && 'bg-muted text-chart-3',
    type === 'sshKey' && 'bg-accent text-chart-2'
  )
}

function describeError(
  error: unknown,
  messages: Record<string, string>,
  unknownError: string,
  fallbackError: string
): string {
  if (!(error instanceof Error)) return unknownError
  const code = Object.keys(messages).find((key) => error.message.includes(key))
  return code ? messages[code] : fallbackError
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

function hostLabel(uri: string | null, unsetLabel: string): string {
  if (!uri) return unsetLabel
  try {
    return new URL(uri).hostname
  } catch {
    return uri
  }
}

function customFieldDisplayValue(
  field: VaultCustomFieldView,
  labels: {
    yes: string
    no: string
    linkedTo: (label: string) => string
    itemField: string
    linkedFields: Record<number, string>
    unset: string
  }
): string {
  if (field.type === 'boolean')
    return field.value?.toLowerCase() === 'true' ? labels.yes : labels.no
  if (field.type === 'linked') {
    return labels.linkedTo(
      field.linkedId === null
        ? labels.itemField
        : (labels.linkedFields[field.linkedId] ?? labels.itemField)
    )
  }
  return field.value || labels.unset
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

function detailFields(login: LoginView, labels: Record<string, string>): DetailField[] {
  if (login.type === 'login') {
    return [
      { field: 'username', label: labels.username!, value: login.username, copyable: true },
      { field: 'password', label: labels.password!, secret: true },
      ...login.uris.map((entry, uriIndex) => ({
        field: 'uri' as const,
        label: uriIndex === 0 ? labels.website! : `${labels.website} ${uriIndex + 1}`,
        value: entry.uri,
        copyable: true,
        openUri: true,
        uriIndex
      }))
    ]
  }
  if (login.type === 'card') {
    return [
      { field: 'number', label: labels.cardNumber!, secret: true },
      { field: 'code', label: labels.securityCode!, secret: true },
      {
        field: 'cardholderName',
        label: labels.cardholder!,
        value: login.cardholderName,
        copyable: true
      },
      { field: 'brand', label: labels.brand!, value: login.brand, copyable: true },
      {
        field: 'cardExpiration',
        label: labels.expirationDate!,
        value: [login.expMonth, login.expYear].filter(Boolean).join(' / '),
        copyable: true
      }
    ]
  }
  if (login.type === 'identity') {
    return [
      {
        field: 'username',
        label: labels.name!,
        value: [login.title, login.firstName, login.middleName, login.lastName]
          .filter(Boolean)
          .join(' ')
      },
      { field: 'username', label: labels.company!, value: login.company },
      { field: 'email', label: labels.email!, value: login.email, copyable: true },
      { field: 'phone', label: labels.phone!, value: login.phone, copyable: true },
      {
        field: 'identityUsername',
        label: labels.username!,
        value: login.identityUsername,
        copyable: true
      },
      {
        field: 'username',
        label: labels.address!,
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
      { field: 'ssn', label: labels.ssn!, secret: true },
      { field: 'passportNumber', label: labels.passportNumber!, secret: true },
      { field: 'licenseNumber', label: labels.licenseNumber!, secret: true }
    ]
  }
  if (login.type === 'sshKey') {
    return [
      { field: 'privateKey', label: labels.privateKey!, secret: true },
      { field: 'publicKey', label: labels.publicKey!, value: login.publicKey, copyable: true },
      {
        field: 'fingerprint',
        label: labels.keyFingerprint!,
        value: login.fingerprint,
        copyable: true
      }
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
  const { t } = useLingui()
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
        <span>
          <Trans>Unfiled</Trans>
        </span>
        <small aria-label={t`${count} items`}>{count}</small>
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
  const { t } = useLingui()
  const TypeIcon = itemTypeIcons[item.type]

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
          label={t`Back to item list`}
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
            <TypeIcon size={18} />
          )}
        </span>
        <div className="[&>span]:text-muted-foreground min-w-0 flex-1 [&>h2]:m-0 [&>h2]:truncate [&>h2]:text-base [&>h2]:font-medium [&>h2]:tracking-[-0.015em] [&>span]:mt-0.5 [&>span]:block [&>span]:truncate [&>span]:text-[10px]">
          <h2>{item.name}</h2>
          <span>
            {item.subtitle ||
              (item.type === 'login'
                ? hostLabel(item.uri, t`Website not set`)
                : t`Securely stored item`)}
          </span>
        </div>
        <Skeleton className="size-[34px] flex-none rounded-md" aria-hidden="true" />
        <Skeleton
          className="h-8 w-[68px] flex-none rounded-md max-[680px]:w-[34px]"
          aria-hidden="true"
        />
        <span className="sr-only" role="status">
          <Trans>Loading item details…</Trans>
        </span>
      </DetailHeader>

      <div className={detailScrollClassName} aria-hidden="true">
        <DetailCard variant="placeholder">
          <CardHeader>
            <Skeleton className="h-3 w-20" />
          </CardHeader>
          <CardContent className="flex flex-col">
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
          <CardHeader>
            <Skeleton className="h-3 w-24" />
          </CardHeader>
          <CardContent className="flex flex-col">
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
  const [accountStatus, setAccountStatus] = useState<AccountStatus | null>(null)
  const [accountBusy, setAccountBusy] = useState(false)
  const [accountBusyLabel, setAccountBusyLabel] = useState('')
  const [accountError, setAccountError] = useState('')
  const [settingsBusy, setSettingsBusy] = useState(false)
  const [touchIdPassword, setTouchIdPassword] = useState('')
  const [portabilityDialogMode, setPortabilityDialogMode] = useState<VaultPortabilityMode | null>(
    null
  )
  const [activeDragId, setActiveDragId] = useState<string | null>(null)
  const [activeDragOverId, setActiveDragOverId] = useState<string | null>(null)
  const foldersBeforeDragRef = useRef<FolderView[] | null>(null)
  const foldersDuringDragRef = useRef<FolderView[] | null>(null)
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

  const requestEditorTransition = useCallback(
    (action: () => void): void => {
      if (editorTransitionApprovedRef.current || !editorDirtyRef.current) {
        action()
        return
      }
      pendingEditorActionRef.current = action
      setDiscardEditorDialogOpen(true)
    },
    [setDiscardEditorDialogOpen]
  )

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
  }, [setDiscardEditorDialogOpen])

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
  }, [setPasswordHistoryDialogOpen, updateSelectedIds])

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
    [setPasswordHistoryDialogOpen]
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
        editorDirtyRef.current = false
        setEditorDirty(false)
        setTotpCodeState(null)
        setRevealedSecrets(emptyRevealedSecrets)
        setRevealedCustomFields(emptyRevealedCustomFields)
      }
    },
    [authorizationToken, setPasswordHistoryDialogOpen]
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
    [discardAuthorizationToken, setPasswordHistoryDialogOpen]
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
  }, [clearDetailCache, describeVaultError, invalidateProtectedDetails])

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
    [authorizationToken, requestEditorTransition, setPasswordHistoryDialogOpen]
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
    (syncStatus.configured ? t`Connected account` : t`Local vault`)

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
          announceError(describeVaultError(searchError))
        }
      )
    }, VAULT_SEARCH_DEBOUNCE_MS)

    return () => window.clearTimeout(timeout)
  }, [describeVaultError, items, query])

  const scopedItems = useMemo(() => {
    const matchedItems = filterVaultSearchMatches(items, query, searchMatches)
    const scoped = matchedItems.filter((item) =>
      matchesVaultSearchNavigation(item, query, scope, typeFilter)
    )
    return sortVaultItems(scoped, scope.kind === 'recent' ? 'recent' : sortMode)
  }, [items, query, scope, searchMatches, sortMode, typeFilter])
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
            setAccountError(t`The local account list could not be loaded. Try again later.`)
          }
        }
      )
    })
    return () => {
      active = false
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
    setSettingsBusy(true)
    try {
      const next = await window.bearwarden.settings.update(update)
      setSettings(next)
      if (update.language) await activateLanguagePreference(next.language).catch(() => undefined)
      if (update.defaultSort) {
        setSortMode(update.defaultSort === 'name' ? 'title' : update.defaultSort)
      }
      announce(t`Settings saved.`)
      return true
    } catch (settingsError) {
      announceError(describeVaultError(settingsError))
      return false
    } finally {
      setSettingsBusy(false)
    }
  }

  async function enableTouchId(): Promise<void> {
    if (!touchIdPassword) {
      announceError(t`Enter your master password before enabling biometrics.`)
      return
    }
    setSettingsBusy(true)
    try {
      const next = await window.bearwarden.settings.enableTouchId({
        masterPassword: touchIdPassword
      })
      setSettings(next)
      setTouchIdPassword('')
      announce(t`Biometrics enabled.`)
    } catch (touchIdError) {
      announceError(describeVaultError(touchIdError))
    } finally {
      setSettingsBusy(false)
    }
  }

  async function disableTouchId(): Promise<void> {
    setSettingsBusy(true)
    try {
      const next = await window.bearwarden.settings.disableTouchId()
      setSettings(next)
      announce(t`Biometrics disabled.`)
    } catch (touchIdError) {
      announceError(describeVaultError(touchIdError))
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
        ? t`Securely switching accounts and restarting`
        : operation === 'remove'
          ? t`Securely removing local account`
          : t`Updating local account order`
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
              ? t`The local account was removed. Remaining encrypted local data will be securely cleaned up on the next launch.`
              : t`The local account and its data on this device were removed.`
          )
        } else if (operation === 'reorder' && result.kind === 'updated') {
          announce(t`Local account order updated.`)
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
        setAccountBusyLabel(t`Reloading local accounts`)
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
            setAccountError(
              t`${message} The list could not be reloaded. Close Settings and try again.`
            )
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
        announce(updated.favorite ? t`Added to favorites.` : t`Removed from favorites.`)
      } catch (favoriteError) {
        announceError(describeVaultError(favoriteError))
      }
    },
    [announce, describeVaultError, t, withReprompt]
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
      editorDirtyRef.current = false
      setEditorDirty(false)
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

  function renderDetailField(field: DetailField): React.JSX.Element {
    const secretField = field.field as VaultSecretField
    const isPasswordField = field.field === 'password'
    const revealedValue =
      field.secret && revealedSecrets.itemId === selectedLogin?.id
        ? revealedSecrets.values[secretField]
        : undefined
    const hasExtraAction = Boolean(field.copyable) && Boolean(field.openUri)
    const canCopyFromValue =
      field.field === 'username' ||
      field.field === 'password' ||
      Boolean(field.copyable && !field.secret && !field.openUri)
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
          t`Not set`
        )
      ) : field.secret ? (
        revealedValue === undefined ? (
          field.field === 'code' ? (
            '•••'
          ) : (
            '••••••••••••'
          )
        ) : field.field === 'number' ? (
          formatPaymentCardNumber(revealedValue) || t`Not set`
        ) : (
          revealedValue || t`Not set`
        )
      ) : (
        field.value || t`Not set`
      )
    const secretHoverHandlers = field.secret
      ? {
          onMouseEnter: () => {
            hoveringSecretFieldsRef.current.add(secretField)
            if (revealedValue !== undefined) return
            hoverRevealedSecretFieldsRef.current.add(secretField)
            void revealSecret(secretField, { quiet: true, forceShow: true })
          },
          onMouseLeave: () => {
            hoveringSecretFieldsRef.current.delete(secretField)
            if (secretField === 'password' && passwordZoomOpenRef.current) return
            if (!hoverRevealedSecretFieldsRef.current.delete(secretField)) return
            hideRevealedSecret(secretField)
          }
        }
      : undefined
    const value = (
      <strong className={valueClassName} {...(canCopyFromValue ? undefined : secretHoverHandlers)}>
        {displayValue}
      </strong>
    )
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
            aria-label={copiedKey === copyKey ? t`${field.label} copied` : t`Copy ${field.label}`}
            disabled={!field.secret && !field.value}
            onClick={() => void copyField(field.field, field.uriIndex)}
            {...secretHoverHandlers}
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
                label={t`Show password in large type`}
                onClick={() => void openPasswordZoom()}
              >
                <ZoomIn />
              </TooltipIconButton>
            ) : (
              <TooltipIconButton
                variant="outline"
                size="icon"
                type="button"
                label={
                  revealedValue === undefined ? t`Show ${field.label}` : t`Hide ${field.label}`
                }
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
              label={copiedKey === copyKey ? t`${field.label} copied` : t`Copy ${field.label}`}
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
                    ? t`${field.label} copied`
                    : t`Copy ${field.label}`
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
                label={t`Open website`}
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
    const label = field.name || t`Unnamed field`
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
              : revealedValue || t`Not set`
            : customFieldDisplayValue(field, customFieldLabels)}
        </strong>
        {hidden && (
          <TooltipIconButton
            variant="outline"
            size="icon"
            type="button"
            label={revealedValue === undefined ? t`Show ${label}` : t`Hide ${label}`}
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
              ? t`${label} copied`
              : t`Copy ${label}`
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
          <p>
            <Trans>Decrypting your items…</Trans>
          </p>
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
          <p>
            <Trans>Decrypting your items…</Trans>
          </p>
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
                label={sidebarOpen ? t`Close sidebar` : t`Open sidebar`}
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
              <Trans>Vault</Trans>
            </Button>
          )}
          {isMac && (
            <div className="inline-flex items-center gap-2 max-[680px]:hidden">
              <BrandMark hideMark />
              <Badge variant="secondary" className="bg-black/5 shadow-(--control-highlight)">
                <Trans>Beta</Trans>
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
                  'text-muted-foreground [@media(prefers-reduced-transparency:reduce)]:bg-card bg-card/50 hover:bg-muted hover:text-foreground absolute left-1/2 h-[38px] w-[clamp(300px,44vw,560px)] min-w-0 -translate-x-1/2 gap-[7px] rounded-[11px] border-0 py-0 pr-2 pl-2.5 focus-within:border-(--focus) max-[880px]:static max-[880px]:max-w-none max-[880px]:flex-1 max-[880px]:translate-x-0 max-[680px]:[&_kbd]:hidden',
                  'shadow-(--control-highlight) hover:shadow-(--control-highlight)',
                  '[-webkit-app-region:no-drag] **:[-webkit-app-region:no-drag]'
                )}
              >
                <Button
                  variant="ghost"
                  className="text-foreground hover:text-foreground h-full min-w-0 flex-1 justify-start bg-transparent p-0 text-xs font-normal shadow-none hover:bg-transparent hover:shadow-none focus-visible:border-transparent focus-visible:ring-0 focus-visible:outline-none aria-expanded:bg-transparent [&>span]:w-full [&>span]:min-w-0 [&>span]:text-left"
                  type="button"
                  aria-label={
                    query ? t`Search vault items, currently ${query}` : t`Search vault items`
                  }
                  aria-haspopup="dialog"
                  aria-expanded={searchOpen}
                  onClick={() => setSearchOpen(true)}
                >
                  <span className={cn('truncate', !query && 'text-muted-foreground')}>
                    {query || t`Search vault`}
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
                      aria-label={t`Clear search`}
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
                label={t`Add item`}
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
          aria-label={t`Close sidebar`}
          aria-hidden={!sidebarOpen}
          tabIndex={sidebarOpen ? 0 : -1}
          onClick={() => setSidebarOpen(false)}
        />

        <CommandDialog
          open={searchOpen}
          onOpenChange={setSearchOpen}
          title={t`Search vault`}
          description={t`Search names, summaries, websites, and content. Start with > for advanced field-specific search.`}
        >
          <Command
            className="max-h-[min(480px,70vh)] [&_[data-slot=command-input-wrapper]]:px-2 [&_[data-slot=command-input-wrapper]]:pt-2 [&_[data-slot=command-input-wrapper]]:pb-0"
            label={t`Search vault items`}
            loop
            shouldFilter={false}
          >
            <CommandInput
              ref={searchRef}
              placeholder={t`Search vault; for example, >name:github`}
              maxLength={MAX_VAULT_SEARCH_QUERY_LENGTH}
              value={query}
              onValueChange={updateQuery}
              endAdornment={
                query ? (
                  <InputGroupAddon align="inline-end">
                    <InputGroupButton
                      size="icon-xs"
                      type="button"
                      aria-label={t`Clear search`}
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
            <CommandList className="scroll-fade-y forced-colors:scroll-fade-none max-h-[min(420px,calc(70vh-54px))] p-1.5">
              <CommandEmpty>
                <Trans>No matching vault items</Trans>
              </CommandEmpty>
              {scopedItems.length > 0 && (
                <CommandGroup
                  heading={
                    normalizedVaultSearchQuery(query)
                      ? t`Search results · ${scopedItems.length} items`
                      : t`${scopeTitle} · ${scopedItems.length} items`
                  }
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
                          className={cn(
                            'bg-foreground/5 text-muted-foreground grid size-[30px] flex-none place-items-center rounded',
                            item.type === 'login' && scope.kind !== 'trash' && 'overflow-hidden'
                          )}
                          aria-hidden="true"
                        >
                          {item.type === 'card' ? (
                            <PaymentCardBrandMark
                              brand={normalizeBitwardenCardBrand(item.cardBrand)}
                              compact
                            />
                          ) : item.type === 'login' && scope.kind !== 'trash' ? (
                            <WebsiteIcon
                              id={item.id}
                              uri={item.uri}
                              enabled={settings?.showWebsiteIcons ?? false}
                            />
                          ) : (
                            <ItemIcon />
                          )}
                        </span>
                        <span className="min-w-0 flex-1">
                          <strong className="block truncate">{item.name}</strong>
                          <small className="text-muted-foreground block truncate text-[10px]">
                            {item.subtitle || item.username || item.uri || t`No summary`}
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
            aria-label={t`Vault navigation`}
          >
            <div className="scroll-fade-y forced-colors:scroll-fade-none min-h-0 flex-1 [scrollbar-color:color-mix(in_oklch,var(--muted-foreground)_25%,transparent)_transparent] overflow-y-auto overscroll-contain max-[880px]:pt-2">
              <section
                className={cn(folderSectionClassName, 'px-[11px] pb-1')}
                aria-labelledby="categories-title"
              >
                <h2 className="hidden" id="categories-title">
                  <Trans>Categories</Trans>
                </h2>
                <nav className="grid grid-cols-2 gap-2 p-0 pt-px" aria-label={t`Vault categories`}>
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
                  <h2 id="quick-title">
                    <Trans>Quick access</Trans>
                  </h2>
                </header>
                <nav className="grid gap-[3px] px-2.5 py-1" aria-label={t`Quick access`}>
                  <SidebarLink
                    icon={<Star size={16} />}
                    label={t`Favorites`}
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
                    label={t({
                      message: 'Recently used',
                      context: 'recent-items-filter',
                      comment:
                        'Navigation and sort label for vault items that have been used most recently.'
                    })}
                    count={activeItems.filter((item) => item.lastUsedAt).length}
                    active={scope.kind === 'recent'}
                    onClick={() => selectScope({ kind: 'recent' })}
                  />
                  <SidebarLink
                    icon={<Archive size={16} />}
                    label={t`Archive`}
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
                    label={t`Trash`}
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
                  <h2 id="folders-title">
                    <Trans>Folders</Trans>
                  </h2>
                  <TooltipIconButton
                    variant="sidebar"
                    size="icon"
                    className="hover:bg-sidebar-overlay-hover hover:text-foreground border-transparent bg-transparent shadow-none hover:shadow-(--control-highlight) dark:bg-transparent"
                    type="button"
                    label={t`Add folder`}
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
                      aria-label={t`Open ${sidebarAccountName} menu`}
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
                      <Trans>Generator</Trans>
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={openOrganizations}>
                      <UsersRound data-icon="inline-start" />
                      <Trans>Organizations</Trans>
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={openEmergencyAccess}>
                      <ShieldAlert data-icon="inline-start" />
                      <Trans>Emergency Access</Trans>
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={openSends}>
                      <SendIcon data-icon="inline-start" />
                      <Trans>Sends</Trans>
                    </DropdownMenuItem>
                  </DropdownMenuGroup>
                  <DropdownMenuSeparator />
                  <DropdownMenuGroup>
                    <DropdownMenuItem onClick={openHealth}>
                      <ShieldCheck data-icon="inline-start" />
                      <Trans>Health report</Trans>
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={openSettings}>
                      <Settings2 data-icon="inline-start" />
                      <Trans>Settings</Trans>
                    </DropdownMenuItem>
                  </DropdownMenuGroup>
                  <DropdownMenuSeparator />
                  <DropdownMenuGroup>
                    <DropdownMenuItem onClick={() => void lockVault()}>
                      <LockKeyhole data-icon="inline-start" />
                      <Trans>Lock vault</Trans>
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
                className="hover:bg-sidebar-overlay-hover hover:text-foreground size-[34px] rounded-[9px] border-transparent bg-transparent shadow-none hover:shadow-(--control-highlight) dark:bg-transparent"
                type="button"
                label={t`Cloud sync: ${syncStateMeta[syncStatus.state].label}`}
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
                          ? t`${selectedIds.size} selected · ${scopedItems.length} items total`
                          : t`${scopedItems.length} items`}
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
                          <SelectTrigger size="sm" variant="embedded" aria-label={t`Sort order`}>
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
                      <span>
                        <Trans>Search “{query}”</Trans>
                      </span>
                      <span>
                        <Trans>{scopedItems.length} results</Trans>
                      </span>
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
                      showTotpCodes={typeFilter === 'totp'}
                      totpCodes={totpListCodes}
                      readOnly={scope.kind === 'trash'}
                      className={cn(typeFilter === 'totp' && 'pb-20')}
                    />
                  ) : (
                    <Empty className="min-h-0 flex-1 gap-0 p-7">
                      <EmptyHeader>
                        <EmptyMedia
                          variant="icon"
                          className="text-primary mb-[13px] size-[52px] rounded-2xl bg-(--accent-soft)"
                        >
                          {query ? (
                            <Search className="size-8" />
                          ) : scope.kind === 'trash' ? (
                            <Trash2 className="size-8" />
                          ) : (
                            <KeyRound className="size-8" />
                          )}
                        </EmptyMedia>
                        <EmptyTitle className="m-0">
                          {query
                            ? t`No matching items`
                            : scope.kind === 'trash'
                              ? t`Trash is empty`
                              : t`There are no vault items here yet`}
                        </EmptyTitle>
                        <EmptyDescription className="text-muted-foreground mb-4 max-w-[290px] leading-[1.55]">
                          {query
                            ? t`Try a shorter search term or switch to All items.`
                            : scope.kind === 'trash'
                              ? t`Deleted items remain here until you restore or permanently delete them, or the server removes them according to its retention policy.`
                              : t`Add your first item and BearWarden will keep it safe.`}
                        </EmptyDescription>
                      </EmptyHeader>
                      <EmptyContent>
                        {query ? (
                          <Button variant="outline" type="button" onClick={() => updateQuery('')}>
                            <Trans>Clear search</Trans>
                          </Button>
                        ) : scope.kind !== 'trash' && scope.kind !== 'archive' ? (
                          <Button
                            className="before:ring-primary-foreground/20 relative h-[38px] gap-2 rounded-[9px] border-0 px-3.5 font-[680] shadow-[var(--subtle-primary-action-shadow)] before:pointer-events-none before:absolute before:inset-0 before:rounded-[inherit] before:ring-1 before:ring-inset has-data-[icon=inline-start]:pl-3.5"
                            type="button"
                            onClick={() => openEditor('create')}
                          >
                            <Plus data-icon="inline-start" />
                            <Trans>Add item</Trans>
                          </Button>
                        ) : null}
                      </EmptyContent>
                    </Empty>
                  )}
                  {typeFilter === 'totp' && scopedItems.length > 0 && (
                    <div
                      className={cn(
                        'pointer-events-none absolute right-4 bottom-4',
                        selectedSummaries.length >= 2 && 'bottom-20'
                      )}
                    >
                      <TotpCountdownIndicator
                        key={totpListCountdown?.code ?? 'loading'}
                        remainingSeconds={totpListCountdown?.remainingSeconds ?? null}
                        period={totpListCountdownPeriodSeconds}
                      />
                    </div>
                  )}
                  {(selectedSummaries.length >= 2 ||
                    (scope.kind === 'trash' && trashItems.length > 0)) && (
                    <footer
                      className="border-border bg-muted flex min-h-16 flex-none flex-wrap items-center justify-end gap-2 border-t px-5 py-1"
                      aria-label={t`List actions`}
                    >
                      {selectedSummaries.length >= 2 && (
                        <div
                          className={cn(
                            'flex flex-wrap items-center gap-2',
                            scope.kind !== 'trash' && 'flex-1'
                          )}
                          role="toolbar"
                          aria-label={t`Bulk actions for selected items`}
                          aria-busy={busy}
                        >
                          <span className="sr-only" aria-live="polite">
                            <Trans>{selectedSummaries.length} items selected</Trans>
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
                                <Trans>Restore</Trans>
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
                                <Trans>Delete permanently</Trans>
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
                                <Trans>Delete</Trans>
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
                                  <Trans>Move</Trans>
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
                                  {scope.kind === 'archive' ? t`Unarchive` : t`Archive`}
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
                          <Trans>Empty Trash</Trans>
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
                          {selectedDetailFields
                            .filter((field) => field.secret || Boolean(field.value))
                            .map(renderDetailField)}
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
                        className="gap-1 pb-0"
                      >
                        <CardHeader>
                          <CardTitle id="attachments-title">
                            <Paperclip aria-hidden="true" />
                            <Trans>Attachments</Trans>
                          </CardTitle>
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
                              <Trans>Upload attachment</Trans>
                            </Button>
                          </CardAction>
                        </CardHeader>
                        <CardContent className="flex flex-col gap-4">
                          {attachmentOperation?.itemId === selectedLogin.id && (
                            <section className="flex flex-col gap-3" aria-live="polite">
                              <Progress value={attachmentProgressPercent(attachmentOperation)}>
                                <ProgressLabel>
                                  {getAttachmentStageLabel(attachmentOperation)}
                                  {attachmentOperation.fileName
                                    ? `：${attachmentOperation.fileName}`
                                    : ''}
                                </ProgressLabel>
                                <ProgressValue>
                                  {() =>
                                    attachmentProgressPercent(attachmentOperation) === null
                                      ? t`Processing`
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
                                {attachmentOperation.canceling ? t`Canceling` : t`Cancel`}
                              </Button>
                            </section>
                          )}
                          {selectedLogin.attachments.length > 0 && (
                            <div className="-mx-(--card-spacing) -mb-(--card-spacing) grid">
                              {selectedLogin.attachments.map((attachment) => (
                                <article
                                  key={attachment.id}
                                  className="border-border [&_small]:text-muted-foreground grid grid-cols-[34px_minmax(0,1fr)_auto] items-center gap-2.5 border-b px-(--card-spacing) py-3 [&_small]:truncate [&_small]:text-[10px] [&_span]:truncate [&_span]:text-[11px] [&_strong]:truncate [&_strong]:text-xs [&>div]:grid [&>div]:min-w-0 [&>div]:gap-[3px]"
                                >
                                  <span
                                    className="text-primary grid size-8 place-items-center rounded-md bg-(--accent-soft)"
                                    aria-hidden="true"
                                  >
                                    <Paperclip size={17} />
                                  </span>
                                  <div>
                                    <strong>{attachment.fileName}</strong>
                                    <span>
                                      {attachment.sizeName}
                                      {attachment.legacy
                                        ? t` · Legacy unauthenticated encryption`
                                        : ''}
                                    </span>
                                  </div>
                                  <section
                                    className="flex flex-wrap items-center justify-end gap-1"
                                    aria-label={t`Attachment actions for ${attachment.fileName}`}
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
                                        <Trans>Repair</Trans>
                                      </Button>
                                    )}
                                    <TooltipIconButton
                                      variant="outline"
                                      size="icon"
                                      type="button"
                                      label={t`Download ${attachment.fileName}`}
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
                                      label={t`Delete ${attachment.fileName}`}
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
                        className="gap-2 py-2"
                        role="region"
                        aria-labelledby="totp-title"
                        aria-busy={!totpRevealReady}
                      >
                        <CardHeader>
                          <CardTitle id="totp-title">
                            <Clock3 aria-hidden="true" />
                            <Trans>One-time verification code</Trans>
                          </CardTitle>
                          {totpGenerationError === 'unsupported' && (
                            <CardDescription>
                              <Trans>Unsupported key format</Trans>
                            </CardDescription>
                          )}
                          {!totpRevealReady && (
                            <span className="sr-only">
                              <Trans>Generating…</Trans>
                            </span>
                          )}
                          {!totpGenerationError && typeFilter !== 'totp' && (
                            <CardAction>
                              <TotpCountdownIndicator
                                key={totpCodeState?.cycle ?? 'loading'}
                                remainingSeconds={totpCode?.remainingSeconds ?? null}
                                period={totpCode?.period ?? totpListCountdownPeriodSeconds}
                                compact
                              />
                            </CardAction>
                          )}
                        </CardHeader>
                        <CardContent className="contents">
                          <div className="grid grid-cols-[minmax(0,1fr)_34px] items-center gap-2 px-(--card-spacing) py-2.5 [&_strong]:font-mono [&_strong]:text-[25px] [&_strong]:tracking-[0.18em]">
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
                                  ? t`One-time verification code copied`
                                  : t`Copy one-time verification code`
                              }
                              disabled={!totpCode || totpGenerationError !== null}
                              onClick={() => void copyTotp()}
                            >
                              <CopyFeedbackIcon copied={copiedKey === `totp:${selectedLogin.id}`} />
                            </TooltipIconButton>
                          </div>
                        </CardContent>
                      </DetailCard>
                    )}

                    {selectedLogin.type === 'login' && selectedLogin.passkeys.length > 0 && (
                      <DetailCard
                        role="region"
                        aria-labelledby="passkeys-title"
                        className="gap-1 pb-0"
                      >
                        <CardHeader>
                          <CardTitle id="passkeys-title">
                            <KeyRound aria-hidden="true" />
                            <Trans>Passkeys</Trans>
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="contents">
                          <div className="grid">
                            {selectedLogin.passkeys.map((passkey) => (
                              <article
                                key={passkey.credentialId}
                                className="border-border [&_small]:text-muted-foreground grid grid-cols-[34px_minmax(0,1fr)] items-start gap-2.5 border-b px-(--card-spacing) py-3 [&_small]:truncate [&_small]:text-[10px] [&_span]:truncate [&_span]:text-[11px] [&_strong]:truncate [&_strong]:text-xs [&>div]:grid [&>div]:min-w-0 [&>div]:gap-[3px]"
                              >
                                <span
                                  className="text-primary grid size-8 place-items-center rounded-md bg-(--accent-soft)"
                                  aria-hidden="true"
                                >
                                  <KeyRound size={17} />
                                </span>
                                <div>
                                  <strong>{passkey.rpName || passkey.rpId}</strong>
                                  <span>
                                    {passkey.userDisplayName || passkey.userName || t`Unnamed user`}
                                  </span>
                                  <small>
                                    {passkey.rpId} · {formatDate(passkey.creationDate)}
                                    {passkey.discoverable ? t` · Discoverable` : ''}
                                  </small>
                                </div>
                              </article>
                            ))}
                          </div>
                          <p className="text-muted-foreground m-0 px-(--card-spacing) pt-2.5 pb-[13px] text-[10px] leading-normal">
                            <Trans>
                              You can safely delete passkeys while editing the item. Private key
                              material is never sent to the renderer.
                            </Trans>
                          </p>
                        </CardContent>
                      </DetailCard>
                    )}

                    {(selectedLogin.type === 'secureNote' || selectedLogin.notes) && (
                      <DetailCard
                        role="region"
                        aria-labelledby="notes-title"
                        className="gap-1 pb-0"
                      >
                        <CardHeader>
                          <CardTitle id="notes-title">
                            <NotebookPen aria-hidden="true" />
                            {selectedLogin.type === 'secureNote' ? t`Secure note` : t`Notes`}
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="contents">
                          <p
                            className={cn(
                              'm-0 px-(--card-spacing) pt-3.5 pb-[17px] text-xs leading-[1.65] whitespace-pre-wrap',
                              !selectedLogin.notes?.trim() && 'text-muted-foreground'
                            )}
                          >
                            {selectedLogin.notes?.trim() ? selectedLogin.notes : t`No content yet`}
                          </p>
                        </CardContent>
                      </DetailCard>
                    )}

                    <DetailCard
                      role="region"
                      aria-labelledby="organization-title"
                      className="gap-1 pb-0"
                    >
                      <CardHeader>
                        <CardTitle id="organization-title">
                          <FolderOpen aria-hidden="true" />
                          <Trans comment="Section heading in a login item details view; groups the folder and the item usage timestamp, not calendar events.">
                            Organization and activity
                          </Trans>
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="contents">
                        <dl className="m-0 px-(--card-spacing) py-1">
                          <div className="border-border grid grid-cols-[minmax(90px,0.28fr)_minmax(0,1fr)] items-center gap-2 border-b py-2.5 last:border-b-0 max-[430px]:grid-cols-1 max-[430px]:items-start max-[430px]:gap-1">
                            <dt className="text-muted-foreground text-[11px] leading-4">
                              <Trans comment="Field label for the folder that contains this login item.">
                                Folder
                              </Trans>
                            </dt>
                            <dd className="m-0 flex min-w-0 items-center gap-2 text-xs leading-4">
                              <span className="min-w-0 flex-1 truncate">
                                {folders.find((folder) => folder.id === selectedLogin.folderId)
                                  ?.name ?? t`Unfiled`}
                              </span>
                              <Button
                                variant="ghost"
                                size="icon-sm"
                                className="-my-1.5 ml-auto"
                                type="button"
                                aria-label={t`Move to folder`}
                                disabled={busy}
                                onClick={openMoveDialogForSelection}
                              >
                                <Pencil aria-hidden="true" />
                              </Button>
                            </dd>
                          </div>
                          <div className="border-border grid grid-cols-[minmax(90px,0.28fr)_minmax(0,1fr)] items-center gap-2 border-b py-2.5 last:border-b-0 max-[430px]:grid-cols-1 max-[430px]:items-start max-[430px]:gap-1">
                            <dt className="text-muted-foreground text-[11px] leading-4">
                              <Trans
                                context="item-last-used"
                                comment="Field label for the last time this vault item was used; this is a usage timestamp, not a recent calendar event."
                              >
                                Recently used
                              </Trans>
                            </dt>
                            <dd className="m-0 min-w-0 text-xs leading-4">
                              {formatDate(selectedLogin.lastUsedAt)}
                            </dd>
                          </div>
                        </dl>
                      </CardContent>
                    </DetailCard>

                    <DetailCard
                      role="region"
                      aria-labelledby="history-title"
                      className="gap-1 pb-0"
                    >
                      <CardHeader>
                        <CardTitle id="history-title">
                          <History aria-hidden="true" />
                          <Trans comment="Section heading for the login item's creation, edit, password-change, and password-history metadata.">
                            Item history
                          </Trans>
                        </CardTitle>
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
            itemName={moveSummaries[0]?.name ?? t`Selected items`}
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
            itemName={t`${trashItems.length} items in Trash`}
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
                      ? t`Permanently delete ${pendingBulkAction.ids.length} items?`
                      : t`Move ${pendingBulkAction.ids.length} items to Trash?`}
                  </AlertDialogTitle>
                  <AlertDialogDescription>
                    {pendingBulkAction.action === 'deletePermanently'
                      ? t`This action cannot be undone. BearWarden does not keep a recoverable plaintext copy.`
                      : t`Items remain encrypted in Trash and can be restored later.`}
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel disabled={busy}>
                    <Trans>Cancel</Trans>
                  </AlertDialogCancel>
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
                    {pendingBulkAction.action === 'deletePermanently'
                      ? t`Delete permanently`
                      : t`Move to Trash`}
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
            title={t`Password`}
            description={t`Symbols, numbers, and letters use different colors to make them easier to distinguish.`}
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
        {loginApprovalPrompts[0] && (
          <LoginApprovalDialog
            key={loginApprovalPrompts[0].token}
            prompt={loginApprovalPrompts[0]}
            onClose={() => setLoginApprovalPrompts((current) => current.slice(1))}
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
              <AlertDialogTitle>
                <Trans>Delete attachment?</Trans>
              </AlertDialogTitle>
              <AlertDialogDescription>
                <Trans>
                  “{attachmentDeleteTarget?.fileName ?? t`This attachment`}” will be permanently
                  deleted from Bitwarden and cannot be recovered.
                </Trans>
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel type="button">
                <Trans>Keep attachment</Trans>
              </AlertDialogCancel>
              <AlertDialogAction
                type="button"
                variant="destructive"
                onClick={() => void deleteSelectedAttachment()}
              >
                <Trash2 data-icon="inline-start" />
                <Trans>Delete attachment</Trans>
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
              <AlertDialogTitle>
                <Trans>Discard unsaved changes?</Trans>
              </AlertDialogTitle>
              <AlertDialogDescription>
                <Trans>These changes have not been saved. Discarding them cannot be undone.</Trans>
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel type="button">
                <Trans>Continue editing</Trans>
              </AlertDialogCancel>
              <AlertDialogAction
                type="button"
                variant="destructive"
                onClick={confirmEditorDiscard}
                disabled={busy}
              >
                <Trans>Discard changes</Trans>
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
