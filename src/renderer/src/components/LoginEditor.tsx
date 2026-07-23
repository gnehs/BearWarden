import { useEffect, useRef, useState, type ReactNode } from 'react'
import {
  closestCenter,
  DndContext,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent
} from '@dnd-kit/core'
import {
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy
} from '@dnd-kit/sortable'
import { CSS } from '@dnd-kit/utilities'
import { Trans, useLingui } from '@lingui/react/macro'
import {
  CheckSquare2,
  ClipboardPaste,
  ContactRound,
  CreditCard,
  Eye,
  EyeOff,
  FileKey2,
  FolderOpen,
  GripVertical,
  KeyRound,
  Link2,
  ListPlus,
  NotebookPen,
  Plus,
  RefreshCw,
  Save,
  Sparkles,
  TextCursorInput,
  Trash2,
  UsersRound,
  X
} from 'lucide-react'
import type {
  FolderView,
  LoginView,
  PasskeyView,
  VaultCustomFieldType,
  VaultCustomFieldUpdate,
  VaultEditorSecretField,
  VaultItemFields,
  VaultItemType,
  VaultLoginUri,
  VaultUriMatch
} from '../../../shared/vault-contract'
import { VAULT_LINKED_FIELD_IDS_BY_TYPE } from '../../../shared/vault-contract'
import { cn } from '../lib/utils'
import {
  detectPaymentCardBrand,
  formatPaymentCardNumber,
  paymentCardBrandOption,
  sanitizePaymentCardNumber,
  type PaymentCardBrand,
  type PaymentCardBrandOption
} from '../lib/payment-card'
import { Button } from './ui/button'
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
} from './ui/alert-dialog'
import { Badge } from './ui/badge'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Checkbox } from './ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from './ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuTrigger
} from './ui/dropdown-menu'
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle
} from './ui/empty'
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSet,
  FieldTitle
} from './ui/field'
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
  InputGroupTextarea
} from './ui/input-group'
import { Input } from './ui/input'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue
} from './ui/select'
import { Spinner } from './ui/spinner'
import { Textarea } from './ui/textarea'
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip'
import CredentialGeneratorDialog from './CredentialGeneratorDialog'
import {
  canSelectCustomFieldType,
  reorderEditorItemsByClientId,
  reorderEditorUris,
  uriMatchRecognizedParts,
  type EditorLoginUri,
  type UriMatchOptionValue
} from './login-editor-ui'
import {
  applyImportedSshKey,
  applyGeneratedSshKey,
  canApplyGeneratedSshKey,
  clearSshKeyMaterial,
  invalidateFailedSshImport,
  isValidSshImportPassphrase,
  isSshKeyGenerationBlockingSave,
  sshKeyImportResultAction,
  sshKeyGenerationAction,
  sshKeyMaterialState,
  type SshKeyGenerationState,
  type SshKeyImportState
} from './ssh-key-editor-state'

type EditorSecretField = VaultEditorSecretField
type EditorErrorKind = 'name' | 'password' | 'ssh' | 'uri' | 'reveal' | null
type SecretLoadState = 'loading' | 'ready' | 'error'

export type EditorCustomField = VaultCustomFieldUpdate & {
  /** Renderer-only identity for stable React list keys. Removed before IPC submission. */
  clientId: string
}

const paymentCardBrands: Exclude<PaymentCardBrand, 'unknown'>[] = [
  'visa',
  'mastercard',
  'jcb',
  'american-express'
]

const fieldGridClassName = 'grid grid-cols-[repeat(auto-fit,minmax(140px,1fr))] gap-[13px]'
const checkFieldClassName =
  'flex items-start gap-2.5 rounded-lg border bg-muted p-2.5 [&_[data-slot=checkbox]]:size-[17px] [&_[data-slot=checkbox]]:accent-[var(--primary)] [&_[data-slot=field-content]]:grid [&_[data-slot=field-content]]:gap-[3px] [&_[data-slot=field-content]_[data-slot=field-label]]:text-xs [&_[data-slot=field-description]]:text-[10px]'

const itemTypeIcons: Record<VaultItemType, typeof KeyRound> = {
  login: KeyRound,
  card: CreditCard,
  identity: ContactRound,
  secureNote: NotebookPen,
  sshKey: FileKey2
}

const emptyFields: VaultItemFields = {
  username: '',
  password: '',
  totp: '',
  uri: null,
  cardholderName: '',
  brand: '',
  number: '',
  expMonth: '',
  expYear: '',
  code: '',
  title: '',
  firstName: '',
  middleName: '',
  lastName: '',
  address1: '',
  address2: '',
  address3: '',
  city: '',
  state: '',
  postalCode: '',
  country: '',
  company: '',
  email: '',
  phone: '',
  ssn: '',
  identityUsername: '',
  passportNumber: '',
  licenseNumber: '',
  privateKey: '',
  publicKey: '',
  fingerprint: ''
}

function newCustomFieldClientId(): string {
  return `custom-field-${crypto.randomUUID()}`
}

function newUriClientId(): string {
  return `uri-${crypto.randomUUID()}`
}

function urisFromLogin(login?: LoginView): EditorLoginUri[] {
  return (login?.uris ?? []).map((entry) => ({ ...entry, clientId: newUriClientId() }))
}

function customFieldsFromLogin(login?: LoginView): EditorCustomField[] {
  return (login?.customFields ?? []).map((field, index) => ({
    clientId: newCustomFieldClientId(),
    source: {
      index,
      name: field.name,
      type: field.type,
      linkedId: field.linkedId
    },
    name: field.name,
    type: field.type,
    value:
      field.type === 'text'
        ? (field.value ?? '')
        : field.type === 'boolean'
          ? field.value === 'true'
            ? 'true'
            : 'false'
          : null,
    linkedId: field.linkedId
  }))
}

function linkedIdsForItemType(itemType: VaultItemType): readonly number[] {
  return VAULT_LINKED_FIELD_IDS_BY_TYPE[itemType]
}

function normalizeCustomFieldsForItemType(
  customFields: EditorCustomField[],
  itemType: VaultItemType
): EditorCustomField[] {
  const linkedIds = linkedIdsForItemType(itemType)

  return customFields.map((field) => {
    if (field.type !== 'linked') return field

    if (linkedIds.length === 0) {
      return { ...field, type: 'text', value: '', linkedId: null }
    }

    return {
      ...field,
      value: null,
      linkedId: linkedIds.includes(field.linkedId ?? Number.NaN)
        ? field.linkedId
        : (linkedIds[0] ?? null)
    }
  })
}

export interface LoginDraft extends VaultItemFields {
  type: VaultItemType
  expectedUpdatedAt: string | null
  name: string
  notes: string
  folderId: string | null
  favorite: boolean
  reprompt: 0 | 1
  uris: EditorLoginUri[]
  changedSecrets: EditorSecretField[]
  customFields: EditorCustomField[]
  /** Renderer-only handle for main-process-only generated or imported private-key material. */
  sshImportToken?: string
}

interface LoginEditorProps {
  login?: LoginView
  folders: FolderView[]
  sharedContext?: {
    organizationName: string
    collectionNames: string[]
    canEditSecrets: boolean
  }
  busy: boolean
  authorizationToken?: string
  onCancel: () => void
  onDirtyChange: (dirty: boolean) => void
  onDeletePasskey: (credentialId: string, expectedUpdatedAt: string) => Promise<LoginView | null>
  onSave: (draft: LoginDraft) => Promise<boolean>
}

function EditorFormSection({
  title,
  titleId,
  icon,
  children
}: {
  title: string
  titleId: string
  icon: ReactNode
  children: ReactNode
}): React.JSX.Element {
  return (
    <Card
      variant="item"
      className="mx-auto mb-3 w-full max-w-[720px]"
      role="region"
      aria-labelledby={titleId}
    >
      <CardHeader>
        <CardTitle id={titleId}>
          {icon}
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <FieldSet>
          <FieldLegend className="sr-only">{title}</FieldLegend>
          {children}
        </FieldSet>
      </CardContent>
    </Card>
  )
}

function EditorSection({
  value,
  className,
  children
}: {
  value: 'details' | 'custom' | 'organize'
  className?: string
  children: ReactNode
}): React.JSX.Element {
  return (
    <section className={className} data-editor-section={value}>
      {children}
    </section>
  )
}

function UriMatchExampleText({
  value,
  rawUri,
  className
}: {
  value: UriMatchOptionValue
  rawUri: string
  className?: string
}): React.JSX.Element {
  const parts = uriMatchRecognizedParts(value, rawUri)
  if (!rawUri.trim()) {
    return (
      <span className={cn('text-muted-foreground text-[10px]', className)}>
        <Trans>Enter a URL to see a matching example</Trans>
      </span>
    )
  }

  return (
    <code
      className={cn('min-w-0 font-mono text-[10px] break-all whitespace-pre-wrap', className)}
      data-uri-match-recognized={value}
    >
      {parts.leading}
      {parts.recognized && (
        <strong className="text-foreground font-semibold">{parts.recognized}</strong>
      )}
      {parts.trailing}
    </code>
  )
}

function UriMatchExample({
  value,
  rawUri
}: {
  value: UriMatchOptionValue
  rawUri: string
}): React.JSX.Element {
  return (
    <p
      className="text-muted-foreground m-0 flex min-w-0 flex-wrap items-baseline gap-x-1.5 px-1 text-[10px] leading-4"
      data-uri-match-example={value}
    >
      <span className="shrink-0 font-medium">
        <Trans>Match example</Trans>
      </span>
      <UriMatchExampleText value={value} rawUri={rawUri} />
    </p>
  )
}

function SortableUriRow({
  id,
  disabled,
  dragLabel,
  actions,
  children
}: {
  id: string
  disabled: boolean
  dragLabel: string
  actions: ReactNode
  children: ReactNode
}): React.JSX.Element {
  const {
    attributes,
    listeners,
    setNodeRef,
    setActivatorNodeRef,
    transform,
    transition,
    isDragging
  } = useSortable({ id, disabled })

  return (
    <div
      ref={setNodeRef}
      className={cn(
        'grid grid-cols-[auto_minmax(0,1fr)_auto] gap-2 rounded-md border p-3',
        isDragging && 'opacity-60'
      )}
      style={{ transform: CSS.Transform.toString(transform), transition }}
      data-uri-sortable-row=""
      data-dragging={isDragging ? 'true' : undefined}
    >
      <Button
        ref={setActivatorNodeRef}
        type="button"
        variant="ghost"
        size="icon-sm"
        className="row-span-2 h-7 w-5 min-w-5 cursor-grab touch-none self-center px-0 active:cursor-grabbing"
        aria-label={dragLabel}
        disabled={disabled}
        {...attributes}
        {...listeners}
      >
        <GripVertical aria-hidden="true" />
      </Button>
      {children}
      <div className="col-start-3 row-start-2 flex items-start justify-end gap-1">{actions}</div>
    </div>
  )
}

function SortableCustomFieldCard({
  id,
  disabled,
  dragLabel,
  children
}: {
  id: string
  disabled: boolean
  dragLabel: string
  children: ReactNode
}): React.JSX.Element {
  const {
    attributes,
    listeners,
    setNodeRef,
    setActivatorNodeRef,
    transform,
    transition,
    isDragging
  } = useSortable({ id, disabled })

  return (
    <div
      ref={setNodeRef}
      className={cn('grid grid-cols-[auto_minmax(0,1fr)] gap-1', isDragging && 'opacity-60')}
      style={{ transform: CSS.Transform.toString(transform), transition }}
      data-custom-field-sortable-row=""
      data-dragging={isDragging ? 'true' : undefined}
    >
      <Button
        ref={setActivatorNodeRef}
        type="button"
        variant="ghost"
        size="icon-sm"
        className="mt-3 h-7 w-5 min-w-5 cursor-grab touch-none px-0 active:cursor-grabbing"
        aria-label={dragLabel}
        disabled={disabled}
        {...attributes}
        {...listeners}
      >
        <GripVertical aria-hidden="true" />
      </Button>
      {children}
    </div>
  )
}

function LoginEditor({
  login,
  folders,
  sharedContext,
  busy,
  authorizationToken,
  onCancel,
  onDirtyChange,
  onDeletePasskey,
  onSave
}: LoginEditorProps): React.JSX.Element {
  const { t } = useLingui()
  const linkedFieldLabels: Record<number, string> = {
    100: t`Username`,
    101: t`Password`,
    300: t`Cardholder`,
    301: t`Expiration month`,
    302: t`Expiration year`,
    303: t`Security code`,
    304: t`Card brand`,
    305: t`Card number`,
    400: t`Title`,
    401: t`Middle name`,
    402: t`Address`,
    403: t`Address line 2`,
    404: t`Address line 3`,
    405: t`City`,
    406: t`State / Province`,
    407: t`Postal code`,
    408: t`Country / Region`,
    409: t`Company`,
    410: t`Email`,
    411: t`Phone`,
    412: t`National ID / Social Security number`,
    413: t`Username`,
    414: t`Passport number`,
    415: t`License number`,
    416: t`First name`,
    417: t`Last name`,
    418: t`Full name`
  }
  const customFieldTypeLabels: Record<VaultCustomFieldType, string> = {
    text: t`Text`,
    hidden: t`Hidden text`,
    boolean: t`Checkbox`,
    linked: t`Linked field`
  }
  const paymentCardBrandLabels: Record<Exclude<PaymentCardBrand, 'unknown'>, string> = {
    visa: t`Visa`,
    mastercard: t`Mastercard`,
    jcb: t`JCB`,
    'american-express': t`American Express`
  }
  const paymentCardBrandSelectItems: Array<{
    value: PaymentCardBrandOption
    label: string
  }> = [
    { value: '', label: t`Not set` },
    ...paymentCardBrands.map((value) => ({ value, label: paymentCardBrandLabels[value] })),
    { value: 'unknown', label: t`Other` }
  ]
  const itemTypes: Array<{ value: VaultItemType; label: string; description: string }> = [
    { value: 'login', label: t`Login`, description: t`Username, password, and websites` },
    { value: 'card', label: t`Card`, description: t`Payment card and security code` },
    { value: 'identity', label: t`Identity`, description: t`Personal and contact information` },
    { value: 'secureNote', label: t`Secure note`, description: t`Encrypted notes only` },
    { value: 'sshKey', label: t`SSH key`, description: t`Private key, public key, and fingerprint` }
  ]
  const typeLabel = (type: VaultItemType): string =>
    itemTypes.find((item) => item.value === type)?.label ?? t`Item`
  const itemTypeSelectItems = itemTypes.map((item) => ({
    value: item.value,
    label: t`${item.label}: ${item.description}`
  }))
  const uriMatchOptions: Array<{ value: UriMatchOptionValue; label: string }> = [
    { value: 'default', label: t`Default` },
    { value: '0', label: t`Base domain` },
    { value: '1', label: t`Host` },
    { value: '2', label: t`Starts with` },
    { value: '3', label: t`Exact` },
    { value: '4', label: t`Regular expression` },
    { value: '5', label: t`Never` }
  ]
  const sshImportErrorMessage = (
    code: Extract<
      Awaited<ReturnType<typeof window.bearwarden.sshKeys.beginImport>>,
      { status: 'error' }
    >['code']
  ): string => {
    const messages = {
      EmptyClipboard: t`The clipboard is empty. Copy an SSH private key and try again.`,
      ClipboardTooLarge: t`The clipboard contents are too large to import safely as an SSH private key.`,
      ParsingError: t`The SSH private key in the clipboard could not be parsed. Make sure the key is complete.`,
      UnsupportedKeyType: t`This SSH private key type is not supported. Use a supported key format.`,
      WrongPassword: t`The private key password is incorrect. Try again.`,
      InvalidPassphrase: t`Enter a valid private key password.`,
      SessionUnavailable: t`The SSH private key import session has expired. Import the key from the clipboard again.`,
      SessionLimitReached: t`Too many SSH private key import sessions are active. Try again later.`
    }
    return messages[code]
  }
  const submittingRef = useRef(false)
  const sharedEditor = sharedContext !== undefined
  const editorMountedRef = useRef(true)
  const sshKeyGenerationRequestRef = useRef(0)
  const sshKeyImportRequestRef = useRef(0)
  const activeSshImportTokenRef = useRef<string | null>(null)
  const sshImportPassphraseRef = useRef<HTMLInputElement>(null)
  const [editorSnapshot] = useState(() =>
    login
      ? {
          id: login.id,
          expectedUpdatedAt: login.updatedAt,
          ...(authorizationToken ? { authorizationToken } : {})
        }
      : null
  )
  const [generatorTarget, setGeneratorTarget] = useState<'password' | 'username' | null>(null)
  const [passkeyDeleteTarget, setPasskeyDeleteTarget] = useState<PasskeyView | null>(null)
  const [draft, setDraft] = useState<LoginDraft>(() => ({
    ...emptyFields,
    ...login,
    // Editor secrets are loaded separately so they never enter LoginView or the detail cache.
    password: '',
    totp: '',
    number: '',
    code: '',
    ssn: '',
    passportNumber: '',
    licenseNumber: '',
    privateKey: '',
    type: login?.type ?? 'login',
    expectedUpdatedAt: login?.updatedAt ?? null,
    name: login?.name ?? '',
    notes: login?.notes ?? '',
    folderId: login?.folderId ?? null,
    favorite: login?.favorite ?? false,
    reprompt: login?.reprompt ?? 0,
    uris: urisFromLogin(login),
    changedSecrets: [],
    customFields: customFieldsFromLogin(login)
  }))
  const [selectedCardBrand, setSelectedCardBrand] = useState<PaymentCardBrandOption>(() =>
    paymentCardBrandOption(login?.brand)
  )
  const [cardBrandAutoDetected, setCardBrandAutoDetected] = useState(!login?.brand)
  const draftRef = useRef(draft)
  const [dirty, setDirty] = useState(false)
  const [visibleSecrets, setVisibleSecrets] = useState<Partial<Record<EditorSecretField, boolean>>>(
    {}
  )
  const [visibleCustomFields, setVisibleCustomFields] = useState<Record<string, boolean>>({})
  const [revealingCustomFields, setRevealingCustomFields] = useState<Record<string, boolean>>({})
  const [error, setError] = useState('')
  const [errorKind, setErrorKind] = useState<EditorErrorKind>(null)
  const [secretLoadState, setSecretLoadState] = useState<SecretLoadState>(
    login ? 'loading' : 'ready'
  )
  const [sshKeyGenerationState, setSshKeyGenerationState] = useState<SshKeyGenerationState>('idle')
  const [sshKeyImportState, setSshKeyImportState] = useState<SshKeyImportState>('idle')
  const [sshKeyImportSession, setSshKeyImportSession] = useState<{
    token: string
    expiresAt: number
  } | null>(null)
  const [sshKeyImportError, setSshKeyImportError] = useState('')
  const sortableSensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  )
  const nameRef = useRef<HTMLInputElement>(null)
  const secretsUnavailable = secretLoadState !== 'ready'
  const sshKeyImportPending =
    sshKeyImportState === 'reading' ||
    sshKeyImportState === 'awaitingPassphrase' ||
    sshKeyImportState === 'submittingPassphrase'
  const sshKeyUnavailable =
    (draft.type === 'sshKey' && sshKeyImportPending) ||
    isSshKeyGenerationBlockingSave(draft.type, sshKeyGenerationState, draft.sshImportToken)
  const sshKeyFieldsDisabled =
    busy || secretsUnavailable || sshKeyGenerationState === 'generating' || sshKeyImportPending

  useEffect(() => nameRef.current?.focus(), [])
  useEffect(() => {
    draftRef.current = draft
  }, [draft])
  useEffect(() => {
    editorMountedRef.current = true
    return () => {
      editorMountedRef.current = false
      sshKeyImportRequestRef.current += 1
      const importToken = activeSshImportTokenRef.current
      activeSshImportTokenRef.current = null
      if (importToken)
        void window.bearwarden.sshKeys.cancelImport({ token: importToken }).catch(() => {})
    }
  }, [])
  useEffect(() => {
    if (!editorSnapshot) return
    let active = true

    const editorSecrets = sharedEditor
      ? window.bearwarden.sharedLogins.revealEditorSecrets
      : window.bearwarden.logins.revealEditorSecrets
    void editorSecrets(editorSnapshot)
      .then((secrets) => {
        if (!active) return
        const customSecrets = new Map(
          secrets.customFields.map((entry) => [entry.source.index, entry])
        )
        setDraft((current) => {
          const next = { ...current }
          for (const [field, value] of Object.entries(secrets.fields) as Array<
            [EditorSecretField, string]
          >) {
            if (!current.changedSecrets.includes(field)) next[field] = value
          }
          next.customFields = current.customFields.map((field) => {
            const source = field.source
            if (!source) return field
            const secret = customSecrets.get(source.index)
            if (
              !secret ||
              secret.source.name !== source.name ||
              secret.source.type !== source.type ||
              secret.source.linkedId !== source.linkedId
            ) {
              return field
            }
            return { ...field, value: secret.value }
          })
          return next
        })
        setSecretLoadState('ready')
      })
      .catch(() => {
        if (!active) return
        setSecretLoadState('error')
        setError(t`Existing sensitive fields could not be loaded. Cancel editing and try again.`)
        setErrorKind('reveal')
      })

    return () => {
      active = false
    }
  }, [editorSnapshot, sharedEditor, t])
  useEffect(() => onDirtyChange(dirty), [dirty, onDirtyChange])
  useEffect(() => () => onDirtyChange(false), [onDirtyChange])
  useEffect(() => {
    if (
      secretLoadState !== 'ready' ||
      draft.type !== 'sshKey' ||
      sshKeyGenerationState !== 'idle' ||
      sshKeyImportState !== 'idle'
    )
      return

    const requestId = ++sshKeyGenerationRequestRef.current
    queueMicrotask(() => {
      if (!editorMountedRef.current || requestId !== sshKeyGenerationRequestRef.current) return
      const action = sshKeyGenerationAction(true, draftRef.current.type, 'idle', draftRef.current)
      if (action === 'ready') {
        setSshKeyGenerationState('ready')
        return
      }
      if (action === 'error') {
        setSshKeyGenerationState('error')
        setError(t`The SSH key data is incomplete. Change the item type and generate it again.`)
        setErrorKind('ssh')
        return
      }
      if (action !== 'generate') {
        return
      }

      setSshKeyGenerationState('generating')
      void window.bearwarden.sshKeys
        .generate()
        .then((generated) => {
          if (generated.status !== 'ready') {
            throw new Error('Generated SSH key material could not be staged')
          }
          const current = draftRef.current
          if (
            !editorMountedRef.current ||
            !canApplyGeneratedSshKey(requestId, sshKeyGenerationRequestRef.current, current)
          ) {
            void window.bearwarden.sshKeys.cancelImport({ token: generated.token }).catch(() => {})
            return
          }
          if (!generated.publicKey.trim() || !generated.fingerprint.trim()) {
            void window.bearwarden.sshKeys.cancelImport({ token: generated.token }).catch(() => {})
            throw new Error('Generated SSH key metadata is incomplete')
          }

          activeSshImportTokenRef.current = generated.token
          setDraft((latest) =>
            applyGeneratedSshKey(requestId, sshKeyGenerationRequestRef.current, latest, generated)
          )
          setDirty(true)
          setVisibleSecrets((visible) => ({ ...visible, privateKey: false }))
          setError('')
          setErrorKind(null)
          setSshKeyGenerationState('ready')
        })
        .catch(() => {
          if (!editorMountedRef.current || requestId !== sshKeyGenerationRequestRef.current) return
          setSshKeyGenerationState('error')
          setError(t`An Ed25519 SSH key could not be generated. Try again.`)
          setErrorKind('ssh')
        })
    })
  }, [
    draft.fingerprint,
    draft.privateKey,
    draft.publicKey,
    draft.type,
    secretLoadState,
    sshKeyGenerationState,
    sshKeyImportState,
    t
  ])
  function cancelActiveSshImport(clearImportedDraft = true): void {
    sshKeyImportRequestRef.current += 1
    const token = activeSshImportTokenRef.current
    activeSshImportTokenRef.current = null
    if (sshImportPassphraseRef.current) sshImportPassphraseRef.current.value = ''
    setSshKeyImportSession(null)
    setSshKeyImportError('')
    setSshKeyImportState('idle')
    if (token) void window.bearwarden.sshKeys.cancelImport({ token }).catch(() => {})
    if (!clearImportedDraft || !token) return

    setDraft((current) => {
      if (current.sshImportToken !== token) return current
      return { ...clearSshKeyMaterial(current), sshImportToken: undefined }
    })
  }

  function requestCancel(): void {
    if (busy) return
    cancelActiveSshImport()
    onCancel()
  }

  function update<K extends keyof LoginDraft>(key: K, value: LoginDraft[K]): void {
    setDirty(true)
    setDraft((current) => ({ ...current, [key]: value }))
  }

  function clearValidationError(kind: Exclude<EditorErrorKind, 'reveal' | null>): void {
    if (errorKind !== kind) return
    setError('')
    setErrorKind(null)
  }

  function updateSecret(field: EditorSecretField, value: string): void {
    if (field === 'password' && value) clearValidationError('password')
    setDirty(true)
    setDraft((current) => ({
      ...current,
      [field]: value,
      changedSecrets: current.changedSecrets.includes(field)
        ? current.changedSecrets
        : [...current.changedSecrets, field]
    }))
  }

  function updateItemType(type: VaultItemType): void {
    const leavingSshKey = draftRef.current.type === 'sshKey' && type !== 'sshKey'
    if (leavingSshKey) {
      cancelActiveSshImport(false)
      sshKeyGenerationRequestRef.current += 1
      setSshKeyGenerationState('idle')
      setVisibleSecrets((current) => ({ ...current, privateKey: false }))
      if (errorKind === 'ssh') {
        setError('')
        setErrorKind(null)
      }
    } else if (type === 'sshKey' && draftRef.current.type !== 'sshKey') {
      setSshKeyGenerationState('idle')
    }

    setDirty(true)
    setDraft((current) => {
      const cleared = leavingSshKey ? clearSshKeyMaterial(current) : current
      return {
        ...cleared,
        ...(leavingSshKey ? { sshImportToken: undefined } : {}),
        type,
        ...(type === 'login' ? { uri: current.uris[0]?.uri ?? null } : { uri: null, uris: [] }),
        customFields: normalizeCustomFieldsForItemType(current.customFields, type)
      }
    })
  }

  function regenerateSshKey(): void {
    if (busy || secretsUnavailable || sshKeyGenerationState === 'generating') return
    cancelActiveSshImport(false)
    sshKeyGenerationRequestRef.current += 1
    setDraft((current) => ({ ...clearSshKeyMaterial(current), sshImportToken: undefined }))
    setVisibleSecrets((current) => ({ ...current, privateKey: false }))
    setError('')
    setErrorKind(null)
    setSshKeyGenerationState('idle')
  }

  function applyReadySshImport(
    requestId: number,
    result: Extract<
      Awaited<ReturnType<typeof window.bearwarden.sshKeys.beginImport>>,
      { status: 'ready' }
    >
  ): void {
    if (
      !editorMountedRef.current ||
      requestId !== sshKeyImportRequestRef.current ||
      draftRef.current.type !== 'sshKey'
    ) {
      void window.bearwarden.sshKeys.cancelImport({ token: result.token }).catch(() => {})
      return
    }

    activeSshImportTokenRef.current = result.token
    setDraft((current) =>
      applyImportedSshKey(requestId, sshKeyImportRequestRef.current, current, result)
    )
    setDirty(true)
    setVisibleSecrets((current) => ({ ...current, privateKey: false }))
    setSshKeyImportSession(null)
    setSshKeyImportError('')
    setSshKeyImportState('ready')
    setSshKeyGenerationState('ready')
    setError('')
    setErrorKind(null)
  }

  async function beginSshKeyImport(): Promise<void> {
    if (
      busy ||
      secretsUnavailable ||
      draftRef.current.type !== 'sshKey' ||
      sshKeyGenerationState === 'generating' ||
      sshKeyImportPending
    )
      return

    const replacingImport = Boolean(draftRef.current.sshImportToken)
    cancelActiveSshImport(false)
    sshKeyGenerationRequestRef.current += 1
    const requestId = ++sshKeyImportRequestRef.current
    if (replacingImport) {
      setDraft((current) => ({ ...clearSshKeyMaterial(current), sshImportToken: undefined }))
      setSshKeyGenerationState('error')
    }
    setSshKeyImportError('')
    setSshKeyImportState('reading')

    try {
      const result = await window.bearwarden.sshKeys.beginImport()
      if (
        !editorMountedRef.current ||
        requestId !== sshKeyImportRequestRef.current ||
        draftRef.current.type !== 'sshKey'
      ) {
        if (result.status !== 'error') {
          void window.bearwarden.sshKeys.cancelImport({ token: result.token }).catch(() => {})
        }
        return
      }

      if (result.status === 'ready') {
        applyReadySshImport(requestId, result)
        return
      }
      if (result.status === 'awaitingPassphrase') {
        activeSshImportTokenRef.current = result.token
        setSshKeyImportSession({ token: result.token, expiresAt: result.expiresAt })
        setSshKeyImportState('awaitingPassphrase')
        requestAnimationFrame(() => sshImportPassphraseRef.current?.focus())
        return
      }

      setSshKeyImportState('idle')
      setError(sshImportErrorMessage(result.code))
      setErrorKind('ssh')
    } catch {
      if (!editorMountedRef.current || requestId !== sshKeyImportRequestRef.current) return
      setSshKeyImportState('idle')
      setError(t`The SSH private key could not be read from the clipboard. Try again later.`)
      setErrorKind('ssh')
    }
  }

  async function submitSshImportPassphrase(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    const session = sshKeyImportSession
    const input = sshImportPassphraseRef.current
    if (!session || !input || busy || sshKeyImportState === 'submittingPassphrase') return

    const requestId = sshKeyImportRequestRef.current
    let passphrase = input.value
    input.value = ''
    if (!isValidSshImportPassphrase(passphrase)) {
      setSshKeyImportError(sshImportErrorMessage('InvalidPassphrase'))
      setSshKeyImportState('awaitingPassphrase')
      requestAnimationFrame(() => sshImportPassphraseRef.current?.focus())
      return
    }
    const request = { token: session.token, passphrase }
    setSshKeyImportError('')
    setSshKeyImportState('submittingPassphrase')

    try {
      const pendingResult = window.bearwarden.sshKeys.submitImportPassphrase(request)
      passphrase = ''
      request.passphrase = ''
      const result = await pendingResult
      if (
        !editorMountedRef.current ||
        requestId !== sshKeyImportRequestRef.current ||
        activeSshImportTokenRef.current !== session.token ||
        draftRef.current.type !== 'sshKey'
      ) {
        if (result.status !== 'error') {
          void window.bearwarden.sshKeys.cancelImport({ token: result.token }).catch(() => {})
        }
        return
      }

      if (result.status === 'ready') {
        applyReadySshImport(requestId, result)
        return
      }
      if (result.status === 'awaitingPassphrase') {
        activeSshImportTokenRef.current = result.token
        setSshKeyImportSession({ token: result.token, expiresAt: result.expiresAt })
        setSshKeyImportState('awaitingPassphrase')
        return
      }
      if (sshKeyImportResultAction(result) === 'retryPassphrase') {
        setSshKeyImportError(sshImportErrorMessage(result.code))
        setSshKeyImportState('awaitingPassphrase')
        requestAnimationFrame(() => sshImportPassphraseRef.current?.focus())
        return
      }

      cancelActiveSshImport(false)
      setError(sshImportErrorMessage(result.code))
      setErrorKind('ssh')
    } catch {
      if (!editorMountedRef.current || requestId !== sshKeyImportRequestRef.current) return
      setSshKeyImportError(t`The private key password could not be verified. Try again.`)
      setSshKeyImportState('awaitingPassphrase')
      requestAnimationFrame(() => sshImportPassphraseRef.current?.focus())
    }
  }

  function cancelSshImportPassphrase(): void {
    cancelActiveSshImport(false)
    if (sshKeyMaterialState(draftRef.current) === 'blank') setSshKeyGenerationState('idle')
  }

  function updateUri(index: number, patch: Partial<VaultLoginUri>): void {
    setDirty(true)
    setDraft((current) => {
      const uris = current.uris.map((entry, entryIndex) =>
        entryIndex === index ? { ...entry, ...patch } : entry
      )
      return { ...current, uris, uri: uris[0]?.uri ?? null }
    })
    if (patch.uri?.trim()) clearValidationError('uri')
  }

  function addUri(): void {
    if (draftRef.current.uris.length >= 1_000) return
    setDirty(true)
    setDraft((current) => ({
      ...current,
      uris: [...current.uris, { clientId: newUriClientId(), uri: '', match: null }]
    }))
  }

  function removeUri(index: number): void {
    setDirty(true)
    setDraft((current) => {
      const uris = current.uris.filter((_, entryIndex) => entryIndex !== index)
      return { ...current, uris, uri: uris[0]?.uri ?? null }
    })
  }

  function reorderUri(event: DragEndEvent): void {
    const overId = event.over ? String(event.over.id) : null
    const activeId = String(event.active.id)
    if (!overId || activeId === overId) return
    setDirty(true)
    setDraft((current) => ({ ...current, ...reorderEditorUris(current.uris, activeId, overId) }))
  }

  function addCustomField(type: VaultCustomFieldType): void {
    const linkedIds = linkedIdsForItemType(draftRef.current.type)
    const resolvedType = type === 'linked' && linkedIds.length === 0 ? 'text' : type
    const clientId = newCustomFieldClientId()
    setDirty(true)
    setDraft((current) => ({
      ...current,
      customFields: [
        ...current.customFields,
        {
          clientId,
          source: null,
          name: '',
          type: resolvedType,
          value: resolvedType === 'linked' ? null : resolvedType === 'boolean' ? 'false' : '',
          linkedId: resolvedType === 'linked' ? (linkedIds[0] ?? null) : null
        }
      ]
    }))
    requestAnimationFrame(() =>
      document.getElementById(`editor-custom-field-${clientId}-name`)?.focus()
    )
  }

  function updateCustomField(
    clientId: string,
    updateField: (field: EditorCustomField) => EditorCustomField,
    markDirty = true
  ): void {
    if (markDirty) setDirty(true)
    setDraft((current) => ({
      ...current,
      customFields: current.customFields.map((field) =>
        field.clientId === clientId ? updateField(field) : field
      )
    }))
  }

  function removeCustomField(clientId: string): void {
    setDirty(true)
    setDraft((current) => ({
      ...current,
      customFields: current.customFields.filter((field) => field.clientId !== clientId)
    }))
  }

  function reorderCustomField(event: DragEndEvent): void {
    const activeId = String(event.active.id)
    const overId = event.over ? String(event.over.id) : null
    if (!overId || activeId === overId) return

    setDirty(true)
    setDraft((current) => {
      const customFields = reorderEditorItemsByClientId(current.customFields, activeId, overId)
      return customFields === current.customFields ? current : { ...current, customFields }
    })
  }

  function updateCustomFieldType(clientId: string, type: VaultCustomFieldType): void {
    updateCustomField(clientId, (field) => {
      if (type === 'linked') {
        const linkedIds = linkedIdsForItemType(draft.type)
        const linkedId = linkedIds.includes(field.linkedId ?? Number.NaN)
          ? field.linkedId
          : (linkedIds[0] ?? null)
        return { ...field, type, value: null, linkedId }
      }

      if (type === 'boolean') {
        return {
          ...field,
          type,
          value: field.type === 'boolean' && field.value === 'true' ? 'true' : 'false',
          linkedId: null
        }
      }

      if (type === 'hidden') {
        const preserveHiddenValue =
          field.type === 'hidden' && field.source?.type === 'hidden' && field.value === null
        return {
          ...field,
          type,
          value: preserveHiddenValue ? null : (field.value ?? ''),
          linkedId: null
        }
      }

      return { ...field, type, value: field.value ?? '', linkedId: null }
    })
  }

  function customFieldAddMenu(buttonVariant: 'default' | 'outline' = 'outline'): React.JSX.Element {
    const canAddLinkedField = linkedIdsForItemType(draft.type).length > 0

    return (
      <DropdownMenu>
        <DropdownMenuTrigger
          render={
            <Button
              type="button"
              variant={buttonVariant}
              size="sm"
              disabled={busy || secretsUnavailable}
            />
          }
        >
          <Plus data-icon="inline-start" />
          <Trans>Add field</Trans>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuGroup>
            <DropdownMenuItem onClick={() => addCustomField('text')}>
              <TextCursorInput />
              <Trans>Text</Trans>
            </DropdownMenuItem>
            {(!sharedContext || sharedContext.canEditSecrets) && (
              <DropdownMenuItem onClick={() => addCustomField('hidden')}>
                <EyeOff />
                <Trans>Hidden text</Trans>
              </DropdownMenuItem>
            )}
            <DropdownMenuItem onClick={() => addCustomField('boolean')}>
              <CheckSquare2 />
              <Trans>Checkbox</Trans>
            </DropdownMenuItem>
            {canAddLinkedField && (
              <DropdownMenuItem onClick={() => addCustomField('linked')}>
                <Link2 />
                <Trans>Linked field</Trans>
              </DropdownMenuItem>
            )}
          </DropdownMenuGroup>
        </DropdownMenuContent>
      </DropdownMenu>
    )
  }

  async function toggleCustomFieldVisibility(customField: EditorCustomField): Promise<void> {
    const currentlyVisible = Boolean(visibleCustomFields[customField.clientId])
    const sourceIndex = customField.source?.index
    const expectedUpdatedAt = draftRef.current.expectedUpdatedAt
    if (currentlyVisible) {
      setVisibleCustomFields((current) => ({ ...current, [customField.clientId]: false }))
      return
    }

    if (!login || !expectedUpdatedAt || sourceIndex === undefined || customField.value !== null) {
      setVisibleCustomFields((current) => ({ ...current, [customField.clientId]: true }))
      return
    }

    setRevealingCustomFields((current) => ({ ...current, [customField.clientId]: true }))
    try {
      const value = await window.bearwarden.logins.revealCustomField({
        id: login.id,
        expectedUpdatedAt,
        source: customField.source!,
        ...(authorizationToken ? { authorizationToken } : {})
      })
      const currentField = draftRef.current.customFields.find(
        (field) => field.clientId === customField.clientId
      )
      const canApplyReveal =
        currentField?.type === 'hidden' &&
        currentField.value === null &&
        currentField.source?.index === sourceIndex
      if (!canApplyReveal) return

      updateCustomField(
        customField.clientId,
        (field) =>
          field.type === 'hidden' && field.value === null && field.source?.index === sourceIndex
            ? { ...field, value }
            : field,
        false
      )
      setVisibleCustomFields((current) => ({ ...current, [customField.clientId]: true }))
      setError('')
      setErrorKind(null)
    } catch {
      setError(t`The custom field contents could not be shown. Try again later.`)
      setErrorKind('reveal')
    } finally {
      setRevealingCustomFields((current) => ({ ...current, [customField.clientId]: false }))
    }
  }

  function secretInput(
    field: EditorSecretField,
    label: string,
    options?: {
      multiline?: boolean
      inputMode?: React.HTMLAttributes<HTMLInputElement>['inputMode']
      displayValue?: string
      onValueChange?: (value: string) => void
      placeholder?: string
      description?: React.ReactNode
      readOnly?: boolean
      disabled?: boolean
      addon?: React.ReactNode
    }
  ): React.JSX.Element {
    const visible = Boolean(visibleSecrets[field])
    const value = options?.displayValue ?? draft[field]
    const invalid =
      (field === 'password' && errorKind === 'password') ||
      (field === 'privateKey' && errorKind === 'ssh' && !draft.privateKey.trim())
    const disabled =
      busy ||
      secretsUnavailable ||
      (sharedContext ? !sharedContext.canEditSecrets : false) ||
      options?.disabled
    const changeValue = (nextValue: string): void => {
      if (options?.onValueChange) {
        options.onValueChange(nextValue)
        return
      }
      updateSecret(field, nextValue)
    }

    return (
      <Field key={field} data-invalid={invalid || undefined} data-disabled={disabled || undefined}>
        <FieldLabel htmlFor={`editor-${field}`}>{label}</FieldLabel>
        <InputGroup className={options?.multiline ? 'min-h-32 items-stretch' : undefined}>
          {options?.multiline ? (
            <InputGroupTextarea
              id={`editor-${field}`}
              className={visible ? undefined : '[-webkit-text-security:disc]'}
              rows={6}
              value={value}
              onChange={(event) => changeValue(event.target.value)}
              readOnly={options?.readOnly}
              autoComplete="off"
              disabled={disabled}
              aria-invalid={invalid || undefined}
              aria-describedby={invalid ? 'editor-error' : undefined}
            />
          ) : (
            <InputGroupInput
              id={`editor-${field}`}
              type={visible ? 'text' : 'password'}
              value={value}
              onChange={(event) => changeValue(event.target.value)}
              readOnly={options?.readOnly}
              inputMode={options?.inputMode}
              placeholder={options?.placeholder}
              autoComplete="off"
              disabled={disabled}
              aria-invalid={invalid || undefined}
              aria-describedby={invalid ? 'editor-error' : undefined}
            />
          )}
          <InputGroupAddon align={options?.multiline ? 'block-end' : 'inline-end'}>
            {options?.addon}
            {field === 'password' && !options?.multiline && (
              <InputGroupButton
                type="button"
                variant="ghost"
                size="icon-xs"
                aria-label={t`Generate password`}
                onClick={() => setGeneratorTarget('password')}
                disabled={disabled}
              >
                <Sparkles />
              </InputGroupButton>
            )}
            <InputGroupButton
              type="button"
              variant="ghost"
              size="icon-xs"
              aria-label={visible ? t`Hide ${label}` : t`Show ${label}`}
              aria-pressed={visible}
              onClick={() => setVisibleSecrets((current) => ({ ...current, [field]: !visible }))}
              disabled={disabled}
            >
              {visible ? <EyeOff /> : <Eye />}
            </InputGroupButton>
          </InputGroupAddon>
        </InputGroup>
        {options?.description && <FieldDescription>{options.description}</FieldDescription>}
      </Field>
    )
  }

  async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (busy || secretsUnavailable || sshKeyUnavailable || submittingRef.current) return
    if (!draft.name.trim()) {
      setError(t`Enter an item name.`)
      setErrorKind('name')
      requestAnimationFrame(() => nameRef.current?.focus())
      return
    }
    if (!login && draft.type === 'login' && !draft.password) {
      setError(t`A password is required when adding a login item.`)
      setErrorKind('password')
      requestAnimationFrame(() => document.getElementById('editor-password')?.focus())
      return
    }
    const blankUriIndex =
      draft.type === 'login' ? draft.uris.findIndex((entry) => !entry.uri.trim()) : -1
    if (blankUriIndex >= 0) {
      setError(t`Website fields cannot be blank. Remove any rows you do not need.`)
      setErrorKind('uri')
      requestAnimationFrame(() => document.getElementById(`editor-uri-${blankUriIndex}`)?.focus())
      return
    }
    const importedSshKeyIncomplete =
      draft.type === 'sshKey' &&
      Boolean(draft.sshImportToken) &&
      (!draft.publicKey.trim() || !draft.fingerprint.trim() || Boolean(draft.privateKey))
    const generatedSshKeyIncomplete =
      draft.type === 'sshKey' &&
      !draft.sshImportToken &&
      (!draft.privateKey.trim() || !draft.publicKey.trim() || !draft.fingerprint.trim())
    if (importedSshKeyIncomplete || generatedSshKeyIncomplete) {
      setError(
        draft.sshImportToken
          ? t`The SSH key staging session or public metadata is incomplete. Generate or import the key again.`
          : t`The SSH key must include a private key, public key, and fingerprint.`
      )
      setErrorKind('ssh')
      const missingFieldId = draft.sshImportToken
        ? !draft.publicKey.trim()
          ? 'editor-public-key'
          : 'editor-fingerprint'
        : !draft.privateKey.trim()
          ? 'editor-privateKey'
          : !draft.publicKey.trim()
            ? 'editor-public-key'
            : 'editor-fingerprint'
      requestAnimationFrame(() => document.getElementById(missingFieldId)?.focus())
      return
    }
    setError('')
    setErrorKind(null)
    submittingRef.current = true
    const submittedImportToken = draft.sshImportToken
    try {
      const saved = await onSave({
        ...draft,
        name: draft.name.trim(),
        username: draft.username.trim()
      })
      if (
        !saved &&
        submittedImportToken &&
        draftRef.current.sshImportToken === submittedImportToken
      ) {
        cancelActiveSshImport(false)
        setDraft((current) => invalidateFailedSshImport(current, submittedImportToken))
        setSshKeyImportState('idle')
        setSshKeyGenerationState('error')
        setError(
          t`This SSH private key staging session has expired. Generate or import the key again before saving.`
        )
        setErrorKind('ssh')
      }
    } finally {
      submittingRef.current = false
    }
  }

  async function deletePasskey(): Promise<void> {
    const target = passkeyDeleteTarget
    const expectedUpdatedAt = draftRef.current.expectedUpdatedAt
    if (!target || expectedUpdatedAt === null) return
    const updated = await onDeletePasskey(target.credentialId, expectedUpdatedAt)
    if (!updated || !editorMountedRef.current) return
    setDraft((current) => ({ ...current, expectedUpdatedAt: updated.updatedAt }))
    setPasskeyDeleteTarget(null)
  }

  const currentTypeLabel = typeLabel(draft.type)
  const headerContent = login
    ? { heading: login.name, eyebrow: t`Edit ${currentTypeLabel}` }
    : { heading: currentTypeLabel, eyebrow: t`Add item` }
  const ItemTypeIcon = itemTypeIcons[draft.type]
  const detectedCardBrand = detectPaymentCardBrand(draft.number)
  const folderSelectItems = [
    { value: '', label: t`Unfiled` },
    ...folders.map((folder) => ({ value: folder.id, label: folder.name }))
  ]

  return (
    <form
      className="flex size-full min-h-0 min-w-0 flex-col"
      data-vault-editor=""
      onSubmit={submit}
      aria-labelledby="editor-title"
    >
      <header className="bg-muted/30 flex items-center gap-2.5 px-4 py-3 max-[680px]:px-3 max-[680px]:py-2.5">
        <span
          className={cn(
            'outline-foreground/5 bg-muted text-primary dark:border-border dark:bg-muted dark:text-muted-foreground grid size-9 shrink-0 place-items-center rounded-md shadow-(--control-highlight) outline max-[430px]:hidden forced-colors:[forced-color-adjust:none] [&>svg]:size-4.5',
            draft.type === 'login' && 'overflow-hidden',
            draft.type === 'card' && 'text-chart-4 dark:bg-website-icon-background',
            draft.type === 'identity' && 'bg-accent text-primary',
            draft.type === 'secureNote' && 'bg-muted text-chart-3',
            draft.type === 'sshKey' && 'bg-accent text-chart-2'
          )}
          data-detail-icon=""
          aria-hidden="true"
        >
          <ItemTypeIcon />
        </span>
        <div className="min-w-0 flex-1">
          <h2 className="m-0 truncate text-base font-medium tracking-[-0.015em]" id="editor-title">
            {headerContent.heading}
          </h2>
          <p className="text-muted-foreground mt-[3px] mb-0 truncate text-[10px]">
            {headerContent.eyebrow}
            {dirty && (
              <>
                {' · '}
                <Trans>Unsaved</Trans>
              </>
            )}
          </p>
        </div>
        <Button
          variant="outline"
          size="icon"
          className="border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground dark:bg-card dark:hover:bg-muted size-[34px] min-w-[34px] rounded-md shadow-(--control-highlight)"
          type="button"
          aria-label={t`Cancel editing`}
          onClick={requestCancel}
          disabled={busy}
        >
          <X />
        </Button>
      </header>

      <div className="scroll-fade-y forced-colors:scroll-fade-none bg-muted/30 grid min-h-0 flex-1 [scrollbar-color:var(--border-strong)_transparent] content-start gap-3 overflow-auto px-4 pt-4 pb-7 max-[680px]:px-3 max-[680px]:pt-3 max-[680px]:pb-5">
        <div className="flex w-full flex-col">
          {error && (
            <FieldError id="editor-error" role="alert" className="mt-2">
              {error}
            </FieldError>
          )}

          <EditorSection value="details">
            <EditorFormSection
              title={t`${currentTypeLabel} details`}
              titleId="item-section-title"
              icon={<ItemTypeIcon aria-hidden="true" />}
            >
              <FieldGroup className="gap-3">
                {!login && (
                  <Field>
                    <FieldLabel htmlFor="editor-type">
                      <Trans
                        context="item-type"
                        comment="Field label for choosing the kind of vault item being edited, such as login, card, identity, or secure note."
                      >
                        Type
                      </Trans>
                    </FieldLabel>
                    <Select
                      items={itemTypeSelectItems}
                      value={draft.type}
                      disabled={busy}
                      onValueChange={(value) => value && updateItemType(value as VaultItemType)}
                    >
                      <SelectTrigger id="editor-type" className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          {itemTypeSelectItems.map((item) => (
                            <SelectItem key={item.value} value={item.value}>
                              {item.label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </Field>
                )}
                <Field data-invalid={errorKind === 'name' || undefined}>
                  <FieldLabel htmlFor="editor-name">
                    <Trans>Name</Trans>
                  </FieldLabel>
                  <Input
                    id="editor-name"
                    ref={nameRef}
                    value={draft.name}
                    onChange={(event) => {
                      update('name', event.target.value)
                      if (event.target.value.trim()) clearValidationError('name')
                    }}
                    maxLength={160}
                    disabled={busy}
                    aria-invalid={errorKind === 'name' || undefined}
                    aria-describedby={errorKind === 'name' ? 'editor-error' : undefined}
                  />
                </Field>

                {draft.type === 'login' && (
                  <>
                    <Field>
                      <FieldLabel htmlFor="editor-username">
                        <Trans>Username</Trans>
                      </FieldLabel>
                      <InputGroup>
                        <InputGroupInput
                          id="editor-username"
                          value={draft.username}
                          onChange={(event) => update('username', event.target.value)}
                          autoComplete="off"
                          maxLength={320}
                          disabled={busy}
                        />
                        <InputGroupAddon align="inline-end">
                          <InputGroupButton
                            type="button"
                            variant="ghost"
                            size="icon-xs"
                            aria-label={t`Generate username`}
                            onClick={() => setGeneratorTarget('username')}
                            disabled={busy}
                          >
                            <Sparkles />
                          </InputGroupButton>
                        </InputGroupAddon>
                      </InputGroup>
                    </Field>
                    {secretInput('password', t`Password`)}
                    {secretInput('totp', t`Authenticator key (TOTP)`, {
                      placeholder: t`Base32, otpauth://…, or steam://…`,
                      description: t`Enter a Base32 key directly. Use an otpauth URI for SHA-1, SHA-256, SHA-512, custom 1–10 digit codes, or custom periods. Use steam:// for Steam codes.`
                    })}
                    <Field data-invalid={errorKind === 'uri' || undefined}>
                      <div className="flex items-center justify-between gap-3">
                        <FieldLabel>
                          <Trans>Websites</Trans>
                        </FieldLabel>
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={addUri}
                          disabled={busy || draft.uris.length >= 1_000}
                        >
                          <Plus data-icon="inline-start" />
                          <Trans>Add website</Trans>
                        </Button>
                      </div>
                      {draft.uris.length === 0 ? (
                        <FieldDescription>
                          <Trans>
                            No websites are set. You can save only a username and password.
                          </Trans>
                        </FieldDescription>
                      ) : (
                        <DndContext
                          sensors={sortableSensors}
                          collisionDetection={closestCenter}
                          accessibility={{
                            screenReaderInstructions: {
                              draggable: t`To reorder a website, press space or enter. Use the arrow keys to move it, then press space or enter again to drop it.`
                            },
                            announcements: {
                              onDragStart: ({ active }) => {
                                const position = draft.uris.findIndex(
                                  (entry) => entry.clientId === String(active.id)
                                )
                                return t`Picked up website ${position + 1} of ${draft.uris.length}.`
                              },
                              onDragOver: ({ over }) => {
                                if (!over) return
                                const position = draft.uris.findIndex(
                                  (entry) => entry.clientId === String(over.id)
                                )
                                return t`Website moved to position ${position + 1} of ${draft.uris.length}.`
                              },
                              onDragEnd: ({ over }) => {
                                if (!over) return t`Website was not moved.`
                                const position = draft.uris.findIndex(
                                  (entry) => entry.clientId === String(over.id)
                                )
                                return t`Website dropped at position ${position + 1} of ${draft.uris.length}.`
                              },
                              onDragCancel: () => t`Website reordering cancelled.`
                            }
                          }}
                          onDragEnd={reorderUri}
                        >
                          <SortableContext
                            items={draft.uris.map((entry) => entry.clientId)}
                            strategy={verticalListSortingStrategy}
                          >
                            <div className="flex flex-col gap-3">
                              {draft.uris.map((entry, index) => (
                                <SortableUriRow
                                  key={entry.clientId}
                                  id={entry.clientId}
                                  disabled={busy || draft.uris.length < 2}
                                  dragLabel={t`Reorder ${`${t`Website`} ${index + 1}`}`}
                                  actions={
                                    <Button
                                      type="button"
                                      variant="ghost"
                                      size="icon-sm"
                                      aria-label={t`Remove website`}
                                      onClick={() => removeUri(index)}
                                      disabled={busy}
                                    >
                                      <Trash2 />
                                    </Button>
                                  }
                                >
                                  <Input
                                    id={`editor-uri-${index}`}
                                    className="col-start-2 col-end-4"
                                    type="text"
                                    inputMode={entry.match === 4 ? 'text' : 'url'}
                                    placeholder={
                                      entry.match === 4
                                        ? '^https://example\\.com/'
                                        : 'https://example.com'
                                    }
                                    value={entry.uri}
                                    onChange={(event) =>
                                      updateUri(index, { uri: event.target.value })
                                    }
                                    disabled={busy}
                                    aria-invalid={
                                      errorKind === 'uri' && !entry.uri.trim() ? true : undefined
                                    }
                                  />
                                  <div className="col-start-2 row-start-2 flex min-w-0 flex-col gap-1.5">
                                    <Select
                                      items={uriMatchOptions}
                                      value={entry.match === null ? 'default' : String(entry.match)}
                                      disabled={busy}
                                      onValueChange={(value) =>
                                        updateUri(index, {
                                          match:
                                            value === 'default' || value === null
                                              ? null
                                              : (Number(value) as VaultUriMatch)
                                        })
                                      }
                                    >
                                      <SelectTrigger
                                        aria-label={t`Matching method for website ${index + 1}`}
                                        className="w-full"
                                      >
                                        <SelectValue />
                                      </SelectTrigger>
                                      <SelectContent
                                        className="w-[min(30rem,calc(100vw-2rem))] min-w-80"
                                        alignItemWithTrigger={false}
                                      >
                                        <SelectGroup>
                                          {uriMatchOptions.map((item) => (
                                            <SelectItem
                                              key={item.value}
                                              value={item.value}
                                              className="items-start py-2"
                                            >
                                              <div className="flex min-w-0 flex-col items-start gap-0.5 whitespace-normal">
                                                <span>{item.label}</span>
                                                <UriMatchExampleText
                                                  value={item.value}
                                                  rawUri={entry.uri}
                                                  className="text-muted-foreground text-xs leading-4"
                                                />
                                              </div>
                                            </SelectItem>
                                          ))}
                                        </SelectGroup>
                                      </SelectContent>
                                    </Select>
                                    <UriMatchExample
                                      value={
                                        (entry.match === null
                                          ? 'default'
                                          : String(entry.match)) as UriMatchOptionValue
                                      }
                                      rawUri={entry.uri}
                                    />
                                  </div>
                                </SortableUriRow>
                              ))}
                            </div>
                          </SortableContext>
                        </DndContext>
                      )}
                    </Field>
                    {login && login.passkeys.length > 0 && (
                      <Field>
                        <FieldLabel>
                          <Trans>Passkeys</Trans>
                        </FieldLabel>
                        <FieldDescription>
                          {sharedContext ? (
                            <Trans>Passkeys on shared items cannot be changed here.</Trans>
                          ) : (
                            <Trans>
                              Deletion syncs immediately without loading private keys into the
                              editor. Other unsaved fields are preserved.
                            </Trans>
                          )}
                        </FieldDescription>
                        <div className="grid overflow-hidden rounded-md border">
                          {login.passkeys.map((passkey, index) => (
                            <article
                              key={`${passkey.credentialId}:${index}`}
                              className="border-border [&_small]:text-muted-foreground grid grid-cols-[34px_minmax(0,1fr)_auto] items-center gap-2.5 border-b px-(--card-spacing) py-3 last:border-b-0 [&_small]:truncate [&_small]:text-[10px] [&_span]:truncate [&_span]:text-[11px] [&_strong]:truncate [&_strong]:text-xs [&>div]:grid [&>div]:min-w-0 [&>div]:gap-[3px]"
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
                                  {passkey.userDisplayName || passkey.userName || (
                                    <Trans>Unnamed user</Trans>
                                  )}
                                </span>
                                <small>{passkey.rpId}</small>
                              </div>
                              {!sharedContext && (
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon-sm"
                                  aria-label={t`Delete the passkey for ${passkey.rpName || passkey.rpId}`}
                                  disabled={busy}
                                  onClick={() => setPasskeyDeleteTarget(passkey)}
                                >
                                  <Trash2 />
                                </Button>
                              )}
                            </article>
                          ))}
                        </div>
                      </Field>
                    )}
                  </>
                )}

                {draft.type === 'card' && (
                  <>
                    <Field>
                      <FieldLabel htmlFor="editor-cardholder-name">
                        <Trans>Cardholder</Trans>
                      </FieldLabel>
                      <Input
                        id="editor-cardholder-name"
                        value={draft.cardholderName}
                        onChange={(event) => update('cardholderName', event.target.value)}
                        disabled={busy}
                      />
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="editor-card-brand">
                        <Trans>Card brand</Trans>
                      </FieldLabel>
                      <Select
                        items={paymentCardBrandSelectItems}
                        value={selectedCardBrand}
                        disabled={busy}
                        onValueChange={(value) => {
                          const brand = (value ?? '') as PaymentCardBrandOption
                          setSelectedCardBrand(brand)
                          setCardBrandAutoDetected(false)
                          update(
                            'brand',
                            brand && brand !== 'unknown' ? paymentCardBrandLabels[brand] : ''
                          )
                        }}
                      >
                        <SelectTrigger id="editor-card-brand" className="w-full">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            {paymentCardBrandSelectItems.map((item) => (
                              <SelectItem key={item.value || 'unset'} value={item.value}>
                                {item.label}
                              </SelectItem>
                            ))}
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                      {selectedCardBrand === 'unknown' && (
                        <Input
                          id="editor-custom-card-brand"
                          aria-label={t`Other card brand name`}
                          value={draft.brand}
                          onChange={(event) => update('brand', event.target.value)}
                          placeholder={t`Enter another card brand`}
                          disabled={busy}
                        />
                      )}
                    </Field>
                    {secretInput('number', t`Card number`, {
                      inputMode: 'numeric',
                      displayValue: formatPaymentCardNumber(draft.number),
                      onValueChange: (value) => {
                        const digits = sanitizePaymentCardNumber(value)
                        updateSecret('number', digits)
                        const detected = detectPaymentCardBrand(digits)
                        if (cardBrandAutoDetected) {
                          const brand = detected === 'unknown' ? '' : detected
                          setSelectedCardBrand(brand)
                          update('brand', brand ? paymentCardBrandLabels[brand] : '')
                        }
                      }
                    })}
                    {cardBrandAutoDetected && detectedCardBrand !== 'unknown' && (
                      <FieldDescription className="-mt-[5px] mb-0 justify-self-start rounded-full border bg-[var(--accent-soft)] px-[9px] py-[5px] text-[10px] font-bold text-[var(--accent-hover)]">
                        <Trans>
                          Card number recognized as {paymentCardBrandLabels[detectedCardBrand]}
                        </Trans>
                      </FieldDescription>
                    )}
                    <FieldGroup className={fieldGridClassName}>
                      <Field>
                        <FieldLabel htmlFor="editor-exp-month">
                          <Trans>Expiration month</Trans>
                        </FieldLabel>
                        <Input
                          id="editor-exp-month"
                          inputMode="numeric"
                          value={draft.expMonth}
                          onChange={(event) => update('expMonth', event.target.value)}
                          disabled={busy}
                        />
                      </Field>
                      <Field>
                        <FieldLabel htmlFor="editor-exp-year">
                          <Trans>Expiration year</Trans>
                        </FieldLabel>
                        <Input
                          id="editor-exp-year"
                          inputMode="numeric"
                          value={draft.expYear}
                          onChange={(event) => update('expYear', event.target.value)}
                          disabled={busy}
                        />
                      </Field>
                    </FieldGroup>
                    {secretInput('code', t`Security code`)}
                  </>
                )}

                {draft.type === 'identity' && (
                  <>
                    <FieldGroup className={fieldGridClassName}>
                      <TextField
                        id="editor-honorific"
                        label={t`Title`}
                        value={draft.title}
                        onChange={(value) => update('title', value)}
                        disabled={busy}
                      />
                      <TextField
                        id="editor-company"
                        label={t`Company`}
                        value={draft.company}
                        onChange={(value) => update('company', value)}
                        disabled={busy}
                      />
                    </FieldGroup>
                    <FieldGroup className={fieldGridClassName}>
                      <TextField
                        id="editor-first-name"
                        label={t`First name`}
                        value={draft.firstName}
                        onChange={(value) => update('firstName', value)}
                        disabled={busy}
                      />
                      <TextField
                        id="editor-middle-name"
                        label={t`Middle name`}
                        value={draft.middleName}
                        onChange={(value) => update('middleName', value)}
                        disabled={busy}
                      />
                      <TextField
                        id="editor-last-name"
                        label={t`Last name`}
                        value={draft.lastName}
                        onChange={(value) => update('lastName', value)}
                        disabled={busy}
                      />
                    </FieldGroup>
                    <TextField
                      id="editor-address-1"
                      label={t`Address`}
                      value={draft.address1}
                      onChange={(value) => update('address1', value)}
                      disabled={busy}
                    />
                    <TextField
                      id="editor-address-2"
                      label={t`Address line 2`}
                      value={draft.address2}
                      onChange={(value) => update('address2', value)}
                      disabled={busy}
                    />
                    <TextField
                      id="editor-address-3"
                      label={t`Address line 3`}
                      value={draft.address3}
                      onChange={(value) => update('address3', value)}
                      disabled={busy}
                    />
                    <FieldGroup className={fieldGridClassName}>
                      <TextField
                        id="editor-city"
                        label={t`City`}
                        value={draft.city}
                        onChange={(value) => update('city', value)}
                        disabled={busy}
                      />
                      <TextField
                        id="editor-state"
                        label={t`State / Province`}
                        value={draft.state}
                        onChange={(value) => update('state', value)}
                        disabled={busy}
                      />
                      <TextField
                        id="editor-postal-code"
                        label={t`Postal code`}
                        value={draft.postalCode}
                        onChange={(value) => update('postalCode', value)}
                        disabled={busy}
                      />
                    </FieldGroup>
                    <TextField
                      id="editor-country"
                      label={t`Country / Region`}
                      value={draft.country}
                      onChange={(value) => update('country', value)}
                      disabled={busy}
                    />
                    <FieldGroup className={fieldGridClassName}>
                      <TextField
                        id="editor-email"
                        label={t`Email`}
                        type="email"
                        value={draft.email}
                        onChange={(value) => update('email', value)}
                        disabled={busy}
                      />
                      <TextField
                        id="editor-phone"
                        label={t`Phone`}
                        type="tel"
                        value={draft.phone}
                        onChange={(value) => update('phone', value)}
                        disabled={busy}
                      />
                    </FieldGroup>
                    <TextField
                      id="editor-identity-username"
                      label={t`Username`}
                      value={draft.identityUsername}
                      onChange={(value) => update('identityUsername', value)}
                      disabled={busy}
                    />
                    {secretInput('ssn', t`National ID / Social Security number`)}
                    {secretInput('passportNumber', t`Passport number`)}
                    {secretInput('licenseNumber', t`License number`)}
                  </>
                )}

                {draft.type === 'secureNote' && (
                  <Field>
                    <FieldLabel htmlFor="editor-notes">
                      <Trans>Content</Trans>
                    </FieldLabel>
                    <Textarea
                      id="editor-notes"
                      rows={12}
                      value={draft.notes}
                      onChange={(event) => update('notes', event.target.value)}
                      maxLength={5000}
                      disabled={busy}
                    />
                  </Field>
                )}

                {draft.type === 'sshKey' && (
                  <>
                    {!sharedContext && (
                      <div className="flex flex-wrap gap-2">
                        <Button
                          type="button"
                          variant="outline"
                          onClick={regenerateSshKey}
                          disabled={
                            busy ||
                            secretsUnavailable ||
                            sshKeyGenerationState === 'generating' ||
                            sshKeyImportPending
                          }
                        >
                          {sshKeyGenerationState === 'generating' ? (
                            <Spinner data-icon="inline-start" />
                          ) : (
                            <RefreshCw data-icon="inline-start" />
                          )}
                          {sshKeyGenerationState === 'generating' ? (
                            <Trans>Generating…</Trans>
                          ) : (
                            <Trans>Generate again</Trans>
                          )}
                        </Button>
                        <Button
                          type="button"
                          variant="outline"
                          onClick={() => void beginSshKeyImport()}
                          disabled={
                            busy ||
                            secretsUnavailable ||
                            sshKeyGenerationState === 'generating' ||
                            sshKeyImportPending
                          }
                        >
                          {sshKeyImportState === 'reading' ? (
                            <Spinner data-icon="inline-start" />
                          ) : (
                            <ClipboardPaste data-icon="inline-start" />
                          )}
                          {sshKeyImportState === 'reading' ? (
                            <Trans>Reading clipboard…</Trans>
                          ) : (
                            <Trans>Import from clipboard</Trans>
                          )}
                        </Button>
                      </div>
                    )}
                    {draft.sshImportToken ? (
                      <Field data-disabled>
                        <FieldLabel htmlFor="editor-privateKey">
                          <Trans>Private key</Trans>
                        </FieldLabel>
                        <Textarea
                          id="editor-privateKey"
                          rows={3}
                          value=""
                          placeholder={t`The private key remains in the secure main process and is not loaded into the editor.`}
                          readOnly
                          disabled
                          autoComplete="off"
                        />
                        <FieldDescription>
                          <Trans>
                            Only a short-lived import token is used when saving. This field neither
                            contains nor displays the private key.
                          </Trans>
                        </FieldDescription>
                      </Field>
                    ) : (
                      secretInput('privateKey', t`Private key`, {
                        multiline: true,
                        readOnly: true,
                        disabled: sshKeyGenerationState === 'generating',
                        description:
                          sshKeyGenerationState === 'generating'
                            ? t`A new Ed25519 key is being created securely.`
                            : sshKeyGenerationState === 'error'
                              ? t`Automatic generation failed. Try again, or change the item type to cancel.`
                              : t`Key material is read-only. Use the show button to view the private key temporarily.`
                      })
                    )}
                    <Field
                      data-invalid={(errorKind === 'ssh' && !draft.publicKey.trim()) || undefined}
                      data-disabled={sshKeyFieldsDisabled || undefined}
                    >
                      <FieldLabel htmlFor="editor-public-key">
                        <Trans>Public key</Trans>
                      </FieldLabel>
                      <Textarea
                        id="editor-public-key"
                        rows={4}
                        value={draft.publicKey}
                        readOnly
                        autoComplete="off"
                        disabled={sshKeyFieldsDisabled}
                        aria-invalid={errorKind === 'ssh' && !draft.publicKey.trim()}
                        aria-describedby={
                          errorKind === 'ssh' && !draft.publicKey.trim()
                            ? 'editor-error'
                            : undefined
                        }
                      />
                    </Field>
                    <Field
                      data-invalid={(errorKind === 'ssh' && !draft.fingerprint.trim()) || undefined}
                      data-disabled={sshKeyFieldsDisabled || undefined}
                    >
                      <FieldLabel htmlFor="editor-fingerprint">
                        <Trans>Key fingerprint</Trans>
                      </FieldLabel>
                      <Input
                        id="editor-fingerprint"
                        value={draft.fingerprint}
                        readOnly
                        autoComplete="off"
                        disabled={sshKeyFieldsDisabled}
                        aria-invalid={errorKind === 'ssh' && !draft.fingerprint.trim()}
                        aria-describedby={
                          errorKind === 'ssh' && !draft.fingerprint.trim()
                            ? 'editor-error'
                            : undefined
                        }
                      />
                    </Field>
                  </>
                )}
              </FieldGroup>
            </EditorFormSection>
          </EditorSection>

          <EditorSection value="organize" className="flex flex-col">
            <EditorFormSection
              title={
                sharedContext
                  ? t({
                      message: 'Organization',
                      context: 'shared-organization',
                      comment:
                        'Section heading in the shared item editor for the Bitwarden organization that owns the item.'
                    })
                  : t({
                      message: 'Organization',
                      comment:
                        'Section heading in the login item editor for organizing the item into a folder and configuring item-level options.'
                    })
              }
              titleId="organization-section-title"
              icon={
                sharedContext ? (
                  <UsersRound aria-hidden="true" />
                ) : (
                  <FolderOpen aria-hidden="true" />
                )
              }
            >
              <FieldGroup className="gap-3">
                {sharedContext ? (
                  <>
                    <Field>
                      <FieldLabel htmlFor="editor-organization">
                        <Trans
                          context="shared-organization"
                          comment="Read-only field label in the shared item editor for the Bitwarden organization that owns the item."
                        >
                          Organization
                        </Trans>
                      </FieldLabel>
                      <Input
                        id="editor-organization"
                        value={sharedContext.organizationName}
                        readOnly
                      />
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="editor-collections">
                        <Trans>Collections</Trans>
                      </FieldLabel>
                      <Input
                        id="editor-collections"
                        value={sharedContext.collectionNames.join(' · ')}
                        readOnly
                      />
                    </Field>
                  </>
                ) : (
                  <>
                    <Field>
                      <FieldLabel htmlFor="editor-folder">
                        <Trans>Folder</Trans>
                      </FieldLabel>
                      <Select
                        items={folderSelectItems}
                        value={draft.folderId ?? ''}
                        disabled={busy}
                        onValueChange={(value) => update('folderId', value || null)}
                      >
                        <SelectTrigger id="editor-folder" className="w-full">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            {folderSelectItems.map((folder) => (
                              <SelectItem key={folder.value || 'unfiled'} value={folder.value}>
                                {folder.label}
                              </SelectItem>
                            ))}
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </Field>
                    <Field
                      className={checkFieldClassName}
                      orientation="horizontal"
                      data-disabled={busy || undefined}
                    >
                      <Checkbox
                        id="editor-favorite"
                        checked={draft.favorite}
                        onCheckedChange={(checked) => update('favorite', checked)}
                        disabled={busy}
                      />
                      <FieldContent>
                        <FieldLabel htmlFor="editor-favorite">
                          <FieldTitle>
                            <Trans>Add to favorites</Trans>
                          </FieldTitle>
                        </FieldLabel>
                        <FieldDescription>
                          <Trans>Find this item quickly from the sidebar</Trans>
                        </FieldDescription>
                      </FieldContent>
                    </Field>
                    <Field
                      className={checkFieldClassName}
                      orientation="horizontal"
                      data-disabled={busy || undefined}
                    >
                      <Checkbox
                        id="editor-reprompt"
                        checked={draft.reprompt === 1}
                        onCheckedChange={(checked) => update('reprompt', checked ? 1 : 0)}
                        disabled={busy}
                      />
                      <FieldContent>
                        <FieldLabel htmlFor="editor-reprompt">
                          <FieldTitle>
                            <Trans>Require master password reprompt</Trans>
                          </FieldTitle>
                        </FieldLabel>
                        <FieldDescription>
                          <Trans>
                            Verify the master password again before viewing or changing this item
                          </Trans>
                        </FieldDescription>
                      </FieldContent>
                    </Field>
                  </>
                )}
              </FieldGroup>
            </EditorFormSection>

            {draft.type !== 'secureNote' && (
              <EditorFormSection
                title={t`Notes`}
                titleId="notes-section-title"
                icon={<NotebookPen aria-hidden="true" />}
              >
                <FieldGroup className="gap-3">
                  <Field>
                    <FieldLabel className="sr-only" htmlFor="editor-notes">
                      <Trans>Notes</Trans>
                    </FieldLabel>
                    <Textarea
                      id="editor-notes"
                      rows={5}
                      value={draft.notes}
                      onChange={(event) => update('notes', event.target.value)}
                      maxLength={5000}
                      disabled={busy}
                    />
                  </Field>
                </FieldGroup>
              </EditorFormSection>
            )}
          </EditorSection>

          <EditorSection value="custom" className="flex flex-col">
            <EditorFormSection
              title={t`Custom fields`}
              titleId="custom-fields-section-title"
              icon={<ListPlus aria-hidden="true" />}
            >
              <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
                <p className="text-muted-foreground m-0 text-sm">
                  <Trans>Add text, hidden text, checkboxes, or links to existing item data.</Trans>
                </p>
                {draft.customFields.length > 0 && customFieldAddMenu()}
              </div>

              {draft.customFields.length === 0 ? (
                <Empty className="border">
                  <EmptyHeader>
                    <EmptyMedia variant="icon">
                      <ListPlus />
                    </EmptyMedia>
                    <EmptyTitle>
                      <Trans>No custom fields yet</Trans>
                    </EmptyTitle>
                    <EmptyDescription>
                      <Trans>Add fields as needed to store data specific to this item.</Trans>
                    </EmptyDescription>
                  </EmptyHeader>
                  <EmptyContent>{customFieldAddMenu('default')}</EmptyContent>
                </Empty>
              ) : (
                <DndContext
                  sensors={sortableSensors}
                  collisionDetection={closestCenter}
                  accessibility={{
                    screenReaderInstructions: {
                      draggable: t`To reorder a custom field, press space or enter. Use the arrow keys to move it, then press space or enter again to drop it.`
                    },
                    announcements: {
                      onDragStart: ({ active }) => {
                        const position = draft.customFields.findIndex(
                          (field) => field.clientId === String(active.id)
                        )
                        return t`Picked up custom field ${position + 1} of ${draft.customFields.length}.`
                      },
                      onDragOver: ({ over }) => {
                        if (!over) return
                        const position = draft.customFields.findIndex(
                          (field) => field.clientId === String(over.id)
                        )
                        return t`Custom field moved to position ${position + 1} of ${draft.customFields.length}.`
                      },
                      onDragEnd: ({ over }) => {
                        if (!over) return t`Custom field was not moved.`
                        const position = draft.customFields.findIndex(
                          (field) => field.clientId === String(over.id)
                        )
                        return t`Custom field dropped at position ${position + 1} of ${draft.customFields.length}.`
                      },
                      onDragCancel: () => t`Custom field reordering cancelled.`
                    }
                  }}
                  onDragEnd={reorderCustomField}
                >
                  <SortableContext
                    items={draft.customFields.map((field) => field.clientId)}
                    strategy={verticalListSortingStrategy}
                  >
                    <FieldGroup>
                      {draft.customFields.map((customField, index) => {
                        const linkedIds = linkedIdsForItemType(draft.type)
                        const customFieldTypeItems = (
                          Object.entries(customFieldTypeLabels) as Array<
                            [VaultCustomFieldType, string]
                          >
                        )
                          .filter(([type]) =>
                            canSelectCustomFieldType(type, {
                              canUseLinked: linkedIds.length > 0,
                              canEditSecrets: !sharedContext || sharedContext.canEditSecrets
                            })
                          )
                          .map(([value, label]) => ({ value, label }))
                        const customFieldId = `editor-custom-field-${customField.clientId}`
                        const customFieldNameId = `${customFieldId}-name`
                        const customFieldTypeId = `${customFieldId}-type`
                        const customFieldValueId = `${customFieldId}-value`
                        const customFieldLabel = customField.name.trim() || t`Field ${index + 1}`
                        const customFieldVisible = Boolean(
                          visibleCustomFields[customField.clientId]
                        )
                        const customFieldBusy =
                          busy ||
                          secretsUnavailable ||
                          Boolean(
                            sharedContext &&
                            !sharedContext.canEditSecrets &&
                            customField.source?.type === 'hidden'
                          ) ||
                          Boolean(revealingCustomFields[customField.clientId])

                        return (
                          <SortableCustomFieldCard
                            key={customField.clientId}
                            id={customField.clientId}
                            disabled={customFieldBusy || draft.customFields.length < 2}
                            dragLabel={t`Reorder ${`${customFieldLabel}`}`}
                          >
                            <Card
                              size="sm"
                              aria-labelledby={`${customFieldId}-title`}
                              aria-disabled={customFieldBusy || undefined}
                            >
                              <CardHeader>
                                <CardTitle
                                  id={`${customFieldId}-title`}
                                  className="flex min-w-0 flex-wrap items-center gap-2"
                                >
                                  <span className="truncate">
                                    {customField.name || <Trans>Unnamed field</Trans>}
                                  </span>
                                  <Badge variant="secondary">
                                    {customFieldTypeLabels[customField.type]}
                                  </Badge>
                                </CardTitle>
                                <CardDescription>
                                  <Trans>Field {index + 1}</Trans>
                                </CardDescription>
                                <CardAction className="flex items-center gap-1">
                                  <Tooltip>
                                    <TooltipTrigger
                                      render={
                                        <Button
                                          type="button"
                                          variant="ghost"
                                          size="icon-sm"
                                          aria-label={t`Delete “${customFieldLabel}”`}
                                          onClick={() => removeCustomField(customField.clientId)}
                                          disabled={customFieldBusy}
                                        />
                                      }
                                    >
                                      <Trash2 />
                                    </TooltipTrigger>
                                    <TooltipContent>
                                      <Trans>Delete</Trans>
                                    </TooltipContent>
                                  </Tooltip>
                                </CardAction>
                              </CardHeader>
                              <CardContent>
                                <FieldGroup>
                                  <FieldGroup className={fieldGridClassName}>
                                    <Field>
                                      <FieldLabel htmlFor={customFieldNameId}>
                                        <Trans>Name</Trans>
                                      </FieldLabel>
                                      <Input
                                        id={customFieldNameId}
                                        value={customField.name}
                                        onChange={(event) =>
                                          updateCustomField(customField.clientId, (field) => ({
                                            ...field,
                                            name: event.target.value
                                          }))
                                        }
                                        maxLength={5000}
                                        disabled={customFieldBusy}
                                      />
                                    </Field>
                                    <Field>
                                      <FieldLabel htmlFor={customFieldTypeId}>
                                        <Trans
                                          context="custom-field-type"
                                          comment="Field label for choosing the data type of a custom field, such as text, hidden, or boolean."
                                        >
                                          Type
                                        </Trans>
                                      </FieldLabel>
                                      <Select
                                        items={customFieldTypeItems}
                                        value={customField.type}
                                        disabled={customFieldBusy}
                                        onValueChange={(value) => {
                                          if (value) {
                                            updateCustomFieldType(
                                              customField.clientId,
                                              value as VaultCustomFieldType
                                            )
                                          }
                                        }}
                                      >
                                        <SelectTrigger id={customFieldTypeId} className="w-full">
                                          <SelectValue />
                                        </SelectTrigger>
                                        <SelectContent>
                                          <SelectGroup>
                                            {customFieldTypeItems.map((item) => (
                                              <SelectItem key={item.value} value={item.value}>
                                                {item.label}
                                              </SelectItem>
                                            ))}
                                          </SelectGroup>
                                        </SelectContent>
                                      </Select>
                                    </Field>
                                  </FieldGroup>

                                  {customField.type === 'text' && (
                                    <Field>
                                      <FieldLabel htmlFor={customFieldValueId}>
                                        <Trans>Content</Trans>
                                      </FieldLabel>
                                      <Input
                                        id={customFieldValueId}
                                        value={customField.value ?? ''}
                                        onChange={(event) =>
                                          updateCustomField(customField.clientId, (field) => ({
                                            ...field,
                                            value: event.target.value
                                          }))
                                        }
                                        maxLength={5000}
                                        disabled={customFieldBusy}
                                      />
                                    </Field>
                                  )}

                                  {customField.type === 'hidden' && (
                                    <Field>
                                      <FieldLabel htmlFor={customFieldValueId}>
                                        <Trans>Content</Trans>
                                      </FieldLabel>
                                      <InputGroup>
                                        <InputGroupInput
                                          id={customFieldValueId}
                                          type={customFieldVisible ? 'text' : 'password'}
                                          value={customField.value ?? ''}
                                          onChange={(event) =>
                                            updateCustomField(customField.clientId, (field) => ({
                                              ...field,
                                              value: event.target.value
                                            }))
                                          }
                                          maxLength={5000}
                                          autoComplete="off"
                                          disabled={customFieldBusy}
                                        />
                                        <InputGroupAddon align="inline-end">
                                          <InputGroupButton
                                            type="button"
                                            variant="ghost"
                                            size="icon-xs"
                                            aria-label={
                                              customFieldVisible
                                                ? t`Hide custom field contents`
                                                : t`Show custom field contents`
                                            }
                                            aria-pressed={customFieldVisible}
                                            onClick={() =>
                                              void toggleCustomFieldVisibility(customField)
                                            }
                                            disabled={customFieldBusy}
                                          >
                                            {revealingCustomFields[customField.clientId] ? (
                                              <Spinner />
                                            ) : customFieldVisible ? (
                                              <EyeOff />
                                            ) : (
                                              <Eye />
                                            )}
                                          </InputGroupButton>
                                        </InputGroupAddon>
                                      </InputGroup>
                                    </Field>
                                  )}

                                  {customField.type === 'boolean' && (
                                    <Field
                                      className={checkFieldClassName}
                                      orientation="horizontal"
                                      data-disabled={customFieldBusy || undefined}
                                    >
                                      <Checkbox
                                        id={customFieldValueId}
                                        checked={customField.value === 'true'}
                                        onCheckedChange={(checked) =>
                                          updateCustomField(customField.clientId, (field) => ({
                                            ...field,
                                            value: checked ? 'true' : 'false'
                                          }))
                                        }
                                        disabled={customFieldBusy}
                                      />
                                      <FieldContent>
                                        <FieldLabel htmlFor={customFieldValueId}>
                                          <FieldTitle>
                                            <Trans>Enabled</Trans>
                                          </FieldTitle>
                                        </FieldLabel>
                                      </FieldContent>
                                    </Field>
                                  )}

                                  {customField.type === 'linked' && (
                                    <Field>
                                      <FieldLabel htmlFor={customFieldValueId}>
                                        <Trans>Link to</Trans>
                                      </FieldLabel>
                                      <Select
                                        items={linkedIds.map((linkedId) => ({
                                          value: String(linkedId),
                                          label: linkedFieldLabels[linkedId] ?? t`Field ${linkedId}`
                                        }))}
                                        value={String(customField.linkedId ?? linkedIds[0] ?? '')}
                                        disabled={customFieldBusy}
                                        onValueChange={(value) => {
                                          const linkedId = Number(value)
                                          if (linkedIds.includes(linkedId)) {
                                            updateCustomField(customField.clientId, (field) => ({
                                              ...field,
                                              value: null,
                                              linkedId
                                            }))
                                          }
                                        }}
                                      >
                                        <SelectTrigger id={customFieldValueId} className="w-full">
                                          <SelectValue />
                                        </SelectTrigger>
                                        <SelectContent>
                                          <SelectGroup>
                                            {linkedIds.map((linkedId) => (
                                              <SelectItem key={linkedId} value={String(linkedId)}>
                                                {linkedFieldLabels[linkedId] ??
                                                  t`Field ${linkedId}`}
                                              </SelectItem>
                                            ))}
                                          </SelectGroup>
                                        </SelectContent>
                                      </Select>
                                    </Field>
                                  )}
                                </FieldGroup>
                              </CardContent>
                            </Card>
                          </SortableCustomFieldCard>
                        )
                      })}
                    </FieldGroup>
                  </SortableContext>
                </DndContext>
              )}
            </EditorFormSection>
          </EditorSection>
        </div>
      </div>

      <footer className="bg-card flex min-h-16 items-center justify-end gap-2 border-t px-5 py-1">
        <Button variant="secondary" type="button" onClick={requestCancel} disabled={busy}>
          <Trans>Cancel</Trans>
        </Button>
        <Button type="submit" disabled={busy || secretsUnavailable || sshKeyUnavailable}>
          {busy ||
          secretLoadState === 'loading' ||
          sshKeyGenerationState === 'generating' ||
          sshKeyImportPending ? (
            <Spinner data-icon="inline-start" />
          ) : (
            <Save data-icon="inline-start" />
          )}
          {secretLoadState === 'loading' ? (
            <Trans>Loading…</Trans>
          ) : sshKeyGenerationState === 'generating' ? (
            <Trans>Generating SSH key…</Trans>
          ) : sshKeyImportState === 'reading' ? (
            <Trans>Reading clipboard…</Trans>
          ) : sshKeyImportState === 'awaitingPassphrase' ? (
            <Trans>Waiting for private key password…</Trans>
          ) : sshKeyImportState === 'submittingPassphrase' ? (
            <Trans>Verifying private key password…</Trans>
          ) : (
            <Trans>Save</Trans>
          )}
        </Button>
      </footer>
      <Dialog
        open={Boolean(sshKeyImportSession)}
        onOpenChange={(open) => {
          if (!open) cancelSshImportPassphrase()
        }}
      >
        <DialogContent showCloseButton={false}>
          <form onSubmit={(event) => void submitSshImportPassphrase(event)}>
            <DialogHeader>
              <DialogTitle>
                <Trans>Enter the SSH private key password</Trans>
              </DialogTitle>
              <DialogDescription>
                <Trans>
                  The private key in the clipboard is encrypted. The password is sent only to the
                  main process to decrypt this import and is not stored in the editor draft.
                </Trans>
              </DialogDescription>
            </DialogHeader>
            <FieldGroup className="py-4">
              <Field data-invalid={Boolean(sshKeyImportError) || undefined}>
                <FieldLabel htmlFor="ssh-import-passphrase">
                  <Trans>Private key password</Trans>
                </FieldLabel>
                <Input
                  ref={sshImportPassphraseRef}
                  id="ssh-import-passphrase"
                  name="ssh-import-passphrase"
                  type="password"
                  autoComplete="off"
                  disabled={busy || sshKeyImportState === 'submittingPassphrase'}
                  aria-invalid={Boolean(sshKeyImportError) || undefined}
                  aria-describedby={sshKeyImportError ? 'ssh-import-passphrase-error' : undefined}
                />
                {sshKeyImportError && (
                  <FieldError id="ssh-import-passphrase-error" role="alert">
                    {sshKeyImportError}
                  </FieldError>
                )}
              </Field>
            </FieldGroup>
            <DialogFooter>
              <Button
                type="button"
                variant="secondary"
                onClick={cancelSshImportPassphrase}
                disabled={busy || sshKeyImportState === 'submittingPassphrase'}
              >
                <Trans>Cancel</Trans>
              </Button>
              <Button type="submit" disabled={busy || sshKeyImportState === 'submittingPassphrase'}>
                {sshKeyImportState === 'submittingPassphrase' && (
                  <Spinner data-icon="inline-start" />
                )}
                {sshKeyImportState === 'submittingPassphrase' ? (
                  <Trans>Verifying…</Trans>
                ) : (
                  <Trans>Continue import</Trans>
                )}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      <AlertDialog
        open={passkeyDeleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setPasskeyDeleteTarget(null)
        }}
      >
        <AlertDialogContent size="sm">
          <AlertDialogHeader>
            <AlertDialogMedia>
              <Trash2 />
            </AlertDialogMedia>
            <AlertDialogTitle>
              <Trans>Delete this passkey?</Trans>
            </AlertDialogTitle>
            <AlertDialogDescription>
              {passkeyDeleteTarget ? (
                <Trans>
                  The passkey for “{passkeyDeleteTarget.rpName || passkeyDeleteTarget.rpId}” will be
                  removed from this login and synced immediately. This action cannot be undone.
                </Trans>
              ) : (
                <Trans>This passkey will be removed from the login immediately.</Trans>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel type="button" disabled={busy}>
              <Trans>Keep passkey</Trans>
            </AlertDialogCancel>
            <AlertDialogAction
              type="button"
              variant="destructive"
              disabled={busy}
              onClick={() => void deletePasskey()}
            >
              {busy ? <Spinner data-icon="inline-start" /> : <Trash2 data-icon="inline-start" />}
              {busy ? <Trans>Deleting…</Trans> : <Trans>Delete passkey</Trans>}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      {generatorTarget && (
        <CredentialGeneratorDialog
          initialTab={generatorTarget}
          onClose={() => setGeneratorTarget(null)}
          onGenerate={window.bearwarden.generator.generate}
          onCopyGenerated={(token) => window.bearwarden.generator.copyGenerated({ token })}
          onListHistory={window.bearwarden.generator.history}
          onCopyHistory={window.bearwarden.generator.copyHistory}
          onClearHistory={window.bearwarden.generator.clearHistory}
          useCategories={generatorTarget === 'password' ? ['password'] : ['username', 'email']}
          onUseCredential={(generated) => {
            if (generatorTarget === 'password' && generated.category === 'password') {
              updateSecret('password', generated.credential)
              setGeneratorTarget(null)
            } else if (
              generatorTarget === 'username' &&
              (generated.category === 'username' || generated.category === 'email')
            ) {
              update('username', generated.credential)
              setGeneratorTarget(null)
            }
          }}
        />
      )}
    </form>
  )
}

interface TextFieldProps {
  id: string
  label: string
  value: string
  onChange: (value: string) => void
  disabled: boolean
  type?: React.HTMLInputTypeAttribute
}

function TextField({
  id,
  label,
  value,
  onChange,
  disabled,
  type = 'text'
}: TextFieldProps): React.JSX.Element {
  return (
    <Field>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <Input
        id={id}
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={disabled}
      />
    </Field>
  )
}

export default LoginEditor
