import { useEffect, useRef, useState } from 'react'
import {
  ArrowDown,
  ArrowUp,
  CheckSquare2,
  Eye,
  EyeOff,
  FileKey2,
  FolderHeart,
  Link2,
  ListPlus,
  Plus,
  Save,
  TextCursorInput,
  Trash2,
  X
} from 'lucide-react'
import type {
  FolderView,
  LoginView,
  VaultCustomFieldType,
  VaultCustomFieldUpdate,
  VaultEditorSecretField,
  VaultItemFields,
  VaultItemType
} from '../../../shared/vault-contract'
import { VAULT_LINKED_FIELD_IDS_BY_TYPE } from '../../../shared/vault-contract'
import {
  detectPaymentCardBrand,
  formatPaymentCardNumber,
  paymentCardBrandOption,
  sanitizePaymentCardNumber,
  type PaymentCardBrand,
  type PaymentCardBrandOption
} from '../lib/payment-card'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Checkbox } from './ui/checkbox'
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs'
import { Textarea } from './ui/textarea'
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip'

type EditorSecretField = VaultEditorSecretField
type EditorTab = 'details' | 'custom' | 'organize'
type EditorErrorKind = 'name' | 'password' | 'ssh' | 'reveal' | null
type SecretLoadState = 'loading' | 'ready' | 'error'

export type EditorCustomField = VaultCustomFieldUpdate & {
  /** Renderer-only identity for stable React list keys. Removed before IPC submission. */
  clientId: string
}

const linkedFieldLabels: Record<number, string> = {
  100: '使用者名稱',
  101: '密碼',
  300: '持卡人',
  301: '到期月',
  302: '到期年',
  303: '安全碼',
  304: '發卡組織',
  305: '卡號',
  400: '稱謂',
  401: '中間名',
  402: '地址',
  403: '地址第二行',
  404: '地址第三行',
  405: '城市',
  406: '州／縣市',
  407: '郵遞區號',
  408: '國家／地區',
  409: '公司',
  410: '電子郵件',
  411: '電話',
  412: '身分證／社會安全號',
  413: '使用者名稱',
  414: '護照號碼',
  415: '駕照號碼',
  416: '名字',
  417: '姓氏',
  418: '全名'
}

const customFieldTypeLabels: Record<VaultCustomFieldType, string> = {
  text: '文字',
  hidden: '隱藏文字',
  boolean: '核取方塊',
  linked: '連結欄位'
}

const paymentCardBrandLabels: Record<Exclude<PaymentCardBrand, 'unknown'>, string> = {
  visa: 'Visa',
  mastercard: 'Mastercard',
  jcb: 'JCB',
  'american-express': 'American Express'
}

const paymentCardBrands = Object.keys(paymentCardBrandLabels) as Exclude<
  PaymentCardBrand,
  'unknown'
>[]

const paymentCardBrandSelectItems: Array<{ value: PaymentCardBrandOption; label: string }> = [
  { value: '', label: '未設定' },
  ...paymentCardBrands.map((value) => ({ value, label: paymentCardBrandLabels[value] })),
  { value: 'unknown', label: '其他' }
]

const itemTypes: Array<{ value: VaultItemType; label: string; description: string }> = [
  { value: 'login', label: '登入', description: '帳號、密碼與網站' },
  { value: 'card', label: '卡片', description: '付款卡與安全碼' },
  { value: 'identity', label: '身分資料', description: '個人與聯絡資訊' },
  { value: 'secureNote', label: '安全備註', description: '只保留加密備註' },
  { value: 'sshKey', label: 'SSH 金鑰', description: '私鑰、公鑰與指紋' }
]

const itemTypeSelectItems = itemTypes.map((item) => ({
  value: item.value,
  label: `${item.label}：${item.description}`
}))

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
  changedSecrets: EditorSecretField[]
  customFields: EditorCustomField[]
}

interface LoginEditorProps {
  login?: LoginView
  folders: FolderView[]
  busy: boolean
  onCancel: () => void
  onDirtyChange: (dirty: boolean) => void
  onSave: (draft: LoginDraft) => Promise<void>
}

function typeLabel(type: VaultItemType): string {
  return itemTypes.find((item) => item.value === type)?.label ?? '項目'
}

function LoginEditor({
  login,
  folders,
  busy,
  onCancel,
  onDirtyChange,
  onSave
}: LoginEditorProps): React.JSX.Element {
  const submittingRef = useRef(false)
  const [editorSnapshot] = useState(() =>
    login ? { id: login.id, expectedUpdatedAt: login.updatedAt } : null
  )
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
  const [activeTab, setActiveTab] = useState<EditorTab>('details')
  const [error, setError] = useState('')
  const [errorKind, setErrorKind] = useState<EditorErrorKind>(null)
  const [secretLoadState, setSecretLoadState] = useState<SecretLoadState>(
    login ? 'loading' : 'ready'
  )
  const nameRef = useRef<HTMLInputElement>(null)
  const secretsUnavailable = secretLoadState !== 'ready'

  useEffect(() => nameRef.current?.focus(), [])
  useEffect(() => {
    draftRef.current = draft
  }, [draft])
  useEffect(() => {
    if (!editorSnapshot) return
    let active = true

    void window.bearwarden.logins
      .revealEditorSecrets(editorSnapshot)
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
        setError('無法載入現有敏感欄位，請取消編輯後再試一次。')
        setErrorKind('reveal')
        setActiveTab('details')
      })

    return () => {
      active = false
    }
  }, [editorSnapshot])
  useEffect(() => onDirtyChange(dirty), [dirty, onDirtyChange])
  useEffect(() => () => onDirtyChange(false), [onDirtyChange])

  function requestCancel(): void {
    if (busy) return
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
    setDirty(true)
    setDraft((current) => ({
      ...current,
      type,
      customFields: normalizeCustomFieldsForItemType(current.customFields, type)
    }))
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
    setActiveTab('custom')
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

  function moveCustomField(index: number, direction: -1 | 1): void {
    const destination = index + direction
    if (destination < 0 || destination >= draftRef.current.customFields.length) return
    setDirty(true)
    setDraft((current) => {
      if (destination < 0 || destination >= current.customFields.length) return current

      const customFields = [...current.customFields]
      const [field] = customFields.splice(index, 1)
      if (!field) return current
      customFields.splice(destination, 0, field)
      return { ...current, customFields }
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
          新增欄位
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuGroup>
            <DropdownMenuItem onClick={() => addCustomField('text')}>
              <TextCursorInput />
              文字
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => addCustomField('hidden')}>
              <EyeOff />
              隱藏文字
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => addCustomField('boolean')}>
              <CheckSquare2 />
              核取方塊
            </DropdownMenuItem>
            {canAddLinkedField && (
              <DropdownMenuItem onClick={() => addCustomField('linked')}>
                <Link2 />
                連結欄位
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
        source: customField.source!
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
      setError('無法顯示自訂欄位內容，請稍後再試。')
      setErrorKind('reveal')
      setActiveTab('custom')
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
    }
  ): React.JSX.Element {
    const visible = Boolean(visibleSecrets[field])
    const value = options?.displayValue ?? draft[field]
    const invalid =
      (field === 'password' && errorKind === 'password') ||
      (field === 'privateKey' && errorKind === 'ssh' && !draft.privateKey.trim())
    const changeValue = (nextValue: string): void => {
      if (options?.onValueChange) {
        options.onValueChange(nextValue)
        return
      }
      updateSecret(field, nextValue)
    }

    return (
      <Field key={field} data-invalid={invalid || undefined}>
        <FieldLabel htmlFor={`editor-${field}`}>{label}</FieldLabel>
        <InputGroup className={options?.multiline ? 'min-h-32 items-stretch' : undefined}>
          {options?.multiline ? (
            <InputGroupTextarea
              id={`editor-${field}`}
              className={visible ? undefined : 'masked-textarea'}
              rows={6}
              value={value}
              onChange={(event) => changeValue(event.target.value)}
              autoComplete="off"
              disabled={busy || secretsUnavailable}
              aria-invalid={invalid || undefined}
              aria-describedby={invalid ? 'editor-error' : undefined}
            />
          ) : (
            <InputGroupInput
              id={`editor-${field}`}
              type={visible ? 'text' : 'password'}
              value={value}
              onChange={(event) => changeValue(event.target.value)}
              inputMode={options?.inputMode}
              placeholder={options?.placeholder}
              autoComplete="off"
              disabled={busy || secretsUnavailable}
              aria-invalid={invalid || undefined}
              aria-describedby={invalid ? 'editor-error' : undefined}
            />
          )}
          <InputGroupAddon align={options?.multiline ? 'block-end' : 'inline-end'}>
            <InputGroupButton
              type="button"
              variant="ghost"
              size="icon-xs"
              aria-label={visible ? `隱藏輸入的${label}` : `顯示輸入的${label}`}
              aria-pressed={visible}
              onClick={() => setVisibleSecrets((current) => ({ ...current, [field]: !visible }))}
              disabled={busy || secretsUnavailable}
            >
              {visible ? <EyeOff /> : <Eye />}
            </InputGroupButton>
          </InputGroupAddon>
        </InputGroup>
      </Field>
    )
  }

  async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (busy || secretsUnavailable || submittingRef.current) return
    if (!draft.name.trim()) {
      setError('請輸入項目名稱。')
      setErrorKind('name')
      setActiveTab('details')
      requestAnimationFrame(() => nameRef.current?.focus())
      return
    }
    if (!login && draft.type === 'login' && !draft.password) {
      setError('新增登入項目時必須輸入密碼。')
      setErrorKind('password')
      setActiveTab('details')
      requestAnimationFrame(() => document.getElementById('editor-password')?.focus())
      return
    }
    if (
      !login &&
      draft.type === 'sshKey' &&
      (!draft.privateKey.trim() || !draft.publicKey.trim() || !draft.fingerprint.trim())
    ) {
      setError('新增 SSH 金鑰時必須輸入私鑰、公鑰與金鑰指紋。')
      setErrorKind('ssh')
      setActiveTab('details')
      const missingFieldId = !draft.privateKey.trim()
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
    try {
      await onSave({ ...draft, name: draft.name.trim(), username: draft.username.trim() })
    } finally {
      submittingRef.current = false
    }
  }

  const editorTitle = login ? `編輯${typeLabel(draft.type)}` : `新增 ${typeLabel(draft.type)}`
  const detectedCardBrand = detectPaymentCardBrand(draft.number)
  const folderSelectItems = [
    { value: '', label: '未分類' },
    ...folders.map((folder) => ({ value: folder.id, label: folder.name }))
  ]

  return (
    <form className="editor" onSubmit={submit} aria-labelledby="editor-title">
      <header className="detail-header editor-header">
        <div>
          <p className="eyebrow">{editorTitle}</p>
          <h2 id="editor-title">{login?.name || `新的 ${typeLabel(draft.type)}項目`}</h2>
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="secondary">{typeLabel(draft.type)}</Badge>
            {dirty && <Badge variant="outline">未儲存</Badge>}
          </div>
        </div>
        <Button
          variant="ghost"
          size="icon"
          type="button"
          aria-label="取消編輯"
          onClick={requestCancel}
          disabled={busy}
        >
          <X />
        </Button>
      </header>

      <div className="editor-scroll">
        <Tabs
          value={activeTab}
          onValueChange={(value) => setActiveTab(value as EditorTab)}
          className="w-full"
        >
          <TabsList
            variant="line"
            aria-label="編輯器區段"
            className="w-full justify-start overflow-x-auto"
          >
            <TabsTrigger value="details">
              <FileKey2 data-icon="inline-start" />
              資料
            </TabsTrigger>
            <TabsTrigger value="custom">
              <ListPlus data-icon="inline-start" />
              自訂
              <Badge variant="secondary">{draft.customFields.length}</Badge>
            </TabsTrigger>
            <TabsTrigger value="organize">
              <FolderHeart data-icon="inline-start" />
              整理
            </TabsTrigger>
          </TabsList>

          {error && (
            <FieldError id="editor-error" role="alert" className="mt-2">
              {error}
            </FieldError>
          )}

          <TabsContent value="details" className="pt-4">
            <FieldSet className="form-section" aria-labelledby="item-section-title">
              <FieldLegend id="item-section-title">{typeLabel(draft.type)}資料</FieldLegend>
              <FieldGroup>
                {!login && (
                  <Field>
                    <FieldLabel htmlFor="editor-type">類型</FieldLabel>
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
                  <FieldLabel htmlFor="editor-name">名稱</FieldLabel>
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
                      <FieldLabel htmlFor="editor-username">使用者名稱</FieldLabel>
                      <Input
                        id="editor-username"
                        value={draft.username}
                        onChange={(event) => update('username', event.target.value)}
                        autoComplete="off"
                        maxLength={320}
                        disabled={busy}
                      />
                    </Field>
                    {secretInput('password', '密碼')}
                    {secretInput('totp', '驗證碼密鑰', {
                      placeholder: 'otpauth://… 或 Base32 密鑰'
                    })}
                    <Field>
                      <FieldLabel htmlFor="editor-uri">網站</FieldLabel>
                      <Input
                        id="editor-uri"
                        type="url"
                        inputMode="url"
                        placeholder="https://example.com"
                        value={draft.uri ?? ''}
                        onChange={(event) => update('uri', event.target.value || null)}
                        disabled={busy}
                      />
                    </Field>
                  </>
                )}

                {draft.type === 'card' && (
                  <>
                    <Field>
                      <FieldLabel htmlFor="editor-cardholder-name">持卡人</FieldLabel>
                      <Input
                        id="editor-cardholder-name"
                        value={draft.cardholderName}
                        onChange={(event) => update('cardholderName', event.target.value)}
                        disabled={busy}
                      />
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="editor-card-brand">發卡組織</FieldLabel>
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
                          aria-label="其他發卡組織名稱"
                          value={draft.brand}
                          onChange={(event) => update('brand', event.target.value)}
                          placeholder="輸入其他發卡組織"
                          disabled={busy}
                        />
                      )}
                    </Field>
                    {secretInput('number', '卡號', {
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
                      <FieldDescription className={`card-brand-hint ${detectedCardBrand}`}>
                        卡號已辨識為 {paymentCardBrandLabels[detectedCardBrand]}
                      </FieldDescription>
                    )}
                    <FieldGroup className="field-grid">
                      <Field>
                        <FieldLabel htmlFor="editor-exp-month">到期月</FieldLabel>
                        <Input
                          id="editor-exp-month"
                          inputMode="numeric"
                          value={draft.expMonth}
                          onChange={(event) => update('expMonth', event.target.value)}
                          disabled={busy}
                        />
                      </Field>
                      <Field>
                        <FieldLabel htmlFor="editor-exp-year">到期年</FieldLabel>
                        <Input
                          id="editor-exp-year"
                          inputMode="numeric"
                          value={draft.expYear}
                          onChange={(event) => update('expYear', event.target.value)}
                          disabled={busy}
                        />
                      </Field>
                    </FieldGroup>
                    {secretInput('code', '安全碼')}
                  </>
                )}

                {draft.type === 'identity' && (
                  <>
                    <FieldGroup className="field-grid">
                      <TextField
                        id="editor-honorific"
                        label="稱謂"
                        value={draft.title}
                        onChange={(value) => update('title', value)}
                        disabled={busy}
                      />
                      <TextField
                        id="editor-company"
                        label="公司"
                        value={draft.company}
                        onChange={(value) => update('company', value)}
                        disabled={busy}
                      />
                    </FieldGroup>
                    <FieldGroup className="field-grid">
                      <TextField
                        id="editor-first-name"
                        label="名字"
                        value={draft.firstName}
                        onChange={(value) => update('firstName', value)}
                        disabled={busy}
                      />
                      <TextField
                        id="editor-middle-name"
                        label="中間名"
                        value={draft.middleName}
                        onChange={(value) => update('middleName', value)}
                        disabled={busy}
                      />
                      <TextField
                        id="editor-last-name"
                        label="姓氏"
                        value={draft.lastName}
                        onChange={(value) => update('lastName', value)}
                        disabled={busy}
                      />
                    </FieldGroup>
                    <TextField
                      id="editor-address-1"
                      label="地址"
                      value={draft.address1}
                      onChange={(value) => update('address1', value)}
                      disabled={busy}
                    />
                    <TextField
                      id="editor-address-2"
                      label="地址第二行"
                      value={draft.address2}
                      onChange={(value) => update('address2', value)}
                      disabled={busy}
                    />
                    <TextField
                      id="editor-address-3"
                      label="地址第三行"
                      value={draft.address3}
                      onChange={(value) => update('address3', value)}
                      disabled={busy}
                    />
                    <FieldGroup className="field-grid">
                      <TextField
                        id="editor-city"
                        label="城市"
                        value={draft.city}
                        onChange={(value) => update('city', value)}
                        disabled={busy}
                      />
                      <TextField
                        id="editor-state"
                        label="州／縣市"
                        value={draft.state}
                        onChange={(value) => update('state', value)}
                        disabled={busy}
                      />
                      <TextField
                        id="editor-postal-code"
                        label="郵遞區號"
                        value={draft.postalCode}
                        onChange={(value) => update('postalCode', value)}
                        disabled={busy}
                      />
                    </FieldGroup>
                    <TextField
                      id="editor-country"
                      label="國家／地區"
                      value={draft.country}
                      onChange={(value) => update('country', value)}
                      disabled={busy}
                    />
                    <FieldGroup className="field-grid">
                      <TextField
                        id="editor-email"
                        label="電子郵件"
                        type="email"
                        value={draft.email}
                        onChange={(value) => update('email', value)}
                        disabled={busy}
                      />
                      <TextField
                        id="editor-phone"
                        label="電話"
                        type="tel"
                        value={draft.phone}
                        onChange={(value) => update('phone', value)}
                        disabled={busy}
                      />
                    </FieldGroup>
                    <TextField
                      id="editor-identity-username"
                      label="使用者名稱"
                      value={draft.identityUsername}
                      onChange={(value) => update('identityUsername', value)}
                      disabled={busy}
                    />
                    {secretInput('ssn', '身分證／社會安全號')}
                    {secretInput('passportNumber', '護照號碼')}
                    {secretInput('licenseNumber', '駕照號碼')}
                  </>
                )}

                {draft.type === 'secureNote' && (
                  <Field>
                    <FieldLabel htmlFor="editor-notes">內容</FieldLabel>
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
                    {secretInput('privateKey', '私鑰', { multiline: true })}
                    <Field
                      data-invalid={(errorKind === 'ssh' && !draft.publicKey.trim()) || undefined}
                    >
                      <FieldLabel htmlFor="editor-public-key">公鑰</FieldLabel>
                      <Textarea
                        id="editor-public-key"
                        rows={4}
                        value={draft.publicKey}
                        onChange={(event) => update('publicKey', event.target.value)}
                        autoComplete="off"
                        disabled={busy}
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
                    >
                      <FieldLabel htmlFor="editor-fingerprint">金鑰指紋</FieldLabel>
                      <Input
                        id="editor-fingerprint"
                        value={draft.fingerprint}
                        onChange={(event) => update('fingerprint', event.target.value)}
                        autoComplete="off"
                        disabled={busy}
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
            </FieldSet>
          </TabsContent>

          <TabsContent value="organize" className="flex flex-col gap-4 pt-4">
            <FieldSet className="form-section" aria-labelledby="organization-section-title">
              <FieldLegend id="organization-section-title">整理</FieldLegend>
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="editor-folder">資料夾</FieldLabel>
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
                  className="check-field"
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
                      <FieldTitle>加入常用項目</FieldTitle>
                    </FieldLabel>
                    <FieldDescription>從側邊欄快速找到這筆資料</FieldDescription>
                  </FieldContent>
                </Field>
              </FieldGroup>
            </FieldSet>

            {draft.type !== 'secureNote' && (
              <FieldSet className="form-section" aria-labelledby="notes-section-title">
                <FieldLegend id="notes-section-title">備註</FieldLegend>
                <FieldGroup>
                  <Field>
                    <FieldLabel className="sr-only" htmlFor="editor-notes">
                      備註
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
              </FieldSet>
            )}
          </TabsContent>

          <TabsContent value="custom" className="flex flex-col gap-4 pt-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="flex min-w-0 flex-col gap-1">
                <h3 className="font-medium">自訂欄位</h3>
                <p className="text-muted-foreground text-sm">
                  新增文字、隱藏文字、核取方塊，或連結項目的既有資料。
                </p>
              </div>
              {draft.customFields.length > 0 && customFieldAddMenu()}
            </div>

            {draft.customFields.length === 0 ? (
              <Empty className="border">
                <EmptyHeader>
                  <EmptyMedia variant="icon">
                    <ListPlus />
                  </EmptyMedia>
                  <EmptyTitle>還沒有自訂欄位</EmptyTitle>
                  <EmptyDescription>依用途新增欄位，補充這筆項目專屬的資料。</EmptyDescription>
                </EmptyHeader>
                <EmptyContent>{customFieldAddMenu('default')}</EmptyContent>
              </Empty>
            ) : (
              <FieldGroup>
                {draft.customFields.map((customField, index) => {
                  const linkedIds = linkedIdsForItemType(draft.type)
                  const customFieldTypeItems = (
                    Object.entries(customFieldTypeLabels) as Array<[VaultCustomFieldType, string]>
                  )
                    .filter(([type]) => type !== 'linked' || linkedIds.length > 0)
                    .map(([value, label]) => ({ value, label }))
                  const customFieldId = `editor-custom-field-${customField.clientId}`
                  const customFieldNameId = `${customFieldId}-name`
                  const customFieldTypeId = `${customFieldId}-type`
                  const customFieldValueId = `${customFieldId}-value`
                  const customFieldLabel = customField.name.trim() || `欄位 ${index + 1}`
                  const customFieldVisible = Boolean(visibleCustomFields[customField.clientId])
                  const customFieldBusy =
                    busy ||
                    secretsUnavailable ||
                    Boolean(revealingCustomFields[customField.clientId])

                  return (
                    <Card
                      key={customField.clientId}
                      size="sm"
                      aria-labelledby={`${customFieldId}-title`}
                      aria-disabled={customFieldBusy || undefined}
                    >
                      <CardHeader>
                        <CardTitle
                          id={`${customFieldId}-title`}
                          className="flex min-w-0 flex-wrap items-center gap-2"
                        >
                          <span className="truncate">{customField.name || '未命名欄位'}</span>
                          <Badge variant="secondary">
                            {customFieldTypeLabels[customField.type]}
                          </Badge>
                        </CardTitle>
                        <CardDescription>欄位 {index + 1}</CardDescription>
                        <CardAction className="flex items-center gap-1">
                          <Tooltip>
                            <TooltipTrigger
                              render={
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon-sm"
                                  aria-label={`上移「${customFieldLabel}」`}
                                  onClick={() => moveCustomField(index, -1)}
                                  disabled={customFieldBusy || index === 0}
                                />
                              }
                            >
                              <ArrowUp />
                            </TooltipTrigger>
                            <TooltipContent>上移</TooltipContent>
                          </Tooltip>
                          <Tooltip>
                            <TooltipTrigger
                              render={
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon-sm"
                                  aria-label={`下移「${customFieldLabel}」`}
                                  onClick={() => moveCustomField(index, 1)}
                                  disabled={
                                    customFieldBusy || index === draft.customFields.length - 1
                                  }
                                />
                              }
                            >
                              <ArrowDown />
                            </TooltipTrigger>
                            <TooltipContent>下移</TooltipContent>
                          </Tooltip>
                          <Tooltip>
                            <TooltipTrigger
                              render={
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon-sm"
                                  aria-label={`刪除「${customFieldLabel}」`}
                                  onClick={() => removeCustomField(customField.clientId)}
                                  disabled={customFieldBusy}
                                />
                              }
                            >
                              <Trash2 />
                            </TooltipTrigger>
                            <TooltipContent>刪除</TooltipContent>
                          </Tooltip>
                        </CardAction>
                      </CardHeader>
                      <CardContent>
                        <FieldGroup>
                          <FieldGroup className="field-grid">
                            <Field>
                              <FieldLabel htmlFor={customFieldNameId}>名稱</FieldLabel>
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
                              <FieldLabel htmlFor={customFieldTypeId}>類型</FieldLabel>
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
                              <FieldLabel htmlFor={customFieldValueId}>內容</FieldLabel>
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
                              <FieldLabel htmlFor={customFieldValueId}>內容</FieldLabel>
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
                                      customFieldVisible ? '隱藏自訂欄位內容' : '顯示自訂欄位內容'
                                    }
                                    aria-pressed={customFieldVisible}
                                    onClick={() => void toggleCustomFieldVisibility(customField)}
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
                              className="check-field"
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
                                  <FieldTitle>已啟用</FieldTitle>
                                </FieldLabel>
                              </FieldContent>
                            </Field>
                          )}

                          {customField.type === 'linked' && (
                            <Field>
                              <FieldLabel htmlFor={customFieldValueId}>連結至</FieldLabel>
                              <Select
                                items={linkedIds.map((linkedId) => ({
                                  value: String(linkedId),
                                  label: linkedFieldLabels[linkedId] ?? `欄位 ${linkedId}`
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
                                        {linkedFieldLabels[linkedId] ?? `欄位 ${linkedId}`}
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
                  )
                })}
              </FieldGroup>
            )}
          </TabsContent>
        </Tabs>
      </div>

      <footer className="editor-actions">
        <Button variant="secondary" type="button" onClick={requestCancel} disabled={busy}>
          取消
        </Button>
        <Button type="submit" disabled={busy || secretsUnavailable}>
          {busy || secretLoadState === 'loading' ? (
            <Spinner data-icon="inline-start" />
          ) : (
            <Save data-icon="inline-start" />
          )}
          {secretLoadState === 'loading' ? '載入中…' : '儲存'}
        </Button>
      </footer>
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
