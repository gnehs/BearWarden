import { useEffect, useRef, useState } from 'react'
import { Eye, EyeOff, Save, X } from 'lucide-react'
import type {
  FolderView,
  LoginView,
  VaultItemFields,
  VaultItemType,
  VaultSecretField
} from '../../../shared/vault-contract'
import {
  detectPaymentCardBrand,
  formatPaymentCardNumber,
  normalizeBitwardenCardBrand,
  sanitizePaymentCardNumber,
  type PaymentCardBrand
} from '../lib/payment-card'
import { Button } from './ui/button'
import { Checkbox } from './ui/checkbox'
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
import { ToggleGroup, ToggleGroupItem } from './ui/toggle-group'
import PaymentCardBrandMark from './PaymentCardBrandMark'

type EditorSecretField = VaultSecretField | 'totp'

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

export interface LoginDraft extends VaultItemFields {
  type: VaultItemType
  name: string
  notes: string
  folderId: string | null
  favorite: boolean
  changedSecrets: EditorSecretField[]
}

interface LoginEditorProps {
  login?: LoginView
  folders: FolderView[]
  busy: boolean
  onCancel: () => void
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
  onSave
}: LoginEditorProps): React.JSX.Element {
  const submittingRef = useRef(false)
  const [draft, setDraft] = useState<LoginDraft>(() => ({
    ...emptyFields,
    ...login,
    // Secrets are intentionally never returned in LoginView. Keeping these empty means an edit
    // does not replace them unless the user deliberately changes the corresponding input.
    password: '',
    totp: '',
    number: '',
    code: '',
    ssn: '',
    passportNumber: '',
    licenseNumber: '',
    privateKey: '',
    type: login?.type ?? 'login',
    name: login?.name ?? '',
    notes: login?.notes ?? '',
    folderId: login?.folderId ?? null,
    favorite: login?.favorite ?? false,
    changedSecrets: []
  }))
  const [visibleSecrets, setVisibleSecrets] = useState<Partial<Record<EditorSecretField, boolean>>>(
    {}
  )
  const [error, setError] = useState('')
  const nameRef = useRef<HTMLInputElement>(null)

  useEffect(() => nameRef.current?.focus(), [])

  function update<K extends keyof LoginDraft>(key: K, value: LoginDraft[K]): void {
    setDraft((current) => ({ ...current, [key]: value }))
  }

  function updateSecret(field: EditorSecretField, value: string): void {
    setDraft((current) => ({
      ...current,
      [field]: value,
      changedSecrets: current.changedSecrets.includes(field)
        ? current.changedSecrets
        : [...current.changedSecrets, field]
    }))
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
    const hint = login ? '留白則不變更' : undefined
    const changeValue = (nextValue: string): void => {
      if (options?.onValueChange) {
        options.onValueChange(nextValue)
        return
      }
      updateSecret(field, nextValue)
    }

    return (
      <Field key={field} className="field">
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
              disabled={busy}
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
              disabled={busy}
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
              disabled={busy}
            >
              {visible ? <EyeOff /> : <Eye />}
            </InputGroupButton>
          </InputGroupAddon>
        </InputGroup>
        {hint && <FieldDescription>{hint}</FieldDescription>}
      </Field>
    )
  }

  async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (busy || submittingRef.current) return
    if (!draft.name.trim()) {
      setError('請輸入項目名稱。')
      nameRef.current?.focus()
      return
    }
    if (!login && draft.type === 'login' && !draft.password) {
      setError('新增登入項目時必須輸入密碼。')
      return
    }
    if (
      !login &&
      draft.type === 'sshKey' &&
      (!draft.privateKey.trim() || !draft.publicKey.trim() || !draft.fingerprint.trim())
    ) {
      setError('新增 SSH 金鑰時必須輸入私鑰、公鑰與金鑰指紋。')
      return
    }
    setError('')
    submittingRef.current = true
    try {
      await onSave({ ...draft, name: draft.name.trim(), username: draft.username.trim() })
    } finally {
      submittingRef.current = false
    }
  }

  const editorTitle = login ? `編輯${typeLabel(draft.type)}` : `新增 ${typeLabel(draft.type)}`
  const detectedCardBrand = detectPaymentCardBrand(draft.number)
  const selectedCardBrand =
    detectedCardBrand === 'unknown' ? normalizeBitwardenCardBrand(draft.brand) : detectedCardBrand
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
        </div>
        <Button
          variant="ghost"
          size="icon"
          type="button"
          aria-label="取消編輯"
          onClick={onCancel}
          disabled={busy}
        >
          <X />
        </Button>
      </header>

      <div className="editor-scroll">
        <FieldSet className="form-section" aria-labelledby="item-section-title">
          <FieldLegend id="item-section-title">{typeLabel(draft.type)}資料</FieldLegend>
          <FieldGroup>
            {!login && (
              <Field className="field">
                <FieldLabel htmlFor="editor-type">類型</FieldLabel>
                <Select
                  items={itemTypeSelectItems}
                  value={draft.type}
                  disabled={busy}
                  onValueChange={(value) => value && update('type', value as VaultItemType)}
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
            <Field className="field" data-invalid={Boolean(error)}>
              <FieldLabel htmlFor="editor-name">名稱</FieldLabel>
              <Input
                id="editor-name"
                ref={nameRef}
                value={draft.name}
                onChange={(event) => update('name', event.target.value)}
                maxLength={160}
                disabled={busy}
                aria-invalid={Boolean(error)}
                aria-describedby={error ? 'editor-error' : undefined}
              />
            </Field>

            {draft.type === 'login' && (
              <>
                <Field className="field">
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
                <Field className="field">
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
                <Field className="field">
                  <FieldLabel htmlFor="editor-cardholder-name">持卡人</FieldLabel>
                  <Input
                    id="editor-cardholder-name"
                    value={draft.cardholderName}
                    onChange={(event) => update('cardholderName', event.target.value)}
                    disabled={busy}
                  />
                </Field>
                <FieldSet className="payment-brand-picker">
                  <FieldLegend variant="label">發卡組織</FieldLegend>
                  <ToggleGroup
                    value={[selectedCardBrand]}
                    disabled={busy}
                    aria-label="常用發卡組織"
                    onValueChange={(values) => {
                      const brand = values.at(-1) as PaymentCardBrand | undefined
                      update(
                        'brand',
                        brand && brand !== 'unknown' ? paymentCardBrandLabels[brand] : ''
                      )
                    }}
                  >
                    {paymentCardBrands.map((brand) => (
                      <ToggleGroupItem
                        key={brand}
                        value={brand}
                        aria-label={paymentCardBrandLabels[brand]}
                      >
                        <PaymentCardBrandMark brand={brand} />
                      </ToggleGroupItem>
                    ))}
                    <ToggleGroupItem value="unknown" aria-label="其他發卡組織">
                      <PaymentCardBrandMark brand="unknown" />
                      <span>其他</span>
                    </ToggleGroupItem>
                  </ToggleGroup>
                  {selectedCardBrand === 'unknown' && (
                    <Input
                      aria-label="其他發卡組織名稱"
                      value={draft.brand}
                      onChange={(event) => update('brand', event.target.value)}
                      placeholder="輸入其他發卡組織"
                      disabled={busy}
                    />
                  )}
                </FieldSet>
                {secretInput('number', '卡號', {
                  inputMode: 'numeric',
                  displayValue: formatPaymentCardNumber(draft.number),
                  onValueChange: (value) => {
                    const digits = sanitizePaymentCardNumber(value)
                    updateSecret('number', digits)
                    const detected = detectPaymentCardBrand(digits)
                    if (
                      detected !== 'unknown' &&
                      (!draft.brand || normalizeBitwardenCardBrand(draft.brand) !== 'unknown')
                    ) {
                      update('brand', paymentCardBrandLabels[detected])
                    }
                  }
                })}
                {selectedCardBrand !== 'unknown' && (
                  <FieldDescription className={`card-brand-hint ${selectedCardBrand}`}>
                    卡號已辨識為 {paymentCardBrandLabels[selectedCardBrand]}
                  </FieldDescription>
                )}
                <FieldGroup className="field-grid">
                  <Field className="field">
                    <FieldLabel htmlFor="editor-exp-month">到期月</FieldLabel>
                    <Input
                      id="editor-exp-month"
                      inputMode="numeric"
                      value={draft.expMonth}
                      onChange={(event) => update('expMonth', event.target.value)}
                      disabled={busy}
                    />
                  </Field>
                  <Field className="field">
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
              <Field className="field note-content-field">
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
                <Field className="field">
                  <FieldLabel htmlFor="editor-public-key">公鑰</FieldLabel>
                  <Textarea
                    id="editor-public-key"
                    rows={4}
                    value={draft.publicKey}
                    onChange={(event) => update('publicKey', event.target.value)}
                    autoComplete="off"
                    disabled={busy}
                  />
                </Field>
                <Field className="field">
                  <FieldLabel htmlFor="editor-fingerprint">金鑰指紋</FieldLabel>
                  <Input
                    id="editor-fingerprint"
                    value={draft.fingerprint}
                    onChange={(event) => update('fingerprint', event.target.value)}
                    autoComplete="off"
                    disabled={busy}
                  />
                </Field>
              </>
            )}
          </FieldGroup>
        </FieldSet>

        <FieldSet className="form-section" aria-labelledby="organization-section-title">
          <FieldLegend id="organization-section-title">整理</FieldLegend>
          <FieldGroup>
            <Field className="field">
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
              <Field className="field visually-labeled">
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

        {error && <FieldError id="editor-error">{error}</FieldError>}
      </div>

      <footer className="editor-actions">
        <Button variant="secondary" type="button" onClick={onCancel} disabled={busy}>
          取消
        </Button>
        <Button type="submit" disabled={busy}>
          {busy ? <Spinner data-icon="inline-start" /> : <Save data-icon="inline-start" />}
          儲存
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
    <Field className="field">
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
