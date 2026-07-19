import { useEffect, useMemo, useRef, useState } from 'react'
import { History, RefreshCw, ShieldAlert, Trash2 } from 'lucide-react'
import type {
  CredentialGeneratorRequest,
  CredentialGeneratorResult,
  GeneratorCredentialCategory,
  GeneratorHistoryEntry,
  GeneratorHistoryLocator
} from '../../../shared/vault-contract'
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import { Button } from '@renderer/components/ui/button'
import { Checkbox } from '@renderer/components/ui/checkbox'
import { DialogClose, DialogFooter } from '@renderer/components/ui/dialog'
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSet,
  FieldTitle
} from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput
} from '@renderer/components/ui/input-group'
import { Spinner } from '@renderer/components/ui/spinner'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@renderer/components/ui/tabs'
import { ToggleGroup, ToggleGroupItem } from '@renderer/components/ui/toggle-group'
import { useCopyFeedback } from '@renderer/hooks/use-copy-feedback'
import { Modal } from './Dialogs'
import { CopyFeedbackIcon } from './CopyFeedbackIcon'

type GeneratorTab = 'password' | 'username' | 'history'
type PasswordAlgorithm = 'password' | 'passphrase'
type UsernameAlgorithm = 'username' | 'subaddress' | 'catchall'

interface CredentialGeneratorDialogProps {
  initialTab?: Exclude<GeneratorTab, 'history'>
  onClose: () => void
  onGenerate: (request: CredentialGeneratorRequest) => Promise<CredentialGeneratorResult>
  onCopyGenerated: (token: string) => Promise<void>
  onListHistory: () => Promise<GeneratorHistoryEntry[]>
  onCopyHistory: (locator: GeneratorHistoryLocator) => Promise<void>
  onClearHistory: () => Promise<void>
  onUseCredential?: (result: CredentialGeneratorResult) => void
  useCategories?: readonly GeneratorCredentialCategory[]
}

const historyAlgorithmLabels: Record<NonNullable<GeneratorHistoryEntry['algorithm']>, string> = {
  password: '密碼',
  passphrase: '密語',
  username: '隨機單字',
  subaddress: 'Plus Address',
  catchall: 'Catch-all'
}

const generatedCopyFeedbackKey = 'generated'

function historyLocator(entry: GeneratorHistoryEntry, index: number): GeneratorHistoryLocator {
  return {
    index,
    generationDate: entry.generationDate,
    category: entry.category,
    ...(entry.algorithm === undefined ? {} : { algorithm: entry.algorithm })
  }
}

function copyFeedbackKey(locator: GeneratorHistoryLocator): string {
  return [locator.category, locator.algorithm ?? '', locator.generationDate, locator.index].join(
    ':'
  )
}

function NumberField({
  id,
  label,
  value,
  min,
  max,
  disabled,
  onChange
}: {
  id: string
  label: string
  value: number
  min: number
  max: number
  disabled: boolean
  onChange: (value: number) => void
}): React.JSX.Element {
  return (
    <Field>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <Input
        id={id}
        type="number"
        inputMode="numeric"
        value={value}
        min={min}
        max={max}
        disabled={disabled}
        onChange={(event) => onChange(Number(event.target.value))}
      />
    </Field>
  )
}

function CheckboxField({
  id,
  title,
  description,
  checked,
  disabled,
  onCheckedChange
}: {
  id: string
  title: string
  description?: string
  checked: boolean
  disabled: boolean
  onCheckedChange: (checked: boolean) => void
}): React.JSX.Element {
  return (
    <Field orientation="horizontal" data-disabled={disabled || undefined}>
      <Checkbox id={id} checked={checked} disabled={disabled} onCheckedChange={onCheckedChange} />
      <FieldContent>
        <FieldLabel htmlFor={id}>
          <FieldTitle>{title}</FieldTitle>
        </FieldLabel>
        {description && <FieldDescription>{description}</FieldDescription>}
      </FieldContent>
    </Field>
  )
}

export default function CredentialGeneratorDialog({
  initialTab = 'password',
  onClose,
  onGenerate,
  onCopyGenerated,
  onListHistory,
  onCopyHistory,
  onClearHistory,
  onUseCredential,
  useCategories
}: CredentialGeneratorDialogProps): React.JSX.Element {
  const mountedRef = useRef(true)
  const requestGenerationRef = useRef(0)
  const [tab, setTab] = useState<GeneratorTab>(initialTab)
  const [passwordAlgorithm, setPasswordAlgorithm] = useState<PasswordAlgorithm>('password')
  const [usernameAlgorithm, setUsernameAlgorithm] = useState<UsernameAlgorithm>('username')
  const [result, setResult] = useState<CredentialGeneratorResult | null>(null)
  const [history, setHistory] = useState<GeneratorHistoryEntry[]>([])
  const [historyLoaded, setHistoryLoaded] = useState(false)
  const [busy, setBusy] = useState(true)
  const [error, setError] = useState('')
  const [length, setLength] = useState(14)
  const [uppercase, setUppercase] = useState(true)
  const [lowercase, setLowercase] = useState(true)
  const [numbers, setNumbers] = useState(true)
  const [special, setSpecial] = useState(false)
  const [avoidAmbiguous, setAvoidAmbiguous] = useState(false)
  const [minUppercase, setMinUppercase] = useState(1)
  const [minLowercase, setMinLowercase] = useState(1)
  const [minNumber, setMinNumber] = useState(1)
  const [minSpecial, setMinSpecial] = useState(0)
  const [wordCount, setWordCount] = useState(6)
  const [separator, setSeparator] = useState('-')
  const [capitalize, setCapitalize] = useState(false)
  const [includeNumber, setIncludeNumber] = useState(false)
  const [usernameCapitalize, setUsernameCapitalize] = useState(false)
  const [usernameIncludeNumber, setUsernameIncludeNumber] = useState(false)
  const [email, setEmail] = useState('')
  const [domain, setDomain] = useState('')
  const { copiedKey, clearCopied, showCopied } = useCopyFeedback()
  const canUseResult = Boolean(
    result && onUseCredential && (!useCategories || useCategories.includes(result.category))
  )

  const generateLabel =
    tab === 'password'
      ? passwordAlgorithm === 'password'
        ? '密碼'
        : '密語'
      : usernameAlgorithm === 'username'
        ? '使用者名稱'
        : 'Email'

  const generatorRequest = useMemo<CredentialGeneratorRequest | null>(() => {
    if (tab === 'history') return null
    if (tab === 'password') {
      return passwordAlgorithm === 'password'
        ? {
            algorithm: 'password',
            options: {
              length,
              uppercase,
              lowercase,
              numbers,
              special,
              minUppercase: uppercase ? minUppercase : 0,
              minLowercase: lowercase ? minLowercase : 0,
              minNumber: numbers ? minNumber : 0,
              minSpecial: special ? minSpecial : 0,
              avoidAmbiguous
            }
          }
        : {
            algorithm: 'passphrase',
            options: { wordCount, separator, capitalize, includeNumber }
          }
    }
    if (usernameAlgorithm === 'username') {
      return {
        algorithm: 'username',
        options: { capitalize: usernameCapitalize, includeNumber: usernameIncludeNumber }
      }
    }
    if (usernameAlgorithm === 'subaddress') {
      return email.length > 0 ? { algorithm: 'subaddress', email } : null
    }
    return domain.length > 0 ? { algorithm: 'catchall', domain } : null
  }, [
    avoidAmbiguous,
    capitalize,
    domain,
    email,
    includeNumber,
    length,
    lowercase,
    minLowercase,
    minNumber,
    minSpecial,
    minUppercase,
    numbers,
    passwordAlgorithm,
    separator,
    special,
    tab,
    uppercase,
    usernameAlgorithm,
    usernameCapitalize,
    usernameIncludeNumber,
    wordCount
  ])

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
      requestGenerationRef.current += 1
    }
  }, [])

  useEffect(() => {
    if (!generatorRequest) return
    let ignore = false
    const generation = ++requestGenerationRef.current
    const delay =
      generatorRequest.algorithm === 'subaddress' || generatorRequest.algorithm === 'catchall'
        ? 250
        : 0

    const timer = window.setTimeout(() => {
      if (ignore || !mountedRef.current || requestGenerationRef.current !== generation) return
      setBusy(true)
      setError('')
      setResult(null)
      clearCopied()
      void onGenerate(generatorRequest)
        .then((generated) => {
          if (!ignore && mountedRef.current && requestGenerationRef.current === generation) {
            setResult(generated)
          }
        })
        .catch(() => {
          if (!ignore && mountedRef.current && requestGenerationRef.current === generation) {
            setError('設定無法產生有效的值，請檢查長度、最少字元與 Email／網域。')
          }
        })
        .finally(() => {
          if (!ignore && mountedRef.current && requestGenerationRef.current === generation) {
            setBusy(false)
          }
        })
    }, delay)

    return () => {
      ignore = true
      window.clearTimeout(timer)
      if (requestGenerationRef.current === generation) requestGenerationRef.current += 1
    }
  }, [clearCopied, generatorRequest, onGenerate, tab])

  function invalidatePlaintext(): void {
    requestGenerationRef.current += 1
    setResult(null)
    setHistory([])
    setHistoryLoaded(false)
    setEmail('')
    setDomain('')
    setError('')
    setBusy(false)
    clearCopied()
  }

  function changeSetting<T>(setter: (value: T) => void, value: T): void {
    setter(value)
    setResult(null)
    setError('')
    clearCopied()
  }

  async function loadHistory(): Promise<void> {
    const generation = ++requestGenerationRef.current
    setBusy(true)
    setError('')
    try {
      const entries = await onListHistory()
      if (!mountedRef.current || requestGenerationRef.current !== generation) return
      setHistory(entries)
      setHistoryLoaded(true)
    } catch {
      if (mountedRef.current && requestGenerationRef.current === generation) {
        setError('無法讀取產生器歷史。')
      }
    } finally {
      if (mountedRef.current && requestGenerationRef.current === generation) setBusy(false)
    }
  }

  function changeTab(nextTab: GeneratorTab): void {
    if (nextTab === tab) return
    invalidatePlaintext()
    setTab(nextTab)
    if (nextTab === 'history') {
      void loadHistory()
    }
  }

  async function generate(): Promise<void> {
    if (!generatorRequest) {
      setError('設定無法產生有效的值，請檢查長度、最少字元與 Email／網域。')
      return
    }
    const generation = ++requestGenerationRef.current

    setBusy(true)
    setError('')
    setResult(null)
    clearCopied()
    try {
      const generated = await onGenerate(generatorRequest)
      if (!mountedRef.current || requestGenerationRef.current !== generation) return
      setResult(generated)
    } catch {
      if (mountedRef.current && requestGenerationRef.current === generation) {
        setError('設定無法產生有效的值，請檢查長度、最少字元與 Email／網域。')
      }
    } finally {
      if (mountedRef.current && requestGenerationRef.current === generation) setBusy(false)
    }
  }

  async function copyGenerated(token: string): Promise<void> {
    const generation = ++requestGenerationRef.current
    setBusy(true)
    setError('')
    clearCopied()
    try {
      await onCopyGenerated(token)
      if (mountedRef.current && requestGenerationRef.current === generation) {
        showCopied(generatedCopyFeedbackKey)
      }
    } catch {
      if (mountedRef.current && requestGenerationRef.current === generation) {
        setError('無法複製產生結果，請重新產生後再試。')
      }
    } finally {
      if (mountedRef.current && requestGenerationRef.current === generation) setBusy(false)
    }
  }

  async function copyHistory(locator: GeneratorHistoryLocator): Promise<void> {
    const generation = ++requestGenerationRef.current
    const feedbackKey = copyFeedbackKey(locator)
    setBusy(true)
    setError('')
    clearCopied()
    try {
      await onCopyHistory(locator)
      if (mountedRef.current && requestGenerationRef.current === generation) {
        showCopied(feedbackKey)
      }
    } catch {
      if (mountedRef.current && requestGenerationRef.current === generation) {
        setError('無法複製；這筆歷史可能已變更。')
      }
    } finally {
      if (mountedRef.current && requestGenerationRef.current === generation) setBusy(false)
    }
  }

  async function clearHistory(): Promise<void> {
    const generation = ++requestGenerationRef.current
    setBusy(true)
    setError('')
    try {
      await onClearHistory()
      if (!mountedRef.current || requestGenerationRef.current !== generation) return
      setHistory([])
      setHistoryLoaded(true)
      setResult(null)
    } catch {
      if (mountedRef.current && requestGenerationRef.current === generation) {
        setError('無法清除產生器歷史。')
      }
    } finally {
      if (mountedRef.current && requestGenerationRef.current === generation) setBusy(false)
    }
  }

  return (
    <Modal
      title="產生器"
      busy={busy}
      onClose={() => {
        invalidatePlaintext()
        onClose()
      }}
    >
      {() => (
        <>
          <div className="modal-body h-[min(65vh,calc(100vh-11rem))] overflow-hidden">
            <Tabs
              className="min-h-0 overflow-hidden p-px"
              value={tab}
              onValueChange={(value) => changeTab(value as GeneratorTab)}
            >
              <TabsList sliding className="w-full shrink-0">
                <TabsTrigger value="password">密碼</TabsTrigger>
                <TabsTrigger value="username">使用者名稱</TabsTrigger>
                <TabsTrigger value="history">歷史</TabsTrigger>
              </TabsList>

              {tab !== 'history' && (
                <div className="flex shrink-0 flex-col gap-3">
                  <InputGroup>
                    <InputGroupInput
                      id="generator-result"
                      className="font-mono"
                      value={result?.credential ?? ''}
                      placeholder={busy ? '正在安全產生…' : '結果會顯示在這裡'}
                      readOnly
                      autoComplete="off"
                      aria-label="產生結果"
                      onCopy={(event) => {
                        event.preventDefault()
                        if (result && !busy) void copyGenerated(result.copyToken)
                      }}
                      onKeyDown={(event) => {
                        if (
                          !event.nativeEvent.isComposing &&
                          (event.metaKey || event.ctrlKey) &&
                          event.key.toLowerCase() === 'c'
                        ) {
                          event.preventDefault()
                          if (result && !busy) void copyGenerated(result.copyToken)
                        }
                      }}
                    />
                    <InputGroupAddon align="inline-end" className="flex gap-1">
                      <InputGroupButton
                        size="icon-xs"
                        disabled={busy}
                        aria-label={result ? `重新產生${generateLabel}` : `產生${generateLabel}`}
                        onClick={() => void generate()}
                      >
                        {busy ? <Spinner /> : <RefreshCw />}
                      </InputGroupButton>
                      <InputGroupButton
                        size="xs"
                        disabled={busy || !result}
                        aria-label={
                          copiedKey === generatedCopyFeedbackKey ? '產生結果已複製' : '複製產生結果'
                        }
                        onClick={() => {
                          if (result) void copyGenerated(result.copyToken)
                        }}
                      >
                        <CopyFeedbackIcon
                          copied={copiedKey === generatedCopyFeedbackKey}
                          placement="inline-start"
                        />
                        {copiedKey === generatedCopyFeedbackKey ? '已複製' : '複製'}
                      </InputGroupButton>
                    </InputGroupAddon>
                  </InputGroup>
                  <div className="sr-only" role="status" aria-live="polite">
                    {result && copiedKey === generatedCopyFeedbackKey
                      ? '產生結果已複製'
                      : result
                        ? '已產生新結果'
                        : busy
                          ? '正在產生'
                          : ''}
                  </div>
                  {canUseResult && result && onUseCredential && (
                    <div className="flex justify-end">
                      <Button type="button" disabled={busy} onClick={() => onUseCredential(result)}>
                        使用這個值
                      </Button>
                    </div>
                  )}
                </div>
              )}

              {error && (
                <Alert id="generator-error" variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <TabsContent value="password" className="min-h-0 overflow-hidden">
                <FieldGroup className="scroll-fade-y forced-colors:scroll-fade-none h-full overflow-y-auto p-px">
                  <FieldSet>
                    <FieldLegend variant="label">類型</FieldLegend>
                    <ToggleGroup
                      value={[passwordAlgorithm]}
                      variant="outline"
                      className="w-full"
                      disabled={busy}
                      onValueChange={(values) => {
                        const value = values[0] as PasswordAlgorithm | undefined
                        if (value) {
                          changeSetting(setPasswordAlgorithm, value)
                        }
                      }}
                    >
                      <ToggleGroupItem value="password" className="flex-1">
                        密碼
                      </ToggleGroupItem>
                      <ToggleGroupItem value="passphrase" className="flex-1">
                        密語
                      </ToggleGroupItem>
                    </ToggleGroup>
                  </FieldSet>

                  {passwordAlgorithm === 'password' ? (
                    <>
                      <NumberField
                        id="generator-length"
                        label="長度"
                        value={length}
                        min={5}
                        max={128}
                        disabled={busy}
                        onChange={(value) => changeSetting(setLength, value)}
                      />
                      <FieldSet>
                        <FieldLegend variant="label">字元類型</FieldLegend>
                        <FieldGroup data-slot="checkbox-group">
                          <CheckboxField
                            id="generator-upper"
                            title="大寫字母"
                            checked={uppercase}
                            disabled={busy}
                            onCheckedChange={(value) => changeSetting(setUppercase, value)}
                          />
                          <CheckboxField
                            id="generator-lower"
                            title="小寫字母"
                            checked={lowercase}
                            disabled={busy}
                            onCheckedChange={(value) => changeSetting(setLowercase, value)}
                          />
                          <CheckboxField
                            id="generator-number"
                            title="數字"
                            checked={numbers}
                            disabled={busy}
                            onCheckedChange={(value) => changeSetting(setNumbers, value)}
                          />
                          <CheckboxField
                            id="generator-special"
                            title="特殊字元 !@#$%^&*"
                            checked={special}
                            disabled={busy}
                            onCheckedChange={(value) => changeSetting(setSpecial, value)}
                          />
                          <CheckboxField
                            id="generator-ambiguous"
                            title="避免易混淆字元"
                            description="排除 0、O、1、l、I"
                            checked={avoidAmbiguous}
                            disabled={busy}
                            onCheckedChange={(value) => changeSetting(setAvoidAmbiguous, value)}
                          />
                        </FieldGroup>
                      </FieldSet>
                      <div className="grid grid-cols-2 gap-3">
                        <NumberField
                          id="generator-min-upper"
                          label="最少大寫"
                          value={minUppercase}
                          min={0}
                          max={128}
                          disabled={busy || !uppercase}
                          onChange={(value) => changeSetting(setMinUppercase, value)}
                        />
                        <NumberField
                          id="generator-min-lower"
                          label="最少小寫"
                          value={minLowercase}
                          min={0}
                          max={128}
                          disabled={busy || !lowercase}
                          onChange={(value) => changeSetting(setMinLowercase, value)}
                        />
                        <NumberField
                          id="generator-min-number"
                          label="最少數字"
                          value={minNumber}
                          min={0}
                          max={9}
                          disabled={busy || !numbers}
                          onChange={(value) => changeSetting(setMinNumber, value)}
                        />
                        <NumberField
                          id="generator-min-special"
                          label="最少特殊字元"
                          value={minSpecial}
                          min={0}
                          max={9}
                          disabled={busy || !special}
                          onChange={(value) => changeSetting(setMinSpecial, value)}
                        />
                      </div>
                    </>
                  ) : (
                    <>
                      <NumberField
                        id="generator-word-count"
                        label="單字數"
                        value={wordCount}
                        min={3}
                        max={20}
                        disabled={busy}
                        onChange={(value) => changeSetting(setWordCount, value)}
                      />
                      <Field>
                        <FieldLabel htmlFor="generator-separator">分隔字元</FieldLabel>
                        <Input
                          id="generator-separator"
                          value={separator}
                          maxLength={1}
                          disabled={busy}
                          onChange={(event) => changeSetting(setSeparator, event.target.value)}
                        />
                        <FieldDescription>
                          Bitwarden 相容設定只允許一個 UTF-16 字元。
                        </FieldDescription>
                      </Field>
                      <FieldSet>
                        <FieldLegend variant="label">格式</FieldLegend>
                        <FieldGroup data-slot="checkbox-group">
                          <CheckboxField
                            id="generator-capitalize"
                            title="每個單字首字母大寫"
                            checked={capitalize}
                            disabled={busy}
                            onCheckedChange={(value) => changeSetting(setCapitalize, value)}
                          />
                          <CheckboxField
                            id="generator-include-number"
                            title="加入一個數字"
                            checked={includeNumber}
                            disabled={busy}
                            onCheckedChange={(value) => changeSetting(setIncludeNumber, value)}
                          />
                        </FieldGroup>
                      </FieldSet>
                    </>
                  )}
                </FieldGroup>
              </TabsContent>

              <TabsContent value="username" className="min-h-0 overflow-hidden">
                <FieldGroup className="scroll-fade-y forced-colors:scroll-fade-none h-full overflow-y-auto p-px">
                  <FieldSet>
                    <FieldLegend variant="label">類型</FieldLegend>
                    <ToggleGroup
                      value={[usernameAlgorithm]}
                      variant="outline"
                      className="w-full"
                      disabled={busy}
                      onValueChange={(values) => {
                        const value = values[0] as UsernameAlgorithm | undefined
                        if (value) {
                          changeSetting(setUsernameAlgorithm, value)
                        }
                      }}
                    >
                      <ToggleGroupItem value="username" className="flex-1">
                        單字
                      </ToggleGroupItem>
                      <ToggleGroupItem value="subaddress" className="flex-1">
                        Plus
                      </ToggleGroupItem>
                      <ToggleGroupItem value="catchall" className="flex-1">
                        Catch-all
                      </ToggleGroupItem>
                    </ToggleGroup>
                  </FieldSet>
                  {usernameAlgorithm === 'username' ? (
                    <FieldSet>
                      <FieldLegend variant="label">格式</FieldLegend>
                      <FieldGroup data-slot="checkbox-group">
                        <CheckboxField
                          id="generator-username-capitalize"
                          title="首字母大寫"
                          checked={usernameCapitalize}
                          disabled={busy}
                          onCheckedChange={(value) => changeSetting(setUsernameCapitalize, value)}
                        />
                        <CheckboxField
                          id="generator-username-number"
                          title="加入四位數字"
                          checked={usernameIncludeNumber}
                          disabled={busy}
                          onCheckedChange={(value) =>
                            changeSetting(setUsernameIncludeNumber, value)
                          }
                        />
                      </FieldGroup>
                    </FieldSet>
                  ) : usernameAlgorithm === 'subaddress' ? (
                    <Field data-invalid={Boolean(error) || undefined}>
                      <FieldLabel htmlFor="generator-email">Email</FieldLabel>
                      <Input
                        id="generator-email"
                        type="email"
                        autoComplete="off"
                        value={email}
                        maxLength={320}
                        disabled={busy}
                        aria-invalid={Boolean(error)}
                        aria-describedby={error ? 'generator-error' : undefined}
                        onChange={(event) => changeSetting(setEmail, event.target.value)}
                      />
                      <FieldDescription>
                        例如 name@example.com；只在這次產生期間使用。
                      </FieldDescription>
                    </Field>
                  ) : (
                    <Field data-invalid={Boolean(error) || undefined}>
                      <FieldLabel htmlFor="generator-domain">Catch-all 網域</FieldLabel>
                      <Input
                        id="generator-domain"
                        autoComplete="off"
                        value={domain}
                        maxLength={253}
                        disabled={busy}
                        aria-invalid={Boolean(error)}
                        aria-describedby={error ? 'generator-error' : undefined}
                        onChange={(event) => changeSetting(setDomain, event.target.value)}
                      />
                      <FieldDescription>
                        例如 example.com；不會連線到第三方轉寄服務。
                      </FieldDescription>
                    </Field>
                  )}
                  <Alert>
                    <ShieldAlert />
                    <AlertTitle>本機產生器</AlertTitle>
                    <AlertDescription>
                      目前不提供需要 API 憑證的第三方 Email 轉寄整合。
                    </AlertDescription>
                  </Alert>
                </FieldGroup>
              </TabsContent>

              <TabsContent value="history" className="min-h-0 overflow-hidden">
                <FieldGroup className="scroll-fade-y forced-colors:scroll-fade-none h-full overflow-y-auto p-px">
                  <Alert>
                    <ShieldAlert />
                    <AlertTitle>歷史會以明文顯示</AlertTitle>
                    <AlertDescription>
                      這些值只存在這台裝置的加密密碼庫；關閉或離開本頁會清除畫面中的明文。
                    </AlertDescription>
                  </Alert>
                  {!historyLoaded && !busy ? (
                    <Button type="button" variant="outline" onClick={() => void loadHistory()}>
                      <History data-icon="inline-start" />
                      顯示歷史
                    </Button>
                  ) : history.length === 0 ? (
                    <FieldDescription>尚無產生紀錄。</FieldDescription>
                  ) : (
                    <ul className="flex flex-col gap-2" aria-label="產生器歷史">
                      {history.map((entry, index) => (
                        <li
                          key={`${entry.generationDate}:${index}`}
                          className="bg-muted flex items-center gap-2 rounded-lg p-2"
                        >
                          <div className="min-w-0 flex-1">
                            <div className="truncate font-mono text-sm">{entry.credential}</div>
                            <div className="text-muted-foreground text-xs">
                              {entry.algorithm
                                ? historyAlgorithmLabels[entry.algorithm]
                                : entry.category}
                              {' · '}
                              {new Date(entry.generationDate).toLocaleString('zh-TW')}
                            </div>
                          </div>
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon-sm"
                            aria-label={
                              copiedKey === copyFeedbackKey(historyLocator(entry, index))
                                ? '這筆歷史已複製'
                                : '複製這筆歷史'
                            }
                            disabled={busy}
                            onClick={() => void copyHistory(historyLocator(entry, index))}
                          >
                            <CopyFeedbackIcon
                              copied={copiedKey === copyFeedbackKey(historyLocator(entry, index))}
                            />
                          </Button>
                        </li>
                      ))}
                    </ul>
                  )}
                  {historyLoaded && history.length > 0 && (
                    <Button
                      type="button"
                      variant="outline"
                      disabled={busy}
                      onClick={() => void clearHistory()}
                    >
                      <Trash2 data-icon="inline-start" />
                      清除歷史
                    </Button>
                  )}
                </FieldGroup>
              </TabsContent>
            </Tabs>
          </div>
          <DialogFooter className="modal-actions mx-0 mb-0">
            <DialogClose render={<Button variant="secondary" type="button" disabled={busy} />}>
              關閉
            </DialogClose>
          </DialogFooter>
        </>
      )}
    </Modal>
  )
}
