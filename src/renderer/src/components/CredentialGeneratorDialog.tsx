import { useEffect, useRef, useState } from 'react'
import { Clipboard, History, ShieldAlert, Sparkles, Trash2 } from 'lucide-react'
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
  FieldError,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSet,
  FieldTitle
} from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import { Spinner } from '@renderer/components/ui/spinner'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@renderer/components/ui/tabs'
import { ToggleGroup, ToggleGroupItem } from '@renderer/components/ui/toggle-group'
import { Modal } from './Dialogs'

type GeneratorTab = 'password' | 'username' | 'history'
type PasswordAlgorithm = 'password' | 'passphrase'
type UsernameAlgorithm = 'username' | 'subaddress' | 'catchall'

interface CredentialGeneratorDialogProps {
  initialTab?: Exclude<GeneratorTab, 'history'>
  onClose: () => void
  onGenerate: (request: CredentialGeneratorRequest) => Promise<CredentialGeneratorResult>
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

function historyLocator(entry: GeneratorHistoryEntry, index: number): GeneratorHistoryLocator {
  return {
    index,
    generationDate: entry.generationDate,
    category: entry.category,
    ...(entry.algorithm === undefined ? {} : { algorithm: entry.algorithm })
  }
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
  const [busy, setBusy] = useState(false)
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

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
      requestGenerationRef.current += 1
    }
  }, [])

  function invalidatePlaintext(): void {
    requestGenerationRef.current += 1
    setResult(null)
    setHistory([])
    setHistoryLoaded(false)
    setEmail('')
    setDomain('')
    setError('')
    setBusy(false)
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
    if (nextTab === 'history') void loadHistory()
  }

  async function generate(): Promise<void> {
    const generation = ++requestGenerationRef.current
    let request: CredentialGeneratorRequest
    if (tab === 'password') {
      request =
        passwordAlgorithm === 'password'
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
    } else if (usernameAlgorithm === 'username') {
      request = {
        algorithm: 'username',
        options: { capitalize: usernameCapitalize, includeNumber: usernameIncludeNumber }
      }
    } else if (usernameAlgorithm === 'subaddress') {
      request = { algorithm: 'subaddress', email }
    } else {
      request = { algorithm: 'catchall', domain }
    }

    setBusy(true)
    setError('')
    setResult(null)
    try {
      const generated = await onGenerate(request)
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

  async function copy(locator: GeneratorHistoryLocator): Promise<void> {
    const generation = ++requestGenerationRef.current
    setBusy(true)
    setError('')
    try {
      await onCopyHistory(locator)
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
      description="在本機安全產生密碼、密語與使用者名稱。產生的值會加入這台裝置的加密歷史。"
      busy={busy}
      onClose={() => {
        invalidatePlaintext()
        onClose()
      }}
    >
      {() => (
        <>
          <div className="modal-body max-h-[65vh] overflow-y-auto">
            <Tabs value={tab} onValueChange={(value) => changeTab(value as GeneratorTab)}>
              <TabsList className="w-full">
                <TabsTrigger value="password">密碼</TabsTrigger>
                <TabsTrigger value="username">使用者名稱</TabsTrigger>
                <TabsTrigger value="history">歷史</TabsTrigger>
              </TabsList>

              <TabsContent value="password">
                <FieldGroup>
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
                          setPasswordAlgorithm(value)
                          setResult(null)
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
                        onChange={setLength}
                      />
                      <FieldSet>
                        <FieldLegend variant="label">字元類型</FieldLegend>
                        <FieldGroup data-slot="checkbox-group">
                          <CheckboxField
                            id="generator-upper"
                            title="大寫字母"
                            checked={uppercase}
                            disabled={busy}
                            onCheckedChange={setUppercase}
                          />
                          <CheckboxField
                            id="generator-lower"
                            title="小寫字母"
                            checked={lowercase}
                            disabled={busy}
                            onCheckedChange={setLowercase}
                          />
                          <CheckboxField
                            id="generator-number"
                            title="數字"
                            checked={numbers}
                            disabled={busy}
                            onCheckedChange={setNumbers}
                          />
                          <CheckboxField
                            id="generator-special"
                            title="特殊字元 !@#$%^&*"
                            checked={special}
                            disabled={busy}
                            onCheckedChange={setSpecial}
                          />
                          <CheckboxField
                            id="generator-ambiguous"
                            title="避免易混淆字元"
                            description="排除 0、O、1、l、I"
                            checked={avoidAmbiguous}
                            disabled={busy}
                            onCheckedChange={setAvoidAmbiguous}
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
                          onChange={setMinUppercase}
                        />
                        <NumberField
                          id="generator-min-lower"
                          label="最少小寫"
                          value={minLowercase}
                          min={0}
                          max={128}
                          disabled={busy || !lowercase}
                          onChange={setMinLowercase}
                        />
                        <NumberField
                          id="generator-min-number"
                          label="最少數字"
                          value={minNumber}
                          min={0}
                          max={9}
                          disabled={busy || !numbers}
                          onChange={setMinNumber}
                        />
                        <NumberField
                          id="generator-min-special"
                          label="最少特殊字元"
                          value={minSpecial}
                          min={0}
                          max={9}
                          disabled={busy || !special}
                          onChange={setMinSpecial}
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
                        onChange={setWordCount}
                      />
                      <Field>
                        <FieldLabel htmlFor="generator-separator">分隔字元</FieldLabel>
                        <Input
                          id="generator-separator"
                          value={separator}
                          maxLength={1}
                          disabled={busy}
                          onChange={(event) => setSeparator(event.target.value)}
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
                            onCheckedChange={setCapitalize}
                          />
                          <CheckboxField
                            id="generator-include-number"
                            title="加入一個數字"
                            checked={includeNumber}
                            disabled={busy}
                            onCheckedChange={setIncludeNumber}
                          />
                        </FieldGroup>
                      </FieldSet>
                    </>
                  )}
                </FieldGroup>
              </TabsContent>

              <TabsContent value="username">
                <FieldGroup>
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
                          setUsernameAlgorithm(value)
                          setResult(null)
                          setEmail('')
                          setDomain('')
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
                          onCheckedChange={setUsernameCapitalize}
                        />
                        <CheckboxField
                          id="generator-username-number"
                          title="加入四位數字"
                          checked={usernameIncludeNumber}
                          disabled={busy}
                          onCheckedChange={setUsernameIncludeNumber}
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
                        onChange={(event) => setEmail(event.target.value)}
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
                        onChange={(event) => setDomain(event.target.value)}
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

              <TabsContent value="history">
                <FieldGroup>
                  <Alert>
                    <ShieldAlert />
                    <AlertTitle>歷史會以明文顯示</AlertTitle>
                    <AlertDescription>
                      這些值只存在這台裝置的加密保管庫；關閉或離開本頁會清除畫面中的明文。
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
                            aria-label="複製這筆歷史"
                            disabled={busy}
                            onClick={() => void copy(historyLocator(entry, index))}
                          >
                            <Clipboard />
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

            {result && tab !== 'history' && (
              <Field>
                <FieldLabel htmlFor="generator-result">產生結果</FieldLabel>
                <Input
                  id="generator-result"
                  className="font-mono"
                  value={result.credential}
                  readOnly
                  autoComplete="off"
                />
                <div className="flex flex-wrap gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    disabled={busy}
                    onClick={() => void copy(result.historyLocator)}
                  >
                    <Clipboard data-icon="inline-start" />
                    複製
                  </Button>
                  {onUseCredential &&
                    (!useCategories || useCategories.includes(result.category)) && (
                      <Button type="button" disabled={busy} onClick={() => onUseCredential(result)}>
                        使用這個值
                      </Button>
                    )}
                </div>
              </Field>
            )}

            {error && <FieldError>{error}</FieldError>}
          </div>
          <DialogFooter className="modal-actions mx-0 mb-0">
            <DialogClose render={<Button variant="secondary" type="button" disabled={busy} />}>
              關閉
            </DialogClose>
            {tab !== 'history' && (
              <Button type="button" disabled={busy} onClick={() => void generate()}>
                {busy ? (
                  <Spinner data-icon="inline-start" />
                ) : (
                  <Sparkles data-icon="inline-start" />
                )}
                產生
              </Button>
            )}
          </DialogFooter>
        </>
      )}
    </Modal>
  )
}
