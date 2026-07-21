import { useEffect, useMemo, useRef, useState } from 'react'
import { History, RefreshCw, ShieldAlert, Trash2 } from 'lucide-react'
import { Trans, useLingui } from '@lingui/react/macro'
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
import { DialogClose } from '@renderer/components/ui/dialog'
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
import { ModalBody, ModalFooter } from './ModalLayout'
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
  const { i18n, t } = useLingui()
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
  const historyAlgorithmLabels: Record<NonNullable<GeneratorHistoryEntry['algorithm']>, string> = {
    password: t`Password`,
    passphrase: t`Passphrase`,
    username: t`Random word`,
    subaddress: t`Plus Address`,
    catchall: t`Catch-all`
  }
  const historyCategoryLabels: Record<GeneratorCredentialCategory, string> = {
    password: t`Password`,
    username: t`Username`,
    email: t`Email`
  }

  const generateLabel =
    tab === 'password'
      ? passwordAlgorithm === 'password'
        ? t`Password`
        : t`Passphrase`
      : usernameAlgorithm === 'username'
        ? t`Username`
        : t`Email`

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
            setError(
              t`The settings cannot generate a valid value. Check the length, minimum characters, and email or domain.`
            )
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
  }, [clearCopied, generatorRequest, onGenerate, t, tab])

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
        setError(t`Unable to read generator history.`)
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
      setError(
        t`The settings cannot generate a valid value. Check the length, minimum characters, and email or domain.`
      )
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
        setError(
          t`The settings cannot generate a valid value. Check the length, minimum characters, and email or domain.`
        )
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
        setError(t`Unable to copy the generated result. Generate it again and try once more.`)
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
        setError(t`Unable to copy. This history entry may have changed.`)
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
        setError(t`Unable to clear generator history.`)
      }
    } finally {
      if (mountedRef.current && requestGenerationRef.current === generation) setBusy(false)
    }
  }

  return (
    <Modal
      title={t`Generator`}
      busy={busy}
      onClose={() => {
        invalidatePlaintext()
        onClose()
      }}
    >
      {() => (
        <>
          <ModalBody className="h-[min(65vh,calc(100vh-11rem))] overflow-hidden">
            <Tabs
              className="min-h-0 overflow-hidden p-px"
              value={tab}
              onValueChange={(value) => changeTab(value as GeneratorTab)}
            >
              <TabsList sliding className="w-full shrink-0">
                <TabsTrigger value="password">
                  <Trans>Password</Trans>
                </TabsTrigger>
                <TabsTrigger value="username">
                  <Trans>Username</Trans>
                </TabsTrigger>
                <TabsTrigger value="history">
                  <Trans comment="Tab showing previously generated credentials stored in the local generator history.">
                    History
                  </Trans>
                </TabsTrigger>
              </TabsList>

              {tab !== 'history' && (
                <div className="flex shrink-0 flex-col gap-3">
                  <InputGroup>
                    <InputGroupInput
                      id="generator-result"
                      className="font-mono"
                      value={result?.credential ?? ''}
                      placeholder={busy ? t`Generating securely…` : t`The result will appear here`}
                      readOnly
                      autoComplete="off"
                      aria-label={t`Generated result`}
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
                        aria-label={
                          result ? t`Regenerate ${generateLabel}` : t`Generate ${generateLabel}`
                        }
                        onClick={() => void generate()}
                      >
                        {busy ? <Spinner /> : <RefreshCw />}
                      </InputGroupButton>
                      <InputGroupButton
                        size="xs"
                        disabled={busy || !result}
                        aria-label={
                          copiedKey === generatedCopyFeedbackKey
                            ? t`Generated result copied`
                            : t`Copy generated result`
                        }
                        onClick={() => {
                          if (result) void copyGenerated(result.copyToken)
                        }}
                      >
                        <CopyFeedbackIcon
                          copied={copiedKey === generatedCopyFeedbackKey}
                          placement="inline-start"
                        />
                        {copiedKey === generatedCopyFeedbackKey ? (
                          <Trans>Copied</Trans>
                        ) : (
                          <Trans>Copy</Trans>
                        )}
                      </InputGroupButton>
                    </InputGroupAddon>
                  </InputGroup>
                  <div className="sr-only" role="status" aria-live="polite">
                    {result && copiedKey === generatedCopyFeedbackKey
                      ? t`Generated result copied`
                      : result
                        ? t`New result generated`
                        : busy
                          ? t`Generating`
                          : ''}
                  </div>
                  {canUseResult && result && onUseCredential && (
                    <div className="flex justify-end">
                      <Button type="button" disabled={busy} onClick={() => onUseCredential(result)}>
                        <Trans>Use this value</Trans>
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
                    <FieldLegend variant="label">
                      <Trans
                        context="credential-generator-type"
                        comment="Fieldset label for choosing the password or username generation algorithm or format."
                      >
                        Type
                      </Trans>
                    </FieldLegend>
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
                        <Trans>Password</Trans>
                      </ToggleGroupItem>
                      <ToggleGroupItem value="passphrase" className="flex-1">
                        <Trans>Passphrase</Trans>
                      </ToggleGroupItem>
                    </ToggleGroup>
                  </FieldSet>

                  {passwordAlgorithm === 'password' ? (
                    <>
                      <NumberField
                        id="generator-length"
                        label={t`Length`}
                        value={length}
                        min={5}
                        max={128}
                        disabled={busy}
                        onChange={(value) => changeSetting(setLength, value)}
                      />
                      <FieldSet>
                        <FieldLegend variant="label">
                          <Trans>Character types</Trans>
                        </FieldLegend>
                        <FieldGroup data-slot="checkbox-group">
                          <CheckboxField
                            id="generator-upper"
                            title={t`Uppercase letters`}
                            checked={uppercase}
                            disabled={busy}
                            onCheckedChange={(value) => changeSetting(setUppercase, value)}
                          />
                          <CheckboxField
                            id="generator-lower"
                            title={t`Lowercase letters`}
                            checked={lowercase}
                            disabled={busy}
                            onCheckedChange={(value) => changeSetting(setLowercase, value)}
                          />
                          <CheckboxField
                            id="generator-number"
                            title={t`Numbers`}
                            checked={numbers}
                            disabled={busy}
                            onCheckedChange={(value) => changeSetting(setNumbers, value)}
                          />
                          <CheckboxField
                            id="generator-special"
                            title={t`Special characters !@#$%^&*`}
                            checked={special}
                            disabled={busy}
                            onCheckedChange={(value) => changeSetting(setSpecial, value)}
                          />
                          <CheckboxField
                            id="generator-ambiguous"
                            title={t`Avoid ambiguous characters`}
                            description={t`Excludes 0, O, 1, l, and I`}
                            checked={avoidAmbiguous}
                            disabled={busy}
                            onCheckedChange={(value) => changeSetting(setAvoidAmbiguous, value)}
                          />
                        </FieldGroup>
                      </FieldSet>
                      <div className="grid grid-cols-2 gap-3">
                        <NumberField
                          id="generator-min-upper"
                          label={t`Minimum uppercase`}
                          value={minUppercase}
                          min={0}
                          max={128}
                          disabled={busy || !uppercase}
                          onChange={(value) => changeSetting(setMinUppercase, value)}
                        />
                        <NumberField
                          id="generator-min-lower"
                          label={t`Minimum lowercase`}
                          value={minLowercase}
                          min={0}
                          max={128}
                          disabled={busy || !lowercase}
                          onChange={(value) => changeSetting(setMinLowercase, value)}
                        />
                        <NumberField
                          id="generator-min-number"
                          label={t`Minimum numbers`}
                          value={minNumber}
                          min={0}
                          max={9}
                          disabled={busy || !numbers}
                          onChange={(value) => changeSetting(setMinNumber, value)}
                        />
                        <NumberField
                          id="generator-min-special"
                          label={t`Minimum special characters`}
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
                        label={t`Word count`}
                        value={wordCount}
                        min={3}
                        max={20}
                        disabled={busy}
                        onChange={(value) => changeSetting(setWordCount, value)}
                      />
                      <Field>
                        <FieldLabel htmlFor="generator-separator">
                          <Trans>Separator</Trans>
                        </FieldLabel>
                        <Input
                          id="generator-separator"
                          value={separator}
                          maxLength={1}
                          disabled={busy}
                          onChange={(event) => changeSetting(setSeparator, event.target.value)}
                        />
                        <FieldDescription>
                          <Trans>
                            Bitwarden-compatible settings allow only one UTF-16 character.
                          </Trans>
                        </FieldDescription>
                      </Field>
                      <FieldSet>
                        <FieldLegend variant="label">
                          <Trans>Format</Trans>
                        </FieldLegend>
                        <FieldGroup data-slot="checkbox-group">
                          <CheckboxField
                            id="generator-capitalize"
                            title={t`Capitalize each word`}
                            checked={capitalize}
                            disabled={busy}
                            onCheckedChange={(value) => changeSetting(setCapitalize, value)}
                          />
                          <CheckboxField
                            id="generator-include-number"
                            title={t`Include one number`}
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
                    <FieldLegend variant="label">
                      <Trans
                        context="credential-generator-type"
                        comment="Fieldset label for choosing the password or username generation algorithm or format."
                      >
                        Type
                      </Trans>
                    </FieldLegend>
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
                        <Trans>Words</Trans>
                      </ToggleGroupItem>
                      <ToggleGroupItem value="subaddress" className="flex-1">
                        <Trans>Plus</Trans>
                      </ToggleGroupItem>
                      <ToggleGroupItem value="catchall" className="flex-1">
                        <Trans>Catch-all</Trans>
                      </ToggleGroupItem>
                    </ToggleGroup>
                  </FieldSet>
                  {usernameAlgorithm === 'username' ? (
                    <FieldSet>
                      <FieldLegend variant="label">
                        <Trans>Format</Trans>
                      </FieldLegend>
                      <FieldGroup data-slot="checkbox-group">
                        <CheckboxField
                          id="generator-username-capitalize"
                          title={t`Capitalize`}
                          checked={usernameCapitalize}
                          disabled={busy}
                          onCheckedChange={(value) => changeSetting(setUsernameCapitalize, value)}
                        />
                        <CheckboxField
                          id="generator-username-number"
                          title={t`Include four digits`}
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
                      <FieldLabel htmlFor="generator-email">
                        <Trans>Email</Trans>
                      </FieldLabel>
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
                        <Trans>For example, name@example.com. Used only for this generation.</Trans>
                      </FieldDescription>
                    </Field>
                  ) : (
                    <Field data-invalid={Boolean(error) || undefined}>
                      <FieldLabel htmlFor="generator-domain">
                        <Trans>Catch-all domain</Trans>
                      </FieldLabel>
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
                        <Trans>
                          For example, example.com. No connection is made to a third-party
                          forwarding service.
                        </Trans>
                      </FieldDescription>
                    </Field>
                  )}
                  <Alert>
                    <ShieldAlert />
                    <AlertTitle>
                      <Trans>Local generator</Trans>
                    </AlertTitle>
                    <AlertDescription>
                      <Trans>
                        Third-party email forwarding integrations that require API credentials are
                        not available.
                      </Trans>
                    </AlertDescription>
                  </Alert>
                </FieldGroup>
              </TabsContent>

              <TabsContent value="history" className="min-h-0 overflow-hidden">
                <FieldGroup className="scroll-fade-y forced-colors:scroll-fade-none h-full overflow-y-auto p-px">
                  <Alert>
                    <ShieldAlert />
                    <AlertTitle>
                      <Trans>History is shown in plaintext</Trans>
                    </AlertTitle>
                    <AlertDescription>
                      <Trans>
                        These values exist only in this device’s encrypted vault. Closing or leaving
                        this page clears plaintext from the screen.
                      </Trans>
                    </AlertDescription>
                  </Alert>
                  {!historyLoaded && !busy ? (
                    <Button type="button" variant="outline" onClick={() => void loadHistory()}>
                      <History data-icon="inline-start" />
                      <Trans>Show history</Trans>
                    </Button>
                  ) : history.length === 0 ? (
                    <FieldDescription>
                      <Trans>No generated entries yet.</Trans>
                    </FieldDescription>
                  ) : (
                    <ul className="flex flex-col gap-2" aria-label={t`Generator history`}>
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
                                : historyCategoryLabels[entry.category]}
                              {' · '}
                              {new Date(entry.generationDate).toLocaleString(i18n.locale)}
                            </div>
                          </div>
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon-sm"
                            aria-label={
                              copiedKey === copyFeedbackKey(historyLocator(entry, index))
                                ? t`This history entry is copied`
                                : t`Copy this history entry`
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
                      <Trans>Clear history</Trans>
                    </Button>
                  )}
                </FieldGroup>
              </TabsContent>
            </Tabs>
          </ModalBody>
          <ModalFooter>
            <DialogClose render={<Button variant="secondary" type="button" disabled={busy} />}>
              <Trans>Close</Trans>
            </DialogClose>
          </ModalFooter>
        </>
      )}
    </Modal>
  )
}
