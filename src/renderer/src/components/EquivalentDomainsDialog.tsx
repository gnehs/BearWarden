import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AlertCircle, Globe2, Plus, Search, Trash2 } from 'lucide-react'
import { Trans, useLingui } from '@lingui/react/macro'
import type { EquivalentDomainSettingsView } from '../../../shared/vault-contract'
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import { Badge } from '@renderer/components/ui/badge'
import { Button } from '@renderer/components/ui/button'
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger
} from '@renderer/components/ui/dialog'
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSet
} from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import { ScrollArea } from '@renderer/components/ui/scroll-area'
import { Spinner } from '@renderer/components/ui/spinner'
import { Switch } from '@renderer/components/ui/switch'
import { Textarea } from '@renderer/components/ui/textarea'
import {
  equivalentDomainRows,
  isEquivalentDomainSettingsView,
  parseEquivalentDomainDraft
} from '@renderer/lib/equivalent-domains-ui'

interface DomainRow {
  id: number
  value: string
}

function sameNumbers(left: readonly number[], right: readonly number[]): boolean {
  if (left.length !== right.length) return false
  return left.every((value, index) => value === right[index])
}

function EquivalentDomainsDialog(): React.JSX.Element {
  const { i18n, t } = useLingui()
  const rowId = useRef(0)
  const requestId = useRef(0)
  const [settings, setSettings] = useState<EquivalentDomainSettingsView | null>(null)
  const [rows, setRows] = useState<DomainRow[]>([])
  const [excludedTypes, setExcludedTypes] = useState<Set<number>>(new Set())
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showUpdateMessage, setShowUpdateMessage] = useState(false)
  const [open, setOpen] = useState(false)

  const errorMessage = useCallback(
    (loadError: unknown): string => {
      if (!(loadError instanceof Error))
        return t`Unable to read equivalent domain settings. Try again later.`
      if (loadError.message.includes('SYNC_CONFLICT')) {
        return t`Settings changed on another device. The server version has been reloaded; review it before saving.`
      }
      if (loadError.message.includes('SYNC_AUTH_REQUIRED')) {
        return t`Your Bitwarden account needs to sign in again or unlock.`
      }
      if (loadError.message.includes('LOCKED'))
        return t`The vault is locked. Unlock it and try again.`
      if (loadError.message.includes('INVALID_INPUT')) {
        return t`Check the domain format. Use commas or line breaks to separate each row.`
      }
      return t`Unable to save equivalent domain settings. Check your connection and try again.`
    },
    [t]
  )

  useEffect(
    () => () => {
      requestId.current += 1
    },
    []
  )

  const hydrate = useCallback((next: EquivalentDomainSettingsView): void => {
    setSettings(next)
    setRows(
      equivalentDomainRows(next).map((value) => ({
        id: ++rowId.current,
        value
      }))
    )
    setExcludedTypes(
      new Set(
        next.globalEquivalentDomains.filter(({ excluded }) => excluded).map(({ type }) => type)
      )
    )
  }, [])

  const loadSettings = useCallback(
    async (successMessage?: string): Promise<void> => {
      const currentRequest = ++requestId.current
      setLoading(true)
      setError(null)
      setShowUpdateMessage(false)
      try {
        const result: unknown = await window.bearwarden.domainRules.get()
        if (currentRequest !== requestId.current) return
        if (!isEquivalentDomainSettingsView(result)) throw new Error('INVALID_RESPONSE')
        hydrate(result)
        setError(successMessage ?? null)
      } catch (loadError) {
        if (currentRequest === requestId.current) {
          setSettings(null)
          setError(errorMessage(loadError))
        }
      } finally {
        if (currentRequest === requestId.current) setLoading(false)
      }
    },
    [errorMessage, hydrate]
  )

  const parsedDraft = useMemo(() => {
    try {
      return { value: parseEquivalentDomainDraft(rows.map(({ value }) => value)), error: null }
    } catch {
      return {
        value: null,
        error: t`Shorten the domain content and use commas or line breaks to separate each row.`
      }
    }
  }, [rows, t])

  const excludedTypeList = useMemo(
    () => [...excludedTypes].sort((left, right) => left - right),
    [excludedTypes]
  )
  const initialExcludedTypeList = useMemo(
    () =>
      (settings?.globalEquivalentDomains ?? [])
        .filter(({ excluded }) => excluded)
        .map(({ type }) => type)
        .sort((left, right) => left - right),
    [settings]
  )
  const changed = useMemo(() => {
    if (!settings || !parsedDraft.value) return false
    return (
      JSON.stringify(parsedDraft.value.groups) !== JSON.stringify(settings.equivalentDomains) ||
      !sameNumbers(excludedTypeList, initialExcludedTypeList)
    )
  }, [excludedTypeList, initialExcludedTypeList, parsedDraft.value, settings])

  const filteredGlobals = useMemo(() => {
    const query = search.trim().toLocaleLowerCase(i18n.locale)
    if (!query) return settings?.globalEquivalentDomains ?? []
    return (settings?.globalEquivalentDomains ?? []).filter(({ domains }) =>
      domains.some((domain) => domain.toLocaleLowerCase(i18n.locale).includes(query))
    )
  }, [i18n.locale, search, settings])

  function setRowValue(id: number, value: string): void {
    setRows((current) => current.map((row) => (row.id === id ? { ...row, value } : row)))
  }

  function removeRow(id: number): void {
    setRows((current) => current.filter((row) => row.id !== id))
  }

  function addRow(): void {
    setRows((current) => [...current, { id: ++rowId.current, value: '' }])
  }

  function toggleGlobal(type: number, included: boolean): void {
    setExcludedTypes((current) => {
      const next = new Set(current)
      if (included) next.delete(type)
      else next.add(type)
      return next
    })
  }

  function changeOpen(nextOpen: boolean): void {
    if (saving) return
    setOpen(nextOpen)
    if (nextOpen) {
      void loadSettings()
      return
    }
    if (!nextOpen) {
      requestId.current += 1
      setSearch('')
      setError(null)
      setShowUpdateMessage(false)
    }
  }

  async function save(): Promise<void> {
    if (!settings || !parsedDraft.value || !changed || saving) return
    setSaving(true)
    setError(null)
    try {
      const result: unknown = await window.bearwarden.domainRules.update({
        equivalentDomains: parsedDraft.value.groups,
        excludedGlobalEquivalentDomains: excludedTypeList,
        expectedRevision: settings.revision
      })
      if (!isEquivalentDomainSettingsView(result)) throw new Error('INVALID_RESPONSE')
      hydrate(result)
      requestId.current += 1
      setSearch('')
      setError(null)
      setOpen(false)
    } catch (saveError) {
      if (saveError instanceof Error && saveError.message.includes('SYNC_CONFLICT')) {
        await loadSettings(errorMessage(saveError))
        setShowUpdateMessage(true)
      } else {
        setError(errorMessage(saveError))
      }
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={changeOpen}>
      <DialogTrigger render={<Button variant="outline" size="sm" type="button" />}>
        <Globe2 data-icon="inline-start" aria-hidden="true" />
        <Trans>Equivalent domains</Trans>
      </DialogTrigger>
      <DialogContent
        className="max-h-[min(88vh,760px)] grid-rows-[auto_minmax(0,1fr)_auto] sm:max-w-2xl"
        showCloseButton={false}
      >
        <DialogHeader>
          <div className="flex items-start gap-3">
            <span
              className="bg-primary/10 text-primary grid size-9 shrink-0 place-items-center rounded-lg"
              aria-hidden="true"
            >
              <Globe2 className="size-4" />
            </span>
            <div className="min-w-0">
              <DialogTitle>
                <Trans>Equivalent domains</Trans>
              </DialogTitle>
              <DialogDescription className="mt-1">
                <Trans>
                  Treat different domains for the same service as related, such as example.com and
                  example.net.
                </Trans>
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <ScrollArea className="min-h-0 pr-3">
          <div className="flex flex-col gap-5 py-1">
            <Alert>
              <Globe2 aria-hidden="true" />
              <AlertTitle>
                <Trans>This is an account-level setting</Trans>
              </AlertTitle>
              <AlertDescription>
                <Trans>
                  Saving replaces all equivalent domains on the server and syncs them to other
                  Bitwarden clients.
                </Trans>
              </AlertDescription>
            </Alert>

            {error && (
              <Alert variant={showUpdateMessage ? 'default' : 'destructive'}>
                <AlertCircle aria-hidden="true" />
                <AlertTitle>
                  {showUpdateMessage ? (
                    <Trans>Settings updated</Trans>
                  ) : (
                    <Trans>Unable to complete</Trans>
                  )}
                </AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            {loading ? (
              <div
                className="text-muted-foreground flex min-h-48 items-center justify-center gap-2 text-sm"
                role="status"
              >
                <Spinner /> <Trans>Loading domain rules…</Trans>
              </div>
            ) : settings ? (
              <>
                <FieldSet>
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <FieldLegend>
                        <Trans>Custom equivalent domains</Trans>
                      </FieldLegend>
                      <FieldDescription>
                        <Trans>
                          Each row is a group. Use commas or line breaks to separate domains. URLs
                          are converted to registrable domains in the main process.
                        </Trans>
                      </FieldDescription>
                    </div>
                    <Button variant="outline" size="sm" type="button" onClick={addRow}>
                      <Plus data-icon="inline-start" aria-hidden="true" />
                      <Trans>Add group</Trans>
                    </Button>
                  </div>
                  <FieldGroup className="gap-3">
                    {rows.length === 0 ? (
                      <div className="text-muted-foreground rounded-lg border border-dashed p-4 text-center text-sm">
                        <Trans>No custom groups yet.</Trans>
                      </div>
                    ) : (
                      rows.map((row, index) => (
                        <Field key={row.id} data-invalid={Boolean(parsedDraft.error)}>
                          <div className="flex items-center justify-between gap-2">
                            <FieldLabel htmlFor={`equivalent-domain-${row.id}`}>
                              {t`Group ${index + 1}`}
                            </FieldLabel>
                            <Button
                              variant="ghost"
                              size="icon-sm"
                              type="button"
                              aria-label={t`Remove group ${index + 1}`}
                              onClick={() => removeRow(row.id)}
                            >
                              <Trash2 aria-hidden="true" />
                            </Button>
                          </div>
                          <Textarea
                            id={`equivalent-domain-${row.id}`}
                            value={row.value}
                            rows={2}
                            aria-invalid={Boolean(parsedDraft.error)}
                            placeholder={t`example.com, example.net`}
                            onChange={(event) => setRowValue(row.id, event.target.value)}
                          />
                        </Field>
                      ))
                    )}
                    {parsedDraft.error && <FieldError>{parsedDraft.error}</FieldError>}
                    {parsedDraft.value && parsedDraft.value.singleDomainGroupCount > 0 && (
                      <p className="text-muted-foreground text-xs">
                        {t`${parsedDraft.value.singleDomainGroupCount} groups currently have only one domain. You can save them, but they will not create cross-domain associations.`}
                      </p>
                    )}
                  </FieldGroup>
                </FieldSet>

                <FieldSet>
                  <div className="flex flex-wrap items-end justify-between gap-3">
                    <div>
                      <FieldLegend>
                        <Trans>Built-in global rules</Trans>
                      </FieldLegend>
                      <FieldDescription>
                        <Trans>
                          Default service groups provided by Vaultwarden. Turning one off adds it to
                          this account’s exclusion list.
                        </Trans>
                      </FieldDescription>
                    </div>
                    <Badge variant="secondary">
                      {t`${settings.globalEquivalentDomains.length - excludedTypes.size} / ${settings.globalEquivalentDomains.length} enabled`}
                    </Badge>
                  </div>
                  <Field>
                    <FieldLabel className="sr-only" htmlFor="global-domain-search">
                      <Trans>Search global rules</Trans>
                    </FieldLabel>
                    <div className="relative">
                      <Search
                        className="text-muted-foreground pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2"
                        aria-hidden="true"
                      />
                      <Input
                        id="global-domain-search"
                        className="pl-8"
                        type="search"
                        value={search}
                        placeholder={t`Search domains`}
                        onChange={(event) => setSearch(event.target.value)}
                      />
                    </div>
                  </Field>
                  <div className="divide-y rounded-lg border">
                    {filteredGlobals.length === 0 ? (
                      <p className="text-muted-foreground p-4 text-center text-sm">
                        <Trans>No matching rules found.</Trans>
                      </p>
                    ) : (
                      filteredGlobals.map((group) => {
                        const switchId = `global-domain-${group.type}`
                        const groupName = group.domains[0] ?? t`Rule ${group.type}`
                        return (
                          <Field key={group.type} className="p-3" orientation="horizontal">
                            <FieldContent>
                              <FieldLabel htmlFor={switchId}>{groupName}</FieldLabel>
                              <FieldDescription className="break-words">
                                {group.domains.join(', ') || t`This rule has no domains`}
                              </FieldDescription>
                            </FieldContent>
                            <Switch
                              id={switchId}
                              checked={!excludedTypes.has(group.type)}
                              aria-label={t`${groupName} equivalent domains`}
                              onCheckedChange={(checked) => toggleGlobal(group.type, checked)}
                            />
                          </Field>
                        )
                      })
                    )}
                  </div>
                </FieldSet>
              </>
            ) : (
              <div className="flex min-h-48 flex-col items-center justify-center gap-3 text-center">
                <p className="text-muted-foreground text-sm">
                  <Trans>Domain rules cannot be displayed right now.</Trans>
                </p>
                <Button
                  variant="outline"
                  size="sm"
                  type="button"
                  onClick={() => void loadSettings()}
                >
                  <Trans>Reload</Trans>
                </Button>
              </div>
            )}
          </div>
        </ScrollArea>

        <DialogFooter>
          <DialogClose render={<Button variant="outline" type="button" disabled={saving} />}>
            <Trans>Cancel</Trans>
          </DialogClose>
          <Button
            type="button"
            disabled={loading || saving || !changed || Boolean(parsedDraft.error)}
            onClick={() => void save()}
          >
            {saving && <Spinner data-icon="inline-start" />}
            <Trans>Save domain rules</Trans>
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export default EquivalentDomainsDialog
