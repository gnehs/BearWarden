import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AlertCircle, Globe2, Plus, Search, Trash2 } from 'lucide-react'
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
  equivalentDomainErrorMessage,
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
  const rowId = useRef(0)
  const requestId = useRef(0)
  const [settings, setSettings] = useState<EquivalentDomainSettingsView | null>(null)
  const [rows, setRows] = useState<DomainRow[]>([])
  const [excludedTypes, setExcludedTypes] = useState<Set<number>>(new Set())
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)

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
      try {
        const result: unknown = await window.bearwarden.domainRules.get()
        if (currentRequest !== requestId.current) return
        if (!isEquivalentDomainSettingsView(result)) throw new Error('INVALID_RESPONSE')
        hydrate(result)
        setError(successMessage ?? null)
      } catch (loadError) {
        if (currentRequest === requestId.current) {
          setSettings(null)
          setError(equivalentDomainErrorMessage(loadError))
        }
      } finally {
        if (currentRequest === requestId.current) setLoading(false)
      }
    },
    [hydrate]
  )

  const parsedDraft = useMemo(() => {
    try {
      return { value: parseEquivalentDomainDraft(rows.map(({ value }) => value)), error: null }
    } catch {
      return { value: null, error: '請縮短網域內容，並確認每一列使用逗號或換行分隔。' }
    }
  }, [rows])

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
    const query = search.trim().toLocaleLowerCase()
    if (!query) return settings?.globalEquivalentDomains ?? []
    return (settings?.globalEquivalentDomains ?? []).filter(({ domains }) =>
      domains.some((domain) => domain.toLocaleLowerCase().includes(query))
    )
  }, [search, settings])

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
        await loadSettings(equivalentDomainErrorMessage(saveError))
      } else {
        setError(equivalentDomainErrorMessage(saveError))
      }
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={changeOpen}>
      <DialogTrigger render={<Button variant="outline" size="sm" type="button" />}>
        <Globe2 data-icon="inline-start" aria-hidden="true" />
        等效網域
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
              <DialogTitle>等效網域</DialogTitle>
              <DialogDescription className="mt-1">
                將同一服務的不同網域視為相關，例如 example.com 與 example.net。
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <ScrollArea className="min-h-0 pr-3">
          <div className="flex flex-col gap-5 py-1">
            <Alert>
              <Globe2 aria-hidden="true" />
              <AlertTitle>這是帳號層級設定</AlertTitle>
              <AlertDescription>
                儲存後會整組取代伺服器上的等效網域，並同步到其他 Bitwarden 用戶端。
              </AlertDescription>
            </Alert>

            {error && (
              <Alert variant={error.includes('已重新載入') ? 'default' : 'destructive'}>
                <AlertCircle aria-hidden="true" />
                <AlertTitle>{error.includes('已重新載入') ? '設定已更新' : '無法完成'}</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            {loading ? (
              <div
                className="text-muted-foreground flex min-h-48 items-center justify-center gap-2 text-sm"
                role="status"
              >
                <Spinner /> 正在讀取網域規則…
              </div>
            ) : settings ? (
              <>
                <FieldSet>
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <FieldLegend>自訂等效網域</FieldLegend>
                      <FieldDescription>
                        每一列是一組；使用逗號或換行分隔網域。網址會在主程序轉為可註冊網域。
                      </FieldDescription>
                    </div>
                    <Button variant="outline" size="sm" type="button" onClick={addRow}>
                      <Plus data-icon="inline-start" aria-hidden="true" />
                      新增群組
                    </Button>
                  </div>
                  <FieldGroup className="gap-3">
                    {rows.length === 0 ? (
                      <div className="text-muted-foreground rounded-lg border border-dashed p-4 text-center text-sm">
                        尚未建立自訂群組。
                      </div>
                    ) : (
                      rows.map((row, index) => (
                        <Field key={row.id} data-invalid={Boolean(parsedDraft.error)}>
                          <div className="flex items-center justify-between gap-2">
                            <FieldLabel htmlFor={`equivalent-domain-${row.id}`}>
                              群組 {index + 1}
                            </FieldLabel>
                            <Button
                              variant="ghost"
                              size="icon-sm"
                              type="button"
                              aria-label={`移除群組 ${index + 1}`}
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
                            placeholder="example.com, example.net"
                            onChange={(event) => setRowValue(row.id, event.target.value)}
                          />
                        </Field>
                      ))
                    )}
                    {parsedDraft.error && <FieldError>{parsedDraft.error}</FieldError>}
                    {parsedDraft.value && parsedDraft.value.singleDomainGroupCount > 0 && (
                      <p className="text-muted-foreground text-xs">
                        {parsedDraft.value.singleDomainGroupCount}{' '}
                        組目前只有一個網域；可以儲存，但不會形成跨網域關聯。
                      </p>
                    )}
                  </FieldGroup>
                </FieldSet>

                <FieldSet>
                  <div className="flex flex-wrap items-end justify-between gap-3">
                    <div>
                      <FieldLegend>內建全域規則</FieldLegend>
                      <FieldDescription>
                        Vaultwarden 提供的預設服務群組；關閉後會加入帳號的排除清單。
                      </FieldDescription>
                    </div>
                    <Badge variant="secondary">
                      {settings.globalEquivalentDomains.length - excludedTypes.size} /{' '}
                      {settings.globalEquivalentDomains.length} 已啟用
                    </Badge>
                  </div>
                  <Field>
                    <FieldLabel className="sr-only" htmlFor="global-domain-search">
                      搜尋全域規則
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
                        placeholder="搜尋網域"
                        onChange={(event) => setSearch(event.target.value)}
                      />
                    </div>
                  </Field>
                  <div className="divide-y rounded-lg border">
                    {filteredGlobals.length === 0 ? (
                      <p className="text-muted-foreground p-4 text-center text-sm">
                        找不到符合的規則。
                      </p>
                    ) : (
                      filteredGlobals.map((group) => {
                        const switchId = `global-domain-${group.type}`
                        return (
                          <Field key={group.type} className="p-3" orientation="horizontal">
                            <FieldContent>
                              <FieldLabel htmlFor={switchId}>
                                {group.domains[0] ?? `規則 ${group.type}`}
                              </FieldLabel>
                              <FieldDescription className="break-words">
                                {group.domains.join(', ') || '此規則沒有網域'}
                              </FieldDescription>
                            </FieldContent>
                            <Switch
                              id={switchId}
                              checked={!excludedTypes.has(group.type)}
                              aria-label={`${group.domains[0] ?? `規則 ${group.type}`} 等效網域`}
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
                <p className="text-muted-foreground text-sm">目前無法顯示網域規則。</p>
                <Button
                  variant="outline"
                  size="sm"
                  type="button"
                  onClick={() => void loadSettings()}
                >
                  重新載入
                </Button>
              </div>
            )}
          </div>
        </ScrollArea>

        <DialogFooter>
          <DialogClose render={<Button variant="outline" type="button" disabled={saving} />}>
            取消
          </DialogClose>
          <Button
            type="button"
            disabled={loading || saving || !changed || Boolean(parsedDraft.error)}
            onClick={() => void save()}
          >
            {saving && <Spinner data-icon="inline-start" />}
            儲存網域規則
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export default EquivalentDomainsDialog
