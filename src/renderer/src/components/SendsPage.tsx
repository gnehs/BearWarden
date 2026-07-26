import {
  AlertTriangle,
  Download,
  FilePlus,
  FileText,
  Pencil,
  Plus,
  RefreshCw,
  Save,
  Trash2
} from 'lucide-react'
import { plural } from '@lingui/core/macro'
import { Trans, useLingui } from '@lingui/react/macro'
import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { useCopyFeedback } from '@renderer/hooks/use-copy-feedback'
import type { SendCreateRequest, SendView } from '../../../shared/vault-contract'
import { Badge } from '@renderer/components/ui/badge'
import { Button } from '@renderer/components/ui/button'
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
  EmptyTitle
} from '@renderer/components/ui/empty'
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel
} from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import { Spinner } from '@renderer/components/ui/spinner'
import { Switch } from '@renderer/components/ui/switch'
import { Textarea } from '@renderer/components/ui/textarea'
import { Alert, AlertAction, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle
} from '@renderer/components/ui/alert-dialog'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from '@renderer/components/ui/dialog'
import AuxiliaryPageLayout, { AuxiliaryPageContent } from './AuxiliaryPageLayout'
import { CopyFeedbackIcon } from './CopyFeedbackIcon'
import FeatureUnderConstructionNotice from './FeatureUnderConstructionNotice'
import {
  dateTimeLocalToIso,
  dateTimeLocalValue,
  sendStatuses,
  type SendStatus,
  usesEmailVerification
} from './send-ui'

const emptyDraft: SendCreateRequest = {
  name: '',
  notes: null,
  text: '',
  hidden: false,
  password: null,
  maxAccessCount: null,
  expirationDate: null,
  deletionDate: null,
  disabled: false,
  hideEmail: true
}

function draftFromSend(send: SendView, fileSendErrorMessage: string): SendCreateRequest {
  if (send.type !== 'text') {
    throw new Error(fileSendErrorMessage)
  }
  return {
    name: send.name,
    notes: send.notes,
    text: send.text,
    hidden: send.hidden,
    password: undefined,
    maxAccessCount: send.maxAccessCount,
    expirationDate: send.expirationDate,
    deletionDate: send.deletionDate,
    disabled: send.disabled,
    hideEmail: send.hideEmail
  }
}

function isValidMaxAccessCount(value: number | null | undefined): boolean {
  return (
    value === null ||
    value === undefined ||
    (Number.isSafeInteger(value) && value > 0 && value <= 2_147_483_647)
  )
}

function SendStatusBadge({ status }: { status: SendStatus }): React.JSX.Element {
  const { t } = useLingui()
  const label =
    status.key === 'password'
      ? t`Password required`
      : status.key === 'email-verification'
        ? t`Email verification`
        : status.key === 'disabled'
          ? t`Disabled`
          : status.key === 'expired'
            ? t`Expired`
            : status.key === 'max-access-reached'
              ? t`Access limit reached`
              : status.key === 'pending-deletion'
                ? t`Pending deletion`
                : status.key === 'hidden-text'
                  ? t`Hide text by default`
                  : t`Hide sender email`

  return <Badge variant="outline">{label}</Badge>
}

function SendsPage(): React.JSX.Element {
  const { i18n, t } = useLingui()
  const [sends, setSends] = useState<SendView[]>([])
  const { copiedKey, clearCopied, showCopied } = useCopyFeedback()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [draft, setDraft] = useState<SendCreateRequest>(emptyDraft)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [busy, setBusy] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<SendView | null>(null)
  const [sendDialogOpen, setSendDialogOpen] = useState(false)
  const [createMode, setCreateMode] = useState<'text' | 'file'>('text')

  const selected = sends.find((send) => send.id === selectedId) ?? null

  function formatDate(value: string | null): string {
    if (!value) return t`Not set`
    const date = new Date(value)
    if (!Number.isFinite(date.getTime())) return t`Invalid date`
    return new Intl.DateTimeFormat(i18n.locale, {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    }).format(date)
  }

  async function retryLoad(): Promise<void> {
    setLoading(true)
    setLoadError(false)
    try {
      setSends(await window.bearwarden.sends.list())
    } catch {
      setLoadError(true)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    let active = true
    void window.bearwarden.sends.list().then(
      (value) => {
        if (!active) return
        setSends(value)
        setLoading(false)
      },
      () => {
        if (!active) return
        setLoadError(true)
        setLoading(false)
      }
    )
    return () => {
      active = false
    }
  }, [])

  function startCreate(mode: 'text' | 'file' = 'text'): void {
    setSelectedId(null)
    setDraft({ ...emptyDraft })
    setCreateMode(mode)
    setSendDialogOpen(true)
  }

  function startEdit(send: SendView): void {
    if (usesEmailVerification(send)) {
      toast.info(
        t`This Send uses email verification. BearWarden does not yet support OTP, so it cannot be safely edited.`
      )
      return
    }
    if (send.type !== 'text') {
      toast.info(t`File Sends can currently only be viewed and their links copied.`)
      return
    }
    setSelectedId(send.id)
    setCreateMode('text')
    setDraft(
      draftFromSend(send, t`File Sends are read-only until file transfer support is enabled`)
    )
    setSendDialogOpen(true)
  }

  async function save(): Promise<void> {
    if (draft.name.trim().length === 0 || draft.text.length === 0) {
      toast.error(t`Enter a Send name and content.`)
      return
    }
    if (selected?.type === 'file') {
      toast.info(t`Editing file Sends is not available yet.`)
      return
    }
    if (selected && usesEmailVerification(selected)) {
      toast.error(
        t`This Send uses email verification. Editing is disabled because OTP is not yet supported, preserving its security requirements.`
      )
      return
    }
    if (!isValidMaxAccessCount(draft.maxAccessCount)) {
      toast.error(t`Maximum access count must be an integer between 1 and 2,147,483,647.`)
      return
    }
    setBusy(true)
    try {
      const saved = selected
        ? await window.bearwarden.sends.update({ ...draft, id: selected.id })
        : await window.bearwarden.sends.create(draft)
      setSends((current) => [saved, ...current.filter((send) => send.id !== saved.id)])
      setSelectedId(saved.id)
      setDraft(
        draftFromSend(saved, t`File Sends are read-only until file transfer support is enabled`)
      )
      setSendDialogOpen(false)
      toast.success(selected ? t`Send updated` : t`Send created`)
    } catch {
      toast.error(t`Could not save the Send. Confirm that sync is connected.`)
    } finally {
      setBusy(false)
    }
  }

  async function createFile(): Promise<void> {
    const name = draft.name.trim()
    if (name.length === 0) {
      toast.error(t`Enter a Send name first.`)
      return
    }
    if (!isValidMaxAccessCount(draft.maxAccessCount)) {
      toast.error(t`Maximum access count must be an integer between 1 and 2,147,483,647.`)
      return
    }
    setBusy(true)
    try {
      const result = await window.bearwarden.sends.createFile({
        operationId: crypto.randomUUID(),
        name,
        notes: draft.notes,
        maxAccessCount: draft.maxAccessCount,
        expirationDate: draft.expirationDate,
        deletionDate: draft.deletionDate,
        password: draft.password,
        disabled: draft.disabled,
        hideEmail: draft.hideEmail
      })
      if (result.canceled || !result.send) return
      setSends((current) => [
        result.send!,
        ...current.filter((send) => send.id !== result.send!.id)
      ])
      setSelectedId(null)
      setSendDialogOpen(false)
      toast.success(t`File Send created`)
    } catch {
      toast.error(t`Could not create the file Send. Confirm that sync is connected.`)
    } finally {
      setBusy(false)
    }
  }

  async function remove(send: SendView): Promise<void> {
    setBusy(true)
    try {
      await window.bearwarden.sends.delete({ id: send.id })
      setSends((current) => current.filter((entry) => entry.id !== send.id))
      if (selectedId === send.id) {
        setSelectedId(null)
        setDraft({ ...emptyDraft })
        setSendDialogOpen(false)
      }
      toast.success(t`Send deleted`)
    } catch {
      toast.error(t`Could not delete the Send.`)
    } finally {
      setBusy(false)
    }
  }

  async function copyLink(send: SendView): Promise<void> {
    clearCopied()
    try {
      await window.bearwarden.sends.copyLink({ id: send.id })
      showCopied(send.id)
    } catch {
      toast.error(t`Could not copy the sharing link.`)
    }
  }

  async function downloadFile(send: SendView): Promise<void> {
    if (send.type !== 'file') return
    if (usesEmailVerification(send)) {
      toast.error(
        t`This Send requires email OTP verification. BearWarden does not yet support downloading it.`
      )
      return
    }
    let password: string | null = null
    if (send.passwordProtected) {
      password = window.prompt(t`Enter the Send access password`)
      if (password === null) return
    }
    setBusy(true)
    try {
      const result = await window.bearwarden.sends.downloadFile({ id: send.id, password })
      if (!result.canceled) toast.success(t`Saved ${result.fileName}`)
    } catch {
      toast.error(t`Could not download the file Send. Check the password and sync connection.`)
    } finally {
      setBusy(false)
    }
  }

  async function removePassword(): Promise<void> {
    if (!selected) return
    setBusy(true)
    try {
      const saved = await window.bearwarden.sends.removePassword({ id: selected.id })
      setSends((current) => [saved, ...current.filter((send) => send.id !== saved.id)])
      setDraft(
        draftFromSend(saved, t`File Sends are read-only until file transfer support is enabled`)
      )
      toast.success(t`Send password removed`)
    } catch {
      toast.error(t`Could not remove the Send password.`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuxiliaryPageLayout
      title={t`Sends`}
      titleId="sends-title"
      subtitle={t`Text and file Send metadata is decrypted in the main process first.`}
      headerActions={
        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            type="button"
            onClick={() => startCreate('file')}
            disabled={busy}
          >
            <FilePlus data-icon="inline-start" />
            <Trans>Create file Send</Trans>
          </Button>
          <Button type="button" onClick={() => startCreate()} disabled={busy}>
            <Plus data-icon="inline-start" />
            <Trans>Create text Send</Trans>
          </Button>
        </div>
      }
    >
      <FeatureUnderConstructionNotice>
        <Trans>
          Core text and file Send workflows are available. File editing, advanced verification, and
          the complete public receiving flow are still in development.
        </Trans>
      </FeatureUnderConstructionNotice>
      {loading ? (
        <div className="flex items-center justify-center gap-2 py-16" role="status">
          <Spinner />
          <Trans>Loading Sends…</Trans>
        </div>
      ) : loadError ? (
        <Alert variant="destructive">
          <AlertTriangle aria-hidden="true" />
          <AlertTitle>
            <Trans>Could not load Sends</Trans>
          </AlertTitle>
          <AlertDescription>
            <Trans>
              Confirm that sync is connected and try again. Existing data has not been changed.
            </Trans>
          </AlertDescription>
          <AlertAction>
            <Button size="sm" variant="outline" type="button" onClick={() => void retryLoad()}>
              <RefreshCw data-icon="inline-start" />
              <Trans>Try again</Trans>
            </Button>
          </AlertAction>
        </Alert>
      ) : (
        <AuxiliaryPageContent>
          <main className="col-start-2 flex min-w-0 flex-col gap-4 max-[880px]:col-start-1">
            {sends.length === 0 ? (
              <Empty>
                <EmptyHeader>
                  <EmptyTitle>
                    <Trans>No Sends yet</Trans>
                  </EmptyTitle>
                  <EmptyDescription>
                    <Trans>Create a text Send to securely share one-time content.</Trans>
                  </EmptyDescription>
                </EmptyHeader>
                <EmptyContent>
                  <Button type="button" onClick={() => startCreate()}>
                    <Plus data-icon="inline-start" />
                    <Trans>Create your first Send</Trans>
                  </Button>
                </EmptyContent>
              </Empty>
            ) : (
              sends.map((send) => (
                <Card
                  key={send.id}
                  className={selectedId === send.id ? 'border-primary' : undefined}
                >
                  <CardHeader>
                    <CardTitle className="flex flex-wrap items-center gap-2">
                      {send.type === 'file' && <FileText aria-hidden="true" />}
                      {send.name}
                      {sendStatuses(send).map((status) => (
                        <SendStatusBadge key={status.key} status={status} />
                      ))}
                    </CardTitle>
                    <CardDescription>
                      {t({
                        message: plural(send.accessCount, { one: '# access', other: '# accesses' })
                      })}
                      {send.maxAccessCount
                        ? t` / maximum ${new Intl.NumberFormat(i18n.locale).format(send.maxAccessCount)}`
                        : ''}
                    </CardDescription>
                    <CardAction className="flex gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        type="button"
                        onClick={() => void copyLink(send)}
                        aria-label={
                          copiedKey === send.id ? t`Sharing link copied` : t`Copy sharing link`
                        }
                      >
                        <CopyFeedbackIcon copied={copiedKey === send.id} />
                      </Button>
                      {send.type === 'file' && (
                        <Button
                          variant="ghost"
                          size="icon"
                          type="button"
                          onClick={() => void downloadFile(send)}
                          aria-label={t`Download file Send`}
                          disabled={busy || usesEmailVerification(send)}
                        >
                          <Download />
                        </Button>
                      )}
                      <Button
                        variant="ghost"
                        size="icon"
                        type="button"
                        onClick={() => startEdit(send)}
                        aria-label={t`Edit Send`}
                        disabled={send.type === 'file' || usesEmailVerification(send)}
                      >
                        <Pencil />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        type="button"
                        onClick={() => setDeleteTarget(send)}
                        aria-label={t`Delete Send`}
                      >
                        <Trash2 />
                      </Button>
                    </CardAction>
                  </CardHeader>
                  <CardContent>
                    {usesEmailVerification(send) && (
                      <Alert className="mb-3">
                        <AlertTriangle aria-hidden="true" />
                        <AlertTitle>
                          <Trans>Email-verified Send</Trans>
                        </AlertTitle>
                        <AlertDescription>
                          <Trans>
                            BearWarden does not yet support recipient OTP. To avoid removing
                            verification requirements, this Send cannot be edited or downloaded.
                          </Trans>
                        </AlertDescription>
                      </Alert>
                    )}
                    {send.type === 'file' && send.file ? (
                      <div className="text-muted-foreground flex items-center gap-2 text-sm">
                        <FileText aria-hidden="true" />
                        <span className="truncate">{send.file.fileName}</span>
                        <span className="shrink-0">
                          {send.file.sizeName ?? (
                            <Trans>
                              {new Intl.NumberFormat(i18n.locale).format(send.file.size)} bytes
                            </Trans>
                          )}
                        </span>
                      </div>
                    ) : (
                      <p className="text-muted-foreground line-clamp-3 text-sm whitespace-pre-wrap">
                        {send.text}
                      </p>
                    )}
                    {send.notes && (
                      <div className="mt-3 flex flex-col gap-1 text-sm">
                        <span className="font-medium">
                          <Trans>Private notes</Trans>
                        </span>
                        <p className="text-muted-foreground whitespace-pre-wrap">{send.notes}</p>
                      </div>
                    )}
                    <dl className="text-muted-foreground mt-3 grid gap-x-4 gap-y-1 text-sm sm:grid-cols-2">
                      <div className="flex justify-between gap-2">
                        <dt>
                          <Trans>Expires</Trans>
                        </dt>
                        <dd>{formatDate(send.expirationDate)}</dd>
                      </div>
                      <div className="flex justify-between gap-2">
                        <dt>
                          <Trans>Deletes</Trans>
                        </dt>
                        <dd>{formatDate(send.deletionDate)}</dd>
                      </div>
                      <div className="flex justify-between gap-2 sm:col-span-2">
                        <dt>
                          <Trans>Last revised</Trans>
                        </dt>
                        <dd>{formatDate(send.revisionDate)}</dd>
                      </div>
                    </dl>
                  </CardContent>
                </Card>
              ))
            )}
          </main>

          <Dialog
            open={sendDialogOpen}
            onOpenChange={(open) => {
              if (busy) return
              setSendDialogOpen(open)
            }}
          >
            <DialogContent className="max-h-[calc(100%-2rem)] max-w-2xl overflow-hidden p-0">
              <DialogHeader className="border-b px-5 pt-5 pb-4">
                <DialogTitle>
                  {selected ? <Trans>Edit Send</Trans> : <Trans>Create Send</Trans>}
                </DialogTitle>
                <DialogDescription>
                  <Trans>
                    Content is encrypted in the main process before it is sent to the server.
                  </Trans>
                </DialogDescription>
              </DialogHeader>
              <div className="max-h-[min(68vh,640px)] overflow-auto px-5 py-4">
                <FieldGroup>
                  <Field>
                    <FieldLabel htmlFor="send-name">
                      <Trans>Name</Trans>
                    </FieldLabel>
                    <Input
                      id="send-name"
                      value={draft.name}
                      onChange={(event) => setDraft({ ...draft, name: event.target.value })}
                    />
                  </Field>
                  {createMode === 'text' && (
                    <Field>
                      <FieldLabel htmlFor="send-text">
                        <Trans>Content</Trans>
                      </FieldLabel>
                      <Textarea
                        id="send-text"
                        rows={8}
                        value={draft.text}
                        onChange={(event) => setDraft({ ...draft, text: event.target.value })}
                      />
                      <FieldDescription>
                        <Trans>Text content is not included in the sharing link.</Trans>
                      </FieldDescription>
                    </Field>
                  )}
                  <Field>
                    <FieldLabel htmlFor="send-password">
                      {selected ? (
                        <Trans>Access password (leave blank to keep the current password)</Trans>
                      ) : (
                        <Trans>Access password (optional)</Trans>
                      )}
                    </FieldLabel>
                    <Input
                      id="send-password"
                      type="password"
                      value={draft.password ?? ''}
                      onChange={(event) =>
                        setDraft({
                          ...draft,
                          password:
                            event.target.value.length > 0
                              ? event.target.value
                              : selected
                                ? undefined
                                : null
                        })
                      }
                      autoComplete="new-password"
                    />
                    {selected?.passwordProtected && (
                      <Button
                        variant="outline"
                        type="button"
                        onClick={() => void removePassword()}
                        disabled={busy}
                      >
                        <Trans>Remove current password</Trans>
                      </Button>
                    )}
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="send-notes">
                      <Trans>Private notes</Trans>
                    </FieldLabel>
                    <Textarea
                      id="send-notes"
                      rows={3}
                      value={draft.notes ?? ''}
                      onChange={(event) =>
                        setDraft({ ...draft, notes: event.target.value || null })
                      }
                    />
                    <FieldDescription>
                      <Trans>Only you can see this. It is not shown to recipients.</Trans>
                    </FieldDescription>
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="send-max-access-count">
                      <Trans>Maximum access count</Trans>
                    </FieldLabel>
                    <Input
                      id="send-max-access-count"
                      type="number"
                      min={1}
                      max={2_147_483_647}
                      step={1}
                      value={draft.maxAccessCount ?? ''}
                      onChange={(event) =>
                        setDraft({
                          ...draft,
                          maxAccessCount:
                            event.target.value === '' ? null : Number(event.target.value)
                        })
                      }
                    />
                    <FieldDescription>
                      <Trans>Leave blank for no limit.</Trans>
                    </FieldDescription>
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="send-expiration-date">
                      <Trans>Expiration date</Trans>
                    </FieldLabel>
                    <Input
                      id="send-expiration-date"
                      type="datetime-local"
                      value={dateTimeLocalValue(draft.expirationDate ?? null)}
                      onChange={(event) =>
                        setDraft({
                          ...draft,
                          expirationDate: dateTimeLocalToIso(event.target.value)
                        })
                      }
                    />
                    <FieldDescription>
                      <Trans>
                        After this date, the link stops accepting access, but the Send is not
                        immediately deleted.
                      </Trans>
                    </FieldDescription>
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="send-deletion-date">
                      <Trans>Deletion date</Trans>
                    </FieldLabel>
                    <Input
                      id="send-deletion-date"
                      type="datetime-local"
                      value={dateTimeLocalValue(draft.deletionDate ?? null)}
                      onChange={(event) =>
                        setDraft({
                          ...draft,
                          deletionDate: dateTimeLocalToIso(event.target.value)
                        })
                      }
                    />
                    <FieldDescription>
                      <Trans>After this time, the server permanently removes the Send.</Trans>
                    </FieldDescription>
                  </Field>
                  <Field orientation="horizontal">
                    <FieldContent>
                      <FieldLabel htmlFor="send-hidden">
                        <Trans>Hide text by default</Trans>
                      </FieldLabel>
                      <FieldDescription>
                        <Trans>Recipients must actively reveal the text to see it.</Trans>
                      </FieldDescription>
                    </FieldContent>
                    <Switch
                      id="send-hidden"
                      checked={draft.hidden ?? false}
                      onCheckedChange={(checked) => setDraft({ ...draft, hidden: checked })}
                    />
                  </Field>
                  <Field orientation="horizontal">
                    <FieldContent>
                      <FieldLabel htmlFor="send-disabled">
                        <Trans>Disable Send</Trans>
                      </FieldLabel>
                      <FieldDescription>
                        <Trans>Keep the Send but prevent all recipient access.</Trans>
                      </FieldDescription>
                    </FieldContent>
                    <Switch
                      id="send-disabled"
                      checked={draft.disabled ?? false}
                      onCheckedChange={(checked) => setDraft({ ...draft, disabled: checked })}
                    />
                  </Field>
                  <Field orientation="horizontal">
                    <FieldContent>
                      <FieldLabel htmlFor="send-hide-email">
                        <Trans>Hide sender email</Trans>
                      </FieldLabel>
                      <FieldDescription>
                        <Trans>Do not show your account email to recipients.</Trans>
                      </FieldDescription>
                    </FieldContent>
                    <Switch
                      id="send-hide-email"
                      checked={draft.hideEmail ?? false}
                      onCheckedChange={(checked) => setDraft({ ...draft, hideEmail: checked })}
                    />
                  </Field>
                </FieldGroup>
              </div>
              <DialogFooter className="px-5 py-4">
                <Button
                  type="button"
                  onClick={() => void (createMode === 'file' && !selected ? createFile() : save())}
                  disabled={busy}
                >
                  {createMode === 'file' && !selected ? (
                    <FilePlus data-icon="inline-start" />
                  ) : (
                    <Save data-icon="inline-start" />
                  )}
                  {busy ? (
                    <Trans>Saving…</Trans>
                  ) : createMode === 'file' && !selected ? (
                    <Trans>Create file Send</Trans>
                  ) : (
                    <Trans>Save</Trans>
                  )}
                </Button>
                <Button
                  variant="outline"
                  type="button"
                  onClick={() => setSendDialogOpen(false)}
                  disabled={busy}
                >
                  <Trans>Cancel</Trans>
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </AuxiliaryPageContent>
      )}
      <AlertDialog
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open && !busy) setDeleteTarget(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              <Trans>Delete this Send?</Trans>
            </AlertDialogTitle>
            <AlertDialogDescription>
              <Trans>
                “{deleteTarget?.name ?? ''}” will be removed from Vaultwarden and cannot be restored
                from the trash.
              </Trans>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>
              <Trans>Cancel</Trans>
            </AlertDialogCancel>
            <AlertDialogAction
              disabled={busy || deleteTarget === null}
              onClick={(event) => {
                event.preventDefault()
                const target = deleteTarget
                if (!target) return
                void remove(target).finally(() => setDeleteTarget(null))
              }}
            >
              <Trans>Delete</Trans>
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </AuxiliaryPageLayout>
  )
}

export default SendsPage
