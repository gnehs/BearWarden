import { useEffect, useRef, useState } from 'react'
import { AlertTriangle, Eye, EyeOff, FolderInput, History, KeyRound, X } from 'lucide-react'
import { plural } from '@lingui/core/macro'
import { Trans, useLingui } from '@lingui/react/macro'
import type { FolderView } from '../../../shared/vault-contract'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogMedia,
  AlertDialogTitle,
  AlertDialogTrigger
} from '@renderer/components/ui/alert-dialog'
import { Alert, AlertAction, AlertDescription } from '@renderer/components/ui/alert'
import { Button } from '@renderer/components/ui/button'
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '@renderer/components/ui/card'
import { Dialog, DialogClose, DialogDescription, DialogTitle } from '@renderer/components/ui/dialog'
import { Field, FieldGroup, FieldLabel } from '@renderer/components/ui/field'
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle
} from '@renderer/components/ui/empty'
import { Input } from '@renderer/components/ui/input'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue
} from '@renderer/components/ui/select'
import { Spinner } from '@renderer/components/ui/spinner'
import { Skeleton } from '@renderer/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@renderer/components/ui/tooltip'
import {
  usePasswordHistory,
  type UsePasswordHistoryOptions
} from '@renderer/hooks/use-password-history'
import {
  composeVaultFolderName,
  isVaultFolderNameDuplicate,
  MAX_VAULT_FOLDER_NAME_LENGTH,
  vaultFolderFormValue,
  vaultFolderParentCandidateRows
} from '@renderer/lib/vault-folder-tree'
import { CopyFeedbackIcon } from './CopyFeedbackIcon'
import { ModalActionGroup, ModalBody, ModalContent, ModalFooter, ModalHeader } from './ModalLayout'

interface ModalProps {
  title: string
  description?: string
  children: React.ReactNode | ((close: () => void) => React.ReactNode)
  busy?: boolean
  onClose: () => void
}

export function Modal({
  title,
  description,
  children,
  busy = false,
  onClose
}: ModalProps): React.JSX.Element {
  const { t } = useLingui()
  const [open, setOpen] = useState(true)

  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (!busy) setOpen(nextOpen)
      }}
      onOpenChangeComplete={(nextOpen) => {
        if (!nextOpen) onClose()
      }}
    >
      <ModalContent showCloseButton={false}>
        <ModalHeader hasDescription={Boolean(description)}>
          <div>
            <DialogTitle className="m-0 text-[17px]">{title}</DialogTitle>
            {description && (
              <DialogDescription className="mt-[5px] mb-0 text-[11px] leading-[1.5]">
                {description}
              </DialogDescription>
            )}
          </div>
          <DialogClose
            render={
              <Button
                variant="ghost"
                size="icon-sm"
                type="button"
                aria-label={t`Close`}
                disabled={busy}
              />
            }
          >
            <X aria-hidden="true" />
          </DialogClose>
        </ModalHeader>
        {typeof children === 'function' ? children(() => setOpen(false)) : children}
      </ModalContent>
    </Dialog>
  )
}

interface FolderDialogProps {
  folder?: FolderView
  folders: FolderView[]
  busy: boolean
  onClose: () => void
  onSave: (name: string) => Promise<void>
  onDelete?: () => Promise<void>
}

export function FolderDialog({
  folder,
  folders,
  busy,
  onClose,
  onSave,
  onDelete
}: FolderDialogProps): React.JSX.Element {
  const { t } = useLingui()
  const submittingRef = useRef(false)
  const initialValue = vaultFolderFormValue(folder, folders)
  const [name, setName] = useState(initialValue.name)
  const [parentId, setParentId] = useState(initialValue.parentId)
  const [confirmingDelete, setConfirmingDelete] = useState(false)
  const [error, setError] = useState('')

  async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (busy || submittingRef.current) return
    const nextLeafName = name.trim()
    if (!nextLeafName) {
      setError(t`Enter a folder name.`)
      return
    }
    const nextName = composeVaultFolderName(nextLeafName, parentId, folders)
    if (!nextName) {
      setError(t`Choose an available parent folder.`)
      return
    }
    if (nextName.length > MAX_VAULT_FOLDER_NAME_LENGTH) {
      setError(t`Folder names can be up to ${MAX_VAULT_FOLDER_NAME_LENGTH} characters.`)
      return
    }
    if (isVaultFolderNameDuplicate(nextName, folders, folder?.id)) {
      setError(t`That name is already in use. Choose another name.`)
      return
    }
    setError('')
    submittingRef.current = true
    try {
      await onSave(nextName)
    } finally {
      submittingRef.current = false
    }
  }

  const parentItems = [
    { label: t`No parent folder`, displayLabel: t`No parent folder`, value: '', depth: 0 },
    ...vaultFolderParentCandidateRows(folders, folder).map((row) => ({
      label: row.folder.name,
      displayLabel: row.label,
      value: row.folder.id,
      depth: row.depth
    }))
  ]
  const selectedParent = folders.find((candidate) => candidate.id === parentId)
  const leafNameMaxLength = selectedParent
    ? Math.max(0, MAX_VAULT_FOLDER_NAME_LENGTH - selectedParent.name.length - 1)
    : MAX_VAULT_FOLDER_NAME_LENGTH

  return (
    <Modal
      title={folder ? t`Edit folder` : t`Add folder`}
      description={t`Folders organize your items without changing their login details.`}
      busy={busy}
      onClose={onClose}
    >
      <form onSubmit={submit}>
        <ModalBody>
          <FieldGroup>
            <Field data-invalid={Boolean(error)}>
              <FieldLabel htmlFor="folder-name">
                <Trans>Name</Trans>
              </FieldLabel>
              <Input
                id="folder-name"
                autoFocus
                value={name}
                onChange={(event) => setName(event.target.value)}
                maxLength={leafNameMaxLength}
                disabled={busy}
                aria-invalid={Boolean(error)}
                aria-describedby={error ? 'folder-error' : undefined}
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="folder-parent">
                <Trans>Parent folder</Trans>
              </FieldLabel>
              <Select
                items={parentItems}
                value={parentId}
                onValueChange={(value) => setParentId(value ?? '')}
                disabled={busy}
              >
                <SelectTrigger id="folder-parent" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {parentItems.map((parent) => (
                      <SelectItem
                        key={parent.value || 'no-parent'}
                        value={parent.value}
                        label={parent.label}
                        aria-label={parent.label}
                        style={{ paddingInlineStart: `${6 + parent.depth * 16}px` }}
                      >
                        {parent.displayLabel}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </Field>
          </FieldGroup>
          {error && (
            <Alert id="folder-error" variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </ModalBody>
        <ModalFooter split>
          <div>
            {folder && onDelete && (
              <AlertDialog
                open={confirmingDelete}
                onOpenChange={(open) => {
                  if (!busy) setConfirmingDelete(open)
                }}
              >
                <AlertDialogTrigger render={<Button type="button" variant="ghost" />}>
                  <Trans>Delete</Trans>
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogMedia>
                      <AlertTriangle aria-hidden="true" />
                    </AlertDialogMedia>
                    <AlertDialogTitle>{t`Delete “${folder.name}”?`}</AlertDialogTitle>
                    <AlertDialogDescription>
                      <Trans>Its items will move to Unfiled and will not be deleted.</Trans>
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel disabled={busy}>
                      <Trans>Back</Trans>
                    </AlertDialogCancel>
                    <AlertDialogAction
                      variant="destructive"
                      type="button"
                      disabled={busy}
                      onClick={onDelete}
                    >
                      {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                      <Trans>Delete folder</Trans>
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            )}
          </div>
          <ModalActionGroup>
            <DialogClose render={<Button variant="secondary" type="button" disabled={busy} />}>
              <Trans>Cancel</Trans>
            </DialogClose>
            <Button type="submit" disabled={busy}>
              {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
              <Trans>Save</Trans>
            </Button>
          </ModalActionGroup>
        </ModalFooter>
      </form>
    </Modal>
  )
}

interface MoveDialogProps {
  itemName: string
  itemCount?: number
  currentFolderId: string | null | undefined
  folders: FolderView[]
  busy: boolean
  onClose: () => void
  onMove: (folderId: string | null) => Promise<boolean>
}

export function MoveDialog({
  itemName,
  itemCount = 1,
  currentFolderId,
  folders,
  busy,
  onClose,
  onMove
}: MoveDialogProps): React.JSX.Element {
  const { t } = useLingui()
  const submittingRef = useRef(false)
  const [folderId, setFolderId] = useState<string | null>(
    currentFolderId === undefined ? null : (currentFolderId ?? '')
  )
  const folderItems = [
    { label: t`Unfiled`, value: '' },
    ...folders.map((folder) => ({ label: folder.name, value: folder.id }))
  ]

  return (
    <Modal
      title={t`Move to folder`}
      description={
        itemCount > 1
          ? t({
              message: plural(itemCount, {
                one: `Choose a new location for # item. This is a keyboard alternative to drag and drop.`,
                other: `Choose a new location for # items. This is a keyboard alternative to drag and drop.`
              })
            })
          : t`Choose a new location for “${itemName}”. This is a keyboard alternative to drag and drop.`
      }
      busy={busy}
      onClose={onClose}
    >
      {(close) => (
        <form
          onSubmit={async (event) => {
            event.preventDefault()
            if (busy || submittingRef.current) return
            submittingRef.current = true
            try {
              if (await onMove(folderId || null)) close()
            } finally {
              submittingRef.current = false
            }
          }}
        >
          <ModalBody className="grid-cols-[auto_minmax(0,1fr)] items-end">
            <span
              className="text-primary grid size-[42px] place-items-center rounded-[11px] bg-[var(--accent-soft)]"
              aria-hidden="true"
            >
              <FolderInput />
            </span>
            <Field className="min-w-0">
              <FieldLabel htmlFor="move-folder">
                <Trans>Folder</Trans>
              </FieldLabel>
              <Select
                items={folderItems}
                value={folderId}
                onValueChange={(value) => setFolderId(value ?? '')}
                disabled={busy}
              >
                <SelectTrigger id="move-folder" autoFocus className="w-full">
                  <SelectValue placeholder={t`Choose a folder`} />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {folderItems.map((folder) => (
                      <SelectItem key={folder.value} value={folder.value}>
                        {folder.label}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </Field>
          </ModalBody>
          <ModalFooter>
            <DialogClose render={<Button variant="secondary" type="button" disabled={busy} />}>
              <Trans>Cancel</Trans>
            </DialogClose>
            <Button type="submit" disabled={busy}>
              {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
              <Trans>Move</Trans>
            </Button>
          </ModalFooter>
        </form>
      )}
    </Modal>
  )
}

interface DeleteLoginDialogProps {
  itemName: string
  busy: boolean
  permanent?: boolean
  onClose: () => void
  onDelete: () => Promise<void>
}

export function DeleteLoginDialog({
  itemName,
  busy,
  permanent = false,
  onClose,
  onDelete
}: DeleteLoginDialogProps): React.JSX.Element {
  const { t } = useLingui()
  return (
    <AlertDialog
      open
      onOpenChange={(open) => {
        if (!open && !busy) onClose()
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogMedia>
            <AlertTriangle aria-hidden="true" />
          </AlertDialogMedia>
          <AlertDialogTitle>
            {permanent ? t`Permanently delete “${itemName}”?` : t`Move “${itemName}” to the trash?`}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {permanent
              ? t`This action cannot be undone. BearWarden does not retain a recoverable plaintext copy.`
              : t`The item remains in the encrypted trash and can be restored later.`}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>
            <Trans>Cancel</Trans>
          </AlertDialogCancel>
          <AlertDialogAction variant="destructive" type="button" disabled={busy} onClick={onDelete}>
            {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
            {permanent ? <Trans>Permanently delete</Trans> : <Trans>Move to trash</Trans>}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

interface RepromptDialogProps {
  itemName: string
  busy: boolean
  onCancel: () => void
  onAuthorize: (masterPassword: string) => Promise<void>
}

export function RepromptDialog({
  itemName,
  busy,
  onCancel,
  onAuthorize
}: RepromptDialogProps): React.JSX.Element {
  const { t } = useLingui()
  const passwordRef = useRef<HTMLInputElement>(null)
  const submittingRef = useRef(false)
  const [error, setError] = useState('')

  return (
    <Modal
      title={t`Master password required`}
      description={t`“${itemName}” requires master password reprompt.`}
      busy={busy}
      onClose={onCancel}
    >
      <form
        onSubmit={async (event) => {
          event.preventDefault()
          if (busy || submittingRef.current) return
          const input = passwordRef.current
          const masterPassword = input?.value ?? ''
          if (input) input.value = ''
          if (!masterPassword) {
            setError(t`Enter your master password.`)
            return
          }
          submittingRef.current = true
          setError('')
          try {
            await onAuthorize(masterPassword)
          } catch (authorizeError) {
            setError(
              authorizeError instanceof Error &&
                authorizeError.message.includes('INVALID_MASTER_PASSWORD')
                ? t`Incorrect master password.`
                : t`Unable to verify the master password. Try again.`
            )
            queueMicrotask(() => passwordRef.current?.focus())
          } finally {
            submittingRef.current = false
          }
        }}
      >
        <ModalBody>
          <span
            className="text-primary grid size-[42px] place-items-center rounded-[11px] bg-[var(--accent-soft)]"
            aria-hidden="true"
          >
            <KeyRound />
          </span>
          <Field className="min-w-0" data-invalid={Boolean(error)}>
            <FieldLabel htmlFor="reprompt-master-password">
              <Trans>Master password</Trans>
            </FieldLabel>
            <Input
              ref={passwordRef}
              id="reprompt-master-password"
              type="password"
              autoComplete="current-password"
              autoFocus
              disabled={busy}
              aria-invalid={Boolean(error)}
              aria-describedby={error ? 'reprompt-error' : undefined}
            />
          </Field>
          {error && (
            <Alert id="reprompt-error" variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </ModalBody>
        <ModalFooter>
          <Button type="button" variant="secondary" disabled={busy} onClick={onCancel}>
            <Trans>Cancel</Trans>
          </Button>
          <Button type="submit" disabled={busy}>
            {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
            <Trans>Verify</Trans>
          </Button>
        </ModalFooter>
      </form>
    </Modal>
  )
}

interface PasswordHistoryDialogProps extends UsePasswordHistoryOptions {
  itemName: string
  count: number
  onClose: () => void
}

function PasswordHistoryIconButton({
  label,
  children,
  ...props
}: React.ComponentProps<typeof Button> & {
  label: string
  children: React.ReactNode
}): React.JSX.Element {
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Button type="button" variant="ghost" size="icon-sm" aria-label={label} {...props} />
        }
      >
        {children}
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}

export function PasswordHistoryDialog({
  itemName,
  count,
  onClose,
  onLoad,
  onReveal,
  onCopy
}: PasswordHistoryDialogProps): React.JSX.Element {
  const { i18n, t } = useLingui()
  const historyTransitionRef = useRef<HTMLDivElement>(null)
  const historySkeletonRef = useRef<HTMLDivElement>(null)
  const {
    history,
    loading,
    revealedValues,
    revealing,
    copying,
    copiedKey,
    error,
    clearSecrets,
    loadHistory,
    toggleReveal,
    copyEntry
  } = usePasswordHistory({ onLoad, onReveal, onCopy })

  useEffect(() => {
    const transition = historyTransitionRef.current
    const skeleton = historySkeletonRef.current
    if (!transition || !skeleton) return

    if (loading) {
      transition.dataset.revealState = 'resetting'
      skeleton.dataset.pulsing = 'false'
      void skeleton.offsetWidth
      transition.dataset.revealState = 'loading'
      skeleton.dataset.pulsing = 'true'
      return
    }

    transition.dataset.revealState = 'revealed'
  }, [loading])

  const closeDialog = (): void => {
    clearSecrets()
    onClose()
  }

  const skeletonRowCount = Math.min(Math.max(count, 1), 5)
  const historySlotHeight = Math.min(Math.max(skeletonRowCount * 88, 176), 360)

  return (
    <Modal
      title={t`Password history`}
      description={t({
        message: plural(count, {
          one: `“${itemName}” has # history entry.`,
          other: `“${itemName}” has # history entries.`
        })
      })}
      onClose={closeDialog}
    >
      <ModalBody className="flex flex-col gap-3">
        <div
          ref={historyTransitionRef}
          className="relative data-[reveal-state=resetting]:[&>_*]:!transition-none data-[reveal-state=revealed]:[&>[data-slot=password-history-content]]:opacity-100 data-[reveal-state=revealed]:[&>[data-slot=password-history-content]]:blur-none data-[reveal-state=revealed]:[&>[data-slot=password-history-skeleton]]:opacity-0 data-[reveal-state=revealed]:[&>[data-slot=password-history-skeleton]]:blur-[var(--reveal-blur)]"
          data-state={loading ? 'loading' : 'loaded'}
          data-reveal-state="loading"
          aria-busy={loading}
          style={{ height: `min(50vh, ${historySlotHeight}px)` }}
        >
          <div
            ref={historySkeletonRef}
            data-slot="password-history-skeleton"
            className="absolute inset-0 z-1 flex flex-col gap-2 overflow-hidden opacity-100 blur-none transition-[opacity,filter] duration-[var(--reveal-dur)] ease-[var(--reveal-ease)] motion-reduce:!transition-none data-[pulsing=true]:[&>*]:animate-[pulse_var(--pulse-dur)_ease-in-out_var(--pulse-count)] motion-reduce:data-[pulsing=true]:[&>*]:!animate-none"
            data-pulsing="true"
            role="status"
            aria-label={t`Loading password history`}
            aria-hidden={!loading}
          >
            {Array.from({ length: skeletonRowCount }, (_, index) => (
              <Card key={index} size="sm">
                <CardHeader>
                  <Skeleton className="h-4 w-24" />
                </CardHeader>
                <CardContent>
                  <Skeleton className="h-9 w-full" />
                </CardContent>
              </Card>
            ))}
          </div>
          <div
            data-slot="password-history-content"
            className="absolute inset-0 z-2 flex min-h-0 flex-col gap-3 opacity-0 blur-[var(--reveal-blur)] transition-[opacity,filter] duration-[var(--reveal-dur)] ease-[var(--reveal-ease)] motion-reduce:!transition-none"
            aria-hidden={loading}
            inert={loading}
          >
            {history && history.entries.length > 0 && (
              <ol className="scroll-fade-y forced-colors:scroll-fade-none flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto p-px pr-1">
                {history.entries.map((entry, index) => {
                  const key = `${index}:${entry.lastUsedDate}`
                  const revealedValue = revealedValues[key]
                  const isRevealed = revealedValue !== undefined
                  const rowBusy = Boolean(revealing[key] || copying[key])
                  return (
                    <li key={key}>
                      <Card size="sm">
                        <CardHeader>
                          <CardTitle>
                            {new Date(entry.lastUsedDate).toLocaleString(i18n.locale)}
                          </CardTitle>
                          <CardAction className="flex gap-1">
                            <PasswordHistoryIconButton
                              label={
                                isRevealed
                                  ? t`Hide this historical password`
                                  : t`Show this historical password`
                              }
                              aria-pressed={isRevealed}
                              disabled={rowBusy}
                              onClick={() => void toggleReveal(index, entry.lastUsedDate)}
                            >
                              {revealing[key] ? (
                                <Spinner aria-hidden="true" />
                              ) : isRevealed ? (
                                <EyeOff aria-hidden="true" />
                              ) : (
                                <Eye aria-hidden="true" />
                              )}
                            </PasswordHistoryIconButton>
                            <PasswordHistoryIconButton
                              label={
                                copiedKey === key ? t`Copied` : t`Copy this historical password`
                              }
                              disabled={rowBusy}
                              onClick={() => void copyEntry(index, entry.lastUsedDate)}
                            >
                              {copying[key] ? (
                                <Spinner aria-hidden="true" />
                              ) : (
                                <CopyFeedbackIcon copied={copiedKey === key} />
                              )}
                            </PasswordHistoryIconButton>
                          </CardAction>
                        </CardHeader>
                        <CardContent>
                          <div className="bg-muted/60 min-h-9 rounded-lg px-3 py-2">
                            {isRevealed ? (
                              <code className="text-sm break-all select-text">{revealedValue}</code>
                            ) : (
                              <>
                                <code className="text-sm" aria-hidden="true">
                                  ••••••••••••
                                </code>
                                <span className="sr-only">
                                  <Trans>Historical password is masked</Trans>
                                </span>
                              </>
                            )}
                          </div>
                        </CardContent>
                      </Card>
                    </li>
                  )
                })}
              </ol>
            )}
            {history && history.entries.length === 0 && (
              <Empty className="h-full">
                <EmptyHeader>
                  <EmptyMedia variant="icon">
                    <History aria-hidden="true" />
                  </EmptyMedia>
                  <EmptyTitle>
                    <Trans>No password history</Trans>
                  </EmptyTitle>
                  <EmptyDescription>
                    <Trans>There are no history entries to display.</Trans>
                  </EmptyDescription>
                </EmptyHeader>
              </Empty>
            )}
            {error && (
              <Alert className={history ? undefined : 'my-auto'} variant="destructive">
                <AlertTriangle aria-hidden="true" />
                <AlertDescription>{error}</AlertDescription>
                {!history && (
                  <AlertAction>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => loadHistory(true)}
                    >
                      <Trans>Reload</Trans>
                    </Button>
                  </AlertAction>
                )}
              </Alert>
            )}
          </div>
        </div>
      </ModalBody>
      <ModalFooter>
        <Button type="button" variant="secondary" onClick={closeDialog}>
          <Trans>Close</Trans>
        </Button>
      </ModalFooter>
    </Modal>
  )
}
