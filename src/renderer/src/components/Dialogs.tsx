import { useEffect, useRef, useState } from 'react'
import { AlertTriangle, FolderInput, History, KeyRound, RotateCcw, X } from 'lucide-react'
import type { FolderView, VaultPasswordHistoryEntry } from '../../../shared/vault-contract'
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
import { Alert, AlertDescription } from '@renderer/components/ui/alert'
import { Button } from '@renderer/components/ui/button'
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from '@renderer/components/ui/dialog'
import { Field, FieldLabel } from '@renderer/components/ui/field'
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
      <DialogContent className="modal modal-card" showCloseButton={false}>
        <DialogHeader className="modal-header">
          <div>
            <DialogTitle>{title}</DialogTitle>
            {description && <DialogDescription>{description}</DialogDescription>}
          </div>
          <DialogClose
            render={
              <Button
                variant="ghost"
                size="icon-sm"
                type="button"
                aria-label="關閉"
                disabled={busy}
              />
            }
          >
            <X aria-hidden="true" />
          </DialogClose>
        </DialogHeader>
        {typeof children === 'function' ? children(() => setOpen(false)) : children}
      </DialogContent>
    </Dialog>
  )
}

interface FolderDialogProps {
  folder?: FolderView
  busy: boolean
  onClose: () => void
  onSave: (name: string) => Promise<void>
  onDelete?: () => Promise<void>
}

export function FolderDialog({
  folder,
  busy,
  onClose,
  onSave,
  onDelete
}: FolderDialogProps): React.JSX.Element {
  const submittingRef = useRef(false)
  const [name, setName] = useState(folder?.name ?? '')
  const [confirmingDelete, setConfirmingDelete] = useState(false)
  const [error, setError] = useState('')

  async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (busy || submittingRef.current) return
    const nextName = name.trim()
    if (!nextName) {
      setError('請輸入資料夾名稱。')
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

  return (
    <Modal
      title={folder ? '編輯資料夾' : '新增資料夾'}
      description="資料夾只會整理你的項目，不會改變其中的登入資料。"
      busy={busy}
      onClose={onClose}
    >
      <form onSubmit={submit}>
        <div className="modal-body">
          <Field data-invalid={Boolean(error)}>
            <FieldLabel htmlFor="folder-name">名稱</FieldLabel>
            <Input
              id="folder-name"
              autoFocus
              value={name}
              onChange={(event) => setName(event.target.value)}
              maxLength={80}
              disabled={busy}
              aria-invalid={Boolean(error)}
              aria-describedby={error ? 'folder-error' : undefined}
            />
          </Field>
          {error && (
            <Alert id="folder-error" variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </div>
        <DialogFooter className="modal-actions split mx-0 mb-0">
          <div>
            {folder && onDelete && (
              <AlertDialog
                open={confirmingDelete}
                onOpenChange={(open) => {
                  if (!busy) setConfirmingDelete(open)
                }}
              >
                <AlertDialogTrigger render={<Button type="button" variant="ghost" />}>
                  刪除
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogMedia>
                      <AlertTriangle aria-hidden="true" />
                    </AlertDialogMedia>
                    <AlertDialogTitle>刪除「{folder.name}」？</AlertDialogTitle>
                    <AlertDialogDescription>
                      其中的項目會移到「未分類」，不會被刪除。
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel disabled={busy}>返回</AlertDialogCancel>
                    <AlertDialogAction
                      variant="destructive"
                      type="button"
                      disabled={busy}
                      onClick={onDelete}
                    >
                      {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                      刪除資料夾
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            )}
          </div>
          <div className="action-group">
            <DialogClose render={<Button variant="secondary" type="button" disabled={busy} />}>
              取消
            </DialogClose>
            <Button type="submit" disabled={busy}>
              {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
              儲存
            </Button>
          </div>
        </DialogFooter>
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
  const submittingRef = useRef(false)
  const [folderId, setFolderId] = useState<string | null>(
    currentFolderId === undefined ? null : (currentFolderId ?? '')
  )
  const folderItems = [
    { label: '未分類', value: '' },
    ...folders.map((folder) => ({ label: folder.name, value: folder.id }))
  ]

  return (
    <Modal
      title="移動至資料夾"
      description={
        itemCount > 1
          ? `選擇這 ${itemCount} 個項目的新位置。這是拖放操作的鍵盤替代方式。`
          : `選擇「${itemName}」的新位置。這是拖放操作的鍵盤替代方式。`
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
          <div className="modal-body move-dialog-body">
            <span className="move-dialog-icon" aria-hidden="true">
              <FolderInput />
            </span>
            <Field className="grow">
              <FieldLabel htmlFor="move-folder">資料夾</FieldLabel>
              <Select
                items={folderItems}
                value={folderId}
                onValueChange={(value) => setFolderId(value ?? '')}
                disabled={busy}
              >
                <SelectTrigger id="move-folder" autoFocus className="w-full">
                  <SelectValue placeholder="選擇資料夾" />
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
          </div>
          <DialogFooter className="modal-actions mx-0 mb-0">
            <DialogClose render={<Button variant="secondary" type="button" disabled={busy} />}>
              取消
            </DialogClose>
            <Button type="submit" disabled={busy}>
              {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
              移動
            </Button>
          </DialogFooter>
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
            {permanent ? `永久刪除「${itemName}」？` : `將「${itemName}」移至垃圾桶？`}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {permanent
              ? '這個動作無法復原。BearWarden 不會保留可復原的明文副本。'
              : '項目會保留在加密的垃圾桶中，之後仍可還原。'}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>取消</AlertDialogCancel>
          <AlertDialogAction variant="destructive" type="button" disabled={busy} onClick={onDelete}>
            {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
            {permanent ? '永久刪除' : '移至垃圾桶'}
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
  const passwordRef = useRef<HTMLInputElement>(null)
  const submittingRef = useRef(false)
  const [error, setError] = useState('')

  return (
    <Modal
      title="需要主密碼"
      description={`「${itemName}」已啟用主密碼重新提示。`}
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
            setError('請輸入主密碼。')
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
                ? '主密碼不正確。'
                : '無法驗證主密碼，請再試一次。'
            )
            queueMicrotask(() => passwordRef.current?.focus())
          } finally {
            submittingRef.current = false
          }
        }}
      >
        <div className="modal-body">
          <span className="move-dialog-icon" aria-hidden="true">
            <KeyRound />
          </span>
          <Field className="grow" data-invalid={Boolean(error)}>
            <FieldLabel htmlFor="reprompt-master-password">主密碼</FieldLabel>
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
        </div>
        <DialogFooter className="modal-actions mx-0 mb-0">
          <Button type="button" variant="secondary" disabled={busy} onClick={onCancel}>
            取消
          </Button>
          <Button type="submit" disabled={busy}>
            {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
            驗證
          </Button>
        </DialogFooter>
      </form>
    </Modal>
  )
}

interface PasswordHistoryDialogProps {
  itemName: string
  count: number
  onClose: () => void
  onReveal: () => Promise<VaultPasswordHistoryEntry[]>
  onRestore?: (index: number, lastUsedDate: string) => Promise<void>
}

export function PasswordHistoryRestoreButton({
  busy,
  onRestore
}: {
  busy: boolean
  onRestore?: () => void | Promise<void>
}): React.JSX.Element | null {
  if (!onRestore) return null
  return (
    <Button type="button" variant="outline" size="sm" disabled={busy} onClick={onRestore}>
      <RotateCcw data-icon="inline-start" aria-hidden="true" />
      套用為目前密碼
    </Button>
  )
}

export function PasswordHistoryDialog({
  itemName,
  count,
  onClose,
  onReveal,
  onRestore
}: PasswordHistoryDialogProps): React.JSX.Element {
  const [entries, setEntries] = useState<VaultPasswordHistoryEntry[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const entriesRef = useRef<VaultPasswordHistoryEntry[]>([])
  const mountedRef = useRef(true)

  const clearEntries = (): void => {
    entriesRef.current = []
    setEntries(null)
  }

  useEffect(
    () => () => {
      mountedRef.current = false
      entriesRef.current = []
    },
    []
  )

  return (
    <Modal
      title="密碼歷史"
      description={`「${itemName}」有 ${count} 筆歷史紀錄。`}
      busy={busy}
      onClose={() => {
        clearEntries()
        onClose()
      }}
    >
      <div className="modal-body">
        {entries === null ? (
          <Alert>
            <AlertTriangle aria-hidden="true" />
            <AlertDescription>
              繼續後，舊密碼與已變更的隱藏欄位會以明文顯示在螢幕上。請先確認周遭無人能看見。
            </AlertDescription>
          </Alert>
        ) : (
          <div aria-live="polite">
            <div className="move-dialog-icon" aria-hidden="true">
              <History />
            </div>
            <ol>
              {entries.map((entry, index) => (
                <li key={`${entry.lastUsedDate}:${index}`}>
                  <code>{entry.password}</code>
                  <small>{new Date(entry.lastUsedDate).toLocaleString('zh-TW')}</small>
                  <PasswordHistoryRestoreButton
                    busy={busy}
                    {...(onRestore
                      ? {
                          onRestore: async () => {
                            setBusy(true)
                            setError('')
                            try {
                              await onRestore(index, entry.lastUsedDate)
                              if (!mountedRef.current) return
                              clearEntries()
                              onClose()
                            } catch {
                              if (mountedRef.current) {
                                setError('無法套用這筆歷史，項目可能已在其他地方變更。')
                              }
                            } finally {
                              if (mountedRef.current) setBusy(false)
                            }
                          }
                        }
                      : {})}
                  />
                </li>
              ))}
            </ol>
            {onRestore ? (
              <p className="text-muted-foreground mt-3 text-sm">
                歷史中也可能包含「欄位名稱:
                舊值」格式的隱藏欄位紀錄；只有確定要作為登入密碼的列才套用。
              </p>
            ) : (
              <p className="text-muted-foreground mt-3 text-sm">
                垃圾桶項目只能查看歷史；必須先還原項目才能套用舊密碼。
              </p>
            )}
          </div>
        )}
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
      </div>
      <DialogFooter className="modal-actions mx-0 mb-0">
        <Button
          type="button"
          variant="secondary"
          disabled={busy}
          onClick={() => {
            clearEntries()
            onClose()
          }}
        >
          關閉
        </Button>
        {entries === null && (
          <Button
            type="button"
            disabled={busy}
            onClick={async () => {
              setBusy(true)
              setError('')
              try {
                const revealed = await onReveal()
                if (!mountedRef.current) return
                entriesRef.current = revealed
                setEntries(revealed)
              } catch {
                if (mountedRef.current) setError('無法讀取密碼歷史，請再試一次。')
              } finally {
                if (mountedRef.current) setBusy(false)
              }
            }}
          >
            {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
            顯示明文
          </Button>
        )}
      </DialogFooter>
    </Modal>
  )
}
