import { useRef, useState } from 'react'
import { AlertTriangle, FolderInput, X } from 'lucide-react'
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
  onClose: () => void
  onDelete: () => Promise<void>
}

export function DeleteLoginDialog({
  itemName,
  busy,
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
          <AlertDialogTitle>永久刪除「{itemName}」？</AlertDialogTitle>
          <AlertDialogDescription>
            這個動作無法復原。BearWarden 不會保留可復原的明文副本。
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>取消</AlertDialogCancel>
          <AlertDialogAction variant="destructive" type="button" disabled={busy} onClick={onDelete}>
            {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
            永久刪除
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
