import { useCallback, useEffect, useRef, useState } from 'react'
import {
  AlertTriangle,
  Check,
  Copy,
  Eye,
  EyeOff,
  FolderInput,
  History,
  KeyRound,
  X
} from 'lucide-react'
import type {
  FolderView,
  PasswordHistoryEntryRequest,
  VaultPasswordHistoryView
} from '../../../shared/vault-contract'
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

type PasswordHistoryEntryLocator = Omit<PasswordHistoryEntryRequest, 'id' | 'authorizationToken'>

interface PasswordHistoryDialogProps {
  itemName: string
  count: number
  onClose: () => void
  onLoad: () => Promise<VaultPasswordHistoryView>
  onReveal: (locator: PasswordHistoryEntryLocator) => Promise<string>
  onCopy: (locator: PasswordHistoryEntryLocator) => Promise<void>
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
  const [history, setHistory] = useState<VaultPasswordHistoryView | null>(null)
  const [loading, setLoading] = useState(true)
  const [revealedValues, setRevealedValues] = useState<Record<string, string>>({})
  const [revealing, setRevealing] = useState<Record<string, boolean>>({})
  const [copying, setCopying] = useState<Record<string, boolean>>({})
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [error, setError] = useState('')
  const mountedRef = useRef(true)
  const loadRequestRef = useRef<Promise<VaultPasswordHistoryView> | null>(null)
  const revealTimersRef = useRef(new Map<string, number>())
  const copiedTimerRef = useRef<number | null>(null)

  const clearRevealTimer = useCallback((key: string): void => {
    const timer = revealTimersRef.current.get(key)
    if (timer !== undefined) window.clearTimeout(timer)
    revealTimersRef.current.delete(key)
  }, [])

  const clearSecrets = useCallback((): void => {
    for (const timer of revealTimersRef.current.values()) window.clearTimeout(timer)
    revealTimersRef.current.clear()
    setRevealedValues({})
  }, [])

  const loadHistory = useCallback(
    (retry = false): void => {
      if (retry) loadRequestRef.current = null
      setLoading(true)
      setError('')
      const request = loadRequestRef.current ?? onLoad()
      loadRequestRef.current = request
      void request
        .then((loaded) => {
          if (!mountedRef.current) return
          setHistory(loaded)
        })
        .catch(() => {
          if (!mountedRef.current) return
          setError('無法讀取密碼歷史，請再試一次。')
        })
        .finally(() => {
          if (mountedRef.current) setLoading(false)
        })
    },
    [onLoad]
  )

  useEffect(() => {
    mountedRef.current = true
    const revealTimers = revealTimersRef.current
    queueMicrotask(() => {
      if (mountedRef.current) loadHistory()
    })
    return () => {
      mountedRef.current = false
      for (const timer of revealTimers.values()) window.clearTimeout(timer)
      revealTimers.clear()
      if (copiedTimerRef.current !== null) window.clearTimeout(copiedTimerRef.current)
    }
  }, [loadHistory])

  const closeDialog = (): void => {
    clearSecrets()
    onClose()
  }

  const locatorFor = (index: number, lastUsedDate: string): PasswordHistoryEntryLocator => ({
    index,
    lastUsedDate,
    expectedUpdatedAt: history!.expectedUpdatedAt
  })

  const toggleReveal = async (index: number, lastUsedDate: string): Promise<void> => {
    const key = `${index}:${lastUsedDate}`
    if (revealedValues[key] !== undefined) {
      clearRevealTimer(key)
      setRevealedValues((current) => {
        const next = { ...current }
        delete next[key]
        return next
      })
      return
    }
    setRevealing((current) => ({ ...current, [key]: true }))
    setError('')
    try {
      const value = await onReveal(locatorFor(index, lastUsedDate))
      if (!mountedRef.current) return
      setRevealedValues((current) => ({ ...current, [key]: value }))
      clearRevealTimer(key)
      revealTimersRef.current.set(
        key,
        window.setTimeout(() => {
          revealTimersRef.current.delete(key)
          setRevealedValues((current) => {
            const next = { ...current }
            delete next[key]
            return next
          })
        }, 30_000)
      )
    } catch {
      if (mountedRef.current) setError('無法顯示這筆歷史，項目可能已在其他地方變更。')
    } finally {
      if (mountedRef.current) {
        setRevealing((current) => {
          const next = { ...current }
          delete next[key]
          return next
        })
      }
    }
  }

  const copyEntry = async (index: number, lastUsedDate: string): Promise<void> => {
    const key = `${index}:${lastUsedDate}`
    setCopying((current) => ({ ...current, [key]: true }))
    setError('')
    try {
      await onCopy(locatorFor(index, lastUsedDate))
      if (!mountedRef.current) return
      setCopiedKey(key)
      if (copiedTimerRef.current !== null) window.clearTimeout(copiedTimerRef.current)
      copiedTimerRef.current = window.setTimeout(() => {
        copiedTimerRef.current = null
        setCopiedKey(null)
      }, 2_000)
    } catch {
      if (mountedRef.current) setError('無法複製這筆歷史，項目可能已在其他地方變更。')
    } finally {
      if (mountedRef.current) {
        setCopying((current) => {
          const next = { ...current }
          delete next[key]
          return next
        })
      }
    }
  }

  return (
    <Modal
      title="密碼歷史"
      description={`「${itemName}」有 ${count} 筆歷史紀錄。`}
      onClose={closeDialog}
    >
      <div className="modal-body flex flex-col gap-3">
        {loading && (
          <div className="flex flex-col gap-2" role="status" aria-label="正在載入密碼歷史">
            {Array.from({ length: Math.min(Math.max(count, 1), 5) }, (_, index) => (
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
        )}
        {!loading && history && history.entries.length > 0 && (
          <ol className="scroll-fade-y forced-colors:scroll-fade-none flex max-h-[min(50vh,360px)] flex-col gap-2 overflow-y-auto p-px pr-1">
            {history.entries.map((entry, index) => {
              const key = `${index}:${entry.lastUsedDate}`
              const revealedValue = revealedValues[key]
              const isRevealed = revealedValue !== undefined
              const rowBusy = Boolean(revealing[key] || copying[key])
              return (
                <li key={key}>
                  <Card size="sm">
                    <CardHeader>
                      <CardTitle>{new Date(entry.lastUsedDate).toLocaleString('zh-TW')}</CardTitle>
                      <CardAction className="flex gap-1">
                        <PasswordHistoryIconButton
                          label={isRevealed ? '隱藏這筆歷史密碼' : '顯示這筆歷史密碼'}
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
                          label={copiedKey === key ? '已複製' : '複製這筆歷史密碼'}
                          disabled={rowBusy}
                          onClick={() => void copyEntry(index, entry.lastUsedDate)}
                        >
                          {copying[key] ? (
                            <Spinner aria-hidden="true" />
                          ) : copiedKey === key ? (
                            <Check aria-hidden="true" />
                          ) : (
                            <Copy aria-hidden="true" />
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
                            <code className="masked-value text-sm" aria-hidden="true">
                              ••••••••••••
                            </code>
                            <span className="sr-only">歷史密碼已遮蔽</span>
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
        {!loading && history && history.entries.length === 0 && (
          <Empty>
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <History aria-hidden="true" />
              </EmptyMedia>
              <EmptyTitle>沒有密碼歷史</EmptyTitle>
              <EmptyDescription>目前沒有可顯示的歷史紀錄。</EmptyDescription>
            </EmptyHeader>
          </Empty>
        )}
        {error && (
          <Alert variant="destructive">
            <AlertTriangle aria-hidden="true" />
            <AlertDescription>{error}</AlertDescription>
            {!history && !loading && (
              <AlertAction>
                <Button type="button" variant="outline" size="sm" onClick={() => loadHistory(true)}>
                  重新載入
                </Button>
              </AlertAction>
            )}
          </Alert>
        )}
      </div>
      <DialogFooter className="modal-actions mx-0 mb-0">
        <Button type="button" variant="secondary" onClick={closeDialog}>
          關閉
        </Button>
      </DialogFooter>
    </Modal>
  )
}
