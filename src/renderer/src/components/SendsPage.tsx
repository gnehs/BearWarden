import { Download, FilePlus, FileText, Pencil, Plus, Save, Trash2 } from 'lucide-react'
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
  CardFooter,
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
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import { Spinner } from '@renderer/components/ui/spinner'
import { Textarea } from '@renderer/components/ui/textarea'
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
import AuxiliaryPageLayout, { AuxiliaryPageContent } from './AuxiliaryPageLayout'
import { CopyFeedbackIcon } from './CopyFeedbackIcon'
import FeatureUnderConstructionNotice from './FeatureUnderConstructionNotice'

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

function draftFromSend(send: SendView): SendCreateRequest {
  if (send.type !== 'text') {
    throw new Error('File Sends are read-only until file transfer support is enabled')
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

function SendsPage(): React.JSX.Element {
  const [sends, setSends] = useState<SendView[]>([])
  const { copiedKey, clearCopied, showCopied } = useCopyFeedback()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [draft, setDraft] = useState<SendCreateRequest>(emptyDraft)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<SendView | null>(null)

  const selected = sends.find((send) => send.id === selectedId) ?? null

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
        setLoading(false)
        toast.error('無法載入 Sends')
      }
    )
    return () => {
      active = false
    }
  }, [])

  function startCreate(): void {
    setSelectedId(null)
    setDraft({ ...emptyDraft })
  }

  function startEdit(send: SendView): void {
    if (send.type !== 'text') {
      toast.info('檔案 Send 目前只能查看與複製連結')
      return
    }
    setSelectedId(send.id)
    setDraft(draftFromSend(send))
  }

  async function save(): Promise<void> {
    if (draft.name.trim().length === 0 || draft.text.length === 0) {
      toast.error('請填寫 Send 名稱與內容')
      return
    }
    if (selected?.type === 'file') {
      toast.info('檔案 Send 編輯功能尚未開放')
      return
    }
    setBusy(true)
    try {
      const saved = selected
        ? await window.bearwarden.sends.update({ ...draft, id: selected.id })
        : await window.bearwarden.sends.create(draft)
      setSends((current) => [saved, ...current.filter((send) => send.id !== saved.id)])
      setSelectedId(saved.id)
      setDraft(draftFromSend(saved))
      toast.success(selected ? 'Send 已更新' : 'Send 已建立')
    } catch {
      toast.error('Send 儲存失敗，請確認同步已連線')
    } finally {
      setBusy(false)
    }
  }

  async function createFile(): Promise<void> {
    const name = draft.name.trim()
    if (name.length === 0) {
      toast.error('請先填寫 Send 名稱')
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
      toast.success('檔案 Send 已建立')
    } catch {
      toast.error('檔案 Send 建立失敗，請確認同步已連線')
    } finally {
      setBusy(false)
    }
  }

  async function remove(send: SendView): Promise<void> {
    setBusy(true)
    try {
      await window.bearwarden.sends.delete({ id: send.id })
      setSends((current) => current.filter((entry) => entry.id !== send.id))
      if (selectedId === send.id) startCreate()
      toast.success('Send 已刪除')
    } catch {
      toast.error('Send 刪除失敗')
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
      toast.error('無法複製分享連結')
    }
  }

  async function downloadFile(send: SendView): Promise<void> {
    if (send.type !== 'file') return
    let password: string | null = null
    if (send.passwordProtected) {
      password = window.prompt('請輸入 Send 存取密碼')
      if (password === null) return
    }
    setBusy(true)
    try {
      const result = await window.bearwarden.sends.downloadFile({ id: send.id, password })
      if (!result.canceled) toast.success(`已儲存 ${result.fileName}`)
    } catch {
      toast.error('檔案 Send 下載失敗，請確認密碼與同步連線')
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
      setDraft(draftFromSend(saved))
      toast.success('Send 密碼已移除')
    } catch {
      toast.error('Send 密碼移除失敗')
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuxiliaryPageLayout
      eyebrow="Bitwarden Send"
      title="Sends"
      titleId="sends-title"
      subtitle="文字與檔案 Send 都會先在主程序解密 metadata。"
      headerActions={
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" type="button" onClick={() => void createFile()} disabled={busy}>
            <FilePlus data-icon="inline-start" />
            建立檔案 Send
          </Button>
          <Button type="button" onClick={startCreate} disabled={busy}>
            <Plus data-icon="inline-start" />
            新增文字 Send
          </Button>
        </div>
      }
    >
      <FeatureUnderConstructionNotice>
        文字與檔案 Send 的主要流程已可使用；檔案編輯、進階驗證與完整公開接收流程仍在開發中。
      </FeatureUnderConstructionNotice>
      {loading ? (
        <div className="flex items-center justify-center gap-2 py-16" role="status">
          <Spinner />
          載入 Sends…
        </div>
      ) : (
        <AuxiliaryPageContent>
          <main className="col-start-2 flex min-w-0 flex-col gap-4 max-[880px]:col-start-1">
            {sends.length === 0 ? (
              <Empty>
                <EmptyHeader>
                  <EmptyTitle>還沒有 Send</EmptyTitle>
                  <EmptyDescription>建立文字 Send，安全地分享一次性內容。</EmptyDescription>
                </EmptyHeader>
                <EmptyContent>
                  <Button type="button" onClick={startCreate}>
                    <Plus data-icon="inline-start" />
                    建立第一個 Send
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
                    <CardTitle className="flex items-center gap-2">
                      {send.type === 'file' && <FileText aria-hidden="true" />}
                      {send.name}
                      {send.disabled && <Badge variant="outline">已停用</Badge>}
                    </CardTitle>
                    <CardDescription>
                      {send.accessCount} 次存取
                      {send.maxAccessCount ? `／上限 ${send.maxAccessCount}` : ''}
                      {send.passwordProtected ? ' · 需要密碼' : ' · 無密碼'}
                    </CardDescription>
                    <CardAction className="flex gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        type="button"
                        onClick={() => void copyLink(send)}
                        aria-label={copiedKey === send.id ? '分享連結已複製' : '複製分享連結'}
                      >
                        <CopyFeedbackIcon copied={copiedKey === send.id} />
                      </Button>
                      {send.type === 'file' && (
                        <Button
                          variant="ghost"
                          size="icon"
                          type="button"
                          onClick={() => void downloadFile(send)}
                          aria-label="下載檔案 Send"
                          disabled={busy}
                        >
                          <Download />
                        </Button>
                      )}
                      <Button
                        variant="ghost"
                        size="icon"
                        type="button"
                        onClick={() => startEdit(send)}
                        aria-label="編輯 Send"
                        disabled={send.type === 'file'}
                      >
                        <Pencil />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        type="button"
                        onClick={() => setDeleteTarget(send)}
                        aria-label="刪除 Send"
                      >
                        <Trash2 />
                      </Button>
                    </CardAction>
                  </CardHeader>
                  <CardContent>
                    {send.type === 'file' && send.file ? (
                      <div className="text-muted-foreground flex items-center gap-2 text-sm">
                        <FileText aria-hidden="true" />
                        <span className="truncate">{send.file.fileName}</span>
                        <span className="shrink-0">
                          {send.file.sizeName ?? `${send.file.size} bytes`}
                        </span>
                      </div>
                    ) : (
                      <p className="text-muted-foreground line-clamp-3 text-sm whitespace-pre-wrap">
                        {send.text}
                      </p>
                    )}
                  </CardContent>
                </Card>
              ))
            )}
          </main>

          <aside className="col-start-2 flex min-w-0 flex-col gap-[18px] max-[880px]:col-start-1">
            <Card>
              <CardHeader>
                <CardTitle>{selected ? '編輯 Send' : '新增 Send'}</CardTitle>
                <CardDescription>內容在主程序加密後才會送往伺服器。</CardDescription>
              </CardHeader>
              <CardContent>
                <FieldGroup>
                  <Field>
                    <FieldLabel htmlFor="send-name">名稱</FieldLabel>
                    <Input
                      id="send-name"
                      value={draft.name}
                      onChange={(event) => setDraft({ ...draft, name: event.target.value })}
                    />
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="send-text">內容</FieldLabel>
                    <Textarea
                      id="send-text"
                      rows={8}
                      value={draft.text}
                      onChange={(event) => setDraft({ ...draft, text: event.target.value })}
                    />
                    <FieldDescription>文字內容不會加入分享連結。</FieldDescription>
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="send-password">
                      存取密碼（{selected ? '留空維持現有密碼' : '選填'}）
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
                        移除現有密碼
                      </Button>
                    )}
                  </Field>
                </FieldGroup>
              </CardContent>
              <CardFooter className="flex gap-2">
                <Button type="button" onClick={() => void save()} disabled={busy}>
                  <Save data-icon="inline-start" />
                  {busy ? '儲存中…' : '儲存'}
                </Button>
                <Button variant="outline" type="button" onClick={startCreate} disabled={busy}>
                  清除
                </Button>
              </CardFooter>
            </Card>
          </aside>
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
            <AlertDialogTitle>刪除這個 Send？</AlertDialogTitle>
            <AlertDialogDescription>
              「{deleteTarget?.name ?? ''}」會從 Vaultwarden 移除，且無法從垃圾桶還原。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>取消</AlertDialogCancel>
            <AlertDialogAction
              disabled={busy || deleteTarget === null}
              onClick={(event) => {
                event.preventDefault()
                const target = deleteTarget
                if (!target) return
                void remove(target).finally(() => setDeleteTarget(null))
              }}
            >
              刪除
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </AuxiliaryPageLayout>
  )
}

export default SendsPage
