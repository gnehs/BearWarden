import { useEffect, useRef, useState } from 'react'
import { ArchiveRestore, FileKey2, ShieldAlert } from 'lucide-react'
import type {
  NativeRestorePreviewResult,
  NativeRestoreProgress,
  NativeRestoreRunResult,
  VaultExportRequest,
  VaultExportResult,
  VaultImportRequest,
  VaultImportResult
} from '../../../shared/vault-contract'
import { Modal } from './Dialogs'
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import { Button } from '@renderer/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@renderer/components/ui/card'
import { DialogFooter } from '@renderer/components/ui/dialog'
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel
} from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import { NativeSelect, NativeSelectOption } from '@renderer/components/ui/native-select'
import { Progress, ProgressLabel, ProgressValue } from '@renderer/components/ui/progress'
import { Spinner } from '@renderer/components/ui/spinner'

export type VaultPortabilityMode = 'export' | 'import'
type ExportFormat = 'bitwarden-json' | 'bitwarden-zip' | 'bearwarden-native'
type ImportFormat = 'portable' | 'bearwarden-native'

interface VaultPortabilityDialogProps {
  mode: VaultPortabilityMode
  onClose: () => void
  onExport: (request: VaultExportRequest) => Promise<VaultExportResult>
  onImport: (request: VaultImportRequest) => Promise<VaultImportResult>
  onExported: (result: VaultExportResult) => void
  onImported: (result: VaultImportResult) => Promise<void>
}

function formatBackupBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function formatBackupCreatedAt(value: string): string {
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return '未知時間'
  return new Intl.DateTimeFormat('zh-TW', {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(date)
}

function VaultPortabilityDialog({
  mode,
  onClose,
  onExport,
  onImport,
  onExported,
  onImported
}: VaultPortabilityDialogProps): React.JSX.Element {
  const mountedRef = useRef(true)
  const submittingRef = useRef(false)
  const [masterPassword, setMasterPassword] = useState('')
  const [backupPassword, setBackupPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [exportFormat, setExportFormat] = useState<ExportFormat>('bitwarden-json')
  const [importFormat, setImportFormat] = useState<ImportFormat>('portable')
  const [preview, setPreview] = useState<Extract<
    NativeRestorePreviewResult,
    { canceled: false }
  > | null>(null)
  const [restoreResult, setRestoreResult] = useState<NativeRestoreRunResult | null>(null)
  const [progress, setProgress] = useState<NativeRestoreProgress | null>(null)
  const [confirmClear, setConfirmClear] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const scrubPasswords = (): void => {
    setMasterPassword('')
    setBackupPassword('')
    setConfirmPassword('')
  }

  useEffect(() => {
    mountedRef.current = true
    const sessionId = preview?.sessionId
    const unsubscribe = window.bearwarden.portability.onNativeRestoreProgress((next) => {
      if (mountedRef.current && sessionId && next.sessionId === sessionId) setProgress(next)
    })
    return () => {
      mountedRef.current = false
      unsubscribe()
    }
  }, [preview?.sessionId])

  const closeSafely = async (): Promise<void> => {
    const sessionId = preview?.sessionId
    scrubPasswords()
    if (sessionId && restoreResult?.state !== 'complete') {
      await window.bearwarden.portability.cancelNativeRestore({ sessionId }).catch(() => undefined)
    }
    onClose()
  }

  async function submit(event: React.FormEvent<HTMLFormElement>, close: () => void): Promise<void> {
    event.preventDefault()
    if (busy || submittingRef.current) return
    const nativeImport = mode === 'import' && importFormat === 'bearwarden-native'
    const plaintextZip = mode === 'export' && exportFormat === 'bitwarden-zip'
    if (!nativeImport && !masterPassword) {
      setError('請輸入目前的主密碼。')
      return
    }
    if (((mode === 'export' && !plaintextZip) || nativeImport) && backupPassword.length < 12) {
      setError('備份密碼至少需要 12 個字元。')
      return
    }
    if (mode === 'export' && !plaintextZip && backupPassword !== confirmPassword) {
      setError('兩次輸入的備份密碼不一致。')
      return
    }

    setError('')
    setBusy(true)
    submittingRef.current = true
    try {
      if (mode === 'export') {
        const exportRequest: VaultExportRequest = plaintextZip
          ? { masterPassword, format: 'bitwarden-zip' }
          : {
              masterPassword,
              password: backupPassword,
              format: exportFormat === 'bearwarden-native' ? 'bearwarden-native' : 'bitwarden-json'
            }
        const result = await onExport(exportRequest)
        scrubPasswords()
        if (result.canceled) return
        onExported(result)
        close()
      } else if (!nativeImport) {
        const result = await onImport({
          masterPassword,
          ...(backupPassword ? { password: backupPassword } : {})
        })
        scrubPasswords()
        if (result.canceled) return
        await onImported(result)
        close()
      } else if (!preview) {
        const result = await window.bearwarden.portability.previewNativeRestore({
          password: backupPassword
        })
        setBackupPassword('')
        if (!result.canceled) setPreview(result)
      } else {
        if (!masterPassword) {
          setError('請輸入目前的主密碼，確認要還原到這個保管庫。')
          return
        }
        const result = await window.bearwarden.portability.startNativeRestore({
          sessionId: preview.sessionId,
          masterPassword
        })
        setMasterPassword('')
        setRestoreResult(result)
        if (result.state === 'complete') {
          await onImported({
            canceled: false,
            importedFolders: 0,
            importedItems: result.summary.totalItems,
            skippedTrashItems: 0
          }).catch(() => undefined)
        }
      }
    } catch (portabilityFailure) {
      scrubPasswords()
      if (mountedRef.current) {
        setError(
          mode === 'export'
            ? plaintextZip &&
              portabilityFailure instanceof Error &&
              portabilityFailure.message.includes('EXPORT_RESULT_UNKNOWN')
              ? 'ZIP 是否已完整寫入無法確認。請先檢查剛才選擇的儲存位置；若檔案存在，它包含未加密的密碼與附件，確認前請勿直接重試。'
              : plaintextZip
                ? '無法建立 ZIP。請確認主密碼、儲存位置與附件狀態後再試一次。'
                : '無法建立備份。請確認主密碼、儲存位置與備份密碼後再試一次。'
            : nativeImport
              ? '還原未完成。若顯示衝突，請先確認伺服器上的同名附件；進度已安全保留，可重新選取同一份備份續傳。'
              : '無法匯入檔案。請確認主密碼、檔案格式與備份密碼後再試一次。'
        )
      }
    } finally {
      submittingRef.current = false
      if (mountedRef.current) setBusy(false)
    }
  }

  const clearCompleted = async (): Promise<void> => {
    if (!preview || !confirmClear || busy) return
    setBusy(true)
    try {
      await window.bearwarden.portability.clearCompletedNativeRestore({
        sessionId: preview.sessionId
      })
      scrubPasswords()
      onClose()
    } catch {
      setError('無法清除完成紀錄；備份資料本身沒有被刪除。')
    } finally {
      if (mountedRef.current) setBusy(false)
    }
  }

  const exporting = mode === 'export'
  const plaintextZip = exporting && exportFormat === 'bitwarden-zip'
  const nativeImport = !exporting && importFormat === 'bearwarden-native'
  const completed = restoreResult?.state === 'complete'
  const progressPercent = progress?.totalBytes
    ? Math.min(100, Math.round((progress.completedBytes / progress.totalBytes) * 100))
    : progress?.phase === 'complete'
      ? 100
      : 0

  return (
    <Modal
      title={
        exporting
          ? plaintextZip
            ? '匯出 Bitwarden 附件 ZIP'
            : '匯出加密備份'
          : nativeImport
            ? '還原完整備份'
            : '匯入密碼資料'
      }
      description={
        exporting
          ? plaintextZip
            ? '建立可由 Bitwarden 相容工具解壓使用的個人保管庫與附件明文副本。'
            : '建立受密碼保護的可攜備份。'
          : nativeImport
            ? '從 BearWarden 完整備份還原項目與附件，可在中斷後安全續傳。'
            : '將 Bitwarden JSON、Bitwarden CSV 或 Chrome／Chromium 密碼 CSV 加入目前的保管庫。既有項目不會被覆蓋。'
      }
      busy={busy && !(nativeImport && preview && !completed)}
      onClose={() => void closeSafely()}
    >
      {(close) => (
        <form onSubmit={(event) => void submit(event, close)}>
          <div className="modal-body flex flex-col gap-4">
            {!preview && (
              <Field data-disabled={busy || undefined}>
                <FieldLabel htmlFor="portability-format">備份格式</FieldLabel>
                <NativeSelect
                  id="portability-format"
                  className="w-full"
                  disabled={busy}
                  value={exporting ? exportFormat : importFormat}
                  onChange={(event) => {
                    setError('')
                    if (exporting) {
                      setExportFormat(event.target.value as ExportFormat)
                      setBackupPassword('')
                      setConfirmPassword('')
                    } else setImportFormat(event.target.value as ImportFormat)
                  }}
                >
                  {exporting ? (
                    <>
                      <NativeSelectOption value="bitwarden-json">
                        Bitwarden 密碼保護 JSON
                      </NativeSelectOption>
                      <NativeSelectOption value="bitwarden-zip">
                        Bitwarden 明文 ZIP（含附件）
                      </NativeSelectOption>
                      <NativeSelectOption value="bearwarden-native">
                        BearWarden 完整備份（含附件）
                      </NativeSelectOption>
                    </>
                  ) : (
                    <>
                      <NativeSelectOption value="portable">
                        Bitwarden JSON／CSV 或 Chrome CSV
                      </NativeSelectOption>
                      <NativeSelectOption value="bearwarden-native">
                        BearWarden 完整備份（.bwbackup）
                      </NativeSelectOption>
                    </>
                  )}
                </NativeSelect>
              </Field>
            )}

            <Alert>
              {nativeImport ? (
                <ArchiveRestore aria-hidden="true" />
              ) : exporting && !plaintextZip ? (
                <FileKey2 aria-hidden="true" />
              ) : (
                <ShieldAlert aria-hidden="true" />
              )}
              <AlertTitle>
                {plaintextZip
                  ? 'ZIP 內的密碼與附件都是未加密明文'
                  : exporting && exportFormat === 'bearwarden-native'
                    ? '完整備份不是 Bitwarden 相容格式'
                    : nativeImport
                      ? '可安全續傳，但不會自動解決伺服器衝突'
                      : exporting
                        ? '請妥善保存備份密碼'
                        : '匯入不會自動去除重複項目'}
              </AlertTitle>
              <AlertDescription>
                {plaintextZip
                  ? '只應儲存在受信任的加密磁碟，使用後請安全刪除。格式對齊 Bitwarden 個人保管庫 ZIP 匯出；官方目前不支援把附件 ZIP 批次匯入，因此 BearWarden 不宣稱可用它無損還原附件。垃圾桶與 Sends 不包含在內。'
                  : exporting && exportFormat === 'bearwarden-native'
                    ? '加密的 .bwbackup 會包含個人項目與附件，只能由支援此格式的 BearWarden 還原；Bitwarden 官方客戶端無法直接匯入。垃圾桶與 Sends 不包含在內。'
                    : nativeImport
                      ? '若上傳結果不明，BearWarden 會先比對伺服器附件的完整內容；只有確認不存在時才重試。取消只會停止本次工作，不會丟失續傳進度。'
                      : exporting
                        ? '垃圾桶、附件與 Sends 不會包含在 Bitwarden JSON 中；忘記備份密碼後將無法解密。'
                        : '所有項目都會以新識別碼加入。JSON 垃圾桶項目會略過，CSV 不包含附件或 Passkey。'}
              </AlertDescription>
            </Alert>

            {preview && (
              <Card size="sm">
                <CardHeader>
                  <CardTitle>備份內容</CardTitle>
                </CardHeader>
                <CardContent>
                  <dl className="grid grid-cols-2 gap-3">
                    <div>
                      <dt className="text-muted-foreground">建立時間</dt>
                      <dd>{formatBackupCreatedAt(preview.createdAt)}</dd>
                    </div>
                    <div>
                      <dt className="text-muted-foreground">附件大小</dt>
                      <dd>{formatBackupBytes(preview.attachmentBytes)}</dd>
                    </div>
                    <div>
                      <dt className="text-muted-foreground">資料夾</dt>
                      <dd>{preview.folderCount}</dd>
                    </div>
                    <div>
                      <dt className="text-muted-foreground">項目／附件</dt>
                      <dd>
                        {preview.itemCount}／{preview.attachmentCount}
                      </dd>
                    </div>
                  </dl>
                </CardContent>
              </Card>
            )}

            {progress && (
              <Progress value={progressPercent}>
                <ProgressLabel>
                  {progress.state === 'conflict'
                    ? '需要處理衝突'
                    : progress.state === 'partial'
                      ? '部分完成，可稍後續傳'
                      : progress.state === 'complete'
                        ? '還原完成'
                        : '正在還原附件'}
                </ProgressLabel>
                <ProgressValue>
                  {() => `${progress.uploadedAttachments} / ${progress.totalAttachments}`}
                </ProgressValue>
              </Progress>
            )}

            {restoreResult?.state === 'conflict' && (
              <FieldError>
                伺服器上有多個同名附件，或內容無法確認。為避免重複上傳，BearWarden
                已停止並保留進度。
              </FieldError>
            )}
            {restoreResult?.state === 'partial' && (
              <FieldError>
                本次未能完成所有附件。請重新選取同一份備份與輸入備份密碼，即可從保留的進度繼續。
              </FieldError>
            )}

            {!completed && (
              <FieldGroup>
                {(!nativeImport || preview) && (
                  <Field>
                    <FieldLabel htmlFor="portability-master-password">目前的主密碼</FieldLabel>
                    <Input
                      id="portability-master-password"
                      type="password"
                      autoComplete="current-password"
                      autoFocus
                      value={masterPassword}
                      disabled={busy}
                      maxLength={1024}
                      onChange={(event) => setMasterPassword(event.target.value)}
                    />
                    <FieldDescription>
                      {nativeImport
                        ? '預覽後需要新的本機擁有者驗證，才會開始同步與還原。'
                        : '只會送到本機主程序確認保管庫擁有者。'}
                    </FieldDescription>
                  </Field>
                )}
                {!preview && !plaintextZip && (
                  <Field>
                    <FieldLabel htmlFor="portability-backup-password">
                      {exporting
                        ? '新的備份密碼'
                        : nativeImport
                          ? '完整備份密碼'
                          : '備份密碼（選填）'}
                    </FieldLabel>
                    <Input
                      id="portability-backup-password"
                      type="password"
                      autoComplete="new-password"
                      value={backupPassword}
                      disabled={busy}
                      maxLength={1024}
                      onChange={(event) => setBackupPassword(event.target.value)}
                    />
                    <FieldDescription>
                      {exporting || nativeImport
                        ? '至少 12 個字元，只會交給本機主程序加解密。'
                        : '密碼保護的 JSON 需要填寫；未加密 JSON 或 CSV 請留空。'}
                    </FieldDescription>
                  </Field>
                )}
                {exporting && !plaintextZip && (
                  <Field>
                    <FieldLabel htmlFor="portability-confirm-password">再次輸入備份密碼</FieldLabel>
                    <Input
                      id="portability-confirm-password"
                      type="password"
                      autoComplete="new-password"
                      value={confirmPassword}
                      disabled={busy}
                      maxLength={1024}
                      onChange={(event) => setConfirmPassword(event.target.value)}
                    />
                  </Field>
                )}
                {error && <FieldError>{error}</FieldError>}
              </FieldGroup>
            )}

            {completed && (
              <Alert>
                <ArchiveRestore aria-hidden="true" />
                <AlertTitle>完整備份已還原</AlertTitle>
                <AlertDescription>
                  已還原 {restoreResult.summary.totalItems} 個項目與{' '}
                  {restoreResult.summary.uploadedAttachments}{' '}
                  個附件。請確認後清除完成紀錄；這不會刪除備份檔案。
                </AlertDescription>
              </Alert>
            )}
          </div>

          <DialogFooter className="modal-actions mx-0 mb-0">
            <Button
              variant="secondary"
              type="button"
              disabled={busy && !(nativeImport && preview && !completed)}
              onClick={() => void closeSafely()}
            >
              {busy && nativeImport && preview ? '停止並保留進度' : '取消'}
            </Button>
            {completed ? (
              confirmClear ? (
                <Button type="button" disabled={busy} onClick={() => void clearCompleted()}>
                  {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}確認清除完成紀錄
                </Button>
              ) : (
                <Button type="button" onClick={() => setConfirmClear(true)}>
                  完成並清除續傳紀錄
                </Button>
              )
            ) : (
              <Button
                type="submit"
                disabled={
                  busy ||
                  (!nativeImport && !masterPassword) ||
                  (((exporting && !plaintextZip) || nativeImport) &&
                    !preview &&
                    backupPassword.length < 12) ||
                  (exporting && !plaintextZip && backupPassword !== confirmPassword)
                }
              >
                {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                {exporting
                  ? '選擇儲存位置'
                  : nativeImport
                    ? preview
                      ? restoreResult
                        ? restoreResult.state === 'conflict'
                          ? '重新檢查衝突'
                          : '繼續還原'
                        : '確認並開始還原'
                      : '選擇完整備份'
                    : '選擇並匯入檔案'}
              </Button>
            )}
          </DialogFooter>
        </form>
      )}
    </Modal>
  )
}

export default VaultPortabilityDialog
