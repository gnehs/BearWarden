import { useEffect, useRef, useState } from 'react'
import { FileKey2, ShieldAlert } from 'lucide-react'
import type {
  VaultExportRequest,
  VaultExportResult,
  VaultImportRequest,
  VaultImportResult
} from '../../../shared/vault-contract'
import { Modal } from './Dialogs'
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import { Button } from '@renderer/components/ui/button'
import { DialogClose, DialogFooter } from '@renderer/components/ui/dialog'
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel
} from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import { Spinner } from '@renderer/components/ui/spinner'

export type VaultPortabilityMode = 'export' | 'import'

interface VaultPortabilityDialogProps {
  mode: VaultPortabilityMode
  onClose: () => void
  onExport: (request: VaultExportRequest) => Promise<VaultExportResult>
  onImport: (request: VaultImportRequest) => Promise<VaultImportResult>
  onExported: (result: VaultExportResult) => void
  onImported: (result: VaultImportResult) => Promise<void>
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
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
    }
  }, [])

  async function submit(event: React.FormEvent<HTMLFormElement>, close: () => void): Promise<void> {
    event.preventDefault()
    if (busy || submittingRef.current) return
    if (!masterPassword) {
      setError('請輸入目前的主密碼。')
      return
    }
    if (mode === 'export' && backupPassword.length < 12) {
      setError('備份密碼至少需要 12 個字元。')
      return
    }
    if (mode === 'export' && backupPassword !== confirmPassword) {
      setError('兩次輸入的備份密碼不一致。')
      return
    }

    setError('')
    setBusy(true)
    submittingRef.current = true
    try {
      if (mode === 'export') {
        const result = await onExport({ masterPassword, password: backupPassword })
        if (result.canceled) return
        onExported(result)
      } else {
        const result = await onImport({
          masterPassword,
          ...(backupPassword ? { password: backupPassword } : {})
        })
        if (result.canceled) return
        await onImported(result)
      }
      close()
    } catch {
      if (mountedRef.current) {
        setError(
          mode === 'export'
            ? '無法建立備份。請確認主密碼、儲存位置與備份密碼後再試一次。'
            : '無法匯入檔案。請確認主密碼、檔案格式與備份密碼後再試一次。'
        )
      }
    } finally {
      submittingRef.current = false
      if (mountedRef.current) setBusy(false)
    }
  }

  const exporting = mode === 'export'

  return (
    <Modal
      title={exporting ? '匯出加密備份' : '匯入 Bitwarden JSON'}
      description={
        exporting
          ? '建立可攜、受密碼保護的 Bitwarden JSON 備份。'
          : '將 Bitwarden JSON 加入目前的保管庫。既有項目不會被覆蓋。'
      }
      busy={busy}
      onClose={onClose}
    >
      {(close) => (
        <form onSubmit={(event) => void submit(event, close)}>
          <div className="modal-body">
            <Alert>
              {exporting ? <FileKey2 aria-hidden="true" /> : <ShieldAlert aria-hidden="true" />}
              <AlertTitle>
                {exporting ? '請妥善保存備份密碼' : '匯入不會自動去除重複項目'}
              </AlertTitle>
              <AlertDescription>
                {exporting
                  ? '垃圾桶、附件與 Sends 不會包含在這份備份中；忘記備份密碼後將無法解密。'
                  : '所有項目都會以新識別碼加入。支援密碼保護或未加密的 Bitwarden JSON；垃圾桶項目會略過。'}
              </AlertDescription>
            </Alert>

            <FieldGroup>
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
                <FieldDescription>只會送到本機主程序確認保管庫擁有者。</FieldDescription>
              </Field>

              <Field>
                <FieldLabel htmlFor="portability-backup-password">
                  {exporting ? '新的備份密碼' : '備份密碼（選填）'}
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
                  {exporting
                    ? '至少 12 個字元，且可以和主密碼不同。'
                    : '密碼保護的匯出檔需要填寫；未加密 JSON 請留空。'}
                </FieldDescription>
              </Field>

              {exporting && (
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
          </div>

          <DialogFooter className="modal-actions mx-0 mb-0">
            <DialogClose render={<Button variant="secondary" type="button" disabled={busy} />}>
              取消
            </DialogClose>
            <Button
              type="submit"
              disabled={
                busy ||
                !masterPassword ||
                (exporting && (backupPassword.length < 12 || backupPassword !== confirmPassword))
              }
            >
              {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
              {exporting ? '選擇儲存位置' : '選擇並匯入檔案'}
            </Button>
          </DialogFooter>
        </form>
      )}
    </Modal>
  )
}

export default VaultPortabilityDialog
