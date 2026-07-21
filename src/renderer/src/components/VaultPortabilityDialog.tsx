import { useEffect, useRef, useState } from 'react'
import { ArchiveRestore, FileKey2, ShieldAlert } from 'lucide-react'
import { Plural, Trans, useLingui } from '@lingui/react/macro'
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
import { ModalBody, ModalFooter } from './ModalLayout'
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import { Button } from '@renderer/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@renderer/components/ui/card'
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
import { createVaultImportRequest, executeVaultExport } from '../lib/vault-portability-ui'

export type VaultPortabilityMode = 'export' | 'import'
type ExportFormat = 'bitwarden-json' | 'bitwarden-csv' | 'bitwarden-zip' | 'bearwarden-native'
type ImportFormat = 'portable' | 'keepass-xml' | 'bearwarden-native'

interface VaultPortabilityDialogProps {
  mode: VaultPortabilityMode
  onClose: () => void
  onExport: (request: VaultExportRequest) => Promise<VaultExportResult>
  onImport: (request: VaultImportRequest) => Promise<VaultImportResult>
  onExported: (result: VaultExportResult) => void
  onImported: (result: VaultImportResult) => Promise<void>
}

function FormattedBackupBytes({ bytes }: { bytes: number }): React.JSX.Element {
  const { i18n } = useLingui()
  const normalizedBytes = Number.isFinite(bytes) && bytes >= 0 ? bytes : 0

  if (normalizedBytes < 1024) {
    const formattedBytes = new Intl.NumberFormat(i18n.locale).format(normalizedBytes)
    return <Trans>{formattedBytes} B</Trans>
  }

  const formatter = new Intl.NumberFormat(i18n.locale, {
    minimumFractionDigits: 1,
    maximumFractionDigits: 1
  })
  if (normalizedBytes < 1024 * 1024) {
    const formattedKilobytes = formatter.format(normalizedBytes / 1024)
    return <Trans>{formattedKilobytes} KB</Trans>
  }

  const formattedMegabytes = formatter.format(normalizedBytes / 1024 / 1024)
  return <Trans>{formattedMegabytes} MB</Trans>
}

function formatBackupCreatedAt(value: string, locale: string): string | null {
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return null
  return new Intl.DateTimeFormat(locale, {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(date)
}

export function VaultCsvExportWarning(): React.JSX.Element {
  return (
    <Trans>
      CSV is not a complete backup. It only exports active and archived logins, secure notes, and
      some text values. It does not include trash, attachments, cards, identities, SSH keys,
      passkeys, password history, or Sends. URI matching and some login metadata are lost. Custom
      fields are flattened into “name: value” text, so their types and original structure may not be
      recoverable when names are empty or contain line breaks or “: ”. Use encrypted JSON for more
      complete portable data, or a full BearWarden backup to include attachments. Only inspect CSV
      files in a text editor. If opened in a spreadsheet, original fields beginning with =, +, -, or
      @ may execute as formulas. To preserve Bitwarden compatibility and data fidelity, BearWarden
      does not rewrite these secrets.
    </Trans>
  )
}

export function VaultKeePassXmlImportWarning(): React.JSX.Element {
  return (
    <Trans>
      KeePass 2 XML is unencrypted plaintext containing directly readable passwords. Only open it
      from a trusted encrypted drive, and securely delete it after importing. BearWarden imports
      personal entries only and flattens nested groups into folder paths. Attachment binaries,
      history revisions, and advanced metadata are not imported, and recycle-bin and template groups
      are skipped. Modern KeePass TimeOtp fields are converted into a code-generating format. If the
      secret, encoding, or parameters conflict or cannot be converted, the entire import stops
      instead of silently skipping the authenticator.
    </Trans>
  )
}

function VaultPortabilityDialog({
  mode,
  onClose,
  onExport,
  onImport,
  onExported,
  onImported
}: VaultPortabilityDialogProps): React.JSX.Element {
  const { i18n, t } = useLingui()
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
    const keepassImport = mode === 'import' && importFormat === 'keepass-xml'
    const plaintextZip = mode === 'export' && exportFormat === 'bitwarden-zip'
    const plaintextCsv = mode === 'export' && exportFormat === 'bitwarden-csv'
    const passwordlessExport = plaintextZip || plaintextCsv
    if (!nativeImport && !masterPassword) {
      setError(t`Enter your current master password.`)
      return
    }
    if (
      ((mode === 'export' && !passwordlessExport) || nativeImport) &&
      backupPassword.length < 12
    ) {
      setError(t`The backup password must be at least 12 characters.`)
      return
    }
    if (mode === 'export' && !passwordlessExport && backupPassword !== confirmPassword) {
      setError(t`The backup passwords do not match.`)
      return
    }

    setError('')
    setBusy(true)
    submittingRef.current = true
    try {
      if (mode === 'export') {
        const exportRequest: VaultExportRequest = passwordlessExport
          ? { masterPassword, format: plaintextZip ? 'bitwarden-zip' : 'bitwarden-csv' }
          : {
              masterPassword,
              password: backupPassword,
              format: exportFormat === 'bearwarden-native' ? 'bearwarden-native' : 'bitwarden-json'
            }
        const result = await executeVaultExport(exportRequest, onExport)
        scrubPasswords()
        if (result.canceled) return
        onExported(result)
        close()
      } else if (!nativeImport) {
        const result = await onImport(
          createVaultImportRequest(masterPassword, backupPassword, keepassImport)
        )
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
          setError(t`Enter your current master password to confirm restoring to this vault.`)
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
              ? t`It is unclear whether the ZIP was written completely. Check the save location you just selected before retrying. If the file exists, it contains unencrypted passwords and attachments.`
              : plaintextZip
                ? t`Could not create the ZIP. Check the master password, save location, and attachment status, then try again.`
                : plaintextCsv
                  ? t`Could not create the CSV. Check the master password and save location, then try again.`
                  : t`Could not create the backup. Check the master password, save location, and backup password, then try again.`
            : nativeImport
              ? t`The restore did not finish. If a conflict is shown, check attachments with the same name on the server. Progress was saved safely; select the same backup again to resume.`
              : keepassImport
                ? t`Could not import the KeePass XML. Check the master password and make sure the file is a complete XML export from KeePass 2.`
                : t`Could not import the file. Check the master password, file format, and backup password, then try again.`
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
      setError(t`Could not clear the completion record. The backup data itself was not deleted.`)
    } finally {
      if (mountedRef.current) setBusy(false)
    }
  }

  const exporting = mode === 'export'
  const plaintextZip = exporting && exportFormat === 'bitwarden-zip'
  const plaintextCsv = exporting && exportFormat === 'bitwarden-csv'
  const passwordlessExport = plaintextZip || plaintextCsv
  const nativeImport = !exporting && importFormat === 'bearwarden-native'
  const keepassImport = !exporting && importFormat === 'keepass-xml'
  const completed = restoreResult?.state === 'complete'
  const progressPercent = progress?.totalBytes
    ? Math.min(100, Math.round((progress.completedBytes / progress.totalBytes) * 100))
    : progress?.phase === 'complete'
      ? 100
      : 0
  const numberFormatter = new Intl.NumberFormat(i18n.locale)
  const backupCreatedAt = preview ? formatBackupCreatedAt(preview.createdAt, i18n.locale) : null
  const formattedItemCount = numberFormatter.format(preview?.itemCount ?? 0)
  const formattedAttachmentCount = numberFormatter.format(preview?.attachmentCount ?? 0)
  const formattedUploadedAttachments = numberFormatter.format(progress?.uploadedAttachments ?? 0)
  const formattedTotalAttachments = numberFormatter.format(progress?.totalAttachments ?? 0)
  const restoredItemCount = restoreResult?.summary.totalItems ?? 0
  const restoredAttachmentCount = restoreResult?.summary.uploadedAttachments ?? 0

  return (
    <Modal
      title={
        exporting
          ? plaintextZip
            ? t`Export Bitwarden attachment ZIP`
            : plaintextCsv
              ? t`Export Bitwarden CSV`
              : t`Export encrypted backup`
          : nativeImport
            ? t`Restore full backup`
            : t`Import password data`
      }
      description={
        exporting
          ? plaintextZip
            ? t`Create a plaintext copy of your personal vault and attachments that Bitwarden-compatible tools can extract.`
            : plaintextCsv
              ? t`Create a plaintext copy of logins and secure notes that can be imported into Bitwarden.`
              : t`Create a password-protected portable backup.`
          : nativeImport
            ? t`Restore items and attachments from a full BearWarden backup, with safe resuming after interruptions.`
            : keepassImport
              ? t`Add entries from a plaintext KeePass 2 XML export to the current vault. Existing items are not overwritten.`
              : t`Add a Bitwarden JSON, Bitwarden CSV, or Chrome/Chromium password CSV to the current vault. Existing items are not overwritten.`
      }
      busy={busy && !(nativeImport && preview && !completed)}
      onClose={() => void closeSafely()}
    >
      {(close) => (
        <form onSubmit={(event) => void submit(event, close)}>
          <ModalBody className="flex flex-col gap-4">
            {!preview && (
              <Field data-disabled={busy || undefined}>
                <FieldLabel htmlFor="portability-format">
                  <Trans>Backup format</Trans>
                </FieldLabel>
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
                    } else {
                      setImportFormat(event.target.value as ImportFormat)
                      setBackupPassword('')
                      setConfirmPassword('')
                    }
                  }}
                >
                  {exporting ? (
                    <>
                      <NativeSelectOption value="bitwarden-json">
                        <Trans>Bitwarden password-protected JSON</Trans>
                      </NativeSelectOption>
                      <NativeSelectOption value="bitwarden-csv">
                        <Trans>Bitwarden plaintext CSV (logins and secure notes)</Trans>
                      </NativeSelectOption>
                      <NativeSelectOption value="bitwarden-zip">
                        <Trans>Bitwarden plaintext ZIP (with attachments)</Trans>
                      </NativeSelectOption>
                      <NativeSelectOption value="bearwarden-native">
                        <Trans>Full BearWarden backup (with attachments)</Trans>
                      </NativeSelectOption>
                    </>
                  ) : (
                    <>
                      <NativeSelectOption value="portable">
                        <Trans>Bitwarden JSON/CSV or Chrome CSV</Trans>
                      </NativeSelectOption>
                      <NativeSelectOption value="keepass-xml">
                        <Trans>KeePass 2 plaintext XML</Trans>
                      </NativeSelectOption>
                      <NativeSelectOption value="bearwarden-native">
                        <Trans>Full BearWarden backup (.bwbackup)</Trans>
                      </NativeSelectOption>
                    </>
                  )}
                </NativeSelect>
              </Field>
            )}

            <Alert>
              {nativeImport ? (
                <ArchiveRestore aria-hidden="true" />
              ) : exporting && !passwordlessExport ? (
                <FileKey2 aria-hidden="true" />
              ) : (
                <ShieldAlert aria-hidden="true" />
              )}
              <AlertTitle>
                {plaintextZip
                  ? t`Passwords and attachments in the ZIP are unencrypted plaintext`
                  : plaintextCsv
                    ? t`CSV is an incomplete, unencrypted plaintext export`
                    : keepassImport
                      ? t`Passwords in KeePass XML are unencrypted plaintext`
                      : exporting && exportFormat === 'bearwarden-native'
                        ? t`Full backups are not in a Bitwarden-compatible format`
                        : nativeImport
                          ? t`Safe resuming is supported, but server conflicts are not resolved automatically`
                          : exporting
                            ? t`Keep the backup password safe`
                            : t`Importing does not remove duplicate items automatically`}
              </AlertTitle>
              <AlertDescription>
                {plaintextZip ? (
                  <Trans>
                    Store it only on a trusted encrypted drive, and securely delete it after use.
                    The format matches Bitwarden personal vault ZIP exports. Bitwarden does not
                    currently support bulk importing attachment ZIPs, so BearWarden does not claim
                    that this can restore attachments without loss. Trash and Sends are not
                    included.
                  </Trans>
                ) : plaintextCsv ? (
                  <VaultCsvExportWarning />
                ) : keepassImport ? (
                  <VaultKeePassXmlImportWarning />
                ) : exporting && exportFormat === 'bearwarden-native' ? (
                  <Trans>
                    The encrypted .bwbackup contains personal items and attachments and can only be
                    restored by a BearWarden version that supports this format. Official Bitwarden
                    clients cannot import it directly. Trash and Sends are not included.
                  </Trans>
                ) : nativeImport ? (
                  <Trans>
                    If an upload result is unknown, BearWarden compares the full server attachment
                    contents first and retries only after confirming that the attachment is absent.
                    Canceling stops only this run and does not discard resume progress.
                  </Trans>
                ) : exporting ? (
                  <Trans>
                    Trash, attachments, and Sends are not included in Bitwarden JSON. The backup
                    cannot be decrypted if you forget its password.
                  </Trans>
                ) : (
                  <Trans>
                    Every item is added with a new identifier. Trashed JSON items are skipped, and
                    CSV does not include attachments or passkeys.
                  </Trans>
                )}
              </AlertDescription>
            </Alert>

            {preview && (
              <Card size="sm">
                <CardHeader>
                  <CardTitle>
                    <Trans>Backup contents</Trans>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <dl className="grid grid-cols-2 gap-3">
                    <div>
                      <dt className="text-muted-foreground">
                        <Trans
                          context="backup-created"
                          comment="Metadata label showing when the backup file was created."
                        >
                          Created
                        </Trans>
                      </dt>
                      <dd>{backupCreatedAt ?? <Trans>Unknown time</Trans>}</dd>
                    </div>
                    <div>
                      <dt className="text-muted-foreground">
                        <Trans>Attachment size</Trans>
                      </dt>
                      <dd>
                        <FormattedBackupBytes bytes={preview.attachmentBytes} />
                      </dd>
                    </div>
                    <div>
                      <dt className="text-muted-foreground">
                        <Trans>Folders</Trans>
                      </dt>
                      <dd>{numberFormatter.format(preview.folderCount)}</dd>
                    </div>
                    <div>
                      <dt className="text-muted-foreground">
                        <Trans>Items / attachments</Trans>
                      </dt>
                      <dd>{t`${formattedItemCount} / ${formattedAttachmentCount}`}</dd>
                    </div>
                  </dl>
                </CardContent>
              </Card>
            )}

            {progress && (
              <Progress value={progressPercent}>
                <ProgressLabel>
                  {progress.state === 'conflict'
                    ? t`Conflict requires attention`
                    : progress.state === 'partial'
                      ? t`Partially complete; you can resume later`
                      : progress.state === 'complete'
                        ? t`Restore complete`
                        : t`Restoring attachments`}
                </ProgressLabel>
                <ProgressValue>
                  {() => t`${formattedUploadedAttachments} / ${formattedTotalAttachments}`}
                </ProgressValue>
              </Progress>
            )}

            {restoreResult?.state === 'conflict' && (
              <FieldError>
                <Trans>
                  The server has multiple attachments with the same name, or their contents could
                  not be verified. BearWarden stopped and saved progress to avoid duplicate uploads.
                </Trans>
              </FieldError>
            )}
            {restoreResult?.state === 'partial' && (
              <FieldError>
                <Trans>
                  Not all attachments were completed this time. Select the same backup again and
                  enter its password to continue from the saved progress.
                </Trans>
              </FieldError>
            )}

            {!completed && (
              <FieldGroup>
                {(!nativeImport || preview) && (
                  <Field>
                    <FieldLabel htmlFor="portability-master-password">
                      <Trans>Current master password</Trans>
                    </FieldLabel>
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
                        ? t`After previewing, new local owner verification is required before syncing and restoring begin.`
                        : t`This is sent only to the local main process to verify the vault owner.`}
                    </FieldDescription>
                  </Field>
                )}
                {!preview && !passwordlessExport && !keepassImport && (
                  <Field>
                    <FieldLabel htmlFor="portability-backup-password">
                      {exporting
                        ? t`New backup password`
                        : nativeImport
                          ? t`Full backup password`
                          : t`Backup password (optional)`}
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
                        ? t`At least 12 characters. It is provided only to the local main process for encryption or decryption.`
                        : t`Required for password-protected JSON. Leave blank for unencrypted JSON or CSV.`}
                    </FieldDescription>
                  </Field>
                )}
                {exporting && !passwordlessExport && (
                  <Field>
                    <FieldLabel htmlFor="portability-confirm-password">
                      <Trans>Enter the backup password again</Trans>
                    </FieldLabel>
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
                <AlertTitle>
                  <Trans>Full backup restored</Trans>
                </AlertTitle>
                <AlertDescription>
                  <Trans>
                    Restored <Plural value={restoredItemCount} one="# item" other="# items" /> and{' '}
                    <Plural
                      value={restoredAttachmentCount}
                      one="# attachment"
                      other="# attachments"
                    />
                    . Review the result, then clear the completion record. This does not delete the
                    backup file.
                  </Trans>
                </AlertDescription>
              </Alert>
            )}
          </ModalBody>

          <ModalFooter>
            <Button
              variant="secondary"
              type="button"
              disabled={busy && !(nativeImport && preview && !completed)}
              onClick={() => void closeSafely()}
            >
              {busy && nativeImport && preview ? t`Stop and save progress` : t`Cancel`}
            </Button>
            {completed ? (
              confirmClear ? (
                <Button type="button" disabled={busy} onClick={() => void clearCompleted()}>
                  {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                  <Trans>Confirm clearing completion record</Trans>
                </Button>
              ) : (
                <Button type="button" onClick={() => setConfirmClear(true)}>
                  <Trans>Finish and clear resume record</Trans>
                </Button>
              )
            ) : (
              <Button
                type="submit"
                disabled={
                  busy ||
                  (!nativeImport && !masterPassword) ||
                  (((exporting && !passwordlessExport) || nativeImport) &&
                    !preview &&
                    backupPassword.length < 12) ||
                  (exporting && !passwordlessExport && backupPassword !== confirmPassword)
                }
              >
                {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                {exporting
                  ? t`Choose save location`
                  : nativeImport
                    ? preview
                      ? restoreResult
                        ? restoreResult.state === 'conflict'
                          ? t`Check conflicts again`
                          : t`Continue restoring`
                        : t`Confirm and start restoring`
                      : t`Choose full backup`
                    : t`Choose and import file`}
              </Button>
            )}
          </ModalFooter>
        </form>
      )}
    </Modal>
  )
}

export default VaultPortabilityDialog
