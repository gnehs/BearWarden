import { Trans, useLingui } from '@lingui/react/macro'
import { AlertTriangle, Trash2 } from 'lucide-react'
import type { ComponentProps } from 'react'
import type {
  FolderView,
  LoginApprovalPrompt,
  LoginSummary,
  SyncStatus
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
  AlertDialogTitle
} from '@renderer/components/ui/alert-dialog'
import { Spinner } from '@renderer/components/ui/spinner'
import { ColoredPassword } from './ColoredPassword'
import CredentialGeneratorDialog from './CredentialGeneratorDialog'
import {
  DeleteLoginDialog,
  FolderDialog,
  Modal,
  MoveDialog,
  PasswordHistoryDialog,
  RepromptDialog
} from './Dialogs'
import LoginApprovalDialog from './LoginApprovalDialog'
import { ModalBody } from './ModalLayout'
import SyncDialog from './SyncDialog'
import type { AttachmentDeleteTarget } from './vault-attachment-ui'
import VaultPortabilityDialog, { type VaultPortabilityMode } from './VaultPortabilityDialog'
import type { BulkActionSnapshot, MoveSnapshot, RepromptPromptState } from './VaultShell-model'

type SelectedSummary = Pick<LoginSummary, 'deletedAt' | 'name' | 'passwordHistoryCount'>

export interface VaultShellItemDialogs {
  busy: boolean
  folder: {
    value: FolderView | 'new' | null
    folders: FolderView[]
    onClose: () => void
    onSave: ComponentProps<typeof FolderDialog>['onSave']
    onDelete: ComponentProps<typeof FolderDialog>['onDelete']
  }
  move: {
    snapshot: MoveSnapshot | null
    itemName: string | undefined
    currentFolderId: string | null | undefined
    folders: FolderView[]
    onClose: () => void
    onMove: (snapshot: MoveSnapshot, folderId: string | null) => Promise<boolean>
  }
  deletion: {
    selectedSummary: SelectedSummary | null
    deleteOpen: boolean
    onCloseDelete: () => void
    onDelete: ComponentProps<typeof DeleteLoginDialog>['onDelete']
    trashItemCount: number
    emptyTrashOpen: boolean
    onCloseEmptyTrash: () => void
    onEmptyTrash: ComponentProps<typeof DeleteLoginDialog>['onDelete']
    pendingBulkAction: BulkActionSnapshot | null
    onCloseBulkAction: () => void
    onPerformBulkAction: (snapshot: BulkActionSnapshot) => Promise<boolean>
  }
  passwordHistory: {
    open: boolean
    selectedSummary: SelectedSummary | null
    onClose: () => void
    onLoad: ComponentProps<typeof PasswordHistoryDialog>['onLoad']
    onReveal: ComponentProps<typeof PasswordHistoryDialog>['onReveal']
    onCopy: ComponentProps<typeof PasswordHistoryDialog>['onCopy']
  }
  passwordZoom: {
    value: string | null
    onClose: () => void
  }
  generator: {
    open: boolean
    onClose: () => void
    onGenerate: ComponentProps<typeof CredentialGeneratorDialog>['onGenerate']
    onCopyGenerated: ComponentProps<typeof CredentialGeneratorDialog>['onCopyGenerated']
    onListHistory: ComponentProps<typeof CredentialGeneratorDialog>['onListHistory']
    onCopyHistory: ComponentProps<typeof CredentialGeneratorDialog>['onCopyHistory']
    onClearHistory: ComponentProps<typeof CredentialGeneratorDialog>['onClearHistory']
  }
  attachment: {
    deleteTarget: AttachmentDeleteTarget | null
    onCloseDelete: () => void
    onDelete: () => Promise<void>
  }
}

export interface VaultShellSecurityDialogs {
  reprompt: {
    prompt: RepromptPromptState | null
    busy: boolean
    onCancel: () => void
    onAuthorize: ComponentProps<typeof RepromptDialog>['onAuthorize']
  }
  loginApproval: {
    prompt: LoginApprovalPrompt | undefined
    onClose: () => void
  }
  editorDiscard: {
    open: boolean
    busy: boolean
    onOpenChange: (open: boolean) => void
    onConfirm: () => void
  }
}

export interface VaultShellSyncDialogs {
  sync: {
    open: boolean
    status: SyncStatus
    onClose: () => void
    onStatusChange: (status: SyncStatus) => void
    onSynced: () => Promise<void>
  }
  portability: {
    mode: VaultPortabilityMode | null
    onClose: () => void
    onExport: ComponentProps<typeof VaultPortabilityDialog>['onExport']
    onImport: ComponentProps<typeof VaultPortabilityDialog>['onImport']
    onExported: ComponentProps<typeof VaultPortabilityDialog>['onExported']
    onImported: ComponentProps<typeof VaultPortabilityDialog>['onImported']
  }
}

interface VaultShellDialogsProps {
  itemDialogs: VaultShellItemDialogs
  securityDialogs: VaultShellSecurityDialogs
  syncDialogs: VaultShellSyncDialogs
}

function VaultShellDialogs({
  itemDialogs,
  securityDialogs,
  syncDialogs
}: VaultShellDialogsProps): React.JSX.Element {
  const { t } = useLingui()
  const { busy, folder, move, deletion, passwordHistory, passwordZoom, generator, attachment } =
    itemDialogs
  const moveSnapshot = move.snapshot
  const pendingBulkAction = deletion.pendingBulkAction

  return (
    <>
      {folder.value && (
        <FolderDialog
          folder={folder.value === 'new' ? undefined : folder.value}
          folders={folder.folders}
          busy={busy}
          onClose={folder.onClose}
          onSave={folder.onSave}
          onDelete={folder.value === 'new' ? undefined : folder.onDelete}
        />
      )}
      {moveSnapshot && (
        <MoveDialog
          itemName={move.itemName ?? t`Selected items`}
          itemCount={moveSnapshot.ids.length}
          currentFolderId={move.currentFolderId}
          folders={move.folders}
          busy={busy}
          onClose={move.onClose}
          onMove={(folderId) => move.onMove(moveSnapshot, folderId)}
        />
      )}
      {deletion.deleteOpen && deletion.selectedSummary && (
        <DeleteLoginDialog
          itemName={deletion.selectedSummary.name}
          busy={busy}
          permanent={Boolean(deletion.selectedSummary.deletedAt)}
          onClose={deletion.onCloseDelete}
          onDelete={deletion.onDelete}
        />
      )}
      {deletion.emptyTrashOpen && deletion.trashItemCount > 0 && (
        <DeleteLoginDialog
          itemName={t`${deletion.trashItemCount} items in Trash`}
          busy={busy}
          permanent
          onClose={deletion.onCloseEmptyTrash}
          onDelete={deletion.onEmptyTrash}
        />
      )}
      {pendingBulkAction &&
        (pendingBulkAction.action === 'delete' ||
          pendingBulkAction.action === 'deletePermanently') && (
          <AlertDialog
            open
            onOpenChange={(open) => {
              if (!open && !busy) deletion.onCloseBulkAction()
            }}
          >
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogMedia>
                  <AlertTriangle aria-hidden="true" />
                </AlertDialogMedia>
                <AlertDialogTitle>
                  {pendingBulkAction.action === 'deletePermanently'
                    ? t`Permanently delete ${pendingBulkAction.ids.length} items?`
                    : t`Move ${pendingBulkAction.ids.length} items to Trash?`}
                </AlertDialogTitle>
                <AlertDialogDescription>
                  {pendingBulkAction.action === 'deletePermanently'
                    ? t`This action cannot be undone. BearWarden does not keep a recoverable plaintext copy.`
                    : t`Items remain encrypted in Trash and can be restored later.`}
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel disabled={busy}>
                  <Trans>Cancel</Trans>
                </AlertDialogCancel>
                <AlertDialogAction
                  variant="destructive"
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    const snapshot = pendingBulkAction
                    void deletion.onPerformBulkAction(snapshot).then((completed) => {
                      if (completed) deletion.onCloseBulkAction()
                    })
                  }}
                >
                  {busy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                  {pendingBulkAction.action === 'deletePermanently'
                    ? t`Delete permanently`
                    : t`Move to Trash`}
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        )}
      {passwordHistory.open && passwordHistory.selectedSummary && (
        <PasswordHistoryDialog
          itemName={passwordHistory.selectedSummary.name}
          count={passwordHistory.selectedSummary.passwordHistoryCount}
          onClose={passwordHistory.onClose}
          onLoad={passwordHistory.onLoad}
          onReveal={passwordHistory.onReveal}
          onCopy={passwordHistory.onCopy}
        />
      )}
      {passwordZoom.value !== null && (
        <Modal
          title={t`Password`}
          description={t`Symbols, numbers, and letters use different colors to make them easier to distinguish.`}
          onClose={passwordZoom.onClose}
        >
          <ModalBody>
            <div className="bg-muted/60 rounded-xl px-4 py-5">
              <ColoredPassword
                value={passwordZoom.value}
                className="text-[22px] leading-[1.7] select-text"
              />
            </div>
          </ModalBody>
        </Modal>
      )}
      {generator.open && (
        <CredentialGeneratorDialog
          onClose={generator.onClose}
          onGenerate={generator.onGenerate}
          onCopyGenerated={generator.onCopyGenerated}
          onListHistory={generator.onListHistory}
          onCopyHistory={generator.onCopyHistory}
          onClearHistory={generator.onClearHistory}
        />
      )}
      {securityDialogs.reprompt.prompt && (
        <RepromptDialog
          itemName={securityDialogs.reprompt.prompt.itemName}
          busy={securityDialogs.reprompt.busy}
          onCancel={securityDialogs.reprompt.onCancel}
          onAuthorize={securityDialogs.reprompt.onAuthorize}
        />
      )}
      {securityDialogs.loginApproval.prompt && (
        <LoginApprovalDialog
          key={securityDialogs.loginApproval.prompt.token}
          prompt={securityDialogs.loginApproval.prompt}
          onClose={securityDialogs.loginApproval.onClose}
        />
      )}
      {syncDialogs.sync.open && (
        <SyncDialog
          status={syncDialogs.sync.status}
          onClose={syncDialogs.sync.onClose}
          onStatusChange={syncDialogs.sync.onStatusChange}
          onSynced={syncDialogs.sync.onSynced}
        />
      )}
      {syncDialogs.portability.mode && (
        <VaultPortabilityDialog
          mode={syncDialogs.portability.mode}
          onClose={syncDialogs.portability.onClose}
          onExport={syncDialogs.portability.onExport}
          onImport={syncDialogs.portability.onImport}
          onExported={syncDialogs.portability.onExported}
          onImported={syncDialogs.portability.onImported}
        />
      )}
      <AlertDialog
        open={attachment.deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) attachment.onCloseDelete()
        }}
      >
        <AlertDialogContent size="sm">
          <AlertDialogHeader>
            <AlertDialogTitle>
              <Trans>Delete attachment?</Trans>
            </AlertDialogTitle>
            <AlertDialogDescription>
              <Trans>
                “{attachment.deleteTarget?.fileName ?? t`This attachment`}” will be permanently
                deleted from Bitwarden and cannot be recovered.
              </Trans>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel type="button">
              <Trans>Keep attachment</Trans>
            </AlertDialogCancel>
            <AlertDialogAction
              type="button"
              variant="destructive"
              onClick={() => void attachment.onDelete()}
            >
              <Trash2 data-icon="inline-start" />
              <Trans>Delete attachment</Trans>
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <AlertDialog
        open={securityDialogs.editorDiscard.open}
        onOpenChange={securityDialogs.editorDiscard.onOpenChange}
      >
        <AlertDialogContent size="sm">
          <AlertDialogHeader>
            <AlertDialogTitle>
              <Trans>Discard unsaved changes?</Trans>
            </AlertDialogTitle>
            <AlertDialogDescription>
              <Trans>These changes have not been saved. Discarding them cannot be undone.</Trans>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel type="button">
              <Trans>Continue editing</Trans>
            </AlertDialogCancel>
            <AlertDialogAction
              type="button"
              variant="destructive"
              onClick={securityDialogs.editorDiscard.onConfirm}
              disabled={securityDialogs.editorDiscard.busy}
            >
              <Trans>Discard changes</Trans>
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

export default VaultShellDialogs
