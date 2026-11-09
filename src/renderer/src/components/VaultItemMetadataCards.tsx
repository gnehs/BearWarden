import { Trans, useLingui } from '@lingui/react/macro'
import { FolderOpen, History, KeyRound, NotebookPen, Pencil, UsersRound } from 'lucide-react'
import type { JSX } from 'react'
import type {
  CollectionView,
  FolderView,
  LoginView,
  OrganizationView
} from '../../../shared/vault-contract'
import { cn } from '@renderer/lib/utils'
import { Button } from '@renderer/components/ui/button'
import { CardContent, CardHeader, CardTitle } from '@renderer/components/ui/card'
import { ItemHistoryRows } from './ItemHistoryRows'
import { DetailCard, DetailMetaRow, DetailRowGroup } from './VaultDetailSurface'

interface VaultItemMetadataCardsProps {
  selectedLogin: LoginView
  folders: readonly FolderView[]
  formatDate: (value: string | null) => string
  busy: boolean
  onMoveToFolder: () => void
  onViewPasswordHistory: () => void
  sharedContext?: {
    organization: OrganizationView | null
    collections: readonly CollectionView[]
  }
}

export function VaultItemMetadataCards({
  selectedLogin,
  folders,
  formatDate,
  busy,
  onMoveToFolder,
  onViewPasswordHistory,
  sharedContext
}: VaultItemMetadataCardsProps): JSX.Element {
  const { t } = useLingui()

  return (
    <>
      {!sharedContext && selectedLogin.type === 'login' && selectedLogin.passkeys.length > 0 && (
        <DetailCard tone="brand" role="region" aria-labelledby="passkeys-title">
          <CardHeader>
            <CardTitle id="passkeys-title">
              <KeyRound aria-hidden="true" />
              <Trans>Passkeys</Trans>
            </CardTitle>
          </CardHeader>
          <CardContent className="contents">
            <DetailRowGroup className="mx-(--card-spacing)">
              {selectedLogin.passkeys.map((passkey) => (
                <article
                  key={passkey.credentialId}
                  className="[&_small]:text-muted-foreground grid grid-cols-[auto_minmax(0,1fr)] items-start gap-2.5 border-b border-(--surface-ring) px-3 py-2 last:border-b-0 [&_small]:truncate [&_small]:text-xs [&_span]:truncate [&_span]:text-xs [&_strong]:truncate [&_strong]:text-xs [&>div]:grid [&>div]:min-w-0 [&>div]:gap-1"
                >
                  <span
                    className="text-brand bg-card grid size-8 place-items-center rounded-lg shadow-(--surface-shadow)"
                    aria-hidden="true"
                  >
                    <KeyRound size={16} />
                  </span>
                  <div>
                    <strong>{passkey.rpName || passkey.rpId}</strong>
                    <span>{passkey.userDisplayName || passkey.userName || t`Unnamed user`}</span>
                    <small>
                      {passkey.rpId} · {formatDate(passkey.creationDate)}
                      {passkey.discoverable ? t` · Discoverable` : ''}
                    </small>
                  </div>
                </article>
              ))}
            </DetailRowGroup>
            <p className="text-muted-foreground m-0 px-(--card-spacing) text-xs leading-normal">
              <Trans>
                You can safely delete passkeys while editing the item. Private key material is never
                sent to the renderer.
              </Trans>
            </p>
          </CardContent>
        </DetailCard>
      )}

      {(selectedLogin.type === 'secureNote' || selectedLogin.notes) && (
        <DetailCard tone="rose" role="region" aria-labelledby="notes-title">
          <CardHeader>
            <CardTitle id="notes-title">
              <NotebookPen aria-hidden="true" />
              {selectedLogin.type === 'secureNote' ? t`Secure note` : t`Notes`}
            </CardTitle>
          </CardHeader>
          <CardContent className="contents">
            <p
              className={cn(
                'mx-(--card-spacing) my-0 rounded-xl bg-(--inset-surface) px-3 py-2.5 text-xs leading-relaxed whitespace-pre-wrap shadow-(--inset-shadow)',
                !selectedLogin.notes?.trim() && 'text-muted-foreground'
              )}
            >
              {selectedLogin.notes?.trim() ? selectedLogin.notes : t`No content yet`}
            </p>
          </CardContent>
        </DetailCard>
      )}

      <DetailCard tone="sky" role="region" aria-labelledby="organization-title">
        <CardHeader>
          <CardTitle id="organization-title">
            {sharedContext ? <UsersRound aria-hidden="true" /> : <FolderOpen aria-hidden="true" />}
            {sharedContext ? (
              <Trans
                context="shared-organization-activity"
                comment="Section heading in a shared vault item details view; groups the owning Bitwarden organization, Collections, and usage timestamp."
              >
                Organization and activity
              </Trans>
            ) : (
              <Trans comment="Section heading in a login item details view; groups the folder and the item usage timestamp, not calendar events.">
                Organization and activity
              </Trans>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <DetailRowGroup as="dl">
            {sharedContext ? (
              <>
                <DetailMetaRow label={<Trans>Organization</Trans>} valueClassName="truncate">
                  {sharedContext.organization?.name ?? t`Unavailable`}
                </DetailMetaRow>
                <DetailMetaRow label={<Trans>Collections</Trans>}>
                  {sharedContext.collections.length > 0
                    ? sharedContext.collections.map((collection) => collection.name).join(' · ')
                    : t`Unavailable`}
                </DetailMetaRow>
              </>
            ) : (
              <DetailMetaRow
                label={
                  <Trans comment="Field label for the folder that contains this login item.">
                    Folder
                  </Trans>
                }
                valueClassName="flex items-center gap-2"
              >
                <span className="min-w-0 flex-1 truncate">
                  {folders.find((folder) => folder.id === selectedLogin.folderId)?.name ??
                    t`Unfiled`}
                </span>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  className="-my-1.5 ml-auto"
                  type="button"
                  aria-label={t`Move to folder`}
                  disabled={busy}
                  onClick={onMoveToFolder}
                >
                  <Pencil aria-hidden="true" />
                </Button>
              </DetailMetaRow>
            )}
            <DetailMetaRow
              label={
                <Trans
                  context="item-last-used"
                  comment="Field label for the last time this vault item was used; this is a usage timestamp, not a recent calendar event."
                >
                  Recently used
                </Trans>
              }
            >
              {formatDate(selectedLogin.lastUsedAt)}
            </DetailMetaRow>
          </DetailRowGroup>
        </CardContent>
      </DetailCard>

      <DetailCard tone="neutral" role="region" aria-labelledby="history-title">
        <CardHeader>
          <CardTitle id="history-title">
            <History aria-hidden="true" />
            <Trans comment="Section heading for the login item's creation, edit, password-change, and password-history metadata.">
              Item history
            </Trans>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ItemHistoryRows
            item={selectedLogin}
            formatDate={formatDate}
            busy={busy}
            onViewPasswordHistory={sharedContext ? undefined : onViewPasswordHistory}
          />
        </CardContent>
      </DetailCard>
    </>
  )
}
