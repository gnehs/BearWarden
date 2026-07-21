import { Trans, useLingui } from '@lingui/react/macro'
import { FolderOpen, History, KeyRound, NotebookPen, Pencil } from 'lucide-react'
import type { JSX } from 'react'
import type { FolderView, LoginView } from '../../../shared/vault-contract'
import { cn } from '@renderer/lib/utils'
import { Button } from '@renderer/components/ui/button'
import { CardContent, CardHeader, CardTitle } from '@renderer/components/ui/card'
import { ItemHistoryRows } from './ItemHistoryRows'
import { DetailCard } from './VaultShell-primitives'

interface VaultItemMetadataCardsProps {
  selectedLogin: LoginView
  folders: readonly FolderView[]
  formatDate: (value: string | null) => string
  busy: boolean
  onMoveToFolder: () => void
  onViewPasswordHistory: () => void
}

export function VaultItemMetadataCards({
  selectedLogin,
  folders,
  formatDate,
  busy,
  onMoveToFolder,
  onViewPasswordHistory
}: VaultItemMetadataCardsProps): JSX.Element {
  const { t } = useLingui()

  return (
    <>
      {selectedLogin.type === 'login' && selectedLogin.passkeys.length > 0 && (
        <DetailCard role="region" aria-labelledby="passkeys-title" className="gap-1 pb-0">
          <CardHeader>
            <CardTitle id="passkeys-title">
              <KeyRound aria-hidden="true" />
              <Trans>Passkeys</Trans>
            </CardTitle>
          </CardHeader>
          <CardContent className="contents">
            <div className="grid">
              {selectedLogin.passkeys.map((passkey) => (
                <article
                  key={passkey.credentialId}
                  className="border-border [&_small]:text-muted-foreground grid grid-cols-[34px_minmax(0,1fr)] items-start gap-2.5 border-b px-(--card-spacing) py-3 [&_small]:truncate [&_small]:text-[10px] [&_span]:truncate [&_span]:text-[11px] [&_strong]:truncate [&_strong]:text-xs [&>div]:grid [&>div]:min-w-0 [&>div]:gap-[3px]"
                >
                  <span
                    className="text-primary grid size-8 place-items-center rounded-md bg-(--accent-soft)"
                    aria-hidden="true"
                  >
                    <KeyRound size={17} />
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
            </div>
            <p className="text-muted-foreground m-0 px-(--card-spacing) pt-2.5 pb-[13px] text-[10px] leading-normal">
              <Trans>
                You can safely delete passkeys while editing the item. Private key material is never
                sent to the renderer.
              </Trans>
            </p>
          </CardContent>
        </DetailCard>
      )}

      {(selectedLogin.type === 'secureNote' || selectedLogin.notes) && (
        <DetailCard role="region" aria-labelledby="notes-title" className="gap-1 pb-0">
          <CardHeader>
            <CardTitle id="notes-title">
              <NotebookPen aria-hidden="true" />
              {selectedLogin.type === 'secureNote' ? t`Secure note` : t`Notes`}
            </CardTitle>
          </CardHeader>
          <CardContent className="contents">
            <p
              className={cn(
                'm-0 px-(--card-spacing) pt-3.5 pb-[17px] text-xs leading-[1.65] whitespace-pre-wrap',
                !selectedLogin.notes?.trim() && 'text-muted-foreground'
              )}
            >
              {selectedLogin.notes?.trim() ? selectedLogin.notes : t`No content yet`}
            </p>
          </CardContent>
        </DetailCard>
      )}

      <DetailCard role="region" aria-labelledby="organization-title" className="gap-1 pb-0">
        <CardHeader>
          <CardTitle id="organization-title">
            <FolderOpen aria-hidden="true" />
            <Trans comment="Section heading in a login item details view; groups the folder and the item usage timestamp, not calendar events.">
              Organization and activity
            </Trans>
          </CardTitle>
        </CardHeader>
        <CardContent className="contents">
          <dl className="m-0 px-(--card-spacing) py-1">
            <div className="border-border grid grid-cols-[minmax(90px,0.28fr)_minmax(0,1fr)] items-center gap-2 border-b py-2.5 last:border-b-0 max-[430px]:grid-cols-1 max-[430px]:items-start max-[430px]:gap-1">
              <dt className="text-muted-foreground text-[11px] leading-4">
                <Trans comment="Field label for the folder that contains this login item.">
                  Folder
                </Trans>
              </dt>
              <dd className="m-0 flex min-w-0 items-center gap-2 text-xs leading-4">
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
              </dd>
            </div>
            <div className="border-border grid grid-cols-[minmax(90px,0.28fr)_minmax(0,1fr)] items-center gap-2 border-b py-2.5 last:border-b-0 max-[430px]:grid-cols-1 max-[430px]:items-start max-[430px]:gap-1">
              <dt className="text-muted-foreground text-[11px] leading-4">
                <Trans
                  context="item-last-used"
                  comment="Field label for the last time this vault item was used; this is a usage timestamp, not a recent calendar event."
                >
                  Recently used
                </Trans>
              </dt>
              <dd className="m-0 min-w-0 text-xs leading-4">
                {formatDate(selectedLogin.lastUsedAt)}
              </dd>
            </div>
          </dl>
        </CardContent>
      </DetailCard>

      <DetailCard role="region" aria-labelledby="history-title" className="gap-1 pb-0">
        <CardHeader>
          <CardTitle id="history-title">
            <History aria-hidden="true" />
            <Trans comment="Section heading for the login item's creation, edit, password-change, and password-history metadata.">
              Item history
            </Trans>
          </CardTitle>
        </CardHeader>
        <CardContent className="contents">
          <ItemHistoryRows
            item={selectedLogin}
            formatDate={formatDate}
            busy={busy}
            onViewPasswordHistory={onViewPasswordHistory}
          />
        </CardContent>
      </DetailCard>
    </>
  )
}
