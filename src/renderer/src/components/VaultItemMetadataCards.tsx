import { Trans, useLingui } from '@lingui/react/macro'
import { Fingerprint, History } from 'lucide-react'
import type { JSX } from 'react'
import type {
  CollectionView,
  LoginView,
  OrganizationView,
  PasskeyView
} from '../../../shared/vault-contract'
import { TooltipIconButton } from './VaultShell-primitives'
import {
  DetailGroup,
  DetailLeadingTile,
  DetailRow,
  DetailTimestamp,
  DetailTimestamps,
  DetailWrappedText,
  detailActionClassName,
  detailValueClassName
} from './VaultDetailLayout'
import { cn } from '@renderer/lib/utils'

interface PasskeyRowsProps {
  passkeys: readonly PasskeyView[]
  formatDate: (value: string | null) => string
}

/** One row per stored passkey, shown inside the primary card of a login. */
export function VaultItemPasskeyRows({ passkeys, formatDate }: PasskeyRowsProps): JSX.Element {
  const { t } = useLingui()
  return (
    <>
      {passkeys.map((passkey) => (
        <DetailRow
          key={passkey.credentialId}
          label={<Trans>Passkey</Trans>}
          leading={
            <DetailLeadingTile>
              <Fingerprint />
            </DetailLeadingTile>
          }
        >
          <strong className={cn(detailValueClassName, 'block')}>
            {passkey.rpName || passkey.rpId}
            <span className="text-muted-foreground font-normal">
              {' · '}
              {passkey.userDisplayName || passkey.userName || t`Unnamed user`}
            </span>
          </strong>
          <small className="text-muted-foreground block truncate text-[11px] leading-4">
            {passkey.rpId} · {formatDate(passkey.creationDate)}
            {passkey.discoverable ? t` · Discoverable` : ''}
          </small>
        </DetailRow>
      ))}
    </>
  )
}

export function VaultItemPasskeyFootnote(): JSX.Element {
  return (
    <p className="text-muted-foreground m-0 mx-auto -mt-2.5 w-full max-w-[720px] shrink-0 px-3 text-[11px] leading-normal">
      <Trans>
        You can safely delete passkeys while editing the item. Private key material is never sent to
        the renderer.
      </Trans>
    </p>
  )
}

/** The notes of an item; a secure note's body is its primary content and carries no caption. */
export function VaultItemNotesGroup({
  selectedLogin
}: {
  selectedLogin: Pick<LoginView, 'type' | 'notes'>
}): JSX.Element | null {
  const { t } = useLingui()
  const isSecureNote = selectedLogin.type === 'secureNote'
  if (!isSecureNote && !selectedLogin.notes) return null
  const hasContent = Boolean(selectedLogin.notes?.trim())

  return (
    <DetailGroup
      caption={isSecureNote ? undefined : <Trans>Notes</Trans>}
      label={isSecureNote ? t`Secure note` : undefined}
    >
      <DetailRow className="py-2">
        <DetailWrappedText className={cn(!hasContent && 'text-muted-foreground')}>
          {hasContent ? selectedLogin.notes : t`No content yet`}
        </DetailWrappedText>
      </DetailRow>
    </DetailGroup>
  )
}

/** The owning organization and Collections of a shared item. */
export function VaultItemSharedContextGroup({
  organization,
  collections
}: {
  organization: OrganizationView | null
  collections: readonly CollectionView[]
}): JSX.Element {
  const { t } = useLingui()
  return (
    <DetailGroup label={t`Organization`}>
      <DetailRow label={<Trans>Organization</Trans>}>
        <strong className={cn(detailValueClassName, 'block')}>
          {organization?.name ?? t`Unavailable`}
        </strong>
      </DetailRow>
      <DetailRow label={<Trans>Collections</Trans>}>
        <strong className="block text-sm font-medium break-words">
          {collections.length > 0
            ? collections.map((collection) => collection.name).join(' · ')
            : t`Unavailable`}
        </strong>
      </DetailRow>
    </DetailGroup>
  )
}

interface PasswordHistoryGroupProps {
  /** Pre-formatted record count, such as "3 records". */
  summary: string
  busy: boolean
  onView: () => void
}

/** Entry point to the read-only password history dialog. */
export function VaultItemPasswordHistoryGroup({
  summary,
  busy,
  onView
}: PasswordHistoryGroupProps): JSX.Element {
  const { t } = useLingui()
  return (
    <DetailGroup label={t`Password history`}>
      <DetailRow
        label={<Trans>Password history</Trans>}
        actions={
          <TooltipIconButton
            className={detailActionClassName}
            variant="ghost"
            size="icon-sm"
            type="button"
            label={t`View password history`}
            disabled={busy}
            onClick={onView}
          >
            <History />
          </TooltipIconButton>
        }
      >
        <strong className={cn(detailValueClassName, 'block')}>{summary}</strong>
      </DetailRow>
    </DetailGroup>
  )
}

interface VaultItemMetadataCardsProps {
  selectedLogin: LoginView
  formatDate: (value: string | null) => string
  busy: boolean
  onViewPasswordHistory: () => void
  sharedContext?: {
    organization: OrganizationView | null
    collections: readonly CollectionView[]
  }
}

/** Everything below the credential groups: shared context, password history and the timestamps. */
export function VaultItemMetadataCards({
  selectedLogin,
  formatDate,
  busy,
  onViewPasswordHistory,
  sharedContext
}: VaultItemMetadataCardsProps): JSX.Element {
  const { t } = useLingui()

  return (
    <>
      {sharedContext && (
        <VaultItemSharedContextGroup
          organization={sharedContext.organization}
          collections={sharedContext.collections}
        />
      )}
      {!sharedContext && selectedLogin.passwordHistoryCount > 0 && (
        <VaultItemPasswordHistoryGroup
          summary={t`${selectedLogin.passwordHistoryCount} records`}
          busy={busy}
          onView={onViewPasswordHistory}
        />
      )}
      <DetailTimestamps>
        <DetailTimestamp
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
        </DetailTimestamp>
        <DetailTimestamp
          label={t({
            message: 'Last edited',
            comment: 'Metadata label showing when this vault item was last modified.'
          })}
        >
          {formatDate(selectedLogin.updatedAt)}
        </DetailTimestamp>
        <DetailTimestamp
          label={t({
            message: 'Created',
            context: 'item-created',
            comment: 'Metadata label showing when this vault item was first created.'
          })}
        >
          {formatDate(selectedLogin.createdAt)}
        </DetailTimestamp>
        {selectedLogin.passwordUpdatedAt !== null && (
          <DetailTimestamp
            label={t({
              message: 'Password last updated',
              comment:
                'Metadata label showing when the password in this login item was last changed.'
            })}
          >
            {formatDate(selectedLogin.passwordUpdatedAt)}
          </DetailTimestamp>
        )}
      </DetailTimestamps>
    </>
  )
}
