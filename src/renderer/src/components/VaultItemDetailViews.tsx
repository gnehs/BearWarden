import { useArchivePremiumMessage } from '@renderer/hooks/use-archive-premium-message'
import { Trans, useLingui } from '@lingui/react/macro'
import {
  Archive,
  ArchiveRestore,
  ArrowLeft,
  Copy,
  Edit3,
  History,
  MoreHorizontal,
  RotateCcw,
  Settings2,
  Star,
  Trash2
} from 'lucide-react'
import { useMemo } from 'react'
import type {
  CollectionView,
  FolderView,
  LoginSummary,
  OrganizationView,
  SharedLoginSummary
} from '../../../shared/vault-contract'
import { Badge } from '@renderer/components/ui/badge'
import { Button } from '@renderer/components/ui/button'
import { CardContent, CardDescription, CardHeader, CardTitle } from '@renderer/components/ui/card'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger
} from '@renderer/components/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@renderer/components/ui/tooltip'
import type { AttachmentOperations } from '@renderer/hooks/use-attachment-operations'
import { useItemTypeMeta } from '@renderer/hooks/use-item-type-meta'
import { useBankAccountTypeLabels } from '@renderer/hooks/use-bank-account-type-labels'
import { formatDocumentDate, isBankAccountType } from '@renderer/lib/document-item-fields'
import type { SelectedItemSecrets } from '@renderer/hooks/use-selected-item-secrets'
import type { SelectedItemTotp } from '@renderer/hooks/use-totp-codes'
import { normalizeBitwardenCardBrand } from '@renderer/lib/payment-card'
import { cn } from '@renderer/lib/utils'
import { formatVaultDate } from '@renderer/lib/vault-date'
import type { SelectedVaultLogin } from '@renderer/stores/vault-session-store'
import PaymentCardBrandMark from './PaymentCardBrandMark'
import { VaultCustomFieldRows, VaultDetailFieldRows } from './VaultDetailFieldRows'
import { canRevealSecretsOnHover } from './VaultDetailFieldRows-model'
import { VaultItemAttachmentsCard, VaultItemTotpCard } from './VaultItemAccessCards'
import { VaultItemMetadataCards } from './VaultItemMetadataCards'
import { totpListCountdownPeriodSeconds } from './VaultShell-model'
import {
  DetailCard,
  DetailHeader,
  DetailHeading,
  DetailMetaRow,
  DetailRowGroup,
  detailIconClassName,
  detailScrollClassName
} from './VaultDetailSurface'
import { TooltipIconButton, hostLabel } from './VaultShell-primitives'
import { hasTrashPasswordHistory } from './VaultShell-security'
import { detailFields } from './vault-detail-view-model'
import WebsiteIcon from './WebsiteIcon'

interface TrashedItemDetailProps {
  summary: LoginSummary
  folders: readonly FolderView[]
  busy: boolean
  onBack: () => void
  onViewPasswordHistory: () => void
  onRestore: () => void
  onDelete: () => void
}

/** A trashed item: only metadata, because deleted secrets stay hidden until restored. */
export function TrashedItemDetail({
  summary,
  folders,
  busy,
  onBack,
  onViewPasswordHistory,
  onRestore,
  onDelete
}: TrashedItemDetailProps): React.JSX.Element {
  const { t } = useLingui()
  const itemTypeMeta = useItemTypeMeta()
  return (
    <article className="flex size-full min-h-0 min-w-0 flex-col">
      <DetailHeader>
        <TooltipIconButton
          variant="outline"
          size="icon"
          className="hidden max-[680px]:grid"
          data-detail-back=""
          type="button"
          label={t`Back to Trash`}
          onClick={onBack}
        >
          <ArrowLeft />
        </TooltipIconButton>
        <span className={detailIconClassName()} aria-hidden="true">
          <Trash2 />
        </span>
        <DetailHeading
          title={summary.name}
          subtitle={itemTypeMeta[summary.type].label}
          chips={
            <Badge variant="warning">
              <Trans>Trash</Trans>
            </Badge>
          }
        />
      </DetailHeader>
      <div className={cn('scroll-fade-y forced-colors:scroll-fade-none', detailScrollClassName)}>
        <DetailCard tone="rose">
          <CardHeader>
            <CardTitle>
              <Trash2 aria-hidden="true" />
              <Trans>This item is in Trash</Trans>
            </CardTitle>
            <CardDescription>
              <Trans>
                To protect deleted sensitive data, restore the item before viewing or editing its
                contents.
              </Trans>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <DetailRowGroup as="dl">
              <DetailMetaRow label={<Trans>Deleted</Trans>}>
                {formatVaultDate(summary.deletedAt)}
              </DetailMetaRow>
              <DetailMetaRow label={<Trans>Original folder</Trans>}>
                {folders.find((folder) => folder.id === summary.folderId)?.name ?? t`Unfiled`}
              </DetailMetaRow>
            </DetailRowGroup>
          </CardContent>
        </DetailCard>
        {hasTrashPasswordHistory(summary) && (
          <DetailCard tone="neutral" role="region" aria-labelledby="trash-password-history-title">
            <CardHeader>
              <CardTitle id="trash-password-history-title">
                <History aria-hidden="true" />
                <Trans>Item history</Trans>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <DetailRowGroup as="dl">
                <DetailMetaRow
                  label={<Trans>Password history</Trans>}
                  valueClassName="flex items-center gap-2"
                >
                  <span className="min-w-0 flex-1 truncate">
                    <Trans>{summary.passwordHistoryCount} read-only records</Trans>
                  </span>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    className="-my-1.5 ml-auto"
                    type="button"
                    aria-label={t`View password history`}
                    disabled={busy}
                    onClick={onViewPasswordHistory}
                  >
                    <History aria-hidden="true" />
                  </Button>
                </DetailMetaRow>
              </DetailRowGroup>
            </CardContent>
          </DetailCard>
        )}
        <div className="mx-auto flex max-w-[720px] flex-wrap justify-end gap-2">
          <Button type="button" disabled={busy} onClick={onRestore}>
            <RotateCcw data-icon="inline-start" />
            <Trans>Restore item</Trans>
          </Button>
          <Button variant="destructive" type="button" disabled={busy} onClick={onDelete}>
            <Trash2 data-icon="inline-start" />
            <Trans>Delete permanently</Trans>
          </Button>
        </div>
      </div>
    </article>
  )
}

interface SelectedItemDetailProps {
  login: SelectedVaultLogin
  sharedSummary: SharedLoginSummary | null
  sharedContext?: { organization: OrganizationView | null; collections: readonly CollectionView[] }
  folders: readonly FolderView[]
  busy: boolean
  showWebsiteIcons: boolean
  cardCoverPreview: string | undefined
  syncReady: boolean
  archiveRequiresPremium: boolean
  showTotpCountdown: boolean
  secrets: SelectedItemSecrets
  attachments: AttachmentOperations
  totp: SelectedItemTotp
  actions: {
    onBack: () => void
    onEdit: () => void
    onToggleFavorite: () => void
    onClone: () => void
    onToggleArchive: () => void
    onDelete: () => void
    onMoveToFolder: () => void
    onViewPasswordHistory: () => void
  }
}

/** The decrypted detail of the selected item with its secrets, attachments and TOTP code. */
export function SelectedItemDetail({
  login,
  sharedSummary,
  sharedContext,
  folders,
  busy,
  showWebsiteIcons,
  cardCoverPreview,
  syncReady,
  archiveRequiresPremium,
  showTotpCountdown,
  secrets,
  attachments,
  totp,
  actions
}: SelectedItemDetailProps): React.JSX.Element {
  const { t } = useLingui()
  const archivePremiumMessage = useArchivePremiumMessage()
  const archiveBlocked = archiveRequiresPremium && !login.archivedAt
  const itemTypeMeta = useItemTypeMeta()
  const detailFieldLabels = useMemo<Record<string, string>>(
    () => ({
      username: t`Username`,
      password: t`Password`,
      website: t`Website`,
      cardNumber: t`Card number`,
      securityCode: t`Security code`,
      cardholder: t`Cardholder`,
      brand: t({
        message: 'Brand',
        comment:
          'Field label for the payment card issuer or network brand, such as Visa or Mastercard.'
      }),
      expirationDate: t`Expiration date`,
      name: t`Name`,
      company: t({
        message: 'Company',
        comment: 'Field label for the company name in an identity item.'
      }),
      email: t`Email`,
      phone: t`Phone`,
      address: t`Address`,
      ssn: t`ID / Social Security number`,
      passportNumber: t`Passport number`,
      licenseNumber: t`Driver's license number`,
      privateKey: t`Private key`,
      publicKey: t`Public key`,
      keyFingerprint: t`Key fingerprint`,
      bankName: t({
        message: 'Bank name',
        comment: 'Field label for the bank of a bank account item.'
      }),
      nameOnAccount: t({
        message: 'Name on account',
        comment: 'Field label for the account holder name of a bank account item.'
      }),
      accountType: t({
        message: 'Account type',
        comment: 'Field label for choosing a bank account kind, such as checking or savings.'
      }),
      accountNumber: t({
        message: 'Account number',
        comment: 'Masked field label for the bank account number.'
      }),
      routingNumber: t({
        message: 'Routing number',
        comment: 'Field label for the bank routing or sort code of a bank account item.'
      }),
      branchNumber: t({
        message: 'Branch number',
        comment: 'Field label for the bank branch number of a bank account item.'
      }),
      bankPin: t({
        message: 'PIN',
        context: 'bank-account-pin',
        comment:
          'Masked field label for the PIN of a bank account or its card, not the app unlock PIN.'
      }),
      swiftCode: t({
        message: 'SWIFT code',
        comment: 'Masked field label for the SWIFT/BIC code of a bank account item.'
      }),
      iban: t({
        message: 'IBAN',
        comment: 'Masked field label for the International Bank Account Number.'
      }),
      bankContactPhone: t({
        message: 'Bank contact phone',
        comment: 'Field label for the phone number of the bank in a bank account item.'
      }),
      firstName: t`First name`,
      middleName: t`Middle name`,
      lastName: t`Last name`,
      dateOfBirth: t({
        message: 'Date of birth',
        comment: "Date field for the holder's birth date on a driver's license or passport."
      }),
      issuingCountry: t({
        message: 'Issuing country',
        comment: "Field label for the country that issued a driver's license or passport."
      }),
      issuingState: t({
        message: 'Issuing state / province',
        comment: "Field label for the state or province that issued a driver's license."
      }),
      issuingAuthority: t({
        message: 'Issuing authority',
        comment: "Field label for the agency that issued a driver's license or passport."
      }),
      issueDate: t({
        message: 'Issue date',
        comment: "Date field for when a driver's license or passport was issued."
      }),
      licenseClass: t({
        message: 'License class',
        comment: "Field label for the vehicle class on a driver's license, such as C or B."
      }),
      givenName: t({
        message: 'Given name',
        comment: 'Field label for the given names printed on a passport.'
      }),
      surname: t({
        message: 'Surname',
        comment: 'Field label for the surname printed on a passport.'
      }),
      sex: t({
        message: 'Sex',
        comment: 'Field label for the sex marker printed on a passport, such as F, M, or X.'
      }),
      birthPlace: t({
        message: 'Place of birth',
        comment: 'Field label for the place of birth printed on a passport.'
      }),
      nationality: t({
        message: 'Nationality',
        comment: 'Field label for the nationality printed on a passport.'
      }),
      passportType: t({
        message: 'Passport type',
        comment: 'Field label for the passport type code, such as P for an ordinary passport.'
      }),
      nationalIdentificationNumber: t({
        message: 'National ID number',
        comment: 'Masked field label for the national identification number on a passport.'
      })
    }),
    [t]
  )
  const bankAccountTypeLabels = useBankAccountTypeLabels()
  const linkedFieldLabels: Record<number, string> = {
    100: t`Username`,
    101: t`Password`,
    300: t`Cardholder`,
    301: t`Expiration month`,
    302: t`Expiration year`,
    303: t`Security code`,
    304: t`Brand`,
    305: t`Card number`,
    400: t`Title`,
    401: t`Middle name`,
    402: t`Address 1`,
    403: t`Address 2`,
    404: t`Address 3`,
    405: t`City`,
    406: t`State / Province`,
    407: t`Postal code`,
    408: t`Country`,
    409: t`Company`,
    410: t`Email`,
    411: t`Phone`,
    412: t`ID / Social Security number`,
    413: t`Username`,
    414: t`Passport number`,
    415: t`Driver's license number`,
    416: t`First name`,
    417: t`Last name`,
    418: t`Full name`
  }
  const customFieldLabels = {
    yes: t`Yes`,
    no: t`No`,
    linkedTo: (label: string): string => t`Linked to ${label}`,
    itemField: t`Item field`,
    linkedFields: linkedFieldLabels,
    unset: t`Not set`
  }
  const detailFieldList = useMemo(
    () =>
      detailFields(login, detailFieldLabels, {
        date: formatDocumentDate,
        bankAccountType: (value) =>
          isBankAccountType(value) ? bankAccountTypeLabels[value] : value
      }),
    [bankAccountTypeLabels, detailFieldLabels, login]
  )
  return (
    <article className="flex size-full min-h-0 min-w-0 flex-col">
      <DetailHeader>
        <TooltipIconButton
          variant="outline"
          size="icon"
          className="hidden max-[680px]:grid"
          data-detail-back=""
          type="button"
          label={t`Back to item list`}
          onClick={actions.onBack}
        >
          <ArrowLeft />
        </TooltipIconButton>
        <span className={detailIconClassName(login.type)} data-detail-icon="" aria-hidden="true">
          {login.type === 'login' ? (
            <WebsiteIcon
              id={login.id}
              uri={login.uri}
              enabled={!sharedSummary && showWebsiteIcons}
            />
          ) : login.type === 'card' ? (
            <PaymentCardBrandMark
              brand={normalizeBitwardenCardBrand(login.brand)}
              imageSrc={cardCoverPreview}
            />
          ) : (
            (() => {
              const TypeIcon = itemTypeMeta[login.type].icon
              return <TypeIcon size={18} />
            })()
          )}
        </span>
        <DetailHeading
          title={login.name}
          subtitle={
            login.subtitle ||
            (login.type === 'login'
              ? hostLabel(login.uri, t`Website not set`)
              : t`Securely stored item`)
          }
          chips={
            <>
              <Badge variant="chip">{itemTypeMeta[login.type].label}</Badge>
              {sharedContext?.organization ? (
                <Badge variant="chip">{sharedContext.organization.name}</Badge>
              ) : (
                <Badge variant="chip">
                  {folders.find((folder) => folder.id === login.folderId)?.name ?? t`Unfiled`}
                </Badge>
              )}
              {login.archivedAt && (
                <Badge variant="warning">
                  <Trans>Archive</Trans>
                </Badge>
              )}
            </>
          }
        />
        <div className="flex flex-none items-center gap-1.5">
          {(!sharedSummary || (sharedSummary.edit && sharedSummary.reprompt === 0)) && (
            <TooltipIconButton
              variant="outline"
              size="icon"
              type="button"
              label={t`Edit`}
              disabled={busy}
              onClick={actions.onEdit}
            >
              <Edit3 />
            </TooltipIconButton>
          )}
          {!sharedSummary && (
            <>
              <TooltipIconButton
                variant="outline"
                size="icon"
                className={cn(login.favorite && 'text-chart-4')}
                type="button"
                label={login.favorite ? t`Remove from favorites` : t`Add to favorites`}
                aria-pressed={login.favorite}
                onClick={actions.onToggleFavorite}
              >
                <Star fill={login.favorite ? 'currentColor' : 'none'} />
              </TooltipIconButton>
              <DropdownMenu>
                <Tooltip>
                  <TooltipTrigger
                    render={
                      <DropdownMenuTrigger
                        render={
                          <Button
                            variant="outline"
                            size="icon"
                            className="border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground dark:bg-card dark:hover:bg-muted rounded-control size-9 min-w-9 shadow-(--control-highlight)"
                            type="button"
                            aria-label={t`More actions`}
                            disabled={busy}
                          />
                        }
                      >
                        <MoreHorizontal aria-hidden="true" />
                      </DropdownMenuTrigger>
                    }
                  />
                  <TooltipContent>
                    <Trans>More actions</Trans>
                  </TooltipContent>
                </Tooltip>
                <DropdownMenuContent align="end">
                  <DropdownMenuGroup>
                    <DropdownMenuItem disabled={busy} onClick={actions.onClone}>
                      <Copy data-icon="inline-start" />
                      <Trans>Duplicate item</Trans>
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      disabled={busy || archiveBlocked}
                      onClick={actions.onToggleArchive}
                    >
                      {login.archivedAt ? (
                        <ArchiveRestore data-icon="inline-start" />
                      ) : (
                        <Archive data-icon="inline-start" />
                      )}
                      <span className="grid gap-0.5">
                        {login.archivedAt ? t`Unarchive` : t`Archive item`}
                        {archiveBlocked && (
                          <span className="text-muted-foreground max-w-56 text-xs font-normal">
                            {archivePremiumMessage}
                          </span>
                        )}
                      </span>
                    </DropdownMenuItem>
                  </DropdownMenuGroup>
                  <DropdownMenuSeparator />
                  <DropdownMenuGroup>
                    <DropdownMenuItem
                      variant="destructive"
                      disabled={busy}
                      onClick={actions.onDelete}
                    >
                      <Trash2 data-icon="inline-start" />
                      <Trans>Move to Trash</Trans>
                    </DropdownMenuItem>
                  </DropdownMenuGroup>
                </DropdownMenuContent>
              </DropdownMenu>
            </>
          )}
        </div>
      </DetailHeader>

      <div className={cn('scroll-fade-y forced-colors:scroll-fade-none', detailScrollClassName)}>
        {detailFieldList.length > 0 && (
          <DetailCard tone="amber" role="region" aria-labelledby="credentials-title">
            <CardHeader>
              <CardTitle id="credentials-title">
                {(() => {
                  const TypeIcon = itemTypeMeta[login.type].icon
                  return <TypeIcon aria-hidden="true" />
                })()}
                {t`${itemTypeMeta[login.type].label} details`}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <DetailRowGroup>
                <VaultDetailFieldRows
                  fields={detailFieldList.filter(
                    (field) =>
                      (!sharedSummary || sharedSummary.viewPassword || !field.secret) &&
                      (field.secret || Boolean(field.value))
                  )}
                  copy={{
                    copiedKey: secrets.copiedKey,
                    itemId: login.id,
                    copyField: secrets.copyField
                  }}
                  reveal={{
                    state: secrets.revealedSecrets,
                    selectedItemId: login.id,
                    hoveringFieldsRef: secrets.hoveringSecretFieldsRef,
                    hoverRevealedFieldsRef: secrets.hoverRevealedSecretFieldsRef,
                    passwordZoomOpenRef: secrets.passwordZoomOpenRef,
                    reveal: secrets.revealSecret,
                    hide: secrets.hideRevealedSecret,
                    openPasswordZoom: secrets.openPasswordZoom,
                    revealOnHover: canRevealSecretsOnHover(sharedSummary)
                  }}
                  website={{ openWebsite: secrets.openWebsite }}
                />
              </DetailRowGroup>
            </CardContent>
          </DetailCard>
        )}

        {login.customFields.length > 0 && (
          <DetailCard tone="violet" role="region" aria-labelledby="custom-fields-title">
            <CardHeader>
              <CardTitle id="custom-fields-title">
                <Settings2 aria-hidden="true" />
                <Trans>Custom fields</Trans>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <DetailRowGroup>
                <VaultCustomFieldRows
                  fields={login.customFields}
                  item={{ id: login.id, updatedAt: login.updatedAt }}
                  labels={customFieldLabels}
                  copy={{
                    copiedKey: secrets.copiedKey,
                    copyField: secrets.copyCustomField
                  }}
                  reveal={{
                    state: secrets.revealedCustomFields,
                    reveal: secrets.revealCustomField
                  }}
                />
              </DetailRowGroup>
            </CardContent>
          </DetailCard>
        )}

        {!sharedSummary && (
          <VaultItemAttachmentsCard
            itemId={login.id}
            attachments={login.attachments}
            busy={busy}
            syncReady={syncReady}
            operation={attachments.operation}
            getOperationStageLabel={attachments.getStageLabel}
            onCancelOperation={attachments.cancel}
            onFixLegacy={attachments.fixLegacy}
            onPreview={attachments.preview}
            onDownload={attachments.download}
            onDelete={attachments.setDeleteTarget}
          />
        )}

        {login.type === 'login' && login.hasTotp && (
          <VaultItemTotpCard
            code={totp.code}
            generationError={totp.generationError}
            revealReady={totp.revealReady}
            showSkeleton={totp.showSkeleton}
            codeCycle={totp.cycle}
            showCountdown={showTotpCountdown}
            copied={secrets.copiedKey === `totp:${login.id}`}
            defaultCountdownPeriodSeconds={totpListCountdownPeriodSeconds}
            onCopy={secrets.copyTotp}
          />
        )}

        <VaultItemMetadataCards
          selectedLogin={login}
          folders={folders}
          formatDate={formatVaultDate}
          busy={busy}
          onMoveToFolder={actions.onMoveToFolder}
          onViewPasswordHistory={actions.onViewPasswordHistory}
          sharedContext={sharedContext}
        />
      </div>
    </article>
  )
}
