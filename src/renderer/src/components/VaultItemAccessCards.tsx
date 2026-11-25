import NumberFlow from '@number-flow/react'
import { Trans, useLingui } from '@lingui/react/macro'
import { Download, Eye, Paperclip, Trash2, Wrench, X } from 'lucide-react'
import type { JSX } from 'react'
import type {
  AttachmentProgressEvent,
  TotpCodeView,
  VaultAttachmentView
} from '../../../shared/vault-contract'
import { Button } from '@renderer/components/ui/button'
import { cn } from '@renderer/lib/utils'
import { Progress, ProgressLabel, ProgressValue } from '@renderer/components/ui/progress'
import { Skeleton } from '@renderer/components/ui/skeleton'
import { Spinner } from '@renderer/components/ui/spinner'
import { CopyFeedbackIcon } from './CopyFeedbackIcon'
import TotpCountdownIndicator from './TotpCountdownIndicator'
import { groupTotpCode } from './vault-detail-view-model'
import {
  attachmentProgressPercent,
  isPreviewableImageAttachment,
  type AttachmentDeleteTarget,
  type AttachmentOperationState
} from './vault-attachment-ui'
import {
  DetailGroup,
  DetailLeadingTile,
  DetailRow,
  detailActionClassName,
  detailValueButtonClassName,
  detailValueClassName
} from './VaultDetailLayout'
import { TooltipIconButton } from './VaultShell-primitives'

interface VaultItemAttachmentsCardProps {
  itemId: string
  attachments: readonly VaultAttachmentView[]
  busy: boolean
  syncReady: boolean
  operation: AttachmentOperationState | null
  getOperationStageLabel: (progress: AttachmentProgressEvent) => string
  onCancelOperation: () => void | Promise<void>
  onFixLegacy: (attachmentId: string) => void | Promise<void>
  onPreview: (attachmentId: string) => void | Promise<void>
  onDownload: (attachmentId: string) => void | Promise<void>
  onDelete: (target: AttachmentDeleteTarget) => void
}

export function VaultItemAttachmentsCard({
  itemId,
  attachments,
  busy,
  syncReady,
  operation,
  getOperationStageLabel,
  onCancelOperation,
  onFixLegacy,
  onPreview,
  onDownload,
  onDelete
}: VaultItemAttachmentsCardProps): JSX.Element | null {
  const { t } = useLingui()

  if (attachments.length === 0 && operation?.itemId !== itemId) return null

  return (
    <DetailGroup caption={<Trans>Attachments</Trans>}>
      {operation?.itemId === itemId && (
        <section className="flex flex-col gap-3 p-3" aria-live="polite">
          <Progress value={attachmentProgressPercent(operation)}>
            <ProgressLabel>
              {getOperationStageLabel(operation)}
              {operation.fileName ? `：${operation.fileName}` : ''}
            </ProgressLabel>
            <ProgressValue>
              {() =>
                attachmentProgressPercent(operation) === null
                  ? t`Processing`
                  : `${attachmentProgressPercent(operation)}%`
              }
            </ProgressValue>
          </Progress>
          <Button
            className="self-end"
            variant="outline"
            size="sm"
            type="button"
            disabled={operation.canceling}
            onClick={() => void onCancelOperation()}
          >
            {operation.canceling ? (
              <Spinner data-icon="inline-start" />
            ) : (
              <X data-icon="inline-start" />
            )}
            {operation.canceling ? t`Canceling` : t`Cancel`}
          </Button>
        </section>
      )}
      {attachments.map((attachment) => (
        <DetailRow
          key={attachment.id}
          leading={
            <DetailLeadingTile>
              <Paperclip />
            </DetailLeadingTile>
          }
          actions={
            <section
              className="flex flex-wrap items-center justify-end"
              aria-label={t`Attachment actions for ${attachment.fileName}`}
            >
              {attachment.legacy && (
                <Button
                  variant="ghost"
                  size="sm"
                  type="button"
                  disabled={busy || operation !== null || !syncReady}
                  onClick={() => void onFixLegacy(attachment.id)}
                >
                  <Wrench data-icon="inline-start" />
                  <Trans>Repair</Trans>
                </Button>
              )}
              {isPreviewableImageAttachment(attachment.fileName) && (
                <TooltipIconButton
                  className={detailActionClassName}
                  variant="ghost"
                  size="icon-sm"
                  type="button"
                  label={t`Preview ${attachment.fileName}`}
                  disabled={busy || operation !== null || !syncReady || attachment.legacy}
                  onClick={() => void onPreview(attachment.id)}
                >
                  <Eye />
                </TooltipIconButton>
              )}
              <TooltipIconButton
                className={detailActionClassName}
                variant="ghost"
                size="icon-sm"
                type="button"
                label={t`Download ${attachment.fileName}`}
                disabled={busy || operation !== null || !syncReady}
                onClick={() => void onDownload(attachment.id)}
              >
                <Download />
              </TooltipIconButton>
              <TooltipIconButton
                className={cn(detailActionClassName, 'text-destructive hover:text-destructive')}
                variant="ghost"
                size="icon-sm"
                type="button"
                label={t`Delete ${attachment.fileName}`}
                disabled={busy || operation !== null || !syncReady}
                onClick={() =>
                  onDelete({
                    itemId,
                    attachmentId: attachment.id,
                    fileName: attachment.fileName
                  })
                }
              >
                <Trash2 />
              </TooltipIconButton>
            </section>
          }
        >
          <strong className={cn(detailValueClassName, 'block')}>{attachment.fileName}</strong>
          <span className="text-muted-foreground block truncate text-[11px] leading-4">
            {attachment.sizeName}
            {attachment.legacy ? t` · Legacy unauthenticated encryption` : ''}
          </span>
        </DetailRow>
      ))}
    </DetailGroup>
  )
}

interface VaultItemTotpRowProps {
  code: TotpCodeView | null
  generationError: 'unsupported' | null
  revealReady: boolean
  showSkeleton: boolean
  codeCycle: number | null
  showCountdown: boolean
  copied: boolean
  defaultCountdownPeriodSeconds: number
  onCopy: () => void | Promise<void>
}

/** The one-time code row of the primary card, with its countdown ring and copy action. */
export function VaultItemTotpRow({
  code,
  generationError,
  revealReady,
  showSkeleton,
  codeCycle,
  showCountdown,
  copied,
  defaultCountdownPeriodSeconds,
  onCopy
}: VaultItemTotpRowProps): JSX.Element {
  const { t } = useLingui()
  const copyLabel = copied
    ? t`One-time verification code copied`
    : t`Copy one-time verification code`

  return (
    <DetailRow
      label={<Trans>One-time verification code</Trans>}
      aria-busy={!revealReady}
      actions={
        <>
          {!generationError && showCountdown && (
            <span className="mr-1 flex">
              <TotpCountdownIndicator
                key={codeCycle ?? 'loading'}
                remainingSeconds={code?.remainingSeconds ?? null}
                period={code?.period ?? defaultCountdownPeriodSeconds}
                compact
              />
            </span>
          )}
          <TooltipIconButton
            className={detailActionClassName}
            variant="ghost"
            size="icon-sm"
            type="button"
            label={copyLabel}
            disabled={!code || generationError !== null}
            onClick={() => void onCopy()}
          >
            <CopyFeedbackIcon copied={copied} />
          </TooltipIconButton>
        </>
      }
    >
      {!revealReady && (
        <span className="sr-only">
          <Trans>Generating…</Trans>
        </span>
      )}
      {code ? (
        <Button
          variant="ghost"
          size="sm"
          className={cn(
            detailValueButtonClassName,
            'text-brand hover:text-brand font-mono text-[17px] font-semibold tracking-wider [&>strong]:text-[17px]'
          )}
          data-field-copy-value=""
          type="button"
          aria-label={copyLabel}
          disabled={generationError !== null}
          onClick={() => void onCopy()}
        >
          <strong className="flex min-w-0 gap-[0.5ch] truncate">
            {groupTotpCode(code.code).map((group, index) =>
              /^\d+$/.test(group) ? (
                <NumberFlow
                  key={index}
                  className="tabular-nums"
                  value={Number(group)}
                  format={{ useGrouping: false, minimumIntegerDigits: group.length }}
                  trend={0}
                />
              ) : (
                <span key={index}>{group}</span>
              )
            )}
          </strong>
        </Button>
      ) : (
        <div className="flex h-7 min-w-0 items-center gap-2">
          {generationError ? (
            <>
              <strong className="text-[17px] font-semibold">—</strong>
              <span className="text-muted-foreground text-[11px]">
                <Trans>Unsupported key format</Trans>
              </span>
            </>
          ) : showSkeleton ? (
            <Skeleton className="h-5 w-24" aria-hidden="true" />
          ) : null}
        </div>
      )}
    </DetailRow>
  )
}
