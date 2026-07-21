import NumberFlow from '@number-flow/react'
import { Trans, useLingui } from '@lingui/react/macro'
import { Clock3, Download, Paperclip, Trash2, Upload, Wrench, X } from 'lucide-react'
import type { JSX } from 'react'
import type {
  AttachmentProgressEvent,
  TotpCodeView,
  VaultAttachmentView
} from '../../../shared/vault-contract'
import { Button } from '@renderer/components/ui/button'
import {
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle
} from '@renderer/components/ui/card'
import { Progress, ProgressLabel, ProgressValue } from '@renderer/components/ui/progress'
import { Skeleton } from '@renderer/components/ui/skeleton'
import { Spinner } from '@renderer/components/ui/spinner'
import { CopyFeedbackIcon } from './CopyFeedbackIcon'
import TotpCountdownIndicator from './TotpCountdownIndicator'
import {
  attachmentProgressPercent,
  type AttachmentDeleteTarget,
  type AttachmentOperationState
} from './vault-attachment-ui'
import { DetailCard, TooltipIconButton } from './VaultShell-primitives'

interface VaultItemAttachmentsCardProps {
  itemId: string
  attachments: readonly VaultAttachmentView[]
  busy: boolean
  syncReady: boolean
  operation: AttachmentOperationState | null
  getOperationStageLabel: (progress: AttachmentProgressEvent) => string
  onUpload: () => void | Promise<void>
  onCancelOperation: () => void | Promise<void>
  onFixLegacy: (attachmentId: string) => void | Promise<void>
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
  onUpload,
  onCancelOperation,
  onFixLegacy,
  onDownload,
  onDelete
}: VaultItemAttachmentsCardProps): JSX.Element | null {
  const { t } = useLingui()

  if (attachments.length === 0 && operation?.itemId !== itemId) return null

  return (
    <DetailCard
      variant="attachment"
      role="region"
      aria-labelledby="attachments-title"
      className="gap-1 pb-0"
    >
      <CardHeader>
        <CardTitle id="attachments-title">
          <Paperclip aria-hidden="true" />
          <Trans>Attachments</Trans>
        </CardTitle>
        <CardAction>
          <Button
            variant="outline"
            size="sm"
            type="button"
            disabled={busy || operation !== null || !syncReady}
            onClick={() => void onUpload()}
          >
            {operation?.kind === 'upload' ? (
              <Spinner data-icon="inline-start" />
            ) : (
              <Upload data-icon="inline-start" />
            )}
            <Trans>Upload attachment</Trans>
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {operation?.itemId === itemId && (
          <section className="flex flex-col gap-3" aria-live="polite">
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
        {attachments.length > 0 && (
          <div className="-mx-(--card-spacing) -mb-(--card-spacing) grid">
            {attachments.map((attachment) => (
              <article
                key={attachment.id}
                className="border-border [&_small]:text-muted-foreground grid grid-cols-[34px_minmax(0,1fr)_auto] items-center gap-2.5 border-b px-(--card-spacing) py-3 [&_small]:truncate [&_small]:text-[10px] [&_span]:truncate [&_span]:text-[11px] [&_strong]:truncate [&_strong]:text-xs [&>div]:grid [&>div]:min-w-0 [&>div]:gap-[3px]"
              >
                <span
                  className="text-primary grid size-8 place-items-center rounded-md bg-(--accent-soft)"
                  aria-hidden="true"
                >
                  <Paperclip size={17} />
                </span>
                <div>
                  <strong>{attachment.fileName}</strong>
                  <span>
                    {attachment.sizeName}
                    {attachment.legacy ? t` · Legacy unauthenticated encryption` : ''}
                  </span>
                </div>
                <section
                  className="flex flex-wrap items-center justify-end gap-1"
                  aria-label={t`Attachment actions for ${attachment.fileName}`}
                >
                  {attachment.legacy && (
                    <Button
                      variant="outline"
                      size="sm"
                      type="button"
                      disabled={busy || operation !== null || !syncReady}
                      onClick={() => void onFixLegacy(attachment.id)}
                    >
                      <Wrench data-icon="inline-start" />
                      <Trans>Repair</Trans>
                    </Button>
                  )}
                  <TooltipIconButton
                    variant="outline"
                    size="icon"
                    type="button"
                    label={t`Download ${attachment.fileName}`}
                    disabled={busy || operation !== null || !syncReady}
                    onClick={() => void onDownload(attachment.id)}
                  >
                    <Download data-icon="inline-start" />
                  </TooltipIconButton>
                  <TooltipIconButton
                    variant="destructive"
                    size="icon"
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
                    <Trash2 data-icon="inline-start" />
                  </TooltipIconButton>
                </section>
              </article>
            ))}
          </div>
        )}
      </CardContent>
    </DetailCard>
  )
}

interface VaultItemTotpCardProps {
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

export function VaultItemTotpCard({
  code,
  generationError,
  revealReady,
  showSkeleton,
  codeCycle,
  showCountdown,
  copied,
  defaultCountdownPeriodSeconds,
  onCopy
}: VaultItemTotpCardProps): JSX.Element {
  const { t } = useLingui()

  return (
    <DetailCard
      className="gap-2 py-2"
      role="region"
      aria-labelledby="totp-title"
      aria-busy={!revealReady}
    >
      <CardHeader>
        <CardTitle id="totp-title">
          <Clock3 aria-hidden="true" />
          <Trans>One-time verification code</Trans>
        </CardTitle>
        {generationError === 'unsupported' && (
          <CardDescription>
            <Trans>Unsupported key format</Trans>
          </CardDescription>
        )}
        {!revealReady && (
          <span className="sr-only">
            <Trans>Generating…</Trans>
          </span>
        )}
        {!generationError && showCountdown && (
          <CardAction>
            <TotpCountdownIndicator
              key={codeCycle ?? 'loading'}
              remainingSeconds={code?.remainingSeconds ?? null}
              period={code?.period ?? defaultCountdownPeriodSeconds}
              compact
            />
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="contents">
        <div className="grid grid-cols-[minmax(0,1fr)_34px] items-center gap-2 px-(--card-spacing) py-2.5 [&_strong]:font-mono [&_strong]:text-[25px] [&_strong]:tracking-[0.18em]">
          <div className="flex h-8 min-w-0 items-center">
            {code ? (
              <strong>
                {/^\d+$/.test(code.code) ? (
                  <NumberFlow
                    className="tabular-nums"
                    value={Number(code.code)}
                    format={{
                      useGrouping: false,
                      minimumIntegerDigits: code.code.length
                    }}
                    trend={0}
                  />
                ) : (
                  code.code
                )}
              </strong>
            ) : generationError ? (
              <strong>—</strong>
            ) : showSkeleton ? (
              <Skeleton className="h-8 w-36" aria-hidden="true" />
            ) : null}
          </div>
          <TooltipIconButton
            variant="outline"
            size="icon"
            type="button"
            label={
              copied ? t`One-time verification code copied` : t`Copy one-time verification code`
            }
            disabled={!code || generationError !== null}
            onClick={() => void onCopy()}
          >
            <CopyFeedbackIcon copied={copied} />
          </TooltipIconButton>
        </div>
      </CardContent>
    </DetailCard>
  )
}
