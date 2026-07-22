import { Check, Copy } from 'lucide-react'
import { Trans, useLingui } from '@lingui/react/macro'
import { useEffect, useState } from 'react'
import { Button } from '@renderer/components/ui/button'
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from '@renderer/components/ui/dialog'
import { buildSyncDiagnosticReport, type SyncDiagnosticInput } from './sync-error-diagnostics'

type CopyState = 'idle' | 'copied' | 'error'

interface SyncErrorDetailsDialogProps extends SyncDiagnosticInput {
  description: string
  detailLabel?: string
  reasonLabel?: string
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
}

export function SyncErrorDetailsDialog({
  appVersion: initialAppVersion,
  code,
  description,
  detail,
  detailLabel,
  reason,
  reasonLabel,
  occurredAt,
  onOpenChange,
  open,
  serverUrl,
  title
}: SyncErrorDetailsDialogProps): React.JSX.Element {
  const { t } = useLingui()
  const [appVersion, setAppVersion] = useState(initialAppVersion ?? '')
  const [copyState, setCopyState] = useState<CopyState>('idle')

  useEffect(() => {
    if (!open || appVersion) return
    let active = true
    void window.bearwarden.updater.state().then(
      (state) => {
        if (active) setAppVersion(state.currentVersion)
      },
      () => undefined
    )
    return () => {
      active = false
    }
  }, [appVersion, open])

  const report = buildSyncDiagnosticReport({
    appVersion,
    code,
    ...(detail ? { detail } : {}),
    ...(reason ? { reason } : {}),
    ...(occurredAt ? { occurredAt } : {}),
    ...(serverUrl ? { serverUrl } : {})
  })

  async function copyReport(): Promise<void> {
    try {
      await navigator.clipboard.writeText(report)
      setCopyState('copied')
    } catch {
      setCopyState('error')
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) setCopyState('idle')
        onOpenChange(nextOpen)
      }}
    >
      <DialogContent className="sm:max-w-lg" forceOverlay>
        <DialogHeader>
          <DialogTitle>
            <Trans>Sync error details</Trans>
          </DialogTitle>
          <DialogDescription>
            <Trans>
              Copy this privacy-safe diagnostic summary when reporting the problem. It does not
              include your account, server address, or vault contents.
            </Trans>
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1">
            <strong>{title}</strong>
            <p className="text-muted-foreground m-0 text-sm leading-relaxed">{description}</p>
          </div>
          <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
            <dt className="text-muted-foreground">
              <Trans>Error code</Trans>
            </dt>
            <dd className="m-0 font-mono break-all">{code}</dd>
            <dt className="text-muted-foreground">
              <Trans>Problem section</Trans>
            </dt>
            <dd className="m-0">{detailLabel ?? t`Unknown`}</dd>
            <dt className="text-muted-foreground">
              <Trans>Safe reason</Trans>
            </dt>
            <dd className="m-0">{reasonLabel ?? t`Unknown`}</dd>
            <dt className="text-muted-foreground">
              <Trans>Occurred at</Trans>
            </dt>
            <dd className="m-0 font-mono break-all">{occurredAt ?? t`Unknown`}</dd>
            <dt className="text-muted-foreground">
              <Trans>App version</Trans>
            </dt>
            <dd className="m-0 font-mono break-all">{appVersion || t`Unknown`}</dd>
          </dl>
          <pre className="bg-muted text-muted-foreground max-h-48 overflow-auto rounded-lg p-3 text-xs leading-relaxed whitespace-pre-wrap select-text">
            {report}
          </pre>
          {copyState === 'error' && (
            <p className="text-destructive m-0 text-sm" role="alert">
              <Trans>
                Could not copy the diagnostic summary. Select the text and copy it manually.
              </Trans>
            </p>
          )}
        </div>
        <DialogFooter>
          <DialogClose render={<Button variant="outline" type="button" />}>
            <Trans>Close</Trans>
          </DialogClose>
          <Button type="button" onClick={() => void copyReport()}>
            {copyState === 'copied' ? (
              <Check data-icon="inline-start" aria-hidden="true" />
            ) : (
              <Copy data-icon="inline-start" aria-hidden="true" />
            )}
            {copyState === 'copied' ? <Trans>Copied</Trans> : <Trans>Copy details</Trans>}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
