import { Trans } from '@lingui/react/macro'
import { useState } from 'react'
import { Button } from '@renderer/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from '@renderer/components/ui/dialog'
import { Field, FieldError, FieldGroup, FieldLabel } from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import type { SendDownloadFailure } from './send-ui'

export type SendPasswordPrompt = Extract<
  SendDownloadFailure,
  'password-required' | 'password-invalid'
>

interface SendPasswordDialogProps {
  sendName: string
  /** Why the password is being requested; `password-invalid` shows the wrong-password message. */
  reason: SendPasswordPrompt
  busy: boolean
  onSubmit: (password: string) => void
  onCancel: () => void
}

/** The password lives only in this component's state and is dropped when the dialog unmounts. */
export function SendPasswordDialog({
  sendName,
  reason,
  busy,
  onSubmit,
  onCancel
}: SendPasswordDialogProps): React.JSX.Element {
  const [password, setPassword] = useState('')
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !busy) onCancel()
      }}
    >
      <DialogContent>
        <form
          onSubmit={(event) => {
            event.preventDefault()
            if (password.length === 0 || busy) return
            onSubmit(password)
            setPassword('')
          }}
        >
          <DialogHeader>
            <DialogTitle>
              <Trans comment="Title of the dialog that asks for the access password of a password-protected file Send before downloading it.">
                Send password required
              </Trans>
            </DialogTitle>
            <DialogDescription>
              <Trans comment="Description in the file Send download password dialog. {sendName} is the user's own Send name.">
                Enter the access password to download “{sendName}”.
              </Trans>
            </DialogDescription>
          </DialogHeader>
          <div className="px-5 py-4">
            <FieldGroup>
              <Field data-invalid={reason === 'password-invalid' || undefined}>
                <FieldLabel htmlFor="send-download-password">
                  <Trans comment="Label of the password field in the file Send download dialog; the password recipients need to open the Send.">
                    Access password
                  </Trans>
                </FieldLabel>
                <Input
                  id="send-download-password"
                  type="password"
                  autoFocus
                  autoComplete="off"
                  aria-invalid={reason === 'password-invalid'}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />
                {reason === 'password-invalid' && (
                  <FieldError>
                    <Trans comment="Inline error in the file Send download dialog shown when the server rejected the entered Send access password.">
                      That password is incorrect. Check it and try again.
                    </Trans>
                  </FieldError>
                )}
              </Field>
            </FieldGroup>
          </div>
          <DialogFooter className="px-5 py-4">
            <Button type="submit" disabled={busy || password.length === 0}>
              <Trans comment="Submit button in the file Send download password dialog; saves the Send's file to disk.">
                Download
              </Trans>
            </Button>
            <Button type="button" variant="outline" onClick={onCancel} disabled={busy}>
              <Trans>Cancel</Trans>
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
