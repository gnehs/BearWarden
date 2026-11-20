import { Trans } from '@lingui/react/macro'
import { Button } from '@renderer/components/ui/button'
import { Field, FieldDescription, FieldLabel } from '@renderer/components/ui/field'
import { Spinner } from '@renderer/components/ui/spinner'
import type { LoginWithDeviceState } from '../hooks/use-login-with-device'

/** The Login with device step that stands in for the master password field while it runs. */
export function LoginWithDevicePanel({
  state,
  onUseMasterPassword
}: {
  state: Exclude<LoginWithDeviceState, { phase: 'idle' }>
  onUseMasterPassword: () => void
}): React.JSX.Element {
  return (
    <Field className="bg-muted grid gap-2 rounded-lg border p-3">
      <FieldLabel htmlFor="login-with-device-phrase">
        <Trans>Verification phrase</Trans>
      </FieldLabel>
      <output
        id="login-with-device-phrase"
        className="bg-background min-h-9 rounded-md border px-2.5 py-2 font-mono text-sm break-words select-text"
        aria-live="polite"
      >
        {state.phase === 'requesting' ? <Spinner aria-hidden="true" /> : state.fingerprint}
      </output>
      <FieldDescription>
        <Trans comment="Explains the Login with device step. The verification phrase is the six-word phrase above, which the approving Bitwarden or BearWarden device also displays.">
          Approve this request in Bitwarden or BearWarden on a device that is already signed in to
          this account. Make sure that device shows the same verification phrase.
        </Trans>
      </FieldDescription>
      <div className="flex flex-wrap items-center gap-2 text-xs" role="status">
        {state.phase === 'two-factor' ? (
          <Trans comment="Status in the Login with device step after another device approved the request but the server still requires two-step verification.">
            Approved. Complete two-step verification to continue.
          </Trans>
        ) : (
          <>
            <Spinner aria-hidden="true" />
            {state.phase === 'requesting' ? (
              <Trans comment="Status while BearWarden creates a Login with device request on the server.">
                Sending the sign-in request…
              </Trans>
            ) : state.phase === 'completing' ? (
              <Trans comment="Status after the Login with device request was approved and BearWarden is signing in and syncing.">
                Signing in…
              </Trans>
            ) : (
              <Trans comment="Status while BearWarden waits for another signed-in device to approve the Login with device request.">
                Waiting for approval…
              </Trans>
            )}
          </>
        )}
      </div>
      <Button
        className="justify-self-start"
        variant="outline"
        size="sm"
        type="button"
        onClick={onUseMasterPassword}
        disabled={state.phase === 'completing'}
      >
        <Trans comment="Button that abandons the Login with device request and returns to the master password field.">
          Use master password instead
        </Trans>
      </Button>
    </Field>
  )
}
