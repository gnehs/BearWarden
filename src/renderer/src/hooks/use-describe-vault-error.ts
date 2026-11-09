import { useLingui } from '@lingui/react/macro'
import { useCallback, useMemo } from 'react'
import { describeError } from '../components/vault-error-ui'

/** Turns a vault IPC error into the translated message shown in the error toast. */
export function useDescribeVaultError(): (error: unknown) => string {
  const { t } = useLingui()
  const errorMessages = useMemo<Record<string, string>>(
    () => ({
      LOCKED: t`The vault is locked. Unlock it and try again.`,
      NOT_FOUND: t`The requested item could not be found.`,
      INVALID_INPUT: t`The input is invalid. Check it and try again.`,
      POLICY_RESTRICTED: t`This operation is restricted by your organization's policy.`,
      DUPLICATE_NAME: t`That name is already in use. Choose another name.`,
      INVALID_URL: t`The website URL is invalid.`,
      ATTACHMENT_FAILED: t`The attachment operation failed. The server content may have changed; sync and try again.`,
      ATTACHMENT_TOO_LARGE: t`The attachment is too large to encrypt within the safe memory limit.`,
      ATTACHMENT_STORAGE_LIMIT: t`There is not enough Bitwarden attachment storage. Free some space and try again.`,
      ATTACHMENT_REJECTED: t`This server or account does not currently allow this attachment to be added.`,
      ATTACHMENT_CANCELED: t`The attachment operation was canceled.`
    }),
    [t]
  )
  return useCallback(
    (error: unknown): string =>
      describeError(
        error,
        errorMessages,
        t`An unknown error occurred.`,
        t`The operation did not finish. Refresh and confirm the current state.`
      ),
    [errorMessages, t]
  )
}
