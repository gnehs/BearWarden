import { useLingui } from '@lingui/react/macro'

/** Why archiving is unavailable: the official clients require premium to archive items. */
export function useArchivePremiumMessage(): string {
  const { t } = useLingui()
  return t({
    message:
      'Archiving requires a premium membership. Items that are already archived can still be viewed and unarchived.',
    comment:
      'Tooltip and error shown when the Archive action is disabled because the Bitwarden account has no premium membership.'
  })
}
