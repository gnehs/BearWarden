import { msg } from '@lingui/core/macro'
import type {
  VaultExportRequest,
  VaultExportResult,
  VaultImportRequest,
  VaultImportResult
} from '../../../shared/vault-contract'
import { i18n } from '../i18n'

export function createVaultImportRequest(
  masterPassword: string,
  backupPassword: string,
  keepass: boolean
): VaultImportRequest {
  return keepass
    ? { masterPassword, format: 'keepass-xml' }
    : {
        masterPassword,
        format: 'portable',
        ...(backupPassword ? { password: backupPassword } : {})
      }
}

export async function executeVaultExport(
  request: VaultExportRequest,
  exportVault: (request: VaultExportRequest) => Promise<VaultExportResult>
): Promise<VaultExportResult> {
  try {
    return await exportVault(request)
  } finally {
    request.masterPassword = ''
    if ('password' in request && typeof request.password === 'string') request.password = ''
  }
}

export function formatVaultExportResult(result: VaultExportResult): string {
  const listSeparator = i18n._(msg`, `)
  const skipped = result.skippedTrashItems
    ? i18n._(msg`, skipped ${result.skippedTrashItems} items in the trash`)
    : ''
  const attachments =
    result.attachmentCount === undefined ? '' : i18n._(msg`, ${result.attachmentCount} attachments`)
  const unsupported = result.skippedUnsupportedItems
    ? i18n._(
        msg`; CSV also skipped ${result.skippedUnsupportedItems} unsupported items (${result.skippedCards ?? 0} cards, ${result.skippedIdentities ?? 0} identities, and ${result.skippedSshKeys ?? 0} SSH keys)`
      )
    : ''
  const passkeys = result.skippedPasskeys
    ? i18n._(msg`, and ${result.skippedPasskeys} passkeys that CSV cannot represent`)
    : ''
  const losses = [
    result.skippedAttachments ? i18n._(msg`${result.skippedAttachments} attachments`) : '',
    result.skippedPasswordHistoryEntries
      ? i18n._(msg`${result.skippedPasswordHistoryEntries} password history entries`)
      : '',
    result.simplifiedUriMatches ? i18n._(msg`${result.simplifiedUriMatches} URI match rules`) : '',
    result.skippedPasswordRevisionDates
      ? i18n._(msg`${result.skippedPasswordRevisionDates} password revision dates`)
      : '',
    result.skippedAutofillSettings
      ? i18n._(msg`${result.skippedAutofillSettings} autofill settings`)
      : '',
    result.simplifiedCustomFieldTypes
      ? i18n._(msg`${result.simplifiedCustomFieldTypes} custom field types simplified to text`)
      : ''
  ].filter(Boolean)
  const riskyFields = result.riskyCustomFields
    ? i18n._(
        msg`; ${result.riskyCustomFields} custom fields may not retain their original structure (${result.emptyCustomFieldNames ?? 0} with empty names, ${result.multilineCustomFields ?? 0} with newlines in names or values, and ${result.colonValueCustomFields ?? 0} with ": " in values)`
      )
    : ''
  const lossSummary =
    losses.length > 0 ? i18n._(msg`; CSV omitted or simplified: ${losses.join(listSeparator)}`) : ''
  const durability = result.durabilityWarning
    ? i18n._(
        msg`; the file was published to the selected location, but directory metadata persistence could not be confirmed. Check that the file is complete before deciding whether to retry`
      )
    : ''
  return i18n._(
    msg`Export file saved: ${result.exportedItems} items and ${result.exportedFolders} folders${attachments}${skipped}${unsupported}${passkeys}${lossSummary}${riskyFields}${durability}.`
  )
}

export function formatVaultImportResult(result: VaultImportResult): string {
  const listSeparator = i18n._(msg`, `)
  const skipped = result.skippedTrashItems
    ? i18n._(msg`, skipped ${result.skippedTrashItems} items in the trash`)
    : ''
  const losses = [
    result.skippedTemplateEntries
      ? i18n._(msg`${result.skippedTemplateEntries} template items`)
      : '',
    result.skippedAttachments ? i18n._(msg`${result.skippedAttachments} attachments`) : '',
    result.skippedHistoryEntries ? i18n._(msg`${result.skippedHistoryEntries} history entries`) : ''
  ].filter(Boolean)
  const lossSummary =
    losses.length > 0 ? i18n._(msg`; KeePass did not import: ${losses.join(listSeparator)}`) : ''
  return i18n._(
    msg`Import complete: ${result.importedItems} items and ${result.importedFolders} folders added${skipped}${lossSummary}.`
  )
}
