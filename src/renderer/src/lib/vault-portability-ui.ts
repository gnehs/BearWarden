import type { VaultExportRequest, VaultExportResult } from '../../../shared/vault-contract'

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
  const skipped = result.skippedTrashItems
    ? `，已略過垃圾桶中的 ${result.skippedTrashItems} 個項目`
    : ''
  const attachments =
    result.attachmentCount === undefined ? '' : `、${result.attachmentCount} 個附件`
  const unsupported = result.skippedUnsupportedItems
    ? `；CSV 另略過 ${result.skippedUnsupportedItems} 個不支援項目（卡片 ${result.skippedCards ?? 0}、身分 ${result.skippedIdentities ?? 0}、SSH 金鑰 ${result.skippedSshKeys ?? 0}）`
    : ''
  const passkeys = result.skippedPasskeys
    ? `，以及 ${result.skippedPasskeys} 個無法由 CSV 表示的 Passkey`
    : ''
  const losses = [
    result.skippedAttachments ? `${result.skippedAttachments} 個附件` : '',
    result.skippedPasswordHistoryEntries
      ? `${result.skippedPasswordHistoryEntries} 筆密碼歷史`
      : '',
    result.simplifiedUriMatches ? `${result.simplifiedUriMatches} 個 URI 比對規則` : '',
    result.skippedPasswordRevisionDates
      ? `${result.skippedPasswordRevisionDates} 筆密碼更新時間`
      : '',
    result.skippedAutofillSettings ? `${result.skippedAutofillSettings} 筆自動填入設定` : '',
    result.simplifiedCustomFieldTypes
      ? `${result.simplifiedCustomFieldTypes} 個被簡化為文字的自訂欄位型別`
      : ''
  ].filter(Boolean)
  const riskyFields = result.riskyCustomFields
    ? `；另有 ${result.riskyCustomFields} 個自訂欄位無法保證原結構（空名稱 ${result.emptyCustomFieldNames ?? 0}、名稱或值含換行 ${result.multilineCustomFields ?? 0}、值含「: 」 ${result.colonValueCustomFields ?? 0}）`
    : ''
  const lossSummary = losses.length > 0 ? `；CSV 未包含或簡化：${losses.join('、')}` : ''
  const durability = result.durabilityWarning
    ? '；檔案已發布到選定位置，但無法確認目錄 metadata 已持久化。請先檢查檔案是否完整，再決定是否重試'
    : ''
  return `匯出檔已儲存，共 ${result.exportedItems} 個項目、${result.exportedFolders} 個資料夾${attachments}${skipped}${unsupported}${passkeys}${lossSummary}${riskyFields}${durability}。`
}
