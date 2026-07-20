import { describe, expect, it, vi } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import {
  createVaultImportRequest,
  executeVaultExport,
  formatVaultExportResult,
  formatVaultImportResult
} from '../lib/vault-portability-ui'
import { VaultCsvExportWarning, VaultKeePassXmlImportWarning } from './VaultPortabilityDialog'

describe('Bitwarden CSV export warning', () => {
  it('explains plaintext, formula, archive, and unsupported-data boundaries', () => {
    const markup = renderToStaticMarkup(<VaultCsvExportWarning />)

    expect(markup).toContain('使用中及封存')
    expect(markup).toContain('不是完整備份')
    expect(markup).toContain('垃圾桶')
    expect(markup).toContain('附件')
    expect(markup).toContain('卡片')
    expect(markup).toContain('身分')
    expect(markup).toContain('SSH')
    expect(markup).toContain('通行密鑰')
    expect(markup).toContain('Sends')
    expect(markup).toContain('試算表')
    expect(markup).toContain('公式')
    expect(markup).toContain('不會改寫這些敏感資料')
    expect(markup).toContain('自訂欄位會攤平成')
    expect(markup).toContain('型別')
    expect(markup).toContain('原始結構可能無法復原')
    expect(markup).toContain('加密')
    expect(markup).toContain('JSON')
    expect(markup).toContain('完整 BearWarden 備份')
  })

  it('reports each skipped CSV category and passkey count after saving', () => {
    const message = formatVaultExportResult({
      canceled: false,
      exportedFolders: 2,
      exportedItems: 4,
      skippedTrashItems: 3,
      skippedUnsupportedItems: 6,
      skippedCards: 1,
      skippedIdentities: 2,
      skippedSshKeys: 3,
      skippedPasskeys: 5,
      skippedAttachments: 6,
      skippedPasswordHistoryEntries: 7,
      simplifiedUriMatches: 8,
      skippedPasswordRevisionDates: 9,
      skippedAutofillSettings: 10,
      simplifiedCustomFieldTypes: 11,
      riskyCustomFields: 12,
      emptyCustomFieldNames: 2,
      multilineCustomFields: 3,
      colonValueCustomFields: 4,
      durabilityWarning: true
    })

    expect(message).toContain('4 個項目')
    expect(message).toContain('2 個資料夾')
    expect(message).toContain('垃圾桶中的 3 個項目')
    expect(message).toContain('6 個不支援的項目')
    expect(message).toContain('1 張卡片')
    expect(message).toContain('2 個身分資料')
    expect(message).toContain('3 個 SSH 金鑰')
    expect(message).toContain('CSV 無法表示的 5 個通行密鑰')
    expect(message).toContain('6 個附件')
    expect(message).toContain('7 筆密碼歷程記錄')
    expect(message).toContain('8 條 URI 比對規則')
    expect(message).toContain('9 個密碼修訂日期')
    expect(message).toContain('10 項自動填寫設定')
    expect(message).toContain('11 種自訂欄位類型已簡化為文字')
    expect(message).toContain('12 個自訂欄位可能無法保留原始結構')
    expect(message).toContain('2 個名稱空白')
    expect(message).toContain('3 個名稱或值含換行')
    expect(message).toContain('4 個值含「: 」')
    expect(message).toContain('檔案已發佈至所選位置')
    expect(message).toContain('無法確認目錄中繼資料是否已儲存')
    expect(message).toContain('決定是否重試前，請先確認檔案完整無誤')
  })

  it('scrubs the renderer-local export request after success and rejection', async () => {
    const success = {
      masterPassword: 'renderer-secret',
      format: 'bitwarden-csv' as const
    }
    await executeVaultExport(
      success,
      vi.fn(async () => ({
        canceled: true,
        exportedFolders: 0,
        exportedItems: 0,
        skippedTrashItems: 0
      }))
    )
    expect(success.masterPassword).toBe('')

    const failure = {
      masterPassword: 'renderer-secret',
      password: 'backup-secret',
      format: 'bitwarden-json' as const
    }
    const intended = new Error('intended export error')
    await expect(
      executeVaultExport(
        failure,
        vi.fn(async () => {
          throw intended
        })
      )
    ).rejects.toBe(intended)
    expect(failure).toMatchObject({ masterPassword: '', password: '' })
  })
})

describe('KeePass XML import warning', () => {
  it('binds each disclosed choice to an explicit import format and never sends a KeePass password', () => {
    expect(createVaultImportRequest('owner-proof', 'backup-secret', true)).toEqual({
      masterPassword: 'owner-proof',
      format: 'keepass-xml'
    })
    expect(createVaultImportRequest('owner-proof', 'backup-secret', false)).toEqual({
      masterPassword: 'owner-proof',
      password: 'backup-secret',
      format: 'portable'
    })
    expect(createVaultImportRequest('owner-proof', '', false)).toEqual({
      masterPassword: 'owner-proof',
      format: 'portable'
    })
  })

  it('states the plaintext and intentionally omitted data boundaries', () => {
    const markup = renderToStaticMarkup(<VaultKeePassXmlImportWarning />)

    expect(markup).toContain('未加密的純文字')
    expect(markup).toContain('安全刪除')
    expect(markup).toContain('個人項目')
    expect(markup).toContain('巢狀群組')
    expect(markup).toContain('附件二進位檔')
    expect(markup).toContain('歷史修訂版')
    expect(markup).toContain('進階中繼資料')
    expect(markup).toContain('資源回收筒')
    expect(markup).toContain('範本群組')
    expect(markup).toContain('TimeOtp')
    expect(markup).toContain('可產生驗證碼的格式')
    expect(markup).toContain('相互衝突')
    expect(markup).toContain('整個匯入作業會停止')
    expect(markup).toContain('不會悄悄略過驗證器')
  })

  it('reports every intentionally omitted KeePass category after import', () => {
    const message = formatVaultImportResult({
      canceled: false,
      importedFolders: 2,
      importedItems: 3,
      skippedTrashItems: 4,
      skippedTemplateEntries: 5,
      skippedAttachments: 6,
      skippedHistoryEntries: 7
    })

    expect(message).toContain('3 個項目')
    expect(message).toContain('2 個資料夾')
    expect(message).toContain('垃圾桶中的 4 個項目')
    expect(message).toContain('5 個範本項目')
    expect(message).toContain('6 個附件')
    expect(message).toContain('7 筆歷程記錄')
  })
})
