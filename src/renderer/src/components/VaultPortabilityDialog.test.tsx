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

    expect(markup).toContain('未封存與封存')
    expect(markup).toContain('不是完整備份')
    expect(markup).toContain('垃圾桶')
    expect(markup).toContain('附件')
    expect(markup).toContain('卡片')
    expect(markup).toContain('身分')
    expect(markup).toContain('SSH')
    expect(markup).toContain('Passkey')
    expect(markup).toContain('Sends')
    expect(markup).toContain('試算表')
    expect(markup).toContain('公式')
    expect(markup).toContain('不會改寫這些秘密')
    expect(markup).toContain('自訂欄位會被壓成')
    expect(markup).toContain('型別')
    expect(markup).toContain('原始結構可能無法還原')
    expect(markup).toContain('加密')
    expect(markup).toContain('JSON')
    expect(markup).toContain('BearWarden 完整備份')
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
    expect(message).toContain('6 個不支援項目')
    expect(message).toContain('卡片 1')
    expect(message).toContain('身分 2')
    expect(message).toContain('SSH 金鑰 3')
    expect(message).toContain('5 個無法由 CSV 表示的 Passkey')
    expect(message).toContain('6 個附件')
    expect(message).toContain('7 筆密碼歷史')
    expect(message).toContain('8 個 URI 比對規則')
    expect(message).toContain('9 筆密碼更新時間')
    expect(message).toContain('10 筆自動填入設定')
    expect(message).toContain('11 個被簡化為文字的自訂欄位型別')
    expect(message).toContain('12 個自訂欄位無法保證原結構')
    expect(message).toContain('空名稱 2')
    expect(message).toContain('名稱或值含換行 3')
    expect(message).toContain('值含「: 」 4')
    expect(message).toContain('檔案已發布到選定位置')
    expect(message).toContain('無法確認目錄 metadata 已持久化')
    expect(message).toContain('先檢查檔案是否完整')
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

    expect(markup).toContain('未加密明文')
    expect(markup).toContain('安全刪除')
    expect(markup).toContain('個人 Entry')
    expect(markup).toContain('巢狀群組')
    expect(markup).toContain('附件 Binary')
    expect(markup).toContain('History')
    expect(markup).toContain('進階 metadata')
    expect(markup).toContain('回收桶')
    expect(markup).toContain('範本群組')
    expect(markup).toContain('TimeOtp')
    expect(markup).toContain('可產碼格式')
    expect(markup).toContain('互相衝突')
    expect(markup).toContain('整次匯入會停止')
    expect(markup).toContain('不會靜默略過驗證碼')
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
    expect(message).toContain('4 個垃圾桶項目')
    expect(message).toContain('5 個範本項目')
    expect(message).toContain('6 個附件')
    expect(message).toContain('7 筆歷史版本')
  })
})
