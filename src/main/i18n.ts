import { setupI18n, type Messages } from '@lingui/core'
import type { AppLanguagePreference } from '../shared/vault-contract'

export const mainLocales = ['en', 'zh-CN', 'zh-TW', 'ja'] as const

export type MainLocale = (typeof mainLocales)[number]

const en = {
  'applicationMenu.vault': 'Vault',
  'applicationMenu.lock': 'Lock',
  'applicationMenu.item': 'Item',
  'applicationMenu.view': 'View',
  'itemContext.website': 'Website',
  'itemContext.unfiled': 'Unfiled',
  'itemContext.moveToFolder': 'Move to Folder',
  'itemContext.openInBrowser': 'Open in Browser',
  'itemContext.copyWebsite': 'Copy Website',
  'itemContext.copyUsername': 'Copy Username',
  'itemContext.copyPassword': 'Copy Password',
  'itemContext.copyTotp': 'Copy Verification Code',
  'itemContext.duplicateItem': 'Duplicate Item',
  'itemContext.unarchive': 'Unarchive',
  'itemContext.archiveItem': 'Archive Item',
  'itemContext.deleteItem': 'Delete Item',
  'touchId.enableUnlock': 'Enable biometric unlock for BearWarden',
  'touchId.createPasskey': 'Create a new BearWarden passkey',
  'touchId.usePasskey': 'Sign in with a BearWarden passkey',
  'touchId.unlock': 'Unlock BearWarden with biometrics',
  'authRequest.title': 'Bitwarden login request received',
  'authRequest.body':
    'Another device requested login. Open BearWarden and verify the fingerprint phrase.',
  'attachment.uploadTitle': 'Upload Attachment',
  'attachment.select': 'Select',
  'attachment.allFiles': 'All Files',
  'attachment.downloadTitle': 'Download Attachment',
  'attachment.save': 'Save',
  'export.bitwardenZipTitle': 'Export Bitwarden Plaintext Attachment ZIP',
  'export.bitwardenCsvTitle': 'Export Bitwarden Plaintext CSV',
  'export.encryptedVaultTitle': 'Export Encrypted Vault',
  'export.button': 'Export',
  'export.nativeBackupFilter': 'BearWarden Native Attachment Backup',
  'export.bitwardenZipFilter': 'Bitwarden ZIP (with attachments)',
  'export.bitwardenCsvFilter': 'Bitwarden CSV',
  'export.bitwardenJsonFilter': 'Bitwarden JSON',
  'import.nativeBackupTitle': 'Restore BearWarden Native Attachment Backup',
  'import.keepassTitle': 'Import KeePass 2 XML',
  'import.passwordDataTitle': 'Import Bitwarden or Chrome Password Data',
  'import.button': 'Import',
  'import.keepassFilter': 'KeePass 2 XML',
  'import.passwordCsvFilter': 'Bitwarden or Chrome CSV',
  'nativeDialog.protectedItem': 'this protected item',
  'nativeDialog.actionFailedTitle': 'Action Failed',
  'nativeDialog.actionFailedMessage': 'Unable to complete this action',
  'nativeDialog.actionFailedDetail':
    'Try again later. No vault data was removed because of this failure.',
  'nativeDialog.moveToTrash': 'Move to Trash',
  'nativeDialog.cancel': 'Cancel',
  'nativeDialog.deleteItemTitle': 'Delete Item',
  'nativeDialog.deleteConfirmationPrefix': 'Are you sure you want to delete “',
  'nativeDialog.deleteConfirmationSuffix': '”?',
  'nativeDialog.restoreFromTrashDetail': 'You can restore this item from Trash later.'
} as const

export type MainMessageId = keyof typeof en

const zhCN: Record<MainMessageId, string> = {
  'applicationMenu.vault': '密码库',
  'applicationMenu.lock': '锁定',
  'applicationMenu.item': '项目',
  'applicationMenu.view': '显示',
  'itemContext.website': '网站',
  'itemContext.unfiled': '未分类',
  'itemContext.moveToFolder': '移至文件夹',
  'itemContext.openInBrowser': '在浏览器中打开',
  'itemContext.copyWebsite': '复制网站',
  'itemContext.copyUsername': '复制用户名',
  'itemContext.copyPassword': '复制密码',
  'itemContext.copyTotp': '复制验证码',
  'itemContext.duplicateItem': '复制项目',
  'itemContext.unarchive': '取消归档',
  'itemContext.archiveItem': '归档项目',
  'itemContext.deleteItem': '删除项目',
  'touchId.enableUnlock': '启用生物识别解锁 BearWarden',
  'touchId.createPasskey': '创建新的 BearWarden 通行密钥',
  'touchId.usePasskey': '使用 BearWarden 通行密钥登录',
  'touchId.unlock': '使用生物识别解锁 BearWarden',
  'authRequest.title': '收到 Bitwarden 登录请求',
  'authRequest.body': '另一台设备请求登录。请打开 BearWarden 并核对验证短语。',
  'attachment.uploadTitle': '上传附件',
  'attachment.select': '选择',
  'attachment.allFiles': '所有文件',
  'attachment.downloadTitle': '下载附件',
  'attachment.save': '保存',
  'export.bitwardenZipTitle': '导出 Bitwarden 明文附件 ZIP',
  'export.bitwardenCsvTitle': '导出 Bitwarden 明文 CSV',
  'export.encryptedVaultTitle': '导出加密密码库',
  'export.button': '导出',
  'export.nativeBackupFilter': 'BearWarden 原生附件备份',
  'export.bitwardenZipFilter': 'Bitwarden ZIP（含附件）',
  'export.bitwardenCsvFilter': 'Bitwarden CSV',
  'export.bitwardenJsonFilter': 'Bitwarden JSON',
  'import.nativeBackupTitle': '还原 BearWarden 原生附件备份',
  'import.keepassTitle': '导入 KeePass 2 XML',
  'import.passwordDataTitle': '导入 Bitwarden 或 Chrome 密码数据',
  'import.button': '导入',
  'import.keepassFilter': 'KeePass 2 XML',
  'import.passwordCsvFilter': 'Bitwarden 或 Chrome CSV',
  'nativeDialog.protectedItem': '这个受保护项目',
  'nativeDialog.actionFailedTitle': '操作失败',
  'nativeDialog.actionFailedMessage': '无法完成此操作',
  'nativeDialog.actionFailedDetail': '请稍后重试；此次失败没有移除你的密码库数据。',
  'nativeDialog.moveToTrash': '移至回收站',
  'nativeDialog.cancel': '取消',
  'nativeDialog.deleteItemTitle': '删除项目',
  'nativeDialog.deleteConfirmationPrefix': '确定要删除“',
  'nativeDialog.deleteConfirmationSuffix': '”吗？',
  'nativeDialog.restoreFromTrashDetail': '你可以稍后从回收站还原此项目。'
}

const zhTW: Record<MainMessageId, string> = {
  'applicationMenu.vault': '密碼庫',
  'applicationMenu.lock': '鎖定',
  'applicationMenu.item': '項目',
  'applicationMenu.view': '顯示方式',
  'itemContext.website': '網站',
  'itemContext.unfiled': '未分類',
  'itemContext.moveToFolder': '移至資料夾',
  'itemContext.openInBrowser': '在瀏覽器打開',
  'itemContext.copyWebsite': '複製網站',
  'itemContext.copyUsername': '複製使用者名稱',
  'itemContext.copyPassword': '複製密碼',
  'itemContext.copyTotp': '複製驗證碼',
  'itemContext.duplicateItem': '複製項目',
  'itemContext.unarchive': '取消封存',
  'itemContext.archiveItem': '封存項目',
  'itemContext.deleteItem': '刪除項目',
  'touchId.enableUnlock': '啟用生物辨識解鎖 BearWarden',
  'touchId.createPasskey': '建立新的 BearWarden 通行密鑰',
  'touchId.usePasskey': '使用 BearWarden 通行密鑰登入',
  'touchId.unlock': '使用生物辨識解鎖 BearWarden',
  'authRequest.title': '收到 Bitwarden 登入要求',
  'authRequest.body': '另一部裝置要求登入。請開啟 BearWarden 並核對驗證詞組。',
  'attachment.uploadTitle': '上傳附件',
  'attachment.select': '選擇',
  'attachment.allFiles': '所有檔案',
  'attachment.downloadTitle': '下載附件',
  'attachment.save': '儲存',
  'export.bitwardenZipTitle': '匯出 Bitwarden 明文附件 ZIP',
  'export.bitwardenCsvTitle': '匯出 Bitwarden 明文 CSV',
  'export.encryptedVaultTitle': '匯出加密密碼庫',
  'export.button': '匯出',
  'export.nativeBackupFilter': 'BearWarden 原生附件備份',
  'export.bitwardenZipFilter': 'Bitwarden ZIP（含附件）',
  'export.bitwardenCsvFilter': 'Bitwarden CSV',
  'export.bitwardenJsonFilter': 'Bitwarden JSON',
  'import.nativeBackupTitle': '還原 BearWarden 原生附件備份',
  'import.keepassTitle': '匯入 KeePass 2 XML',
  'import.passwordDataTitle': '匯入 Bitwarden 或 Chrome 密碼資料',
  'import.button': '匯入',
  'import.keepassFilter': 'KeePass 2 XML',
  'import.passwordCsvFilter': 'Bitwarden 或 Chrome CSV',
  'nativeDialog.protectedItem': '這個受保護項目',
  'nativeDialog.actionFailedTitle': '操作失敗',
  'nativeDialog.actionFailedMessage': '無法完成這個動作',
  'nativeDialog.actionFailedDetail': '請稍後再試；你的密碼庫資料沒有因這次失敗而被移除。',
  'nativeDialog.moveToTrash': '移至垃圾桶',
  'nativeDialog.cancel': '取消',
  'nativeDialog.deleteItemTitle': '刪除項目',
  'nativeDialog.deleteConfirmationPrefix': '確定要刪除「',
  'nativeDialog.deleteConfirmationSuffix': '」嗎？',
  'nativeDialog.restoreFromTrashDetail': '你可以之後從垃圾桶還原這個項目。'
}

const ja: Record<MainMessageId, string> = {
  'applicationMenu.vault': '保管庫',
  'applicationMenu.lock': 'ロック',
  'applicationMenu.item': '項目',
  'applicationMenu.view': '表示',
  'itemContext.website': 'ウェブサイト',
  'itemContext.unfiled': '未分類',
  'itemContext.moveToFolder': 'フォルダーに移動',
  'itemContext.openInBrowser': 'ブラウザーで開く',
  'itemContext.copyWebsite': 'ウェブサイトをコピー',
  'itemContext.copyUsername': 'ユーザー名をコピー',
  'itemContext.copyPassword': 'パスワードをコピー',
  'itemContext.copyTotp': '認証コードをコピー',
  'itemContext.duplicateItem': '項目を複製',
  'itemContext.unarchive': 'アーカイブを解除',
  'itemContext.archiveItem': '項目をアーカイブ',
  'itemContext.deleteItem': '項目を削除',
  'touchId.enableUnlock': 'BearWarden の生体認証ロック解除を有効にする',
  'touchId.createPasskey': '新しい BearWarden パスキーを作成',
  'touchId.usePasskey': 'BearWarden パスキーでサインイン',
  'touchId.unlock': '生体認証で BearWarden のロックを解除',
  'authRequest.title': 'Bitwarden のログイン要求を受信しました',
  'authRequest.body':
    '別のデバイスからログインが要求されました。BearWarden を開き、検証フレーズを確認してください。',
  'attachment.uploadTitle': '添付ファイルをアップロード',
  'attachment.select': '選択',
  'attachment.allFiles': 'すべてのファイル',
  'attachment.downloadTitle': '添付ファイルをダウンロード',
  'attachment.save': '保存',
  'export.bitwardenZipTitle': 'Bitwarden 平文添付ファイル ZIP をエクスポート',
  'export.bitwardenCsvTitle': 'Bitwarden 平文 CSV をエクスポート',
  'export.encryptedVaultTitle': '暗号化された保管庫をエクスポート',
  'export.button': 'エクスポート',
  'export.nativeBackupFilter': 'BearWarden ネイティブ添付ファイルバックアップ',
  'export.bitwardenZipFilter': 'Bitwarden ZIP（添付ファイルを含む）',
  'export.bitwardenCsvFilter': 'Bitwarden CSV',
  'export.bitwardenJsonFilter': 'Bitwarden JSON',
  'import.nativeBackupTitle': 'BearWarden ネイティブ添付ファイルバックアップを復元',
  'import.keepassTitle': 'KeePass 2 XML をインポート',
  'import.passwordDataTitle': 'Bitwarden または Chrome のパスワードデータをインポート',
  'import.button': 'インポート',
  'import.keepassFilter': 'KeePass 2 XML',
  'import.passwordCsvFilter': 'Bitwarden または Chrome CSV',
  'nativeDialog.protectedItem': 'この保護された項目',
  'nativeDialog.actionFailedTitle': '操作に失敗しました',
  'nativeDialog.actionFailedMessage': 'この操作を完了できません',
  'nativeDialog.actionFailedDetail':
    '後でもう一度お試しください。この失敗によって保管庫のデータが削除されることはありません。',
  'nativeDialog.moveToTrash': 'ゴミ箱に移動',
  'nativeDialog.cancel': 'キャンセル',
  'nativeDialog.deleteItemTitle': '項目を削除',
  'nativeDialog.deleteConfirmationPrefix': '「',
  'nativeDialog.deleteConfirmationSuffix': '」を削除してもよろしいですか？',
  'nativeDialog.restoreFromTrashDetail': 'この項目は後でゴミ箱から復元できます。'
}

const catalogs: Record<MainLocale, Messages> = {
  en,
  'zh-CN': zhCN,
  'zh-TW': zhTW,
  ja
}

export const mainI18n = setupI18n({
  locale: 'en',
  messages: catalogs
})

/** Maps Electron/Chromium locale variants onto the catalogs shipped in the main bundle. */
export function normalizeMainLocale(locale: string | null | undefined): MainLocale {
  if (!locale) return 'en'

  const normalized = locale.replaceAll('_', '-').toLowerCase()
  if (
    normalized === 'zh' ||
    normalized.startsWith('zh-cn') ||
    normalized.startsWith('zh-sg') ||
    normalized.startsWith('zh-hans')
  ) {
    return 'zh-CN'
  }
  if (
    normalized.startsWith('zh-tw') ||
    normalized.startsWith('zh-hk') ||
    normalized.startsWith('zh-mo') ||
    normalized.startsWith('zh-hant')
  ) {
    return 'zh-TW'
  }
  if (normalized.startsWith('ja')) return 'ja'
  if (normalized.startsWith('en')) return 'en'
  return 'en'
}

export function initializeMainI18n(locale: string | null | undefined): MainLocale {
  const normalized = normalizeMainLocale(locale)
  mainI18n.activate(normalized)
  return normalized
}

export function initializeMainI18nFromPreference(
  preference: AppLanguagePreference,
  systemLocale: string | null | undefined
): MainLocale {
  return initializeMainI18n(preference === 'system' ? systemLocale : preference)
}

export function translateMain(id: MainMessageId): string {
  return mainI18n._(id)
}
