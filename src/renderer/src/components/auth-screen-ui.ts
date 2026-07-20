/**
 * Maps unlock/setup failures to stable, renderer-safe messages. `LOCKED` surfaces when a
 * concurrent lock (screen lock, suspend, timeout) wins against an in-flight unlock KDF; the
 * master password was not rejected, so the message must invite a retry instead of alarming.
 */
export function describeError(error: unknown): string {
  if (!(error instanceof Error)) return '發生未知錯誤，請稍後再試。'
  if (error.message.includes('INVALID_MASTER_PASSWORD')) return '主密碼不正確。'
  if (error.message.includes('INVALID_PIN')) return 'PIN 不正確。'
  if (error.message.includes('PIN_DISABLED')) return 'PIN 解鎖已停用，請改用主密碼。'
  if (error.message.includes('RATE_LIMITED')) return '嘗試次數過多，請稍後再試。'
  if (error.message.includes('INVALID_INPUT')) return '請檢查輸入內容。'
  if (error.message.includes('LOCKED')) return '密碼庫已鎖定，請再試一次。'
  if (error.message.includes('CORRUPT_VAULT')) {
    return '無法讀取密碼庫資料，請再試一次。若持續出現，密碼庫檔案可能已損毀。'
  }
  if (error.message.includes('NOT_INITIALIZED'))
    return '找不到密碼庫檔案，請確認資料未被移動或刪除。'
  return '目前無法開啟密碼庫，請稍後再試。'
}

export function touchIdUnlockFallback(error: unknown): {
  unlockMethod: 'master-password'
  error: string
} {
  return {
    unlockMethod: 'master-password',
    error:
      error instanceof Error && error.message.includes('TOUCH_ID_UNAVAILABLE')
        ? '生物辨識目前無法使用，請輸入主密碼。'
        : '無法使用生物辨識開啟密碼庫，請輸入主密碼。'
  }
}
