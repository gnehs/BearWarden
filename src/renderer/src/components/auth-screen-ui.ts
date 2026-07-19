export function touchIdUnlockFallback(error: unknown): {
  unlockMethod: 'master-password'
  error: string
} {
  return {
    unlockMethod: 'master-password',
    error:
      error instanceof Error && error.message.includes('TOUCH_ID_UNAVAILABLE')
        ? 'Touch ID 目前無法使用，請輸入主密碼。'
        : '無法使用 Touch ID 開啟密碼庫，請輸入主密碼。'
  }
}
