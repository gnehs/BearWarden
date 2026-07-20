import { describe, expect, it } from 'vitest'
import { describeError, touchIdUnlockFallback } from './auth-screen-ui'

describe('AuthScreen unlock errors', () => {
  it.each([
    ['BEARWARDEN:INVALID_MASTER_PASSWORD', '主密碼不正確。'],
    ['BEARWARDEN:INVALID_PIN', 'PIN 不正確。'],
    ['BEARWARDEN:PIN_DISABLED', 'PIN 解鎖已停用，請改用主密碼。'],
    ['BEARWARDEN:RATE_LIMITED', '嘗試次數過多，請稍後再試。'],
    ['BEARWARDEN:INVALID_INPUT', '請檢查輸入內容。'],
    [
      'BEARWARDEN:CORRUPT_VAULT',
      '無法讀取密碼庫資料，請再試一次。若持續出現，密碼庫檔案可能已損毀。'
    ],
    ['BEARWARDEN:NOT_INITIALIZED', '找不到密碼庫檔案，請確認資料未被移動或刪除。']
  ])('describes %s without blaming the vault', (code, message) => {
    expect(
      describeError(new Error(`Error invoking remote method 'vault:unlock': Error: ${code}`))
    ).toBe(message)
  })

  it('invites a retry when a concurrent lock invalidates an in-flight unlock', () => {
    expect(
      describeError(
        new Error("Error invoking remote method 'vault:unlock': Error: BEARWARDEN:LOCKED")
      )
    ).toBe('密碼庫已鎖定，請再試一次。')
  })

  it.each([new Error('secret internal detail'), 'secret internal detail'])(
    'does not expose unknown error details',
    (error) => {
      const message = describeError(error)
      expect(message).not.toContain('secret internal detail')
      expect(message).toMatch(/稍後再試。$/)
    }
  )
})

describe('AuthScreen biometric fallback', () => {
  it('directs the user to the master password after a biometric failure', () => {
    expect(touchIdUnlockFallback(new Error('TOUCH_ID_FAILED'))).toEqual({
      unlockMethod: 'master-password',
      error: '無法使用生物辨識開啟密碼庫，請輸入主密碼。'
    })
  })

  it('directs the user to the master password when biometrics are unavailable', () => {
    expect(touchIdUnlockFallback(new Error('TOUCH_ID_UNAVAILABLE'))).toEqual({
      unlockMethod: 'master-password',
      error: '生物辨識目前無法使用，請輸入主密碼。'
    })
  })

  it.each([new Error('secret internal detail'), 'secret internal detail'])(
    'does not expose unknown error details',
    (error) => {
      expect(touchIdUnlockFallback(error).error).not.toContain('secret internal detail')
    }
  )
})
