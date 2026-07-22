import { describe, expect, it } from 'vitest'
import { authAccountItems, describeError, touchIdUnlockFallback } from './auth-screen-ui'

describe('AuthScreen local accounts', () => {
  it('shows only user-defined local labels with a slot fallback', () => {
    const activeAccountId = '11111111-1111-4111-8111-111111111111'
    expect(
      authAccountItems({
        revision: 3,
        activeAccountId,
        accounts: [
          { id: activeAccountId, active: true, slot: 1, displayName: 'Personal' },
          {
            id: '22222222-2222-4222-8222-222222222222',
            active: false,
            slot: 2
          }
        ]
      })
    ).toEqual([
      { value: activeAccountId, label: 'Personal' },
      { value: '22222222-2222-4222-8222-222222222222', label: '帳戶 2' }
    ])
  })

  it('has no account choices while status is unavailable', () => {
    expect(authAccountItems(null)).toEqual([])
  })
})

describe('AuthScreen unlock errors', () => {
  it.each([
    ['BEARWARDEN:INVALID_MASTER_PASSWORD', '主密碼不正確。'],
    ['BEARWARDEN:INVALID_PIN', 'PIN 不正確。'],
    ['BEARWARDEN:PIN_DISABLED', 'PIN 解鎖已停用。請改用主密碼。'],
    ['BEARWARDEN:RATE_LIMITED', '嘗試次數過多。請稍後再試。'],
    ['BEARWARDEN:INVALID_INPUT', '請檢查您的輸入。'],
    [
      'BEARWARDEN:CORRUPT_VAULT',
      '無法讀取保管庫資料。請再試一次。若問題持續發生，保管庫檔案可能已損毀。'
    ],
    ['BEARWARDEN:NOT_INITIALIZED', '找不到保管庫檔案。請確認檔案未被移動或刪除。']
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
    ).toBe('保管庫已鎖定。請再試一次。')
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
      error: '無法使用生物辨識驗證開啟保管庫。請輸入主密碼。'
    })
  })

  it('directs the user to the master password when biometrics are unavailable', () => {
    expect(touchIdUnlockFallback(new Error('TOUCH_ID_UNAVAILABLE'))).toEqual({
      unlockMethod: 'master-password',
      error: '目前無法使用生物辨識驗證。請輸入您的主密碼。'
    })
  })

  it.each([new Error('secret internal detail'), 'secret internal detail'])(
    'does not expose unknown error details',
    (error) => {
      expect(touchIdUnlockFallback(error).error).not.toContain('secret internal detail')
    }
  )
})
