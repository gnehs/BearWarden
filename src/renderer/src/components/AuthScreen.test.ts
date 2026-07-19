import { describe, expect, it } from 'vitest'
import { touchIdUnlockFallback } from './auth-screen-ui'

describe('AuthScreen Touch ID fallback', () => {
  it('directs the user to the master password after a Touch ID failure', () => {
    expect(touchIdUnlockFallback(new Error('TOUCH_ID_FAILED'))).toEqual({
      unlockMethod: 'master-password',
      error: '無法使用 Touch ID 開啟密碼庫，請輸入主密碼。'
    })
  })

  it('directs the user to the master password when Touch ID is unavailable', () => {
    expect(touchIdUnlockFallback(new Error('TOUCH_ID_UNAVAILABLE'))).toEqual({
      unlockMethod: 'master-password',
      error: 'Touch ID 目前無法使用，請輸入主密碼。'
    })
  })

  it.each([new Error('secret internal detail'), 'secret internal detail'])(
    'does not expose unknown error details',
    (error) => {
      expect(touchIdUnlockFallback(error).error).not.toContain('secret internal detail')
    }
  )
})
