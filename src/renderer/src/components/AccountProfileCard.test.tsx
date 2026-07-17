import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import AccountProfileCard from './AccountProfileCard'
import { isAvatarColor, profileNameValidationError } from './account-profile-validation'

describe('AccountProfileCard input boundary', () => {
  it('preserves names exactly while enforcing the UTF-8 byte limit', () => {
    expect(profileNameValidationError('')).toBeNull()
    expect(profileNameValidationError('  原樣保留  ')).toBeNull()
    expect(profileNameValidationError('é')).toBeNull()
    expect(profileNameValidationError('a'.repeat(50))).toBeNull()
    expect(profileNameValidationError('界'.repeat(17))).toContain('50')
  })

  it.each(['name\0part', 'first\rsecond', 'first\nsecond'])(
    'rejects control-separated name %j',
    (name) => {
      expect(profileNameValidationError(name)).not.toBeNull()
    }
  )

  it('only accepts exact six-digit hexadecimal avatar colors', () => {
    expect(isAvatarColor('#123ABC')).toBe(true)
    expect(isAvatarColor('#abcdef')).toBe(true)
    expect(isAvatarColor('123ABC')).toBe(false)
    expect(isAvatarColor('#123')).toBe(false)
    expect(isAvatarColor('#123ABCG')).toBe(false)
    expect(isAvatarColor('#123ABC\n')).toBe(false)
  })

  it('shows the current profile, readonly email, and independent actions', () => {
    const markup = renderToStaticMarkup(
      <AccountProfileCard
        onProfileChange={() => undefined}
        profile={{
          name: 'Example User',
          email: 'profile@example.invalid',
          avatarColor: '#123ABC',
          emailVerified: true,
          twoFactorEnabled: false
        }}
      />
    )

    expect(markup).toContain('value="Example User"')
    expect(markup).toContain('value="profile@example.invalid"')
    expect(markup).toContain('readOnly')
    expect(markup).toContain('儲存顯示名稱')
    expect(markup).toContain('儲存頭像顏色')
    expect(markup).toContain('清除自訂顏色')
    expect(markup).toContain('type="color"')
  })
})
