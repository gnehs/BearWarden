import { describe, expect, it } from 'vitest'
import {
  autofillPickerHostname,
  autofillPickerSearchValue,
  type AutofillPickerChoice
} from './autofill-picker-ui'

function choice(overrides: Partial<AutofillPickerChoice> = {}): AutofillPickerChoice {
  return {
    id: 'login-1',
    name: '範例帳號',
    username: 'hello@example.test',
    uri: 'https://accounts.example.test/login?token=do-not-render',
    reprompt: false,
    ...overrides
  }
}

describe('autofill picker presentation', () => {
  it('searches only the display name, username, and hostname', () => {
    const value = autofillPickerSearchValue(choice())

    expect(value).toBe('範例帳號 hello@example.test accounts.example.test')
    expect(value).not.toContain('/login')
    expect(value).not.toContain('token=')
  })

  it('prefers an explicitly supplied hostname and rejects malformed URIs', () => {
    expect(autofillPickerHostname(choice({ hostname: 'signin.example.test' }))).toBe(
      'signin.example.test'
    )
    expect(autofillPickerHostname(choice({ uri: 'not a URL' }))).toBe('')
  })
})
