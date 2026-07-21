import { describe, expect, it } from 'vitest'
import { describeError, isRepromptRequired } from './vault-error-ui'

describe('describeError', () => {
  it('maps known error codes and falls back for unknown errors', () => {
    const messages = { VAULT_LOCKED: 'Vault is locked' }

    expect(
      describeError(new Error('VAULT_LOCKED: unavailable'), messages, 'Unknown', 'Failed')
    ).toBe('Vault is locked')
    expect(describeError(new Error('OTHER_ERROR'), messages, 'Unknown', 'Failed')).toBe('Failed')
    expect(describeError('VAULT_LOCKED', messages, 'Unknown', 'Failed')).toBe('Unknown')
  })
})

describe('isRepromptRequired', () => {
  it('recognizes only Error instances with the reprompt code', () => {
    expect(isRepromptRequired(new Error('REPROMPT_REQUIRED: authorize'))).toBe(true)
    expect(isRepromptRequired(new Error('VAULT_LOCKED'))).toBe(false)
    expect(isRepromptRequired('REPROMPT_REQUIRED')).toBe(false)
  })
})
