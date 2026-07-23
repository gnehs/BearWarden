import { describe, expect, it } from 'vitest'
import { canRevealSecretsOnHover } from './VaultDetailFieldRows-model'

describe('canRevealSecretsOnHover', () => {
  it('keeps the existing hover reveal behavior for personal items', () => {
    expect(canRevealSecretsOnHover(null)).toBe(true)
  })

  it('allows shared items to reveal on hover only when password viewing is permitted', () => {
    expect(canRevealSecretsOnHover({ viewPassword: true, reprompt: 0 })).toBe(true)
    expect(canRevealSecretsOnHover({ viewPassword: false, reprompt: 0 })).toBe(false)
  })

  it('does not silently bypass item reprompt on hover', () => {
    expect(canRevealSecretsOnHover({ viewPassword: true, reprompt: 1 })).toBe(false)
  })
})
