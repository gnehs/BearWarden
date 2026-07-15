import { describe, expect, it } from 'vitest'
import { generateTotp } from './totp'

describe('generateTotp', () => {
  it.each([
    [59_000, '94287082'],
    [1_111_111_109_000, '07081804'],
    [1_111_111_111_000, '14050471'],
    [1_234_567_890_000, '89005924'],
    [2_000_000_000_000, '69279037']
  ])('matches the RFC 6238 SHA-1 vector at %i', (timestamp, expected) => {
    const result = generateTotp(
      'otpauth://totp/example.invalid?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=8&period=30',
      new Date(timestamp)
    )
    expect(result.code).toBe(expected)
  })

  it('supports a raw base32 secret and exposes the countdown', () => {
    expect(generateTotp('JBSW Y3DP-EHPK3PXP', new Date(59_000))).toEqual({
      code: '996554',
      period: 30,
      remainingSeconds: 1
    })
  })

  it.each([
    '',
    'not base32!',
    'otpauth://hotp/example.invalid?secret=JBSWY3DPEHPK3PXP',
    'otpauth://totp/example.invalid?secret=JBSWY3DPEHPK3PXP&digits=2'
  ])('rejects invalid input without leaking the secret (%s)', (value) => {
    expect(() => generateTotp(value)).toThrowError('INVALID_INPUT')
  })
})
