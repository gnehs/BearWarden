import { describe, expect, it } from 'vitest'
import { generateTotp } from './totp'

describe('generateTotp', () => {
  const rfcSha1Secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'

  it.each([
    [59_000, '94287082'],
    [1_111_111_109_000, '07081804'],
    [1_111_111_111_000, '14050471'],
    [1_234_567_890_000, '89005924'],
    [2_000_000_000_000, '69279037']
  ])('matches the RFC 6238 SHA-1 vector at %i', (timestamp, expected) => {
    const result = generateTotp(
      `otpauth://totp/example.invalid?secret=${rfcSha1Secret}&algorithm=SHA1&digits=8&period=30`,
      new Date(timestamp)
    )
    expect(result.code).toBe(expected)
  })

  it.each([
    ['SHA256', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA', '46119246'],
    [
      'SHA512',
      'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA',
      '90693936'
    ]
  ])('matches the RFC 6238 %s vector', (algorithm, secret, expected) => {
    const result = generateTotp(
      `otpauth://totp/example.invalid?secret=${secret}&algorithm=${algorithm}&digits=8&period=30`,
      new Date(59_000)
    )
    expect(result.code).toBe(expected)
  })

  it.each(['steam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ', 'StEaM://hxdmvjecjjwsrb3hwizr4ifugftmxboz'])(
    'matches the Bitwarden Steam vector for %s',
    (secret) => {
      expect(generateTotp(secret, new Date('2023-01-01T00:00:00.000Z'))).toEqual({
        code: '7W6CJ',
        period: 30,
        remainingSeconds: 30
      })
    }
  )

  it.each([
    [1, '2'],
    [10, '1094287082']
  ])('supports %i-digit otpauth codes', (digits, expected) => {
    expect(
      generateTotp(
        `otpauth://totp/example.invalid?secret=${rfcSha1Secret}&digits=${digits}`,
        new Date(59_000)
      ).code
    ).toBe(expected)
  })

  it.each([
    [301, '795389'],
    [0xffff_ffff, '755224']
  ])('supports a period of %i seconds', (period, expected) => {
    const result = generateTotp(
      `otpauth://totp/example.invalid?secret=${rfcSha1Secret}&period=${period}`,
      new Date('2023-01-01T00:00:00.000Z')
    )
    expect(result.code).toBe(expected)
    expect(result.period).toBe(period)
    expect(result.remainingSeconds).toBe(period - (1_672_531_200 % period))
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
    'steam://',
    'steam://ABCD123',
    'otpauth://hotp/example.invalid?secret=JBSWY3DPEHPK3PXP',
    'otpauth://totp/example.invalid',
    'otpauth://totp/example.invalid?secret=',
    'otpauth://totp/example.invalid?secret=JBSWY3DPEHPK3PXP&algorithm=MD5',
    'otpauth://totp/example.invalid?secret=JBSWY3DPEHPK3PXP&digits=0',
    'otpauth://totp/example.invalid?secret=JBSWY3DPEHPK3PXP&digits=11',
    'otpauth://totp/example.invalid?secret=JBSWY3DPEHPK3PXP&period=0',
    'otpauth://totp/example.invalid?secret=JBSWY3DPEHPK3PXP&period=4294967296',
    `otpauth://totp/example.invalid?secret=${'A'.repeat(1_640)}`
  ])('rejects invalid input without leaking the secret (%s)', (value) => {
    expect(() => generateTotp(value)).toThrowError('INVALID_INPUT')
  })

  it('rejects invalid time after parsing a valid secret', () => {
    expect(() => generateTotp(rfcSha1Secret, new Date(Number.NaN))).toThrowError('INVALID_INPUT')
  })
})
