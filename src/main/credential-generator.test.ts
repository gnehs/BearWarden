import { readFile } from 'node:fs/promises'
import { describe, expect, it } from 'vitest'
import { VaultError } from './vault-errors'
import {
  generateCatchAllEmail,
  generatePassphrase,
  generatePassword,
  generatePlusAddressedEmail,
  generateRandomWordUsername,
  PASSPHRASE_LIMITS,
  PASSWORD_LIMITS,
  type RandomInt
} from './credential-generator'
import { decodeEffLongWordlist, loadEffLongWordlist } from './eff-wordlist'
import { EFF_LONG_WORDLIST_GZIP_BASE64, EFF_LONG_WORDLIST_SHA256 } from './eff-wordlist-asset'

const WORDS = ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel']

function zeroRandom(): number {
  return 0
}

function expectInvalid(action: () => unknown): void {
  try {
    action()
    throw new Error('expected INVALID_INPUT')
  } catch (error) {
    expect(error).toBeInstanceOf(VaultError)
    expect((error as VaultError).code).toBe('INVALID_INPUT')
    expect((error as Error).message).toBe('INVALID_INPUT')
  }
}

describe('credential generator', () => {
  it('generates the secure default password shape', () => {
    const password = generatePassword({}, zeroRandom)
    expect(password).toHaveLength(14)
    expect(password).toMatch(/[A-Z]/)
    expect(password).toMatch(/[a-z]/)
    expect(password).toMatch(/[0-9]/)
    expect(password).not.toMatch(/[!@#$%^&*]/)
  })

  it('honours minimum counts and excludes ambiguous characters', () => {
    const password = generatePassword(
      {
        length: 32,
        special: true,
        minUppercase: 4,
        minLowercase: 4,
        minNumbers: 4,
        minSpecial: 4,
        avoidAmbiguous: true
      },
      zeroRandom
    )
    expect(password).toHaveLength(32)
    expect((password.match(/[A-Z]/g) ?? []).length).toBeGreaterThanOrEqual(4)
    expect((password.match(/[a-z]/g) ?? []).length).toBeGreaterThanOrEqual(4)
    expect((password.match(/[0-9]/g) ?? []).length).toBeGreaterThanOrEqual(4)
    expect((password.match(/[!@#$%^&*]/g) ?? []).length).toBeGreaterThanOrEqual(4)
    expect(password).not.toMatch(/[0O1lI]/)
  })

  it('uses the injected random source without accepting biased values', () => {
    const seenLimits: number[] = []
    const randomInt: RandomInt = (limit) => {
      seenLimits.push(limit)
      return limit - 1
    }
    const password = generatePassword({ length: PASSWORD_LIMITS.minLength }, randomInt)
    expect(password).toHaveLength(PASSWORD_LIMITS.minLength)
    expect(seenLimits.length).toBeGreaterThan(0)
    expect(seenLimits.every((limit) => Number.isSafeInteger(limit) && limit > 0)).toBe(true)
    expectInvalid(() => generatePassword({}, () => Number.NaN))
    expectInvalid(() => generatePassword({}, () => 99_999))
  })

  it('rejects impossible or unsafe password options', () => {
    expectInvalid(() => generatePassword(null as never))
    expectInvalid(() => generatePassword({ length: null as never }))
    expectInvalid(() => generatePassword({ length: PASSWORD_LIMITS.minLength - 1 }))
    expectInvalid(() => generatePassword({ length: PASSWORD_LIMITS.maxLength + 1 }))
    expectInvalid(() => generatePassword({ uppercase: false, minUppercase: 1 }))
    expectInvalid(() => generatePassword({ minUppercase: 10, minLowercase: 10, minNumbers: 10 }))
    expectInvalid(() =>
      generatePassword({ uppercase: false, lowercase: false, numbers: false, special: false })
    )
    expectInvalid(() => generatePassword({ length: 14, special: false, minSpecial: 1 }))
    expectInvalid(() => generatePassword({ minNumber: 10 }))
    expectInvalid(() => generatePassword({ minSpecial: 10, special: true }))
    expectInvalid(() => generatePassword({ unknown: true } as never))
  })

  it('generates a six-word hyphenated passphrase by default', () => {
    const passphrase = generatePassphrase({}, WORDS, zeroRandom)
    expect(passphrase.split('-')).toHaveLength(6)
    expect(passphrase.split('-').every((word) => WORDS.includes(word))).toBe(true)
  })

  it('supports capitalization and exactly one included number', () => {
    const passphrase = generatePassphrase(
      { wordCount: 3, separator: '.', capitalize: true, includeNumber: true },
      WORDS,
      zeroRandom
    )
    const words = passphrase.split('.')
    expect(words).toHaveLength(3)
    expect(words.every((word) => /^[A-Z][a-z]*\d?$/u.test(word))).toBe(true)
    expect((passphrase.match(/\d/g) ?? []).length).toBe(1)
  })

  it('requires an injected, valid wordlist and bounded options', () => {
    expectInvalid(() => generatePassphrase(null as never, WORDS, zeroRandom))
    expectInvalid(() => generatePassphrase({}, [], zeroRandom))
    expectInvalid(() =>
      generatePassphrase({ wordCount: PASSPHRASE_LIMITS.minWords - 1 }, WORDS, zeroRandom)
    )
    expectInvalid(() =>
      generatePassphrase({ wordCount: PASSPHRASE_LIMITS.maxWords + 1 }, WORDS, zeroRandom)
    )
    expect(
      generatePassphrase({ wordCount: 3, separator: ' ' }, WORDS, zeroRandom).split(' ')
    ).toHaveLength(3)
    expectInvalid(() => generatePassphrase({ separator: '' }, WORDS, zeroRandom))
    expectInvalid(() => generatePassphrase({ separator: null as never }, WORDS, zeroRandom))
    expectInvalid(() => generatePassphrase({ separator: '🙂' }, WORDS, zeroRandom))
    expectInvalid(() => generatePassphrase({ extra: true } as never, WORDS, zeroRandom))
    expectInvalid(() => generatePassphrase({}, ['ok', 'bad word'], zeroRandom))
    expectInvalid(() => generatePassphrase({}, ['ok', 'ok'], zeroRandom))
  })

  it('authenticates and loads the complete official EFF list offline', () => {
    const words = loadEffLongWordlist()
    expect(words).toHaveLength(7_776)
    expect(words[0]).toBe('abacus')
    expect(words.at(-1)).toBe('zoom')
    expect(words).toContain('drop-down')
    expect(new Set(words).size).toBe(7_776)
    expect(Object.isFrozen(words)).toBe(true)
    expect(loadEffLongWordlist()).toBe(words)
    expect(() =>
      decodeEffLongWordlist(EFF_LONG_WORDLIST_GZIP_BASE64, `0${EFF_LONG_WORDLIST_SHA256.slice(1)}`)
    ).toThrow(expect.objectContaining({ code: 'INTERNAL_ERROR' }))
  })

  it('generates the official random-word username variants', () => {
    expect(generateRandomWordUsername({}, ['lowercase'], zeroRandom)).toBe('lowercase')
    expect(
      generateRandomWordUsername(
        { capitalize: true, includeNumber: true },
        ['lowercase'],
        zeroRandom
      )
    ).toBe('Lowercase0000')
    expectInvalid(() => generateRandomWordUsername({ extra: true } as never, WORDS, zeroRandom))
  })

  it('generates plus-addressed email locally and validates Unicode inputs', () => {
    expect(generatePlusAddressedEmail('使用者@例子.測試', zeroRandom)).toBe(
      '使用者+aaaaaaaa@例子.測試'
    )
    expect(generatePlusAddressedEmail('bear+existing@example.invalid', zeroRandom)).toBe(
      'bear+existingaaaaaaaa@example.invalid'
    )
    for (const invalidEmail of [
      '',
      ' bear@example.invalid',
      'bear@example.invalid ',
      'bear+@example.invalid',
      'bear@@example.invalid',
      'bear@-example.invalid',
      `${'a'.repeat(64)}@example.invalid`
    ]) {
      expectInvalid(() => generatePlusAddressedEmail(invalidEmail, zeroRandom))
    }
  })

  it('generates a local catch-all email with strict domain validation', () => {
    expect(generateCatchAllEmail('example.invalid', zeroRandom)).toBe('aaaaaaaa@example.invalid')
    expect(generateCatchAllEmail('@例子.測試', zeroRandom)).toBe('aaaaaaaa@例子.測試')
    for (const invalidDomain of ['', '@', 'two@signs.invalid', 'bad domain.invalid', '.invalid']) {
      expectInvalid(() => generateCatchAllEmail(invalidDomain, zeroRandom))
    }
  })

  it('contains no fallback randomness, runtime network, or secret logging path', async () => {
    const sources = await Promise.all(
      ['credential-generator.ts', 'eff-wordlist.ts'].map((name) =>
        readFile(new URL(name, import.meta.url), 'utf8')
      )
    )
    expect(sources.join('\n')).not.toMatch(/Math\.random|\bfetch\s*\(|https?:\/\/|console\./)
  })
})
