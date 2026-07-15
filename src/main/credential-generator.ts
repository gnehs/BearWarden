import { randomInt as nodeRandomInt } from 'node:crypto'
import { domainToASCII } from 'node:url'
import { VaultError } from './vault-errors'

/** A synchronous, unbiased random integer source in [0, maxExclusive). */
export type RandomInt = (maxExclusive: number) => number

export interface PasswordGeneratorOptions {
  length?: number
  uppercase?: boolean
  lowercase?: boolean
  numbers?: boolean
  special?: boolean
  minUppercase?: number
  minLowercase?: number
  /** Bitwarden's upstream field name. */
  minNumber?: number
  /** Backwards-friendly plural alias for callers using the UI label. */
  minNumbers?: number
  minSpecial?: number
  avoidAmbiguous?: boolean
}

export interface PassphraseGeneratorOptions {
  wordCount?: number
  separator?: string
  capitalize?: boolean
  includeNumber?: boolean
}

export interface RandomWordUsernameOptions {
  capitalize?: boolean
  includeNumber?: boolean
}

const RANDOM_EMAIL_ALPHABET = 'abcdefghijklmnopqrstuvwxyz1234567890'
const RANDOM_EMAIL_SUFFIX_LENGTH = 8
const MAX_EMAIL_LENGTH = 254
const MAX_EMAIL_LOCAL_LENGTH = 64
const MAX_DOMAIN_LENGTH = 253

export const PASSWORD_DEFAULTS = Object.freeze({
  length: 14,
  uppercase: true,
  lowercase: true,
  numbers: true,
  special: false,
  minUppercase: 1,
  minLowercase: 1,
  minNumbers: 1,
  minSpecial: 0,
  avoidAmbiguous: false
}) satisfies Omit<Required<PasswordGeneratorOptions>, 'minNumber' | 'minNumbers'> & {
  minNumbers: number
}

export const PASSPHRASE_DEFAULTS = Object.freeze({
  wordCount: 6,
  separator: '-',
  capitalize: false,
  includeNumber: false
}) satisfies Required<PassphraseGeneratorOptions>

export const PASSWORD_LIMITS = Object.freeze({ minLength: 5, maxLength: 128 })
export const PASSPHRASE_LIMITS = Object.freeze({ minWords: 3, maxWords: 20 })

const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz'
const NUMBERS = '0123456789'
const SPECIAL = '!@#$%^&*'
// Bitwarden's official SDK documents these five glyphs as ambiguous.
const AMBIGUOUS = new Set('0O1lI'.split(''))

function invalid(): never {
  // Do not include option values in this error: generator inputs can themselves
  // contain sensitive material when the function is called from a UI bridge.
  throw new VaultError('INVALID_INPUT')
}

function integerOption(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number
): number {
  const resolved = value === undefined ? fallback : value
  if (!Number.isSafeInteger(resolved) || resolved < minimum || resolved > maximum) invalid()
  return resolved
}

function booleanOption(value: boolean | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback
  if (typeof value !== 'boolean') invalid()
  return value
}

function exactOptions(value: object, allowedKeys: readonly string[]): void {
  if (Object.keys(value).some((key) => !allowedKeys.includes(key))) invalid()
}

function nextRandom(randomInt: RandomInt, maxExclusive: number): number {
  if (!Number.isSafeInteger(maxExclusive) || maxExclusive <= 0) invalid()
  let value: number
  try {
    value = randomInt(maxExclusive)
  } catch {
    invalid()
  }
  if (!Number.isSafeInteger(value) || value < 0 || value >= maxExclusive) invalid()
  return value
}

function pick<T>(values: readonly T[], randomInt: RandomInt): T {
  if (values.length === 0) invalid()
  return values[nextRandom(randomInt, values.length)]!
}

function shuffle<T>(values: T[], randomInt: RandomInt): void {
  for (let index = values.length - 1; index > 0; index -= 1) {
    const swapIndex = nextRandom(randomInt, index + 1)
    ;[values[index], values[swapIndex]] = [values[swapIndex]!, values[index]!]
  }
}

function characterSet(value: string, avoidAmbiguous: boolean): string {
  if (!avoidAmbiguous) return value
  return [...value].filter((character) => !AMBIGUOUS.has(character)).join('')
}

/**
 * Generate a Bitwarden-compatible password using a cryptographically secure
 * random source. No generated value is logged or persisted by this module.
 */
export function generatePassword(
  options: PasswordGeneratorOptions = {},
  randomInt: RandomInt = nodeRandomInt
): string {
  if (typeof options !== 'object' || options === null || Array.isArray(options)) invalid()
  exactOptions(options, [
    'length',
    'uppercase',
    'lowercase',
    'numbers',
    'special',
    'minUppercase',
    'minLowercase',
    'minNumber',
    'minNumbers',
    'minSpecial',
    'avoidAmbiguous'
  ])
  const length = integerOption(
    options.length,
    PASSWORD_DEFAULTS.length,
    PASSWORD_LIMITS.minLength,
    PASSWORD_LIMITS.maxLength
  )
  const uppercase = booleanOption(options.uppercase, PASSWORD_DEFAULTS.uppercase)
  const lowercase = booleanOption(options.lowercase, PASSWORD_DEFAULTS.lowercase)
  const numbers = booleanOption(options.numbers, PASSWORD_DEFAULTS.numbers)
  const special = booleanOption(options.special, PASSWORD_DEFAULTS.special)
  const avoidAmbiguous = booleanOption(options.avoidAmbiguous, PASSWORD_DEFAULTS.avoidAmbiguous)

  const minUppercase = integerOption(
    options.minUppercase,
    uppercase ? PASSWORD_DEFAULTS.minUppercase : 0,
    0,
    length
  )
  const minLowercase = integerOption(
    options.minLowercase,
    lowercase ? PASSWORD_DEFAULTS.minLowercase : 0,
    0,
    length
  )
  if (options.minNumber !== undefined && options.minNumbers !== undefined) invalid()
  const minNumbers = integerOption(
    options.minNumber ?? options.minNumbers,
    numbers ? PASSWORD_DEFAULTS.minNumbers : 0,
    0,
    9
  )
  const minSpecial = integerOption(
    options.minSpecial,
    special ? PASSWORD_DEFAULTS.minSpecial : 0,
    0,
    9
  )
  if (
    (!uppercase && minUppercase > 0) ||
    (!lowercase && minLowercase > 0) ||
    (!numbers && minNumbers > 0) ||
    (!special && minSpecial > 0)
  )
    invalid()

  const sets = {
    uppercase: characterSet(UPPERCASE, avoidAmbiguous),
    lowercase: characterSet(LOWERCASE, avoidAmbiguous),
    numbers: characterSet(NUMBERS, avoidAmbiguous),
    special: characterSet(SPECIAL, avoidAmbiguous)
  }
  const enabledSets = [
    uppercase ? sets.uppercase : '',
    lowercase ? sets.lowercase : '',
    numbers ? sets.numbers : '',
    special ? sets.special : ''
  ].filter((set) => set.length > 0)
  if (enabledSets.length === 0) invalid()

  const requiredCount = minUppercase + minLowercase + minNumbers + minSpecial
  if (requiredCount > length) invalid()

  const slots: Array<keyof typeof sets | 'any'> = []
  slots.push(...Array.from({ length: minUppercase }, () => 'uppercase' as const))
  slots.push(...Array.from({ length: minLowercase }, () => 'lowercase' as const))
  slots.push(...Array.from({ length: minNumbers }, () => 'numbers' as const))
  slots.push(...Array.from({ length: minSpecial }, () => 'special' as const))
  slots.push(...Array.from({ length: length - requiredCount }, () => 'any' as const))
  shuffle(slots, randomInt)

  const allCharacters = enabledSets.join('')
  return slots
    .map((slot) => {
      const source = slot === 'any' ? allCharacters : sets[slot]
      return pick([...source], randomInt)
    })
    .join('')
}

function validateWordlist(wordlist: readonly string[]): void {
  if (!Array.isArray(wordlist) || wordlist.length === 0 || wordlist.length > 100_000) invalid()
  const seen = new Set<string>()
  for (const word of wordlist) {
    if (
      typeof word !== 'string' ||
      word.length === 0 ||
      word.length > 64 ||
      word.trim() !== word ||
      /\s/u.test(word) ||
      seen.has(word)
    )
      invalid()
    seen.add(word)
  }
}

/**
 * Generate a passphrase from an injected wordlist. The caller must provide a
 * complete, vetted list (for example the official EFF list); this module does
 * not ship or pretend to ship a reduced production wordlist.
 */
export function generatePassphrase(
  options: PassphraseGeneratorOptions = {},
  wordlist: readonly string[],
  randomInt: RandomInt = nodeRandomInt
): string {
  if (typeof options !== 'object' || options === null || Array.isArray(options)) invalid()
  exactOptions(options, ['wordCount', 'separator', 'capitalize', 'includeNumber'])
  const wordCount = integerOption(
    options.wordCount,
    PASSPHRASE_DEFAULTS.wordCount,
    PASSPHRASE_LIMITS.minWords,
    PASSPHRASE_LIMITS.maxWords
  )
  const separator =
    options.separator === undefined ? PASSPHRASE_DEFAULTS.separator : options.separator
  if (
    typeof separator !== 'string' ||
    separator.length === 0 ||
    // Upstream's `maxLength: 1` is a JavaScript/HTML code-unit boundary. This
    // intentionally rejects surrogate-pair emoji separators.
    separator.length > 1 ||
    /[\p{Cc}\p{Cf}]/u.test(separator)
  )
    invalid()
  const capitalize = booleanOption(options.capitalize, PASSPHRASE_DEFAULTS.capitalize)
  const includeNumber = booleanOption(options.includeNumber, PASSPHRASE_DEFAULTS.includeNumber)
  validateWordlist(wordlist)

  const words = Array.from({ length: wordCount }, () => pick(wordlist, randomInt)).map((word) =>
    capitalize ? `${word[0]!.toUpperCase()}${word.slice(1)}` : word
  )
  if (includeNumber) {
    const index = nextRandom(randomInt, words.length)
    words[index] = `${words[index]}${nextRandom(randomInt, 10)}`
  }
  return words.join(separator)
}

function randomAscii(length: number, randomInt: RandomInt): string {
  return Array.from({ length }, () => pick([...RANDOM_EMAIL_ALPHABET], randomInt)).join('')
}

function validateDomain(value: string): string {
  if (
    value.length === 0 ||
    value.length > MAX_DOMAIN_LENGTH ||
    value.trim() !== value ||
    value.includes('/') ||
    /[\p{Cc}\p{Cf}\p{Z}@]/u.test(value)
  )
    invalid()
  const ascii = domainToASCII(value)
  if (
    ascii.length === 0 ||
    ascii.length > MAX_DOMAIN_LENGTH ||
    ascii.endsWith('.') ||
    ascii
      .split('.')
      .some(
        (label) =>
          label.length === 0 ||
          label.length > 63 ||
          !/^[a-z0-9-]+$/i.test(label) ||
          label.startsWith('-') ||
          label.endsWith('-')
      )
  )
    invalid()
  return value
}

function parseEmail(value: string): { username: string; subaddress: string; domain: string } {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_EMAIL_LENGTH ||
    value.trim() !== value ||
    /[\p{Cc}\p{Cf}\p{Z}]/u.test(value)
  )
    invalid()
  const at = value.lastIndexOf('@')
  if (at <= 0 || at !== value.indexOf('@')) invalid()
  const local = value.slice(0, at)
  const domain = validateDomain(value.slice(at + 1))
  if (
    local.length > MAX_EMAIL_LOCAL_LENGTH ||
    local.startsWith('.') ||
    local.endsWith('.') ||
    local.includes('..') ||
    local.includes('[') ||
    local.includes(']') ||
    /[<>(),:;\\"]/u.test(local)
  )
    invalid()
  const plus = local.indexOf('+')
  const username = plus < 0 ? local : local.slice(0, plus)
  const subaddress = plus < 0 ? '' : local.slice(plus + 1)
  if (username.length === 0 || (plus >= 0 && subaddress.length === 0)) invalid()
  return { username, subaddress, domain }
}

/** Generate Bitwarden's EFF random-word username with an optional four-digit suffix. */
export function generateRandomWordUsername(
  options: RandomWordUsernameOptions = {},
  wordlist: readonly string[],
  randomInt: RandomInt = nodeRandomInt
): string {
  if (typeof options !== 'object' || options === null || Array.isArray(options)) invalid()
  exactOptions(options, ['capitalize', 'includeNumber'])
  const capitalize = booleanOption(options.capitalize, false)
  const includeNumber = booleanOption(options.includeNumber, false)
  validateWordlist(wordlist)
  const selected = pick(wordlist, randomInt)
  const word = capitalize ? `${selected[0]!.toUpperCase()}${selected.slice(1)}` : selected
  if (!includeNumber) return word
  const digits = Array.from({ length: 4 }, () => nextRandom(randomInt, 10)).join('')
  return `${word}${digits}`
}

/** Extend a validated email's plus tag with Bitwarden's eight random ASCII characters. */
export function generatePlusAddressedEmail(
  email: string,
  randomInt: RandomInt = nodeRandomInt
): string {
  const parsed = parseEmail(email)
  const suffix = randomAscii(RANDOM_EMAIL_SUFFIX_LENGTH, randomInt)
  const tag = parsed.subaddress ? `${parsed.subaddress}${suffix}` : suffix
  const result = `${parsed.username}+${tag}@${parsed.domain}`
  if (result.length > MAX_EMAIL_LENGTH || result.slice(0, result.lastIndexOf('@')).length > 64) {
    invalid()
  }
  return result
}

/** Generate a validated catch-all address without any provider/network integration. */
export function generateCatchAllEmail(
  domain: string,
  randomInt: RandomInt = nodeRandomInt
): string {
  if (typeof domain !== 'string') invalid()
  const normalized = domain.startsWith('@') ? domain.slice(1) : domain
  const validDomain = validateDomain(normalized)
  return `${randomAscii(RANDOM_EMAIL_SUFFIX_LENGTH, randomInt)}@${validDomain}`
}
