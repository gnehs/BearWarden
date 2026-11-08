import { describe, expect, it } from 'vitest'
import {
  isPlainObjectRecord,
  isRecord,
  LOOSE_LOWERCASE_UUID_PATTERN,
  LOOSE_UUID_PATTERN,
  STRICT_LOWERCASE_UUID_PATTERN,
  UUID_PATTERN
} from './validation-primitives'

describe('record predicates', () => {
  class Custom {}

  it('accepts any non-array object in isRecord', () => {
    expect(isRecord({})).toBe(true)
    expect(isRecord(Object.create(null))).toBe(true)
    expect(isRecord(new Custom())).toBe(true)
    expect(isRecord(new Map())).toBe(true)
    expect(isRecord([])).toBe(false)
    expect(isRecord(null)).toBe(false)
    expect(isRecord('x')).toBe(false)
    expect(isRecord(undefined)).toBe(false)
  })

  it('accepts only Object.prototype or null prototypes in isPlainObjectRecord', () => {
    expect(isPlainObjectRecord({})).toBe(true)
    expect(isPlainObjectRecord(Object.create(null))).toBe(true)
    expect(isPlainObjectRecord(new Custom())).toBe(false)
    expect(isPlainObjectRecord(new Map())).toBe(false)
    expect(isPlainObjectRecord([])).toBe(false)
    expect(isPlainObjectRecord(null)).toBe(false)
  })
})

describe('UUID patterns', () => {
  const version0 = '123e4567-e89b-02d3-a456-426614174000'
  const version9 = '123e4567-e89b-92d3-a456-426614174000'
  const validV4 = '123e4567-e89b-42d3-a456-426614174000'
  const upperV4 = '123E4567-E89B-42D3-A456-426614174000'
  const variantC = '123e4567-e89b-42d3-c456-426614174000'
  const upperLooseOnly = '123E4567-E89B-02D3-C456-426614174000'
  const malformed = [
    '',
    '123e4567e89b42d3a456426614174000',
    `${validV4}0`,
    ` ${validV4}`,
    `${validV4}\n`
  ]

  it.each([
    [
      'UUID_PATTERN',
      UUID_PATTERN,
      [validV4, upperV4],
      [version0, version9, variantC, upperLooseOnly]
    ],
    [
      'STRICT_LOWERCASE_UUID_PATTERN',
      STRICT_LOWERCASE_UUID_PATTERN,
      [validV4],
      [upperV4, version0, version9, variantC]
    ],
    [
      'LOOSE_UUID_PATTERN',
      LOOSE_UUID_PATTERN,
      [validV4, upperV4, version0, version9, variantC, upperLooseOnly],
      []
    ],
    [
      'LOOSE_LOWERCASE_UUID_PATTERN',
      LOOSE_LOWERCASE_UUID_PATTERN,
      [validV4, version0, version9, variantC],
      [upperV4, upperLooseOnly]
    ]
  ])('%s keeps its accept/reject boundary', (_name, pattern, accepted, rejected) => {
    for (const value of accepted) expect(pattern.test(value)).toBe(true)
    for (const value of [...rejected, ...malformed]) expect(pattern.test(value)).toBe(false)
  })
})
