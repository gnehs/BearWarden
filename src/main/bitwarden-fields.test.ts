import { describe, expect, it } from 'vitest'
import { readField, readUnambiguousField } from './bitwarden-fields'

const ambiguous = (): never => {
  throw new Error('ambiguous')
}

describe('readField', () => {
  it.each([
    { label: 'camelCase only', record: { revisionDate: 'a' }, expected: 'a' },
    { label: 'PascalCase only', record: { RevisionDate: 'a' }, expected: 'a' },
    {
      label: 'both spellings, equal',
      record: { revisionDate: 'a', RevisionDate: 'a' },
      expected: 'a'
    },
    {
      label: 'both spellings, different',
      record: { RevisionDate: 'b', revisionDate: 'a' },
      expected: 'a'
    },
    {
      label: 'camelCase null, PascalCase set',
      record: { revisionDate: null, RevisionDate: 'b' },
      expected: 'b'
    },
    { label: 'another casing only', record: { REVISIONDATE: 'a' }, expected: 'a' },
    { label: 'only null', record: { RevisionDate: null }, expected: null },
    { label: 'absent', record: { revision: 'a' }, expected: undefined }
  ])('reads $label', ({ record, expected }) => {
    expect(readField<unknown>(record, 'revisionDate')).toBe(expected)
  })

  it('ignores inherited properties', () => {
    expect(readField(Object.create({ id: 'inherited' }) as Record<string, unknown>, 'id')).toBe(
      undefined
    )
  })
})

describe('readUnambiguousField', () => {
  it.each([
    { label: 'camelCase only', record: { enabled: true }, expected: true },
    { label: 'PascalCase only', record: { Enabled: true }, expected: true },
    { label: 'another casing only', record: { ENABLED: true }, expected: true },
    { label: 'absent', record: {}, expected: undefined }
  ])('reads $label', ({ record, expected }) => {
    expect(readUnambiguousField<unknown>(record, 'enabled', ambiguous)).toBe(expected)
  })

  it.each([
    { label: 'both spellings, equal', record: { enabled: true, Enabled: true } },
    { label: 'both spellings, different', record: { enabled: true, Enabled: false } },
    { label: 'camelCase null, PascalCase set', record: { enabled: null, Enabled: true } }
  ])('rejects $label', ({ record }) => {
    expect(() => readUnambiguousField<unknown>(record, 'enabled', ambiguous)).toThrow('ambiguous')
  })
})
