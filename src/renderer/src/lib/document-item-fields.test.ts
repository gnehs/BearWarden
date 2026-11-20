import { describe, expect, it } from 'vitest'
import { formatDocumentDate, invalidDocumentDateField } from './document-item-fields'

const blank = { dateOfBirth: '', issueDate: '', expirationDate: '' }

describe('invalidDocumentDateField', () => {
  it('accepts blank and real calendar dates on licenses and passports', () => {
    const dates = { dateOfBirth: '1990-01-31', issueDate: '', expirationDate: '2028-02-29' }
    expect(invalidDocumentDateField('driversLicense', dates)).toBeNull()
    expect(invalidDocumentDateField('passport', blank)).toBeNull()
  })

  it('names the first incomplete or impossible date', () => {
    expect(invalidDocumentDateField('passport', { ...blank, issueDate: '2021-02-30' })).toBe(
      'issueDate'
    )
    expect(
      invalidDocumentDateField('driversLicense', { ...blank, expirationDate: '2028-2-1' })
    ).toBe('expirationDate')
  })

  it('keeps an untouched date another client stored in a different format', () => {
    const original = { ...blank, dateOfBirth: '31/01/1990' }
    expect(invalidDocumentDateField('passport', original, original)).toBeNull()
    expect(
      invalidDocumentDateField('passport', { ...original, dateOfBirth: '1/1990' }, original)
    ).toBe('dateOfBirth')
  })

  it('ignores item types without document dates', () => {
    expect(
      invalidDocumentDateField('bankAccount', { ...blank, dateOfBirth: 'not a date' })
    ).toBeNull()
  })
})

describe('formatDocumentDate', () => {
  it('shows a non-ISO value exactly as stored', () => {
    expect(formatDocumentDate('31/01/1990')).toBe('31/01/1990')
  })

  it('formats the stored calendar day without shifting time zones', () => {
    expect(formatDocumentDate('1990-01-31')).toMatch(/31/u)
  })
})
