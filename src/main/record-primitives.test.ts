import { describe, expect, it } from 'vitest'
import { isPlainObjectRecord, isRecord } from './record-primitives'

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
