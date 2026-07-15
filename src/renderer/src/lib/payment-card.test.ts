import { describe, expect, it } from 'vitest'
import {
  detectPaymentCardBrand,
  formatPaymentCardNumber,
  normalizeBitwardenCardBrand,
  sanitizePaymentCardNumber
} from './payment-card'

describe('payment-card display helpers', () => {
  it('sanitizes to ASCII digits and groups every four digits for display', () => {
    expect(sanitizePaymentCardNumber(' 4000-0012 34x ')).toBe('4000001234')
    expect(formatPaymentCardNumber('4000-0012 3456')).toBe('4000 0012 3456')
    expect(formatPaymentCardNumber('12345')).toBe('1234 5')
    expect(formatPaymentCardNumber(null)).toBe('')
  })

  it('uses only conservative prefix ranges when detecting card brands', () => {
    expect(detectPaymentCardBrand('4000 0000')).toBe('visa')
    expect(detectPaymentCardBrand('5100 0000')).toBe('mastercard')
    expect(detectPaymentCardBrand('5500 0000')).toBe('mastercard')
    expect(detectPaymentCardBrand('2221 0000')).toBe('mastercard')
    expect(detectPaymentCardBrand('2720 0000')).toBe('mastercard')
    expect(detectPaymentCardBrand('2220 0000')).toBe('unknown')
    expect(detectPaymentCardBrand('2721 0000')).toBe('unknown')
    expect(detectPaymentCardBrand('3528 0000')).toBe('jcb')
    expect(detectPaymentCardBrand('3589 0000')).toBe('jcb')
    expect(detectPaymentCardBrand('3527 0000')).toBe('unknown')
    expect(detectPaymentCardBrand('3590 0000')).toBe('unknown')
    expect(detectPaymentCardBrand('3400 0000')).toBe('american-express')
    expect(detectPaymentCardBrand('3700 0000')).toBe('american-express')
    expect(detectPaymentCardBrand('6000 0000')).toBe('unknown')
  })

  it('normalizes Bitwarden brand labels without claiming payment validity', () => {
    expect(normalizeBitwardenCardBrand('Visa')).toBe('visa')
    expect(normalizeBitwardenCardBrand('Master Card')).toBe('mastercard')
    expect(normalizeBitwardenCardBrand('JCB')).toBe('jcb')
    expect(normalizeBitwardenCardBrand('American Express')).toBe('american-express')
    expect(normalizeBitwardenCardBrand('Amex')).toBe('american-express')
    expect(normalizeBitwardenCardBrand('Discover')).toBe('unknown')
    expect(normalizeBitwardenCardBrand(null)).toBe('unknown')
  })
})
