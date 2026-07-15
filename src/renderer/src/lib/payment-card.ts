/**
 * Display helpers only. These functions intentionally do not validate card length,
 * checksum (Luhn), issuer allocation, or whether a card can be used for payment.
 */
export type PaymentCardBrand = 'visa' | 'mastercard' | 'jcb' | 'american-express' | 'unknown'
export type PaymentCardBrandOption = PaymentCardBrand | ''

const BITWARDEN_BRAND_ALIASES: Record<string, PaymentCardBrand> = {
  visa: 'visa',
  mastercard: 'mastercard',
  jcb: 'jcb',
  americanexpress: 'american-express',
  amex: 'american-express'
}

/** Returns only ASCII decimal digits, suitable for non-validating display logic. */
export function sanitizePaymentCardNumber(value: string | null | undefined): string {
  return value?.replace(/[^0-9]/g, '') ?? ''
}

/** Formats a number for display or input using groups of four digits. */
export function formatPaymentCardNumber(value: string | null | undefined): string {
  return sanitizePaymentCardNumber(value)
    .replace(/(\d{4})(?=\d)/g, '$1 ')
    .trim()
}

/**
 * Classifies only the requested, stable prefix ranges. This is not a payment-card
 * validity check and intentionally returns unknown for every other range.
 */
export function detectPaymentCardBrand(value: string | null | undefined): PaymentCardBrand {
  const digits = sanitizePaymentCardNumber(value)
  if (digits.startsWith('4')) return 'visa'
  if (digits.startsWith('34') || digits.startsWith('37')) return 'american-express'
  if (
    digits.startsWith('51') ||
    digits.startsWith('52') ||
    digits.startsWith('53') ||
    digits.startsWith('54') ||
    digits.startsWith('55')
  ) {
    return 'mastercard'
  }

  const firstFour = Number(digits.slice(0, 4))
  if (digits.length >= 4 && firstFour >= 2221 && firstFour <= 2720) return 'mastercard'
  if (digits.length >= 4 && firstFour >= 3528 && firstFour <= 3589) return 'jcb'
  return 'unknown'
}

/** Maps Bitwarden's human-readable brand values to the local display brand. */
export function normalizeBitwardenCardBrand(value: string | null | undefined): PaymentCardBrand {
  if (!value) return 'unknown'
  const normalized = value.toLocaleLowerCase('en-US').replace(/[^a-z]/g, '')
  return BITWARDEN_BRAND_ALIASES[normalized] ?? 'unknown'
}

/** Maps a stored brand to the editor select without treating an empty value as "other". */
export function paymentCardBrandOption(value: string | null | undefined): PaymentCardBrandOption {
  return value ? normalizeBitwardenCardBrand(value) : ''
}
