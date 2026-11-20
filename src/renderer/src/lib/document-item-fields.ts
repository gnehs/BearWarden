import { i18n } from '../i18n'
import type { VaultItemFields, VaultItemType } from '../../../shared/vault-contract'

/** Bitwarden `BankAccountType` wire values, in the official editor's order. */
export const BANK_ACCOUNT_TYPES = [
  'checking',
  'savings',
  'certificateOfDeposit',
  'lineOfCredit',
  'investmentBrokerage',
  'moneyMarket',
  'other'
] as const

export type BankAccountType = (typeof BANK_ACCOUNT_TYPES)[number]

export function isBankAccountType(value: string): value is BankAccountType {
  return (BANK_ACCOUNT_TYPES as readonly string[]).includes(value)
}

export type DocumentDateField = 'dateOfBirth' | 'issueDate' | 'expirationDate'

const DATE_FIELDS_BY_TYPE: Partial<Record<VaultItemType, readonly DocumentDateField[]>> = {
  driversLicense: ['dateOfBirth', 'issueDate', 'expirationDate'],
  passport: ['dateOfBirth', 'issueDate', 'expirationDate']
}

const ISO_DATE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/u

function parseIsoDate(value: string): Date | null {
  const match = ISO_DATE_PATTERN.exec(value)
  if (!match) return null
  const [year, month, day] = [Number(match[1]), Number(match[2]), Number(match[3])]
  const date = new Date(Date.UTC(year, month - 1, day))
  return date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
    ? date
    : null
}

/**
 * The first date field that is neither blank nor a real `YYYY-MM-DD` calendar date. Values the
 * user did not touch are exempt so an unusual date written by another client still saves.
 */
export function invalidDocumentDateField(
  type: VaultItemType,
  fields: Pick<VaultItemFields, DocumentDateField>,
  original?: Pick<VaultItemFields, DocumentDateField>
): DocumentDateField | null {
  for (const field of DATE_FIELDS_BY_TYPE[type] ?? []) {
    const value = fields[field]
    if (value === '' || value === original?.[field]) continue
    if (!parseIsoDate(value)) return field
  }
  return null
}

/** Shows a stored `YYYY-MM-DD` date in the UI locale; anything else is shown as stored. */
export function formatDocumentDate(value: string): string {
  const date = parseIsoDate(value)
  if (!date) return value
  return new Intl.DateTimeFormat(i18n.locale || 'en', {
    dateStyle: 'medium',
    timeZone: 'UTC'
  }).format(date)
}
