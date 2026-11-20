import type {
  LoginView,
  VaultCopyField,
  VaultCustomFieldSource,
  VaultCustomFieldView
} from '../../../shared/vault-contract'

export interface DetailField {
  field: VaultCopyField
  label: string
  value?: string | null
  secret?: boolean
  copyable?: boolean
  openUri?: boolean
  uriIndex?: number
}

export function customFieldDisplayValue(
  field: VaultCustomFieldView,
  labels: {
    yes: string
    no: string
    linkedTo: (label: string) => string
    itemField: string
    linkedFields: Record<number, string>
    unset: string
  }
): string {
  if (field.type === 'boolean')
    return field.value?.toLowerCase() === 'true' ? labels.yes : labels.no
  if (field.type === 'linked') {
    return labels.linkedTo(
      field.linkedId === null
        ? labels.itemField
        : (labels.linkedFields[field.linkedId] ?? labels.itemField)
    )
  }
  return field.value || labels.unset
}

export function matchesCustomFieldSource(
  field: VaultCustomFieldView,
  index: number,
  source: VaultCustomFieldSource
): boolean {
  return (
    source.index === index &&
    source.name === field.name &&
    source.type === field.type &&
    source.linkedId === field.linkedId
  )
}

export function customFieldCopyFeedbackKey(
  itemId: string,
  index: number,
  field: VaultCustomFieldView
): string {
  return JSON.stringify(['custom', itemId, index, field.name, field.type, field.linkedId])
}

export function detailFieldCopyFeedbackKey(
  itemId: string | undefined,
  field: VaultCopyField,
  uriIndex: number | undefined
): string {
  return `field:${itemId}:${field}:${uriIndex ?? ''}`
}

export interface DetailFieldFormatters {
  date: (value: string) => string
  bankAccountType: (value: string) => string
}

const identityFormatters: DetailFieldFormatters = {
  date: (value) => value,
  bankAccountType: (value) => value
}

export function detailFields(
  login: LoginView,
  labels: Record<string, string>,
  format: DetailFieldFormatters = identityFormatters
): DetailField[] {
  if (login.type === 'login') {
    return [
      { field: 'username', label: labels.username, value: login.username, copyable: true },
      { field: 'password', label: labels.password, secret: true },
      ...login.uris.map((entry, uriIndex) => ({
        field: 'uri' as const,
        label: uriIndex === 0 ? labels.website : `${labels.website} ${uriIndex + 1}`,
        value: entry.uri,
        copyable: true,
        openUri: true,
        uriIndex
      }))
    ]
  }
  if (login.type === 'card') {
    return [
      { field: 'number', label: labels.cardNumber, secret: true },
      { field: 'code', label: labels.securityCode, secret: true },
      {
        field: 'cardholderName',
        label: labels.cardholder,
        value: login.cardholderName,
        copyable: true
      },
      { field: 'brand', label: labels.brand, value: login.brand, copyable: true },
      {
        field: 'cardExpiration',
        label: labels.expirationDate,
        value: [login.expMonth, login.expYear].filter(Boolean).join(' / '),
        copyable: true
      }
    ]
  }
  if (login.type === 'identity') {
    return [
      {
        field: 'username',
        label: labels.name,
        value: [login.title, login.firstName, login.middleName, login.lastName]
          .filter(Boolean)
          .join(' ')
      },
      { field: 'username', label: labels.company, value: login.company },
      { field: 'email', label: labels.email, value: login.email, copyable: true },
      { field: 'phone', label: labels.phone, value: login.phone, copyable: true },
      {
        field: 'identityUsername',
        label: labels.username,
        value: login.identityUsername,
        copyable: true
      },
      {
        field: 'username',
        label: labels.address,
        value: [
          login.address1,
          login.address2,
          login.address3,
          login.city,
          login.state,
          login.postalCode,
          login.country
        ]
          .filter(Boolean)
          .join('，')
      },
      { field: 'ssn', label: labels.ssn, secret: true },
      { field: 'passportNumber', label: labels.passportNumber, secret: true },
      { field: 'licenseNumber', label: labels.licenseNumber, secret: true }
    ]
  }
  if (login.type === 'bankAccount') {
    return [
      { field: 'username', label: labels.bankName, value: login.bankName },
      {
        field: 'nameOnAccount',
        label: labels.nameOnAccount,
        value: login.nameOnAccount,
        copyable: true
      },
      {
        field: 'username',
        label: labels.accountType,
        value: login.accountType && format.bankAccountType(login.accountType)
      },
      { field: 'accountNumber', label: labels.accountNumber, secret: true },
      {
        field: 'routingNumber',
        label: labels.routingNumber,
        value: login.routingNumber,
        copyable: true
      },
      {
        field: 'branchNumber',
        label: labels.branchNumber,
        value: login.branchNumber,
        copyable: true
      },
      { field: 'pin', label: labels.bankPin, secret: true },
      { field: 'swiftCode', label: labels.swiftCode, secret: true },
      { field: 'iban', label: labels.iban, secret: true },
      { field: 'username', label: labels.bankContactPhone, value: login.bankContactPhone }
    ]
  }
  if (login.type === 'driversLicense') {
    return [
      { field: 'firstName', label: labels.firstName, value: login.firstName, copyable: true },
      { field: 'middleName', label: labels.middleName, value: login.middleName, copyable: true },
      { field: 'lastName', label: labels.lastName, value: login.lastName, copyable: true },
      { field: 'licenseNumber', label: labels.licenseNumber, secret: true },
      ...documentDates(login, labels, format, ['dateOfBirth']),
      { field: 'username', label: labels.issuingCountry, value: login.issuingCountry },
      { field: 'username', label: labels.issuingState, value: login.issuingState },
      { field: 'username', label: labels.issuingAuthority, value: login.issuingAuthority },
      ...documentDates(login, labels, format, ['issueDate', 'expirationDate']),
      { field: 'username', label: labels.licenseClass, value: login.licenseClass }
    ]
  }
  if (login.type === 'passport') {
    return [
      { field: 'givenName', label: labels.givenName, value: login.givenName, copyable: true },
      { field: 'surname', label: labels.surname, value: login.surname, copyable: true },
      ...documentDates(login, labels, format, ['dateOfBirth']),
      { field: 'username', label: labels.sex, value: login.sex },
      { field: 'username', label: labels.birthPlace, value: login.birthPlace },
      { field: 'username', label: labels.nationality, value: login.nationality },
      { field: 'passportNumber', label: labels.passportNumber, secret: true },
      { field: 'username', label: labels.passportType, value: login.passportType },
      {
        field: 'nationalIdentificationNumber',
        label: labels.nationalIdentificationNumber,
        secret: true
      },
      { field: 'username', label: labels.issuingCountry, value: login.issuingCountry },
      { field: 'username', label: labels.issuingAuthority, value: login.issuingAuthority },
      ...documentDates(login, labels, format, ['issueDate', 'expirationDate'])
    ]
  }
  if (login.type === 'sshKey') {
    return [
      { field: 'privateKey', label: labels.privateKey, secret: true },
      { field: 'publicKey', label: labels.publicKey, value: login.publicKey, copyable: true },
      {
        field: 'fingerprint',
        label: labels.keyFingerprint,
        value: login.fingerprint,
        copyable: true
      }
    ]
  }
  return []
}

function documentDates(
  login: LoginView,
  labels: Record<string, string>,
  format: DetailFieldFormatters,
  fields: ReadonlyArray<'dateOfBirth' | 'issueDate' | 'expirationDate'>
): DetailField[] {
  return fields.map((field) => ({
    // Display-only rows reuse a non-secret field id; they are neither copyable nor revealable.
    field: 'username',
    label: labels[field]!,
    value: login[field] && format.date(login[field])
  }))
}
