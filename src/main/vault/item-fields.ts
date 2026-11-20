import type {
  VaultCopyField,
  VaultEditorSecretField,
  VaultItemFields,
  VaultItemType,
  VaultReprompt,
  VaultSecretField
} from '../../shared/vault-contract'
import { VaultError } from '../vault-errors'
import {
  MAX_ITEM_FIELD_LENGTH,
  MAX_PASSWORD_LENGTH,
  MAX_SSH_PRIVATE_KEY_LENGTH,
  MAX_URI_LENGTH
} from './limits'
import { normalizeNullableString, normalizeString } from './parse-primitives'

/** Bitwarden `CipherType` wire values. */
export const WIRE_TYPE_BY_ITEM_TYPE = {
  login: 1,
  secureNote: 2,
  card: 3,
  identity: 4,
  sshKey: 5,
  bankAccount: 6,
  driversLicense: 7,
  passport: 8
} as const satisfies Record<VaultItemType, number>

export type BitwardenCipherWireType = (typeof WIRE_TYPE_BY_ITEM_TYPE)[VaultItemType]

export const ITEM_TYPE_BY_WIRE_TYPE = Object.fromEntries(
  Object.entries(WIRE_TYPE_BY_ITEM_TYPE).map(([itemType, wireType]) => [wireType, itemType])
) as Readonly<Record<BitwardenCipherWireType, VaultItemType>>

export function isBitwardenCipherWireType(value: unknown): value is BitwardenCipherWireType {
  return typeof value === 'number' && Object.hasOwn(ITEM_TYPE_BY_WIRE_TYPE, value)
}

/** Fields introduced with Bitwarden cipher types 6-8; vaults before v24 omit them. */
export const BANK_ACCOUNT_AND_DOCUMENT_FIELD_NAMES = [
  'bankName',
  'nameOnAccount',
  'accountType',
  'accountNumber',
  'routingNumber',
  'branchNumber',
  'pin',
  'swiftCode',
  'iban',
  'bankContactPhone',
  'dateOfBirth',
  'issuingCountry',
  'issuingState',
  'issueDate',
  'expirationDate',
  'issuingAuthority',
  'licenseClass',
  'surname',
  'givenName',
  'sex',
  'birthPlace',
  'nationality',
  'passportType',
  'nationalIdentificationNumber'
] as const satisfies readonly (keyof VaultItemFields)[]

export type BankAccountAndDocumentFieldName = (typeof BANK_ACCOUNT_AND_DOCUMENT_FIELD_NAMES)[number]

export function pickBankAccountAndDocumentFields(
  fields: VaultItemFields
): Pick<VaultItemFields, BankAccountAndDocumentFieldName> {
  return Object.fromEntries(
    BANK_ACCOUNT_AND_DOCUMENT_FIELD_NAMES.map((name) => [name, fields[name]])
  ) as Pick<VaultItemFields, BankAccountAndDocumentFieldName>
}

export const ITEM_FIELD_NAMES = [
  'username',
  'password',
  'totp',
  'uri',
  'cardholderName',
  'brand',
  'number',
  'expMonth',
  'expYear',
  'code',
  'title',
  'firstName',
  'middleName',
  'lastName',
  'address1',
  'address2',
  'address3',
  'city',
  'state',
  'postalCode',
  'country',
  'company',
  'email',
  'phone',
  'ssn',
  'identityUsername',
  'passportNumber',
  'licenseNumber',
  'privateKey',
  'publicKey',
  'fingerprint',
  ...BANK_ACCOUNT_AND_DOCUMENT_FIELD_NAMES
] as const satisfies readonly (keyof VaultItemFields)[]

export type ItemFieldName = (typeof ITEM_FIELD_NAMES)[number]

const ITEM_FIELDS_BY_TYPE: Record<VaultItemType, readonly ItemFieldName[]> = {
  login: ['username', 'password', 'totp', 'uri'],
  card: ['cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code'],
  identity: [
    'title',
    'firstName',
    'middleName',
    'lastName',
    'address1',
    'address2',
    'address3',
    'city',
    'state',
    'postalCode',
    'country',
    'company',
    'email',
    'phone',
    'ssn',
    'identityUsername',
    'passportNumber',
    'licenseNumber'
  ],
  secureNote: [],
  sshKey: ['privateKey', 'publicKey', 'fingerprint'],
  bankAccount: [
    'bankName',
    'nameOnAccount',
    'accountType',
    'accountNumber',
    'routingNumber',
    'branchNumber',
    'pin',
    'swiftCode',
    'iban',
    'bankContactPhone'
  ],
  driversLicense: [
    'firstName',
    'middleName',
    'lastName',
    'dateOfBirth',
    'licenseNumber',
    'issuingCountry',
    'issuingState',
    'issueDate',
    'expirationDate',
    'issuingAuthority',
    'licenseClass'
  ],
  passport: [
    'surname',
    'givenName',
    'dateOfBirth',
    'sex',
    'birthPlace',
    'nationality',
    'issuingCountry',
    'passportNumber',
    'passportType',
    'nationalIdentificationNumber',
    'issuingAuthority',
    'issueDate',
    'expirationDate'
  ]
}

const SECRET_FIELDS_BY_TYPE: Record<VaultItemType, readonly VaultSecretField[]> = {
  login: ['password'],
  card: ['number', 'code'],
  identity: ['ssn', 'passportNumber', 'licenseNumber'],
  secureNote: [],
  sshKey: ['privateKey'],
  bankAccount: ['accountNumber', 'pin', 'swiftCode', 'iban'],
  driversLicense: ['licenseNumber'],
  passport: ['passportNumber', 'nationalIdentificationNumber']
}

export const EDITOR_SECRET_FIELDS_BY_TYPE: Record<
  VaultItemType,
  readonly VaultEditorSecretField[]
> = {
  ...SECRET_FIELDS_BY_TYPE,
  login: ['password', 'totp']
}

const COPY_FIELDS_BY_TYPE: Record<VaultItemType, readonly VaultCopyField[]> = {
  login: ['username', 'password', 'uri'],
  card: ['number', 'code', 'cardholderName', 'brand', 'cardExpiration'],
  identity: ['email', 'phone', 'ssn', 'identityUsername', 'passportNumber', 'licenseNumber'],
  secureNote: [],
  sshKey: ['privateKey', 'publicKey', 'fingerprint'],
  bankAccount: [
    'nameOnAccount',
    'accountNumber',
    'routingNumber',
    'branchNumber',
    'pin',
    'swiftCode',
    'iban'
  ],
  driversLicense: ['firstName', 'middleName', 'lastName', 'licenseNumber'],
  passport: ['givenName', 'surname', 'passportNumber', 'nationalIdentificationNumber']
}

/** Plain string fields owned by each typed payload. Login and SSH key have bespoke codecs. */
export function itemFieldsForType(type: VaultItemType): readonly ItemFieldName[] {
  return ITEM_FIELDS_BY_TYPE[type]
}

export function emptyItemFields(): VaultItemFields {
  return {
    username: '',
    password: '',
    totp: '',
    uri: null,
    cardholderName: '',
    brand: '',
    number: '',
    expMonth: '',
    expYear: '',
    code: '',
    title: '',
    firstName: '',
    middleName: '',
    lastName: '',
    address1: '',
    address2: '',
    address3: '',
    city: '',
    state: '',
    postalCode: '',
    country: '',
    company: '',
    email: '',
    phone: '',
    ssn: '',
    identityUsername: '',
    passportNumber: '',
    licenseNumber: '',
    privateKey: '',
    publicKey: '',
    fingerprint: '',
    bankName: '',
    nameOnAccount: '',
    accountType: '',
    accountNumber: '',
    routingNumber: '',
    branchNumber: '',
    pin: '',
    swiftCode: '',
    iban: '',
    bankContactPhone: '',
    dateOfBirth: '',
    issuingCountry: '',
    issuingState: '',
    issueDate: '',
    expirationDate: '',
    issuingAuthority: '',
    licenseClass: '',
    surname: '',
    givenName: '',
    sex: '',
    birthPlace: '',
    nationality: '',
    passportType: '',
    nationalIdentificationNumber: ''
  }
}

export function normalizeItemFieldsForStorage(input: VaultItemFields): VaultItemFields {
  const fields = emptyItemFields()
  for (const field of ITEM_FIELD_NAMES) {
    const value = input[field]
    if (field === 'uri') {
      fields.uri = normalizeNullableString(value, MAX_URI_LENGTH)
    } else {
      fields[field] = normalizeString(value, maxLengthForItemField(field))
    }
  }
  return fields
}

export function maxLengthForItemField(field: ItemFieldName): number {
  if (field === 'password' || field === 'totp') return MAX_PASSWORD_LENGTH
  if (field === 'uri') return MAX_URI_LENGTH
  if (field === 'privateKey') return MAX_SSH_PRIVATE_KEY_LENGTH
  return MAX_ITEM_FIELD_LENGTH
}

export function isVaultItemType(value: unknown): value is VaultItemType {
  return typeof value === 'string' && Object.hasOwn(ITEM_FIELDS_BY_TYPE, value)
}

export function normalizeItemType(value: unknown): VaultItemType {
  if (!isVaultItemType(value)) throw new VaultError('INVALID_INPUT')
  return value
}

export function normalizeReprompt(value: unknown): VaultReprompt {
  if (value !== 0 && value !== 1) throw new VaultError('INVALID_INPUT')
  return value
}

export function applyItemFields(
  target: VaultItemFields,
  input: Partial<VaultItemFields>,
  type: VaultItemType
): void {
  const allowed = new Set(ITEM_FIELDS_BY_TYPE[type])
  for (const field of ITEM_FIELD_NAMES) {
    const value = input[field]
    if (value === undefined) continue
    if (!allowed.has(field)) {
      if (value === '' || value === null) continue
      throw new VaultError('INVALID_INPUT')
    }
    if (field === 'uri') {
      target.uri = normalizeNullableString(value, MAX_URI_LENGTH)
    } else {
      target[field] = normalizeString(value, maxLengthForItemField(field))
    }
  }
}

export function assertSecretField(type: VaultItemType, field: VaultSecretField): void {
  if (!SECRET_FIELDS_BY_TYPE[type].includes(field)) throw new VaultError('INVALID_INPUT')
}

export function assertCopyField(type: VaultItemType, field: VaultCopyField): void {
  if (!COPY_FIELDS_BY_TYPE[type].includes(field)) throw new VaultError('INVALID_INPUT')
}
