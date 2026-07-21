import { describe, expect, it } from 'vitest'
import type { VaultCustomFieldView } from '../../../shared/vault-contract'
import {
  customFieldCopyFeedbackKey,
  customFieldDisplayValue,
  detailFields,
  matchesCustomFieldSource
} from './vault-detail-view-model'
import { makeLoginView } from './vault-detail-test-fixtures'

const labels = {
  username: 'Username',
  password: 'Password',
  website: 'Website',
  cardNumber: 'Card number',
  securityCode: 'Security code',
  cardholder: 'Cardholder',
  brand: 'Brand',
  expirationDate: 'Expiration date',
  name: 'Name',
  company: 'Company',
  email: 'Email',
  phone: 'Phone',
  address: 'Address',
  ssn: 'SSN',
  passportNumber: 'Passport number',
  licenseNumber: 'License number',
  privateKey: 'Private key',
  publicKey: 'Public key',
  keyFingerprint: 'Fingerprint'
}

describe('detailFields', () => {
  it('projects ordered login URI fields with copy and open metadata', () => {
    const fields = detailFields(
      makeLoginView({
        uris: [
          { uri: 'https://first.example.invalid', match: null },
          { uri: 'https://second.example.invalid', match: 1 }
        ]
      }),
      labels
    )

    expect(fields).toEqual([
      { field: 'username', label: 'Username', value: 'sample-user', copyable: true },
      { field: 'password', label: 'Password', secret: true },
      {
        field: 'uri',
        label: 'Website',
        value: 'https://first.example.invalid',
        copyable: true,
        openUri: true,
        uriIndex: 0
      },
      {
        field: 'uri',
        label: 'Website 2',
        value: 'https://second.example.invalid',
        copyable: true,
        openUri: true,
        uriIndex: 1
      }
    ])
  })

  it('projects card, identity, and SSH-specific display values', () => {
    const card = detailFields(
      makeLoginView({
        type: 'card',
        cardholderName: 'Sample Cardholder',
        brand: 'visa',
        expMonth: '07',
        expYear: '2030'
      }),
      labels
    )
    const identity = detailFields(
      makeLoginView({
        type: 'identity',
        title: 'Dr.',
        firstName: 'Sample',
        lastName: 'Person',
        address1: 'Example Road',
        city: 'Example City',
        country: 'Example Country'
      }),
      labels
    )
    const sshKey = detailFields(
      makeLoginView({ type: 'sshKey', publicKey: 'public-key', fingerprint: 'fingerprint' }),
      labels
    )

    expect(card.find((field) => field.field === 'cardExpiration')?.value).toBe('07 / 2030')
    expect(identity[0]?.value).toBe('Dr. Sample Person')
    expect(identity.find((field) => field.label === 'Address')?.value).toBe(
      'Example Road，Example City，Example Country'
    )
    expect(sshKey).toEqual([
      { field: 'privateKey', label: 'Private key', secret: true },
      { field: 'publicKey', label: 'Public key', value: 'public-key', copyable: true },
      { field: 'fingerprint', label: 'Fingerprint', value: 'fingerprint', copyable: true }
    ])
    expect(detailFields(makeLoginView({ type: 'secureNote' }), labels)).toEqual([])
  })
})

describe('custom field view model', () => {
  const displayLabels = {
    yes: 'Yes',
    no: 'No',
    linkedTo: (label: string): string => `Linked to ${label}`,
    itemField: 'Item field',
    linkedFields: { 100: 'Username' },
    unset: 'Unset'
  }

  it('formats boolean, linked, and unset values', () => {
    expect(
      customFieldDisplayValue(
        { name: 'Enabled', value: 'TRUE', type: 'boolean', linkedId: null },
        displayLabels
      )
    ).toBe('Yes')
    expect(
      customFieldDisplayValue(
        { name: 'Linked', value: null, type: 'linked', linkedId: 100 },
        displayLabels
      )
    ).toBe('Linked to Username')
    expect(
      customFieldDisplayValue(
        { name: 'Missing link', value: null, type: 'linked', linkedId: 999 },
        displayLabels
      )
    ).toBe('Linked to Item field')
    expect(
      customFieldDisplayValue(
        { name: 'Empty', value: '', type: 'text', linkedId: null },
        displayLabels
      )
    ).toBe('Unset')
  })

  it('matches the complete stale-safe source identity', () => {
    const field: VaultCustomFieldView = {
      name: 'Account alias',
      value: 'sample',
      type: 'text',
      linkedId: null
    }
    const source = { index: 2, name: 'Account alias', type: 'text' as const, linkedId: null }

    expect(matchesCustomFieldSource(field, 2, source)).toBe(true)
    expect(matchesCustomFieldSource(field, 1, source)).toBe(false)
    expect(matchesCustomFieldSource({ ...field, name: 'Changed' }, 2, source)).toBe(false)
  })

  it('builds a stable copy feedback key from item and field identity', () => {
    const field: VaultCustomFieldView = {
      name: 'Account alias',
      value: 'sample',
      type: 'text',
      linkedId: null
    }

    expect(customFieldCopyFeedbackKey('item-id', 2, field)).toBe(
      '["custom","item-id",2,"Account alias","text",null]'
    )
  })
})
