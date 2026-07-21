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

export function detailFields(login: LoginView, labels: Record<string, string>): DetailField[] {
  if (login.type === 'login') {
    return [
      { field: 'username', label: labels.username!, value: login.username, copyable: true },
      { field: 'password', label: labels.password!, secret: true },
      ...login.uris.map((entry, uriIndex) => ({
        field: 'uri' as const,
        label: uriIndex === 0 ? labels.website! : `${labels.website} ${uriIndex + 1}`,
        value: entry.uri,
        copyable: true,
        openUri: true,
        uriIndex
      }))
    ]
  }
  if (login.type === 'card') {
    return [
      { field: 'number', label: labels.cardNumber!, secret: true },
      { field: 'code', label: labels.securityCode!, secret: true },
      {
        field: 'cardholderName',
        label: labels.cardholder!,
        value: login.cardholderName,
        copyable: true
      },
      { field: 'brand', label: labels.brand!, value: login.brand, copyable: true },
      {
        field: 'cardExpiration',
        label: labels.expirationDate!,
        value: [login.expMonth, login.expYear].filter(Boolean).join(' / '),
        copyable: true
      }
    ]
  }
  if (login.type === 'identity') {
    return [
      {
        field: 'username',
        label: labels.name!,
        value: [login.title, login.firstName, login.middleName, login.lastName]
          .filter(Boolean)
          .join(' ')
      },
      { field: 'username', label: labels.company!, value: login.company },
      { field: 'email', label: labels.email!, value: login.email, copyable: true },
      { field: 'phone', label: labels.phone!, value: login.phone, copyable: true },
      {
        field: 'identityUsername',
        label: labels.username!,
        value: login.identityUsername,
        copyable: true
      },
      {
        field: 'username',
        label: labels.address!,
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
      { field: 'ssn', label: labels.ssn!, secret: true },
      { field: 'passportNumber', label: labels.passportNumber!, secret: true },
      { field: 'licenseNumber', label: labels.licenseNumber!, secret: true }
    ]
  }
  if (login.type === 'sshKey') {
    return [
      { field: 'privateKey', label: labels.privateKey!, secret: true },
      { field: 'publicKey', label: labels.publicKey!, value: login.publicKey, copyable: true },
      {
        field: 'fingerprint',
        label: labels.keyFingerprint!,
        value: login.fingerprint,
        copyable: true
      }
    ]
  }
  return []
}
